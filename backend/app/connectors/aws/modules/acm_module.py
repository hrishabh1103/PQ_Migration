import base64
import hashlib
import logging
from typing import AsyncIterator
from app.collectors.observations import CertificateObservation, RelationshipObservation
from app.connectors.aws.modules.base_aws_module import BaseAWSModule
from app.connectors.aws_sdk_client import AWSSdkClient

logger = logging.getLogger(__name__)

class ACMModule(BaseAWSModule):
    """
    Discovers AWS Certificate Manager (ACM) public & private X.509 certificate metadata.
    Zero-secret guardrail: Never exports private keys.
    Extracts true X.509 SHA-256 fingerprint from actual DER bytes returned by GetCertificate.
    If DER bytes are unavailable, sets fingerprint=None (never synthesizes fake fingerprint).
    """
    module_name = "ACM"
    capability = "X509"

    async def collect(
        self,
        sdk_client: AWSSdkClient,
        account_id: str,
        region: str,
        target_id: str
    ) -> AsyncIterator:
        acm = sdk_client.get_client("acm", region_override=region)
        paginator = acm.get_paginator("list_certificates")

        for page in paginator.paginate():
            for cert_summary in page.get("CertificateSummaryList", []):
                arn = cert_summary.get("CertificateArn")
                if not arn:
                    continue

                try:
                    desc = acm.describe_certificate(CertificateArn=arn)
                    cert = desc.get("Certificate", {})
                except Exception as e:
                    logger.warning(f"ACM DescribeCertificate failed for '{arn}': {e}")
                    continue

                domain_name = cert.get("DomainName") or cert_summary.get("DomainName", "unknown-domain")
                sans = cert.get("SubjectAlternativeNames", [])
                issuer = cert.get("Issuer", "AWS Certificate Manager")
                serial = cert.get("Serial", "")
                status = cert.get("Status", "UNKNOWN")
                key_algo = cert.get("KeyAlgorithm", "RSA-2048")
                sig_algo = cert.get("SignatureAlgorithm", "SHA256withRSA")

                # Retrieve actual X.509 DER certificate bytes for true SHA-256 fingerprint computation
                sha256_fp = None
                try:
                    cert_body_res = acm.get_certificate(CertificateArn=arn)
                    pem_str = cert_body_res.get("Certificate", "")
                    if pem_str:
                        lines = [line.strip() for line in pem_str.splitlines() if line.strip() and not line.startswith("-----")]
                        der_bytes = base64.b64decode("".join(lines))
                        sha256_fp = hashlib.sha256(der_bytes).hexdigest().lower()
                except Exception as e:
                    logger.info(f"ACM GetCertificate body unavailable for '{arn}': {e}")
                    sha256_fp = None

                cert_obs = CertificateObservation(
                    module_id="aws_acm",
                    fingerprint=sha256_fp,
                    subject=f"CN={domain_name}",
                    issuer=issuer,
                    serial_number=serial,
                    valid_from=str(cert.get("NotBefore")) if cert.get("NotBefore") else None,
                    valid_to=str(cert.get("NotAfter")) if cert.get("NotAfter") else None,
                    pubkey_algo=key_algo,
                    signature_algo=sig_algo,
                    san_list=sans,
                    location_identifier=arn,
                    metadata={
                        "certificate_arn": arn,
                        "status": status,
                        "type": cert.get("Type"),
                        "renewal_eligibility": cert.get("RenewalEligibility"),
                        "in_use_by": cert.get("InUseBy", [])
                    }
                )
                yield cert_obs

                # Yield in-use relationships (e.g. ALB -> USES -> CERTIFICATE)
                for in_use_arn in cert.get("InUseBy", []):
                    yield RelationshipObservation(
                        module_id="aws_acm",
                        source_type="ASSET",
                        source_id_hint=in_use_arn,
                        target_type="CRYPTO_OBJECT",
                        target_id_hint=arn,
                        relationship_type="USES",
                        confidence="HIGH"
                    )
