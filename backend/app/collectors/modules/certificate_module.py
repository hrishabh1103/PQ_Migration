import os
import logging
from typing import List, Dict, Any
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization

from app.collectors.transport import LinuxTransport
from app.collectors.modules.base_module import BaseCollectorModule, ModuleResult, ModuleResultStatus
from app.collectors.observations import CertificateObservation, RelationshipObservation, CryptoObservation, CapabilityState

logger = logging.getLogger(__name__)

APPROVED_CERT_ROOTS = [
    "/etc/ssl/certs",
    "/etc/pki/tls/certs",
    "/etc/letsencrypt/live"
]

SAFE_PATTERNS = ["*.crt", "*.cer", "cert.pem", "chain.pem", "fullchain.pem"]

class CertificateModule(BaseCollectorModule):
    module_id = "system_certificates"
    capability = "X509"

    async def run(self, transport: LinuxTransport) -> ModuleResult:
        observations = []
        seen_fingerprints = set()

        try:
            for root in APPROVED_CERT_ROOTS:
                if not await transport.file_exists(root):
                    continue

                matched_files = await transport.list_files(
                    root=root,
                    patterns=SAFE_PATTERNS,
                    max_depth=3,
                    max_results=30,
                    max_file_size=2_000_000
                )

                for item in matched_files:
                    path = item["path"]
                    fname = item["filename"].lower()

                    # Explicit Security Check: Reject private keys
                    if "privkey" in fname or fname.endswith(".key"):
                        continue

                    content = await transport.read_file(path, max_bytes=500_000)
                    if not content or "BEGIN PRIVATE KEY" in content or "BEGIN RSA PRIVATE KEY" in content or "BEGIN EC PRIVATE KEY" in content:
                        continue

                    try:
                        cert = x509.load_pem_x509_certificate(content.encode("utf-8"), default_backend())
                        fp_sha256 = cert.fingerprint(hashes.SHA256()).hex().lower()

                        if fp_sha256 in seen_fingerprints:
                            continue
                        seen_fingerprints.add(fp_sha256)

                        pubkey = cert.public_key()
                        key_size = getattr(pubkey, "key_size", None)
                        pubkey_algo = pubkey.__class__.__name__.replace("_PublicKey", "").replace("PublicKey", "")

                        c_obs = CertificateObservation(
                            module_id=self.module_id,
                            fingerprint=fp_sha256,
                            subject=cert.subject.rfc4514_string(),
                            issuer=cert.issuer.rfc4514_string(),
                            serial_number=str(cert.serial_number),
                            valid_from=cert.not_valid_before_utc.isoformat(),
                            valid_to=cert.not_valid_after_utc.isoformat(),
                            pubkey_algo=pubkey_algo,
                            pubkey_size=key_size,
                            signature_algo=cert.signature_algorithm_oid._name
                        )
                        observations.append(c_obs)

                        # Represent as CryptoObject CERTIFICATE
                        cobj_key = f"cert:sha256:{fp_sha256}"
                        cobj = CryptoObservation(
                            module_id=self.module_id,
                            canonical_name=f"X509 Certificate ({cert.subject.rfc4514_string()[:40]})",
                            object_type="CERTIFICATE",
                            provider=cert.issuer.rfc4514_string()[:40],
                            identity_key=cobj_key,
                            fingerprint=fp_sha256,
                            capability_state=CapabilityState.INSTALLED
                        )
                        observations.append(cobj)

                        # Create Relationship HOST -> CONTAINS -> CERTIFICATE
                        observations.append(RelationshipObservation(
                            module_id=self.module_id,
                            source_type="Asset",
                            source_id_hint="host",
                            target_type="CryptoObject",
                            target_id_hint=cobj_key,
                            relationship_type="CONTAINS"
                        ))

                    except Exception:
                        continue

            status = ModuleResultStatus.SUCCESS if observations else ModuleResultStatus.NOT_APPLICABLE
            return ModuleResult(
                module_id=self.module_id,
                capability=self.capability,
                status=status,
                observations=observations
            )

        except Exception as e:
            logger.exception(f"CertificateModule execution failed: {e}")
            return ModuleResult(
                module_id=self.module_id,
                capability=self.capability,
                status=ModuleResultStatus.FAILED,
                error_message=str(e)
            )
