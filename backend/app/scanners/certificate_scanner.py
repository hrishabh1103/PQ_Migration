import os
import glob
import logging
from typing import AsyncIterator, Set, Optional, Tuple
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519, x25519

from app.scanners.base import Scanner, RawFinding, ScanContext, ScannerRegistry
from app.models.entities import (
    TargetType, AssetType, TransportProtocol, ApplicationProtocol,
    FindingType, FindingPurpose, FindingConfidence
)

logger = logging.getLogger(__name__)

class CertificateScanner(Scanner):
    scanner_id = "certificate-scanner"
    version = "1.0.0"
    supported_target_types = {
        TargetType.CERT_STORE, TargetType.HOSTNAME, TargetType.URL, TargetType.REPOSITORY
    }

    async def discover(
        self,
        target_value: str,
        target_type: TargetType,
        context: ScanContext
    ) -> AsyncIterator[RawFinding]:
        target_path = target_value.strip()

        # If target path exists on disk, scan directory for cert files
        if os.path.exists(target_path):
            cert_files = []
            if os.path.isfile(target_path):
                cert_files.append(target_path)
            else:
                for ext in ("*.pem", "*.crt", "*.cer", "*.der"):
                    cert_files.extend(glob.glob(os.path.join(target_path, "**", ext), recursive=True))

            for cert_file in cert_files:
                try:
                    with open(cert_file, "rb") as f:
                        data = f.read()

                    if b"-----BEGIN CERTIFICATE-----" in data:
                        certs = x509.load_pem_x509_certificates(data)
                    else:
                        certs = [x509.load_der_x509_certificate(data)]

                    for cert in certs:
                        async for finding in self._process_certificate(cert, location=cert_file):
                            yield finding

                except Exception as e:
                    logger.warning(f"Error parsing cert file '{cert_file}': {e}")
        else:
            logger.info(f"[CertificateScanner] Path '{target_value}' is not a local certificate file; no cert findings extracted.")
            return

    async def _process_certificate(self, cert: x509.Certificate, location: str) -> AsyncIterator[RawFinding]:
        public_key = cert.public_key()
        algo_name, key_size, curve_name = self._parse_public_key(public_key)
        sig_algo = cert.signature_algorithm_oid._name

        yield RawFinding(
            asset_hostname=os.path.basename(location),
            asset_type=AssetType.HOST,
            environment="PRODUCTION",
            finding_type=FindingType.CERTIFICATE_PUBLIC_KEY,
            raw_algorithm_name=algo_name,
            key_size=key_size,
            curve_or_parameter=curve_name,
            purpose=FindingPurpose.AUTHENTICATION,
            location_identifier=f"File: {location} -> X.509 Certificate",
            evidence_snippet=f"X.509 Certificate Subject: {cert.subject.rfc4514_string()}; Public Key: {algo_name}; Sig: {sig_algo}",
            confidence=FindingConfidence.HIGH,
            metadata={
                "file_path": location,
                "cert_subject": cert.subject.rfc4514_string(),
                "cert_issuer": cert.issuer.rfc4514_string(),
                "serial_number": str(cert.serial_number),
                "signature_algorithm": sig_algo,
                "not_valid_after": cert.not_valid_after_utc.isoformat() if hasattr(cert, 'not_valid_after_utc') else cert.not_valid_after.isoformat()
            }
        )

        # Signature algorithm finding
        if sig_algo:
            yield RawFinding(
                asset_hostname=os.path.basename(location),
                asset_type=AssetType.HOST,
                environment="PRODUCTION",
                finding_type=FindingType.SIGNATURE_ALGORITHM,
                raw_algorithm_name=sig_algo.upper().replace("_", "-"),
                purpose=FindingPurpose.DIGITAL_SIGNATURE,
                location_identifier=f"File: {location} -> X.509 SignatureAlgorithm",
                evidence_snippet=f"X.509 Certificate Signature Algorithm: {sig_algo}",
                confidence=FindingConfidence.HIGH,
                metadata={"file_path": location}
            )

    def _parse_public_key(self, public_key) -> Tuple[str, Optional[int], Optional[str]]:
        if isinstance(public_key, rsa.RSAPublicKey):
            return f"RSA-{public_key.key_size}", public_key.key_size, None
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            return f"ECDSA-{public_key.curve.name.upper()}", public_key.key_size, public_key.curve.name
        elif isinstance(public_key, ed25519.Ed25519PublicKey):
            return "Ed25519", 256, "Curve25519"
        elif isinstance(public_key, x25519.X25519PublicKey):
            return "X25519", 256, "Curve25519"
        elif isinstance(public_key, dsa.DSAPublicKey):
            return f"DSA-{public_key.key_size}", public_key.key_size, None
        return "UNKNOWN_PUBLIC_KEY", None, None

    async def _simulated_cert_finding(self, target_value: str) -> AsyncIterator[RawFinding]:
        yield RawFinding(
            asset_hostname=target_value,
            asset_type=AssetType.HOST,
            environment="DEVELOPMENT",
            finding_type=FindingType.CERTIFICATE_PUBLIC_KEY,
            raw_algorithm_name="RSA-2048",
            key_size=2048,
            purpose=FindingPurpose.AUTHENTICATION,
            location_identifier=f"CertStore: {target_value} -> X.509 Certificate",
            evidence_snippet=f"X.509 Certificate Public Key: RSA 2048 bits for {target_value}",
            confidence=FindingConfidence.HIGH,
            metadata={"cert_store": target_value, "issuer": "CN=Development CA"}
        )

ScannerRegistry.register(CertificateScanner())
