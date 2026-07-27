from typing import AsyncIterator, Set
from app.scanners.base import Scanner, RawFinding, ScanContext, ScannerRegistry
from app.models.entities import (
    TargetType, AssetType, TransportProtocol, ApplicationProtocol,
    FindingType, FindingPurpose, FindingConfidence
)

class MockScanner(Scanner):
    scanner_id = "mock-scanner"
    version = "1.0.0"
    supported_target_types = {
        TargetType.HOSTNAME, TargetType.IP_RANGE, TargetType.CIDR, TargetType.URL
    }

    async def discover(
        self,
        target_value: str,
        target_type: TargetType,
        context: ScanContext
    ) -> AsyncIterator[RawFinding]:
        # Generate deterministic mock findings for demo target or any authorized target
        hostname = target_value if target_type == TargetType.HOSTNAME or "demo" in target_value else f"host.{target_value}"
        ip_addr = "127.0.0.1"

        findings = [
            RawFinding(
                asset_hostname=hostname,
                asset_ip=ip_addr,
                asset_type=AssetType.HOST,
                environment="DEVELOPMENT",
                operating_system="Linux / POSIX",
                port=443,
                transport_protocol=TransportProtocol.TCP,
                application_protocol=ApplicationProtocol.HTTPS,
                service_name="https",
                service_metadata={"tls_version": "1.3", "server_banner": "nginx/1.24.0"},
                finding_type=FindingType.CERTIFICATE_PUBLIC_KEY,
                raw_algorithm_name="RSA-2048",
                key_size=2048,
                purpose=FindingPurpose.AUTHENTICATION,
                location_identifier=f"{hostname} -> HTTPS :443 -> TLS 1.3 -> Certificate",
                evidence_snippet="Certificate Public Key: RSA 2048 bits (e 65537)",
                confidence=FindingConfidence.HIGH,
                metadata={"cert_issuer": "CN=Demo Internal CA", "cert_serial": "0x1a2b3c4d"}
            ),
            RawFinding(
                asset_hostname=hostname,
                asset_ip=ip_addr,
                asset_type=AssetType.HOST,
                environment="DEVELOPMENT",
                operating_system="Linux / POSIX",
                port=443,
                transport_protocol=TransportProtocol.TCP,
                application_protocol=ApplicationProtocol.HTTPS,
                service_name="https",
                service_metadata={"tls_version": "1.3"},
                finding_type=FindingType.KEY_EXCHANGE,
                raw_algorithm_name="X25519",
                key_size=256,
                curve_or_parameter="Curve25519",
                purpose=FindingPurpose.KEY_EXCHANGE,
                location_identifier=f"{hostname} -> HTTPS :443 -> TLS 1.3 -> Handshake",
                evidence_snippet="ClientHello / ServerHello Key Exchange Group: X25519 (0x001d)",
                confidence=FindingConfidence.HIGH,
                metadata={"group_id": 29}
            ),
            RawFinding(
                asset_hostname=hostname,
                asset_ip=ip_addr,
                asset_type=AssetType.HOST,
                environment="DEVELOPMENT",
                operating_system="Linux / POSIX",
                port=443,
                transport_protocol=TransportProtocol.TCP,
                application_protocol=ApplicationProtocol.HTTPS,
                service_name="https",
                service_metadata={"tls_version": "1.3"},
                finding_type=FindingType.SYMMETRIC_CIPHER,
                raw_algorithm_name="AES-256-GCM",
                key_size=256,
                purpose=FindingPurpose.ENCRYPTION,
                location_identifier=f"{hostname} -> HTTPS :443 -> TLS 1.3 -> CipherSuite",
                evidence_snippet="Negotiated Cipher Suite: TLS_AES_256_GCM_SHA384 (0x1302)",
                confidence=FindingConfidence.HIGH,
                metadata={"cipher_mode": "GCM"}
            ),
            RawFinding(
                asset_hostname=hostname,
                asset_ip=ip_addr,
                asset_type=AssetType.HOST,
                environment="DEVELOPMENT",
                operating_system="Linux / POSIX",
                port=443,
                transport_protocol=TransportProtocol.TCP,
                application_protocol=ApplicationProtocol.HTTPS,
                service_name="https",
                service_metadata={"tls_version": "1.3"},
                finding_type=FindingType.HASH_FUNCTION,
                raw_algorithm_name="SHA-384",
                key_size=384,
                purpose=FindingPurpose.INTEGRITY,
                location_identifier=f"{hostname} -> HTTPS :443 -> TLS 1.3 -> PRF",
                evidence_snippet="TLS Handshake Digest / PRF: SHA-384",
                confidence=FindingConfidence.HIGH,
                metadata={"usage": "HMAC/PRF"}
            )
        ]

        for finding in findings:
            yield finding

# Register MockScanner on module load
ScannerRegistry.register(MockScanner())
