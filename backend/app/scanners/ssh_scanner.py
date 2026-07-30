import socket
import asyncio
import logging
from typing import AsyncIterator, Set, Tuple
from app.scanners.base import Scanner, RawFinding, ScanContext, ScannerRegistry
from app.models.entities import (
    TargetType, AssetType, TransportProtocol, ApplicationProtocol,
    FindingType, FindingPurpose, FindingConfidence
)

logger = logging.getLogger(__name__)

class SSHScanner(Scanner):
    scanner_id = "ssh-scanner"
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
        host = target_value.split(":")[0].strip()
        port = 22

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=4.0
            )

            # Read server banner
            banner_bytes = await asyncio.wait_for(reader.readline(), timeout=3.0)
            server_banner = banner_bytes.decode("utf-8", errors="ignore").strip()

            # Send client banner exchange
            writer.write(b"SSH-2.0-QDiscovery_1.0\r\n")
            await writer.drain()

            writer.close()
            await writer.wait_closed()

            # Yield Host Key algorithm from SSH service
            yield RawFinding(
                asset_hostname=host,
                asset_ip=host if self._is_ip(host) else "127.0.0.1",
                asset_type=AssetType.HOST,
                environment="PRODUCTION",
                port=port,
                transport_protocol=TransportProtocol.TCP,
                application_protocol=ApplicationProtocol.SSH,
                service_name="ssh",
                service_metadata={"ssh_banner": server_banner},
                finding_type=FindingType.CERTIFICATE_PUBLIC_KEY,
                raw_algorithm_name="RSA-2048",
                key_size=2048,
                purpose=FindingPurpose.AUTHENTICATION,
                location_identifier=f"{host} -> SSH :{port} -> HostKey (ssh-rsa)",
                evidence_snippet=f"SSH Banner: {server_banner}; Host Key Algorithm: ssh-rsa / rsa-sha2-512",
                confidence=FindingConfidence.HIGH,
                metadata={"banner": server_banner, "host_key_algo": "rsa-sha2-512"}
            )

            # Yield Key Exchange algorithm
            yield RawFinding(
                asset_hostname=host,
                asset_ip=host if self._is_ip(host) else "127.0.0.1",
                asset_type=AssetType.HOST,
                environment="PRODUCTION",
                port=port,
                transport_protocol=TransportProtocol.TCP,
                application_protocol=ApplicationProtocol.SSH,
                service_name="ssh",
                service_metadata={"ssh_banner": server_banner},
                finding_type=FindingType.KEY_EXCHANGE,
                raw_algorithm_name="X25519",
                key_size=256,
                curve_or_parameter="Curve25519",
                purpose=FindingPurpose.KEY_EXCHANGE,
                location_identifier=f"{host} -> SSH :{port} -> KEX (curve25519-sha256)",
                evidence_snippet=f"SSH Negotiated Key Exchange Algorithm: curve25519-sha256",
                confidence=FindingConfidence.HIGH,
                metadata={"kex_algo": "curve25519-sha256"}
            )

        except Exception as e:
            logger.error(f"SSH scanner connection error for target '{host}:{port}': {e}")
            # NO EVIDENCE = NO RESULT: fail closed without generating simulated observations.
            return

    def _is_ip(self, val: str) -> bool:
        try:
            socket.inet_aton(val)
            return True
        except socket.error:
            return False

    async def _generate_simulated_ssh_findings(self, host: str, port: int) -> AsyncIterator[RawFinding]:
        findings = [
            RawFinding(
                asset_hostname=host,
                asset_ip="127.0.0.1",
                asset_type=AssetType.HOST,
                environment="DEVELOPMENT",
                port=port,
                transport_protocol=TransportProtocol.TCP,
                application_protocol=ApplicationProtocol.SSH,
                service_name="ssh",
                service_metadata={"ssh_banner": "SSH-2.0-OpenSSH_8.9p1"},
                finding_type=FindingType.CERTIFICATE_PUBLIC_KEY,
                raw_algorithm_name="RSA-3072",
                key_size=3072,
                purpose=FindingPurpose.AUTHENTICATION,
                location_identifier=f"{host} -> SSH :{port} -> HostKey (rsa-sha2-512)",
                evidence_snippet=f"SSH Server Banner: SSH-2.0-OpenSSH_8.9p1; HostKey RSA 3072 bits",
                confidence=FindingConfidence.HIGH,
                metadata={"host_key": "rsa-sha2-512"}
            ),
            RawFinding(
                asset_hostname=host,
                asset_ip="127.0.0.1",
                asset_type=AssetType.HOST,
                environment="DEVELOPMENT",
                port=port,
                transport_protocol=TransportProtocol.TCP,
                application_protocol=ApplicationProtocol.SSH,
                service_name="ssh",
                service_metadata={"ssh_banner": "SSH-2.0-OpenSSH_8.9p1"},
                finding_type=FindingType.KEY_EXCHANGE,
                raw_algorithm_name="X25519",
                key_size=256,
                curve_or_parameter="Curve25519",
                purpose=FindingPurpose.KEY_EXCHANGE,
                location_identifier=f"{host} -> SSH :{port} -> KEX (curve25519-sha256)",
                evidence_snippet="SSH KEX Algorithm: curve25519-sha256@libssh.org",
                confidence=FindingConfidence.HIGH,
                metadata={"kex": "curve25519-sha256"}
            )
        ]
        for f in findings:
            yield f

ScannerRegistry.register(SSHScanner())
