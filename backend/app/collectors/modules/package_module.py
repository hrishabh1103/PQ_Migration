import logging
import re
from app.collectors.transport import LinuxTransport
from app.collectors.modules.base_module import BaseCollectorModule, ModuleResult, ModuleResultStatus
from app.collectors.observations import CryptoObservation, RelationshipObservation, CapabilityState

logger = logging.getLogger(__name__)

TARGET_PACKAGES = [
    "openssl", "libssl", "libssl-dev", "libssl3", "openssh", "openssh-server",
    "gnutls", "libgnutls30", "nss", "libnss3", "libgcrypt", "libgcrypt20",
    "libsodium", "libsodium23", "bouncycastle", "libbouncycastle-java",
    "python3-cryptography", "python-cryptography"
]

class PackageModule(BaseCollectorModule):
    module_id = "crypto_packages"
    capability = "CRYPTO_LIBRARY"

    async def run(self, transport: LinuxTransport) -> ModuleResult:
        observations = []
        try:
            # 1. dpkg-query for Debian/Ubuntu
            code, stdout_dpkg, _ = await transport.run_command(["dpkg-query", "-W", "-f=${Package} ${Version}\\n"])
            if code == 0 and stdout_dpkg:
                for line in stdout_dpkg.splitlines():
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        pkg_name, pkg_ver = parts[0].lower(), parts[1]
                        if any(tp in pkg_name for tp in TARGET_PACKAGES):
                            cobs = CryptoObservation(
                                module_id=self.module_id,
                                canonical_name=parts[0],
                                object_type="LIBRARY",
                                provider="Debian/Ubuntu Package",
                                version=pkg_ver,
                                identity_key=f"pkg:{parts[0]}:{pkg_ver}",
                                capability_state=CapabilityState.INSTALLED
                            )
                            observations.append(cobs)
                            observations.append(RelationshipObservation(
                                module_id=self.module_id,
                                source_type="Asset",
                                source_id_hint="host",
                                target_type="CryptoObject",
                                target_id_hint=cobs.identity_key,
                                relationship_type="CONTAINS"
                            ))

            # 2. rpm -qa for RHEL/CentOS/Fedora if dpkg produced no findings
            if not observations:
                code, stdout_rpm, _ = await transport.run_command(["rpm", "-qa", "--queryformat", "%{NAME} %{VERSION}\\n"])
                if code == 0 and stdout_rpm:
                    for line in stdout_rpm.splitlines():
                        parts = line.strip().split()
                        if len(parts) >= 2:
                            pkg_name, pkg_ver = parts[0].lower(), parts[1]
                            if any(tp in pkg_name for tp in TARGET_PACKAGES):
                                cobs = CryptoObservation(
                                    module_id=self.module_id,
                                    canonical_name=parts[0],
                                    object_type="LIBRARY",
                                    provider="RPM Package",
                                    version=pkg_ver,
                                    identity_key=f"pkg:{parts[0]}:{pkg_ver}",
                                    capability_state=CapabilityState.INSTALLED
                                )
                                observations.append(cobs)
                                observations.append(RelationshipObservation(
                                    module_id=self.module_id,
                                    source_type="Asset",
                                    source_id_hint="host",
                                    target_type="CryptoObject",
                                    target_id_hint=cobs.identity_key,
                                    relationship_type="CONTAINS"
                                ))

            status = ModuleResultStatus.SUCCESS if observations else ModuleResultStatus.NOT_APPLICABLE
            return ModuleResult(
                module_id=self.module_id,
                capability=self.capability,
                status=status,
                observations=observations
            )

        except Exception as e:
            logger.exception(f"PackageModule execution failed: {e}")
            return ModuleResult(
                module_id=self.module_id,
                capability=self.capability,
                status=ModuleResultStatus.FAILED,
                error_message=str(e)
            )
