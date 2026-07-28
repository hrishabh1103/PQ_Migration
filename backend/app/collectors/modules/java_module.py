import re
import logging
from app.collectors.transport import LinuxTransport
from app.collectors.modules.base_module import BaseCollectorModule, ModuleResult, ModuleResultStatus
from app.collectors.observations import CryptoObservation, CapabilityObservation, CapabilityState

logger = logging.getLogger(__name__)

class JavaModule(BaseCollectorModule):
    module_id = "java_crypto"
    capability = "CRYPTO_LIBRARY"

    async def run(self, transport: LinuxTransport) -> ModuleResult:
        observations = []
        try:
            code, stdout, stderr = await transport.run_command(["java", "-version"])
            output = stderr or stdout
            if code != 0 or not output:
                return ModuleResult(
                    module_id=self.module_id,
                    capability=self.capability,
                    status=ModuleResultStatus.NOT_APPLICABLE,
                    observations=[]
                )

            version_str = output.splitlines()[0] if output else "Java Runtime"
            vendor = "OpenJDK / Oracle" if "openjdk" in output.lower() else "Java Vendor"

            cobs = CryptoObservation(
                module_id=self.module_id,
                canonical_name="Java Cryptography Architecture (JCA)",
                object_type="LIBRARY",
                provider=vendor,
                version=version_str,
                identity_key=f"crypto:java:{version_str[:30]}",
                capability_state=CapabilityState.AVAILABLE
            )
            observations.append(cobs)

            # Check java.security for security providers (SUN, SunEC, BouncyCastle)
            sec_content = await transport.read_file("/etc/java-11-openjdk/security/java.security") or await transport.read_file("/etc/java/security/java.security") or ""
            providers = re.findall(r"security\.provider\.\d+=(.*)", sec_content)

            observations.append(CapabilityObservation(
                module_id=self.module_id,
                capability_name="JAVA_JCA_PROVIDERS",
                capability_state=CapabilityState.CONFIGURED if providers else CapabilityState.AVAILABLE,
                algorithm_name="JCA Security Providers",
                details={"jca_providers": providers, "java_version": version_str}
            ))

            return ModuleResult(
                module_id=self.module_id,
                capability=self.capability,
                status=ModuleResultStatus.SUCCESS,
                observations=observations
            )

        except Exception as e:
            logger.exception(f"JavaModule execution failed: {e}")
            return ModuleResult(
                module_id=self.module_id,
                capability=self.capability,
                status=ModuleResultStatus.PARTIAL,
                error_message=str(e),
                observations=observations
            )
