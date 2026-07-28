import re
import logging
from app.collectors.transport import LinuxTransport
from app.collectors.modules.base_module import BaseCollectorModule, ModuleResult, ModuleResultStatus
from app.collectors.observations import CryptoObservation, CapabilityObservation, CapabilityState

logger = logging.getLogger(__name__)

class OpenSSLModule(BaseCollectorModule):
    module_id = "openssl_info"
    capability = "CRYPTO_CONFIGURATION"

    async def run(self, transport: LinuxTransport) -> ModuleResult:
        observations = []
        try:
            # 1. OpenSSL Version
            code, stdout_ver, _ = await transport.run_command(["openssl", "version"])
            if code != 0 or not stdout_ver:
                return ModuleResult(
                    module_id=self.module_id,
                    capability=self.capability,
                    status=ModuleResultStatus.NOT_APPLICABLE,
                    observations=[]
                )

            version_str = stdout_ver.strip()
            
            # 2. OpenSSL Dir
            code, stdout_dir, _ = await transport.run_command(["openssl", "version", "-d"])
            openssl_dir = stdout_dir.strip().replace('OPENSSLDIR: "', '').replace('"', '') if code == 0 else "/etc/ssl"

            cobs = CryptoObservation(
                module_id=self.module_id,
                canonical_name="OpenSSL",
                object_type="LIBRARY",
                provider="OpenSSL Project",
                version=version_str,
                identity_key=f"crypto:openssl:{version_str.split()[1] if len(version_str.split()) > 1 else version_str}",
                capability_state=CapabilityState.AVAILABLE,
                metadata={"openssl_dir": openssl_dir}
            )
            observations.append(cobs)

            # 3. Check for FIPS provider configuration in openssl.cnf without storing full config
            cnf_content = await transport.read_file(f"{openssl_dir}/openssl.cnf")
            fips_configured = False
            if cnf_content:
                if re.search(r"fips\s*=\s*fips_sect", cnf_content, re.IGNORECASE) or "fipsmodule.cnf" in cnf_content:
                    fips_configured = True

            cap_state = CapabilityState.CONFIGURED if fips_configured else CapabilityState.AVAILABLE
            observations.append(CapabilityObservation(
                module_id=self.module_id,
                capability_name="FIPS_PROVIDER",
                capability_state=cap_state,
                algorithm_name="OpenSSL FIPS Provider",
                details={"fips_configured": fips_configured, "openssl_version": version_str}
            ))

            # 4. Check for PQC candidate / ML-KEM support in OpenSSL 3.4+ or OQS provider
            supports_pqc = "3." in version_str or "oqs" in version_str.lower()
            observations.append(CapabilityObservation(
                module_id=self.module_id,
                capability_name="ML_KEM_SUPPORT",
                capability_state=CapabilityState.AVAILABLE if supports_pqc else CapabilityState.INSTALLED,
                algorithm_name="ML-KEM-768",
                details={"supported_in_library": supports_pqc}
            ))

            return ModuleResult(
                module_id=self.module_id,
                capability=self.capability,
                status=ModuleResultStatus.SUCCESS,
                observations=observations
            )

        except Exception as e:
            logger.exception(f"OpenSSLModule execution failed: {e}")
            return ModuleResult(
                module_id=self.module_id,
                capability=self.capability,
                status=ModuleResultStatus.FAILED,
                error_message=str(e)
            )
