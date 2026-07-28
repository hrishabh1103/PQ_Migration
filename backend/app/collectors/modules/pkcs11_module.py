import logging
from app.collectors.transport import LinuxTransport
from app.collectors.modules.base_module import BaseCollectorModule, ModuleResult, ModuleResultStatus
from app.collectors.observations import CryptoObservation, CapabilityState

logger = logging.getLogger(__name__)

PKCS11_DIRS = ["/etc/pkcs11/modules", "/usr/lib64/pkcs11", "/usr/lib/x86_64-linux-gnu/pkcs11"]

class PKCS11Module(BaseCollectorModule):
    module_id = "pkcs11_config"
    capability = "CRYPTO_CONFIGURATION"

    async def run(self, transport: LinuxTransport) -> ModuleResult:
        observations = []
        try:
            for root in PKCS11_DIRS:
                if not await transport.file_exists(root):
                    continue

                matched = await transport.list_files(
                    root=root,
                    patterns=["*.module", "*.so"],
                    max_depth=2,
                    max_results=10,
                    max_file_size=5_000_000
                )

                for item in matched:
                    path = item["path"]
                    fname = item["filename"]

                    cobs = CryptoObservation(
                        module_id=self.module_id,
                        canonical_name=f"PKCS#11 Module ({fname})",
                        object_type="CRYPTO_MODULE",
                        provider="PKCS#11 Provider",
                        identity_key=f"pkcs11:{path}",
                        capability_state=CapabilityState.INSTALLED,
                        metadata={"module_path": path}
                    )
                    observations.append(cobs)

            status = ModuleResultStatus.SUCCESS if observations else ModuleResultStatus.NOT_APPLICABLE
            return ModuleResult(
                module_id=self.module_id,
                capability=self.capability,
                status=status,
                observations=observations
            )

        except Exception as e:
            logger.exception(f"PKCS11Module execution failed: {e}")
            return ModuleResult(
                module_id=self.module_id,
                capability=self.capability,
                status=ModuleResultStatus.PARTIAL,
                error_message=str(e),
                observations=observations
            )
