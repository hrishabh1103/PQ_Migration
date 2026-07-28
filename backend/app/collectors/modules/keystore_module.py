import os
import logging
from app.collectors.transport import LinuxTransport
from app.collectors.modules.base_module import BaseCollectorModule, ModuleResult, ModuleResultStatus
from app.collectors.observations import CryptoObservation, CapabilityState

logger = logging.getLogger(__name__)

KEYSTORE_ROOTS = ["/etc/ssl/certs", "/etc/pki", "/etc/java"]
KEYSTORE_PATTERNS = ["*.jks", "*.p12", "*.pfx", "cacerts"]

class KeystoreModule(BaseCollectorModule):
    module_id = "keystores"
    capability = "KEYSTORE"

    async def run(self, transport: LinuxTransport) -> ModuleResult:
        observations = []
        try:
            for root in KEYSTORE_ROOTS:
                if not await transport.file_exists(root):
                    continue

                matched = await transport.list_files(
                    root=root,
                    patterns=KEYSTORE_PATTERNS,
                    max_depth=3,
                    max_results=10,
                    max_file_size=5_000_000
                )

                for item in matched:
                    path = item["path"]
                    fname = item["filename"]

                    ks_type = "JKS" if fname.endswith(".jks") or fname == "cacerts" else "PKCS12"
                    cobs = CryptoObservation(
                        module_id=self.module_id,
                        canonical_name=f"Keystore ({fname})",
                        object_type="KEYSTORE",
                        provider="Java / System",
                        identity_key=f"keystore:{path}",
                        capability_state=CapabilityState.INSTALLED,
                        metadata={
                            "keystore_type": ks_type,
                            "location": path,
                            "inspection_status": "AUTHENTICATION_REQUIRED",
                            "message": "Keystore metadata discovered without credential extraction"
                        }
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
            logger.exception(f"KeystoreModule execution failed: {e}")
            return ModuleResult(
                module_id=self.module_id,
                capability=self.capability,
                status=ModuleResultStatus.PARTIAL,
                error_message=str(e),
                observations=observations
            )
