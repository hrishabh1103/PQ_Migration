import logging
from app.collectors.transport import LinuxTransport
from app.collectors.modules.base_module import BaseCollectorModule, ModuleResult, ModuleResultStatus
from app.collectors.observations import CapabilityObservation, CapabilityState

logger = logging.getLogger(__name__)

class CryptoPolicyModule(BaseCollectorModule):
    module_id = "crypto_policy"
    capability = "SYSTEM_CRYPTO_POLICY"

    async def run(self, transport: LinuxTransport) -> ModuleResult:
        observations = []
        try:
            policy_name = None
            code, stdout, _ = await transport.run_command(["update-crypto-policies", "--show"])
            if code == 0 and stdout:
                policy_name = stdout.strip()

            if not policy_name:
                pol_file = await transport.read_file("/etc/crypto-policies/state/current")
                if pol_file:
                    policy_name = pol_file.strip()

            if not policy_name:
                return ModuleResult(
                    module_id=self.module_id,
                    capability=self.capability,
                    status=ModuleResultStatus.NOT_APPLICABLE,
                    observations=[]
                )

            c_obs = CapabilityObservation(
                module_id=self.module_id,
                capability_name="SYSTEM_CRYPTO_POLICY",
                capability_state=CapabilityState.CONFIGURED,
                algorithm_name=f"System Policy ({policy_name})",
                details={"policy_name": policy_name}
            )
            observations.append(c_obs)

            return ModuleResult(
                module_id=self.module_id,
                capability=self.capability,
                status=ModuleResultStatus.SUCCESS,
                observations=observations
            )

        except Exception as e:
            logger.exception(f"CryptoPolicyModule execution failed: {e}")
            return ModuleResult(
                module_id=self.module_id,
                capability=self.capability,
                status=ModuleResultStatus.PARTIAL,
                error_message=str(e),
                observations=observations
            )
