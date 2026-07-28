import re
import logging
from app.collectors.transport import LinuxTransport
from app.collectors.modules.base_module import BaseCollectorModule, ModuleResult, ModuleResultStatus
from app.collectors.observations import CryptoObservation, CapabilityObservation, CapabilityState

logger = logging.getLogger(__name__)

class OpenSSHModule(BaseCollectorModule):
    module_id = "openssh_info"
    capability = "CRYPTO_CONFIGURATION"

    async def run(self, transport: LinuxTransport) -> ModuleResult:
        observations = []
        try:
            # Fallback version detection: sshd -V -> ssh -V -> dpkg/rpm
            version_str = None
            code, stdout, stderr = await transport.run_command(["sshd", "-V"])
            output = stderr or stdout
            if code == 0 or "OpenSSH" in output:
                version_str = output.strip()
            else:
                code, stdout, stderr = await transport.run_command(["ssh", "-V"])
                output = stderr or stdout
                if "OpenSSH" in output:
                    version_str = output.strip()

            if not version_str:
                return ModuleResult(
                    module_id=self.module_id,
                    capability=self.capability,
                    status=ModuleResultStatus.NOT_APPLICABLE,
                    observations=[]
                )

            observations.append(CryptoObservation(
                module_id=self.module_id,
                canonical_name="OpenSSH",
                object_type="LIBRARY",
                provider="OpenBSD Project",
                version=version_str,
                identity_key=f"crypto:openssh:{version_str.split()[0] if version_str else 'unknown'}",
                capability_state=CapabilityState.AVAILABLE
            ))

            # Effective server configuration via sshd -T (if sshd is running or executable)
            code, stdout_cfg, _ = await transport.run_command(["sshd", "-T"])
            if code == 0 and stdout_cfg:
                kex = []
                ciphers = []
                macs = []
                hostkeys = []

                for line in stdout_cfg.splitlines():
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        key = parts[0].lower()
                        val = parts[1]
                        if key == "kexalgorithms":
                            kex = val.split(",")
                        elif key == "ciphers":
                            ciphers = val.split(",")
                        elif key == "macs":
                            macs = val.split(",")
                        elif key == "hostkeyalgorithms":
                            hostkeys = val.split(",")

                has_hybrid_pqc = any("s256" in k or "mlkem" in k for k in kex)
                observations.append(CapabilityObservation(
                    module_id=self.module_id,
                    capability_name="SSH_KEX_CONFIG",
                    capability_state=CapabilityState.CONFIGURED,
                    algorithm_name="OpenSSH Effective KEX Configuration",
                    details={
                        "kex_algorithms": kex,
                        "ciphers": ciphers,
                        "macs": macs,
                        "host_key_algorithms": hostkeys,
                        "pqc_hybrid_configured": has_hybrid_pqc
                    }
                ))

            return ModuleResult(
                module_id=self.module_id,
                capability=self.capability,
                status=ModuleResultStatus.SUCCESS,
                observations=observations
            )

        except Exception as e:
            logger.exception(f"OpenSSHModule execution failed: {e}")
            return ModuleResult(
                module_id=self.module_id,
                capability=self.capability,
                status=ModuleResultStatus.PARTIAL,
                error_message=str(e),
                observations=observations
            )
