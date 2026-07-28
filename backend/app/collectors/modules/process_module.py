import re
import logging
from app.collectors.transport import LinuxTransport
from app.collectors.modules.base_module import BaseCollectorModule, ModuleResult, ModuleResultStatus
from app.collectors.observations import ProcessObservation, AssetObservation, RelationshipObservation

logger = logging.getLogger(__name__)

TARGET_PROCESSES = ["sshd", "nginx", "httpd", "apache2", "haproxy", "java", "node", "python", "python3", "postgres", "mysqld"]

class ProcessModule(BaseCollectorModule):
    module_id = "crypto_processes"
    capability = "PROCESS_INVENTORY"

    async def run(self, transport: LinuxTransport) -> ModuleResult:
        observations = []
        try:
            code, stdout, _ = await transport.run_command(["ps", "-eo", "pid,comm,args"])
            if code == 0 and stdout:
                for line in stdout.splitlines()[1:]:
                    parts = line.strip().split(None, 2)
                    if len(parts) >= 2 and parts[0].isdigit():
                        pid = int(parts[0])
                        pname = parts[1].lower()
                        raw_args = parts[2] if len(parts) > 2 else ""

                        if any(tp == pname or pname.endswith("/" + tp) for tp in TARGET_PROCESSES):
                            # Sanitize command-line arguments (strip passwords, tokens, keys)
                            clean_args = re.sub(r'--(password|pass|secret|token|key|cred)=\S+', r'--\1=[REDACTED]', raw_args, flags=re.IGNORECASE)

                            pobs = ProcessObservation(
                                module_id=self.module_id,
                                pid=pid,
                                process_name=parts[1],
                                executable_path=f"/proc/{pid}/exe",
                                sanitized_args=clean_args
                            )
                            observations.append(pobs)

                            # Represent Process through Generic Asset Model (asset_type="process", asset_category="runtime")
                            process_asset_key = f"process:{parts[1]}:{pid}"
                            observations.append(AssetObservation(
                                module_id=self.module_id,
                                hostname=None,
                                asset_type="process",
                                asset_category="runtime",
                                identity_key=process_asset_key,
                                external_id=f"pid-{pid}"
                            ))

                            # Create relationship HOST -> CONTAINS -> PROCESS
                            observations.append(RelationshipObservation(
                                module_id=self.module_id,
                                source_type="Asset",
                                source_id_hint="host",
                                target_type="Asset",
                                target_id_hint=process_asset_key,
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
            logger.exception(f"ProcessModule execution failed: {e}")
            return ModuleResult(
                module_id=self.module_id,
                capability=self.capability,
                status=ModuleResultStatus.FAILED,
                error_message=str(e)
            )
