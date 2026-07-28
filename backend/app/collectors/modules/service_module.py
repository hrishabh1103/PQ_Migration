import re
import logging
from app.collectors.transport import LinuxTransport
from app.collectors.modules.base_module import BaseCollectorModule, ModuleResult, ModuleResultStatus
from app.collectors.observations import ServiceObservation

logger = logging.getLogger(__name__)

class ServiceModule(BaseCollectorModule):
    module_id = "listening_services"
    capability = "SERVICE_INVENTORY"

    async def run(self, transport: LinuxTransport) -> ModuleResult:
        observations = []
        try:
            # Run ss -tulpn or netstat -tulpn
            code, stdout, _ = await transport.run_command(["ss", "-tulpn"])
            if code != 0 or not stdout:
                code, stdout, _ = await transport.run_command(["netstat", "-tulpn"])

            if code == 0 and stdout:
                for line in stdout.splitlines():
                    if "LISTEN" not in line and "udp" not in line.lower():
                        continue

                    parts = line.split()
                    if len(parts) >= 4:
                        # Extract protocol (tcp/udp)
                        proto = "TCP" if "tcp" in parts[0].lower() else "UDP"
                        
                        # Extract local address and port
                        addr_part = parts[4] if len(parts) > 4 else parts[3]
                        if ":" in addr_part:
                            port_str = addr_part.rsplit(":", 1)[-1]
                            if port_str.isdigit():
                                port = int(port_str)
                                
                                # Infer app protocol & service name
                                app_proto = "HTTPS" if port == 443 else ("SSH" if port == 22 else "HTTP" if port == 80 else "UNKNOWN")
                                svc_name = "https" if port == 443 else ("ssh" if port == 22 else ("http" if port == 80 else f"port-{port}"))

                                # Parse pid/process if present in ss output
                                pid = None
                                pname = None
                                pid_match = re.search(r'users:\(\("([^"]+)",pid=(\d+)', line)
                                if pid_match:
                                    pname = pid_match.group(1)
                                    pid = int(pid_match.group(2))

                                observations.append(ServiceObservation(
                                    module_id=self.module_id,
                                    port=port,
                                    transport_protocol=proto,
                                    application_protocol=app_proto,
                                    service_name=svc_name,
                                    process_pid=pid,
                                    process_name=pname
                                ))

            status = ModuleResultStatus.SUCCESS if observations else ModuleResultStatus.NOT_APPLICABLE
            return ModuleResult(
                module_id=self.module_id,
                capability=self.capability,
                status=status,
                observations=observations
            )

        except Exception as e:
            logger.exception(f"ServiceModule execution failed: {e}")
            return ModuleResult(
                module_id=self.module_id,
                capability=self.capability,
                status=ModuleResultStatus.FAILED,
                error_message=str(e)
            )
