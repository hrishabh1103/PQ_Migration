import re
import logging
from app.collectors.transport import LinuxTransport
from app.collectors.modules.base_module import BaseCollectorModule, ModuleResult, ModuleResultStatus
from app.collectors.observations import AssetObservation

logger = logging.getLogger(__name__)

class HostModule(BaseCollectorModule):
    module_id = "host_info"
    capability = "HOST_INVENTORY"

    async def run(self, transport: LinuxTransport) -> ModuleResult:
        try:
            # 1. Hostname & FQDN
            code, stdout_host, _ = await transport.run_command(["hostname", "-f"])
            fqdn = stdout_host.strip() if code == 0 and stdout_host.strip() else None

            code, stdout_h, _ = await transport.run_command(["hostname"])
            hostname = stdout_h.strip() if code == 0 and stdout_h.strip() else "linux-host"

            # 2. Kernel & Architecture
            code, stdout_k, _ = await transport.run_command(["uname", "-r"])
            kernel = stdout_k.strip() if code == 0 else None

            code, stdout_a, _ = await transport.run_command(["uname", "-m"])
            arch = stdout_a.strip() if code == 0 else None

            # 3. OS Distribution from /etc/os-release
            os_distro = "Linux"
            os_ver = "Unknown"
            os_rel_content = await transport.read_file("/etc/os-release")
            if os_rel_content:
                name_match = re.search(r'^NAME=["\']?(.*?)["\']?$', os_rel_content, re.MULTILINE)
                ver_match = re.search(r'^VERSION_ID=["\']?(.*?)["\']?$', os_rel_content, re.MULTILINE)
                if name_match:
                    os_distro = name_match.group(1)
                if ver_match:
                    os_ver = ver_match.group(1)

            asset_obs = AssetObservation(
                module_id=self.module_id,
                hostname=hostname,
                fqdn=fqdn,
                ip_address=None,
                os_distribution=os_distro,
                os_version=os_ver,
                kernel_version=kernel,
                architecture=arch,
                asset_type="HOST",
                asset_category="INFRASTRUCTURE",
                identity_key=f"host:{fqdn or hostname}"
            )

            return ModuleResult(
                module_id=self.module_id,
                capability=self.capability,
                status=ModuleResultStatus.SUCCESS,
                observations=[asset_obs]
            )

        except Exception as e:
            logger.exception(f"HostModule execution failed: {e}")
            return ModuleResult(
                module_id=self.module_id,
                capability=self.capability,
                status=ModuleResultStatus.FAILED,
                error_message=str(e)
            )
