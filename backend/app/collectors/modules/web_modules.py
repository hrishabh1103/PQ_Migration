import re
import logging
from app.collectors.transport import LinuxTransport
from app.collectors.modules.base_module import BaseCollectorModule, ModuleResult, ModuleResultStatus
from app.collectors.observations import ServiceObservation, CryptoObservation, CapabilityObservation, RelationshipObservation, CapabilityState

logger = logging.getLogger(__name__)

class NginxModule(BaseCollectorModule):
    module_id = "nginx_tls"
    capability = "CRYPTO_CONFIGURATION"

    async def run(self, transport: LinuxTransport) -> ModuleResult:
        observations = []
        try:
            # Check if nginx exists or is running
            code, stdout_v, _ = await transport.run_command(["nginx", "-v"])
            if code != 0 and not await transport.file_exists("/etc/nginx/nginx.conf"):
                return ModuleResult(
                    module_id=self.module_id,
                    capability=self.capability,
                    status=ModuleResultStatus.NOT_APPLICABLE,
                    observations=[]
                )

            # Inspect /etc/nginx/nginx.conf or /etc/nginx/sites-enabled/
            conf_content = await transport.read_file("/etc/nginx/nginx.conf")
            if not conf_content:
                conf_content = ""

            # Extract ssl_protocols, ssl_ciphers, ssl_certificate without storing full file
            protocols = re.findall(r"ssl_protocols\s+([^;]+);", conf_content)
            ciphers = re.findall(r"ssl_ciphers\s+([^;]+);", conf_content)
            cert_paths = re.findall(r"ssl_certificate\s+([^;]+);", conf_content)

            has_tls13 = any("TLSv1.3" in p for p in protocols)
            has_pqc_group = any("X25519MLKEM768" in c or "mlkem" in c.lower() for c in ciphers)

            # Register Nginx CryptoObservation
            cobs = CryptoObservation(
                module_id=self.module_id,
                canonical_name="Nginx Web Server",
                object_type="LIBRARY",
                provider="F5 / Nginx",
                version="Observed Configured",
                identity_key="crypto:nginx:tls",
                capability_state=CapabilityState.CONFIGURED
            )
            observations.append(cobs)

            # Register CapabilityObservation
            observations.append(CapabilityObservation(
                module_id=self.module_id,
                capability_name="NGINX_TLS_CONFIG",
                capability_state=CapabilityState.CONFIGURED,
                algorithm_name="Nginx TLS Policy",
                details={
                    "ssl_protocols": protocols,
                    "ssl_ciphers": ciphers,
                    "certificate_paths": cert_paths,
                    "tls13_enabled": has_tls13,
                    "pqc_hybrid_configured": has_pqc_group
                }
            ))

            # Create Relationships
            observations.append(RelationshipObservation(
                module_id=self.module_id,
                source_type="Asset",
                source_id_hint="host",
                target_type="CryptoObject",
                target_id_hint=cobs.identity_key,
                relationship_type="CONTAINS"
            ))

            return ModuleResult(
                module_id=self.module_id,
                capability=self.capability,
                status=ModuleResultStatus.SUCCESS,
                observations=observations
            )

        except Exception as e:
            logger.exception(f"NginxModule execution failed: {e}")
            return ModuleResult(
                module_id=self.module_id,
                capability=self.capability,
                status=ModuleResultStatus.PARTIAL,
                error_message=str(e),
                observations=observations
            )


class ApacheModule(BaseCollectorModule):
    module_id = "apache_tls"
    capability = "CRYPTO_CONFIGURATION"

    async def run(self, transport: LinuxTransport) -> ModuleResult:
        observations = []
        try:
            # Check if apache2 / httpd exists
            if not await transport.file_exists("/etc/httpd/conf/httpd.conf") and not await transport.file_exists("/etc/apache2/apache2.conf"):
                return ModuleResult(
                    module_id=self.module_id,
                    capability=self.capability,
                    status=ModuleResultStatus.NOT_APPLICABLE,
                    observations=[]
                )

            conf_content = await transport.read_file("/etc/httpd/conf/httpd.conf") or await transport.read_file("/etc/apache2/apache2.conf") or ""

            protocols = re.findall(r"SSLProtocol\s+([^;\n]+)", conf_content)
            ciphers = re.findall(r"SSLCipherSuite\s+([^;\n]+)", conf_content)

            cobs = CryptoObservation(
                module_id=self.module_id,
                canonical_name="Apache HTTP Server",
                object_type="LIBRARY",
                provider="Apache Software Foundation",
                version="Observed Configured",
                identity_key="crypto:apache:tls",
                capability_state=CapabilityState.CONFIGURED
            )
            observations.append(cobs)

            observations.append(CapabilityObservation(
                module_id=self.module_id,
                capability_name="APACHE_TLS_CONFIG",
                capability_state=CapabilityState.CONFIGURED,
                algorithm_name="Apache SSL Policy",
                details={"ssl_protocols": protocols, "ssl_ciphers": ciphers}
            ))

            return ModuleResult(
                module_id=self.module_id,
                capability=self.capability,
                status=ModuleResultStatus.SUCCESS,
                observations=observations
            )

        except Exception as e:
            logger.exception(f"ApacheModule execution failed: {e}")
            return ModuleResult(
                module_id=self.module_id,
                capability=self.capability,
                status=ModuleResultStatus.PARTIAL,
                error_message=str(e),
                observations=observations
            )
