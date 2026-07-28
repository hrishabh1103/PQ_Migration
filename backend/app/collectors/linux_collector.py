import logging
from typing import AsyncIterator, Set, List, Dict, Any
from app.scanners.plugins import Collector, PluginType, PluginCapability, PluginRegistry
from app.scanners.base import RawFinding, ScanContext
from app.models.entities import TargetType, AssetType, TransportProtocol, ApplicationProtocol, FindingType, FindingPurpose, FindingConfidence

from app.collectors.transport import LinuxTransport, LocalTransport
from app.collectors.observations import (
    DiscoveryObservation, AssetObservation, ServiceObservation, ProcessObservation,
    CryptoObservation, CertificateObservation, RelationshipObservation, CapabilityObservation
)
from app.collectors.modules.base_module import BaseCollectorModule, ModuleResult, ModuleResultStatus
from app.collectors.modules.host_module import HostModule
from app.collectors.modules.package_module import PackageModule
from app.collectors.modules.openssl_module import OpenSSLModule
from app.collectors.modules.openssh_module import OpenSSHModule
from app.collectors.modules.service_module import ServiceModule
from app.collectors.modules.process_module import ProcessModule
from app.collectors.modules.web_modules import NginxModule, ApacheModule
from app.collectors.modules.certificate_module import CertificateModule
from app.collectors.modules.java_module import JavaModule
from app.collectors.modules.keystore_module import KeystoreModule
from app.collectors.modules.pkcs11_module import PKCS11Module
from app.collectors.modules.crypto_policy_module import CryptoPolicyModule

logger = logging.getLogger(__name__)

class LinuxCollector(Collector):
    """
    Production-oriented Linux Host Collector plugin.
    Discovers cryptographic inventory from authorized Linux hosts using read-only metadata collection.
    """
    plugin_id = "linux-host"
    version = "1.0.0"
    plugin_type = PluginType.COLLECTOR
    supported_target_types = {TargetType.HOSTNAME, TargetType.IP_RANGE, TargetType.CLOUD_SERVER}
    capabilities = {
        PluginCapability.HOST_INVENTORY,
        PluginCapability.PROCESS_INVENTORY,
        PluginCapability.SERVICE_INVENTORY,
        PluginCapability.CRYPTO_LIBRARY,
        PluginCapability.CRYPTO_CONFIGURATION,
        PluginCapability.X509,
        PluginCapability.KEYSTORE,
        PluginCapability.SYSTEM_CRYPTO_POLICY
    }

    def __init__(self, transport: LinuxTransport = None):
        self.transport = transport or LocalTransport()
        self.modules: List[BaseCollectorModule] = [
            HostModule(),
            PackageModule(),
            OpenSSLModule(),
            OpenSSHModule(),
            ServiceModule(),
            ProcessModule(),
            NginxModule(),
            ApacheModule(),
            CertificateModule(),
            JavaModule(),
            KeystoreModule(),
            PKCS11Module(),
            CryptoPolicyModule()
        ]

    async def run_collection(self, transport: LinuxTransport = None) -> List[ModuleResult]:
        """
        Runs all 13 discovery modules with failure isolation.
        A module failure records its status without preventing other modules from executing.
        """
        t = transport or self.transport
        results = []
        for mod in self.modules:
            try:
                res = await mod.run(t)
                results.append(res)
            except Exception as e:
                logger.exception(f"Module {mod.module_id} failed unexpectedly: {e}")
                results.append(ModuleResult(
                    module_id=mod.module_id,
                    capability=mod.capability,
                    status=ModuleResultStatus.FAILED,
                    error_message=str(e),
                    observations=[]
                ))
        return results

    async def discover(
        self,
        target_value: str,
        target_type: TargetType,
        context: ScanContext
    ) -> AsyncIterator[RawFinding]:
        """
        Backward-compatible discovery generator producing RawFinding stream for the orchestrator.
        """
        module_results = await self.run_collection()
        host_hostname = target_value

        for res in module_results:
            for obs in res.observations:
                if isinstance(obs, AssetObservation) and obs.hostname:
                    host_hostname = obs.hostname

                elif isinstance(obs, CryptoObservation):
                    yield RawFinding(
                        asset_hostname=host_hostname,
                        asset_ip="127.0.0.1",
                        asset_type=AssetType.SERVER,
                        environment="PRODUCTION",
                        operating_system="Linux",
                        port=None,
                        transport_protocol=TransportProtocol.NONE,
                        application_protocol=ApplicationProtocol.UNKNOWN,
                        service_name=obs.canonical_name,
                        finding_type=FindingType.LIBRARY_DEPENDENCY,
                        raw_algorithm_name=obs.canonical_name,
                        purpose=FindingPurpose.UNKNOWN,
                        location_identifier=f"linux-host://{obs.identity_key}",
                        evidence_snippet=f"Object: {obs.canonical_name}, Provider: {obs.provider or 'N/A'}, Version: {obs.version or 'N/A'}",
                        confidence=FindingConfidence.HIGH,
                        metadata=obs.metadata
                    )

                elif isinstance(obs, CertificateObservation):
                    yield RawFinding(
                        asset_hostname=host_hostname,
                        asset_ip="127.0.0.1",
                        asset_type=AssetType.SERVER,
                        environment="PRODUCTION",
                        operating_system="Linux",
                        port=443,
                        transport_protocol=TransportProtocol.TCP,
                        application_protocol=ApplicationProtocol.HTTPS,
                        service_name="x509-certificate",
                        finding_type=FindingType.CERTIFICATE_PUBLIC_KEY,
                        raw_algorithm_name=f"{obs.pubkey_algo}-{obs.pubkey_size or 2048}",
                        key_size=obs.pubkey_size,
                        purpose=FindingPurpose.AUTHENTICATION,
                        location_identifier=f"cert-store://sha256:{obs.fingerprint}",
                        evidence_snippet=f"Subject: {obs.subject}, Issuer: {obs.issuer}, Signature: {obs.signature_algo}",
                        confidence=FindingConfidence.HIGH,
                        metadata={
                            "fingerprint": obs.fingerprint,
                            "serial_number": obs.serial_number,
                            "san_list": obs.san_list
                        }
                    )

# Register plugin
PluginRegistry.register(LinuxCollector())
