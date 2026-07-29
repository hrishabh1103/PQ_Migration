import logging
from typing import AsyncIterator, Set, Dict, Any, Optional, List

from app.models.entities import TargetType
from app.scanners.base import ScanContext, RawFinding
from app.scanners.plugins import Connector, PluginType, PluginCapability, PluginRegistry
from app.collectors.observations import DiscoveryObservation
from app.connectors.azure_client import AzureSdkClient
from app.connectors.azure.modules import (
    BaseAzureModule,
    AzureIdentityModule,
    AzureResourceGroupModule,
    AzureRegionModule,
    AzureVMModule,
    AzureStorageModule,
    AzureKeyVaultModule,
    AzureAppGatewayModule,
    AzureSqlModule,
    AzureFrontDoorModule,
    AzureNetworkModule
)

logger = logging.getLogger(__name__)

class AzureConnector(Connector):
    """
    Enterprise Azure Cryptographic Discovery Connector plugin performing read-only
    discovery across Azure Tenants, Subscriptions, Resource Groups, VMs, Disks,
    Storage Accounts, Key Vaults, App Gateways, Azure SQL, and Front Door endpoints.
    """
    plugin_id = "azure"
    version = "1.0.0"
    plugin_type = PluginType.CONNECTOR
    supported_target_types: Set[TargetType] = {
        TargetType.CLOUD_PROVIDER,
        TargetType.CLOUD_SERVER,
        TargetType.CLOUD_KMS
    }
    capabilities: Set[PluginCapability] = {
        PluginCapability.CLOUD_RESOURCE,
        PluginCapability.CLOUD_COMPUTE,
        PluginCapability.CLOUD_STORAGE,
        PluginCapability.CLOUD_DATABASE,
        PluginCapability.CLOUD_LOAD_BALANCER,
        PluginCapability.CLOUD_CDN,
        PluginCapability.CLOUD_IDENTITY,
        PluginCapability.CLOUD_NETWORK,
        PluginCapability.KMS,
        PluginCapability.CERTIFICATE,
        PluginCapability.ENCRYPTION_CONFIGURATION,
        PluginCapability.TLS_CONFIGURATION
    }

    def __init__(self):
        self.modules: List[BaseAzureModule] = [
            AzureIdentityModule(),
            AzureResourceGroupModule(),
            AzureRegionModule(),
            AzureVMModule(),
            AzureStorageModule(),
            AzureKeyVaultModule(),
            AzureAppGatewayModule(),
            AzureSqlModule(),
            AzureFrontDoorModule(),
            AzureNetworkModule()
        ]

    async def discover(
        self,
        target_value: str,
        target_type: TargetType,
        context: ScanContext
    ) -> AsyncIterator[RawFinding]:
        """
        Legacy discover compatibility wrapper yielding RawFinding stream.
        """
        async for obs in self.collect(target_value, target_type, context):
            yield RawFinding(
                scanner_id=self.plugin_id,
                scanner_version=self.version,
                raw_algorithm_name=getattr(obs, "raw_algorithm_name", "AZURE_RESOURCE"),
                finding_type=getattr(obs, "finding_type", "CLOUD_RESOURCE"),
                location_identifier=getattr(obs, "provider_resource_id", target_value),
                evidence_snippet=f"AzureConnector observation: {obs.__class__.__name__}",
                confidence=getattr(obs, "confidence", "HIGH"),
                metadata_json=getattr(obs, "metadata_json", {})
            )

    async def collect(
        self,
        target_value: str,
        target_type: TargetType,
        context: ScanContext,
        allowed_regions: Optional[List[str]] = None,
        profile_name: Optional[str] = None,
        role_arn: Optional[str] = None,
        **kwargs
    ) -> AsyncIterator[DiscoveryObservation]:
        """
        Primary entry point performing Azure read-only discovery sync across authorized subscriptions.
        Yields structured DiscoveryObservation items with module-level failure isolation.
        """
        logger.info(f"Starting AzureConnector sync for target '{target_value}'...")

        # Parse subscription and tenant IDs if passed in target_value or context
        sub_id = "00000000-0000-0000-0000-000000000000"
        tenant_id = "00000000-0000-0000-0000-000000000000"
        if "subscriptions/" in target_value:
            parts = target_value.split("subscriptions/")
            if len(parts) > 1:
                sub_id = parts[1].split("/")[0]

        sdk_client = AzureSdkClient(subscription_id=sub_id, tenant_id=tenant_id)
        target_id = getattr(context, "target_id", "azure-target-1")

        # Execute discovery modules with failure isolation per module
        for mod in self.modules:
            try:
                async for obs in mod.collect(sdk_client, tenant_id, sub_id, target_id):
                    yield obs
            except Exception as e:
                logger.error(f"Azure module '{mod.module_name}' failed: {sdk_client.classify_error(e)}")

# Auto-register plugin
PluginRegistry.register(AzureConnector)
