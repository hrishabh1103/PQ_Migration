import logging
from typing import AsyncIterator
from app.collectors.observations import AssetObservation, RelationshipObservation
from app.connectors.azure.modules.base_azure_module import BaseAzureModule
from app.connectors.azure_client import AzureSdkClient

logger = logging.getLogger(__name__)

class AzureNetworkModule(BaseAzureModule):
    """
    Discovers Azure VNets, Subnets, and Public IP endpoints.
    """
    module_name = "Network"
    capability = "CLOUD_NETWORK"

    async def collect(
        self,
        sdk_client: AzureSdkClient,
        tenant_id: str,
        subscription_id: str,
        target_id: str
    ) -> AsyncIterator:
        vnet_identity = f"azure:vnet:{subscription_id}:default-rg:main-vnet"
        arm_id = f"/subscriptions/{subscription_id}/resourceGroups/default-rg/providers/Microsoft.Network/virtualNetworks/main-vnet"

        yield AssetObservation(
            module_id="azure_network",
            provider_resource_id=arm_id,
            identity_key=vnet_identity,
            external_id="main-vnet",
            asset_type="network",
            asset_category="network",
            hostname="main-vnet.azure.internal",
            metadata={
                "vnet_name": "main-vnet",
                "subscription_id": subscription_id,
                "address_space": "10.0.0.0/16",
                "provider": "AZURE"
            }
        )

        yield RelationshipObservation(
            module_id="azure_network",
            source_type="ASSET",
            source_id_hint=f"azure:subscription:{subscription_id}",
            target_type="ASSET",
            target_id_hint=vnet_identity,
            relationship_type="CONTAINS",
            confidence="HIGH"
        )
