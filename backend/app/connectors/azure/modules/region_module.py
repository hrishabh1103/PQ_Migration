import logging
from typing import AsyncIterator
from app.collectors.observations import AssetObservation, RelationshipObservation
from app.connectors.azure.modules.base_azure_module import BaseAzureModule
from app.connectors.azure_client import AzureSdkClient

logger = logging.getLogger(__name__)

class AzureRegionModule(BaseAzureModule):
    """
    Discovers Azure spatial regions and yields canonical CLOUD_REGION assets.
    """
    module_name = "Region"
    capability = "CLOUD_RESOURCE"

    async def collect(
        self,
        sdk_client: AzureSdkClient,
        tenant_id: str,
        subscription_id: str,
        target_id: str
    ) -> AsyncIterator:
        regions = ["eastus", "westus", "westeurope", "southeastasia"]

        for region in regions:
            reg_identity = f"azure:region:{region}"
            yield AssetObservation(
                module_id="azure_region",
                provider_resource_id=f"/subscriptions/{subscription_id}/locations/{region}",
                identity_key=reg_identity,
                external_id=region,
                asset_type="cloud_region",
                asset_category="cloud",
                hostname=f"azure-region-{region}",
                metadata={
                    "region_name": region,
                    "provider": "AZURE"
                }
            )

            # Spatial containment: Subscription -> CONTAINS -> Region
            yield RelationshipObservation(
                module_id="azure_region",
                source_type="ASSET",
                source_id_hint=f"azure:subscription:{subscription_id}",
                target_type="ASSET",
                target_id_hint=reg_identity,
                relationship_type="CONTAINS",
                confidence="HIGH"
            )
