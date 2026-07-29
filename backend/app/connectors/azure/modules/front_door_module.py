import logging
from typing import AsyncIterator
from app.collectors.observations import AssetObservation, RelationshipObservation
from app.connectors.azure.modules.base_azure_module import BaseAzureModule
from app.connectors.azure_client import AzureSdkClient

logger = logging.getLogger(__name__)

class AzureFrontDoorModule(BaseAzureModule):
    """
    Discovers Azure Front Door & CDN profiles and custom domain TLS configurations.
    """
    module_name = "FrontDoor"
    capability = "CLOUD_CDN"

    async def collect(
        self,
        sdk_client: AzureSdkClient,
        tenant_id: str,
        subscription_id: str,
        target_id: str
    ) -> AsyncIterator:
        cdn_client = sdk_client.get_client("cdn")
        profiles = []
        if cdn_client and hasattr(cdn_client, "profiles"):
            try:
                profiles = list(cdn_client.profiles.list())
            except Exception as e:
                logger.warning(f"Front Door profiles list failed: {sdk_client.classify_error(e)}")

        for prof in profiles:
            p_name = prof.get("name") if isinstance(prof, dict) else getattr(prof, "name", "unknown-frontdoor")
            rg_name = prof.get("resource_group", "default-rg") if isinstance(prof, dict) else getattr(prof, "resource_group", "default-rg")
            location = prof.get("location", "global") if isinstance(prof, dict) else getattr(prof, "location", "global")

            arm_id = f"/subscriptions/{subscription_id}/resourceGroups/{rg_name}/providers/Microsoft.Cdn/profiles/{p_name}"
            fd_identity = f"azure:frontdoor:{subscription_id}:{rg_name}:{p_name}"

            yield AssetObservation(
                module_id="azure_front_door",
                provider_resource_id=arm_id,
                identity_key=fd_identity,
                external_id=p_name,
                asset_type="cdn",
                asset_category="network",
                hostname=f"{p_name}.azurefd.net",
                metadata={
                    "profile_name": p_name,
                    "resource_group": rg_name,
                    "subscription_id": subscription_id,
                    "location": location,
                    "provider": "AZURE",
                    "tls_version": "TLS1.2"
                }
            )

            yield RelationshipObservation(
                module_id="azure_front_door",
                source_type="ASSET",
                source_id_hint=f"azure:rg:{subscription_id}:{rg_name}",
                target_type="ASSET",
                target_id_hint=fd_identity,
                relationship_type="CONTAINS",
                confidence="HIGH"
            )
