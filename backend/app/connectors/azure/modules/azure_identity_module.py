import logging
from typing import AsyncIterator
from app.collectors.observations import AssetObservation
from app.connectors.azure.modules.base_azure_module import BaseAzureModule
from app.connectors.azure_client import AzureSdkClient

logger = logging.getLogger(__name__)

class AzureIdentityModule(BaseAzureModule):
    """
    Validates Azure tenant and subscription identity and yields canonical CLOUD_TENANT and CLOUD_SUBSCRIPTION Assets.
    """
    module_name = "Identity"
    capability = "CLOUD_IDENTITY"

    async def collect(
        self,
        sdk_client: AzureSdkClient,
        tenant_id: str,
        subscription_id: str,
        target_id: str
    ) -> AsyncIterator:
        val = sdk_client.validate_identity()
        t_id = val.get("tenant_id", tenant_id)
        s_id = val.get("subscription_id", subscription_id)

        # 1. Canonical Azure Tenant Asset
        tenant_asset = AssetObservation(
            module_id="azure_identity",
            provider_resource_id=f"/tenants/{t_id}",
            identity_key=f"azure:tenant:{t_id}",
            external_id=t_id,
            asset_type="cloud_tenant",
            asset_category="cloud",
            hostname=f"azure-tenant-{t_id[:8]}",
            metadata={
                "tenant_id": t_id,
                "provider": "AZURE",
                "validated": val.get("validated", False)
            }
        )
        yield tenant_asset

        # 2. Canonical Azure Subscription Asset
        sub_asset = AssetObservation(
            module_id="azure_identity",
            provider_resource_id=f"/subscriptions/{s_id}",
            identity_key=f"azure:subscription:{s_id}",
            external_id=s_id,
            asset_type="cloud_subscription",
            asset_category="cloud",
            hostname=f"azure-sub-{s_id[:8]}",
            metadata={
                "tenant_id": t_id,
                "subscription_id": s_id,
                "provider": "AZURE",
                "display_name": val.get("display_name", f"Subscription {s_id}")
            }
        )
        yield sub_asset
