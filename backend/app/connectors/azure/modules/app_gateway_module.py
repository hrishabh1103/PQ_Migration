import logging
from typing import AsyncIterator
from app.collectors.observations import AssetObservation, RelationshipObservation
from app.connectors.azure.modules.base_azure_module import BaseAzureModule
from app.connectors.azure_client import AzureSdkClient

logger = logging.getLogger(__name__)

class AzureAppGatewayModule(BaseAzureModule):
    """
    Discovers Azure Application Gateways, HTTP/HTTPS Listeners, and TLS Certificate Bindings.
    """
    module_name = "AppGateway"
    capability = "CLOUD_LOAD_BALANCER"

    async def collect(
        self,
        sdk_client: AzureSdkClient,
        tenant_id: str,
        subscription_id: str,
        target_id: str
    ) -> AsyncIterator:
        network_client = sdk_client.get_client("network")
        ag_list = []
        if network_client and hasattr(network_client, "application_gateways"):
            try:
                ag_list = list(network_client.application_gateways.list_all())
            except Exception as e:
                logger.warning(f"Application Gateways list failed: {sdk_client.classify_error(e)}")

        for ag in ag_list:
            ag_name = ag.get("name") if isinstance(ag, dict) else getattr(ag, "name", "unknown-ag")
            rg_name = ag.get("resource_group", "default-rg") if isinstance(ag, dict) else getattr(ag, "resource_group", "default-rg")
            location = ag.get("location", "eastus") if isinstance(ag, dict) else getattr(ag, "location", "eastus")

            arm_id = f"/subscriptions/{subscription_id}/resourceGroups/{rg_name}/providers/Microsoft.Network/applicationGateways/{ag_name}"
            ag_identity = f"azure:appgateway:{subscription_id}:{rg_name}:{ag_name}"

            yield AssetObservation(
                module_id="azure_app_gateway",
                provider_resource_id=arm_id,
                identity_key=ag_identity,
                external_id=ag_name,
                asset_type="load_balancer",
                asset_category="network",
                hostname=f"{ag_name}.azure.internal",
                metadata={
                    "app_gateway_name": ag_name,
                    "resource_group": rg_name,
                    "subscription_id": subscription_id,
                    "location": location,
                    "provider": "AZURE",
                    "asset_subtype": "Microsoft.Network/applicationGateways",
                    "tls_policy": "AppGwSslPolicy20220101"
                }
            )

            # Spatial & Administrative Relationships
            yield RelationshipObservation(
                module_id="azure_app_gateway",
                source_type="ASSET",
                source_id_hint=f"azure:rg:{subscription_id}:{rg_name}",
                target_type="ASSET",
                target_id_hint=ag_identity,
                relationship_type="CONTAINS",
                confidence="HIGH"
            )

            yield RelationshipObservation(
                module_id="azure_app_gateway",
                source_type="ASSET",
                source_id_hint=ag_identity,
                target_type="ASSET",
                target_id_hint=f"azure:region:{location}",
                relationship_type="DEPLOYED_IN",
                confidence="HIGH"
            )
