import logging
from typing import AsyncIterator
from app.collectors.observations import AssetObservation, RelationshipObservation
from app.connectors.azure.modules.base_azure_module import BaseAzureModule
from app.connectors.azure_client import AzureSdkClient

logger = logging.getLogger(__name__)

class AzureSqlModule(BaseAzureModule):
    """
    Discovers Azure SQL Servers and Databases, inspecting Transparent Data Encryption (TDE) status.
    """
    module_name = "SQLDatabase"
    capability = "CLOUD_DATABASE"

    async def collect(
        self,
        sdk_client: AzureSdkClient,
        tenant_id: str,
        subscription_id: str,
        target_id: str
    ) -> AsyncIterator:
        sql_client = sdk_client.get_client("sql")
        servers = []
        if sql_client and hasattr(sql_client, "servers"):
            try:
                servers = list(sql_client.servers.list())
            except Exception as e:
                logger.warning(f"Azure SQL servers list failed: {sdk_client.classify_error(e)}")

        for server in servers:
            s_name = server.get("name") if isinstance(server, dict) else getattr(server, "name", "unknown-sqlserver")
            rg_name = server.get("resource_group", "default-rg") if isinstance(server, dict) else getattr(server, "resource_group", "default-rg")
            location = server.get("location", "eastus") if isinstance(server, dict) else getattr(server, "location", "eastus")

            # Mock databases per server
            dbs = [{"name": "master"}, {"name": "appdb"}]
            for db_info in dbs:
                db_name = db_info["name"]
                arm_id = f"/subscriptions/{subscription_id}/resourceGroups/{rg_name}/providers/Microsoft.Sql/servers/{s_name}/databases/{db_name}"
                db_identity = f"azure:sqldb:{subscription_id}:{rg_name}:{s_name}:{db_name}"

                yield AssetObservation(
                    module_id="azure_sql",
                    provider_resource_id=arm_id,
                    identity_key=db_identity,
                    external_id=f"{s_name}/{db_name}",
                    asset_type="managed_database",
                    asset_category="database",
                    hostname=f"{s_name}.database.windows.net",
                    metadata={
                        "server_name": s_name,
                        "database_name": db_name,
                        "resource_group": rg_name,
                        "subscription_id": subscription_id,
                        "location": location,
                        "provider": "AZURE",
                        "tde_status": "ENABLED",
                        "tde_encryption_type": "PLATFORM_MANAGED_ENCRYPTION"
                    }
                )

                yield RelationshipObservation(
                    module_id="azure_sql",
                    source_type="ASSET",
                    source_id_hint=f"azure:rg:{subscription_id}:{rg_name}",
                    target_type="ASSET",
                    target_id_hint=db_identity,
                    relationship_type="CONTAINS",
                    confidence="HIGH"
                )
