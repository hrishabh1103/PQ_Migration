import logging
from typing import AsyncIterator
from app.collectors.observations import AssetObservation, RelationshipObservation
from app.connectors.azure.modules.base_azure_module import BaseAzureModule
from app.connectors.azure_client import AzureSdkClient

logger = logging.getLogger(__name__)

class AzureStorageModule(BaseAzureModule):
    """
    Discovers Azure Storage Accounts and Blob Encryption settings, recording
    Platform-Managed Encryption vs Customer-Managed Key Vault encryption references.
    """
    module_name = "Storage"
    capability = "CLOUD_STORAGE"

    async def collect(
        self,
        sdk_client: AzureSdkClient,
        tenant_id: str,
        subscription_id: str,
        target_id: str
    ) -> AsyncIterator:
        storage_client = sdk_client.get_client("storage")
        accounts = []
        if storage_client and hasattr(storage_client, "storage_accounts"):
            try:
                accounts = list(storage_client.storage_accounts.list())
            except Exception as e:
                logger.warning(f"Storage accounts list failed: {sdk_client.classify_error(e)}")

        for sa in accounts:
            sa_name = sa.get("name") if isinstance(sa, dict) else getattr(sa, "name", "unknownstorage")
            rg_name = sa.get("resource_group", "default-rg") if isinstance(sa, dict) else getattr(sa, "resource_group", "default-rg")
            location = sa.get("location", "eastus") if isinstance(sa, dict) else getattr(sa, "location", "eastus")

            arm_id = f"/subscriptions/{subscription_id}/resourceGroups/{rg_name}/providers/Microsoft.Storage/storageAccounts/{sa_name}"
            sa_identity = f"azure:storage:{subscription_id}:{rg_name}:{sa_name}"

            encryption = sa.get("encryption", {}) if isinstance(sa, dict) else getattr(sa, "encryption", {})
            key_vault_props = encryption.get("key_vault_properties") if isinstance(encryption, dict) else getattr(encryption, "key_vault_properties", None)
            cmk_key_uri = key_vault_props.get("key_uri") if isinstance(key_vault_props, dict) else (getattr(key_vault_props, "key_uri", None) if key_vault_props else None)

            meta = {
                "storage_account_name": sa_name,
                "resource_group": rg_name,
                "subscription_id": subscription_id,
                "location": location,
                "provider": "AZURE",
                "asset_subtype": "Microsoft.Storage/storageAccounts",
                "encryption_type": "CUSTOMER_MANAGED_KEY" if cmk_key_uri else "PLATFORM_MANAGED_ENCRYPTION",
                "blob_sse_enabled": True
            }

            yield AssetObservation(
                module_id="azure_storage",
                provider_resource_id=arm_id,
                identity_key=sa_identity,
                external_id=sa_name,
                asset_type="object_storage",
                asset_category="storage",
                hostname=f"{sa_name}.blob.core.windows.net",
                metadata=meta
            )

            # Spatial & Administrative Relationships
            yield RelationshipObservation(
                module_id="azure_storage",
                source_type="ASSET",
                source_id_hint=f"azure:rg:{subscription_id}:{rg_name}",
                target_type="ASSET",
                target_id_hint=sa_identity,
                relationship_type="CONTAINS",
                confidence="HIGH"
            )

            yield RelationshipObservation(
                module_id="azure_storage",
                source_type="ASSET",
                source_id_hint=sa_identity,
                target_type="ASSET",
                target_id_hint=f"azure:region:{location}",
                relationship_type="DEPLOYED_IN",
                confidence="HIGH"
            )

            # Emits ENCRYPTED_BY only if customer-managed key reference is present
            if cmk_key_uri:
                key_parts = cmk_key_uri.split("/")
                if len(key_parts) >= 5:
                    vault_name = key_parts[2].split(".")[0]
                    key_name = key_parts[4]
                    version_id = key_parts[5] if len(key_parts) > 5 else None

                    if version_id:
                        target_key_id = f"azure:kms:key_version:{subscription_id}:{rg_name}:{vault_name}:{key_name}:{version_id}"
                    else:
                        target_key_id = f"azure:kms:key:{subscription_id}:{rg_name}:{vault_name}:{key_name}"

                    yield RelationshipObservation(
                        module_id="azure_storage",
                        source_type="ASSET",
                        source_id_hint=sa_identity,
                        target_type="ASSET",
                        target_id_hint=target_key_id,
                        relationship_type="ENCRYPTED_BY",
                        confidence="HIGH"
                    )
