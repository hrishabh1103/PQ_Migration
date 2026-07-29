from app.connectors.azure.modules.base_azure_module import BaseAzureModule
from app.connectors.azure.modules.azure_identity_module import AzureIdentityModule
from app.connectors.azure.modules.resource_group_module import AzureResourceGroupModule
from app.connectors.azure.modules.region_module import AzureRegionModule
from app.connectors.azure.modules.vm_module import AzureVMModule
from app.connectors.azure.modules.storage_module import AzureStorageModule
from app.connectors.azure.modules.key_vault_module import AzureKeyVaultModule
from app.connectors.azure.modules.app_gateway_module import AzureAppGatewayModule
from app.connectors.azure.modules.sql_database_module import AzureSqlModule
from app.connectors.azure.modules.front_door_module import AzureFrontDoorModule
from app.connectors.azure.modules.network_module import AzureNetworkModule

__all__ = [
    "BaseAzureModule",
    "AzureIdentityModule",
    "AzureResourceGroupModule",
    "AzureRegionModule",
    "AzureVMModule",
    "AzureStorageModule",
    "AzureKeyVaultModule",
    "AzureAppGatewayModule",
    "AzureSqlModule",
    "AzureFrontDoorModule",
    "AzureNetworkModule"
]
