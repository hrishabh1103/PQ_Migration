import logging
from typing import AsyncIterator
from app.collectors.observations import AssetObservation, RelationshipObservation
from app.connectors.azure.modules.base_azure_module import BaseAzureModule
from app.connectors.azure_client import AzureSdkClient

logger = logging.getLogger(__name__)

class AzureVMModule(BaseAzureModule):
    """
    Discovers Azure Virtual Machines and Managed Disks, capturing spatial deployment,
    storage dependencies, and customer-managed key encryption references.
    """
    module_name = "VM"
    capability = "CLOUD_COMPUTE"

    async def collect(
        self,
        sdk_client: AzureSdkClient,
        tenant_id: str,
        subscription_id: str,
        target_id: str
    ) -> AsyncIterator:
        compute_client = sdk_client.get_client("compute")
        vms = []
        if compute_client and hasattr(compute_client, "virtual_machines"):
            try:
                vms = list(compute_client.virtual_machines.list_all())
            except Exception as e:
                logger.warning(f"Azure VM list_all failed: {sdk_client.classify_error(e)}")

        for vm in vms:
            vm_name = vm.get("name") if isinstance(vm, dict) else getattr(vm, "name", "unknown-vm")
            rg_name = vm.get("resource_group", "default-rg") if isinstance(vm, dict) else getattr(vm, "resource_group", "default-rg")
            location = vm.get("location", "eastus") if isinstance(vm, dict) else getattr(vm, "location", "eastus")
            vm_id = vm.get("vm_id") if isinstance(vm, dict) else getattr(vm, "vm_id", f"vm-id-{vm_name}")

            arm_id = f"/subscriptions/{subscription_id}/resourceGroups/{rg_name}/providers/Microsoft.Compute/virtualMachines/{vm_name}"
            vm_identity = f"azure:vm:{subscription_id}:{rg_name}:{vm_name}"

            # 1. VM Asset Observation
            yield AssetObservation(
                module_id="azure_vm",
                provider_resource_id=arm_id,
                identity_key=vm_identity,
                external_id=vm_id,
                asset_type="compute_instance",
                asset_category="compute",
                hostname=f"{vm_name}.azure.internal",
                operating_system=vm.get("os", "Linux") if isinstance(vm, dict) else "Linux",
                metadata={
                    "vm_name": vm_name,
                    "vm_id": vm_id,
                    "compute_instance_id": vm_id,
                    "resource_group": rg_name,
                    "subscription_id": subscription_id,
                    "location": location,
                    "provider": "AZURE",
                    "asset_subtype": "Microsoft.Compute/virtualMachines"
                }
            )

            # Spatial & Administrative Relationships
            yield RelationshipObservation(
                module_id="azure_vm",
                source_type="ASSET",
                source_id_hint=f"azure:rg:{subscription_id}:{rg_name}",
                target_type="ASSET",
                target_id_hint=vm_identity,
                relationship_type="CONTAINS",
                confidence="HIGH"
            )

            yield RelationshipObservation(
                module_id="azure_vm",
                source_type="ASSET",
                source_id_hint=vm_identity,
                target_type="ASSET",
                target_id_hint=f"azure:region:{location}",
                relationship_type="DEPLOYED_IN",
                confidence="HIGH"
            )

            # 2. OS & Data Disks (BLOCK_STORAGE)
            storage_profile = vm.get("storage_profile", {}) if isinstance(vm, dict) else getattr(vm, "storage_profile", {})
            os_disk = storage_profile.get("os_disk", {}) if isinstance(storage_profile, dict) else getattr(storage_profile, "os_disk", {})
            if os_disk:
                disk_name = os_disk.get("name", f"{vm_name}-osdisk") if isinstance(os_disk, dict) else getattr(os_disk, "name", f"{vm_name}-osdisk")
                disk_arm = f"/subscriptions/{subscription_id}/resourceGroups/{rg_name}/providers/Microsoft.Compute/disks/{disk_name}"
                disk_identity = f"azure:disk:{subscription_id}:{rg_name}:{disk_name}"

                encryption_settings = os_disk.get("encryption_settings") if isinstance(os_disk, dict) else getattr(os_disk, "encryption_settings", None)
                cmk_key_uri = None
                if isinstance(encryption_settings, dict):
                    cmk_key_uri = encryption_settings.get("disk_encryption_key", {}).get("secret_url")

                disk_meta = {
                    "disk_name": disk_name,
                    "resource_group": rg_name,
                    "subscription_id": subscription_id,
                    "provider": "AZURE",
                    "asset_subtype": "Microsoft.Compute/disks",
                    "encryption_type": "CUSTOMER_MANAGED_KEY" if cmk_key_uri else "PLATFORM_MANAGED_ENCRYPTION"
                }

                yield AssetObservation(
                    module_id="azure_vm",
                    provider_resource_id=disk_arm,
                    identity_key=disk_identity,
                    external_id=disk_name,
                    asset_type="block_storage",
                    asset_category="storage",
                    hostname=f"azure-disk-{disk_name}",
                    metadata=disk_meta
                )

                # Storage relationship: VM -> USES_STORAGE -> Disk
                yield RelationshipObservation(
                    module_id="azure_vm",
                    source_type="ASSET",
                    source_id_hint=vm_identity,
                    target_type="ASSET",
                    target_id_hint=disk_identity,
                    relationship_type="USES_STORAGE",
                    confidence="HIGH"
                )

                # Only emit ENCRYPTED_BY if a real Customer-Managed Key reference exists
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
                            module_id="azure_vm",
                            source_type="ASSET",
                            source_id_hint=disk_identity,
                            target_type="ASSET",
                            target_id_hint=target_key_id,
                            relationship_type="ENCRYPTED_BY",
                            confidence="HIGH"
                        )
