import pytest
from unittest.mock import MagicMock, patch
from sqlalchemy.orm import Session

from app.models.entities import AuthorizedTarget, Asset, CryptoObject, Relationship
from app.connectors.azure_connector import AzureConnector
from app.connectors.azure_client import AzureSdkClient
from app.orchestrator.engine import DiscoveryOrchestrator
from app.scanners.base import ScanContext

def create_mock_azure_client():
    client = MagicMock(spec=AzureSdkClient)
    client.subscription_id = "00000000-0000-0000-0000-000000000000"
    client.tenant_id = "11111111-1111-1111-1111-111111111111"
    client.validate_identity.return_value = {
        "tenant_id": client.tenant_id,
        "subscription_id": client.subscription_id,
        "display_name": "Test Subscription",
        "validated": True
    }
    client.classify_error.side_effect = lambda e: str(e)

    # Mock Azure Services
    mock_resource = MagicMock()
    mock_resource.resource_groups.list.return_value = [{"name": "rg-test", "location": "eastus"}]

    mock_compute = MagicMock()
    mock_compute.virtual_machines.list_all.return_value = [{
        "name": "vm-test-1",
        "resource_group": "rg-test",
        "location": "eastus",
        "vm_id": "vm-guid-1",
        "storage_profile": {
            "os_disk": {
                "name": "disk-test-1",
                "encryption_settings": {
                    "disk_encryption_key": {
                        "secret_url": "https://kv-test.vault.azure.net/keys/cmk-key-1/v1"
                    }
                }
            }
        }
    }]

    mock_storage = MagicMock()
    mock_storage.storage_accounts.list.return_value = [{
        "name": "satest1",
        "resource_group": "rg-test",
        "location": "eastus",
        "encryption": {
            "key_vault_properties": {
                "key_uri": "https://kv-test.vault.azure.net/keys/cmk-key-1/v1"
            }
        }
    }]

    mock_kv = MagicMock()
    mock_kv.vaults.list.return_value = [{"name": "kv-test", "resource_group": "rg-test", "location": "eastus"}]

    mock_key_data = MagicMock()
    mock_key_data.list_properties_of_keys.return_value = [
        {"name": "cmk-key-1", "kty": "RSA", "enabled": True, "version": "v1"},
        {"name": "cmk-key-1", "kty": "RSA", "enabled": True, "version": "v2"}
    ]

    mock_cert_data = MagicMock()
    mock_cert_data.list_properties_of_certificates.return_value = [
        {"name": "cert-test-1", "x509_thumbprint": "88915019dd6789abcdef0123456789abcdef0123456789abcdef01234567890123"}
    ]

    def get_client_side_effect(service, **kwargs):
        if service == "resource":
            return mock_resource
        elif service == "compute":
            return mock_compute
        elif service == "storage":
            return mock_storage
        elif service == "keyvault":
            return mock_kv
        elif service == "key_data":
            return mock_key_data
        elif service == "cert_data":
            return mock_cert_data
        return MagicMock()

    client.get_client.side_effect = get_client_side_effect
    return client

@pytest.mark.asyncio
async def test_azure_connector_metadata():
    connector = AzureConnector()
    assert connector.plugin_id == "azure"
    assert connector.version == "1.0.0"

@pytest.mark.asyncio
async def test_azure_connector_collect_modules():
    connector = AzureConnector()
    mock_client = create_mock_azure_client()

    with patch("app.connectors.azure_connector.AzureSdkClient", return_value=mock_client):
        context = ScanContext(scan_job_id="job-azure-1", target_id="target-azure-1")
        observations = []
        async for obs in connector.collect(
            target_value="/subscriptions/00000000-0000-0000-0000-000000000000",
            target_type="CLOUD_PROVIDER",
            context=context
        ):
            observations.append(obs)

        assert len(observations) > 0
        asset_types = set(getattr(o, "asset_type", "") for o in observations)
        assert "cloud_tenant" in asset_types
        assert "cloud_subscription" in asset_types
        assert "cloud_resource_group" in asset_types
        assert "compute_instance" in asset_types
        assert "block_storage" in asset_types
        assert "object_storage" in asset_types
        assert "secret_store" in asset_types
        assert "managed_key" in asset_types

@pytest.mark.asyncio
async def test_azure_connector_version_specific_dependency(db_session: Session):
    """
    Verify version-specific Key Vault key dependency:
    Resource referencing v1 (RSA-2048) targets KeyVersion v1, even when v2 is present.
    """
    target = AuthorizedTarget(
        id="target-azure-versioning",
        name="Azure Versioning Test",
        target_type="CLOUD_PROVIDER",
        target_value="/subscriptions/00000000-0000-0000-0000-000000000000",
        environment="DEVELOPMENT"
    )
    db_session.add(target)
    db_session.commit()

    mock_client = create_mock_azure_client()

    with patch("app.scanners.plugins.PluginRegistry.get", return_value=AzureConnector()):
        with patch("app.connectors.azure_connector.AzureSdkClient", return_value=mock_client):
            run = await DiscoveryOrchestrator.run_connector_sync(
                db=db_session,
                target_id=target.id,
                connector_plugin_id="azure"
            )
            assert run.status == "COMPLETED"

            # Check Key Versions created
            key_versions = db_session.query(Asset).filter(Asset.asset_type == "managed_key", Asset.identity_key.contains("key_version")).all()
            assert len(key_versions) == 2
            v1_asset = next(k for k in key_versions if "v1" in k.identity_key)
            assert v1_asset is not None

            # Verify relationship targets v1 specifically
            rel = db_session.query(Relationship).filter(Relationship.target_entity_id == v1_asset.id).first()
            assert rel is not None
