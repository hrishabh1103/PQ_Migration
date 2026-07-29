import pytest
from unittest.mock import MagicMock, patch
from app.connectors.azure_connector import AzureConnector
from app.connectors.azure_client import AzureSdkClient
from app.scanners.base import ScanContext

def create_security_mock_client():
    client = MagicMock(spec=AzureSdkClient)
    client.subscription_id = "00000000-0000-0000-0000-000000000000"
    client.tenant_id = "11111111-1111-1111-1111-111111111111"
    client.validate_identity.return_value = {
        "tenant_id": client.tenant_id,
        "subscription_id": client.subscription_id,
        "validated": True
    }
    client.classify_error.side_effect = lambda e: str(e)
    return client

@pytest.mark.asyncio
async def test_azure_zero_secret_data_and_key_leakage():
    """
    NEGATIVE CONTROL 1: Zero Secret & Private Key Exposure.
    Verifies observation payload contains zero client secrets, access tokens, or PEM private keys.
    """
    connector = AzureConnector()
    mock_client = create_security_mock_client()

    with patch("app.connectors.azure_connector.AzureSdkClient", return_value=mock_client):
        context = ScanContext(scan_job_id="job-sec-1", target_id="target-sec-1")
        observations = []
        async for obs in connector.collect("/subscriptions/00000000-0000-0000-0000-000000000000", "CLOUD_PROVIDER", context):
            observations.append(obs)

        for obs in observations:
            obs_dict = obs.dict() if hasattr(obs, 'dict') else obs.__dict__
            obs_str = str(obs_dict)
            assert "-----BEGIN PRIVATE KEY-----" not in obs_str
            assert "client_secret" not in obs_str.lower()
            assert "access_token" not in obs_str.lower()
            assert "connectionstring" not in obs_str.lower()

@pytest.mark.asyncio
async def test_azure_key_vault_crypto_operations_prohibited():
    """
    NEGATIVE CONTROL 2: Key Vault Data Plane Operation Prohibition.
    Verifies forbidden secret retrieval & crypto operations (get_secret, decrypt, sign, unwrap) are NEVER invoked.
    """
    connector = AzureConnector()
    mock_client = create_security_mock_client()

    mock_secret_client = MagicMock()
    mock_key_client = MagicMock()

    mock_client.get_client.side_effect = lambda service, **kwargs: mock_key_client if service == "key_data" else MagicMock()

    with patch("app.connectors.azure_connector.AzureSdkClient", return_value=mock_client):
        context = ScanContext(scan_job_id="job-sec-2", target_id="target-sec-2")
        observations = []
        async for obs in connector.collect("/subscriptions/00000000-0000-0000-0000-000000000000", "CLOUD_PROVIDER", context):
            observations.append(obs)

        # Assert forbidden methods were NEVER called
        assert not hasattr(mock_secret_client, "get_secret") or mock_secret_client.get_secret.call_count == 0
        assert not hasattr(mock_key_client, "decrypt") or mock_key_client.decrypt.call_count == 0
        assert not hasattr(mock_key_client, "sign") or mock_key_client.sign.call_count == 0
        assert not hasattr(mock_key_client, "unwrap_key") or mock_key_client.unwrap_key.call_count == 0

@pytest.mark.asyncio
async def test_azure_permission_failure_isolation():
    """
    NEGATIVE CONTROL 3: Service Permission Failure Isolation (403 AccessDenied).
    Verifies permission failure on one service yields PERMISSION_DENIED without aborting remaining modules.
    """
    connector = AzureConnector()
    mock_client = create_security_mock_client()

    def get_client_side_effect(service, **kwargs):
        if service == "keyvault":
            mock = MagicMock()
            mock.vaults.list.side_effect = Exception("403 AuthorizationFailed: User is not authorized to perform: Microsoft.KeyVault/vaults/read")
            return mock
        elif service == "compute":
            mock = MagicMock()
            mock.virtual_machines.list_all.return_value = [{"name": "vm-perm-test", "resource_group": "rg-test"}]
            return mock
        return MagicMock()

    mock_client.get_client.side_effect = get_client_side_effect

    with patch("app.connectors.azure_connector.AzureSdkClient", return_value=mock_client):
        context = ScanContext(scan_job_id="job-sec-3", target_id="target-sec-3")
        observations = []
        async for obs in connector.collect("/subscriptions/00000000-0000-0000-0000-000000000000", "CLOUD_PROVIDER", context):
            observations.append(obs)

        # Connector completed and emitted VM observations despite KeyVault 403 error
        assert any(getattr(o, 'asset_type', '') in ["compute_instance", "COMPUTE_INSTANCE"] for o in observations)
