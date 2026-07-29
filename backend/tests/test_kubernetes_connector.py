import pytest
import asyncio
from unittest.mock import MagicMock, patch
from app.models.entities import TargetType
from app.scanners.base import ScanContext
from app.connectors.kubernetes_connector import KubernetesConnector
from app.collectors.observations import (
    AssetObservation, ServiceObservation, CertificateObservation, CryptoObservation
)

@pytest.mark.asyncio
async def test_kubernetes_connector_registration():
    connector = KubernetesConnector()
    assert connector.plugin_id == "kubernetes"
    assert TargetType.KUBERNETES_CLUSTER in connector.supported_target_types

@pytest.mark.asyncio
async def test_kubernetes_connector_mock_sync():
    connector = KubernetesConnector()

    mock_client = MagicMock()
    mock_client.validate_connection.return_value = {"validated": True, "git_version": "v1.30.2"}

    # Mock CoreV1
    mock_ns = MagicMock()
    mock_ns.metadata.name = "default"
    mock_ns.metadata.uid = "ns-uid-123"
    mock_client.core_v1.list_namespace.return_value.items = [mock_ns]

    mock_node = MagicMock()
    mock_node.metadata.name = "node-1"
    mock_node.metadata.uid = "node-uid-456"
    mock_node.spec.provider_id = "aws:///us-east-1a/i-0123456789"
    mock_node.status.addresses = []
    mock_node.status.node_info = None
    mock_client.core_v1.list_node.return_value.items = [mock_node]

    mock_client.apps_v1.list_deployment_for_all_namespaces.return_value.items = []
    mock_client.core_v1.list_pod_for_all_namespaces.return_value.items = []
    mock_client.core_v1.list_service_for_all_namespaces.return_value.items = []
    mock_client.networking_v1.list_ingress_for_all_namespaces.return_value.items = []
    mock_client.core_v1.list_secret_for_all_namespaces.return_value.items = []
    mock_client.core_v1.list_config_map_for_all_namespaces.return_value.items = []
    mock_client.custom_objects.list_cluster_custom_object.side_effect = Exception("404 Not Found")
    mock_client.core_v1.list_service_account_for_all_namespaces.return_value.items = []

    with patch("app.connectors.kubernetes_connector.KubernetesClient", return_value=mock_client):
        context = ScanContext(scan_job_id="job-k8s-test", target_id="target-k8s-test", run_id="run-k8s-test")
        observations = []
        async for obs in connector.collect(
            target_value="arn:aws:eks:us-east-1:123456789012:cluster/test-cluster",
            target_type=TargetType.KUBERNETES_CLUSTER,
            context=context
        ):
            observations.append(obs)

        assert len(observations) >= 3
        cluster_obs = [o for o in observations if isinstance(o, AssetObservation) and o.asset_type == "KUBERNETES_CLUSTER"]
        assert len(cluster_obs) == 1
        assert cluster_obs[0].identity_key == "arn:aws:eks:us-east-1:123456789012:cluster/test-cluster"

        node_obs = [o for o in observations if isinstance(o, AssetObservation) and o.asset_type == "HOST"]
        assert len(node_obs) == 1
        assert node_obs[0].provider_resource_id == "aws:///us-east-1a/i-0123456789"
