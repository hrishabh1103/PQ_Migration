import pytest
import asyncio
from unittest.mock import MagicMock, patch
from app.models.entities import TargetType
from app.scanners.base import ScanContext
from app.connectors.kubernetes_connector import KubernetesConnector
from app.collectors.observations import (
    AssetObservation, CryptoObservation, CapabilityState
)

@pytest.mark.asyncio
async def test_control_1_configmap_pqc_remains_configured():
    """Verify ConfigMap containing 'mlkem768' remains CONFIGURED and is never OBSERVED_IN_USE."""
    connector = KubernetesConnector()

    mock_client = MagicMock()
    mock_client.validate_connection.return_value = {"validated": True, "git_version": "v1.30.2"}

    mock_cm = MagicMock()
    mock_cm.metadata.namespace = "default"
    mock_cm.metadata.name = "pqc-config"
    mock_cm.metadata.uid = "cm-uid-999"
    mock_cm.data = {"nginx.conf": "ssl_ecdh_curve mlkem768:X25519;"}
    mock_client.core_v1.list_config_map_for_all_namespaces.return_value.items = [mock_cm]

    mock_client.core_v1.list_namespace.return_value.items = []
    mock_client.core_v1.list_node.return_value.items = []
    mock_client.apps_v1.list_deployment_for_all_namespaces.return_value.items = []
    mock_client.core_v1.list_pod_for_all_namespaces.return_value.items = []
    mock_client.core_v1.list_service_for_all_namespaces.return_value.items = []
    mock_client.networking_v1.list_ingress_for_all_namespaces.return_value.items = []
    mock_client.core_v1.list_secret_for_all_namespaces.return_value.items = []
    mock_client.custom_objects.list_cluster_custom_object.side_effect = Exception("404 Not Found")
    mock_client.core_v1.list_service_account_for_all_namespaces.return_value.items = []

    with patch("app.connectors.kubernetes_connector.KubernetesClient", return_value=mock_client):
        context = ScanContext(scan_job_id="job-k8s-sec", target_id="target-k8s-sec", run_id="run-k8s-sec")
        observations = []
        async for obs in connector.collect("k8s:cluster:test", TargetType.KUBERNETES_CLUSTER, context):
            observations.append(obs)

        crypto_obs = [o for o in observations if isinstance(o, CryptoObservation)]
        assert len(crypto_obs) >= 1
        assert crypto_obs[0].capability_state == CapabilityState.CONFIGURED
        assert crypto_obs[0].capability_state != CapabilityState.OBSERVED_IN_USE

@pytest.mark.asyncio
async def test_control_2_zero_secret_data_and_tls_key_leakage():
    """Verify tls.key and Secret.data values NEVER enter observations or metadata."""
    connector = KubernetesConnector()

    mock_client = MagicMock()
    mock_client.validate_connection.return_value = {"validated": True, "git_version": "v1.30.2"}

    mock_sec = MagicMock()
    mock_sec.metadata.namespace = "default"
    mock_sec.metadata.name = "my-tls-secret"
    mock_sec.metadata.uid = "sec-uid-111"
    mock_sec.type = "kubernetes.io/tls"
    # Secret containing private key and password
    mock_sec.data = {
        "tls.crt": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCg==",
        "tls.key": "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC...SECRET_PRIVATE_KEY",
        "password": "SUPER_SECRET_PASSWORD"
    }
    mock_client.core_v1.list_secret_for_all_namespaces.return_value.items = [mock_sec]

    mock_client.core_v1.list_namespace.return_value.items = []
    mock_client.core_v1.list_node.return_value.items = []
    mock_client.apps_v1.list_deployment_for_all_namespaces.return_value.items = []
    mock_client.core_v1.list_pod_for_all_namespaces.return_value.items = []
    mock_client.core_v1.list_service_for_all_namespaces.return_value.items = []
    mock_client.networking_v1.list_ingress_for_all_namespaces.return_value.items = []
    mock_client.core_v1.list_config_map_for_all_namespaces.return_value.items = []
    mock_client.custom_objects.list_cluster_custom_object.side_effect = Exception("404 Not Found")
    mock_client.core_v1.list_service_account_for_all_namespaces.return_value.items = []

    with patch("app.connectors.kubernetes_connector.KubernetesClient", return_value=mock_client):
        context = ScanContext(scan_job_id="job-k8s-sec", target_id="target-k8s-sec", run_id="run-k8s-sec")
        observations = []
        async for obs in connector.collect("k8s:cluster:test", TargetType.KUBERNETES_CLUSTER, context):
            observations.append(obs)

        # Assert no observation contains the private key or password string
        for obs in observations:
            obs_str = str(obs.dict())
            assert "SECRET_PRIVATE_KEY" not in obs_str
            assert "SUPER_SECRET_PASSWORD" not in obs_str

@pytest.mark.asyncio
async def test_control_3_uid_identity_separation_on_name_reuse():
    """Verify name reuse with different metadata.uid produces different identity keys."""
    connector = KubernetesConnector()

    mock_client = MagicMock()
    mock_client.validate_connection.return_value = {"validated": True, "git_version": "v1.30.2"}

    pod1 = MagicMock()
    pod1.metadata.namespace = "default"
    pod1.metadata.name = "web-app"
    pod1.metadata.uid = "uid-first-instance"
    pod1.status.pod_ip = "10.0.0.1"
    pod1.status.phase = "Running"
    pod1.spec.containers = []
    pod1.status.container_statuses = []
    pod1.spec.node_name = "node-1"
    pod1.metadata.owner_references = []

    pod2 = MagicMock()
    pod2.metadata.namespace = "default"
    pod2.metadata.name = "web-app" # Same name!
    pod2.metadata.uid = "uid-second-recreated-instance" # Different UID!
    pod2.status.pod_ip = "10.0.0.1"
    pod2.status.phase = "Running"
    pod2.spec.containers = []
    pod2.status.container_statuses = []
    pod2.spec.node_name = "node-1"
    pod2.metadata.owner_references = []

    mock_client.core_v1.list_pod_for_all_namespaces.return_value.items = [pod1, pod2]
    mock_client.core_v1.list_namespace.return_value.items = []
    mock_client.core_v1.list_node.return_value.items = []
    mock_client.apps_v1.list_deployment_for_all_namespaces.return_value.items = []
    mock_client.core_v1.list_service_for_all_namespaces.return_value.items = []
    mock_client.networking_v1.list_ingress_for_all_namespaces.return_value.items = []
    mock_client.core_v1.list_secret_for_all_namespaces.return_value.items = []
    mock_client.core_v1.list_config_map_for_all_namespaces.return_value.items = []
    mock_client.custom_objects.list_cluster_custom_object.side_effect = Exception("404 Not Found")
    mock_client.core_v1.list_service_account_for_all_namespaces.return_value.items = []

    with patch("app.connectors.kubernetes_connector.KubernetesClient", return_value=mock_client):
        context = ScanContext(scan_job_id="job-k8s-sec", target_id="target-k8s-sec", run_id="run-k8s-sec")
        observations = []
        async for obs in connector.collect("k8s:cluster:test", TargetType.KUBERNETES_CLUSTER, context):
            observations.append(obs)

        pod_obs = [o for o in observations if isinstance(o, AssetObservation) and o.asset_type == "KUBERNETES_POD"]
        assert len(pod_obs) == 2
        assert pod_obs[0].identity_key != pod_obs[1].identity_key
        assert "uid-first-instance" in pod_obs[0].identity_key
        assert "uid-second-recreated-instance" in pod_obs[1].identity_key

@pytest.mark.asyncio
async def test_control_4_unreachable_cluster_fails_closed():
    """Verify unreachable cluster fails closed by raising ConnectionError."""
    connector = KubernetesConnector()

    mock_client = MagicMock()
    mock_client.validate_connection.return_value = {"validated": False, "error": "Connection refused"}

    with patch("app.connectors.kubernetes_connector.KubernetesClient", return_value=mock_client):
        context = ScanContext(scan_job_id="job-k8s-sec", target_id="target-k8s-sec", run_id="run-k8s-sec")
        with pytest.raises(ConnectionError):
            async for _ in connector.collect("k8s:cluster:unreachable", TargetType.KUBERNETES_CLUSTER, context):
                pass
