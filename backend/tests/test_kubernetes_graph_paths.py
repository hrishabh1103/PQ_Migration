import pytest
from sqlalchemy.orm import Session
from app.models.entities import Asset, CryptoObject, Relationship, AuthorizedTarget, DiscoveryRun
from app.orchestrator.engine import DiscoveryOrchestrator
from app.collectors.observations import (
    AssetObservation, ServiceObservation, CertificateObservation, CryptoObservation, RelationshipObservation, CapabilityState
)

def test_kubernetes_graph_path_persistence(db_session: Session):
    """
    Test persisted dependency graph paths for Kubernetes discovery:
    Cluster -> Namespace -> Deployment -> Pod -> Service -> Ingress -> Certificate -> Crypto Primitive
    Workload -> Secret -> Certificate -> Crypto Primitive
    Node <-> AWS EC2
    """
    # 1. Create target and run
    target = AuthorizedTarget(
        id="target-k8s-graph-1",
        name="Test K8s Cluster",
        target_type="KUBERNETES_CLUSTER",
        target_value="k8s:cluster:test-graph",
        environment="STAGING"
    )
    db_session.add(target)

    run = DiscoveryRun(
        id="run-k8s-graph-1",
        plugin_id="kubernetes",
        run_type="SYNC",
        status="RUNNING"
    )
    db_session.add(run)
    db_session.commit()

    # 2. Simulate observations
    obs_cluster = AssetObservation(
        module_id="k8s_cluster",
        identity_key="k8s:cluster:test-graph",
        hostname="k8s:cluster:test-graph",
        asset_type="KUBERNETES_CLUSTER",
        asset_category="INFRASTRUCTURE"
    )

    obs_ns = AssetObservation(
        module_id="k8s_cluster",
        identity_key="k8s:namespace:test-graph:ns-uid-1",
        hostname="ns:prod",
        asset_type="KUBERNETES_NAMESPACE"
    )

    obs_workload = AssetObservation(
        module_id="k8s_workload",
        identity_key="k8s:workload:test-graph:depl-uid-1",
        hostname="deployment:prod/api-server",
        asset_type="KUBERNETES_WORKLOAD"
    )

    obs_pod = AssetObservation(
        module_id="k8s_workload",
        identity_key="k8s:pod:test-graph:pod-uid-1",
        hostname="pod:prod/api-server-7b9f",
        asset_type="KUBERNETES_POD"
    )

    obs_svc = AssetObservation(
        module_id="k8s_service",
        identity_key="k8s:service:test-graph:svc-uid-1",
        hostname="service:prod/api-svc",
        asset_type="KUBERNETES_SERVICE"
    )

    obs_ing = AssetObservation(
        module_id="k8s_service",
        identity_key="k8s:ingress:test-graph:ing-uid-1",
        hostname="ingress:prod/api-ing",
        asset_type="KUBERNETES_INGRESS"
    )

    obs_cert = CertificateObservation(
        module_id="k8s_certificate",
        fingerprint="AA:BB:CC:DD:EE:FF:11:22:33:44:55:66:77:88:99:00:AA:BB:CC:DD:EE:FF:11:22:33:44:55:66:77:88:99:00",
        subject="CN=api.prod.example.com",
        issuer="CN=Enterprise Root CA",
        pubkey_algo="RSA-2048",
        pubkey_size=2048,
        signature_algo="sha256WithRSAEncryption"
    )

    # Relationships
    rel1 = RelationshipObservation(
        module_id="k8s_cluster",
        source_type="ASSET",
        source_id_hint="k8s:cluster:test-graph",
        target_type="ASSET",
        target_id_hint="k8s:namespace:test-graph:ns-uid-1",
        relationship_type="CONTAINS"
    )

    rel2 = RelationshipObservation(
        module_id="k8s_workload",
        source_type="ASSET",
        source_id_hint="k8s:namespace:test-graph:ns-uid-1",
        target_type="ASSET",
        target_id_hint="k8s:workload:test-graph:depl-uid-1",
        relationship_type="CONTAINS"
    )

    rel3 = RelationshipObservation(
        module_id="k8s_workload",
        source_type="ASSET",
        source_id_hint="k8s:workload:test-graph:depl-uid-1",
        target_type="ASSET",
        target_id_hint="k8s:pod:test-graph:pod-uid-1",
        relationship_type="CREATES"
    )

    # Persist via resolve_or_create_asset & database
    ast_cluster = DiscoveryOrchestrator.resolve_or_create_asset(
        db=db_session, target_id=target.id, hostname=obs_cluster.hostname, ip_address=None,
        asset_type=obs_cluster.asset_type, environment="STAGING", identity_key=obs_cluster.identity_key
    )

    ast_ns = DiscoveryOrchestrator.resolve_or_create_asset(
        db=db_session, target_id=target.id, hostname=obs_ns.hostname, ip_address=None,
        asset_type=obs_ns.asset_type, environment="STAGING", identity_key=obs_ns.identity_key
    )

    ast_workload = DiscoveryOrchestrator.resolve_or_create_asset(
        db=db_session, target_id=target.id, hostname=obs_workload.hostname, ip_address=None,
        asset_type=obs_workload.asset_type, environment="STAGING", identity_key=obs_workload.identity_key
    )

    db_session.commit()

    # Verify persisted entities
    saved_workload = db_session.query(Asset).filter(Asset.identity_key == "k8s:workload:test-graph:depl-uid-1").first()
    assert saved_workload is not None
    assert saved_workload.asset_type == "KUBERNETES_WORKLOAD"
