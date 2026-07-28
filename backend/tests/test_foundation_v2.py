import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.core.database import get_db
from app.models.entities import (
    AuthorizedTarget, TargetType, Asset, Service, CryptoObject, Relationship,
    DataAsset, DataFlow, DiscoveryCoverage, DiscoveryRun
)
from app.scanners.plugins import (
    DiscoveryPlugin, PluginType, PluginCapability,
    Scanner, Connector, Collector, PluginRegistry, CapabilityRegistry
)
from app.risk.contextual_risk import ContextualRiskEngine, RiskContext, PurposeType
from app.cbom.mapper import InternalInventoryMapper, CycloneDX16Serializer

client = TestClient(app)

def test_plugin_and_capability_registry():
    class DummyScanner(Scanner):
        plugin_id = "test-active-scanner"
        version = "1.0.0"
        supported_target_types = {TargetType.HOSTNAME}
        capabilities = {PluginCapability.TLS, PluginCapability.X509}

        async def discover(self, target_value, target_type, context):
            return

    class DummyConnector(Connector):
        plugin_id = "test-cloud-connector"
        version = "1.0.0"
        supported_target_types = {TargetType.CLOUD_PROVIDER}
        capabilities = {PluginCapability.CLOUD_RESOURCE, PluginCapability.KMS}

        async def discover(self, target_value, target_type, context):
            return

    class DummyCollector(Collector):
        plugin_id = "test-agent-collector"
        version = "1.0.0"
        supported_target_types = {TargetType.HOSTNAME}
        capabilities = {PluginCapability.PASSIVE_NETWORK}

        async def discover(self, target_value, target_type, context):
            return

    s = DummyScanner()
    c = DummyConnector()
    ag = DummyCollector()

    PluginRegistry.register(s)
    PluginRegistry.register(c)
    PluginRegistry.register(ag)

    assert PluginRegistry.get("test-active-scanner") == s
    assert PluginRegistry.get("test-cloud-connector") == c
    assert PluginRegistry.get("test-agent-collector") == ag

    # Test CapabilityRegistry
    kms_plugins = CapabilityRegistry.get_plugins_for_capability(PluginCapability.KMS)
    assert c in kms_plugins

    all_caps = CapabilityRegistry.list_supported_capabilities()
    assert PluginCapability.TLS in all_caps
    assert PluginCapability.CLOUD_RESOURCE in all_caps

def test_crypto_object_deduplication_api(db_session):
    # Test deterministic identity resolution & deduplication
    payload = {
        "object_type": "CERTIFICATE",
        "canonical_name": "Root CA Cert",
        "provider": "DigiCert",
        "identity_key": "sha256-cert-fingerprint-unique-12345",
        "fingerprint": "fingerprint-12345"
    }

    res1 = client.post("/api/v1/crypto-objects", json=payload)
    assert res1.status_code == 201
    data1 = res1.json()
    assert data1["is_new"] is True
    obj_id = data1["id"]

    # Duplicate call with same identity_key
    res2 = client.post("/api/v1/crypto-objects", json=payload)
    assert res2.status_code == 201
    data2 = res2.json()
    assert data2["is_new"] is False
    assert data2["id"] == obj_id

def test_relationship_and_graph_traversal(db_session):
    # Setup asset and target
    target = AuthorizedTarget(name="Graph Target", target_type=TargetType.HOSTNAME, target_value="graph.company.com")
    db_session.add(target)
    db_session.commit()

    asset = Asset(target_id=target.id, hostname="graph.company.com", ip_address="10.0.0.1")
    db_session.add(asset)
    db_session.commit()

    cobj = CryptoObject(object_type="ALGORITHM", canonical_name="RSA-2048", identity_key="algo:rsa-2048")
    db_session.add(cobj)
    db_session.commit()

    # Create relationship
    rel_res = client.post("/api/v1/relationships", json={
        "source_entity_type": "Asset",
        "source_entity_id": asset.id,
        "target_entity_type": "CryptoObject",
        "target_entity_id": cobj.id,
        "relationship_type": "USES",
        "scanner_or_connector_id": "tls-scanner"
    })
    assert rel_res.status_code == 201

    # Query relationships endpoint
    list_res = client.get(f"/api/v1/relationships?source_entity_id={asset.id}")
    assert list_res.status_code == 200
    assert len(list_res.json()) >= 1

    # Query bounded graph traversal API
    graph_res = client.get(f"/api/v1/graph/entity/Asset/{asset.id}?depth=1")
    assert graph_res.status_code == 200
    graph_data = graph_res.json()
    assert "nodes" in graph_data
    assert "edges" in graph_data
    assert graph_data["depth"] == 1
    assert graph_data["truncated"] is False

def test_graph_identical_uuids_across_entity_types(db_session):
    """Test graph traversal matching (entity_type, entity_id) strictly when UUIDs collision occurs."""
    shared_uuid = "shared-uuid-9999"
    target = AuthorizedTarget(name="UUID Collision Target", target_type=TargetType.HOSTNAME, target_value="collision.com")
    db_session.add(target)
    db_session.commit()

    asset = Asset(id=shared_uuid, target_id=target.id, hostname="collision.com", ip_address="10.0.0.99")
    db_session.add(asset)

    cobj = CryptoObject(id="cobj-8888", object_type="ALGORITHM", canonical_name="ECDSA-P256", identity_key="algo:ecdsa-p256")
    db_session.add(cobj)
    db_session.commit()

    # Create relationship for Asset shared_uuid
    rel = Relationship(
        source_entity_type="Asset",
        source_entity_id=shared_uuid,
        target_entity_type="CryptoObject",
        target_entity_id="cobj-8888",
        relationship_type="USES",
        scanner_or_connector_id="test"
    )
    db_session.add(rel)
    db_session.commit()

    # Query graph as Asset
    asset_graph = client.get(f"/api/v1/graph/entity/Asset/{shared_uuid}?depth=1")
    assert asset_graph.status_code == 200
    data = asset_graph.json()
    assert len(data["nodes"]) == 2
    assert data["nodes"][0]["entity_type"] == "Asset"

    # Query graph as Service with same UUID should return 404 because Service shared_uuid does not exist
    svc_graph = client.get(f"/api/v1/graph/entity/Service/{shared_uuid}?depth=1")
    assert svc_graph.status_code == 404

def test_data_asset_and_data_flow_api(db_session):
    da_res = client.post("/api/v1/data/assets", json={
        "name": "Customer PI Data",
        "classification": "RESTRICTED",
        "business_criticality": "HIGH"
    })
    assert da_res.status_code == 201
    da_id = da_res.json()["id"]

    df_res = client.post("/api/v1/data/flows", json={
        "source_entity_type": "Asset",
        "source_entity_id": "asset-src-1",
        "destination_entity_type": "Asset",
        "destination_entity_id": "asset-dest-1",
        "data_asset_id": da_id,
        "protocol": "TLSv1.3",
        "protection_purpose": "ENCRYPTION"
    })
    assert df_res.status_code == 201

    # Query data flows
    flows = client.get("/api/v1/data/flows")
    assert flows.status_code == 200
    assert len(flows.json()) >= 1

def test_contextual_risk_engine():
    # Test Signature distinction vs Key Establishment
    ctx_sig = RiskContext(
        algorithm="RSA-2048",
        purpose=PurposeType.SIGNATURE,
        network_exposure="INTERNET"
    )
    eval_sig = ContextualRiskEngine.evaluate(ctx_sig)
    assert eval_sig.severity == "CRITICAL"
    assert "ML-DSA-65" in eval_sig.recommended_pqc_replacement
    assert any("SIGNATURE" in f for f in eval_sig.known_factors)

    ctx_kex = RiskContext(
        algorithm="RSA-2048",
        purpose=PurposeType.KEY_ESTABLISHMENT,
        network_exposure="INTERNET"
    )
    eval_kex = ContextualRiskEngine.evaluate(ctx_kex)
    assert "ML-KEM-768" in eval_kex.recommended_pqc_replacement
    assert any("KEY_ESTABLISHMENT" in f for f in eval_kex.known_factors)

def test_neutral_risk_context_defaults():
    # Missing optional parameters must not default to HIGH/INTERNET, but remain UNKNOWN & reduce confidence
    ctx = RiskContext(algorithm="RSA-2048")
    eval_res = ContextualRiskEngine.evaluate(ctx)
    assert eval_res.confidence in ["LOW", "MEDIUM"]
    assert any("UNKNOWN" in f for f in eval_res.unknown_factors)
    assert "rationale" in eval_res.model_dump()

def test_coverage_summary_api(db_session):
    res = client.get("/api/v1/coverage/summary")
    assert res.status_code == 200
    data = res.json()
    assert "summary" in data
    assert "not_scanned" in data["summary"]
    assert "scanned_with_findings" in data["summary"]
