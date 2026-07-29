import pytest
import uuid
from sqlalchemy.orm import Session

from app.core.database import Base, engine, SessionLocal
from app.models.entities import (
    AuthorizedTarget, Asset, Service, CryptoObject, Relationship,
    DiscoveryRun, DiscoveryCoverage, CorrelationRecord, ReadinessAssessment, AssessmentRun, utc_now
)
from app.correlation.models import CorrelationDecision, EvidenceStrength
from app.correlation.engine import CorrelationEngine
from app.readiness.taxonomy import CryptographicPurpose, PrimitiveQuantumStatus, AssetReadinessResult
from app.readiness.policy import ReadinessPolicy
from app.readiness.classifier import PqcClassifier
from app.readiness.priority import MigrationPriorityEngine
from app.readiness.evaluator import ReadinessEvaluator

@pytest.fixture(scope="function")
def db_session():
    Base.metadata.create_all(bind=engine)
    session = SessionLocal()
    try:
        yield session
    finally:
        session.rollback()
        session.close()

def test_assessment_run_creation_and_persistence(db_session: Session):
    target = AuthorizedTarget(name="Audit Target 1", target_value="audit1.company.com", target_type="HOSTNAME")
    db_session.add(target)
    db_session.commit()

    asset = Asset(target_id=target.id, hostname="host-audit-1.company.com", asset_type="HOST")
    db_session.add(asset)
    db_session.commit()

    # Execute AssessmentRun
    run = ReadinessEvaluator.execute_assessment_run(
        db=db_session,
        policy_id="pqc-default",
        policy_version="v1.0"
    )

    # 1. Verify AssessmentRun record
    assert run.id is not None
    assert run.status == "COMPLETED"
    assert run.policy_id == "pqc-default"
    assert run.policy_version == "v1.0"
    assert run.evaluated_entity_count >= 1

    # 2. Verify ReadinessAssessment linked to AssessmentRun
    assessment = db_session.query(ReadinessAssessment).filter(ReadinessAssessment.assessment_run_id == run.id).first()
    assert assessment is not None
    assert assessment.assessment_run_id == run.id
    assert assessment.factor_breakdown_json is not None

def test_priority_factor_breakdown_persistence(db_session: Session):
    target = AuthorizedTarget(name="Audit Target 2", target_value="audit2.company.com", target_type="HOSTNAME")
    db_session.add(target)
    db_session.commit()

    asset = Asset(target_id=target.id, hostname="factor-host", asset_type="HOST")
    db_session.add(asset)
    db_session.commit()

    assessment = ReadinessEvaluator.evaluate_asset(db_session, asset.id)

    # Verify factor breakdown persistence
    fb = assessment.factor_breakdown_json
    assert fb is not None
    assert "quantum_exposure" in fb
    assert "cryptographic_purpose" in fb
    assert "network_exposure" in fb
    assert "hndl_context" in fb
    assert "business_criticality" in fb
    assert "dependency_blast_radius" in fb
    assert "migration_complexity" in fb
    assert "discovery_coverage" in fb
    assert "observation_confidence" in fb
    assert "correlation_confidence" in fb

def test_correlation_persistence_and_non_merging(db_session: Session):
    target = AuthorizedTarget(name="Audit Target 3", target_value="audit3.company.com", target_type="HOSTNAME")
    db_session.add(target)
    db_session.commit()

    asset_a = Asset(
        target_id=target.id,
        hostname="web-server-01",
        ip_address="192.168.1.100",
        asset_type="cloud_vm",
        provider="aws",
        provider_resource_id="arn:aws:ec2:us-east-1:123456789012:instance/i-0001"
    )
    asset_b = Asset(
        target_id=target.id,
        hostname="web-server-02",
        ip_address="192.168.1.100",
        asset_type="cloud_vm",
        provider="aws",
        provider_resource_id="arn:aws:ec2:us-east-1:123456789012:instance/i-0002"
    )
    db_session.add_all([asset_a, asset_b])
    db_session.commit()

    rec = CorrelationEngine.evaluate_pair(
        db=db_session,
        source_type="ASSET",
        source_id=asset_a.id,
        target_type="ASSET",
        target_id=asset_b.id
    )

    persisted = db_session.query(CorrelationRecord).filter(CorrelationRecord.id == rec.id).first()
    assert persisted is not None
    assert persisted.decision in [CorrelationDecision.CONFLICTING.value, CorrelationDecision.RELATED.value]

    asset_a_check = db_session.query(Asset).filter(Asset.id == asset_a.id).first()
    asset_b_check = db_session.query(Asset).filter(Asset.id == asset_b.id).first()
    assert asset_a_check is not None
    assert asset_b_check is not None
    assert asset_a_check.id != asset_b_check.id

def test_identity_compatibility_across_namespaces(db_session: Session):
    from app.models.entities import DataAsset
    target = AuthorizedTarget(name="Audit Target 4", target_value="audit4.company.com", target_type="HOSTNAME")
    db_session.add(target)
    db_session.commit()

    res_id = str(uuid.uuid4())
    asset = Asset(id=res_id, target_id=target.id, hostname="host-res", asset_type="HOST")
    da = DataAsset(id=res_id, name="Customer Database", classification="CONFIDENTIAL")
    db_session.add_all([asset, da])
    db_session.commit()

    # Correlate incompatible types (ASSET vs DATA_ASSET with same ID string)
    rec = CorrelationEngine.evaluate_pair(
        db=db_session,
        source_type="ASSET",
        source_id=res_id,
        target_type="DATA_ASSET",
        target_id=res_id
    )

    assert rec.decision == CorrelationDecision.UNRESOLVED.value
    assert "Incompatible" in rec.conflicting_evidence_json["evidence"][0]["description"]

def test_purpose_aware_pqc_classification_broad_taxonomy():
    # RSA Key Establishment vs RSA Signature vs Code Signing
    status_ke, rec_ke, _ = PqcClassifier.classify_primitive("RSA-2048", CryptographicPurpose.KEY_ESTABLISHMENT)
    assert status_ke == PrimitiveQuantumStatus.QUANTUM_VULNERABLE
    assert "ML-KEM" in rec_ke and "ML-DSA" not in rec_ke

    status_sig, rec_sig, _ = PqcClassifier.classify_primitive("RSA-2048", CryptographicPurpose.DIGITAL_SIGNATURE)
    assert status_sig == PrimitiveQuantumStatus.QUANTUM_VULNERABLE
    assert "ML-DSA" in rec_sig and "ML-KEM" not in rec_sig

    status_code, rec_code, _ = PqcClassifier.classify_primitive("ECDSA-P256", CryptographicPurpose.CODE_SIGNING)
    assert status_code == PrimitiveQuantumStatus.QUANTUM_VULNERABLE
    assert "ML-DSA" in rec_code

    status_auth, rec_auth, _ = PqcClassifier.classify_primitive("RSA-4096", CryptographicPurpose.IDENTITY_AUTHENTICATION)
    assert status_auth == PrimitiveQuantumStatus.QUANTUM_VULNERABLE

    # ML-KEM & ML-DSA
    status_kem, rec_kem, _ = PqcClassifier.classify_primitive("ML-KEM-768", CryptographicPurpose.KEY_ESTABLISHMENT)
    assert status_kem == PrimitiveQuantumStatus.QUANTUM_RESISTANT
    assert "ML-DSA" not in rec_kem

    status_dsa, rec_dsa, _ = PqcClassifier.classify_primitive("ML-DSA-65", CryptographicPurpose.DIGITAL_SIGNATURE)
    assert status_dsa == PrimitiveQuantumStatus.QUANTUM_RESISTANT
    assert "ML-KEM" not in rec_dsa

    # Symmetric / Storage Encryption & Hash
    status_sym, _, _ = PqcClassifier.classify_primitive("AES-256-GCM", CryptographicPurpose.STORAGE_ENCRYPTION)
    assert status_sym == PrimitiveQuantumStatus.NOT_APPLICABLE

    status_hash, _, _ = PqcClassifier.classify_primitive("SHA-256", CryptographicPurpose.HASH)
    assert status_hash == PrimitiveQuantumStatus.NOT_APPLICABLE

def test_primitive_vs_asset_readiness(db_session: Session):
    target = AuthorizedTarget(name="Audit Target 5", target_value="audit5.company.com", target_type="HOSTNAME")
    db_session.add(target)
    db_session.commit()

    # Scenario A: Asset with ML-KEM AND ECDSA signature -> Asset must NOT become READY solely because ML-KEM exists
    asset_a = Asset(target_id=target.id, hostname="app-hybrid", asset_type="HOST")
    db_session.add(asset_a)
    db_session.commit()

    c_kem = CryptoObject(object_type="LIBRARY", canonical_name="ML-KEM-768", identity_key=f"c:kem:{uuid.uuid4()}")
    c_ecdsa = CryptoObject(object_type="CERTIFICATE", canonical_name="ECDSA-P256", identity_key=f"c:ecdsa:{uuid.uuid4()}")
    db_session.add_all([c_kem, c_ecdsa])
    db_session.commit()

    rel1 = Relationship(source_entity_type="ASSET", source_entity_id=asset_a.id, target_entity_type="CRYPTO_OBJECT", target_entity_id=c_kem.id, relationship_type="USES", scanner_or_connector_id="test")
    rel2 = Relationship(source_entity_type="ASSET", source_entity_id=asset_a.id, target_entity_type="CRYPTO_OBJECT", target_entity_id=c_ecdsa.id, relationship_type="USES", scanner_or_connector_id="test")
    db_session.add_all([rel1, rel2])

    cov_a = DiscoveryCoverage(asset_id=asset_a.id, capability="OPENSSL", status="SCANNED")
    db_session.add(cov_a)
    db_session.commit()

    eval_a = ReadinessEvaluator.evaluate_asset(db_session, asset_a.id)
    # ASSERT Asset is NOT READY (it has quantum-vulnerable ECDSA despite having ML-KEM)
    assert eval_a.readiness_result == AssetReadinessResult.NOT_READY.value

    # Scenario B: No vulnerable primitive, but coverage is PARTIALLY_SCANNED -> Readiness is INCOMPLETE_COVERAGE
    asset_b = Asset(target_id=target.id, hostname="app-partial", asset_type="HOST")
    db_session.add(asset_b)
    db_session.commit()

    cov_b = DiscoveryCoverage(asset_id=asset_b.id, capability="OPENSSL", status="PARTIALLY_SCANNED")
    db_session.add(cov_b)
    db_session.commit()

    eval_b = ReadinessEvaluator.evaluate_asset(db_session, asset_b.id)
    assert eval_b.readiness_result == AssetReadinessResult.INCOMPLETE_COVERAGE.value

def test_assessment_history_and_policy_versioning(db_session: Session):
    target = AuthorizedTarget(name="Audit Target 6", target_value="audit6.company.com", target_type="HOSTNAME")
    db_session.add(target)
    db_session.commit()

    asset = Asset(target_id=target.id, hostname="history-host", asset_type="HOST")
    db_session.add(asset)
    db_session.commit()

    # Run A with policy pqc-default / v1.0
    run_a = ReadinessEvaluator.execute_assessment_run(db_session, policy_id="pqc-default", policy_version="v1.0", target_id=target.id)
    assessment_a = db_session.query(ReadinessAssessment).filter(ReadinessAssessment.assessment_run_id == run_a.id).first()

    # Run B with policy pqc-default / v1.1
    run_b = ReadinessEvaluator.execute_assessment_run(db_session, policy_id="pqc-default", policy_version="v1.1", target_id=target.id)
    assessment_b = db_session.query(ReadinessAssessment).filter(ReadinessAssessment.assessment_run_id == run_b.id).first()

    # ASSERT Run A remains unchanged and independent of Run B
    assert run_a.id != run_b.id
    assert assessment_a.id != assessment_b.id
    assert assessment_a.policy_version == "v1.0"
    assert assessment_b.policy_version == "v1.1"

def test_migration_priority_factor_sensitivity():
    base = MigrationPriorityEngine.calculate_priority(
        quantum_status=PrimitiveQuantumStatus.QUANTUM_VULNERABLE,
        purpose=CryptographicPurpose.KEY_ESTABLISHMENT,
        is_internet_exposed=False,
        business_criticality="LOW"
    )

    exposed = MigrationPriorityEngine.calculate_priority(
        quantum_status=PrimitiveQuantumStatus.QUANTUM_VULNERABLE,
        purpose=CryptographicPurpose.KEY_ESTABLISHMENT,
        is_internet_exposed=True,
        business_criticality="LOW"
    )

    critical = MigrationPriorityEngine.calculate_priority(
        quantum_status=PrimitiveQuantumStatus.QUANTUM_VULNERABLE,
        purpose=CryptographicPurpose.KEY_ESTABLISHMENT,
        is_internet_exposed=False,
        business_criticality="CRITICAL"
    )

    assert exposed["priority_score"] > base["priority_score"]
    assert critical["priority_score"] > base["priority_score"]

def test_readiness_and_correlation_rest_apis(db_session: Session):
    from fastapi.testclient import TestClient
    from app.main import app

    client = TestClient(app)

    # 1. Summary API
    s_res = client.get("/api/v1/readiness/summary")
    assert s_res.status_code == 200
    s_data = s_res.json()
    assert "policy" in s_data
    assert "quantum_exposure_breakdown" in s_data

    # 2. Assets API
    a_res = client.get("/api/v1/readiness/assets")
    assert a_res.status_code == 200

    # 3. Correlations API
    c_res = client.get("/api/v1/correlations")
    assert c_res.status_code == 200

def test_deterministic_multi_source_scenario(db_session: Session):
    target = AuthorizedTarget(name="AWS Enterprise Account MultiSource", target_value="123456789012", target_type="CLOUD_PROVIDER")
    db_session.add(target)
    db_session.commit()

    # AWS Account Asset
    acc_asset = Asset(target_id=target.id, hostname="aws-account-123456789012", asset_type="cloud_account", provider="aws", provider_resource_id="arn:aws:::123456789012")
    db_session.add(acc_asset)
    db_session.commit()

    # AWS EC2 & Linux Host
    ec2_vm = Asset(target_id=target.id, hostname="ec2-web-01", asset_type="cloud_vm", provider="aws", provider_resource_id="arn:aws:ec2:us-east-1:123456789012:instance/i-0aaa")
    linux_host = Asset(target_id=target.id, hostname="ec2-web-01", asset_type="HOST", provider="linux_collector", identity_key="host:ec2-web-01")
    db_session.add_all([ec2_vm, linux_host])
    db_session.commit()

    # EBS & KMS
    kms_key = Asset(target_id=target.id, hostname="kms-key-master", asset_type="kms_key", provider="aws", provider_resource_id="arn:aws:kms:us-east-1:123456789012:key/k-111")
    ebs_vol = Asset(target_id=target.id, hostname="ebs-vol-data", asset_type="cloud_storage", provider="aws", provider_resource_id="arn:aws:ec2:us-east-1:123456789012:volume/v-222")
    db_session.add_all([kms_key, ebs_vol])
    db_session.commit()

    # Relationships
    rel_ebs_kms = Relationship(source_entity_type="ASSET", source_entity_id=ebs_vol.id, target_entity_type="ASSET", target_entity_id=kms_key.id, relationship_type="ENCRYPTED_BY", scanner_or_connector_id="aws")
    db_session.add(rel_ebs_kms)
    db_session.commit()

    # Coverage
    cov_ec2 = DiscoveryCoverage(asset_id=ec2_vm.id, capability="CLOUD_COMPUTE", status="SCANNED")
    db_session.add(cov_ec2)
    db_session.commit()

    # Execute Assessment
    assessment = ReadinessEvaluator.evaluate_asset(db_session, ec2_vm.id)
    assert assessment.readiness_result is not None
    assert assessment.quantum_exposure is not None
    assert assessment.migration_priority_score >= 0
    assert assessment.factor_breakdown_json is not None
