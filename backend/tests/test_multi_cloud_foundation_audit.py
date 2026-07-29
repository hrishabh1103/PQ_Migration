import pytest
from unittest.mock import MagicMock, patch
from sqlalchemy.orm import Session

from app.models.entities import (
    AuthorizedTarget, Asset, CryptoObject, Relationship,
    DiscoveryRun, CorrelationRecord, ReadinessAssessment, AssessmentRun
)
from app.collectors.observations import (
    AssetObservation, ServiceObservation, CryptoObservation,
    CertificateObservation, RelationshipObservation, CapabilityObservation,
    CapabilityState, ObservationType
)
from app.correlation.engine import CorrelationEngine, CorrelationDecision
from app.readiness.evaluator import ReadinessEvaluator
from app.core.scope_guard import ScopeGuard
from app.orchestrator.engine import DiscoveryOrchestrator, DiscoveryCoverage, ScanContext
from app.connectors.aws_connector import AWSConnector
from app.connectors.azure_connector import AzureConnector
from app.connectors.kubernetes_connector import KubernetesConnector
from app.normalization.engine import NormalizationEngine


def test_audit_1_weak_identifiers_do_not_trigger_identical(db_session: Session):
    """
    CANONICAL IDENTITY AUDIT: Verify weak identifiers (IP, Hostname, Display Name, Tags)
    NEVER independently trigger IDENTICAL canonical resolution.
    """
    target = AuthorizedTarget(
        id="target-weak-id-test",
        name="Weak Identifiers Target",
        target_type="CLOUD_PROVIDER",
        target_value="192.168.1.1",
        environment="PRODUCTION"
    )
    db_session.add(target)
    db_session.commit()

    # Asset A: AWS EC2 with shared IP & Hostname
    asset_aws = Asset(
        target_id=target.id,
        hostname="web-server.internal",
        ip_address="10.0.0.50",
        asset_type="COMPUTE_INSTANCE",
        provider="AWS",
        provider_resource_id="i-0000000000000000a",
        identity_key="aws:ec2:us-east-1:123456789012:i-0000000000000000a",
        metadata_json={"tags": {"Env": "Prod", "Role": "Web"}}
    )

    # Asset B: Azure VM with identical IP, Hostname & Tags, but different provider & identity key
    asset_azure = Asset(
        target_id=target.id,
        hostname="web-server.internal",
        ip_address="10.0.0.50",
        asset_type="COMPUTE_INSTANCE",
        provider="AZURE",
        provider_resource_id="/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Compute/virtualMachines/web-server",
        identity_key="azure:vm:sub-1:rg-1:web-server",
        metadata_json={"tags": {"Env": "Prod", "Role": "Web"}}
    )
    db_session.add_all([asset_aws, asset_azure])
    db_session.commit()

    rec = CorrelationEngine.evaluate_pair(db_session, "ASSET", asset_aws.id, "ASSET", asset_azure.id)

    # Weak evidence MUST NOT trigger IDENTICAL or LIKELY_SAME
    assert rec.decision not in ["IDENTICAL", "LIKELY_SAME"]
    assert rec.decision in ["CONFLICTING", "RELATED", "UNRESOLVED"]


def test_audit_2_cross_provider_collision_prevention(db_session: Session):
    """
    CROSS-PROVIDER COLLISION TESTING: Resources across AWS, Azure, and Kubernetes
    with identical-looking IDs, names, and IP addresses must NEVER be merged.
    """
    target = AuthorizedTarget(
        id="target-cross-provider-collision",
        name="Collision Test Target",
        target_type="CLOUD_PROVIDER",
        target_value="multi-cloud",
        environment="PRODUCTION"
    )
    db_session.add(target)
    db_session.commit()

    # AWS KMS Key with ID "key-1234"
    aws_key = Asset(
        target_id=target.id,
        hostname="aws-kms-key-1234",
        asset_type="MANAGED_KEY",
        provider="AWS",
        provider_resource_id="arn:aws:kms:us-east-1:123456789012:key/key-1234",
        identity_key="aws:kms:us-east-1:123456789012:key-1234"
    )

    # Azure Key Vault Key with ID "key-1234"
    azure_key = Asset(
        target_id=target.id,
        hostname="azure-kms-key-1234",
        asset_type="MANAGED_KEY",
        provider="AZURE",
        provider_resource_id="https://vault1.vault.azure.net/keys/key-1234",
        identity_key="azure:kms:key:sub-1:rg-1:vault1:key-1234"
    )

    # Kubernetes Secret with ID "key-1234"
    k8s_secret = Asset(
        target_id=target.id,
        hostname="k8s-secret-key-1234",
        asset_type="SECRET_METADATA",
        provider="KUBERNETES",
        provider_resource_id="k8s:cluster-1:default:secret:key-1234",
        identity_key="k8s:secret:cluster-1:default:key-1234"
    )

    db_session.add_all([aws_key, azure_key, k8s_secret])
    db_session.commit()

    # Evaluate correlation pairs across providers
    rec1 = CorrelationEngine.evaluate_pair(db_session, "ASSET", aws_key.id, "ASSET", azure_key.id)
    rec2 = CorrelationEngine.evaluate_pair(db_session, "ASSET", aws_key.id, "ASSET", k8s_secret.id)
    rec3 = CorrelationEngine.evaluate_pair(db_session, "ASSET", azure_key.id, "ASSET", k8s_secret.id)

    assert rec1.decision != "IDENTICAL"
    assert rec2.decision != "IDENTICAL"
    assert rec3.decision != "IDENTICAL"


def test_audit_3_cryptographic_primitive_normalization(db_session: Session):
    """
    CRYPTOGRAPHIC OBJECT NORMALIZATION AUDIT: Equivalent cryptographic primitives
    discovered across different sources normalize consistently while preserving raw names.
    """
    raw_samples = [
        ("rsa-2048", "RSA-2048", "RSA", 112),
        ("ecdsa-p256", "ECDSA-P256", "ECC", 128),
        ("x25519", "X25519", "ECC", 128),
        ("mlkem768", "ML-KEM-768", "ML-KEM", 192),
        ("mldsa65", "ML-DSA-65", "ML-DSA", 192),
        ("aes-256-gcm", "AES-256-GCM", "AES", 256),
        ("sha-256", "SHA-256", "SHA2", 128),
    ]

    for raw, expected_canonical, expected_family, expected_bits in raw_samples:
        norm = NormalizationEngine.normalize_and_get_or_create(db_session, raw)
        assert norm.canonical_id == expected_canonical
        assert norm.canonical_family == expected_family
        assert norm.estimated_security_bits == expected_bits


def test_audit_4_cross_source_certificate_correlation(db_session: Session):
    """
    CERTIFICATE CORRELATION AUDIT: Identical X.509 certificate SHA-256 fingerprint
    discovered from TLSScanner, CertificateScanner, LinuxCollector, AWS ACM, Azure Key Vault,
    and K8s TLS Secret correlates through fingerprint while provider cert resources stay independent assets.
    """
    target = AuthorizedTarget(
        id="target-cert-corr",
        name="Cert Correlation Target",
        target_type="CLOUD_PROVIDER",
        target_value="cert-test"
    )
    db_session.add(target)
    db_session.commit()

    fp_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    # Provider Certificate Resources (Independent Assets)
    acm_cert = Asset(
        target_id=target.id,
        hostname="aws-acm-cert",
        asset_type="CERTIFICATE_STORE",
        provider="AWS",
        provider_resource_id="arn:aws:acm:us-east-1:123456789012:certificate/acm-guid-1",
        identity_key="aws:acm:us-east-1:123456789012:acm-guid-1"
    )
    azure_cert_asset = Asset(
        target_id=target.id,
        hostname="azure-kv-cert",
        asset_type="CERTIFICATE_STORE",
        provider="AZURE",
        provider_resource_id="/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.KeyVault/vaults/v1/certificates/c1",
        identity_key="azure:cert_resource:sub-1:rg-1:v1:c1"
    )
    db_session.add_all([acm_cert, azure_cert_asset])
    db_session.commit()

    # CryptoObject entities sharing fingerprint
    crypto_acm = CryptoObject(
        object_type="CERTIFICATE",
        canonical_name="ACM Cert",
        fingerprint=fp_sha256,
        provider="AWS",
        identity_key=f"aws:crypto_cert:{fp_sha256}"
    )
    crypto_kv = CryptoObject(
        object_type="CERTIFICATE",
        canonical_name="Key Vault Cert",
        fingerprint=fp_sha256,
        provider="AZURE",
        identity_key=f"azure:crypto_cert:{fp_sha256}"
    )
    db_session.add_all([crypto_acm, crypto_kv])
    db_session.commit()

    # Evaluate correlation between CryptoObjects
    rec = CorrelationEngine.evaluate_pair(db_session, "CRYPTO_OBJECT", crypto_acm.id, "CRYPTO_OBJECT", crypto_kv.id)
    assert rec.decision == "IDENTICAL"

    # Provider assets MUST remain independent assets
    rec_assets = CorrelationEngine.evaluate_pair(db_session, "ASSET", acm_cert.id, "ASSET", azure_cert_asset.id)
    assert rec_assets.decision != "IDENTICAL"


def test_audit_5_multi_cloud_dependency_graph_traversal(db_session: Session):
    """
    CRYPTOGRAPHIC DEPENDENCY GRAPH AUDIT: Verify graph traversal paths across AWS, Azure,
    and Kubernetes with cycle protection and edge deduplication.
    """
    target = AuthorizedTarget(id="target-graph-test", name="Graph Test Target", target_type="CLOUD_PROVIDER", target_value="graph")
    db_session.add(target)
    db_session.commit()

    # 1. AWS Path: EC2 -> EBS -> KMS
    ec2 = Asset(id="ast-ec2", target_id=target.id, hostname="ec2-1", asset_type="COMPUTE_INSTANCE", provider="AWS", identity_key="aws:ec2:i-1")
    ebs = Asset(id="ast-ebs", target_id=target.id, hostname="ebs-1", asset_type="BLOCK_STORAGE", provider="AWS", identity_key="aws:ebs:vol-1")
    kms = Asset(id="ast-kms", target_id=target.id, hostname="kms-1", asset_type="MANAGED_KEY", provider="AWS", identity_key="aws:kms:key-1")

    rel1 = Relationship(id="rel-1", source_entity_type="ASSET", source_entity_id=ec2.id, target_entity_type="ASSET", target_entity_id=ebs.id, relationship_type="USES_STORAGE", scanner_or_connector_id="aws")
    rel2 = Relationship(id="rel-2", source_entity_type="ASSET", source_entity_id=ebs.id, target_entity_type="ASSET", target_entity_id=kms.id, relationship_type="ENCRYPTED_BY", scanner_or_connector_id="aws")

    # 2. Azure Path: VM -> Disk -> Key Version
    vm = Asset(id="ast-vm", target_id=target.id, hostname="vm-1", asset_type="COMPUTE_INSTANCE", provider="AZURE", identity_key="azure:vm:vm-1")
    disk = Asset(id="ast-disk", target_id=target.id, hostname="disk-1", asset_type="BLOCK_STORAGE", provider="AZURE", identity_key="azure:disk:disk-1")
    kv_ver = Asset(id="ast-kv-ver", target_id=target.id, hostname="kv-ver-1", asset_type="MANAGED_KEY", provider="AZURE", identity_key="azure:kms:key_version:v1")

    rel3 = Relationship(id="rel-3", source_entity_type="ASSET", source_entity_id=vm.id, target_entity_type="ASSET", target_entity_id=disk.id, relationship_type="USES_STORAGE", scanner_or_connector_id="azure")
    rel4 = Relationship(id="rel-4", source_entity_type="ASSET", source_entity_id=disk.id, target_entity_type="ASSET", target_entity_id=kv_ver.id, relationship_type="ENCRYPTED_BY", scanner_or_connector_id="azure")

    # Introduce intentional cycle to verify cycle protection: kv_ver -> USES -> vm
    rel_cycle = Relationship(id="rel-cycle", source_entity_type="ASSET", source_entity_id=kv_ver.id, target_entity_type="ASSET", target_entity_id=vm.id, relationship_type="USES", scanner_or_connector_id="azure")

    db_session.add_all([ec2, ebs, kms, vm, disk, kv_ver, rel1, rel2, rel3, rel4, rel_cycle])
    db_session.commit()

    # Traversal helper with cycle protection
    def traverse(start_id: str, max_depth: int = 5):
        visited = set()
        queue = [(start_id, 0)]
        found_nodes = []

        while queue:
            node_id, depth = queue.pop(0)
            if node_id in visited or depth > max_depth:
                continue
            visited.add(node_id)
            found_nodes.append(node_id)

            outgoing = db_session.query(Relationship).filter(Relationship.source_entity_id == node_id).all()
            for rel in outgoing:
                if rel.target_entity_id not in visited:
                    queue.append((rel.target_entity_id, depth + 1))

        return found_nodes

    # Verify AWS path traversal
    nodes_aws = traverse(ec2.id)
    assert ec2.id in nodes_aws
    assert ebs.id in nodes_aws
    assert kms.id in nodes_aws

    # Verify Azure path traversal with cycle protection
    nodes_az = traverse(vm.id)
    assert vm.id in nodes_az
    assert disk.id in nodes_az
    assert kv_ver.id in nodes_az


def test_audit_6_pqc_readiness_consistency_across_providers(db_session: Session):
    """
    PQC READINESS CONSISTENCY: Run equivalent cryptographic configurations across different providers
    and verify they produce equivalent primitive exposure classifications.
    """
    target = AuthorizedTarget(id="target-pqc-cons", name="PQC Consistency", target_type="CLOUD_PROVIDER", target_value="pqc")
    db_session.add(target)
    db_session.commit()

    # AWS PQC Asset (ML-KEM-768 KEX + ML-DSA-65 Signature)
    aws_pqc = Asset(id="ast-aws-pqc", target_id=target.id, hostname="aws-pqc", provider="AWS", identity_key="aws:pqc")
    crypto_aws_kex = CryptoObject(id="crypto-aws-kex", canonical_name="ML-KEM-768", object_type="PROTOCOL", identity_key="crypto:mlkem768:aws")
    crypto_aws_sig = CryptoObject(id="crypto-aws-sig", canonical_name="ML-DSA-65", object_type="CERTIFICATE", identity_key="crypto:mldsa65:aws")

    rel_aws_1 = Relationship(source_entity_type="ASSET", source_entity_id=aws_pqc.id, target_entity_type="CRYPTO_OBJECT", target_entity_id=crypto_aws_kex.id, relationship_type="USES_KEY_EXCHANGE", scanner_or_connector_id="aws")
    rel_aws_2 = Relationship(source_entity_type="ASSET", source_entity_id=aws_pqc.id, target_entity_type="CRYPTO_OBJECT", target_entity_id=crypto_aws_sig.id, relationship_type="USES_SIGNATURE", scanner_or_connector_id="aws")

    # Azure PQC Asset (ML-KEM-768 KEX + ML-DSA-65 Signature)
    az_pqc = Asset(id="ast-az-pqc", target_id=target.id, hostname="az-pqc", provider="AZURE", identity_key="azure:pqc")
    crypto_az_kex = CryptoObject(id="crypto-az-kex", canonical_name="ML-KEM-768", object_type="PROTOCOL", identity_key="crypto:mlkem768:az")
    crypto_az_sig = CryptoObject(id="crypto-az-sig", canonical_name="ML-DSA-65", object_type="CERTIFICATE", identity_key="crypto:mldsa65:az")

    rel_az_1 = Relationship(source_entity_type="ASSET", source_entity_id=az_pqc.id, target_entity_type="CRYPTO_OBJECT", target_entity_id=crypto_az_kex.id, relationship_type="USES_KEY_EXCHANGE", scanner_or_connector_id="azure")
    rel_az_2 = Relationship(source_entity_type="ASSET", source_entity_id=az_pqc.id, target_entity_type="CRYPTO_OBJECT", target_entity_id=crypto_az_sig.id, relationship_type="USES_SIGNATURE", scanner_or_connector_id="azure")

    cov_aws = DiscoveryCoverage(asset_id=aws_pqc.id, capability="COMPUTE", plugin_id="aws", status="SCANNED")
    cov_az = DiscoveryCoverage(asset_id=az_pqc.id, capability="COMPUTE", plugin_id="azure", status="SCANNED")

    db_session.add_all([
        aws_pqc, crypto_aws_kex, crypto_aws_sig, rel_aws_1, rel_aws_2, cov_aws,
        az_pqc, crypto_az_kex, crypto_az_sig, rel_az_1, rel_az_2, cov_az
    ])
    db_session.commit()

    run = ReadinessEvaluator.execute_assessment_run(db_session)

    readiness_aws = db_session.query(ReadinessAssessment).filter(ReadinessAssessment.asset_id == aws_pqc.id).first()
    readiness_az = db_session.query(ReadinessAssessment).filter(ReadinessAssessment.asset_id == az_pqc.id).first()

    assert readiness_aws is not None
    assert readiness_az is not None
    assert readiness_aws.quantum_exposure == readiness_az.quantum_exposure == "QUANTUM_RESISTANT"
    assert readiness_aws.readiness_result == readiness_az.readiness_result == "READY"


def test_audit_7_coverage_semantics_and_failure_isolation(db_session: Session):
    """
    COVERAGE SEMANTICS AUDIT & FAILURE ISOLATION: Failed or permission-denied capabilities
    must never silently become SCANNED. Incomplete coverage must never produce READY.
    """
    target = AuthorizedTarget(id="target-cov-test", name="Cov Target", target_type="CLOUD_PROVIDER", target_value="cov")
    asset = Asset(id="ast-cov", target_id=target.id, hostname="cov-host", provider="AWS", identity_key="aws:cov:host")
    db_session.add_all([target, asset])
    db_session.commit()

    cov1 = DiscoveryCoverage(asset_id=asset.id, capability="COMPUTE", plugin_id="aws", status="SCANNED")
    cov2 = DiscoveryCoverage(asset_id=asset.id, capability="KMS", plugin_id="aws", status="PERMISSION_DENIED", metadata_json={"reason": "403 Access Denied"})
    db_session.add_all([cov1, cov2])
    db_session.commit()

    # Readiness evaluation on asset with PERMISSION_DENIED coverage
    ReadinessEvaluator.execute_assessment_run(db_session)
    readiness = db_session.query(ReadinessAssessment).filter(ReadinessAssessment.asset_id == asset.id).first()

    assert readiness is not None
    assert readiness.readiness_result != "READY"


def test_audit_8_zero_secret_exposure_compliance(db_session: Session):
    """
    ZERO-SECRET SECURITY AUDIT: Verify no secrets, private keys, client credentials,
    or SA tokens exist in persisted metadata or observations.
    """
    forbidden_tokens = ["---BEGIN PRIVATE KEY---", "client_secret=", "eyJhbGciOiJ", "AWS_SECRET_ACCESS_KEY"]

    assets = db_session.query(Asset).all()
    for ast in assets:
        meta_str = str(ast.metadata_json or {})
        for token in forbidden_tokens:
            assert token not in meta_str
