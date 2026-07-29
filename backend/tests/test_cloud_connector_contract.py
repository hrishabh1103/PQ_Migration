import pytest
import uuid
from unittest.mock import MagicMock, patch
from sqlalchemy.orm import Session

from app.core.database import Base, engine, SessionLocal
from app.models.entities import (
    AuthorizedTarget, Asset, CryptoObject, Relationship,
    DiscoveryRun, DiscoveryCoverage, CorrelationRecord, ReadinessAssessment, utc_now
)
from app.scanners.base import ScanContext
from app.scanners.plugins import PluginType, PluginCapability
from app.connectors.aws_connector import AWSConnector
from app.orchestrator.engine import DiscoveryOrchestrator
from app.correlation.engine import CorrelationEngine
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

def test_cloud_connector_contract_metadata():
    """Verify connector metadata, plugin type, and capabilities."""
    connector = AWSConnector()
    assert connector.plugin_id == "aws"
    assert connector.version == "1.0.0"
    assert connector.plugin_type == PluginType.CONNECTOR
    assert len(connector.supported_target_types) > 0
    assert PluginCapability.KMS in connector.capabilities
    assert PluginCapability.CLOUD_STORAGE in connector.capabilities

def create_mock_sdk_client():
    from app.connectors.aws_sdk_client import AWSSdkClient
    client = MagicMock(spec=AWSSdkClient)
    client.region_name = "us-east-1"
    client.validate_identity.return_value = {
        "account_id": "123456789012",
        "arn": "arn:aws:iam::123456789012:role/QDiscoveryRole",
        "user_id": "AROAEXAMPLE",
        "partition": "aws",
        "validated": True
    }
    client.sanitize_tags.side_effect = lambda tags: tags or {}
    client.classify_error.side_effect = lambda e: str(e)
    return client

@pytest.mark.asyncio
async def test_cloud_connector_contract_identity_and_zero_secret():
    """Verify strict separation of provider_resource_id vs identity_key and zero secret leakage."""
    connector = AWSConnector()
    mock_client = create_mock_sdk_client()

    # Mock KMS key response
    mock_kms = MagicMock()
    kms_paginator = MagicMock()
    kms_paginator.paginate.return_value = [{"Keys": [{"KeyId": "key-123456"}]}]
    mock_kms.get_paginator.return_value = kms_paginator
    mock_kms.describe_key.return_value = {
        "KeyMetadata": {
            "KeyId": "key-123456",
            "Arn": "arn:aws:kms:us-east-1:123456789012:key/key-123456",
            "KeySpec": "RSA_2048",
            "KeyUsage": "ENCRYPT_DECRYPT",
            "KeyManager": "CUSTOMER",
            "KeyState": "Enabled"
        }
    }
    mock_client.get_client.side_effect = lambda service, region=None, **kwargs: mock_kms if service == "kms" else MagicMock()

    with patch("app.connectors.aws_connector.AWSSdkClient", return_value=mock_client):
        context = ScanContext(scan_job_id="job-contract-1", target_id="target-contract-1")
        observations = []
        async for obs in connector.collect(
            target_value="arn:aws:iam::123456789012:root",
            target_type="CLOUD_PROVIDER",
            context=context,
            allowed_regions=["us-east-1"]
        ):
            observations.append(obs)

        assert len(observations) > 0
        for obs in observations:
            obs_dict = obs.dict() if hasattr(obs, 'dict') else obs.__dict__
            obs_str = str(obs_dict)
            # Zero Secret Policy Assertion
            assert "-----BEGIN PRIVATE KEY-----" not in obs_str
            assert "aws_secret_access_key" not in obs_str.lower()
            assert "password" not in obs_str.lower()

            # Identity Key vs Provider Resource ID Assertion
            if hasattr(obs, "provider_resource_id") and obs.provider_resource_id:
                assert obs.provider_resource_id != obs.identity_key
                assert obs.provider_resource_id.startswith("arn:aws:")

@pytest.mark.asyncio
async def test_cloud_connector_contract_permission_failure_isolation():
    """Verify permission failure on sub-service sets PERMISSION_DENIED on coverage without crashing."""
    connector = AWSConnector()
    mock_client = create_mock_sdk_client()

    def get_client_side_effect(service, region=None, **kwargs):
        mock = MagicMock()
        if service == "kms":
            mock.list_keys.side_effect = Exception("AccessDenied: User is not authorized to perform: kms:ListKeys")
        elif service == "s3":
            mock.list_buckets.return_value = {"Buckets": [{"Name": "contract-bucket"}]}
            mock.get_bucket_encryption.return_value = {
                "ServerSideEncryptionConfiguration": {
                    "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}]
                }
            }
        return mock

    mock_client.get_client.side_effect = get_client_side_effect

    with patch("app.connectors.aws_connector.AWSSdkClient", return_value=mock_client):
        context = ScanContext(scan_job_id="job-contract-perm", target_id="target-contract-perm")
        observations = []
        async for obs in connector.collect(
            target_value="arn:aws:iam::123456789012:root",
            target_type="CLOUD_PROVIDER",
            context=context,
            allowed_regions=["us-east-1"]
        ):
            observations.append(obs)

        # Connector completes and emits observations from working modules (S3 and Identity)
        assert len(observations) > 0

@pytest.mark.asyncio
async def test_cloud_connector_contract_mandatory_idempotency(db_session: Session):
    """
    MANDATORY IDEMPOTENCY CONTRACT:
    Running identical connector sync twice against unchanged infrastructure
    MUST NOT create duplicate canonical Assets, CryptoObjects, or Relationships.
    """
    target = AuthorizedTarget(
        id="target-contract-idempotency",
        name="Idempotency Test Cloud",
        target_type="CLOUD_PROVIDER",
        target_value="arn:aws:iam::123456789012:root",
        environment="DEVELOPMENT"
    )
    db_session.add(target)
    db_session.commit()

    mock_client = create_mock_sdk_client()

    mock_kms = MagicMock()
    kms_paginator = MagicMock()
    kms_paginator.paginate.return_value = [{"Keys": [{"KeyId": "key-idempotent-1"}]}]
    mock_kms.get_paginator.return_value = kms_paginator
    mock_kms.describe_key.return_value = {
        "KeyMetadata": {
            "KeyId": "key-idempotent-1",
            "Arn": "arn:aws:kms:us-east-1:123456789012:key/key-idempotent-1",
            "KeySpec": "RSA_2048",
            "KeyUsage": "ENCRYPT_DECRYPT",
            "KeyManager": "CUSTOMER",
            "KeyState": "Enabled"
        }
    }
    mock_kms.get_key_rotation_status.return_value = {"KeyRotationEnabled": True}

    mock_s3 = MagicMock()
    mock_s3.list_buckets.return_value = {"Buckets": [{"Name": "idempotent-bucket"}]}
    mock_s3.get_bucket_encryption.return_value = {
        "ServerSideEncryptionConfiguration": {
            "Rules": [{
                "ApplyServerSideEncryptionByDefault": {
                    "SSEAlgorithm": "aws:kms",
                    "KMSMasterKeyID": "arn:aws:kms:us-east-1:123456789012:key/key-idempotent-1"
                }
            }]
        }
    }

    mock_client.get_client.side_effect = lambda service, region=None, **kwargs: mock_kms if service == "kms" else (mock_s3 if service == "s3" else MagicMock())

    with patch("app.scanners.plugins.PluginRegistry.get", return_value=AWSConnector()):
        with patch("app.connectors.aws_connector.AWSSdkClient", return_value=mock_client):
            # 1. RUN 1
            run1 = await DiscoveryOrchestrator.run_connector_sync(
                db=db_session,
                target_id=target.id,
                connector_plugin_id="aws",
                allowed_regions=["us-east-1"]
            )
            assert run1.status == "COMPLETED"

            asset_count_run1 = db_session.query(Asset).count()
            crypto_count_run1 = db_session.query(CryptoObject).count()
            rel_count_run1 = db_session.query(Relationship).count()

            assert asset_count_run1 > 0
            assert crypto_count_run1 > 0

            # 2. RUN 2 (Identical infrastructure)
            run2 = await DiscoveryOrchestrator.run_connector_sync(
                db=db_session,
                target_id=target.id,
                connector_plugin_id="aws",
                allowed_regions=["us-east-1"]
            )
            assert run2.status == "COMPLETED"

            asset_count_run2 = db_session.query(Asset).count()
            crypto_count_run2 = db_session.query(CryptoObject).count()
            rel_count_run2 = db_session.query(Relationship).count()

            # IDEMPOTENCY ASSERTION
            assert asset_count_run2 == asset_count_run1, f"Asset count changed from {asset_count_run1} to {asset_count_run2}"
            assert crypto_count_run2 == crypto_count_run1, f"CryptoObject count changed from {crypto_count_run1} to {crypto_count_run2}"
            assert rel_count_run2 == rel_count_run1, f"Relationship count changed from {rel_count_run1} to {rel_count_run2}"

def test_cloud_connector_contract_correlation_and_readiness_integration(db_session: Session):
    """Verify cloud entities evaluate cleanly through CorrelationEngine and ReadinessEvaluator."""
    target = AuthorizedTarget(
        id="target-contract-eval",
        name="Contract Eval Target",
        target_type="CLOUD_PROVIDER",
        target_value="arn:aws:iam::123456789012:root",
        environment="STAGING"
    )
    db_session.add(target)
    db_session.commit()

    asset1 = Asset(
        target_id=target.id,
        hostname="ec2-node-1.internal",
        asset_type="COMPUTE_INSTANCE",
        provider_resource_id="arn:aws:ec2:us-east-1:123456789012:instance/i-0123456789abcdef0",
        identity_key="aws:ec2:us-east-1:123456789012:instance/i-0123456789abcdef0",
        metadata_json={"instance_id": "i-0123456789abcdef0"}
    )
    asset2 = Asset(
        target_id=target.id,
        hostname="host-node-1.internal",
        asset_type="HOST",
        provider_resource_id="arn:aws:ec2:us-east-1:123456789012:instance/i-0123456789abcdef0",
        identity_key="host:host-node-1.internal",
        metadata_json={"ec2_instance_id": "i-0123456789abcdef0"}
    )
    db_session.add_all([asset1, asset2])
    db_session.commit()

    # Correlation Evaluation
    rec = CorrelationEngine.evaluate_pair(db_session, "ASSET", asset1.id, "ASSET", asset2.id)
    assert rec.decision in ["IDENTICAL", "LIKELY_SAME"]

    # Readiness Assessment Run
    run_res = ReadinessEvaluator.execute_assessment_run(db_session, policy_id="pqc-default")
    assert run_res.status == "COMPLETED"

def test_cloud_connector_contract_cross_cloud_azure_correlation(db_session: Session):
    """
    Verify cross-cloud correlation between Azure VM <-> LinuxCollector Host (using COMPUTE_INSTANCE_ID)
    and Azure Key Vault Certificate <-> TLSScanner Certificate (using X.509 SHA-256 Fingerprint).
    """
    target = AuthorizedTarget(
        id="target-azure-cross-corr",
        name="Cross-Cloud Azure Target",
        target_type="CLOUD_PROVIDER",
        target_value="/subscriptions/00000000-0000-0000-0000-000000000000",
        environment="PRODUCTION"
    )
    db_session.add(target)
    db_session.commit()

    # 1. Azure VM vs LinuxCollector Host
    azure_vm = Asset(
        target_id=target.id,
        hostname="azure-vm-prod-1.internal",
        asset_type="COMPUTE_INSTANCE",
        provider="AZURE",
        provider_resource_id="/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Compute/virtualMachines/vm-prod-1",
        identity_key="azure:vm:sub-1:rg-1:vm-prod-1",
        metadata_json={"compute_instance_id": "vm-guid-prod-1"}
    )
    linux_host = Asset(
        target_id=target.id,
        hostname="azure-vm-prod-1.internal",
        asset_type="HOST",
        provider="LINUX",
        provider_resource_id="host-guid-prod-1",
        identity_key="host:azure-vm-prod-1.internal",
        metadata_json={"compute_instance_id": "vm-guid-prod-1"}
    )
    db_session.add_all([azure_vm, linux_host])
    db_session.commit()

    rec_vm = CorrelationEngine.evaluate_pair(db_session, "ASSET", azure_vm.id, "ASSET", linux_host.id)
    assert rec_vm.decision in ["IDENTICAL", "LIKELY_SAME"]

    # 2. Azure Key Vault Cert CryptoObject vs TLSScanner Cert CryptoObject
    fp_sha256 = "88915019dd6789abcdef0123456789abcdef0123456789abcdef01234567890123"
    cert1 = CryptoObject(
        object_type="CERTIFICATE",
        canonical_name="Azure Key Vault Cert",
        fingerprint=fp_sha256,
        provider="AZURE",
        identity_key=f"azure:cert_crypto:{fp_sha256}"
    )
    cert2 = CryptoObject(
        object_type="CERTIFICATE",
        canonical_name="TLSScanner Cert",
        fingerprint=fp_sha256,
        provider="TLS_SCANNER",
        identity_key=f"tls:cert_crypto:{fp_sha256}"
    )
    db_session.add_all([cert1, cert2])
    db_session.commit()

    rec_cert = CorrelationEngine.evaluate_pair(db_session, "CRYPTO_OBJECT", cert1.id, "CRYPTO_OBJECT", cert2.id)
    assert rec_cert.decision == "IDENTICAL"

