import pytest
import asyncio
from unittest.mock import MagicMock

from app.connectors.aws_sdk_client import AWSSdkClient
from app.connectors.aws_connector import AWSConnector
from app.connectors.aws.modules.identity_module import AWSIdentityModule
from app.connectors.aws.modules.region_module import AWSRegionModule
from app.connectors.aws.modules.ec2_module import EC2Module
from app.connectors.aws.modules.ebs_module import EBSModule
from app.connectors.aws.modules.kms_module import KMSModule
from app.connectors.aws.modules.acm_module import ACMModule
from app.connectors.aws.modules.elbv2_module import ELBv2Module
from app.connectors.aws.modules.s3_module import S3Module
from app.connectors.aws.modules.rds_module import RDSModule
from app.connectors.aws.modules.cloudfront_module import CloudFrontModule

@pytest.fixture
def mock_sdk_client():
    client = MagicMock(spec=AWSSdkClient)
    client.region_name = "us-east-1"
    client.validate_identity.return_value = {
        "account_id": "123456789012",
        "arn": "arn:aws:iam::123456789012:role/QDiscoveryRole",
        "user_id": "AROAEXAMPLE",
        "partition": "aws",
        "validated": True
    }
    client.sanitize_tags.side_effect = AWSSdkClient.sanitize_tags
    client.classify_error.side_effect = AWSSdkClient.classify_error
    return client

@pytest.mark.asyncio
async def test_aws_identity_module(mock_sdk_client):
    mod = AWSIdentityModule()
    obs_list = []
    async for obs in mod.collect(mock_sdk_client, "123456789012", "us-east-1", "target-1"):
        obs_list.append(obs)

    assert len(obs_list) == 1
    assert obs_list[0].asset_type == "cloud_account"
    assert obs_list[0].provider_resource_id == "arn:aws:::123456789012"
    assert obs_list[0].metadata["account_id"] == "123456789012"

@pytest.mark.asyncio
async def test_aws_region_module(mock_sdk_client):
    ec2_mock = MagicMock()
    ec2_mock.describe_regions.return_value = {
        "Regions": [{"RegionName": "us-east-1"}, {"RegionName": "ap-south-1"}]
    }
    mock_sdk_client.get_client.return_value = ec2_mock

    mod = AWSRegionModule()
    obs_list = []
    async for obs in mod.collect(mock_sdk_client, "123456789012", "us-east-1", "target-1", allowlist=["us-east-1"]):
        obs_list.append(obs)

    assert len(obs_list) == 2  # 1 AssetObservation + 1 RelationshipObservation
    assert obs_list[0].asset_type == "cloud_region"
    assert obs_list[0].external_id == "us-east-1"

@pytest.mark.asyncio
async def test_ec2_module(mock_sdk_client):
    ec2_mock = MagicMock()
    paginator_mock = MagicMock()
    paginator_mock.paginate.return_value = [{
        "Reservations": [{
            "Instances": [{
                "InstanceId": "i-0123456789abcdef0",
                "InstanceType": "t3.micro",
                "State": {"Name": "running"},
                "PrivateDnsName": "ip-10-0-1-5.ec2.internal",
                "PrivateIpAddress": "10.0.1.5",
                "Architecture": "x86_64",
                "PlatformDetails": "Linux/UNIX",
                "Tags": [{"Key": "Name", "Value": "Web-Prod"}]
            }]
        }]
    }]
    ec2_mock.get_paginator.return_value = paginator_mock
    mock_sdk_client.get_client.return_value = ec2_mock

    mod = EC2Module()
    obs_list = []
    async for obs in mod.collect(mock_sdk_client, "123456789012", "us-east-1", "target-1"):
        obs_list.append(obs)

    assert len(obs_list) == 2  # 1 Asset + 1 Relationship
    assert obs_list[0].asset_type == "cloud_vm"
    assert obs_list[0].external_id == "i-0123456789abcdef0"
    assert obs_list[0].ip_address == "10.0.1.5"

@pytest.mark.asyncio
async def test_ebs_module(mock_sdk_client):
    ec2_mock = MagicMock()
    paginator_mock = MagicMock()
    paginator_mock.paginate.return_value = [{
        "Volumes": [{
            "VolumeId": "vol-0987654321fedcba0",
            "Size": 100,
            "VolumeType": "gp3",
            "Encrypted": True,
            "KmsKeyId": "arn:aws:kms:us-east-1:123456789012:key/1234-5678-90ab-cdef",
            "State": "in-use",
            "Attachments": [{"InstanceId": "i-0123456789abcdef0"}]
        }]
    }]
    ec2_mock.get_paginator.return_value = paginator_mock
    mock_sdk_client.get_client.return_value = ec2_mock

    mod = EBSModule()
    obs_list = []
    async for obs in mod.collect(mock_sdk_client, "123456789012", "us-east-1", "target-1"):
        obs_list.append(obs)

    assert len(obs_list) == 3  # 1 Asset + 1 Attachment Rel + 1 Encryption Rel
    assert obs_list[0].asset_type == "cloud_storage"
    assert obs_list[0].external_id == "vol-0987654321fedcba0"

@pytest.mark.asyncio
async def test_kms_module_zero_crypto_ops(mock_sdk_client):
    kms_mock = MagicMock()
    paginator_mock = MagicMock()
    paginator_mock.paginate.return_value = [{
        "Keys": [{"KeyId": "1234-5678-90ab-cdef"}]
    }]
    kms_mock.get_paginator.return_value = paginator_mock
    kms_mock.describe_key.return_value = {
        "KeyMetadata": {
            "Arn": "arn:aws:kms:us-east-1:123456789012:key/1234-5678-90ab-cdef",
            "KeySpec": "RSA_4096",
            "KeyUsage": "ENCRYPT_DECRYPT",
            "KeyManager": "CUSTOMER",
            "KeyState": "Enabled",
            "Origin": "AWS_KMS"
        }
    }
    kms_mock.get_key_rotation_status.return_value = {"KeyRotationEnabled": True}
    mock_sdk_client.get_client.return_value = kms_mock

    mod = KMSModule()
    obs_list = []
    async for obs in mod.collect(mock_sdk_client, "123456789012", "us-east-1", "target-1"):
        obs_list.append(obs)

    assert len(obs_list) == 3  # 1 Key Asset + 1 CryptoObservation + 1 Relationship
    assert obs_list[0].asset_type == "kms_key"
    assert obs_list[1].canonical_name == "RSA-4096"

    # ASSERT ZERO CRYPTOGRAPHIC OPERATIONS WERE CALLED
    kms_mock.encrypt.assert_not_called()
    kms_mock.decrypt.assert_not_called()
    kms_mock.sign.assert_not_called()
    kms_mock.verify.assert_not_called()
    kms_mock.generate_data_key.assert_not_called()

@pytest.mark.asyncio
async def test_acm_module(mock_sdk_client):
    import datetime
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    # 1. Generate real self-signed X.509 test certificate
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "api.company.com")])
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
    ).sign(private_key, hashes.SHA256())

    pem_bytes = cert.public_bytes(serialization.Encoding.PEM)
    pem_str = pem_bytes.decode("utf-8")
    expected_fingerprint = cert.fingerprint(hashes.SHA256()).hex().lower()

    acm_mock = MagicMock()
    paginator_mock = MagicMock()
    paginator_mock.paginate.return_value = [{
        "CertificateSummaryList": [{"CertificateArn": "arn:aws:acm:us-east-1:123456789012:certificate/abc-123"}]
    }]
    acm_mock.get_paginator.return_value = paginator_mock
    acm_mock.describe_certificate.return_value = {
        "Certificate": {
            "DomainName": "api.company.com",
            "SubjectAlternativeNames": ["api.company.com"],
            "Issuer": "Amazon",
            "Serial": "0123456789ABCDEF",
            "Status": "ISSUED",
            "KeyAlgorithm": "RSA-2048",
            "SignatureAlgorithm": "SHA256withRSA"
        }
    }
    acm_mock.get_certificate.return_value = {"Certificate": pem_str}
    mock_sdk_client.get_client.return_value = acm_mock

    mod = ACMModule()
    obs_list = []
    async for obs in mod.collect(mock_sdk_client, "123456789012", "us-east-1", "target-1"):
        obs_list.append(obs)

    assert len(obs_list) == 1
    assert obs_list[0].subject == "CN=api.company.com"
    assert obs_list[0].pubkey_algo == "RSA-2048"
    # ASSERT ACM FINGERPRINT EQUALS CERTIFICATESCANNER FINGERPRINT EXACTLY
    assert obs_list[0].fingerprint == expected_fingerprint

    # 2. Test Malformed PEM -> fingerprint=None
    acm_mock.get_certificate.return_value = {"Certificate": "INVALID_PEM_DATA"}
    obs_list_malformed = []
    async for obs in mod.collect(mock_sdk_client, "123456789012", "us-east-1", "target-1"):
        obs_list_malformed.append(obs)
    assert obs_list_malformed[0].fingerprint is None

    # 3. Test AccessDenied / Exception -> fingerprint=None
    from botocore.exceptions import ClientError
    acm_mock.get_certificate.side_effect = ClientError({"Error": {"Code": "AccessDenied", "Message": "Access Denied"}}, "GetCertificate")
    obs_list_denied = []
    async for obs in mod.collect(mock_sdk_client, "123456789012", "us-east-1", "target-1"):
        obs_list_denied.append(obs)
    assert obs_list_denied[0].fingerprint is None

@pytest.mark.asyncio
async def test_s3_module_zero_object_access(mock_sdk_client):
    s3_mock = MagicMock()
    s3_mock.list_buckets.return_value = {
        "Buckets": [{"Name": "prod-data-bucket", "CreationDate": "2026-01-01T00:00:00Z"}]
    }
    s3_mock.get_bucket_location.return_value = {"LocationConstraint": "us-east-1"}
    s3_mock.get_bucket_encryption.return_value = {
        "ServerSideEncryptionConfiguration": {
            "Rules": [{
                "ApplyServerSideEncryptionByDefault": {
                    "SSEAlgorithm": "aws:kms",
                    "KMSMasterKeyID": "arn:aws:kms:us-east-1:123456789012:key/1234-5678"
                }
            }]
        }
    }
    mock_sdk_client.get_client.return_value = s3_mock

    mod = S3Module()
    obs_list = []
    async for obs in mod.collect(mock_sdk_client, "123456789012", "us-east-1", "target-1"):
        obs_list.append(obs)

    assert len(obs_list) == 3  # 1 S3 Bucket Asset + 1 Contains Rel + 1 KMS Encrypted Rel
    assert obs_list[0].asset_type == "cloud_storage"
    assert obs_list[0].external_id == "prod-data-bucket"

    # ASSERT ZERO S3 OBJECT ACCESS OPERATIONS
    s3_mock.get_object.assert_not_called()
    s3_mock.head_object.assert_not_called()
    s3_mock.list_objects.assert_not_called()
    s3_mock.list_objects_v2.assert_not_called()

def test_tag_sanitization_and_redaction():
    raw_tags = [
        {"Key": "Name", "Value": "Production-Cluster"},
        {"Key": "SecretToken", "Value": "eyJhbGciOiJIUzI1NiJ9"},
        {"Key": "Owner", "Value": "DevOps-Team"}
    ]
    sanitized = AWSSdkClient.sanitize_tags(raw_tags)
    assert sanitized["Name"] == "Production-Cluster"
    assert sanitized["Owner"] == "DevOps-Team"
    assert "SecretToken" not in sanitized or sanitized.get("SecretToken") == "[REDACTED]"
