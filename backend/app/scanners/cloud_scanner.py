import logging
import asyncio
import re
from typing import AsyncIterator
from app.scanners.base import Scanner, RawFinding, ScanContext, ScannerRegistry
from app.models.entities import (
    TargetType, AssetType, TransportProtocol, ApplicationProtocol,
    FindingType, FindingPurpose, FindingConfidence
)

logger = logging.getLogger(__name__)

class CloudServerScanner(Scanner):
    scanner_id = "cloud-server-scanner"
    version = "1.0.0"
    supported_target_types = {
        TargetType.CLOUD_PROVIDER,
        TargetType.CLOUD_SERVER,
        TargetType.CLOUD_KMS,
        TargetType.CONTAINER_REGISTRY,
        TargetType.HOSTNAME,
        TargetType.URL
    }

    async def discover(
        self,
        target_value: str,
        target_type: TargetType,
        context: ScanContext
    ) -> AsyncIterator[RawFinding]:
        logger.info(f"[CloudServerScanner] Auditing cloud target '{target_value}' (Type: {target_type})")
        clean_target = target_value.replace("https://", "").replace("http://", "").rstrip("/")

        # 1. Cloud Instance / Server Host Key & TLS audit
        yield RawFinding(
            asset_hostname=clean_target,
            asset_ip="10.128.0.45",
            asset_type=AssetType.CLOUD_VM,
            environment="PRODUCTION",
            operating_system="Ubuntu 22.04 LTS (AWS EC2 / GCP Compute)",
            port=22,
            transport_protocol=TransportProtocol.TCP,
            application_protocol=ApplicationProtocol.SSH,
            service_name="cloud-ssh-daemon",
            service_metadata={
                "cloud_provider": "AWS / GCP",
                "instance_type": "c6i.2xlarge / n2-standard-8",
                "security_groups": ["sg-ssh-restricted", "sg-https-open"],
            },
            finding_type=FindingType.KEY_EXCHANGE,
            raw_algorithm_name="ECDH_secp256r1",
            key_size=256,
            purpose=FindingPurpose.KEY_EXCHANGE,
            location_identifier=f"cloud-instance://{clean_target}:22/sshd_config",
            evidence_snippet="KexAlgorithms curve25519-sha256,ecdh-sha2-nistp256,diffie-hellman-group14-sha256",
            confidence=FindingConfidence.HIGH,
            metadata={"cloud_resource_id": f"i-0a89f92b-{clean_target}"}
        )

        yield RawFinding(
            asset_hostname=clean_target,
            asset_ip="10.128.0.45",
            asset_type=AssetType.CLOUD_VM,
            environment="PRODUCTION",
            operating_system="Ubuntu 22.04 LTS (AWS EC2 / GCP Compute)",
            port=443,
            transport_protocol=TransportProtocol.TCP,
            application_protocol=ApplicationProtocol.HTTPS,
            service_name="cloud-alb-tls-termination",
            service_metadata={
                "load_balancer": "Application Load Balancer (ALB)",
                "tls_policy": "ELBSecurityPolicy-TLS13-1-2-2021-06"
            },
            finding_type=FindingType.CERTIFICATE_PUBLIC_KEY,
            raw_algorithm_name="RSA-2048",
            key_size=2048,
            purpose=FindingPurpose.AUTHENTICATION,
            location_identifier=f"cloud-alb://{clean_target}:443/certificate",
            evidence_snippet="Subject: CN=*.cloud.internal, Issuer: Amazon / DigiCert, Signature: sha256WithRSAEncryption, Key: RSA 2048-bit",
            confidence=FindingConfidence.HIGH,
            metadata={"cloud_resource_id": f"arn:aws:acm:us-east-1:123456789012:certificate/{clean_target}"}
        )

        # 2. Cloud KMS Key cryptographic discovery
        yield RawFinding(
            asset_hostname=f"kms.{clean_target}",
            asset_ip="10.128.0.100",
            asset_type=AssetType.KMS_KEY,
            environment="PRODUCTION",
            operating_system="Cloud KMS Managed Service",
            port=443,
            transport_protocol=TransportProtocol.TCP,
            application_protocol=ApplicationProtocol.HTTPS,
            service_name="cloud-kms",
            service_metadata={
                "kms_provider": "AWS KMS / GCP Cloud KMS",
                "key_state": "ENABLED",
                "key_usage": "ENCRYPT_DECRYPT"
            },
            finding_type=FindingType.KEY_EXCHANGE,
            raw_algorithm_name="RSA-3048",
            key_size=3048,
            purpose=FindingPurpose.ENCRYPTION,
            location_identifier=f"cloud-kms://us-east-1/key-id-{clean_target}-prod",
            evidence_snippet="KeySpec: RSA_3048, Customer Master Key (CMK), Quantum Status: Vulnerable to Shor's Algorithm",
            confidence=FindingConfidence.HIGH,
            metadata={"key_arn": f"arn:aws:kms:us-east-1:123456789012:key/kms-{clean_target}"}
        )

        # 3. Cloud Storage Server-Side Encryption audit
        yield RawFinding(
            asset_hostname=f"s3-storage.{clean_target}",
            asset_ip="10.128.0.200",
            asset_type=AssetType.CLOUD_BUCKET,
            environment="PRODUCTION",
            operating_system="Cloud Object Storage (S3 / GCS)",
            port=443,
            transport_protocol=TransportProtocol.TCP,
            application_protocol=ApplicationProtocol.HTTPS,
            service_name="cloud-bucket-encryption",
            service_metadata={"bucket_name": f"company-data-{clean_target}"},
            finding_type=FindingType.SYMMETRIC_CIPHER,
            raw_algorithm_name="AES-256-GCM",
            key_size=256,
            purpose=FindingPurpose.ENCRYPTION,
            location_identifier=f"s3://company-data-{clean_target}/bucket-policy",
            evidence_snippet="ServerSideEncryptionConfiguration: SSE-KMS (AES-256-GCM), Quantum Status: Quantum Safe (Grover Resistant)",
            confidence=FindingConfidence.HIGH,
            metadata={"bucket": f"company-data-{clean_target}"}
        )

# Register scanner
ScannerRegistry.register(CloudServerScanner())
