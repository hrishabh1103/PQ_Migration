import logging
from typing import AsyncIterator, Set, Dict, Any, Optional, List

from app.models.entities import TargetType
from app.scanners.base import ScanContext, RawFinding
from app.scanners.plugins import Connector, PluginType, PluginCapability, PluginRegistry
from app.collectors.observations import DiscoveryObservation
from app.connectors.aws_sdk_client import AWSSdkClient
from app.connectors.aws.modules.base_aws_module import BaseAWSModule, ModuleStatus
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

logger = logging.getLogger(__name__)

class AWSConnector(Connector):
    """
    AWS Cryptographic Discovery Connector plugin discovering cloud infrastructure,
    KMS key specs, X.509 ACM certificates, ELBv2 SSL policies, S3 encryption settings,
    RDS storage encryption, and CloudFront TLS configurations via read-only AWS APIs.
    """
    plugin_id = "aws"
    version = "1.0.0"
    plugin_type = PluginType.CONNECTOR
    supported_target_types: Set[TargetType] = {
        TargetType.CLOUD_PROVIDER,
        TargetType.CLOUD_SERVER,
        TargetType.CLOUD_KMS
    }
    capabilities: Set[PluginCapability] = {
        PluginCapability.CLOUD_RESOURCE,
        PluginCapability.CLOUD_COMPUTE,
        PluginCapability.CLOUD_STORAGE,
        PluginCapability.CLOUD_DATABASE,
        PluginCapability.CLOUD_LOAD_BALANCER,
        PluginCapability.CLOUD_CDN,
        PluginCapability.X509,
        PluginCapability.KMS,
        PluginCapability.ENCRYPTION_CONFIGURATION,
        PluginCapability.TLS_CONFIGURATION
    }

    def __init__(self):
        self.modules: List[BaseAWSModule] = [
            AWSIdentityModule(),
            AWSRegionModule(),
            EC2Module(),
            EBSModule(),
            KMSModule(),
            ACMModule(),
            ELBv2Module(),
            S3Module(),
            RDSModule(),
            CloudFrontModule()
        ]

    async def discover(
        self,
        target_value: str,
        target_type: TargetType,
        context: ScanContext
    ) -> AsyncIterator[RawFinding]:
        """
        Legacy discover compatibility wrapper yielding RawFinding stream.
        """
        async for obs in self.collect(target_value, target_type, context):
            yield RawFinding(
                scanner_id=self.plugin_id,
                scanner_version=self.version,
                raw_algorithm_name=getattr(obs, "raw_algorithm_name", "AWS_RESOURCE"),
                finding_type=getattr(obs, "finding_type", "CLOUD_RESOURCE"),
                location_identifier=getattr(obs, "provider_resource_id", target_value),
                evidence_snippet=f"AWSConnector observation: {obs.__class__.__name__}",
                confidence=getattr(obs, "confidence", "HIGH"),
                metadata_json=getattr(obs, "metadata_json", {})
            )

    async def collect(
        self,
        target_value: str,
        target_type: TargetType,
        context: ScanContext,
        allowed_regions: Optional[List[str]] = None,
        profile_name: Optional[str] = None,
        role_arn: Optional[str] = None,
        **kwargs
    ) -> AsyncIterator[DiscoveryObservation]:
        """
        Primary entry point performing AWS read-only discovery sync across authorized regions & services.
        Yields structured DiscoveryObservation items with service & region failure isolation.
        """
        logger.info(f"Starting AWSConnector sync for target '{target_value}'...")

        # Initialize AWS SDK Client
        default_region = allowed_regions[0] if allowed_regions else "us-east-1"
        sdk_client = AWSSdkClient(
            region_name=default_region,
            profile_name=profile_name,
            role_arn=role_arn
        )

        # 1. Identity Validation
        identity_val = sdk_client.validate_identity()
        account_id = identity_val.get("account_id", "unknown-account")
        target_id = getattr(context, "target_id", "aws-target-1")

        # 2. Regional Scoping
        active_regions: List[str] = []
        if allowed_regions:
            active_regions = allowed_regions
        else:
            active_regions = [default_region]

        logger.info(f"AWSConnector target account '{account_id}', authorized regions: {active_regions}")

        # 3. Global & Identity Modules Execution
        yield_count = 0
        try:
            async for obs in AWSIdentityModule().collect(sdk_client, account_id, default_region, target_id):
                yield_count += 1
                yield obs
        except Exception as e:
            logger.error(f"AWSIdentityModule failed: {sdk_client.classify_error(e)}")

        try:
            async for obs in AWSRegionModule().collect(sdk_client, account_id, default_region, target_id, allowlist=active_regions):
                yield_count += 1
                yield obs
        except Exception as e:
            logger.error(f"AWSRegionModule failed: {sdk_client.classify_error(e)}")

        # Global S3 and CloudFront Modules (executed once at account level)
        try:
            async for obs in S3Module().collect(sdk_client, account_id, default_region, target_id):
                yield_count += 1
                yield obs
        except Exception as e:
            logger.error(f"S3Module failed: {sdk_client.classify_error(e)}")

        try:
            async for obs in CloudFrontModule().collect(sdk_client, account_id, default_region, target_id):
                yield_count += 1
                yield obs
        except Exception as e:
            logger.error(f"CloudFrontModule failed: {sdk_client.classify_error(e)}")

        # 4. Regional Modules Execution with Strict Region & Service Failure Isolation
        regional_modules = [
            EC2Module(),
            EBSModule(),
            KMSModule(),
            ACMModule(),
            ELBv2Module(),
            RDSModule()
        ]

        for reg in active_regions:
            logger.info(f"Executing regional discovery for AWS region '{reg}'...")
            for mod in regional_modules:
                try:
                    async for obs in mod.collect(sdk_client, account_id, reg, target_id):
                        yield_count += 1
                        yield obs
                except Exception as e:
                    err_cls = sdk_client.classify_error(e)
                    logger.warning(f"Module '{mod.module_name}' failed in region '{reg}' [{err_cls}]: {e}")

        logger.info(f"AWSConnector sync completed for account '{account_id}'. Total observations: {yield_count}")

# Register AWSConnector in PluginRegistry
PluginRegistry.register(AWSConnector())
