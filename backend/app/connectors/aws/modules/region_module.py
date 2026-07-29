import logging
from typing import AsyncIterator, List, Optional
from app.collectors.observations import AssetObservation, RelationshipObservation
from app.connectors.aws.modules.base_aws_module import BaseAWSModule
from app.connectors.aws_sdk_client import AWSSdkClient

logger = logging.getLogger(__name__)

class AWSRegionModule(BaseAWSModule):
    """
    Discovers enabled AWS regions and yields region assets linked to AWS Account.
    """
    module_name = "Regions"
    capability = "CLOUD_RESOURCE"

    async def collect(
        self,
        sdk_client: AWSSdkClient,
        account_id: str,
        region: str,
        target_id: str,
        allowlist: Optional[List[str]] = None
    ) -> AsyncIterator:
        ec2 = sdk_client.get_client("ec2", region_override="us-east-1")
        try:
            res = ec2.describe_regions(AllRegions=False)
            discovered_regions = [r["RegionName"] for r in res.get("Regions", [])]
        except Exception as e:
            logger.warning(f"Failed to describe regions, falling back to target region '{region}': {e}")
            discovered_regions = [region]

        target_account_arn = f"arn:aws:::{account_id}"

        for r_name in discovered_regions:
            if allowlist and r_name not in allowlist:
                continue

            r_arn = f"arn:aws:ec2:{r_name}:{account_id}:region"
            region_asset = AssetObservation(
                module_id="aws_region",
                provider_resource_id=r_arn,
                external_id=r_name,
                asset_type="cloud_region",
                asset_category="cloud",
                hostname=f"aws-region-{r_name}",
                metadata={"region_name": r_name, "account_id": account_id}
            )
            yield region_asset

            # Relationship: AWS_ACCOUNT -> CONTAINS -> AWS_REGION
            yield RelationshipObservation(
                module_id="aws_region",
                source_type="ASSET",
                source_id_hint=target_account_arn,
                target_type="ASSET",
                target_id_hint=r_arn,
                relationship_type="CONTAINS",
                confidence="HIGH"
            )
