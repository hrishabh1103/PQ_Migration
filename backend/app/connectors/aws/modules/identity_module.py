import logging
from typing import AsyncIterator
from app.collectors.observations import AssetObservation
from app.connectors.aws.modules.base_aws_module import BaseAWSModule
from app.connectors.aws_sdk_client import AWSSdkClient

logger = logging.getLogger(__name__)

class AWSIdentityModule(BaseAWSModule):
    """
    Validates AWS identity via STS GetCallerIdentity and yields canonical AWS Account Asset.
    """
    module_name = "Identity"
    capability = "IDENTITY"

    async def collect(
        self,
        sdk_client: AWSSdkClient,
        account_id: str,
        region: str,
        target_id: str
    ) -> AsyncIterator:
        val = sdk_client.validate_identity()
        acc_id = val.get("account_id", account_id)
        partition = val.get("partition", "aws")
        arn = val.get("arn", "")

        # Canonical AWS Account Asset
        account_asset = AssetObservation(
            module_id="aws_identity",
            provider_resource_id=f"arn:{partition}:::{acc_id}",
            external_id=acc_id,
            asset_type="cloud_account",
            asset_category="cloud",
            hostname=f"aws-account-{acc_id}",
            metadata={
                "account_id": acc_id,
                "arn": arn,
                "partition": partition,
                "validated": val.get("validated", False)
            }
        )
        yield account_asset
