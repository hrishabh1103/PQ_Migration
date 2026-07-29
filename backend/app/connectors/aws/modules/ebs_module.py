import logging
from typing import AsyncIterator
from app.collectors.observations import AssetObservation, RelationshipObservation
from app.connectors.aws.modules.base_aws_module import BaseAWSModule
from app.connectors.aws_sdk_client import AWSSdkClient

logger = logging.getLogger(__name__)

class EBSModule(BaseAWSModule):
    """
    Discovers EBS block volumes, encryption status, KMS key ARNs, and attachments to EC2 instances.
    """
    module_name = "EBS"
    capability = "CLOUD_STORAGE"

    async def collect(
        self,
        sdk_client: AWSSdkClient,
        account_id: str,
        region: str,
        target_id: str
    ) -> AsyncIterator:
        ec2 = sdk_client.get_client("ec2", region_override=region)
        paginator = ec2.get_paginator("describe_volumes")

        for page in paginator.paginate():
            for vol in page.get("Volumes", []):
                vol_id = vol.get("VolumeId")
                if not vol_id:
                    continue

                arn = f"arn:aws:ec2:{region}:{account_id}:volume/{vol_id}"
                encrypted = vol.get("Encrypted", False)
                kms_key_id = vol.get("KmsKeyId")

                vol_asset = AssetObservation(
                    module_id="aws_ebs",
                    provider_resource_id=arn,
                    external_id=vol_id,
                    asset_type="cloud_storage",
                    asset_category="storage",
                    hostname=f"ebs-volume-{vol_id}",
                    metadata={
                        "volume_id": vol_id,
                        "size_gb": vol.get("Size"),
                        "volume_type": vol.get("VolumeType"),
                        "encrypted": encrypted,
                        "kms_key_arn": kms_key_id,
                        "region": region,
                        "account_id": account_id
                    }
                )
                yield vol_asset

                # Volume attachment relationship: EC2_INSTANCE -> USES -> EBS_VOLUME
                for att in vol.get("Attachments", []):
                    inst_id = att.get("InstanceId")
                    if inst_id:
                        inst_arn = f"arn:aws:ec2:{region}:{account_id}:instance/{inst_id}"
                        yield RelationshipObservation(
                            module_id="aws_ebs",
                            source_type="ASSET",
                            source_id_hint=inst_arn,
                            target_type="ASSET",
                            target_id_hint=arn,
                            relationship_type="USES",
                            confidence="HIGH"
                        )

                # Volume encryption relationship: EBS_VOLUME -> ENCRYPTED_BY -> KMS_KEY
                if encrypted and kms_key_id:
                    yield RelationshipObservation(
                        module_id="aws_ebs",
                        source_type="ASSET",
                        source_id_hint=arn,
                        target_type="ASSET",
                        target_id_hint=kms_key_id,
                        relationship_type="ENCRYPTED_BY",
                        confidence="HIGH"
                    )
