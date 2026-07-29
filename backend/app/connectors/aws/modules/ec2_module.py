import logging
from typing import AsyncIterator
from app.collectors.observations import AssetObservation, RelationshipObservation
from app.connectors.aws.modules.base_aws_module import BaseAWSModule
from app.connectors.aws_sdk_client import AWSSdkClient

logger = logging.getLogger(__name__)

class EC2Module(BaseAWSModule):
    """
    Discovers EC2 instance virtual machines using paginated DescribeInstances.
    Zero-secret guardrail: Never reads instance user-data, credentials, or SSH keys.
    """
    module_name = "EC2"
    capability = "CLOUD_COMPUTE"

    async def collect(
        self,
        sdk_client: AWSSdkClient,
        account_id: str,
        region: str,
        target_id: str
    ) -> AsyncIterator:
        ec2 = sdk_client.get_client("ec2", region_override=region)
        paginator = ec2.get_paginator("describe_instances")

        region_arn = f"arn:aws:ec2:{region}:{account_id}:region"

        for page in paginator.paginate():
            for reservation in page.get("Reservations", []):
                for inst in reservation.get("Instances", []):
                    inst_id = inst.get("InstanceId")
                    if not inst_id:
                        continue

                    arn = f"arn:aws:ec2:{region}:{account_id}:instance/{inst_id}"
                    tags = sdk_client.sanitize_tags(inst.get("Tags", []))
                    inst_name = tags.get("Name") or inst_id

                    vm_asset = AssetObservation(
                        module_id="aws_ec2",
                        provider_resource_id=arn,
                        external_id=inst_id,
                        asset_type="cloud_vm",
                        asset_category="infrastructure",
                        hostname=inst.get("PrivateDnsName") or inst.get("PublicDnsName") or inst_name,
                        ip_address=inst.get("PrivateIpAddress") or inst.get("PublicIpAddress"),
                        os_distribution=inst.get("PlatformDetails") or inst.get("Platform") or "Linux/UNIX",
                        architecture=inst.get("Architecture"),
                        metadata={
                            "instance_id": inst_id,
                            "instance_type": inst.get("InstanceType"),
                            "state": inst.get("State", {}).get("Name"),
                            "vpc_id": inst.get("VpcId"),
                            "subnet_id": inst.get("SubnetId"),
                            "region": region,
                            "account_id": account_id,
                            "sanitized_tags": tags
                        }
                    )
                    yield vm_asset

                    # Relationship: AWS_REGION -> CONTAINS -> EC2_INSTANCE
                    yield RelationshipObservation(
                        module_id="aws_ec2",
                        source_type="ASSET",
                        source_id_hint=region_arn,
                        target_type="ASSET",
                        target_id_hint=arn,
                        relationship_type="CONTAINS",
                        confidence="HIGH"
                    )
