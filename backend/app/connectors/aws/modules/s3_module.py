import logging
from typing import AsyncIterator
from app.collectors.observations import AssetObservation, RelationshipObservation
from app.connectors.aws.modules.base_aws_module import BaseAWSModule
from app.connectors.aws_sdk_client import AWSSdkClient

logger = logging.getLogger(__name__)

class S3Module(BaseAWSModule):
    """
    Discovers S3 bucket metadata and default server-side encryption configurations (SSE-S3, SSE-KMS, DSSE-KMS).
    CRITICAL SECURITY RULE: NEVER calls GetObject, HeadObject, or ListObjectsV2. Zero object content reads.
    """
    module_name = "S3"
    capability = "CLOUD_STORAGE"

    async def collect(
        self,
        sdk_client: AWSSdkClient,
        account_id: str,
        region: str,
        target_id: str
    ) -> AsyncIterator:
        s3 = sdk_client.get_client("s3", region_override="us-east-1")

        try:
            res = s3.list_buckets()
            buckets = res.get("Buckets", [])
        except Exception as e:
            logger.warning(f"S3 ListBuckets failed: {e}")
            return

        target_account_arn = f"arn:aws:::{account_id}"

        for b in buckets:
            b_name = b.get("Name")
            if not b_name:
                continue

            b_region = "us-east-1"
            try:
                loc_res = s3.get_bucket_location(Bucket=b_name)
                b_region = loc_res.get("LocationConstraint") or "us-east-1"
                if b_region == "EU":
                    b_region = "eu-west-1"
            except Exception:
                pass

            if region and b_region != region and region != "us-east-1":
                continue

            arn = f"arn:aws:s3:::{b_name}"

            sse_algorithm = "NONE"
            kms_master_key_id = None
            bucket_key_enabled = False

            try:
                enc_res = s3.get_bucket_encryption(Bucket=b_name)
                rules = enc_res.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
                if rules:
                    default_enc = rules[0].get("ApplyServerSideEncryptionByDefault", {})
                    sse_algorithm = default_enc.get("SSEAlgorithm", "AES256")
                    kms_master_key_id = default_enc.get("KMSMasterKeyID")
                    bucket_key_enabled = rules[0].get("BucketKeyEnabled", False)
            except Exception:
                sse_algorithm = "SSE-S3-DEFAULT"

            bucket_asset = AssetObservation(
                module_id="aws_s3",
                provider_resource_id=arn,
                external_id=b_name,
                asset_type="cloud_storage",
                asset_category="storage",
                hostname=f"{b_name}.s3.amazonaws.com",
                metadata={
                    "bucket_name": b_name,
                    "creation_date": str(b.get("CreationDate")),
                    "sse_algorithm": sse_algorithm,
                    "kms_key_arn": kms_master_key_id,
                    "bucket_key_enabled": bucket_key_enabled,
                    "region": b_region,
                    "account_id": account_id
                }
            )
            yield bucket_asset

            # Relationship: AWS_ACCOUNT -> CONTAINS -> S3_BUCKET
            yield RelationshipObservation(
                module_id="aws_s3",
                source_type="ASSET",
                source_id_hint=target_account_arn,
                target_type="ASSET",
                target_id_hint=arn,
                relationship_type="CONTAINS",
                confidence="HIGH"
            )

            # Encryption Relationship: S3_BUCKET -> ENCRYPTED_BY -> KMS_KEY
            if kms_master_key_id:
                yield RelationshipObservation(
                    module_id="aws_s3",
                    source_type="ASSET",
                    source_id_hint=arn,
                    target_type="ASSET",
                    target_id_hint=kms_master_key_id,
                    relationship_type="ENCRYPTED_BY",
                    confidence="HIGH"
                )
