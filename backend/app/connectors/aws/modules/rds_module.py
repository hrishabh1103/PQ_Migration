import logging
from typing import AsyncIterator
from app.collectors.observations import AssetObservation, RelationshipObservation
from app.connectors.aws.modules.base_aws_module import BaseAWSModule
from app.connectors.aws_sdk_client import AWSSdkClient

logger = logging.getLogger(__name__)

class RDSModule(BaseAWSModule):
    """
    Discovers RDS Database instances, DB engines, storage encryption status, KMS keys, and DB CA certificates.
    CRITICAL SECURITY RULE: NEVER connects to the database engine.
    """
    module_name = "RDS"
    capability = "CLOUD_DATABASE"

    async def collect(
        self,
        sdk_client: AWSSdkClient,
        account_id: str,
        region: str,
        target_id: str
    ) -> AsyncIterator:
        rds = sdk_client.get_client("rds", region_override=region)
        paginator = rds.get_paginator("describe_db_instances")

        region_arn = f"arn:aws:ec2:{region}:{account_id}:region"

        for page in paginator.paginate():
            for db in page.get("DBInstances", []):
                db_id = db.get("DBInstanceIdentifier")
                db_arn = db.get("DBInstanceArn", f"arn:aws:rds:{region}:{account_id}:db:{db_id}")
                if not db_id:
                    continue

                encrypted = db.get("StorageEncrypted", False)
                kms_key_id = db.get("KmsKeyId")
                ca_cert_id = db.get("CACertificateIdentifier")
                endpoint = db.get("Endpoint", {})

                db_asset = AssetObservation(
                    module_id="aws_rds",
                    provider_resource_id=db_arn,
                    external_id=db_id,
                    asset_type="cloud_database",
                    asset_category="database",
                    hostname=endpoint.get("Address") or db_id,
                    metadata={
                        "db_instance_identifier": db_id,
                        "engine": db.get("Engine"),
                        "engine_version": db.get("EngineVersion"),
                        "storage_encrypted": encrypted,
                        "kms_key_arn": kms_key_id,
                        "ca_certificate_identifier": ca_cert_id,
                        "region": region,
                        "account_id": account_id
                    }
                )
                yield db_asset

                # Relationship: AWS_REGION -> CONTAINS -> RDS_DB
                yield RelationshipObservation(
                    module_id="aws_rds",
                    source_type="ASSET",
                    source_id_hint=region_arn,
                    target_type="ASSET",
                    target_id_hint=db_arn,
                    relationship_type="CONTAINS",
                    confidence="HIGH"
                )

                # Storage Encryption Relationship: RDS -> ENCRYPTED_BY -> KMS_KEY
                if encrypted and kms_key_id:
                    yield RelationshipObservation(
                        module_id="aws_rds",
                        source_type="ASSET",
                        source_id_hint=db_arn,
                        target_type="ASSET",
                        target_id_hint=kms_key_id,
                        relationship_type="ENCRYPTED_BY",
                        confidence="HIGH"
                    )
