import logging
from typing import AsyncIterator
from app.collectors.observations import AssetObservation, CryptoObservation, RelationshipObservation
from app.connectors.aws.modules.base_aws_module import BaseAWSModule
from app.connectors.aws_sdk_client import AWSSdkClient

logger = logging.getLogger(__name__)

KEY_SPEC_MAP = {
    "SYMMETRIC_DEFAULT": ("AES-256-GCM", "SYMMETRIC_CIPHER"),
    "RSA_2048": ("RSA-2048", "CERTIFICATE_PUBLIC_KEY"),
    "RSA_3072": ("RSA-3072", "CERTIFICATE_PUBLIC_KEY"),
    "RSA_4096": ("RSA-4096", "CERTIFICATE_PUBLIC_KEY"),
    "ECC_NIST_P256": ("ECDSA-P256", "SIGNATURE_ALGORITHM"),
    "ECC_NIST_P384": ("ECDSA-P384", "SIGNATURE_ALGORITHM"),
    "ECC_NIST_P521": ("ECDSA-P521", "SIGNATURE_ALGORITHM"),
    "ECC_SECG_P256K1": ("ECDSA-SECP256K1", "SIGNATURE_ALGORITHM"),
    "HMAC_256": ("HMAC-SHA256", "HASH_FUNCTION")
}

class KMSModule(BaseAWSModule):
    """
    Discovers Customer-Managed and AWS-Managed KMS Keys metadata using ListKeys, DescribeKey, and GetKeyRotationStatus.
    CRITICAL SECURITY RULE: NEVER calls Encrypt, Decrypt, Sign, Verify, or GenerateDataKey.
    """
    module_name = "KMS"
    capability = "KMS"

    async def collect(
        self,
        sdk_client: AWSSdkClient,
        account_id: str,
        region: str,
        target_id: str
    ) -> AsyncIterator:
        kms = sdk_client.get_client("kms", region_override=region)
        paginator = kms.get_paginator("list_keys")

        for page in paginator.paginate():
            for key_entry in page.get("Keys", []):
                key_id = key_entry.get("KeyId")
                if not key_id:
                    continue

                try:
                    desc_res = kms.describe_key(KeyId=key_id)
                    key_meta = desc_res.get("KeyMetadata", {})
                except Exception as e:
                    logger.warning(f"KMS DescribeKey failed for KeyId '{key_id}': {e}")
                    continue

                arn = key_meta.get("Arn", f"arn:aws:kms:{region}:{account_id}:key/{key_id}")
                key_spec = key_meta.get("CustomerMasterKeySpec") or key_meta.get("KeySpec", "SYMMETRIC_DEFAULT")
                key_usage = key_meta.get("KeyUsage", "ENCRYPT_DECRYPT")
                key_manager = key_meta.get("KeyManager", "CUSTOMER")

                # Check rotation status for CUSTOMER managed keys
                rotation_enabled = False
                if key_manager == "CUSTOMER" and key_meta.get("KeyState") == "Enabled":
                    try:
                        rot_res = kms.get_key_rotation_status(KeyId=key_id)
                        rotation_enabled = rot_res.get("KeyRotationEnabled", False)
                    except Exception:
                        rotation_enabled = False

                # KMS Resource Asset
                key_asset = AssetObservation(
                    module_id="aws_kms",
                    provider_resource_id=arn,
                    external_id=key_id,
                    asset_type="kms_key",
                    asset_category="cryptography",
                    hostname=f"kms-key-{key_id[:8]}",
                    metadata={
                        "key_id": key_id,
                        "arn": arn,
                        "key_spec": key_spec,
                        "key_usage": key_usage,
                        "key_manager": key_manager,
                        "key_state": key_meta.get("KeyState"),
                        "origin": key_meta.get("Origin"),
                        "multi_region": key_meta.get("MultiRegion", False),
                        "rotation_enabled": rotation_enabled,
                        "region": region,
                        "account_id": account_id
                    }
                )
                yield key_asset

                algo_name, obj_type = KEY_SPEC_MAP.get(key_spec, (key_spec, "SYMMETRIC_CIPHER"))

                crypto_obs = CryptoObservation(
                    module_id="aws_kms",
                    canonical_name=algo_name,
                    object_type=obj_type,
                    provider="AWS_KMS",
                    identity_key=f"crypto:{algo_name}",
                    metadata={
                        "kms_key_arn": arn,
                        "key_spec": key_spec,
                        "key_usage": key_usage,
                        "rotation_enabled": rotation_enabled
                    }
                )
                yield crypto_obs

                # Relationship: AWS_KMS_KEY -> USES -> CRYPTOGRAPHIC_ALGORITHM
                yield RelationshipObservation(
                    module_id="aws_kms",
                    source_type="ASSET",
                    source_id_hint=arn,
                    target_type="CRYPTO_OBJECT",
                    target_id_hint=f"crypto:{algo_name}",
                    relationship_type="USES",
                    confidence="HIGH"
                )
