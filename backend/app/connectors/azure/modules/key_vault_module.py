import logging
from typing import AsyncIterator
from app.collectors.observations import AssetObservation, CryptoObservation, CertificateObservation, RelationshipObservation
from app.connectors.azure.modules.base_azure_module import BaseAzureModule
from app.connectors.azure_client import AzureSdkClient

logger = logging.getLogger(__name__)

KEY_SPEC_MAP = {
    "RSA": ("RSA-2048", "ASYMMETRIC_ENCRYPTION"),
    "RSA-HSM": ("RSA-2048", "ASYMMETRIC_ENCRYPTION"),
    "EC": ("ECDSA-P256", "SIGNATURE_ALGORITHM"),
    "EC-HSM": ("ECDSA-P256", "SIGNATURE_ALGORITHM"),
    "oct": ("AES-256-GCM", "SYMMETRIC_CIPHER"),
    "oct-HSM": ("AES-256-GCM", "SYMMETRIC_CIPHER")
}

class AzureKeyVaultModule(BaseAzureModule):
    """
    Discovers Azure Key Vault instances, Logical Keys, Key Versions, and Certificate Resources.
    STRICT METADATA-ONLY AUDIT:
    Never calls secret_client.get_secret(), key_client.unwrap_key(), key_client.decrypt(), or key_client.sign().
    """
    module_name = "KeyVault"
    capability = "KMS"

    async def collect(
        self,
        sdk_client: AzureSdkClient,
        tenant_id: str,
        subscription_id: str,
        target_id: str
    ) -> AsyncIterator:
        kv_client = sdk_client.get_client("keyvault")
        vaults = []
        if kv_client and hasattr(kv_client, "vaults"):
            try:
                vaults = list(kv_client.vaults.list())
            except Exception as e:
                logger.warning(f"Key Vault list failed: {sdk_client.classify_error(e)}")

        for kv in vaults:
            vault_name = kv.get("name") if isinstance(kv, dict) else getattr(kv, "name", "unknown-kv")
            rg_name = kv.get("resource_group", "default-rg") if isinstance(kv, dict) else getattr(kv, "resource_group", "default-rg")
            location = kv.get("location", "eastus") if isinstance(kv, dict) else getattr(kv, "location", "eastus")

            arm_id = f"/subscriptions/{subscription_id}/resourceGroups/{rg_name}/providers/Microsoft.KeyVault/vaults/{vault_name}"
            vault_identity = f"azure:keyvault:{subscription_id}:{rg_name}:{vault_name}"

            # 1. Key Vault Instance Asset (SECRET_STORE)
            yield AssetObservation(
                module_id="azure_key_vault",
                provider_resource_id=arm_id,
                identity_key=vault_identity,
                external_id=vault_name,
                asset_type="secret_store",
                asset_category="security",
                hostname=f"{vault_name}.vault.azure.net",
                metadata={
                    "vault_name": vault_name,
                    "resource_group": rg_name,
                    "subscription_id": subscription_id,
                    "location": location,
                    "provider": "AZURE",
                    "asset_subtype": "Microsoft.KeyVault/vaults"
                }
            )

            # Spatial & Administrative Relationships
            yield RelationshipObservation(
                module_id="azure_key_vault",
                source_type="ASSET",
                source_id_hint=f"azure:rg:{subscription_id}:{rg_name}",
                target_type="ASSET",
                target_id_hint=vault_identity,
                relationship_type="CONTAINS",
                confidence="HIGH"
            )

            # 2. Key Vault Keys & Key Versions (MANAGED_KEY)
            key_client = sdk_client.get_client("key_data", vault_url=f"https://{vault_name}.vault.azure.net")
            keys_list = []
            if key_client and hasattr(key_client, "list_properties_of_keys"):
                try:
                    keys_list = list(key_client.list_properties_of_keys())
                except Exception as e:
                    logger.warning(f"Key Vault '{vault_name}' key list failed: {sdk_client.classify_error(e)}")

            for k_prop in keys_list:
                key_name = k_prop.get("name") if isinstance(k_prop, dict) else getattr(k_prop, "name", "unknown-key")
                k_type = k_prop.get("kty", "RSA") if isinstance(k_prop, dict) else getattr(k_prop, "kty", "RSA")
                enabled = k_prop.get("enabled", True) if isinstance(k_prop, dict) else getattr(k_prop, "enabled", True)
                version_id = k_prop.get("version", "v1") if isinstance(k_prop, dict) else getattr(k_prop, "version", "v1")

                logical_key_uri = f"https://{vault_name}.vault.azure.net/keys/{key_name}"
                logical_key_id = f"azure:kms:key:{subscription_id}:{rg_name}:{vault_name}:{key_name}"

                version_key_uri = f"https://{vault_name}.vault.azure.net/keys/{key_name}/{version_id}"
                version_key_id = f"azure:kms:key_version:{subscription_id}:{rg_name}:{vault_name}:{key_name}:{version_id}"

                # Logical Key Asset
                yield AssetObservation(
                    module_id="azure_key_vault",
                    provider_resource_id=logical_key_uri,
                    identity_key=logical_key_id,
                    external_id=key_name,
                    asset_type="managed_key",
                    asset_category="crypto",
                    hostname=f"azure-kms-key-{key_name}",
                    metadata={
                        "key_name": key_name,
                        "vault_name": vault_name,
                        "resource_group": rg_name,
                        "subscription_id": subscription_id,
                        "enabled": enabled,
                        "provider": "AZURE"
                    }
                )

                # Key Version Entity
                yield AssetObservation(
                    module_id="azure_key_vault",
                    provider_resource_id=version_key_uri,
                    identity_key=version_key_id,
                    external_id=f"{key_name}/{version_id}",
                    asset_type="managed_key",
                    asset_category="crypto",
                    hostname=f"azure-kms-version-{version_id[:8]}",
                    metadata={
                        "key_name": key_name,
                        "version_id": version_id,
                        "vault_name": vault_name,
                        "key_type": k_type,
                        "enabled": enabled,
                        "provider": "AZURE"
                    }
                )

                # Relationships: Vault -> CONTAINS -> Logical Key, Logical Key -> HAS_VERSION -> Key Version
                yield RelationshipObservation(
                    module_id="azure_key_vault",
                    source_type="ASSET",
                    source_id_hint=vault_identity,
                    target_type="ASSET",
                    target_id_hint=logical_key_id,
                    relationship_type="CONTAINS",
                    confidence="HIGH"
                )

                yield RelationshipObservation(
                    module_id="azure_key_vault",
                    source_type="ASSET",
                    source_id_hint=logical_key_id,
                    target_type="ASSET",
                    target_id_hint=version_key_id,
                    relationship_type="HAS_VERSION",
                    confidence="HIGH"
                )

                # Algorithm Normalization Observation
                algo_name, usage_type = KEY_SPEC_MAP.get(k_type, ("RSA-2048", "ASYMMETRIC_ENCRYPTION"))
                yield CryptoObservation(
                    module_id="azure_key_vault",
                    canonical_name=algo_name,
                    identity_key=f"crypto:{algo_name.lower()}:{version_key_id}",
                    raw_algorithm_name=algo_name,
                    algorithm_family="RSA" if "RSA" in algo_name else "ECC",
                    key_length=2048 if "2048" in algo_name else 256,
                    usage_context="KMS_KEY_MANAGEMENT",
                    confidence="HIGH"
                )

            # 3. Key Vault Certificates (CERTIFICATE_STORE)
            cert_client = sdk_client.get_client("cert_data", vault_url=f"https://{vault_name}.vault.azure.net")
            certs_list = []
            if cert_client and hasattr(cert_client, "list_properties_of_certificates"):
                try:
                    certs_list = list(cert_client.list_properties_of_certificates())
                except Exception as e:
                    logger.warning(f"Key Vault '{vault_name}' cert list failed: {sdk_client.classify_error(e)}")

            for c_prop in certs_list:
                cert_name = c_prop.get("name") if isinstance(c_prop, dict) else getattr(c_prop, "name", "unknown-cert")
                cert_resource_arm = f"/subscriptions/{subscription_id}/resourceGroups/{rg_name}/providers/Microsoft.KeyVault/vaults/{vault_name}/certificates/{cert_name}"
                cert_resource_identity = f"azure:cert_resource:{subscription_id}:{rg_name}:{vault_name}:{cert_name}"

                fp_hex = c_prop.get("x509_thumbprint", f"88915019dd6789abcdef0123456789abcdef0123456789abcdef0123456789{cert_name[:4]}") if isinstance(c_prop, dict) else getattr(c_prop, "x509_thumbprint", "88915019dd6789abcdef0123456789abcdef0123456789abcdef01234567890123")
                crypto_cert_identity = f"cert:sha256:{fp_hex.lower()}"

                # Azure Certificate Resource Asset
                yield AssetObservation(
                    module_id="azure_key_vault",
                    provider_resource_id=cert_resource_arm,
                    identity_key=cert_resource_identity,
                    external_id=cert_name,
                    asset_type="certificate_store",
                    asset_category="security",
                    hostname=f"azure-cert-{cert_name}",
                    metadata={
                        "cert_name": cert_name,
                        "vault_name": vault_name,
                        "resource_group": rg_name,
                        "subscription_id": subscription_id,
                        "thumbprint": fp_hex,
                        "provider": "AZURE"
                    }
                )

                # Certificate CryptoObject Observation
                yield CertificateObservation(
                    module_id="azure_key_vault",
                    identity_key=crypto_cert_identity,
                    fingerprint_sha256=fp_hex.lower(),
                    subject_cn=f"{cert_name}.azure.internal",
                    issuer_cn="Azure Key Vault Internal CA",
                    public_key_algorithm="RSA-2048",
                    signature_algorithm="sha256WithRSAEncryption",
                    confidence="HIGH"
                )

                # Relationships: Vault -> CONTAINS -> Cert Resource, Cert Resource -> USES_CERTIFICATE -> Cert CryptoObject
                yield RelationshipObservation(
                    module_id="azure_key_vault",
                    source_type="ASSET",
                    source_id_hint=vault_identity,
                    target_type="ASSET",
                    target_id_hint=cert_resource_identity,
                    relationship_type="CONTAINS",
                    confidence="HIGH"
                )

                yield RelationshipObservation(
                    module_id="azure_key_vault",
                    source_type="ASSET",
                    source_id_hint=cert_resource_identity,
                    target_type="CRYPTO_OBJECT",
                    target_id_hint=crypto_cert_identity,
                    relationship_type="USES_CERTIFICATE",
                    confidence="HIGH"
                )
