import logging
from typing import AsyncIterator, Any
from app.collectors.observations import (
    AssetObservation, DiscoveryObservation
)
from app.connectors.kubernetes.modules.base_k8s_module import BaseK8sModule, CapabilityStatus

logger = logging.getLogger(__name__)

class SecretMetadataModule(BaseK8sModule):
    """
    Discovers Kubernetes Secret objects as INVENTORY METADATA ONLY.
    STRICT ZERO-SECRET BOUNDARY:
    - Secret.data and Secret.stringData values are NEVER read, logged, or stored.
    - Decoded secret contents, private keys, passwords, and tokens are strictly excluded.
    - Captures metadata only: namespace, name, type, metadata.uid, creationTimestamp.
    """
    module_id = "k8s_secret_metadata"
    capability_name = "secret_metadata"

    async def collect(
        self,
        client: Any,
        cluster_id: str,
        target_id: str
    ) -> AsyncIterator[DiscoveryObservation]:
        logger.info(f"[{self.module_id}] Discovering Secret Metadata (Zero-Data Exposure Policy) for '{cluster_id}'...")

        try:
            sec_list = client.core_v1.list_secret_for_all_namespaces()
            for sec in sec_list.items:
                ns_name = sec.metadata.namespace
                sec_name = sec.metadata.name
                sec_uid = sec.metadata.uid
                sec_type = sec.type or "Opaque"
                sec_id = f"k8s:secret:{cluster_id}:{sec_uid}"

                # ZERO-SECRET GUARANTEE: Filter keys present, but DO NOT capture values!
                data_keys = list((sec.data or {}).keys())

                yield AssetObservation(
                    module_id=self.module_id,
                    identity_key=sec_id,
                    hostname=f"secret:{ns_name}/{sec_name}",
                    asset_type="KMS_KEY", # Classified as metadata inventory entity
                    asset_category="SECRET_METADATA",
                    metadata={
                        "cluster_id": cluster_id,
                        "namespace": ns_name,
                        "secret_name": sec_name,
                        "uid": sec_uid,
                        "secret_type": sec_type,
                        "data_keys_present": data_keys,
                        "creation_timestamp": sec.metadata.creation_timestamp.isoformat() if sec.metadata.creation_timestamp else None
                    }
                )

            self.status = CapabilityStatus.SCANNED
        except Exception as e:
            err_msg = client.classify_error(e)
            logger.error(f"Failed to list Secret metadata: {err_msg}")
            self.status = CapabilityStatus.FAILED
            self.error_detail = err_msg
