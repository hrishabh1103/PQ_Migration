import logging
from typing import AsyncIterator, Any
from app.collectors.observations import (
    AssetObservation, RelationshipObservation, DiscoveryObservation
)
from app.connectors.kubernetes.modules.base_k8s_module import BaseK8sModule, CapabilityStatus

logger = logging.getLogger(__name__)

class CertManagerModule(BaseK8sModule):
    """
    Discovers cert-manager CRD resources (Certificate, Issuer, ClusterIssuer).
    If cert-manager CRDs do not exist in the cluster, sets status = NOT_APPLICABLE gracefully.
    """
    module_id = "k8s_cert_manager"
    capability_name = "cert_manager"

    async def collect(
        self,
        client: Any,
        cluster_id: str,
        target_id: str
    ) -> AsyncIterator[DiscoveryObservation]:
        logger.info(f"[{self.module_id}] Checking cert-manager CRDs for '{cluster_id}'...")

        try:
            # Query custom objects for cert-manager Certificates
            cr_list = client.custom_objects.list_cluster_custom_object(
                group="cert-manager.io",
                version="v1",
                plural="certificates"
            )
            items = cr_list.get("items", [])
            for cr in items:
                meta = cr.get("metadata", {})
                ns_name = meta.get("namespace", "default")
                cert_name = meta.get("name")
                cert_uid = meta.get("uid")

                yield AssetObservation(
                    module_id=self.module_id,
                    identity_key=f"k8s:certmanager:{cluster_id}:{cert_uid}",
                    hostname=f"cert-manager:{ns_name}/{cert_name}",
                    asset_type="APPLICATION",
                    asset_category="CERTIFICATE_MANAGEMENT",
                    metadata={
                        "cluster_id": cluster_id,
                        "namespace": ns_name,
                        "name": cert_name,
                        "uid": cert_uid,
                        "spec": cr.get("spec", {})
                    }
                )
            self.status = CapabilityStatus.SCANNED
        except Exception as e:
            # If 404 Not Found, cert-manager CRD is not installed in the cluster -> NOT_APPLICABLE
            err_msg = str(e)
            if "404" in err_msg or "NotFound" in err_msg or "Reason: Not Found" in err_msg:
                logger.info(f"[{self.module_id}] cert-manager CRDs not installed in cluster (NOT_APPLICABLE).")
                self.status = CapabilityStatus.NOT_APPLICABLE
            else:
                logger.warning(f"Failed to query cert-manager CRDs: {client.classify_error(e)}")
                self.status = CapabilityStatus.PARTIALLY_SCANNED
