import logging
from typing import AsyncIterator, Any
from app.collectors.observations import (
    AssetObservation, DiscoveryObservation
)
from app.connectors.kubernetes.modules.base_k8s_module import BaseK8sModule, CapabilityStatus

logger = logging.getLogger(__name__)

class RbacModule(BaseK8sModule):
    """
    Discovers Kubernetes ServiceAccounts, Roles, ClusterRoles, and Bindings for Identity Cryptographic Context.
    Identity key rule: k8s:sa:<cluster_id>:<namespace>/<name>
    """
    module_id = "k8s_rbac"
    capability_name = "rbac"

    async def collect(
        self,
        client: Any,
        cluster_id: str,
        target_id: str
    ) -> AsyncIterator[DiscoveryObservation]:
        logger.info(f"[{self.module_id}] Discovering ServiceAccounts & RBAC for '{cluster_id}'...")

        try:
            sa_list = client.core_v1.list_service_account_for_all_namespaces()
            for sa in sa_list.items:
                ns_name = sa.metadata.namespace
                sa_name = sa.metadata.name
                sa_uid = sa.metadata.uid
                sa_id = f"k8s:sa:{cluster_id}:{ns_name}/{sa_name}"

                yield AssetObservation(
                    module_id=self.module_id,
                    identity_key=sa_id,
                    hostname=f"sa:{ns_name}/{sa_name}",
                    asset_type="APPLICATION",
                    asset_category="IDENTITY",
                    metadata={
                        "cluster_id": cluster_id,
                        "namespace": ns_name,
                        "sa_name": sa_name,
                        "uid": sa_uid
                    }
                )

            self.status = CapabilityStatus.SCANNED
        except Exception as e:
            err_msg = client.classify_error(e)
            logger.error(f"Failed to list ServiceAccounts: {err_msg}")
            self.status = CapabilityStatus.FAILED
            self.error_detail = err_msg
