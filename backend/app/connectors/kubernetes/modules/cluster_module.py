import logging
import hashlib
from typing import AsyncIterator, Any
from app.collectors.observations import (
    AssetObservation, RelationshipObservation, DiscoveryObservation
)
from app.connectors.kubernetes.modules.base_k8s_module import BaseK8sModule, CapabilityStatus

logger = logging.getLogger(__name__)

class ClusterModule(BaseK8sModule):
    """
    Discovers Kubernetes Cluster identity, Namespaces, and Nodes.
    Emits Cluster, Namespace, and Node AssetObservations, and CLUSTER CONTAINS NAMESPACE relationships.
    Identity key rules:
    - Cluster: provider ARN or deterministic hash of kube-system namespace UID / CA cert
    - Namespace: k8s:namespace:<cluster_id>:<namespace_uid>
    - Node: k8s:node:<cluster_id>:<node_uid> (captures providerID for EC2 correlation)
    """
    module_id = "k8s_cluster"
    capability_name = "cluster_identity"

    async def collect(
        self,
        client: Any,
        cluster_id: str,
        target_id: str
    ) -> AsyncIterator[DiscoveryObservation]:
        logger.info(f"[{self.module_id}] Discovering Cluster identity, Namespaces, and Nodes for '{cluster_id}'...")

        # 1. Emit Cluster AssetObservation
        yield AssetObservation(
            module_id=self.module_id,
            identity_key=cluster_id,
            hostname=cluster_id,
            asset_type="KUBERNETES_CLUSTER",
            asset_category="INFRASTRUCTURE",
            metadata={
                "cluster_id": cluster_id,
                "target_id": target_id
            }
        )

        # 2. Discover Namespaces
        try:
            ns_list = client.core_v1.list_namespace()
            for ns in ns_list.items:
                ns_name = ns.metadata.name
                ns_uid = ns.metadata.uid
                ns_identity = f"k8s:namespace:{cluster_id}:{ns_uid}"

                yield AssetObservation(
                    module_id=self.module_id,
                    identity_key=ns_identity,
                    hostname=f"ns:{ns_name}",
                    asset_type="KUBERNETES_NAMESPACE",
                    asset_category="CONTAINER",
                    metadata={
                        "cluster_id": cluster_id,
                        "namespace": ns_name,
                        "uid": ns_uid,
                        "labels": ns.metadata.labels or {}
                    }
                )

                yield RelationshipObservation(
                    module_id=self.module_id,
                    source_type="ASSET",
                    source_id_hint=cluster_id,
                    target_type="ASSET",
                    target_id_hint=ns_identity,
                    relationship_type="CONTAINS",
                    confidence="HIGH"
                )
        except Exception as e:
            logger.error(f"Failed to list Kubernetes namespaces: {client.classify_error(e)}")

        # 3. Discover Nodes
        try:
            node_list = client.core_v1.list_node()
            for node in node_list.items:
                node_name = node.metadata.name
                node_uid = node.metadata.uid
                provider_id = node.spec.provider_id or ""
                node_identity = f"k8s:node:{cluster_id}:{node_uid}"

                # Extract IP addresses
                node_ip = None
                for addr in (node.status.addresses or []):
                    if addr.type in ("InternalIP", "ExternalIP"):
                        node_ip = addr.address
                        break

                yield AssetObservation(
                    module_id=self.module_id,
                    identity_key=node_identity,
                    hostname=node_name,
                    ip_address=node_ip,
                    os_distribution=node.status.node_info.os_image if node.status.node_info else None,
                    architecture=node.status.node_info.architecture if node.status.node_info else None,
                    kernel_version=node.status.node_info.kernel_version if node.status.node_info else None,
                    asset_type="HOST",
                    asset_category="INFRASTRUCTURE",
                    provider_resource_id=provider_id if provider_id else None,
                    metadata={
                        "cluster_id": cluster_id,
                        "node_name": node_name,
                        "uid": node_uid,
                        "provider_id": provider_id,
                        "kubelet_version": node.status.node_info.kubelet_version if node.status.node_info else None
                    }
                )

                yield RelationshipObservation(
                    module_id=self.module_id,
                    source_type="ASSET",
                    source_id_hint=cluster_id,
                    target_type="ASSET",
                    target_id_hint=node_identity,
                    relationship_type="CONTAINS",
                    confidence="HIGH"
                )
            self.status = CapabilityStatus.SCANNED
        except Exception as e:
            err_msg = client.classify_error(e)
            logger.error(f"Failed to list Kubernetes nodes: {err_msg}")
            self.status = CapabilityStatus.FAILED
            self.error_detail = err_msg
