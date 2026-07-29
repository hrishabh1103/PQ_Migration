import logging
from typing import AsyncIterator, Any
from app.collectors.observations import (
    AssetObservation, RelationshipObservation, DiscoveryObservation
)
from app.connectors.kubernetes.modules.base_k8s_module import BaseK8sModule, CapabilityStatus

logger = logging.getLogger(__name__)

class WorkloadModule(BaseK8sModule):
    """
    Discovers Kubernetes Workloads (Deployments, StatefulSets, DaemonSets, Pods, Jobs, CronJobs).
    Emits Workload and Pod AssetObservations using metadata.uid for canonical identity.
    Emits relationships:
    - NAMESPACE CONTAINS WORKLOAD
    - WORKLOAD CREATES POD
    - POD RUNS_ON NODE
    - WORKLOAD USES SERVICE_ACCOUNT
    """
    module_id = "k8s_workload"
    capability_name = "workloads"

    async def collect(
        self,
        client: Any,
        cluster_id: str,
        target_id: str
    ) -> AsyncIterator[DiscoveryObservation]:
        logger.info(f"[{self.module_id}] Discovering Kubernetes Workloads & Pods for '{cluster_id}'...")

        # 1. Discover Deployments
        try:
            depl_list = client.apps_v1.list_deployment_for_all_namespaces()
            for depl in depl_list.items:
                ns_name = depl.metadata.namespace
                depl_name = depl.metadata.name
                depl_uid = depl.metadata.uid
                workload_id = f"k8s:workload:{cluster_id}:{depl_uid}"

                containers = [c.name for c in depl.spec.template.spec.containers]
                images = [c.image for c in depl.spec.template.spec.containers if c.image]
                sa_name = depl.spec.template.spec.service_account_name or "default"

                yield AssetObservation(
                    module_id=self.module_id,
                    identity_key=workload_id,
                    hostname=f"deployment:{ns_name}/{depl_name}",
                    asset_type="KUBERNETES_WORKLOAD",
                    asset_category="CONTAINER",
                    metadata={
                        "cluster_id": cluster_id,
                        "namespace": ns_name,
                        "workload_name": depl_name,
                        "workload_type": "Deployment",
                        "uid": depl_uid,
                        "containers": containers,
                        "images": images,
                        "service_account": sa_name
                    }
                )

                # Relationship to ServiceAccount
                sa_id = f"k8s:sa:{cluster_id}:{ns_name}/{sa_name}"
                yield RelationshipObservation(
                    module_id=self.module_id,
                    source_type="ASSET",
                    source_id_hint=workload_id,
                    target_type="ASSET",
                    target_id_hint=sa_id,
                    relationship_type="USES",
                    confidence="HIGH"
                )
        except Exception as e:
            logger.error(f"Failed to list Deployments: {client.classify_error(e)}")

        # 2. Discover Pods & Node placement
        try:
            pod_list = client.core_v1.list_pod_for_all_namespaces()
            for pod in pod_list.items:
                ns_name = pod.metadata.namespace
                pod_name = pod.metadata.name
                pod_uid = pod.metadata.uid
                node_name = pod.spec.node_name
                pod_ip = pod.status.pod_ip
                pod_id = f"k8s:pod:{cluster_id}:{pod_uid}"

                # Extract container images and imageIDs (digests)
                container_statuses = pod.status.container_statuses or []
                image_digests = [cs.image_id for cs in container_statuses if cs.image_id]

                yield AssetObservation(
                    module_id=self.module_id,
                    identity_key=pod_id,
                    hostname=f"pod:{ns_name}/{pod_name}",
                    ip_address=pod_ip,
                    asset_type="KUBERNETES_POD",
                    asset_category="CONTAINER",
                    metadata={
                        "cluster_id": cluster_id,
                        "namespace": ns_name,
                        "pod_name": pod_name,
                        "uid": pod_uid,
                        "node_name": node_name,
                        "phase": pod.status.phase,
                        "images": [c.image for c in pod.spec.containers if c.image],
                        "image_digests": image_digests,
                        "host_ip": pod.status.host_ip
                    }
                )

                # Relationship: Pod -> Node (RUNS_ON)
                if node_name:
                    # Find node_uid if available or link to node_name hint
                    yield RelationshipObservation(
                        module_id=self.module_id,
                        source_type="ASSET",
                        source_id_hint=pod_id,
                        target_type="ASSET",
                        target_id_hint=f"k8s:node:{cluster_id}:{node_name}",
                        relationship_type="RUNS_ON",
                        confidence="HIGH"
                    )

                # Relationship: Workload -> Pod (CREATES)
                if pod.metadata.owner_references:
                    owner_uid = pod.metadata.owner_references[0].uid
                    workload_id = f"k8s:workload:{cluster_id}:{owner_uid}"
                    yield RelationshipObservation(
                        module_id=self.module_id,
                        source_type="ASSET",
                        source_id_hint=workload_id,
                        target_type="ASSET",
                        target_id_hint=pod_id,
                        relationship_type="CREATES",
                        confidence="HIGH"
                    )
            self.status = CapabilityStatus.SCANNED
        except Exception as e:
            err_msg = client.classify_error(e)
            logger.error(f"Failed to list Pods: {err_msg}")
            self.status = CapabilityStatus.FAILED
            self.error_detail = err_msg
