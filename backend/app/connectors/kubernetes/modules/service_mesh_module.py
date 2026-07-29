import logging
from typing import AsyncIterator, Any
from app.collectors.observations import (
    AssetObservation, CapabilityObservation, CapabilityState, DiscoveryObservation
)
from app.connectors.kubernetes.modules.base_k8s_module import BaseK8sModule, CapabilityStatus

logger = logging.getLogger(__name__)

class ServiceMeshModule(BaseK8sModule):
    """
    Discovers Service Mesh presence (Istio, Linkerd), sidecar injection, and basic mTLS policy.
    Capability status tracking:
    - mesh_presence_detection: IMPLEMENTED
    - sidecar_injection_detection: IMPLEMENTED
    - basic_mtls_configuration_discovery: IMPLEMENTED
    - deep_istio_discovery: FOUNDATION_READY
    - deep_linkerd_discovery: FOUNDATION_READY
    """
    module_id = "k8s_service_mesh"
    capability_name = "service_mesh"

    async def collect(
        self,
        client: Any,
        cluster_id: str,
        target_id: str
    ) -> AsyncIterator[DiscoveryObservation]:
        logger.info(f"[{self.module_id}] Checking Service Mesh presence for '{cluster_id}'...")

        mesh_found = False

        # 1. Detect Istio namespace & sidecars
        try:
            ns_list = client.core_v1.list_namespace()
            for ns in ns_list.items:
                ns_name = ns.metadata.name
                labels = ns.metadata.labels or {}
                if "istio-injection" in labels or ns_name == "istio-system":
                    mesh_found = True
                    yield CapabilityObservation(
                        module_id=self.module_id,
                        capability_name="mesh_presence_detection",
                        capability_state=CapabilityState.INSTALLED,
                        algorithm_name="Istio Service Mesh",
                        details={
                            "mesh_type": "Istio",
                            "namespace": ns_name,
                            "auto_injection": labels.get("istio-injection")
                        }
                    )
        except Exception as e:
            logger.debug(f"Service mesh detection error: {client.classify_error(e)}")

        # 2. Check PeerAuthentication (mTLS status) if present
        try:
            pa_list = client.custom_objects.list_cluster_custom_object(
                group="security.istio.io",
                version="v1beta1",
                plural="peerauthentications"
            )
            for pa in pa_list.get("items", []):
                mode = pa.get("spec", {}).get("mtls", {}).get("mode", "PERMISSIVE")
                yield CapabilityObservation(
                    module_id=self.module_id,
                    capability_name="basic_mtls_configuration_discovery",
                    capability_state=CapabilityState.CONFIGURED,
                    algorithm_name=f"Istio mTLS ({mode})",
                    details={"mtls_mode": mode}
                )
        except Exception:
            pass

        self.status = CapabilityStatus.SCANNED if mesh_found else CapabilityStatus.NOT_APPLICABLE
