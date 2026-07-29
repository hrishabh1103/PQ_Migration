import logging
from typing import AsyncIterator, Any
from app.collectors.observations import (
    AssetObservation, ServiceObservation, RelationshipObservation, DiscoveryObservation
)
from app.connectors.kubernetes.modules.base_k8s_module import BaseK8sModule, CapabilityStatus

logger = logging.getLogger(__name__)

class ServiceModule(BaseK8sModule):
    """
    Discovers Kubernetes Services, Ingresses, and Network Policies.
    Emits Service and Ingress AssetObservations, ServiceObservations for ports, and relationships:
    - SERVICE EXPOSES WORKLOAD
    - INGRESS EXPOSES SERVICE
    """
    module_id = "k8s_service"
    capability_name = "services"

    async def collect(
        self,
        client: Any,
        cluster_id: str,
        target_id: str
    ) -> AsyncIterator[DiscoveryObservation]:
        logger.info(f"[{self.module_id}] Discovering Kubernetes Services & Ingresses for '{cluster_id}'...")

        # 1. Discover Services
        try:
            svc_list = client.core_v1.list_service_for_all_namespaces()
            for svc in svc_list.items:
                ns_name = svc.metadata.namespace
                svc_name = svc.metadata.name
                svc_uid = svc.metadata.uid
                svc_id = f"k8s:service:{cluster_id}:{svc_uid}"
                svc_type = svc.spec.type or "ClusterIP"
                cluster_ip = svc.spec.cluster_ip

                yield AssetObservation(
                    module_id=self.module_id,
                    identity_key=svc_id,
                    hostname=f"service:{ns_name}/{svc_name}",
                    ip_address=cluster_ip if cluster_ip and cluster_ip != "None" else None,
                    asset_type="KUBERNETES_SERVICE",
                    asset_category="SERVICE",
                    metadata={
                        "cluster_id": cluster_id,
                        "namespace": ns_name,
                        "service_name": svc_name,
                        "uid": svc_uid,
                        "type": svc_type,
                        "cluster_ip": cluster_ip,
                        "selector": svc.spec.selector or {}
                    }
                )

                # Emit ServiceObservations for exposed ports
                for port in (svc.spec.ports or []):
                    app_proto = "HTTPS" if port.port in (443, 8443) or port.name and "https" in port.name.lower() else "HTTP"
                    yield ServiceObservation(
                        module_id=self.module_id,
                        port=port.port,
                        transport_protocol=port.protocol or "TCP",
                        application_protocol=app_proto,
                        service_name=f"{svc_name}:{port.port}",
                        metadata={
                            "service_uid": svc_uid,
                            "target_port": str(port.target_port)
                        }
                    )
        except Exception as e:
            logger.error(f"Failed to list Services: {client.classify_error(e)}")

        # 2. Discover Ingresses
        try:
            ing_list = client.networking_v1.list_ingress_for_all_namespaces()
            for ing in ing_list.items:
                ns_name = ing.metadata.namespace
                ing_name = ing.metadata.name
                ing_uid = ing.metadata.uid
                ing_id = f"k8s:ingress:{cluster_id}:{ing_uid}"

                hosts = []
                tls_secrets = []
                for rule in (ing.spec.rules or []):
                    if rule.host:
                        hosts.append(rule.host)

                for tls in (ing.spec.tls or []):
                    if tls.secret_name:
                        tls_secrets.append(tls.secret_name)

                yield AssetObservation(
                    module_id=self.module_id,
                    identity_key=ing_id,
                    hostname=f"ingress:{ns_name}/{ing_name}",
                    asset_type="KUBERNETES_INGRESS",
                    asset_category="SERVICE",
                    metadata={
                        "cluster_id": cluster_id,
                        "namespace": ns_name,
                        "ingress_name": ing_name,
                        "uid": ing_uid,
                        "hosts": hosts,
                        "tls_secrets": tls_secrets,
                        "ingress_class_name": ing.spec.ingress_class_name
                    }
                )

                # Relationship: INGRESS EXPOSES SERVICE & INGRESS USES SECRET
                for rule in (ing.spec.rules or []):
                    if rule.http and rule.http.paths:
                        for path in rule.http.paths:
                            if path.backend and path.backend.service:
                                target_svc_name = path.backend.service.name
                                yield RelationshipObservation(
                                    module_id=self.module_id,
                                    source_type="ASSET",
                                    source_id_hint=ing_id,
                                    target_type="ASSET",
                                    target_id_hint=f"k8s:service:{cluster_id}:{ns_name}/{target_svc_name}",
                                    relationship_type="EXPOSES",
                                    confidence="HIGH"
                                )

                for sec_name in tls_secrets:
                    sec_id = f"k8s:secret:{cluster_id}:{ns_name}/{sec_name}"
                    yield RelationshipObservation(
                        module_id=self.module_id,
                        source_type="ASSET",
                        source_id_hint=ing_id,
                        target_type="ASSET",
                        target_id_hint=sec_id,
                        relationship_type="USES",
                        confidence="HIGH"
                    )
            self.status = CapabilityStatus.SCANNED
        except Exception as e:
            err_msg = client.classify_error(e)
            logger.error(f"Failed to list Ingresses: {err_msg}")
            self.status = CapabilityStatus.FAILED
            self.error_detail = err_msg
