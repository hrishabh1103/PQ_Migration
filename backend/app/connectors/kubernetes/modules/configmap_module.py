import logging
import re
from typing import AsyncIterator, Any
from app.collectors.observations import (
    CryptoObservation, CapabilityState, DiscoveryObservation
)
from app.connectors.kubernetes.modules.base_k8s_module import BaseK8sModule, CapabilityStatus

logger = logging.getLogger(__name__)

# Config crypto patterns
PQC_PATTERN = re.compile(r'\b(mlkem768|mldsa65|x25519_mlkem768|bikel1|frodo640)\b', re.IGNORECASE)
CLASSICAL_TLS_PATTERN = re.compile(r'\b(TLSv1\.2|TLSv1\.3|ECDHE-RSA|AES128-GCM|AES256-GCM)\b', re.IGNORECASE)

class ConfigMapModule(BaseK8sModule):
    """
    Discovers Cryptographic Configurations in ConfigMaps.
    Configured PQC strings (e.g., 'mlkem768') remain CapabilityState.CONFIGURED.
    They are NEVER classified as OBSERVED_IN_USE without runtime handshake evidence.
    """
    module_id = "k8s_configmap"
    capability_name = "configmaps"

    async def collect(
        self,
        client: Any,
        cluster_id: str,
        target_id: str
    ) -> AsyncIterator[DiscoveryObservation]:
        logger.info(f"[{self.module_id}] Inspecting ConfigMaps for Cryptographic Configurations for '{cluster_id}'...")

        try:
            cm_list = client.core_v1.list_config_map_for_all_namespaces()
            for cm in cm_list.items:
                ns_name = cm.metadata.namespace
                cm_name = cm.metadata.name
                cm_uid = cm.metadata.uid

                if not cm.data:
                    continue

                for key, val in cm.data.items():
                    if not val:
                        continue

                    # 1. Search for PQC config references
                    pqc_matches = PQC_PATTERN.findall(val)
                    if pqc_matches:
                        algo = pqc_matches[0].upper()
                        yield CryptoObservation(
                            module_id=self.module_id,
                            canonical_name=f"Configured PQC Primitive: {algo}",
                            object_type="ALGORITHM",
                            provider="KUBERNETES_CONFIGMAP",
                            identity_key=f"crypto:configmap:{cluster_id}:{cm_uid}:{key}:{algo}",
                            capability_state=CapabilityState.CONFIGURED, # MUST BE CONFIGURED!
                            metadata={
                                "cluster_id": cluster_id,
                                "namespace": ns_name,
                                "configmap_name": cm_name,
                                "config_key": key,
                                "raw_algorithm_name": algo,
                                "evidence_snippet": f"Found {algo} in ConfigMap {ns_name}/{cm_name}[{key}]"
                            }
                        )

                    # 2. Search for classical TLS config references
                    tls_matches = CLASSICAL_TLS_PATTERN.findall(val)
                    if tls_matches:
                        proto = tls_matches[0].upper()
                        yield CryptoObservation(
                            module_id=self.module_id,
                            canonical_name=f"Configured TLS Setting: {proto}",
                            object_type="PROTOCOL",
                            provider="KUBERNETES_CONFIGMAP",
                            identity_key=f"crypto:configmap:{cluster_id}:{cm_uid}:{key}:{proto}",
                            capability_state=CapabilityState.CONFIGURED,
                            metadata={
                                "cluster_id": cluster_id,
                                "namespace": ns_name,
                                "configmap_name": cm_name,
                                "config_key": key,
                                "evidence_snippet": f"Found {proto} setting in ConfigMap {ns_name}/{cm_name}[{key}]"
                            }
                        )

            self.status = CapabilityStatus.SCANNED
        except Exception as e:
            err_msg = client.classify_error(e)
            logger.error(f"Failed to inspect ConfigMaps: {err_msg}")
            self.status = CapabilityStatus.FAILED
            self.error_detail = err_msg
