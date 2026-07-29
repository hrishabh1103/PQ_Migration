import logging
from typing import AsyncIterator, Any
from app.collectors.observations import (
    CapabilityObservation, CapabilityState, DiscoveryObservation
)
from app.connectors.kubernetes.modules.base_k8s_module import BaseK8sModule, CapabilityStatus

logger = logging.getLogger(__name__)

class EncryptionAtRestModule(BaseK8sModule):
    """
    Discovers Kubernetes API Server Secret Encryption at Rest Configuration.
    CONSERVATIVE SEMANTICS:
    - Status is UNKNOWN by default unless authoritative evidence is obtained from API server EncryptionConfiguration.
    - Never infers 'Secret exists -> Encrypted' or 'KMS present -> Encryption verified'.
    """
    module_id = "k8s_encryption_at_rest"
    capability_name = "encryption_at_rest"

    async def collect(
        self,
        client: Any,
        cluster_id: str,
        target_id: str
    ) -> AsyncIterator[DiscoveryObservation]:
        logger.info(f"[{self.module_id}] Checking Encryption-at-Rest configuration for '{cluster_id}'...")

        # In managed Kubernetes (EKS/AKS/GKE) or default read-only RBAC,
        # API Server host configuration files like /etc/kubernetes/enc/config.yaml are inaccessible.
        # Preserve UNKNOWN status per specification.

        yield CapabilityObservation(
            module_id=self.module_id,
            capability_name="secret_encryption_at_rest",
            capability_state=CapabilityState.INSTALLED,
            algorithm_name="Kubernetes Secret Encryption",
            details={
                "encryption_status": "UNKNOWN",
                "reason": "API server EncryptionConfiguration inaccessible via read-only API"
            }
        )

        self.status = CapabilityStatus.UNKNOWN
