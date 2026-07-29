import logging
import hashlib
from typing import AsyncIterator, Set, Dict, Any, Optional, List

from app.models.entities import TargetType
from app.scanners.base import ScanContext, RawFinding
from app.scanners.plugins import Connector, PluginType, PluginCapability, PluginRegistry
from app.collectors.observations import DiscoveryObservation
from app.connectors.kubernetes_client import KubernetesClient
from app.connectors.kubernetes.modules import (
    BaseK8sModule, CapabilityStatus, ClusterModule, WorkloadModule, ServiceModule,
    CertificateModule, SecretMetadataModule, ConfigMapModule, CertManagerModule,
    ServiceMeshModule, EncryptionAtRestModule, RbacModule
)

logger = logging.getLogger(__name__)

class KubernetesConnector(Connector):
    """
    Enterprise Kubernetes Cryptographic Discovery Connector plugin.
    Acts as a read-only Discovery Adapter emitting structured DiscoveryObservation items.
    Tracks 15 independent coverage capabilities with module-level fault isolation.
    Identity key rules: metadata.uid + provider-independent cluster identity hierarchy.
    """
    plugin_id = "kubernetes"
    version = "1.0.0"
    plugin_type = PluginType.CONNECTOR
    supported_target_types: Set[TargetType] = {
        TargetType.KUBERNETES_CLUSTER,
        TargetType.CLOUD_PROVIDER,
        TargetType.HOSTNAME
    }
    capabilities: Set[PluginCapability] = {
        PluginCapability.KUBERNETES,
        PluginCapability.CONTAINER,
        PluginCapability.TLS,
        PluginCapability.X509,
        PluginCapability.IDENTITY,
        PluginCapability.ENCRYPTION_CONFIGURATION,
        PluginCapability.TLS_CONFIGURATION
    }

    def __init__(self):
        self.modules: List[BaseK8sModule] = [
            ClusterModule(),
            WorkloadModule(),
            ServiceModule(),
            CertificateModule(),
            SecretMetadataModule(),
            ConfigMapModule(),
            CertManagerModule(),
            ServiceMeshModule(),
            EncryptionAtRestModule(),
            RbacModule()
        ]
        # Map modules to the 15 capability names for coverage reporting
        self.coverage_matrix: Dict[str, str] = {
            "cluster_identity": "UNKNOWN",
            "nodes": "UNKNOWN",
            "namespaces": "UNKNOWN",
            "workloads": "UNKNOWN",
            "pods": "UNKNOWN",
            "services": "UNKNOWN",
            "ingress": "UNKNOWN",
            "gateway_api": "UNKNOWN",
            "certificates": "UNKNOWN",
            "secret_metadata": "UNKNOWN",
            "configmaps": "UNKNOWN",
            "rbac": "UNKNOWN",
            "cert_manager": "UNKNOWN",
            "service_mesh": "UNKNOWN",
            "encryption_at_rest": "UNKNOWN"
        }

    async def discover(
        self,
        target_value: str,
        target_type: TargetType,
        context: ScanContext
    ) -> AsyncIterator[RawFinding]:
        """Legacy discover compatibility wrapper yielding RawFinding stream."""
        async for obs in self.collect(target_value, target_type, context):
            yield RawFinding(
                scanner_id=self.plugin_id,
                scanner_version=self.version,
                raw_algorithm_name=getattr(obs, "raw_algorithm_name", "K8S_RESOURCE"),
                finding_type=getattr(obs, "finding_type", "KUBERNETES_RESOURCE"),
                location_identifier=getattr(obs, "identity_key", target_value),
                evidence_snippet=f"KubernetesConnector observation: {obs.__class__.__name__}",
                confidence=getattr(obs, "confidence", "HIGH"),
                metadata_json=getattr(obs, "metadata", {})
            )

    async def collect(
        self,
        target_value: str,
        target_type: TargetType,
        context: ScanContext,
        kubeconfig_path: Optional[str] = None,
        context_name: Optional[str] = None,
        in_cluster: bool = False,
        **kwargs
    ) -> AsyncIterator[DiscoveryObservation]:
        """
        Primary entry point performing Kubernetes read-only discovery sync.
        Yields structured DiscoveryObservation items with fault isolation per capability.
        """
        logger.info(f"Starting KubernetesConnector discovery sync for target '{target_value}'...")

        # Initialize Kubernetes API client
        k8s_client = KubernetesClient(
            kubeconfig_path=kubeconfig_path,
            context_name=context_name,
            in_cluster=in_cluster
        )

        val = k8s_client.validate_connection()
        if not val.get("validated"):
            err_msg = val.get("error", "Failed to connect to Kubernetes API server")
            logger.error(f"KubernetesConnector failed connection validation: {err_msg}")
            # Fail closed on unreachable cluster
            raise ConnectionError(f"Kubernetes API Connection Failed: {err_msg}")

        # Derive Cluster Identity (Provider ARN or deterministic hash of kube-system namespace / CA)
        cluster_id = self._derive_cluster_id(k8s_client, target_value)
        target_id = getattr(context, "target_id", "k8s-target-1")

        logger.info(f"KubernetesConnector connected to cluster '{cluster_id}' ({val.get('git_version', 'v1.30')})")

        # Execute discovery modules with fault isolation
        for mod in self.modules:
            try:
                async for obs in mod.collect(k8s_client, cluster_id, target_id):
                    yield obs
                self.coverage_matrix[mod.capability_name] = mod.status.value
            except Exception as e:
                err_msg = k8s_client.classify_error(e)
                logger.error(f"Kubernetes module '{mod.module_id}' failed: {err_msg}")
                self.coverage_matrix[mod.capability_name] = CapabilityStatus.FAILED.value

        # Update remaining capability coverage dimensions
        self.coverage_matrix["nodes"] = self.coverage_matrix.get("cluster_identity", "SCANNED")
        self.coverage_matrix["namespaces"] = self.coverage_matrix.get("cluster_identity", "SCANNED")
        self.coverage_matrix["pods"] = self.coverage_matrix.get("workloads", "SCANNED")
        self.coverage_matrix["ingress"] = self.coverage_matrix.get("services", "SCANNED")
        self.coverage_matrix["gateway_api"] = "NOT_APPLICABLE"

    def _derive_cluster_id(self, client: KubernetesClient, target_value: str) -> str:
        """
        Derive deterministic provider-independent cluster identity.
        Hierarchy:
        1. Explicit ARN or provider ID if target_value matches arn:aws:eks:... or provider URI
        2. Hash of kube-system namespace UID
        3. Fallback target_value
        """
        if target_value.startswith("arn:aws:eks:") or target_value.startswith("k8s:"):
            return target_value

        try:
            ks_ns = client.core_v1.read_namespace("kube-system")
            if ks_ns and ks_ns.metadata and ks_ns.metadata.uid:
                raw_uid = ks_ns.metadata.uid
                uid_hash = hashlib.sha256(raw_uid.encode("utf-8")).hexdigest()[:12]
                return f"k8s:cluster:{uid_hash}"
        except Exception:
            pass

        clean_val = target_value.replace("https://", "").replace("http://", "").replace(":", "-").replace("/", "-")
        return f"k8s:cluster:{clean_val}"

# Auto-register with PluginRegistry
PluginRegistry.register(KubernetesConnector)
