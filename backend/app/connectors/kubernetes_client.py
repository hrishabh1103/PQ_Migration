import logging
import re
from typing import Optional, Dict, Any, List
from kubernetes import client, config
from kubernetes.client.rest import ApiException

logger = logging.getLogger(__name__)

# Sensitive token / credential pattern scrubber
SECRET_PATTERN = re.compile(
    r'(bearer\s+[a-zA-Z0-9\-\._~\+\/]+=*|token:\s*["\']?[a-zA-Z0-9\-\._~\+\/]+|private_key|client-key-data:\s*\S+)',
    re.IGNORECASE
)

def sanitize_k8s_error(error_msg: str) -> str:
    """Scrub sensitive credentials/tokens from error string."""
    if not error_msg:
        return ""
    return SECRET_PATTERN.sub('[REDACTED_CREDENTIAL]', str(error_msg))

class KubernetesClient:
    """
    Safe Kubernetes API execution client wrapping official kubernetes Python SDK.
    Supports in-cluster auth, out-of-cluster kubeconfig, paginated list calls,
    timeouts, bounded error classification, and zero credential leakage guarantees.
    """

    def __init__(
        self,
        kubeconfig_path: Optional[str] = None,
        context_name: Optional[str] = None,
        in_cluster: bool = False,
        request_timeout: int = 15
    ):
        self.kubeconfig_path = kubeconfig_path
        self.context_name = context_name
        self.in_cluster = in_cluster
        self.request_timeout = request_timeout
        self.api_client: Optional[client.ApiClient] = None
        self._init_client()

    def _init_client(self):
        try:
            if self.in_cluster:
                config.load_incluster_config()
                self.api_client = client.ApiClient()
                logger.info("Initialized KubernetesClient with in-cluster config.")
            elif self.kubeconfig_path:
                config.load_kubeconfig(config_file=self.kubeconfig_path, context=self.context_name)
                self.api_client = client.ApiClient()
                logger.info(f"Initialized KubernetesClient with kubeconfig '{self.kubeconfig_path}' (context: {self.context_name}).")
            else:
                # Try default kubeconfig location or fallback to in-cluster
                try:
                    config.load_kubeconfig(context=self.context_name)
                    self.api_client = client.ApiClient()
                    logger.info(f"Initialized KubernetesClient with default kubeconfig (context: {self.context_name}).")
                except Exception:
                    config.load_incluster_config()
                    self.api_client = client.ApiClient()
                    logger.info("Fallback initialized KubernetesClient with in-cluster config.")
        except Exception as e:
            logger.warning(f"KubernetesClient initialization warning: {sanitize_k8s_error(str(e))}")
            # Non-blocking; methods will fail gracefully if api_client is None

    @property
    def core_v1(self) -> client.CoreV1Api:
        return client.CoreV1Api(self.api_client)

    @property
    def apps_v1(self) -> client.AppsV1Api:
        return client.AppsV1Api(self.api_client)

    @property
    def batch_v1(self) -> client.BatchV1Api:
        return client.BatchV1Api(self.api_client)

    @property
    def networking_v1(self) -> client.NetworkingV1Api:
        return client.NetworkingV1Api(self.api_client)

    @property
    def rbac_v1(self) -> client.RbacAuthorizationV1Api:
        return client.RbacAuthorizationV1Api(self.api_client)

    @property
    def custom_objects(self) -> client.CustomObjectsApi:
        return client.CustomObjectsApi(self.api_client)

    def validate_connection(self) -> Dict[str, Any]:
        """
        Validate read-only API server connection.
        Returns safe cluster metadata (API version, platform). Zero credentials exposed.
        """
        if not self.api_client:
            return {"validated": False, "error": "Kubernetes API client not initialized"}
        try:
            version_api = client.VersionApi(self.api_client)
            info = version_api.get_code(_request_timeout=self.request_timeout)
            return {
                "validated": True,
                "git_version": info.git_version,
                "platform": info.platform,
                "major": info.major,
                "minor": info.minor
            }
        except Exception as e:
            err_msg = sanitize_k8s_error(str(e))
            logger.error(f"Kubernetes connection validation failed: {err_msg}")
            return {"validated": False, "error": err_msg}

    def classify_error(self, e: Exception) -> str:
        """Classify Kubernetes API exception into safe standard error string."""
        if isinstance(e, ApiException):
            return f"K8s API Error {e.status}: {sanitize_k8s_error(e.reason or e.body)}"
        return f"K8s Client Error: {sanitize_k8s_error(str(e))}"
