from enum import Enum
from typing import AsyncIterator, Dict, Any, Optional
from app.collectors.observations import DiscoveryObservation

class CapabilityStatus(str, Enum):
    SCANNED = "SCANNED"
    PARTIALLY_SCANNED = "PARTIALLY_SCANNED"
    FAILED = "FAILED"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    UNKNOWN = "UNKNOWN"

class BaseK8sModule:
    """
    Abstract Base Class for Kubernetes Discovery Implementation Modules.
    Modules are implementation components; capabilities are coverage dimensions.
    """
    module_id: str = "k8s_base"
    capability_name: str = "base"

    def __init__(self):
        self.status: CapabilityStatus = CapabilityStatus.UNKNOWN
        self.error_detail: Optional[str] = None

    async def collect(
        self,
        client: Any,
        cluster_id: str,
        target_id: str
    ) -> AsyncIterator[DiscoveryObservation]:
        raise NotImplementedError("Subclasses must implement collect()")
