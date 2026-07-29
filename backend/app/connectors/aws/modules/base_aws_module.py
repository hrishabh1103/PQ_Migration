from abc import ABC, abstractmethod
from enum import Enum
from typing import AsyncIterator, List, Dict, Any, Optional
from app.collectors.observations import DiscoveryObservation
from app.connectors.aws_sdk_client import AWSSdkClient

class ModuleStatus(str, Enum):
    SUCCESS = "SCANNED"
    PARTIAL = "PARTIALLY_SCANNED"
    FAILED = "FAILED"
    NOT_APPLICABLE = "NOT_APPLICABLE"

class BaseAWSModule(ABC):
    """
    Abstract base class for modular AWS service discovery components.
    Provides failure isolation per region/service and yields structured DiscoveryObservations.
    """
    module_name: str
    capability: str

    @abstractmethod
    async def collect(
        self,
        sdk_client: AWSSdkClient,
        account_id: str,
        region: str,
        target_id: str
    ) -> AsyncIterator[DiscoveryObservation]:
        pass
