from abc import ABC, abstractmethod
from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

from app.collectors.transport import LinuxTransport
from app.collectors.observations import DiscoveryObservation

class ModuleResultStatus(str, Enum):
    SUCCESS = "SUCCESS"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    NOT_APPLICABLE = "NOT_APPLICABLE"

class ModuleResult(BaseModel):
    module_id: str
    capability: str
    status: ModuleResultStatus
    observations: List[DiscoveryObservation] = Field(default_factory=list)
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

class BaseCollectorModule(ABC):
    module_id: str
    capability: str

    @abstractmethod
    async def run(self, transport: LinuxTransport) -> ModuleResult:
        pass
