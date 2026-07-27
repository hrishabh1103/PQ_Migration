from abc import ABC, abstractmethod
from typing import AsyncIterator, Set, Dict, Any, Optional
from pydantic import BaseModel, Field
from app.models.entities import (
    TargetType, AssetType, TransportProtocol, ApplicationProtocol,
    FindingType, FindingPurpose, FindingConfidence
)

class RawFinding(BaseModel):
    asset_hostname: Optional[str] = None
    asset_ip: Optional[str] = None
    asset_type: AssetType = AssetType.HOST
    environment: str = "DEVELOPMENT"
    operating_system: Optional[str] = None
    
    port: Optional[int] = None
    transport_protocol: TransportProtocol = TransportProtocol.TCP
    application_protocol: ApplicationProtocol = ApplicationProtocol.HTTPS
    service_name: str = "https"
    service_metadata: Dict[str, Any] = Field(default_factory=dict)
    
    finding_type: FindingType
    raw_algorithm_name: str
    key_size: Optional[int] = None
    curve_or_parameter: Optional[str] = None
    purpose: FindingPurpose = FindingPurpose.UNKNOWN
    location_identifier: str
    evidence_snippet: str
    confidence: FindingConfidence = FindingConfidence.HIGH
    metadata: Dict[str, Any] = Field(default_factory=dict)

class ScanContext(BaseModel):
    scan_job_id: str
    target_id: str
    options: Dict[str, Any] = Field(default_factory=dict)

class Scanner(ABC):
    scanner_id: str
    version: str
    supported_target_types: Set[TargetType]

    @abstractmethod
    async def discover(
        self,
        target_value: str,
        target_type: TargetType,
        context: ScanContext
    ) -> AsyncIterator[RawFinding]:
        pass

class ScannerRegistry:
    _registry: Dict[str, Scanner] = {}

    @classmethod
    def register(cls, scanner: Scanner) -> None:
        cls._registry[scanner.scanner_id] = scanner

    @classmethod
    def get(cls, scanner_id: str) -> Optional[Scanner]:
        return cls._registry.get(scanner_id)

    @classmethod
    def list_scanners(cls) -> Dict[str, Scanner]:
        return dict(cls._registry)

    @classmethod
    def clear(cls):
        cls._registry.clear()
