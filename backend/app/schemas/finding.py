from pydantic import BaseModel, ConfigDict
from datetime import datetime
from typing import Optional, Dict, Any
from app.models.entities import (
    FindingType, FindingPurpose, FindingConfidence, QuantumSafetyStatus, PrimitiveType
)

class NormalizedAlgorithmResponse(BaseModel):
    canonical_id: str
    name: str
    observed_name: str
    canonical_family: str
    canonical_variant: str
    implementation_variant: Optional[str] = None
    primitive_type: PrimitiveType
    quantum_safety_status: QuantumSafetyStatus
    estimated_security_bits: Optional[int] = None
    nist_standard_status: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)

class CryptoFindingResponse(BaseModel):
    id: str
    scan_job_id: str
    asset_id: str
    service_id: Optional[str] = None
    scanner_id: str
    scanner_version: str
    finding_type: FindingType
    raw_algorithm_name: str
    normalized_algorithm_id: str
    purpose: FindingPurpose
    location_identifier: str
    evidence_snippet: str
    evidence_hash: str
    confidence: FindingConfidence
    metadata_json: Dict[str, Any]
    first_seen_at: datetime
    last_seen_at: datetime
    normalized_algorithm: Optional[NormalizedAlgorithmResponse] = None

    model_config = ConfigDict(from_attributes=True)
