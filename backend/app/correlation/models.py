from enum import Enum
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field

class CorrelationDecision(str, Enum):
    IDENTICAL = "IDENTICAL"
    LIKELY_SAME = "LIKELY_SAME"
    RELATED = "RELATED"
    UNRESOLVED = "UNRESOLVED"
    CONFLICTING = "CONFLICTING"

class EvidenceStrength(str, Enum):
    STRONG = "STRONG"
    MEDIUM = "MEDIUM"
    WEAK = "WEAK"

class CorrelationEvidence(BaseModel):
    evidence_type: str  # e.g. "PROVIDER_RESOURCE_ID", "X509_FINGERPRINT", "PRIVATE_DNS", "IP_ADDRESS"
    source_value: Optional[str] = None
    target_value: Optional[str] = None
    strength: EvidenceStrength
    matched: bool
    description: str
