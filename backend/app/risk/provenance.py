from datetime import datetime, timezone
from enum import Enum
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field

def utc_now():
    return datetime.now(timezone.utc)

class CollectionMethod(str, Enum):
    ACTIVE = "ACTIVE"
    PASSIVE = "PASSIVE"
    API = "API"
    AGENT = "AGENT"
    IMPORT = "IMPORT"
    STATIC_ANALYSIS = "STATIC_ANALYSIS"

class Provenance(BaseModel):
    plugin_id: str
    plugin_version: str = "1.0.0"
    discovery_run_id: Optional[str] = None
    target_id: Optional[str] = None
    observed_at: datetime = Field(default_factory=utc_now)
    evidence_type: str = "OBSERVATION"
    evidence_hash: str
    confidence: str = "HIGH"
    collection_method: CollectionMethod = CollectionMethod.ACTIVE
    metadata: Dict[str, Any] = Field(default_factory=dict)
