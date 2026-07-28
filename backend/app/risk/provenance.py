from datetime import datetime, timezone
from enum import Enum
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.models.entities import Provenance as ProvenanceModel, utc_now

class CollectionMethod(str, Enum):
    ACTIVE = "ACTIVE"
    PASSIVE = "PASSIVE"
    API = "API"
    AGENT = "AGENT"
    IMPORT = "IMPORT"
    STATIC_ANALYSIS = "STATIC_ANALYSIS"

class ProvenanceSchema(BaseModel):
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

def create_provenance_record(
    db: Session,
    plugin_id: str,
    evidence_hash: str,
    plugin_version: str = "1.0.0",
    discovery_run_id: Optional[str] = None,
    target_id: Optional[str] = None,
    collection_method: str = "ACTIVE",
    evidence_type: str = "OBSERVATION",
    confidence: str = "HIGH",
    metadata_json: Optional[Dict[str, Any]] = None
) -> ProvenanceModel:
    """
    Creates and persists a standardized Provenance record.
    Strips any private keys, credentials, or sensitive secrets from metadata.
    """
    clean_meta = dict(metadata_json or {})
    # Strip sensitive keys if present
    for secret_key in ["private_key", "pem", "secret", "token", "password"]:
        clean_meta.pop(secret_key, None)

    prov = ProvenanceModel(
        plugin_id=plugin_id,
        plugin_version=plugin_version,
        discovery_run_id=discovery_run_id,
        target_id=target_id,
        collection_method=collection_method,
        observed_at=utc_now(),
        evidence_type=evidence_type,
        evidence_hash=evidence_hash,
        confidence=confidence,
        metadata_json=clean_meta
    )
    db.add(prov)
    db.flush()
    return prov
