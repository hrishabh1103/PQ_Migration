import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field

from app.core.database import get_db
from app.models.entities import Relationship, utc_now

logger = logging.getLogger(__name__)
router = APIRouter()

class RelationshipCreate(BaseModel):
    source_entity_type: str = Field(..., json_schema_extra={"example": "Asset"})
    source_entity_id: str = Field(..., json_schema_extra={"example": "asset-uuid-1"})
    target_entity_type: str = Field(..., json_schema_extra={"example": "CryptoObject"})
    target_entity_id: str = Field(..., json_schema_extra={"example": "crypto-uuid-1"})
    relationship_type: str = Field(..., json_schema_extra={"example": "USES"})
    scanner_or_connector_id: str = Field("tls-scanner", json_schema_extra={"example": "tls-scanner"})
    evidence_snippet: Optional[str] = None
    evidence_hash: Optional[str] = None
    confidence: str = "HIGH"
    metadata_json: dict = Field(default_factory=dict)

@router.get("", response_model=List[dict])
def list_relationships(
    source_entity_id: Optional[str] = Query(None),
    target_entity_id: Optional[str] = Query(None),
    relationship_type: Optional[str] = Query(None),
    entity_type: Optional[str] = Query(None),
    plugin_id: Optional[str] = Query(None),
    min_confidence: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    query = db.query(Relationship)

    if source_entity_id:
        query = query.filter(Relationship.source_entity_id == source_entity_id)
    if target_entity_id:
        query = query.filter(Relationship.target_entity_id == target_entity_id)
    if relationship_type:
        query = query.filter(Relationship.relationship_type == relationship_type)
    if entity_type:
        query = query.filter(
            (Relationship.source_entity_type == entity_type) | (Relationship.target_entity_type == entity_type)
        )
    if plugin_id:
        query = query.filter(Relationship.scanner_or_connector_id == plugin_id)
    if min_confidence:
        query = query.filter(Relationship.confidence == min_confidence)

    relationships = query.all()
    return [
        {
            "id": r.id,
            "source_entity_type": r.source_entity_type,
            "source_entity_id": r.source_entity_id,
            "target_entity_type": r.target_entity_type,
            "target_entity_id": r.target_entity_id,
            "relationship_type": r.relationship_type,
            "scanner_or_connector_id": r.scanner_or_connector_id,
            "evidence_snippet": r.evidence_snippet,
            "evidence_hash": r.evidence_hash,
            "confidence": r.confidence,
            "metadata_json": r.metadata_json,
            "status": r.status,
            "first_seen_at": r.first_seen_at.isoformat() if r.first_seen_at else None,
            "last_seen_at": r.last_seen_at.isoformat() if r.last_seen_at else None
        }
        for r in relationships
    ]

@router.get("/{id}")
def get_relationship_by_id(id: str, db: Session = Depends(get_db)):
    r = db.query(Relationship).filter(Relationship.id == id).first()
    if not r:
        raise HTTPException(status_code=404, detail="Relationship not found")
    return {
        "id": r.id,
        "source_entity_type": r.source_entity_type,
        "source_entity_id": r.source_entity_id,
        "target_entity_type": r.target_entity_type,
        "target_entity_id": r.target_entity_id,
        "relationship_type": r.relationship_type,
        "scanner_or_connector_id": r.scanner_or_connector_id,
        "evidence_snippet": r.evidence_snippet,
        "evidence_hash": r.evidence_hash,
        "confidence": r.confidence,
        "metadata_json": r.metadata_json,
        "status": r.status,
        "first_seen_at": r.first_seen_at.isoformat() if r.first_seen_at else None,
        "last_seen_at": r.last_seen_at.isoformat() if r.last_seen_at else None
    }

@router.post("", status_code=status.HTTP_201_CREATED)
def create_relationship(input_data: RelationshipCreate, db: Session = Depends(get_db)):
    rel = Relationship(
        source_entity_type=input_data.source_entity_type,
        source_entity_id=input_data.source_entity_id,
        target_entity_type=input_data.target_entity_type,
        target_entity_id=input_data.target_entity_id,
        relationship_type=input_data.relationship_type,
        scanner_or_connector_id=input_data.scanner_or_connector_id,
        evidence_snippet=input_data.evidence_snippet,
        evidence_hash=input_data.evidence_hash,
        confidence=input_data.confidence,
        metadata_json=input_data.metadata_json
    )
    db.add(rel)
    db.commit()
    db.refresh(rel)
    return {"message": "Relationship created", "id": rel.id}
