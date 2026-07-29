import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.entities import CorrelationRecord
from app.correlation.engine import CorrelationEngine

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/correlations", tags=["Entity Correlation"])

class EvaluateCorrelationRequest(BaseModel):
    source_entity_type: str = Field(..., description="Source entity type (e.g. ASSET, CLOUD_VM, CRYPTO_OBJECT)")
    source_entity_id: str = Field(..., description="Source entity ID")
    target_entity_type: str = Field(..., description="Target entity type")
    target_entity_id: str = Field(..., description="Target entity ID")

@router.get("")
def list_correlations(
    decision: Optional[str] = Query(None, description="Filter by decision (IDENTICAL, LIKELY_SAME, RELATED, UNRESOLVED, CONFLICTING)"),
    source_type: Optional[str] = Query(None, description="Filter by source entity type"),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db)
):
    """
    List persisted correlation records from the database.
    Operates on auditable CorrelationRecord DB rows rather than transient in-memory state.
    """
    query = db.query(CorrelationRecord)
    if decision:
        query = query.filter(CorrelationRecord.decision == decision.upper())
    if source_type:
        query = query.filter(CorrelationRecord.source_entity_type == source_type.upper())

    records = query.order_by(CorrelationRecord.created_at.desc()).limit(limit).all()
    return [
        {
            "id": r.id,
            "source_entity_type": r.source_entity_type,
            "source_entity_id": r.source_entity_id,
            "target_entity_type": r.target_entity_type,
            "target_entity_id": r.target_entity_id,
            "decision": r.decision,
            "confidence": r.confidence,
            "matching_evidence": r.matching_evidence_json,
            "conflicting_evidence": r.conflicting_evidence_json,
            "rule_id": r.rule_id,
            "rule_version": r.rule_version,
            "created_at": r.created_at.isoformat()
        } for r in records
    ]

@router.get("/{correlation_id}")
def get_correlation_detail(correlation_id: str, db: Session = Depends(get_db)):
    """
    Get detailed persisted correlation decision record by ID.
    """
    r = db.query(CorrelationRecord).filter(CorrelationRecord.id == correlation_id).first()
    if not r:
        raise HTTPException(status_code=404, detail=f"CorrelationRecord '{correlation_id}' not found")

    return {
        "id": r.id,
        "source_entity_type": r.source_entity_type,
        "source_entity_id": r.source_entity_id,
        "target_entity_type": r.target_entity_type,
        "target_entity_id": r.target_entity_id,
        "decision": r.decision,
        "confidence": r.confidence,
        "matching_evidence": r.matching_evidence_json,
        "conflicting_evidence": r.conflicting_evidence_json,
        "rule_id": r.rule_id,
        "rule_version": r.rule_version,
        "status": r.status,
        "created_at": r.created_at.isoformat(),
        "updated_at": r.updated_at.isoformat()
    }

@router.post("/evaluate")
def evaluate_correlation(req: EvaluateCorrelationRequest, db: Session = Depends(get_db)):
    """
    Trigger CorrelationEngine evaluation for an entity pair and persist result.
    Executes controlled canonical resolution ONLY if decision is IDENTICAL.
    """
    rec = CorrelationEngine.evaluate_pair(
        db=db,
        source_type=req.source_entity_type,
        source_id=req.source_entity_id,
        target_type=req.target_entity_type,
        target_id=req.target_entity_id
    )

    return {
        "id": rec.id,
        "decision": rec.decision,
        "confidence": rec.confidence,
        "matching_evidence": rec.matching_evidence_json,
        "conflicting_evidence": rec.conflicting_evidence_json,
        "rule_id": rec.rule_id,
        "rule_version": rec.rule_version
    }
