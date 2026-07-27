from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session, joinedload
from typing import List

from app.core.database import get_db
from app.models.entities import CryptoFinding
from app.schemas.finding import CryptoFindingResponse

router = APIRouter()

@router.get("/findings", response_model=List[CryptoFindingResponse])
def list_findings(db: Session = Depends(get_db)):
    return db.query(CryptoFinding).options(joinedload(CryptoFinding.normalized_algorithm)).order_by(CryptoFinding.first_seen_at.desc()).all()

@router.get("/findings/{finding_id}", response_model=CryptoFindingResponse)
def get_finding(finding_id: str, db: Session = Depends(get_db)):
    finding = db.query(CryptoFinding).options(joinedload(CryptoFinding.normalized_algorithm)).filter(CryptoFinding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail=f"CryptoFinding {finding_id} not found")
    return finding
