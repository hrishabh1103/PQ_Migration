from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List

from app.core.database import get_db
from app.models.entities import AuthorizedTarget
from app.schemas.target import TargetCreate, TargetResponse

router = APIRouter()

@router.post("/targets", response_model=TargetResponse, status_code=status.HTTP_201_CREATED)
def create_target(target_in: TargetCreate, db: Session = Depends(get_db)):
    target = AuthorizedTarget(
        name=target_in.name,
        target_type=target_in.target_type,
        target_value=target_in.target_value,
        is_authorized=target_in.is_authorized,
        environment=target_in.environment
    )
    db.add(target)
    db.commit()
    db.refresh(target)
    return target

@router.get("/targets", response_model=List[TargetResponse])
def list_targets(db: Session = Depends(get_db)):
    return db.query(AuthorizedTarget).order_by(AuthorizedTarget.created_at.desc()).all()

@router.get("/targets/{target_id}", response_model=TargetResponse)
def get_target(target_id: str, db: Session = Depends(get_db)):
    target = db.query(AuthorizedTarget).filter(AuthorizedTarget.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail=f"Target {target_id} not found")
    return target
