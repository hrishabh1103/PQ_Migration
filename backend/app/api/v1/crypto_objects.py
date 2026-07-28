import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from pydantic import BaseModel, Field

from app.core.database import get_db
from app.models.entities import CryptoObject

logger = logging.getLogger(__name__)
router = APIRouter()

class CryptoObjectCreate(BaseModel):
    object_type: str = Field(..., json_schema_extra={"example": "CERTIFICATE"})
    canonical_name: str = Field(..., json_schema_extra={"example": "DigiCert TLS RSA SHA256 Root CA"})
    provider: Optional[str] = Field("DigiCert", json_schema_extra={"example": "DigiCert"})
    version: Optional[str] = Field("v3", json_schema_extra={"example": "v3"})
    identity_key: str = Field(..., json_schema_extra={"example": "cert-sha256-a1b2c3d4e5f6"})
    fingerprint: Optional[str] = Field(None, json_schema_extra={"example": "a1b2c3d4e5f67890"})
    external_id: Optional[str] = None
    provider_resource_id: Optional[str] = None
    metadata_json: dict = Field(default_factory=dict)

@router.get("", response_model=List[dict])
def list_crypto_objects(
    object_type: Optional[str] = Query(None),
    fingerprint: Optional[str] = Query(None),
    provider: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    query = db.query(CryptoObject)
    if object_type:
        query = query.filter(CryptoObject.object_type == object_type)
    if fingerprint:
        query = query.filter(CryptoObject.fingerprint == fingerprint)
    if provider:
        query = query.filter(CryptoObject.provider == provider)

    objs = query.all()
    return [
        {
            "id": o.id,
            "object_type": o.object_type,
            "canonical_name": o.canonical_name,
            "provider": o.provider,
            "version": o.version,
            "identity_key": o.identity_key,
            "fingerprint": o.fingerprint,
            "external_id": o.external_id,
            "provider_resource_id": o.provider_resource_id,
            "metadata_json": o.metadata_json,
            "status": o.status,
            "first_seen_at": o.first_seen_at.isoformat() if o.first_seen_at else None,
            "last_seen_at": o.last_seen_at.isoformat() if o.last_seen_at else None
        }
        for o in objs
    ]

@router.get("/{id}")
def get_crypto_object_by_id(id: str, db: Session = Depends(get_db)):
    o = db.query(CryptoObject).filter(CryptoObject.id == id).first()
    if not o:
        raise HTTPException(status_code=404, detail="CryptoObject not found")
    return {
        "id": o.id,
        "object_type": o.object_type,
        "canonical_name": o.canonical_name,
        "provider": o.provider,
        "version": o.version,
        "identity_key": o.identity_key,
        "fingerprint": o.fingerprint,
        "external_id": o.external_id,
        "provider_resource_id": o.provider_resource_id,
        "metadata_json": o.metadata_json,
        "status": o.status,
        "first_seen_at": o.first_seen_at.isoformat() if o.first_seen_at else None,
        "last_seen_at": o.last_seen_at.isoformat() if o.last_seen_at else None
    }

@router.post("", status_code=status.HTTP_201_CREATED)
def get_or_create_crypto_object(input_data: CryptoObjectCreate, db: Session = Depends(get_db)):
    """
    Deterministic identity resolution & deduplication for CryptoObject based on identity_key.
    Uses database uniqueness guarantees and handles IntegrityError for concurrent requests.
    """
    effective_key = input_data.identity_key
    if input_data.object_type.upper() == "CERTIFICATE" and input_data.fingerprint:
        clean_fp = input_data.fingerprint.lower().replace(":", "").replace(" ", "")
        effective_key = f"cert:sha256:{clean_fp}"

    existing = db.query(CryptoObject).filter(CryptoObject.identity_key == effective_key).first()
    if existing:
        return {
            "message": "CryptoObject resolved (existing found)",
            "id": existing.id,
            "is_new": False,
            "identity_key": existing.identity_key
        }

    try:
        cobj = CryptoObject(
            object_type=input_data.object_type,
            canonical_name=input_data.canonical_name,
            provider=input_data.provider,
            version=input_data.version,
            identity_key=effective_key,
            fingerprint=input_data.fingerprint,
            external_id=input_data.external_id,
            provider_resource_id=input_data.provider_resource_id,
            metadata_json=input_data.metadata_json
        )
        db.add(cobj)
        db.commit()
        db.refresh(cobj)
        return {
            "message": "CryptoObject created",
            "id": cobj.id,
            "is_new": True,
            "identity_key": cobj.identity_key
        }
    except IntegrityError:
        db.rollback()
        existing = db.query(CryptoObject).filter(CryptoObject.identity_key == effective_key).first()
        if existing:
            return {
                "message": "CryptoObject resolved (concurrency conflict handled)",
                "id": existing.id,
                "is_new": False,
                "identity_key": existing.identity_key
            }
        raise HTTPException(status_code=500, detail="Failed to resolve CryptoObject concurrently")
