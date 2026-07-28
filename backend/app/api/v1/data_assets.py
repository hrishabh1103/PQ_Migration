import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field

from app.core.database import get_db
from app.models.entities import DataAsset, DataFlow

logger = logging.getLogger(__name__)
router = APIRouter()

class DataAssetCreate(BaseModel):
    name: str = Field(..., json_schema_extra={"example": "Customer Financial Transactions"})
    classification: str = Field("RESTRICTED", json_schema_extra={"example": "RESTRICTED"})
    retention_period: Optional[str] = Field("7_YEARS", json_schema_extra={"example": "7_YEARS"})
    business_criticality: str = Field("HIGH", json_schema_extra={"example": "HIGH"})
    metadata_json: dict = Field(default_factory=dict)

class DataFlowCreate(BaseModel):
    source_entity_type: str = Field(..., json_schema_extra={"example": "Asset"})
    source_entity_id: str = Field(..., json_schema_extra={"example": "asset-1"})
    destination_entity_type: str = Field(..., json_schema_extra={"example": "Asset"})
    destination_entity_id: str = Field(..., json_schema_extra={"example": "asset-2"})
    data_asset_id: Optional[str] = None
    protocol: Optional[str] = Field("TLSv1.3", json_schema_extra={"example": "TLSv1.3"})
    crypto_object_id: Optional[str] = None
    protection_purpose: str = Field("ENCRYPTION", json_schema_extra={"example": "ENCRYPTION"})
    direction: str = Field("INBOUND", json_schema_extra={"example": "INBOUND"})
    metadata_json: dict = Field(default_factory=dict)

@router.get("/assets", response_model=List[dict])
def list_data_assets(db: Session = Depends(get_db)):
    items = db.query(DataAsset).all()
    return [
        {
            "id": d.id,
            "name": d.name,
            "classification": d.classification,
            "retention_period": d.retention_period,
            "business_criticality": d.business_criticality,
            "metadata_json": d.metadata_json,
            "status": d.status,
            "first_seen_at": d.first_seen_at.isoformat() if d.first_seen_at else None
        }
        for d in items
    ]

@router.post("/assets", status_code=status.HTTP_201_CREATED)
def create_data_asset(input_data: DataAssetCreate, db: Session = Depends(get_db)):
    da = DataAsset(
        name=input_data.name,
        classification=input_data.classification,
        retention_period=input_data.retention_period,
        business_criticality=input_data.business_criticality,
        metadata_json=input_data.metadata_json
    )
    db.add(da)
    db.commit()
    db.refresh(da)
    return {"message": "DataAsset created", "id": da.id}

@router.get("/flows", response_model=List[dict])
def list_data_flows(db: Session = Depends(get_db)):
    items = db.query(DataFlow).all()
    return [
        {
            "id": f.id,
            "source_entity_type": f.source_entity_type,
            "source_entity_id": f.source_entity_id,
            "destination_entity_type": f.destination_entity_type,
            "destination_entity_id": f.destination_entity_id,
            "data_asset_id": f.data_asset_id,
            "protocol": f.protocol,
            "crypto_object_id": f.crypto_object_id,
            "protection_purpose": f.protection_purpose,
            "direction": f.direction,
            "metadata_json": f.metadata_json,
            "status": f.status,
            "first_seen_at": f.first_seen_at.isoformat() if f.first_seen_at else None
        }
        for f in items
    ]

@router.post("/flows", status_code=status.HTTP_201_CREATED)
def create_data_flow(input_data: DataFlowCreate, db: Session = Depends(get_db)):
    df = DataFlow(
        source_entity_type=input_data.source_entity_type,
        source_entity_id=input_data.source_entity_id,
        destination_entity_type=input_data.destination_entity_type,
        destination_entity_id=input_data.destination_entity_id,
        data_asset_id=input_data.data_asset_id,
        protocol=input_data.protocol,
        crypto_object_id=input_data.crypto_object_id,
        protection_purpose=input_data.protection_purpose,
        direction=input_data.direction,
        metadata_json=input_data.metadata_json
    )
    db.add(df)
    db.commit()
    db.refresh(df)
    return {"message": "DataFlow created", "id": df.id}
