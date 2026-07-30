from pydantic import BaseModel, ConfigDict
from datetime import datetime
from typing import Optional, List, Dict, Any
from app.models.entities import AssetType, TransportProtocol, ApplicationProtocol

class ServiceResponse(BaseModel):
    id: str
    asset_id: str
    port: Optional[int] = None
    transport_protocol: TransportProtocol
    application_protocol: ApplicationProtocol
    service_name: str
    metadata_json: Dict[str, Any]
    first_seen_at: datetime
    last_seen_at: datetime

    model_config = ConfigDict(from_attributes=True)

class AssetBase(BaseModel):
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    asset_type: str
    environment: str
    operating_system: Optional[str] = None

class AssetResponse(AssetBase):
    id: str
    target_id: str
    metadata_json: Dict[str, Any]
    first_seen_at: datetime
    last_seen_at: datetime
    services: List[ServiceResponse] = []

    model_config = ConfigDict(from_attributes=True)
