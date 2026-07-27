from pydantic import BaseModel, ConfigDict
from datetime import datetime
from typing import Optional, List, Dict, Any
from app.models.entities import ScanStatus

class ScanCreate(BaseModel):
    target_id: str
    requested_scanners: Optional[List[str]] = None

class ScanResponse(BaseModel):
    id: str
    target_id: str
    status: ScanStatus
    requested_scanners: List[str]
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None
    stats_json: Dict[str, Any]

    model_config = ConfigDict(from_attributes=True)
