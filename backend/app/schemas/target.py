from pydantic import BaseModel, ConfigDict
from datetime import datetime
from typing import Optional
from app.models.entities import TargetType

class TargetBase(BaseModel):
    name: str
    target_type: TargetType
    target_value: str
    is_authorized: bool = True
    environment: str = "DEVELOPMENT"

class TargetCreate(TargetBase):
    pass

class TargetResponse(TargetBase):
    id: str
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)
