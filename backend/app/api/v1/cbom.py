from fastapi import APIRouter, Depends, Response
from sqlalchemy.orm import Session
import json

from app.core.database import get_db
from app.cbom.builder import CycloneDXCBOMBuilder

router = APIRouter()

@router.get("/cbom/export")
def export_cbom_json(db: Session = Depends(get_db)):
    cbom_data = CycloneDXCBOMBuilder.generate_cbom_json(db)
    return Response(
        content=json.dumps(cbom_data, indent=2),
        media_type="application/json",
        headers={
            "Content-Disposition": "attachment; filename=cyclonedx_cbom_1.6.json"
        }
    )
