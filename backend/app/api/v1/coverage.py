import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.entities import DiscoveryCoverage, Asset, CryptoFinding

logger = logging.getLogger(__name__)
router = APIRouter()

@router.get("", response_model=List[dict])
def list_coverage(
    asset_id: Optional[str] = Query(None),
    capability: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    query = db.query(DiscoveryCoverage)
    if asset_id:
        query = query.filter(DiscoveryCoverage.asset_id == asset_id)
    if capability:
        query = query.filter(DiscoveryCoverage.capability == capability)

    records = query.all()
    return [
        {
            "id": r.id,
            "asset_id": r.asset_id,
            "capability": r.capability,
            "status": r.status,
            "findings_count": r.findings_count,
            "last_evaluated_at": r.last_evaluated_at.isoformat() if r.last_evaluated_at else None
        }
        for r in records
    ]

@router.get("/summary")
def get_coverage_summary(db: Session = Depends(get_db)):
    """
    Returns enterprise capability coverage summary distinguishing:
    Not Scanned, Scan Failed, Partially Scanned, Scanned With Findings, Scanned Without Findings.
    """
    records = db.query(DiscoveryCoverage).all()
    total_assets = db.query(Asset).count()

    summary_counts = {
        "not_scanned": 0,
        "scan_failed": 0,
        "partially_scanned": 0,
        "scanned_with_findings": 0,
        "scanned_without_findings": 0,
        "not_applicable": 0
    }

    for r in records:
        st = r.status.upper()
        if st == "NOT_SCANNED" or st == "UNKNOWN":
            summary_counts["not_scanned"] += 1
        elif st == "FAILED":
            summary_counts["scan_failed"] += 1
        elif st == "PARTIALLY_SCANNED":
            summary_counts["partially_scanned"] += 1
        elif st == "SCANNED":
            if r.findings_count > 0:
                summary_counts["scanned_with_findings"] += 1
            else:
                summary_counts["scanned_without_findings"] += 1
        elif st == "NOT_APPLICABLE":
            summary_counts["not_applicable"] += 1

    return {
        "total_assets_registered": total_assets,
        "coverage_records_count": len(records),
        "summary": summary_counts
    }
