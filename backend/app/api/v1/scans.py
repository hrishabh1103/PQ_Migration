from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, status
from sqlalchemy.orm import Session
from typing import List

from app.core.database import get_db
from app.models.entities import ScanJob, AuthorizedTarget, ScanStatus, utc_now
from app.schemas.scan import ScanCreate, ScanResponse
from app.orchestrator.engine import DiscoveryOrchestrator

router = APIRouter()

async def execute_scan_task(scan_job_id: str):
    from app.core.database import SessionLocal
    db = SessionLocal()
    try:
        await DiscoveryOrchestrator.run_scan_job(db, scan_job_id)
    finally:
        db.close()

@router.post("/scans", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
async def create_scan(
    scan_in: ScanCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    target = db.query(AuthorizedTarget).filter(AuthorizedTarget.id == scan_in.target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail=f"Target {scan_in.target_id} not found")

    scanners = scan_in.requested_scanners or ["mock-scanner"]
    scan_job = ScanJob(
        target_id=target.id,
        status=ScanStatus.PENDING,
        requested_scanners=scanners,
        stats_json={}
    )
    db.add(scan_job)
    db.commit()
    db.refresh(scan_job)

    # Launch background scan execution
    background_tasks.add_task(execute_scan_task, scan_job.id)

    return scan_job

@router.get("/scans", response_model=List[ScanResponse])
def list_scans(db: Session = Depends(get_db)):
    return db.query(ScanJob).order_by(ScanJob.started_at.desc().nullslast()).all()

@router.get("/scans/export/archive")
def export_scans_archive(db: Session = Depends(get_db)):
    from app.models.entities import CryptoFinding, Asset, Service
    from fastapi.responses import JSONResponse
    import json

    scans = db.query(ScanJob).all()
    targets = db.query(AuthorizedTarget).all()
    findings = db.query(CryptoFinding).all()

    archive_data = {
        "exported_at": str(utc_now()),
        "total_targets": len(targets),
        "total_scans": len(scans),
        "total_findings": len(findings),
        "targets": [
            {
                "id": t.id,
                "name": t.name,
                "target_type": t.target_type,
                "target_value": t.target_value,
                "environment": t.environment,
            }
            for t in targets
        ],
        "scans": [
            {
                "id": s.id,
                "target_id": s.target_id,
                "status": s.status,
                "requested_scanners": s.requested_scanners,
                "started_at": str(s.started_at) if s.started_at else None,
                "completed_at": str(s.completed_at) if s.completed_at else None,
                "stats": s.stats_json,
            }
            for s in scans
        ],
        "findings": [
            {
                "id": f.id,
                "scan_job_id": f.scan_job_id,
                "raw_algorithm": f.raw_algorithm_name,
                "finding_type": f.finding_type,
                "location_identifier": f.location_identifier,
                "evidence_snippet": f.evidence_snippet,
            }
            for f in findings
        ]
    }

    return JSONResponse(
        content=archive_data,
        headers={
            "Content-Disposition": "attachment; filename=pqc_discovery_archive.json"
        }
    )

@router.get("/scans/{scan_id}", response_model=ScanResponse)
def get_scan(scan_id: str, db: Session = Depends(get_db)):
    scan_job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
    if not scan_job:
        raise HTTPException(status_code=404, detail=f"ScanJob {scan_id} not found")
    return scan_job

@router.delete("/scans/{scan_id}", status_code=status.HTTP_200_OK)
def delete_scan(scan_id: str, db: Session = Depends(get_db)):
    scan_job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
    if not scan_job:
        raise HTTPException(status_code=404, detail=f"ScanJob {scan_id} not found")
    
    db.delete(scan_job)
    db.commit()
    return {"message": f"Successfully deleted scan job {scan_id} and associated findings."}

@router.delete("/scans", status_code=status.HTTP_200_OK)
def clear_all_scans(db: Session = Depends(get_db)):
    from app.models.entities import CryptoFinding
    num_scans = db.query(ScanJob).delete()
    num_findings = db.query(CryptoFinding).delete()
    db.commit()
    return {
        "message": f"Successfully cleared all previous scan history and findings.",
        "deleted_scans": num_scans,
        "deleted_findings": num_findings
    }

