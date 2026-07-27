from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, status
from sqlalchemy.orm import Session
from typing import List

from app.core.database import get_db
from app.models.entities import ScanJob, AuthorizedTarget, ScanStatus
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

@router.get("/scans/{scan_id}", response_model=ScanResponse)
def get_scan(scan_id: str, db: Session = Depends(get_db)):
    scan_job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
    if not scan_job:
        raise HTTPException(status_code=404, detail=f"ScanJob {scan_id} not found")
    return scan_job
