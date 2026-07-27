from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.core.database import get_db
from app.models.entities import Asset, Service, CryptoFinding, ScanJob, NormalizedAlgorithm, ScanStatus
from app.schemas.stats import DashboardStatsResponse

router = APIRouter()

@router.get("/stats/dashboard", response_model=DashboardStatsResponse)
def get_dashboard_stats(db: Session = Depends(get_db)):
    assets_count = db.query(Asset).count()
    services_count = db.query(Service).count()
    findings_count = db.query(CryptoFinding).count()
    scan_jobs_count = db.query(ScanJob).count()

    # Algorithm family distribution
    algo_dist = {
        "RSA": 0,
        "ECDSA": 0,
        "ECDH": 0,
        "X25519": 0,
        "AES": 0,
        "SHA": 0,
        "ML-KEM": 0,
        "ML-DSA": 0,
        "Unknown": 0
    }

    findings = db.query(CryptoFinding).all()
    for finding in findings:
        norm = db.query(NormalizedAlgorithm).filter(NormalizedAlgorithm.canonical_id == finding.normalized_algorithm_id).first()
        if not norm:
            algo_dist["Unknown"] += 1
            continue

        family = (norm.canonical_family or "").upper()
        raw = (finding.raw_algorithm_name or "").upper()
        canonical_id = (norm.canonical_id or "").upper()

        if "RSA" in family or "RSA" in raw:
            algo_dist["RSA"] += 1
        elif "ECDSA" in family or "ECDSA" in raw or "P256" in raw:
            algo_dist["ECDSA"] += 1
        elif "ECDH" in family or "ECDH" in raw:
            algo_dist["ECDH"] += 1
        elif "X25519" in family or "X25519" in raw or "25519" in canonical_id:
            algo_dist["X25519"] += 1
        elif "AES" in family or "AES" in raw:
            algo_dist["AES"] += 1
        elif "SHA" in family or "SHA" in raw:
            algo_dist["SHA"] += 1
        elif "ML-KEM" in family or "KYBER" in raw or "ML-KEM" in canonical_id:
            algo_dist["ML-KEM"] += 1
        elif "ML-DSA" in family or "DILITHIUM" in raw or "ML-DSA" in canonical_id:
            algo_dist["ML-DSA"] += 1
        else:
            algo_dist["Unknown"] += 1

    # Scan status distribution
    scan_dist = {
        "Pending": 0,
        "Running": 0,
        "Completed": 0,
        "Failed": 0,
        "Cancelled": 0
    }

    scans = db.query(ScanJob).all()
    for scan in scans:
        st = scan.status.value.capitalize()
        if st in scan_dist:
            scan_dist[st] += 1

    return DashboardStatsResponse(
        assets_count=assets_count,
        services_count=services_count,
        findings_count=findings_count,
        scan_jobs_count=scan_jobs_count,
        algorithm_distribution=algo_dist,
        scan_status_distribution=scan_dist
    )
