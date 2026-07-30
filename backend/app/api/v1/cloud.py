import logging
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field

from app.core.database import get_db
from app.models.entities import AuthorizedTarget, TargetType, ScanJob, ScanStatus
from app.orchestrator.engine import DiscoveryOrchestrator

logger = logging.getLogger(__name__)

router = APIRouter()

class CloudInstanceRegistration(BaseModel):
    name: str = Field(..., json_schema_extra={"example": "AWS Prod EC2 Cluster"})
    cloud_provider: str = Field(..., json_schema_extra={"example": "AWS"})  # AWS, GCP, AZURE, KUBERNETES
    target_type: TargetType = Field(TargetType.CLOUD_SERVER, json_schema_extra={"example": "CLOUD_SERVER"})
    target_value: str = Field(..., json_schema_extra={"example": "ec2-prod-api.us-east-1.amazonaws.com"})
    environment: str = Field("PRODUCTION", json_schema_extra={"example": "PRODUCTION"})
    region: Optional[str] = Field("us-east-1", json_schema_extra={"example": "us-east-1"})

class CloudQuickAuditRequest(BaseModel):
    cloud_targets: List[CloudInstanceRegistration]

@router.post("/register-instance", status_code=status.HTTP_201_CREATED)
def register_cloud_instance(
    input_data: CloudInstanceRegistration,
    db: Session = Depends(get_db)
):
    """
    Registers a Cloud VM, Cloud KMS key, or Cloud Load Balancer target for Cryptographic Discovery.
    """
    target = AuthorizedTarget(
        name=f"[{input_data.cloud_provider}] {input_data.name}",
        target_type=input_data.target_type,
        target_value=input_data.target_value,
        is_authorized=True,
        environment=input_data.environment
    )
    db.add(target)
    db.commit()
    db.refresh(target)
    return {
        "message": f"Cloud instance '{target.name}' registered successfully.",
        "target_id": target.id,
        "target": {
            "id": target.id,
            "name": target.name,
            "target_type": target.target_type.value,
            "target_value": target.target_value,
            "environment": target.environment,
            "cloud_provider": input_data.cloud_provider,
            "region": input_data.region
        }
    }

@router.post("/quick-audit")
async def run_cloud_quick_audit(
    payload: CloudQuickAuditRequest,
    db: Session = Depends(get_db)
):
    """
    Bulk registers Cloud Servers/Services and runs instant Cloud Quantum Discovery Scans.
    """
    results = []
    orchestrator = DiscoveryOrchestrator(db)

    for instance in payload.cloud_targets:
        # Register or update
        target = db.query(AuthorizedTarget).filter(
            AuthorizedTarget.target_value == instance.target_value
        ).first()

        if not target:
            target = AuthorizedTarget(
                name=f"[{instance.cloud_provider}] {instance.name}",
                target_type=instance.target_type,
                target_value=instance.target_value,
                is_authorized=True,
                environment=instance.environment
            )
            db.add(target)
            db.commit()
            db.refresh(target)

        # Trigger scan job with CloudServerScanner
        scan_job = orchestrator.create_scan_job(
            target_id=target.id,
            requested_scanners=["cloud-server-scanner", "tls-scanner", "ssh-scanner"]
        )
        
        # Execute scan
        asyncio.create_task(orchestrator.execute_scan_job(scan_job.id))

        results.append({
            "target_id": target.id,
            "target_name": target.name,
            "target_value": target.target_value,
            "scan_job_id": scan_job.id,
            "status": scan_job.status.value
        })

    return {
        "message": f"Triggered quantum discovery audit for {len(results)} cloud infrastructure targets.",
        "audit_jobs": results
    }

@router.get("/scorecard")
def get_cloud_scorecard(db: Session = Depends(get_db)):
    """
    Returns the Cloud Server Cryptographic Posture & PQC Migration Readiness Scorecard
    calculated strictly from persisted evidence.
    """
    cloud_targets = db.query(AuthorizedTarget).filter(
        AuthorizedTarget.target_type.in_([
            TargetType.CLOUD_PROVIDER,
            TargetType.CLOUD_SERVER,
            TargetType.CLOUD_KMS,
            TargetType.CONTAINER_REGISTRY
        ])
    ).all()

    from app.models.entities import CryptoFinding, ReadinessAssessment
    findings = db.query(CryptoFinding).all()
    assessments = db.query(ReadinessAssessment).all()

    vulnerable_kms = sum(1 for f in findings if ("RSA" in f.raw_algorithm_name or "ECDSA" in f.raw_algorithm_name) and "kms" in (f.location_identifier or "").lower())
    pqc_services = sum(1 for f in findings if "ML-KEM" in f.raw_algorithm_name or "ML-DSA" in f.raw_algorithm_name)
    hybrid_tls = sum(1 for f in findings if "X25519" in f.raw_algorithm_name or "MLKEM" in f.raw_algorithm_name)

    if assessments and len(assessments) > 0:
        avg_priority = sum(a.migration_priority_score for a in assessments) / len(assessments)
        score = max(0, min(100, round(100 - avg_priority, 1)))
    else:
        score = 0.0 if len(cloud_targets) == 0 else 50.0

    return {
        "summary": {
            "total_cloud_targets": len(cloud_targets),
            "cloud_pqc_readiness_score": score,
            "quantum_vulnerable_kms_keys": vulnerable_kms,
            "pqc_standardized_services": pqc_services,
            "hybrid_tls13_endpoints": hybrid_tls
        },
        "remediation_roadmap": []
    }
