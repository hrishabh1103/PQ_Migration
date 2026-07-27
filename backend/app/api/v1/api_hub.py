from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from urllib.parse import urlparse
import json

from app.core.database import get_db
from app.models.entities import AuthorizedTarget, TargetType, ScanJob, ScanStatus
from app.schemas.target import TargetResponse
from app.orchestrator.engine import DiscoveryOrchestrator

router = APIRouter()

class BulkApiServerInput(BaseModel):
    name: Optional[str] = "Team API Server"
    endpoints: List[str]  # e.g. ["https://api.company.com", "10.0.0.1:443", "https://auth.internal.net"]
    environment: str = "PRODUCTION"
    run_immediate_scan: bool = True

@router.post("/api-hub/bulk-register")
async def bulk_register_api_servers(
    payload: BulkApiServerInput,
    db: Session = Depends(get_db)
):
    created_targets = []
    created_scans = []

    for idx, raw_endpoint in enumerate(payload.endpoints):
        endpoint = raw_endpoint.strip()
        if not endpoint:
            continue

        # Parse target type & host
        if "://" in endpoint:
            parsed = urlparse(endpoint)
            target_value = parsed.hostname or endpoint
            target_type = TargetType.URL
        elif ":" in endpoint and not endpoint.startswith("["):
            target_value = endpoint
            target_type = TargetType.HOSTNAME
        else:
            target_value = endpoint
            target_type = TargetType.HOSTNAME

        target_name = f"{payload.name} ({target_value})"

        # Check if already registered
        existing = db.query(AuthorizedTarget).filter(
            AuthorizedTarget.target_value == target_value
        ).first()

        if not existing:
            target = AuthorizedTarget(
                name=target_name,
                target_type=target_type,
                target_value=target_value,
                is_authorized=True,
                environment=payload.environment
            )
            db.add(target)
            db.flush()
            existing = target

        created_targets.append(existing)

        # Trigger immediate scan if requested
        if payload.run_immediate_scan:
            scan_job = ScanJob(
                target_id=existing.id,
                status=ScanStatus.PENDING,
                requested_scanners=["tls-scanner", "ssh-scanner", "certificate-scanner", "mock-scanner"]
            )
            db.add(scan_job)
            db.flush()
            created_scans.append(scan_job)

    db.commit()

    # Run orchestrator async for created scans
    for scan in created_scans:
        await DiscoveryOrchestrator.run_scan_job(db, scan.id)

    return {
        "message": f"Successfully registered {len(created_targets)} API servers and initiated quantum discovery scans.",
        "registered_targets_count": len(created_targets),
        "initiated_scans_count": len(created_scans)
    }

@router.post("/api-hub/import-openapi")
async def import_openapi_spec(
    file: UploadFile = File(...),
    environment: str = "PRODUCTION",
    db: Session = Depends(get_db)
):
    try:
        content = await file.read()
        spec = json.loads(content.decode("utf-8"))

        servers = spec.get("servers", [])
        endpoints = []
        for server in servers:
            url = server.get("url")
            if url:
                endpoints.append(url)

        if not endpoints:
            raise HTTPException(status_code=400, detail="No server URLs found in OpenAPI specification file.")

        bulk_input = BulkApiServerInput(
            name=f"OpenAPI Spec ({file.filename})",
            endpoints=endpoints,
            environment=environment,
            run_immediate_scan=True
        )
        return await bulk_register_api_servers(bulk_input, db)

    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to parse OpenAPI file: {str(e)}")
