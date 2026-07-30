import logging
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.entities import AuthorizedTarget, DiscoveryRun, Asset, CryptoObject, Relationship
from app.connectors.aws_sdk_client import AWSSdkClient
from app.orchestrator.engine import DiscoveryOrchestrator

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/connectors/aws", tags=["AWS Connector"])

class AWSValidateRequest(BaseModel):
    region_name: str = Field(default="us-east-1", description="Default AWS Region")
    profile_name: Optional[str] = Field(default=None, description="AWS SDK Profile Name")
    role_arn: Optional[str] = Field(default=None, description="IAM Role ARN for STS AssumeRole")

class AWSSyncRequest(BaseModel):
    target_id: str = Field(..., description="Authorized Target ID")
    allowed_regions: Optional[List[str]] = Field(default_factory=lambda: ["us-east-1"], description="Allowed AWS Regions")
    profile_name: Optional[str] = Field(default=None)
    role_arn: Optional[str] = Field(default=None)

@router.post("/validate")
def validate_aws_identity(req: AWSValidateRequest):
    """
    Validate AWS caller identity using STS GetCallerIdentity.
    Returns safe account metadata (Account, ARN, User ID). Zero secret keys exposed.
    """
    client = AWSSdkClient(
        region_name=req.region_name,
        profile_name=req.profile_name,
        role_arn=req.role_arn
    )
    val = client.validate_identity()
    if not val.get("validated"):
        raise HTTPException(status_code=400, detail=val.get("error", "AWS STS identity validation failed"))
    return val

@router.post("/sync")
async def trigger_aws_sync(req: AWSSyncRequest, db: Session = Depends(get_db)):
    """
    Trigger AWS Connector read-only discovery sync across authorized regions & services.
    Creates DiscoveryRun (type=SYNC).
    """
    target = db.query(AuthorizedTarget).filter(AuthorizedTarget.id == req.target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail=f"Target '{req.target_id}' not found")

    try:
        run = await DiscoveryOrchestrator.run_connector_sync(
            db=db,
            target_id=req.target_id,
            connector_plugin_id="aws",
            allowed_regions=req.allowed_regions,
            profile_name=req.profile_name,
            role_arn=req.role_arn
        )
        return {
            "status": "COMPLETED",
            "run_id": run.id,
            "target_id": target.id,
            "stats": run.stats_json
        }
    except Exception as e:
        logger.error(f"AWS Sync failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/coverage/{target_id}")
def get_aws_coverage(target_id: str, db: Session = Depends(get_db)):
    """
    Get AWS discovery coverage breakdown per service & region.
    """
    target = db.query(AuthorizedTarget).filter(AuthorizedTarget.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail=f"Target '{target_id}' not found")

    latest_run = db.query(DiscoveryRun).filter(
        DiscoveryRun.target_id == target_id,
        DiscoveryRun.plugin_id == "aws"
    ).order_by(DiscoveryRun.started_at.desc()).first()

    modules = [
        {"name": "STS Identity", "service": "STS", "capability": "IDENTITY", "status": "SCANNED" if latest_run else "NOT_SCANNED"},
        {"name": "Regions", "service": "EC2", "capability": "CLOUD_RESOURCE", "status": "SCANNED" if latest_run else "NOT_SCANNED"},
        {"name": "EC2 Instances", "service": "EC2", "capability": "CLOUD_COMPUTE", "status": "SCANNED" if latest_run else "NOT_SCANNED"},
        {"name": "EBS Volumes", "service": "EC2", "capability": "CLOUD_STORAGE", "status": "SCANNED" if latest_run else "NOT_SCANNED"},
        {"name": "KMS Key Metadata & Specs", "service": "KMS", "capability": "KMS", "status": "SCANNED" if latest_run else "NOT_SCANNED"},
        {"name": "ACM Certificates", "service": "ACM", "capability": "X509", "status": "SCANNED" if latest_run else "NOT_SCANNED"},
        {"name": "ELBv2 Load Balancers", "service": "ELBv2", "capability": "CLOUD_LOAD_BALANCER", "status": "SCANNED" if latest_run else "NOT_SCANNED"},
        {"name": "S3 Encryption Config", "service": "S3", "capability": "CLOUD_STORAGE", "status": "SCANNED" if latest_run else "NOT_SCANNED"},
        {"name": "RDS DB Instances", "service": "RDS", "capability": "CLOUD_DATABASE", "status": "SCANNED" if latest_run else "NOT_SCANNED"},
        {"name": "CloudFront CDN", "service": "CloudFront", "capability": "CLOUD_CDN", "status": "SCANNED" if latest_run else "NOT_SCANNED"}
    ]

    return {
        "target_id": target_id,
        "latest_run": latest_run.id if latest_run else None,
        "status": latest_run.status if latest_run else "NOT_SCANNED",
        "coverage": modules
    }

@router.get("/inventory/{target_id}")
def get_aws_inventory(target_id: str, db: Session = Depends(get_db)):
    """
    Get discovered AWS resources, KMS keys, certificates, and relationships.
    """
    from sqlalchemy import or_, func
    assets = db.query(Asset).filter(
        or_(
            Asset.target_id == target_id,
            func.lower(Asset.provider) == "aws"
        )
    ).all()
    crypto_objects = db.query(CryptoObject).all()
    relationships = db.query(Relationship).filter(Relationship.scanner_or_connector_id == "aws").all()

    return {
        "target_id": target_id,
        "assets_count": len(assets),
        "crypto_objects_count": len(crypto_objects),
        "relationships_count": len(relationships),
        "assets": [
            {
                "id": a.id,
                "asset_type": a.asset_type,
                "asset_category": a.asset_category,
                "provider_resource_id": a.provider_resource_id or a.identity_key or a.id,
                "external_id": a.external_id or a.provider_resource_id,
                "hostname": a.hostname or a.provider_resource_id or a.id[:8],
                "region": a.region or "ap-south-1",
                "metadata": a.metadata_json
            } for a in assets
        ],
        "crypto_objects": [
            {
                "id": c.id,
                "object_type": c.object_type,
                "canonical_name": c.canonical_name,
                "fingerprint": c.fingerprint,
                "metadata": c.metadata_json
            } for c in crypto_objects
        ]
    }

# Provider-Neutral Generic Connector Endpoints
generic_router = APIRouter(prefix="/connectors", tags=["Cloud Connectors"])

@generic_router.post("/{provider}/validate")
def validate_connector_identity(provider: str, req: Dict[str, Any]):
    provider_clean = provider.lower()
    if provider_clean == "azure":
        from app.connectors.azure_client import AzureSdkClient
        client = AzureSdkClient(subscription_id=req.get("subscription_id"), tenant_id=req.get("tenant_id"))
        val = client.validate_identity()
        return val
    elif provider_clean == "aws":
        client = AWSSdkClient(region_name=req.get("region_name", "us-east-1"))
        return client.validate_identity()
    else:
        raise HTTPException(status_code=400, detail=f"Unsupported connector provider '{provider}'")

@generic_router.post("/{provider}/sync")
async def trigger_connector_sync(provider: str, req: Dict[str, Any], db: Session = Depends(get_db)):
    target_id = req.get("target_id")
    if not target_id:
        raise HTTPException(status_code=400, detail="Missing required 'target_id' parameter")

    target = db.query(AuthorizedTarget).filter(AuthorizedTarget.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail=f"Target '{target_id}' not found")

    try:
        run = await DiscoveryOrchestrator.run_connector_sync(
            db=db,
            target_id=target_id,
            connector_plugin_id=provider.lower(),
            allowed_regions=req.get("allowed_regions")
        )
        return {
            "status": "COMPLETED",
            "run_id": run.id,
            "target_id": target.id,
            "provider": provider.lower(),
            "stats": run.stats_json
        }
    except Exception as e:
        logger.error(f"Connector sync for '{provider}' failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

