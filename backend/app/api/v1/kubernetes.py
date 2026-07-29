import logging
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.entities import AuthorizedTarget, DiscoveryRun, Asset, CryptoObject, Relationship
from app.connectors.kubernetes_client import KubernetesClient
from app.orchestrator.engine import DiscoveryOrchestrator

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/connectors/kubernetes", tags=["Kubernetes Connector"])

class K8sValidateRequest(BaseModel):
    kubeconfig_path: Optional[str] = Field(default=None, description="Optional path to kubeconfig file")
    context_name: Optional[str] = Field(default=None, description="Optional kubeconfig context name")
    in_cluster: bool = Field(default=False, description="Set True if running inside a K8s pod")

class K8sSyncRequest(BaseModel):
    target_id: str = Field(..., description="Authorized Target ID")
    kubeconfig_path: Optional[str] = Field(default=None)
    context_name: Optional[str] = Field(default=None)
    in_cluster: bool = Field(default=False)

@router.post("/validate")
def validate_kubernetes_connection(req: K8sValidateRequest):
    """
    Validate Kubernetes API server read-only connection.
    Returns safe cluster version & platform metadata. Zero credentials exposed.
    """
    client = KubernetesClient(
        kubeconfig_path=req.kubeconfig_path,
        context_name=req.context_name,
        in_cluster=req.in_cluster
    )
    val = client.validate_connection()
    if not val.get("validated"):
        raise HTTPException(status_code=400, detail=val.get("error", "Kubernetes API validation failed"))
    return val

@router.post("/sync")
async def trigger_kubernetes_sync(req: K8sSyncRequest, db: Session = Depends(get_db)):
    """
    Trigger read-only Kubernetes discovery sync across all 15 capability dimensions.
    """
    target = db.query(AuthorizedTarget).filter(AuthorizedTarget.id == req.target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail=f"Target '{req.target_id}' not found")

    try:
        run = await DiscoveryOrchestrator.run_connector_sync(
            db=db,
            target_id=req.target_id,
            connector_plugin_id="kubernetes",
            kubeconfig_path=req.kubeconfig_path,
            context_name=req.context_name,
            in_cluster=req.in_cluster
        )
        return {
            "status": "COMPLETED",
            "run_id": run.id,
            "target_id": target.id,
            "stats": run.stats_json
        }
    except Exception as e:
        logger.error(f"Kubernetes Sync failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/coverage/{target_id}")
def get_kubernetes_coverage(target_id: str, db: Session = Depends(get_db)):
    """
    Get Kubernetes 15-capability discovery coverage breakdown.
    """
    target = db.query(AuthorizedTarget).filter(AuthorizedTarget.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail=f"Target '{target_id}' not found")

    latest_run = db.query(DiscoveryRun).filter(
        DiscoveryRun.target_id == target_id,
        DiscoveryRun.plugin_id == "kubernetes"
    ).order_by(DiscoveryRun.started_at.desc()).first()

    default_status = "SCANNED" if latest_run and latest_run.status == "COMPLETED" else "NOT_SCANNED"

    capabilities = [
        {"capability": "cluster_identity", "status": default_status},
        {"capability": "nodes", "status": default_status},
        {"capability": "namespaces", "status": default_status},
        {"capability": "workloads", "status": default_status},
        {"capability": "pods", "status": default_status},
        {"capability": "services", "status": default_status},
        {"capability": "ingress", "status": default_status},
        {"capability": "gateway_api", "status": "NOT_APPLICABLE"},
        {"capability": "certificates", "status": default_status},
        {"capability": "secret_metadata", "status": default_status},
        {"capability": "configmaps", "status": default_status},
        {"capability": "rbac", "status": default_status},
        {"capability": "cert_manager", "status": default_status},
        {"capability": "service_mesh", "status": default_status},
        {"capability": "encryption_at_rest", "status": "UNKNOWN"}
    ]

    return {
        "target_id": target_id,
        "plugin_id": "kubernetes",
        "latest_run_id": latest_run.id if latest_run else None,
        "capabilities": capabilities
    }

@router.get("/inventory/{target_id}")
def get_kubernetes_inventory(target_id: str, db: Session = Depends(get_db)):
    """
    Get discovered Kubernetes inventory breakdown for target (Zero secrets/credentials returned).
    """
    target = db.query(AuthorizedTarget).filter(AuthorizedTarget.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail=f"Target '{target_id}' not found")

    assets = db.query(Asset).filter(Asset.target_id == target_id).all()
    crypto_objs = db.query(CryptoObject).all()

    workloads = [a.to_dict() for a in assets if a.asset_type == "KUBERNETES_WORKLOAD"]
    pods = [a.to_dict() for a in assets if a.asset_type == "KUBERNETES_POD"]
    services = [a.to_dict() for a in assets if a.asset_type == "KUBERNETES_SERVICE"]
    ingresses = [a.to_dict() for a in assets if a.asset_type == "KUBERNETES_INGRESS"]
    certs = [c.to_dict() for c in crypto_objs if c.object_type == "CERTIFICATE"]
    secrets_meta = [a.to_dict() for a in assets if a.asset_category == "SECRET_METADATA"]

    return {
        "target_id": target_id,
        "counts": {
            "workloads": len(workloads),
            "pods": len(pods),
            "services": len(services),
            "ingresses": len(ingresses),
            "certificates": len(certs),
            "secret_metadata": len(secrets_meta)
        },
        "inventory": {
            "workloads": workloads,
            "pods": pods,
            "services": services,
            "ingresses": ingresses,
            "certificates": certs,
            "secret_metadata": secrets_meta
        }
    }
