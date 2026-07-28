import os
import platform
import sys
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import text
from app.core.database import get_db

router = APIRouter()

@router.get("/health")
def get_health(db: Session = Depends(get_db)):
    db_healthy = False
    try:
        db.execute(text("SELECT 1"))
        db_healthy = True
    except Exception:
        db_healthy = False

    cloud_env = "Local / On-Premise"
    if os.environ.get("AWS_EXECUTION_ENV") or os.environ.get("AWS_REGION"):
        cloud_env = "AWS (Elastic Container Service / EC2)"
    elif os.environ.get("KUBERNETES_SERVICE_HOST"):
        cloud_env = "Kubernetes Cluster (GKE / EKS / AKS)"
    elif os.environ.get("K_SERVICE"):
        cloud_env = "GCP Cloud Run"

    return {
        "status": "healthy" if db_healthy else "degraded",
        "service": "Enterprise Cryptographic Discovery Platform",
        "version": "1.0.0",
        "database_connected": db_healthy,
        "environment": cloud_env,
        "runtime": {
            "python_version": sys.version.split()[0],
            "platform": platform.system(),
            "architecture": platform.machine()
        }
    }
