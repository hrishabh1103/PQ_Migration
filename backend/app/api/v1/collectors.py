import logging
from typing import Dict, Any, List
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field

from app.core.database import get_db, SessionLocal
from app.models.entities import AuthorizedTarget, DiscoveryRun, DiscoveryCoverage, Asset, Service, CryptoObject
from app.orchestrator.engine import DiscoveryOrchestrator
from app.scanners.plugins import PluginRegistry, PluginType

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/collectors", tags=["Linux Collector & Telemetry"])

class CollectionRunRequest(BaseModel):
    target_id: str = Field(..., description="ID of the authorized Linux target")
    plugin_id: str = Field("linux-host", description="Collector plugin ID")

@router.get("/plugins")
def list_collector_plugins() -> List[Dict[str, Any]]:
    plugins = PluginRegistry.list_plugins(PluginType.COLLECTOR)
    res = []
    for pid, p in plugins.items():
        caps = getattr(p, "capabilities", set())
        res.append({
            "plugin_id": pid,
            "plugin_type": "COLLECTOR",
            "version": getattr(p, "version", "1.0.0"),
            "capabilities": [c.value if hasattr(c, 'value') else str(c) for c in caps]
        })
    return res

async def _execute_collection_async(target_id: str, plugin_id: str):
    db = SessionLocal()
    try:
        await DiscoveryOrchestrator.run_collection_job(db=db, target_id=target_id, collector_plugin_id=plugin_id)
    except Exception as e:
        logger.exception(f"Async collection run failed for target {target_id}: {e}")
    finally:
        db.close()

@router.post("/linux/run")
async def trigger_linux_collection(
    req: CollectionRunRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
) -> Dict[str, Any]:
    target = db.query(AuthorizedTarget).filter(AuthorizedTarget.id == req.target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail=f"Target '{req.target_id}' not found.")

    background_tasks.add_task(_execute_collection_async, target.id, req.plugin_id)
    return {
        "status": "QUEUED",
        "message": f"Linux collection initiated for target '{target.target_value}' via plugin '{req.plugin_id}'",
        "target_id": target.id,
        "plugin_id": req.plugin_id
    }

@router.get("/linux/coverage/{target_id}")
def get_target_collection_coverage(target_id: str, db: Session = Depends(get_db)) -> Dict[str, Any]:
    target = db.query(AuthorizedTarget).filter(AuthorizedTarget.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail=f"Target '{target_id}' not found.")

    host_asset = db.query(Asset).filter(
        Asset.target_id == target_id,
        Asset.asset_type == "HOST"
    ).first()

    coverage_items = []
    if host_asset:
        records = db.query(DiscoveryCoverage).filter(DiscoveryCoverage.asset_id == host_asset.id).all()
        for r in records:
            coverage_items.append({
                "capability": r.capability,
                "plugin_id": r.plugin_id,
                "status": r.status,
                "findings_count": r.findings_count,
                "last_evaluated_at": r.last_evaluated_at.isoformat() if r.last_evaluated_at else None
            })

    return {
        "target_id": target_id,
        "target_value": target.target_value,
        "host_asset_id": host_asset.id if host_asset else None,
        "coverage": coverage_items
    }
