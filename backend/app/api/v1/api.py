from fastapi import APIRouter
from app.api.v1 import health, targets, scans, assets, findings, stats, reports, cbom, api_hub, cloud

api_router = APIRouter()

api_router.include_router(health.router, tags=["Health"])
api_router.include_router(targets.router, tags=["Targets"])
api_router.include_router(scans.router, tags=["Scans"])
api_router.include_router(assets.router, tags=["Assets"])
api_router.include_router(findings.router, tags=["Findings"])
api_router.include_router(stats.router, tags=["Stats"])
api_router.include_router(reports.router, tags=["Reports"])
api_router.include_router(cbom.router, tags=["CBOM Export"])
api_router.include_router(api_hub.router, tags=["API & Server Hub"])
api_router.include_router(cloud.router, prefix="/cloud", tags=["Cloud Servers"])
