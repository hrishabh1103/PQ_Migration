from fastapi import APIRouter
from app.api.v1 import (
    health, targets, scans, assets, findings, stats, reports, cbom, api_hub, cloud,
    relationships, graph, crypto_objects, data_assets, coverage, collectors, connectors,
    correlations, readiness
)

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
api_router.include_router(collectors.router, tags=["Linux Collector & Telemetry"])
api_router.include_router(connectors.router, tags=["AWS Connector & Cloud Sync"])

# V2 Foundation Routers
api_router.include_router(relationships.router, prefix="/relationships", tags=["Relationships"])
api_router.include_router(graph.router, prefix="/graph", tags=["Graph Traversal"])
api_router.include_router(crypto_objects.router, prefix="/crypto-objects", tags=["CryptoObjects"])
api_router.include_router(data_assets.router, prefix="/data", tags=["Data Assets & Data Flows"])
api_router.include_router(coverage.router, prefix="/coverage", tags=["Discovery Coverage"])
api_router.include_router(correlations.router, tags=["Entity Correlation"])
api_router.include_router(readiness.router, tags=["PQC Readiness Engine"])
