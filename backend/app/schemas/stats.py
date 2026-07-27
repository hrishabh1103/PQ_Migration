from pydantic import BaseModel
from typing import Dict

class DashboardStatsResponse(BaseModel):
    assets_count: int
    services_count: int
    findings_count: int
    scan_jobs_count: int
    algorithm_distribution: Dict[str, int]
    scan_status_distribution: Dict[str, int]
