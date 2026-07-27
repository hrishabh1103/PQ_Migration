from app.risk.engine import RiskAndRemediationEngine
from app.models.entities import AuthorizedTarget, TargetType, ScanJob, ScanStatus
from app.orchestrator.engine import DiscoveryOrchestrator
import pytest

@pytest.mark.asyncio
async def test_risk_remediation_engine(db_session):
    target = AuthorizedTarget(
        name="Risk Test Target",
        target_type=TargetType.HOSTNAME,
        target_value="demo.internal",
        is_authorized=True
    )
    db_session.add(target)
    db_session.commit()

    scan_job = ScanJob(target_id=target.id, status=ScanStatus.PENDING, requested_scanners=["mock-scanner"])
    db_session.add(scan_job)
    db_session.commit()

    await DiscoveryOrchestrator.run_scan_job(db_session, scan_job.id)

    report = RiskAndRemediationEngine.generate_risk_report(db_session)
    assert "vulnerabilities" in report
    assert report["summary"]["total_findings"] == 4
    assert len(report["vulnerabilities"]) >= 1
    
    vuln = report["vulnerabilities"][0]
    assert "flaw_description" in vuln
    assert "mitigation_strategy" in vuln

def test_api_report_endpoints(client):
    res_json = client.get("/api/v1/reports/remediation")
    assert res_json.status_code == 200
    assert "vulnerabilities" in res_json.json()

    res_md = client.get("/api/v1/reports/export/markdown")
    assert res_md.status_code == 200
    assert "# Enterprise Post-Quantum Cryptographic Migration" in res_md.text

    res_cbom = client.get("/api/v1/cbom/export")
    assert res_cbom.status_code == 200
    assert "CycloneDX" in res_cbom.text
