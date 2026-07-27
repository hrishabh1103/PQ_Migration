import pytest
from app.models.entities import AuthorizedTarget, ScanJob, TargetType, ScanStatus, Asset, Service, CryptoFinding
from app.orchestrator.engine import DiscoveryOrchestrator

@pytest.mark.asyncio
async def test_orchestrator_end_to_end_mock_scan(db_session):
    # 1. Create target
    target = AuthorizedTarget(
        name="Demo Target",
        target_type=TargetType.HOSTNAME,
        target_value="demo.internal",
        is_authorized=True
    )
    db_session.add(target)
    db_session.commit()

    # 2. Create scan job
    scan_job = ScanJob(
        target_id=target.id,
        status=ScanStatus.PENDING,
        requested_scanners=["mock-scanner"]
    )
    db_session.add(scan_job)
    db_session.commit()

    # 3. Run orchestrator
    completed_job = await DiscoveryOrchestrator.run_scan_job(db_session, scan_job.id)

    # 4. Verify job completed and assets, services, findings persisted
    assert completed_job.status == ScanStatus.COMPLETED
    assert completed_job.stats_json["findings_found"] == 4

    assets = db_session.query(Asset).filter(Asset.target_id == target.id).all()
    assert len(assets) == 1
    asset = assets[0]
    assert asset.hostname == "demo.internal"

    services = db_session.query(Service).filter(Service.asset_id == asset.id).all()
    assert len(services) == 1
    service = services[0]
    assert service.port == 443
    assert service.application_protocol.value == "HTTPS"

    findings = db_session.query(CryptoFinding).filter(CryptoFinding.asset_id == asset.id).all()
    assert len(findings) == 4
