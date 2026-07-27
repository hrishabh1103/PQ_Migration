import pytest
from app.scanners.base import ScannerRegistry, ScanContext
from app.scanners.mock_scanner import MockScanner
from app.models.entities import TargetType

@pytest.mark.asyncio
async def test_mock_scanner_discovery():
    scanner = ScannerRegistry.get("mock-scanner")
    assert scanner is not None
    assert scanner.scanner_id == "mock-scanner"

    context = ScanContext(scan_job_id="test-job", target_id="test-target")
    findings = []
    async for f in scanner.discover("demo.internal", TargetType.HOSTNAME, context):
        findings.append(f)

    assert len(findings) == 4
    algos = [f.raw_algorithm_name for f in findings]
    assert "RSA-2048" in algos
    assert "X25519" in algos
    assert "AES-256-GCM" in algos
    assert "SHA-384" in algos
