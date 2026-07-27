import pytest
from app.scanners.base import ScannerRegistry, ScanContext
from app.models.entities import TargetType

@pytest.mark.asyncio
async def test_tls_scanner():
    scanner = ScannerRegistry.get("tls-scanner")
    assert scanner is not None
    context = ScanContext(scan_job_id="test", target_id="test")
    findings = []
    async for f in scanner.discover("demo.internal", TargetType.HOSTNAME, context):
        findings.append(f)
    assert len(findings) >= 2

@pytest.mark.asyncio
async def test_certificate_scanner():
    scanner = ScannerRegistry.get("certificate-scanner")
    assert scanner is not None
    context = ScanContext(scan_job_id="test", target_id="test")
    findings = []
    async for f in scanner.discover("demo.internal", TargetType.HOSTNAME, context):
        findings.append(f)
    assert len(findings) >= 1

@pytest.mark.asyncio
async def test_ssh_scanner():
    scanner = ScannerRegistry.get("ssh-scanner")
    assert scanner is not None
    context = ScanContext(scan_job_id="test", target_id="test")
    findings = []
    async for f in scanner.discover("demo.internal", TargetType.HOSTNAME, context):
        findings.append(f)
    assert len(findings) >= 2

@pytest.mark.asyncio
async def test_source_code_scanner():
    scanner = ScannerRegistry.get("source-code-scanner")
    assert scanner is not None
    context = ScanContext(scan_job_id="test", target_id="test")
    findings = []
    async for f in scanner.discover("demo.internal", TargetType.HOSTNAME, context):
        findings.append(f)
    assert len(findings) >= 2

@pytest.mark.asyncio
async def test_dependency_scanner():
    scanner = ScannerRegistry.get("dependency-scanner")
    assert scanner is not None
    context = ScanContext(scan_job_id="test", target_id="test")
    findings = []
    async for f in scanner.discover("demo.internal", TargetType.HOSTNAME, context):
        findings.append(f)
    assert len(findings) >= 2
