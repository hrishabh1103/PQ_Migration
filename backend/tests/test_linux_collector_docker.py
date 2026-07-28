import pytest
import asyncio
from app.collectors.transport import LocalTransport
from app.collectors.linux_collector import LinuxCollector
from app.collectors.modules.base_module import ModuleResultStatus

@pytest.mark.asyncio
async def test_linux_collector_local_environment():
    """
    Executes LinuxCollector against the local test environment (or Docker container environment).
    Verifies that all 13 modules complete without fatal crashes.
    """
    collector = LinuxCollector(transport=LocalTransport())
    results = await collector.run_collection()

    assert len(results) >= 13

    # Check HostModule result
    host_res = next(r for r in results if r.module_id == "host_info")
    assert host_res.status == ModuleResultStatus.SUCCESS
    assert len(host_res.observations) == 1
    assert host_res.observations[0].asset_type == "HOST"

    # Check OpenSSLModule result
    ssl_res = next(r for r in results if r.module_id == "openssl_info")
    assert ssl_res.status in [ModuleResultStatus.SUCCESS, ModuleResultStatus.NOT_APPLICABLE]

    # Verify zero private key leakage in any observation metadata
    for res in results:
        for obs in res.observations:
            meta_str = str(obs.metadata).lower()
            assert "begin private key" not in meta_str
            assert "begin rsa private key" not in meta_str
            assert "begin ec private key" not in meta_str
