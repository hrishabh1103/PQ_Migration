import os
import pytest
import tempfile
import asyncio
from typing import List, Tuple, Optional, Dict, Any

from app.scanners.plugins import PluginRegistry, PluginType, PluginCapability, CapabilityRegistry
from app.collectors.transport import LinuxTransport, LocalTransport, SSHTransport
from app.collectors.observations import (
    AssetObservation, ServiceObservation, ProcessObservation, CryptoObservation,
    CertificateObservation, RelationshipObservation, CapabilityObservation, CapabilityState
)
from app.collectors.modules.base_module import ModuleResultStatus
from app.collectors.modules.host_module import HostModule
from app.collectors.modules.package_module import PackageModule
from app.collectors.modules.openssl_module import OpenSSLModule
from app.collectors.modules.openssh_module import OpenSSHModule
from app.collectors.modules.service_module import ServiceModule
from app.collectors.modules.process_module import ProcessModule
from app.collectors.modules.web_modules import NginxModule, ApacheModule
from app.collectors.modules.certificate_module import CertificateModule
from app.collectors.modules.java_module import JavaModule
from app.collectors.modules.keystore_module import KeystoreModule
from app.collectors.modules.pkcs11_module import PKCS11Module
from app.collectors.modules.crypto_policy_module import CryptoPolicyModule
from app.collectors.linux_collector import LinuxCollector

class MockTransport(LinuxTransport):
    """
    Mock transport fixture returning deterministic system outputs for unit testing.
    """
    def __init__(self, command_responses: Dict[str, Tuple[int, str, str]] = None, files: Dict[str, str] = None):
        self.responses = command_responses or {}
        self.files = files or {}

    async def run_command(self, cmd: List[str], timeout: int = 10) -> Tuple[int, str, str]:
        cmd_str = " ".join(cmd)
        for pattern, resp in self.responses.items():
            if pattern in cmd_str:
                return resp
        return (0, "", "")

    async def read_file(self, path: str, max_bytes: int = 1_000_000) -> Optional[str]:
        return self.files.get(path)

    async def file_exists(self, path: str) -> bool:
        return path in self.files

    async def list_files(self, root: str, patterns: List[str], max_depth: int = 3, max_results: int = 100, max_file_size: int = 10_000_000) -> List[Dict[str, Any]]:
        res = []
        for path in self.files.keys():
            if path.startswith(root):
                fname = os.path.basename(path)
                res.append({"path": path, "filename": fname, "size_bytes": len(self.files[path]), "modified_at": 1000})
        return res[:max_results]


@pytest.mark.asyncio
async def test_linux_collector_registration():
    collector = LinuxCollector()
    p = PluginRegistry.get("linux-host")
    assert p is not None
    assert p.plugin_type == PluginType.COLLECTOR
    assert PluginCapability.HOST_INVENTORY in p.capabilities
    assert PluginCapability.X509 in p.capabilities


@pytest.mark.asyncio
async def test_host_module():
    mock_t = MockTransport(command_responses={
        "hostname -f": (0, "prod-server-01.company.internal\n", ""),
        "hostname": (0, "prod-server-01\n", ""),
        "uname -r": (0, "6.1.0-21-amd64\n", ""),
        "uname -m": (0, "x86_64\n", "")
    }, files={
        "/etc/os-release": 'NAME="Ubuntu"\nVERSION_ID="22.04"\n'
    })

    mod = HostModule()
    res = await mod.run(mock_t)
    assert res.status == ModuleResultStatus.SUCCESS
    assert len(res.observations) == 1
    obs = res.observations[0]
    assert isinstance(obs, AssetObservation)
    assert obs.hostname == "prod-server-01"
    assert obs.fqdn == "prod-server-01.company.internal"
    assert obs.os_distribution == "Ubuntu"
    assert obs.os_version == "22.04"


@pytest.mark.asyncio
async def test_openssl_and_pqc_capability_module():
    mock_t = MockTransport(command_responses={
        "openssl version -d": (0, 'OPENSSLDIR: "/etc/ssl"\n', ""),
        "openssl version": (0, "OpenSSL 3.0.2 15 Mar 2022\n", "")
    }, files={
        "/etc/ssl/openssl.cnf": "fips = fips_sect\n"
    })

    mod = OpenSSLModule()
    res = await mod.run(mock_t)
    assert res.status == ModuleResultStatus.SUCCESS
    caps = [o for o in res.observations if isinstance(o, CapabilityObservation)]
    assert len(caps) >= 2
    fips_cap = next(c for c in caps if c.capability_name == "FIPS_PROVIDER")
    assert fips_cap.capability_state == CapabilityState.CONFIGURED


@pytest.mark.asyncio
async def test_openssh_effective_config():
    mock_t = MockTransport(command_responses={
        "sshd -V": (0, "", "OpenSSH_8.9p1 Ubuntu-3ubuntu0.1, OpenSSL 3.0.2\n"),
        "sshd -T": (0, "kexalgorithms s256-mlkem768,curve25519-sha256\nciphers aes256-gcm@openssh.com\n", "")
    })

    mod = OpenSSHModule()
    res = await mod.run(mock_t)
    assert res.status == ModuleResultStatus.SUCCESS
    cobs = [o for o in res.observations if isinstance(o, CapabilityObservation)]
    assert len(cobs) == 1
    assert cobs[0].details["pqc_hybrid_configured"] is True


@pytest.mark.asyncio
async def test_process_module_argument_sanitization():
    mock_t = MockTransport(command_responses={
        "ps -eo": (0, "  PID COMM ARGS\n 1234 nginx nginx -c /etc/nginx.conf --secret=SUPER_SECRET_KEY_123\n", "")
    })

    mod = ProcessModule()
    res = await mod.run(mock_t)
    assert res.status == ModuleResultStatus.SUCCESS
    pobs = [o for o in res.observations if isinstance(o, ProcessObservation)][0]
    assert "SUPER_SECRET_KEY_123" not in pobs.sanitized_args
    assert "[REDACTED]" in pobs.sanitized_args


@pytest.mark.asyncio
async def test_certificate_module_private_key_rejection():
    mock_t = MockTransport(files={
        "/etc/ssl/certs/privkey.pem": "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC...\n-----END PRIVATE KEY-----",
        "/etc/ssl/certs/test.key": "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----"
    })

    mod = CertificateModule()
    res = await mod.run(mock_t)
    # Both files contain private keys so zero certificates should be parsed
    cert_obs = [o for o in res.observations if isinstance(o, CertificateObservation)]
    assert len(cert_obs) == 0


@pytest.mark.asyncio
async def test_module_failure_isolation():
    class FailingModule(HostModule):
        async def run(self, transport: LinuxTransport):
            raise RuntimeError("Module execution crashed")

    collector = LinuxCollector()
    collector.modules.append(FailingModule())

    mock_t = MockTransport(command_responses={
        "hostname": (0, "test-host\n", "")
    })

    results = await collector.run_collection(mock_t)
    # Ensure all modules ran despite the single module failure
    assert len(results) == 14
    failed_res = next(r for r in results if r.error_message == "Module execution crashed")
    assert failed_res.status == ModuleResultStatus.FAILED
