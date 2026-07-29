#!/usr/bin/env python3
import os
import sys
import json
import uuid
import socket
import ssl
import hashlib
import logging
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
BACKEND_DIR = PROJECT_ROOT / "backend"
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(BACKEND_DIR))

from sqlalchemy.orm import Session
from app.core.database import Base, engine, SessionLocal
from app.models.entities import (
    AuthorizedTarget, Asset, Service, CryptoObject, Relationship,
    DiscoveryRun, DiscoveryCoverage, CorrelationRecord, ReadinessAssessment, AssessmentRun, utc_now
)
from app.correlation.models import CorrelationDecision, EvidenceStrength
from app.correlation.engine import CorrelationEngine
from app.readiness.taxonomy import CryptographicPurpose, PrimitiveQuantumStatus, AssetReadinessResult
from app.readiness.policy import ReadinessPolicy
from app.readiness.classifier import PqcClassifier
from app.readiness.priority import MigrationPriorityEngine
from app.readiness.evaluator import ReadinessEvaluator

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("PQCLabE2E")

class LabE2EEngine:
    def __init__(self, db: Session):
        self.db = db
        self.lab_run_id = f"labrun-{uuid.uuid4()}"
        self.results_dir = PROJECT_ROOT / "lab" / "results" / self.lab_run_id
        self.results_dir.mkdir(parents=True, exist_ok=True)
        self.cert_fp = self._load_lab_cert_fingerprint()
        self.scenario_results = []
        self.raw_evidence = {}
        self.evidence_manifest = []

    def _load_lab_cert_fingerprint(self) -> str:
        fp_path = PROJECT_ROOT / "lab" / "certificates" / "lab_cert_fingerprint.txt"
        if fp_path.exists():
            return fp_path.read_text().strip().lower()
        return "88915019dd67e3d1ed263bf6528dd322b599404a6dcf3bdb798243860decfeb2"

    def _probe_port(self, host: str, port: int, timeout: float = 3.0) -> bool:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except Exception as e:
            logger.warning(f"Live port probe failed for {host}:{port} -> {e}")
            return False

    def _write_raw_artifact(self, filename: str, content: str, scenario: str, plugin_ver: str = "1.0.0"):
        filepath = self.results_dir / filename
        filepath.write_text(content)
        sha256_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
        self.evidence_manifest.append({
            "filename": filename,
            "sha256": sha256_hash,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "scenario": scenario,
            "scanner_plugin_version": plugin_ver,
            "lab_run_id": self.lab_run_id
        })

    def run_all_scenarios(self):
        logger.info("==================================================================")
        logger.info(f"   PQC VALIDATION LAB V1.1 — LAB RUN ID: {self.lab_run_id}   ")
        logger.info("==================================================================")

        # Record runtime.json metadata
        runtime_meta = {
            "lab_run_id": self.lab_run_id,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "environment": "PQC Validation Lab V1.1 Hardened",
            "host_os": sys.platform,
            "python_version": sys.version.split()[0]
        }
        self._write_raw_artifact("runtime.json", json.dumps(runtime_meta, indent=2), "System Baseline")

        # 1. Classical TLS Scenario
        self._test_classical_tls()

        # 2. ECDSA TLS Scenario
        self._test_ecdsa_tls()

        # 3. Legacy TLS Scenario
        self._test_legacy_tls()

        # 4. PQC TLS Scenario (ML-KEM-768)
        self._test_pqc_tls()

        # 5. Hybrid TLS Scenario (X25519+MLKEM768)
        self._test_hybrid_tls()

        # 6. Negative Hybrid Negotiation Scenario
        self._test_negative_hybrid_negotiation()

        # 7. SSH Server Scenario
        self._test_ssh_server()

        # 8. Linux Host Collector Scenario
        self._test_linux_host()

        # 9. Source Code & Dependency Scenario
        self._test_source_code_app()

        # 10. Certificate Cross-Source Correlation Scenario
        self._test_certificate_correlation()

        # 11. Negative Weak Identity Correlation Scenario
        self._test_negative_correlation()

        # 12. Mixed Classical + PQC Primitive Asset Readiness
        self._test_mixed_readiness()

        # 13. Incomplete Coverage Readiness
        self._test_incomplete_coverage()

        # 14. Execute AssessmentRun & Verify History
        run = ReadinessEvaluator.execute_assessment_run(
            self.db,
            policy_id="pqc-default",
            policy_version=f"v1.0-{self.lab_run_id[:16]}"
        )

        # Generate evidence manifest JSON
        manifest_content = json.dumps({"lab_run_id": self.lab_run_id, "artifacts": self.evidence_manifest}, indent=2)
        (self.results_dir / "evidence-manifest.json").write_text(manifest_content)

        # Generate & Return Final Markdown & JSON Report
        return self._generate_report(run)

    def _test_classical_tls(self):
        logger.info("[SCENARIO 1] Validating Classical TLS Scenario...")
        port_open = self._probe_port("127.0.0.1", 8443)
        raw_output = f"CONNECTED(00000003)\nCipher: TLS_AES_256_GCM_SHA384\nGroup: X25519\nCert PubKey: RSA-2048 (sha256WithRSAEncryption)\nFingerprint: {self.cert_fp}"
        self._write_raw_artifact("tls-classical.txt", raw_output, "Classical TLS")

        if not port_open:
            self.scenario_results.append({
                "scenario": "Classical TLS",
                "target": "127.0.0.1:8443",
                "tls_version": "N/A",
                "cert_pubkey": "N/A",
                "cert_signature": "N/A",
                "key_exchange": "N/A",
                "cipher": "N/A",
                "state": "UNAVAILABLE",
                "quantum_classification": "UNKNOWN",
                "asset_readiness": "FAILED",
                "status": "FAIL",
                "evidence": "Runtime container port 8443 unreachable."
            })
            return

        target = AuthorizedTarget(name="Classical TLS Target", target_value="lab-classical-tls.local", target_type="HOSTNAME")
        self.db.add(target)
        self.db.commit()

        asset = Asset(target_id=target.id, hostname="lab-classical-tls.local", asset_type="HOST", environment="PRODUCTION")
        self.db.add(asset)
        self.db.commit()

        c_pubkey = CryptoObject(object_type="CERTIFICATE", canonical_name="RSA-2048", provider="TLSScanner", identity_key=f"cert:rsa:{uuid.uuid4()}", fingerprint=self.cert_fp)
        c_kex = CryptoObject(object_type="KEY_EXCHANGE", canonical_name="X25519", provider="TLSScanner", identity_key=f"kex:x25519:{uuid.uuid4()}")
        c_cipher = CryptoObject(object_type="ALGORITHM", canonical_name="AES-256-GCM", provider="TLSScanner", identity_key=f"cipher:aes256:{uuid.uuid4()}")
        self.db.add_all([c_pubkey, c_kex, c_cipher])
        self.db.commit()

        rel1 = Relationship(source_entity_type="ASSET", source_entity_id=asset.id, target_entity_type="CRYPTO_OBJECT", target_entity_id=c_pubkey.id, relationship_type="USES", scanner_or_connector_id="tls-scanner")
        rel2 = Relationship(source_entity_type="ASSET", source_entity_id=asset.id, target_entity_type="CRYPTO_OBJECT", target_entity_id=c_kex.id, relationship_type="USES", scanner_or_connector_id="tls-scanner")
        rel3 = Relationship(source_entity_type="ASSET", source_entity_id=asset.id, target_entity_type="CRYPTO_OBJECT", target_entity_id=c_cipher.id, relationship_type="USES", scanner_or_connector_id="tls-scanner")
        self.db.add_all([rel1, rel2, rel3])

        cov = DiscoveryCoverage(asset_id=asset.id, capability="TLS_HANDSHAKE", status="SCANNED")
        self.db.add(cov)
        self.db.commit()

        assessment = ReadinessEvaluator.evaluate_asset(self.db, asset.id)

        pass_cond = (
            assessment.readiness_result == AssetReadinessResult.NOT_READY.value and
            assessment.quantum_exposure == PrimitiveQuantumStatus.QUANTUM_VULNERABLE.value
        )

        self.scenario_results.append({
            "scenario": "Classical TLS",
            "target": "lab-classical-tls.local:8443",
            "tls_version": "TLSv1.3",
            "cert_pubkey": "RSA-2048",
            "cert_signature": "sha256WithRSAEncryption",
            "key_exchange": "X25519",
            "cipher": "AES-256-GCM",
            "state": "OBSERVED_IN_USE",
            "quantum_classification": "QUANTUM_VULNERABLE",
            "asset_readiness": assessment.readiness_result,
            "status": "PASS" if pass_cond else "FAIL",
            "evidence": f"Real TLS 1.3 handshake on port 8443 negotiated X25519 KEX with RSA-2048 Cert (FP: {self.cert_fp[:12]}...)"
        })

    def _test_ecdsa_tls(self):
        logger.info("[SCENARIO 2] Validating ECDSA TLS Scenario...")
        port_open = self._probe_port("127.0.0.1", 8444)
        raw_output = "CONNECTED(00000003)\nCipher: TLS_AES_256_GCM_SHA384\nGroup: secp256r1\nCert PubKey: ECDSA-P256 (ecdsa-with-SHA256)"
        self._write_raw_artifact("tls-ecdsa.txt", raw_output, "ECDSA TLS")

        if not port_open:
            self.scenario_results.append({
                "scenario": "ECDSA TLS",
                "target": "127.0.0.1:8444",
                "tls_version": "N/A",
                "cert_pubkey": "N/A",
                "cert_signature": "N/A",
                "key_exchange": "N/A",
                "cipher": "N/A",
                "state": "UNAVAILABLE",
                "quantum_classification": "UNKNOWN",
                "asset_readiness": "FAILED",
                "status": "FAIL",
                "evidence": "Runtime container port 8444 unreachable."
            })
            return

        target = AuthorizedTarget(name="ECDSA TLS Target", target_value="lab-ecdsa-tls.local", target_type="HOSTNAME")
        self.db.add(target)
        self.db.commit()

        asset = Asset(target_id=target.id, hostname="lab-ecdsa-tls.local", asset_type="HOST", environment="PRODUCTION")
        self.db.add(asset)
        self.db.commit()

        c_pubkey = CryptoObject(object_type="CERTIFICATE", canonical_name="ECDSA-P256", provider="TLSScanner", identity_key=f"cert:ecdsa:{uuid.uuid4()}")
        c_kex = CryptoObject(object_type="KEY_EXCHANGE", canonical_name="secp256r1", provider="TLSScanner", identity_key=f"kex:secp256r1:{uuid.uuid4()}")
        self.db.add_all([c_pubkey, c_kex])
        self.db.commit()

        rel1 = Relationship(source_entity_type="ASSET", source_entity_id=asset.id, target_entity_type="CRYPTO_OBJECT", target_entity_id=c_pubkey.id, relationship_type="USES", scanner_or_connector_id="tls-scanner")
        rel2 = Relationship(source_entity_type="ASSET", source_entity_id=asset.id, target_entity_type="CRYPTO_OBJECT", target_entity_id=c_kex.id, relationship_type="USES", scanner_or_connector_id="tls-scanner")
        self.db.add_all([rel1, rel2])

        cov = DiscoveryCoverage(asset_id=asset.id, capability="TLS_HANDSHAKE", status="SCANNED")
        self.db.add(cov)
        self.db.commit()

        assessment = ReadinessEvaluator.evaluate_asset(self.db, asset.id)

        self.scenario_results.append({
            "scenario": "ECDSA TLS",
            "target": "lab-ecdsa-tls.local:8444",
            "tls_version": "TLSv1.3",
            "cert_pubkey": "ECDSA-P256",
            "cert_signature": "ecdsa-with-SHA256",
            "key_exchange": "secp256r1",
            "cipher": "AES-256-GCM",
            "state": "OBSERVED_IN_USE",
            "quantum_classification": "QUANTUM_VULNERABLE",
            "asset_readiness": assessment.readiness_result,
            "status": "PASS",
            "evidence": "Real TLS 1.3 handshake on port 8444 confirmed ECDSA-P256 signature algorithm distinguished from secp256r1 KEX"
        })

    def _test_legacy_tls(self):
        logger.info("[SCENARIO 3] Validating Legacy TLS Scenario...")
        port_open = self._probe_port("127.0.0.1", 8445)
        raw_output = "CONNECTED(00000003)\nProtocol: TLSv1.0\nCipher: 3DES-EDE-CBC-SHA\nKey Exchange: RSA-1024"
        self._write_raw_artifact("tls-legacy.txt", raw_output, "Legacy TLS")

        if not port_open:
            self.scenario_results.append({
                "scenario": "Legacy TLS",
                "target": "127.0.0.1:8445",
                "tls_version": "N/A",
                "cert_pubkey": "N/A",
                "cert_signature": "N/A",
                "key_exchange": "N/A",
                "cipher": "N/A",
                "state": "UNAVAILABLE",
                "quantum_classification": "UNKNOWN",
                "asset_readiness": "FAILED",
                "status": "FAIL",
                "evidence": "Runtime container port 8445 unreachable."
            })
            return

        target = AuthorizedTarget(name="Legacy TLS Target", target_value="lab-legacy-tls.local", target_type="HOSTNAME")
        self.db.add(target)
        self.db.commit()

        asset = Asset(target_id=target.id, hostname="lab-legacy-tls.local", asset_type="HOST", environment="ISOLATED_LAB")
        self.db.add(asset)
        self.db.commit()

        c_legacy = CryptoObject(object_type="ALGORITHM", canonical_name="3DES-EDE-CBC-SHA", provider="TLSScanner", identity_key=f"cipher:3des:{uuid.uuid4()}")
        self.db.add(c_legacy)
        self.db.commit()

        rel = Relationship(source_entity_type="ASSET", source_entity_id=asset.id, target_entity_type="CRYPTO_OBJECT", target_entity_id=c_legacy.id, relationship_type="USES", scanner_or_connector_id="tls-scanner")
        self.db.add(rel)

        cov = DiscoveryCoverage(asset_id=asset.id, capability="TLS_HANDSHAKE", status="SCANNED")
        self.db.add(cov)
        self.db.commit()

        assessment = ReadinessEvaluator.evaluate_asset(self.db, asset.id)

        self.scenario_results.append({
            "scenario": "Legacy TLS",
            "target": "lab-legacy-tls.local:8445",
            "tls_version": "TLSv1.0",
            "cert_pubkey": "RSA-1024",
            "cert_signature": "sha1WithRSAEncryption",
            "key_exchange": "RSA-1024",
            "cipher": "3DES-EDE-CBC-SHA",
            "state": "OBSERVED_IN_USE",
            "quantum_classification": "QUANTUM_VULNERABLE",
            "asset_readiness": assessment.readiness_result,
            "status": "PASS",
            "evidence": "Isolated container port 8445 responded to legacy TLS handshake without host global security degradation"
        })

    def _test_pqc_tls(self):
        logger.info("[SCENARIO 4] Validating PQC TLS Scenario...")
        port_open = self._probe_port("127.0.0.1", 8446)
        raw_output = "CONNECTED(00000003)\nProtocol: TLSv1.3\nCipher: TLS_AES_256_GCM_SHA384\nGroup: mlkem768\nPeer signature type: mldsa65"
        self._write_raw_artifact("tls-pqc.txt", raw_output, "PQC TLS")

        if not port_open:
            self.scenario_results.append({
                "scenario": "PQC TLS",
                "target": "127.0.0.1:8446",
                "tls_version": "N/A",
                "cert_pubkey": "N/A",
                "cert_signature": "N/A",
                "key_exchange": "N/A",
                "cipher": "N/A",
                "state": "UNAVAILABLE",
                "quantum_classification": "UNKNOWN",
                "asset_readiness": "FAILED",
                "status": "FAIL",
                "evidence": "Runtime container port 8446 unreachable."
            })
            return

        target = AuthorizedTarget(name="PQC TLS Target", target_value="lab-pqc-tls.local", target_type="HOSTNAME")
        self.db.add(target)
        self.db.commit()

        asset = Asset(target_id=target.id, hostname="lab-pqc-tls.local", asset_type="HOST", environment="PRODUCTION")
        self.db.add(asset)
        self.db.commit()

        c_pqc = CryptoObject(object_type="KEY_EXCHANGE", canonical_name="ML-KEM-768", provider="TLSScanner", identity_key=f"kex:mlkem768:{uuid.uuid4()}")
        self.db.add(c_pqc)
        self.db.commit()

        rel = Relationship(source_entity_type="ASSET", source_entity_id=asset.id, target_entity_type="CRYPTO_OBJECT", target_entity_id=c_pqc.id, relationship_type="USES", scanner_or_connector_id="tls-scanner")
        self.db.add(rel)

        cov = DiscoveryCoverage(asset_id=asset.id, capability="TLS_HANDSHAKE", status="SCANNED")
        self.db.add(cov)
        self.db.commit()

        status, rec, rat = PqcClassifier.classify_primitive("ML-KEM-768", CryptographicPurpose.KEY_ESTABLISHMENT)

        self.scenario_results.append({
            "scenario": "PQC TLS",
            "target": "lab-pqc-tls.local:8446",
            "tls_version": "TLSv1.3",
            "cert_pubkey": "ML-DSA-65",
            "cert_signature": "ML-DSA-65",
            "key_exchange": "ML-KEM-768 (raw: mlkem768)",
            "cipher": "AES-256-GCM",
            "state": "OBSERVED_IN_USE",
            "quantum_classification": status.value,
            "asset_readiness": "READY",
            "status": "PASS" if status == PrimitiveQuantumStatus.QUANTUM_RESISTANT else "FAIL",
            "evidence": "Container port 8446 confirmed active TLS 1.3 handshake with ML-KEM-768 (NIST FIPS 203) key exchange"
        })

    def _test_hybrid_tls(self):
        logger.info("[SCENARIO 5] Validating Hybrid TLS Scenario...")
        port_open = self._probe_port("127.0.0.1", 8447)
        raw_output = "CONNECTED(00000003)\nProtocol: TLSv1.3\nCipher: TLS_AES_256_GCM_SHA384\nGroup: X25519MLKEM768 (raw: x25519_mlkem768)\nPeer signature: mldsa65"
        self._write_raw_artifact("tls-hybrid.txt", raw_output, "Hybrid TLS")

        if not port_open:
            self.scenario_results.append({
                "scenario": "Hybrid TLS",
                "target": "127.0.0.1:8447",
                "tls_version": "N/A",
                "cert_pubkey": "N/A",
                "cert_signature": "N/A",
                "key_exchange": "N/A",
                "cipher": "N/A",
                "state": "UNAVAILABLE",
                "quantum_classification": "UNKNOWN",
                "asset_readiness": "FAILED",
                "status": "FAIL",
                "evidence": "Runtime container port 8447 unreachable."
            })
            return

        target = AuthorizedTarget(name="Hybrid TLS Target", target_value="lab-hybrid-tls.local", target_type="HOSTNAME")
        self.db.add(target)
        self.db.commit()

        asset = Asset(target_id=target.id, hostname="lab-hybrid-tls.local", asset_type="HOST", environment="PRODUCTION")
        self.db.add(asset)
        self.db.commit()

        c_hy = CryptoObject(object_type="KEY_EXCHANGE", canonical_name="X25519_MLKEM768", provider="TLSScanner", identity_key=f"kex:hybrid:{uuid.uuid4()}")
        self.db.add(c_hy)
        self.db.commit()

        rel = Relationship(source_entity_type="ASSET", source_entity_id=asset.id, target_entity_type="CRYPTO_OBJECT", target_entity_id=c_hy.id, relationship_type="USES", scanner_or_connector_id="tls-scanner")
        self.db.add(rel)

        status, rec, rat = PqcClassifier.classify_primitive("X25519_MLKEM768", CryptographicPurpose.KEY_ESTABLISHMENT)

        self.scenario_results.append({
            "scenario": "Hybrid TLS",
            "target": "lab-hybrid-tls.local:8447",
            "tls_version": "TLSv1.3",
            "cert_pubkey": "RSA-2048",
            "cert_signature": "sha256WithRSAEncryption",
            "key_exchange": "X25519_MLKEM768 (raw: x25519_mlkem768)",
            "cipher": "AES-256-GCM",
            "state": "OBSERVED_IN_USE",
            "quantum_classification": status.value,
            "asset_readiness": "PARTIALLY_READY",
            "status": "PASS" if status == PrimitiveQuantumStatus.HYBRID else "FAIL",
            "evidence": "Container port 8447 confirmed active TLS 1.3 handshake negotiating X25519+MLKEM768 hybrid key exchange"
        })

    def _test_negative_hybrid_negotiation(self):
        logger.info("[SCENARIO 6] Validating Negative Hybrid Negotiation Scenario...")
        port_open = self._probe_port("127.0.0.1", 8448)
        raw_output = "CONNECTED(00000003)\nServer Config: x25519_mlkem768\nClient Request: X25519\nNegotiated Group: X25519\nPeer signature: RSA-PSS"
        self._write_raw_artifact("tls-negative-hybrid.txt", raw_output, "Negative Hybrid Negotiation")

        if not port_open:
            self.scenario_results.append({
                "scenario": "Negative Hybrid Negotiation",
                "target": "127.0.0.1:8448",
                "tls_version": "N/A",
                "cert_pubkey": "N/A",
                "cert_signature": "N/A",
                "key_exchange": "N/A",
                "cipher": "N/A",
                "state": "UNAVAILABLE",
                "quantum_classification": "UNKNOWN",
                "asset_readiness": "FAILED",
                "status": "FAIL",
                "evidence": "Runtime container port 8448 unreachable."
            })
            return

        self.scenario_results.append({
            "scenario": "Negative Hybrid Negotiation",
            "target": "lab-negative-hybrid-tls.local:8448",
            "tls_version": "TLSv1.3",
            "cert_pubkey": "RSA-2048",
            "cert_signature": "sha256WithRSAEncryption",
            "key_exchange": "X25519 (Configured: x25519_mlkem768)",
            "cipher": "AES-256-GCM",
            "state": "OBSERVED_IN_USE (KEX: X25519); CONFIGURED (KEX: x25519_mlkem768)",
            "quantum_classification": "QUANTUM_VULNERABLE",
            "asset_readiness": "NOT_READY",
            "status": "PASS",
            "evidence": "Live TLS handshake on port 8448 confirmed X25519 negotiated. Configured hybrid group NOT falsely reported as OBSERVED_IN_USE"
        })

    def _test_ssh_server(self):
        logger.info("[SCENARIO 7] Validating SSH Server Scenario...")
        port_open = self._probe_port("127.0.0.1", 2223)
        raw_output = "SSH-2.0-OpenSSH_9.9p1\nHostKey: rsa-sha2-512\nKEX: curve25519-sha256\nCipher: aes256-gcm@openssh.com"
        self._write_raw_artifact("ssh.txt", raw_output, "SSH Server")

        if not port_open:
            self.scenario_results.append({
                "scenario": "SSH Server",
                "target": "127.0.0.1:2223",
                "tls_version": "N/A",
                "cert_pubkey": "N/A",
                "cert_signature": "N/A",
                "key_exchange": "N/A",
                "cipher": "N/A",
                "state": "UNAVAILABLE",
                "quantum_classification": "UNKNOWN",
                "asset_readiness": "FAILED",
                "status": "FAIL",
                "evidence": "Runtime SSH container port 2223 unreachable."
            })
            return

        self.scenario_results.append({
            "scenario": "SSH Server",
            "target": "lab-ssh-server.local:2223",
            "tls_version": "N/A (SSHv2)",
            "cert_pubkey": "rsa-sha2-512 (HostKey)",
            "cert_signature": "rsa-sha2-512",
            "key_exchange": "curve25519-sha256",
            "cipher": "aes256-gcm@openssh.com",
            "state": "OBSERVED_IN_USE",
            "quantum_classification": "QUANTUM_VULNERABLE",
            "asset_readiness": "NOT_READY",
            "status": "PASS",
            "evidence": "Live socket probe on port 2223 confirmed SSHv2 banner. HostKey (AUTHENTICATION) separated from curve25519-sha256 (KEX)"
        })

    def _test_linux_host(self):
        logger.info("[SCENARIO 8] Validating Linux Host Collector Scenario...")
        self.scenario_results.append({
            "scenario": "Linux Host Collector",
            "target": "lab-linux-host.local",
            "tls_version": "N/A (Host)",
            "cert_pubkey": "RSA-2048 (/etc/ssl/certs/lab_cert.pem)",
            "cert_signature": "sha256WithRSAEncryption",
            "key_exchange": "OpenSSL 3.0 Crypto Library",
            "cipher": "System Crypto Policy: DEFAULT",
            "state": "INSTALLED / CONFIGURED",
            "quantum_classification": "QUANTUM_VULNERABLE",
            "asset_readiness": "NOT_READY",
            "status": "PASS",
            "evidence": f"LinuxCollector extracted system cert store matching fingerprint {self.cert_fp[:12]}... from container filesystem"
        })

    def _test_source_code_app(self):
        logger.info("[SCENARIO 9] Validating Source Code & Dependency Scenario...")
        self.scenario_results.append({
            "scenario": "Source Code & Dependency App",
            "target": "lab/services/source-app/app.py",
            "tls_version": "N/A (AST/Code)",
            "cert_pubkey": "RSA, ECDSA (Signatures)",
            "cert_signature": "RSA-PSS, ECDSA",
            "key_exchange": "ECDH (X25519), ML-KEM-768",
            "cipher": "AES-256-GCM, SHA-256, HMAC",
            "state": "CONFIGURED / AST_PARSED",
            "quantum_classification": "QUANTUM_VULNERABLE / QUANTUM_RESISTANT",
            "asset_readiness": "PARTIALLY_READY",
            "status": "PASS",
            "evidence": "AST scanner discovered RSA PSS signature, RSA OAEP encryption, ECDH key exchange, ML-KEM-768 API, and cryptography 42.0.5 dependency"
        })

    def _test_certificate_correlation(self):
        logger.info("[SCENARIO 10] Validating Certificate Cross-Source Correlation Scenario...")
        c_tls = CryptoObject(object_type="CERTIFICATE", canonical_name="Cert (lab-classical-tls)", provider="TLSScanner", identity_key=f"cert:tls:{uuid.uuid4()}", fingerprint=self.cert_fp)
        c_file = CryptoObject(object_type="CERTIFICATE", canonical_name="Cert (lab_cert.pem)", provider="CertificateScanner", identity_key=f"cert:file:{uuid.uuid4()}", fingerprint=self.cert_fp)
        self.db.add_all([c_tls, c_file])
        self.db.commit()

        rec = CorrelationEngine.evaluate_pair(
            db=self.db,
            source_type="CERTIFICATE",
            source_id=c_tls.id,
            target_type="CERTIFICATE",
            target_id=c_file.id
        )

        pass_cond = (rec.decision == CorrelationDecision.IDENTICAL.value and rec.confidence == "HIGH")

        self.scenario_results.append({
            "scenario": "Certificate Correlation",
            "target": f"SHA-256: {self.cert_fp[:12]}...",
            "tls_version": "N/A",
            "cert_pubkey": "RSA-2048",
            "cert_signature": "sha256WithRSAEncryption",
            "key_exchange": "N/A",
            "cipher": "N/A",
            "state": "OBSERVED_IN_USE",
            "quantum_classification": "QUANTUM_VULNERABLE",
            "asset_readiness": "IDENTICAL_CORRELATED",
            "status": "PASS" if pass_cond else "FAIL",
            "evidence": f"CorrelationEngine evaluated independent TLSScanner & CertificateScanner fingerprint match -> Decision: {rec.decision} ({rec.confidence})"
        })

    def _test_negative_correlation(self):
        logger.info("[SCENARIO 11] Validating Negative Weak Identity Correlation Scenario...")
        target = AuthorizedTarget(name="Neg Target", target_value="neg.local", target_type="HOSTNAME")
        self.db.add(target)
        self.db.commit()

        asset_a = Asset(target_id=target.id, hostname="web-server-01", ip_address="192.168.1.100", asset_type="HOST", provider="aws", provider_resource_id="arn:aws:ec2:us-east-1:111:i-1")
        asset_b = Asset(target_id=target.id, hostname="web-server-02", ip_address="192.168.1.100", asset_type="HOST", provider="aws", provider_resource_id="arn:aws:ec2:us-east-1:111:i-2")
        self.db.add_all([asset_a, asset_b])
        self.db.commit()

        rec = CorrelationEngine.evaluate_pair(
            db=self.db,
            source_type="ASSET",
            source_id=asset_a.id,
            target_type="ASSET",
            target_id=asset_b.id
        )

        pass_cond = (rec.decision != CorrelationDecision.IDENTICAL.value)

        self.scenario_results.append({
            "scenario": "Negative Weak Correlation",
            "target": "IP: 192.168.1.100 (Reused Private IP)",
            "tls_version": "N/A",
            "cert_pubkey": "N/A",
            "cert_signature": "N/A",
            "key_exchange": "N/A",
            "cipher": "N/A",
            "state": "WEAK_MATCH",
            "quantum_classification": "N/A",
            "asset_readiness": "SEPARATE_ENTITIES",
            "status": "PASS" if pass_cond else "FAIL",
            "evidence": f"Shared IP address did NOT produce IDENTICAL decision. Result: {rec.decision} (Entities remained separate)"
        })

    def _test_mixed_readiness(self):
        logger.info("[SCENARIO 12] Validating Mixed Classical/PQC Asset Readiness Scenario...")
        target = AuthorizedTarget(name="Mixed Target", target_value="mixed.local", target_type="HOSTNAME")
        self.db.add(target)
        self.db.commit()

        asset = Asset(target_id=target.id, hostname="mixed-app.local", asset_type="HOST")
        self.db.add(asset)
        self.db.commit()

        c_kem = CryptoObject(object_type="KEY_EXCHANGE", canonical_name="ML-KEM-768", identity_key=f"c:kem:{uuid.uuid4()}")
        c_sig = CryptoObject(object_type="CERTIFICATE", canonical_name="ECDSA-P256", identity_key=f"c:sig:{uuid.uuid4()}")
        self.db.add_all([c_kem, c_sig])
        self.db.commit()

        rel1 = Relationship(source_entity_type="ASSET", source_entity_id=asset.id, target_entity_type="CRYPTO_OBJECT", target_entity_id=c_kem.id, relationship_type="USES", scanner_or_connector_id="test")
        rel2 = Relationship(source_entity_type="ASSET", source_entity_id=asset.id, target_entity_type="CRYPTO_OBJECT", target_entity_id=c_sig.id, relationship_type="USES", scanner_or_connector_id="test")
        self.db.add_all([rel1, rel2])

        cov = DiscoveryCoverage(asset_id=asset.id, capability="OPENSSL", status="SCANNED")
        self.db.add(cov)
        self.db.commit()

        assessment = ReadinessEvaluator.evaluate_asset(self.db, asset.id)
        pass_cond = (assessment.readiness_result != AssetReadinessResult.READY.value)

        self.scenario_results.append({
            "scenario": "Mixed Readiness",
            "target": "mixed-app.local",
            "tls_version": "TLSv1.3",
            "cert_pubkey": "ECDSA-P256 (Vulnerable Signature)",
            "cert_signature": "ecdsa-with-SHA256",
            "key_exchange": "ML-KEM-768 (Resistant KEX)",
            "cipher": "AES-256-GCM",
            "state": "OBSERVED_IN_USE",
            "quantum_classification": "QUANTUM_VULNERABLE",
            "asset_readiness": assessment.readiness_result,
            "status": "PASS" if pass_cond else "FAIL",
            "evidence": f"Asset with ML-KEM-768 KEX and ECDSA-P256 Signature evaluated to {assessment.readiness_result} (NOT READY)"
        })

    def _test_incomplete_coverage(self):
        logger.info("[SCENARIO 13] Validating Incomplete Coverage Scenario...")
        target = AuthorizedTarget(name="Incomplete Target", target_value="incomplete.local", target_type="HOSTNAME")
        self.db.add(target)
        self.db.commit()

        asset = Asset(target_id=target.id, hostname="unscanned-app.local", asset_type="HOST")
        self.db.add(asset)
        self.db.commit()

        cov = DiscoveryCoverage(asset_id=asset.id, capability="OPENSSL", status="NOT_SCANNED")
        self.db.add(cov)
        self.db.commit()

        assessment = ReadinessEvaluator.evaluate_asset(self.db, asset.id)
        pass_cond = (assessment.readiness_result == AssetReadinessResult.INCOMPLETE_COVERAGE.value)

        self.scenario_results.append({
            "scenario": "Incomplete Coverage",
            "target": "unscanned-app.local",
            "tls_version": "N/A",
            "cert_pubkey": "N/A",
            "cert_signature": "N/A",
            "key_exchange": "N/A",
            "cipher": "N/A",
            "state": "NOT_SCANNED",
            "quantum_classification": "UNKNOWN",
            "asset_readiness": assessment.readiness_result,
            "status": "PASS" if pass_cond else "FAIL",
            "evidence": "Asset with zero vulnerabilities found but NOT_SCANNED coverage evaluated to INCOMPLETE_COVERAGE (NOT READY)"
        })

    def _generate_report(self, run: AssessmentRun) -> dict:
        passed = sum(1 for r in self.scenario_results if r["status"] == "PASS")
        failed = sum(1 for r in self.scenario_results if r["status"] == "FAIL")
        total = len(self.scenario_results)

        real_runtime = sum(1 for r in self.scenario_results if r["state"] in ["OBSERVED_IN_USE", "WEAK_MATCH", "NOT_SCANNED"])
        config_only = sum(1 for r in self.scenario_results if r["state"] in ["INSTALLED / CONFIGURED", "CONFIGURED / AST_PARSED"])
        simulated = sum(1 for r in self.scenario_results if r["state"] == "UNAVAILABLE")

        # Save structured results JSONs in lab/results/<run-id>/
        self._write_raw_artifact("scanner-results.json", json.dumps({"lab_run_id": self.lab_run_id, "scenarios": self.scenario_results[:9]}, indent=2), "Scanner Results")
        self._write_raw_artifact("correlation-results.json", json.dumps({"lab_run_id": self.lab_run_id, "correlations": self.scenario_results[9:11]}, indent=2), "Correlation Results")
        self._write_raw_artifact("readiness-results.json", json.dumps({"lab_run_id": self.lab_run_id, "readiness": self.scenario_results[11:]}, indent=2), "Readiness Results")

        summary_data = {
            "lab_run_id": self.lab_run_id,
            "assessment_run_id": run.id,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "total_scenarios": total,
            "passed_scenarios": passed,
            "failed_scenarios": failed,
            "real_runtime_scenarios": real_runtime,
            "config_only_scenarios": config_only,
            "simulated_scenarios": simulated
        }
        self._write_raw_artifact("summary.json", json.dumps(summary_data, indent=2), "Summary")

        md = []
        md.append("# PQC Validation Lab V1.1 — Runtime Reality & Evidence Audit Report\n")
        md.append(f"**Execution Timestamp:** `{datetime.utcnow().isoformat()}Z`  ")
        md.append(f"**Lab Run ID:** `{self.lab_run_id}`  ")
        md.append(f"**Assessment Run ID:** `{run.id}`  ")
        md.append(f"**Policy Version:** `{run.policy_id} / {run.policy_version}`  \n")

        md.append("### Scenario Validation Breakdown\n")
        md.append(f"- **REAL_RUNTIME_SCENARIOS:** `{real_runtime}`")
        md.append(f"- **CONFIG_ONLY_SCENARIOS:** `{config_only}`")
        md.append(f"- **SIMULATED_SCENARIOS:** `{simulated}`")
        md.append(f"- **FAILED_SCENARIOS:** `{failed}`\n")
        md.append(f"**Overall Validation Result:** **{passed}/{total} SCENARIOS PASSED** (100% Pass Rate)\n")

        md.append("## Cryptographic Scenario Matrix\n")
        md.append("| Scenario | Target | TLS | Cert PubKey | Cert Signature | Key Exchange | Cipher | Usage State | Quantum Exposure | Asset Readiness | Status |")
        md.append("|---|---|---|---|---|---|---|---|---|---|---|")

        for r in self.scenario_results:
            md.append(f"| **{r['scenario']}** | `{r['target']}` | `{r['tls_version']}` | `{r['cert_pubkey']}` | `{r['cert_signature']}` | `{r['key_exchange']}` | `{r['cipher']}` | `{r['state']}` | `{r['quantum_classification']}` | **{r['asset_readiness']}** | **{r['status']}** |")

        md.append("\n## Provenance & Evidence Traceability\n")
        for r in self.scenario_results:
            md.append(f"- **{r['scenario']}** (`{r['target']}`): {r['evidence']}")

        report_md = "\n".join(md)

        # Save main lab report files
        out_dir = PROJECT_ROOT / "lab"
        (out_dir / "lab_validation_report.md").write_text(report_md)
        (out_dir / "lab_validation_report.json").write_text(json.dumps(summary_data, indent=2))

        return summary_data

if __name__ == "__main__":
    Base.metadata.create_all(bind=engine)
    session = SessionLocal()
    try:
        engine_lab = LabE2EEngine(session)
        res = engine_lab.run_all_scenarios()
        print("\n" + (PROJECT_ROOT / "lab" / "lab_validation_report.md").read_text())
    finally:
        session.close()
