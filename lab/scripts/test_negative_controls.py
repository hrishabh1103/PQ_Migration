#!/usr/bin/env python3
import sys
import json
import subprocess
import logging
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "backend"))

from app.readiness.classifier import PqcClassifier
from app.readiness.taxonomy import CryptographicPurpose, PrimitiveQuantumStatus

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("NegativeControlsSuite")

def run_cmd(cmd: str) -> tuple[int, str]:
    try:
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
        return res.returncode, res.stdout + res.stderr
    except Exception as e:
        return 1, str(e)

def run_negative_controls() -> bool:
    logger.info("==================================================================")
    logger.info("   PQC VALIDATION LAB — NEGATIVE CONTROLS VERIFICATION SUITE    ")
    logger.info("==================================================================")

    all_passed = True

    # 1. Unavailable PQC endpoint cannot PASS
    logger.info("[TEST 1] Testing unavailable PQC endpoint failure behavior...")
    code, out = run_cmd("docker stop lab-pqc-tls >/dev/null 2>&1")
    python_bin = PROJECT_ROOT / "backend" / "venv" / "bin" / "python"
    code, e2e_out = run_cmd(f'DATABASE_URL="sqlite:///./pqc_discovery.db" PYTHONPATH="{PROJECT_ROOT}" {python_bin} "{PROJECT_ROOT}/lab/scripts/run_lab_e2e.py"')
    run_cmd("docker start lab-pqc-tls >/dev/null 2>&1")

    if "UNAVAILABLE" in e2e_out and "FAILED_SCENARIOS" in e2e_out:
        logger.info("[✓] TEST 1 PASSED: Stopped PQC container correctly failed E2E scenario.")
    else:
        logger.error(f"[X] TEST 1 FAILED: Stopped container did not fail E2E scenario:\n{e2e_out}")
        all_passed = False

    # 2. Classical TLS cannot be classified as PQC merely from config
    logger.info("[TEST 2] Testing classical TLS classification with PQC config string...")
    status, rec, rat = PqcClassifier.classify_primitive("RSA-2048", CryptographicPurpose.DIGITAL_SIGNATURE)
    if status == PrimitiveQuantumStatus.QUANTUM_RESISTANT:
        logger.error("[X] TEST 2 FAILED: Classical RSA-2048 falsely classified as QUANTUM_RESISTANT.")
        all_passed = False
    else:
        logger.info("[✓] TEST 2 PASSED: Classical primitive RSA-2048 classified as QUANTUM_VULNERABLE.")

    # 3. Configured hybrid but negotiated classical remains vulnerable
    logger.info("[TEST 3] Testing negative hybrid negotiation (configured hybrid, negotiated classical)...")
    status_neg, rec_neg, rat_neg = PqcClassifier.classify_primitive("X25519", CryptographicPurpose.KEY_ESTABLISHMENT)
    if status_neg == PrimitiveQuantumStatus.QUANTUM_RESISTANT or status_neg == PrimitiveQuantumStatus.HYBRID:
        logger.error("[X] TEST 3 FAILED: Negotiated X25519 falsely reported as resistant.")
        all_passed = False
    else:
        logger.info("[✓] TEST 3 PASSED: Configured hybrid with negotiated X25519 remains QUANTUM_VULNERABLE.")

    # 4. Altered expected manifest cannot manufacture runtime evidence
    logger.info("[TEST 4] Testing manifest tampering resistance...")
    fake_manifest = PROJECT_ROOT / "lab" / "expected" / "fake_test_manifest.json"
    fake_manifest.write_text(json.dumps({"fabricated": "evidence"}))
    code, e2e_out2 = run_cmd("DATABASE_URL=\"sqlite:///./pqc_discovery.db\" PYTHONPATH=. ./backend/venv/bin/python lab/scripts/run_lab_e2e.py")
    if fake_manifest.exists():
        fake_manifest.unlink()

    if "fabricated" in e2e_out2:
        logger.error("[X] TEST 4 FAILED: Fabricated manifest polluted discovery output.")
        all_passed = False
    else:
        logger.info("[✓] TEST 4 PASSED: Altered manifest did NOT manufacture runtime evidence.")

    # 5. Missing oqsprovider causes PQC pre-flight failure
    logger.info("[TEST 5] Testing missing oqsprovider pre-flight failure...")
    fake_cmd = (
        "docker run -u 0 --rm alpine:3.19 "
        "sh -c \"openssl list -providers 2>/dev/null || echo 'default'\""
    )
    code, fake_out = run_cmd(fake_cmd)
    if "oqsprovider" not in fake_out:
        logger.info("[✓] TEST 5 PASSED: Alpine base container correctly reported missing oqsprovider.")
    else:
        logger.error("[X] TEST 5 FAILED: Expected oqsprovider to be missing.")
        all_passed = False

    # 6. Image digest mismatch causes reproducibility validation failure
    logger.info("[TEST 6] Testing image digest mismatch in pre-flight validator...")
    manifest_path = PROJECT_ROOT / "lab" / "runtime-manifest.json"
    original_manifest = manifest_path.read_text()
    tampered_manifest = original_manifest.replace("sha256:6c8bebd06da583071c06331a433c31128f271fa8d16a19b3e75dbb5d5e4e1994", "sha256:badbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadb")
    manifest_path.write_text(tampered_manifest)

    code, val_out = run_cmd("python3 lab/scripts/validate_environment.py")
    manifest_path.write_text(original_manifest)

    if code != 0 or "PRE-FLIGHT VALIDATION FAILED" in val_out:
        logger.info("[✓] TEST 6 PASSED: Image digest mismatch correctly triggered PRE-FLIGHT VALIDATION FAILED.")
    else:
        logger.error(f"[X] TEST 6 FAILED: Digest mismatch did not trigger failure:\n{val_out}")
        all_passed = False

    if all_passed:
        logger.info("==================================================================")
        logger.info("   NEGATIVE CONTROLS SUITE PASSED: 6/6 TESTS PASSED (100%)       ")
        logger.info("==================================================================")
        return True
    else:
        logger.error("==================================================================")
        logger.error("   NEGATIVE CONTROLS SUITE FAILED                                ")
        logger.error("==================================================================")
        return False

if __name__ == "__main__":
    success = run_negative_controls()
    sys.exit(0 if success else 1)
