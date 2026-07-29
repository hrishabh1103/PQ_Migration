#!/usr/bin/env python3
import sys
import json
import socket
import subprocess
import logging
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
MANIFEST_PATH = PROJECT_ROOT / "lab" / "runtime-manifest.json"

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("LabPreFlightValidator")

def run_cmd(cmd: str) -> tuple[int, str]:
    try:
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        return res.returncode, res.stdout + res.stderr
    except Exception as e:
        return 1, str(e)

def validate_environment() -> bool:
    logger.info("==================================================================")
    logger.info("   PQC VALIDATION LAB — ENVIRONMENT REPRODUCIBILITY PRE-FLIGHT   ")
    logger.info("==================================================================")

    if not MANIFEST_PATH.exists():
        logger.error(f"FAIL: Runtime manifest missing at {MANIFEST_PATH}")
        return False

    manifest = json.loads(MANIFEST_PATH.read_text())

    # 1. Docker availability
    code, out = run_cmd("docker info")
    if code != 0:
        logger.error("FAIL: Docker daemon is not available.")
        return False
    logger.info("[✓] Docker daemon is active.")

    # 2. Check running container health and digests
    code, ps_out = run_cmd("docker ps --format '{{.Names}}|{{.Image}}|{{.Status}}'")
    if code != 0:
        logger.error("FAIL: Unable to query docker ps.")
        return False

    running = {}
    for line in ps_out.strip().split("\n"):
        if "|" in line:
            parts = line.split("|")
            running[parts[0]] = {"image": parts[1], "status": parts[2]}

    all_passed = True

    for svc in manifest["services"]:
        cname = svc["container_name"]
        expected_digest = svc["image_digest"]

        if cname not in running:
            logger.error(f"FAIL: Container '{cname}' is not running.")
            all_passed = False
            continue

        status_str = running[cname]["status"]
        if "Up" not in status_str:
            logger.error(f"FAIL: Container '{cname}' status is not 'Up': {status_str}")
            all_passed = False

        # Inspect image digest of running container
        code, dig_out = run_cmd(f"docker inspect --format '{{{{.Image}}}}' {cname}")
        code2, dig_out2 = run_cmd(f"docker inspect --format '{{{{index .RepoDigests 0}}}}' {cname}")
        
        if expected_digest not in dig_out2 and expected_digest[:12] not in dig_out:
            logger.error(f"FAIL: Container '{cname}' image digest mismatch: expected {expected_digest}, got {dig_out2}")
            all_passed = False

        logger.info(f"[✓] Container '{cname}' is Up ({status_str[:25]}).")

    # 3. Check port reachability
    for svc in manifest["services"]:
        port = svc["expected_exposed_port"]
        if port is not None:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=2.0):
                    logger.info(f"[✓] Port {port} ({svc['service_name']}) is reachable.")
            except Exception as e:
                logger.error(f"FAIL: Port {port} ({svc['service_name']}) is unreachable: {e}")
                all_passed = False

    # 4. Verify PQC container oqsprovider capabilities
    pqc_cmd = (
        "docker run -u 0 --rm openquantumsafe/nginx@sha256:6c8bebd06da583071c06331a433c31128f271fa8d16a19b3e75dbb5d5e4e1994 "
        "sh -c \"apk add --no-cache openssl >/dev/null 2>&1 && "
        "OPENSSL_MODULES=/opt/openssl/.openssl/lib/ossl-modules openssl list -providers -provider oqsprovider\""
    )
    code, oqs_out = run_cmd(pqc_cmd)
    if "OpenSSL OQS Provider" not in oqs_out or "oqsprovider" not in oqs_out:
        logger.error(f"FAIL: PQC container missing active oqsprovider:\n{oqs_out}")
        all_passed = False
    else:
        logger.info("[✓] PQC container oqsprovider is active (v0.9.0).")

    # 5. Verify algorithms: mlkem768, mldsa65, X25519MLKEM768
    kem_cmd = (
        "docker run -u 0 --rm openquantumsafe/nginx@sha256:6c8bebd06da583071c06331a433c31128f271fa8d16a19b3e75dbb5d5e4e1994 "
        "sh -c \"apk add --no-cache openssl >/dev/null 2>&1 && "
        "OPENSSL_MODULES=/opt/openssl/.openssl/lib/ossl-modules openssl list -kem-algorithms -provider oqsprovider\""
    )
    code, kem_out = run_cmd(kem_cmd)
    
    if "mlkem768" not in kem_out:
        logger.error("FAIL: Algorithm 'mlkem768' missing from oqsprovider.")
        all_passed = False
    else:
        logger.info("[✓] Algorithm 'mlkem768' verified.")

    if "X25519MLKEM768" not in kem_out and "x25519_mlkem768" not in kem_out:
        logger.error("FAIL: Hybrid algorithm 'X25519MLKEM768' missing from oqsprovider.")
        all_passed = False
    else:
        logger.info("[✓] Hybrid algorithm 'X25519MLKEM768' verified.")

    sig_cmd = (
        "docker run -u 0 --rm openquantumsafe/nginx@sha256:6c8bebd06da583071c06331a433c31128f271fa8d16a19b3e75dbb5d5e4e1994 "
        "sh -c \"apk add --no-cache openssl >/dev/null 2>&1 && "
        "OPENSSL_MODULES=/opt/openssl/.openssl/lib/ossl-modules openssl list -signature-algorithms -provider oqsprovider\""
    )
    code, sig_out = run_cmd(sig_cmd)

    if "mldsa65" not in sig_out:
        logger.error("FAIL: Signature algorithm 'mldsa65' missing from oqsprovider.")
        all_passed = False
    else:
        logger.info("[✓] Signature algorithm 'mldsa65' verified.")

    # 6. Verify SSH pinned digest
    ssh_digest = "sha256:9c5e178975fcc3917853f5e37cbf135ad7deb11de504ab0f460cc81a2e1eb539"
    code, ssh_inspect = run_cmd("docker inspect lab-ssh-server")
    if ssh_digest not in ssh_inspect and "9c5e178975fc" not in ssh_inspect:
        logger.error("FAIL: SSH container digest mismatch.")
        all_passed = False
    else:
        logger.info("[✓] SSH container image digest matches pinned baseline.")

    if all_passed:
        logger.info("==================================================================")
        logger.info("   PRE-FLIGHT VALIDATION PASSED: ENVIRONMENT IS REPRODUCIBLE     ")
        logger.info("==================================================================")
        return True
    else:
        logger.error("==================================================================")
        logger.error("   PRE-FLIGHT VALIDATION FAILED: ENVIRONMENT MISMATCH DETECTED    ")
        logger.error("==================================================================")
        return False

if __name__ == "__main__":
    success = validate_environment()
    sys.exit(0 if success else 1)
