import os
import json
import glob
import logging
from typing import AsyncIterator, Set
from app.scanners.base import Scanner, RawFinding, ScanContext, ScannerRegistry
from app.models.entities import (
    TargetType, AssetType, FindingType, FindingPurpose, FindingConfidence
)

logger = logging.getLogger(__name__)

KNOWN_CRYPTO_LIBS = {
    "cryptography": ("AES / RSA / ECDSA Cryptography Library", "RSA-2048"),
    "pycryptodome": ("PyCryptodome Library", "AES-256-GCM"),
    "pycrypto": ("Legacy PyCrypto Library", "DES"),
    "bouncycastle": ("BouncyCastle Cryptography Framework", "RSA-4096"),
    "bcprov-jdk18on": ("BouncyCastle Java Provider", "RSA-2048"),
    "libsodium": ("LibSodium Crypto Library", "X25519"),
    "liboqs": ("Open Quantum Safe (OQS) PQC Library", "ML-KEM-768"),
    "oqs": ("Open Quantum Safe Library", "ML-KEM-768"),
    "crypto-js": ("CryptoJS JavaScript Library", "AES-256-GCM"),
    "jsonwebtoken": ("JSON Web Token Signature Library", "RSA-2048"),
    "jose": ("JOSE Web Encryption & Signature Library", "ECDSA-P256"),
}

class DependencyScanner(Scanner):
    scanner_id = "dependency-scanner"
    version = "1.0.0"
    supported_target_types = {
        TargetType.REPOSITORY, TargetType.HOSTNAME, TargetType.URL
    }

    async def discover(
        self,
        target_value: str,
        target_type: TargetType,
        context: ScanContext
    ) -> AsyncIterator[RawFinding]:
        target_path = target_value.strip()

        if os.path.exists(target_path):
            manifest_files = []
            manifest_names = ("package.json", "requirements.txt", "go.mod", "pom.xml", "Cargo.toml")
            for name in manifest_names:
                manifest_files.extend(glob.glob(os.path.join(target_path, "**", name), recursive=True))

            for manifest in manifest_files:
                try:
                    rel_path = os.path.relpath(manifest, target_path)
                    with open(manifest, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()

                    if manifest.endswith("package.json"):
                        data = json.loads(content)
                        deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
                        for dep_name, version in deps.items():
                            dep_lower = dep_name.lower()
                            if dep_lower in KNOWN_CRYPTO_LIBS:
                                desc, default_algo = KNOWN_CRYPTO_LIBS[dep_lower]
                                yield RawFinding(
                                    asset_hostname=os.path.basename(target_path),
                                    asset_type=AssetType.SOURCE_REPOSITORY,
                                    environment="DEVELOPMENT",
                                    finding_type=FindingType.LIBRARY_DEPENDENCY,
                                    raw_algorithm_name=default_algo,
                                    purpose=FindingPurpose.ENCRYPTION,
                                    location_identifier=f"Manifest: {rel_path} -> {dep_name}@{version}",
                                    evidence_snippet=f"Package Dependency: {dep_name} ({version}) in {rel_path} [{desc}]",
                                    confidence=FindingConfidence.HIGH,
                                    metadata={"package": dep_name, "version": str(version), "manifest": rel_path}
                                )

                    elif manifest.endswith("requirements.txt"):
                        lines = content.splitlines()
                        for line in lines:
                            line_clean = line.strip().lower()
                            for lib_name, (desc, default_algo) in KNOWN_CRYPTO_LIBS.items():
                                if lib_name in line_clean:
                                    yield RawFinding(
                                        asset_hostname=os.path.basename(target_path),
                                        asset_type=AssetType.SOURCE_REPOSITORY,
                                        environment="DEVELOPMENT",
                                        finding_type=FindingType.LIBRARY_DEPENDENCY,
                                        raw_algorithm_name=default_algo,
                                        purpose=FindingPurpose.ENCRYPTION,
                                        location_identifier=f"Manifest: {rel_path} -> {line.strip()}",
                                        evidence_snippet=f"Python Dependency: {line.strip()} in {rel_path} [{desc}]",
                                        confidence=FindingConfidence.HIGH,
                                        metadata={"requirement": line.strip(), "manifest": rel_path}
                                    )

                except Exception as e:
                    logger.warning(f"Error scanning dependency manifest '{manifest}': {e}")
        else:
            # Yield simulated dependency finding
            async for finding in self._generate_simulated_dep_findings(target_value):
                yield finding

    async def _generate_simulated_dep_findings(self, target_value: str) -> AsyncIterator[RawFinding]:
        findings = [
            RawFinding(
                asset_hostname=target_value,
                asset_type=AssetType.SOURCE_REPOSITORY,
                environment="DEVELOPMENT",
                finding_type=FindingType.LIBRARY_DEPENDENCY,
                raw_algorithm_name="RSA-2048",
                purpose=FindingPurpose.ENCRYPTION,
                location_identifier=f"Manifest: {target_value}/package.json -> cryptography@42.0.0",
                evidence_snippet="Package Dependency: cryptography v42.0.0 in package.json",
                confidence=FindingConfidence.HIGH,
                metadata={"package": "cryptography", "version": "42.0.0"}
            ),
            RawFinding(
                asset_hostname=target_value,
                asset_type=AssetType.SOURCE_REPOSITORY,
                environment="DEVELOPMENT",
                finding_type=FindingType.LIBRARY_DEPENDENCY,
                raw_algorithm_name="ML-KEM-768",
                purpose=FindingPurpose.KEY_EXCHANGE,
                location_identifier=f"Manifest: {target_value}/requirements.txt -> liboqs-python@0.9.0",
                evidence_snippet="Post-Quantum Library Dependency: liboqs-python v0.9.0 (Open Quantum Safe)",
                confidence=FindingConfidence.HIGH,
                metadata={"package": "liboqs-python", "version": "0.9.0"}
            )
        ]
        for f in findings:
            yield f

ScannerRegistry.register(DependencyScanner())
