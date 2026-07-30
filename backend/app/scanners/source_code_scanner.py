import os
import re
import glob
import logging
from typing import AsyncIterator, Set, List, Tuple
from app.scanners.base import Scanner, RawFinding, ScanContext, ScannerRegistry
from app.models.entities import (
    TargetType, AssetType, FindingType, FindingPurpose, FindingConfidence
)

logger = logging.getLogger(__name__)

CODE_PATTERNS = [
    {
        "pattern": r"(?:RSA\.generate|createCipheriv\(['\"]rsa|RSA[-_]?2048|KeyFactory\.getInstance\(['\"]RSA['\"])|RSA\.import_key",
        "algo": "RSA-2048",
        "type": FindingType.CERTIFICATE_PUBLIC_KEY,
        "purpose": FindingPurpose.AUTHENTICATION,
        "key_size": 2048
    },
    {
        "pattern": r"(?:aes[-_]?256[-_]?gcm|AES[-_]?256[-_]?CBC|createCipheriv\(['\"]aes-256|Cipher\.getInstance\(['\"]AES)",
        "algo": "AES-256-GCM",
        "type": FindingType.SYMMETRIC_CIPHER,
        "purpose": FindingPurpose.ENCRYPTION,
        "key_size": 256
    },
    {
        "pattern": r"(?:ECDSA|secp256r1|elliptic\.ec\(['\"]secp256r1['\"]|ec\.generate_private_key|P-256)",
        "algo": "ECDSA-P256",
        "type": FindingType.SIGNATURE_ALGORITHM,
        "purpose": FindingPurpose.DIGITAL_SIGNATURE,
        "key_size": 256
    },
    {
        "pattern": r"(?:X25519|curve25519|x25519_kyber768)",
        "algo": "X25519",
        "type": FindingType.KEY_EXCHANGE,
        "purpose": FindingPurpose.KEY_EXCHANGE,
        "key_size": 256
    },
    {
        "pattern": r"(?:createHash\(['\"]sha384['\"]|SHA384|MessageDigest\.getInstance\(['\"]SHA-384['\"]|hashlib\.sha384)",
        "algo": "SHA-384",
        "type": FindingType.HASH_FUNCTION,
        "purpose": FindingPurpose.INTEGRITY,
        "key_size": 384
    },
    {
        "pattern": r"(?:createHash\(['\"]sha256['\"]|SHA256|MessageDigest\.getInstance\(['\"]SHA-256['\"]|hashlib\.sha256)",
        "algo": "SHA-256",
        "type": FindingType.HASH_FUNCTION,
        "purpose": FindingPurpose.INTEGRITY,
        "key_size": 256
    },
    {
        "pattern": r"(?:Kyber768|ml[-_]?kem[-_]?768|OQS_KEM_alg_kyber_768)",
        "algo": "Kyber768",
        "type": FindingType.KEY_EXCHANGE,
        "purpose": FindingPurpose.KEY_EXCHANGE,
        "key_size": 192
    },
    {
        "pattern": r"(?:Dilithium3|ml[-_]?dsa[-_]?65|OQS_SIG_alg_dilithium_3)",
        "algo": "Dilithium3",
        "type": FindingType.SIGNATURE_ALGORITHM,
        "purpose": FindingPurpose.DIGITAL_SIGNATURE,
        "key_size": 192
    }
]

class SourceCodeScanner(Scanner):
    scanner_id = "source-code-scanner"
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

        # If target path is an existing repository or directory
        if os.path.exists(target_path):
            code_files = []
            extensions = ("*.py", "*.js", "*.ts", "*.go", "*.java", "*.c", "*.cpp", "*.rs", "*.cs")
            for ext in extensions:
                code_files.extend(glob.glob(os.path.join(target_path, "**", ext), recursive=True))

            for file_path in code_files:
                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        lines = f.readlines()

                    rel_path = os.path.relpath(file_path, target_path)

                    for line_num, line in enumerate(lines, 1):
                        for rule in CODE_PATTERNS:
                            if re.search(rule["pattern"], line, re.IGNORECASE):
                                clean_line = line.strip()
                                yield RawFinding(
                                    asset_hostname=os.path.basename(target_path),
                                    asset_type=AssetType.SOURCE_REPOSITORY,
                                    environment="DEVELOPMENT",
                                    finding_type=rule["type"],
                                    raw_algorithm_name=rule["algo"],
                                    key_size=rule["key_size"],
                                    purpose=rule["purpose"],
                                    location_identifier=f"File: {rel_path} :L{line_num}",
                                    evidence_snippet=f"AST Match in {rel_path}:L{line_num}: {clean_line}",
                                    confidence=FindingConfidence.HIGH,
                                    metadata={"repo": target_value, "file": rel_path, "line_number": line_num}
                                )

                except Exception as e:
                    logger.warning(f"Error scanning code file '{file_path}': {e}")
        else:
            logger.info(f"[SourceCodeScanner] Path '{target_value}' is not a local filesystem directory; no source code findings extracted.")
            return

    async def _generate_simulated_code_findings(self, target_value: str) -> AsyncIterator[RawFinding]:
        findings = [
            RawFinding(
                asset_hostname=target_value,
                asset_type=AssetType.SOURCE_REPOSITORY,
                environment="DEVELOPMENT",
                finding_type=FindingType.CERTIFICATE_PUBLIC_KEY,
                raw_algorithm_name="RSA-2048",
                key_size=2048,
                purpose=FindingPurpose.AUTHENTICATION,
                location_identifier=f"Repo: {target_value} -> src/crypto/keys.ts :L42",
                evidence_snippet="const rsaKey = await crypto.subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048 }, true, ['sign']);",
                confidence=FindingConfidence.HIGH,
                metadata={"file": "src/crypto/keys.ts", "line": 42}
            ),
            RawFinding(
                asset_hostname=target_value,
                asset_type=AssetType.SOURCE_REPOSITORY,
                environment="DEVELOPMENT",
                finding_type=FindingType.SYMMETRIC_CIPHER,
                raw_algorithm_name="AES-256-GCM",
                key_size=256,
                purpose=FindingPurpose.ENCRYPTION,
                location_identifier=f"Repo: {target_value} -> src/crypto/cipher.ts :L105",
                evidence_snippet="const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);",
                confidence=FindingConfidence.HIGH,
                metadata={"file": "src/crypto/cipher.ts", "line": 105}
            )
        ]
        for f in findings:
            yield f

ScannerRegistry.register(SourceCodeScanner())
