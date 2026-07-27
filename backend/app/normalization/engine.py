from typing import Dict, Any, Tuple
from sqlalchemy.orm import Session
from app.models.entities import (
    NormalizedAlgorithm, PrimitiveType, QuantumSafetyStatus
)

# Comprehensive taxonomy table mapping observed patterns to canonical fields
TAXONOMY_RULES = [
    # RSA
    {
        "pattern": r"^rsa[-_]?2048$",
        "canonical_id": "RSA-2048",
        "name": "RSA 2048-bit",
        "family": "RSA",
        "variant": "RSA-2048",
        "impl": None,
        "primitive": PrimitiveType.ASYMMETRIC_ENCRYPTION,
        "status": QuantumSafetyStatus.QUANTUM_VULNERABLE,
        "bits": 112,
        "nist": "NIST SP 800-56B (Vulnerable to Shor's Algorithm)"
    },
    {
        "pattern": r"^rsa[-_]?3072$",
        "canonical_id": "RSA-3072",
        "name": "RSA 3072-bit",
        "family": "RSA",
        "variant": "RSA-3072",
        "impl": None,
        "primitive": PrimitiveType.ASYMMETRIC_ENCRYPTION,
        "status": QuantumSafetyStatus.QUANTUM_VULNERABLE,
        "bits": 128,
        "nist": "NIST SP 800-56B (Vulnerable to Shor's Algorithm)"
    },
    {
        "pattern": r"^rsa[-_]?4096$",
        "canonical_id": "RSA-4096",
        "name": "RSA 4096-bit",
        "family": "RSA",
        "variant": "RSA-4096",
        "impl": None,
        "primitive": PrimitiveType.ASYMMETRIC_ENCRYPTION,
        "status": QuantumSafetyStatus.QUANTUM_VULNERABLE,
        "bits": 152,
        "nist": "NIST SP 800-56B (Vulnerable to Shor's Algorithm)"
    },

    # ECC / Key Exchange
    {
        "pattern": r"^x25519$",
        "canonical_id": "X25519",
        "name": "Curve25519 ECDH Key Exchange",
        "family": "ECC",
        "variant": "X25519",
        "impl": "Curve25519",
        "primitive": PrimitiveType.KEY_EXCHANGE,
        "status": QuantumSafetyStatus.QUANTUM_VULNERABLE,
        "bits": 128,
        "nist": "RFC 7748 (Vulnerable to Shor's Algorithm)"
    },
    {
        "pattern": r"^ecdsa[-_]?p256|secp256r1$",
        "canonical_id": "ECDSA-P256",
        "name": "ECDSA P-256 Signature",
        "family": "ECC",
        "variant": "P-256",
        "impl": "secp256r1",
        "primitive": PrimitiveType.SIGNATURE,
        "status": QuantumSafetyStatus.QUANTUM_VULNERABLE,
        "bits": 128,
        "nist": "FIPS 186-5 (Vulnerable to Shor's Algorithm)"
    },

    # PQC Standardized / Candidates
    {
        "pattern": r"^kyber768$",
        "canonical_id": "ML-KEM-768-Kyber768",
        "name": "Kyber-768 (Pre-standardization ML-KEM)",
        "family": "ML-KEM",
        "variant": "ML-KEM-768",
        "impl": "Kyber768",
        "primitive": PrimitiveType.KEY_EXCHANGE,
        "status": QuantumSafetyStatus.PQC_CANDIDATE,
        "bits": 192,
        "nist": "NIST PQC Round 3 Candidate / FIPS 203 Draft"
    },
    {
        "pattern": r"^ml[-_]?kem[-_]?768$",
        "canonical_id": "ML-KEM-768",
        "name": "ML-KEM-768 (Module-Lattice Key Encapsulation)",
        "family": "ML-KEM",
        "variant": "ML-KEM-768",
        "impl": None,
        "primitive": PrimitiveType.KEY_EXCHANGE,
        "status": QuantumSafetyStatus.PQC_STANDARDIZED,
        "bits": 192,
        "nist": "NIST FIPS 203 Standard"
    },
    {
        "pattern": r"^dilithium3$",
        "canonical_id": "ML-DSA-65-Dilithium3",
        "name": "Dilithium3 (Pre-standardization ML-DSA)",
        "family": "ML-DSA",
        "variant": "ML-DSA-65",
        "impl": "Dilithium3",
        "primitive": PrimitiveType.SIGNATURE,
        "status": QuantumSafetyStatus.PQC_CANDIDATE,
        "bits": 192,
        "nist": "NIST PQC Round 3 Candidate / FIPS 204 Draft"
    },
    {
        "pattern": r"^ml[-_]?dsa[-_]?65$",
        "canonical_id": "ML-DSA-65",
        "name": "ML-DSA-65 (Module-Lattice Digital Signature)",
        "family": "ML-DSA",
        "variant": "ML-DSA-65",
        "impl": None,
        "primitive": PrimitiveType.SIGNATURE,
        "status": QuantumSafetyStatus.PQC_STANDARDIZED,
        "bits": 192,
        "nist": "NIST FIPS 204 Standard"
    },

    # Hybrid
    {
        "pattern": r"^x25519mlkem768|x25519_kyber768$",
        "canonical_id": "HYBRID-X25519-MLKEM768",
        "name": "Hybrid X25519 + ML-KEM-768 Key Exchange",
        "family": "HYBRID",
        "variant": "X25519-MLKEM768",
        "impl": "X25519-Kyber768",
        "primitive": PrimitiveType.KEY_EXCHANGE,
        "status": QuantumSafetyStatus.HYBRID,
        "bits": 192,
        "nist": "Draft RFC Hybrid Key Exchange"
    },

    # Symmetric Ciphers
    {
        "pattern": r"^aes[-_]?256[-_]?gcm$",
        "canonical_id": "AES-256-GCM",
        "name": "AES 256-bit GCM",
        "family": "AES",
        "variant": "AES-256-GCM",
        "impl": None,
        "primitive": PrimitiveType.SYMMETRIC,
        "status": QuantumSafetyStatus.SYMMETRIC,
        "bits": 256,
        "nist": "NIST SP 800-38D (Resistant to Grover's Algorithm)"
    },
    {
        "pattern": r"^aes[-_]?128[-_]?gcm$",
        "canonical_id": "AES-128-GCM",
        "name": "AES 128-bit GCM",
        "family": "AES",
        "variant": "AES-128-GCM",
        "impl": None,
        "primitive": PrimitiveType.SYMMETRIC,
        "status": QuantumSafetyStatus.SYMMETRIC,
        "bits": 128,
        "nist": "NIST SP 800-38D"
    },

    # Hashes
    {
        "pattern": r"^sha[-_]?384$",
        "canonical_id": "SHA-384",
        "name": "SHA-384 Hash Function",
        "family": "SHA2",
        "variant": "SHA-384",
        "impl": None,
        "primitive": PrimitiveType.HASH,
        "status": QuantumSafetyStatus.HASH,
        "bits": 192,
        "nist": "FIPS 180-4"
    },
    {
        "pattern": r"^sha[-_]?256$",
        "canonical_id": "SHA-256",
        "name": "SHA-256 Hash Function",
        "family": "SHA2",
        "variant": "SHA-256",
        "impl": None,
        "primitive": PrimitiveType.HASH,
        "status": QuantumSafetyStatus.HASH,
        "bits": 128,
        "nist": "FIPS 180-4"
    },

    # Deprecated / Legacy
    {
        "pattern": r"^md5$",
        "canonical_id": "MD5",
        "name": "MD5 Hash Function",
        "family": "MD5",
        "variant": "MD5",
        "impl": None,
        "primitive": PrimitiveType.HASH,
        "status": QuantumSafetyStatus.DEPRECATED,
        "bits": 0,
        "nist": "Deprecated (Collision Vulnerable)"
    },
    {
        "pattern": r"^sha[-_]?1$",
        "canonical_id": "SHA-1",
        "name": "SHA-1 Hash Function",
        "family": "SHA1",
        "variant": "SHA-1",
        "impl": None,
        "primitive": PrimitiveType.HASH,
        "status": QuantumSafetyStatus.DEPRECATED,
        "bits": 64,
        "nist": "Deprecated (FIPS 180-4)"
    }
]

import re

class NormalizationEngine:
    """
    Algorithm Normalization Engine.
    Maps observed algorithm strings to standardized canonical taxonomy entries
    while strictly preserving observed names and distinguishing historical vs standardized implementations.
    """

    @classmethod
    def normalize_and_get_or_create(cls, db: Session, raw_algorithm_name: str) -> NormalizedAlgorithm:
        clean_raw = raw_algorithm_name.strip()
        raw_lower = clean_raw.lower()

        # Find matching taxonomy rule
        matched_rule = None
        for rule in TAXONOMY_RULES:
            if re.search(rule["pattern"], raw_lower):
                matched_rule = rule
                break

        if matched_rule:
            canonical_id = matched_rule["canonical_id"]
            name = matched_rule["name"]
            family = matched_rule["family"]
            variant = matched_rule["variant"]
            impl = matched_rule["impl"]
            primitive = matched_rule["primitive"]
            status = matched_rule["status"]
            bits = matched_rule["bits"]
            nist = matched_rule["nist"]
        else:
            # Fallback for unknown algorithm
            canonical_id = f"UNKNOWN-{clean_raw.upper().replace(' ', '-')}"
            name = f"Unclassified Algorithm ({clean_raw})"
            family = clean_raw.upper().split("-")[0]
            variant = clean_raw
            impl = None
            primitive = PrimitiveType.ASYMMETRIC_ENCRYPTION
            status = QuantumSafetyStatus.UNKNOWN
            bits = None
            nist = "Unrecognized algorithm string"

        # Query DB for existing algorithm entity
        existing = db.query(NormalizedAlgorithm).filter(NormalizedAlgorithm.canonical_id == canonical_id).first()
        if existing:
            return existing

        # Create new NormalizedAlgorithm entity
        new_algo = NormalizedAlgorithm(
            canonical_id=canonical_id,
            name=name,
            observed_name=clean_raw,
            canonical_family=family,
            canonical_variant=variant,
            implementation_variant=impl,
            primitive_type=primitive,
            quantum_safety_status=status,
            estimated_security_bits=bits,
            nist_standard_status=nist
        )
        db.add(new_algo)
        db.flush()
        return new_algo
