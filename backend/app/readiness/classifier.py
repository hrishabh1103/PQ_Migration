import logging
from typing import Tuple, Dict, Any, Optional
from app.readiness.taxonomy import CryptographicPurpose, PrimitiveQuantumStatus

logger = logging.getLogger(__name__)

class PqcClassifier:
    """
    Provider-independent PQC Readiness Primitive Classifier & Purpose-Aware Migration Recommender.
    Evaluates cryptographic algorithms by explicit PURPOSE.
    """

    @classmethod
    def classify_primitive(
        cls,
        algorithm_name: str,
        purpose: CryptographicPurpose
    ) -> Tuple[PrimitiveQuantumStatus, str, str]:
        """
        Classifies an algorithm primitive and yields (PrimitiveQuantumStatus, recommendation, rationale).
        """
        algo_upper = algorithm_name.upper().strip()

        # 1. Quantum Resistant Primitives
        if "ML-KEM" in algo_upper or "KYBER" in algo_upper:
            return (
                PrimitiveQuantumStatus.QUANTUM_RESISTANT,
                "Standardized PQC Primitive (NIST FIPS 203)",
                "ML-KEM lattice-based key encapsulation mechanism is quantum-resistant."
            )
        if "ML-DSA" in algo_upper or "DILITHIUM" in algo_upper or "SLH-DSA" in algo_upper or "SPHINCS" in algo_upper:
            return (
                PrimitiveQuantumStatus.QUANTUM_RESISTANT,
                "Standardized PQC Signature Primitive (NIST FIPS 204 / FIPS 205)",
                "ML-DSA / SLH-DSA lattice/hash-based signature scheme is quantum-resistant."
            )
        if "HYBRID" in algo_upper or ("X25519" in algo_upper and "MLKEM" in algo_upper):
            return (
                PrimitiveQuantumStatus.HYBRID,
                "Approved Dual-Primitive Hybrid Key Exchange",
                "Combines classical ECDH with quantum-resistant ML-KEM for defense-in-depth."
            )

        # 2. Symmetric Encryption & Hashing
        if purpose in [CryptographicPurpose.SYMMETRIC_ENCRYPTION, CryptographicPurpose.STORAGE_ENCRYPTION, CryptographicPurpose.HASH, CryptographicPurpose.MAC]:
            if "256" in algo_upper or "AES" in algo_upper or "SHA2" in algo_upper or "SHA3" in algo_upper:
                return (
                    PrimitiveQuantumStatus.NOT_APPLICABLE,
                    "Maintain AES-256 / SHA-256 symmetric key sizes",
                    "Grover's algorithm halves effective symmetric key length; 256-bit keys remain secure."
                )

        # 3. Purpose-Aware Vulnerable Asymmetric Primitives (RSA, ECDH, ECDSA)
        if "RSA" in algo_upper or "ECDH" in algo_upper or "ECDSA" in algo_upper or "DH" in algo_upper or "DSA" in algo_upper or "ED25519" in algo_upper:
            if purpose in [CryptographicPurpose.KEY_ESTABLISHMENT, CryptographicPurpose.PUBLIC_KEY_ENCRYPTION]:
                return (
                    PrimitiveQuantumStatus.QUANTUM_VULNERABLE,
                    "Migrate Key Establishment to ML-KEM-768 or X25519+MLKEM768 Hybrid",
                    "Shor's algorithm breaks RSA/ECDH discrete logarithm & prime factorization."
                )
            elif purpose in [CryptographicPurpose.DIGITAL_SIGNATURE, CryptographicPurpose.CERTIFICATE_SIGNATURE, CryptographicPurpose.CODE_SIGNING, CryptographicPurpose.IDENTITY_AUTHENTICATION]:
                return (
                    PrimitiveQuantumStatus.QUANTUM_VULNERABLE,
                    "Migrate Signature Scheme to ML-DSA-65 or SLH-DSA-SHA2-128f",
                    "Shor's algorithm allows quantum forgery of RSA/ECDSA digital signatures."
                )
            else:
                return (
                    PrimitiveQuantumStatus.QUANTUM_VULNERABLE,
                    "Migrate Asymmetric Primitive based on purpose",
                    "Classical asymmetric algorithm vulnerable to Shor's algorithm on quantum hardware."
                )

        return (
            PrimitiveQuantumStatus.UNKNOWN,
            "Evaluate algorithm details with Security Architecture",
            "Algorithm status or purpose requires further context."
        )
