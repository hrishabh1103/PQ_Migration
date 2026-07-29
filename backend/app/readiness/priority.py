import logging
from typing import Dict, Any, List, Optional
from app.readiness.taxonomy import CryptographicPurpose, PrimitiveQuantumStatus

logger = logging.getLogger(__name__)

class MigrationPriorityEngine:
    """
    Calculates purpose-aware PQC Migration Priority combining vulnerability, purpose,
    network exposure, HNDL context, asset criticality, dependency blast radius, and coverage confidence.
    Explictly preserves UNKNOWN factors.
    """

    @classmethod
    def calculate_priority(
        cls,
        quantum_status: PrimitiveQuantumStatus,
        purpose: CryptographicPurpose,
        is_internet_exposed: Optional[bool] = None,
        business_criticality: Optional[str] = None,
        hndl_relevance: Optional[bool] = None,
        confidentiality_lifetime: Optional[str] = None,
        downstream_dependents_count: int = 0,
        coverage_status: str = "SCANNED",
        correlation_confidence: str = "HIGH"
    ) -> Dict[str, Any]:
        score = 0
        known_factors: List[str] = []
        unknown_factors: List[str] = []
        rationales: List[str] = []

        # 1. Quantum Vulnerability Base Weight
        if quantum_status == PrimitiveQuantumStatus.QUANTUM_VULNERABLE:
            score += 40
            known_factors.append("Primitive is Quantum-Vulnerable (Shor's Algorithm)")
        elif quantum_status == PrimitiveQuantumStatus.HYBRID:
            score += 10
            known_factors.append("Primitive is Hybrid (Defense-in-depth transition)")
        elif quantum_status == PrimitiveQuantumStatus.QUANTUM_RESISTANT:
            score += 0
            known_factors.append("Primitive is Quantum-Resistant")
        else:
            unknown_factors.append("Primitive Quantum Safety Status is UNKNOWN")

        # 2. Cryptographic Purpose Weight & HNDL Context
        if purpose in [CryptographicPurpose.KEY_ESTABLISHMENT, CryptographicPurpose.PUBLIC_KEY_ENCRYPTION]:
            score += 25
            known_factors.append(f"Purpose '{purpose.value}' is susceptible to Harvest-Now-Decrypt-Later (HNDL)")
            if hndl_relevance is True:
                score += 15
                known_factors.append("High HNDL Relevance (Long-term confidentiality required)")
            elif hndl_relevance is None:
                unknown_factors.append("HNDL Confidentiality Lifetime Requirement is UNKNOWN")
        elif purpose in [CryptographicPurpose.DIGITAL_SIGNATURE, CryptographicPurpose.CERTIFICATE_SIGNATURE, CryptographicPurpose.CODE_SIGNING]:
            score += 20
            known_factors.append(f"Purpose '{purpose.value}' is vulnerable to Quantum Signature Forgery")
        elif purpose == CryptographicPurpose.IDENTITY_AUTHENTICATION:
            score += 15
            known_factors.append("Purpose 'IDENTITY_AUTHENTICATION' is vulnerable to Identity Forgery")
        else:
            known_factors.append(f"Purpose '{purpose.value}' has lower quantum migration urgency")

        # 3. External Network Exposure
        if is_internet_exposed is True:
            score += 15
            known_factors.append("Asset is Internet-Exposed (High attack surface)")
        elif is_internet_exposed is False:
            known_factors.append("Asset is Internal-Only")
        else:
            unknown_factors.append("Network Exposure State is UNKNOWN")

        # 4. Asset Criticality
        if business_criticality:
            bc_upper = business_criticality.upper()
            if bc_upper == "CRITICAL":
                score += 10
                known_factors.append("Business Criticality is CRITICAL")
            elif bc_upper == "HIGH":
                score += 5
                known_factors.append("Business Criticality is HIGH")
        else:
            unknown_factors.append("Business Criticality is UNKNOWN")

        # 5. Dependency Blast Radius
        if downstream_dependents_count > 0:
            added = min(10, downstream_dependents_count * 2)
            score += added
            known_factors.append(f"Dependency Blast Radius: {downstream_dependents_count} downstream dependent resources")

        # 6. Coverage Confidence Penalty
        readiness_confidence = "HIGH"
        if coverage_status in ["NOT_SCANNED", "PARTIALLY_SCANNED", "FAILED", "UNKNOWN"]:
            readiness_confidence = "LOW"
            unknown_factors.append(f"Discovery Coverage is incomplete ({coverage_status})")
        elif correlation_confidence == "LOW":
            readiness_confidence = "MEDIUM"

        score = min(100, score)

        category = "LOW"
        if score >= 80:
            category = "CRITICAL"
        elif score >= 60:
            category = "HIGH"
        elif score >= 40:
            category = "MEDIUM"
        elif score >= 20:
            category = "LOW"
        else:
            category = "NEGLIGIBLE"

        rationale = f"Migration Priority Score {score}/100 ({category}). " + "; ".join(known_factors)

        factor_breakdown = {
            "quantum_exposure": quantum_status.value if hasattr(quantum_status, 'value') else str(quantum_status),
            "cryptographic_purpose": purpose.value if hasattr(purpose, 'value') else str(purpose),
            "network_exposure": "INTERNET_EXPOSED" if is_internet_exposed is True else ("INTERNAL" if is_internet_exposed is False else None),
            "hndl_context": "HIGH_RELEVANCE" if hndl_relevance is True else ("NOT_RELEVANT" if hndl_relevance is False else None),
            "confidentiality_lifetime": confidentiality_lifetime,
            "business_criticality": business_criticality,
            "dependency_blast_radius": downstream_dependents_count,
            "migration_complexity": "MEDIUM",
            "discovery_coverage": coverage_status,
            "observation_confidence": "HIGH",
            "correlation_confidence": correlation_confidence
        }

        return {
            "priority_score": score,
            "category": category,
            "confidence": readiness_confidence,
            "known_factors": known_factors,
            "unknown_factors": unknown_factors,
            "factor_breakdown": factor_breakdown,
            "rationale": rationale
        }
