import logging
from enum import Enum
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

class PurposeType(str, Enum):
    SIGNATURE = "SIGNATURE"
    KEY_ESTABLISHMENT = "KEY_ESTABLISHMENT"
    KEY_TRANSPORT = "KEY_TRANSPORT"
    ENCRYPTION = "ENCRYPTION"
    AUTHENTICATION = "AUTHENTICATION"
    HASHING = "HASHING"
    KDF = "KDF"
    UNKNOWN = "UNKNOWN"

class RiskContext(BaseModel):
    algorithm: str
    purpose: PurposeType = PurposeType.UNKNOWN
    protocol: Optional[str] = None
    network_exposure: Optional[str] = None # INTERNET, INTERNAL, ISOLATED, UNKNOWN
    asset_criticality: Optional[str] = None # HIGH, MEDIUM, LOW, UNKNOWN
    data_classification: Optional[str] = None # RESTRICTED, CONFIDENTIAL, PUBLIC, UNKNOWN
    confidentiality_lifetime: Optional[str] = None # >10_YEARS, 5-10_YEARS, <5_YEARS, UNKNOWN
    regulatory_context: Optional[str] = None # CNSA_2.0, FIPS_203_204_205, PCI_DSS, GENERAL, UNKNOWN
    migration_deadline: Optional[str] = None
    migration_complexity: Optional[str] = None

class ContextualRiskEvaluation(BaseModel):
    severity: str # CRITICAL, HIGH, MEDIUM, LOW, INFO
    score: float # 0.0 to 10.0
    confidence: str # HIGH, MEDIUM, LOW
    cnsa_timeline: str
    flaw_description: str
    mitigation_strategy: str
    recommended_pqc_replacement: str
    known_factors: List[str]
    unknown_factors: List[str]
    rationale: str

    @property
    def contributing_factors(self) -> List[str]:
        return self.known_factors

class ContextualRiskEngine:
    """
    Evaluates cryptographic findings using rich contextual factors (purpose, network exposure,
    data confidentiality lifetime, asset criticality, regulatory context) and provides rationales.
    Missing context reduces confidence score rather than artificially inflating risk severity.
    """

    @classmethod
    def evaluate(cls, ctx: RiskContext) -> ContextualRiskEvaluation:
        algo_upper = ctx.algorithm.upper()
        known_factors: List[str] = []
        unknown_factors: List[str] = []
        
        base_score = 0.0
        severity = "LOW"
        timeline = "Review Required"
        flaw = "Algorithm requires contextual risk assessment."
        mitigation = "Review cryptographic parameters against NIST SP 800-56A/B recommendations."
        replacement = "ML-KEM-768 / ML-DSA-65"

        # Track contextual knowledge ratio for confidence
        total_context_fields = 4
        known_count = 0

        # 1. Evaluate Pure Cryptographic Properties
        is_rsa = "RSA" in algo_upper
        is_ecdsa = "ECDSA" in algo_upper or "P256" in algo_upper or "P-256" in algo_upper or "SECP256" in algo_upper
        is_ecdh = "ECDH" in algo_upper or "X25519" in algo_upper
        is_hash_legacy = "MD5" in algo_upper or "SHA-1" in algo_upper or "SHA1" in algo_upper
        is_aes_128 = "AES" in algo_upper and ("128" in algo_upper or "AES128" in algo_upper)

        if is_rsa or is_ecdsa or is_ecdh:
            base_score = 8.5
            known_factors.append(f"Algorithm '{ctx.algorithm}' is vulnerable to Shor's polynomial-time quantum algorithm.")

            # Distinguish Purpose carefully
            if ctx.purpose in [PurposeType.SIGNATURE, PurposeType.AUTHENTICATION]:
                flaw = f"{ctx.algorithm} signature scheme can be forged by a CRQC breaking private key mathematical structure."
                replacement = "ML-DSA-65 (NIST FIPS 204) / SLH-DSA (NIST FIPS 205)"
                mitigation = "Re-issue certificates and code signatures using ML-DSA-65 (FIPS 204) digital signature standard."
                known_factors.append("Purpose is SIGNATURE/AUTHENTICATION: Recommended replacement is ML-DSA-65 or SLH-DSA (FIPS 204/205).")
            elif ctx.purpose in [PurposeType.KEY_ESTABLISHMENT, PurposeType.KEY_TRANSPORT, PurposeType.ENCRYPTION]:
                flaw = f"{ctx.algorithm} key establishment enables Harvest Now, Decrypt Later (HNDL) adversary attacks."
                replacement = "ML-KEM-768 (NIST FIPS 203) / Hybrid X25519+ML-KEM-768"
                mitigation = "Upgrade key exchange protocol to hybrid X25519+ML-KEM-768 or pure ML-KEM-768 (FIPS 203)."
                known_factors.append("Purpose is KEY_ESTABLISHMENT: Recommended replacement is ML-KEM-768 (FIPS 203).")
            else:
                unknown_factors.append("Purpose is UNKNOWN: Assessed general asymmetric quantum vulnerability.")
                if is_rsa:
                    replacement = "ML-KEM-768 (Key Exchange) / ML-DSA-65 (Signatures)"
                    mitigation = "For key exchange use ML-KEM-768; for signatures migrate to ML-DSA-65."
                elif is_ecdsa:
                    replacement = "ML-DSA-65 (NIST FIPS 204)"
                    mitigation = "Migrate digital signature scheme to ML-DSA-65."
                else:
                    replacement = "Hybrid X25519 + ML-KEM-768"
                    mitigation = "Enable hybrid post-quantum key exchange."

            timeline = "Phase 1 Transition (Complete by 2030)"

        elif is_hash_legacy:
            base_score = 7.0
            flaw = "MD5/SHA-1 exhibit classical collision vulnerabilities."
            mitigation = "Replace MD5/SHA-1 with SHA-384 (FIPS 180-4) or SHA3-256 (FIPS 202)."
            replacement = "SHA-384 / SHA3-256"
            timeline = "Immediate Remediation Required"
            known_factors.append("Hash algorithm exhibits classical collision weakness under differential cryptanalysis.")

        elif is_aes_128:
            base_score = 4.0
            flaw = "AES-128 effective security is reduced to 64 bits against Grover's quantum search."
            mitigation = "Upgrade symmetric cipher key length from 128 bits to AES-256-GCM."
            replacement = "AES-256-GCM (NIST SP 800-38D)"
            timeline = "Phase 2 Transition (Complete by 2033)"
            known_factors.append("Symmetric key length < 256 bits offers reduced quantum security against Grover search.")

        else:
            base_score = 1.0
            flaw = "No critical quantum vulnerability detected."
            mitigation = "Maintain monitoring and ensure software libraries remain updated."
            replacement = "Quantum-Resistant"
            timeline = "Compliant"
            known_factors.append("Algorithm aligns with standard symmetric or PQC candidate taxonomies.")

        # 2. Contextual Weightings & Unknown Tracking
        if ctx.network_exposure in ["INTERNET", "EXTERNAL"]:
            base_score += 1.0
            known_count += 1
            known_factors.append("Network Exposure is INTERNET (+1.0 Weight).")
        elif ctx.network_exposure in ["INTERNAL", "ISOLATED"]:
            known_count += 1
            known_factors.append(f"Network Exposure is {ctx.network_exposure}.")
        else:
            unknown_factors.append("Network Exposure is UNKNOWN.")

        if ctx.data_classification in ["RESTRICTED", "CONFIDENTIAL"]:
            base_score += 0.5
            known_count += 1
            known_factors.append(f"Data Classification is {ctx.data_classification} (+0.5 Weight).")
        elif ctx.data_classification == "PUBLIC":
            known_count += 1
            known_factors.append("Data Classification is PUBLIC.")
        else:
            unknown_factors.append("Data Classification is UNKNOWN.")

        if ctx.asset_criticality == "HIGH":
            base_score += 0.5
            known_count += 1
            known_factors.append("Asset Criticality is HIGH (+0.5 Weight).")
        elif ctx.asset_criticality in ["MEDIUM", "LOW"]:
            known_count += 1
            known_factors.append(f"Asset Criticality is {ctx.asset_criticality}.")
        else:
            unknown_factors.append("Asset Criticality is UNKNOWN.")

        if ctx.regulatory_context:
            known_count += 1
            known_factors.append(f"Regulatory Context is {ctx.regulatory_context}.")
        else:
            unknown_factors.append("Regulatory Context is UNKNOWN.")

        # Compute confidence based on proportion of known contextual factors
        if known_count >= 3:
            confidence = "HIGH"
        elif known_count >= 1:
            confidence = "MEDIUM"
        else:
            confidence = "LOW"

        final_score = round(min(max(base_score, 0.0), 10.0), 1)

        if final_score >= 8.5:
            severity = "CRITICAL"
        elif final_score >= 6.5:
            severity = "HIGH"
        elif final_score >= 4.0:
            severity = "MEDIUM"
        elif final_score >= 2.0:
            severity = "LOW"
        else:
            severity = "INFO"

        rationale = f"Evaluated '{ctx.algorithm}' with {confidence} confidence based on {len(known_factors)} known factor(s) and {len(unknown_factors)} unknown factor(s)."

        return ContextualRiskEvaluation(
            severity=severity,
            score=final_score,
            confidence=confidence,
            cnsa_timeline=timeline,
            flaw_description=flaw,
            mitigation_strategy=mitigation,
            recommended_pqc_replacement=replacement,
            known_factors=known_factors,
            unknown_factors=unknown_factors,
            rationale=rationale
        )
