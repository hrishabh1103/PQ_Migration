from datetime import datetime, timezone
from typing import List, Dict, Any
from sqlalchemy.orm import Session
from app.models.entities import (
    CryptoFinding, NormalizedAlgorithm, Asset, Service, QuantumSafetyStatus, PrimitiveType
)

class RiskAndRemediationEngine:
    """
    Risk Assessment & Mitigation Engine.
    Evaluates cryptographic findings against NIST PQC FIPS 203/204/205 standards
    and CNSA 2.0 timelines to generate actionable migration strategies.
    """

    @classmethod
    def generate_risk_report(cls, db: Session) -> Dict[str, Any]:
        findings = db.query(CryptoFinding).all()
        
        vulnerabilities = []
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        
        for finding in findings:
            norm = db.query(NormalizedAlgorithm).filter(
                NormalizedAlgorithm.canonical_id == finding.normalized_algorithm_id
            ).first()
            
            asset = db.query(Asset).filter(Asset.id == finding.asset_id).first()
            service = db.query(Service).filter(Service.id == finding.service_id).first() if finding.service_id else None

            status = norm.quantum_safety_status if norm else QuantumSafetyStatus.UNKNOWN
            raw_name = finding.raw_algorithm_name
            primitive = norm.primitive_type if norm else PrimitiveType.ASYMMETRIC_ENCRYPTION

            risk_info = cls._evaluate_flaw_and_mitigation(raw_name, status, primitive, norm)
            
            if risk_info:
                severity_counts[risk_info["severity"]] += 1
                vulnerabilities.append({
                    "finding_id": finding.id,
                    "asset": asset.hostname if asset else "Unknown Host",
                    "location": finding.location_identifier,
                    "raw_algorithm": raw_name,
                    "canonical_algorithm": norm.canonical_id if norm else raw_name,
                    "quantum_status": status.value if hasattr(status, 'value') else str(status),
                    "severity": risk_info["severity"],
                    "cnsa_timeline": risk_info["cnsa_timeline"],
                    "flaw_description": risk_info["flaw_description"],
                    "mitigation_strategy": risk_info["mitigation_strategy"],
                    "recommended_pqc_replacement": risk_info["recommended_pqc_replacement"],
                    "evidence_snippet": finding.evidence_snippet
                })

        return {
            "report_title": "Post-Quantum Cryptographic Risk & Remediation Assessment Report",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "total_findings": len(findings),
                "quantum_vulnerable_count": len(vulnerabilities),
                "severity_counts": severity_counts
            },
            "vulnerabilities": vulnerabilities
        }

    @classmethod
    def _evaluate_flaw_and_mitigation(
        cls,
        raw_name: str,
        status: QuantumSafetyStatus,
        primitive: PrimitiveType,
        norm: NormalizedAlgorithm
    ) -> Dict[str, str]:
        
        name_upper = raw_name.upper()

        if status == QuantumSafetyStatus.QUANTUM_VULNERABLE or "RSA" in name_upper or "ECDSA" in name_upper or "X25519" in name_upper or "ECDH" in name_upper:
            if "RSA-2048" in name_upper or "RSA" in name_upper:
                return {
                    "severity": "CRITICAL",
                    "cnsa_timeline": "Phase 1 Transition (Complete by 2030)",
                    "flaw_description": "RSA integer factorization algorithm is vulnerable to polynomial-time breaking via Shor's Algorithm on Cryptographically Relevant Quantum Computers (CRQCs).",
                    "mitigation_strategy": "Migrate key exchange to hybrid X25519+ML-KEM-768 or pure ML-KEM-768 (FIPS 203). For digital signatures, migrate to ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205).",
                    "recommended_pqc_replacement": "ML-KEM-768 (Key Exchange) / ML-DSA-65 (Signatures)"
                }
            elif "ECDSA" in name_upper or "P256" in name_upper or "P-256" in name_upper:
                return {
                    "severity": "CRITICAL",
                    "cnsa_timeline": "Phase 1 Transition (Complete by 2030)",
                    "flaw_description": "ECDSA elliptic curve discrete logarithm problem is completely broken by Shor's Algorithm on a CRQC.",
                    "mitigation_strategy": "Replace ECDSA signature schemes with ML-DSA-65 (FIPS 204) for general authentication or SLH-DSA (FIPS 205) for stateful hash-based signing.",
                    "recommended_pqc_replacement": "ML-DSA-65 (FIPS 204)"
                }
            elif "X25519" in name_upper or "ECDH" in name_upper:
                return {
                    "severity": "HIGH",
                    "cnsa_timeline": "Phase 1 Transition (Complete by 2030)",
                    "flaw_description": "Elliptic Curve Diffie-Hellman (X25519/ECDH) enables 'Harvest Now, Decrypt Later' (HNDL) attacks where adversaries record current ciphertexts to decrypt post-CRQC.",
                    "mitigation_strategy": "Deploy Hybrid Key Exchange (X25519 + ML-KEM-768) immediately for TLS 1.3 endpoints to protect against retroactive decryption of recorded sessions.",
                    "recommended_pqc_replacement": "Hybrid X25519 + ML-KEM-768 (Draft RFC)"
                }

        if status == QuantumSafetyStatus.DEPRECATED or "MD5" in name_upper or "SHA-1" in name_upper or "SHA1" in name_upper:
            return {
                "severity": "HIGH",
                "cnsa_timeline": "Immediate Remediation Required",
                "flaw_description": "Classical collision vulnerability. MD5 and SHA-1 are cryptographically broken under classical cryptanalysis.",
                "mitigation_strategy": "Replace MD5/SHA-1 hashing immediately with SHA-256, SHA-384, or SHA3-256.",
                "recommended_pqc_replacement": "SHA-384 (FIPS 180-4) / SHA3-256 (FIPS 202)"
            }

        if status == QuantumSafetyStatus.SYMMETRIC and "128" in name_upper:
            return {
                "severity": "MEDIUM",
                "cnsa_timeline": "Phase 2 Transition (Complete by 2033)",
                "flaw_description": "AES-128 key length is reduced to 64 effective security bits against Grover's quantum search algorithm.",
                "mitigation_strategy": "Upgrade symmetric cipher suite configuration from AES-128 to AES-256-GCM to maintain 128-bit post-quantum security.",
                "recommended_pqc_replacement": "AES-256-GCM (NIST SP 800-38D)"
            }

        if status == QuantumSafetyStatus.PQC_STANDARDIZED or status == QuantumSafetyStatus.PQC_CANDIDATE or status == QuantumSafetyStatus.HYBRID:
            return {
                "severity": "INFO",
                "cnsa_timeline": "Compliant / Quantum-Resistant",
                "flaw_description": "No immediate quantum flaw detected. Algorithm aligns with NIST PQC standard or hybrid implementation.",
                "mitigation_strategy": "Maintain monitoring; ensure software libraries stay updated as final FIPS implementations stabilize.",
                "recommended_pqc_replacement": "Already Quantum-Resistant"
            }

        return {
            "severity": "LOW",
            "cnsa_timeline": "Review Required",
            "flaw_description": "Algorithm requires verification against PQC migration standards.",
            "mitigation_strategy": "Review key size and usage purpose against NIST SP 800-56A/B recommendations.",
            "recommended_pqc_replacement": "ML-KEM-768 / ML-DSA-65"
        }
