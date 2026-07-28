from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from app.models.entities import (
    CryptoFinding, NormalizedAlgorithm, Asset, Service, QuantumSafetyStatus, PrimitiveType, FindingPurpose
)
from app.risk.contextual_risk import ContextualRiskEngine, RiskContext, PurposeType

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

            # Build RiskContext
            purpose_enum = PurposeType.UNKNOWN
            if finding.purpose == FindingPurpose.DIGITAL_SIGNATURE or finding.purpose == FindingPurpose.AUTHENTICATION:
                purpose_enum = PurposeType.SIGNATURE
            elif finding.purpose == FindingPurpose.KEY_EXCHANGE:
                purpose_enum = PurposeType.KEY_ESTABLISHMENT
            elif finding.purpose == FindingPurpose.ENCRYPTION:
                purpose_enum = PurposeType.ENCRYPTION

            ctx = RiskContext(
                algorithm=raw_name,
                purpose=purpose_enum,
                protocol=service.application_protocol.value if service else "TLS",
                network_exposure="INTERNET" if asset and asset.ip_address and not asset.ip_address.startswith("10.") else "INTERNAL",
                asset_criticality="HIGH" if asset and asset.environment == "PRODUCTION" else "MEDIUM",
                data_classification="CONFIDENTIAL",
                regulatory_context="CNSA_2.0"
            )

            eval_res = ContextualRiskEngine.evaluate(ctx)
            
            severity_counts[eval_res.severity] += 1
            vulnerabilities.append({
                "finding_id": finding.id,
                "asset": asset.hostname if asset else "Unknown Host",
                "location": finding.location_identifier,
                "raw_algorithm": raw_name,
                "canonical_algorithm": norm.canonical_id if norm else raw_name,
                "quantum_status": status.value if hasattr(status, 'value') else str(status),
                "severity": eval_res.severity,
                "risk_score": eval_res.score,
                "cnsa_timeline": eval_res.cnsa_timeline,
                "flaw_description": eval_res.flaw_description,
                "mitigation_strategy": eval_res.mitigation_strategy,
                "recommended_pqc_replacement": eval_res.recommended_pqc_replacement,
                "contributing_factors": eval_res.contributing_factors,
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
        norm: Optional[NormalizedAlgorithm] = None
    ) -> Dict[str, str]:
        ctx = RiskContext(algorithm=raw_name)
        res = ContextualRiskEngine.evaluate(ctx)
        return {
            "severity": res.severity,
            "cnsa_timeline": res.cnsa_timeline,
            "flaw_description": res.flaw_description,
            "mitigation_strategy": res.mitigation_strategy,
            "recommended_pqc_replacement": res.recommended_pqc_replacement
        }
