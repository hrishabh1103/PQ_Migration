from fastapi import APIRouter, Depends, Response
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.risk.engine import RiskAndRemediationEngine

router = APIRouter()

@router.get("/reports/remediation")
def get_remediation_report(db: Session = Depends(get_db)):
    return RiskAndRemediationEngine.generate_risk_report(db)

@router.get("/reports/export/markdown")
def export_remediation_markdown(db: Session = Depends(get_db)):
    report_data = RiskAndRemediationEngine.generate_risk_report(db)
    summary = report_data["summary"]
    vulnerabilities = report_data["vulnerabilities"]

    md_lines = [
        "# Enterprise Post-Quantum Cryptographic Migration & Risk Assessment Report",
        "",
        f"**Generated Date:** {report_data['generated_at']}",
        "**Compliance Standards Evaluated:** NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA), CNSA 2.0",
        "",
        "---",
        "",
        "## 1. Executive Summary",
        "",
        f"- **Total Cryptographic Findings Analyzed:** {summary['total_findings']}",
        f"- **Quantum-Vulnerable / Flawed Primitives:** {summary['quantum_vulnerable_count']}",
        "",
        "### Risk Breakdown by Severity",
        f"- **Critical:** {summary['severity_counts']['CRITICAL']}",
        f"- **High:** {summary['severity_counts']['HIGH']}",
        f"- **Medium:** {summary['severity_counts']['MEDIUM']}",
        f"- **Low:** {summary['severity_counts']['LOW']}",
        f"- **Informational / Quantum-Safe:** {summary['severity_counts']['INFO']}",
        "",
        "---",
        "",
        "## 2. Detailed Cryptographic Flaws & Mitigation Strategies",
        ""
    ]

    if not vulnerabilities:
        md_lines.append("_No cryptographic flaws detected in current inventory._")
    else:
        for idx, v in enumerate(vulnerabilities, 1):
            md_lines.extend([
                f"### {idx}. {v['raw_algorithm']} on `{v['asset']}`",
                f"- **Location Identifier:** `{v['location']}`",
                f"- **Severity Rating:** `{v['severity']}`",
                f"- **CNSA 2.0 Timeline Category:** {v['cnsa_timeline']}",
                f"- **Quantum Safety Status:** `{v['quantum_status']}`",
                "",
                "#### Flaw Description",
                f"> {v['flaw_description']}",
                "",
                "#### Technical Mitigation Strategy",
                f"{v['mitigation_strategy']}",
                "",
                "#### Recommended PQC Replacement",
                f"**Target Standard:** `{v['recommended_pqc_replacement']}`",
                "",
                "#### Evidence Snippet",
                "```text",
                f"{v['evidence_snippet']}",
                "```",
                "",
                "---",
                ""
            ])

    md_content = "\n".join(md_lines)
    return Response(
        content=md_content,
        media_type="text/markdown",
        headers={
            "Content-Disposition": "attachment; filename=PQC_Cryptographic_Remediation_Report.md"
        }
    )
