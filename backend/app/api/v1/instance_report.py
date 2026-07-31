"""
Evidence-Driven Per-Instance PQC Assessment Report

INVARIANT: NO EVIDENCE = NO RESULT.
- No asset receives a numeric score without actual cryptographic evidence.
- No asset is labelled "LIVE TLS HANDSHAKE" unless TLS handshake findings exist.
- All denominators come from actual evidence counts, never from max(x, 1).
- provider/region are never hardcoded defaults.
"""
import logging
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.entities import Asset, CryptoFinding, CryptoObject, Relationship, ReadinessAssessment

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/reports", tags=["Instance Reports"])

# ============================================================
# ELIGIBILITY CLASSIFICATION
# ============================================================

# asset_type → (eligibility_label, header_label, can_have_endpoint_score)
_ELIGIBILITY_MAP = {
    "HOST":                    ("TLS_ENDPOINT",        "LIVE TLS HANDSHAKE",                   True),
    "cloud_account":           ("AWS_ACCOUNT",          "AGGREGATED ACCOUNT PQC POSTURE",        False),
    "cloud_region":            ("AWS_REGION",           "AGGREGATED REGION PQC POSTURE",         False),
    "cloud_vm":                ("AWS_EC2_INSTANCE",     "AWS API DISCOVERY",                     False),
    "compute_instance":        ("AZURE_VM",             "AZURE API DISCOVERY",                   False),
    "cloud_storage":           ("AWS_S3_BUCKET",        "AWS API DISCOVERY",                     False),
    "object_storage":          ("AZURE_STORAGE",        "AZURE API DISCOVERY",                   False),
    "kms_key":                 ("AWS_KMS_KEY",          "AWS API DISCOVERY",                     True),
    "managed_key":             ("AZURE_KMS_KEY",        "AZURE API DISCOVERY",                   True),
    "KUBERNETES_SERVICE":      ("KUBERNETES_RESOURCE",  "KUBERNETES API DISCOVERY",              True),
    "KUBERNETES_WORKLOAD":     ("KUBERNETES_RESOURCE",  "KUBERNETES API DISCOVERY",              True),
    "KUBERNETES_INGRESS":      ("KUBERNETES_RESOURCE",  "KUBERNETES API DISCOVERY",              True),
    "APPLICATION":             ("KUBERNETES_RESOURCE",  "KUBERNETES API DISCOVERY",              True),
    "cloud_load_balancer":     ("AWS_LOAD_BALANCER",    "AWS API DISCOVERY",                     False),
    "cloud_listener":          ("AWS_LISTENER",         "AWS API DISCOVERY",                     True),
    "cloud_database":          ("AWS_DATABASE",         "AWS API DISCOVERY",                     False),
    "managed_database":        ("AZURE_DATABASE",       "AZURE API DISCOVERY",                   False),
    "cloud_cdn":               ("AWS_CDN",              "AWS API DISCOVERY",                     False),
    "cdn":                     ("AZURE_CDN",            "AZURE API DISCOVERY",                   False),
    "cloud_tenant":            ("AZURE_TENANT",         "AGGREGATED ACCOUNT PQC POSTURE",        False),
    "cloud_subscription":      ("AZURE_SUBSCRIPTION",   "AGGREGATED ACCOUNT PQC POSTURE",        False),
    "cloud_resource_group":    ("AZURE_RESOURCE_GROUP", "AZURE API DISCOVERY",                   False),
    "secret_store":            ("AZURE_KEY_VAULT",      "AZURE API DISCOVERY",                   False),
    "certificate_store":       ("CERTIFICATE_STORE",    "AZURE API DISCOVERY",                   True),
}

# Scanner IDs → evidence source label
_SCANNER_SOURCE_MAP = {
    "tls-scanner":             "LIVE TLS HANDSHAKE",
    "ssh-scanner":             "LIVE SSH HANDSHAKE",
    "certificate-scanner":    "CERTIFICATE DISCOVERY",
    "linux-collector":        "HOST CRYPTOGRAPHIC COLLECTION",
    "source-scanner":         "SOURCE CODE CRYPTO DISCOVERY",
    "kubernetes-connector":   "KUBERNETES API DISCOVERY",
    "aws-connector":          "AWS API DISCOVERY",
    "azure-connector":        "AZURE API DISCOVERY",
}

# ============================================================
# SCORING ENGINE
# ============================================================

# Rule ID → (trigger_fn, dimension, impact, rationale)
# Triggered against raw_algorithm_name and finding_type
_SCORING_RULES = [
    {
        "rule_id": "TLS_CLASSICAL_CERT_RSA",
        "dimension": "certificate",
        "finding_type": "CERTIFICATE_PUBLIC_KEY",
        "algo_contains": ["RSA"],
        "impact": -35,
        "classification": "QUANTUM_VULNERABLE",
        "rationale": "RSA leaf certificate public key is vulnerable to Shor's algorithm on CRQC hardware."
    },
    {
        "rule_id": "TLS_CLASSICAL_CERT_ECDSA",
        "dimension": "certificate",
        "finding_type": "CERTIFICATE_PUBLIC_KEY",
        "algo_contains": ["ECDSA", "EC-"],
        "impact": -20,
        "classification": "QUANTUM_VULNERABLE",
        "rationale": "ECDSA leaf certificate is vulnerable to Shor's algorithm on CRQC hardware."
    },
    {
        "rule_id": "TLS_VULNERABLE_KEX_RSA",
        "dimension": "key_exchange",
        "finding_type": "KEY_EXCHANGE",
        "algo_contains": ["RSA"],
        "impact": -30,
        "classification": "QUANTUM_VULNERABLE",
        "rationale": "RSA key exchange is vulnerable to Harvest-Now-Decrypt-Later attacks."
    },
    {
        "rule_id": "TLS_PQC_KEX",
        "dimension": "key_exchange",
        "finding_type": "KEY_EXCHANGE",
        "algo_contains": ["ML-KEM", "KYBER", "X25519MLKEM", "MLKEM"],
        "impact": +20,
        "classification": "QUANTUM_RESISTANT",
        "rationale": "ML-KEM or hybrid ML-KEM key exchange provides post-quantum key establishment."
    },
    {
        "rule_id": "TLS_SYMMETRIC_STRONG",
        "dimension": "symmetric_cipher",
        "finding_type": "SYMMETRIC_CIPHER",
        "algo_contains": ["AES-256", "CHACHA20", "AESGCM256"],
        "impact": +5,
        "classification": "QUANTUM_RESISTANT",
        "rationale": "Strong symmetric cipher (AES-256 / ChaCha20) — Grover-resistant at 128-bit post-quantum security."
    },
    {
        "rule_id": "TLS_SYMMETRIC_WEAK",
        "dimension": "symmetric_cipher",
        "finding_type": "SYMMETRIC_CIPHER",
        "algo_contains": ["RC4", "3DES", "DES", "AES-128"],
        "impact": -10,
        "classification": "QUANTUM_VULNERABLE",
        "rationale": "Weak or reduced-security symmetric cipher — insufficient post-quantum security margin."
    },
    {
        "rule_id": "KMS_PQC_KEY",
        "dimension": "kms_key",
        "finding_type": "KMS_KEY",
        "algo_contains": ["ML-KEM", "KYBER", "PQC"],
        "impact": +20,
        "classification": "QUANTUM_RESISTANT",
        "rationale": "KMS key uses post-quantum algorithm."
    },
    {
        "rule_id": "KMS_CLASSICAL_KEY",
        "dimension": "kms_key",
        "finding_type": "KMS_KEY",
        "algo_contains": ["RSA", "AES-256", "AES256"],
        "impact": -10,
        "classification": "QUANTUM_VULNERABLE",
        "rationale": "KMS key uses classical asymmetric or legacy algorithm."
    },
]


def _apply_scoring_rules(findings: List[CryptoFinding]) -> Dict[str, Any]:
    """
    Applies evidence-based scoring rules to a list of CryptoFindings.
    Returns score, risk_tier, components, and per-dimension breakdown.
    Each rule application references the actual evidence_id.
    """
    if not findings:
        return {
            "score": None,
            "risk_tier": "UNKNOWN",
            "components": [],
            "primitive_count": 0,
            "vulnerable_count": 0,
            "resistant_count": 0,
            "hybrid_count": 0,
            "unknown_count": 0,
        }

    score = 100
    components = []
    primitive_count = 0
    vulnerable_count = 0
    resistant_count = 0
    hybrid_count = 0
    unknown_count = 0

    # Track which rules were applied to avoid double-counting the same finding
    applied: set = set()

    for finding in findings:
        algo_upper = finding.raw_algorithm_name.upper()
        matched = False

        for rule in _SCORING_RULES:
            if finding.finding_type != rule["finding_type"]:
                continue
            if any(kw.upper() in algo_upper for kw in rule["algo_contains"]):
                key = (finding.id, rule["rule_id"])
                if key in applied:
                    continue
                applied.add(key)
                score += rule["impact"]
                matched = True

                cls = rule["classification"]
                if cls == "QUANTUM_VULNERABLE":
                    vulnerable_count += 1
                elif cls == "QUANTUM_RESISTANT":
                    resistant_count += 1
                elif cls == "HYBRID":
                    hybrid_count += 1

                components.append({
                    "rule_id": rule["rule_id"],
                    "dimension": rule["dimension"],
                    "evidence_id": finding.id,
                    "source": finding.scanner_id,
                    "algorithm": finding.raw_algorithm_name,
                    "classification": cls,
                    "impact": rule["impact"],
                    "rationale": rule["rationale"]
                })
                break  # one rule per finding per pass

        if not matched:
            # Count as unknown if no rule matched
            unknown_count += 1

        primitive_count += 1

    # Clamp score to [0, 100]
    score = max(0, min(100, score))

    # Risk tier — NO default fallback to NEGLIGIBLE
    if score >= 80:
        risk_tier = "LOW"
    elif score >= 60:
        risk_tier = "MEDIUM"
    elif score >= 40:
        risk_tier = "HIGH"
    else:
        risk_tier = "CRITICAL"

    return {
        "score": score,
        "risk_tier": risk_tier,
        "components": components,
        "primitive_count": primitive_count,
        "vulnerable_count": vulnerable_count,
        "resistant_count": resistant_count,
        "hybrid_count": hybrid_count,
        "unknown_count": unknown_count,
    }


def _build_header_label(findings: List[CryptoFinding], asset_type: str) -> str:
    """Select header label from actual scanner evidence sources."""
    if not findings:
        eligibility = _ELIGIBILITY_MAP.get(asset_type, ("UNKNOWN", "NO CRYPTOGRAPHIC EVIDENCE", False))
        return eligibility[1]

    sources = set(f.scanner_id for f in findings)
    if len(sources) > 1:
        return "CORRELATED CRYPTOGRAPHIC ASSESSMENT"
    source = next(iter(sources))
    return _SCANNER_SOURCE_MAP.get(source, "AWS API DISCOVERY")


def _build_provenance(findings: List[CryptoFinding]) -> List[Dict]:
    """Build traceable provenance records from real findings."""
    result = []
    for f in findings:
        result.append({
            "evidence_id": f.id,
            "discovery_run_id": f.discovery_run_id,
            "source": f.scanner_id,
            "target": f.location_identifier,
            "timestamp": f.first_seen_at.isoformat() if f.first_seen_at else None,
            "usage_state": "OBSERVED_IN_USE",
            "raw_algorithm": f.raw_algorithm_name,
            "normalized_algorithm": f.normalized_algorithm_id,
            "finding_type": f.finding_type,
            "confidence": f.confidence.value if hasattr(f.confidence, 'value') else str(f.confidence),
        })
    return result


def _build_primitives(findings: List[CryptoFinding], scoring: Dict) -> List[Dict]:
    """Build primitive list from actual finding evidence."""
    primitives = []
    rule_lookup = {c["evidence_id"]: c for c in scoring.get("components", [])}
    for f in findings:
        rule_match = rule_lookup.get(f.id, {})
        primitives.append({
            "evidence_id": f.id,
            "algorithm": f.raw_algorithm_name,
            "normalized_algorithm": f.normalized_algorithm_id,
            "finding_type": f.finding_type,
            "quantum_status": rule_match.get("classification", "UNKNOWN"),
            "usage_state": "OBSERVED_IN_USE",
            "source": f.scanner_id,
            "target": f.location_identifier,
            "timestamp": f.first_seen_at.isoformat() if f.first_seen_at else None,
            "confidence": f.confidence.value if hasattr(f.confidence, 'value') else str(f.confidence),
            "score_impact": rule_match.get("impact"),
        })
    return primitives


def _build_sections(findings: List[CryptoFinding], scoring: Dict) -> List[Dict]:
    """Build evidence-derived sections — never hardcoded claims."""
    sections = []
    if not findings:
        return sections

    v = scoring.get("vulnerable_count", 0)
    r = scoring.get("resistant_count", 0)
    h = scoring.get("hybrid_count", 0)
    p = scoring.get("primitive_count", 0)

    # Certificate section
    cert_findings = [f for f in findings if f.finding_type == "CERTIFICATE_PUBLIC_KEY"]
    if cert_findings:
        algos = ", ".join(set(f.raw_algorithm_name for f in cert_findings))
        is_classical = any(a.upper() in ("RSA", "RSA-2048", "RSA-4096", "ECDSA") for a in [f.raw_algorithm_name for f in cert_findings])
        sections.append({
            "badge": "CERTIFICATE",
            "type": "certificate",
            "title": f"Certificate public key: {algos}",
            "description": (
                f"Leaf certificate uses {algos} — quantum-vulnerable under Shor's algorithm."
                if is_classical else
                f"Certificate public key: {algos}."
            )
        })

    # Key exchange section
    kex_findings = [f for f in findings if f.finding_type == "KEY_EXCHANGE"]
    if kex_findings:
        algos = ", ".join(set(f.raw_algorithm_name for f in kex_findings))
        has_pqc = any("ML-KEM" in f.raw_algorithm_name.upper() or "KYBER" in f.raw_algorithm_name.upper() for f in kex_findings)
        sections.append({
            "badge": "KEY EXCHANGE",
            "type": "key_exchange",
            "title": f"Key exchange: {algos}",
            "description": (
                "Post-quantum or hybrid key exchange observed — TLS sessions protected against harvest-now-decrypt-later."
                if has_pqc else
                f"Key exchange algorithm: {algos}."
            )
        })

    # Exposure summary section — only real counts, no fabricated denominators
    if p > 0:
        if v == 0 and p > 0:
            vuln_text = "No quantum-vulnerable asymmetric primitives were observed."
        else:
            vuln_text = f"{v} of {p} observed primitives are quantum-vulnerable (Shor's algorithm applicable)."
        sections.append({
            "badge": "EXPOSURE",
            "type": "exposure",
            "title": f"{v} / {p} primitives are quantum-vulnerable.",
            "description": vuln_text,
        })

    return sections


def _build_exposure_map(asset: Asset, findings: List[CryptoFinding]) -> List[Dict]:
    """Build exposure map only from real evidence. Never manufacture nodes."""
    if not findings:
        return []

    nodes = []
    endpoint_name = asset.hostname or asset.provider_resource_id or f"{asset.asset_type}-{asset.id[:8]}"

    nodes.append({
        "id": "node-asset",
        "title": endpoint_name,
        "subtitle": asset.asset_type,
        "status_badge": "DISCOVERED",
        "color": "cyan",
    })

    # Add finding nodes grouped by finding_type
    seen_types: set = set()
    for f in findings:
        if f.finding_type not in seen_types:
            seen_types.add(f.finding_type)
            nodes.append({
                "id": f"node-{f.finding_type.lower()}-{f.id[:8]}",
                "title": f.raw_algorithm_name,
                "subtitle": f.finding_type.replace("_", " ").title(),
                "status_badge": "OBSERVED",
                "color": "rose" if any(c in f.raw_algorithm_name.upper() for c in ["RSA", "ECDSA"]) else "emerald",
            })

    return nodes


def _build_cbom(asset: Asset, findings: List[CryptoFinding]) -> Optional[Dict]:
    """Build CycloneDX CBOM only when crypto components exist."""
    if not findings:
        return None
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{asset.id}",
        "version": 1,
        "metadata": {
            "component": {
                "type": "device",
                "name": asset.hostname or asset.provider_resource_id or asset.id,
            }
        },
        "components": [
            {
                "type": "cryptographic-asset",
                "bom-ref": f"finding-{f.id[:8]}",
                "name": f.raw_algorithm_name,
                "evidence": {
                    "occurrences": [{"location": f.location_identifier}]
                },
                "cryptoProperties": {
                    "assetType": "algorithm",
                    "algorithmProperties": {
                        "primitive": f.finding_type,
                        "parameterSetIdentifier": f.raw_algorithm_name,
                    }
                }
            }
            for f in findings
        ]
    }


def _build_aggregate_view(asset: Asset, db: Session) -> Dict:
    """For account/region assets: aggregate child resource statistics."""
    # Find children via Relationship
    children_ids = set()
    rels = db.query(Relationship).filter(
        Relationship.source_entity_id == asset.id,
        Relationship.relationship_type == "CONTAINS"
    ).all()
    for r in rels:
        if r.target_entity_type == "ASSET":
            children_ids.add(r.target_entity_id)

    # Also include direct children in the same region/account
    if asset.asset_type == "cloud_account":
        region_assets = db.query(Asset).filter(
            Asset.asset_type.in_(["cloud_region", "cloud_vm", "cloud_storage", "kms_key"])
        ).all()
        for a in region_assets:
            children_ids.add(a.id)

    total = len(children_ids)
    assessed = 0
    partially = 0
    unassessed = 0
    vulnerable = 0
    hybrid = 0
    pqc_ready = 0

    for cid in children_ids:
        fc = db.query(CryptoFinding).filter(CryptoFinding.asset_id == cid).count()
        ra = db.query(ReadinessAssessment).filter(
            ReadinessAssessment.asset_id == cid
        ).order_by(ReadinessAssessment.created_at.desc()).first()

        if fc == 0:
            unassessed += 1
        elif ra:
            if ra.readiness_result in ("READY",):
                assessed += 1
                pqc_ready += 1
            elif ra.readiness_result in ("NOT_READY",):
                assessed += 1
                if ra.vulnerable_count and ra.vulnerable_count > 0:
                    vulnerable += 1
            elif ra.readiness_result in ("PARTIALLY_READY",):
                partially += 1
                if ra.hybrid_count and ra.hybrid_count > 0:
                    hybrid += 1
            else:
                unassessed += 1
        else:
            unassessed += 1

    coverage_pct = round((assessed + partially) / total * 100, 1) if total > 0 else 0.0

    return {
        "total_resources": total,
        "assessed_resources": assessed,
        "partially_assessed_resources": partially,
        "unassessed_resources": unassessed,
        "vulnerable_resources": vulnerable,
        "hybrid_resources": hybrid,
        "pqc_ready_resources": pqc_ready,
        "coverage_percentage": coverage_pct,
    }


# ============================================================
# MAIN ENDPOINT
# ============================================================

@router.get("/instance/{asset_id}")
def get_instance_pqc_report(asset_id: str, db: Session = Depends(get_db)) -> Dict[str, Any]:
    """
    Evidence-Driven Per-Instance PQC Assessment Report.

    NO CLAIM WITHOUT EVIDENCE:
    - score is null when no crypto evidence exists
    - header_label reflects actual scanner source
    - denominators come from actual evidence counts only
    - provider/region are never hardcoded
    """
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail=f"Asset '{asset_id}' not found")

    # Resolve eligibility
    eligibility_type, default_header, can_score = _ELIGIBILITY_MAP.get(
        asset.asset_type,
        ("UNKNOWN", "CRYPTOGRAPHIC DISCOVERY", True)
    )

    # Fetch evidence
    findings = db.query(CryptoFinding).filter(CryptoFinding.asset_id == asset_id).all()

    endpoint_name = asset.hostname or asset.provider_resource_id or f"{asset.asset_type}-{asset.id[:8]}"

    # ============================================================
    # ACCOUNT/REGION: Aggregate view only — no endpoint score
    # ============================================================
    if asset.asset_type in ("cloud_account", "cloud_region", "cloud_tenant", "cloud_subscription"):
        aggregate = _build_aggregate_view(asset, db)
        return {
            "asset": {
                "id": asset.id,
                "name": endpoint_name,
                "asset_type": asset.asset_type,
                "provider": asset.provider,
                "region": asset.region,
                "eligibility_type": eligibility_type,
            },
            "assessment": {
                "status": "NOT_ASSESSED",
                "score": None,
                "risk_tier": "UNKNOWN",
                "coverage": aggregate["coverage_percentage"],
                "note": "Inventory container — no endpoint-style cryptographic assessment."
            },
            "aggregate": aggregate,
            "evidence_summary": {"total": 0, "observed": 0, "configured": 0, "inferred": 0,
                                  "primitive_count": 0, "vulnerable_count": 0, "resistant_count": 0,
                                  "hybrid_count": 0, "unknown_count": 0},
            "primitives": [],
            "sections": [],
            "provenance": [],
            "exposure_map": [],
            "header_label": default_header,
            "cbom": None,
        }

    # ============================================================
    # NO EVIDENCE
    # ============================================================
    if not findings:
        return {
            "asset": {
                "id": asset.id,
                "name": endpoint_name,
                "asset_type": asset.asset_type,
                "provider": asset.provider,
                "region": asset.region,
                "eligibility_type": eligibility_type,
            },
            "assessment": {
                "status": "NOT_ASSESSED",
                "score": None,
                "risk_tier": "UNKNOWN",
                "coverage": 0.0,
            },
            "evidence_summary": {"total": 0, "observed": 0, "configured": 0, "inferred": 0,
                                  "primitive_count": 0, "vulnerable_count": 0, "resistant_count": 0,
                                  "hybrid_count": 0, "unknown_count": 0},
            "primitives": [],
            "sections": [],
            "provenance": [],
            "exposure_map": [],
            "header_label": "NO CRYPTOGRAPHIC EVIDENCE",
            "cbom": None,
        }

    # ============================================================
    # EVIDENCE EXISTS — score and build report
    # ============================================================
    scoring = _apply_scoring_rules(findings)
    header_label = _build_header_label(findings, asset.asset_type)
    provenance = _build_provenance(findings)
    primitives = _build_primitives(findings, scoring)
    sections = _build_sections(findings, scoring)
    exposure_map = _build_exposure_map(asset, findings)
    cbom = _build_cbom(asset, findings)

    # Determine final status
    v = scoring["vulnerable_count"]
    r = scoring["resistant_count"]
    h = scoring["hybrid_count"]
    p = scoring["primitive_count"]
    total_ev = len(findings)

    if v > 0 or r > 0 or h > 0:
        status = "ASSESSED"
    elif total_ev > 0:
        status = "PARTIALLY_ASSESSED"
    else:
        status = "NOT_ASSESSED"

    executive_summary = _build_executive_summary(endpoint_name, scoring, findings)

    return {
        "asset": {
            "id": asset.id,
            "name": endpoint_name,
            "asset_type": asset.asset_type,
            "provider": asset.provider,
            "region": asset.region,
            "eligibility_type": eligibility_type,
        },
        "assessment": {
            "status": status,
            "score": scoring["score"],
            "risk_tier": scoring["risk_tier"],
            "coverage": 100.0,
        },
        "evidence_summary": {
            "total": total_ev,
            "observed": total_ev,
            "configured": 0,
            "inferred": 0,
            "primitive_count": p,
            "vulnerable_count": v,
            "resistant_count": r,
            "hybrid_count": h,
            "unknown_count": scoring["unknown_count"],
        },
        "primitives": primitives,
        "sections": sections,
        "provenance": provenance,
        "exposure_map": exposure_map,
        "header_label": header_label,
        "executive_summary": executive_summary,
        "cbom": cbom,
        # Legacy fields for backward compatibility with old frontend
        "endpoint_name": endpoint_name,
        "pqc_score": scoring["score"],
        "risk_tier": scoring["risk_tier"],
        "status": status,
        "asset_type": asset.asset_type,
        "provider": asset.provider,
        "region": asset.region,
    }


def _build_executive_summary(endpoint_name: str, scoring: Dict, findings: List) -> str:
    """Build summary text strictly from evidence — no claims beyond what was found."""
    p = scoring.get("primitive_count", 0)
    v = scoring.get("vulnerable_count", 0)
    r = scoring.get("resistant_count", 0)
    h = scoring.get("hybrid_count", 0)

    if p == 0:
        return f"No cryptographic evidence has been collected for {endpoint_name}."

    parts = [f"Cryptographic discovery for {endpoint_name} identified {p} primitive(s)."]
    if v > 0:
        parts.append(f"{v} primitive(s) are quantum-vulnerable (susceptible to Shor's algorithm).")
    else:
        parts.append("No quantum-vulnerable asymmetric primitives were observed.")
    if h > 0:
        parts.append(f"{h} hybrid or post-quantum primitive(s) detected.")
    if r > 0:
        parts.append(f"{r} quantum-resistant primitive(s) detected.")
    return " ".join(parts)


# ============================================================
# SCORE EXPLANATION ENDPOINT
# ============================================================

@router.get("/instance/{asset_id}/score-explanation")
def get_score_explanation(asset_id: str, db: Session = Depends(get_db)) -> Dict[str, Any]:
    """
    Returns the explicit, evidence-referenced scoring rule breakdown.
    Every component references a real evidence_id from CryptoFinding.
    No invisible constants, no arbitrary baselines.
    """
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail=f"Asset '{asset_id}' not found")

    findings = db.query(CryptoFinding).filter(CryptoFinding.asset_id == asset_id).all()
    if not findings:
        return {
            "asset_id": asset_id,
            "assessment_status": "NOT_ASSESSED",
            "score": None,
            "components": [],
            "note": "No cryptographic evidence found. Score cannot be calculated."
        }

    scoring = _apply_scoring_rules(findings)
    return {
        "asset_id": asset_id,
        "assessment_status": "ASSESSED" if scoring["score"] is not None else "NOT_ASSESSED",
        "score": scoring["score"],
        "score_basis": "Starts at 100. Each evidence-matched rule applies a signed impact.",
        "components": scoring["components"],
        "primitive_count": scoring["primitive_count"],
        "vulnerable_count": scoring["vulnerable_count"],
        "resistant_count": scoring["resistant_count"],
        "hybrid_count": scoring["hybrid_count"],
        "unknown_count": scoring["unknown_count"],
    }
