"""
Evidence-Driven Per-Instance PQC Assessment Report

INVARIANTS:
1. NO EVIDENCE = NO RESULT:
   - No asset receives a numeric score without actual cryptographic evidence.
   - No fallback, default, or synthetic scores are ever introduced.
   - Every score is strictly traceable to underlying CryptoFinding records.
2. CANONICAL ASSET IDENTIFIERS:
   - All reports operate on canonical Asset.id.
3. EXPLICIT ASSESSMENT SCOPE:
   - INSTANCE: Per-instance cryptographic assessment and score.
   - AGGREGATE: Container asset (Tenant, Subscription, Account, Project, Region) with child inventory statistics only (score = None).
   - NOT_ELIGIBLE: Non-cryptographic infrastructure (Network, Subnet) with eligibility note (score = None).
4. CONTEXTUAL SCORING & DEDUPLICATION:
   - Evaluates finding_type, scanner source, asset_type, and raw_algorithm_name.
   - Identical cryptographic objects observed across multiple scanners are deduplicated for scoring (impact applied once), while preserving all provenance sources.
5. AWS CONNECTOR PROTECTED:
   - AWS finding sources are normalized cleanly in provenance, without altering AWS connector code.
"""
import logging
from typing import Dict, Any, List, Optional, Tuple
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.entities import Asset, CryptoFinding, Relationship, ReadinessAssessment

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/reports", tags=["Instance Reports"])

# ============================================================
# ELIGIBILITY CLASSIFICATION & ASSESSMENT SCOPE
# asset_type → (eligibility_label, header_label, assessment_scope, can_have_endpoint_score)
# ============================================================
_ELIGIBILITY_MAP: Dict[str, Tuple[str, str, str, bool]] = {
    # Instance Assets
    "HOST":                    ("HOST_SERVER",         "LIVE TLS HANDSHAKE",                   "INSTANCE",     True),
    "SERVER":                  ("HOST_SERVER",         "HOST CRYPTOGRAPHIC COLLECTION",        "INSTANCE",     True),
    "APPLICATION":             ("APPLICATION",         "APPLICATION CRYPTOGRAPHIC DISCOVERY",  "INSTANCE",     True),
    "SOURCE_REPOSITORY":       ("SOURCE_REPOSITORY",   "SOURCE CODE CRYPTO DISCOVERY",         "INSTANCE",     True),
    "CONTAINER":               ("CONTAINER",           "CONTAINER CRYPTOGRAPHIC DISCOVERY",    "INSTANCE",     True),
    "CLOUD_VM":                ("CLOUD_COMPUTE",       "CLOUD COMPUTE DISCOVERY",              "INSTANCE",     True),
    "CLOUD_INSTANCE":          ("CLOUD_COMPUTE",       "CLOUD COMPUTE DISCOVERY",              "INSTANCE",     True),
    "COMPUTE_INSTANCE":        ("CLOUD_COMPUTE",       "AZURE COMPUTE DISCOVERY",              "INSTANCE",     True),
    "cloud_vm":                ("CLOUD_COMPUTE",       "AWS COMPUTE DISCOVERY",                "INSTANCE",     True),
    "BLOCK_STORAGE":           ("STORAGE_RESOURCE",    "BLOCK STORAGE DISCOVERY",              "INSTANCE",     True),
    "OBJECT_STORAGE":          ("STORAGE_RESOURCE",    "OBJECT STORAGE DISCOVERY",             "INSTANCE",     True),
    "cloud_storage":           ("STORAGE_RESOURCE",    "AWS STORAGE DISCOVERY",                "INSTANCE",     True),
    "object_storage":          ("STORAGE_RESOURCE",    "AZURE STORAGE DISCOVERY",              "INSTANCE",     True),
    "KMS_KEY":                 ("MANAGED_KEY",         "KMS KEY DISCOVERY",                    "INSTANCE",     True),
    "MANAGED_KEY":             ("MANAGED_KEY",         "MANAGED KEY DISCOVERY",                "INSTANCE",     True),
    "kms_key":                 ("MANAGED_KEY",         "AWS KMS DISCOVERY",                    "INSTANCE",     True),
    "managed_key":             ("MANAGED_KEY",         "AZURE KEY VAULT DISCOVERY",            "INSTANCE",     True),
    "MANAGED_DATABASE":        ("MANAGED_DATABASE",    "MANAGED DATABASE DISCOVERY",           "INSTANCE",     True),
    "cloud_database":          ("MANAGED_DATABASE",    "AWS DATABASE DISCOVERY",               "INSTANCE",     True),
    "managed_database":        ("MANAGED_DATABASE",    "AZURE DATABASE DISCOVERY",             "INSTANCE",     True),
    "LOAD_BALANCER":           ("NETWORK_ENDPOINT",    "LOAD BALANCER DISCOVERY",              "INSTANCE",     True),
    "CLOUD_LOAD_BALANCER":     ("NETWORK_ENDPOINT",    "CLOUD LOAD BALANCER DISCOVERY",        "INSTANCE",     True),
    "cloud_load_balancer":     ("NETWORK_ENDPOINT",    "AWS LOAD BALANCER DISCOVERY",          "INSTANCE",     True),
    "cloud_listener":          ("NETWORK_ENDPOINT",    "AWS LISTENER DISCOVERY",               "INSTANCE",     True),
    "TLS_TERMINATOR":          ("NETWORK_ENDPOINT",    "TLS TERMINATOR DISCOVERY",             "INSTANCE",     True),
    "CDN":                     ("NETWORK_ENDPOINT",    "CDN DISCOVERY",                        "INSTANCE",     True),
    "cloud_cdn":               ("NETWORK_ENDPOINT",    "AWS CDN DISCOVERY",                    "INSTANCE",     True),
    "cdn":                     ("NETWORK_ENDPOINT",    "AZURE CDN DISCOVERY",                  "INSTANCE",     True),
    "SECRET_STORE":            ("SECRET_STORE",        "SECRET STORE DISCOVERY",               "INSTANCE",     True),
    "secret_store":            ("SECRET_STORE",        "AZURE KEY VAULT DISCOVERY",            "INSTANCE",     True),
    "CERTIFICATE_STORE":       ("CERTIFICATE_STORE",   "CERTIFICATE STORE DISCOVERY",          "INSTANCE",     True),
    "certificate_store":       ("CERTIFICATE_STORE",   "AZURE CERTIFICATE DISCOVERY",          "INSTANCE",     True),
    "KUBERNETES_WORKLOAD":     ("KUBERNETES_RESOURCE", "KUBERNETES WORKLOAD DISCOVERY",        "INSTANCE",     True),
    "KUBERNETES_POD":          ("KUBERNETES_RESOURCE", "KUBERNETES POD DISCOVERY",             "INSTANCE",     True),
    "KUBERNETES_SERVICE":      ("KUBERNETES_RESOURCE", "KUBERNETES SERVICE DISCOVERY",         "INSTANCE",     True),
    "KUBERNETES_INGRESS":      ("KUBERNETES_RESOURCE", "KUBERNETES INGRESS DISCOVERY",         "INSTANCE",     True),
    "KUBERNETES_CLUSTER":      ("KUBERNETES_CLUSTER",  "KUBERNETES CLUSTER DISCOVERY",         "INSTANCE",     True),

    # Aggregate Container Assets (Scope: AGGREGATE — Score = None)
    "CLOUD_ORGANIZATION":      ("CLOUD_CONTAINER",     "AGGREGATED ORGANIZATIONAL POSTURE",    "AGGREGATE",    False),
    "CLOUD_TENANT":            ("CLOUD_CONTAINER",     "AGGREGATED TENANT POSTURE",            "AGGREGATE",    False),
    "CLOUD_SUBSCRIPTION":      ("CLOUD_CONTAINER",     "AGGREGATED SUBSCRIPTION POSTURE",      "AGGREGATE",    False),
    "CLOUD_PROJECT":           ("CLOUD_CONTAINER",     "AGGREGATED PROJECT POSTURE",           "AGGREGATE",    False),
    "CLOUD_RESOURCE_GROUP":    ("CLOUD_CONTAINER",     "AGGREGATED RESOURCE GROUP POSTURE",    "AGGREGATE",    False),
    "CLOUD_ACCOUNT":           ("CLOUD_CONTAINER",     "AGGREGATED ACCOUNT POSTURE",           "AGGREGATE",    False),
    "CLOUD_REGION":            ("CLOUD_CONTAINER",     "AGGREGATED REGION POSTURE",            "AGGREGATE",    False),
    "CLOUD_ZONE":              ("CLOUD_CONTAINER",     "AGGREGATED ZONE POSTURE",              "AGGREGATE",    False),
    "CLOUD_FOLDER":            ("CLOUD_CONTAINER",     "AGGREGATED FOLDER POSTURE",            "AGGREGATE",    False),
    "cloud_account":           ("CLOUD_CONTAINER",     "AGGREGATED ACCOUNT POSTURE",           "AGGREGATE",    False),
    "cloud_region":            ("CLOUD_CONTAINER",     "AGGREGATED REGION POSTURE",            "AGGREGATE",    False),
    "cloud_tenant":            ("CLOUD_CONTAINER",     "AGGREGATED TENANT POSTURE",            "AGGREGATE",    False),
    "cloud_subscription":      ("CLOUD_CONTAINER",     "AGGREGATED SUBSCRIPTION POSTURE",      "AGGREGATE",    False),
    "cloud_resource_group":    ("CLOUD_CONTAINER",     "AGGREGATED RESOURCE GROUP POSTURE",    "AGGREGATE",    False),
    "KUBERNETES_NAMESPACE":    ("KUBERNETES_CONTAINER","AGGREGATED NAMESPACE POSTURE",         "AGGREGATE",    False),

    # Non-Eligible Infrastructure (Scope: NOT_ELIGIBLE — Score = None)
    "NETWORK":                 ("INFRASTRUCTURE",      "INFRASTRUCTURE RESOURCE",              "NOT_ELIGIBLE", False),
    "SUBNET":                  ("INFRASTRUCTURE",      "INFRASTRUCTURE RESOURCE",              "NOT_ELIGIBLE", False),
    "PUBLIC_ENDPOINT":         ("INFRASTRUCTURE",      "INFRASTRUCTURE RESOURCE",              "NOT_ELIGIBLE", False),
    "IDENTITY":                ("IDENTITY",             "IDENTITY RESOURCE",                    "NOT_ELIGIBLE", False),
    "SERVICE_IDENTITY":        ("IDENTITY",             "IDENTITY RESOURCE",                    "NOT_ELIGIBLE", False),
}

# Scanner / Collector IDs → Evidence Source Provenance Label
_SCANNER_SOURCE_MAP: Dict[str, str] = {
    "tls-scanner":             "LIVE TLS HANDSHAKE",
    "tls_scanner":             "LIVE TLS HANDSHAKE",
    "ssh-scanner":             "LIVE SSH HANDSHAKE",
    "ssh_scanner":             "LIVE SSH HANDSHAKE",
    "certificate-scanner":    "CERTIFICATE DISCOVERY",
    "cert_scanner":            "CERTIFICATE DISCOVERY",
    "linux-collector":        "HOST CRYPTOGRAPHIC COLLECTION",
    "linux-host":             "HOST CRYPTOGRAPHIC COLLECTION",
    "linux_collector":        "HOST CRYPTOGRAPHIC COLLECTION",
    "source-code-scanner":    "SOURCE CODE CRYPTO DISCOVERY",
    "source-scanner":         "SOURCE CODE CRYPTO DISCOVERY",
    "source_scanner":         "SOURCE CODE CRYPTO DISCOVERY",
    "dependency-scanner":     "DEPENDENCY DISCOVERY",
    "cloud-server-scanner":    "CLOUD SERVER DISCOVERY",
    "kubernetes-connector":   "KUBERNETES API DISCOVERY",
    "kubernetes":             "KUBERNETES API DISCOVERY",
    "azure-connector":        "AZURE API DISCOVERY",
    "azure":                  "AZURE API DISCOVERY",
    "gcp-connector":          "GCP API DISCOVERY",
    "gcp":                    "GCP API DISCOVERY",
    "aws-connector":          "AWS API DISCOVERY",
    "aws":                    "AWS API DISCOVERY",
}

# ============================================================
# CONTEXT-AWARE SCORING ENGINE
# ============================================================
# Matching dimensions: finding_type, raw_algorithm_name, scanner_id, asset_type
_CONTEXTUAL_SCORING_RULES = [
    # 1. Classical Asymmetric Certificates & Keys (Critical Shor Vulnerability)
    {
        "rule_id": "CERT_RSA_CLASSICAL",
        "dimension": "certificate",
        "finding_types": ["CERTIFICATE_PUBLIC_KEY", "CERTIFICATE"],
        "algo_keywords": ["RSA", "RSA-2048", "RSA-3072", "RSA-4096"],
        "impact": -35,
        "classification": "QUANTUM_VULNERABLE",
        "rationale": "RSA leaf/ca certificate public key is vulnerable to Shor's algorithm on CRQC hardware."
    },
    {
        "rule_id": "CERT_ECDSA_CLASSICAL",
        "dimension": "certificate",
        "finding_types": ["CERTIFICATE_PUBLIC_KEY", "CERTIFICATE"],
        "algo_keywords": ["ECDSA", "SECP256R1", "SECP384R1", "PRIME256V1", "EC-"],
        "impact": -20,
        "classification": "QUANTUM_VULNERABLE",
        "rationale": "ECDSA certificate public key is vulnerable to Shor's algorithm on CRQC hardware."
    },

    # 2. Key Exchange Primitives (Harvest-Now-Decrypt-Later Threat)
    {
        "rule_id": "KEX_RSA_VULNERABLE",
        "dimension": "key_exchange",
        "finding_types": ["KEY_EXCHANGE"],
        "algo_keywords": ["RSA"],
        "impact": -30,
        "classification": "QUANTUM_VULNERABLE",
        "rationale": "RSA key exchange is vulnerable to Harvest-Now-Decrypt-Later retroactive decryption."
    },
    {
        "rule_id": "KEX_PQC_RESISTANT",
        "dimension": "key_exchange",
        "finding_types": ["KEY_EXCHANGE"],
        "algo_keywords": ["ML-KEM", "KYBER", "X25519MLKEM", "MLKEM768", "MLKEM1024"],
        "impact": +20,
        "classification": "QUANTUM_RESISTANT",
        "rationale": "ML-KEM or hybrid ML-KEM key exchange provides post-quantum confidentiality."
    },
    {
        "rule_id": "KEX_SSH_OPENSSH",
        "dimension": "key_exchange",
        "finding_types": ["KEY_EXCHANGE"],
        "scanner_keywords": ["ssh"],
        "algo_keywords": ["CURVE25519-SHA256", "ECDH-SHA2-NISTP256"],
        "impact": +10,
        "classification": "QUANTUM_VULNERABLE",
        "rationale": "Modern SSH KEX algorithm observed — requires upgrade to sntrup761x25519 or ML-KEM."
    },

    # 3. Post-Quantum Signatures
    {
        "rule_id": "SIG_PQC_RESISTANT",
        "dimension": "signature",
        "finding_types": ["SIGNATURE_ALGORITHM", "CERTIFICATE_PUBLIC_KEY", "ALGORITHM"],
        "algo_keywords": ["ML-DSA", "MLDSA", "DILITHIUM", "SLH-DSA", "SPHINCS"],
        "impact": +20,
        "classification": "QUANTUM_RESISTANT",
        "rationale": "NIST FIPS 204/205 post-quantum digital signature algorithm observed."
    },

    # 4. Symmetric Ciphers (Grover's Algorithm Security Margin)
    {
        "rule_id": "SYMMETRIC_STRONG_256",
        "dimension": "symmetric_cipher",
        "finding_types": ["SYMMETRIC_CIPHER"],
        "algo_keywords": ["AES-256", "AES256", "CHACHA20", "AES-256-GCM"],
        "impact": +5,
        "classification": "QUANTUM_RESISTANT",
        "rationale": "Strong 256-bit symmetric cipher — maintains 128-bit post-quantum security against Grover's search."
    },
    {
        "rule_id": "SYMMETRIC_WEAK_LEGACY",
        "dimension": "symmetric_cipher",
        "finding_types": ["SYMMETRIC_CIPHER"],
        "algo_keywords": ["RC4", "3DES", "DES", "AES-128", "AES128"],
        "impact": -10,
        "classification": "QUANTUM_VULNERABLE",
        "rationale": "Weak or 128-bit symmetric cipher — reduced security margin against quantum search."
    },

    # 5. Cryptographic Hash Functions
    {
        "rule_id": "HASH_BROKEN_LEGACY",
        "dimension": "hash_function",
        "finding_types": ["HASH_FUNCTION"],
        "algo_keywords": ["MD5", "SHA-1", "SHA1"],
        "impact": -25,
        "classification": "QUANTUM_VULNERABLE",
        "rationale": "MD5/SHA-1 legacy hash function is broken under classical and quantum collision attacks."
    },

    # 6. Source Code AST & Static Findings (Context-Aware)
    {
        "rule_id": "SOURCE_CODE_RSA_AST",
        "dimension": "source_code",
        "finding_types": ["ALGORITHM", "LIBRARY_DEPENDENCY"],
        "scanner_keywords": ["source"],
        "algo_keywords": ["RSA", "RSA-2048", "PKCS1"],
        "impact": -15,
        "classification": "QUANTUM_VULNERABLE",
        "rationale": "Source code AST callsite references classical RSA cryptography."
    },

    # 7. Cloud Managed Keys & KMS (AWS, Azure, GCP)
    {
        "rule_id": "KMS_PQC_MANAGED_KEY",
        "dimension": "kms_key",
        "finding_types": ["KMS_KEY", "ALGORITHM", "CLOUD_RESOURCE"],
        "algo_keywords": ["ML-KEM", "KYBER", "PQC"],
        "impact": +20,
        "classification": "QUANTUM_RESISTANT",
        "rationale": "Cloud Key Management Service key uses post-quantum algorithm."
    },
    {
        "rule_id": "KMS_CLASSICAL_MANAGED_KEY",
        "dimension": "kms_key",
        "finding_types": ["KMS_KEY", "ALGORITHM", "CLOUD_RESOURCE"],
        "algo_keywords": ["RSA", "RSA-2048", "RSA-4096", "ECDSA_P256"],
        "impact": -10,
        "classification": "QUANTUM_VULNERABLE",
        "rationale": "Cloud KMS key uses classical asymmetric algorithm."
    },

    # 8. Host Library Dependencies (LinuxCollector)
    {
        "rule_id": "HOST_LIB_OPENSSL_LEGACY",
        "dimension": "library_dependency",
        "finding_types": ["LIBRARY_DEPENDENCY"],
        "algo_keywords": ["OPENSSL 1.1", "OPENSSL 1.0", "OPENSSL_1_1"],
        "impact": -15,
        "classification": "QUANTUM_VULNERABLE",
        "rationale": "Legacy OpenSSL 1.1.x host library detected — lacks native provider PQC algorithm support."
    },
]


def _deduplicate_and_score_findings(findings: List[CryptoFinding]) -> Dict[str, Any]:
    """
    Deduplicates overlapping findings targeting the same underlying cryptographic object
    (by cert fingerprint, location, or algorithm identity), applying rule score impact ONCE
    per distinct crypto object while preserving all provenance evidence.
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
            "deduplicated_findings": [],
        }

    # Group findings into distinct crypto objects for deduplication
    dedup_groups: Dict[str, List[CryptoFinding]] = {}
    for f in findings:
        # Construct deduplication key
        location = f.location_identifier or "unknown"
        algo = f.raw_algorithm_name.upper()
        ftype = f.finding_type
        
        # Check metadata for cert fingerprint if available
        meta = f.metadata_json or {}
        cert_fp = meta.get("fingerprint_sha256") or meta.get("sha256_fingerprint") or meta.get("cert_sha256")
        
        if cert_fp:
            dedup_key = f"cert_fp:{cert_fp}"
        else:
            dedup_key = f"{ftype}:{algo}:{location}"
            
        if dedup_key not in dedup_groups:
            dedup_groups[dedup_key] = []
        dedup_groups[dedup_key].append(f)

    score = 100
    components = []
    vulnerable_count = 0
    resistant_count = 0
    hybrid_count = 0
    unknown_count = 0
    primitive_count = len(dedup_groups)

    for dedup_key, group in dedup_groups.items():
        primary_finding = group[0]
        algo_upper = primary_finding.raw_algorithm_name.upper()
        ftype = primary_finding.finding_type
        scanner_id = (primary_finding.scanner_id or "").lower()

        matched_rule = None

        for rule in _CONTEXTUAL_SCORING_RULES:
            # Check finding type
            if ftype not in rule["finding_types"]:
                continue
            # Check scanner keyword if rule restricts scanner
            if "scanner_keywords" in rule:
                if not any(sk.lower() in scanner_id for sk in rule["scanner_keywords"]):
                    continue
            # Check algorithm keyword
            if any(kw.upper() in algo_upper for kw in rule["algo_keywords"]):
                matched_rule = rule
                break

        # Sources aggregated across all deduplicated findings in group
        sources = list(set(_SCANNER_SOURCE_MAP.get(f.scanner_id, f.scanner_id) for f in group))

        if matched_rule:
            score += matched_rule["impact"]
            cls = matched_rule["classification"]
            if cls == "QUANTUM_VULNERABLE":
                vulnerable_count += 1
            elif cls == "QUANTUM_RESISTANT":
                resistant_count += 1
            elif cls == "HYBRID":
                hybrid_count += 1

            components.append({
                "rule_id": matched_rule["rule_id"],
                "dimension": matched_rule["dimension"],
                "evidence_id": primary_finding.id,
                "all_evidence_ids": [f.id for f in group],
                "source": ", ".join(sources),
                "algorithm": primary_finding.raw_algorithm_name,
                "classification": cls,
                "impact": matched_rule["impact"],
                "rationale": matched_rule["rationale"],
                "occurrence_count": len(group),
            })
        else:
            unknown_count += 1

    # Clamp numeric score to [0, 100]
    score = max(0, min(100, score))

    # Risk Tier assignment
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
        "deduplicated_groups_count": len(dedup_groups),
        "total_raw_findings_count": len(findings),
    }


def _build_header_label(findings: List[CryptoFinding], asset_type: str) -> str:
    """Select header label from actual scanner evidence sources."""
    if not findings:
        eligibility = _ELIGIBILITY_MAP.get(asset_type, ("UNKNOWN", "NO CRYPTOGRAPHIC EVIDENCE", "NOT_ELIGIBLE", False))
        return eligibility[1]

    sources = set(_SCANNER_SOURCE_MAP.get(f.scanner_id, f.scanner_id) for f in findings)
    if len(sources) > 1:
        return "CORRELATED CRYPTOGRAPHIC ASSESSMENT"
    return next(iter(sources))


def _build_provenance(findings: List[CryptoFinding]) -> List[Dict]:
    """Build traceable provenance records from real findings."""
    result = []
    for f in findings:
        src_label = _SCANNER_SOURCE_MAP.get(f.scanner_id, f.scanner_id)
        result.append({
            "evidence_id": f.id,
            "discovery_run_id": f.discovery_run_id,
            "source": f.scanner_id,
            "source_label": src_label,
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
    rule_lookup = {}
    for c in scoring.get("components", []):
        for eid in c.get("all_evidence_ids", [c.get("evidence_id")]):
            rule_lookup[eid] = c

    for f in findings:
        rule_match = rule_lookup.get(f.id, {})
        primitives.append({
            "evidence_id": f.id,
            "algorithm": f.raw_algorithm_name,
            "normalized_algorithm": f.normalized_algorithm_id,
            "finding_type": f.finding_type,
            "quantum_status": rule_match.get("classification", "UNKNOWN"),
            "usage_state": "OBSERVED_IN_USE",
            "source": _SCANNER_SOURCE_MAP.get(f.scanner_id, f.scanner_id),
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
    p = scoring.get("primitive_count", 0)

    # Certificate section
    cert_findings = [f for f in findings if f.finding_type in ("CERTIFICATE_PUBLIC_KEY", "CERTIFICATE")]
    if cert_findings:
        algos = ", ".join(set(f.raw_algorithm_name for f in cert_findings))
        is_classical = any(a.upper() in ("RSA", "RSA-2048", "RSA-3072", "RSA-4096", "ECDSA", "SECP256R1") for a in [f.raw_algorithm_name for f in cert_findings])
        sections.append({
            "badge": "CERTIFICATE",
            "type": "certificate",
            "title": f"Certificate public key: {algos}",
            "description": (
                f"Certificate public key ({algos}) is quantum-vulnerable under Shor's algorithm."
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
                "Post-quantum or hybrid key exchange observed — TLS/SSH sessions protected against retroactive decryption."
                if has_pqc else
                f"Key exchange algorithm: {algos}."
            )
        })

    # Exposure summary section
    if p > 0:
        vuln_text = "No quantum-vulnerable asymmetric primitives were observed." if v == 0 else f"{v} of {p} distinct cryptographic objects are quantum-vulnerable (Shor's algorithm applicable)."
        sections.append({
            "badge": "EXPOSURE",
            "type": "exposure",
            "title": f"{v} / {p} distinct crypto objects are quantum-vulnerable.",
            "description": vuln_text,
        })

    return sections


def _build_exposure_map(asset: Asset, findings: List[CryptoFinding]) -> List[Dict]:
    """Build exposure map only from real evidence."""
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

    seen_types: set = set()
    for f in findings:
        if f.finding_type not in seen_types:
            seen_types.add(f.finding_type)
            nodes.append({
                "id": f"node-{f.finding_type.lower()}-{f.id[:8]}",
                "title": f.raw_algorithm_name,
                "subtitle": f.finding_type.replace("_", " ").title(),
                "status_badge": "OBSERVED",
                "color": "rose" if any(c in f.raw_algorithm_name.upper() for c in ["RSA", "ECDSA", "MD5", "SHA-1"]) else "emerald",
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
                    "occurrences": [{"location": f.location_identifier or "unknown"}]
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
    """For container assets (Subscription/Account/Project): aggregate child resource statistics."""
    children_ids = set()
    rels = db.query(Relationship).filter(
        Relationship.source_entity_id == asset.id,
        Relationship.relationship_type == "CONTAINS"
    ).all()
    for r in rels:
        if r.target_entity_type == "ASSET":
            children_ids.add(r.target_entity_id)

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
# MAIN INSTANCE REPORT ENDPOINT
# ============================================================

@router.get("/instance/{asset_id}")
def get_instance_pqc_report(asset_id: str, db: Session = Depends(get_db)) -> Dict[str, Any]:
    """
    Evidence-Driven Per-Instance PQC Assessment Report.

    INVARIANTS:
    - Operate on canonical backend Asset.id
    - Zero qualifying evidence -> NOT_ASSESSED + score = null
    - Explicit assessment scope (INSTANCE, AGGREGATE, NOT_ELIGIBLE)
    """
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail=f"Asset '{asset_id}' not found")

    # Lookup asset eligibility and scope
    eligibility_info = _ELIGIBILITY_MAP.get(
        asset.asset_type,
        ("UNKNOWN", "CRYPTOGRAPHIC DISCOVERY", "INSTANCE", True)
    )
    eligibility_label, default_header, assessment_scope, can_score = eligibility_info

    endpoint_name = asset.hostname or asset.provider_resource_id or f"{asset.asset_type}-{asset.id[:8]}"

    # ============================================================
    # 1. AGGREGATE CONTAINER SCOPE
    # ============================================================
    if assessment_scope == "AGGREGATE":
        aggregate = _build_aggregate_view(asset, db)
        return {
            "asset": {
                "id": asset.id,
                "name": endpoint_name,
                "asset_type": asset.asset_type,
                "provider": asset.provider,
                "region": asset.region,
                "eligibility_type": eligibility_label,
                "assessment_scope": "AGGREGATE",
            },
            "assessment": {
                "status": "NOT_ASSESSED",
                "score": None,
                "risk_tier": "UNKNOWN",
                "coverage": aggregate["coverage_percentage"],
                "note": "Container asset — aggregated child inventory posture only."
            },
            "aggregate": aggregate,
            "evidence_summary": {
                "total": 0, "observed": 0, "configured": 0, "inferred": 0,
                "primitive_count": 0, "vulnerable_count": 0, "resistant_count": 0,
                "hybrid_count": 0, "unknown_count": 0
            },
            "primitives": [],
            "sections": [],
            "provenance": [],
            "exposure_map": [],
            "header_label": default_header,
            "cbom": None,
        }

    # ============================================================
    # 2. NOT ELIGIBLE INFRASTRUCTURE SCOPE
    # ============================================================
    if assessment_scope == "NOT_ELIGIBLE":
        return {
            "asset": {
                "id": asset.id,
                "name": endpoint_name,
                "asset_type": asset.asset_type,
                "provider": asset.provider,
                "region": asset.region,
                "eligibility_type": eligibility_label,
                "assessment_scope": "NOT_ELIGIBLE",
            },
            "assessment": {
                "status": "NOT_ASSESSED",
                "score": None,
                "risk_tier": "UNKNOWN",
                "coverage": 0.0,
                "note": "Asset type is not eligible for instance PQC assessment."
            },
            "evidence_summary": {
                "total": 0, "observed": 0, "configured": 0, "inferred": 0,
                "primitive_count": 0, "vulnerable_count": 0, "resistant_count": 0,
                "hybrid_count": 0, "unknown_count": 0
            },
            "primitives": [],
            "sections": [],
            "provenance": [],
            "exposure_map": [],
            "header_label": default_header,
            "cbom": None,
        }

    # Fetch evidence findings
    findings = db.query(CryptoFinding).filter(CryptoFinding.asset_id == asset_id).all()

    # ============================================================
    # 3. ZERO CRYPTOGRAPHIC EVIDENCE
    # ============================================================
    if not findings:
        return {
            "asset": {
                "id": asset.id,
                "name": endpoint_name,
                "asset_type": asset.asset_type,
                "provider": asset.provider,
                "region": asset.region,
                "eligibility_type": eligibility_label,
                "assessment_scope": "INSTANCE",
            },
            "assessment": {
                "status": "NOT_ASSESSED",
                "score": None,
                "risk_tier": "UNKNOWN",
                "coverage": 0.0,
                "note": "No cryptographic evidence observed for this asset."
            },
            "evidence_summary": {
                "total": 0, "observed": 0, "configured": 0, "inferred": 0,
                "primitive_count": 0, "vulnerable_count": 0, "resistant_count": 0,
                "hybrid_count": 0, "unknown_count": 0
            },
            "primitives": [],
            "sections": [],
            "provenance": [],
            "exposure_map": [],
            "header_label": "NO CRYPTOGRAPHIC EVIDENCE",
            "cbom": None,
        }

    # ============================================================
    # 4. QUALIFYING CRYPTOGRAPHIC EVIDENCE OBSERVED
    # ============================================================
    scoring = _deduplicate_and_score_findings(findings)
    header_label = _build_header_label(findings, asset.asset_type)
    provenance = _build_provenance(findings)
    primitives = _build_primitives(findings, scoring)
    sections = _build_sections(findings, scoring)
    exposure_map = _build_exposure_map(asset, findings)
    cbom = _build_cbom(asset, findings)

    v = scoring["vulnerable_count"]
    r = scoring["resistant_count"]
    h = scoring["hybrid_count"]
    p = scoring["primitive_count"]
    total_ev = len(findings)

    return {
        "asset": {
            "id": asset.id,
            "name": endpoint_name,
            "asset_type": asset.asset_type,
            "provider": asset.provider,
            "region": asset.region,
            "eligibility_type": eligibility_label,
            "assessment_scope": "INSTANCE",
        },
        "assessment": {
            "status": "ASSESSED",
            "score": scoring["score"],
            "risk_tier": scoring["risk_tier"],
            "coverage": 100.0 if total_ev > 0 else 0.0,
            "deduplicated_objects_count": p,
            "total_raw_findings_count": total_ev,
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
        "scoring_components": scoring["components"],
        "provenance": provenance,
        "exposure_map": exposure_map,
        "header_label": header_label,
        "cbom": cbom,
    }
