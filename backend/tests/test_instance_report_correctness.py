"""
test_instance_report_correctness.py

Anti-constant, mutation, evidence-gating, deduplication, and scope correctness tests.

INVARIANTS:
  1. Assets with no evidence get score=None, status=NOT_ASSESSED
  2. Score changes when evidence changes (anti-constant / mutation)
  3. Different evidence produces different scores (anti-constant)
  4. Deduplicated evidence applies scoring penalty ONCE per crypto object while preserving all provenance
  5. Assessment scopes (INSTANCE, AGGREGATE, NOT_ELIGIBLE) enforced cleanly
  6. No hardcoded fallback constants survive
"""
import pytest
from unittest.mock import MagicMock
from datetime import datetime, timezone

from app.api.v1.instance_report import (
    _deduplicate_and_score_findings,
    _build_sections,
    _build_header_label,
    _build_provenance,
    _ELIGIBILITY_MAP,
    _SCANNER_SOURCE_MAP,
    _CONTEXTUAL_SCORING_RULES,
)


def _utc():
    return datetime.now(timezone.utc)


def _make_finding(
    finding_id: str,
    raw_algorithm: str,
    finding_type: str,
    scanner_id: str = "tls-scanner",
    location: str = "test-host.example.com:443",
    confidence: str = "HIGH",
    metadata: dict = None
):
    """Create a mock CryptoFinding object."""
    f = MagicMock()
    f.id = finding_id
    f.raw_algorithm_name = raw_algorithm
    f.normalized_algorithm_id = raw_algorithm
    f.finding_type = finding_type
    f.scanner_id = scanner_id
    f.location_identifier = location
    f.confidence = MagicMock()
    f.confidence.value = confidence
    f.first_seen_at = _utc()
    f.last_seen_at = _utc()
    f.discovery_run_id = "dr-test-001"
    f.metadata_json = metadata or {}
    return f


# ============================================================
# Test 1: Empty Evidence & Scope Gating
# ============================================================
class TestNotAssessedGating:
    """All assets with no evidence must produce null score."""

    def test_empty_findings_produces_null_score(self):
        result = _deduplicate_and_score_findings([])
        assert result["score"] is None, "Empty evidence must produce score=None, not a fallback integer."
        assert result["risk_tier"] == "UNKNOWN"
        assert result["primitive_count"] == 0
        assert result["vulnerable_count"] == 0

    def test_eligibility_scopes(self):
        # Aggregate scope
        _, _, scope_acc, can_score_acc = _ELIGIBILITY_MAP["CLOUD_ACCOUNT"]
        assert scope_acc == "AGGREGATE"
        assert can_score_acc is False

        _, _, scope_sub, _ = _ELIGIBILITY_MAP["CLOUD_SUBSCRIPTION"]
        assert scope_sub == "AGGREGATE"

        # Not eligible scope
        _, _, scope_net, _ = _ELIGIBILITY_MAP["NETWORK"]
        assert scope_net == "NOT_ELIGIBLE"

        # Instance scope
        _, _, scope_host, can_score_host = _ELIGIBILITY_MAP["HOST"]
        assert scope_host == "INSTANCE"
        assert can_score_host is True

        _, _, scope_vm, _ = _ELIGIBILITY_MAP["COMPUTE_INSTANCE"]
        assert scope_vm == "INSTANCE"


# ============================================================
# Test 2: Classical Asymmetric Findings (RSA & ECDSA)
# ============================================================
class TestClassicalFindings:
    def test_rsa2048_cert_score_below_80(self):
        f = [_make_finding("f-cert-rsa", "RSA-2048", "CERTIFICATE_PUBLIC_KEY")]
        result = _deduplicate_and_score_findings(f)
        assert result["score"] is not None
        assert result["score"] == 65  # 100 - 35
        assert result["risk_tier"] == "MEDIUM"
        assert result["vulnerable_count"] == 1

    def test_ecdsa_cert_score(self):
        f = [_make_finding("f-cert-ec", "ECDSA", "CERTIFICATE_PUBLIC_KEY")]
        result = _deduplicate_and_score_findings(f)
        assert result["score"] is not None
        assert result["score"] == 80  # 100 - 20
        assert result["vulnerable_count"] == 1


# ============================================================
# Test 3: Deduplication of Overlapping Evidence
# ============================================================
class TestEvidenceDeduplication:
    """Identical crypto objects across multiple scanners apply score penalty ONCE."""

    def test_duplicate_cert_fingerprints_deduplicated(self):
        meta = {"fingerprint_sha256": "sha256-cert-abcd-1234"}
        f1 = _make_finding("f1", "RSA-2048", "CERTIFICATE_PUBLIC_KEY", scanner_id="tls-scanner", metadata=meta)
        f2 = _make_finding("f2", "RSA-2048", "CERTIFICATE_PUBLIC_KEY", scanner_id="linux-collector", metadata=meta)
        f3 = _make_finding("f3", "RSA-2048", "CERTIFICATE_PUBLIC_KEY", scanner_id="kubernetes-connector", metadata=meta)

        result = _deduplicate_and_score_findings([f1, f2, f3])
        # Score penalty (-35) applied once to base 100 -> 65
        assert result["score"] == 65
        assert result["primitive_count"] == 1
        assert result["total_raw_findings_count"] == 3
        # Sources in component should list all 3 scanners
        comp = result["components"][0]
        assert "LIVE TLS HANDSHAKE" in comp["source"]
        assert "HOST CRYPTOGRAPHIC COLLECTION" in comp["source"]
        assert "KUBERNETES API DISCOVERY" in comp["source"]


# ============================================================
# Test 4: Post-Quantum Evidence (ML-KEM & ML-DSA)
# ============================================================
class TestPostQuantumEvidence:
    def test_mlkem_key_exchange(self):
        f = [_make_finding("f-mlkem", "ML-KEM-768", "KEY_EXCHANGE")]
        result = _deduplicate_and_score_findings(f)
        assert result["score"] == 100  # 100 + 20 clamped to 100
        assert result["resistant_count"] == 1
        assert result["risk_tier"] == "LOW"

    def test_mldsa_signature(self):
        f = [_make_finding("f-mldsa", "ML-DSA-65", "SIGNATURE_ALGORITHM")]
        result = _deduplicate_and_score_findings(f)
        assert result["score"] == 100
        assert result["resistant_count"] == 1

    def test_combined_rsa_cert_and_mlkem_kex(self):
        findings = [
            _make_finding("f-rsa", "RSA-2048", "CERTIFICATE_PUBLIC_KEY"),
            _make_finding("f-pqc", "ML-KEM-768", "KEY_EXCHANGE"),
        ]
        result = _deduplicate_and_score_findings(findings)
        # 100 - 35 + 20 = 85
        assert result["score"] == 85
        assert result["vulnerable_count"] == 1
        assert result["resistant_count"] == 1


# ============================================================
# Test 5: Source Code & Host Library Findings
# ============================================================
class TestScannerSpecificContextRules:
    def test_source_code_rsa_ast_finding(self):
        f = [_make_finding("f-src", "RSA-2048", "ALGORITHM", scanner_id="source-code-scanner")]
        result = _deduplicate_and_score_findings(f)
        # Source code AST RSA: -15 -> 85
        assert result["score"] == 85

    def test_host_openssl_legacy_finding(self):
        f = [_make_finding("f-openssl", "OpenSSL 1.1.1u", "LIBRARY_DEPENDENCY", scanner_id="linux-collector")]
        result = _deduplicate_and_score_findings(f)
        # Legacy OpenSSL: -15 -> 85
        assert result["score"] == 85


# ============================================================
# Test 6: Anti-Constant & Mutation Proofs
# ============================================================
class TestAntiConstantAndMutation:
    def test_score_differs_by_algorithm(self):
        s_rsa = _deduplicate_and_score_findings([_make_finding("f1", "RSA-2048", "CERTIFICATE_PUBLIC_KEY")])["score"]
        s_ec = _deduplicate_and_score_findings([_make_finding("f2", "ECDSA", "CERTIFICATE_PUBLIC_KEY")])["score"]
        s_pqc = _deduplicate_and_score_findings([_make_finding("f3", "ML-KEM-768", "KEY_EXCHANGE")])["score"]

        assert s_rsa != s_ec
        assert s_rsa != s_pqc
        assert s_pqc > s_rsa

    def test_no_hardcoded_fallback_constants(self):
        for algo, ftype in [("RSA-2048", "CERTIFICATE_PUBLIC_KEY"), ("ECDSA", "CERTIFICATE_PUBLIC_KEY"), ("ML-KEM-768", "KEY_EXCHANGE")]:
            res = _deduplicate_and_score_findings([_make_finding("f", algo, ftype)])
            assert res["score"] not in (95, 82, 75)


# ============================================================
# Test 7: Scanner Provenance Normalization
# ============================================================
class TestProvenanceNormalization:
    def test_all_scanners_normalized(self):
        findings = [
            _make_finding("f1", "RSA-2048", "CERTIFICATE_PUBLIC_KEY", scanner_id="tls-scanner"),
            _make_finding("f2", "ECDSA", "CERTIFICATE_PUBLIC_KEY", scanner_id="ssh-scanner"),
            _make_finding("f3", "ML-KEM-768", "KEY_EXCHANGE", scanner_id="kubernetes-connector"),
            _make_finding("f4", "AES-256", "SYMMETRIC_CIPHER", scanner_id="azure-connector"),
            _make_finding("f5", "RSA-4096", "ALGORITHM", scanner_id="aws-connector"),
        ]
        prov = _build_provenance(findings)
        labels = [p["source_label"] for p in prov]
        assert "LIVE TLS HANDSHAKE" in labels
        assert "LIVE SSH HANDSHAKE" in labels
        assert "KUBERNETES API DISCOVERY" in labels
        assert "AZURE API DISCOVERY" in labels
        assert "AWS API DISCOVERY" in labels
