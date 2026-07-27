import hashlib
from app.scanners.base import RawFinding
from app.core.sanitizer import Sanitizer
from app.models.entities import FindingType, FindingPurpose

SAMPLE_PEM_PRIVATE_KEY = """
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAzX10w+3k2jH3Z5m0A9x9Gv2Z1p9lX4k9...
-----END RSA PRIVATE KEY-----
"""

def test_sanitizer_redacts_pem_private_key():
    finding = RawFinding(
        asset_hostname="demo.internal",
        finding_type=FindingType.CERTIFICATE_PUBLIC_KEY,
        raw_algorithm_name="RSA-2048",
        purpose=FindingPurpose.AUTHENTICATION,
        location_identifier="TLS Certificate",
        evidence_snippet=f"Found key material: {SAMPLE_PEM_PRIVATE_KEY}",
        metadata={"private_key": "MIIEowIBAAKCAQE...", "public_exp": 65537}
    )

    clean_finding = Sanitizer.sanitize(finding)

    assert "-----BEGIN RSA PRIVATE KEY-----" not in clean_finding.evidence_snippet
    assert "[REDACTED PRIVATE KEY MATERIAL]" in clean_finding.evidence_snippet
    assert clean_finding.metadata["private_key"] == "[REDACTED]"
    assert clean_finding.metadata["public_exp"] == 65537
    assert "_evidence_hash" in clean_finding.metadata
    assert len(clean_finding.metadata["_evidence_hash"]) == 64
