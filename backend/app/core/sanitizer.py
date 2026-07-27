import re
import hashlib
from typing import Dict, Any
from app.scanners.base import RawFinding

PEM_PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN (?:[A-Z0-9_-]+\s+)?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9_-]+\s+)?PRIVATE KEY-----",
    re.IGNORECASE
)

KEYWORD_PRIVATE_KEY_PATTERN = re.compile(
    r"(?:rsa|ec|dsa|openssh|encrypted)?\s*private\s*key\s*[:=]\s*[^\n\r]+",
    re.IGNORECASE
)

SECRET_TOKEN_PATTERN = re.compile(
    r"(?:bearer\s+[a-zA-Z0-9_\-\.]+|api[_-]?key[:=]\s*[a-zA-Z0-9_\-]+|password[:=]\s*[^\s,]+)",
    re.IGNORECASE
)

class Sanitizer:
    """
    Sanitizes raw discovery findings by enforcing zero private key collection
    and redacting secret tokens before storage. Computes SHA-256 evidence hash.
    """

    @classmethod
    def sanitize(cls, finding: RawFinding) -> RawFinding:
        # Sanitize evidence snippet
        sanitized_snippet = cls.clean_string(finding.evidence_snippet)
        
        # Sanitize metadata recursively
        sanitized_metadata = cls.clean_dict(finding.metadata)

        # Compute SHA-256 hash of sanitized evidence snippet
        evidence_hash = hashlib.sha256(sanitized_snippet.encode("utf-8")).hexdigest()

        # Update finding
        finding.evidence_snippet = sanitized_snippet
        finding.metadata = sanitized_metadata
        finding.metadata["_evidence_hash"] = evidence_hash

        return finding

    @classmethod
    def clean_string(cls, input_text: str) -> str:
        if not input_text:
            return ""
        
        # Redact PEM private key blocks
        cleaned = PEM_PRIVATE_KEY_PATTERN.sub("[REDACTED PRIVATE KEY MATERIAL]", input_text)
        # Redact inline private key patterns
        cleaned = KEYWORD_PRIVATE_KEY_PATTERN.sub("[REDACTED PRIVATE KEY MATERIAL]", cleaned)
        # Redact secret tokens
        cleaned = SECRET_TOKEN_PATTERN.sub("[REDACTED SECRET TOKEN]", cleaned)
        return cleaned

    @classmethod
    def clean_dict(cls, data: Dict[str, Any]) -> Dict[str, Any]:
        cleaned = {}
        for key, value in data.items():
            # Check key name for private key or secret hints
            key_lower = key.lower()
            if any(secret_term in key_lower for secret_term in ("private_key", "secret", "password", "token", "auth")):
                cleaned[key] = "[REDACTED]"
            elif isinstance(value, str):
                cleaned[key] = cls.clean_string(value)
            elif isinstance(value, dict):
                cleaned[key] = cls.clean_dict(value)
            else:
                cleaned[key] = value
        return cleaned
