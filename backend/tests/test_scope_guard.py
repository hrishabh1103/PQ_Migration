import pytest
from app.models.entities import AuthorizedTarget, TargetType
from app.core.scope_guard import ScopeGuard, ScopeGuardError

def test_scope_guard_authorized_target():
    target = AuthorizedTarget(
        name="Valid Target",
        target_type=TargetType.HOSTNAME,
        target_value="demo.internal",
        is_authorized=True
    )
    assert ScopeGuard.validate_target(target) is True

def test_scope_guard_unauthorized_target():
    target = AuthorizedTarget(
        name="Unauthorized Target",
        target_type=TargetType.HOSTNAME,
        target_value="malicious.local",
        is_authorized=False
    )
    with pytest.raises(ScopeGuardError) as exc_info:
        ScopeGuard.validate_target(target)
    assert "not authorized" in str(exc_info.value)

def test_scope_guard_dns_resolution_demo():
    ips = ScopeGuard.resolve_and_validate_hostname("demo.internal")
    assert "127.0.0.1" in ips

def test_scope_guard_redirect_validation():
    assert ScopeGuard.validate_redirect_url("api.company.com", "https://api.company.com/v1/auth") is True
    with pytest.raises(ScopeGuardError):
        ScopeGuard.validate_redirect_url("api.company.com", "https://attacker.com/steal")
