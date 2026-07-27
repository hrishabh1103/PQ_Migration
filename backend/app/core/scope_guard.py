import socket
import ipaddress
from typing import List, Tuple
from app.models.entities import AuthorizedTarget, TargetType

class ScopeGuardError(Exception):
    pass

class ScopeGuard:
    """
    Enforces authorization scope validation before network connection
    and re-validates scope post-DNS resolution for hostnames.
    """

    @staticmethod
    def validate_target(target: AuthorizedTarget) -> bool:
        if not target.is_authorized:
            raise ScopeGuardError(f"Target '{target.name}' ({target.target_value}) is not authorized for scanning.")
        return True

    @staticmethod
    def resolve_and_validate_hostname(hostname: str, allowed_ips: List[str] = None) -> List[str]:
        """
        Resolves hostname to IP addresses and performs post-DNS scope validation.
        """
        # Clean hostname
        clean_host = hostname.split(":")[0].strip().lower()
        if clean_host in ("localhost", "127.0.0.1", "::1", "demo.internal"):
            # Internal/demo development targets are authorized for testing
            return ["127.0.0.1"]

        try:
            addr_info = socket.getaddrinfo(clean_host, None)
            resolved_ips = list(set([item[4][0] for item in addr_info]))
        except socket.gaierror as e:
            raise ScopeGuardError(f"DNS resolution failed for target host '{clean_host}': {e}")

        if not resolved_ips:
            raise ScopeGuardError(f"No IP addresses resolved for hostname '{clean_host}'.")

        # If strict IP filtering rules are provided, check resolved IPs against allowed networks
        if allowed_ips:
            allowed_networks = [ipaddress.ip_network(ip_str, strict=False) for ip_str in allowed_ips]
            for resolved_ip in resolved_ips:
                ip_obj = ipaddress.ip_address(resolved_ip)
                if not any(ip_obj in net for net in allowed_networks):
                    raise ScopeGuardError(
                        f"Resolved IP {resolved_ip} for hostname '{clean_host}' is outside authorized IP scope."
                    )

        return resolved_ips

    @staticmethod
    def validate_redirect_url(original_host: str, redirect_url: str) -> bool:
        """
        Validates if redirect target stays within authorized scope.
        """
        from urllib.parse import urlparse
        parsed = urlparse(redirect_url)
        redirect_host = parsed.netloc.split(":")[0].lower()
        if redirect_host and redirect_host != original_host.split(":")[0].lower():
            raise ScopeGuardError(
                f"Unauthorized redirect attempted from '{original_host}' to unauthorized host '{redirect_host}'."
            )
        return True
