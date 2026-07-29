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
        original_clean = original_host.split(":")[0].lower()
        if redirect_host != original_clean:
            raise ScopeGuardError(f"Cross-domain redirect from '{original_clean}' to '{redirect_host}' blocked by ScopeGuard.")
        return True

    @staticmethod
    def validate_azure_scope(
        tenant_id: str,
        subscription_id: str,
        allowed_tenant_ids: List[str] = None,
        allowed_subscription_ids: List[str] = None
    ) -> bool:
        """
        Validates Azure Tenant and Subscription IDs against authorized scope lists.
        Fails closed with ScopeGuardError if identity falls outside authorized scope.
        """
        if allowed_tenant_ids and tenant_id not in allowed_tenant_ids:
            raise ScopeGuardError(f"Azure Tenant ID '{tenant_id}' is outside authorized scope {allowed_tenant_ids}.")
        if allowed_subscription_ids and subscription_id not in allowed_subscription_ids:
            raise ScopeGuardError(f"Azure Subscription ID '{subscription_id}' is outside authorized scope {allowed_subscription_ids}.")
        return True
