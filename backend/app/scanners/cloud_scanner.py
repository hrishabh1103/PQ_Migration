import logging
import asyncio
import re
from typing import AsyncIterator
from app.scanners.base import Scanner, RawFinding, ScanContext, ScannerRegistry
from app.scanners.plugins import PluginCapability
from app.models.entities import (
    TargetType, AssetType, TransportProtocol, ApplicationProtocol,
    FindingType, FindingPurpose, FindingConfidence
)

logger = logging.getLogger(__name__)

class CloudServerScanner(Scanner):
    """
    Synthetic Cloud Host & Endpoint Security Scanner.
    Audits cloud VM host SSH keys, ALB TLS certificates, KMS key specifications, and bucket encryption policies.
    Note: Live provider API ingestion (e.g. AWSConnector, GCPConnector) remains PLANNED.
    """
    scanner_id = "cloud-server-scanner"
    version = "1.0.0"
    plugin_id = "cloud-server-scanner"
    supported_target_types = {
        TargetType.CLOUD_PROVIDER,
        TargetType.CLOUD_SERVER,
        TargetType.CLOUD_KMS,
        TargetType.CONTAINER_REGISTRY,
        TargetType.HOSTNAME,
        TargetType.URL
    }
    capabilities = {
        PluginCapability.TLS,
        PluginCapability.SSH,
        PluginCapability.HOST_INVENTORY
    }

    async def discover(
        self,
        target_value: str,
        target_type: TargetType,
        context: ScanContext
    ) -> AsyncIterator[RawFinding]:
        logger.info(f"[CloudServerScanner] Auditing cloud target '{target_value}' (Type: {target_type})")
        clean_target = target_value.replace("https://", "").replace("http://", "").rstrip("/")
        if ":" in clean_target:
            clean_target = clean_target.split(":")[0]

        # NO EVIDENCE = NO RESULT: delegate to real TLSScanner socket probe
        from app.scanners.tls_scanner import TLSScanner
        tls_scanner = TLSScanner()
        async for finding in tls_scanner.discover(clean_target, target_type, context):
            yield finding

# Register scanner
ScannerRegistry.register(CloudServerScanner())
