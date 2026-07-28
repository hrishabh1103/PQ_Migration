import logging
from abc import ABC, abstractmethod
from enum import Enum
from typing import AsyncIterator, Set, Dict, Any, Optional, List
from pydantic import BaseModel, Field

from app.scanners.base import RawFinding, ScanContext
from app.models.entities import TargetType

logger = logging.getLogger(__name__)

class PluginType(str, Enum):
    SCANNER = "SCANNER"
    CONNECTOR = "CONNECTOR"
    COLLECTOR = "COLLECTOR"

class PluginCapability(str, Enum):
    TLS = "TLS"
    SSH = "SSH"
    X509 = "X509"
    IPSEC = "IPSEC"
    IKE = "IKE"
    SOURCE_CODE = "SOURCE_CODE"
    DEPENDENCIES = "DEPENDENCIES"
    CLOUD_RESOURCE = "CLOUD_RESOURCE"
    KMS = "KMS"
    HSM = "HSM"
    PKI = "PKI"
    CONTAINER = "CONTAINER"
    KUBERNETES = "KUBERNETES"
    DATABASE = "DATABASE"
    IDENTITY = "IDENTITY"
    CODE_SIGNING = "CODE_SIGNING"
    PASSIVE_NETWORK = "PASSIVE_NETWORK"
    DATA_FLOW = "DATA_FLOW"

class DiscoveryPlugin(ABC):
    """
    Abstract Base Class for all Enterprise Discovery Plugins (Scanners, Connectors, Collectors).
    """
    plugin_id: str
    version: str = "1.0.0"
    plugin_type: PluginType = PluginType.SCANNER
    supported_target_types: Set[TargetType] = set()
    capabilities: Set[PluginCapability] = set()

    @abstractmethod
    async def discover(
        self,
        target_value: str,
        target_type: TargetType,
        context: ScanContext
    ) -> AsyncIterator[RawFinding]:
        pass

class Scanner(DiscoveryPlugin):
    """
    Active/direct scanner plugin for TLS, SSH, certificates, source code, etc.
    """
    plugin_type: PluginType = PluginType.SCANNER

    @property
    def scanner_id(self) -> str:
        return self.__dict__.get("scanner_id") or self.__dict__.get("plugin_id") or getattr(self, "plugin_id", self.__class__.__name__)

class Connector(DiscoveryPlugin):
    """
    External API connector for AWS, Azure, GCP, Kubernetes, Vault, PKI, etc.
    """
    plugin_type: PluginType = PluginType.CONNECTOR

class Collector(DiscoveryPlugin):
    """
    Installed agent, endpoint inventory, or passive telemetry collector.
    """
    plugin_type: PluginType = PluginType.COLLECTOR

class PluginRegistry:
    """
    Canonical Plugin Registry for all DiscoveryPlugin instances.
    """
    _registry: Dict[str, Any] = {}

    @classmethod
    def register(cls, plugin: Any) -> None:
        p_id = getattr(plugin, "plugin_id", None) or getattr(plugin, "scanner_id", None) or plugin.__class__.__name__
        cls._registry[p_id] = plugin
        
        p_type = getattr(plugin, "plugin_type", PluginType.SCANNER)
        p_type_val = p_type.value if hasattr(p_type, 'value') else str(p_type)
        caps = getattr(plugin, "capabilities", set())
        cap_list = [c.value if hasattr(c, 'value') else str(c) for c in caps]
        
        logger.info(f"Registered plugin '{p_id}' ({p_type_val}) with capabilities: {cap_list}")

    @classmethod
    def get(cls, plugin_id: str) -> Optional[Any]:
        return cls._registry.get(plugin_id)

    @classmethod
    def list_plugins(cls, plugin_type: Optional[PluginType] = None) -> Dict[str, Any]:
        if plugin_type:
            return {k: v for k, v in cls._registry.items() if getattr(v, "plugin_type", PluginType.SCANNER) == plugin_type}
        return dict(cls._registry)

    @classmethod
    def clear(cls) -> None:
        cls._registry.clear()

class CapabilityRegistry:
    """
    Registry for querying discovery capabilities across registered plugins.
    """
    @classmethod
    def get_plugins_for_capability(cls, capability: PluginCapability) -> List[Any]:
        all_plugins = PluginRegistry.list_plugins()
        res = []
        for p in all_plugins.values():
            caps = getattr(p, "capabilities", set())
            if capability in caps:
                res.append(p)
        return res

    @classmethod
    def list_supported_capabilities(cls) -> Set[PluginCapability]:
        supported = set()
        for plugin in PluginRegistry.list_plugins().values():
            caps = getattr(plugin, "capabilities", set())
            supported.update(caps)
        return supported
