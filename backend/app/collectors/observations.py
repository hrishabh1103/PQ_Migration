from enum import Enum
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field

class CapabilityState(str, Enum):
    INSTALLED = "INSTALLED" # Package/library/provider exists on host
    AVAILABLE = "AVAILABLE" # Runtime/provider advertises capability
    CONFIGURED = "CONFIGURED" # Service/application/policy configured to use capability
    OBSERVED_IN_USE = "OBSERVED_IN_USE" # Direct runtime or protocol evidence confirms active usage

class ObservationType(str, Enum):
    ASSET = "ASSET"
    SERVICE = "SERVICE"
    PROCESS = "PROCESS"
    CRYPTO_OBJECT = "CRYPTO_OBJECT"
    CERTIFICATE = "CERTIFICATE"
    RELATIONSHIP = "RELATIONSHIP"
    CAPABILITY = "CAPABILITY"

class DiscoveryObservation(BaseModel):
    """
    Base Structured Observation Contract emitted by Collector and Connector plugins.
    Not a database ORM entity, but a clean transport/plugin output contract.
    """
    observation_type: ObservationType
    module_id: str
    metadata: Dict[str, Any] = Field(default_factory=dict)

class AssetObservation(DiscoveryObservation):
    observation_type: ObservationType = ObservationType.ASSET
    hostname: Optional[str] = None
    fqdn: Optional[str] = None
    ip_address: Optional[str] = None
    os_distribution: Optional[str] = None
    os_version: Optional[str] = None
    kernel_version: Optional[str] = None
    architecture: Optional[str] = None
    asset_type: str = "HOST"
    asset_category: str = "INFRASTRUCTURE"
    identity_key: Optional[str] = None
    external_id: Optional[str] = None
    provider_resource_id: Optional[str] = None

class ServiceObservation(DiscoveryObservation):
    observation_type: ObservationType = ObservationType.SERVICE
    port: int
    transport_protocol: str = "TCP" # TCP, UDP
    application_protocol: str = "HTTPS"
    service_name: str = "https"
    process_pid: Optional[int] = None
    process_name: Optional[str] = None

class ProcessObservation(DiscoveryObservation):
    observation_type: ObservationType = ObservationType.PROCESS
    pid: int
    process_name: str
    executable_path: Optional[str] = None
    sanitized_args: Optional[str] = None
    listening_ports: List[int] = Field(default_factory=list)

class CryptoObservation(DiscoveryObservation):
    observation_type: ObservationType = ObservationType.CRYPTO_OBJECT
    canonical_name: str
    object_type: str = "LIBRARY" # ALGORITHM, KEY, CERTIFICATE, PROTOCOL, LIBRARY, CRYPTO_MODULE, KEYSTORE
    provider: Optional[str] = None
    version: Optional[str] = None
    identity_key: str
    fingerprint: Optional[str] = None
    capability_state: CapabilityState = CapabilityState.INSTALLED

class CertificateObservation(DiscoveryObservation):
    observation_type: ObservationType = ObservationType.CERTIFICATE
    fingerprint: str # SHA-256 fingerprint
    subject: str
    issuer: str
    serial_number: Optional[str] = None
    valid_from: Optional[str] = None
    valid_to: Optional[str] = None
    pubkey_algo: str
    pubkey_size: Optional[int] = None
    signature_algo: str
    san_list: List[str] = Field(default_factory=list)
    key_usage: List[str] = Field(default_factory=list)

class RelationshipObservation(DiscoveryObservation):
    observation_type: ObservationType = ObservationType.RELATIONSHIP
    source_type: str
    source_id_hint: str # e.g. "host", "process:nginx", "service:443"
    target_type: str
    target_id_hint: str # e.g. "crypto:OpenSSL", "cert:sha256-abc"
    relationship_type: str # RUNS_ON, CONTAINS, USES, EXPOSES, TERMINATES_TLS_AT, STORES_DATA
    confidence: str = "HIGH"

class CapabilityObservation(DiscoveryObservation):
    observation_type: ObservationType = ObservationType.CAPABILITY
    capability_name: str
    capability_state: CapabilityState
    algorithm_name: str
    details: Dict[str, Any] = Field(default_factory=dict)
