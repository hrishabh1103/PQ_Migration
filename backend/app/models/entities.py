import uuid
from datetime import datetime, timezone
from typing import Optional, List
from sqlalchemy import (
    String, Boolean, Integer, DateTime, ForeignKey, Text, JSON, Enum as SQLEnum
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
import enum

from app.core.database import Base

def utc_now():
    return datetime.now(timezone.utc)

class TargetType(str, enum.Enum):
    HOSTNAME = "HOSTNAME"
    IP_RANGE = "IP_RANGE"
    CIDR = "CIDR"
    URL = "URL"
    REPOSITORY = "REPOSITORY"
    CERT_STORE = "CERT_STORE"
    CLOUD_PROVIDER = "CLOUD_PROVIDER"
    CLOUD_SERVER = "CLOUD_SERVER"
    CLOUD_KMS = "CLOUD_KMS"
    CONTAINER_REGISTRY = "CONTAINER_REGISTRY"
    KUBERNETES_CLUSTER = "KUBERNETES_CLUSTER"

class ScanStatus(str, enum.Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"

class AssetType(str, enum.Enum):
    HOST = "HOST"
    SERVER = "SERVER"
    APPLICATION = "APPLICATION"
    SOURCE_REPOSITORY = "SOURCE_REPOSITORY"
    CONTAINER = "CONTAINER"
    CLOUD_VM = "CLOUD_VM"
    CLOUD_INSTANCE = "CLOUD_INSTANCE"
    KMS_KEY = "KMS_KEY"
    CLOUD_BUCKET = "CLOUD_BUCKET"
    KUBERNETES_CLUSTER = "KUBERNETES_CLUSTER"
    KUBERNETES_NAMESPACE = "KUBERNETES_NAMESPACE"
    KUBERNETES_WORKLOAD = "KUBERNETES_WORKLOAD"
    KUBERNETES_POD = "KUBERNETES_POD"
    KUBERNETES_SERVICE = "KUBERNETES_SERVICE"
    KUBERNETES_INGRESS = "KUBERNETES_INGRESS"
    
    # Canonical Multi-Cloud Hierarchy & Asset Taxonomy
    CLOUD_ORGANIZATION = "CLOUD_ORGANIZATION"
    CLOUD_TENANT = "CLOUD_TENANT"
    CLOUD_SUBSCRIPTION = "CLOUD_SUBSCRIPTION"
    CLOUD_PROJECT = "CLOUD_PROJECT"
    CLOUD_RESOURCE_GROUP = "CLOUD_RESOURCE_GROUP"
    CLOUD_FOLDER = "CLOUD_FOLDER"
    CLOUD_ACCOUNT = "CLOUD_ACCOUNT"
    CLOUD_REGION = "CLOUD_REGION"
    CLOUD_ZONE = "CLOUD_ZONE"
    
    COMPUTE_INSTANCE = "COMPUTE_INSTANCE"
    BLOCK_STORAGE = "BLOCK_STORAGE"
    OBJECT_STORAGE = "OBJECT_STORAGE"
    MANAGED_DATABASE = "MANAGED_DATABASE"
    
    LOAD_BALANCER = "LOAD_BALANCER"
    TLS_TERMINATOR = "TLS_TERMINATOR"
    CDN = "CDN"
    NETWORK = "NETWORK"
    SUBNET = "SUBNET"
    PUBLIC_ENDPOINT = "PUBLIC_ENDPOINT"
    
    MANAGED_KEY = "MANAGED_KEY"
    HSM = "HSM"
    CERTIFICATE_STORE = "CERTIFICATE_STORE"
    SECRET_STORE = "SECRET_STORE"
    IDENTITY = "IDENTITY"
    SERVICE_IDENTITY = "SERVICE_IDENTITY"

class TransportProtocol(str, enum.Enum):
    TCP = "TCP"
    UDP = "UDP"
    NONE = "NONE"

class ApplicationProtocol(str, enum.Enum):
    HTTPS = "HTTPS"
    TLS = "TLS"
    SSH = "SSH"
    HTTP = "HTTP"
    UNKNOWN = "UNKNOWN"

class FindingType(str, enum.Enum):
    CERTIFICATE_PUBLIC_KEY = "CERTIFICATE_PUBLIC_KEY"
    KEY_EXCHANGE = "KEY_EXCHANGE"
    SYMMETRIC_CIPHER = "SYMMETRIC_CIPHER"
    HASH_FUNCTION = "HASH_FUNCTION"
    SIGNATURE_ALGORITHM = "SIGNATURE_ALGORITHM"
    LIBRARY_DEPENDENCY = "LIBRARY_DEPENDENCY"
    ALGORITHM = "ALGORITHM"
    CERTIFICATE = "CERTIFICATE"

class FindingPurpose(str, enum.Enum):
    AUTHENTICATION = "AUTHENTICATION"
    KEY_EXCHANGE = "KEY_EXCHANGE"
    ENCRYPTION = "ENCRYPTION"
    INTEGRITY = "INTEGRITY"
    DIGITAL_SIGNATURE = "DIGITAL_SIGNATURE"
    UNKNOWN = "UNKNOWN"

class FindingConfidence(str, enum.Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

class QuantumSafetyStatus(str, enum.Enum):
    QUANTUM_VULNERABLE = "QUANTUM_VULNERABLE"
    PQC_STANDARDIZED = "PQC_STANDARDIZED"
    PQC_CANDIDATE = "PQC_CANDIDATE"
    HYBRID = "HYBRID"
    SYMMETRIC = "SYMMETRIC"
    HASH = "HASH"
    LEGACY = "LEGACY"
    DEPRECATED = "DEPRECATED"
    UNKNOWN = "UNKNOWN"

class PrimitiveType(str, enum.Enum):
    ASYMMETRIC_ENCRYPTION = "ASYMMETRIC_ENCRYPTION"
    SIGNATURE = "SIGNATURE"
    KEY_EXCHANGE = "KEY_EXCHANGE"
    SYMMETRIC = "SYMMETRIC"
    HASH = "HASH"

class AuthorizedTarget(Base):
    __tablename__ = "authorized_targets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    target_type: Mapped[TargetType] = mapped_column(SQLEnum(TargetType), nullable=False)
    target_value: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    is_authorized: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    environment: Mapped[str] = mapped_column(String(64), default="DEVELOPMENT", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False)

    scans: Mapped[List["ScanJob"]] = relationship("ScanJob", back_populates="target", cascade="all, delete-orphan")
    assets: Mapped[List["Asset"]] = relationship("Asset", back_populates="target", cascade="all, delete-orphan")

class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    target_id: Mapped[str] = mapped_column(String(36), ForeignKey("authorized_targets.id"), nullable=False)
    status: Mapped[ScanStatus] = mapped_column(SQLEnum(ScanStatus), default=ScanStatus.PENDING, nullable=False)
    requested_scanners: Mapped[dict] = mapped_column(JSON, default=list, nullable=False)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    stats_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)

    target: Mapped["AuthorizedTarget"] = relationship("AuthorizedTarget", back_populates="scans")
    findings: Mapped[List["CryptoFinding"]] = relationship("CryptoFinding", back_populates="scan_job", cascade="all, delete-orphan")

class DiscoveryRun(Base):
    __tablename__ = "discovery_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    run_type: Mapped[str] = mapped_column(String(32), default="SCAN", nullable=False) # SCAN, SYNC, COLLECTION, IMPORT, PASSIVE_INGESTION
    plugin_id: Mapped[str] = mapped_column(String(64), nullable=False)
    plugin_version: Mapped[str] = mapped_column(String(32), default="1.0.0", nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="PENDING", nullable=False)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    stats_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

class Provenance(Base):
    __tablename__ = "provenance"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    discovery_run_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("discovery_runs.id"), nullable=True)
    target_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("authorized_targets.id"), nullable=True)
    plugin_id: Mapped[str] = mapped_column(String(64), nullable=False)
    plugin_version: Mapped[str] = mapped_column(String(32), default="1.0.0", nullable=False)
    collection_method: Mapped[str] = mapped_column(String(32), default="ACTIVE", nullable=False) # ACTIVE, PASSIVE, API, AGENT, IMPORT, STATIC_ANALYSIS
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    evidence_type: Mapped[str] = mapped_column(String(64), default="OBSERVATION", nullable=False)
    evidence_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    confidence: Mapped[str] = mapped_column(String(16), default="HIGH", nullable=False)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)

class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    target_id: Mapped[str] = mapped_column(String(36), ForeignKey("authorized_targets.id"), nullable=False)
    hostname: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    
    # Extensible Asset Taxonomy
    asset_type: Mapped[str] = mapped_column(String(64), default="HOST", nullable=False, index=True)
    asset_category: Mapped[str] = mapped_column(String(64), default="INFRASTRUCTURE", nullable=False, index=True)
    asset_subtype: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    taxonomy_namespace: Mapped[Optional[str]] = mapped_column(String(64), default="enterprise_v2", nullable=True)
    
    # Identity & Enterprise Metadata
    identity_key: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    external_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    provider_resource_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    provider: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    region: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    account_or_tenant_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)

    # Environment & Lifecycle
    environment: Mapped[str] = mapped_column(String(64), default="DEVELOPMENT", nullable=False)
    operating_system: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="ACTIVE", nullable=False, index=True) # ACTIVE, STALE, REMOVED, UNKNOWN
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False)

    target: Mapped["AuthorizedTarget"] = relationship("AuthorizedTarget", back_populates="assets")
    services: Mapped[List["Service"]] = relationship("Service", back_populates="asset", cascade="all, delete-orphan")
    findings: Mapped[List["CryptoFinding"]] = relationship("CryptoFinding", back_populates="asset", cascade="all, delete-orphan")
    coverage_records: Mapped[List["DiscoveryCoverage"]] = relationship("DiscoveryCoverage", back_populates="asset", cascade="all, delete-orphan")

class Service(Base):
    __tablename__ = "services"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    asset_id: Mapped[str] = mapped_column(String(36), ForeignKey("assets.id"), nullable=False)
    port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    transport_protocol: Mapped[TransportProtocol] = mapped_column(SQLEnum(TransportProtocol), default=TransportProtocol.TCP, nullable=False)
    application_protocol: Mapped[ApplicationProtocol] = mapped_column(SQLEnum(ApplicationProtocol), default=ApplicationProtocol.HTTPS, nullable=False)
    service_name: Mapped[str] = mapped_column(String(64), default="https", nullable=False)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="ACTIVE", nullable=False)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False)

    asset: Mapped["Asset"] = relationship("Asset", back_populates="services")
    findings: Mapped[List["CryptoFinding"]] = relationship("CryptoFinding", back_populates="service", cascade="all, delete-orphan")

class NormalizedAlgorithm(Base):
    __tablename__ = "normalized_algorithms"

    canonical_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    observed_name: Mapped[str] = mapped_column(String(128), nullable=False)
    canonical_family: Mapped[str] = mapped_column(String(64), nullable=False)
    canonical_variant: Mapped[str] = mapped_column(String(64), nullable=False)
    implementation_variant: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    primitive_type: Mapped[PrimitiveType] = mapped_column(SQLEnum(PrimitiveType), nullable=False)
    quantum_safety_status: Mapped[QuantumSafetyStatus] = mapped_column(SQLEnum(QuantumSafetyStatus), nullable=False)
    estimated_security_bits: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    nist_standard_status: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)

    findings: Mapped[List["CryptoFinding"]] = relationship("CryptoFinding", back_populates="normalized_algorithm")

class CryptoObject(Base):
    __tablename__ = "crypto_objects"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    object_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True) # ALGORITHM, KEY, CERTIFICATE, PROTOCOL, LIBRARY, CRYPTO_MODULE, KEYSTORE
    canonical_name: Mapped[str] = mapped_column(String(255), nullable=False)
    provider: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    version: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    
    identity_key: Mapped[str] = mapped_column(String(255), nullable=False, index=True, unique=True)
    fingerprint: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    external_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    provider_resource_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    provenance_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("provenance.id"), nullable=True)
    discovery_run_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("discovery_runs.id"), nullable=True)

    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="ACTIVE", nullable=False) # ACTIVE, STALE, REMOVED, UNKNOWN
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False)

    findings: Mapped[List["CryptoFinding"]] = relationship("CryptoFinding", back_populates="crypto_object")

class CryptoFinding(Base):
    __tablename__ = "crypto_findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_job_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("scan_jobs.id"), nullable=True)
    discovery_run_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("discovery_runs.id"), nullable=True)
    provenance_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("provenance.id"), nullable=True)

    asset_id: Mapped[str] = mapped_column(String(36), ForeignKey("assets.id"), nullable=False)
    service_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("services.id"), nullable=True)
    crypto_object_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("crypto_objects.id"), nullable=True)
    
    scanner_id: Mapped[str] = mapped_column(String(64), nullable=False)
    scanner_version: Mapped[str] = mapped_column(String(32), default="1.0.0", nullable=False)
    finding_type: Mapped[str] = mapped_column(String(64), nullable=False)
    raw_algorithm_name: Mapped[str] = mapped_column(String(128), nullable=False)
    normalized_algorithm_id: Mapped[str] = mapped_column(String(64), ForeignKey("normalized_algorithms.canonical_id"), nullable=False)
    purpose: Mapped[FindingPurpose] = mapped_column(SQLEnum(FindingPurpose), default=FindingPurpose.UNKNOWN, nullable=False)
    location_identifier: Mapped[str] = mapped_column(String(512), nullable=False)
    evidence_snippet: Mapped[str] = mapped_column(Text, nullable=False)
    evidence_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    confidence: Mapped[FindingConfidence] = mapped_column(SQLEnum(FindingConfidence), default=FindingConfidence.HIGH, nullable=False)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False)

    scan_job: Mapped["ScanJob"] = relationship("ScanJob", back_populates="findings")
    asset: Mapped["Asset"] = relationship("Asset", back_populates="findings")
    service: Mapped[Optional["Service"]] = relationship("Service", back_populates="findings")
    normalized_algorithm: Mapped["NormalizedAlgorithm"] = relationship("NormalizedAlgorithm", back_populates="findings")
    crypto_object: Mapped[Optional["CryptoObject"]] = relationship("CryptoObject", back_populates="findings")
    provenance: Mapped[Optional["Provenance"]] = relationship("Provenance")

class Relationship(Base):
    __tablename__ = "relationships"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    source_entity_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    source_entity_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    target_entity_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    target_entity_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    
    relationship_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    scanner_or_connector_id: Mapped[str] = mapped_column(String(64), nullable=False)
    provenance_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("provenance.id"), nullable=True)
    discovery_run_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("discovery_runs.id"), nullable=True)

    evidence_snippet: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    evidence_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    confidence: Mapped[str] = mapped_column(String(16), default="HIGH", nullable=False)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="ACTIVE", nullable=False)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False)

class DataAsset(Base):
    __tablename__ = "data_assets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    classification: Mapped[str] = mapped_column(String(64), default="CONFIDENTIAL", nullable=False)
    required_confidentiality_until: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    retention_period: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    business_criticality: Mapped[str] = mapped_column(String(32), default="MEDIUM", nullable=False)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="ACTIVE", nullable=False)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False)

class DataFlow(Base):
    __tablename__ = "data_flows"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    source_entity_type: Mapped[str] = mapped_column(String(64), nullable=False)
    source_entity_id: Mapped[str] = mapped_column(String(64), nullable=False)
    destination_entity_type: Mapped[str] = mapped_column(String(64), nullable=False)
    destination_entity_id: Mapped[str] = mapped_column(String(64), nullable=False)
    
    data_asset_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("data_assets.id"), nullable=True)
    protocol: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    crypto_object_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("crypto_objects.id"), nullable=True)
    provenance_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("provenance.id"), nullable=True)

    protection_purpose: Mapped[str] = mapped_column(String(64), default="ENCRYPTION", nullable=False)
    direction: Mapped[str] = mapped_column(String(32), default="INBOUND", nullable=False)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="ACTIVE", nullable=False)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False)

class DiscoveryCoverage(Base):
    __tablename__ = "discovery_coverage"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    asset_id: Mapped[str] = mapped_column(String(36), ForeignKey("assets.id"), nullable=False, index=True)
    capability: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    plugin_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    discovery_run_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("discovery_runs.id"), nullable=True)
    
    status: Mapped[str] = mapped_column(String(32), default="NOT_SCANNED", nullable=False) # UNKNOWN, NOT_SCANNED, IN_PROGRESS, SCANNED, PARTIALLY_SCANNED, FAILED, NOT_APPLICABLE
    findings_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_evaluated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)

    asset: Mapped["Asset"] = relationship("Asset", back_populates="coverage_records")

class CorrelationRecord(Base):
    __tablename__ = "correlation_records"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    source_entity_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    source_entity_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    target_entity_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    target_entity_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    decision: Mapped[str] = mapped_column(String(32), nullable=False) # IDENTICAL, LIKELY_SAME, RELATED, UNRESOLVED, CONFLICTING
    confidence: Mapped[str] = mapped_column(String(32), default="MEDIUM", nullable=False) # HIGH, MEDIUM, LOW
    matching_evidence_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    conflicting_evidence_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    
    rule_id: Mapped[str] = mapped_column(String(64), default="rule-default", nullable=False)
    rule_version: Mapped[str] = mapped_column(String(32), default="v1.0", nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="ACTIVE", nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False)

class AssessmentRun(Base):
    __tablename__ = "assessment_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    policy_id: Mapped[str] = mapped_column(String(64), default="pqc-default", nullable=False)
    policy_version: Mapped[str] = mapped_column(String(32), default="v1.0", nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="RUNNING", nullable=False) # RUNNING, COMPLETED, FAILED
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    evaluated_entity_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    failed_entity_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)

    assessments: Mapped[List["ReadinessAssessment"]] = relationship("ReadinessAssessment", back_populates="assessment_run")

class ReadinessAssessment(Base):
    __tablename__ = "readiness_assessments"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    assessment_run_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("assessment_runs.id"), nullable=True, index=True)
    target_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("authorized_targets.id"), nullable=True, index=True)
    asset_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("assets.id"), nullable=True, index=True)

    policy_id: Mapped[str] = mapped_column(String(64), default="pqc-default", nullable=False)
    policy_version: Mapped[str] = mapped_column(String(32), default="v1.0", nullable=False)

    readiness_result: Mapped[str] = mapped_column(String(32), nullable=False) # READY, PARTIALLY_READY, NOT_READY, INCOMPLETE_COVERAGE, UNKNOWN
    quantum_exposure: Mapped[str] = mapped_column(String(32), nullable=False) # QUANTUM_VULNERABLE, QUANTUM_RESISTANT, HYBRID, NOT_APPLICABLE, UNKNOWN
    
    migration_priority_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    migration_category: Mapped[str] = mapped_column(String(32), default="LOW", nullable=False) # CRITICAL, HIGH, MEDIUM, LOW, NEGLIGIBLE
    confidence: Mapped[str] = mapped_column(String(32), default="MEDIUM", nullable=False)

    known_factors_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    unknown_factors_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    factor_breakdown_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    rationale: Mapped[str] = mapped_column(Text, default="", nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)

    assessment_run: Mapped[Optional["AssessmentRun"]] = relationship("AssessmentRun", back_populates="assessments")

