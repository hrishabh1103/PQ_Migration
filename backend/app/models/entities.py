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

class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    target_id: Mapped[str] = mapped_column(String(36), ForeignKey("authorized_targets.id"), nullable=False)
    hostname: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    asset_type: Mapped[AssetType] = mapped_column(SQLEnum(AssetType), default=AssetType.HOST, nullable=False)
    environment: Mapped[str] = mapped_column(String(64), default="DEVELOPMENT", nullable=False)
    operating_system: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False)

    target: Mapped["AuthorizedTarget"] = relationship("AuthorizedTarget", back_populates="assets")
    services: Mapped[List["Service"]] = relationship("Service", back_populates="asset", cascade="all, delete-orphan")
    findings: Mapped[List["CryptoFinding"]] = relationship("CryptoFinding", back_populates="asset", cascade="all, delete-orphan")

class Service(Base):
    __tablename__ = "services"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    asset_id: Mapped[str] = mapped_column(String(36), ForeignKey("assets.id"), nullable=False)
    port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    transport_protocol: Mapped[TransportProtocol] = mapped_column(SQLEnum(TransportProtocol), default=TransportProtocol.TCP, nullable=False)
    application_protocol: Mapped[ApplicationProtocol] = mapped_column(SQLEnum(ApplicationProtocol), default=ApplicationProtocol.HTTPS, nullable=False)
    service_name: Mapped[str] = mapped_column(String(64), default="https", nullable=False)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False)

    asset: Mapped["Asset"] = relationship("Asset", back_populates="services")
    findings: Mapped[List["CryptoFinding"]] = relationship("CryptoFinding", back_populates="service", cascade="all, delete-orphan")

class NormalizedAlgorithm(Base):
    __tablename__ = "normalized_algorithms"

    canonical_id: Mapped[str] = mapped_column(String(64), primary_key=True)  # e.g. "RSA-2048", "X25519"
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    observed_name: Mapped[str] = mapped_column(String(128), nullable=False)
    canonical_family: Mapped[str] = mapped_column(String(64), nullable=False) # e.g. "RSA", "ML-KEM"
    canonical_variant: Mapped[str] = mapped_column(String(64), nullable=False) # e.g. "RSA-2048", "ML-KEM-768"
    implementation_variant: Mapped[Optional[str]] = mapped_column(String(64), nullable=True) # e.g. "Kyber768"
    primitive_type: Mapped[PrimitiveType] = mapped_column(SQLEnum(PrimitiveType), nullable=False)
    quantum_safety_status: Mapped[QuantumSafetyStatus] = mapped_column(SQLEnum(QuantumSafetyStatus), nullable=False)
    estimated_security_bits: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    nist_standard_status: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)

    findings: Mapped[List["CryptoFinding"]] = relationship("CryptoFinding", back_populates="normalized_algorithm")

class CryptoFinding(Base):
    __tablename__ = "crypto_findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_job_id: Mapped[str] = mapped_column(String(36), ForeignKey("scan_jobs.id"), nullable=False)
    asset_id: Mapped[str] = mapped_column(String(36), ForeignKey("assets.id"), nullable=False)
    service_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("services.id"), nullable=True)
    scanner_id: Mapped[str] = mapped_column(String(64), nullable=False)
    scanner_version: Mapped[str] = mapped_column(String(32), default="1.0.0", nullable=False)
    finding_type: Mapped[FindingType] = mapped_column(SQLEnum(FindingType), nullable=False)
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
