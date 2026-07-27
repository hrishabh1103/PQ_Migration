# Architecture Specification: Enterprise Cryptographic Discovery Platform (PQC Readiness)

## 1. Executive Overview & System Goals

The Enterprise Cryptographic Discovery Platform is a modular, high-assurance system designed to discover, catalog, normalize, and evaluate cryptographic assets across enterprise digital real estate (network endpoints, TLS/SSH services, X.509 certificates, source code repositories, and dependency manifests).

The platform serves as the foundational data collector and normalization engine for Post-Quantum Cryptography (PQC) migration readiness.

### Key Design Principles

1. **Hierarchy-Aware Entity Modeling**:
   Distinct separation between Authorized Targets, Scan Jobs, Discovered Assets (Hosts/Servers/Apps), Discovered Services (Ports/Protocols), Cryptographic Findings (Observations & Provenance), and Normalized Algorithms.

2. **Modular Scanner Plugin Architecture**:
   Scanners implement a common asynchronous interface producing generic `RawFinding` streams. A centralized `ScannerRegistry` decouples scanner implementations from the orchestrator.

3. **Preservation of Observed Algorithm Names**:
   Raw algorithm identifiers (e.g. `Kyber768`, `RSA-2048`, `ECDSA_P256`) are preserved as observed. Canonical standardization (`ML-KEM-768`, `ML-DSA-65`) occurs via explicit normalization mapping without erasing historical or implementation details.

4. **Factual Discovery vs. Risk Interpretation**:
   Scanners output pure, verifiable observations (algorithm, key size, parameters, location, evidence snippet). Risk classification (e.g., migration priority, exposure risk, compliance deadline) occurs downstream in a separate Risk Assessment engine.

5. **Non-Dogmatic Quantum Safety Taxonomy**:
   Categorizes algorithm safety into `QUANTUM_VULNERABLE`, `PQC_STANDARDIZED`, `PQC_CANDIDATE`, `HYBRID`, `SYMMETRIC`, `HASH`, `LEGACY`, `DEPRECATED`, and `UNKNOWN`.

6. **Strict Scope Security & Privacy Safeguards**:
   Active scanners operate only against explicitly authorized targets. Network scanners validate scope before connecting and re-validate IP address range post-DNS resolution. Private key material (PEM blocks, secret keys, tokens) is stripped and redacted at the `Sanitizer` layer before persistence.

---

## 2. Platform Architecture Diagram

```
+-----------------------------------------------------------------------------------+
|                            React + TypeScript Frontend                            |
|             Dashboard  |  Targets  |  Scans  |  Assets  |  Findings           |
+-----------------------------------------------------------------------------------+
                                         |
                                         v HTTP / REST API
+-----------------------------------------------------------------------------------+
|                                 FastAPI REST API                                  |
|         /api/v1/targets | /api/v1/scans | /api/v1/assets | /api/v1/findings          |
+-----------------------------------------------------------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
|                               Discovery Orchestrator                              |
|       - ScopeGuard Authorization Check                                            |
|       - Post-DNS IP Scope Re-validation                                           |
|       - Scanner Selection via ScannerRegistry                                     |
+-----------------------------------------------------------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
|                                 Scanner Plugins                                   |
|   [MockScanner]  (Future: TLSScanner, SSHScanner, CertScanner, SourceCodeScanner)  |
+-----------------------------------------------------------------------------------+
                                         |
                                         v AsyncIterator[RawFinding]
+-----------------------------------------------------------------------------------+
|                                   Sanitizer                                       |
|   - Strips PEM private key headers & secret tokens                                |
|   - Computes evidence SHA-256 hash                                                |
+-----------------------------------------------------------------------------------+
                                         |
                                         v Clean RawFinding
+-----------------------------------------------------------------------------------+
|                              Normalization Engine                                 |
|   - Maps raw_algorithm_name -> canonical_family, canonical_variant, status        |
|   - Links to NormalizedAlgorithm entity                                           |
+-----------------------------------------------------------------------------------+
                                         |
                                         v Entity Persistence Pipeline
+-----------------------------------------------------------------------------------+
|                               PostgreSQL Database                                 |
|  AuthorizedTarget -> ScanJob -> Asset -> Service -> CryptoFinding -> AlgoTaxonomy |
+-----------------------------------------------------------------------------------+
```

---

## 3. Data Model & Entity Hierarchy

```
[AuthorizedTarget]
        │
        └──1:N──► [ScanJob]
                    │
                    └──1:N──► [Asset] (Host, IP, Server, Source Repo)
                                │
                                └──1:N──► [Service] (Port, Transport, App Protocol)
                                            │
                                            └──1:N──► [CryptoFinding] (Observation)
                                                          │
                                                          └──N:1──► [NormalizedAlgorithm]
```

### Entity Schemas

#### 1. AuthorizedTarget
- `id`: UUID (Primary Key)
- `name`: String (Human identifier, e.g. "Internal API Gateway")
- `target_type`: Enum (`HOSTNAME`, `IP_RANGE`, `CIDR`, `URL`, `REPOSITORY`, `CERT_STORE`)
- `target_value`: String (e.g. `demo.internal`, `10.0.0.0/16`)
- `is_authorized`: Boolean (Must be `True` for scanner execution)
- `environment`: String (`PRODUCTION`, `STAGING`, `DEVELOPMENT`)
- `created_at`, `updated_at`: DateTime

#### 2. ScanJob
- `id`: UUID (Primary Key)
- `target_id`: UUID (Foreign Key -> AuthorizedTarget.id)
- `status`: Enum (`PENDING`, `RUNNING`, `COMPLETED`, `FAILED`, `CANCELLED`)
- `requested_scanners`: JSON Array of Scanner IDs (e.g., `["mock-scanner"]`)
- `started_at`, `completed_at`: DateTime (Nullable)
- `error_message`: Text (Nullable)
- `stats_json`: JSONB (`{assets_found: 1, services_found: 1, findings_found: 4}`)

#### 3. Asset
- `id`: UUID (Primary Key)
- `target_id`: UUID (Foreign Key -> AuthorizedTarget.id)
- `hostname`: String (Nullable, e.g., `demo.internal`)
- `ip_address`: String (Nullable, e.g., `127.0.0.1`)
- `asset_type`: Enum (`HOST`, `SERVER`, `APPLICATION`, `SOURCE_REPOSITORY`, `CONTAINER`)
- `environment`: String
- `operating_system`: String (Nullable)
- `metadata_json`: JSONB
- `first_seen_at`, `last_seen_at`: DateTime

#### 4. Service
- `id`: UUID (Primary Key)
- `asset_id`: UUID (Foreign Key -> Asset.id)
- `port`: Integer (Nullable, e.g., `443`)
- `transport_protocol`: Enum (`TCP`, `UDP`, `NONE`)
- `application_protocol`: Enum (`HTTPS`, `TLS`, `SSH`, `HTTP`, `UNKNOWN`)
- `service_name`: String (e.g., `https`)
- `metadata_json`: JSONB (e.g., `{tls_version: "1.3"}`)
- `first_seen_at`, `last_seen_at`: DateTime

#### 5. CryptoFinding
- `id`: UUID (Primary Key)
- `scan_job_id`: UUID (Foreign Key -> ScanJob.id)
- `asset_id`: UUID (Foreign Key -> Asset.id)
- `service_id`: UUID (Foreign Key -> Service.id, Nullable)
- `scanner_id`: String (e.g., `mock-scanner`)
- `scanner_version`: String
- `finding_type`: Enum (`CERTIFICATE_PUBLIC_KEY`, `KEY_EXCHANGE`, `SYMMETRIC_CIPHER`, `HASH_FUNCTION`, `SIGNATURE_ALGORITHM`, `LIBRARY_DEPENDENCY`)
- `raw_algorithm_name`: String (e.g., `RSA`, `X25519`, `AES-256-GCM`, `SHA-384`)
- `normalized_algorithm_id`: String (Foreign Key -> NormalizedAlgorithm.canonical_id)
- `purpose`: Enum (`AUTHENTICATION`, `KEY_EXCHANGE`, `ENCRYPTION`, `INTEGRITY`, `DIGITAL_SIGNATURE`, `UNKNOWN`)
- `location_identifier`: String (e.g., `HTTPS :443 TLS 1.3 Handshake`)
- `evidence_snippet`: Text (Sanitized evidence)
- `evidence_hash`: String (SHA-256 hex digest)
- `confidence`: Enum (`HIGH`, `MEDIUM`, `LOW`)
- `metadata_json`: JSONB
- `first_seen_at`, `last_seen_at`: DateTime

#### 6. NormalizedAlgorithm
- `canonical_id`: String (Primary Key, e.g., `RSA-2048`, `X25519`, `AES-256-GCM`, `SHA-384`, `ML-KEM-768`)
- `name`: String
- `observed_name`: String
- `canonical_family`: String (e.g., `RSA`, `ECC`, `AES`, `SHA2`, `ML-KEM`)
- `canonical_variant`: String (e.g., `RSA-2048`, `X25519`, `ML-KEM-768`)
- `implementation_variant`: String (Nullable, e.g., `Kyber768`)
- `primitive_type`: Enum (`ASYMMETRIC_ENCRYPTION`, `SIGNATURE`, `KEY_EXCHANGE`, `SYMMETRIC`, `HASH`)
- `quantum_safety_status`: Enum (`QUANTUM_VULNERABLE`, `PQC_STANDARDIZED`, `PQC_CANDIDATE`, `HYBRID`, `SYMMETRIC`, `HASH`, `LEGACY`, `DEPRECATED`, `UNKNOWN`)
- `estimated_security_bits`: Integer
- `nist_standard_status`: String

---

## 4. Scanner Plugin Interface & Architecture

All discovery scanners inherit from `Scanner` abstract base class and register with `ScannerRegistry`.

```python
from abc import ABC, abstractmethod
from typing import AsyncIterator, Set
from pydantic import BaseModel

class RawFinding(BaseModel):
    asset_hostname: str | None = None
    asset_ip: str | None = None
    asset_type: str = "HOST"
    port: int | None = None
    transport_protocol: str = "TCP"
    application_protocol: str = "HTTPS"
    service_name: str = "https"
    finding_type: str
    raw_algorithm_name: str
    key_size: int | None = None
    curve_or_parameter: str | None = None
    purpose: str = "UNKNOWN"
    location_identifier: str
    evidence_snippet: str
    confidence: str = "HIGH"
    metadata: dict = {}

class Scanner(ABC):
    scanner_id: str
    version: str
    supported_target_types: Set[str]

    @abstractmethod
    async def discover(
        self,
        target: AuthorizedTarget,
        context: ScanContext
    ) -> AsyncIterator[RawFinding]:
        pass
```

### Sanitizer Pipeline Guardrails
1. Receives `RawFinding`.
2. Inspects `evidence_snippet` and `metadata` for string or byte patterns matching private key material (PEM headers `-----BEGIN *PRIVATE KEY-----`).
3. Replaces matches with `[REDACTED PRIVATE KEY MATERIAL]`.
4. Computes SHA-256 `evidence_hash` of sanitized evidence.

### Scope Security Enforcement
- Scanners will only execute if `target.is_authorized` is `True`.
- Network/Host target scan context executes:
  1. Scope validation of raw target string.
  2. DNS resolution for hostname targets.
  3. IP range validation of resolved addresses against target boundaries.
  4. Connection initialization.

---

## 5. API Contracts (FastAPI REST)

- `GET /api/v1/health`: System status.
- `POST /api/v1/targets`: Register authorized target.
- `GET /api/v1/targets`: List targets.
- `GET /api/v1/targets/{id}`: Target details.
- `POST /api/v1/scans`: Trigger scan job.
- `GET /api/v1/scans`: List scan jobs.
- `GET /api/v1/scans/{id}`: Scan job details & statistics.
- `GET /api/v1/assets`: List assets with filtering.
- `GET /api/v1/assets/{id}`: Asset details with Service & Finding hierarchy.
- `GET /api/v1/findings`: List cryptographic findings.
- `GET /api/v1/findings/{id}`: Finding details & provenance.

---

## 6. Frontend Dashboard (React + TypeScript + Tailwind)

Components:
- **Dashboard**: Asset count, service count, crypto finding count, scan job count, algorithm distribution breakdown, scan status distribution.
- **Targets Page & Modal**: List targets, create new target.
- **Scans Page & Detail**: List scan jobs, launch new scan, detailed scan status view.
- **Assets Page & Detail**: Interactive asset tree showing Asset -> Service -> CryptoFinding.
- **Findings Table**: Detailed tabular list of findings with search/filter.
