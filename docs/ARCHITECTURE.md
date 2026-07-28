# Architecture Specification: Enterprise Cryptographic Discovery Platform (Foundation V2.1 Hardened)

## 1. Executive Overview & System Goals

The Enterprise Cryptographic Discovery Platform is a modular, high-assurance system designed to discover, catalog, normalize, and evaluate cryptographic assets across enterprise digital real estate (network endpoints, TLS/SSH services, X.509 certificates, source code repositories, and dependency lockfiles).

The platform serves as the foundational data collector, normalization engine, and contextual risk assessment platform for Post-Quantum Cryptography (PQC) migration readiness.

---

## 2. Hardened V2.1 Architecture Hierarchy

```
+-----------------------------------------------------------------------------------+
|                            React + TypeScript Frontend                            |
|    Dashboard | Inventory Graph | Cloud Servers | API Hub | Scans | Assets | Reports|
+-----------------------------------------------------------------------------------+
                                         |
                                         v REST API
+-----------------------------------------------------------------------------------+
|                                 FastAPI REST API                                  |
|   /api/v1/targets | /api/v1/scans | /api/v1/assets | /api/v1/relationships        |
|   /api/v1/graph   | /api/v1/crypto-objects | /api/v1/data | /api/v1/coverage       |
+-----------------------------------------------------------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
|                           Plugin & Capability Architecture                        |
|                     PluginRegistry | CapabilityRegistry                           |
|       - Scanner  (Active/Direct Scanners: TLS, SSH, X.509, Source, Dep)           |
|       - Connector (External Inventory APIs: AWS, GCP, Azure, K8s, PKI)             |
|       - Collector (Installed Agents, Telemetry, Passive Monitoring)               |
+-----------------------------------------------------------------------------------+
                                         |
                                         v DiscoveryRun & RawFinding Stream
+-----------------------------------------------------------------------------------+
|                           Sanitizer & Provenance Pipeline                         |
|   - Strips PEM private key headers & secret tokens (Zero Private Key Collection)  |
|   - Creates Provenance record (collection_method, evidence_hash, discovery_run_id)|
+-----------------------------------------------------------------------------------+
                                         |
                                         v Clean RawFinding & Provenance
+-----------------------------------------------------------------------------------+
|                     Normalization Engine & Identity Resolution                    |
|   - Maps raw_algorithm_name -> canonical_family, canonical_variant, status        |
|   - Deterministic Asset Resolution (provider_resource_id > external_id > key)     |
|   - Deterministic CryptoObject deduplication & Cert fingerprint normalization     |
+-----------------------------------------------------------------------------------+
                                         |
                                         v Entity Persistence Pipeline
+-----------------------------------------------------------------------------------+
|                           Enterprise PostgreSQL Database                          |
|  Asset <--> Service <--> CryptoObject <--> Relationship <--> DataAsset/DataFlow   |
|                       Linked to Provenance & DiscoveryRun                         |
+-----------------------------------------------------------------------------------+
```

---

## 3. Capability & Plugin Domain Status Matrix

| Plugin Domain / Module | Type | Status | Description |
| :--- | :--- | :--- | :--- |
| **TLS & Network Scanner (`TLSScanner`)** | `Scanner` | `IMPLEMENTED` | Performs active TLS handshakes over TCP port 443; extracts server certificates, public key algorithms, and negotiated cipher suites. |
| **SSH Host Scanner (`SSHScanner`)** | `Scanner` | `IMPLEMENTED` | Connects to TCP port 22 to inspect SSH server banners, Host Key algorithms (`rsa-sha2-512`, `ssh-ed25519`), and KEX algorithms. |
| **X.509 Certificate Scanner (`CertificateScanner`)** | `Scanner` | `IMPLEMENTED` | Scans local certificate stores on disk (`.crt`, `.pem`, `.cer`), extracting Subject/Issuer names, validity, and key usage. |
| **Source Code AST Scanner (`SourceCodeScanner`)** | `Scanner` | `IMPLEMENTED` | Scans source code files (`.py`, `.js`, `.ts`, `.go`, `.java`, `.cpp`, `.rs`) for AST cryptographic call sites. |
| **Package Dependency Scanner (`DependencyScanner`)** | `Scanner` | `IMPLEMENTED` | Identifies package dependencies in manifest lockfiles (`package.json`, `requirements.txt`, `go.mod`, `Cargo.toml`). |
| **Cloud Server Scanner (`CloudServerScanner`)** | `Scanner` | `IMPLEMENTED` | Audits Cloud VMs, SSH host keys, Cloud Load Balancer TLS policies, Cloud KMS keys, and S3/GCS bucket storage encryption. |
| **Plugin Architecture Core** | Core | `FOUNDATION READY` | `DiscoveryPlugin` base class, `Scanner`/`Connector`/`Collector` hierarchy, `PluginRegistry`, and `CapabilityRegistry`. |
| **Generic Relationship Model & Bounded Graph API** | Core | `FOUNDATION READY` | `Relationship` entity with 16+ relationship types, `(entity_type, entity_id)` strict matching, depth limits (`depth=1..3`), and edge deduplication. |
| **Provenance & DiscoveryRun Pipeline** | Core | `FOUNDATION READY` | `Provenance` model (`collection_method`, `evidence_hash`, `discovery_run_id`, secret redaction) linked to findings and discovery runs. |
| **CryptoObject Identity & Deduplication** | Core | `FOUNDATION READY` | `CryptoObject` model with deterministic `identity_key` deduplication, `IntegrityError` rollback handling, and normalized cert fingerprints. |
| **DataAsset & DataFlow Models** | Core | `FOUNDATION READY` | `DataAsset` & `DataFlow` models for tracking sensitive data flows across cryptographic channels. |
| **DiscoveryCoverage Lifecycle** | Core | `FOUNDATION READY` | Auto-updates coverage state (`NOT_SCANNED` → `IN_PROGRESS` → `SCANNED` / `FAILED` / `PARTIALLY_SCANNED`). |
| **Contextual Risk Engine** | Core | `FOUNDATION READY` | `ContextualRiskEngine` with neutral defaults (`UNKNOWN`), contextual confidence score (`HIGH`/`MEDIUM`/`LOW`), and explicit factor rationales. |
| **AWS Connector (`AWSConnector`)** | `Connector` | `PLANNED` | Direct AWS API connector for EC2, KMS, ALB, and ECR discovery. |
| **Azure Connector (`AzureConnector`)** | `Connector` | `PLANNED` | Azure Key Vault, App Service, and Virtual Machine API connector. |
| **GCP Connector (`GCPConnector`)** | `Connector` | `PLANNED` | Google Cloud Compute Engine, Cloud KMS, and GKE API connector. |
| **Kubernetes Connector (`KubernetesConnector`)** | `Connector` | `PLANNED` | Kubernetes API reader for Ingress TLS secrets, Service Accounts, and Cert-Manager objects. |
| **Linux Agent Collector (`LinuxCollector`)** | `Collector` | `PLANNED` | Endpoint inventory collector for Linux OpenSSL / GnuTLS system crypto policies. |
| **Windows Endpoint Collector (`WindowsCollector`)** | `Collector` | `PLANNED` | Endpoint inventory collector for Windows Schannel, CAPI, and CNG crypto providers. |
| **Network Device Connector (`NetworkDeviceConnector`)** | `Connector` | `PLANNED` | SSH/NETCONF connector for routers, switches, firewalls, and VPN gateways. |
| **IPsec & IKE Scanner (`IPsecScanner`)** | `Scanner` | `PLANNED` | Scanner for IPsec IKEv1/IKEv2 proposal negotiation and SA parameters. |
| **PKI & CA Connector (`PKIConnector`)** | `Connector` | `PLANNED` | Connector for EJBCA, Microsoft AD CS, HashiCorp Vault PKI, and Let's Encrypt ACME. |
| **KMS Connector (`KMSConnector`)** | `Connector` | `PLANNED` | Direct KMS connector for AWS KMS, GCP KMS, Vault Transit secrets engine. |
| **HSM Connector (`HSMConnector`)** | `Connector` | `PLANNED` | PKCS#11 / KMIP connector for hardware security modules (nCipher, Thales, AWS CloudHSM). |
| **Database Crypto Connector (`DatabaseConnector`)** | `Connector` | `PLANNED` | Audits TLS connections, Transparent Data Encryption (TDE), and column-level encryption in databases. |
| **Identity System Connector (`IdentityConnector`)** | `Connector` | `PLANNED` | Inspects SAML, OAuth/OIDC, Kerberos, and LDAP signing/encryption certificate keys. |
| **CI/CD Pipeline Connector (`CICDConnector`)** | `Connector` | `PLANNED` | Inspects GitHub Actions, GitLab CI, and Jenkins code signing certificates and secrets. |
| **Passive Network Collector (`PassiveNetworkCollector`)** | `Collector` | `PLANNED` | SPAN/TAP passive packet capture for TLS Server Name Indication (SNI) and cipher suite negotiation. |
| **IoT & OT Device Collector (`IoTCollector`/`OTCollector`)** | `Collector` | `PLANNED` | Discovers embedded device firmware crypto primitives and Modbus/DNP3 TLS profiles. |

---

## 4. Key Data Models (V2.1 Spec)

### 1. Asset (Extensible Taxonomy & Identity Resolution)
- `id`: String(36) UUID
- `target_id`: String(36) FK
- `hostname`, `ip_address`: Optional String
- `asset_type`: String (e.g. `HOST`, `VM`, `SERVER`, `APPLICATION`, `ROUTER`, `LOAD_BALANCER`, `KMS`)
- `asset_category`: String (e.g. `INFRASTRUCTURE`, `CLOUD`, `DATA`)
- `asset_subtype`, `taxonomy_namespace`: Optional String
- `identity_key`: String (indexed identity resolution key)
- `external_id`, `provider_resource_id`, `provider`, `region`, `account_or_tenant_id`: Cloud/Enterprise Metadata
- `status`: String (`ACTIVE`, `STALE`, `REMOVED`, `UNKNOWN`)
- `first_seen_at`, `last_seen_at`: DateTime

### 2. Provenance (Auditable Evidence Trail)
- `id`: String(36) UUID
- `discovery_run_id`: String(36) FK to `discovery_runs.id`
- `target_id`: String(36) FK to `authorized_targets.id`
- `plugin_id`, `plugin_version`: String
- `collection_method`: String (`ACTIVE`, `PASSIVE`, `API`, `AGENT`, `IMPORT`, `STATIC_ANALYSIS`)
- `observed_at`: DateTime
- `evidence_type`, `evidence_hash`, `confidence`: String
- `metadata_json`: JSON (Zero Secrets Policy)

### 3. Relationship (Strict Pair Graph Edge)
- `id`: String(36) UUID
- `source_entity_type`, `source_entity_id`: String (Strict matching pair)
- `target_entity_type`, `target_entity_id`: String (Strict matching pair)
- `relationship_type`: String (`RUNS_ON`, `DEPLOYED_IN`, `CONNECTS_TO`, `DEPENDS_ON`, `USES`, `PROTECTS`, `AUTHENTICATES_WITH`, `SIGNED_BY`, `ISSUED_BY`, `STORES_KEY_IN`, `TERMINATES_TLS_AT`, `EXPOSED_BY`, `ENCRYPTED_BY`, `MANAGED_BY`, `CONTAINS`, `COMMUNICATES_WITH`)
- `provenance_id`, `discovery_run_id`: Foreign Keys
- `scanner_or_connector_id`, `evidence_snippet`, `evidence_hash`, `confidence`, `status`
