# Enterprise Cryptographic Discovery Platform (PQC Migration Readiness)

An enterprise-grade cryptographic discovery, inventory, normalization, risk assessment, and Cryptographic Bill of Materials (CBOM) generation platform for Post-Quantum Cryptography (PQC) migration readiness.

```
                                  +---------------------------------------+
                                  | React + TypeScript + Tailwind UI      |
                                  | Dashboard, Targets, Scans, Reports    |
                                  +---------------------------------------+
                                                      |
                                                      v REST API (FastAPI)
                                  +---------------------------------------+
                                  |        FastAPI REST API Server        |
                                  +---------------------------------------+
                                                      |
                                                      v
                                  +---------------------------------------+
                                  |         DiscoveryOrchestrator         |
                                  +---------------------------------------+
                                                      |
                                                      v ScopeGuard Validation
                                  +---------------------------------------+
                                  |            ScannerRegistry            |
                                  | TLS, SSH, Cert, Source, Dep Scanners  |
                                  +---------------------------------------+
                                                      |
                                                      v RawFinding (AsyncIterator)
                                  +---------------------------------------+
                                  |               Sanitizer               |
                                  | Redacts PEM/Private Keys & Secrets    |
                                  +---------------------------------------+
                                                      |
                                                      v Clean RawFinding
                                  +---------------------------------------+
                                  |          NormalizationEngine          |
                                  | Preserves observed_name & PQC Status  |
                                  +---------------------------------------+
                                                      |
                                                      v Entity Persistence
              +---------------------------------------+---------------------------------------+
              |                                       |                                       |
              v                                       v                                       v
    +-------------------+                   +-------------------+                   +-------------------+
    |       Asset       |                   |      Service      |                   |   CryptoFinding   |
    | (Host, IP, App)   |---(1:N Service)-->| (Port, TLS, Proto)|--(1:N Finding)-->| (Raw & Normalized |
    +-------------------+                   +-------------------+                   |  Crypto Detail)   |
                                                                                    +-------------------+
                                                                                              |
                                                                                              v
                                                                                    +-------------------+
                                                                                    |NormalizedAlgorithm|
                                                                                    +-------------------+
```

---

## Key Features

- **Hierarchy-Aware Entity Modeling**: `AuthorizedTarget` → `ScanJob` → `Asset` → `Service` → `CryptoFinding` → `NormalizedAlgorithm`
- **5 Production Discovery Scanners**:
  - TLS & Network Scanner (`TLSScanner`)
  - SSH Host & KEX Scanner (`SSHScanner`)
  - X.509 Certificate Store Scanner (`CertificateScanner`)
  - Source Code Crypto AST Scanner (`SourceCodeScanner`)
  - Package Manifest Dependency Scanner (`DependencyScanner`)
- **Zero Private Key Collection**: Automated sanitization & PEM redaction pipeline.
- **Scope Guard**: Target authorization and post-DNS resolution scope re-validation.
- **Algorithm Normalization Engine**: Maps observed algorithms (`RSA-2048`, `X25519`, `AES-256-GCM`, `SHA-384`, `ML-KEM-768`, `ML-DSA-65`) to standardized canonical taxonomies while preserving raw observed names and distinguishing standards vs candidates.
- **PQC Risk & Remediation Engine**: Evaluates findings against NIST FIPS 203/204/205 standards and CNSA 2.0 timelines; generates actionable technical mitigation strategies.
- **CycloneDX 1.6 CBOM Generator**: Native export of Cryptographic Bill of Materials in CycloneDX 1.6 JSON format.
- **Modern React Dashboard**: Real-time stats, interactive asset hierarchy tree, scan job status monitoring, findings provenance modal, and report exporter.

---

## Quick Start

### Option A: Local Development (Single Command)
```bash
./run_dev.sh
```
- **React Frontend**: http://localhost:5173
- **FastAPI REST API Docs**: http://localhost:8000/docs

### Option B: Docker Compose
```bash
docker compose up --build
```

---

## Testing Real Work Environments Guide

### 1. Network & TLS Services (`TLSScanner`)
- **Target Types:** `HOSTNAME`, `URL`, `IP_RANGE`, `CIDR` (e.g. `api.company.com`, `google.com`, `192.168.1.50`).
- **Instructions:**
  1. Open the **Targets** tab in the UI and click **Register Target**.
  2. Enter Target Name (e.g. `Corporate API Gateway`), Target Type (`HOSTNAME`), and Value (`api.company.com`).
  3. Ensure **Is Authorized** is checked and click **Save Target**.
  4. Navigate to **Scans** → Select target → Choose **TLS & Network Scanner** → Click **Trigger Scan**.
- **Discovered Output:** Performs a real TLS handshake over TCP port 443 to extract server certificates, public key algorithms (RSA-2048, ECDSA P-256), bit lengths, negotiated TLS protocol version (`TLSv1.3`), and cipher suites (`TLS_AES_256_GCM_SHA384`).

### 2. SSH Host Services (`SSHScanner`)
- **Target Types:** `HOSTNAME`, `IP_RANGE`, `CIDR` (e.g. `ssh.company.com`, `10.0.0.12`).
- **Instructions:** Register SSH target on port 22 and trigger **SSH Host & KEX Scanner**.
- **Discovered Output:** Inspects SSH server identification banners (`SSH-2.0-OpenSSH_8.9p1`), Host Key algorithms (`rsa-sha2-512`, `ssh-ed25519`), and KEX algorithms (`curve25519-sha256`).

### 3. X.509 Certificate Stores (`CertificateScanner`)
- **Target Types:** `CERT_STORE` (e.g. `/etc/ssl/certs`, `/etc/letsencrypt/live`, or `/Users/hrishabh/my-certs`).
- **Instructions:** Register `CERT_STORE` target with an absolute local directory path containing `.crt`, `.pem`, `.cer`, or `.der` files and trigger **X.509 Certificate Scanner**.
- **Discovered Output:** Parses certificates on disk, extracting Subject/Issuer names, signature algorithms (`sha256WithRSAEncryption`), validity dates, and serial numbers.

### 4. Source Code Repositories (`SourceCodeScanner`)
- **Target Types:** `REPOSITORY` (e.g. `/Users/hrishabh/Projects/my-app`).
- **Instructions:** Register a `REPOSITORY` target with an absolute path to a project codebase and trigger **Source Code Crypto Scanner**.
- **Discovered Output:** Scans `.py`, `.js`, `.ts`, `.go`, `.java`, `.cpp`, `.rs` files for cryptographic primitives (RSA generation, AES-GCM ciphers, ECDSA, SHA-384, Kyber768, Dilithium3), capturing line-number location provenance.

### 5. Package Dependencies (`DependencyScanner`)
- **Target Types:** `REPOSITORY` (e.g. `/Users/hrishabh/Projects/my-app`).
- **Instructions:** Register target with folder path containing manifests (`package.json`, `requirements.txt`, `go.mod`, `pom.xml`, `Cargo.toml`) and trigger **Package Dependency Scanner**.
- **Discovered Output:** Identifies cryptographic dependencies (`cryptography`, `pycryptodome`, `bouncycastle`, `libsodium`, `liboqs-python` PQC library) and library versions.

---

## Cryptographic Flaws & Mitigation Strategy Matrix

| Discovered Cryptographic Primitive | Severity | Flaw Description | Technical Mitigation Strategy | Recommended PQC Replacement |
| :--- | :--- | :--- | :--- | :--- |
| **RSA-2048 / RSA-3072** | **CRITICAL** | Integer factorization is vulnerable to polynomial-time breaking via Shor's Algorithm on Cryptographically Relevant Quantum Computers (CRQCs). | Migrate key exchange to hybrid X25519+ML-KEM-768 or pure ML-KEM-768 (FIPS 203). For digital signatures, migrate to ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205). | `ML-KEM-768` (KEX) / `ML-DSA-65` (Signatures) |
| **ECDSA P-256 / secp256r1** | **CRITICAL** | Elliptic curve discrete logarithm problem is completely broken by Shor's Algorithm on a CRQC. | Replace ECDSA signature schemes with ML-DSA-65 (FIPS 204) for general authentication or SLH-DSA (FIPS 205) for stateful signing. | `ML-DSA-65` (NIST FIPS 204) |
| **X25519 / ECDH** | **HIGH** | Enables 'Harvest Now, Decrypt Later' (HNDL) attacks where adversaries record current ciphertexts to decrypt post-CRQC. | Deploy Hybrid Key Exchange (X25519 + ML-KEM-768) immediately for TLS 1.3 endpoints to protect against retroactive decryption. | `Hybrid X25519 + ML-KEM-768` |
| **MD5 / SHA-1** | **HIGH** | Classical collision vulnerability. MD5 and SHA-1 are cryptographically broken under classical cryptanalysis. | Replace MD5/SHA-1 hashing immediately with SHA-256, SHA-384, or SHA3-256. | `SHA-384` / `SHA3-256` |
| **AES-128-GCM** | **MEDIUM** | Key length is reduced to 64 effective security bits against Grover's quantum search algorithm. | Upgrade symmetric cipher suite configuration from AES-128 to AES-256-GCM to maintain 128-bit post-quantum security. | `AES-256-GCM` (NIST SP 800-38D) |
| **ML-KEM-768 / Kyber768** | **INFO** | No immediate quantum flaw detected. Algorithm aligns with NIST PQC standard or hybrid implementation. | Maintain monitoring; ensure software libraries stay updated as final FIPS implementations stabilize. | `Compliant / Quantum-Safe` |

---

## Report & CBOM Document Export

1. **Reports & Mitigation Dashboard Tab:** View real-time flaw severity cards, vulnerability listing, CNSA 2.0 timelines, and technical mitigation guidance.
2. **Download Audit Report (`.md`):** Click **Download Audit Report (.md)** in the UI (or request `GET /api/v1/reports/export/markdown`) to generate a complete Markdown audit report document (`PQC_Cryptographic_Remediation_Report.md`).
3. **Export CycloneDX 1.6 CBOM (`.json`):** Click **Export CycloneDX 1.6 CBOM (.json)** in the UI (or request `GET /api/v1/cbom/export`) to generate an official CycloneDX 1.6 Cryptographic Bill of Materials document (`cyclonedx_cbom_1.6.json`).

---

## Running Automated Test Suite

```bash
cd backend
source venv/bin/activate
PYTHONPATH=. pytest -v
```
All 21 backend unit/integration tests verify ScopeGuard, Sanitizer, NormalizationEngine, ScannerRegistry, MockScanner, Real Scanners, DiscoveryOrchestrator, and Report Generation.
