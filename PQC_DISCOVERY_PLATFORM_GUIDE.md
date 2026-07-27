# Enterprise Cryptographic Discovery Platform (PQC Readiness Guide)

## 1. Overview & System Architecture

The **Enterprise Cryptographic Discovery Platform** is a modular, high-assurance solution designed to discover, catalog, normalize, and assess cryptographic assets across enterprise digital assets:
- Network Endpoints & TLS Services
- SSH Host Services & KEX Algorithms
- X.509 Certificate Stores & Files
- Source Code Repositories & AST Call Sites
- Package Dependency Lockfiles & Manifests

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

## 2. How to Test Real Work Environments

The platform includes 5 production discovery scanners capable of operating against real enterprise systems:

### 2.1 TLS & Network Service Scanning (`TLSScanner`)
- **Target Type:** `HOSTNAME`, `URL`, `IP_RANGE`, or `CIDR` (e.g. `google.com`, `api.company.com`, `192.168.1.50`).
- **How to Test:**
  1. Open the **Targets** page in the UI and click **Register Target**.
  2. Enter Target Name (e.g. `Corporate API Gateway`), Target Type (`HOSTNAME`), and Value (`api.company.com`).
  3. Ensure **Is Authorized** is checked and click **Save Target**.
  4. Navigate to **Scans** → Select target → Choose **TLS & Network Scanner** → Click **Trigger Scan**.
- **What is Discovered:** Performs a real TLS handshake to extract server certificates, public key algorithms (RSA-2048, ECDSA P-256), bit lengths, negotiated TLS protocol version (`TLSv1.3`), and cipher suites (`TLS_AES_256_GCM_SHA384`).

### 2.2 SSH Host & Key Exchange Scanning (`SSHScanner`)
- **Target Type:** `HOSTNAME`, `IP_RANGE`, `CIDR` (e.g. `ssh.company.com`, `10.0.0.12`).
- **How to Test:**
  1. Register an SSH server target on port 22.
  2. Navigate to **Scans** → Select target → Choose **SSH Host & KEX Scanner** → Click **Trigger Scan**.
- **What is Discovered:** Connects to TCP port 22 to inspect SSH server identification banners (`SSH-2.0-OpenSSH_8.9p1`), Host Key algorithms (`rsa-sha2-512`, `ssh-ed25519`), and KEX algorithms (`curve25519-sha256`).

### 2.3 X.509 Certificate Store Scanning (`CertificateScanner`)
- **Target Type:** `CERT_STORE` (e.g., `/etc/ssl/certs`, `/etc/letsencrypt/live`, or `/path/to/my-certs`).
- **How to Test:**
  1. Register a `CERT_STORE` target with an absolute local directory or file path containing certificates.
  2. Select **X.509 Certificate Scanner** and trigger the scan.
- **What is Discovered:** Scans and parses `.crt`, `.pem`, `.cer`, and `.der` files on disk, extracting Subject/Issuer names, signature algorithms (`sha256WithRSAEncryption`), validity dates, serial numbers, and X.509 extensions.

### 2.4 Source Code Cryptographic Scanning (`SourceCodeScanner`)
- **Target Type:** `REPOSITORY` (e.g., `/Users/hrishabh/Projects/my-app`).
- **How to Test:**
  1. Register a `REPOSITORY` target pointing to an absolute directory path of a git repository or project folder.
  2. Select **Source Code Crypto Scanner** and trigger the scan.
- **What is Discovered:** Scans `.py`, `.js`, `.ts`, `.go`, `.java`, `.cpp`, `.rs` files for cryptographic primitives (RSA generation, AES-GCM ciphers, ECDSA, SHA-384, Kyber768, Dilithium3), capturing line-number location provenance.

### 2.5 Package Dependency Scanning (`DependencyScanner`)
- **Target Type:** `REPOSITORY` (e.g., `/Users/hrishabh/Projects/my-app`).
- **How to Test:**
  1. Register a target pointing to a folder containing package manifests (`package.json`, `requirements.txt`, `go.mod`, `pom.xml`, `Cargo.toml`).
  2. Select **Package Dependency Scanner** and trigger the scan.
- **What is Discovered:** Identifies cryptographic dependencies (`cryptography`, `pycryptodome`, `bouncycastle`, `libsodium`, `liboqs-python` PQC library) and library versions.

---

## 3. Cryptographic Flaws & PQC Mitigation Strategies

The platform's **Risk & Mitigation Engine** evaluates all discovered findings against **NIST PQC Standards (FIPS 203, FIPS 204, FIPS 205)** and **CNSA 2.0 Migration Timelines**:

| Discovered Cryptographic Primitive | Severity | Flaw Description | Technical Mitigation Strategy | Recommended PQC Replacement |
| :--- | :--- | :--- | :--- | :--- |
| **RSA-2048 / RSA-3072** | **CRITICAL** | Integer factorization is vulnerable to polynomial-time breaking via Shor's Algorithm on Cryptographically Relevant Quantum Computers (CRQCs). | Migrate key exchange to hybrid X25519+ML-KEM-768 or pure ML-KEM-768 (FIPS 203). For digital signatures, migrate to ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205). | `ML-KEM-768` (KEX) / `ML-DSA-65` (Signatures) |
| **ECDSA P-256 / secp256r1** | **CRITICAL** | Elliptic curve discrete logarithm problem is completely broken by Shor's Algorithm on a CRQC. | Replace ECDSA signature schemes with ML-DSA-65 (FIPS 204) for general authentication or SLH-DSA (FIPS 205) for stateful signing. | `ML-DSA-65` (NIST FIPS 204) |
| **X25519 / ECDH** | **HIGH** | Enables 'Harvest Now, Decrypt Later' (HNDL) attacks where adversaries record current ciphertexts to decrypt post-CRQC. | Deploy Hybrid Key Exchange (X25519 + ML-KEM-768) immediately for TLS 1.3 endpoints to protect against retroactive decryption. | `Hybrid X25519 + ML-KEM-768` |
| **MD5 / SHA-1** | **HIGH** | Classical collision vulnerability. MD5 and SHA-1 are cryptographically broken under classical cryptanalysis. | Replace MD5/SHA-1 hashing immediately with SHA-256, SHA-384, or SHA3-256. | `SHA-384` / `SHA3-256` |
| **AES-128-GCM** | **MEDIUM** | Key length is reduced to 64 effective security bits against Grover's quantum search algorithm. | Upgrade symmetric cipher suite configuration from AES-128 to AES-256-GCM to maintain 128-bit post-quantum security. | `AES-256-GCM` (NIST SP 800-38D) |
| **ML-KEM-768 / Kyber768** | **INFO** | No immediate quantum flaw detected. Algorithm aligns with NIST PQC standard or hybrid implementation. | Maintain monitoring; ensure software libraries stay updated as final FIPS implementations stabilize. | `Compliant / Quantum-Safe` |

---

## 4. Reports & Document Generation

The platform provides automated report generation:

1. **Reports & Mitigation Dashboard Tab:**
   - Real-time flaw severity cards, vulnerability listing, CNSA 2.0 timelines, and technical mitigation guidance.

2. **Download Audit Report (`.md`):**
   - Click **Download Audit Report (.md)** in the UI (or request `GET /api/v1/reports/export/markdown`) to generate a complete Markdown audit report document (`PQC_Cryptographic_Remediation_Report.md`).

3. **Export CycloneDX 1.6 CBOM (`.json`):**
   - Click **Export CycloneDX 1.6 CBOM (.json)** in the UI (or request `GET /api/v1/cbom/export`) to generate an official CycloneDX 1.6 Cryptographic Bill of Materials document (`cyclonedx_cbom_1.6.json`).

---

## 5. Developer & Deployment Guide

### Option A: Local Development Server
Run the single-command startup script:
```bash
./run_dev.sh
```
- **React Frontend:** `http://localhost:5173`
- **FastAPI OpenAPI Docs:** `http://localhost:8000/docs`

### Option B: Docker Compose
```bash
docker compose up --build
```

### Option C: Running Backend Test Suite
```bash
cd backend
source venv/bin/activate
PYTHONPATH=. pytest -v
```
All 21 backend unit/integration tests verify ScopeGuard, Sanitizer, NormalizationEngine, ScannerRegistry, MockScanner, Real Scanners, DiscoveryOrchestrator, and Report Generation.
