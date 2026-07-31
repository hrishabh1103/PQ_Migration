# Enterprise Cryptographic Discovery Platform (PQC Migration Readiness)

> **Post-Quantum Cryptography (PQC) Migration Readiness Platform**  
> An enterprise-grade cryptographic discovery, inventory normalization, cross-cloud correlation, PQC risk assessment, and Cryptographic Bill of Materials (CBOM) generation platform supporting **AWS**, **Azure**, **Kubernetes**, **Linux**, **Network Endpoints (TLS/SSH)**, and **Application Source Code**.

> **Runtime Truth Recovery V1 Complete** — All hardcoded/synthetic demo data has been purged. Every value displayed in the UI is now derived from real runtime evidence. Zero-state shows empty results. Real TLS scans produce real findings.

> **Universal Evidence-Driven PQC Instance Report Expansion — COMPLETE** — Per-instance evidence-driven PQC assessment reports are now universally integrated across all 11 frontend pages (`LinuxCollectorPage`, `AzureConnectorPage`, `KubernetesConnectorPage`, `CloudServersPage`, `PqcReadinessPage`, `FindingsPage`, `ScansPage`, `TargetsPage`, `InventoryGraphPage`, `DashboardPage`, `ReportsPage`). All reports operate strictly on canonical backend `asset_id`s, enforce explicit assessment scopes (`INSTANCE`, `AGGREGATE`, `NOT_ELIGIBLE`), deduplicate overlapping evidence (applying rule score impact once while aggregating provenance), and gate on actual cryptographic findings (`score=null`, `status="NOT_ASSESSED"` when zero evidence exists). 13/13 backend correctness unit tests and full production frontend build (`npm run build`) pass cleanly.


---

## 🔰 [CLICK HERE FOR THE BEGINNER'S GUIDE](BEGINNERS_GUIDE.md)

If you are new to the platform or want a complete step-by-step tutorial on how to test every feature, read our **[BEGINNERS_GUIDE.md](BEGINNERS_GUIDE.md)**!

---


## 📚 Documentation & Subsystem Guides Index

* 🔰 **[Beginner's Guide & Testing Manual](BEGINNERS_GUIDE.md)**: Zero-to-Hero guide for beginners on how to run, navigate, test web endpoints, scan source code, sync cloud resources, and export PQC reports.
* ⚙️ **[Backend Engine Architecture & REST API Guide](backend/README.md)**: Deep dive into FastAPI, SQLAlchemy, DiscoveryOrchestrator, Scanners, and pytest test suite.
* 🎨 **[Frontend Dashboard & React UI Guide](frontend/README.md)**: Overview of React 18, TypeScript, Tailwind styling, page components, and API service integration.
* 📖 **[Platform Architecture & PQC Standard Specification](docs/ARCHITECTURE.md)**: Complete system design, ScopeGuard security boundaries, and NIST PQC FIPS standard compliance mapping.

---

## 🌟 What Project Quantum Offers

Project Quantum is built to solve the **Harvest Now, Decrypt Later (HNDL)** threat posed by future Cryptographically Relevant Quantum Computers (CRQCs).

### Key Features & Core Capabilities

| Capability Module | Functionality & Offered Services |
| :--- | :--- |
| 🌐 **TLS & Network Service Scanner** | Real-time TLS handshakes evaluating protocol versions (`TLSv1.3`), cipher suites (`TLS_AES_256_GCM_SHA384`), public key algorithms (`RSA-2048`, `ECDSA P-256`), and key exchange groups (`X25519`, `ML-KEM-768`). |
| 🔑 **SSH Host & KEX Scanner** | Inspects SSH banners, server host key algorithms (`rsa-sha2-512`, `ssh-ed25519`), and key exchange algorithms (`curve25519-sha256`). |
| 📜 **X.509 Certificate Store Scanner** | Recursively scans disk locations for `.crt`, `.pem`, `.cer`, `.der` files, extracting validity ranges, subjects, issuers, serial numbers, and signature algorithms. |
| 💻 **Source Code Cryptographic Scanner** | Performs AST/pattern scanning across `.py`, `.js`, `.ts`, `.go`, `.java`, `.cpp`, `.rs` codebases to locate hardcoded crypto primitives (RSA, AES-GCM, ECDSA, SHA-384, Kyber768, Dilithium3) with exact line number provenance. |
| 📦 **Package Dependency Scanner** | Scans manifest files (`package.json`, `requirements.txt`, `go.mod`, `pom.xml`, `Cargo.toml`) for cryptographic dependencies (`cryptography`, `bouncycastle`, `liboqs-python`, etc.). |
| ⚡ **API & Server Hub** | Enables bulk registration of company backend server URLs or import of OpenAPI 3.0 / Swagger JSON specifications for automated parallel quantum audits. |
| ☁️ **AWS Cloud Connector** | Read-only sync across AWS KMS key specs, ACM X.509 certificates, ELBv2 SSL policies, S3 bucket encryption, RDS DB encryption, and CloudFront CDNs. |
| 🔷 **Azure Cloud Connector** | Read-only sync across Azure Entra ID, Key Vault keys & certificates, VM managed disks, Storage Accounts, App Gateways, SQL databases, and Front Door. |
| ☸️ **Kubernetes Cluster Connector** | Read-only sync across K8s cluster nodes, workloads, pods, services, ingresses, and TLS public certificate secret metadata under a strict **Zero-Secret Policy**. |
| 🛡️ **PQC Readiness Engine** | Maps all discovered algorithms against **NIST PQC Standards (FIPS 203 ML-KEM, FIPS 204 ML-DSA, FIPS 205 SLH-DSA)** and **CNSA 2.0 timelines**. |
| 📄 **CBOM & Report Generator** | Generates official **CycloneDX 1.6 Cryptographic Bill of Materials (CBOM)** JSON files and downloadable Markdown remediation reports. |

---

## 🚀 Quick Start Guide

### 1. One-Command Local Launch

Run the single-command startup script from the project root:

```bash
./run_dev.sh
```

This automatically initializes the Python virtual environment (`backend/venv`), installs backend & frontend dependencies, runs database migrations, and launches both servers concurrently:

- 💻 **Interactive React UI Dashboard:** [`http://localhost:5173`](http://localhost:5173)
- 🔌 **FastAPI REST API Server:** [`http://localhost:8000`](http://localhost:8000)
- 📖 **Interactive OpenAPI / Swagger Documentation:** [`http://localhost:8000/docs`](http://localhost:8000/docs)

---

### 2. Docker Launch (Production-Ready)

```bash
docker compose up --build
```

---

## 🔑 Environment Variables & Configuration

Configure optional environment variables in `backend/.env` to enable AWS, Azure, and Kubernetes connectors:

```ini
# Database & Core Engine Configuration
DATABASE_URL=sqlite:///./pqc_discovery.db
CORS_ORIGINS=http://localhost:5173,http://localhost:3000

# AWS Credentials (Read-Only IAM Policy)
AWS_ACCESS_KEY_ID=AKIAXXXXXXXXXXXXXXXX
AWS_SECRET_ACCESS_KEY=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
AWS_DEFAULT_REGION=us-east-1

# Azure Service Principal Credentials (Read-Only)
AZURE_TENANT_ID=00000000-0000-0000-0000-000000000000
AZURE_CLIENT_ID=11111111-1111-1111-1111-111111111111
AZURE_CLIENT_SECRET=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
AZURE_SUBSCRIPTION_ID=22222222-2222-2222-2222-222222222222

# Kubernetes Cluster Configuration
KUBECONFIG_PATH=/Users/youruser/.kube/config
K8S_CONTEXT_NAME=kind-lab-kind-cluster
K8S_IN_CLUSTER=false
```

---

## 🛠️ Step-by-Step Basic Beginner Workflow

1. **Launch application:** Run `./run_dev.sh` and open [`http://localhost:5173`](http://localhost:5173).
2. **Scan an API/URL endpoint:** Go to **API & Server Hub** → Paste `http://43.204.101.138:8080/` or `https://google.com` → Click **Register & Run Quantum Discovery**.
3. **Scan source code:** Go to **Targets** → Add target with `Type = REPOSITORY` and path `/path/to/your/project` → Run **Source Code Crypto Scanner**.
4. **View PQC findings:** Go to **Crypto Findings** to inspect discovered key algorithms (`RSA-2048`, `ECDSA`, `ML-KEM-768`).
5. **Export reports:** Go to **PQC Readiness** → Download **CycloneDX 1.6 CBOM (.json)** and **Markdown Audit Report (.md)**.

For complete beginner instructions, read the **[Beginner's Guide & Testing Manual](BEGINNERS_GUIDE.md)**.

---

## 🧪 Testing Backend Suite

```bash
cd backend
source venv/bin/activate
PYTHONPATH=. pytest -v
```
