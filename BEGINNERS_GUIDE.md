# 🔰 Project Quantum: Complete Beginner's Guide & Testing Manual

Welcome to **Project Quantum** (Enterprise Post-Quantum Cryptography Discovery & Readiness Platform)! 

This guide is written specifically so that anyone—even a complete beginner with no previous security or command-line experience—can easily run, test, and use every single feature of the platform freely.

---

## 📖 Table of Contents
1. [What is Project Quantum & Why Use It?](#-1-what-is-project-quantum--why-use-it)
2. [Prerequisites & System Requirements](#-2-prerequisites--system-requirements)
3. [How to Launch the Application](#-3-how-to-launch-the-application)
4. [Dashboard & Navigation Overview](#-4-dashboard--navigation-overview)
5. [Step-by-Step Testing Instructions for Every Feature](#-5-step-by-step-testing-instructions-for-every-feature)
   - [Testing Web & Server Endpoints (e.g., Jenkins / HTTPS)](#51-testing-web--server-endpoints-eg-jenkins--https)
   - [Bulk Endpoint Import & OpenAPI / Swagger Spec Import](#52-bulk-endpoint-import--openapi--swagger-spec-import)
   - [Scanning Local Source Code Repositories](#53-scanning-local-source-code-repositories)
   - [Scanning Package Dependency Lockfiles](#54-scanning-package-dependency-lockfiles)
   - [Scanning Local X.509 Certificate Stores](#55-scanning-local-x509-certificate-stores)
   - [Scanning SSH Host Services](#56-scanning-ssh-host-services)
   - [Syncing AWS Cloud Infrastructure](#57-syncing-aws-cloud-infrastructure)
   - [Syncing Azure Cloud Infrastructure](#58-syncing-azure-cloud-infrastructure)
   - [Syncing Kubernetes (K8s) Clusters](#59-syncing-kubernetes-k8s-clusters)
6. [Understanding Quantum Risks & NIST PQC Standards](#-6-understanding-quantum-risks--nist-pqc-standards)
7. [Exporting Reports & CBOM (Cryptographic Bill of Materials)](#-7-exporting-reports--cbom-cryptographic-bill-of-materials)
8. [Running Automated Tests](#-8-running-automated-tests)
9. [Troubleshooting & FAQs](#-9-troubleshooting--faqs)

---

## 🌟 1. What is Project Quantum & Why Use It?

Modern applications and internet communications rely on encryption like **RSA** and **ECC (Elliptic Curve Cryptography)**. However, future **Cryptographically Relevant Quantum Computers (CRQCs)** will be powerful enough to break these traditional encryption algorithms using Shor's Algorithm.

To protect against this, **NIST (National Institute of Standards and Technology)** has published official **Post-Quantum Cryptography (PQC)** standards (such as **ML-KEM-768** for key exchange and **ML-DSA-65** for digital signatures).

**Project Quantum** automatically scans, inventories, normalizes, and evaluates all encryption across your web servers, codebases, cloud accounts, and containers—telling you exactly where you are vulnerable and how to migrate to quantum-safe standards.

---

## 🛠️ 2. Prerequisites & System Requirements

To run Project Quantum locally on macOS or Linux, you only need:
* **Python 3.10** or higher
* **Node.js 18** or higher (with `npm`)
* **Git**

*(Optional for Docker mode: Docker & Docker Compose)*

---

## 🚀 3. How to Launch the Application

### Option A: Standard 1-Command Launch (Recommended)

1. Open your Terminal application.
2. Navigate into the project folder:
   ```bash
   cd /path/to/Projext_Quantum
   ```
3. Execute the dev startup script:
   ```bash
   ./run_dev.sh
   ```
4. **What happens automatically:**
   - Creates a Python virtual environment in `backend/venv` and installs dependencies.
   - Applies database schema migrations (`pqc_discovery.db`).
   - Launches the **FastAPI REST API server** on [`http://localhost:8000`](http://localhost:8000).
   - Launches the **React Web Dashboard** on [`http://localhost:5173`](http://localhost:5173).

5. Open your web browser and navigate to:  
   👉 **[`http://localhost:5173`](http://localhost:5173)**

---

### Option B: Docker Launch (Production Mode)

If you prefer using Docker:
```bash
docker compose up --build
```

---

## 🖥️ 4. Dashboard & Navigation Overview

When you open [`http://localhost:5173`](http://localhost:5173), you will see the left sidebar navigation:

| Menu Item | Icon | Description |
| :--- | :---: | :--- |
| **Dashboard** | 📊 | Overall summary of scanned assets, risk ratings, and top vulnerable algorithms. |
| **Targets** | 🎯 | Manage scope target endpoints, repositories, certificate paths, or cloud connectors. |
| **Scans** | 🔍 | Trigger and view live status of real-time discovery scans. |
| **Crypto Findings** | 🔐 | Complete searchable database of all discovered cryptographic algorithms & key sizes. |
| **API & Server Hub** | ⚡ | Quick tool to bulk-test server URLs or upload OpenAPI/Swagger JSON specs. |
| **AWS Connector** | ☁️ | Read-only discovery sync across AWS KMS, ACM, ELB, S3, RDS, CloudFront. |
| **Azure Connector** | 🔷 | Read-only discovery sync across Azure Key Vaults, VMs, Storage, SQL DBs. |
| **Kubernetes Connector** | ☸️ | Read-only audit of K8s cluster nodes, workloads, pods, ingresses, certs. |
| **PQC Readiness** | 🛡️ | NIST FIPS PQC compliance scorecards and CNSA 2.0 timeline guidance. |
| **Reports** | 📄 | Download CycloneDX 1.6 CBOM (`.json`) or Executive Audit Reports (`.md`). |

---

## 🧪 5. Step-by-Step Testing Instructions for Every Feature

### 5.1 Testing Web & Server Endpoints (e.g., Jenkins / HTTPS)

**Goal:** Scan any web server, API endpoint, or Jenkins instance (e.g., `43.204.101.138:8080` or `https://google.com`) to evaluate its TLS version, public keys, and ciphers.

#### Steps:
1. Open the UI at [`http://localhost:5173`](http://localhost:5173).
2. Click **API & Server Hub** in the left menu.
3. In the text area under **Register Server Endpoints**, enter your endpoint:
   ```text
   http://43.204.101.138:8080/
   ```
4. Click **Register Servers & Run Quantum Discovery**.
5. The system automatically registers the target and runs a TLS audit!

#### Alternative via Targets Page:
1. Go to **Targets** → Click **Register Target**.
2. Set **Target Name** = `Jenkins Server`, **Target Type** = `HOSTNAME` (or `URL`), **Target Value** = `43.204.101.138`.
3. Check **Is Authorized** → Click **Save Target**.
4. Go to **Scans** → Click **New Scan** → Select your target → Select **TLS & Network Scanner** → Click **Trigger Scan**.

---

### 5.2 Bulk Endpoint Import & OpenAPI / Swagger Spec Import

**Goal:** Import an entire list of company API endpoints or an OpenAPI specification file (`openapi.json`).

#### Steps:
1. Go to **API & Server Hub** tab.
2. **Bulk List Method:** Paste multiple URLs separated by lines:
   ```text
   https://api.company.com
   https://auth.company.com/v1
   10.0.0.12:443
   ```
   Click **Register Servers & Run Quantum Discovery**.
3. **OpenAPI File Upload Method:** Click **Choose File** under OpenAPI Import → Select your `swagger.json` or `openapi.json` file → The system extracts all server host URLs automatically.

---

### 5.3 Scanning Local Source Code Repositories

**Goal:** Find hardcoded cryptographic function calls (RSA key generation, AES-GCM ciphers, ECDSA signatures, SHA-384 hashes, or Kyber768 PQC calls) inside your code.

#### Steps:
1. Go to **Targets** → Click **Register Target**.
2. Set:
   - **Target Name**: `My Backend Codebase`
   - **Target Type**: `REPOSITORY`
   - **Target Value**: Absolute folder path (e.g., `/Users/hrishabh/Downloads/Projext_Quantum/backend`)
3. Check **Is Authorized** → Click **Save Target**.
4. Go to **Scans** → Click **New Scan** → Select `My Backend Codebase` → Choose **Source Code Crypto Scanner** → Click **Trigger Scan**.
5. Go to **Crypto Findings** to see every matching file and exact line number!

---

### 5.4 Scanning Package Dependency Lockfiles

**Goal:** Identify cryptographic software libraries used in your dependencies (`cryptography`, `pycryptodome`, `bouncycastle`, `liboqs`, etc.).

#### Steps:
1. Register a `REPOSITORY` target pointing to a folder containing manifest files (`package.json`, `requirements.txt`, `go.mod`, or `pom.xml`).
2. Go to **Scans** → Trigger **Package Dependency Scanner**.
3. View identified crypto library packages and version numbers in **Crypto Findings**.

---

### 5.5 Scanning Local X.509 Certificate Stores

**Goal:** Scan X.509 `.pem`, `.crt`, `.cer`, or `.der` certificate files on disk.

#### Steps:
1. Go to **Targets** → Click **Register Target**.
2. Set **Target Type** = `CERT_STORE` and **Target Value** = `/etc/ssl/certs` (or any local directory containing certificates).
3. Save target → Go to **Scans** → Select target → Choose **X.509 Certificate Scanner** → Trigger scan.

---

### 5.6 Scanning SSH Host Services

**Goal:** Inspect SSH server banners (port 22) for host key algorithms and Key Exchange (KEX) algorithms.

#### Steps:
1. Register a target with **Target Type** = `HOSTNAME` and **Target Value** = `ssh.company.com` (or an IP running SSH on port 22).
2. Go to **Scans** → Trigger **SSH Host & KEX Scanner**.

---

### 5.7 Syncing AWS Cloud Infrastructure

**Goal:** Sync read-only cryptographic assets from AWS KMS, ACM, ELBv2, S3, RDS, and CloudFront.

#### Steps:
1. Open `backend/.env` and configure your AWS credentials:
   ```ini
   AWS_ACCESS_KEY_ID=AKIAXXXXXXXXXXXXXXXX
   AWS_SECRET_ACCESS_KEY=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
   AWS_DEFAULT_REGION=us-east-1
   ```
2. Go to **AWS Connector** tab in the UI.
3. Click **Validate Credentials** (verifies STS connection).
4. Click **Run AWS Discovery Sync**.

---

### 5.8 Syncing Azure Cloud Infrastructure

**Goal:** Sync read-only assets from Azure Key Vaults, Virtual Machines, Storage Accounts, and SQL Databases.

#### Steps:
1. Open `backend/.env` and configure Azure credentials:
   ```ini
   AZURE_TENANT_ID=00000000-0000-0000-0000-000000000000
   AZURE_CLIENT_ID=11111111-1111-1111-1111-111111111111
   AZURE_CLIENT_SECRET=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
   AZURE_SUBSCRIPTION_ID=22222222-2222-2222-2222-222222222222
   ```
2. Go to **Azure Connector** tab → Click **Validate Azure Credentials** → Click **Trigger Full Azure Discovery**.

---

### 5.9 Syncing Kubernetes (K8s) Clusters

**Goal:** Perform read-only audit of K8s cluster nodes, workloads, pods, services, ingresses, and TLS public cert secret metadata under a strict **Zero-Secret Policy**.

#### Steps:
1. Open `backend/.env` and set your kubeconfig path:
   ```ini
   KUBECONFIG_PATH=/Users/youruser/.kube/config
   K8S_CONTEXT_NAME=my-k8s-cluster
   ```
2. Go to **Kubernetes Connector** tab → Click **Trigger Kubernetes Discovery**.

---

## 🛡️ 6. Understanding Quantum Risks & NIST PQC Standards

The system automatically classifies findings into 4 vulnerability levels based on NIST guidelines:

| Status | Meaning | Examples | Remediation Action |
| :--- | :--- | :--- | :--- |
| 🔴 **QUANTUM_VULNERABLE** | Vulnerable to Shor's algorithm on a quantum computer. | RSA-2048, RSA-3072, ECDSA P-256, X25519 | Replace with ML-KEM-768 for KEX, ML-DSA-65 for Signatures. |
| 🟡 **LEGACY_BROKEN** | Vulnerable to classical cryptanalysis. | MD5, SHA-1, DES, 3DES | Upgrade immediately to SHA-256 / SHA-384 / AES-256. |
| 🔵 **HYBRID_QUANTUM_SAFE** | Combines classical algorithm with PQC. | Hybrid X25519 + ML-KEM-768 | Maintain monitoring; aligns with transitional guidance. |
| 🟢 **QUANTUM_RESISTANT** | Fully compliant with NIST PQC standards. | ML-KEM-768 (FIPS 203), ML-DSA-65 (FIPS 204), AES-256 | Compliant. Keep software libraries updated. |

---

## 📄 7. Exporting Reports, Saving Archives & Clearing Scan History

### Exporting Reports & Backup Archives
After running discovery scans:
1. Navigate to **Scans** or **Reports & Readiness** tab.
2. **Download Full Backup Archive:** Click **Save Archive (.json)** (or request `GET /api/v1/scans/export/archive`) to download a complete JSON backup archive containing all targets, scan executions, and cryptographic findings (`pqc_discovery_archive.json`).
3. **Download Markdown Report:** Click **Download Report (.md)** to get a comprehensive remediation report document (`PQC_Cryptographic_Remediation_Report.md`).
4. **Export CycloneDX 1.6 CBOM:** Click **Export CBOM (.json)** to generate an official CycloneDX 1.6 Cryptographic Bill of Materials JSON document (`cyclonedx_cbom_1.6.json`).

### Clearing Scan History & Deleting Jobs
To reset your environment or start a fresh audit:
1. **Clear All History:** On the **Scans** or **Reports** page, click the red **Clear Scan History** button. A modal prompt will appear giving you the option to download a backup archive before permanently purging scan logs and findings from the database.
2. **Delete Single Scan:** On the **Scans** page, click the red trash icon on any individual scan job row to delete that specific scan and its findings.


---

## 🧪 8. Running Automated Tests

To verify that the system backend logic, API endpoints, sanitizers, and scanners are working properly:

```bash
cd backend
source venv/bin/activate
PYTHONPATH=. pytest -v
```

All unit/integration tests run against an in-memory database and verify 100% core contract compliance.

---

## ❓ 9. Troubleshooting & FAQs

**Q1: Port 5173 or 8000 is already in use.**  
*Solution:* Stop any process using those ports or kill them:
```bash
lsof -i :8000
lsof -i :5173
```

**Q2: Does Project Quantum modify or risk shutting down any of my servers?**  
*Solution:* No! All discovery operations, network probes, and cloud integrations operate strictly in **read-only** mode.

**Q3: Where can I see interactive API endpoints?**  
*Solution:* Open [`http://localhost:8000/docs`](http://localhost:8000/docs) in your browser to use FastAPI's built-in Swagger interface.
