# Enterprise Cryptographic Discovery Platform (PQC Migration Readiness)

> **Post-Quantum Cryptography (PQC) Migration Readiness Platform**  
> An enterprise-grade cryptographic discovery, inventory normalization, cross-cloud correlation, PQC risk assessment, and Cryptographic Bill of Materials (CBOM) generation platform supporting **AWS**, **Azure**, **Kubernetes**, **Linux**, and **Application Source Code**.

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

## 🔑 Environment Variables & API Key Configuration

To connect the platform to your cloud providers, Kubernetes clusters, and local targets, configure environment variables in `backend/.env` (or pass them via shell environment):

```ini
# Database & Core Engine Configuration
DATABASE_URL=sqlite:///./pqc_discovery.db
CORS_ORIGINS=http://localhost:5173,http://localhost:3000

# AWS Credentials (Read-Only IAM Policy)
AWS_ACCESS_KEY_ID=AKIAXXXXXXXXXXXXXXXX
AWS_SECRET_ACCESS_KEY=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
AWS_DEFAULT_REGION=us-east-1
AWS_ROLE_ARN=arn:aws:iam::123456789012:role/PQCDiscoveryReadOnlyRole

# Azure Service Principal Credentials (Read-Only Reader + Key Vault Certificate User)
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

## 🛠️ Step-by-Step Usage Guide

### 1. Register & Scan Web Endpoints (TLS/HTTPS)
1. Open the UI at [`http://localhost:5173`](http://localhost:5173).
2. Go to **Targets** → Click **Register Target**.
3. Set `Name = Corporate API`, `Type = HOSTNAME`, `Value = api.company.com`.
4. Navigate to **Scans** → Select target → Choose **TLS & Network Scanner** → Click **Trigger Scan**.
5. The platform performs a live TLS 1.3 / 1.2 handshake, evaluating public key algorithms (`RSA-2048`, `ECDSA P-256`), bit lengths, X.509 signature schemes (`sha256WithRSAEncryption`), negotiated cipher suites (`TLS_AES_256_GCM_SHA384`), and PQC readiness (`QUANTUM_VULNERABLE` vs `QUANTUM_RESISTANT`).

### 2. Import OpenAPI / Swagger Specs for Bulk Endpoint Discovery
1. Go to **API & Server Hub** in the navbar.
2. Click **Import OpenAPI Spec** → Upload your `openapi.json` or paste server URLs (e.g., `https://auth.company.com/v1`, `https://payments.company.com`).
3. Click **Register & Run Quantum Discovery** to automatically register targets and trigger parallel quantum readiness audits.

### 3. Connect AWS Cloud Infrastructure (`AWSConnector`)
1. Ensure `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` are configured in `backend/.env`.
2. Go to **AWS Connector** tab in the UI.
3. Click **Validate Credentials** to test STS connectivity.
4. Click **Run AWS Discovery Sync** to perform read-only discovery across STS Identity, EC2 Instances, EBS Volumes, KMS Keys, ACM Certificates, ELBv2 Load Balancers, S3 Encryption, RDS DBs, and CloudFront CDNs.

### 4. Connect Azure Cloud Infrastructure (`AzureConnector`)
1. Ensure `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, and `AZURE_CLIENT_SECRET` are configured in `backend/.env`.
2. Go to **Azure Connector** tab in the UI.
3. Click **Validate Azure Credentials** to verify Entra ID authentication.
4. Click **Trigger Full Azure Discovery** to perform read-only discovery across Entra ID Tenants, Subscriptions, Resource Groups, Spatial Regions, Virtual Machines, Managed Disks, Storage Accounts, Key Vaults (keys & certificates), Application Gateways, Azure SQL Databases, Front Door, and VNets.

### 5. Connect Kubernetes Clusters (`KubernetesConnector`)
1. Go to **Kubernetes Connector** tab in the UI.
2. Select your `Kubeconfig Path` and `Context Name` (or choose In-Cluster ServiceAccount mode).
3. Click **Trigger Kubernetes Discovery** to sync across Clusters, Namespaces, Nodes, Workloads (Deployments, StatefulSets, DaemonSets), Pods, Services, Ingresses, Public X.509 Certificates, Secret Metadata, ConfigMaps, and RBAC ServiceAccounts under a strict Zero-Secret Policy.

### 6. Audit Linux Hosts (`LinuxCollector`)
1. Install or run `LinuxCollector` on target Linux hosts/containers.
2. The collector inspects OpenSSL system library versions (`/usr/lib/...`), active crypto policies (`/etc/crypto-policies/state`), system certificate trust stores (`/etc/ssl/certs`), and SSH server configurations.

### 7. Evaluate PQC Migration Readiness & Export CBOM
1. Navigate to **PQC Readiness** tab in the UI.
2. Click **Execute Readiness Assessment** to evaluate all discovered assets against NIST PQC Standards (FIPS 203 ML-KEM, FIPS 204 ML-DSA, FIPS 205 SLH-DSA) and CNSA 2.0 timelines.
3. Go to **Reports & CBOM**:
   - Click **Download Audit Report (.md)** for executive markdown remediation guidance.
   - Click **Export CycloneDX 1.6 CBOM (.json)** for standard CycloneDX 1.6 Cryptographic Bill of Materials output.

---

## 📡 REST API Reference Guide

The platform exposes a full OpenAPI 3.0 REST API at `http://localhost:8000/api/v1`. Anyone can integrate with these endpoints programmatically using `curl`, Python, Go, Node.js, or CI/CD pipelines.

### 1. Authorized Targets API

#### Register a New Target
```bash
curl -X POST "http://localhost:8000/api/v1/targets/" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Production Payment Gateway",
    "target_type": "HOSTNAME",
    "target_value": "api.payments.company.com",
    "environment": "PRODUCTION",
    "is_authorized": true
  }'
```

#### List All Authorized Targets
```bash
curl -X GET "http://localhost:8000/api/v1/targets/"
```

---

### 2. Discovery Scans API

#### Trigger a Discovery Scan Job
```bash
curl -X POST "http://localhost:8000/api/v1/scans/trigger" \
  -H "Content-Type: application/json" \
  -d '{
    "target_id": "TARGET_UUID_HERE",
    "scanners": ["TLSScanner", "SSHScanner", "CertificateScanner"]
  }'
```

#### Check Scan Status & Results
```bash
curl -X GET "http://localhost:8000/api/v1/scans/SCAN_JOB_UUID_HERE"
```

---

### 3. Multi-Cloud Connectors API

#### Validate AWS Credentials & Scope
```bash
curl -X POST "http://localhost:8000/api/v1/connectors/aws/validate" \
  -H "Content-Type: application/json" \
  -d '{
    "target_id": "AWS_TARGET_UUID_HERE"
  }'
```

#### Trigger AWS Discovery Sync
```bash
curl -X POST "http://localhost:8000/api/v1/connectors/aws/sync" \
  -H "Content-Type: application/json" \
  -d '{
    "target_id": "AWS_TARGET_UUID_HERE",
    "allowed_regions": ["us-east-1", "us-west-2"]
  }'
```

#### Validate Azure Credentials & Scope
```bash
curl -X POST "http://localhost:8000/api/v1/connectors/azure/validate" \
  -H "Content-Type: application/json" \
  -d '{
    "target_id": "AZURE_TARGET_UUID_HERE"
  }'
```

#### Trigger Azure Discovery Sync
```bash
curl -X POST "http://localhost:8000/api/v1/connectors/azure/sync" \
  -H "Content-Type: application/json" \
  -d '{
    "target_id": "AZURE_TARGET_UUID_HERE"
  }'
```

#### Validate Kubernetes Cluster & Scope
```bash
curl -X POST "http://localhost:8000/api/v1/connectors/kubernetes/validate" \
  -H "Content-Type: application/json" \
  -d '{
    "target_id": "K8S_TARGET_UUID_HERE"
  }'
```

#### Trigger Kubernetes Discovery Sync
```bash
curl -X POST "http://localhost:8000/api/v1/connectors/kubernetes/sync" \
  -H "Content-Type: application/json" \
  -d '{
    "target_id": "K8S_TARGET_UUID_HERE"
  }'
```

---

### 4. Cryptographic Inventory & Graph API

#### List Discovered Inventory Assets
```bash
curl -X GET "http://localhost:8000/api/v1/inventory/assets"
```

#### List Discovered Cryptographic Objects & Algorithms
```bash
curl -X GET "http://localhost:8000/api/v1/inventory/crypto-objects"
```

#### Get Cryptographic Dependency Graph (Nodes & Edges)
```bash
curl -X GET "http://localhost:8000/api/v1/inventory/graph"
```

---

### 5. PQC Readiness & Assessment API

#### Execute Assessment Run (NIST FIPS 203/204/205 Policy)
```bash
curl -X POST "http://localhost:8000/api/v1/readiness/assess" \
  -H "Content-Type: application/json" \
  -d '{
    "policy_id": "pqc-default",
    "policy_version": "v1.0"
  }'
```

#### Get Latest Asset PQC Readiness Results
```bash
curl -X GET "http://localhost:8000/api/v1/readiness/results"
```

---

### 6. Reports & CycloneDX 1.6 CBOM Export API

#### Export Markdown PQC Remediation Report
```bash
curl -X GET "http://localhost:8000/api/v1/reports/export/markdown" \
  -o PQC_Cryptographic_Remediation_Report.md
```

#### Export CycloneDX 1.6 CBOM (JSON)
```bash
curl -X GET "http://localhost:8000/api/v1/cbom/export" \
  -o cyclonedx_cbom_1.6.json
```

---

## 🏛️ Architecture Overview

```
                                  +---------------------------------------+
                                  | React + TypeScript + Tailwind UI      |
                                  | Dashboard, Connectors, Scans, Reports |
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
                                  | AWS, Azure, K8s, TLS, SSH, Cert, AST  |
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
                                  | Standardizes NIST PQC Primitives      |
                                  +---------------------------------------+
                                                      |
                                                      v Entity Persistence
              +---------------------------------------+---------------------------------------+
              |                                       |                                       |
              v                                       v                                       v
    +-------------------+                   +-------------------+                   +-------------------+
    |       Asset       |                   |      Service      |                   |   CryptoFinding   |
    | (Cloud, Host, K8s)|---(1:N Service)-->| (Port, TLS, Proto)|--(1:N Finding)-->| (Raw & Normalized |
    +-------------------+                   +-------------------+                   |  Crypto Detail)   |
                                                                                    +-------------------+
                                                                                              |
                                                                                              v
                                                                                    +-------------------+
                                                                                    |CryptoObject & Graph|
                                                                                    +-------------------+
```

---

## 🔒 Security & Zero-Secret Guarantees

1. **Read-Only Cloud Scopes:** Both `AWSConnector` and `AzureConnector` operate exclusively under read-only IAM policies / Reader roles. They do **not** require or execute write, encrypt, decrypt, or secret retrieval permissions.
2. **Zero-Secret Data Exposure Policy:** `Secret.data` and Key Vault secret payloads are **never** read or persisted. Public certificate material (`tls.crt`) is extracted for X.509 fingerprinting only. Private keys (`tls.key`), tokens, API keys, and connection strings are strictly ignored and sanitized.
3. **ScopeGuard Authorization:** Every scan or sync request is validated by `ScopeGuard` to fail closed if targets outside authorized scopes are requested.

---

## 🧪 Testing & Verification

Run the full backend test suite (86 test cases across all connectors & core engines):

```bash
cd backend
source venv/bin/activate
PYTHONPATH=. pytest -v
```

Run frontend production build verification:

```bash
cd frontend
npm run build
```

---

## 📄 License & Attribution

Designed & Developed for Post-Quantum Cryptography Migration Readiness, compliant with **NIST FIPS 203 (ML-KEM)**, **NIST FIPS 204 (ML-DSA)**, **NIST FIPS 205 (SLH-DSA)**, and **CycloneDX 1.6 CBOM Specification**.
