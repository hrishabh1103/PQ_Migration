# ⚙️ Project Quantum - Backend Core Architecture & API Guide

The **Project Quantum Backend** is built with **FastAPI**, **SQLAlchemy ORM**, **Alembic migrations**, and an asynchronous **Discovery Engine** designed to discover, analyze, normalize, and evaluate cryptographic assets across enterprise digital environments.

---

## 🏗️ Architecture Overview

```
+-----------------------------------------------------------------------------------+
|                                FastAPI REST Server                                |
|   /api/v1/targets, /api/v1/scans, /api/v1/findings, /api/v1/connectors, etc.      |
+-----------------------------------------------------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|                               DiscoveryOrchestrator                               |
|   Validates ScopeGuard -> Executes Scanners -> Sanitizes -> Normalizes -> Persists    |
+-----------------------------------------------------------------------------------+
                                          |
    +-------------------------------------+-------------------------------------+
    |                                     |                                     |
    v                                     v                                     v
+-----------------------+     +-----------------------+     +-----------------------+
|  Discovery Scanners   |     |    Cloud Connectors   |     |    System Collectors  |
|  - TLSScanner         |     |  - AWSConnector       |     |  - LinuxCollector     |
|  - SSHScanner         |     |  - AzureConnector     |     |                       |
|  - CertificateScanner |     |  - KubernetesConnector|     |                       |
|  - SourceCodeScanner  |     +-----------------------+     +-----------------------+
|  - DependencyScanner  |
+-----------------------+
```

---

## 🧩 Component Breakdown

### 1. Scanners (`app/scanners/`)
* **`tls_scanner.py` (`TLSScanner`)**: Performs live asynchronous TLS handshakes against hostnames, IP addresses, or URLs. Extracts public keys, curve parameters, signature schemes, and negotiated cipher suites.
* **`ssh_scanner.py` (`SSHScanner`)**: Connects to SSH port 22 to extract identification banners, host key algorithms (`rsa-sha2-512`, `ssh-ed25519`), and KEX algorithms (`curve25519-sha256`).
* **`certificate_scanner.py` (`CertificateScanner`)**: Recursively scans `.pem`, `.crt`, `.cer`, and `.der` files on disk, parsing X.509 structure, validity ranges, subject/issuer, and signature algorithms.
* **`source_code_scanner.py` (`SourceCodeScanner`)**: Scans `.py`, `.js`, `.ts`, `.go`, `.java`, `.cpp`, `.rs` source files for cryptographic calls (RSA, ECDSA, AES-GCM, SHA-384, Kyber, Dilithium) and captures file provenance.
* **`dependency_scanner.py` (`DependencyScanner`)**: Parses manifest files (`package.json`, `requirements.txt`, `go.mod`, `pom.xml`) for cryptographic libraries and version details.

### 2. Cloud & Infrastructure Connectors (`app/connectors/`)
* **`aws_connector.py` (`AWSConnector`)**: Read-only discovery across AWS KMS key specs, ACM certificates, ELBv2 SSL policies, S3 encryption, RDS encryption, and CloudFront CDNs.
* **`azure_connector.py` (`AzureConnector`)**: Read-only discovery across Azure Entra ID, Key Vault keys/certs, VM disks, Storage Accounts, App Gateways, SQL databases, and Front Door.
* **`k8s_connector.py` (`KubernetesConnector`)**: Read-only discovery across K8s cluster nodes, workloads, pods, services, ingresses, and public cert secrets under a strict **Zero-Secret Policy**.

### 3. Normalization & Mitigation Engine (`app/normalization/` & `app/risk/`)
* Maps raw observed algorithm strings (e.g. `sha256WithRSAEncryption`, `ecdh-sha2-nistp256`) to canonical PQC entities.
* Evaluates NIST PQC compliance against **FIPS 203 (ML-KEM)**, **FIPS 204 (ML-DSA)**, and **FIPS 205 (SLH-DSA)** standards.
* Assigns quantum vulnerability statuses: `QUANTUM_VULNERABLE`, `QUANTUM_RESISTANT`, `HYBRID_QUANTUM_SAFE`, or `LEGACY_BROKEN`.

---

## 🔌 REST API Endpoints Summary

All API endpoints are prefixed with `/api/v1`. Interactive Swagger documentation is served at [`http://localhost:8000/docs`](http://localhost:8000/docs).

| Router Module | Path | Description |
| :--- | :--- | :--- |
| `targets.py` | `GET /api/v1/targets`, `POST /api/v1/targets` | Register and manage discovery target scope. |
| `scans.py` | `POST /api/v1/scans/trigger`, `GET /api/v1/scans/{id}` | Launch discovery scan jobs and check status. |
| `findings.py` | `GET /api/v1/findings` | Query discovered cryptographic findings with filters. |
| `api_hub.py` | `POST /api/v1/api-hub/bulk-register` | Bulk register server endpoints or import OpenAPI specs. |
| `connectors.py` | `POST /api/v1/connectors/aws/sync`, `POST /api/v1/connectors/azure/sync`, `POST /api/v1/connectors/k8s/sync` | Trigger read-only cloud discovery sync jobs. |
| `readiness.py` | `GET /api/v1/readiness/assess` | Compute system PQC readiness metrics & CNSA 2.0 timelines. |
| `cbom.py` | `GET /api/v1/cbom/export` | Generate CycloneDX 1.6 Cryptographic Bill of Materials JSON. |
| `reports.py` | `GET /api/v1/reports/export/markdown` | Generate downloadable Markdown executive audit report. |

---

## 🛠️ Local Development & Testing

### Virtual Environment Setup
```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Database Migrations
```bash
alembic upgrade head
```

### Running Test Suite
```bash
PYTHONPATH=. pytest -v
```
All unit and integration tests run against an in-memory SQLite database, verifying ScopeGuard, Sanitizer, Normalization Engine, Scanners, API routes, and CBOM exports.
