# 🔰 Project Quantum: Absolute Beginner's Step-by-Step Guide

Welcome to **Project Quantum** (Enterprise Post-Quantum Cryptography Discovery & Readiness Platform)! This guide is designed specifically for beginners. You do not need deep security background or complex command-line experience to get started.

---

## 🌟 What is Project Quantum?

**Project Quantum** helps you inspect and inventory all encryption used across your organization's servers, cloud providers, source code, and Kubernetes clusters.

### Why is this important?
Quantum computers in the future will be capable of breaking conventional encryption standards like **RSA** and **ECC (Elliptic Curve Cryptography)**. NIST (National Institute of Standards and Technology) has released new **Post-Quantum Cryptography (PQC)** standards (such as **ML-KEM-768** and **ML-DSA-65**).

Project Quantum scans your infrastructure, finds old/vulnerable encryption algorithms, and gives you a clear **remediation roadmap** and **Cryptographic Bill of Materials (CBOM)**.

---

## 🚀 Step 1: How to Launch the Application

### Option A: Standard 1-Command Startup (Recommended)

1. Open your Terminal on macOS/Linux.
2. Navigate to the project folder:
   ```bash
   cd /path/to/Projext_Quantum
   ```
3. Run the single startup script:
   ```bash
   ./run_dev.sh
   ```
4. That's it! The script automatically:
   - Sets up Python dependencies in `backend/venv`
   - Applies database migrations
   - Starts the backend server at [`http://localhost:8000`](http://localhost:8000)
   - Starts the web dashboard at [`http://localhost:5173`](http://localhost:5173)

5. Open your web browser and go to:
   👉 **[`http://localhost:5173`](http://localhost:5173)**

---

## 🖥️ Step 2: Navigating the Dashboard & Key Features

When you open the web UI, you will see a left-hand navigation menu with the following main sections:

| Menu Item | Purpose | Beginner Explanation |
| :--- | :--- | :--- |
| 📊 **Dashboard** | System-wide Cryptographic Summary | Overview of total scanned targets, total findings, risk ratings, and top vulnerable algorithms. |
| 🎯 **Targets** | Target Management | Register servers, web URLs, IP addresses, local repository folders, or certificate stores. |
| 🔍 **Scans** | Run Scanners | Trigger real-time discovery scans (TLS/HTTPS scanner, SSH scanner, X.509 cert scanner, etc.). |
| 🔐 **Crypto Findings** | Detailed Inventory | View every single discovered cryptographic algorithm, key size, and quantum vulnerability status. |
| ⚡ **API & Server Hub** | Bulk Server & Spec Importer | Register entire lists of API server URLs or upload OpenAPI/Swagger JSON files for bulk auditing. |
| ☁️ **AWS Connector** | AWS Cloud Discovery | Read-only scan of AWS KMS keys, ACM certificates, ELB load balancers, S3, and RDS encryption. |
| 🔷 **Azure Connector** | Azure Cloud Discovery | Read-only scan of Azure Key Vaults, Virtual Machines, Storage Accounts, and SQL Databases. |
| ☸️ **Kubernetes Connector** | K8s Cluster Audit | Audit Kubernetes cluster nodes, pods, services, ingresses, and TLS secret metadata securely. |
| 🛡️ **PQC Readiness & Reports** | Risk & CBOM Generation | Evaluate overall compliance with NIST PQC standards (FIPS 203/204/205) and download CBOM/Audit reports. |

---

## 🧪 Step 3: How to Scan Your First Server / Web Endpoint

Suppose you want to test a web server or Jenkins instance (e.g. `http://43.204.101.138:8080` or `https://google.com`).

### Method 1: Using the API & Server Hub
1. Click **API & Server Hub** in the left menu.
2. In the **Server Endpoints List** text area, paste your URL or IP:
   ```text
   http://43.204.101.138:8080
   ```
3. Click **Register Servers & Run Quantum Discovery**.
4. The system automatically registers the target and launches a scan!

### Method 2: Registering a Target Manually
1. Click **Targets** in the left menu.
2. Click the **Register Target** button in the top right.
3. Fill in:
   - **Target Name**: `My Test Server`
   - **Target Type**: Select `HOSTNAME` or `URL`
   - **Target Value**: `43.204.101.138` (or `google.com`)
   - Check **Is Authorized**
4. Click **Save Target**.
5. Click **Scans** in the left menu → Click **New Scan** → Select your target → Select **TLS & Network Scanner** → Click **Trigger Scan**.

---

## 📁 Step 4: How to Scan Source Code & Dependency Manifests

You can scan local project folders on your computer for hardcoded cryptographic usage or library dependencies.

1. Go to **Targets** → Click **Register Target**.
2. Set:
   - **Target Type**: `REPOSITORY`
   - **Target Value**: Absolute folder path (e.g. `/Users/hrishabh/Projects/my-app`)
3. Go to **Scans** → Trigger **Source Code Crypto Scanner** or **Package Dependency Scanner**.
4. The scanner reads source code files (`.py`, `.ts`, `.js`, `.go`, `.java`, etc.) and manifest files (`package.json`, `requirements.txt`) to locate RSA, AES, ECDSA, SHA-256, or Kyber library usages with exact line numbers!

---

## ☁️ Step 5: How to Sync AWS, Azure, or Kubernetes Cloud Resources

### AWS Cloud Sync
1. Open `backend/.env` file and set your AWS read-only credentials:
   ```ini
   AWS_ACCESS_KEY_ID=AKIA...
   AWS_SECRET_ACCESS_KEY=...
   AWS_DEFAULT_REGION=us-east-1
   ```
2. Go to **AWS Connector** tab in the UI.
3. Click **Validate Credentials** → Click **Run AWS Discovery Sync**.

### Azure Cloud Sync
1. Open `backend/.env` and set Azure service principal credentials:
   ```ini
   AZURE_TENANT_ID=...
   AZURE_CLIENT_ID=...
   AZURE_CLIENT_SECRET=...
   AZURE_SUBSCRIPTION_ID=...
   ```
2. Go to **Azure Connector** tab → Click **Validate Azure Credentials** → Click **Trigger Full Azure Discovery**.

### Kubernetes Cluster Sync
1. Set `KUBECONFIG_PATH` in `backend/.env` (e.g. `/Users/yourusername/.kube/config`).
2. Go to **Kubernetes Connector** tab → Click **Trigger Kubernetes Discovery**.
3. *Note: Zero private keys or passwords are ever read! The scanner operates under strict read-only public metadata security policies.*

---

## 📄 Step 6: How to Export Reports & Cryptographic Bill of Materials (CBOM)

Once scans complete:
1. Navigate to **PQC Readiness & Reports** tab.
2. View real-time risk scores and NIST PQC FIPS standard readiness.
3. Click **Download Audit Report (.md)** to get a complete Markdown remediation report.
4. Click **Export CycloneDX 1.6 CBOM (.json)** to generate an industry-standard Cryptographic Bill of Materials file (`cyclonedx_cbom_1.6.json`).

---

## ❓ Frequently Asked Questions (FAQ)

**Q: Does Project Quantum modify any of my servers or cloud settings?**  
*A: No! All discovery scanners and cloud connectors operate strictly in **read-only** mode.*

**Q: Can I access the API directly?**  
*A: Yes! Open [`http://localhost:8000/docs`](http://localhost:8000/docs) in your browser to view and execute all REST API endpoints interactively via Swagger UI.*

**Q: How do I run automated unit tests?**  
*A:*
```bash
cd backend
source venv/bin/activate
PYTHONPATH=. pytest -v
```
