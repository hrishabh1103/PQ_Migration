# Enterprise Cryptographic Discovery Platform (PQC Migration Readiness)

An enterprise-grade cryptographic discovery, inventory, normalization, risk assessment, and Cryptographic Bill of Materials (CBOM) generation platform for Post-Quantum Cryptography (PQC) migration readiness.

## Features

- **Hierarchy-Aware Entity Modeling**: `AuthorizedTarget` -> `ScanJob` -> `Asset` -> `Service` -> `CryptoFinding` -> `NormalizedAlgorithm`
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

### Local Development (Single Command)
```bash
./run_dev.sh
```
- **React Frontend**: http://localhost:5173
- **FastAPI REST API Docs**: http://localhost:8000/docs

### Docker Compose
```bash
docker compose up --build
```

---

## Running Test Suite

```bash
cd backend
source venv/bin/activate
PYTHONPATH=. pytest -v
```

---

## Documentation

For full architecture details, scanner testing guides, and risk assessment specifications, see:
- [PQC_DISCOVERY_PLATFORM_GUIDE.md](PQC_DISCOVERY_PLATFORM_GUIDE.md)
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
