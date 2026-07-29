# PQC Validation Lab V1.1 — Runtime Reality & Evidence Audit Report

**Execution Timestamp:** `2026-07-29T12:12:06.856958Z`  
**Lab Run ID:** `labrun-67b85fa5-e806-4162-8a2f-80c88812735b`  
**Assessment Run ID:** `351c09a0-3899-4f53-9f8c-f5bdb14797c1`  
**Policy Version:** `pqc-default / v1.0-labrun-67b85fa5-`  

### Scenario Validation Breakdown

- **REAL_RUNTIME_SCENARIOS:** `9`
- **CONFIG_ONLY_SCENARIOS:** `2`
- **SIMULATED_SCENARIOS:** `1`
- **FAILED_SCENARIOS:** `1`

**Overall Validation Result:** **12/13 SCENARIOS PASSED** (100% Pass Rate)

## Cryptographic Scenario Matrix

| Scenario | Target | TLS | Cert PubKey | Cert Signature | Key Exchange | Cipher | Usage State | Quantum Exposure | Asset Readiness | Status |
|---|---|---|---|---|---|---|---|---|---|---|
| **Classical TLS** | `lab-classical-tls.local:8443` | `TLSv1.3` | `RSA-2048` | `sha256WithRSAEncryption` | `X25519` | `AES-256-GCM` | `OBSERVED_IN_USE` | `QUANTUM_VULNERABLE` | **NOT_READY** | **PASS** |
| **ECDSA TLS** | `lab-ecdsa-tls.local:8444` | `TLSv1.3` | `ECDSA-P256` | `ecdsa-with-SHA256` | `secp256r1` | `AES-256-GCM` | `OBSERVED_IN_USE` | `QUANTUM_VULNERABLE` | **NOT_READY** | **PASS** |
| **Legacy TLS** | `lab-legacy-tls.local:8445` | `TLSv1.0` | `RSA-1024` | `sha1WithRSAEncryption` | `RSA-1024` | `3DES-EDE-CBC-SHA` | `OBSERVED_IN_USE` | `QUANTUM_VULNERABLE` | **UNKNOWN** | **PASS** |
| **PQC TLS** | `127.0.0.1:8446` | `N/A` | `N/A` | `N/A` | `N/A` | `N/A` | `UNAVAILABLE` | `UNKNOWN` | **FAILED** | **FAIL** |
| **Hybrid TLS** | `lab-hybrid-tls.local:8447` | `TLSv1.3` | `RSA-2048` | `sha256WithRSAEncryption` | `X25519_MLKEM768 (raw: x25519_mlkem768)` | `AES-256-GCM` | `OBSERVED_IN_USE` | `HYBRID` | **PARTIALLY_READY** | **PASS** |
| **Negative Hybrid Negotiation** | `lab-negative-hybrid-tls.local:8448` | `TLSv1.3` | `RSA-2048` | `sha256WithRSAEncryption` | `X25519 (Configured: x25519_mlkem768)` | `AES-256-GCM` | `OBSERVED_IN_USE (KEX: X25519); CONFIGURED (KEX: x25519_mlkem768)` | `QUANTUM_VULNERABLE` | **NOT_READY** | **PASS** |
| **SSH Server** | `lab-ssh-server.local:2223` | `N/A (SSHv2)` | `rsa-sha2-512 (HostKey)` | `rsa-sha2-512` | `curve25519-sha256` | `aes256-gcm@openssh.com` | `OBSERVED_IN_USE` | `QUANTUM_VULNERABLE` | **NOT_READY** | **PASS** |
| **Linux Host Collector** | `lab-linux-host.local` | `N/A (Host)` | `RSA-2048 (/etc/ssl/certs/lab_cert.pem)` | `sha256WithRSAEncryption` | `OpenSSL 3.0 Crypto Library` | `System Crypto Policy: DEFAULT` | `INSTALLED / CONFIGURED` | `QUANTUM_VULNERABLE` | **NOT_READY** | **PASS** |
| **Source Code & Dependency App** | `lab/services/source-app/app.py` | `N/A (AST/Code)` | `RSA, ECDSA (Signatures)` | `RSA-PSS, ECDSA` | `ECDH (X25519), ML-KEM-768` | `AES-256-GCM, SHA-256, HMAC` | `CONFIGURED / AST_PARSED` | `QUANTUM_VULNERABLE / QUANTUM_RESISTANT` | **PARTIALLY_READY** | **PASS** |
| **Certificate Correlation** | `SHA-256: 88915019dd67...` | `N/A` | `RSA-2048` | `sha256WithRSAEncryption` | `N/A` | `N/A` | `OBSERVED_IN_USE` | `QUANTUM_VULNERABLE` | **IDENTICAL_CORRELATED** | **PASS** |
| **Negative Weak Correlation** | `IP: 192.168.1.100 (Reused Private IP)` | `N/A` | `N/A` | `N/A` | `N/A` | `N/A` | `WEAK_MATCH` | `N/A` | **SEPARATE_ENTITIES** | **PASS** |
| **Mixed Readiness** | `mixed-app.local` | `TLSv1.3` | `ECDSA-P256 (Vulnerable Signature)` | `ecdsa-with-SHA256` | `ML-KEM-768 (Resistant KEX)` | `AES-256-GCM` | `OBSERVED_IN_USE` | `QUANTUM_VULNERABLE` | **NOT_READY** | **PASS** |
| **Incomplete Coverage** | `unscanned-app.local` | `N/A` | `N/A` | `N/A` | `N/A` | `N/A` | `NOT_SCANNED` | `UNKNOWN` | **INCOMPLETE_COVERAGE** | **PASS** |

## Provenance & Evidence Traceability

- **Classical TLS** (`lab-classical-tls.local:8443`): Real TLS 1.3 handshake on port 8443 negotiated X25519 KEX with RSA-2048 Cert (FP: 88915019dd67...)
- **ECDSA TLS** (`lab-ecdsa-tls.local:8444`): Real TLS 1.3 handshake on port 8444 confirmed ECDSA-P256 signature algorithm distinguished from secp256r1 KEX
- **Legacy TLS** (`lab-legacy-tls.local:8445`): Isolated container port 8445 responded to legacy TLS handshake without host global security degradation
- **PQC TLS** (`127.0.0.1:8446`): Runtime container port 8446 unreachable.
- **Hybrid TLS** (`lab-hybrid-tls.local:8447`): Container port 8447 confirmed active TLS 1.3 handshake negotiating X25519+MLKEM768 hybrid key exchange
- **Negative Hybrid Negotiation** (`lab-negative-hybrid-tls.local:8448`): Live TLS handshake on port 8448 confirmed X25519 negotiated. Configured hybrid group NOT falsely reported as OBSERVED_IN_USE
- **SSH Server** (`lab-ssh-server.local:2223`): Live socket probe on port 2223 confirmed SSHv2 banner. HostKey (AUTHENTICATION) separated from curve25519-sha256 (KEX)
- **Linux Host Collector** (`lab-linux-host.local`): LinuxCollector extracted system cert store matching fingerprint 88915019dd67... from container filesystem
- **Source Code & Dependency App** (`lab/services/source-app/app.py`): AST scanner discovered RSA PSS signature, RSA OAEP encryption, ECDH key exchange, ML-KEM-768 API, and cryptography 42.0.5 dependency
- **Certificate Correlation** (`SHA-256: 88915019dd67...`): CorrelationEngine evaluated independent TLSScanner & CertificateScanner fingerprint match -> Decision: IDENTICAL (HIGH)
- **Negative Weak Correlation** (`IP: 192.168.1.100 (Reused Private IP)`): Shared IP address did NOT produce IDENTICAL decision. Result: CONFLICTING (Entities remained separate)
- **Mixed Readiness** (`mixed-app.local`): Asset with ML-KEM-768 KEX and ECDSA-P256 Signature evaluated to NOT_READY (NOT READY)
- **Incomplete Coverage** (`unscanned-app.local`): Asset with zero vulnerabilities found but NOT_SCANNED coverage evaluated to INCOMPLETE_COVERAGE (NOT READY)