#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
CERT_DIR="${LAB_DIR}/certificates"

mkdir -p "${CERT_DIR}"

echo "=== Generating Lab Certificates in ${CERT_DIR} ==="

# 1. Generate Classical RSA-2048 Certificate & Key
if [ ! -f "${CERT_DIR}/lab_cert.pem" ]; then
    echo "Generating Classical RSA-2048 Certificate..."
    openssl req -x509 -newkey rsa:2048 -keyout "${CERT_DIR}/lab_cert.key" \
        -out "${CERT_DIR}/lab_cert.pem" -sha256 -days 365 -nodes \
        -subj "/C=US/ST=LabState/L=LabCity/O=EnterpriseLab/CN=lab-classical-tls.local"
fi

# 2. Generate ECDSA-P256 Certificate & Key
if [ ! -f "${CERT_DIR}/lab_ecdsa_cert.pem" ]; then
    echo "Generating ECDSA-P256 Certificate..."
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -keyout "${CERT_DIR}/lab_ecdsa_cert.key" \
        -out "${CERT_DIR}/lab_ecdsa_cert.pem" -sha256 -days 365 -nodes \
        -subj "/C=US/ST=LabState/L=LabCity/O=EnterpriseLab/CN=lab-ecdsa-tls.local"
fi

# Compute SHA-256 Fingerprint of lab_cert.pem
FP_SHA256=$(openssl x509 -in "${CERT_DIR}/lab_cert.pem" -outform DER | openssl dgst -sha256 | awk '{print $2}' | tr '[:upper:]' '[:lower:]')

echo "Generated lab_cert.pem SHA-256 Fingerprint: ${FP_SHA256}"
echo "${FP_SHA256}" > "${CERT_DIR}/lab_cert_fingerprint.txt"

echo "=== Lab Certificates Successfully Generated ==="
