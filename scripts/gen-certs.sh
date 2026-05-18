#!/usr/bin/env bash
# Generate CA, server, listener, and operator client certificates for Co2H.
# Run once before first deployment.
set -euo pipefail

CERTS_DIR="$(dirname "$0")/../certs"
mkdir -p "$CERTS_DIR"
cd "$CERTS_DIR"

DAYS=3650

echo "[*] Generating CA..."
openssl genrsa -out ca.key 4096
openssl req -new -x509 -days $DAYS -key ca.key -out ca.crt \
    -subj "/CN=Co2H-CA/O=Co2H/C=XX"

echo "[*] Generating team server certificate..."
openssl genrsa -out server.key 4096
openssl req -new -key server.key -out server.csr \
    -subj "/CN=teamserver/O=Co2H/C=XX"
openssl x509 -req -days $DAYS -in server.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out server.crt

echo "[*] Generating HTTPS listener certificate..."
openssl genrsa -out listener.key 4096
openssl req -new -key listener.key -out listener.csr \
    -subj "/CN=listener/O=Co2H/C=XX"
openssl x509 -req -days $DAYS -in listener.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out listener.crt

echo "[*] Generating operator client certificate (operator)..."
openssl genrsa -out operator.key 4096
openssl req -new -key operator.key -out operator.csr \
    -subj "/CN=operator/O=Co2H/C=XX"
openssl x509 -req -days $DAYS -in operator.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out operator.crt

# Clean up CSRs.
rm -f *.csr

echo "[+] Done. Files in: $CERTS_DIR"
echo "    ca.crt        — CA certificate (distribute to clients)"
echo "    server.crt/key — team server TLS"
echo "    listener.crt/key — HTTPS listener TLS"
echo "    operator.crt/key — operator client certificate"
