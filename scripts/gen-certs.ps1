# Generate CA, server, listener, and operator client certificates for Co2H.
# Requires openssl.exe on PATH (comes with Git for Windows or vcpkg).
param(
    [int]$Days = 3650,
    [string]$CertsDir = (Join-Path $PSScriptRoot "..\certs")
)

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path $CertsDir | Out-Null

Push-Location $CertsDir

Write-Host "[*] Generating CA..."
& openssl genrsa -out ca.key 4096
& openssl req -new -x509 -days $Days -key ca.key -out ca.crt `
    -subj "/CN=Co2H-CA/O=Co2H/C=XX"

Write-Host "[*] Generating team server certificate..."
& openssl genrsa -out server.key 4096
& openssl req -new -key server.key -out server.csr `
    -subj "/CN=teamserver/O=Co2H/C=XX"
& openssl x509 -req -days $Days -in server.csr -CA ca.crt -CAkey ca.key `
    -CAcreateserial -out server.crt

Write-Host "[*] Generating HTTPS listener certificate..."
& openssl genrsa -out listener.key 4096
& openssl req -new -key listener.key -out listener.csr `
    -subj "/CN=listener/O=Co2H/C=XX"
& openssl x509 -req -days $Days -in listener.csr -CA ca.crt -CAkey ca.key `
    -CAcreateserial -out listener.crt

Write-Host "[*] Generating operator client certificate..."
& openssl genrsa -out operator.key 4096
& openssl req -new -key operator.key -out operator.csr `
    -subj "/CN=operator/O=Co2H/C=XX"
& openssl x509 -req -days $Days -in operator.csr -CA ca.crt -CAkey ca.key `
    -CAcreateserial -out operator.crt

Remove-Item -Force *.csr -ErrorAction SilentlyContinue

Pop-Location

Write-Host "[+] Done. Certificates in: $CertsDir"
