#!/usr/bin/env bash
# Generates the development PKI for the reference deployment: a local CA
# and a localhost server certificate. Operators trust ca.pem on their
# client; TLS verification is never disabled.
#
# Usage: deploy/generate-dev-certs.sh [output-dir]   (default: deploy/certs)
#
# These certificates are for self-hosted development and testing only.
set -euo pipefail

out="${1:-$(cd "$(dirname "$0")" && pwd)/certs}"

if [[ -f "$out/ca.pem" && -f "$out/tls.crt" && -f "$out/tls.key" ]]; then
    echo "certificates already exist in $out (delete to regenerate)"
    exit 0
fi

mkdir -p "$out"

# Local trust anchor.
openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$out/ca.key" -out "$out/ca.pem" \
    -days 365 -subj "/CN=TermKeep Development CA" 2>/dev/null

# Server certificate for localhost, signed by the CA above.
openssl req -newkey rsa:2048 -nodes \
    -keyout "$out/tls.key" -out "$out/tls.csr" \
    -subj "/CN=localhost" 2>/dev/null

openssl x509 -req \
    -in "$out/tls.csr" \
    -CA "$out/ca.pem" -CAkey "$out/ca.key" -CAcreateserial \
    -out "$out/tls.crt" -days 365 \
    -extfile <(printf 'subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1') 2>/dev/null

rm -f "$out/tls.csr" "$out/ca.srl"
chmod 600 "$out/ca.key" "$out/tls.key"

echo "development certificates written to $out"
echo "client usage: termkeep --ca-cert $out/ca.pem status"
