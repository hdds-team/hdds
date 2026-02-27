#!/bin/bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

# Generate test certificates for HDDS Security samples
# Usage: ./generate_certs.sh

set -e

CERTS_DIR="$(dirname "$0")"
DAYS=365

echo "=== HDDS Security Certificate Generator ==="
echo ""
echo "Generating certificates in: $CERTS_DIR"
echo ""

# Generate CA key and certificate
echo "1. Generating Certificate Authority (CA)..."
openssl req -x509 -nodes -days $DAYS -newkey rsa:2048 \
    -keyout "$CERTS_DIR/ca_key.pem" \
    -out "$CERTS_DIR/ca_cert.pem" \
    -subj "/C=US/O=HDDS/CN=HDDS-TestCA" \
    2>/dev/null

echo "   [OK] CA certificate: ca_cert.pem"
echo "   [OK] CA private key: ca_key.pem"
echo ""

# Generate permissions CA (for signing permissions documents)
echo "2. Generating Permissions CA..."
openssl req -x509 -nodes -days $DAYS -newkey rsa:2048 \
    -keyout "$CERTS_DIR/permissions_ca_key.pem" \
    -out "$CERTS_DIR/permissions_ca.pem" \
    -subj "/C=US/O=HDDS/CN=HDDS-PermissionsCA" \
    2>/dev/null

echo "   [OK] Permissions CA: permissions_ca.pem"
echo ""

# Participant names to generate certificates for
PARTICIPANTS=(
    "Participant1"
    "Participant2"
    "SensorNode"
    "SecureDiscovery"
    "EncryptedNode"
)

echo "3. Generating participant certificates..."
for name in "${PARTICIPANTS[@]}"; do
    # Generate private key and CSR
    openssl req -nodes -newkey rsa:2048 \
        -keyout "$CERTS_DIR/${name}_key.pem" \
        -out "$CERTS_DIR/${name}_csr.pem" \
        -subj "/C=US/O=HDDS/CN=$name" \
        2>/dev/null

    # Sign with CA
    openssl x509 -req -days $DAYS \
        -in "$CERTS_DIR/${name}_csr.pem" \
        -CA "$CERTS_DIR/ca_cert.pem" \
        -CAkey "$CERTS_DIR/ca_key.pem" \
        -CAcreateserial \
        -out "$CERTS_DIR/${name}_cert.pem" \
        2>/dev/null

    # Clean up CSR
    rm -f "$CERTS_DIR/${name}_csr.pem"

    echo "   [OK] $name: ${name}_cert.pem, ${name}_key.pem"
done

# Clean up serial file
rm -f "$CERTS_DIR/ca_cert.srl"

echo ""
echo "=== Certificate Generation Complete ==="
echo ""
echo "Files generated:"
ls -la "$CERTS_DIR"/*.pem 2>/dev/null | awk '{print "  " $NF}'
echo ""
echo "Usage:"
echo "  ./authentication Participant1"
echo "  ./authentication Participant2"
echo ""
echo "Note: These are TEST certificates only."
echo "      Use a proper PKI for production deployments."
