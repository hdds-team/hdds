#!/bin/bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

# Generate test certificates for HDDS Security samples
# Usage: ./generate_certs.sh

set -e

CERTS_DIR="$(dirname "$0")"
DAYS=365

# The permissions CA signs documents whose grants run to 2036, and HDDS checks
# that CA's own validity window before it checks the signature. A one-year CA
# would therefore stop every sample participant from starting 366 days after
# this script ran, with an expired-certificate error that names the CA and not
# the script that dated it. So it gets the horizon of the grants it signs.
PERM_CA_NOT_BEFORE="20200101000000Z"
PERM_CA_NOT_AFTER="20360101000000Z"

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
openssl req -x509 -nodes -newkey rsa:2048 \
    -not_before "$PERM_CA_NOT_BEFORE" -not_after "$PERM_CA_NOT_AFTER" \
    -keyout "$CERTS_DIR/permissions_ca_key.pem" \
    -out "$CERTS_DIR/permissions_ca.pem" \
    -subj "/C=US/O=HDDS/CN=HDDS-PermissionsCA" \
    2>/dev/null

echo "   [OK] Permissions CA: permissions_ca.pem (valid until 2036)"
echo "   NOTE: this overwrites the previous permissions CA. Any document signed"
echo "         by the old one stops verifying, so re-sign every governance and"
echo "         permissions file after regenerating it."
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

# ---------------------------------------------------------------------------
# Governance and permissions, SIGNED
#
# HDDS verifies both documents against the permissions CA before a participant
# starts. An unsigned, plain-XML document is refused: anyone who can write the
# file could otherwise rewrite the domain's access rules. This is the recipe to
# copy for your own documents.
# ---------------------------------------------------------------------------

echo "4. Writing and signing the governance and permissions documents..."

# Five elements, all required. HDDS chooses no security setting on the
# operator's behalf, so a <domain_rule> missing any one of them is refused at
# load, naming it. This document used to carry only three and was therefore
# signed, shipped, and rejected by the library it was generated for.
#
# This is the shorthand form: the domain-level <data_protection_kind> stands
# for one <topic_rule> matching every topic, with read and write access
# control on. Per-topic <topic_access_rules> are read as well; topic-level
# grants are in the permissions documents written below.
cat > "$CERTS_DIR/governance.xml" <<'XML'
<?xml version="1.0" encoding="utf-8"?>
<dds>
  <domain_access_rules>
    <domain_rule>
      <domains>0</domains>
      <allow_unauthenticated_participants>false</allow_unauthenticated_participants>
      <enable_join_access_control>true</enable_join_access_control>
      <discovery_protection_kind>ENCRYPT</discovery_protection_kind>
      <data_protection_kind>ENCRYPT</data_protection_kind>
    </domain_rule>
  </domain_access_rules>
</dds>
XML

# -text puts the `Content-Type: text/plain` MIME sub-header on the signed part,
# which is the shape every DDS vendor's tooling produces and expects.
# Do NOT add -nodetach here: for S/MIME output that would produce an opaque
# application/pkcs7-mime blob instead of multipart/signed.
openssl smime -sign \
    -in "$CERTS_DIR/governance.xml" \
    -signer "$CERTS_DIR/permissions_ca.pem" \
    -inkey "$CERTS_DIR/permissions_ca_key.pem" \
    -outform SMIME -text -md sha256 \
    -out "$CERTS_DIR/governance.p7s"

echo "   [OK] governance.p7s (signed by permissions_ca.pem)"

for name in "${PARTICIPANTS[@]}"; do
    # The subject_name MUST match the participant certificate's subject, or the
    # grant belongs to somebody else and HDDS will not apply it.
    subject=$(openssl x509 -in "$CERTS_DIR/${name}_cert.pem" -noout -subject \
        | sed 's/^subject=//')

    cat > "$CERTS_DIR/permissions_${name}.xml" <<XML
<?xml version="1.0" encoding="utf-8"?>
<dds>
  <permissions>
    <grant name="${name}Grant">
      <subject_name>${subject}</subject_name>
      <validity>
        <not_before>2020-01-01T00:00:00</not_before>
        <not_after>2036-01-01T00:00:00</not_after>
      </validity>
      <allow_rule>
        <domains>0</domains>
        <publish>
          <topics>
            <topic>SensorData</topic>
            <topic>CommandTopic</topic>
            <topic>LogData</topic>
          </topics>
        </publish>
        <subscribe>
          <topics>*</topics>
        </subscribe>
      </allow_rule>
      <deny_rule>
        <domains>0</domains>
        <publish>
          <topics>RestrictedTopic</topics>
        </publish>
      </deny_rule>
    </grant>
  </permissions>
</dds>
XML

    openssl smime -sign \
        -in "$CERTS_DIR/permissions_${name}.xml" \
        -signer "$CERTS_DIR/permissions_ca.pem" \
        -inkey "$CERTS_DIR/permissions_ca_key.pem" \
        -outform SMIME -text -md sha256 \
        -out "$CERTS_DIR/permissions_${name}.p7s"

    echo "   [OK] permissions_${name}.p7s for ${subject}"
done

echo ""
echo "5. Verifying the signatures the way HDDS does..."
openssl smime -verify -in "$CERTS_DIR/governance.p7s" \
    -CAfile "$CERTS_DIR/permissions_ca.pem" -out /dev/null \
    && echo "   [OK] governance.p7s verifies"
for name in "${PARTICIPANTS[@]}"; do
    openssl smime -verify -in "$CERTS_DIR/permissions_${name}.p7s" \
        -CAfile "$CERTS_DIR/permissions_ca.pem" -out /dev/null \
        && echo "   [OK] permissions_${name}.p7s verifies"
done

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
echo "Point HDDS at the SIGNED documents, never at the .xml sources:"
echo "  .governance_xml(\"governance.p7s\")"
echo "  .permissions_xml(\"permissions_Participant1.p7s\")"
echo "  .permissions_ca(\"permissions_ca.pem\")"
echo ""
echo "Note: These are TEST certificates only."
echo "      Use a proper PKI for production deployments."
