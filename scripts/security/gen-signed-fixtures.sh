#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com
#
# Regenerate the signed governance/permissions fixtures used by the
# DDS-Security document verifier tests (crates/hdds/src/security/cms.rs,
# signed_document.rs, p7s.rs).
#
# The tests NEVER run this script: they consume the committed files under
# crates/hdds/src/security/fixtures/ through include_bytes!. Run it by hand
# when a fixture must change, then commit the regenerated files.
#
# Every certificate minted here is valid until 2036 (or already expired, for
# the expired-CA case) so no test starts failing on a calendar boundary.
#
# Requires: openssl 3.x (developed against 3.5.6).

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${HERE}/../../crates/hdds/src/security/fixtures"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

# Taken before anything is written, so the completeness check at the bottom can
# tell "regenerated" from "left over from a previous run".
RUN_MARKER="${WORK}/.run-started"
: > "${RUN_MARKER}"

mkdir -p "${OUT}"

# The identity these documents are written for: the subject of
# crates/hdds/src/security/test_pki.rs TEST_IDENTITY_CERT_PEM.
IDENTITY_DN="CN=DDS Test Identity, O=HDDS Test"
OTHER_DN="CN=Somebody Else, O=HDDS Test"

# ---------------------------------------------------------------------------
# Certificate authorities
# ---------------------------------------------------------------------------

# Every validity window is written explicitly, so regenerating the set on a
# different day does not move any boundary a test depends on.
VALID_FROM="20200101000000Z"
VALID_TO="20360101000000Z"

# EC P-256 permissions CA, the primary signer.
openssl ecparam -name prime256v1 -genkey -noout -out "${WORK}/perm_ca_ec.key" 2>/dev/null
openssl req -x509 -new -key "${WORK}/perm_ca_ec.key" -sha256 \
    -subj "/CN=HDDS Test Permissions CA/O=HDDS Test" \
    -not_before "${VALID_FROM}" -not_after "${VALID_TO}" \
    -out "${OUT}/perm_ca_ec.pem" 2>/dev/null

# RSA-2048 permissions CA, to prove the RSA branch of the OID map.
openssl req -x509 -new -newkey rsa:2048 -nodes -keyout "${WORK}/perm_ca_rsa.key" \
    -sha256 -subj "/CN=HDDS Test RSA Permissions CA/O=HDDS Test" \
    -not_before "${VALID_FROM}" -not_after "${VALID_TO}" \
    -out "${OUT}/perm_ca_rsa.pem" 2>/dev/null

# A second, unrelated CA: documents signed by it must be refused.
openssl ecparam -name prime256v1 -genkey -noout -out "${WORK}/other_ca.key" 2>/dev/null
openssl req -x509 -new -key "${WORK}/other_ca.key" -sha256 \
    -subj "/CN=HDDS Other Permissions CA/O=HDDS Test" \
    -not_before "${VALID_FROM}" -not_after "${VALID_TO}" \
    -out "${OUT}/other_perm_ca.pem" 2>/dev/null

# An already-expired CA: a window that closed in 2020.
openssl ecparam -name prime256v1 -genkey -noout -out "${WORK}/expired_ca.key" 2>/dev/null
openssl req -x509 -new -key "${WORK}/expired_ca.key" -sha256 \
    -subj "/CN=HDDS Expired Permissions CA/O=HDDS Test" \
    -not_before "${VALID_FROM}" -not_after "20200201000000Z" \
    -out "${OUT}/expired_perm_ca.pem" 2>/dev/null

# ---------------------------------------------------------------------------
# Documents
# ---------------------------------------------------------------------------

# Every protection this release can decide is stated explicitly. The parser
# refuses a domain_rule that leaves one unsaid, because an absent protection
# element used to read as "off" with no diagnostic - which is the one reading
# an operator never intends.
cat > "${WORK}/governance.xml" <<'XML'
<?xml version="1.0" encoding="utf-8"?>
<dds>
  <domain_access_rules>
    <domain_rule>
      <domains>0</domains>
      <allow_unauthenticated_participants>false</allow_unauthenticated_participants>
      <enable_join_access_control>true</enable_join_access_control>
      <discovery_protection_kind>ENCRYPT</discovery_protection_kind>
      <liveliness_protection_kind>NONE</liveliness_protection_kind>
      <rtps_protection_kind>NONE</rtps_protection_kind>
      <data_protection_kind>ENCRYPT</data_protection_kind>
    </domain_rule>
  </domain_access_rules>
</dds>
XML

write_permissions() {
    # $1 = output path, $2 = subject DN, $3 = not_before, $4 = not_after
    cat > "$1" <<XML
<?xml version="1.0" encoding="utf-8"?>
<dds>
  <permissions>
    <grant name="HddsTestGrant">
      <subject_name>$2</subject_name>
      <validity>
        <not_before>$3</not_before>
        <not_after>$4</not_after>
      </validity>
      <allow_rule>
        <domains>0</domains>
        <publish>
          <topics>*</topics>
        </publish>
        <subscribe>
          <topics>*</topics>
        </subscribe>
      </allow_rule>
    </grant>
  </permissions>
</dds>
XML
}

write_permissions "${WORK}/permissions.xml" "${IDENTITY_DN}" \
    "2020-01-01T00:00:00" "2036-01-01T00:00:00"
write_permissions "${WORK}/permissions_other_subject.xml" "${OTHER_DN}" \
    "2020-01-01T00:00:00" "2036-01-01T00:00:00"
write_permissions "${WORK}/permissions_expired_grant.xml" "${IDENTITY_DN}" \
    "2020-01-01T00:00:00" "2021-01-01T00:00:00"

cp "${WORK}/governance.xml" "${OUT}/governance.xml"
cp "${WORK}/permissions.xml" "${OUT}/permissions.xml"

sign_smime() {
    # $1 = document, $2 = signer cert, $3 = signer key, $4 = output, $5.. extra flags
    local doc="$1" cert="$2" key="$3" out="$4"
    shift 4
    # S/MIME output with NO -nodetach is multipart/signed (RFC 5751): the
    # document travels as the first body part and the CMS blob as the second.
    # -nodetach would instead produce an opaque base64 application/pkcs7-mime.
    #
    # -text prefixes the signed part with a `Content-Type: text/plain` MIME
    # sub-header. That is the shape every vendor document on disk uses (the
    # eProsima and OMG TESTONLY files included), and the sub-header is part of
    # what the messageDigest covers, so it is the shape worth testing. openssl
    # 3.x without -text emits a part with NO sub-headers at all; one fixture
    # below keeps that shape on purpose.
    openssl smime -sign -in "${doc}" -signer "${cert}" -inkey "${key}" \
        -outform SMIME -text -md sha256 "$@" -out "${out}"
}

# Sign naming the signer by subjectKeyIdentifier instead of issuer+serial.
#
# This needs `openssl cms`, not `openssl smime`. The smime app has no -keyid:
# handed one it prints "Unknown option or cipher: keyid" on stderr and then
# EXITS 0, so `set -e` never fires and the output file is silently left at
# whatever it contained before: the two key-identifier CAs would be
# regenerated while the documents they signed stayed untouched, leaving a
# fixture set signed by a CA that no longer exists. `openssl cms ... -keyid`
# yields the same `d.subjectKeyIdentifier` SignerInfo shape as the committed
# fixtures.
sign_smime_keyid() {
    # $1 = document, $2 = signer cert, $3 = signer key, $4 = output
    openssl cms -sign -in "$1" -signer "$2" -inkey "$3" \
        -outform SMIME -text -md sha256 -keyid -out "$4"
}

sign_smime "${WORK}/governance.xml" "${OUT}/perm_ca_ec.pem" "${WORK}/perm_ca_ec.key" \
    "${OUT}/governance_ec.smime"
sign_smime "${WORK}/permissions.xml" "${OUT}/perm_ca_ec.pem" "${WORK}/perm_ca_ec.key" \
    "${OUT}/permissions_ec.smime"
sign_smime "${WORK}/permissions.xml" "${OUT}/perm_ca_rsa.pem" "${WORK}/perm_ca_rsa.key" \
    "${OUT}/permissions_rsa.smime"
sign_smime "${WORK}/permissions.xml" "${OUT}/other_perm_ca.pem" "${WORK}/other_ca.key" \
    "${OUT}/permissions_other_ca.smime"
sign_smime "${WORK}/permissions.xml" "${OUT}/expired_perm_ca.pem" "${WORK}/expired_ca.key" \
    "${OUT}/permissions_expired_ca.smime"
sign_smime "${WORK}/permissions_other_subject.xml" "${OUT}/perm_ca_ec.pem" \
    "${WORK}/perm_ca_ec.key" "${OUT}/permissions_other_subject_ec.smime"
sign_smime "${WORK}/permissions_expired_grant.xml" "${OUT}/perm_ca_ec.pem" \
    "${WORK}/perm_ca_ec.key" "${OUT}/permissions_expired_grant_ec.smime"

# No signed attributes at all: RFC 5652 5.3 lets a signer omit signedAttrs, but
# DDS-Security documents must carry contentType + messageDigest, so the verifier
# refuses this shape.
sign_smime "${WORK}/permissions.xml" "${OUT}/perm_ca_ec.pem" "${WORK}/perm_ca_ec.key" \
    "${OUT}/permissions_noattr_ec.smime" -noattr

# The access-control audit end-to-end fixture: domain 229, sensor/* granted and
# admin/* denied, for the identity in test_pki.rs. Its XML sources are committed
# next to the signed output because the assertions in security::e2e_tests read
# like the rules do.
sign_smime "${OUT}/audit_governance.xml" "${OUT}/perm_ca_ec.pem" "${WORK}/perm_ca_ec.key" \
    "${OUT}/audit_governance.smime"
sign_smime "${OUT}/audit_permissions.xml" "${OUT}/perm_ca_ec.pem" "${WORK}/perm_ca_ec.key" \
    "${OUT}/audit_permissions.smime"

# openssl 3.x default S/MIME shape: a first body part with no sub-headers and
# no blank line before the content. A parser that hunts for the header/body
# separator unconditionally reads this part as empty.
openssl smime -sign -in "${WORK}/permissions.xml" -signer "${OUT}/perm_ca_ec.pem" \
    -inkey "${WORK}/perm_ca_ec.key" -outform SMIME -md sha256 \
    -out "${OUT}/permissions_ec_no_subheaders.smime"

# ---------------------------------------------------------------------------
# subjectKeyIdentifier signers
# ---------------------------------------------------------------------------
#
# RFC 5652 5.3 lets a SignerInfo name its signer either by issuer+serial or by
# subjectKeyIdentifier, and both are accept paths in the trust check. openssl
# writes issuer+serial unless -keyid is passed, so without these two fixtures
# the key-identifier branch is untested code inside a trust decision. Their CAs
# are minted separately so that regenerating THIS section does not disturb the
# fixtures above.

openssl ecparam -name prime256v1 -genkey -noout -out "${WORK}/perm_ca_keyid.key" 2>/dev/null
openssl req -x509 -new -key "${WORK}/perm_ca_keyid.key" -sha256 \
    -subj "/CN=HDDS Test KeyId Permissions CA/O=HDDS Test" \
    -not_before "${VALID_FROM}" -not_after "${VALID_TO}" \
    -out "${OUT}/perm_ca_keyid.pem" 2>/dev/null

openssl ecparam -name prime256v1 -genkey -noout -out "${WORK}/other_ca_keyid.key" 2>/dev/null
openssl req -x509 -new -key "${WORK}/other_ca_keyid.key" -sha256 \
    -subj "/CN=HDDS Other KeyId Permissions CA/O=HDDS Test" \
    -not_before "${VALID_FROM}" -not_after "${VALID_TO}" \
    -out "${OUT}/other_perm_ca_keyid.pem" 2>/dev/null

sign_smime_keyid "${WORK}/permissions.xml" "${OUT}/perm_ca_keyid.pem" \
    "${WORK}/perm_ca_keyid.key" "${OUT}/permissions_keyid.smime"
sign_smime_keyid "${WORK}/permissions.xml" "${OUT}/other_perm_ca_keyid.pem" \
    "${WORK}/other_ca_keyid.key" "${OUT}/permissions_other_ca_keyid.smime"

# Attached DER PKCS#7 (eContent present): the second shape the spec allows.
openssl smime -sign -in "${WORK}/permissions.xml" -signer "${OUT}/perm_ca_ec.pem" \
    -inkey "${WORK}/perm_ca_ec.key" -outform DER -nodetach -md sha256 \
    -out "${OUT}/permissions_ec_attached.p7s"

# Detached DER PKCS#7 (eContent absent): carries a signature but no document,
# so it can never be a governance/permissions source.
openssl smime -sign -in "${WORK}/permissions.xml" -signer "${OUT}/perm_ca_ec.pem" \
    -inkey "${WORK}/perm_ca_ec.key" -outform DER -md sha256 \
    -out "${OUT}/permissions_ec_detached.p7s"

# Tampered body: a validly signed S/MIME whose XML was edited afterwards.
python3 - "${OUT}/permissions_ec.smime" "${OUT}/permissions_tampered.smime" <<'PY'
import sys
src, dst = sys.argv[1], sys.argv[2]
data = open(src, "rb").read()
needle = b"<topics>*</topics>"
assert data.count(needle) >= 1, "fixture layout changed"
out = data.replace(needle, b"<topics>#</topics>", 1)
assert out != data
open(dst, "wb").write(out)
PY

# ---------------------------------------------------------------------------
# Revocation: a CA, two leaves it issued, and a CRL revoking one of them
# ---------------------------------------------------------------------------
#
# The identity CA in test_pki.rs has no private key in this repository, so no
# CRL can ever be issued for it. Revocation therefore gets its own small PKI
# rather than a rewrite of the existing one: a CA, a certificate it revokes,
# and a certificate it does not - because a test that only proves a revoked
# certificate is refused cannot tell that apart from refusing everything.

REVDIR="${WORK}/rev"
mkdir -p "${REVDIR}/db"
: > "${REVDIR}/db/index.txt"
echo 01 > "${REVDIR}/db/serial"
echo 01 > "${REVDIR}/db/crlnumber"

openssl ecparam -name prime256v1 -genkey -noout -out "${REVDIR}/ca.key" 2>/dev/null
openssl req -x509 -new -key "${REVDIR}/ca.key" -sha256 \
    -subj "/CN=HDDS Test Revocation CA/O=HDDS Test" \
    -not_before "${VALID_FROM}" -not_after "${VALID_TO}" \
    -out "${OUT}/revocation_ca.pem" 2>/dev/null
cp "${OUT}/revocation_ca.pem" "${REVDIR}/ca.pem"

cat > "${REVDIR}/ca.cnf" <<CNF
[ ca ]
default_ca = CA_default
[ CA_default ]
dir = ${REVDIR}
database = ${REVDIR}/db/index.txt
serial = ${REVDIR}/db/serial
crlnumber = ${REVDIR}/db/crlnumber
certificate = ${REVDIR}/ca.pem
private_key = ${REVDIR}/ca.key
new_certs_dir = ${REVDIR}/db
default_md = sha256
policy = pol
# Ten years, so the CRL's own nextUpdate does not expire under a test suite
# that refuses a stale CRL on purpose.
default_crl_days = 3650
[ pol ]
commonName = supplied
organizationName = optional
CNF

# Three leaves: the one that gets revoked (serial 01), the one that does not
# (02), and the LOCAL identity a test participant authenticates AS (03).
#
# The private keys of the first two go to WORK and die with it: no test reads
# them, and writing them to OUT would commit private keys to the repository.
# A fixture directory holds what tests consume; a key nothing consumes is only
# a liability.
#
# The LOCAL identity's key IS committed, as `revocation_local_identity_key.pem`,
# because a test that drives `process_handshake` with revocation ON needs a
# participant whose own CA has a CRL in the list, and the only CA with a CRL
# here is this one. It is a TEST credential with exactly the status of
# TEST_IDENTITY_KEY_PEM in test_pki.rs: trusted by nothing outside the test
# suite, consumed by a named test.
for who in revoked good local; do
    keydir="${WORK}"
    [[ "${who}" == "local" ]] && keydir="${OUT}"
    keyfile="${keydir}/revocation_${who}_identity.key"
    [[ "${who}" == "local" ]] && keyfile="${OUT}/revocation_local_identity_key.pem"
    # PKCS#8 ("BEGIN PRIVATE KEY"), the only form the signing code accepts;
    # `ecparam -genkey` would write SEC1 ("BEGIN EC PRIVATE KEY").
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 \
        -out "${keyfile}" 2>/dev/null
    openssl req -new -key "${keyfile}" \
        -subj "/CN=HDDS ${who} Identity, O=HDDS Test" \
        -out "${REVDIR}/${who}.csr" 2>/dev/null
    openssl ca -batch -notext -config "${REVDIR}/ca.cnf" -in "${REVDIR}/${who}.csr" \
        -out "${OUT}/revocation_${who}_identity.pem" \
        -startdate "${VALID_FROM}" -enddate "${VALID_TO}" 2>/dev/null
done

openssl ca -batch -config "${REVDIR}/ca.cnf" \
    -revoke "${OUT}/revocation_revoked_identity.pem" >/dev/null 2>&1
openssl ca -batch -config "${REVDIR}/ca.cnf" -gencrl \
    -out "${OUT}/revocation_crl.pem" 2>/dev/null

# A CRL that expired one second after it was issued, so it is permanently
# stale from the moment it is committed. `-crlsec 1` is what makes it
# deterministic: the fixture does not depend on when the test runs.
openssl ca -batch -config "${REVDIR}/ca.cnf" -gencrl -crlsec 1 \
    -out "${OUT}/revocation_expired_crl.pem" 2>/dev/null

# An empty CRL from the same CA: proves the refusal comes from the SERIAL being
# listed, not from the mere presence of a CRL.
: > "${REVDIR}/db/index.txt"
echo 01 > "${REVDIR}/db/crlnumber"
openssl ca -batch -config "${REVDIR}/ca.cnf" -gencrl \
    -out "${OUT}/revocation_empty_crl.pem" 2>/dev/null

# Two CRLs that must be REFUSED for a reason other than staleness, because a
# check that only compares serials accepts both of them:
#   - forged:       an impostor CA with the SAME subject name as the revocation
#                   CA, but its own key. Its CRL names the right issuer and is
#                   signed by the wrong key. Anyone on the network can mint one.
#   - other_issuer: an honest CRL from a DIFFERENT CA. It says nothing about
#                   the certificates the revocation CA issued, so it cannot
#                   prove one of them is not revoked.
# Both are empty: the point is who signed them, not what they list.
mint_ca_with_empty_crl() {
    local dir="$1" subject="$2" out_crl="$3"
    mkdir -p "${dir}/db"
    : > "${dir}/db/index.txt"
    echo 01 > "${dir}/db/serial"
    echo 01 > "${dir}/db/crlnumber"
    openssl ecparam -name prime256v1 -genkey -noout -out "${dir}/ca.key" 2>/dev/null
    openssl req -x509 -new -key "${dir}/ca.key" -sha256 -subj "${subject}" \
        -not_before "${VALID_FROM}" -not_after "${VALID_TO}" \
        -out "${dir}/ca.pem" 2>/dev/null
    sed -e "s#${REVDIR}#${dir}#g" "${REVDIR}/ca.cnf" > "${dir}/ca.cnf"
    openssl ca -batch -config "${dir}/ca.cnf" -gencrl -out "${out_crl}" 2>/dev/null
}
mint_ca_with_empty_crl "${WORK}/rev-forged" \
    "/CN=HDDS Test Revocation CA/O=HDDS Test" "${OUT}/revocation_forged_crl.pem"
mint_ca_with_empty_crl "${WORK}/rev-other" \
    "/CN=HDDS Test Other CA/O=HDDS Test" "${OUT}/revocation_other_issuer_crl.pem"

# ---------------------------------------------------------------------------
# Completeness check
# ---------------------------------------------------------------------------
#
# A generator that half-succeeds is worse than one that fails: it leaves a
# fixture set where some documents are signed by CAs this run replaced, and
# the only symptom is a test failing somewhere else with a message about trust.
# That is exactly what happened here for over a day - see sign_smime_keyid.
#
# So every file this script is responsible for must have been WRITTEN by this
# run. A file older than the marker taken at the top was not regenerated,
# whatever the exit status of the command that was meant to write it.
# Files in this directory that this script does NOT produce, named so the
# check stays honest rather than being widened until it passes:
#   - fastdds_*      captured from eProsima, a FOREIGN toolchain. The whole
#                    point of those fixtures is that we did not make them.
#   - audit_*.xml    committed INPUTS, read from here and signed; the
#                    assertions in security::e2e_tests read like the rules do.
NOT_OURS=(
    "fastdds_maincacert.pem"
    "fastdds_othercacert.pem"
    "fastdds_permissions.smime"
    "fastdds_permissions_other_ca.smime"
    "audit_governance.xml"
    "audit_permissions.xml"
)

stale=0
for f in "${OUT}"/*.pem "${OUT}"/*.smime "${OUT}"/*.p7s "${OUT}"/*.xml; do
    [[ -e "$f" ]] || continue
    base="$(basename "$f")"
    skip=0
    for known in "${NOT_OURS[@]}"; do
        [[ "$base" == "$known" ]] && skip=1 && break
    done
    [[ "$skip" -eq 1 ]] && continue
    if [[ ! "$f" -nt "${RUN_MARKER}" ]]; then
        echo "NOT REGENERATED: ${base}" >&2
        stale=$((stale + 1))
    fi
done

if [[ "${stale}" -gt 0 ]]; then
    echo >&2
    echo "${stale} fixture(s) were not written by this run. The set is now INCOHERENT:" >&2
    echo "the CAs above were reminted, so any document still signed by an older one" >&2
    echo "no longer verifies. Fix the generator, do not commit this state." >&2
    exit 1
fi

echo "fixtures regenerated in ${OUT}:"
ls -l "${OUT}"
