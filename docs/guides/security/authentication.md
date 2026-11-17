# Authentication

HDDS uses **X.509 PKI-DH** authentication to verify participant identity.

## Overview

Authentication ensures that:
- Participants have valid certificates signed by a trusted CA
- Participants prove possession of their private key
- Unauthorized participants cannot join the domain

## Certificate Requirements

### Supported Algorithms

| Type | Algorithm | Key Size |
|------|-----------|----------|
| RSA | Certificates signed with PKCS#1 v1.5 and SHA-256; handshake signatures RSASSA-PSS with SHA-256 | 2048-8192 bits |
| ECDSA | P-256 (secp256r1) with SHA-256 | 256 bits |

Other curves (P-384, P-521) and other signature hashes are not accepted for
certificates or for the handshake signature.

### Certificate Extensions

- **KeyUsage**: Optional. When present on the identity certificate it must include `digitalSignature`; when present on a CA it must include `keyCertSign`
- **BasicConstraints**: Every issuer on the path must be a CA, and its `pathLenConstraint` must allow the intermediates below it (paths up to 8 certificates, leaf and trust anchor included)
- **Validity**: notBefore/notAfter checked at runtime
- **Subject**: The full subject name is the participant's identity: it is what a permissions grant's `subject_name` is matched against (see [Access Control](../../guides/security/access-control.md))

### File Format

Certificates must be **PEM encoded**:

```
-----BEGIN CERTIFICATE-----
MIICxjCCAa6gAwIBAgIJALZ...
-----END CERTIFICATE-----
```

The private key must be an **unencrypted PKCS#8 PEM** (`-----BEGIN PRIVATE KEY-----`).
The traditional RSA format (`-----BEGIN RSA PRIVATE KEY-----`) and the SEC1
EC format (`-----BEGIN EC PRIVATE KEY-----`, which is what
`openssl ecparam -genkey` writes) are not read. Convert with
`openssl pkcs8 -topk8 -nocrypt -in old_key.pem -out key.pem`, or generate the
key with `openssl genpkey`.

## Certificate Generation

### Using OpenSSL

#### Generate CA

```bash
# Generate CA private key (PKCS#8)
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out ca_key.pem

# Generate CA certificate (self-signed)
openssl req -x509 -new -nodes \
  -key ca_key.pem \
  -sha256 -days 1825 \
  -out ca_cert.pem \
  -subj "/CN=HDDS Root CA/O=MyOrg"
```

#### Generate Participant Certificate

```bash
# Generate participant private key (PKCS#8)
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out participant_key.pem

# Generate certificate signing request
openssl req -new \
  -key participant_key.pem \
  -out participant_csr.pem \
  -subj "/CN=SensorNode1/O=MyOrg"

# Sign with CA
openssl x509 -req \
  -in participant_csr.pem \
  -CA ca_cert.pem \
  -CAkey ca_key.pem \
  -CAcreateserial \
  -out participant_cert.pem \
  -days 365 \
  -sha256
```

#### Verify Certificate

```bash
# Verify certificate chain
openssl verify -CAfile ca_cert.pem participant_cert.pem
# Expected: participant_cert.pem: OK

# View certificate details
openssl x509 -in participant_cert.pem -text -noout
```

### Using ECDSA (P-256)

```bash
# Generate ECDSA CA key and certificate (PKCS#8)
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ca_key.pem
openssl req -x509 -new -nodes -key ca_key.pem -sha256 -days 1825 \
  -out ca_cert.pem -subj "/CN=HDDS Root CA/O=MyOrg"

# Generate ECDSA participant key and certificate request
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out participant_key.pem
openssl req -new -key participant_key.pem -out participant_csr.pem \
  -subj "/CN=SensorNode1/O=MyOrg"
```

Sign the request with `openssl x509 -req` as above.

## Identity Token in Discovery

When security is enabled, participants announce an identity token in the
`PID_IDENTITY_TOKEN` parameter of their SPDP (Simple Participant Discovery
Protocol) messages. The token is a DDS-Security `DataHolder` whose class id
names the authentication plugin (`DDS:Auth:PKI-DH:1.0`); it does not carry the
certificate. The certificate chain is verified later, during the PKI-DH
handshake.

### Discovery Flow with Security

```mermaid
sequenceDiagram
    participant A as Participant A
    participant B as Participant B

    A->>B: SPDP (with identity token)
    Note over B: Admission check: well-formed token,<br/>class id DDS:Auth:PKI-DH, major version 1
    alt Token accepted
        B->>A: Handshake request (stateless message channel)
        A->>B: Handshake reply / final (see below)
        Note over B: Certificate chain and signatures verified
    else Token missing or rejected
        Note over B: Participant rejected, security_errors metric incremented
    end
```

### Admission Check

The discovery layer calls the security suite for every incoming SPDP
announcement (`SecurityValidatorAdapter`, which implements the
`SecurityValidator` trait). A participant whose identity token is malformed or
names another plugin is rejected, and the discovery `security_errors` counter
is incremented. A participant that carries no identity token is rejected
unless `require_authentication` is `false` and, when a governance document is
configured, its domain rule allows unauthenticated participants
(`allow_unauthenticated_participants`).

## Authentication Handshake

The handshake is the builtin PKI-DH handshake of DDS Security v1.1 section
9.3.2.5: three messages exchanged on the participant stateless message topic
(plaintext, best effort):

```mermaid
sequenceDiagram
    participant I as Initiator
    participant R as Responder

    I->>R: 1. Request (cert, permissions, DH key, challenge)
    Note over R: Validate cert chain
    R->>I: 2. Reply (cert, permissions, DH key, challenges, signature)
    Note over I: Validate cert chain, verify signature
    I->>R: 3. Final (signature)
    Note over R: Verify signature
```

### Handshake Details

1. **Request**: Initiator sends its identity certificate, its signed permissions document (`c.perm`, empty when it has none), its ephemeral ECDH public key and a 32-byte random challenge
2. **Reply**: Responder validates the certificate chain, then sends its own certificate, permissions document, ECDH public key, its own 32-byte challenge, and a signature over both DH keys, both challenges and the hashes of both messages' `c.` properties
3. **Final**: Initiator verifies the responder's signature and answers with its own signature over the same elements
4. **Complete**: Both sides derive the same shared secret via ECDH (P-256 by default); it seeds the keys used to distribute data-plane keys (see [Encryption](../../guides/security/encryption.md))

Messages are retransmitted with exponential backoff (1 s, 4 s, 16 s, at most
three attempts), and a handshake that has not completed within 30 s fails. The
responder keeps a window of the last 1024 request challenges and silently drops
a repeated one.

See the [Security Guide](../../security-guide.md#pki-dh-handshake-on-the-wire)
for the message layouts.

## Configuration

```rust
use hdds::{Participant, TransportMode};
use hdds::security::SecurityConfig;

let security = SecurityConfig::builder()
    // Required: Identity
    .identity_certificate("certs/participant.pem")
    .private_key("certs/participant_key.pem")

    // Required: Trust anchors
    .ca_certificates("certs/ca.pem")

    // Optional: Require all participants to authenticate (default: true)
    .require_authentication(true)

    // Optional: Check certificate revocation against a CRL (default: false)
    .check_certificate_revocation(true)
    .certificate_revocation_list("certs/crl.pem")

    .build()?;
```

`check_certificate_revocation(true)` requires `certificate_revocation_list(..)`,
and the CRL needs to be named only when the flag is on; `build()` refuses
either one without the other. Both the local identity and every remote peer
certificate are checked against the list. OCSP is not supported.
`SecurityConfig::secure_builder()` starts with revocation checking switched on, so it needs a list as well.

## Certificate Validation

HDDS performs these checks:

1. **Format validation**: Valid PEM structure
2. **Chain validation**: Traces to a trusted CA, every link signed by its issuer
3. **Validity period**: Current time within notBefore/notAfter
4. **KeyUsage**: digitalSignature present when the extension is present
5. **Revocation**: Not listed in the configured CRL, when checking is enabled
6. **Signature verification**: The handshake signature verifies under the certificate's key

A participant whose own identity certificate has expired begins and advances
no handshake.

### Validation Errors

| Error | Cause | Resolution |
|-------|-------|------------|
| `CertificateInvalid` | Malformed PEM, no path to a trusted CA, bad signature, unusable KeyUsage, or a certificate listed in the CRL (or a CRL that is stale or not issued by the certificate's CA) | Check the certificate, the CA in the trust store and the CRL |
| `CertificateExpired` | Outside the validity period | Issue a new certificate |
| `AuthenticationFailed` | Handshake step failed (for example a signature or challenge mismatch) | Check both sides' configuration and logs |

These are `SecurityError` variants. A local configuration problem surfaces as
`Error::Config` from `build()`; a failure against a remote peer is logged and
audited, and that peer is not authenticated.

## Unauthenticated Participants

By default, authenticated participants won't communicate with unauthenticated ones.

To allow mixed environments (not recommended):

```rust
let security = SecurityConfig::builder()
    .identity_certificate("cert.pem")
    .private_key("key.pem")
    .ca_certificates("ca.pem")
    .require_authentication(false)  // Allow unauthenticated
    .build()?;
```

When a governance document is configured, its
`<allow_unauthenticated_participants>` setting decides, whatever
`require_authentication` says: `false` there rejects every participant that
presents no identity token.

## Multi-CA Environments

To trust multiple CAs, concatenate certificates:

```bash
cat ca1.pem ca2.pem > trusted_cas.pem
```

```rust
let security = SecurityConfig::builder()
    .ca_certificates("trusted_cas.pem")  // Multiple CAs
    // ...
    .build()?;
```

## Certificate Rotation

The certificate and key are configured when the participant is built, so
rotating an identity means building a new participant with the new files:

1. Generate a new certificate (validity may overlap the old one)
2. Update the application configuration
3. Restart the application (or rebuild the participant)

Peers authenticate the new participant with a fresh handshake and judge its
new certificate on its own merits.

## Best Practices

1. **Use strong keys**: RSA 2048+ or ECDSA P-256
2. **Short validity**: 90-365 days for participant certs
3. **Protect private keys**: Restrict file permissions (0600)
4. **Separate CA**: Dedicated, offline CA machine
5. **Rotate regularly**: Automate certificate renewal

## Troubleshooting

### Authentication Fails

HDDS logs through the `log` crate. With an `env_logger`-style logger installed
by your application:

```bash
# Enable debug logging
export RUST_LOG=hdds::security=debug
```

### Certificate Not Trusted

```bash
# Verify CA is correct
openssl verify -CAfile ca.pem participant.pem
```

### Key Mismatch

```bash
# Check key matches certificate (RSA and EC)
openssl x509 -in cert.pem -noout -pubkey | openssl md5
openssl pkey -in key.pem -pubout | openssl md5
# Hashes must match
```

## Next Steps

- [Access Control](../../guides/security/access-control.md) - Fine-grained permissions
- [Encryption](../../guides/security/encryption.md) - Data protection
