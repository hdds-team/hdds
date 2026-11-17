# DDS Security

HDDS implements the plugin model of the **OMG DDS Security v1.1** specification
(authentication, access control, cryptographic and logging plugins) for secure
publish-subscribe communication. Read [Scope and Limitations](#scope-and-limitations)
for what is not implemented.

Security is compiled in with the `security` Cargo feature (the governance and
permissions parsers need `qos-loaders`, which is a default feature):

```toml
[dependencies]
hdds = { path = "/absolute/path/to/hdds/crates/hdds", features = ["security"] }
```

## Security Features

| Feature | Description |
|---------|-------------|
| Authentication | X.509 PKI-DH handshake (three messages, signed, with ECDH key agreement) |
| Access Control | Signed governance and permissions documents; checked when a local endpoint is created and against each remote participant's signed permissions |
| Encryption | AES-256-GCM protection of the serialized sample payload (DDS-Security payload framing) |
| Key Exchange | ECDH P-256 (default) or P-384 with HKDF |
| Audit Logging | Hash-chained event log, optional RFC 5424 syslog mirror |

See [Scope and Limitations](#scope-and-limitations) before relying on any
of these for a security argument.

## Architecture

HDDS implements security through a `SecurityPluginSuite` that encapsulates the four DDS Security v1.1 plugins plus the runtime state the data plane uses:

```
+-------------------------------------------------------------+
|                         Participant                          |
+-------------------------------------------------------------+
|  +---------------------------------------------------------+|
|  |                  SecurityPluginSuite                     ||
|  |  +----------------+  +----------------+                 ||
|  |  | Authentication |  | AccessControl  |                 ||
|  |  |    Plugin      |  |    Plugin      |                 ||
|  |  |   (X.509)      |  | (governance +  |                 ||
|  |  |                |  |  permissions)  |                 ||
|  |  +----------------+  +----------------+                 ||
|  |  +----------------+  +----------------+                 ||
|  |  | Cryptographic  |  |    Logging     |                 ||
|  |  |    Plugin      |  |    Plugin      |                 ||
|  |  | (AES-256-GCM)  |  | (audit trail)  |                 ||
|  |  +----------------+  +----------------+                 ||
|  +---------------------------------------------------------+|
+-------------------------------------------------------------+
|  Discovery: identity-token admission check on SPDP,          |
|  PKI-DH handshake on the stateless message channel           |
+-------------------------------------------------------------+
|                      RTPS Protocol                           |
+-------------------------------------------------------------+
|                         Transport                            |
+-------------------------------------------------------------+
```

### SecurityPluginSuite Components

```text
SecurityPluginSuite
+-- authentication   X.509 certificate validation (required)
+-- access_control   governance + permissions enforcement (optional:
|                    present when both documents are configured)
+-- cryptographic    encryption-requested marker (optional): its presence
|                    turns the data plane on; the sealing itself lives in
|                    crypto::user_data
+-- logging          hash-chained audit log (optional)
+-- handshakes       PKI-DH handshake state machine, one state per remote
|                    participant; per-peer keys live in its Complete state
+-- data_keys        per-writer data-plane keys, local and remote,
                     keyed (writer GUID, key id)
```

## Quick Start

### 1. Generate Certificates

Three pieces of PKI are involved: an identity CA that issues participant
certificates, a participant certificate and key, and a **Permissions CA**
that signs the governance and permissions documents. The Permissions CA is a
different trust role from the identity CA and is configured separately.

```bash
# Identity CA (trust anchor for participant certificates)
openssl req -x509 -nodes -days 365 \
  -newkey rsa:2048 \
  -keyout ca_key.pem \
  -out ca_cert.pem \
  -subj "/CN=HDDS CA"

# Permissions CA (signs governance and permissions documents)
openssl req -x509 -nodes -days 365 \
  -newkey rsa:2048 \
  -keyout permissions_ca_key.pem \
  -out permissions_ca.pem \
  -subj "/CN=HDDS Permissions CA"

# Participant key and certificate
openssl req -nodes -newkey rsa:2048 \
  -keyout participant_key.pem \
  -out participant_csr.pem \
  -subj "/CN=Participant1"

openssl x509 -req -days 365 \
  -in participant_csr.pem \
  -CA ca_cert.pem \
  -CAkey ca_key.pem \
  -CAcreateserial \
  -out participant_cert.pem
```

The private key must be an unencrypted PKCS#8 PEM (`-----BEGIN PRIVATE KEY-----`),
which is what `openssl req -nodes -newkey` and `openssl genpkey` write.

### 2. Create and Sign the Governance and Permissions Documents

Access control needs **both** documents, and HDDS only accepts them signed by
the Permissions CA. A plain XML file is refused when the participant is built.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<dds>
  <domain_access_rules>
    <domain_rule>
      <domains><id>0</id></domains>
      <allow_unauthenticated_participants>false</allow_unauthenticated_participants>
      <enable_join_access_control>true</enable_join_access_control>
      <discovery_protection_kind>ENCRYPT</discovery_protection_kind>
      <data_protection_kind>ENCRYPT</data_protection_kind>
    </domain_rule>
  </domain_access_rules>
</dds>
```

Save it as `governance.xml`. Then the permissions document, `permissions.xml`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<dds>
  <permissions>
    <grant name="Participant1">
      <subject_name>CN=Participant1</subject_name>
      <validity>
        <not_before>2020-01-01T00:00:00</not_before>
        <not_after>2036-01-01T00:00:00</not_after>
      </validity>
      <allow_rule>
        <domains><id>0</id></domains>
        <publish>
          <topics><topic>*</topic></topics>
        </publish>
        <subscribe>
          <topics><topic>*</topic></topics>
        </subscribe>
      </allow_rule>
    </grant>
  </permissions>
</dds>
```

The `subject_name` must equal the full subject of the participant certificate
(every attribute, not only the CN). Sign both documents as S/MIME with the
Permissions CA:

```bash
for doc in governance permissions; do
  openssl smime -sign \
    -in ${doc}.xml \
    -signer permissions_ca.pem \
    -inkey permissions_ca_key.pem \
    -outform SMIME -text -md sha256 \
    -out ${doc}.p7s
done
```

Point HDDS at the `.p7s` files, never at the `.xml` sources. The Permissions
CA certificate must be valid for as long as the signed documents are used
(HDDS checks its validity window before it checks the signature).

### 3. Configure HDDS

```rust
use hdds::{Participant, TransportMode};
use hdds::security::SecurityConfig;

let security = SecurityConfig::builder()
    // Identity (required)
    .identity_certificate("participant_cert.pem")
    .private_key("participant_key.pem")
    .ca_certificates("ca_cert.pem")

    // Access control: both documents, signed, plus the Permissions CA
    .governance_xml("governance.p7s")
    .permissions_xml("permissions.p7s")
    .permissions_ca("permissions_ca.pem")

    // Encryption (required here: the governance above asks for ENCRYPT)
    .enable_encryption(true)

    // Audit logging
    .enable_audit_log(true)
    .audit_log_path("/var/log/hdds/audit.log")

    .build()?;

let participant = Participant::builder("app")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .with_security(security)  // Enable security plugins
    .build()?;
```

`build()` fails with `Error::Config` when `governance_xml` or `permissions_xml`
is set without the other, when either is set without `permissions_ca`, when a
document is not signed by that CA, or when no grant in the permissions
document is in force for this participant's certificate subject.

### Security Integration

When security is enabled via `with_security()`, HDDS automatically:

1. **Writer/Reader creation**: Checks the endpoint's topic, partitions and data tags against the signed permissions (and the governance) before allowing creation; a refusal is `Error::PermissionDenied`
2. **Key mint + distribution**: Each encrypting writer mints a random AES-256 data-plane key at build time; the key is announced to every authenticated peer over the `ParticipantVolatileMessageSecure` channel, protected with that peer's key material (derived from the PKI-DH handshake secret)
3. **Data transmission**: Seals every serialized sample (and dispose/unregister lifecycle DATA) under the writer's key before sending -- and FAILS CLOSED: a writer with encryption enabled and no key refuses the write with `EncryptionUnavailable`, never emits cleartext
4. **Data reception**: Classifies every incoming payload at ingest, before any reception bookkeeping -- plaintext passes through, secured payloads are decrypted with the key from the `DataKeyStore`, and undecryptable payloads are dropped (reliable readers recover via NACK repair once the key arrives)
5. **Audit logging**: Records handshake outcomes, access-control decisions and key events through the `LoggingPlugin` when enabled

```rust
// Security checks are automatic - PermissionDenied error if access denied
let topic = participant.topic::<SensorData>("SensorTopic")?;

// This will fail with hdds::Error::PermissionDenied if not authorized
let writer = topic.writer().qos(QoS::reliable()).build()?;
```

## Security Plugins

### Authentication Plugin

PKI-DH authentication using X.509 certificates:

- **Certificate validation**: Chain verification to the CA, validity period, KeyUsage
- **Handshake**: three signed messages (Request, Reply, Final) with ECDH key agreement
- **Algorithms**: RSA 2048-8192 bits or ECDSA P-256 identities

[Learn more ->](../../guides/security/authentication.md)

### Access Control Plugin

Permissions for participants and topics, from signed documents:

- **Governance**: Domain-wide security policies
- **Permissions**: Per-participant access rules
- **Wildcards**: POSIX `fnmatch()` topic and partition expressions

[Learn more ->](../../guides/security/access-control.md)

### Cryptographic Plugin

Data protection with authenticated encryption:

- **Algorithm**: AES-256-GCM, one key per writer
- **Key exchange**: ECDH P-256 / P-384 with HKDF (fail-closed suite policy)
- **Key distribution**: per-peer protected announcements over ParticipantVolatileMessageSecure
- **IV**: Unique 96-bit value per message (session id and a counter suffix)

[Learn more ->](../../guides/security/encryption.md)

### Logging Plugin

Hash-chained audit trail for security events:

- **Events logged**: Authentication outcomes, access-control decisions, key installation and key-envelope failures
- **Format**: one text line per record, chained with SHA-256 (`prev=`, `hash=`, `seq=`)
- **Tamper detection**: `hdds::security::audit::verify_chain` walks a file and names the first broken link
- **Export**: optional RFC 5424 syslog mirror over UDP (`audit_syslog_address`)

```rust
let security = SecurityConfig::builder()
    // ... other config ...
    .enable_audit_log(true)
    .audit_log_path("/var/log/hdds/audit.log")
    .build()?;
```

Example log entry (one line, shortened here):
```text
AccessControl { participant_guid: [...], action: "create_writer", resource: "sensor/temp", outcome: Allowed, timestamp: ... } prev=<64 hex> hash=<64 hex> seq=<n>
```

## Security Levels

### Level 1: Authentication Only

Verify participant identity without encryption:

```rust
let security = SecurityConfig::builder()
    .identity_certificate("cert.pem")
    .private_key("key.pem")
    .ca_certificates("ca.pem")
    .enable_encryption(false)  // No encryption
    .build()?;
```

### Level 2: Authentication and Payload Encryption

Authenticate participants and encrypt sample payloads:

```rust
let security = SecurityConfig::builder()
    .identity_certificate("cert.pem")
    .private_key("key.pem")
    .ca_certificates("ca.pem")
    .enable_encryption(true)   // Payload encryption
    .enable_audit_log(true)    // Audit trail
    .build()?;
```

Payload encryption does not hide RTPS headers or inline QoS; see
[Scope and Limitations](#scope-and-limitations).

## Performance Impact

There is no committed reference-grade security performance benchmark. The
cost depends on the certificate suite, payload, QoS, topology, transport,
hardware, and build. Measure secured and unsecured configurations under the
same stamped conditions before publishing an overhead.

## Scope and Limitations

Honest boundaries of the current implementation -- read these before
building a security argument on the features above:

- **Full cross-vendor security interoperability is unverified.** User payloads
  use DDS-Security CryptoHeader / CryptoContent / CryptoFooter; the complete
  security deployment also depends on authentication, discovery and tokens.
- **Payload-only protection leaves metadata visible.** RTPS headers and inline
  QoS remain clear; the CDR encapsulation is encrypted with the payload.
  Protected KeyHash values always use MD5, including short keys, but a small
  key space remains vulnerable to dictionary enumeration.
- **No per-reader origin authentication for payloads.** All matched authorized
  readers share the writer's common payload material.
- **No automatic master-key rotation or payload replay window.** Session keys
  advance at their block bound. Replacing master tokens retires old material;
  GCM alone does not establish freshness of the surrounding RTPS metadata.
- **Governance protections that are not applied are refused, not ignored.**
  Whole-RTPS-message protection (`rtps_protection_kind`), liveliness
  protection, `metadata_protection_kind`, `SIGN`-only data protection and the
  `..._WITH_ORIGIN_AUTHENTICATION` discovery kinds are refused when the
  governance document is loaded.
- **Revocation is CRL-only.** OCSP is not supported. Finite-field key
  agreement (`DH+MODP-2048-256`) is not implemented.
- **A remote peer's permissions are enforced, but only against an HDDS peer.**
  Each participant presents its signed permissions document in the handshake
  (`c.perm`), and a discovered remote endpoint is checked against it before it
  is surfaced. A peer that presents no document holds no grant: it is
  refused when `enable_join_access_control` is on, and when it is off it is
  let in but refused on every topic whose governance rule enables read or
  write access control (no document, no access); it matches only on topics
  the governance leaves open. No HDDS release before 1.5.0 sends `c.perm`
  (nor authenticates with 1.5.0 at all), so a secured deployment must
  upgrade together.

## Specifications Referenced

The security implementation is built against:

- **OMG DDS Security v1.1** (formal/18-04-01)
- **RFC 5280** - X.509 Certificate Profile
- **RFC 5869** - HKDF Key Derivation
- **NIST SP 800-38D** - GCM Specification

## Next Steps

- [Authentication](../../guides/security/authentication.md) - Certificate-based identity
- [Access Control](../../guides/security/access-control.md) - Permission management
- [Encryption](../../guides/security/encryption.md) - Data protection
