# HDDS Security Guide

> DDS Security v1.1 implementation in HDDS -- authentication, access control, encryption, and audit logging.

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Authentication (X.509 PKI)](#authentication-x509-pki)
4. [Access Control](#access-control)
5. [Encryption (AES-256-GCM)](#encryption-aes-256-gcm)
6. [Key Exchange (ECDH P-256 / P-384)](#key-exchange-ecdh-p-256--p-384)
7. [Session Key Management](#session-key-management)
8. [Certificate Setup](#certificate-setup)
9. [Configuration](#configuration)
10. [Governance XML](#governance-xml)
11. [Permissions XML](#permissions-xml)
12. [Audit Logging](#audit-logging)
13. [Protected SerializedPayload Wire Format](#protected-serializedpayload-wire-format)
14. [Known Limitations](#known-limitations)
15. [Performance Considerations](#performance-considerations)
16. [Troubleshooting](#troubleshooting)

---

## Overview

HDDS implements the OMG DDS Security v1.1 specification (formal/18-04-01), providing:

- **Authentication** -- X.509 certificate-based participant identity verification
- **Access Control** -- Topic/partition authorization via Permissions XML with deny-by-default semantics
- **Encryption** -- AES-256-GCM authenticated encryption of serialized sample payloads (HDDS<->HDDS framing; see [Known Limits](#known-limits-read-before-relying-on-the-properties-above))
- **Audit Logging** -- hash-chained audit trail for security events

### Security Model

Each DDS participant has a cryptographic identity:

- **Identity Certificate** -- X.509 PEM certificate signed by a trusted CA
- **Private Key** -- PKCS#8 PEM private key for the handshake signatures: EC P-256 (ECDSA-SHA256) or RSA (RSASSA-PSS-SHA256)
- **CA Certificates** -- Root of trust for validating remote participants

Communication between participants is authenticated, authorized, and optionally encrypted:

```text
Participant A                              Participant B
+-----------+                              +-----------+
| cert_a    |--- Authentication Handshake ->| cert_b    |
| key_a     |<-- Challenge/Response --------| key_b     |
| ca.pem    |                              | ca.pem    |
+-----------+                              +-----------+
      |                                         |
      |--- ECDH Key Exchange (P-256 / P-384) -->|
      |<-- SharedSecret (both derive) ---------->|
      |                                         |
      |--- Writer key tokens, per peer -------->|
      |<-- Writer key tokens, per peer ---------|
      |                                         |
      |=== AES-256-GCM Encrypted Data =========>|
      |<=== AES-256-GCM Encrypted Data =========|
```

### Feature Gate

Security features are gated behind the `security` Cargo feature:

```toml
[dependencies]
hdds = { version = "1.5", features = ["security"] }
```

The `qos-loaders` feature (enabled by default) is also required for governance and permissions XML parsing.

---

## Architecture

HDDS security follows a plugin architecture. The suite holds the four DDS
Security v1.1 plugins plus the runtime state the data plane actually runs on:

```text
SecurityPluginSuite
+-- AuthenticationPlugin    (X.509 certificate validation)
+-- AccessControlPlugin     (governance + permissions enforcement)
+-- CryptoPlugin            (encryption-requested marker; the sealing itself
|                            lives in crypto::user_data + the key stores)
+-- LoggingPlugin           (audit trail, hash-chained, behind one shared chain)
+-- HandshakeMachine        (PKI-DH state, one entry per remote participant)
+-- DataKeyStore            (per-writer data-plane keys, local and remote)
+-- ParticipantKeyStore     (participant key material, exchanged as
|                            ParticipantCryptoTokens)
+-- VolatileChannel         (state of ParticipantVolatileMessageSecure)
```

`CryptoPlugin` is deliberately a fieldless marker: its presence (from
`enable_encryption(true)`) is what switches the data plane on. Encryption and
decryption are performed by free functions in `security/crypto/user_data.rs`
using keys held by `DataKeyStore` and `HandshakeMachine`, not by methods on
the plugin object.

### Plugin Lifecycle

1. `SecurityConfig::builder()` -- Configure security parameters
2. `SecurityPluginSuite::new(config, domain_id)` -- Initialize all plugins; the
   participant builder does this for you
3. Attach the configuration to `Participant` during creation via
   `.with_security(config)`
4. Plugins are invoked automatically during discovery and data send/receive

### Module Layout

| Module | Purpose |
|--------|---------|
| `security/config.rs` | `SecurityConfig` builder |
| `security/mod.rs` | `SecurityPluginSuite`, `SecurityError` |
| `security/authentication.rs` | `AuthenticationPlugin` trait, handshake tokens |
| `security/authentication/x509/` | X.509 certificate validation |
| `security/handshake/` | `HandshakeMachine` -- PKI-DH 3-message handshake, fail-closed suite policy |
| `security/signed_document.rs`, `cms.rs`, `p7s.rs` | Loading of the signed governance and permissions documents, verified against the Permissions CA |
| `security/revocation.rs` | CRL check shared by the handshake and the local identity |
| `security/access/mod.rs` | `AccessControlPlugin` |
| `security/access/permissions.rs` | Governance + Permissions XML parsing |
| `security/access/rules.rs` | Deny-by-default rules engine |
| `security/access/remote.rs` | Access control applied to a remote participant's endpoints |
| `security/crypto/mod.rs` | `CryptoPlugin` marker (encryption on/off) |
| `security/crypto/aes_gcm.rs` | `AesGcmCipher`, a standalone AES-256-GCM primitive (not used on the data path) |
| `security/crypto/key_exchange.rs` | ECDH P-256 / P-384 key agreement |
| `security/crypto/session_keys.rs` | HKDF helpers (used for the handshake's MasterSharedSecret) |
| `security/crypto/kx_keys.rs` | Key material of the volatile channel, derived from the handshake (Table 67) |
| `security/crypto/crypto_token.rs` | `DDS:Crypto:AES_GCM_GMAC` CryptoToken codec |
| `security/crypto/secure_submessage.rs` | SEC_PREFIX / SEC_BODY / SEC_POSTFIX submessage protection |
| `security/crypto/user_data.rs` | SerializedPayload protection: CryptoHeader / CryptoContent / CryptoFooter codec |
| `security/crypto/data_keys.rs` | `DataKeyStore` -- per-writer data-plane keys |
| `security/crypto/peer_keys.rs` | `PeerKeys` -- per-peer inputs retained with the completed handshake |
| `security/crypto/volatile.rs` | `WriterKeyAnnouncement` -- DatawriterCryptoTokens message |
| `security/crypto/secure_sedp.rs` | Secure SEDP submessage protection |
| `security/permissions/dynamic.rs` | Local restriction overlay -- unsigned, hot-reloaded, refuse-only |
| `security/audit/mod.rs` | `LoggingPlugin` with hash-chain, `verify_chain` |

---

## Authentication (X.509 PKI)

### Overview

HDDS uses X.509 certificate-based authentication per DDS Security v1.1 Section 8.3. Each participant proves its identity through a challenge-response handshake.

### Authentication Flow

```text
Initiator                      Responder
   |                              |
   |  1. begin_handshake()        |
   |----------------------------->|
   |     (identity certificate)   |
   |                              |
   |  2. process_handshake()      |
   |<-----------------------------|
   |     (challenge + signature)  |
   |                              |
   |  3. process_handshake()      |
   |----------------------------->|
   |     (response + signature)   |
   |                              |
   |  4. Authentication success   |
   |<-----------------------------|
```

### AuthenticationPlugin Trait

The `AuthenticationPlugin` trait defines three operations:

```rust
pub trait AuthenticationPlugin: fmt::Debug + Send + Sync {
    /// Validate local participant identity
    fn validate_identity(&self) -> Result<IdentityHandle, SecurityError>;

    /// Begin authentication handshake with remote participant
    fn begin_handshake(
        &self,
        local_identity: &IdentityHandle,
        remote_guid: GUID,
    ) -> Result<HandshakeRequestToken, SecurityError>;

    /// Process challenge/response from remote participant
    fn process_handshake(
        &self,
        local_identity: &IdentityHandle,
        request: &HandshakeRequestToken,
    ) -> Result<Option<HandshakeReplyToken>, SecurityError>;
}
```

### Validation Checks

The `process_handshake()` method validates the remote certificate against:

1. **Trust Chain** -- Certificate is signed by a CA in the trust store
2. **Expiration** -- Certificate is within validity period (notBefore/notAfter)
3. **KeyUsage** -- If the certificate carries a KeyUsage extension, it asserts digitalSignature (an absent extension places no restriction)
4. **Signature** -- Challenge signature is valid for this certificate

### Identity Handle

```rust
pub struct IdentityHandle {
    pub guid: GUID,
    pub subject_name: String,        // e.g., "CN=participant1.example.com"
    pub expiration_time: u64,        // Unix epoch seconds
    pub(crate) certificate_data: Vec<u8>,
}
```

### Handshake Tokens

```rust
// Request (initiator -> responder)
pub struct HandshakeRequestToken {
    pub class_id: String,               // "DDS:Auth:PKI-DH:1.0"
    pub identity_certificate: Vec<u8>,  // PEM-encoded X.509
    pub challenge: Option<Vec<u8>>,     // 32-byte crypto-secure nonce
    pub signature: Option<Vec<u8>>,     // RSA/ECDSA digital signature
}

// Reply (responder -> initiator)
pub struct HandshakeReplyToken {
    pub challenge_response: Vec<u8>,    // Signature of received challenge
    pub new_challenge: Option<Vec<u8>>, // New challenge for next step
    pub signature: Vec<u8>,            // Digital signature
}
```

### PKI-DH Handshake on the Wire

The tokens above are the plugin API. What goes on the wire between two
participants is the builtin PKI-DH handshake of DDS Security v1.1
Sec.9.3.2.5, three messages on the stateless message topic:

| Message | class_id | Binary properties |
|---------|----------|-------------------|
| Request (Table 49) | `DDS:Auth:PKI-DH:1.0+Req` | `c.id`, `c.perm`, `c.pdata`, `c.dsign_algo`, `c.kagree_algo`, `hash_c1`, `dh1`, `challenge1` |
| Reply (Table 50) | `DDS:Auth:PKI-DH:1.0+Reply` | `c.id`, `c.perm`, `c.pdata`, `c.dsign_algo`, `c.kagree_algo`, `hash_c2`, `dh2`, `hash_c1`, `dh1`, `challenge1`, `challenge2`, `signature` |
| Final (Table 51) | `DDS:Auth:PKI-DH:1.0+Final` | `hash_c1`, `hash_c2`, `dh1`, `dh2`, `challenge1`, `challenge2`, `signature` |

- `hash_c1` / `hash_c2`: SHA-256 of the CDR Big Endian serialization of a
  BinaryPropertySeq holding the request's / the reply's `c.` properties, in
  the order of the table. `c.perm` is sent always, empty when the
  participant has no access control (Cyclone DDS refuses a handshake
  message without it). A peer's absent, empty or lone-NUL `c.perm` is no
  permissions document (see "Enforcement scope" under Access Control).
- Reply signature: over the CDR Big Endian BinaryPropertySeq
  `hash_c2, challenge2, dh2, challenge1, dh1, hash_c1`.
- Final signature: over `hash_c1, challenge1, dh1, challenge2, dh2, hash_c2`.
- Each signature binds both DH public keys and both sides' `c.` properties
  (certificate, permissions document, participant data) to the signer's
  identity key. An ECDSA signature is DER-encoded (ANSI X9.62). An RSA
  identity signs RSASSA-PSS with SHA-256 and MGF1-SHA-256, salt of 32
  octets; a peer's RSASSA-PSS signature is verified whatever its salt
  length (the specification fixes none, and OpenSSL 1.1.1 / 3.0 sign with
  the maximum by default). PKCS#1 v1.5 and MGF1-SHA1 are refused.

The test suite pins the hashes, the signed bytes and a signature against
vectors produced by Cyclone DDS 0.11.0 (its serializer and its signature
routine), not by HDDS's own encoder.

**HDDS 1.4.x secure peers cannot authenticate with 1.5.0.** Earlier
releases signed `c.id || challenge1 || dh1 || challenge2` in the reply,
leaving the responder's DH key unsigned, and no hash in the final. 1.5.0
does not accept that signature. A 1.4.x handshake message is refused with
"peer uses the pre-1.5 handshake signature" (warning log), and a 1.4.x
participant is logged and audited as unable to authenticate when discovery
first sees it. Upgrade all secure participants together.

### Discovery Integration

HDDS includes a `SecurityValidatorAdapter` that bridges the `AuthenticationPlugin` to the discovery system. When security is enabled, incoming SPDP discovery packets are automatically validated. Participants with invalid identity tokens are rejected.

---

## Access Control

### Overview

Access control enforces fine-grained topic/partition authorization using two XML configuration files:

- **governance.xml** -- Domain-wide security policies (encryption requirements, authentication rules)
- **permissions.xml** -- Per-participant topic allow/deny rules

### Security Model: Deny-by-Default

HDDS implements a **deny-by-default** security model per DDS Security v1.1:

1. The governance first: a topic no `<topic_rule>` matches is **DENIED**; a
   topic whose rule sets `<enable_write_access_control>` (writers) or
   `<enable_read_access_control>` (readers) to `FALSE` is **ALLOWED** without
   the permissions document, in every partition
2. The grant's `allow_rule` and `deny_rule` entries, **in document order**:
   the first rule with a criterion that matches decides, **ALLOWED** or
   **DENIED** (9.4.1.3.2.3, "The rules are applied in the same order that
   appear in the document"). A criterion (`<publish>` for writers,
   `<subscribe>` for readers) matches when its topic, partition and data tag
   conditions all match the endpoint (see Rule Fields)
3. If no rule matches, the grant's `<default>` decides; without one, **DENIED**

Write a deny rule BEFORE the broader allow rule it carves out of: an allow
rule written first matches first.

### AccessControlPlugin API

```rust
pub struct AccessControlPlugin {
    rules: RulesEngine,
}

impl AccessControlPlugin {
    /// Create from XML content strings (already-verified documents; applies
    /// every grant of the permissions document, whoever it was issued to)
    pub fn from_xml(
        governance_xml: &str,
        permissions_xml: &str,
        domain_id: u32,
    ) -> Result<Self, SecurityError>;

    /// Check if participant can join domain
    pub fn check_create_participant(&self, domain_id: u32) -> Result<(), SecurityError>;

    /// Check if participant can create writer on topic
    pub fn check_create_writer(
        &self,
        topic: &str,
        partition: Option<&str>,
    ) -> Result<(), SecurityError>;

    /// Check if participant can create reader on topic
    pub fn check_create_reader(
        &self,
        topic: &str,
        partition: Option<&str>,
    ) -> Result<(), SecurityError>;

    /// check_create_datawriter (9.4.1.3.2.3): every partition the writer
    /// names (empty: the default partition) and its data tags
    pub fn check_create_datawriter(
        &self,
        topic: &str,
        partitions: &[String],
        data_tags: &[DataTag],
    ) -> Result<(), SecurityError>;

    /// check_create_datareader, as check_create_datawriter for readers
    pub fn check_create_datareader(
        &self,
        topic: &str,
        partitions: &[String],
        data_tags: &[DataTag],
    ) -> Result<(), SecurityError>;
}
```

`check_create_writer` / `check_create_reader` judge one partition and no
data tags; the participant's builders use the two others, with the
endpoint's whole PARTITION QoS.

A participant does not go through `from_xml`. Its plugin is built from the two
documents after their signatures have verified (see "Signed governance and
permissions documents"), keeping only the grants whose `<subject_name>` is the
subject of its own identity certificate and whose `<validity>` window contains
the current time. A signed document that leaves this participant no grant in
force is an error, not an empty rule set.

> **Enforcement scope.** The checks above gate LOCAL writer and reader
> creation. A REMOTE participant's endpoints are judged by one admission
> verdict per (remote participant, topic, writer or reader), reached when
> discovery pairs them and cached until something it was reached from
> changes (the participant leaves, its authentication state changes, an
> endpoint is announced or changes):
>
> - an "Unauthenticated" participant (no identity token) is rejected when
>   the governance says `<allow_unauthenticated_participants>FALSE`, and
>   refused on every topic with read or write access control when it says
>   `TRUE`;
> - a participant whose handshake is in progress or failed is refused;
> - an authenticated participant, on a topic whose governance rule enables
>   read or write access control, is judged by the permissions document it
>   presented in its handshake, signed by our Permissions CA: its rules in
>   document order, on the topic and on the partitions and data tags
>   (`PID_DATA_TAGS`) the endpoint announced, for publish (its writers) or
>   subscribe (its readers). One that presented no document (no `c.perm`,
>   or an empty one) holds no grant: it is refused when
>   `<enable_join_access_control>` is `TRUE`, and otherwise refused on
>   every topic whose rule enables read (its readers) or write (its
>   writers) access control, and on any topic no rule matches. No document
>   means no access to an access-controlled topic (DDS-Security v1.1
>   Table 63); join access control off only lets the participant in.
>
> The verdict decides the match, and the data plane applies the same one:
> our writers send a refused reader nothing (data, heartbeats, repairs, the
> late-joiner history replay of a TRANSIENT_LOCAL writer, the participant
> fallback taken before any reader is known, the answer to its ACKNACK; a
> durable reader refused while its participant's handshake is in progress
> gets the history when it completes; such withheld replays are kept for at
> most 256 readers and 64 KiB of topic and type names per participant, 4096
> and 1 MiB overall, a participant past its bound losing only its own
> oldest), and our readers refuse a refused writer's samples, dispose and
> unregister, and its HEARTBEATs and GAPs: no ACKNACK is sent, and nothing
> the reader acknowledges, asks again or counts as lost moves. A sample or lifecycle change that names no writer, and an
> ACKNACK or NACK_FRAG that names no reader, are refused by a participant
> running the security plugins.
>
> What it does not reach: data a writer sends to a multicast group, or puts
> in its shared-memory ring, reaches whoever listens on the group or opens
> the ring on the host. A protected topic's writer sends nothing to a
> multicast group, whose audience it does not know: no fallback for its
> samples, HEARTBEATs, HEARTBEAT_FRAGs, ends of coherent sets or repairs,
> and its large-sample multicast route is closed; still, whoever can capture the traffic reads it in clear
> unless the topic's `<data_protection_kind>` is `ENCRYPT`. A remote
> endpoint's partitions and data tags are those it announces: the access
> control trusts an authenticated peer's announcement of its own endpoints,
> as the specification's `check_remote_datawriter` /
> `check_remote_datareader` do.
>
> The TypeLookup service (DDS-XTypes getTypes, and HDDS's own) does not
> describe a type to a participant that has not authenticated with us when
> our endpoints announce it on discovery-protected topics only
> (`<enable_discovery_protection>TRUE`): their announcement, type
> information included, reaches authenticated participants only, on the
> secure SEDP topics (DDS-Security v1.1 7.4.1.7, 7.4.1.8). DDS-Security v1.1
> says nothing of TypeLookup itself.

### Topic Expressions

Topic expressions in permissions rules are POSIX `fnmatch()` patterns, as
in the governance (DDS-Security v1.1 9.4.1.3.2.3.1.3), matched by the same
code:

| Pattern | Matches |
|---------|---------|
| `*` | Any topic |
| `sensor/*` | `sensor/temperature`, `sensor/a/b` (a star crosses `/`), not `sensorAdmin` |
| `Secret*` | `Secret`, `SecretPlans` |
| `*/temperature` | `sensor/temperature`, `hvac/temperature`, not `footemperature` |
| `*temp*` | Any topic containing "temp" |
| `T?pic`, `Topic[0-9]` | One character; a set |
| `sensor/temperature` | Exact match only |

Expressions are matched as glibc's `fnmatch(pattern, topic, 0)` matches them
in the "C" locale (the one a process runs in until it calls `setlocale`),
byte by byte: `[!...]` and `[^...]` negate, `[[:upper:]]` and the eleven
other POSIX classes match ASCII bytes only, `[[=a=]]` and `[[.a.]]` name one
byte. Outside ASCII a character is the bytes of its UTF-8 encoding: `?`
matches one byte of it, so `caf?` does not match a `cafe` whose last letter
is U+00E9 (two bytes) while `caf??` and `caf*` do, and a bracket element or
a range is a byte. glibc in a UTF-8 locale matches by character instead; on
ASCII the two agree. A bracket glibc gives up on (an unknown class such as
`[[:uper:]]`, a collating symbol of more than one byte, which a non-ASCII
character is) is refused when the document is loaded: in a deny rule it
would deny nothing. So is an expression longer than 4096 bytes, in the
governance and the permissions alike. Until 1.5.0 the permissions engine had a matcher of its own that knew
the first four shapes above and nothing else: a deny rule on `Secret*`
denied nothing.

### Local Restriction Overlay

`permissions.xml` is signed by the Permissions CA, and that signature is the
whole reason anyone believes it. Changing what a fleet may do therefore means
reissuing and redistributing a signed document -- which is right for granting,
and far too slow for the day you need to close a topic now.

The overlay is the other half. It is a plain, unsigned file that HDDS re-reads
when it changes, and it can **only take an action away**:

```rust
let security = SecurityConfig::builder()
    .identity_certificate("certs/identity.pem")
    .private_key("certs/identity.key")
    .ca_certificates("certs/ca.pem")
    .governance_xml("governance.p7s")
    .permissions_xml("permissions.p7s")
    .permissions_ca("certs/permissions_ca.pem")
    .permissions_overlay("/etc/hdds/local-restrictions.txt")
    .permissions_overlay_poll(Duration::from_secs(5))
    .build()?;
```

From C: `hdds_security_config_set_permissions_overlay()` and
`hdds_security_config_set_permissions_overlay_poll_ms()`.

**Why an unsigned file is allowed to do this.** DDS Security v1.1 section
9.4.1.3 makes the Permissions CA the root of what a participant *may* do, so
an unsigned file that could widen a grant would be a way around the chain of
trust, reachable by whoever can write one file. Narrowing is not a property
anyone has to defend: refusing more than you are permitted to refuse breaks no
guarantee. So the signed document remains the only thing that grants, and the
overlay is read **after** it, never instead of it.

#### File format

```text
# Comments start with '#'
[subject: CN=sensor-node-1,O=HDDS]
default: allow
deny publish: sensors/raw
deny subscribe: admin/*
allow publish: data/telemetry partitions=p1,p2
```

- The subject is matched as an RFC 4514 **distinguished name**, not as a
  string: attribute order, spacing and alias spellings (`E` / `emailAddress`,
  `CN` / `commonName`) do not matter. A subject that is not a readable DN is a
  parse error, because a restriction that matches nothing restricts nothing.
- `default:` applies to the subject it appears under, when no rule matches.
- Rules are evaluated deny-first, then allow (the overlay's own format; the
  signed document applies its rules in document order).
- The overlay evaluates `partitions=` against every partition the endpoint
  names, as the signed document does: a refusal in one refuses the endpoint.
  An endpoint naming none is in the default partition, which a rule naming
  partitions does not cover.
- **A subject the file does not name is not restricted at all.** The signed
  decision stands untouched.

#### Behaviour

| Situation | Result |
|---|---|
| File missing at build | Participant build **fails** by name -- a missing restriction file would silently leave a topic open |
| File becomes malformed while running | Previous document stays in force, a `FileError` entry is written to the permission audit log |
| Poll interval set with no file | Build fails -- nothing to re-read |
| Overlay says `allow` for something the signed document denies | Still denied |
| Overlay refuses | Endpoint creation fails, and **one** `AccessControl` record with `outcome: Denied` lands in the audit chain |

---

## Encryption (AES-256-GCM)

### Overview

HDDS uses AES-256 in Galois/Counter Mode (GCM) for authenticated encryption of serialized sample payloads. This provides both confidentiality (encryption) and integrity (authentication tag).

The data plane uses the DDS-Security 1.1 builtin AES-GCM-GMAC format
([specification](https://www.omg.org/spec/DDS-SECURITY/1.1/PDF),
8.5.1.9.1 and 9.5.3.3.3-4):

1. Each protected writer owns a master sender key, master salt and four-octet
   sender key id. `DatawriterCryptoTokens` distributes that material to its
   matched authenticated readers over `ParticipantVolatileMessageSecure`.
2. The writer protects the complete SerializedPayload, including its CDR
   encapsulation and declared trailing padding. ENCRYPT emits CryptoHeader,
   CryptoContent and CryptoFooter in place of the SerializedPayload. SIGN
   emits CryptoHeader, the unchanged SerializedPayload and CryptoFooter.
3. Session keys are HMAC-SHA256 derivatives of the announced master key,
   master salt and session id. GCM uses an empty AAD and encrypts the entire
   SerializedPayload; GMAC authenticates that payload as AAD. The IV is the
   session id followed by a fresh eight-octet suffix. A process-wide block
   counter advances the session id before the configured session bound.
4. Reliable history retains the protected octets. Repairs and durable replay
   preserve these octets, source timestamp, representation and coherent-set
   metadata, including when the sample is fragmented.
5. A reader selects protection from the writer's SEDP security attributes.
   Missing attributes or key material leave protected traffic unacknowledged.
   Authentication precedes decoding, reliability credit and coherent staging.
   Unprotected application bytes cannot select decryption by their content.
   Governance ENCRYPT is enforced even when the optional crypto plugin
   is disabled: unavailable keys or cipherless delivery refuse the write.
6. For an ENCRYPT writer of a keyed type, inline PID_KEY_HASH always uses
   MD5 over the CDR big-endian key fields, even for keys shorter than
   sixteen bytes (7.3.4); a type with no instance key announces none.
   Lifecycle DATA protects the complete serialized key and is
   authenticated before resolving its instance. Hand-written keyed DDS types
   must implement `write_key_holder`; a missing hook refuses protected writes.
   A keyed type must also implement `key_hash_of_key_payload`, which reads a
   key-only payload back and hashes it exactly as `compute_key` does;
   `keys_round_trip` advertises the pair with `encode_key`. Without it, every
   dispose and unregister of a key-protected topic would be dropped by the
   reader, so endpoint creation refuses such a type on a topic under key
   protection, writer and reader alike. Generated types provide both hooks.
   Opaque keyed writers without key serialization are refused under key
   protection.

### Known Limits (read before relying on the properties above)

- **Local payload governance supports NONE and ENCRYPT.** SIGN is still refused
  at configuration load. The GMAC SerializedPayload codec is available
  independently; its wire layout below does not enable SIGN in governance.

- **Full cross-vendor security interoperability is not established.** The user
  payload codec follows DDS-Security; an interoperable security deployment
  also depends on authentication, discovery, token exchange and configuration.
- **RTPS metadata remains visible with payload-only protection.** Topic names,
  sequence numbers, status and instance MD5 digests are not encrypted by
  `encode_serialized_payload`. MD5 hides literal short keys but does not make
  a small key space resistant to dictionary enumeration.
- **Payload protection has no receiver-specific origin authentication.** All
  authorized readers receive the writer's common payload material.
- **No automatic master-key rotation.** Session keys advance without token
  exchange. Installing replacement writer tokens retires the old material;
  old ciphertext is refused under the replacement material.
- **No cryptographic payload replay window.** Reader sequence handling detects
  retransmissions; GCM itself authenticates content without establishing
  freshness of its surrounding RTPS metadata.
- **Cipherless local delivery paths refuse protected writes.** They do not
  silently deliver a cleartext copy.

### AesGcmCipher API

```rust
pub struct AesGcmCipher {
    key: [u8; 32],
}

impl AesGcmCipher {
    /// Create cipher with 256-bit key
    pub fn new(key: &[u8; 32]) -> Result<Self, SecurityError>;

    /// Encrypt plaintext (returns ciphertext + 16-byte auth tag)
    pub fn encrypt(
        &self,
        plaintext: &[u8],
        nonce: &[u8; 12],
        aad: &[u8],
    ) -> Result<Vec<u8>, SecurityError>;

    /// Decrypt ciphertext (verifies auth tag over ciphertext + aad)
    pub fn decrypt(
        &self,
        ciphertext: &[u8],
        nonce: &[u8; 12],
        aad: &[u8],
    ) -> Result<Vec<u8>, SecurityError>;

    /// Generate cryptographically secure 96-bit nonce
    pub fn generate_nonce() -> Result<[u8; 12], SecurityError>;
}
```

`AesGcmCipher` is a standalone public primitive over `ring`. The data plane
does not call it: protected payloads and submessages go through the codecs in
`security/crypto/user_data.rs` and `security/crypto/secure_submessage.rs`
(see [Protected SerializedPayload Wire Format](#protected-serializedpayload-wire-format)).

### Usage Example

```rust
use hdds::security::crypto::AesGcmCipher;

let key = [0u8; 32]; // In practice, use a properly derived key
let cipher = AesGcmCipher::new(&key)?;
let nonce = AesGcmCipher::generate_nonce()?;
let aad = 7u64.to_le_bytes(); // any context bytes both sides know

// Encrypt
let plaintext = b"secret DDS message";
let ciphertext = cipher.encrypt(plaintext, &nonce, &aad)?;
assert_eq!(ciphertext.len(), plaintext.len() + 16); // +16 for GCM auth tag

// Decrypt
let decrypted = cipher.decrypt(&ciphertext, &nonce, &aad)?;
assert_eq!(plaintext.as_ref(), decrypted.as_slice());
```

### Tamper Detection

If any byte of the ciphertext is modified, decryption fails with a `SecurityError::CryptoError`. The GCM authentication tag ensures both integrity and authenticity.

```rust
let mut tampered = ciphertext.clone();
tampered[5] ^= 0x01; // Flip one bit

// Decryption fails -- auth tag mismatch
assert!(cipher.decrypt(&tampered, &nonce, &aad).is_err());
```

---

## Key Exchange (ECDH P-256 / P-384)

### Overview

HDDS uses ephemeral Elliptic Curve Diffie-Hellman (ECDH) inside the PKI-DH authentication handshake to establish the per-peer MasterSharedSecret. Two curves are supported, selected by `key_establishment_algorithm`:

| `kagree_algo` string | Curve | Public key | Shared secret |
|----------------------|-------|------------|---------------|
| `"ECDH+prime256v1-CEUM"` (default, spec-defined) | NIST P-256 | 65 bytes | 32 bytes |
| `"ECDH+secp384r1-CEUM"` (HDDS extension) | NIST P-384 | 97 bytes | 48 bytes |

The spec-defined finite-field `"DH+MODP-2048-256"` is NOT implemented and is refused.

### Algorithm

1. The initiator generates an ephemeral keypair for its configured suite and advertises the suite string plus its public key (`dh1`) in the `AuthRequest` token -- over the ParticipantStatelessMessage channel, not SPDP/SEDP
2. The responder enforces an EXACT match against its own configured suite: an unknown or different suite fails the handshake instead of downgrading (see below)
3. Each side derives the shared secret: `agree(our_private, peer_public)`
4. Both sides derive the authentication `SharedSecret` (SHA-256 of the raw ECDH output) and the handshake's MasterSharedSecret (HKDF over the raw output, salted with both challenges), and the `SharedSecret` keys the volatile channel that carries the writers' key material ([Session Key Management](#session-key-management))

### Fail-Closed Suite Policy

Suite selection is policy, not negotiation (`security/handshake/machine.rs`):

- A config typo (`key_establishment_algorithm` set to an unknown string) is a loud local error when the first handshake starts -- it never silently falls back to P-256.
- A responder whose configured suite differs from the one the initiator advertises refuses the handshake with an explicit "suite mismatch" failure. Fleets that intend P-384 therefore get it on both sides or get a visible authentication failure -- a downgrade cannot happen silently. The flip side: mixed-suite fleets must switch together.

Note the scope: only the KEY AGREEMENT is P-384. Handshake signatures remain ECDSA-P256-SHA256/RSA-PSS-SHA256, the `SharedSecret` that keys the volatile channel is a SHA-256 digest whatever the suite, and the data plane is AES-256 whatever the suite. A claim of "P-384 throughout" would overstate it.

### EcdhKeyExchange API

```rust
pub struct EcdhKeyExchange;

impl EcdhKeyExchange {
    /// Generate ephemeral keypair for the given suite
    /// Returns (public_key_bytes, private_key)
    pub fn generate_keypair(
        suite: KeyAgreementSuite,
    ) -> Result<(Vec<u8>, EphemeralPrivateKey), SecurityError>;

    /// Derive shared secret from our private key + peer's public key
    /// Returns 32 bytes (P-256) or 48 bytes (P-384), wiped when dropped
    pub fn derive_shared_secret(
        suite: KeyAgreementSuite,
        private_key: EphemeralPrivateKey,
        peer_public: &[u8],
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, SecurityError>;

    /// Serialize public key for transmission
    pub fn serialize_public_key(public_key: &[u8]) -> Vec<u8>;

    /// Deserialize and validate public key (65 or 97 bytes, 0x04 prefix)
    pub fn deserialize_public_key(raw: &[u8]) -> Result<Vec<u8>, SecurityError>;
}
```

### Key Format

- Public key: uncompressed point `0x04 || X || Y` (65 bytes P-256, 97 bytes P-384)
- Shared secret: 32 bytes (P-256) or 48 bytes (P-384)

### Forward Secrecy

The DH keypairs are ephemeral per handshake, so compromise of one peer session's secrets does not reveal another session's. This does NOT extend to the data plane: writer keys are random values distributed in CryptoTokens under the per-peer volatile-channel keys and are never rotated, so a captured writer key decrypts that writer's whole recorded stream.

---

## Session Key Management

### Overview

Symmetric keys in the subsystem come from two sources:

- **Per-PEER keys** are derived independently by both sides from the PKI-DH
  handshake and never exchanged. They key the volatile channel that carries
  the writers' key material.
- **Per-WRITER data-plane keys** are random values minted when the writer is
  built and DISTRIBUTED to authenticated peers as DDS Security
  `DatawriterCryptoTokens`.

### Per-peer keys

When the handshake completes, both sides hold the authentication
`SharedSecret` (DDS Security v1.1 Table 53: the SHA-256 digest of the raw ECDH
output) and the two 32-byte challenges (`challenge1` from the initiator,
`challenge2` from the responder). From these, and only these, each side
derives the key material of the volatile channel as DDS Security v1.1 Table 67
specifies, with HMAC-SHA256 (Table 68) and a `sender_key_id` of 0
(`security/crypto/kx_keys.rs`). It is derived on demand and not stored in a
second table that could drift from the secret it came from.

The handshake additionally computes a MasterSharedSecret: HKDF (RFC 5869) over
the raw ECDH output, salted with `challenge1 || challenge2`, using HKDF-SHA256
for P-256 and HKDF-SHA384 for P-384. It is kept in the handshake's per-peer
state (`HandshakeState::Complete`); the volatile channel keys above do not
read it.

### SessionKeyManager API

`SessionKeyManager` is a namespace for the static HKDF helpers; it holds no
state. The handshake uses the suite-aware variant for the MasterSharedSecret:

```rust
pub struct SessionKeyManager;

impl SessionKeyManager {
    /// Derive a 32-byte AES key from a shared secret via HKDF-SHA256
    pub fn derive_session_key(
        shared_secret: &[u8],
        salt: &[u8],
        info: &[u8],
    ) -> Result<Zeroizing<[u8; 32]>, SecurityError>;

    /// Suite-aware variant (HKDF hash and output length follow the suite)
    pub fn derive_session_key_with_suite(
        suite: KeyAgreementSuite,
        shared_secret: &[u8],
        salt: &[u8],
        info: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, SecurityError>;
}
```

### Data-Plane Key Distribution

Each protected writer owns a master sender key, a master salt and a
four-octet key id (`KeyMaterial_AES_GCM_GMAC`, DDS Security v1.1 9.5.2.1.1).
The secure discovery writers each have key material of their own, distributed
the same way. The material reaches each subscriber over the
`ParticipantVolatileMessageSecure` builtin channel (DDS Security v1.1 Section
7.4.4, entities `0xff0202c3`/`c4`):

```text
Writer side (per authenticated peer, per matched reader):
  (writer GUID, key id, master key, master salt)
    -> CryptoToken "DDS:Crypto:AES_GCM_GMAC"   crypto/crypto_token.rs
    -> ParticipantGenericMessage
       (class "dds.sec.datawriter_crypto_tokens")  crypto/volatile.rs
    -> DATA submessage protected as SEC_PREFIX / SEC_BODY / SEC_POSTFIX,
       AES-256-GCM under THAT peer's volatile-channel key material
    -> ParticipantVolatileMessageSecure (reliable, unicast)

Reader side:
  message from an authenticated peer
    -> opened with our volatile-channel key material for that peer
    -> installed in DataKeyStore under (writer GUID, key id) only when the
       destination is one of our endpoints matched with that writer
    -> reader decrypt gate finds it at ingest
```

A background sweep, running every 250 ms, writes into the volatile channel
what an authenticated peer is owed and has not been given: a key just minted,
a peer just authenticated, a new match. A lost message is repaired by the
reliable channel's own retransmission. Messages from peers whose handshake has
not completed are dropped before any crypto runs.

A sample's own session key is derived per DDS Security v1.1 9.5.3.3.3 from
the writer's master key, master salt and the session id of its CryptoHeader
(see [Encryption](#encryption-aes-256-gcm)).

### Key Rotation

**Not implemented.** A writer's data-plane key is minted once at build time
and lives as long as the writer; per-peer keys live as long as the
authenticated session. There is no rotation trigger and no re-keying API.
The per-session keys derived from a writer's master key advance with the
session id, but a captured master key derives all of them. Plan deployments
accordingly: a compromised writer key exposes that writer's full stream until
the writer (not just the key) is torn down.

---

## Certificate Setup

### Generating Test Certificates

HDDS includes a script that generates test material at
`sdk/samples/05_security/certs/generate_certs.sh`: an identity CA, a separate
Permissions CA and identity certificates for the sample participants. Write
your own governance and permissions documents (see the sections below) and
sign them as shown in [Signed governance and permissions documents](#signed-governance-and-permissions-documents).

```bash
cd sdk/samples/05_security/certs
./generate_certs.sh
```

The core of it is plain `openssl`. The two CAs are distinct on purpose: a key
that can issue identities must not, by that fact alone, be able to forge
permissions.

```bash
# Identity CA (trust anchor for participant certificates)
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout ca_key.pem -out ca_cert.pem \
    -subj "/C=US/O=HDDS/CN=HDDS-TestCA"

# Permissions CA (signs governance and permissions documents). HDDS checks
# its validity window before it checks a signature, so give it the lifetime
# of the grants it signs.
openssl req -x509 -nodes -newkey rsa:2048 \
    -not_before 20200101000000Z -not_after 20360101000000Z \
    -keyout permissions_ca_key.pem -out permissions_ca.pem \
    -subj "/C=US/O=HDDS/CN=HDDS-PermissionsCA"

# One participant identity, signed by the identity CA
openssl req -nodes -newkey rsa:2048 \
    -keyout Participant1_key.pem -out Participant1_csr.pem \
    -subj "/C=US/O=HDDS/CN=Participant1"
openssl x509 -req -days 365 -in Participant1_csr.pem \
    -CA ca_cert.pem -CAkey ca_key.pem -CAcreateserial \
    -out Participant1_cert.pem
```

### Certificate Files

| File | Purpose |
|------|---------|
| `ca_cert.pem` | Identity CA certificate (trust anchor for participant identities) |
| `ca_key.pem` | Identity CA private key (keep secure, signs participant certs) |
| `permissions_ca.pem` | Permissions CA certificate (trust anchor for the signed documents) |
| `permissions_ca_key.pem` | Permissions CA private key (keep secure, signs the documents) |
| `Participant1_cert.pem` | Participant identity certificate (PEM) |
| `Participant1_key.pem` | Participant private key (PKCS#8 PEM) |
| `governance.p7s`, `permissions_Participant1.p7s` | Signed governance and permissions documents (produced as shown below) |

### X.509 Subject Name Format

```text
CN=Participant1,O=HDDS,C=US
|              |         |
|              |         +-- Country
|              +-- Organization
+-- Common Name (participant identity)
```

The `<subject_name>` of a grant must name the SAME subject as the identity
certificate: the full distinguished name, not only its CN. Names are compared
as RFC 4514 distinguished names, so attribute order, spacing and alias
spellings (`E` / `emailAddress`) do not matter, but every attribute must
match. A grant issued to a different subject is dropped when the participant
starts.

### Signed governance and permissions documents

HDDS requires both documents to be signed by the Permissions CA
(DDS-Security v1.1 9.4.1.2 and 9.4.1.3) and verifies the signature before the
participant starts. A plain-XML document is refused and the participant build
fails. Point `governance_xml` and `permissions_xml` at the SIGNED files and
name the Permissions CA with `permissions_ca`; either document without
`permissions_ca` is a build error, and there is no fallback to
`ca_certificates`.

Sign with `openssl smime` and the Permissions CA key (the permissions document
here is the one you wrote for `Participant1`):

```bash
openssl smime -sign -in governance.xml \
    -signer permissions_ca.pem -inkey permissions_ca_key.pem \
    -outform SMIME -text -md sha256 -out governance.p7s

openssl smime -sign -in permissions_Participant1.xml \
    -signer permissions_ca.pem -inkey permissions_ca_key.pem \
    -outform SMIME -text -md sha256 -out permissions_Participant1.p7s

# Check the way HDDS does
openssl smime -verify -in governance.p7s -CAfile permissions_ca.pem -out /dev/null
```

Do not add `-nodetach`: for S/MIME output it produces an opaque
`application/pkcs7-mime` blob instead of `multipart/signed`. A DER PKCS#7
envelope with the document attached is accepted as well. The signer must be
the Permissions CA key itself (a signing certificate issued by the Permissions
CA is refused), and certificates carried inside the envelope are never used as
trust anchors. Governance and permissions documents are both required, or
neither: setting only one is a participant build error.

For local development only, `SecurityConfigBuilder::insecure_allow_unsigned_documents(true)`
accepts plain XML for this participant's OWN documents, with a warning and,
when audit logging is on, an audit record. It does not exist in the C API or
in the XML/YAML loaders, and a remote peer's unsigned permissions document is
always refused.

### Production Recommendations

- Use a proper PKI infrastructure (not self-signed test certs)
- Use identity keys the handshake can sign with: EC P-256 or RSA, as PKCS#8 PEM
- Set appropriate certificate validity periods (1-2 years typical)
- Check certificate revocation: set `check_certificate_revocation(true)` and
  name a CRL with `certificate_revocation_list(path)`. HDDS checks both the
  local identity and every remote peer certificate against it. A CRL is
  believed only when it was issued by the certificate's own CA and its
  signature verifies against that CA's key; with the flag on, every issuing CA
  in your trust store needs a current CRL in the list, so the list is usually
  a PEM bundle of several CRLs (a single DER CRL is accepted too). HDDS
  refuses a CRL that is past its `nextUpdate`, or carries none - stale revocation data cannot
  prove that a certificate has not been revoked since the list was issued -
  and refuses a list nobody would consult (a CRL named with the flag off). A
  revoked local identity fails at participant build. OCSP is not
  supported: it needs an outbound HTTP connection that an air-gapped
  deployment does not have
- Restrict access to the private key file: HDDS reads the identity key from a PEM file, and hardware-backed keys (HSM, PKCS#11) are not supported

---

## Configuration

### SecurityConfig Builder

```rust
use hdds::security::SecurityConfig;

let config = SecurityConfig::builder()
    // Required: identity and trust
    .identity_certificate("certs/Participant1_cert.pem")
    .private_key("certs/Participant1_key.pem")
    .ca_certificates("certs/ca_cert.pem")

    // Optional: access control (both documents or neither, signed by the
    // Permissions CA)
    .governance_xml("governance.p7s")
    .permissions_xml("permissions_Participant1.p7s")
    .permissions_ca("certs/permissions_ca.pem")

    // Optional: encryption
    .enable_encryption(true)

    // Optional: audit logging
    .enable_audit_log(true)
    .audit_log_path("/var/log/hdds_audit.log")

    // Optional: authentication settings
    .require_authentication(true)           // default: true
    .check_certificate_revocation(true)     // default: false on builder(), true on secure_builder()
    .certificate_revocation_list("certs/crl.pem")  // REQUIRED when the flag is on

    .build()?;
```

### Attaching Security to a Participant

```rust
use hdds::security::SecurityConfig;
use hdds::{Participant, TransportMode};

let security = SecurityConfig::builder()
    .identity_certificate("certs/Participant1_cert.pem")
    .private_key("certs/Participant1_key.pem")
    .ca_certificates("certs/ca_cert.pem")
    .governance_xml("certs/governance.p7s")
    .permissions_xml("certs/permissions_Participant1.p7s")
    .permissions_ca("certs/permissions_ca.pem")
    .enable_encryption(true)
    .enable_audit_log(true)
    .build()?;

let participant = Participant::builder("secure_app")
    .with_transport(TransportMode::UdpMulticast)
    .with_security(security)
    .build()?;
```

### SecurityConfig Fields

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `identity_certificate` | Yes | -- | X.509 PEM certificate path |
| `private_key` | Yes | -- | PEM private key path |
| `ca_certificates` | Yes | -- | CA PEM certificate(s) path |
| `governance_xml` | No | None | Signed governance document path. Set it together with `permissions_xml` or not at all |
| `permissions_xml` | No | None | Signed permissions document path. With neither document, no access control is applied |
| `permissions_ca` | With either document | None | Permissions CA certificate (PEM), the only trust anchor of the signed documents. Not required with `insecure_allow_unsigned_documents` |
| `insecure_allow_unsigned_documents` | No | `false` | Development only: accept plain-XML local documents, with a warning and an audit record. Absent from the C API |
| `permissions_overlay` | No | None | Local restriction file, see [Local Restriction Overlay](#local-restriction-overlay) |
| `permissions_overlay_poll` | No | None | Interval at which the overlay file is re-read; requires `permissions_overlay` |
| `legacy_partition_matching` | No | `false` | Read the allowed partitions conditions of permissions documents (ours and the peers') with the "legacy matching" of DDS-Security v1.1 9.4.1.3.2.3.1.4: one partition of the endpoint matching is enough |
| `enable_encryption` | No | `false` | Enable AES-256-GCM encryption |
| `enable_audit_log` | No | `false` | Enable security audit logging |
| `audit_log_path` | No | None | Audit log file path (in-memory if unset) |
| `audit_syslog_address` | No | None | UDP address of an RFC 5424 syslog collector that mirrors the audit records; requires `enable_audit_log` |
| `key_establishment_algorithm` | No | `"ECDH+prime256v1-CEUM"` | Key agreement suite, or `"ECDH+secp384r1-CEUM"`; see [Key Exchange](#key-exchange-ecdh-p-256--p-384) |
| `require_authentication` | No | `true` | Require PKI auth for all participants (with a governance document, `<allow_unauthenticated_participants>FALSE` rejects them even when this is `false`) |
| `check_certificate_revocation` | No | `false` | Check certificates against a CRL. `true` on `secure_builder()` |
| `certificate_revocation_list` | Only if the flag is on | None | PEM bundle of CRLs (one per issuing CA) or a single DER CRL, each verified against its issuer's key. The build FAILS if the flag is on and this is unset, and if this is set with the flag off |

### Build Validation

The `build()` method validates:

1. All required fields are set (returns `Error::Config` if missing)
2. All certificate files exist on disk
3. Governance XML, Permissions XML, the Permissions CA and the overlay file exist if specified
4. `permissions_ca` is set when either document is (unless `insecure_allow_unsigned_documents` is on)
5. Revocation checking and the CRL go together (see the table above)

File format validation (PEM parsing, signature verification, XML schema) is deferred to participant creation: a participant given only one of the two documents, an unsigned or wrongly signed document, or a governance document that does not parse fails to build there, with an `Error::Config`.

---

## Governance XML

Governance XML defines domain-wide security policies. It specifies which DDS domains a participant may join, and how traffic on them is protected.

Element names are the ones DDS-Security v1.1 defines (section 9.4.1.2). Earlier
revisions of this guide taught a shorter set -- `allow_unauthenticated`,
`encrypt_discovery`, `encrypt_topics` -- and those still work, so a document
written against the old guide keeps parsing. Write the specification's names in
anything new.

### Format

The `<domain_rule>` elements are found wherever they sit in the document, so
both a bare `<governance>` root and the specification's
`<dds><domain_access_rules>` nesting are read. The document is signed by the
Permissions CA before HDDS loads it (see
[Signed governance and permissions documents](#signed-governance-and-permissions-documents)).

```xml
<?xml version="1.0"?>
<governance>
  <domain_rule>
    <domains>0</domains>
    <allow_unauthenticated_participants>false</allow_unauthenticated_participants>
    <enable_join_access_control>true</enable_join_access_control>
    <discovery_protection_kind>ENCRYPT</discovery_protection_kind>
    <data_protection_kind>ENCRYPT</data_protection_kind>
  </domain_rule>
</governance>
```

### Fields

There is no default for a setting that decides a protection: a rule that does
not say what it protects is refused at load, naming the missing element. An
absent element used to read as "off", silently, which is the one reading an
operator never means.

A `<domain_rule>` takes one of two forms.

**The specification's form** (DDS-Security v1.1 section 9.4.1.2.3), every
element required:

| Element | Description |
|---------|-------------|
| `<domains>` | Domain ids this rule applies to. Either a number, or `<id>`/`<id_range>` children (see below) |
| `<allow_unauthenticated_participants>` | `FALSE`: a participant presenting no identity token is rejected at discovery, whatever `require_authentication` says. `TRUE` (insecure): it is admitted; on a topic with read or write access control it is never matched, our writers send its readers nothing, and our readers refuse its writers' samples, dispose and unregister (see "Enforcement scope" under Access Control); on other topics it is matched like anyone |
| `<enable_join_access_control>` | If `TRUE`, a participant's permissions are checked before it joins the domain: one that presents no permissions document is refused. `FALSE` lets such a participant in, but grants it nothing: it is still refused on every topic whose rule enables read or write access control |
| `<discovery_protection_kind>` | Protection of the secure discovery endpoints: `NONE` (announced on them, untransformed), `SIGN` (AES-GMAC) or `ENCRYPT` (AES-GCM); either `..._WITH_ORIGIN_AUTHENTICATION` is refused, see below |
| `<liveliness_protection_kind>` | `NONE` (anything else is refused, see below) |
| `<rtps_protection_kind>` | `NONE` (anything else is refused, see below) |
| `<topic_access_rules>` | One or more `<topic_rule>`, evaluated in order: the FIRST whose `<topic_expression>` matches a topic is the one applied to it |

Each `<topic_rule>` carries, all required:

| Element | Description |
|---------|-------------|
| `<topic_expression>` | POSIX `fnmatch()` pattern: `*`, `?`, `[...]`, backslash quoting (an unpaired backslash at the end matches nothing) |
| `<enable_discovery_protection>` | `TRUE`: the endpoint is announced on the secure discovery topics (`DCPSPublicationsSecure` / `DCPSSubscriptionsSecure`); `FALSE`: on the regular ones |
| `<enable_liveliness_protection>` | `FALSE` (`TRUE` is refused, see below) |
| `<enable_read_access_control>` | `TRUE`: creating or matching a reader is checked against the permissions document; `FALSE`: allowed without consulting it (its deny rules included) |
| `<enable_write_access_control>` | The same for writers |
| `<metadata_protection_kind>` | `NONE` (anything else is refused, see below) |
| `<data_protection_kind>` | `NONE` or `ENCRYPT`: whether the payload of the topic's samples is encrypted. `ENCRYPT` needs a participant built with `enable_encryption(true)`: without it, creating a writer or reader of the topic is refused rather than letting its samples cross in clear |

A topic that no rule matches is refused (section 9.4.1.2.7); end the list with a
`<topic_expression>*</topic_expression>` rule to give every other topic a
policy.

**The shorthand** this guide documented first: no `<topic_access_rules>`, and a
domain-level `<data_protection_kind>` instead. It reads as one `*` topic rule:
discovery protection on when `<discovery_protection_kind>` is not `NONE`, read
and write access control on, no liveliness or metadata protection, and the data
protection it names. `<liveliness_protection_kind>` and `<rtps_protection_kind>`
are optional in this form and read as `NONE`. A rule that carries both a
domain-level `<data_protection_kind>` and `<topic_access_rules>` is refused.

Booleans are read as the specification writes them: `TRUE`, `FALSE`, `true`,
`false`, `1`, `0`. `yes` and an empty element are refused rather than read as
`false`. An element given twice in one rule is refused.

A protection this release does not apply is refused at load, naming the
element, because accepting a protection nobody applies is worse than refusing
it -- the operator cannot tell. Refused today: `<rtps_protection_kind>` and
`<liveliness_protection_kind>` other than `NONE`, `<enable_liveliness_protection>`
`TRUE`, `<metadata_protection_kind>` other than `NONE`, `<data_protection_kind>`
`SIGN`, and `<discovery_protection_kind>` `SIGN_WITH_ORIGIN_AUTHENTICATION` or
`ENCRYPT_WITH_ORIGIN_AUTHENTICATION`: origin authentication needs a
receiver-specific key for each matched remote reader (DDS-Security v1.1 Table
70, `register_matched_remote_datareader`), and the secure discovery writers
announce one key material per writer to every authenticated participant.

### Discovery protection

Each endpoint is announced where its topic rule says (DDS-Security v1.1 Table
29): with `<enable_discovery_protection>` `TRUE` on the secure discovery topics
(`DCPSPublicationsSecure` / `DCPSSubscriptionsSecure`), protected as
`<discovery_protection_kind>` says, and only to participants that have
authenticated -- a participant that has not gets a GAP for that announcement and
never learns the endpoint; with `FALSE`, on the regular discovery topics, in
clear, to everyone. A plain announcement of an endpoint of a topic your
governance protects is not taken, from anybody, and a secure announcement is
read only when it is at least as protected as your own
`<discovery_protection_kind>` asks.

Participant discovery (SPDP) stays on the regular topic, in clear: it is what
lets two participants find each other and start the authentication handshake.

Under a governance document a participant announces its
`ParticipantSecurityAttributes` in `PID_PARTICIPANT_SECURITY_INFO` and each
endpoint its `EndpointSecurityAttributes` in `PID_ENDPOINT_SECURITY_INFO`, with
the bits of DDS-Security v1.1 Tables 28, 31, 60 and 62. Two participants of one
governance announce the same masks.

A participant configured without a governance document keeps the behaviour of
earlier releases: every endpoint announced encrypted to authenticated
participants and in clear to the others. An HDDS 1.4.x peer receives every
announcement in the sealed form it reads, whatever the topic's protection.

Any other element is refused, naming the element.

### Domain ranges

`<domains>` takes ranges as well as single ids. `<max>` may be omitted, which
means "from `<min>` upwards".

```xml
<domains>
  <id>0</id>
  <id_range><min>10</min><max>20</max></id_range>
</domains>
```

Ranges are stored as bounds, not expanded, so a wide range costs nothing.

### Multiple Domain Rules

```xml
<governance>
  <domain_rule>
    <domains>0</domains>
    <allow_unauthenticated_participants>false</allow_unauthenticated_participants>
    <enable_join_access_control>true</enable_join_access_control>
    <discovery_protection_kind>ENCRYPT</discovery_protection_kind>
    <data_protection_kind>ENCRYPT</data_protection_kind>
  </domain_rule>
  <domain_rule>
    <domains>1</domains>
    <allow_unauthenticated_participants>true</allow_unauthenticated_participants>
    <enable_join_access_control>false</enable_join_access_control>
    <discovery_protection_kind>NONE</discovery_protection_kind>
    <data_protection_kind>NONE</data_protection_kind>
  </domain_rule>
</governance>
```

### A domain no rule covers is refused

The governance decides whether a participant may join at all. Building a
participant on a domain that no `<domain_rule>` names fails with a
`PermissionDenied` error, before any socket is bound. That is deliberate: a
deployment that configured security and then joined a domain its own policy
does not describe has a configuration error, and admitting it quietly is the
outcome that cannot be defended to an auditor.

---

## Permissions XML

Permissions XML defines per-participant topic-level access control. Each `<grant>` element specifies what a participant (identified by certificate subject name) is allowed or denied to do. A permissions document is signed by the Permissions CA (see [Signed governance and permissions documents](#signed-governance-and-permissions-documents)); the examples below show the XML before signing. One signed document may hold the grants of several participants: each participant applies the grants whose subject is its own.

### Format

```xml
<?xml version="1.0"?>
<permissions>
  <grant>
    <subject_name>CN=SensorNode,O=HDDS,C=US</subject_name>
    <validity>
      <not_before>2024-01-01T00:00:00</not_before>
      <not_after>2030-01-01T00:00:00</not_after>
    </validity>

    <!-- Allow rules -->
    <allow_rule>
      <domains>0</domains>
      <publish>
        <topics>sensor/*</topics>
      </publish>
      <subscribe>
        <topics>command/*</topics>
      </subscribe>
    </allow_rule>

    <!-- Deny rules (evaluated in document order, together with the allow rules) -->
    <deny_rule>
      <domains>0</domains>
      <publish>
        <topics>admin/*</topics>
      </publish>
    </deny_rule>
  </grant>
</permissions>
```

### Grant Fields

| Element | Description |
|---------|-------------|
| `<subject_name>` | X.509 subject distinguished name of the participant the grant is issued to; must equal the subject of its identity certificate (every attribute, in any order) |
| `<validity>` | Time window during which this grant is active |
| `<allow_rule>` | Topics, partitions and data tags this participant CAN publish or subscribe with |
| `<deny_rule>` | Topics, partitions and data tags this participant CANNOT publish or subscribe with |
| `<default>` | `ALLOW` or `DENY` (case-insensitive): the decision when no rule matches. Absent: `DENY`. It must come after every rule; given twice, or before a rule, the document is refused |

### Rule Fields

| Element | Description |
|---------|-------------|
| `<domains>` | Domain ID this rule applies to |
| `<publish><topics>` | Topic patterns the participant can publish to: exactly one `<topics>` element per criterion, holding the expression as text or several `<topic>` children |
| `<subscribe><topics>` | Topic patterns the participant can subscribe to, same shape |
| `<publish><partitions>`, `<subscribe><partitions>` | Partition expressions (fnmatch) of that criterion |
| `<publish><data_tags>`, `<subscribe><data_tags>` | Data tags (`<tag><name>..</name><value>..</value></tag>`) of that criterion |
| `<relay>` | Kept in the model, never grants publish/subscribe; a remote endpoint whose only matching permission is relay is refused (HDDS mints no `relay_only` cryptographic material, 8.4.2.9.10-11, 9.5.3.3.4) |

Each `<publish>` / `<subscribe>` is one criterion, evaluated on its own:
topic AND partitions AND data tags (9.4.1.3.2.3.1.2).

- An allow rule's `<partitions>` is met when **every** partition the
  endpoint names matches one of its expressions (POSIX `fnmatch()`, the
  matcher of the topic expressions): allowed in `A`, in `B` or in `{A, B}`
  under `A, B`, not in `{A, B, C}`. Without `<partitions>`, only the default
  (empty string) partition (9.4.1.3.2.3.1.4). The "legacy matching" the same
  section asks implementations to offer as an option is selected with
  `SecurityConfig::builder().legacy_partition_matching(true)` (off by
  default): an allow rule's `<partitions>` is then met when **one**
  partition the endpoint names matches (`{A, B, C}` allowed under `A, B`),
  and without `<partitions>` when one of them is the default partition. It
  applies to this participant's document and to those its peers present;
  deny rules read the same either way.
- A deny rule's `<partitions>` is met when **one** partition the endpoint
  names matches; without `<partitions>`, in every partition
  (9.4.1.3.2.3.2.4).
- An allow rule's `<data_tags>` is met when the endpoint's data tags are a
  subset of its tags (name and value); without `<data_tags>`, only an
  endpoint without data tags (9.4.1.3.2.3.1.5). A deny rule's is met when
  the endpoint has one of its tags; without `<data_tags>`, whatever its
  tags (9.4.1.3.2.3.2.5).
- An endpoint with no PARTITION is in the default partition. A remote
  endpoint's data tags are those of its `PID_DATA_TAGS`; HDDS endpoints
  carry none (one created with data tags is refused).

These apply locally when a writer or reader is created, and to a remote
participant's endpoints at matching and on the data plane, on what the
endpoint announced; a re-announcement that changes its partitions or data
tags is judged again. A `<partitions>` or `<data_tags>` directly in a rule
(the schema puts them in a criterion), a criterion without `<topics>`, an
empty `<partitions>` or `<data_tags>`, or a `<tag>` without one `<name>` and
one `<value>` is refused at load.

### Rule Evaluation Order

1. **Governance** -- no topic rule: denied; access control off for the topic: allowed
2. **Rules in document order** -- the first allow or deny rule with a matching criterion decides
3. **`<default>`** -- if no rule matches; absent, access is denied (zero trust)

### Example: Multi-Role Permissions

```xml
<?xml version="1.0"?>
<permissions>
  <!-- Sensor nodes: can publish sensor data, subscribe to commands -->
  <grant>
    <subject_name>CN=SensorNode,O=HDDS,C=US</subject_name>
    <validity>
      <not_before>2024-01-01T00:00:00</not_before>
      <not_after>2030-01-01T00:00:00</not_after>
    </validity>
    <allow_rule>
      <domains>0</domains>
      <publish>
        <topics>sensor/*</topics>
      </publish>
      <subscribe>
        <topics>command/*</topics>
      </subscribe>
    </allow_rule>
  </grant>

  <!-- Controller: can publish commands, subscribe to everything -->
  <grant>
    <subject_name>CN=Controller,O=HDDS,C=US</subject_name>
    <validity>
      <not_before>2024-01-01T00:00:00</not_before>
      <not_after>2030-01-01T00:00:00</not_after>
    </validity>
    <allow_rule>
      <domains>0</domains>
      <publish>
        <topics>command/*</topics>
      </publish>
      <subscribe>
        <topics>*</topics>
      </subscribe>
    </allow_rule>
    <deny_rule>
      <domains>0</domains>
      <publish>
        <topics>admin/*</topics>
      </publish>
    </deny_rule>
  </grant>

  <!-- Admin: full access -->
  <grant>
    <subject_name>CN=Admin,O=HDDS,C=US</subject_name>
    <validity>
      <not_before>2024-01-01T00:00:00</not_before>
      <not_after>2030-01-01T00:00:00</not_after>
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
```

---

## Audit Logging

### Overview

The `LoggingPlugin` provides an audit trail for security events: authentication
outcomes, access-control decisions and key-handling operations. Every record is
hash-chained to the previous one to make tampering detectable.

### Security Event Types

```rust
pub enum SecurityEvent {
    Authentication {
        participant_guid: [u8; 16],
        outcome: AuthenticationOutcome,  // Success, Failed, Revoked
        timestamp: u64,                  // nanoseconds since the Unix epoch
    },
    AccessControl {
        participant_guid: [u8; 16],
        action: String,                 // e.g. "create_writer", "create_reader"
        resource: String,               // topic name (and partitions)
        outcome: AccessOutcome,         // Allowed, Denied
        timestamp: u64,
    },
    Crypto {
        key_id: u64,
        operation: String,              // e.g. "install_data_key"
        outcome: CryptoOutcome,         // Success, Failed
        timestamp: u64,
    },
}
```

### Hash-Chain Integrity

One record per line:

```text
<event> prev=<64 hex> hash=<64 hex> seq=<n>
```

`<event>` is the `Debug` rendering of the `SecurityEvent`, `prev` is the hash of
the previous line, `seq` is the line ordinal counted from the first line of
the file, and `hash` is `SHA-256(prev || seq || <event>)` (`seq` as eight
bytes, big endian). The first line of a file carries `prev` = 32 zero bytes
and `seq` = 0.

The chain is continuous over the whole file. Each time the file is opened, an
`AuditChainStart` marker is appended that chains onto the last line already
there, so a participant restart is a visible boundary and removing a whole run
breaks a link. If any record is modified or deleted in the middle, every later
hash becomes invalid.

`hdds::security::audit::verify_chain(contents)` walks a file and names the
first line that is malformed, out of sequence, or does not chain. It cannot
detect the removal of the end of the file: a prefix of a valid chain is a
valid chain, and detecting that needs an anchor kept outside the file (an
offsite copy of the last hash).

### Failure Policy

Opening the audit file is fail-closed at participant build, and so is a file
whose last line cannot be read back. A write that fails while the participant
runs cannot undo the decision it records, so the chain is marked degraded for
the life of the participant: it then refuses to start or advance any
handshake, to install any new key and to create any new endpoint. A lost
record stops new trust from being established.

Audit files are created with mode 0600 on unix. One file belongs to one
participant: a path already open in this process is refused at build.

### Configuration

```rust
// File-backed audit log
let config = SecurityConfig::builder()
    .identity_certificate("certs/participant.pem")
    .private_key("certs/participant_key.pem")
    .ca_certificates("certs/ca.pem")
    .enable_audit_log(true)
    .audit_log_path("/var/log/hdds_audit.log")
    .build()?;

// In-memory audit log (no file path)
let config = SecurityConfig::builder()
    .identity_certificate("certs/participant.pem")
    .private_key("certs/participant_key.pem")
    .ca_certificates("certs/ca.pem")
    .enable_audit_log(true)
    .build()?;
```

`audit_syslog_address(addr)` additionally exports every record to an RFC 5424
syslog collector over UDP. Alongside a file, the export is a mirror whose
failure is logged; with no file, the export is the record, and a failed emit
degrades the chain.

### Thread Safety

All decision points share one audit chain inside `SecurityPluginSuite`, behind
a lock. The convenience method `log_security_event()` handles locking
automatically:

```rust
// Thread-safe logging via SecurityPluginSuite
suite.log_security_event(&event)?;
```

---

## Protected SerializedPayload Wire Format

DDS-Security 1.1 9.5.3.3.4.1-4 defines the user payload replacement below.
These are submessage *elements*, with no SEC_PREFIX / SEC_BODY / SEC_POSTFIX
submessage headers around them. The complete replacement is fragmented when
DATA_FRAG is required.

```text
CryptoHeader (20 octets):
  transformation_kind       octet[4], AES256_GCM = 00 00 00 04
  transformation_key_id     octet[4], writer's announced sender_key_id
  session_id                octet[4]
  initialization_vector_suffix octet[8]
CryptoContent (ENCRYPT):
  length                    u32 big endian
  ciphertext                length octets, encrypted encapsulation + body
CryptoFooter:
  common_mac                octet[16], immediately after ciphertext
  alignment                 zero padding to a four-octet boundary
  receiver_specific_macs    u32 big endian count, zero for payload protection
```

The SIGN encoder takes a four-aligned SerializedPayload including its declared
CDR padding. For SIGN, transformation_kind is `00 00 00 03`, the unchanged SerializedPayload
replaces CryptoContent (there is no content-length word), and common_mac is
its AES-GMAC tag. The CryptoHeader and CryptoFooter fields use big endian
independently of the DATA submessage E flag and the encrypted CDR byte order.

There is no clear CDR encapsulation outside these elements. After successful
authentication the reader recovers the original representation id, removes
only the padding declared by its options, and delivers the original body.
The key lookup is `(writer GUID, transformation_key_id)`; both master key and
salt come from that writer's installed CryptoToken generation. Token
replacement immediately makes prior material unavailable to new lookups.

The ENCRYPT overhead is 44 octets for an aligned SerializedPayload: twenty
for CryptoHeader, four for the content length and twenty for CryptoFooter.
SIGN adds forty octets. These counts exclude RTPS headers, inline QoS and
the original SerializedPayload encapsulation and padding.

---

## Known Limitations

### Control submessages of user endpoints are not authenticated

Metadata protection (`<metadata_protection_kind>`) and whole-message
protection (`<rtps_protection_kind>`) are not implemented. The payload of a
sample on a protected topic is encrypted and authenticated, but the control
submessages of user writers and readers travel unauthenticated: HEARTBEAT,
GAP, ACKNACK and the end-of-coherent-set marker.

An on-path attacker who knows a writer's GUID can forge these submessages.
With them it can truncate a coherent set, so that a reader delivers part of
the set as if it were complete, and it can make a reader drop the next
genuine sample of that writer. It cannot make a reader deliver data that was
not authenticated: a sample whose payload does not authenticate is never
delivered.

A governance document that requests metadata protection or RTPS protection
(any kind other than `NONE`) is refused when the participant is created,
naming the element and the kind, so a deployment cannot believe it has a
protection that is not applied.

### A directly created authentication plugin reads the CRL once

A participant re-reads its certificate revocation list while it runs and
judges every handshake against the list in force. `create_authentication_plugin`
and `X509AuthenticationPlugin::new`, used directly outside a participant,
read the CRL once, when they are called. An application that embeds the
plugin this way must create it again after every CRL rotation; otherwise it
keeps judging certificates against the old list.

### Source filtering is not supported

`HDDS_SOURCE_ALLOW` and `HDDS_SOURCE_DENY` (source address allow and deny
lists) are not supported in 1.5.0. Setting either variable makes participant
creation fail with "source filtering is not supported in this release", so a
deployment cannot believe it filters sources when it does not. Restrict
sources with a network firewall or with DDS Security access control.

---

## Performance Considerations

HDDS does not currently publish a reference-grade security performance
benchmark. Authentication, key agreement, encryption, and revocation costs
depend on the certificate suite, payload, topology, hardware, and transport.
Measure the secured and unsecured paths with identical source revisions,
build flags, QoS, payloads, and machine configuration before quoting an
overhead.

### Optimization Tips

1. **Keep revocation checking enabled when the deployment policy requires it.**
2. **Benchmark the configured certificate suite on the target hardware.**

---

## Troubleshooting

### Common Issues

#### 1. "Error::Config" on SecurityConfig::build()

**Cause**: Required fields missing or certificate files not found.

**Fix**: Verify all required paths exist:

```bash
ls -la certs/participant_cert.pem certs/participant_key.pem certs/ca_cert.pem
```

Ensure all three required fields are set:
- `identity_certificate()`
- `private_key()`
- `ca_certificates()`

#### 2. Authentication Fails with CertificateInvalid

**Cause**: Certificate not signed by the trusted CA.

**Fix**: Verify the certificate chain:

```bash
openssl verify -CAfile ca_cert.pem participant_cert.pem
```

Expected output: `participant_cert.pem: OK`

#### 3. Authentication Fails with CertificateExpired

**Cause**: Certificate validity period has passed.

**Fix**: Check certificate dates:

```bash
openssl x509 -in participant_cert.pem -noout -dates
```

Regenerate certificates if expired.

#### 4. PermissionsDenied on Topic Write/Read

**Cause**: No matching `allow_rule` for the topic, or a `deny_rule` matches.

**Fix**: Check the permissions XML:
- Verify the `subject_name` is the full subject of the identity certificate (`openssl x509 -in participant_cert.pem -noout -subject`); a grant issued to another subject is dropped at startup
- Verify the document is signed by the Permissions CA and that `permissions_ca` names it
- Verify the topic pattern in `<publish>` or `<subscribe>` matches your topic
- Verify the `<validity>` dates are current
- Remember: rules apply in document order, the first match deciding; a deny
  rule written after a broader allow rule is never reached
- Check the partitions the endpoint names: an allow rule without
  `<partitions>` grants the default partition only

#### 5. Protected samples are not delivered right after a peer appears

**Cause**: A secured sample arrived before the writer's key material (its `DatawriterCryptoTokens`). The reader cannot open it, does not deliver it, and does not credit its sequence number as received.

**Fix**: Usually nothing -- this is normal during startup. The writer's key is sent to each authenticated peer as soon as the handshake completes and on every distribution sweep (250 ms), and RELIABLE readers recover the withheld samples via NACK repair once the key lands. If it persists:
- Verify the two participants actually completed the PKI-DH handshake (same CA, valid certificates) -- key distributions from unauthenticated peers are dropped before any crypto runs
- Verify BOTH sides enabled encryption; a participant built without it never opens the key material

#### 6. Writer refuses writes with EncryptionUnavailable

**Cause**: Encryption is enabled but the writer holds no data-plane key, or a delivery leg has no cipher. This is the fail-closed contract: an encrypting writer never degrades to cleartext, including on the intra-process leg and for dispose/unregister lifecycle DATA.

**Fix**:
- Ensure the writer was built with an RTPS endpoint (keys are minted at build time and need a wire to encrypt for); `TransportMode::UdpMulticast` provides one
- If the refusal is on an intra-process-only leg, that is by design: the process-wide registry can deliver to readers of a different security principal, so cleartext local delivery is refused

#### 7. Reader logs "protected payload from writer=... failed to open"

**Cause**: The GCM tag did not verify -- tampering or truncation in transit, or the reader holds a stale key for that `(writer GUID, key id)` pair.

**Fix**:
- A writer restart re-mints its key under a fresh key id; the new key is distributed to authenticated peers and installed on arrival, after which new samples open normally (samples sealed under the old key are gone with the old writer)
- If it persists, capture the traffic and check for middlebox interference; a consistently failing tag on an unchanged pair is tampering until proven otherwise

#### 8. "Governance XML parsing requires 'qos-loaders' feature"

**Cause**: The `qos-loaders` Cargo feature is not enabled.

**Fix**: Add the feature to your `Cargo.toml`:

```toml
hdds = { version = "1.5", features = ["security", "qos-loaders"] }
```

Note: `qos-loaders` is included in the default feature set.

#### 9. Discovery Rejects Remote Participants

**Cause**: Security is enabled but remote participants either lack certificates or have certificates from a different CA.

**Fix**: Ensure all participants in the domain:
- Have certificates signed by the same CA
- Use the same `ca_certificates` file
- Have non-expired certificates

### Security Error Types

```rust
pub enum SecurityError {
    CertificateInvalid(String),   // Certificate validation failed
    CertificateExpired,           // Certificate past notAfter date
    CertificateRevoked,           // Certificate on CRL/OCSP revocation list
    AuthenticationFailed(String), // Handshake challenge/response failed
    PermissionsDenied(String),    // Access control denied the operation
    CryptoFailed(String),         // Encryption/decryption failed
    CryptoError(String),          // Cryptographic operation error
    ConfigError(String),          // Configuration error (missing files, bad XML)
}
```

### Diagnostic Logging

HDDS logs through the `log` facade, so the application has to install a logger
(for example `env_logger`). With `env_logger`, enable debug logging for the
`hdds` target to see security events:

```bash
RUST_LOG=hdds=debug cargo run
```

This will show:
- `[discovery] Security: Authenticated participant <GUID>` on successful auth (debug level)
- `[discovery] Security: Rejected participant <GUID> - <reason>` on auth failure (warn level)
- `[security] ...` lines for access-control refusals and withheld replays
