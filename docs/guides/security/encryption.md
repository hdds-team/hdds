# Encryption

HDDS protects user-data payloads with **AES-256-GCM** authenticated encryption.

> **Read [Scope and Limits](#scope-and-limits) before relying on this.** The
> payload framing follows DDS-Security v1.1, but full cross-vendor security
> interoperability (authentication, discovery, tokens) is unverified.

## Overview

Encryption protects:
- **Confidentiality**: the serialized sample body cannot be read by parties
  without the writer's data key
- **Integrity**: any modification of the sealed payload fails the GCM tag

Note what is deliberately absent from that list: origin authentication. See
[Scope and Limits](#scope-and-limits).

## Algorithm Details

| Property | Value | Source |
|----------|-------|--------|
| Cipher | AES-256-GCM | `security/crypto/secure_submessage.rs` |
| Key Size | 256 bits (32 bytes) | per-writer master key; the per-session key is derived from it |
| IV Size | 96 bits (12 bytes): session id (4) + iv suffix (8) | fresh per sample |
| Auth Tag | 128 bits (16 bytes) | `ring` AEAD |
| AAD | none (empty) | the header fields select the key and IV |
| Hardware Accel | AES-NI (when available) | via `ring` |

## Configuration

```rust
use hdds::{Participant, TransportMode};
use hdds::security::SecurityConfig;

let security = SecurityConfig::builder()
    .identity_certificate("cert.pem")
    .private_key("key.pem")
    .ca_certificates("ca.pem")
    .enable_encryption(true)   // arms the sealed data plane
    .build()?;

let participant = Participant::builder("app")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .with_security(security)
    .build()?;
```

`enable_encryption(true)` is **fail closed**: a writer that cannot seal a
sample returns `Error::EncryptionUnavailable` instead of emitting cleartext.
That includes local deliveries that have no cipher: a write whose only readers
are in the same process (no remote peer has matched), and a write on a writer
with no transport. An encrypting writer refuses those paths rather than
bypassing the seal.

## Key Hierarchy

Three different keys, derived at three different moments. Confusing them is
the most common way to misread this subsystem.

**1. MasterSharedSecret (per peer pair, control plane).**
The PKI-DH handshake runs ECDH and both sides derive the same secret.

| Suite | kagree_algo | Curve | Secret | Derivation |
|-------|-------------|-------|--------|------------|
| Default | `ECDH+prime256v1-CEUM` | P-256 | 32 bytes | HKDF-SHA256 |
| Opt-in | `ECDH+secp384r1-CEUM` | P-384 | 48 bytes | HKDF-SHA384 |

The suite is **policy, not negotiation**: a participant refuses a peer that
advertises a suite differing from its own configured one, rather than
downgrading to it. An unknown or unimplemented suite string is refused
locally, before any packet leaves. `ECDH+secp384r1-CEUM` is an HDDS extension
(DDS-Security v1.1 defines only P-256 and finite-field DH), so P-384 is
HDDS<->HDDS only. The handshake signature does not depend on the suite: ECDSA with SHA-256 for an EC P-256 identity, RSASSA-PSS with SHA-256 for an RSA identity.

**2. Per-peer bootstrap material (control plane).**
The authenticated SharedSecret and both handshake challenges derive the peer's
KxKeys for `ParticipantVolatileMessageSecure` (DDS-Security 1.1 Table 67).
That protected channel carries the CryptoTokens used to install endpoint
master key material. See [Session Key Management](../../security-guide.md#session-key-management)
for the control-plane derivation and exchange.

**3. Per-writer data key (data plane).**
Each encrypting DataWriter mints its own 256-bit master key and master salt
at build time, with a writer-chosen four-octet random key id. It is stored in the process `DataKeyStore` keyed
by `(writer GUID, key id)` -- never by key id alone, because ids carry no
global-uniqueness contract and two writers colliding on one must not
overwrite each other. The key is announced to each authenticated peer over
the SecureVolatile channel as DatawriterCryptoTokens, protected with that
peer's KxKeys.

A reader that has not yet received a writer's key **drops the sample without
crediting its sequence number**, so the sample is redelivered by the normal
reliability machinery once the key arrives. Startup races converge instead of
losing data.

## What Gets Encrypted

| Data | Encrypted | Notes |
|------|-----------|-------|
| User data payload | yes | complete SerializedPayload, including CDR encapsulation and declared padding |
| Lifecycle DATA (dispose / unregister) | yes | complete serialized key payload, authenticated before resolving the instance |
| History cache contents | yes | sealed bytes are what is stored, so replay and repair carry ciphertext |
| RTPS metadata | separate protection | payload encryption alone leaves DATA metadata visible; secure builtin channels use submessage protection |
| Inline QoS metadata (`PID_KEY_HASH`, `PID_TOPIC_NAME`, `PID_STATUS_INFO`) | no | routing and instance bookkeeping read it in cleartext |
| Encapsulation header | yes | inside CryptoContent, recovered after authentication |
| Discovery (SPDP) | no | required before any handshake exists |
| Discovery (SEDP) | per governance | with a governance document, as `discovery_protection_kind` and each topic's `enable_discovery_protection` say (secure discovery topics, SIGN or ENCRYPT); without one, announced encrypted to authenticated participants |

## Wire Format

DDS-Security 1.1 9.5.3.3.4.1-4 replaces the complete SerializedPayload:

```text
CryptoHeader:  kind[4], sender_key_id[4], session_id[4], iv_suffix[8]
CryptoContent: u32 BE length N, N ciphertext octets
CryptoFooter:  common_mac[16], alignment to 4, u32 BE receiver MAC count = 0
```

The MAC follows the ciphertext immediately; only the count that follows it
needs alignment. There is no clear CDR encapsulation in front of these
elements. For aligned SerializedPayloads, ENCRYPT adds 44 octets. SIGN uses
an unchanged aligned SerializedPayload instead of CryptoContent and adds 40.
Local governance still refuses SIGN at load; the GMAC codec is available
independently of that configuration guard.

The SessionKey is HMAC-SHA256 of `"SessionKey" | master_salt | session_id`
under the announced master sender key. GCM uses empty AAD and an IV made of
`session_id | iv_suffix`. Header, length and footer fields use big endian.
The original CDR representation and padding are recovered after authentication.

The reader chooses protection from the writer's announced endpoint security
attributes, never from a content prefix. Missing attributes or key material
under security leave the sample unacknowledged for reliable repair. The key
lookup remains `(writer GUID, sender_key_id)`. For ENCRYPT, inline PID_KEY_HASH
is an MD5 digest of the CDR big-endian key fields even for a short key.

See the [complete wire format](../../security-guide.md#protected-serializedpayload-wire-format)
for layout and input requirements.

## Scope and Limits

Read these before treating "encryption enabled" as a security posture.

- **Full cross-vendor security interoperability is unverified.** Payload
  protection uses the DDS-Security format; a complete interoperable deployment
  also depends on authentication, discovery, tokens and configuration.
- **No origin authentication.** The GCM tag proves the sender held the
  writer's data key, but every authorized reader of that topic holds the same
  key. Any of them can forge a sample that verifies. Per-sender origin
  authentication requires separate origin-authenticating protection.
- **No automatic master-key rotation.** Session keys advance at the session
  block bound without a new token exchange. Replacing master tokens retires
  the old material; retained old ciphertext is not automatically re-encrypted.
- **No anti-replay on the data plane.** A captured sealed sample replayed
  later still decrypts. (The *handshake* does carry replay protection: a
  1024-entry window of recently seen `challenge1` nonces rejects repeats.
  That is the control plane only.)
- **Metadata is cleartext.** Topic name, key hash and status info travel in
  the clear. An observer learns which instance of which topic changed, and
  when, without opening a single payload.
- **Local deliveries without a cipher are refused.** An encrypting writer
  whose only readers are in the same process, or that has no transport,
  refuses the write instead of delivering cleartext.
- **Governance can ask for more than HDDS applies.** `SIGN`-only data
  protection, metadata protection, liveliness protection and whole-message
  RTPS protection are refused when the governance document is loaded; see the
  [Security Guide](../../security-guide.md#governance-xml).

## Nonce Management

Each sample uses `session_id | iv_suffix` as its 96-bit IV. The process-wide
suffix counter starts at a random value and takes a new value per operation.
The session id advances before an operation would exceed the session block
bound, deriving a new SessionKey from the same announced master material.

## Hardware Acceleration

HDDS uses the `ring` crate, which selects:
- **x86_64**: AES-NI instructions
- **ARM**: ARMv8 Crypto extensions
- **Fallback**: software implementation

Check hardware support:
```bash
# x86_64
grep -o aes /proc/cpuinfo | head -1
# Output: aes (if supported)

# ARM
grep Features /proc/cpuinfo | grep -o aes
```

## Performance

**Not measured.** There is no committed reference-grade encryption
performance benchmark, so this page states no latency, throughput or CPU
figures. What can be said from the design alone: ENCRYPT adds 44 bytes to an
aligned SerializedPayload and performs an AES-GCM transformation over the
complete payload. Runtime cost still needs measurement.

To measure it on your own hardware, run the same publisher twice -- once with
`enable_encryption(false)`, once with `true` -- and compare. Do not apply a
generic overhead to a deployment: compare secured and unsecured runs with the
same operation, payload, QoS, topology, source revision, build flags, and
machine configuration.

## Audit Logging

```rust
let security = SecurityConfig::builder()
    // ...
    .enable_encryption(true)
    .enable_audit_log(true)
    .build()?;
```

Records written to the audit chain by the runtime:

- **Authentication**: the outcome of each handshake (success, failed, revoked), with the peer GUID
- **Access control**: each `create_writer` / `create_reader` decision (allowed or denied) with participant GUID, topic and partitions
- **Crypto**: installation of data-plane and builtin keys, a failed open of a key announcement, a refused revocation list

Sample payload encryption and decryption are not audited per sample: there
is no per-operation or per-decryption-failure record. Do not build monitoring
on events this subsystem does not produce. If the chain loses a record, no new
handshake, key or endpoint is accepted until the participant is rebuilt. See
the [Overview](../../guides/security/overview.md#security-plugins) for the file
format and `hdds::security::audit::verify_chain`.

## Troubleshooting

### Samples never arrive on an encrypting pair

A reader that cannot open a sample drops it without crediting its sequence
number. While the writer's key announcement has not arrived the drop raises no error
and the reliability machinery redelivers the sample once the key is installed.
A payload that fails to open (key material that does not match, or tampering) is logged by the reader:

```
protected payload from writer=... failed to open: ...
```

If samples never arrive, the writer's key announcement is not reaching this
reader: check that the pair authenticated at all (the volatile channel only
carries keys between authenticated peers).

### The writer errors instead of sending

`Error::EncryptionUnavailable` is the fail-closed path: the writer had no way
to seal, so it refused rather than emitting cleartext. Typical causes are a
write that would be delivered only locally (readers in the same process and no
remote peer, or a writer with no transport) and a writer that holds no
data-plane key.

```bash
export RUST_LOG=hdds::security=debug
```

(This needs an `env_logger`-style logger installed by your application.)

### Decryption fails on a pair that used to work

- Key mismatch: confirm both sides completed the handshake, and that neither
  restarted (a restarted writer mints a new key with a new id).
- Corrupted ciphertext: a GCM tag failure is indistinguishable from tampering
  by design; check the transport first.

## Best Practices

1. **Pair encryption with authentication.** Encryption without an
   authenticated peer set gives you confidentiality against outsiders only,
   and the key-distribution channel needs authentication anyway.
2. **Protect private keys** at rest and restrict file permissions.
3. **Do not treat the GCM tag as proof of sender identity** -- see
   [Scope and Limits](#scope-and-limits).
4. **Size messages with the 44-byte overhead in mind**; it is per sample, so
   very small samples pay proportionally more.

## Next Steps

- [Access Control](../../guides/security/access-control.md) - Topic-level permissions
- [Authentication](../../guides/security/authentication.md) - Identity verification
