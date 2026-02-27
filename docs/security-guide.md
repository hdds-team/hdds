# HDDS Security Guide

> DDS Security v1.1 implementation in HDDS -- authentication, access control, encryption, and audit logging.

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Authentication (X.509 PKI)](#authentication-x509-pki)
4. [Access Control](#access-control)
5. [Encryption (AES-256-GCM)](#encryption-aes-256-gcm)
6. [Key Exchange (ECDH P-256)](#key-exchange-ecdh-p-256)
7. [Session Key Management](#session-key-management)
8. [Certificate Setup](#certificate-setup)
9. [Configuration](#configuration)
10. [Governance XML](#governance-xml)
11. [Permissions XML](#permissions-xml)
12. [Audit Logging](#audit-logging)
13. [SecuredPayload Wire Format](#securedpayload-wire-format)
14. [Performance Considerations](#performance-considerations)
15. [Troubleshooting](#troubleshooting)

---

## Overview

HDDS implements the OMG DDS Security v1.1 specification (formal/18-04-01), providing:

- **Authentication** -- X.509 certificate-based participant identity verification
- **Access Control** -- Topic/partition authorization via Permissions XML with deny-by-default semantics
- **Encryption** -- AES-256-GCM authenticated encryption for RTPS submessage confidentiality and integrity
- **Audit Logging** -- ANSSI-compliant hash-chain audit trail for security events

### Security Model

Each DDS participant has a cryptographic identity:

- **Identity Certificate** -- X.509 PEM certificate signed by a trusted CA
- **Private Key** -- RSA or ECDSA private key for challenge-response handshake
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
      |--- ECDH Key Exchange (P-256) ---------->|
      |<-- Shared Secret ---------------------->|
      |                                         |
      |=== AES-256-GCM Encrypted Data =========>|
      |<=== AES-256-GCM Encrypted Data =========|
```

### Feature Gate

Security features are gated behind the `security` Cargo feature:

```toml
[dependencies]
hdds = { version = "1.0", features = ["security"] }
```

The `qos-loaders` feature (enabled by default) is also required for governance and permissions XML parsing.

---

## Architecture

HDDS security follows a plugin architecture with four main components:

```text
SecurityPluginSuite
+-- AuthenticationPlugin    (X.509 certificate validation)
+-- AccessControlPlugin     (Permissions XML enforcement)
+-- CryptographicPlugin     (AES-256-GCM encryption)
+-- LoggingPlugin           (Audit trail + ANSSI hash-chain)
```

### Plugin Lifecycle

1. `SecurityConfig::builder()` -- Configure security parameters
2. `SecurityPluginSuite::new(config)` -- Initialize all plugins
3. Attach to `Participant` during creation via `.security(config)`
4. Plugins are invoked automatically during discovery and data send/receive

### Module Layout

| Module | Purpose |
|--------|---------|
| `security/config.rs` | `SecurityConfig` builder |
| `security/mod.rs` | `SecurityPluginSuite`, `SecurityError` |
| `security/authentication.rs` | `AuthenticationPlugin` trait, handshake tokens |
| `security/authentication/x509/` | X.509 certificate validation |
| `security/access/mod.rs` | `AccessControlPlugin` |
| `security/access/permissions.rs` | Governance + Permissions XML parsing |
| `security/access/rules.rs` | Deny-by-default rules engine |
| `security/crypto/mod.rs` | `CryptoPlugin` (orchestrates encryption) |
| `security/crypto/aes_gcm.rs` | AES-256-GCM cipher |
| `security/crypto/key_exchange.rs` | ECDH P-256 key exchange |
| `security/crypto/session_keys.rs` | HKDF session key derivation |
| `security/crypto/transform.rs` | SecuredPayload wire format |
| `security/audit/mod.rs` | `LoggingPlugin` with hash-chain |

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
3. **KeyUsage** -- Certificate has digitalSignature extension
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

1. Check all `deny_rule` entries -- if ANY matches, return **DENIED**
2. Check all `allow_rule` entries -- if ANY matches, return **ALLOWED**
3. If no rules match, return **DENIED** (implicit deny)

This ensures security-by-default even with misconfigured permissions.

### AccessControlPlugin API

```rust
pub struct AccessControlPlugin {
    rules: RulesEngine,
}

impl AccessControlPlugin {
    /// Create from XML content strings
    pub fn from_xml(
        governance_xml: &str,
        permissions_xml: &str,
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

    /// Check if matching with remote writer is allowed
    pub fn check_remote_writer(&self, topic: &str) -> Result<(), SecurityError>;

    /// Check if matching with remote reader is allowed
    pub fn check_remote_reader(&self, topic: &str) -> Result<(), SecurityError>;
}
```

### Wildcard Pattern Matching

Topic names in permissions rules support glob-style wildcards:

| Pattern | Matches |
|---------|---------|
| `*` | Any topic |
| `sensor/*` | `sensor/temperature`, `sensor/pressure`, etc. |
| `*/temperature` | `sensor/temperature`, `hvac/temperature`, etc. |
| `*temp*` | Any topic containing "temp" |
| `sensor/temperature` | Exact match only |

---

## Encryption (AES-256-GCM)

### Overview

HDDS uses AES-256 in Galois/Counter Mode (GCM) for authenticated encryption of RTPS submessages. This provides both confidentiality (encryption) and integrity (authentication tag).

### Security Properties

- **Confidentiality**: AES-256 encryption (256-bit key)
- **Integrity**: GCM 128-bit authentication tag
- **Nonce**: 96-bit cryptographically random nonce (never reused)
- **Hardware Acceleration**: Uses AES-NI when available (via the `ring` crate)

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
    ) -> Result<Vec<u8>, SecurityError>;

    /// Decrypt ciphertext (verifies auth tag)
    pub fn decrypt(
        &self,
        ciphertext: &[u8],
        nonce: &[u8; 12],
    ) -> Result<Vec<u8>, SecurityError>;

    /// Generate cryptographically secure 96-bit nonce
    pub fn generate_nonce() -> [u8; 12];
}
```

### Usage Example

```rust
use hdds::security::crypto::AesGcmCipher;

let key = [0u8; 32]; // In practice, use a properly derived key
let cipher = AesGcmCipher::new(&key)?;
let nonce = AesGcmCipher::generate_nonce();

// Encrypt
let plaintext = b"secret DDS message";
let ciphertext = cipher.encrypt(plaintext, &nonce)?;
assert_eq!(ciphertext.len(), plaintext.len() + 16); // +16 for GCM auth tag

// Decrypt
let decrypted = cipher.decrypt(&ciphertext, &nonce)?;
assert_eq!(plaintext.as_ref(), decrypted.as_slice());
```

### Tamper Detection

If any byte of the ciphertext is modified, decryption fails with a `SecurityError::CryptoError`. The GCM authentication tag ensures both integrity and authenticity.

```rust
let mut tampered = ciphertext.clone();
tampered[5] ^= 0x01; // Flip one bit

// Decryption fails -- auth tag mismatch
assert!(cipher.decrypt(&tampered, &nonce).is_err());
```

---

## Key Exchange (ECDH P-256)

### Overview

HDDS uses Elliptic Curve Diffie-Hellman (ECDH) with the P-256 curve (NIST secp256r1) for secure session key establishment. Each session uses ephemeral keys, providing forward secrecy.

### Algorithm

1. Each participant generates an ephemeral P-256 keypair
2. Participants exchange public keys (via SPDP/SEDP discovery)
3. Each derives the shared secret: `agree(our_private, peer_public)`
4. Shared secret is passed through HKDF to derive the session encryption key

### EcdhKeyExchange API

```rust
pub struct EcdhKeyExchange;

impl EcdhKeyExchange {
    /// Generate ephemeral P-256 keypair
    /// Returns (public_key_bytes, private_key)
    pub fn generate_keypair() -> Result<(Vec<u8>, EphemeralPrivateKey), SecurityError>;

    /// Derive shared secret from our private key + peer's public key
    /// Returns 32-byte shared secret
    pub fn derive_shared_secret(
        private_key: EphemeralPrivateKey,
        peer_public: &[u8],
    ) -> Result<Vec<u8>, SecurityError>;

    /// Serialize public key for transmission
    pub fn serialize_public_key(public_key: &[u8]) -> Vec<u8>;

    /// Deserialize and validate public key
    pub fn deserialize_public_key(raw: &[u8]) -> Result<Vec<u8>, SecurityError>;
}
```

### Key Format

- Public key: 65 bytes (uncompressed P-256: `0x04 || X || Y`)
- Shared secret: 32 bytes

### CryptoPlugin Key Exchange Flow

The `CryptoPlugin` provides a higher-level API that combines ECDH + HKDF:

```rust
use hdds::security::crypto::CryptoPlugin;

let mut alice = CryptoPlugin::new();
let mut bob = CryptoPlugin::new();

// Step 1: Both parties generate ephemeral keypairs
let alice_pub = alice.initiate_key_exchange()?;   // 65-byte P-256 public key
let bob_pub = bob.initiate_key_exchange()?;

// Step 2: Exchange public keys (via discovery or out-of-band)
// Step 3: Both derive the same session key

let alice_key_id = alice.complete_key_exchange(&bob_pub)?;
let bob_key_id = bob.complete_key_exchange(&alice_pub)?;

// Both now have the same session key (verified by the HDDS test suite)
// Alice encrypts, Bob decrypts:
let encrypted = alice.encrypt_data(b"secret message", alice_key_id)?;
let decrypted = bob.decrypt_data(&encrypted, bob_key_id)?;
assert_eq!(b"secret message".as_ref(), decrypted.as_slice());
```

### Forward Secrecy

Each call to `initiate_key_exchange()` generates a new ephemeral keypair. Compromise of one session key does not reveal keys from other sessions.

---

## Session Key Management

### Overview

Session keys are derived from ECDH shared secrets using HKDF (HMAC-based Key Derivation Function) per RFC 5869.

### Key Derivation Flow

```text
ECDH shared secret (32 bytes)
  |
  v
HKDF-Extract (with salt)
  |
  v
Pseudorandom Key (PRK)
  |
  v
HKDF-Expand (with info: "DDS Security v1.1 Session Key")
  |
  v
Session Key (32 bytes for AES-256)
```

### SessionKeyManager API

```rust
pub struct SessionKeyManager {
    keys: HashMap<u64, [u8; 32]>,
    next_key_id: AtomicU64,
}

impl SessionKeyManager {
    /// Create new session key manager
    pub fn new() -> Self;

    /// Derive session key from ECDH shared secret via HKDF
    pub fn derive_session_key(
        shared_secret: &[u8],
        salt: &[u8],
        info: &[u8],
    ) -> Result<[u8; 32], SecurityError>;

    /// Store a session key, returns unique key ID
    pub fn store_session_key(&mut self, key: [u8; 32]) -> u64;

    /// Retrieve session key by ID
    pub fn get_session_key(&self, key_id: u64) -> Option<[u8; 32]>;

    /// Rotate session key (derive new key from existing)
    pub fn rotate_session_key(&mut self, old_key_id: u64) -> Result<u64, SecurityError>;

    /// Remove expired session keys
    pub fn remove_old_keys(&mut self, max_key_id: u64) -> usize;
}
```

### Key Rotation

Session keys should be rotated periodically to limit the impact of key compromise:

```rust
use hdds::security::crypto::SessionKeyManager;

let mut manager = SessionKeyManager::new();

// Initial key from ECDH
let initial_key = SessionKeyManager::derive_session_key(
    &shared_secret,
    b"session-salt",
    b"DDS Security v1.1 Session Key",
)?;
let key_id = manager.store_session_key(initial_key);

// Rotate after N messages or T time
let new_key_id = manager.rotate_session_key(key_id)?;

// Clean up old keys
manager.remove_old_keys(key_id);
```

Recommended rotation triggers:

- After 1 million encrypted messages
- After 24 hours
- On suspected compromise

---

## Certificate Setup

### Generating Test Certificates

HDDS includes a certificate generation script at `sdk/samples/05_security/certs/generate_certs.sh`:

```bash
#!/bin/bash
# Generate test certificates for HDDS Security

# 1. Generate Certificate Authority (CA)
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout ca_key.pem \
    -out ca_cert.pem \
    -subj "/C=US/O=HDDS/CN=HDDS-TestCA"

# 2. Generate Permissions CA (for signing permissions documents)
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout permissions_ca_key.pem \
    -out permissions_ca.pem \
    -subj "/C=US/O=HDDS/CN=HDDS-PermissionsCA"

# 3. Generate participant certificates (signed by CA)
for name in Participant1 Participant2 SensorNode; do
    # Generate private key and CSR
    openssl req -nodes -newkey rsa:2048 \
        -keyout ${name}_key.pem \
        -out ${name}_csr.pem \
        -subj "/C=US/O=HDDS/CN=$name"

    # Sign with CA
    openssl x509 -req -days 365 \
        -in ${name}_csr.pem \
        -CA ca_cert.pem \
        -CAkey ca_key.pem \
        -CAcreateserial \
        -out ${name}_cert.pem

    # Clean up CSR
    rm -f ${name}_csr.pem
done
```

Or run the script directly:

```bash
cd sdk/samples/05_security/certs
./generate_certs.sh
```

### Certificate Files

| File | Purpose |
|------|---------|
| `ca_cert.pem` | Certificate Authority root certificate (trust anchor) |
| `ca_key.pem` | CA private key (keep secure, used to sign participant certs) |
| `permissions_ca.pem` | Permissions CA (for signing permissions documents) |
| `Participant1_cert.pem` | Participant identity certificate (PEM) |
| `Participant1_key.pem` | Participant private key (PEM) |

### X.509 Subject Name Format

```text
CN=Participant1,O=HDDS,C=US
|              |         |
|              |         +-- Country
|              +-- Organization
+-- Common Name (participant identity)
```

The subject name in the certificate must match the `subject_name` field in the permissions XML grant.

### Production Recommendations

- Use a proper PKI infrastructure (not self-signed test certs)
- Use ECDSA P-256 keys for better performance (instead of RSA 2048)
- Set appropriate certificate validity periods (1-2 years typical)
- Implement certificate revocation via CRL or OCSP
- Store private keys in hardware security modules (HSM) for critical deployments

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

    // Optional: access control
    .governance_xml("governance.xml")
    .permissions_xml("permissions.xml")

    // Optional: encryption
    .enable_encryption(true)

    // Optional: audit logging
    .enable_audit_log(true)
    .audit_log_path("/var/log/hdds_audit.log")

    // Optional: authentication settings
    .require_authentication(true)           // default: true
    .check_certificate_revocation(false)    // default: false (performance)

    .build()?;
```

### Attaching Security to a Participant

```rust
use hdds::api::Participant;
use hdds::security::SecurityConfig;

let security = SecurityConfig::builder()
    .identity_certificate("certs/participant1.pem")
    .private_key("certs/participant1_key.pem")
    .ca_certificates("certs/ca.pem")
    .permissions_xml("permissions.xml")
    .enable_encryption(true)
    .enable_audit_log(true)
    .build()?;

let participant = Participant::builder("secure_app")
    .security(security)
    .build()?;
```

### SecurityConfig Fields

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `identity_certificate` | Yes | -- | X.509 PEM certificate path |
| `private_key` | Yes | -- | PEM private key path |
| `ca_certificates` | Yes | -- | CA PEM certificate(s) path |
| `governance_xml` | No | None | Governance XML path |
| `permissions_xml` | No | None | Permissions XML path (permissive if unset) |
| `enable_encryption` | No | `false` | Enable AES-256-GCM encryption |
| `enable_audit_log` | No | `false` | Enable security audit logging |
| `audit_log_path` | No | None | Audit log file path (in-memory if unset) |
| `require_authentication` | No | `true` | Require PKI auth for all participants |
| `check_certificate_revocation` | No | `false` | Validate via CRL/OCSP |

### Build Validation

The `build()` method validates:

1. All required fields are set (returns `Error::Config` if missing)
2. All certificate files exist on disk
3. Governance XML exists if specified
4. Permissions XML exists if specified

File format validation (PEM parsing, XML schema) is deferred to plugin initialization at runtime.

---

## Governance XML

Governance XML defines domain-wide security policies. It specifies which DDS domains require authentication and encryption.

### Format

```xml
<?xml version="1.0"?>
<governance>
  <domain_rule>
    <domains>0</domains>
    <allow_unauthenticated>false</allow_unauthenticated>
    <encrypt_discovery>true</encrypt_discovery>
    <encrypt_topics>true</encrypt_topics>
  </domain_rule>
</governance>
```

### Fields

| Element | Description |
|---------|-------------|
| `<domains>` | Domain ID this rule applies to |
| `<allow_unauthenticated>` | If `true`, unauthenticated participants can join (insecure) |
| `<encrypt_discovery>` | If `true`, SPDP/SEDP discovery traffic is encrypted |
| `<encrypt_topics>` | If `true`, user data topics are encrypted |

### Multiple Domain Rules

```xml
<governance>
  <domain_rule>
    <domains>0</domains>
    <allow_unauthenticated>false</allow_unauthenticated>
    <encrypt_discovery>true</encrypt_discovery>
    <encrypt_topics>true</encrypt_topics>
  </domain_rule>
  <domain_rule>
    <domains>1</domains>
    <allow_unauthenticated>true</allow_unauthenticated>
    <encrypt_discovery>false</encrypt_discovery>
    <encrypt_topics>false</encrypt_topics>
  </domain_rule>
</governance>
```

---

## Permissions XML

Permissions XML defines per-participant topic-level access control. Each `<grant>` element specifies what a participant (identified by certificate subject name) is allowed or denied to do.

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

    <!-- Deny rules (checked BEFORE allow rules) -->
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
| `<subject_name>` | X.509 subject name (must match certificate CN) |
| `<validity>` | Time window during which this grant is active |
| `<allow_rule>` | Topics/partitions this participant CAN access |
| `<deny_rule>` | Topics/partitions this participant CANNOT access (checked first) |

### Rule Fields

| Element | Description |
|---------|-------------|
| `<domains>` | Domain ID this rule applies to |
| `<publish><topics>` | Topic patterns the participant can publish to |
| `<subscribe><topics>` | Topic patterns the participant can subscribe to |
| `<partitions>` | Partition patterns (optional) |

### Rule Evaluation Order

1. **Deny rules checked first** -- deny takes precedence
2. **Allow rules checked second** -- if any allow rule matches, access is granted
3. **Default: DENIED** -- if no rules match, access is denied (zero trust)

### Example: Multi-Role Permissions

```xml
<?xml version="1.0"?>
<permissions>
  <!-- Sensor nodes: can publish sensor data, subscribe to commands -->
  <grant>
    <subject_name>CN=SensorNode</subject_name>
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
    <subject_name>CN=Controller</subject_name>
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
    <subject_name>CN=Admin</subject_name>
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

The `LoggingPlugin` provides an audit trail for security events. It implements ANSSI-compliant hash-chaining to detect log tampering.

### Security Event Types

```rust
pub enum SecurityEvent {
    Authentication {
        participant_guid: [u8; 16],
        outcome: AuthenticationOutcome,  // Success, Failed, Revoked
        timestamp: u64,
    },
    AccessControl {
        participant_guid: [u8; 16],
        action: String,                 // "create_writer", "create_reader"
        resource: String,               // topic name
        outcome: AccessOutcome,         // Allowed, Denied
        timestamp: u64,
    },
    Crypto {
        key_id: u64,
        operation: String,              // "encrypt", "decrypt", "key_rotation"
        outcome: CryptoOutcome,         // Success, Failed
        timestamp: u64,
    },
}
```

### Hash-Chain Integrity

Each log entry is hashed with the previous entry's hash, creating a chain:

```text
Entry 1: H1 = SHA-256(H0 || event_1)    (H0 = all zeros)
Entry 2: H2 = SHA-256(H1 || event_2)
Entry 3: H3 = SHA-256(H2 || event_3)
...
```

If any entry is modified or deleted, all subsequent hashes become invalid, making tampering detectable.

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

### Thread Safety

The `LoggingPlugin` is wrapped in a `Mutex` inside `SecurityPluginSuite` for thread-safe concurrent access. The convenience method `log_security_event()` handles locking automatically:

```rust
// Thread-safe logging via SecurityPluginSuite
suite.log_security_event(&event)?;
```

---

## SecuredPayload Wire Format

Encrypted RTPS submessages use the `SecuredPayload` format (RTPS v2.5 Section 9.6.2, submessage kind `0x30`):

### Wire Layout

```text
+-------------------+
| session_key_id    |  8 bytes (u64, little-endian)
+-------------------+
| nonce             | 12 bytes (AES-GCM IV)
+-------------------+
| ciphertext        |  N bytes (encrypted payload + 16-byte GCM auth tag)
+-------------------+
```

### SecuredPayload API

```rust
pub struct SecuredPayload {
    pub session_key_id: u64,
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

impl SecuredPayload {
    /// Encode to wire format
    pub fn encode(&self) -> Result<Vec<u8>, SecurityError>;

    /// Decode from wire format
    pub fn decode(bytes: &[u8]) -> Result<Self, SecurityError>;
}
```

### Size Overhead

- Fixed overhead: 20 bytes (8 key_id + 12 nonce)
- Authentication tag: 16 bytes (appended to ciphertext by AES-GCM)
- Total overhead per message: 36 bytes

---

## Performance Considerations

### Benchmark Guidelines

| Operation | Typical Latency | Notes |
|-----------|----------------|-------|
| Authentication handshake | 10-50 ms per participant | One-time, during discovery |
| AES-256-GCM encryption | ~200 ns per 1 KB | Hardware-accelerated via AES-NI |
| ECDH P-256 key generation | ~1 ms | Per session/key exchange |
| ECDH shared secret derivation | ~1 ms | Per session |
| HKDF key derivation | < 1 us | Negligible |
| Certificate revocation check | 50-200 ms | Network round-trip (CRL/OCSP) |

### Encryption Impact

- **Latency**: +200 ns per write (< 80% slowdown on typical messages)
- **CPU**: +5% at 50,000 messages/second
- **Bandwidth**: +36 bytes per message (SecuredPayload overhead)

### Optimization Tips

1. **Disable CRL/OCSP** (`check_certificate_revocation: false`) unless required -- saves 50-200 ms per participant
2. **Use ECDSA P-256** certificates instead of RSA 2048 for faster handshakes
3. **Batch small messages** to amortize encryption overhead
4. **Use partition-based access control** instead of per-topic encryption when confidentiality is not needed (use SIGN/GMAC for integrity only)

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
- Verify the `subject_name` matches the certificate CN exactly
- Verify the topic pattern in `<publish>` or `<subscribe>` matches your topic
- Verify the `<validity>` dates are current
- Remember: deny rules are checked BEFORE allow rules

#### 5. CryptoError: "Session key not found"

**Cause**: Using a key ID that does not exist or has been rotated away.

**Fix**: Ensure you are using the key ID returned by `complete_key_exchange()` or `generate_session_key()`. If you rotated keys, use the new key ID.

#### 6. CryptoError: "Authentication tag mismatch"

**Cause**: Data was tampered with in transit, or wrong key/nonce used for decryption.

**Fix**:
- Verify both parties derived the same session key (same ECDH public keys exchanged)
- Verify the nonce matches between encrypt and decrypt
- Check for network corruption or man-in-the-middle attack

#### 7. "Governance XML parsing requires 'qos-loaders' feature"

**Cause**: The `qos-loaders` Cargo feature is not enabled.

**Fix**: Add the feature to your `Cargo.toml`:

```toml
hdds = { version = "1.0", features = ["security", "qos-loaders"] }
```

Note: `qos-loaders` is included in the default feature set.

#### 8. Discovery Rejects Remote Participants

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

Enable debug logging to see security events:

```bash
RUST_LOG=hdds::security=debug cargo run
```

This will show:
- `[security] Authenticated participant <GUID>` on successful auth
- `[security] Rejected participant <GUID>: <reason>` on auth failure
