# DDS Security

HDDS implements the **OMG DDS Security v1.1** specification for secure publish-subscribe communication.

## Security Features

| Feature | Description | Status |
|---------|-------------|--------|
| Authentication | X.509 PKI with challenge-response | ✅ |
| Access Control | XML-based permissions | ✅ |
| Encryption | AES-256-GCM | ✅ |
| Key Exchange | ECDH P-256 with HKDF | ✅ |
| Audit Logging | Hash-chained event log | ✅ |

## Architecture

HDDS implements security through a `SecurityPluginSuite` that encapsulates the four DDS Security v1.1 plugins:

```
┌─────────────────────────────────────────────────────────────┐
│                     DomainParticipant                        │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────────┐│
│  │                  SecurityPluginSuite                     ││
│  │  ┌────────────────┐  ┌────────────────┐                 ││
│  │  │ Authentication │  │ AccessControl  │                 ││
│  │  │    Plugin      │  │    Plugin      │                 ││
│  │  │   (X.509)      │  │ (permissions)  │                 ││
│  │  └────────────────┘  └────────────────┘                 ││
│  │  ┌────────────────┐  ┌────────────────┐                 ││
│  │  │ Cryptographic  │  │    Logging     │                 ││
│  │  │    Plugin      │  │    Plugin      │                 ││
│  │  │ (AES-256-GCM)  │  │ (audit trail)  │                 ││
│  │  └────────────────┘  └────────────────┘                 ││
│  └─────────────────────────────────────────────────────────┘│
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────────┐│
│  │                    DiscoveryFsm                          ││
│  │    security_validator: Arc<dyn SecurityValidator>        ││
│  │    → validate_identity(guid, token) during SPDP          ││
│  └─────────────────────────────────────────────────────────┘│
├─────────────────────────────────────────────────────────────┤
│                      RTPS Protocol                           │
├─────────────────────────────────────────────────────────────┤
│                   Transport (UDP/TCP/SHM)                    │
└─────────────────────────────────────────────────────────────┘
```

### SecurityPluginSuite Components

```rust
pub struct SecurityPluginSuite {
    /// X.509 certificate-based authentication (required)
    pub authentication: Box<dyn AuthenticationPlugin>,

    /// XML-based permissions enforcement (optional)
    pub access_control: Option<AccessControlPlugin>,

    /// AES-256-GCM encryption with ECDH P-256 key exchange (optional)
    pub cryptographic: Option<CryptoPlugin>,

    /// Hash-chained audit log (optional)
    pub logging: Option<LoggingPlugin>,
}
```

## Quick Start

### 1. Generate Certificates

```bash
# Generate CA certificate
openssl req -x509 -nodes -days 365 \
  -newkey rsa:2048 \
  -keyout ca_key.pem \
  -out ca_cert.pem \
  -subj "/CN=HDDS CA"

# Generate participant certificate
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

### 2. Create Permissions File

```xml
<?xml version="1.0" encoding="UTF-8"?>
<permissions>
    <grant name="Participant1">
        <subject_name>CN=Participant1</subject_name>
        <validity>
            <not_before>2024-01-01T00:00:00</not_before>
            <not_after>2025-12-31T23:59:59</not_after>
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
```

### 3. Configure HDDS

```rust
use hdds::{Participant, TransportMode};
use hdds::security::SecurityConfig;

let security = SecurityConfig::builder()
    // Identity (required)
    .identity_certificate("participant_cert.pem")
    .private_key("participant_key.pem")
    .ca_certificates("ca_cert.pem")

    // Access control (required for permissions)
    .permissions_xml("permissions.xml")
    .governance_xml("governance.xml")  // Domain-wide security rules

    // Encryption
    .enable_encryption(true)

    // Audit logging
    .audit_log_path("/var/log/hdds/audit.log")

    .build()?;

let participant = Participant::builder("app")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .with_security(security)  // Enable security plugins
    .build()?;
```

### Security Integration

When security is enabled via `with_security()`, HDDS automatically:

1. **Writer/Reader creation**: Calls `AccessControlPlugin::check_create_writer()` and `check_create_reader()` before allowing endpoint creation
2. **Data transmission**: Calls `CryptoPlugin::encrypt_payload()` before sending via UDP
3. **Data reception**: Calls `CryptoPlugin::decrypt_payload()` on incoming data
4. **Audit logging**: Logs security events via `LoggingPlugin` when enabled

```rust
// Security checks are automatic - PermissionDenied error if access denied
let topic = participant.topic::<SensorData>("SensorTopic")?;

// This will fail with hdds::Error::PermissionDenied if not authorized
let writer = topic.writer().qos(QoS::reliable()).build()?;
```

## Security Plugins

### Authentication Plugin

PKI-DH authentication using X.509 certificates:

- **Certificate validation**: Chain verification to CA
- **Challenge-response**: 4-step handshake protocol
- **Algorithms**: RSA-2048/4096, ECDSA P-256

[Learn more →](../../guides/security/authentication.md)

### Access Control Plugin

Fine-grained permissions for participants and topics:

- **Governance**: Domain-wide security policies
- **Permissions**: Per-participant access rules
- **Wildcards**: Glob-style topic matching

[Learn more →](../../guides/security/access-control.md)

### Cryptographic Plugin

Data protection with authenticated encryption:

- **Algorithm**: AES-256-GCM
- **Key exchange**: ECDH P-256 with HKDF-SHA256
- **Nonce**: Unique 96-bit per message

[Learn more →](../../guides/security/encryption.md)

### Logging Plugin

Hash-chained audit trail for security events:

- **Events logged**: Authentication, authorization, key exchange, errors
- **Format**: JSON lines with SHA-256 chain
- **Tamper detection**: Hash chain verification

```rust
let security = SecurityConfig::builder()
    // ... other config ...
    .audit_log_path("/var/log/hdds/audit.log")
    .build()?;
```

Example log entry:
```json
{"ts":"2024-01-15T10:30:00Z","event":"AUTH_SUCCESS","guid":"01.0f.ab.cd...","prev_hash":"a1b2c3..."}
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

### Level 2: Full Encryption

Authenticate and encrypt all traffic:

```rust
let security = SecurityConfig::builder()
    .identity_certificate("cert.pem")
    .private_key("key.pem")
    .ca_certificates("ca.pem")
    .enable_encryption(true)   // Full encryption
    .enable_audit_log(true)    // Audit trail
    .build()?;
```

## Performance Impact

| Feature | Overhead |
|---------|----------|
| Authentication handshake | 10-50 ms per participant |
| Encryption (per message) | ~200 ns |
| Latency increase | ~80% |
| CPU usage | ~5% at 50K msg/s |

## Compliance

HDDS security implementation follows:

- **OMG DDS Security v1.1** (formal/18-04-01)
- **RFC 5280** - X.509 Certificate Profile
- **RFC 5869** - HKDF Key Derivation
- **NIST SP 800-38D** - GCM Specification
- **NIST FIPS 186-4** - ECDSA

## Next Steps

- [Authentication](../../guides/security/authentication.md) - Certificate-based identity
- [Access Control](../../guides/security/access-control.md) - Permission management
- [Encryption](../../guides/security/encryption.md) - Data protection
