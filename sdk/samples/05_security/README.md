# 05 - Security Samples

This directory contains samples demonstrating DDS Security features for authentication, access control, and encryption.

## Overview

DDS Security provides comprehensive protection for distributed systems:
- **Authentication**: Verify participant identity using X.509 certificates
- **Access Control**: Define permissions for topics, domains, and partitions
- **Cryptography**: Encrypt data with AES-GCM, authenticate with GMAC

## Samples

| Sample | Description |
|--------|-------------|
| **authentication** | PKI-based participant authentication with X.509 certificates |
| **access_control** | Governance and permissions for topic-level access control |
| **encryption** | Data encryption (AES-GCM) and message authentication (GMAC) |
| **secure_discovery** | Authenticated SPDP/SEDP discovery protocol |

## Sample Descriptions

### authentication

Demonstrates PKI-based identity verification:

- X.509 certificate chain validation
- CA trust configuration
- Mutual authentication between participants
- Certificate-based identity

**Files needed:**
```
certs/
├── ca_cert.pem           # Certificate Authority
├── Participant1_cert.pem # Participant certificate
├── Participant1_key.pem  # Participant private key
```

**Usage:**
```bash
# Terminal 1
./authentication Participant1

# Terminal 2
./authentication Participant2
```

### access_control

Shows how to configure topic-level permissions:

- Governance document (domain-level policies)
- Permissions document (per-participant rules)
- Allow/deny rules for publish/subscribe
- Partition access control

**Key documents:**
- `governance.xml`: Domain security policies
- `permissions.xml`: Participant access rights (signed)

**Permission types:**
- Publish: Create DataWriters on topics
- Subscribe: Create DataReaders on topics
- Relay: Forward data (for routing)

### encryption

Demonstrates cryptographic protection levels:

- **AES-128/256-GCM**: Authenticated encryption
- **GMAC**: Message authentication (integrity only)
- **Protection kinds**: None, Sign, Encrypt, Sign+Encrypt

**Protection levels:**
| Level | Confidentiality | Integrity | Overhead |
|-------|-----------------|-----------|----------|
| NONE | No | No | 0 bytes |
| SIGN (GMAC) | No | Yes | 16 bytes |
| ENCRYPT (GCM) | Yes | Yes | 16 bytes |
| SIGN+ENCRYPT | Yes | Yes | 32 bytes |

### secure_discovery

Shows authenticated participant discovery:

- Secure SPDP (participant discovery)
- Secure SEDP (endpoint discovery)
- Rejection of unauthenticated participants
- Protected liveliness assertions

**Benefits:**
- Prevents rogue participant injection
- Encrypts discovery metadata
- Validates all participant announcements

## DDS Security Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Application Layer                         │
├─────────────────────────────────────────────────────────────┤
│                      DDS Layer                               │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │
│  │ DataWriter  │  │ DataReader  │  │  Discovery  │          │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘          │
├─────────┴────────────────┴────────────────┴─────────────────┤
│                   Security Plugins                           │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │
│  │Authentication│  │Access Control│  │Cryptography │          │
│  │   Plugin    │  │   Plugin    │  │   Plugin    │          │
│  └─────────────┘  └─────────────┘  └─────────────┘          │
├─────────────────────────────────────────────────────────────┤
│                    Transport Layer                           │
│              (UDP/TCP with TLS optional)                     │
└─────────────────────────────────────────────────────────────┘
```

## Certificate Setup

### Generate Test Certificates

Create a `generate_certs.sh` script:

```bash
#!/bin/bash
CERTS_DIR="./certs"
mkdir -p $CERTS_DIR

# Generate CA
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout $CERTS_DIR/ca_key.pem \
    -out $CERTS_DIR/ca_cert.pem \
    -subj "/C=US/O=HDDS/CN=HDDS-CA"

# Generate participant certificates
for name in Participant1 Participant2 SensorNode SecureDiscovery; do
    openssl req -nodes -newkey rsa:2048 \
        -keyout $CERTS_DIR/${name}_key.pem \
        -out $CERTS_DIR/${name}_csr.pem \
        -subj "/C=US/O=HDDS/CN=$name"

    openssl x509 -req -days 365 \
        -in $CERTS_DIR/${name}_csr.pem \
        -CA $CERTS_DIR/ca_cert.pem \
        -CAkey $CERTS_DIR/ca_key.pem \
        -CAcreateserial \
        -out $CERTS_DIR/${name}_cert.pem

    rm $CERTS_DIR/${name}_csr.pem
done

echo "Certificates generated in $CERTS_DIR"
```

### Governance Document Example

```xml
<?xml version="1.0" encoding="UTF-8"?>
<dds xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <domain_access_rules>
    <domain_rule>
      <domains><id>0</id></domains>
      <allow_unauthenticated_participants>false</allow_unauthenticated_participants>
      <enable_join_access_control>true</enable_join_access_control>
      <discovery_protection_kind>ENCRYPT</discovery_protection_kind>
      <liveliness_protection_kind>SIGN</liveliness_protection_kind>
      <topic_access_rules>
        <topic_rule>
          <topic_expression>*</topic_expression>
          <enable_discovery_protection>true</enable_discovery_protection>
          <enable_read_access_control>true</enable_read_access_control>
          <enable_write_access_control>true</enable_write_access_control>
          <data_protection_kind>ENCRYPT</data_protection_kind>
        </topic_rule>
      </topic_access_rules>
    </domain_rule>
  </domain_access_rules>
</dds>
```

### Permissions Document Example

```xml
<?xml version="1.0" encoding="UTF-8"?>
<dds xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <permissions>
    <grant name="SensorNodeGrant">
      <subject_name>CN=SensorNode,O=HDDS,C=US</subject_name>
      <validity>
        <not_before>2024-01-01T00:00:00</not_before>
        <not_after>2025-12-31T23:59:59</not_after>
      </validity>
      <allow_rule>
        <domains><id>0</id></domains>
        <publish>
          <topics><topic>SensorData</topic></topics>
        </publish>
        <subscribe>
          <topics><topic>*</topic></topics>
        </subscribe>
      </allow_rule>
      <deny_rule>
        <domains><id>0</id></domains>
        <publish>
          <topics><topic>RestrictedTopic</topic></topics>
        </publish>
      </deny_rule>
      <default>DENY</default>
    </grant>
  </permissions>
</dds>
```

## Building

### C
```bash
cd c
mkdir build && cd build
cmake ..
make
```

### C++
```bash
cd cpp
mkdir build && cd build
cmake ..
make
```

### Rust
```bash
cd rust
cargo build --release
```

### Python
```bash
cd python
python authentication.py
```

## Security Best Practices

1. **Certificate Management**
   - Use a proper PKI infrastructure in production
   - Rotate certificates before expiration
   - Secure private keys (HSM for production)
   - Use certificate revocation lists (CRL)

2. **Access Control**
   - Follow principle of least privilege
   - Use specific topic patterns, avoid `*` wildcards
   - Sign permissions documents
   - Audit permission changes

3. **Encryption**
   - Use ENCRYPT for sensitive data
   - Use SIGN for non-confidential but integrity-critical data
   - Consider performance impact of encryption
   - Enable hardware acceleration (AES-NI)

4. **Network Security**
   - Use secure discovery in untrusted networks
   - Consider TLS for transport layer
   - Firewall DDS ports appropriately
   - Monitor for authentication failures

## Troubleshooting

### Authentication Failures
1. Verify certificate chain is complete
2. Check certificate validity dates
3. Ensure CA certificate is trusted
4. Verify subject names match permissions

### Access Denied
1. Check permissions document is signed
2. Verify subject name in permissions matches certificate
3. Check topic patterns in allow/deny rules
4. Ensure domain ID is permitted

### Encryption Errors
1. Verify crypto plugin is properly configured
2. Check for key exchange failures in logs
3. Ensure both endpoints use compatible protection kinds
4. Verify hardware crypto support if using acceleration
