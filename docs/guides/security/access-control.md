# Access Control

HDDS implements fine-grained access control for topics and domains.

## Overview

Access control defines:
- Which participants can join which domains
- Which topics a participant can publish to
- Which topics a participant can subscribe to
- Which partitions are accessible

## Configuration Files

### Governance

Domain-wide security policies:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<governance>
    <domain_rule>
        <domains><id>0</id></domains>
        <allow_unauthenticated_participants>false</allow_unauthenticated_participants>
        <enable_discovery_protection>true</enable_discovery_protection>
        <enable_liveliness_protection>true</enable_liveliness_protection>
        <topic_rule>
            <topic_expression>*</topic_expression>
            <enable_encryption>true</enable_encryption>
        </topic_rule>
    </domain_rule>
</governance>
```

### Permissions

Per-participant access rules:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<permissions>
    <grant name="SensorNode">
        <subject_name>CN=SensorNode1</subject_name>
        <validity>
            <not_before>2024-01-01T00:00:00</not_before>
            <not_after>2025-12-31T23:59:59</not_after>
        </validity>
        <allow_rule>
            <domains><id>0</id></domains>
            <publish>
                <topics><topic>sensor/*</topic></topics>
            </publish>
            <subscribe>
                <topics><topic>command/*</topic></topics>
            </subscribe>
        </allow_rule>
        <deny_rule>
            <domains><id>0</id></domains>
            <publish>
                <topics><topic>admin/*</topic></topics>
            </publish>
        </deny_rule>
    </grant>
</permissions>
```

## Grant Structure

```xml
<grant name="GrantName">
    <!-- X.509 Common Name to match -->
    <subject_name>CN=ParticipantName</subject_name>

    <!-- Validity period -->
    <validity>
        <not_before>2024-01-01T00:00:00</not_before>
        <not_after>2025-12-31T23:59:59</not_after>
    </validity>

    <!-- Allow rules (evaluated first) -->
    <allow_rule>...</allow_rule>

    <!-- Deny rules (take precedence) -->
    <deny_rule>...</deny_rule>
</grant>
```

## Rule Matching

### Topic Wildcards

| Pattern | Matches | Does Not Match |
|---------|---------|----------------|
| `*` | Any topic | - |
| `sensor/*` | `sensor/temp`, `sensor/humidity` | `command/start` |
| `*/status` | `robot/status`, `sensor/status` | `robot/command` |
| `*temp*` | `temperature`, `sensor/temp` | `humidity` |

### Domain Matching

```xml
<!-- Single domain -->
<domains><id>0</id></domains>

<!-- Multiple domains -->
<domains>
    <id>0</id>
    <id>1</id>
    <id>2</id>
</domains>

<!-- Domain range -->
<domains>
    <id_range><min>0</min><max>10</max></id_range>
</domains>
```

### Partition Matching

```xml
<allow_rule>
    <domains><id>0</id></domains>
    <publish>
        <topics><topic>sensor/*</topic></topics>
        <partitions>
            <partition>production</partition>
            <partition>test</partition>
        </partitions>
    </publish>
</allow_rule>
```

## Rule Precedence

1. **Deny rules are checked first** - explicit deny always wins
2. **Allow rules are checked second** - must have explicit allow
3. **Default deny** - if no rule matches, access is denied

```xml
<!-- Deny admin topics to everyone except admin role -->
<deny_rule>
    <domains><id>0</id></domains>
    <publish>
        <topics><topic>admin/*</topic></topics>
    </publish>
</deny_rule>

<allow_rule>
    <domains><id>0</id></domains>
    <publish>
        <topics><topic>*</topic></topics>
    </publish>
</allow_rule>
```

## Configuration in HDDS

```rust
use hdds::{Participant, TransportMode};
use hdds::security::SecurityConfig;

let security = SecurityConfig::builder()
    .identity_certificate("certs/participant.pem")
    .private_key("certs/participant_key.pem")
    .ca_certificates("certs/ca.pem")
    .permissions_xml("permissions.xml")  // Access control rules
    .build()?;
```

## Access Check Points

HDDS checks permissions at these points:

| Operation | Check |
|-----------|-------|
| Join domain | Domain ID in grant |
| Create DataWriter | Publish permission for topic |
| Create DataReader | Subscribe permission for topic |
| Match remote writer | Subscribe permission |
| Match remote reader | Publish permission |

## Example Configurations

### Sensor Node (Publish Only)

```xml
<grant name="SensorNode">
    <subject_name>CN=Sensor*</subject_name>
    <validity>
        <not_before>2024-01-01T00:00:00</not_before>
        <not_after>2025-12-31T23:59:59</not_after>
    </validity>
    <allow_rule>
        <domains><id>0</id></domains>
        <publish>
            <topics><topic>sensor/*</topic></topics>
        </publish>
    </allow_rule>
</grant>
```

### Controller (Full Access)

```xml
<grant name="Controller">
    <subject_name>CN=MainController</subject_name>
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
```

### Monitor (Subscribe Only)

```xml
<grant name="Monitor">
    <subject_name>CN=Monitor*</subject_name>
    <validity>
        <not_before>2024-01-01T00:00:00</not_before>
        <not_after>2025-12-31T23:59:59</not_after>
    </validity>
    <allow_rule>
        <domains><id>0</id></domains>
        <subscribe>
            <topics><topic>*</topic></topics>
        </subscribe>
    </allow_rule>
    <deny_rule>
        <domains><id>0</id></domains>
        <publish>
            <topics><topic>*</topic></topics>
        </publish>
    </deny_rule>
</grant>
```

## Validation Errors

| Error | Cause | Resolution |
|-------|-------|------------|
| `PermissionsDenied` | No matching allow rule | Add allow rule for topic |
| `SubjectMismatch` | CN doesn't match grant | Check certificate subject |
| `ValidityExpired` | Grant validity expired | Update not_after date |
| `DomainNotAllowed` | Domain ID not in grant | Add domain to grant |

## Audit Logging

Enable audit logging to track access decisions:

```rust
let security = SecurityConfig::builder()
    // ...
    .permissions_xml("permissions.xml")
    .enable_audit_log(true)
    .build()?;
```

Logged events:
- Access granted (with topic/domain)
- Access denied (with reason)
- Permission file parse errors

## Best Practices

1. **Principle of least privilege**: Only grant what's needed
2. **Use wildcards carefully**: Be specific when possible
3. **Explicit deny for sensitive topics**: Even if not allowed elsewhere
4. **Short validity periods**: Rotate permissions regularly
5. **Audit logging**: Enable in production

## Troubleshooting

### Access Denied

```bash
# Enable access control debug logging
export RUST_LOG=hdds::security::access=debug
```

Check:
1. Certificate CN matches grant subject_name
2. Topic pattern matches requested topic
3. Domain ID is in grant
4. Current time within validity period

### Permissions File Not Loading

Validate XML syntax:
```bash
xmllint --noout permissions.xml
```

## Next Steps

- [Encryption](../../guides/security/encryption.md) - Data protection
- [Authentication](../../guides/security/authentication.md) - Identity verification
