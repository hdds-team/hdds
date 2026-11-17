# Access Control

HDDS implements fine-grained access control for topics and domains.

## Overview

Access control defines:
- Which domains the governance covers
- Which topics a participant can publish to
- Which topics a participant can subscribe to
- Which partitions are accessible

Access control needs **both** documents (`governance_xml` and `permissions_xml`),
signed by the Permissions CA (`permissions_ca`); see
[Signing the documents](#signing-the-documents).

## Configuration Files

### Governance

Domain-wide security policies:

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

All five elements are required. There is no default for a setting that decides
a protection, so a `<domain_rule>` that omits one is refused at load, naming the
missing element. This is the shorthand form: a domain-level
`<data_protection_kind>` stands for one `<topic_rule>` matching every topic,
with read and write access control on.

Per-topic rules are written as the specification writes them, in a
`<topic_access_rules>` block of `<topic_rule>` elements; each rule says whether
its topics are announced on the secure discovery topics and whether reading and
writing them is checked against the permissions document. A protection this
release does not apply (liveliness protection, submessage protection,
`SIGN`-only data protection) is refused at load rather than silently dropped --
an operator cannot tell a setting nobody read from a setting that did not
apply, and only one of those leaves them protected.

See [Governance XML](../../security-guide.md#governance-xml) for the full element
reference, including domain ranges.

### Permissions

Per-participant access rules:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<dds>
    <permissions>
        <grant name="SensorNode">
            <subject_name>CN=SensorNode1</subject_name>
            <validity>
                <not_before>2020-01-01T00:00:00</not_before>
                <not_after>2036-01-01T00:00:00</not_after>
            </validity>
            <deny_rule>
                <domains><id>0</id></domains>
                <publish>
                    <topics><topic>admin/*</topic></topics>
                </publish>
            </deny_rule>
            <allow_rule>
                <domains><id>0</id></domains>
                <publish>
                    <topics><topic>sensor/*</topic></topics>
                </publish>
                <subscribe>
                    <topics><topic>command/*</topic></topics>
                </subscribe>
            </allow_rule>
        </grant>
    </permissions>
</dds>
```

A participant is given the grants whose `subject_name` equals the **complete
subject** of its identity certificate (every attribute, in any order; no
wildcards) and whose `<validity>` window contains the current time. If no grant
qualifies, building the participant fails with `Error::Config`.

### Signing the documents

HDDS accepts governance and permissions only when they are signed by the
Permissions CA, a trust anchor distinct from the identity CA (`ca_certificates`).
A plain XML file is refused when the participant is built. Sign each document
as S/MIME and configure the signed files:

```bash
openssl smime -sign \
  -in permissions.xml \
  -signer permissions_ca.pem \
  -inkey permissions_ca_key.pem \
  -outform SMIME -text -md sha256 \
  -out permissions.p7s
```

Do the same for `governance.xml`, then pass `governance.p7s`, `permissions.p7s`
and `permissions_ca.pem` to the `SecurityConfig` builder (see
[Configuration in HDDS](#configuration-in-hdds)).

## Grant Structure

```xml
<grant name="GrantName">
    <!-- Full subject of the identity certificate -->
    <subject_name>CN=ParticipantName</subject_name>

    <!-- Validity period -->
    <validity>
        <not_before>2020-01-01T00:00:00</not_before>
        <not_after>2036-01-01T00:00:00</not_after>
    </validity>

    <!-- Allow and deny rules, evaluated in document order -->
    <allow_rule>...</allow_rule>
    <deny_rule>...</deny_rule>

    <!-- Optional, after every rule: ALLOW or DENY (default DENY) -->
    <default>DENY</default>
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
| `Secret*` | `Secret`, `SecretPlans` | `TopSecret` |
| `T?pic`, `T[0-9]` | `Topic`; `T7` | `Tpic`; `TA` |

Topic expressions are POSIX `fnmatch()` patterns (DDS-Security v1.1
9.4.1.3.2.3.1.3), as in the governance, matched as glibc's `fnmatch()`
matches them in the "C" locale, byte by byte: `*` crosses `/`, `?` is one
byte, `[...]` a set of bytes, POSIX classes such as `[[:upper:]]` included
(ASCII only). Outside ASCII a character is its UTF-8 bytes (`?` matches one
of them; glibc in a UTF-8 locale would match the whole character); on ASCII
names nothing differs. A bracket `fnmatch()` gives up on (an unknown class
such as `[[:uper:]]`, a collating symbol of more than one byte) and an
expression longer than 4096 bytes are refused when the document loads.

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

### Partitions and data tags

Each `<publish>` / `<subscribe>` is one criterion: its topic, partition and
data tag conditions must all match, and it is evaluated on its own
(DDS-Security v1.1 9.4.1.3.2.3.1.2).

```xml
<allow_rule>
    <domains><id>0</id></domains>
    <publish>
        <topics><topic>Square</topic></topics>
        <partitions><partition>A*</partition></partitions>
        <data_tags>
            <tag><name>level</name><value>public</value></tag>
        </data_tags>
    </publish>
</allow_rule>
```

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
  applies to this participant's document and to its peers'; deny rules read
  the same either way.
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

They apply when a local writer or reader is created and to a remote
participant's endpoints, on what each endpoint announced.

## Rule Precedence

1. **Rules apply in document order** - allow and deny alike, the first rule
   with a matching criterion decides (DDS-Security v1.1 9.4.1.3.2.3). Write a
   deny rule before the broader allow rule it carves out of
2. **`<default>`** - `ALLOW` or `DENY`, after every rule; if no rule matches,
   it decides, and without one access is denied

```xml
<!-- Carve admin/* out of the broad allow rule below -->
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
use hdds::security::SecurityConfig;

let security = SecurityConfig::builder()
    .identity_certificate("certs/participant.pem")
    .private_key("certs/participant_key.pem")
    .ca_certificates("certs/ca.pem")
    .governance_xml("governance.p7s")      // Signed domain rules
    .permissions_xml("permissions.p7s")    // Signed access control rules
    .permissions_ca("certs/permissions_ca.pem")
    .enable_encryption(true)               // Required by the ENCRYPT governance above
    .build()?;
```

`build()` fails when only one of the two documents is configured, or when a
document is set without `permissions_ca`. A governance rule that asks for
`ENCRYPT` data protection also needs `enable_encryption(true)`: without it,
creating a writer or reader of a topic that rule covers is refused instead of
letting its samples cross in clear.

## Access Check Points

HDDS checks permissions at these points:

| Operation | Check |
|-----------|-------|
| Build participant | A governance `<domain_rule>` covers the domain, and a grant is in force for the certificate subject |
| Create DataWriter | Publish permission for topic, partitions and data tags (refusal: `Error::PermissionDenied`) |
| Create DataReader | Subscribe permission for topic, partitions and data tags (refusal: `Error::PermissionDenied`) |
| Discover remote endpoint | The remote participant's own signed permissions document, presented in the handshake, must allow it |

## Example Configurations

A grant names one subject, so a fleet of participants needs one grant per
certificate subject.

### Sensor Node (Publish Only)

```xml
<grant name="SensorNode">
    <subject_name>CN=SensorNode1</subject_name>
    <validity>
        <not_before>2020-01-01T00:00:00</not_before>
        <not_after>2036-01-01T00:00:00</not_after>
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
```

### Monitor (Subscribe Only)

```xml
<grant name="Monitor">
    <subject_name>CN=Monitor1</subject_name>
    <validity>
        <not_before>2020-01-01T00:00:00</not_before>
        <not_after>2036-01-01T00:00:00</not_after>
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

## Errors

| Error | When | Cause |
|-------|------|-------|
| `Error::Config` from `SecurityConfig::build()` | Configuration | Only one of governance/permissions set, or no `permissions_ca` |
| `Error::Config` from `Participant::builder(..).build()` | Participant creation | A document is unsigned or not signed by the Permissions CA; a document does not parse, or asks for a protection that is not applied; no grant is in force for the certificate subject (wrong subject, or outside `<validity>`) |
| `Error::PermissionDenied` | Participant creation | No governance `<domain_rule>` covers the domain |
| `Error::PermissionDenied` | Writer or reader creation | A deny rule matched, or no rule matched and the default is DENY; the message names the rule |

## Audit Logging

Enable audit logging to track access decisions:

```rust
let security = SecurityConfig::builder()
    // ...
    .governance_xml("governance.p7s")
    .permissions_xml("permissions.p7s")
    .permissions_ca("certs/permissions_ca.pem")
    .enable_audit_log(true)
    .audit_log_path("/var/log/hdds/audit.log")
    .build()?;
```

Logged access-control events:
- Writer or reader creation allowed or denied (participant GUID, topic and partitions)
- A governance or permissions document accepted unsigned through `insecure_allow_unsigned_documents` (development only)

The file is a SHA-256 hash chain; see [Overview](../../guides/security/overview.md#security-plugins).
If the audit chain cannot record a decision, the endpoint is refused.

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
1. The full certificate subject equals the grant's subject_name
2. Topic pattern matches requested topic
3. Domain ID is in the rule, and a governance `<domain_rule>` covers it
4. Current time within validity period
5. Rule order: the first rule with a matching criterion decides

### Permissions File Not Loading

Validate XML syntax and the signature:
```bash
xmllint --noout permissions.xml
openssl smime -verify -in permissions.p7s -CAfile permissions_ca.pem -out /dev/null
```

## Next Steps

- [Encryption](../../guides/security/encryption.md) - Data protection
- [Authentication](../../guides/security/authentication.md) - Identity verification
