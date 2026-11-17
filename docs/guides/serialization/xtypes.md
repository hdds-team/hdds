# XTypes (Extensible Types)

XTypes enables type evolution and compatibility between different versions of data types.

## Overview

XTypes (DDS-XTypes v1.3) provides:
- **Type evolution** - Add/remove fields without breaking compatibility
- **Type compatibility** - Rules for matching different type versions
- **Dynamic types** - Runtime type description and encoding without compiled types
- **Type objects** - Machine-readable type descriptions

Types are written in IDL and compiled with `hddsgen` (see the
[IDL syntax](../../tools/hdds-gen/idl-syntax/basic-types.md) pages), or declared
in Rust with `#[derive(hdds::DDS)]`.

## Extensibility Kinds

A struct without an extensibility annotation is `@appendable`, the DDS-XTypes 1.3
default; `hddsgen` 2.0 and `#[derive(hdds::DDS)]` both follow it. Writer and reader
must use the same extensibility kind for their types to match.

### Final Types

Cannot be extended. Strictest compatibility.

```c
@final
struct SensorReading {
    uint32 sensor_id;
    float value;
};
```

- Readers and writers must have the same members, in the same order
- No delimiter or member headers on the wire: the smallest encoding

### Appendable Types (Default)

New fields can be added at the end.

```c
@appendable
struct SensorReading {
    uint32 sensor_id;
    float value;
    // Later versions append members here
};
```

- A reader of a newer version reads data from an older writer; the members
  the writer did not send take the zero value of their type
- A reader of an older version reads data from a newer writer and skips the
  members it does not know
- Under XCDR2 the body starts with a DHEADER (a 4-byte length); under XCDR1
  there is no delimiter

### Mutable Types

Fields can be added, removed, or reordered.

```c
@mutable
struct SensorReading {
    @id(1) uint32 sensor_id;
    @id(2) float value;
    @id(3) @optional string unit;
};
```

- Members are identified by id, not by position
- Under XCDR2 every member carries an EMHEADER (see [CDR2 Overview](cdr2-overview.md))
- Give every member an explicit `@id` so that its identity survives reordering and removal

## Member Annotations

### @id - Member Identity

```c
@mutable
struct Config {
    @id(1) uint32 version;
    @id(2) string name;
    @id(3) float threshold;  // Can reorder, ID preserved
};
```

### @optional - Optional Fields

```c
struct SensorData {
    uint32 sensor_id;
    float value;
    @optional float uncertainty;  // May be absent
    @optional string notes;
};
```

An `@optional` member is generated as `Option<T>` in Rust. Reading it:

```rust
if let Some(sample) = reader.take()? {
    if let Some(uncertainty) = sample.uncertainty {
        println!("Uncertainty: {}", uncertainty);
    }
}
```

### @default - Default Values

```c
struct Config {
    uint32 version;
    @default(100) uint32 timeout_ms;
    @default("unnamed") string name;
};
```

`hddsgen` accepts `@default(V)`. In the Rust output it is the value the
generated builder uses for a member that was not set. The decoder does not
apply it: a member missing from an older writer's sample decodes to the zero
value of its type (`0`, an empty string).

### @must_understand

Fields that receivers must support:

```c
@mutable
struct Command {
    @id(1) @must_understand uint32 command_id;
    @id(2) string parameters;
};
```

A writer type with a `@must_understand` member that the reader type does not
have is incompatible: the two endpoints do not match. The same holds for a
`@must_understand` member of the reader that the writer lacks.

## Type Evolution Examples

### Adding a Field (Appendable)

The type keeps its name; only its members change.

**Version 1:**
```c
@appendable
struct SensorReading {
    uint32 sensor_id;
    float value;
};
```

**Version 2:**
```c
@appendable
struct SensorReading {
    uint32 sensor_id;
    float value;
    uint64 timestamp;  // Added field
};
```

| Writer | Reader | Result |
|--------|--------|--------|
| V1 | V1 | Works |
| V2 | V2 | Works |
| V1 | V2 | Works (timestamp = 0) |
| V2 | V1 | Works (timestamp ignored) |

### Reordering Fields (Mutable)

**Version 1:**
```c
@mutable
struct Config {
    @id(1) string name;
    @id(2) uint32 value;
};
```

**Version 2:**
```c
@mutable
struct Config {
    @id(2) uint32 value;   // Reordered
    @id(1) string name;
    @id(3) float scale;    // Added
};
```

Fields are matched by `@id`, not position.

### Adding Optional Fields

```c
// Original
struct Robot {
    uint32 robot_id;
    float position_x;
    float position_y;
};

// Extended
struct Robot {
    uint32 robot_id;
    float position_x;
    float position_y;
    @optional float position_z;      // New
    @optional float orientation;     // New
};
```

## Type Compatibility

### Type Consistency Enforcement

The policy is a reader-side setting. It is the public field
`QoS::type_consistency`, an `Option<hdds::TypeConsistencyEnforcement>`; `None`
keeps the permissive default (`ALLOW_TYPE_COERCION`, sequence and string bounds
ignored).

```rust
use hdds::{QoS, TypeConsistencyEnforcement};

// Strict: no type coercion
let mut strict = QoS::reliable();
strict.type_consistency = Some(TypeConsistencyEnforcement {
    kind: 0, // DISALLOW_TYPE_COERCION
    ..Default::default()
});

// Allow coercion, match members by id only, widening allowed
let mut lenient = QoS::reliable();
lenient.type_consistency = Some(TypeConsistencyEnforcement {
    kind: 1, // ALLOW_TYPE_COERCION
    ignore_member_names: true,
    prevent_type_widening: false,
    ..Default::default()
});
```

The other fields are `ignore_sequence_bounds`, `ignore_string_bounds` and
`force_type_validation`.

### Compatibility Rules

Evaluated when two endpoints are discovered, from their TypeObjects:

- The two types must have the same extensibility kind.
- **Final:** same number of members, same member ids in the same order, each
  member type assignable.
- **Appendable and mutable:** members are matched by member id. A writer member
  the reader does not have is ignored. A reader member the writer does not have
  takes its zero value, unless it is `@must_understand` or the reader sets
  `prevent_type_widening`. At least one member id must be shared.
- A `@must_understand` writer member that the reader lacks makes the types
  incompatible.
- With `ALLOW_TYPE_COERCION` and `prevent_type_widening` unset, a primitive may
  widen within the signed integers, the unsigned integers or the floats
  (for example `int16` written, `int32` read).
- A member whose type changes in any other way is incompatible.

A pair with no DATA_REPRESENTATION in common, or one that negotiates XCDR1 for a
type that cannot encode it, is refused as an incompatible QoS (policy 23). A type
mismatch is reported as an inconsistent topic.

## Type Objects

XTypes uses TypeObjects for runtime type information. A type that implements
`hdds::DdsTrait` returns its own:

```rust
use hdds::xtypes::CompleteTypeObject;
use hdds::DdsTrait;

if let Some(CompleteTypeObject::Struct(s)) = SensorData::get_type_object() {
    println!("Type name: {}", s.header.detail.type_name);
    for member in &s.member_seq {
        println!("  {} (id={})", member.detail.name, member.common.member_id);
    }
}
```

### Type Identifier

On the wire a type is named by a `TypeIdentifier` (`hdds::xtypes::TypeIdentifier`):
a primitive or string kind directly, or a 14-byte `EquivalenceHash` of the
type's minimal or complete TypeObject. SEDP announces the identifiers of an
endpoint's type as `PID_TYPE_INFORMATION`. With the default
`xtypes-structural-assignability` feature, a participant that sees only an
identifier asks the peer for the complete TypeObject, so that assignability can
be evaluated.

### Type Discovery

Discover the topics and types of remote participants:

```rust
for topic in participant.discover_topics()? {
    println!("Topic: {} (type: {})", topic.name, topic.type_name);
    if let Some(CompleteTypeObject::Struct(s)) = &topic.type_object {
        println!("  {} members", s.member_seq.len());
    }
}
```

## Dynamic Types

`hdds::dynamic` describes and encodes types at runtime. It is a codec: a
`DynamicData` converts to and from CDR bytes.

```rust
use hdds::dynamic::{
    decode_dynamic_with_version, encode_dynamic_with_version, DynamicData, Extensibility,
    PrimitiveKind, TypeDescriptorBuilder,
};
use hdds::CdrVersion;
use std::sync::Arc;

// Build a type dynamically
let descriptor = Arc::new(
    TypeDescriptorBuilder::new("SensorData")
        .field("sensor_id", PrimitiveKind::U32)
        .field("value", PrimitiveKind::F32)
        .optional_field("timestamp", PrimitiveKind::U64)
        .build()
        .with_extensibility(Extensibility::Appendable),
);

// Create dynamic data
let mut data = DynamicData::new(&descriptor);
data.set("sensor_id", 42u32)?;
data.set("value", 23.5f32)?;

// Encode, then decode with the same descriptor
let bytes = encode_dynamic_with_version(&data, CdrVersion::Xcdr2)?;
let decoded = decode_dynamic_with_version(&bytes, &descriptor, CdrVersion::Xcdr2)?;
let value: f32 = decoded.get("value")?;
```

To publish or read such bytes on a topic without a compiled type, use the raw
endpoints (`Participant::create_raw_writer_with_type` and
`create_raw_reader_with_type`).

## IDL Annotations Summary

| Annotation | Applies To | Purpose |
|------------|------------|---------|
| `@final` | Struct | No extension allowed |
| `@appendable` | Struct | Add fields at end |
| `@mutable` | Struct | Full flexibility |
| `@id(N)` | Member | Stable member identity |
| `@optional` | Member | May be absent |
| `@default(V)` | Member | Value used by the generated builder (Rust) |
| `@must_understand` | Member | Required for receivers |
| `@key` | Member | Instance key |
| `@external` | Member | Separate allocation |

## Best Practices

1. **Start with @appendable** - Good balance of flexibility and encoding size
2. **Use @id on mutable types** - Enables safe reordering
3. **Append new members at the end of appendable types** - Older readers skip them
4. **Make members @optional when absence is meaningful** - A missing non-optional member decodes to zero
5. **Avoid @final unless needed** - Limits evolution

## Migration Strategy

### Phase 1: Plan

```c
// Add version field for explicit versioning
@appendable
struct SensorData {
    uint32 schema_version;  // Track schema changes
    uint32 sensor_id;
    float value;
};
```

### Phase 2: Add Fields

```c
// Append members at the end (older readers skip them)
@appendable
struct SensorData {
    uint32 schema_version;
    uint32 sensor_id;
    float value;
    @optional uint64 timestamp;  // New in v2
};
```

### Phase 3: Deprecate

```c
// Keep old members in place and say so in a comment
@appendable
struct SensorData {
    uint32 schema_version;
    uint32 sensor_id;      // Deprecated: use sensor_guid
    float value;
    @optional uint64 timestamp;
    @optional string sensor_guid;  // Replacement
};
```

## Troubleshooting

### Writer and Reader Do Not Match

- Check that both types use the same extensibility annotation
- Verify that `@id` values are consistent
- Check that the type names match (an endpoint that carries no TypeObject is
  judged by its type name)
- Check the reader's `type_consistency` policy
- Check that the DATA_REPRESENTATION lists overlap (see [CDR2 Overview](cdr2-overview.md))
- `participant.discover_endpoints()` lists what discovery has found

### Missing Optional Field

```rust
// Handle gracefully
let value = sample.optional_field.unwrap_or_default();
```

### Unknown Member ID

An appendable or mutable reader skips the members it does not know. When the
writer marks such a member `@must_understand`, the two endpoints do not match.

## Next Steps

- [CDR2 Overview](../../guides/serialization/cdr2-overview.md) - Wire format details
- [IDL Annotations](../../tools/hdds-gen/idl-syntax/annotations.md) - Complete annotation reference
