# XTypes (Extensible Types)

XTypes enables type evolution and compatibility between different versions of data types.

## Overview

XTypes (DDS-XTypes v1.3) provides:
- **Type evolution** - Add/remove fields without breaking compatibility
- **Type compatibility** - Rules for matching different type versions
- **Dynamic types** - Runtime type discovery and introspection
- **Type objects** - Machine-readable type descriptions

## Extensibility Kinds

### Final Types

Cannot be extended. Strictest compatibility.

```c
@final
struct SensorReading {
    uint32 sensor_id;
    float value;
};
```

- Readers and writers must have identical types
- Smallest wire size
- Best performance

### Appendable Types (Default)

New fields can be added at the end.

```c
@appendable
struct SensorReading {
    uint32 sensor_id;
    float value;
    // Future: can add fields here
};
```

- New readers can read old data (new fields get defaults)
- Old readers can read new data (ignore extra fields)
- Moderate wire overhead (DHEADER)

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

- Maximum flexibility
- Higher wire overhead (EMHEADER per member)
- Requires `@id` annotations

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

Reading optional fields:

```rust
let sample = reader.take_one()?;
if let Some(uncertainty) = sample.uncertainty {
    println!("Uncertainty: {}", uncertainty);
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

### @must_understand

Fields that receivers must support:

```c
@mutable
struct Command {
    @id(1) @must_understand uint32 command_id;
    @id(2) string parameters;
};
```

Readers that don't recognize `@must_understand` fields reject the sample.

## Type Evolution Examples

### Adding a Field (Appendable)

**Version 1:**
```c
@appendable
struct SensorV1 {
    uint32 sensor_id;
    float value;
};
```

**Version 2:**
```c
@appendable
struct SensorV2 {
    uint32 sensor_id;
    float value;
    uint64 timestamp;  // Added field
};
```

| Writer | Reader | Result |
|--------|--------|--------|
| V1 | V1 | Works |
| V2 | V2 | Works |
| V1 | V2 | Works (timestamp = default) |
| V2 | V1 | Works (timestamp ignored) |

### Reordering Fields (Mutable)

**Version 1:**
```c
@mutable
struct ConfigV1 {
    @id(1) string name;
    @id(2) uint32 value;
};
```

**Version 2:**
```c
@mutable
struct ConfigV2 {
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

```rust
use hdds::QoS;

// Strict: types must be identical
let qos = QoS::reliable().type_consistency(TypeConsistency::DisallowTypeCoercion);

// Allow compatible types (default)
let qos = QoS::reliable().type_consistency(TypeConsistency::AllowTypeCoercion);

// Ignore member names, match by structure
let qos = QoS::reliable().type_consistency(TypeConsistency::IgnoreMemberNames);
```

### Compatibility Rules

**Always Compatible:**
- Same type definition
- Appendable types with added trailing fields (if optional/default)

**Compatible with AllowTypeCoercion:**
- Mutable types with different field order
- Types with optional fields added/removed
- Widening conversions (int16 -> int32)

**Never Compatible:**
- Final types with any difference
- Changed field types (incompatible)
- Required field removed

## Type Objects

XTypes uses TypeObjects for runtime type information:

```rust
// Get type object for a registered type
let type_object = participant.get_type_object::<SensorData>()?;

println!("Type name: {}", type_object.name());
println!("Extensibility: {:?}", type_object.extensibility());

for member in type_object.members() {
    println!("  {} (id={}): {:?}",
        member.name(),
        member.id(),
        member.type_kind()
    );
}
```

### Type Identifier

Types are identified by hash:

```rust
let type_id = TypeIdentifier::from_type::<SensorData>();
println!("Type ID: {:?}", type_id);  // 14-byte hash
```

### Type Discovery

Discover types from remote participants:

```rust
for topic in participant.discovered_topics() {
    if let Some(type_info) = topic.type_info {
        println!("Topic: {}", topic.name);
        println!("  Type: {}", type_info.type_name);
        println!("  Type ID: {:?}", type_info.type_id);
    }
}
```

## Dynamic Types

Create types at runtime:

```rust
use hdds::dynamic::*;

// Build type dynamically
let sensor_type = DynamicTypeBuilder::new("SensorData")
    .extensibility(Extensibility::Appendable)
    .add_member("sensor_id", TypeKind::UInt32)
    .add_member("value", TypeKind::Float32)
    .add_optional_member("timestamp", TypeKind::UInt64)
    .build()?;

// Create dynamic data
let mut data = DynamicData::new(&sensor_type);
data.set_u32("sensor_id", 42)?;
data.set_f32("value", 23.5)?;

// Write dynamic data
let writer = publisher.create_dynamic_writer("SensorTopic", &sensor_type)?;
writer.write(&data)?;
```

## IDL Annotations Summary

| Annotation | Applies To | Purpose |
|------------|------------|---------|
| `@final` | Struct | No extension allowed |
| `@appendable` | Struct | Add fields at end |
| `@mutable` | Struct | Full flexibility |
| `@id(N)` | Member | Stable member identity |
| `@optional` | Member | May be absent |
| `@default(V)` | Member | Default value |
| `@must_understand` | Member | Required for receivers |
| `@key` | Member | Instance key |
| `@external` | Member | Separate allocation |

## Best Practices

1. **Start with @appendable** - Good balance of flexibility and efficiency
2. **Use @id on mutable types** - Enables safe reordering
3. **Make new fields @optional** - Backward compatible
4. **Use @default for required fields** - Forward compatible
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
// Add optional fields (backward compatible)
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
// Mark old fields (still present for compatibility)
@appendable
struct SensorData {
    uint32 schema_version;
    @deprecated uint32 sensor_id;  // Use sensor_guid instead
    float value;
    @optional uint64 timestamp;
    @optional string sensor_guid;  // Replacement
};
```

## Troubleshooting

### Type Mismatch Error

```
Error: TypeConsistency check failed
```

- Check extensibility annotations match
- Verify @id values are consistent
- Check type names match exactly

### Missing Optional Field

```rust
// Handle gracefully
let value = sample.optional_field.unwrap_or_default();
```

### Unknown Member ID

For mutable types with unknown members:

```rust
use hdds::QoS;

let qos = QoS::reliable()
    .type_consistency(TypeConsistency::AllowTypeCoercion)
    .ignore_unknown_members(true);
```

## Next Steps

- [CDR2 Overview](../../guides/serialization/cdr2-overview.md) - Wire format details
- [IDL Annotations](../../tools/hdds-gen/idl-syntax/annotations.md) - Complete annotation reference
