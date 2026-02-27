# IDL Annotations

HDDS supports **26 standard annotations** from IDL 4.2 plus custom annotation declarations.

## Key Annotations

### @key

Marks a field as part of the topic key for instance identification.

```idl
struct SensorReading {
    @key string sensor_id;    // Part of key
    @key uint32_t region;     // Part of key
    float temperature;        // Not part of key
    float humidity;
};
```

**Effect**: Key fields are used to compute instance identity via FNV-1a hash. Readers can filter by key values.

### @optional

Marks a field as optional (may be omitted during serialization).

```idl
struct UserProfile {
    @key uint32_t user_id;
    string username;
    @optional string nickname;      // Can be null
    @optional string avatar_url;    // Can be null
};
```

**Generated Rust**: Optional fields become `Option<T>` types.

### @id

Assigns an explicit member ID for serialization (PL_CDR2/XCDR2 encoding).

```idl
@mutable
struct Message {
    @id(1) int32_t id;
    @id(2) string content;
    @id(100) @optional string metadata;  // Sparse ID allowed
};
```

**Validation**: IDs must be unique within a struct.

## Extensibility Annotations

### @extensibility

Controls type evolution capabilities.

| Mode | Description |
|------|-------------|
| `FINAL` | No changes allowed after deployment |
| `APPENDABLE` | New fields can only be appended |
| `MUTABLE` | Fields can be added/removed freely |

```idl
@extensibility(MUTABLE)
struct Config {
    @id(1) int32_t version;
    @id(2) string name;
};
```

### Shorthand Forms

```idl
@final
struct Point { float x; float y; };

@appendable
struct Message { int32_t id; string text; };

@mutable
struct Config { int32_t version; };
```

## Numeric Constraints

### @min / @max

Declare value constraints for numeric fields.

```idl
struct Sensor {
    @min(0) @max(100) float percentage;
    @min(-40) @max(125) int8_t temperature_c;
};
```

### @range

Combined min/max constraint.

```idl
struct Battery {
    @range(min=0, max=100) uint8_t charge_level;
    @range(min=2.7, max=4.2) float voltage;
};
```

### @unit

Documents the unit of measurement.

```idl
struct Telemetry {
    @unit("meters/second") float velocity;
    @unit("milliseconds") uint32_t latency;
    @unit("celsius") float temperature;
};
```

## Serialization Annotations

### @data_representation

Selects the wire encoding format.

```idl
@data_representation(XCDR2)
struct ModernData {
    int32_t value;
};
```

| Format | Description |
|--------|-------------|
| `XCDR1` | Classic CDR encoding |
| `XCDR2` | Extended CDR2 (default for HDDS) |

### @non_serialized

Excludes a field from serialization.

```idl
struct CachedData {
    int32_t id;
    string value;
    @non_serialized int64_t cache_timestamp;  // Local only
};
```

### @must_understand

Indicates the field must be understood by receivers.

```idl
@mutable
struct Critical {
    @must_understand @id(1) int32_t critical_flag;
    @id(2) string optional_info;
};
```

## Bitset Annotations

### @bit_bound

Specifies maximum bit position for a bitset.

```idl
@bit_bound(32)
bitmask StatusFlags {
    @position(0) FLAG_ACTIVE,
    @position(1) FLAG_VALID,
    @position(7) FLAG_ERROR,
    @position(31) FLAG_CRITICAL
};
```

### @position

Assigns explicit bit position.

```idl
@bit_bound(16)
bitmask Permissions {
    @position(0) READ,
    @position(1) WRITE,
    @position(2) EXECUTE,
    @position(8) ADMIN
};
```

## Union Annotations

### @default

Marks the default union case.

```idl
union Value switch(int32_t) {
    case 1: int32_t int_val;
    case 2: float float_val;
    case 3: string string_val;
    @default: octet raw_data[64];
};
```

## Type Annotations

### @nested

Marks a type for nested composition.

```idl
@nested
struct Position {
    float x;
    float y;
    float z;
};

struct Entity {
    @key uint32_t id;
    Position pos;  // Nested struct
};
```

### @external

Indicates a type is defined externally.

```idl
struct Message {
    @key int32_t id;
    @external CustomType payload;  // Defined in C++ header
};
```

## Auto ID Generation

### @autoid

Controls automatic member ID generation.

```idl
@autoid(SEQUENTIAL)
struct OrderedData {
    @id(1) int32_t first;   // IDs must increase
    @id(2) int32_t second;
    @id(3) int32_t third;
};

@autoid(HASH)
struct HashedData {
    int32_t alpha;   // ID = hash("alpha") & 0x0FFFFFFF
    int32_t beta;    // ID = hash("beta") & 0x0FFFFFFF
};
```

| Mode | Description |
|------|-------------|
| `SEQUENTIAL` | IDs assigned 0, 1, 2... by field order |
| `HASH` | IDs computed via MD5 hash of field names (default) |

## Custom Annotations

### Declaration

```idl
@annotation MyAnnotation {
    int32_t priority;
    string category default "general";
};
```

### Usage

```idl
@MyAnnotation(priority=10, category="critical")
struct ImportantData {
    int32_t value;
};
```

**Validation**:
- Required parameters (no default) must be provided
- Parameters can be positional or named
- Duplicate parameters cause errors

## Annotation Location Rules

| Annotation | Type Level | Member Level |
|------------|------------|--------------|
| @key | - | ✓ |
| @optional | - | ✓ |
| @id | - | ✓ |
| @autoid | ✓ | - |
| @extensibility | ✓ | - |
| @final / @appendable / @mutable | ✓ | - |
| @min / @max / @range | - | ✓ |
| @unit | - | ✓ |
| @data_representation | ✓ | - |
| @non_serialized | - | ✓ |
| @must_understand | - | ✓ |
| @bit_bound | ✓ | - |
| @position | - | ✓ (bitset) |
| @default | - | ✓ (union) |
| @nested | ✓ | - |
| @external | ✓ | ✓ |

## Validation Rules

hdds_gen validates annotation usage:

- **Conflict detection**: Cannot combine `@final` + `@appendable` + `@mutable`
- **Duplicate IDs**: Error if `@id` value used twice in same struct
- **Range consistency**: Error if `@min` > `@max`
- **Type checking**: Warning if `@min`/`@max` on non-numeric field
- **Location checking**: Error if annotation used at wrong level

## Next Steps

- [Enums](../../../tools/hdds-gen/idl-syntax/enums.md) - Enumeration types
- [Sequences](../../../tools/hdds-gen/idl-syntax/sequences.md) - Variable-length collections
