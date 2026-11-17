# IDL Annotations

`hddsgen` recognizes the annotations on this page, plus custom annotation
declarations. An annotation it does not know is kept, and `hddsgen check` reports
it as `unknown annotation` unless the file declares it. Each annotation is tagged
below with what the generated code does with it.

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

**Effect**: Key fields identify the instance. The generated code computes the
instance `KeyHash` as RTPS 2.5 Sec. 9.6.4.8 specifies: when the key's maximum
serialized size is at most 16 bytes, the hash is the serialized key, zero-extended
to 16 bytes; otherwise it is the MD5 (RFC 1321) of the serialized key. The choice
depends on the type, never on the value.

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

**Validation**: IDs must be unique within a struct. On the wire, the IDs matter
for `@mutable` types (each member is written with its ID); for `@final` and
`@appendable` types they only appear in the TypeObject. Without `@id` the IDs
follow `@autoid` (see below).

## Extensibility Annotations

### @extensibility

Controls type evolution capabilities. A struct, union, enum or bitmask without
one of these annotations is `APPENDABLE` (the DDS-XTypes 1.3 default); the
`--default-extensibility` option of `hddsgen gen` changes that default.

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

Declare value constraints for numeric fields. `hddsgen check` validates them
(numeric values, `@min` not above `@max`, bounds inside the field's type, a
warning on a non-numeric field); the generated code does not enforce them.

```idl
struct Sensor {
    @min(0) @max(100) float percentage;
    @min(-40) @max(125) int8_t temperature_c;
};
```

### @range

Combined min/max constraint, validated like `@min` / `@max` and not enforced by
the generated code.

```idl
struct Battery {
    @range(min=0, max=100) uint8_t charge_level;
    @range(min=2.7, max=4.2) float voltage;
};
```

### @unit

Documents the unit of measurement. It is validated (numeric field, one `@unit`
per field) and has no effect on the generated code.

```idl
struct Telemetry {
    @unit("meters/second") float velocity;
    @unit("milliseconds") uint32_t latency;
    @unit("celsius") float temperature;
};
```

## Serialization Annotations

### @data_representation

Selects the wire encoding format. It applies to a type, not to a member; a
`@mutable` type cannot be pinned to `XCDR1` (or `PLAIN_CDR`), which `hddsgen
check` refuses.

```idl
@data_representation(XCDR2)
struct ModernData {
    int32_t value;
};
```

| Format | Description |
|--------|-------------|
| `XCDR1` | Classic CDR encoding (`PLAIN_CDR` is accepted as a synonym) |
| `XCDR2` | Extended CDR2 (`PLAIN_CDR2` is accepted as a synonym) |

What a Rust DataWriter puts on the wire is its DATA_REPRESENTATION QoS: XCDR1
when it sets none, XCDR2 with `data_representation_xcdr2()`.

### @non_serialized

Excludes a member from serialization. The member stays in the generated struct
and takes its default value when a sample is decoded. It is an error on a type.

```idl
struct CachedData {
    int32_t id;
    string value;
    @non_serialized int64_t cache_timestamp;  // Local only
};
```

### @must_understand

Sets the `IS_MUST_UNDERSTAND` flag of the member in the type's TypeObject.

```idl
@mutable
struct Critical {
    @must_understand @id(1) int32_t critical_flag;
    @id(2) string optional_info;
};
```

## Bit Annotations

### @bit_bound

Specifies the number of bits of a bitmask, bitset or enum. For a bitmask or an
enum it also sets the width on the wire (1, 2, 4 or 8 bytes); `hddsgen check`
refuses a bitmask with more flags than `@bit_bound` allows.

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

## Default Annotations

### @default

`@default(value)` on a struct member sets the value the generated Rust builder
uses when the field was not set; the other backends ignore it.

```idl
struct Settings {
    @default(5000) int32_t timeout;
    @default("auto") string mode;
};
```

The default branch of a union is the `default:` label, not an annotation:

```idl
union Value switch(int32_t) {
    case 1: int32_t int_val;
    case 2: float float_val;
    case 3: string string_val;
    default: octet raw_data[64];
};
```

## Type Annotations

### @nested

Marks a type that is only used inside other types. The Rust backend does not
generate topic-type support (the `DDS` trait implementation) for a `@nested`
struct, and the TypeObject carries the nested flag.

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

Marks a member as stored by reference (DDS-XTypes `@external`).

```idl
struct CustomType {
    int32_t v;
};

struct Message {
    @key int32_t id;
    @external CustomType payload;
};
```

In the Rust output the member becomes `Box<CustomType>` (`Option<Box<T>>` with
`@optional`). The C, C++ and Python output generate an ordinary member.

## Auto ID Generation

### @autoid

Controls automatic member ID generation.

```idl
@autoid(SEQUENTIAL)
struct OrderedData {
    int32_t first;    // ID 0
    int32_t second;   // ID 1
    @id(10) int32_t third;   // explicit ID 10
    int32_t fourth;   // ID 11
};

@autoid(HASH)
struct HashedData {
    int32_t alpha;   // ID from the hash of "alpha"
    int32_t beta;    // ID from the hash of "beta"
};
```

| Mode | Description |
|------|-------------|
| `SEQUENTIAL` | The default: IDs are 0, 1, 2... by field order (the base type's members first); after an explicit `@id`, the next member takes that ID plus one |
| `HASH` | ID = the first four bytes of the MD5 of the member name, little endian, masked to 28 bits |

`@autoid` can also be put on a module. It applies to the types of the module that
do not carry their own.

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

## Annotation Location

Where each annotation is meant to be used. `hddsgen check` enforces only some
of these placements (see Validation Rules below); the others are accepted
anywhere.

| Annotation | Type Level | Member Level |
|------------|------------|--------------|
| @key | - | Yes |
| @optional | - | Yes |
| @id | - | Yes |
| @autoid | Yes | - |
| @extensibility | Yes | - |
| @final / @appendable / @mutable | Yes | - |
| @min / @max / @range | - | Yes |
| @unit | - | Yes |
| @data_representation | Yes | - |
| @non_serialized | - | Yes |
| @must_understand | - | Yes |
| @bit_bound | Yes | - |
| @position | - | Yes (bitmask flag) |
| @default | - | Yes |
| @nested | Yes | - |
| @external | Yes | Yes |

## Validation Rules

`hddsgen check` validates annotation usage (and `hddsgen gen` refuses the files
it reports as errors):

- **Conflict detection**: error on two different extensibility annotations on one type
- **Duplicate IDs**: error if an `@id` value is used twice in the same struct
- **Range consistency**: error if `@min` > `@max` (or `@range` has `min` > `max`)
- **Type checking**: warning if `@min`, `@max`, `@range` or `@unit` is on a non-numeric member
- **Location checking**: error for `@data_representation` on a member and for
  `@non_serialized` on a type
- **Data representation**: error for a value other than `XCDR1`, `XCDR2`,
  `PLAIN_CDR`, `PLAIN_CDR2`
- **Custom annotations**: error for missing, unknown or duplicate parameters;
  warning for an annotation with no declaration

`hddsgen check` exits non-zero on warnings too; `hddsgen gen` prints them and
carries on.

## Next Steps

- [Enums](../../../tools/hdds-gen/idl-syntax/enums.md) - Enumeration types
- [Sequences](../../../tools/hdds-gen/idl-syntax/sequences.md) - Variable-length collections
