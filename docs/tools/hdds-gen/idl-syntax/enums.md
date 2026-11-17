# Enumeration Types

Enumerations define a set of named constants with optional explicit values.

## Basic Enums

```idl
enum Color {
    RED,
    GREEN,
    BLUE
};
```

**Generated Rust** (excerpt, the file also holds the CDR2 codec): the
enumerators keep their IDL names, and the first one is the `Default`:
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u32)]
pub enum Color {
    #[default]
    RED = 0,
    GREEN = 1,
    BLUE = 2,
}
```

## Explicit Values

Assign specific ordinal values:

```idl
enum HttpStatus {
    OK = 200,
    CREATED = 201,
    BAD_REQUEST = 400,
    NOT_FOUND = 404,
    INTERNAL_ERROR = 500
};
```

Gaps between values are allowed. `hddsgen` does not check that the values are
unique: `hddsgen check` and `hddsgen gen` refuse two enumerators with the same value, whether
written or computed from the previous one, and exit 1.

## Mixed Values

Enumerators without a value are numbered 0, 1, 2... in declaration order:

```idl
enum Priority {
    LOW,           // 0
    NORMAL,        // 1
    HIGH = 10      // 10
};
```

:::warning
Give every enumerator an explicit value as soon as one has one. hddsgen 2.0.0
numbers an enumerator without a value that follows one with a value differently
depending on the backend: Rust, TypeScript and micro use its position in the
list, C, C++ and Python continue from the previous value. Two peers generated
from the same IDL in different languages would then disagree on the wire value.
:::

## Enums with Annotations

### Extensibility

```idl
@extensibility(APPENDABLE)
enum Status {
    UNKNOWN,
    PENDING,
    ACTIVE,
    COMPLETED
};
```

With `@appendable`, new values can be added in future versions without breaking compatibility.

### Default Value

In the Rust and Python output a member of enumeration type starts as the first
enumerator of the enumeration (the `Default` of the Rust enum).

## Bitmask Enums

For flag-style enumerations, use `bitmask`:

```idl
@bit_bound(16)
bitmask FilePermissions {
    @position(0) READ,
    @position(1) WRITE,
    @position(2) EXECUTE,
    @position(4) DELETE,
    @position(8) ADMIN
};
```

`@bit_bound` gives the width on the wire (1 to 8 bits: 1 byte, 9 to 16: 2 bytes,
17 to 32: 4 bytes, above: 8 bytes; 32 when omitted).

**Generated Rust**: an integer type alias and one constant per flag. The
constant name is the bitmask name in upper case, an underscore and the flag
name:
```rust
pub type FilePermissions = u64;
pub const FILEPERMISSIONS_READ: FilePermissions = 1u64 << 0;
pub const FILEPERMISSIONS_WRITE: FilePermissions = 1u64 << 1;
pub const FILEPERMISSIONS_EXECUTE: FilePermissions = 1u64 << 2;
pub const FILEPERMISSIONS_DELETE: FilePermissions = 1u64 << 4;
pub const FILEPERMISSIONS_ADMIN: FilePermissions = 1u64 << 8;
```

**Usage**:
```rust
let perms: FilePermissions = FILEPERMISSIONS_READ | FILEPERMISSIONS_WRITE;
assert!(perms & FILEPERMISSIONS_READ != 0);
```

C++ generates an `enum class` with `|`, `&`, `^` and `~` operators, and Python
a `FilePermissions(int)` subclass with the flags as class constants.

## Using Enums in Structs

```idl
enum SensorType {
    TEMPERATURE,
    HUMIDITY,
    PRESSURE,
    ACCELEROMETER
};

enum Unit {
    CELSIUS,
    FAHRENHEIT,
    KELVIN,
    PERCENT,
    PASCAL,
    G_FORCE
};

struct SensorReading {
    @key uint32_t sensor_id;
    SensorType type;
    Unit unit;
    float value;
    uint64_t timestamp;
};
```

## Scoped Enums

Enums inside modules are scoped:

```idl
module sensors {
    enum Type {
        ANALOG,
        DIGITAL,
        PWM
    };

    struct Config {
        Type sensor_type;
    };
};

// Usage from outside module:
// sensors::Type::ANALOG
```

## Wire Format

An enum is serialized as a 32-bit integer by default; `@bit_bound(n)` narrows it
to 1 byte (n up to 8) or 2 bytes (n up to 16). With the default width:

| Enum Value | Wire Bytes (LE) |
|------------|-----------------|
| 0 | `00 00 00 00` |
| 1 | `01 00 00 00` |
| 255 | `FF 00 00 00` |
| 65536 | `00 00 01 00` |

## Language Mappings

| IDL | Rust | C | C++ | Python |
|-----|------|---|-----|--------|
| `enum E { A, B }` | `enum E { A = 0, B = 1 }` | `typedef enum { E_A, E_B } E;` | `enum class E { A, B };` | `class E(IntEnum): A = 0; B = 1` |
| Value access | `E::A` | `E_A` | `E::A` | `E.A` |

TypeScript generates `export enum E { A = 0, B = 1 }`.

## Validation Rules

`hddsgen check` and `hddsgen gen` report:

- **Duplicate names**: error if the same enumerator name is used twice
- **Empty enum**: error if an enum declares no enumerator
- **Reserved keywords**: an IDL keyword is not accepted as an enumerator name (parse error)
- **Annotation placement**: `@external` and `@non_serialized` are errors on an enum

## Best Practices

1. **Use meaningful names**: `ACTIVE` not `A`
2. **Reserve value 0**: For "unknown" or "default" state
3. **Use explicit values** for protocol enums (stable across versions)
4. **Use @appendable** if enum may grow
5. **Document meaning** with comments

```idl
// Sensor operational state
@appendable
enum SensorState {
    UNKNOWN = 0,      // Initial/invalid state
    INITIALIZING = 1, // Starting up
    READY = 2,        // Operational
    ERROR = 3,        // Recoverable error
    FAULT = 4         // Non-recoverable fault
};
```

## Next Steps

- [Sequences](../../../tools/hdds-gen/idl-syntax/sequences.md) - Variable-length arrays
- [Annotations](../../../tools/hdds-gen/idl-syntax/annotations.md) - Metadata annotations
