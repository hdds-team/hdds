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

**Generated Rust**:
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Color {
    Red = 0,
    Green = 1,
    Blue = 2,
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

**Rules**:
- Values must be unique within the enum
- Values must be valid `uint32` (0 to 2^32-1)
- Gaps between values are allowed

## Mixed Values

Combine automatic and explicit values:

```idl
enum Priority {
    LOW,           // 0 (auto)
    NORMAL,        // 1 (auto)
    HIGH = 10,     // 10 (explicit)
    CRITICAL       // 11 (auto, continues from previous)
};
```

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

### Default Values

Use in struct fields with default:

```idl
enum LogLevel {
    DEBUG,
    INFO,
    WARN,
    ERROR
};

struct LogConfig {
    LogLevel level default INFO;
    boolean enabled default TRUE;
};
```

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

**Generated Rust**:
```rust
bitflags::bitflags! {
    #[derive(Debug, Clone, Copy)]
    pub struct FilePermissions: u16 {
        const READ    = 1 << 0;
        const WRITE   = 1 << 1;
        const EXECUTE = 1 << 2;
        const DELETE  = 1 << 4;
        const ADMIN   = 1 << 8;
    }
}
```

**Usage**:
```rust
let perms = FilePermissions::READ | FilePermissions::WRITE;
assert!(perms.contains(FilePermissions::READ));
```

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

Enums are serialized as 32-bit unsigned integers (CDR specification):

| Enum Value | Wire Bytes (LE) |
|------------|-----------------|
| 0 | `00 00 00 00` |
| 1 | `01 00 00 00` |
| 255 | `FF 00 00 00` |
| 65536 | `00 00 01 00` |

## Language Mappings

| IDL | Rust | C | C++ | Python |
|-----|------|---|-----|--------|
| `enum E { A, B }` | `enum E { A=0, B=1 }` | `typedef enum { A=0, B=1 } E;` | `enum class E { A=0, B=1 };` | `class E(Enum): A=0; B=1` |
| Value access | `E::A` | `A` | `E::A` | `E.A` |
| Underlying type | `u32` | `uint32_t` | `uint32_t` | `int` |

## Validation Rules

hdds_gen validates:

- **Duplicate names**: Error if same name used twice
- **Duplicate values**: Error if same ordinal assigned twice
- **Value overflow**: Error if value > 2^32-1
- **Reserved keywords**: Error if name is IDL reserved word

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
