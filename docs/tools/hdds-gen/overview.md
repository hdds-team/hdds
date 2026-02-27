# hdds_gen Code Generator

**hdds_gen** (CLI: `idl-gen`) is a high-performance IDL 4.2 code generator that produces type support code for multiple languages from a single IDL source.

## Features

- **Full IDL 4.2 compliance** - 100% support for basic types, templates, constructs
- **6 target languages** - Rust, C++, C, Python, Micro (embedded Rust), C-Micro
- **Zero dependencies** - Generated code is self-contained
- **CDR2 serialization** - Automatic encode/decode implementation
- **XTypes support** - Type evolution and compatibility
- **CI/CD ready** - JSON diagnostics, deterministic output

## Quick Start

```bash
# Install
cargo install hdds-gen

# Generate Rust code
idl-gen gen rust MyTypes.idl -o my_types.rs

# Generate C++ with namespace
idl-gen gen cpp MyTypes.idl --namespace-cpp "MyApp::Types" -o my_types.hpp

# Generate full example project
idl-gen gen rust MyTypes.idl --example --out-dir ./my_project
```

## Subcommands

| Command | Purpose |
|---------|---------|
| `gen` | Generate code in target language |
| `parse` | Validate IDL and pretty-print AST |
| `check` | Validate with structural checks (CI-friendly) |
| `fmt` | Reformat IDL to canonical style |

## Target Languages

| Language | Output | Use Case |
|----------|--------|----------|
| `rust` | Idiomatic Rust with derives | Native Rust DDS applications |
| `cpp` | Modern C++ headers (.hpp) | C++ DDS applications |
| `c` | Header-only C99 | Embedded systems, FFI |
| `python` | Dataclasses with type hints | Scripting, prototyping |
| `micro` | no_std Rust | Embedded Rust (ESP32, ARM) |
| `c-micro` | Header-only MCU C | STM32, AVR, PIC, ESP32 |

## Example

**Input: Temperature.idl**
```idl
module sensors {
    @topic
    struct Temperature {
        @key string sensor_id;
        float value;
        unsigned long long timestamp;
    };
};
```

**Output: Rust**
```rust
#[derive(Debug, Clone, Serialize, Deserialize, Topic)]
pub struct Temperature {
    #[key]
    pub sensor_id: String,
    pub value: f32,
    pub timestamp: u64,
}
```

**Output: C**
```c
typedef struct {
    char* sensor_id;
    float value;
    uint64_t timestamp;
} sensors_Temperature;

int32_t sensors_Temperature_encode(const sensors_Temperature* p, uint8_t* buf, uint32_t len);
int32_t sensors_Temperature_decode(sensors_Temperature* p, const uint8_t* buf, uint32_t len);
```

## Next Steps

- [Installation](../../tools/hdds-gen/installation.md) - Install hdds_gen
- [CLI Reference](../../tools/hdds-gen/cli-reference.md) - All command options
- [IDL Syntax](../../tools/hdds-gen/idl-syntax/basic-types.md) - Supported IDL features
