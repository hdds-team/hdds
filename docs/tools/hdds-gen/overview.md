# hdds_gen Code Generator

**hdds_gen** (CLI: `hddsgen`) is an IDL 4.2 parser and code generator that produces type support code for multiple languages from a single IDL source.

## Features

- **IDL 4.2 parser** with `#include` preprocessing and semantic validation
- **7 target languages** - Rust, C++, C, Python, TypeScript, Micro (embedded Rust), C-Micro
- **CDR serialization** - Generated XCDR2 encode/decode code (the Rust, C, Python and TypeScript output also decodes XCDR1; the C++ output is XCDR2 only)
- **XTypes** - Generated code carries the type's extensibility and a `TypeObject` (Rust)
- **CI/CD ready** - `--json` diagnostics, and the same input produces the same output on every run

The generated C, C++, Python and TypeScript code is self-contained. Generated
Rust code uses the `hdds` crate (`hdds::Cdr2Encode`, `hdds::Cdr2Decode`) and
needs an `hdds` release that matches the generator: hddsgen 2.0 pairs with
HDDS 1.5.

## Quick Start

```bash
# Install (separate repository; see installation.md)
git clone https://git.hdds.io/hdds/hdds_gen.git && cargo install --path hdds_gen

# Generate Rust code
hddsgen gen rust MyTypes.idl -o my_types.rs

# Generate C++ with namespace
hddsgen gen cpp MyTypes.idl --namespace-cpp "MyApp::Types" -o my_types.hpp

# Generate a full example project (Cargo.toml, publisher, subscriber)
hddsgen gen rust MyTypes.idl --example --out-dir ./my_project
```

## Subcommands

| Command | Purpose |
|---------|---------|
| `gen` | Generate code in target language |
| `parse` | Parse IDL (syntax only); `--pretty` prints it back as IDL |
| `check` | Parse and run the semantic checks (CI-friendly) |
| `fmt` | Reformat IDL to canonical style |

## Target Languages

| Language | Output | Use Case |
|----------|--------|----------|
| `rust` | Rust structs with CDR2 codecs and builders | Native Rust DDS applications |
| `cpp` | C++ header (`.hpp`) | C++ DDS applications |
| `c` | Header-only C (C99 by default, C89 and C11 selectable) | Embedded systems, FFI |
| `python` | Dataclasses with CDR2 encode/decode | Scripting, prototyping |
| `typescript` | Interfaces with CDR2 encode/decode functions | TypeScript applications |
| `micro` | `no_std` Rust | Embedded Rust (ESP32, ARM) |
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

**Output: Rust** (excerpt; the file also holds the CDR2 codec, the type
object and a `TemperatureBuilder`)
```rust
pub mod sensors {
    #[derive(Debug, Clone, PartialEq)]
    pub struct Temperature {
        pub sensor_id: String,
        pub value: f32,
        pub timestamp: u64,
    }
    // ...
}
```

**Output: C** (excerpt)
```c
typedef struct sensors_Temperature {
    char* sensor_id;
    float value;
    uint64_t timestamp;
} sensors_Temperature ;

static inline int sensors_temperature_encode_cdr2_le(const sensors_Temperature* value, uint8_t* dst, size_t len);
static inline int sensors_temperature_decode_cdr2_le(sensors_Temperature* out, const uint8_t* src, size_t len);
```

`sensors_temperature_encode_cdr2_le` returns the number of bytes written, or a
negative value on error. A type that holds strings or sequences needs an
allocator to decode (`sensors_temperature_decode_cdr2_le_alloc`); the generated
header says so next to the plain `decode` function.

## Next Steps

- [Installation](../../tools/hdds-gen/installation.md) - Install hdds_gen
- [CLI Reference](../../tools/hdds-gen/cli-reference.md) - All command options
- [IDL Syntax](../../tools/hdds-gen/idl-syntax/basic-types.md) - Supported IDL features
