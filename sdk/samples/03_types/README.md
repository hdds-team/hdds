# 03_types - DDS Type System Samples

This directory contains samples demonstrating all DDS type system features with HDDS.
Each sample is implemented in C, C++, Python, and Rust.

## Samples Overview

| Sample | Description | Key Concepts |
|--------|-------------|--------------|
| primitives | All DDS primitive types | bool, char, integers, floats |
| strings | String type variations | bounded, unbounded, wstring |
| sequences | Variable-length collections | bounded, unbounded sequences |
| arrays | Fixed-size collections | 1D arrays, 2D matrices |
| maps | Key-value collections | string-int, int-string maps |
| enums | Enumeration types | simple enums, explicit values |
| unions | Discriminated unions | switch/case type selection |
| nested_structs | Composite types | structs containing structs |
| bitsets_bitmasks | Bit manipulation | flags, permissions, status |
| optional_fields | Optional members | presence flags, sparse data |

## Directory Structure

```
03_types/
├── idl/                    # IDL type definitions
│   ├── Primitives.idl
│   ├── Strings.idl
│   ├── Sequences.idl
│   ├── Arrays.idl
│   ├── Maps.idl
│   ├── Enums.idl
│   ├── Unions.idl
│   ├── Nested.idl
│   ├── Bits.idl
│   └── Optional.idl
├── c/                      # C implementations
│   ├── generated/          # Generated type headers
│   ├── CMakeLists.txt
│   ├── primitives.c
│   ├── strings.c
│   └── ...
├── cpp/                    # C++ implementations
│   ├── generated/          # Generated type headers
│   ├── CMakeLists.txt
│   ├── primitives.cpp
│   ├── strings.cpp
│   └── ...
├── python/                 # Python implementations
│   ├── generated/          # Generated type modules
│   ├── primitives.py
│   ├── strings.py
│   └── ...
└── rust/                   # Rust implementations
    ├── src/bin/            # Sample binaries
    ├── generated/          # Generated type modules
    └── Cargo.toml
```

## Building the Samples

### C

```bash
cd c
mkdir build && cd build
cmake ..
make
./primitives
./strings
# etc.
```

### C++

```bash
cd cpp
mkdir build && cd build
cmake ..
make
./primitives
./strings
# etc.
```

### Python

```bash
cd python
python3 primitives.py
python3 strings.py
# etc.
```

### Rust

```bash
cd rust
cargo run --bin primitives
cargo run --bin strings
# etc.
```

## Sample Details

### primitives

Demonstrates all DDS primitive types:
- Boolean (`bool`)
- Octet (`uint8`)
- Character (`char`)
- Integers: `int16`, `uint16`, `int32`, `uint32`, `int64`, `uint64`
- Floating point: `float32`, `float64`

### strings

Demonstrates string handling:
- Unbounded strings (variable length)
- Bounded strings (max length constraint)
- Wide strings (UTF-16/UTF-32 stored as UTF-8)

### sequences

Demonstrates sequence (dynamic array) types:
- `LongSeq` - unbounded sequence of int32
- `StringSeq` - unbounded sequence of strings
- `BoundedLongSeq` - bounded sequence with max 10 elements

### arrays

Demonstrates fixed-size array types:
- `LongArray` - 10-element int32 array
- `StringArray` - 5-element string array
- `Matrix` - 3x3 double matrix

### maps

Demonstrates map (dictionary) types:
- `StringLongMap` - string keys, int32 values
- `LongStringMap` - int32 keys, string values

### enums

Demonstrates enumeration types:
- `Color` - simple enum (RED, GREEN, BLUE)
- `Status` - enum with explicit values (UNKNOWN=0, PENDING=10, etc.)

### unions

Demonstrates discriminated union types:
- `DataValue` - union with INTEGER, FLOAT, or TEXT variants
- Discriminator-based type selection

### nested_structs

Demonstrates composite/nested types:
- `Point` - simple 2D coordinate
- `Pose` - position + orientation
- `Robot` - complex type with nested structs and sequences

### bitsets_bitmasks

Demonstrates bit manipulation types:
- `Permissions` - bitmask for READ/WRITE/EXECUTE/DELETE
- `StatusFlags` - bitset for ENABLED/VISIBLE/SELECTED/etc.

### optional_fields

Demonstrates optional (nullable) fields:
- Required fields (always present)
- Optional fields (may be absent)
- Presence flags for space efficiency

## CDR Serialization

All types use CDR (Common Data Representation) serialization format:
- Little-endian byte order
- 4-byte length prefix for variable-length data
- Null terminator for strings
- Alignment as per DDS specification

## Key Concepts

### Type Safety

Each language provides type-safe wrappers:
- Rust: Strong typing with `Result<T, E>` error handling
- C++: Classes with RAII and exceptions
- Python: Dataclasses with type hints
- C: Structs with explicit length fields

### Serialization Round-Trip

All samples demonstrate:
1. Creating a type instance
2. Serializing to bytes
3. Deserializing back
4. Verifying equality

### Edge Cases

Samples test:
- Empty collections
- Maximum values
- Unicode strings
- Zero values
- Bounds checking
