# CDR2 Serialization

HDDS uses CDR2 (Common Data Representation version 2) for serializing data, ensuring interoperability with all DDS implementations.

## Overview

CDR2 is the standard serialization format for DDS/RTPS, providing:
- **Binary encoding** - Compact and fast
- **Platform independence** - Cross-architecture compatibility
- **Type safety** - Preserves IDL type information
- **Interoperability** - Works with all DDS vendors

## Encoding Formats

HDDS supports multiple CDR encodings:

| Format | ID | Description |
|--------|-----|-------------|
| CDR1 (Plain) | 0x0000 | Original CDR, big-endian default |
| CDR2 (Plain) | 0x0001 | Little-endian default |
| PL_CDR1 | 0x0002 | Parameter list, mutable types |
| PL_CDR2 | 0x0003 | Parameter list, little-endian |
| XCDR2 | 0x0006 | Extended CDR2 for XTypes |
| D_CDR2 | 0x0007 | Delimited CDR2 |

Default: **XCDR2** (0x0006)

## Wire Format

### Encapsulation Header

Every serialized payload starts with a 4-byte header:

```
Byte 0-1: Encapsulation ID (e.g., 0x0006 for XCDR2)
Byte 2:   Options (flags)
Byte 3:   Reserved (0x00)
```

```rust
// Encapsulation header structure
struct EncapsulationHeader {
    id: u16,      // Format identifier
    options: u8,  // Bit 0: endianness (0=BE, 1=LE)
    reserved: u8, // Always 0
}
```

### Primitive Types

| IDL Type | Wire Size | Alignment |
|----------|-----------|-----------|
| boolean | 1 byte | 1 |
| octet/int8/uint8 | 1 byte | 1 |
| int16/uint16 | 2 bytes | 2 |
| int32/uint32 | 4 bytes | 4 |
| int64/uint64 | 8 bytes | 8 |
| float | 4 bytes | 4 |
| double | 8 bytes | 8 |
| char | 1 byte | 1 |
| wchar | 2 bytes | 2 |

### Alignment Rules

Data is aligned to natural boundaries:

```
Offset:  0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
        ┌──┬──┬──┬──┬──────────┬──────────────────────┐
        │u8│  │u16 │   u32    │        u64           │
        └──┴──┴──┴──┴──────────┴──────────────────────┘
             ↑  ↑        ↑              ↑
          pad(1) align(2) align(4)    align(8)
```

### String Encoding

```
┌────────────┬────────────────────────────┐
│ Length (4) │ UTF-8 data + NUL terminator│
└────────────┴────────────────────────────┘
```

Example: "Hello" (5 chars)
```
00 00 00 06   48 65 6C 6C 6F 00
└─ length ─┘  └─ "Hello\0" ───┘
```

### Sequence Encoding

```
┌────────────┬──────────────────────────────┐
│ Count (4)  │ Elements (each aligned)      │
└────────────┴──────────────────────────────┘
```

Example: `sequence<uint32>` with [1, 2, 3]
```
00 00 00 03   00 00 00 01   00 00 00 02   00 00 00 03
└─ count ─┘   └── 1 ────┘   └── 2 ────┘   └── 3 ────┘
```

### Array Encoding

Fixed-size arrays have no length prefix:

```c
float values[4];  // IDL

// Wire format: 16 bytes (4 x float32)
00 00 80 3F   00 00 00 40   00 00 40 40   00 00 80 40
└── 1.0 ──┘   └── 2.0 ──┘   └── 3.0 ──┘   └── 4.0 ──┘
```

### Struct Encoding

Members are serialized in declaration order with alignment:

```c
struct SensorData {
    uint32 sensor_id;   // Offset 0, align 4
    float temperature;  // Offset 4, align 4
    uint64 timestamp;   // Offset 8, align 8
};  // Total: 16 bytes
```

Wire format:
```
00 00 00 01   42 28 00 00   00 00 00 00 12 34 56 78
└─ sensor ─┘  └─ temp ──┘   └────── timestamp ─────┘
```

## XCDR2 Extensions

XCDR2 adds support for extensible types:

### Delimited Headers (DHEADER)

For mutable/appendable types:

```
┌──────────────┬────────────────────────────┐
│ Size (4)     │ Serialized members         │
└──────────────┴────────────────────────────┘
```

### Member Headers (EMHEADER)

For optional and mutable members:

```
┌──────────────────────────────┬─────────────────┐
│ Member ID + Flags (4)        │ Member data     │
└──────────────────────────────┴─────────────────┘

Bits 0-27:  Member ID
Bits 28-29: Length code (0=1B, 1=2B, 2=4B, 3=8B/NEXTINT)
Bit 30:     Must understand
Bit 31:     Extended header follows
```

### Optional Fields

```c
@optional float temperature;

// Present: EMHEADER + value
// Absent: No bytes (or sentinel in PL_CDR)
```

## Configuration

### Setting Data Representation

```rust
use hdds::QoS;

let qos = QoS::reliable().data_representation(DataRepresentation::XCDR2);

// Or for compatibility with older implementations
let qos = QoS::reliable().data_representation(DataRepresentation::CDR2);
```

### Endianness

HDDS uses **little-endian** by default (native on x86/ARM):

```rust
// Force big-endian for legacy systems
let config = SerializationConfig::default()
    .byte_order(ByteOrder::BigEndian);
```

## Performance

### Serialization Speed

| Payload | Serialize | Deserialize |
|---------|-----------|-------------|
| 64 B struct | 50 ns | 40 ns |
| 256 B struct | 120 ns | 100 ns |
| 1 KB struct | 400 ns | 350 ns |
| 4 KB struct | 1.5 us | 1.3 us |

### Size Overhead

| Content | Raw Size | CDR Size | Overhead |
|---------|----------|----------|----------|
| 4 primitives | 20 B | 24 B | 20% |
| Struct + string | 50 B | 58 B | 16% |
| Large array | 4 KB | 4.004 KB | 0.1% |

## Manual Serialization

For advanced use cases:

```rust
use hdds::serialization::{CdrSerializer, CdrDeserializer};

// Serialize
let mut buf = Vec::new();
let mut ser = CdrSerializer::new(&mut buf);
ser.serialize_u32(sensor_id)?;
ser.serialize_f32(temperature)?;
ser.serialize_string("status")?;

// Deserialize
let mut de = CdrDeserializer::new(&buf);
let sensor_id = de.deserialize_u32()?;
let temperature = de.deserialize_f32()?;
let status = de.deserialize_string()?;
```

## Troubleshooting

### Alignment Issues

```
Error: Deserialization failed - unexpected alignment
```

Check that IDL types match on both sides.

### Endianness Mismatch

```
Error: Invalid data (endianness?)
```

Verify encapsulation header byte order matches data.

### Type Mismatch

```
Error: Type hash mismatch
```

Regenerate types from the same IDL on both sides.

## Next Steps

- [XTypes](../../guides/serialization/xtypes.md) - Type evolution and compatibility
- [IDL Syntax](../../tools/hdds-gen/idl-syntax/basic-types.md) - Type definitions
