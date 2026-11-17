# CDR2 Serialization

HDDS serializes samples with the CDR family of data representations defined by DDS-XTypes: XCDR1 (CDR version 1) and XCDR2 (CDR version 2). This page describes the layout of both.

## Overview

CDR is the standard serialization format for DDS/RTPS, providing:
- **Binary encoding** - the layout follows the IDL type: member order, alignment and extensibility
- **Platform independence** - the byte order is part of the encapsulation identifier
- **Interoperability** - the representations are defined by the DDS-XTypes and RTPS specifications

CDR carries no type information in the payload: both sides must agree on the
type, which discovery checks (see [XTypes](xtypes.md)).

## Encoding Formats

HDDS supports multiple CDR encodings:

| Format | ID (BE / LE) | Description |
|--------|-----|-------------|
| CDR | 0x0000 / 0x0001 | XCDR1, final and appendable types |
| PL_CDR | 0x0002 / 0x0003 | XCDR1 parameter list, mutable types |
| CDR2 | 0x0006 / 0x0007 | XCDR2, final types |
| D_CDR2 | 0x0008 / 0x0009 | XCDR2 delimited, appendable types |
| PL_CDR2 | 0x000A / 0x000B | XCDR2 parameter list, mutable types |

Default: a DataWriter that sets no DATA_REPRESENTATION offers and encodes
**XCDR1** (DDS-XTypes 1.3 7.6.3.1.1: an empty list is `[XCDR]`), XCDR2 only
for a type that does not encode XCDR1 natively. Set
`QoS::data_representation_xcdr2()` on the writer to send XCDR2. A reader that
sets none requests both.

## Wire Format

### Encapsulation Header

Every serialized payload on the wire starts with a 4-byte header:

```
Byte 0-1: Encapsulation identifier, big-endian (e.g. 00 07 for little-endian CDR2)
Byte 2-3: Options; the two low bits of byte 3 give the number of padding
          bytes appended to reach a 4-byte boundary
```

The byte order of the body is part of the identifier: even values are big-endian,
odd values are little-endian (see the table above). The `encode` and
`encode_cdr2_le` calls shown below produce the body only; the header is added
when a sample is sent.

### Primitive Types

| IDL Type | Wire Size | XCDR1 alignment | XCDR2 alignment |
|----------|-----------|-----------------|-----------------|
| boolean | 1 byte | 1 | 1 |
| octet/int8/uint8 | 1 byte | 1 | 1 |
| int16/uint16 | 2 bytes | 2 | 2 |
| int32/uint32 | 4 bytes | 4 | 4 |
| int64/uint64 | 8 bytes | 8 | 4 |
| float | 4 bytes | 4 | 4 |
| double | 8 bytes | 8 | 4 |
| char | 1 byte | 1 | 1 |
| wchar | 2 bytes | 2 | 2 |

### Alignment Rules

Data is aligned to natural boundaries, relative to the start of the body.
XCDR2 caps the alignment at 4 bytes, so an 8-byte member is aligned to 8
under XCDR1 and to 4 under XCDR2. Under XCDR1:

```
Offset:  0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
        +--+--+--+--+----------+----------------------+
        |u8|  |u16 |   u32    |        u64           |
        +--+--+--+--+----------+----------------------+
             ^  ^        ^              ^
          pad(1) align(2) align(4)    align(8)
```

For `@final struct Wide { uint32 a; uint64 b; }` with `a = 1` and `b = 2`, the
little-endian body is 16 bytes under XCDR1 (4 padding bytes before `b`) and
12 bytes under XCDR2 (no padding):

```
XCDR1: 01 00 00 00  00 00 00 00  02 00 00 00 00 00 00 00
XCDR2: 01 00 00 00  02 00 00 00 00 00 00 00
```

### String Encoding

```
+------------+----------------------------+
| Length (4) | UTF-8 data + NUL terminator|
+------------+----------------------------+
```

Example: "Hello" (5 chars), little-endian
```
06 00 00 00   48 65 6C 6C 6F 00
+- length -+  +- "Hello\0" ---+
```

### Sequence Encoding

```
+------------+------------------------------+
| Count (4)  | Elements (each aligned)      |
+------------+------------------------------+
```

Example: `sequence<uint32>` with [1, 2, 3], little-endian
```
03 00 00 00   01 00 00 00   02 00 00 00   03 00 00 00
+- count -+   +-- 1 ----+   +-- 2 ----+   +-- 3 ----+
```

Under XCDR2, a sequence whose elements are not primitives (strings,
structures) is also preceded by a DHEADER holding the byte length of what
follows. XCDR1 has no DHEADER.

### Array Encoding

Fixed-size arrays have no length prefix:

```c
float values[4];  // IDL

// Wire format, little-endian: 16 bytes (4 x float32)
00 00 80 3F   00 00 00 40   00 00 40 40   00 00 80 40
+-- 1.0 --+   +-- 2.0 --+   +-- 3.0 --+   +-- 4.0 --+
```

### Struct Encoding

Members are serialized in declaration order with alignment:

```c
@final
struct SensorData {
    uint32 sensor_id;   // Offset 0, align 4
    float temperature;  // Offset 4, align 4
    uint64 timestamp;   // Offset 8, align 8 (XCDR1) or 4 (XCDR2)
};  // Total: 16 bytes
```

Wire format for `sensor_id = 1`, `temperature = 42.0`, `timestamp = 1000`
(little-endian, identical under XCDR1 and XCDR2 for this layout):
```
01 00 00 00   00 00 28 42   E8 03 00 00 00 00 00 00
+- sensor -+  +- temp --+   +------ timestamp -----+
```

## XCDR2 Extensions

XCDR2 adds support for extensible types:

### Delimited Headers (DHEADER)

For appendable and mutable types:

```
+--------------+----------------------------+
| Size (4)     | Serialized members         |
+--------------+----------------------------+
```

The size is the byte count of the members that follow. A reader skips whatever
remains inside the delimited block after its last known member, which is what
lets a writer append members. For `struct Appendable { uint32 sensor_id; float value; }`
with `sensor_id = 1` and `value = 1.0`:

```
XCDR2: 08 00 00 00  01 00 00 00  00 00 80 3F
XCDR1: 01 00 00 00  00 00 80 3F
```

XCDR1 has no DHEADER for appendable types.

### Member Headers (EMHEADER)

For the members of mutable types:

```
+------------------------------+-----------------+
| Member ID + Flags (4)        | Member data     |
+------------------------------+-----------------+

Bits 0-27:  Member ID
Bits 28-30: Length code (0 to 3: the member is 1, 2, 4 or 8 bytes long;
            4: a NEXTINT word follows and gives the length;
            5 to 7: the member's own leading length word is the NEXTINT)
Bit 31:     Must understand
```

For `@mutable struct Mut { @id(1) uint32 sensor_id; @id(2) float value; @id(3) @optional string unit; }`
with `sensor_id = 7`, `value = 1.0` and `unit = "C"`, the XCDR2 body is:

```
1A 00 00 00                      DHEADER: 26 bytes follow
01 00 00 20  07 00 00 00         EMHEADER (id 1, length code 2), sensor_id
02 00 00 20  00 00 80 3F         EMHEADER (id 2, length code 2), value
03 00 00 50  02 00 00 00 43 00   EMHEADER (id 3, length code 5), unit = "C"
```

### Optional Fields

```c
@optional float temperature;
```

In a mutable type an optional member that is absent contributes no bytes, and
a present one is written behind its EMHEADER. In a final or appendable type
under XCDR2 every optional member is written as a one-byte presence flag,
followed by the value aligned to its own boundary when the flag is set. For
`@appendable struct Opt { uint32 id; @optional float z; }` with `id = 7`:

```
z present (1.0): 0C 00 00 00  07 00 00 00  01 00 00 00  00 00 80 3F
z absent:        05 00 00 00  07 00 00 00  00
```

XCDR1 writes optional members behind a parameter-list header instead.

## Configuration

### Setting Data Representation

```rust
use hdds::QoS;

// Offer and encode XCDR2
let qos = QoS::reliable().data_representation_xcdr2();

// Offer and encode XCDR1
let qos = QoS::reliable().data_representation_xcdr1();
```

A writer offers one representation, the first of its list. A writer that
requests XCDR1 for a type that cannot encode it is refused at creation.

### Endianness

HDDS serializes little-endian (the codec calls are named `*_le`); there is no
byte-order setting.

## Performance

Serialization time and encoded size depend on the exact type layout, bounds,
alignment, representation, build, and machine. HDDS does not currently publish
a reference-grade serialization matrix. Retain the type definition, benchmark
source, environment stamp, and raw output with any new result.

## Manual Serialization

For advanced use cases, a type that implements `hdds::DdsTrait` (the
`#[derive(hdds::DDS)]` macro or a generated type) encodes to and decodes from a
byte buffer at a chosen representation:

```rust
use hdds::{CdrVersion, DdsTrait};

#[derive(hdds::DDS, Debug, PartialEq)]
#[dds(final)]
struct SensorData {
    sensor_id: u32,
    temperature: f32,
    timestamp: u64,
}

fn round_trip() -> hdds::Result<()> {
    let sample = SensorData { sensor_id: 1, temperature: 42.0, timestamp: 1000 };

    let mut buf = [0u8; 64];
    let len = sample.encode(&mut buf, CdrVersion::Xcdr2)?;
    let decoded = SensorData::decode(&buf[..len], CdrVersion::Xcdr2)?;
    assert_eq!(decoded, sample);
    Ok(())
}
```

Types generated by `hddsgen` also implement the `hdds::Cdr2Encode` and
`hdds::Cdr2Decode` traits (`encode_cdr2_le`, `decode_cdr2_le`).

## Troubleshooting

### Decoding fails

A sample that cannot be decoded surfaces as `hdds::Error::SerializationError`;
a buffer that is too small for an encode as `hdds::Error::BufferTooSmall`.
The usual cause of a decode failure is a layout difference between the two
sides: a different extensibility, a different member order, or a different
representation (XCDR1 or XCDR2). Check that the IDL types match on both sides.

### No samples arrive

A writer and a reader of the same topic match only when their types and
DATA_REPRESENTATION are compatible. Regenerate the types from the same IDL on
both sides and compare the extensibility and the representation each endpoint
offers.

## Next Steps

- [XTypes](../../guides/serialization/xtypes.md) - Type evolution and compatibility
- [IDL Syntax](../../tools/hdds-gen/idl-syntax/basic-types.md) - Type definitions
