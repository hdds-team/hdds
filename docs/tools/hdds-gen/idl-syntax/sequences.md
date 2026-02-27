# Sequences & Collections

HDDS supports three collection types: sequences (variable-length), arrays (fixed-length), and maps (key-value).

## Sequences

Variable-length ordered collections.

### Unbounded Sequences

```idl
struct SensorData {
    sequence<float> readings;        // No size limit
    sequence<string> labels;
};
```

**Generated Rust**:
```rust
pub struct SensorData {
    pub readings: Vec<f32>,
    pub labels: Vec<String>,
}
```

### Bounded Sequences

Limit maximum size for memory safety:

```idl
struct Packet {
    sequence<octet, 1500> payload;   // Max 1500 bytes
    sequence<float, 100> samples;    // Max 100 floats
};
```

**Generated Rust**:
```rust
pub struct Packet {
    pub payload: BoundedVec<u8, 1500>,
    pub samples: BoundedVec<f32, 100>,
}
```

### Sequences of Structs

```idl
struct Point {
    float x;
    float y;
};

struct Polygon {
    sequence<Point, 256> vertices;
};
```

## Arrays

Fixed-size collections.

### Single Dimension

```idl
struct Matrix3x3 {
    float values[9];
};

struct IPv4Address {
    octet octets[4];
};
```

**Generated Rust**:
```rust
pub struct Matrix3x3 {
    pub values: [f32; 9],
}
```

### Multi-Dimensional

```idl
struct Image {
    octet pixels[1920][1080][3];  // Width x Height x RGB
};

struct Transform {
    float matrix[4][4];  // 4x4 transformation matrix
};
```

### Arrays of Strings

```idl
struct Config {
    string options[10];      // 10 strings, each unbounded
    string<64> names[5];     // 5 strings, max 64 chars each
};
```

## Maps

Key-value associative containers (IDL 4.2+).

### Basic Maps

```idl
struct UserPrefs {
    map<string, string> settings;
    map<int32, float> calibration;
};
```

**Generated Rust**:
```rust
use std::collections::HashMap;

pub struct UserPrefs {
    pub settings: HashMap<String, String>,
    pub calibration: HashMap<i32, f32>,
}
```

### Bounded Maps

```idl
struct Cache {
    map<string, string, 100> entries;  // Max 100 entries
};
```

### Maps with Complex Values

```idl
struct Point { float x; float y; };

struct Registry {
    map<string, Point> locations;
    map<uint32, sequence<float>> measurements;
};
```

## Nested Collections

Collections can be nested up to 5 levels deep:

```idl
struct Dataset {
    // Sequence of arrays
    sequence<float[3]> points_3d;

    // Array of sequences
    sequence<float>[10] channels;

    // Sequence of sequences
    sequence<sequence<int32>> matrix;

    // Map of sequences
    map<string, sequence<float>> timeseries;
};
```

:::warning Nesting Limit
hdds_gen enforces a maximum nesting depth of 5 levels for collections.
:::

## String Collections

### Bounded Strings in Collections

```idl
struct MessageLog {
    sequence<string<256>, 1000> messages;  // 1000 messages, max 256 chars each
};
```

### String Maps

```idl
struct Dictionary {
    map<string<64>, string<1024>> entries;
};
```

## Wire Format

### Sequence Serialization (CDR)

```
+------------------+------------------------------+
| length (4 bytes) | elements (length x elem_size)|
+------------------+------------------------------+
```

Example: `sequence<int32>` with values [1, 2, 3]:
```
03 00 00 00    // length = 3
01 00 00 00    // element[0] = 1
02 00 00 00    // element[1] = 2
03 00 00 00    // element[2] = 3
```

### Array Serialization (CDR)

Arrays have no length prefix (size is fixed):

```
+----------------------------------------------+
| elements (fixed count x elem_size)           |
+----------------------------------------------+
```

Example: `int32 values[3]` with values [1, 2, 3]:
```
01 00 00 00    // element[0] = 1
02 00 00 00    // element[1] = 2
03 00 00 00    // element[2] = 3
```

### Map Serialization (CDR2)

```
+------------------+----------------------------------+
| count (4 bytes)  | pairs (key1, val1, key2, val2...) |
+------------------+----------------------------------+
```

## Language Mappings

| IDL | Rust | C | C++ | Python |
|-----|------|---|-----|--------|
| `sequence<T>` | `Vec<T>` | `T* data; size_t len;` | `std::vector<T>` | `list[T]` |
| `sequence<T,N>` | `BoundedVec<T,N>` | `T data[N]; size_t len;` | `dds::bounded_sequence<T,N>` | `list[T]` |
| `T[N]` | `[T; N]` | `T[N]` | `std::array<T,N>` | `list[T]` |
| `map<K,V>` | `HashMap<K,V>` | `struct { K* keys; V* vals; }` | `std::map<K,V>` | `dict[K,V]` |

## Examples

### Telemetry Buffer

```idl
struct TelemetryPacket {
    @key uint32_t device_id;
    uint64_t timestamp;
    sequence<float, 1000> samples;
    map<string, float> metadata;
};
```

### Point Cloud

```idl
struct Point3D {
    float x;
    float y;
    float z;
};

struct PointCloud {
    @key string frame_id;
    uint64_t timestamp;
    sequence<Point3D, 65536> points;
    sequence<octet, 262144> colors;  // RGBA per point
};
```

### Configuration Tree

```idl
struct ConfigNode {
    string name;
    string value;
    sequence<ConfigNode, 100> children;  // Recursive structure
};

struct Configuration {
    @key string config_id;
    ConfigNode root;
};
```

## Validation Rules

hdds_gen validates:

- **Nesting depth**: Maximum 5 levels
- **Bound values**: Must be positive integers
- **Array size**: Must be > 0
- **Map key types**: Must be primitive or string

## Best Practices

1. **Use bounds** for real-time systems to guarantee memory usage
2. **Prefer sequences** over arrays when size varies
3. **Use maps** for sparse key-value data
4. **Document bounds** in comments for API clarity

```idl
// GPS track with up to 10000 waypoints
struct Track {
    @key uint32_t track_id;
    sequence<Point3D, 10000> waypoints;  // Max 10K points (~120KB)
};
```

## Next Steps

- [Annotations](../../../tools/hdds-gen/idl-syntax/annotations.md) - Metadata annotations
- [Structs](../../../tools/hdds-gen/idl-syntax/structs.md) - Composite types
