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

Limit the maximum number of elements. The generated encoders and decoders
refuse a sequence longer than its bound:

```idl
struct Packet {
    sequence<octet, 1500> payload;   // Max 1500 bytes
    sequence<float, 100> samples;    // Max 100 floats
};
```

**Generated Rust**: a bounded sequence is a `Vec` like an unbounded one; the
bound is checked when the sample is encoded and decoded:
```rust
pub struct Packet {
    pub payload: Vec<u8>,
    pub samples: Vec<f32>,
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
    map<int32_t, float> calibration;
};
```

**Generated Rust**:
```rust
pub struct UserPrefs {
    pub settings: std::collections::HashMap<String, String>,
    pub calibration: std::collections::HashMap<i32, f32>,
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
    map<uint32_t, sequence<float>> measurements;
};
```

## Nested Collections

Collections nest. An array or sequence of an array or sequence needs a typedef
for the inner type (the IDL grammar does not allow `sequence<float[3]>` or
`sequence<float>[10]`):

```idl
typedef float Vec3[3];
typedef sequence<float> FloatSeq;

struct Dataset {
    // Sequence of arrays
    sequence<Vec3> points_3d;

    // Array of sequences
    FloatSeq channels[10];

    // Sequence of sequences
    sequence<sequence<int32_t>> matrix;

    // Map of sequences
    map<string, sequence<float>> timeseries;
};
```

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

Example: `sequence<int32_t>` with values [1, 2, 3]:
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

Example: `int32_t values[3]` with values [1, 2, 3]:
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

When keys or values are not primitive (for example a string key), the map is
preceded by a 4-byte length header (DHEADER), as for any collection of
non-primitive elements under XCDR2.

## Language Mappings

| IDL | Rust | C | C++ | Python | TypeScript |
|-----|------|---|-----|--------|------------|
| `sequence<T>` | `Vec<T>` | `struct { T* data; uint32_t len; }` | `std::vector<T>` | `List[T]` | `T[]` |
| `sequence<T,N>` | `Vec<T>` | `struct { T* data; uint32_t len; }` | `std::vector<T>` | `List[T]` | `T[]` |
| `T[N]` | `[T; N]` | `T[N]` | `std::array<T, N>` | `List[T]` | `T[]` |
| `map<K,V>` | `std::collections::HashMap<K, V>` | `struct { K* keys; V* values; uint32_t len; }` | `std::map<K, V>` | `Dict[K, V]` | `Map<K, V>` |

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

The Rust and C++ output compile for a recursive structure like `ConfigNode`. The
C output of hddsgen 2.0.0 does not: the sequence member names the struct inside
its own definition, which C rejects.

## Validation Rules

`hddsgen check` and `hddsgen gen` report:

- **Map bound**: `map<K, V, N>` requires `N > 0` (parse error)
- **Map key types**: a floating-point key type is an error

The generated Rust code enforces sequence and string bounds when encoding and
decoding. The decoders also limit the storage one sample may demand to a
multiple of its size (64 by default, `CDR_MAX_ALLOC_RATIO` in the C, C++, Python
and TypeScript output).

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
