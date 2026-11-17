# IDL Structs

Structs are the primary composite type in IDL, used to define DDS topic data types.

## Basic Struct

```idl
struct Point {
    float x;
    float y;
};
```

**Generated Rust:**
```rust
#[derive(Debug, Clone, PartialEq)]
pub struct Point {
    pub x: f32,
    pub y: f32,
}
```

The generated file also holds the CDR2 codec and a `PointBuilder`. Pass
`--serde` to `hddsgen gen rust` to add serde derives.

## Topic Annotation

`@topic` marks a struct as a topic type. It is accepted and kept when the IDL is
formatted, and it does not change the generated code: a struct is usable as a
topic type with or without it.

```idl
@topic
struct SensorReading {
    @key string sensor_id;
    float value;
    uint64_t timestamp;
};
```

## Key Fields

Use `@key` to mark instance keys for DDS:

```idl
struct VehiclePosition {
    @key string vehicle_id;  // Instance key
    @key uint32_t domain;    // Composite key
    double latitude;
    double longitude;
};
```

:::tip
Key fields identify unique instances. DDS tracks each key combination separately, maintaining independent history per instance.
:::

## Nested Structs

Structs can contain other structs:

```idl
struct Vector3 {
    float x;
    float y;
    float z;
};

struct Pose {
    Vector3 position;
    Vector3 orientation;
};
```

## Struct Inheritance

IDL supports single inheritance. In the generated code C++ and Python structs
derive from their base and a TypeScript interface extends it; Rust and C structs
hold the base in a `base` member:

```idl
struct Base {
    int32_t id;
};

struct Derived : Base {
    string name;
    // Also carries the members of Base
};
```

**With modules:**
```idl
module geometry {
    struct Shape {
        string name;
    };
};

struct Circle : geometry::Shape {
    float radius;
};
```

## Optional Fields

Use `@optional` for fields that may not be present:

```idl
struct Config {
    string name;
    @optional string description;
    @optional int32_t timeout;
};
```

**Generated Rust:**
```rust
pub struct Config {
    pub name: String,
    pub description: Option<String>,
    pub timeout: Option<i32>,
}
```

## Field IDs

Assign explicit member IDs with `@id`:

```idl
@mutable
struct Message {
    @id(1) int32_t version;
    @id(2) string content;
    @id(10) uint64_t timestamp;
};
```

The IDs are written on the wire by `@mutable` types (each member carries its
ID); for `@final` and `@appendable` types they appear only in the type's
TypeObject. IDs must be unique within a struct.

## Extensibility

Control struct evolution with extensibility annotations. A struct without one
is `@appendable` (the DDS-XTypes 1.3 default); pass
`--default-extensibility final` to `hddsgen gen` for the `@final` layout of
hddsgen 1.x.

```idl
@final
struct Immutable {
    int32_t a;
    // No fields can be added in future versions
};

@appendable
struct Extensible {
    int32_t a;
    // New fields can only be appended
};

@mutable
struct FullyEvolvable {
    int32_t a;
    // Fields can be added, removed, or reordered
};
```

## Default Values

Specify default values for fields:

```idl
struct Settings {
    @default(5000) int32_t timeout;
    @default("auto") string mode;
    @default(TRUE) boolean enabled;
};
```

In the Rust output, `@default` is the value the generated builder uses for a
field that was not set (`SettingsBuilder::build`). The other backends and the
generated `Default` value ignore it.

## Constraints

Declare value constraints with annotations:

```idl
struct Sensor {
    @min(0) @max(100) int32_t percentage;
    @range(min=-40, max=85) float temperature;
    @unit("meters") double distance;
};
```

`hddsgen check` validates these annotations (`@min` must not exceed `@max`, the
bounds must be numbers and fit the field type). The generated code does not
enforce them: a sample outside the range is encoded as it is.

## Arrays in Structs

```idl
struct Matrix {
    float values[4][4];  // 4x4 matrix
    char name[32];       // Array of 32 characters (use string<32> for a bounded string)
};
```

## Complete Example

```idl
module robotics {
    struct Timestamp {
        int32_t sec;
        uint32_t nanosec;
    };

    @topic
    struct Odometry {
        @key string frame_id;

        Timestamp stamp;

        // Position
        double x;
        double y;
        double z;

        // Orientation (quaternion)
        double qx;
        double qy;
        double qz;
        double qw;

        // Covariance (6x6 matrix, row-major)
        double pose_covariance[36];

        @optional string child_frame_id;
    };
};
```
