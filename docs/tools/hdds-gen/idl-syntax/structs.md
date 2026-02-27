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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Point {
    pub x: f32,
    pub y: f32,
}
```

## Topic Annotation

Mark a struct as a DDS topic with `@topic`:

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

IDL supports single inheritance:

```idl
struct Base {
    int32_t id;
};

struct Derived : Base {
    string name;
    // Inherits 'id' from Base
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

Assign explicit field IDs for wire compatibility:

```idl
struct Message {
    @id(1) int32_t version;
    @id(2) string content;
    @id(10) uint64_t timestamp;
};
```

## Extensibility

Control struct evolution with extensibility annotations:

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

## Constraints

Add value constraints with annotations:

```idl
struct Sensor {
    @min(0) @max(100) int32_t percentage;
    @range(min=-40, max=85) float temperature;
    @unit("meters") double distance;
};
```

## Arrays in Structs

```idl
struct Matrix {
    float values[4][4];  // 4x4 matrix
    char name[32];       // Fixed-size string
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
