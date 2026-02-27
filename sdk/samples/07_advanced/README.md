# 07 Advanced - Advanced DDS Patterns

This section covers advanced DDS patterns for sophisticated use cases including content filtering, request-reply communication, event-driven programming with WaitSets, and runtime type manipulation.

## Samples Overview

| Sample | Description |
|--------|-------------|
| `content_filter` | SQL-like content filtering for efficient data subscription |
| `request_reply` | RPC-style communication patterns over DDS |
| `waitsets` | Condition-based event handling and multiplexing |
| `dynamic_data` | Runtime type manipulation and introspection |

## Content Filter

Demonstrates content-filtered topics that allow subscribers to receive only data matching SQL-like filter expressions.

### Key Features
- SQL-like filter expressions (`temperature > 25.0`)
- Pattern matching (`location LIKE 'Building%'`)
- Parameterized filters (`humidity > %0`)
- Dynamic filter updates at runtime

### Filter Expression Syntax
```
temperature > 30.0           -- Comparison
location = 'ServerRoom'      -- Equality
sensor_id BETWEEN 1 AND 10   -- Range
humidity > %0                -- Parameter reference
location LIKE 'Building%'    -- Pattern matching
temp > 25 AND hum > 60      -- Logical operators
```

### Benefits
- **Network efficiency**: Filtering at source reduces traffic
- **CPU efficiency**: Subscriber processes only relevant data
- **Flexibility**: Complex expressions without code changes
- **Dynamic updates**: Modify filters without recreating readers

## Request-Reply

Implements RPC-style request-reply patterns over DDS, enabling service-oriented communication.

### Architecture
```
  Requester                     Replier
  ---------                     -------
      |                             |
      |---- Request (ID=1) ------->|
      |                             | process
      |<---- Reply (ID=1) ---------|
```

### Key Features
- Correlation IDs for matching responses
- Timeout handling for unresponsive services
- Multiple concurrent requests
- Server/client mode operation

### Usage
```bash
# Run as service (replier)
./request_reply --server

# Run as client (requester)
./request_reply
./request_reply --client Client2
```

### Pattern Variations
1. **Synchronous**: Block until reply (simple)
2. **Asynchronous**: Callback on reply (non-blocking)
3. **Future-based**: Returns future, await later
4. **Fire-and-forget**: No reply expected

## WaitSets

Demonstrates condition-based event handling for efficient waiting on multiple data sources.

### Architecture
```
  ┌─────────────────────────────────────────┐
  │               WaitSet                   │
  │  ┌───────────┐ ┌───────────┐           │
  │  │ ReadCond  │ │ StatusCond│           │
  │  │ (Topic A) │ │ (Reader)  │           │
  │  └───────────┘ └───────────┘           │
  │  ┌───────────┐ ┌───────────┐           │
  │  │ GuardCond │ │ ReadCond  │           │
  │  │ (Shutdown)│ │ (Topic B) │           │
  │  └───────────┘ └───────────┘           │
  └─────────────────────────────────────────┘
                    │
                    ▼
              wait(timeout)
                    │
                    ▼
         Active Conditions List
```

### Condition Types
| Type | Trigger | Use Case |
|------|---------|----------|
| `ReadCondition` | Data available | Data reception |
| `StatusCondition` | Entity status changed | Liveliness, matches |
| `GuardCondition` | Application signal | Shutdown, inter-thread |
| `QueryCondition` | Filtered data available | Content-filtered reads |

### Event Loop Pattern
```c
while (running) {
    active = waitset_wait(ws, conditions, timeout);

    for (cond in active) {
        if (cond == shutdown_guard)
            running = false;
        else if (cond == data_ready)
            process_data(reader);
        else if (cond == status_changed)
            handle_status(entity);
    }
}
```

### Best Practices
1. Use one WaitSet per processing thread
2. Prefer WaitSets over polling for efficiency
3. Use GuardConditions for inter-thread signaling
4. Set appropriate timeouts for responsiveness
5. Process all triggered conditions before waiting again

## Dynamic Data

Enables runtime type manipulation without compile-time type definitions.

### Architecture
```
  TypeFactory ──────> DynamicType
    │                   - name
    │ create_struct()   - kind
    │                   - members[]
    │                      │
    │                      ▼
    │                DynamicData
    │                  - type
    │                  - values[]
    │                  - get/set()
```

### Use Cases
- Generic data recording/replay tools
- Protocol bridges (DDS ↔ REST/MQTT/JSON)
- Data visualization without type knowledge
- Testing and debugging utilities
- Schema evolution handling

### Creating Types at Runtime
```cpp
// Create type
auto sensor_type = factory.create_struct("SensorReading");
sensor_type->add_member("sensor_id", TypeKind::Int32, /*key=*/true);
sensor_type->add_member("temperature", TypeKind::Float64);
sensor_type->add_member("location", TypeKind::String);

// Create data
DynamicData reading(sensor_type);
reading.set_int32("sensor_id", 101);
reading.set_float64("temperature", 23.5);
reading.set_string("location", "Room-1");

// Read data
auto temp = reading.get_float64("temperature");
```

### Type Introspection
```cpp
for (const auto& member : type->members()) {
    std::cout << "Member: " << member.name
              << ", Type: " << type_kind_str(member.type)
              << ", Key: " << member.is_key << "\n";
}
```

## Building

### C (CMake)
```bash
cd c
mkdir build && cd build
cmake ..
make
```

### C++ (CMake)
```bash
cd cpp
mkdir build && cd build
cmake ..
make
```

### Python
```bash
cd python
python content_filter.py
python request_reply.py
python waitsets.py
python dynamic_data.py
```

### Rust (Cargo)
```bash
cd rust
cargo build --release
cargo run --bin content_filter
cargo run --bin request_reply
cargo run --bin waitsets
cargo run --bin dynamic_data
```

## Related Documentation

- [DDS Specification - Content-Filtered Topics](https://www.omg.org/spec/DDS/)
- [DDS-RPC Specification](https://www.omg.org/spec/DDS-RPC/)
- [X-Types Specification (Dynamic Types)](https://www.omg.org/spec/DDS-XTypes/)
