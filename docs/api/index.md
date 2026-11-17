# API Reference

HDDS provides native bindings for multiple programming languages. Each binding is designed to feel idiomatic in its target language while maintaining consistent DDS semantics.

## Supported Languages

| Language | Package (built from the repository) | Documentation |
|----------|-------------------------------------|---------------|
| **Rust** | crate `hdds` (`crates/hdds`) | [Rust API](../api/rust.md) |
| **C** | crate `hdds-c` (`libhdds_c`, header `hdds.h`) | [C API](../api/c.md) |
| **C++** | `hdds_cxx` (`sdk/cxx`, header `hdds.hpp`) | [C++ API](../api/cpp.md) |
| **Python** | `hdds` (`sdk/python`, not on PyPI) | [Python API](../api/python.md) |

## Quick Reference

### Creating a Participant

import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';

<Tabs>
  <TabItem value="rust" label="Rust" default>

```rust
use hdds::{Participant, TransportMode};

let participant = Participant::builder("my_app")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;
```

  </TabItem>
  <TabItem value="c" label="C">

```c
struct HddsParticipant *participant =
    hdds_participant_create_with_transport("my_app", HDDS_TRANSPORT_UDP_MULTICAST);
```

  </TabItem>
  <TabItem value="cpp" label="C++">

```cpp
hdds::Participant participant("my_app");
```

  </TabItem>
  <TabItem value="python" label="Python">

```python
with hdds.Participant("my_app") as participant:
    # use participant
    pass
```

  </TabItem>
</Tabs>

### Creating a Writer

<Tabs>
  <TabItem value="rust" label="Rust" default>

```rust
let writer = participant
    .topic::<Temperature>("sensors/temp")?
    .writer()
    .qos(QoS::reliable())
    .build()?;
```

  </TabItem>
  <TabItem value="c" label="C">

```c
struct HddsQoS *qos = hdds_qos_reliable();
struct HddsDataWriter *writer =
    hdds_writer_create_with_qos(participant, "sensors/temp", qos);
hdds_qos_destroy(qos);
```

  </TabItem>
  <TabItem value="cpp" label="C++">

```cpp
auto qos = hdds::QoS::reliable().transient_local();
auto writer = participant.create_writer_raw("sensors/temp", qos);
```

  </TabItem>
  <TabItem value="python" label="Python">

```python
qos = hdds.QoS.reliable().transient_local()
writer = participant.create_writer("sensors/temp", qos=qos)
```

  </TabItem>
</Tabs>

### Writing Data

<Tabs>
  <TabItem value="rust" label="Rust" default>

```rust
let sample = Temperature { sensor_id: 1, value: 23.5 };
writer.write(&sample)?;
```

  </TabItem>
  <TabItem value="c" label="C">

```c
// Raw bytes (use hddsgen for typed data)
const char *msg = "Hello DDS";
hdds_writer_write(writer, msg, strlen(msg));
```

  </TabItem>
  <TabItem value="cpp" label="C++">

```cpp
std::vector<uint8_t> data = {1, 2, 3, 4};
writer->write_raw(data);
```

  </TabItem>
  <TabItem value="python" label="Python">

```python
writer.write(b"Hello DDS")
```

  </TabItem>
</Tabs>

### Reading Data

<Tabs>
  <TabItem value="rust" label="Rust" default>

```rust
while let Some(sample) = reader.take()? {
    println!("Received: {:?}", sample);
}
```

  </TabItem>
  <TabItem value="c" label="C">

```c
char buffer[1024];
size_t len;
while (hdds_reader_take(reader, buffer, sizeof(buffer), &len) == HDDS_OK) {
    // process buffer (len bytes)
}
```

  </TabItem>
  <TabItem value="cpp" label="C++">

```cpp
while (auto data = reader->take_raw()) {
    // process *data (std::vector<uint8_t>)
}
```

  </TabItem>
  <TabItem value="python" label="Python">

```python
while (data := reader.take()) is not None:
    print(f"Received: {data}")
```

  </TabItem>
</Tabs>

## Core Entities

All DDS implementations share the same core entities:

```mermaid
classDiagram
    DomainParticipant --> Publisher
    DomainParticipant --> Subscriber
    DomainParticipant --> Topic
    Publisher --> DataWriter
    Subscriber --> DataReader
    DataWriter --> Topic
    DataReader --> Topic

    class DomainParticipant {
        +domain_id()
        +create_publisher()
        +create_subscriber()
        +topic(name)
    }

    class Topic {
        +writer()
        +reader()
    }

    class DataWriter {
        +write(data)
        +dispose(instance)
    }

    class DataReader {
        +read()
        +take()
    }
```

## Feature Comparison

| Feature | Rust | C | C++ | Python |
|---------|------|---|-----|--------|
| Typed Data | `#[derive(DDS)]` or `hddsgen` | `hddsgen` | `hddsgen` | `hddsgen` |
| Raw Bytes | Yes | Yes | Yes | Yes |
| Fluent QoS | Yes | No | Yes | Yes |
| RAII | Yes | Manual | Yes | Context Mgr |
| WaitSet | Yes | Yes | Yes | Yes |
| Telemetry | Yes | Yes | Yes | Yes |
| Listeners | Yes | Yes | Yes | Yes |
