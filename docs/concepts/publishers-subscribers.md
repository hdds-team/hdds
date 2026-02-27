# Publishers and Subscribers

In HDDS, DataWriters publish data and DataReaders subscribe to data. The Participant creates topics, and topics create writers and readers.

## Overview

```
Participant
├── Topic<SensorData> ("SensorTopic")
│   ├── DataWriter    (writes samples)
│   └── DataReader    (reads samples)
│
└── Topic<Command> ("CommandTopic")
    ├── DataWriter    (writes samples)
    └── DataReader    (reads samples)
```

## Creating Writers and Readers

### Basic Pattern

```rust
use hdds::{Participant, QoS, TransportMode};

let participant = Participant::builder("app")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;

// Create topic
let topic = participant.topic::<SensorData>("SensorTopic")?;

// Create writer
let writer = topic.writer().build()?;

// Create reader
let reader = topic.reader().build()?;
```

### With QoS

```rust
use hdds::{Participant, QoS, TransportMode};

let participant = Participant::builder("app")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;

let topic = participant.topic::<SensorData>("SensorTopic")?;

// Writer with reliable QoS
let writer = topic
    .writer()
    .qos(QoS::reliable().keep_last(100).transient_local())
    .build()?;

// Reader with reliable QoS
let reader = topic
    .reader()
    .qos(QoS::reliable().keep_last(100))
    .build()?;
```

## DataWriter

DataWriters are the endpoints that publish data.

### Writing Data

```rust
use hdds::{Participant, QoS, DDS, TransportMode};

#[derive(Debug, Clone, DDS)]
struct SensorData {
    sensor_id: u32,
    value: f32,
    timestamp: u64,
}

let participant = Participant::builder("sensor_publisher")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;

let topic = participant.topic::<SensorData>("SensorTopic")?;
let writer = topic.writer().qos(QoS::reliable()).build()?;

// Basic write
let sample = SensorData {
    sensor_id: 1,
    value: 42.5,
    timestamp: 1234567890,
};
writer.write(&sample)?;
```

### Writer Status

```rust
// Check matched readers
let matched = writer.matched_subscriptions();
println!("Matched {} readers", matched.len());
```

## DataReader

DataReaders are the endpoints that receive data.

### Reading Data

```rust
use hdds::{Participant, QoS, TransportMode};

let participant = Participant::builder("sensor_subscriber")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;

let topic = participant.topic::<SensorData>("SensorTopic")?;
let reader = topic.reader().qos(QoS::reliable()).build()?;

// Take samples (removes from cache)
while let Some(sample) = reader.try_take()? {
    println!("Received: {:?}", sample);
}
```

### Polling Loop

```rust
use std::time::Duration;
use std::thread;

loop {
    // Try to take available samples
    while let Some(sample) = reader.try_take()? {
        println!("Received: sensor={}, value={}", sample.sensor_id, sample.value);
    }

    // Small delay to avoid busy-waiting
    thread::sleep(Duration::from_millis(100));
}
```

## Alternative: Direct Writer/Reader Creation

You can also create writers and readers directly from the participant:

```rust
use hdds::{Participant, QoS, TransportMode};

let participant = Participant::builder("app")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;

// Create writer directly with topic name and QoS
let writer = participant
    .create_writer::<SensorData>("SensorTopic", QoS::reliable())?;

// Create reader directly with topic name and QoS
let reader = participant
    .create_reader::<SensorData>("SensorTopic", QoS::reliable())?;
```

## In-Process Communication

For same-process communication (zero-copy):

```rust
use hdds::{Participant, QoS, TransportMode};

let participant = Participant::builder("intra_process_app")
    .domain_id(0)
    .with_transport(TransportMode::IntraProcess)
    .build()?;

let topic = participant.topic::<SensorData>("internal/data")?;

let writer = topic.writer().qos(QoS::reliable()).build()?;
let reader = topic.reader().qos(QoS::reliable()).build()?;

// Bind reader to writer for in-process delivery
reader.bind_to_writer(writer.merger());

// Data is now shared without serialization
writer.write(&sample)?;
while let Some(data) = reader.try_take()? {
    println!("Received: {:?}", data);
}
```

## WaitSet for Event-Driven Reading

Wait for data efficiently:

```rust
use hdds::{Participant, QoS, WaitSet, TransportMode};
use std::time::Duration;

let participant = Participant::builder("waitset_example")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;

let topic = participant.topic::<SensorData>("SensorTopic")?;
let reader = topic.reader().qos(QoS::reliable()).build()?;

// Get status condition and create waitset
let condition = reader.get_status_condition();
let mut waitset = WaitSet::new();
waitset.attach(&condition)?;

loop {
    // Wait for data (blocks until data available or timeout)
    let _active = waitset.wait(Duration::from_secs(5))?;

    // Take all available samples
    while let Some(sample) = reader.try_take()? {
        println!("Received: {:?}", sample);
    }
}
```

## Best Practices

1. **Match QoS between writers and readers** - Ensure compatibility
2. **Use appropriate QoS presets** - `QoS::reliable()` for guaranteed delivery, `QoS::best_effort()` for speed
3. **Use try_take() in loops** - Non-blocking read pattern
4. **Consider WaitSet for efficiency** - Avoid busy-waiting

## Common Patterns

### Request-Reply

```rust
use hdds::{Participant, QoS, DDS, TransportMode};

#[derive(Debug, Clone, DDS)]
struct Request {
    request_id: u32,
    query: String,
}

#[derive(Debug, Clone, DDS)]
struct Reply {
    request_id: u32,
    result: String,
}

let participant = Participant::builder("request_reply")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;

// Client side
let request_topic = participant.topic::<Request>("service/request")?;
let reply_topic = participant.topic::<Reply>("service/reply")?;

let request_writer = request_topic.writer().qos(QoS::reliable()).build()?;
let reply_reader = reply_topic.reader().qos(QoS::reliable()).build()?;

// Send request
request_writer.write(&Request { request_id: 1, query: "hello".into() })?;

// Wait for reply
while let Some(reply) = reply_reader.try_take()? {
    println!("Got reply: {:?}", reply);
}
```

### Multiple Sensors

```rust
use hdds::{Participant, QoS, DDS, TransportMode};

#[derive(Debug, Clone, DDS)]
struct SensorReading {
    #[key]
    sensor_id: u32,
    value: f32,
}

let participant = Participant::builder("multi_sensor")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;

let topic = participant.topic::<SensorReading>("sensors/readings")?;
let writer = topic.writer().qos(QoS::reliable().keep_last(10)).build()?;

// Write data for multiple sensors
for sensor_id in 1..=5 {
    writer.write(&SensorReading { sensor_id, value: 25.0 + sensor_id as f32 })?;
}
```

## Next Steps

- [QoS Overview](../concepts/qos-overview.md) - Quality of Service policies
- [Discovery](../concepts/discovery.md) - How endpoints find each other
- [Reliable Delivery Example](../examples/reliable-delivery.md) - Guaranteed delivery
