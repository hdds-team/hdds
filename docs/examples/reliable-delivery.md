# Reliable Delivery Example

Demonstrates guaranteed message delivery using HDDS reliable QoS.

## Overview

This example shows:
- Configuring reliable delivery
- Handling acknowledgments
- Recovery from packet loss

## How Reliable Delivery Works

```
Writer                              Reader
  |                                   |
  |------ DATA (seq=1) -------------->|
  |<----- ACKNACK (ack=2) ------------|
  |                                   |
  |------ DATA (seq=2) -----X         | (lost)
  |                                   |
  |------ HEARTBEAT (seq=1-2) ------->|
  |<----- ACKNACK (missing=2) --------|
  |                                   |
  |------ DATA (seq=2) -------------->| (retransmit)
  |<----- ACKNACK (ack=3) ------------|
```

## Data Type Definition

```rust
use hdds::DDS;

#[derive(Debug, Clone, DDS)]
enum CommandType {
    Start,
    Stop,
    Configure,
    Reset,
}

#[derive(Debug, Clone, DDS)]
struct Command {
    #[key]
    device_id: u32,
    sequence_number: u64,
    command_type: CommandType,
    parameters: String,
}
```

## Publisher (Reliable)

```rust title="src/command_sender.rs"
use hdds::{Participant, QoS, DDS, TransportMode};
use std::time::Duration;

#[derive(Debug, Clone, DDS)]
enum CommandType { Start, Stop, Configure, Reset }

#[derive(Debug, Clone, DDS)]
struct Command {
    #[key]
    device_id: u32,
    sequence_number: u64,
    command_type: CommandType,
    parameters: String,
}

fn main() -> Result<(), hdds::Error> {
    let participant = Participant::builder("command_sender")
        .domain_id(0)
        .with_transport(TransportMode::UdpMulticast)
        .build()?;

    // Create topic and reliable writer
    let topic = participant.topic::<Command>("CommandTopic")?;
    let writer = topic
        .writer()
        .qos(QoS::reliable().keep_all().transient_local())
        .build()?;

    // Wait for at least one subscriber
    println!("Waiting for subscriber...");
    while writer.matched_subscriptions().is_empty() {
        std::thread::sleep(Duration::from_millis(100));
    }
    println!("Subscriber connected!");

    // Send commands
    for seq in 1..=10 {
        let cmd = Command {
            device_id: 1,
            sequence_number: seq,
            command_type: CommandType::Configure,
            parameters: format!("config_{}", seq),
        };

        writer.write(&cmd)?;
        println!("Command {} sent", seq);
    }

    println!("All commands delivered!");
    Ok(())
}
```

## Subscriber (Reliable)

```rust title="src/command_receiver.rs"
use hdds::{Participant, QoS, DDS, TransportMode};
use std::time::Duration;
use std::thread;
use std::collections::HashSet;

#[derive(Debug, Clone, DDS)]
enum CommandType { Start, Stop, Configure, Reset }

#[derive(Debug, Clone, DDS)]
struct Command {
    #[key]
    device_id: u32,
    sequence_number: u64,
    command_type: CommandType,
    parameters: String,
}

fn main() -> Result<(), hdds::Error> {
    let participant = Participant::builder("command_receiver")
        .domain_id(0)
        .with_transport(TransportMode::UdpMulticast)
        .build()?;

    // Create topic and reliable reader
    let topic = participant.topic::<Command>("CommandTopic")?;
    let reader = topic
        .reader()
        .qos(QoS::reliable().keep_all().transient_local())
        .build()?;

    println!("Receiving commands...");

    let mut received = HashSet::new();

    loop {
        while let Some(sample) = reader.try_take()? {
            if received.insert(sample.sequence_number) {
                println!(
                    "Received command {}: {:?} - {}",
                    sample.sequence_number,
                    sample.command_type,
                    sample.parameters
                );
            }
        }

        thread::sleep(Duration::from_millis(10));
    }
}
```

## Late Joiner Support

With `transient_local()` durability, late subscribers receive historical data:

```rust
use hdds::{Participant, QoS, TransportMode};

let participant = Participant::builder("late_joiner")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;

let topic = participant.topic::<Command>("CommandTopic")?;

// Publisher: keep last 100 samples for late joiners
let writer = topic
    .writer()
    .qos(QoS::reliable().keep_last(100).transient_local())
    .build()?;

// Subscriber: request historical data
let reader = topic
    .reader()
    .qos(QoS::reliable().transient_local())
    .build()?;
```

## QoS Compatibility

| Writer | Reader | Result |
|--------|--------|--------|
| reliable() | reliable() | Full reliability |
| reliable() | best_effort() | Works (reader ignores retransmits) |
| best_effort() | reliable() | **Incompatible** - no match |
| best_effort() | best_effort() | No reliability |

## History Depth Tuning

```rust
use hdds::{Participant, QoS, TransportMode};

let participant = Participant::builder("history_example")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;

let topic = participant.topic::<Command>("CommandTopic")?;

// High-throughput: limit buffer
let writer = topic
    .writer()
    .qos(QoS::reliable().keep_last(1000))
    .build()?;

// Command queue: keep all (use with caution)
let writer = topic
    .writer()
    .qos(QoS::reliable().keep_all())
    .build()?;
```

## Performance Considerations

| Factor | Impact |
|--------|--------|
| Network RTT | Affects acknowledgment latency |
| History depth | Memory usage, retransmit buffer |
| Packet loss rate | More retransmits, higher latency |

## Troubleshooting

### QoS Mismatch

```
Warning: No matching subscriptions found
```

**Check:**
- Both sides use same reliability mode
- Durability is compatible (writer >= reader)
- Topic and type names match exactly

## Next Steps

- [Key Instance](../examples/key-instance.md) - Per-instance reliability
- [Deadline QoS](../guides/qos-policies/deadline.md) - Timing requirements
- [Liveliness](../guides/qos-policies/liveliness.md) - Failure detection
