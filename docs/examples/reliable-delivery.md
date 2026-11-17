# Reliable Delivery Example

Demonstrates guaranteed message delivery using HDDS reliable QoS.

## Overview

This example shows:
- Configuring reliable delivery
- Waiting for acknowledgments
- How lost samples are recovered

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

`Command` uses an enum member, which the `DDS` derive macro does not support,
so the type is defined in IDL and generated with `hddsgen`:

```c title="Command.idl"
enum CommandType {
    START,
    STOP,
    CONFIGURE,
    RESET
};

struct Command {
    @key unsigned long device_id;
    unsigned long long sequence_number;
    CommandType command_type;
    string parameters;
};
```

`hddsgen` comes from the separate `hdds_gen` repository (build it from
source: `git clone https://git.hdds.io/hdds/hdds_gen.git && cargo install --path hdds_gen`).

```bash
hddsgen gen rust Command.idl -o src/command.rs
```

Declare the generated file as a module of the package. The binaries below
refer to the package as `my_app`; use your own package name:

```rust title="src/lib.rs"
pub mod command;
```

Generated enum variants keep the case used in the IDL (`CommandType::CONFIGURE`).

## Publisher (Reliable)

```rust title="src/bin/command_sender.rs"
use hdds::{Participant, QoS, TransportMode};
use my_app::command::{Command, CommandType};
use std::time::Duration;

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
    while writer.matched_reader_count() == 0 {
        std::thread::sleep(Duration::from_millis(100));
    }
    println!("Subscriber connected!");

    // Send commands
    for seq in 1..=10 {
        let cmd = Command {
            device_id: 1,
            sequence_number: seq,
            command_type: CommandType::CONFIGURE,
            parameters: format!("config_{}", seq),
        };

        writer.write(&cmd)?;
        println!("Command {} sent", seq);
    }

    // Block until every matched reliable reader has acknowledged every sample
    writer.wait_for_acknowledgments(Duration::from_secs(5))?;
    println!("All commands acknowledged!");
    Ok(())
}
```

## Subscriber (Reliable)

```rust title="src/bin/command_receiver.rs"
use hdds::{Participant, QoS, TransportMode};
use my_app::command::Command;
use std::collections::HashSet;
use std::thread;
use std::time::Duration;

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
        while let Some(sample) = reader.take()? {
            if received.insert(sample.sequence_number) {
                println!(
                    "Received command {}: {:?} - {}",
                    sample.sequence_number, sample.command_type, sample.parameters
                );
            }
        }

        thread::sleep(Duration::from_millis(10));
    }
}
```

Start the subscriber first, then the sender:

```bash
cargo run --bin command_receiver
cargo run --bin command_sender
```

Sender output:

```
Waiting for subscriber...
Subscriber connected!
Command 1 sent
...
Command 10 sent
All commands acknowledged!
```

Subscriber output:

```
Receiving commands...
Received command 1: CONFIGURE - config_1
...
Received command 10: CONFIGURE - config_10
```

## Late Joiner Support

With `transient_local()` durability, late subscribers receive historical data:

```rust
use hdds::{Participant, QoS, TransportMode};
use my_app::command::Command;

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
use my_app::command::Command;

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

If a writer never matches a reader, `writer.matched_reader_count()` stays at 0.
`writer.get_offered_incompatible_qos_status()` reports the incompatibilities
the writer has seen.

**Check:**
- Both sides use same reliability mode
- Durability is compatible (writer >= reader)
- Topic and type names match exactly

## Next Steps

- [Key Instance](../examples/key-instance.md) - Per-instance reliability
- [Deadline QoS](../guides/qos-policies/deadline.md) - Timing requirements
- [Liveliness](../guides/qos-policies/liveliness.md) - Failure detection
