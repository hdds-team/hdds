# Multi-Topic Example

Demonstrates handling multiple topics with different types in a single application.

## Overview

Real-world DDS applications typically work with multiple topics:
- Sensor data (high frequency, best effort)
- Commands (low frequency, reliable)
- Status updates (periodic, transient local)
- Alarms (sporadic, reliable + durable)

## IDL Definitions

```c title="RobotTypes.idl"
module robot {
    // High-frequency sensor data
    @topic
    struct SensorData {
        @key unsigned long sensor_id;
        unsigned long long timestamp;
        float values[8];
    };

    // Command interface
    enum CommandType { MOVE, STOP, HOME, CALIBRATE };

    @topic
    struct Command {
        @key unsigned long robot_id;
        unsigned long long seq_num;  // "sequence" is an IDL keyword
        CommandType cmd;
        float parameters[4];
    };

    // Status feedback
    enum RobotState { IDLE, BUSY, ERROR, MAINTENANCE };

    @topic
    struct Status {
        @key unsigned long robot_id;
        RobotState state;
        float position[3];
        float battery;
    };

    // Alarm notifications
    enum AlarmSeverity { INFO, WARNING, CRITICAL };

    @topic
    struct Alarm {
        @key unsigned long alarm_id;
        unsigned long robot_id;
        AlarmSeverity severity;
        string<256> message;
        unsigned long long timestamp;
    };
};
```

Generate the Rust types with `hddsgen` (built from the separate `hdds_gen`
repository: `git clone https://git.hdds.io/hdds/hdds_gen.git && cargo install --path hdds_gen`):

```bash
hddsgen gen rust RobotTypes.idl -o src/robot_types.rs
```

Declare the generated file as a module of the package. The programs below
refer to the package as `my_app`; use your own package name:

```rust title="src/lib.rs"
pub mod robot_types;
```

The IDL module `robot` becomes the Rust module `robot_types::robot`. Generated
enum variants keep the case used in the IDL (`RobotState::IDLE`).

## Multi-Topic Publisher

```rust title="src/bin/robot_node.rs"
use hdds::{DataReader, DataWriter, Participant, QoS, TransportMode};
use my_app::robot_types::robot::{
    Alarm, AlarmSeverity, Command, RobotState, SensorData, Status,
};
use std::sync::Arc;
use std::time::Duration;

struct RobotNode {
    // Keep the participant alive: discovery stops when it is dropped
    _participant: Arc<Participant>,
    sensor_writer: DataWriter<SensorData>,
    status_writer: DataWriter<Status>,
    alarm_writer: DataWriter<Alarm>,
    command_reader: DataReader<Command>,
}

impl RobotNode {
    fn new(domain_id: u32) -> Result<Self, hdds::Error> {
        let participant = Participant::builder("robot_node")
            .domain_id(domain_id)
            .with_transport(TransportMode::UdpMulticast)
            .build()?;

        // Sensor topic: high frequency, best effort
        let sensor_topic = participant.topic::<SensorData>("SensorData")?;
        let sensor_writer = sensor_topic
            .writer()
            .qos(QoS::best_effort().keep_last(1))
            .build()?;

        // Status topic: periodic, transient local for late joiners
        let status_topic = participant.topic::<Status>("RobotStatus")?;
        let status_writer = status_topic
            .writer()
            .qos(QoS::reliable().keep_last(1).transient_local())
            .build()?;

        // Alarm topic: reliable + durable for important events
        let alarm_topic = participant.topic::<Alarm>("Alarms")?;
        let alarm_writer = alarm_topic
            .writer()
            .qos(QoS::reliable().keep_all().transient_local())
            .build()?;

        // Command topic: reliable subscriber
        let command_topic = participant.topic::<Command>("Commands")?;
        let command_reader = command_topic
            .reader()
            .qos(QoS::reliable().keep_all())
            .build()?;

        Ok(Self {
            _participant: participant,
            sensor_writer,
            status_writer,
            alarm_writer,
            command_reader,
        })
    }

    fn run(&mut self, robot_id: u32) -> Result<(), hdds::Error> {
        let mut tick = 0u64;

        loop {
            // Publish sensor data at 100 Hz
            self.publish_sensors(robot_id, tick)?;

            // Publish status at 10 Hz
            if tick % 10 == 0 {
                self.publish_status(robot_id)?;
            }

            // Check for commands
            self.process_commands(robot_id)?;

            tick += 1;
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn publish_sensors(&self, sensor_id: u32, tick: u64) -> Result<(), hdds::Error> {
        let data = SensorData {
            sensor_id,
            timestamp: tick,
            values: [0.0; 8], // Actual sensor readings
        };
        self.sensor_writer.write(&data)
    }

    fn publish_status(&self, robot_id: u32) -> Result<(), hdds::Error> {
        let status = Status {
            robot_id,
            state: RobotState::IDLE,
            position: [0.0, 0.0, 0.0],
            battery: 85.0,
        };
        self.status_writer.write(&status)
    }

    fn publish_alarm(&self, robot_id: u32, msg: &str) -> Result<(), hdds::Error> {
        static ALARM_ID: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

        let alarm = Alarm {
            alarm_id: ALARM_ID.fetch_add(1, std::sync::atomic::Ordering::SeqCst),
            robot_id,
            severity: AlarmSeverity::WARNING,
            message: msg.to_string(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64,
        };
        self.alarm_writer.write(&alarm)
    }

    fn process_commands(&mut self, robot_id: u32) -> Result<(), hdds::Error> {
        while let Some(cmd) = self.command_reader.take()? {
            if cmd.robot_id == robot_id {
                println!("Received command: {:?}", cmd.cmd);
                // Execute command...
            }
        }
        Ok(())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut node = RobotNode::new(0)?;
    node.run(1)?;
    Ok(())
}
```

## Multi-Topic Subscriber (Monitoring)

```rust title="src/bin/monitor.rs"
use hdds::{Participant, QoS, TransportMode};
use my_app::robot_types::robot::{Alarm, SensorData, Status};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

enum Event {
    Sensor(SensorData),
    Status(Status),
    Alarm(Alarm),
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let participant = Participant::builder("monitor")
        .domain_id(0)
        .with_transport(TransportMode::UdpMulticast)
        .build()?;

    // Channel for unified event handling
    let (tx, rx) = mpsc::channel::<Event>();

    // Spawn reader threads for each topic
    let tx1 = tx.clone();
    let sensor_topic = participant.topic::<SensorData>("SensorData")?;
    let sensor_reader = sensor_topic
        .reader()
        .qos(QoS::best_effort().keep_last(1))
        .build()?;
    thread::spawn(move || loop {
        while let Ok(Some(sample)) = sensor_reader.take() {
            tx1.send(Event::Sensor(sample)).ok();
        }
        thread::sleep(Duration::from_millis(1));
    });

    let tx2 = tx.clone();
    let status_topic = participant.topic::<Status>("RobotStatus")?;
    let status_reader = status_topic
        .reader()
        .qos(QoS::reliable().keep_last(1).transient_local())
        .build()?;
    thread::spawn(move || loop {
        while let Ok(Some(sample)) = status_reader.take() {
            tx2.send(Event::Status(sample)).ok();
        }
        thread::sleep(Duration::from_millis(10));
    });

    let tx3 = tx.clone();
    let alarm_topic = participant.topic::<Alarm>("Alarms")?;
    let alarm_reader = alarm_topic
        .reader()
        .qos(QoS::reliable().keep_all().transient_local())
        .build()?;
    thread::spawn(move || loop {
        while let Ok(Some(sample)) = alarm_reader.take() {
            tx3.send(Event::Alarm(sample)).ok();
        }
        thread::sleep(Duration::from_millis(10));
    });

    // Unified event loop
    println!("Monitoring all topics...");
    for event in rx {
        match event {
            Event::Sensor(_s) => {
                // High volume, only log occasionally
            }
            Event::Status(s) => {
                println!(
                    "Robot {} status: {:?}, battery: {:.1}%",
                    s.robot_id, s.state, s.battery
                );
            }
            Event::Alarm(a) => {
                println!("[{:?}] Robot {}: {}", a.severity, a.robot_id, a.message);
            }
        }
    }

    Ok(())
}
```

## Using WaitSets

A `WaitSet` blocks until any of its conditions is triggered. Each reader has a
status condition; enabling `DATA_AVAILABLE` on it makes it trigger when the
reader has data. `wait` returns `Err(hdds::Error::WouldBlock)` when the timeout
expires with nothing triggered, and only one thread may block on a given
`WaitSet` at a time.

```rust title="src/bin/multi_waitset.rs"
use hdds::dds::{Condition, StatusMask};
use hdds::{Participant, QoS, TransportMode, WaitSet};
use my_app::robot_types::robot::{Alarm, SensorData, Status};
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let participant = Participant::builder("app")
        .domain_id(0)
        .with_transport(TransportMode::UdpMulticast)
        .build()?;

    let sensor_reader = participant
        .topic::<SensorData>("SensorData")?
        .reader()
        .qos(QoS::best_effort())
        .build()?;
    let status_reader = participant
        .topic::<Status>("RobotStatus")?
        .reader()
        .qos(QoS::reliable())
        .build()?;
    let alarm_reader = participant
        .topic::<Alarm>("Alarms")?
        .reader()
        .qos(QoS::reliable())
        .build()?;

    // One status condition per reader, triggered when data is available
    let sensor_cond = sensor_reader.get_status_condition();
    let status_cond = status_reader.get_status_condition();
    let alarm_cond = alarm_reader.get_status_condition();
    for cond in [&sensor_cond, &status_cond, &alarm_cond] {
        cond.set_enabled_statuses(StatusMask::DATA_AVAILABLE);
    }

    let waitset = WaitSet::new();
    waitset.attach_condition(sensor_cond.clone())?;
    waitset.attach_condition(status_cond.clone())?;
    waitset.attach_condition(alarm_cond.clone())?;

    loop {
        // Wait for any topic to have data
        let triggered = match waitset.wait(Some(Duration::from_secs(1))) {
            Ok(triggered) => triggered,
            Err(hdds::Error::WouldBlock) => continue, // timeout: nothing arrived
            Err(e) => return Err(e.into()),
        };

        for condition in triggered {
            let id = condition.condition_id();
            if id == sensor_cond.condition_id() {
                while let Some(_sample) = sensor_reader.take()? {
                    // Process sensor data
                }
            } else if id == status_cond.condition_id() {
                while let Some(_sample) = status_reader.take()? {
                    // Process status
                }
            } else if id == alarm_cond.condition_id() {
                while let Some(_sample) = alarm_reader.take()? {
                    // Process alarms
                }
            }
        }
    }
}
```

## Topic Organization Patterns

### By Function

```
/sensors/lidar
/sensors/camera
/sensors/imu
/control/commands
/control/feedback
/diagnostics/health
/diagnostics/alarms
```

### By Robot/Device

```
/robot_001/sensors
/robot_001/commands
/robot_002/sensors
/robot_002/commands
```

### Using Partitions

```rust
use hdds::QoS;

// Separate traffic with partitions
let writer_qos = QoS::reliable().add_partition("zone_a").add_partition("sensors");
let reader_qos = QoS::reliable().partition_single("zone_*"); // Wildcard match
```

## QoS Profile Summary

| Topic Type | Reliability | Durability | History |
|------------|-------------|------------|---------|
| Sensor stream | BestEffort | Volatile | keep_last(1) |
| Commands | Reliable | Volatile | keep_all() |
| Status | Reliable | TransientLocal | keep_last(1) |
| Alarms | Reliable | TransientLocal | keep_all() |

## Next Steps

- [Cross-Vendor](../examples/cross-vendor.md) - Interoperability example
- [Partitions](../guides/qos-policies/overview.md) - Topic filtering
- [WaitSets](../api/rust.md#waitset) - Efficient multi-topic waiting
