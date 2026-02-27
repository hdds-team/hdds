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
        @key uint32 sensor_id;
        uint64 timestamp;
        float values[8];
    };

    // Command interface
    enum CommandType { MOVE, STOP, HOME, CALIBRATE };

    @topic
    struct Command {
        @key uint32 robot_id;
        uint64 sequence;
        CommandType cmd;
        float parameters[4];
    };

    // Status feedback
    enum RobotState { IDLE, BUSY, ERROR, MAINTENANCE };

    @topic
    struct Status {
        @key uint32 robot_id;
        RobotState state;
        float position[3];
        float battery;
    };

    // Alarm notifications
    enum AlarmSeverity { INFO, WARNING, CRITICAL };

    @topic
    struct Alarm {
        @key uint32 alarm_id;
        uint32 robot_id;
        AlarmSeverity severity;
        string<256> message;
        uint64 timestamp;
    };
};
```

## Multi-Topic Publisher

```rust title="src/robot_node.rs"
use hdds::{Participant, QoS, DDS, TransportMode, DataWriter, DataReader};
use robot::*;
use std::time::Duration;

struct RobotNode {
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
            state: RobotState::Idle,
            position: [0.0, 0.0, 0.0],
            battery: 85.0,
        };
        self.status_writer.write(&status)
    }

    fn publish_alarm(&self, robot_id: u32, msg: &str) -> Result<(), hdds::Error> {
        static ALARM_ID: std::sync::atomic::AtomicU32 =
            std::sync::atomic::AtomicU32::new(0);

        let alarm = Alarm {
            alarm_id: ALARM_ID.fetch_add(1, std::sync::atomic::Ordering::SeqCst),
            robot_id,
            severity: AlarmSeverity::Warning,
            message: msg.to_string(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64,
        };
        self.alarm_writer.write(&alarm)
    }

    fn process_commands(&mut self, robot_id: u32) -> Result<(), hdds::Error> {
        while let Some(cmd) = self.command_reader.try_take()? {
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

```rust title="src/monitor.rs"
use hdds::{Participant, QoS, DDS, TransportMode};
use robot::*;
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
    thread::spawn(move || {
        loop {
            while let Ok(Some(sample)) = sensor_reader.try_take() {
                tx1.send(Event::Sensor(sample)).ok();
            }
            thread::sleep(Duration::from_millis(1));
        }
    });

    let tx2 = tx.clone();
    let status_topic = participant.topic::<Status>("RobotStatus")?;
    let status_reader = status_topic
        .reader()
        .qos(QoS::reliable().keep_last(1).transient_local())
        .build()?;
    thread::spawn(move || {
        loop {
            while let Ok(Some(sample)) = status_reader.try_take() {
                tx2.send(Event::Status(sample)).ok();
            }
            thread::sleep(Duration::from_millis(10));
        }
    });

    let tx3 = tx.clone();
    let alarm_topic = participant.topic::<Alarm>("Alarms")?;
    let alarm_reader = alarm_topic
        .reader()
        .qos(QoS::reliable().keep_all().transient_local())
        .build()?;
    thread::spawn(move || {
        loop {
            while let Ok(Some(sample)) = alarm_reader.try_take() {
                tx3.send(Event::Alarm(sample)).ok();
            }
            thread::sleep(Duration::from_millis(10));
        }
    });

    // Unified event loop
    println!("Monitoring all topics...");
    for event in rx {
        match event {
            Event::Sensor(_s) => {
                // High volume, only log occasionally
            }
            Event::Status(s) => {
                println!("Robot {} status: {:?}, battery: {:.1}%",
                    s.robot_id, s.state, s.battery);
            }
            Event::Alarm(a) => {
                println!("[{:?}] Robot {}: {}",
                    a.severity, a.robot_id, a.message);
            }
        }
    }

    Ok(())
}
```

## Using Waitsets

For efficient multi-topic waiting:

```rust
use hdds::{Participant, QoS, TransportMode, WaitSet};
use std::time::Duration;

let participant = Participant::builder("app")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .build()?;

let sensor_topic = participant.topic::<SensorData>("SensorData")?;
let sensor_reader = sensor_topic.reader().qos(QoS::best_effort()).build()?;

let status_topic = participant.topic::<Status>("RobotStatus")?;
let status_reader = status_topic.reader().qos(QoS::reliable()).build()?;

let alarm_topic = participant.topic::<Alarm>("Alarms")?;
let alarm_reader = alarm_topic.reader().qos(QoS::reliable()).build()?;

let waitset = WaitSet::new()?;

// Attach read conditions
let sensor_condition = sensor_reader.read_condition()?;
let status_condition = status_reader.read_condition()?;
let alarm_condition = alarm_reader.read_condition()?;

waitset.attach(&sensor_condition)?;
waitset.attach(&status_condition)?;
waitset.attach(&alarm_condition)?;

loop {
    // Wait for any topic to have data
    let triggered = waitset.wait(Duration::from_secs(1))?;

    for condition in triggered {
        if condition == sensor_condition {
            // Process sensor data
        } else if condition == status_condition {
            // Process status
        } else if condition == alarm_condition {
            // Process alarms
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
let writer_qos = QoS::reliable().partition(&["zone_a", "sensors"]);
let reader_qos = QoS::reliable().partition(&["zone_*"]);  // Wildcard match
```

## QoS Profile Summary

| Topic Type | Reliability | Durability | History |
|------------|-------------|------------|---------|
| Sensor stream | BestEffort | Volatile | keep_last(1) |
| Commands | Reliable | Volatile | keep_all() |
| Status | Reliable | TransientLocal | keep_last(1) |
| Alarms | Reliable | TransientLocal | keep_all() |
| Configuration | Reliable | Persistent | keep_last(1) |

## Next Steps

- [Cross-Vendor](../examples/cross-vendor.md) - Interoperability example
- [Partitions](../guides/qos-policies/overview.md) - Topic filtering
- [WaitSets](../api.md) - Efficient multi-topic waiting
