// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! # HDDS Sample: WaitSets
//!
//! Demonstrates **condition-based event handling** using WaitSets - efficient
//! blocking on multiple conditions without polling.
//!
//! ## WaitSet Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                           WaitSet                                   │
//! │  ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐       │
//! │  │  SensorReader   │ │  CommandReader  │ │  GuardCondition │       │
//! │  │  (data avail)   │ │  (data avail)   │ │  (shutdown sig) │       │
//! │  └────────┬────────┘ └────────┬────────┘ └────────┬────────┘       │
//! │           │                   │                   │                │
//! │           └───────────────────┼───────────────────┘                │
//! │                               ▼                                    │
//! │                    waitset.wait(timeout)                           │
//! │                               │                                    │
//! │                               ▼                                    │
//! │              Returns when ANY condition triggers                   │
//! └─────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Condition Types
//!
//! | Condition Type    | Triggers When                    | Use Case           |
//! |-------------------|----------------------------------|--------------------|
//! | Reader attachment | Data available on DataReader     | Data processing    |
//! | GuardCondition    | Application calls trigger()      | Shutdown, events   |
//! | StatusCondition   | Entity status changes            | Discovery, errors  |
//!
//! ## Event Loop Pattern
//!
//! ```rust
//! while running {
//!     if waitset.wait(timeout)? {
//!         // One or more conditions triggered
//!         while let Some(data) = sensor_reader.take()? {
//!             process_sensor(&data);
//!         }
//!         while let Some(cmd) = command_reader.take()? {
//!             handle_command(&cmd);
//!         }
//!     }
//! }
//! ```
//!
//! ## Use Cases
//!
//! - **Multi-topic processing**: Wait on multiple readers efficiently
//! - **Event-driven**: React to data arrival instead of polling
//! - **Graceful shutdown**: Use GuardCondition for clean exit
//!
//! ## Running the Sample
//!
//! ```bash
//! # Terminal 1 - Subscriber (uses WaitSet for multiple topics)
//! cargo run --bin waitsets
//!
//! # Terminal 2 - Publisher (sends to both topics)
//! cargo run --bin waitsets -- pub
//! ```

use std::env;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

// =============================================================================
// Generated Types
// =============================================================================
//
// Types are generated from IDL files using hdds_gen.

#[allow(dead_code)]
mod generated {
    include!("../../generated/waitset_types.rs");
}

use generated::Message;

fn print_waitset_overview() {
    println!("--- WaitSet Overview ---\n");
    println!("WaitSet Architecture:\n");
    println!("  +---------------------------------------------+");
    println!("  |               WaitSet                       |");
    println!("  |  +-----------+ +-----------+ +-----------+  |");
    println!("  |  | Reader A  | | Reader B  | | GuardCond |  |");
    println!("  |  | (Sensors) | | (Commands)| | (Shutdown)|  |");
    println!("  |  +-----------+ +-----------+ +-----------+  |");
    println!("  +---------------------------------------------+");
    println!("                    |");
    println!("                    v");
    println!("              wait(timeout)");
    println!("                    |");
    println!("                    v");
    println!("           Returns true if any");
    println!("           condition triggered");
    println!();
    println!("Condition Types:");
    println!("  - Reader attachment: Data available on reader");
    println!("  - GuardCondition: Application-triggered signal");
    println!();
}

fn run_publisher(participant: &Arc<hdds::Participant>) -> Result<(), hdds::Error> {
    println!("[Publisher] Creating writers for multiple topics...");

    let sensor_writer =
        participant.create_writer::<Message>("SensorTopic", hdds::QoS::default())?;
    let command_writer =
        participant.create_writer::<Message>("CommandTopic", hdds::QoS::default())?;

    println!("[Publisher] Publishing to SensorTopic and CommandTopic...\n");

    for i in 0..5 {
        // Publish sensor data
        let sensor_msg = Message::new("SensorTopic", i * 2, format!("Sensor reading {}", i));
        sensor_writer.write(&sensor_msg)?;
        println!(
            "  [SENT] Sensor: seq={}, '{}'",
            sensor_msg.sequence, sensor_msg.content
        );

        thread::sleep(Duration::from_millis(100));

        // Publish command
        let cmd_msg = Message::new("CommandTopic", i * 2 + 1, format!("Command {}", i));
        command_writer.write(&cmd_msg)?;
        println!(
            "  [SENT] Command: seq={}, '{}'",
            cmd_msg.sequence, cmd_msg.content
        );

        thread::sleep(Duration::from_millis(300));
    }

    println!("\n[Publisher] Done publishing.");
    Ok(())
}

fn run_subscriber(participant: &Arc<hdds::Participant>) -> Result<(), hdds::Error> {
    println!("[Subscriber] Creating readers and WaitSet...\n");

    // Create readers for multiple topics
    let sensor_reader =
        participant.create_reader::<Message>("SensorTopic", hdds::QoS::default())?;
    let command_reader =
        participant.create_reader::<Message>("CommandTopic", hdds::QoS::default())?;

    // Create WaitSet and attach readers via their status conditions
    let waitset = hdds::WaitSet::new();
    waitset.attach(&sensor_reader)?;
    waitset.attach(&command_reader)?;

    println!("[OK] SensorTopic reader attached to WaitSet");
    println!("[OK] CommandTopic reader attached to WaitSet");

    // Create a guard condition for shutdown signaling
    let shutdown_guard = Arc::new(hdds::GuardCondition::new());
    waitset.attach_condition(shutdown_guard.clone())?;
    println!("[OK] Shutdown GuardCondition attached to WaitSet\n");

    // Shared flag to simulate shutdown trigger
    let running = Arc::new(AtomicBool::new(true));
    let running_clone = running.clone();

    // Spawn a thread that will trigger shutdown after some time
    let shutdown_guard_clone = shutdown_guard.clone();
    thread::spawn(move || {
        thread::sleep(Duration::from_secs(8));
        println!("\n[SIGNAL] Triggering shutdown via GuardCondition...");
        running_clone.store(false, Ordering::SeqCst);
        shutdown_guard_clone.set_trigger_value(true);
    });

    println!("--- WaitSet Event Loop ---\n");
    println!("Waiting for data on multiple topics...");
    println!("(Shutdown will be triggered after 8 seconds)\n");

    let mut sensor_count = 0u32;
    let mut command_count = 0u32;
    let mut timeout_count = 0u32;

    while running.load(Ordering::SeqCst) {
        match waitset.wait(Some(Duration::from_secs(2))) {
            Ok(triggered) => {
                if !triggered.is_empty() {
                    // Check sensor reader
                    while let Some(msg) = sensor_reader.take()? {
                        sensor_count += 1;
                        println!(
                            "  [SENSOR #{}] seq={}, '{}'",
                            sensor_count, msg.sequence, msg.content
                        );
                    }

                    // Check command reader
                    while let Some(msg) = command_reader.take()? {
                        command_count += 1;
                        println!(
                            "  [COMMAND #{}] seq={}, '{}'",
                            command_count, msg.sequence, msg.content
                        );
                    }
                }
            }
            Err(hdds::Error::WouldBlock) => {
                timeout_count += 1;
                println!("  (timeout #{} - no data available)", timeout_count);
            }
            Err(e) => {
                eprintln!("Wait error: {:?}", e);
                break;
            }
        }
    }

    println!("\n--- WaitSet Summary ---");
    println!("Sensor messages received: {}", sensor_count);
    println!("Command messages received: {}", command_count);
    println!("Timeouts: {}", timeout_count);

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let is_publisher = args.get(1).map(|s| s == "pub").unwrap_or(false);

    println!("{}", "=".repeat(60));
    println!("HDDS WaitSets Sample");
    println!("{}", "=".repeat(60));
    println!();

    print_waitset_overview();

    let participant = hdds::Participant::builder("WaitSetDemo")
        .with_transport(hdds::TransportMode::IntraProcess)
        .build()?;
    println!("[OK] Participant created\n");

    if is_publisher {
        run_publisher(&participant)?;
    } else {
        run_subscriber(&participant)?;
    }

    // Event loop pattern code example
    println!("\n--- Event Loop Pattern (Code Example) ---\n");
    println!("  while running {{");
    println!("      if waitset.wait(timeout)? {{");
    println!("          // Check each reader for data");
    println!("          while let Some(data) = reader1.take()? {{");
    println!("              process_data(&data);");
    println!("          }}");
    println!("          while let Some(data) = reader2.take()? {{");
    println!("              handle_command(&data);");
    println!("          }}");
    println!("      }}");
    println!("  }}");

    // Best practices
    println!("\n--- WaitSet Best Practices ---");
    println!("1. Use one WaitSet per processing thread");
    println!("2. Prefer WaitSets over polling for efficiency");
    println!("3. Use GuardConditions for inter-thread signaling");
    println!("4. Set appropriate timeouts for responsiveness");
    println!("5. Process all available data before waiting again");
    println!("6. Detach readers before dropping them");

    println!("\n=== Sample Complete ===");
    Ok(())
}
