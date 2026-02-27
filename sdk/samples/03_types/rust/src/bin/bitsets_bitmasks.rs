// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! # HDDS Sample: Bitsets and Bitmasks
//!
//! Demonstrates **bit-level** type support in DDS/IDL - efficient storage
//! for flags, permissions, and packed fields.
//!
//! ## Bitmask vs Bitset
//!
//! ```text
//! ┌───────────────────────────────────────────────────────────────────┐
//! │ Type     │ Purpose              │ IDL                 │ Rust      │
//! ├──────────┼──────────────────────┼─────────────────────┼───────────┤
//! │ Bitmask  │ Named bit flags      │ @bit_bound(8)       │ u8/u16/u32│
//! │          │ (OR-able)            │ bitmask Permissions │           │
//! ├──────────┼──────────────────────┼─────────────────────┼───────────┤
//! │ Bitset   │ Packed bit fields    │ bitset StatusFlags  │ Generated │
//! │          │ (struct of bits)     │ { bitfield<4> prio }│ struct    │
//! └───────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Bitmask Layout
//!
//! ```text
//! bitmask Permissions { READ, WRITE, EXECUTE, DELETE };
//!
//! Bit positions:
//! ┌─────────────────────────────────────────┐
//! │ 7 │ 6 │ 5 │ 4 │ 3    │ 2   │ 1    │ 0   │
//! │ - │ - │ - │ - │DELETE│EXEC │WRITE │READ │
//! └─────────────────────────────────────────┘
//!
//! Example: READ | WRITE | EXECUTE = 0b0111 = 0x07
//! ```
//!
//! ## Bitset Layout
//!
//! ```text
//! bitset StatusFlags {
//!     bitfield<4> priority;  // bits 0-3
//!     boolean active;        // bit 4
//!     boolean error;         // bit 5
//!     boolean warning;       // bit 6
//! };
//!
//! ┌────────────────────────────────────────────────┐
//! │ 7   │ 6      │ 5    │ 4     │ 3 │ 2 │ 1 │ 0   │
//! │ -   │warning │error │active │  priority (0-15)│
//! └────────────────────────────────────────────────┘
//! ```
//!
//! ## IDL Definition
//!
//! ```idl
//! @bit_bound(8)
//! bitmask Permissions {
//!     @position(0) READ,
//!     @position(1) WRITE,
//!     @position(2) EXECUTE,
//!     @position(3) DELETE
//! };
//!
//! bitset StatusFlags {
//!     bitfield<4> priority;  // 4-bit field (0-15)
//!     boolean active;
//!     boolean error;
//!     boolean warning;
//! };
//!
//! struct Bits {
//!     Permissions perms;
//!     StatusFlags flags;
//! };
//! ```
//!
//! ## Use Cases
//!
//! - **Permissions**: File/API access flags
//! - **Status bits**: Compact device status
//! - **Protocol headers**: Packed flag fields
//!
//! ## Running the Sample
//!
//! ```bash
//! # Terminal 1 - Subscriber
//! cargo run --bin bitsets_bitmasks
//!
//! # Terminal 2 - Publisher
//! cargo run --bin bitsets_bitmasks -- pub
//! ```

use std::env;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

// Include generated type
#[allow(dead_code)]
mod generated {
    include!("../../generated/bits.rs");
}

use generated::hdds_samples::{
    Bits, StatusFlags, PERMISSIONS_DELETE, PERMISSIONS_EXECUTE, PERMISSIONS_READ, PERMISSIONS_WRITE,
};

#[allow(clippy::useless_vec)]
fn run_publisher(participant: &Arc<hdds::Participant>) -> Result<(), hdds::Error> {
    println!("Creating writer...");
    let writer = participant.create_writer::<Bits>("BitsTopic", hdds::QoS::reliable())?;

    println!("Publishing bit samples...\n");

    let samples = vec![
        // READ + WRITE permissions, active status with priority 5
        Bits::builder()
            .perms(PERMISSIONS_READ | PERMISSIONS_WRITE)
            .flags(StatusFlags::zero().with_priority(5).with_active(1))
            .build()
            .expect("build"),
        // All permissions, error + warning flags
        Bits::builder()
            .perms(PERMISSIONS_READ | PERMISSIONS_WRITE | PERMISSIONS_EXECUTE | PERMISSIONS_DELETE)
            .flags(
                StatusFlags::zero()
                    .with_priority(15)
                    .with_error(1)
                    .with_warning(1),
            )
            .build()
            .expect("build"),
        // No permissions, no flags
        Bits::builder()
            .perms(0)
            .flags(StatusFlags::zero())
            .build()
            .expect("build"),
    ];

    for (i, data) in samples.iter().enumerate() {
        writer.write(data)?;
        println!("Published sample {}:", i);
        println!(
            "  perms: 0x{:02X} (R:{} W:{} X:{} D:{})",
            data.perms,
            if data.perms & PERMISSIONS_READ != 0 {
                "Y"
            } else {
                "N"
            },
            if data.perms & PERMISSIONS_WRITE != 0 {
                "Y"
            } else {
                "N"
            },
            if data.perms & PERMISSIONS_EXECUTE != 0 {
                "Y"
            } else {
                "N"
            },
            if data.perms & PERMISSIONS_DELETE != 0 {
                "Y"
            } else {
                "N"
            }
        );
        println!(
            "  flags: priority={}, active={}, error={}, warning={}",
            data.flags.priority(),
            data.flags.active(),
            data.flags.error(),
            data.flags.warning()
        );
        println!();
        thread::sleep(Duration::from_millis(500));
    }

    println!("Done publishing.");
    Ok(())
}

fn run_subscriber(participant: &Arc<hdds::Participant>) -> Result<(), hdds::Error> {
    println!("Creating reader...");
    let reader = participant.create_reader::<Bits>("BitsTopic", hdds::QoS::reliable())?;

    let status_condition = reader.get_status_condition();
    let waitset = hdds::dds::WaitSet::new();
    waitset.attach_condition(status_condition)?;

    println!("Waiting for bit samples...\n");

    let mut received = 0;
    while received < 3 {
        match waitset.wait(Some(Duration::from_secs(5))) {
            Ok(triggered) => {
                if !triggered.is_empty() {
                    while let Some(data) = reader.take()? {
                        received += 1;
                        println!("Received sample {}:", received);

                        // Decode permissions bitmask
                        let mut perms_str = Vec::new();
                        if data.perms & PERMISSIONS_READ != 0 {
                            perms_str.push("READ");
                        }
                        if data.perms & PERMISSIONS_WRITE != 0 {
                            perms_str.push("WRITE");
                        }
                        if data.perms & PERMISSIONS_EXECUTE != 0 {
                            perms_str.push("EXECUTE");
                        }
                        if data.perms & PERMISSIONS_DELETE != 0 {
                            perms_str.push("DELETE");
                        }

                        println!("  perms: [{}]", perms_str.join(" | "));

                        // Decode status flags bitset
                        println!("  flags:");
                        println!("    priority: {} (4-bit field)", data.flags.priority());
                        println!(
                            "    active:   {}",
                            if data.flags.active() != 0 {
                                "true"
                            } else {
                                "false"
                            }
                        );
                        println!(
                            "    error:    {}",
                            if data.flags.error() != 0 {
                                "true"
                            } else {
                                "false"
                            }
                        );
                        println!(
                            "    warning:  {}",
                            if data.flags.warning() != 0 {
                                "true"
                            } else {
                                "false"
                            }
                        );
                        println!();
                    }
                }
            }
            Err(hdds::Error::WouldBlock) => {
                println!("  (timeout - no data)");
            }
            Err(e) => {
                eprintln!("Wait error: {:?}", e);
            }
        }
    }

    println!("Done receiving.");
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let is_publisher = args.get(1).map(|s| s == "pub").unwrap_or(false);

    println!("{}", "=".repeat(60));
    println!("Bitsets and Bitmasks Demo");
    println!("Demonstrates: bitmask (permission flags), bitset (status fields)");
    println!("{}", "=".repeat(60));

    let participant = hdds::Participant::builder("BitsDemo")
        .with_transport(hdds::TransportMode::UdpMulticast)
        .build()?;

    if is_publisher {
        run_publisher(&participant)?;
    } else {
        run_subscriber(&participant)?;
    }

    Ok(())
}
