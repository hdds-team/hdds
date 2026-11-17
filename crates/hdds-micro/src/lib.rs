// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! # HDDS Micro - Embedded DDS for Microcontrollers
//!
//! A `no_std` implementation of DDS (Data Distribution Service) for resource-constrained
//! embedded systems such as ESP32, RP2040, and STM32 microcontrollers.
//!
//! ## Design Constraints
//!
//! - **Flash**: < 100 KB (target: 60-80 KB)
//! - **RAM**: < 50 KB (target: 30-40 KB)
//! - **No heap allocations** in core (const generics for fixed buffers)
//! - **No floating point** (embedded-friendly)
//! - **`no_std` compatible**
//!
//! ## Architecture
//!
//! ```text
//! +-----------------------------------------+
//! |  Application (User Code)                |
//! +-----------------------------------------+
//!           v                    ^
//! +-----------------------------------------+
//! |  MicroParticipant / MicroWriter / Reader|
//! +-----------------------------------------+
//!           v                    ^
//! +-----------------------------------------+
//! |  RTPS Lite (Header, Submessages)        |
//! +-----------------------------------------+
//!           v                    ^
//! +-----------------------------------------+
//! |  CDR Micro (Encoder/Decoder)            |
//! +-----------------------------------------+
//!           v                    ^
//! +-----------------------------------------+
//! |  Transport (WiFi UDP / LoRa / Serial)   |
//! +-----------------------------------------+
//! ```
//!
//! ## Perimeter -- who this crate talks to
//!
//! **hdds-micro speaks to HDDS participants.** It is not a general-purpose
//! RTPS stack, and it does not claim conformance against an arbitrary vendor.
//! That is a scope decision, not an omission: the budget at the top of this
//! page is what it buys.
//!
//! What follows from it, stated rather than left to be inferred from the
//! code, because a claim carries its perimeter and this one had none written:
//!
//! - Submessage BODY fields are read little-endian only
//!   (`Data`/`Heartbeat`/`AckNack`). HDDS emits little-endian, so within the
//!   perimeter that is exact.
//! - Submessage HEADERS are NOT in that scope: their `octetsToNextHeader` is
//!   read and written in the endianness the E flag of that same submessage
//!   declares (RTPS v2.5 Sec.8.3.3.3). Framing decides where a submessage
//!   ENDS, so getting it wrong does not mis-read one message, it derails the
//!   walk over all of them.
//! - Sample bodies are classic CDR, XCDR1, little endian (`cdr` module).
//!   `MicroWriter` puts them behind a `CDR_LE` SerializedPayloadHeader
//!   (RTPS v2.5 Sec.10.2); `MicroReader` hands out the body and the
//!   identifier, and `Sample::decoder` refuses a body that is not XCDR1
//!   little endian. A full HDDS writer encodes every sample in the one
//!   representation it offers, resolved when it is created and whatever it
//!   has matched (this crate runs no discovery): XCDR1 when its QoS names
//!   XCDR, or names nothing and its type encodes XCDR1 natively
//!   (`#[derive(DDS)]`, the Rust `hdds_gen` emits); XCDR2 otherwise (a
//!   writer of the C ABI or of a type that does not say it encodes XCDR1),
//!   whose samples `Sample::decoder` refuses.
//! - A sample this crate cannot read is REFUSED, never delivered as a
//!   partially-decoded one. That is what makes the first bullet defensible
//!   rather than dangerous, and it is pinned by
//!   `core::reader::tests::a_big_endian_peers_sample_is_refused_not_read_as_noise`.
//!
//! **The gateway is the exception, and it is not a small one.** Its socket
//! joins a MULTICAST group, and a DDS multicast group carries every vendor's
//! traffic whatever this page says. So `gateway::Router` must stay correct on
//! packets from outside the perimeter - not because it serves them, but
//! because the decision it takes on a packet it misreads is a decision taken
//! anyway: an unreadable topic BYPASSES the topic filter and goes out over
//! the radio.
//!
//! ## Feature Flags
//!
//! - `esp32` -- ESP32-specific optimizations
//! - `rp2040` -- RP2040-specific optimizations
//! - `stm32` -- STM32-specific optimizations
//! - `wifi` -- `WiFi` UDP transport
//! - `lora` -- `LoRa` transport (SX1276/78)
//! - `alloc` -- Enable heap allocator
//! - `std` -- Enable std (for host testing)

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![warn(missing_docs)]

#[cfg(feature = "alloc")]
extern crate alloc;

/// RTPS Lite protocol implementation (types, header, submessages)
pub mod rtps;

/// CDR Micro encoder/decoder (fixed buffer, no allocations)
pub mod cdr;

/// Transport abstraction for WiFi, LoRa, Serial
pub mod transport;

/// Core DDS structs (MicroParticipant, MicroWriter, MicroReader)
pub mod core;

/// Error types for HDDS Micro
pub mod error;

/// LoRa <-> WiFi/UDP Gateway (requires `std` feature)
#[cfg(feature = "std")]
pub mod gateway;

// Re-exports for convenience
pub use crate::core::{MicroParticipant, MicroReader, MicroWriter, Next};
pub use crate::error::{Error, Result};
pub use crate::rtps::{EntityId, GuidPrefix, SequenceNumber};
pub use crate::transport::Transport;

/// Maximum packet size (MTU) for embedded environments
pub const MAX_PACKET_SIZE: usize = 1024;

/// Maximum number of samples in history cache
pub const MAX_HISTORY_DEPTH: usize = 16;

/// Version of HDDS Micro
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
