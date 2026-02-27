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
pub use crate::core::{MicroParticipant, MicroReader, MicroWriter};
pub use crate::error::{Error, Result};
pub use crate::rtps::{EntityId, GuidPrefix, SequenceNumber};
pub use crate::transport::Transport;

/// Maximum packet size (MTU) for embedded environments
pub const MAX_PACKET_SIZE: usize = 1024;

/// Maximum number of samples in history cache
pub const MAX_HISTORY_DEPTH: usize = 16;

/// Version of HDDS Micro
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
