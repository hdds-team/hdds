// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! # HDDS Rust SDK
//!
//! **For Rust, the SDK _is_ the `hdds` crate.** Unlike C/C++/Python/TypeScript
//! which need FFI wrappers, Rust has direct access to the full HDDS API with
//! zero overhead. This crate simply re-exports `hdds` so the SDK examples
//! compile, and serves as documentation for Rust users.
//!
//! ## Quick Start
//!
//! Add `hdds` to your `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! hdds = "1.0"
//! ```
//!
//! ### Publisher
//!
//! ```rust,no_run
//! use hdds::{Participant, QoS};
//!
//! #[derive(hdds::DDS)]
//! struct SensorData {
//!     pub temperature: f32,
//!     pub humidity: f32,
//! }
//!
//! fn main() -> hdds::Result<()> {
//!     let participant = Participant::builder("sensor_pub")
//!         .domain_id(0)
//!         .build()?;
//!
//!     let writer = participant
//!         .topic::<SensorData>("sensors/environment")?
//!         .writer()
//!         .qos(QoS::reliable().transient_local())
//!         .build()?;
//!
//!     writer.write(&SensorData { temperature: 23.5, humidity: 65.0 })?;
//!     Ok(())
//! }
//! ```
//!
//! ### Subscriber
//!
//! ```rust,no_run
//! use hdds::{Participant, QoS};
//!
//! # #[derive(hdds::DDS)]
//! # struct SensorData { pub temperature: f32, pub humidity: f32 }
//! fn main() -> hdds::Result<()> {
//!     let participant = Participant::builder("sensor_sub")
//!         .domain_id(0)
//!         .build()?;
//!
//!     let reader = participant
//!         .topic::<SensorData>("sensors/environment")?
//!         .reader()
//!         .qos(QoS::reliable())
//!         .build()?;
//!
//!     if let Some(sample) = reader.take()? {
//!         println!("Temperature: {}C", sample.temperature);
//!     }
//!     Ok(())
//! }
//! ```
//!
//! ## Key Differences from Other SDKs
//!
//! | Feature | Other SDKs | Rust |
//! |---------|-----------|------|
//! | Type safety | Runtime type name matching | Compile-time via `#[derive(DDS)]` |
//! | Serialization | Manual `encode_cdr2_le()` | Automatic via `DDS` trait |
//! | Error handling | Exceptions / error codes | `Result<T>` with `?` operator |
//! | Resource cleanup | `close()` / `dispose()` | Automatic via `Drop` |
//! | QoS builder | Fluent API | Same fluent API, but type-checked |
//!
//! ## Why No Wrapper?
//!
//! A thin "SDK" wrapper over `hdds` would add a layer of indirection with no
//! benefit. Rust users get the full API surface including:
//!
//! - **`Participant::builder()`** — fluent participant configuration
//! - **`participant.topic::<T>(name)`** — type-safe topic/reader/writer builder
//! - **`#[derive(hdds::DDS)]`** — automatic CDR2 serialization + XTypes
//! - **`WaitSet`** — event-driven async reading
//! - **`QoS` presets** — `QoS::reliable()`, `QoS::best_effort()`, etc.
//! - **Raw API** — `create_raw_reader()` / `create_raw_writer()` for untyped access
//!
//! See the [`hdds` crate documentation](https://docs.rs/hdds) for the full API.

// Re-export the entire hdds crate
pub use hdds::*;
