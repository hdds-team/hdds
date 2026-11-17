// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! HDDS InfluxDB Sink
//!
//! Bridges DDS topics to InfluxDB v2 Line Protocol format.
//!
//! This crate provides:
//! - YAML-based configuration for topic-to-measurement mapping
//! - InfluxDB v2 Line Protocol generation
//! - Field mapping from JSON DDS samples to tags/fields
//! - Batching with size and time-based flushing
//! - Downsampling via configurable sample rates
//!
//! # Overview
//!
//! ```text
//! DDS Sample (JSON) --> FieldMapper --> LineProtocolWriter --> BatchBuffer
//!                   --> InfluxHttpClient --> POST /api/v2/write
//! ```
//!
//! [`InfluxHttpClient`] is a small HTTP/1.1 client on `std::net::TcpStream`:
//! no HTTP crate, no async runtime. It fails closed - an `https://` URL
//! without the `tls` feature is refused instead of downgraded, a refused
//! token stops the client, and a 5xx keeps the batch.

pub mod buffer;
pub mod config;
pub mod http;
pub mod influx;
pub mod mapping;
pub mod recorder;
#[cfg(feature = "hdds")]
pub mod runner;

pub use config::SinkConfig;
pub use http::{Endpoint, InfluxError, InfluxHttpClient, WriteOutcome};
pub use influx::LineProtocolWriter;
pub use recorder::DdsSink;

#[cfg(feature = "hdds")]
pub use runner::{RunnerError, SinkRunner};
