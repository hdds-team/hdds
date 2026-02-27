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
//! The sink does NOT perform HTTP requests to InfluxDB. It produces
//! Line Protocol strings that can be sent via any HTTP client.
//!
//! ```text
//! DDS Sample (JSON) --> FieldMapper --> LineProtocolWriter --> BatchBuffer --> Vec<String>
//! ```

pub mod buffer;
pub mod config;
pub mod influx;
pub mod mapping;
pub mod recorder;

pub use config::SinkConfig;
pub use influx::LineProtocolWriter;
pub use recorder::DdsSink;
