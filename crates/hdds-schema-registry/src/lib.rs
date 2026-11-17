// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Schema Registry for DDS type management.
//!
//! Provides centralized schema storage, versioning, and compatibility checking
//! for DDS topic types. Inspired by Confluent Schema Registry but tailored
//! for DDS/XTypes semantics.
//!
//! # Features
//!
//! - **Schema storage**: Register and retrieve type schemas by name and version
//! - **Compatibility checking**: Validate schema evolution against DDS XTypes rules
//!   (FULL, BACKWARD, FORWARD, NONE compatibility levels)
//! - **Persistence**: JSON files on disk, one per schema version
//! - **HTTP server**: REST API for schema operations (feature `server`)
//!
//! # Architecture
//!
//! ```text
//! Producers/Consumers
//!        |
//!        v
//!   SchemaRegistry (in-memory cache)
//!        |
//!        v
//!   FilePersistence ({dir}/{schema}/v{n}.json)
//! ```
//!
//! There is no SQLite backend: persistence is JSON files, which is what
//! `persistence.rs` implements and all that is claimed here.

pub mod compatibility;
#[cfg(feature = "dds")]
pub mod distribution;
#[cfg(feature = "server")]
pub mod http;
pub mod persistence;
pub mod registry;
pub mod server;

pub use compatibility::{check_compatibility, Compatibility, CompatibilityResult};
pub use persistence::FilePersistence;
pub use registry::{RegistryError, SchemaEntry, SchemaFormat, SchemaRegistry};
pub use server::SchemaRegistryApi;

#[cfg(feature = "server")]
pub use http::{router, ServerState};

#[cfg(feature = "dds")]
pub use distribution::{SchemaAnnouncer, SchemaSubscriber, SCHEMA_TOPIC};
