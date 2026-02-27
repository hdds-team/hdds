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
//! - **Persistence**: Optional durable storage for schema history
//! - **HTTP server**: REST API for schema operations (Confluent-compatible subset)
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
//!   Persistence (optional SQLite backend)
//! ```

pub mod registry;
pub mod compatibility;
pub mod persistence;
pub mod server;

pub use registry::{SchemaRegistry, SchemaEntry, SchemaFormat, RegistryError};
pub use compatibility::{Compatibility, CompatibilityResult, check_compatibility};
