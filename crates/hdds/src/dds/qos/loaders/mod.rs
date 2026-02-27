// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! QoS profile loaders for XML and YAML formats.
//!
//! This module provides runtime loading of QoS policies from:
//! - Vendor XML files (FastDDS, RTI, Cyclone)
//! - YAML configuration files (HDDS native format)
//!
//! # Example
//!
//! ```rust,ignore
//! use hdds::dds::qos::loaders::{YamlLoader, ProfileLoader};
//!
//! // Load from YAML
//! let qos = YamlLoader::load_qos("qos_profiles.yaml", Some("reliable_sensor"))?;
//!
//! // Auto-detect format
//! let qos = ProfileLoader::load("config.yaml", Some("my_profile"))?;
//! ```

#[cfg(feature = "qos-loaders")]
pub mod fastdds;

#[cfg(feature = "qos-loaders")]
pub mod yaml;

#[cfg(feature = "qos-loaders")]
pub mod common;

#[cfg(feature = "qos-loaders")]
mod profile_loader;

#[cfg(feature = "qos-loaders")]
pub use fastdds::FastDdsLoader;

#[cfg(feature = "qos-loaders")]
pub use yaml::{YamlLoader, YamlQosDocument, YamlQosProfile};

#[cfg(feature = "qos-loaders")]
pub use profile_loader::ProfileLoader;
