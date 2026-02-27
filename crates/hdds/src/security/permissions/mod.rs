// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Dynamic Permissions module for DDS Security
//!
//! Provides runtime-reloadable permission rules that complement the static
//! XML-based access control (see `access` module). Permissions are loaded
//! from a simple text-based config file and can be hot-reloaded by polling
//! the file's modification time.
//!
//! # Architecture
//!
//! This module sits alongside the existing `access` module:
//!
//! ```text
//! security/
//! +-- access/          (static XML-based access control per DDS Security v1.1)
//! +-- permissions/     (dynamic file-based permissions with hot-reload)
//!     +-- dynamic.rs   (permission engine, parser, file watcher)
//! ```
//!
//! # Example
//!
//! ```ignore
//! use hdds::security::permissions::DynamicPermissionManager;
//! use std::time::Duration;
//!
//! let mgr = DynamicPermissionManager::new("permissions.txt".into())?;
//! mgr.start_watching(Duration::from_secs(5));
//!
//! if mgr.check_publish("CN=sensor,O=HDDS", "sensors/temp", "") {
//!     // publish allowed
//! }
//! ```

pub mod dynamic;

pub use dynamic::{
    DynamicPermissionManager, PermissionAuditEntry, PermissionChangeType, PermissionDocument,
    PermissionRule, PermissionSet, ReloadResult, RuleAction,
};

// Re-export the parser for testing/tooling
pub use dynamic::parse_permission_file;
