// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Local restriction overlay: hot-reloadable permission rules that can only
//! TAKE AWAY.
//!
//! Permission rules are read from a simple line-based file and re-read when
//! it changes. They sit on top of the static, S/MIME-signed access control of
//! the `access` module - they never replace it.
//!
//! # What this module is allowed to decide
//!
//! DDS-Security v1.1 section 9.4.1.3 makes the Permissions CA the root of
//! what a participant may do: the permissions document is signed, and that
//! signature is the whole reason anyone believes it. A plain file next to it,
//! unsigned and re-read on an mtime change, cannot be allowed to GRANT
//! anything - that would be a way around the chain of trust, reachable by
//! whoever can write one file.
//!
//! Narrowing needs no signature. Refusing more than you are permitted to
//! refuse is not a security property anyone has to defend, and it buys the
//! thing operators actually ask for: closing a topic on a running fleet
//! without reissuing and redistributing a signed XML document.
//!
//! So there are two doors into the same rules, and they read an unnamed
//! subject differently on purpose:
//!
//! - [`DynamicPermissionManager::check_publish`] /
//!   [`DynamicPermissionManager::check_subscribe`] - the engine standing
//!   alone, for a caller who has nothing else. An unnamed subject is denied.
//! - [`DynamicPermissionManager::check_local_restriction`] - the overlay
//!   door, which is what a `Participant` consults. An unnamed subject gets no
//!   restriction, because the signed document has already decided and this
//!   file said nothing about it.
//!
//! # Architecture
//!
//! ```text
//! security/
//! +-- access/          (signed XML access control per DDS Security v1.1 -- GRANTS)
//! +-- permissions/     (unsigned local overlay, hot-reloaded -- only REFUSES)
//!     +-- dynamic.rs   (permission engine, parser, file watcher)
//! ```
//!
//! # Configuring it on a participant
//!
//! ```ignore
//! let security = SecurityConfig::builder()
//!     // ... identity, CA, governance, signed permissions, permissions CA ...
//!     .permissions_overlay("/etc/hdds/local-restrictions.txt")
//!     .permissions_overlay_poll(Duration::from_secs(5))
//!     .build()?;
//! ```
//!
//! # Using the engine on its own
//!
//! ```ignore
//! use hdds::security::permissions::DynamicPermissionManager;
//! use std::time::Duration;
//!
//! let mgr = DynamicPermissionManager::new("permissions.txt".into())?;
//! mgr.start_watching(Duration::from_secs(5))?;
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
