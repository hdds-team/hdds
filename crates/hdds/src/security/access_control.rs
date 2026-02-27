// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Access Control Plugin SPI
//!
//! Fine-grained authorization using OMG Permissions XML.
//!
//! # OMG DDS Security v1.1 Sec.8.4 (Access Control)
//!
//! **Phase 1 Prep (Mode Nuit 2025-10-26):** Trait defined only

use super::SecurityError;

/// Access control plugin trait
///
/// Enforces permissions policy (Permissions XML) for topic/partition/action authorization.
pub trait AccessControlPlugin: Send + Sync {
    /// Check if participant creation is allowed
    fn check_create_participant(&self, domain_id: u32) -> Result<(), SecurityError>;

    /// Check if local writer creation is allowed
    fn check_create_writer(
        &self,
        topic: &str,
        partition: Option<&str>,
    ) -> Result<(), SecurityError>;

    /// Check if local reader creation is allowed
    fn check_create_reader(
        &self,
        topic: &str,
        partition: Option<&str>,
    ) -> Result<(), SecurityError>;

    /// Check if matching with remote writer is allowed
    fn check_remote_writer(&self, topic: &str) -> Result<(), SecurityError>;

    /// Check if matching with remote reader is allowed
    fn check_remote_reader(&self, topic: &str) -> Result<(), SecurityError>;
}
