// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Logging Plugin SPI
//!
//! Tamper-evident audit trail for security events.
//!
//! # OMG DDS Security v1.1 Sec.8.6 (Logging)
//!
//! **Phase 1 Prep (Mode Nuit 2025-10-26):** Trait defined only

use super::SecurityError;

/// Logging plugin trait
///
/// Exports security events to syslog (RFC 5424) with optional hash-chain.
pub trait LoggingPlugin: Send + Sync {
    /// Log authentication event
    fn log_authentication(
        &self,
        participant_guid: &[u8],
        outcome: AuthenticationOutcome,
    ) -> Result<(), SecurityError>;

    /// Log access control decision
    fn log_access_control(
        &self,
        participant_guid: &[u8],
        action: &str,
        resource: &str,
        outcome: AccessOutcome,
    ) -> Result<(), SecurityError>;

    /// Log cryptographic event (key generation, encryption failure)
    fn log_crypto_event(&self, event: &str) -> Result<(), SecurityError>;
}

/// Authentication outcome for logging
#[derive(Debug, Clone, Copy)]
pub enum AuthenticationOutcome {
    Success,
    Failure,
}

/// Access control outcome for logging
#[derive(Debug, Clone, Copy)]
pub enum AccessOutcome {
    Allow,
    Deny,
}
