// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! SPDP/SEDP discovery protocol implementation.
//!
//! Handles participant and endpoint discovery via RTPS discovery messages.

pub mod endpoints;
pub mod fragment_buffer;
pub mod guid;
pub mod matcher;
pub mod multicast;
pub mod participant;
pub mod replay;
pub mod seen_table;
// v61: Service-request builtin endpoints - MIGRATED to protocol/dialect/rti/handshake.rs
pub mod spdp_announcer;

use std::fmt;

pub use endpoints::EndpointRegistry;
pub use fragment_buffer::FragmentBuffer;
pub use guid::GUID;
pub use matcher::Matcher;
pub use participant::{Discovery, NetPeer};
pub use replay::{ReplayRegistry, ReplayToken};
pub use seen_table::SeenTable;
pub use spdp_announcer::SpdpAnnouncer;

/// Result alias for discovery-related operations.
pub type DiscoveryResult<T> = Result<T, DiscoveryError>;

/// Discovery subsystem error categorisation.
#[derive(Debug, Clone)]
pub enum DiscoveryError {
    /// Requested participant not present in registry/database.
    ParticipantNotFound { guid: String },
    /// Parsing or decoding failed.
    ParseFailed { reason: String },
    /// Underlying network interaction failed.
    NetworkFailed { reason: String },
    /// RwLock/Mutex poisoned but recovered.
    RegistryPoisoned { context: String },
    /// Generic invalid data or invariant violation.
    InvalidData { reason: String },
    /// Catch-all for other discovery errors.
    OperationFailed { reason: String },
}

impl fmt::Display for DiscoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DiscoveryError::ParticipantNotFound { guid } => {
                write!(f, "Participant not found: {}", guid)
            }
            DiscoveryError::ParseFailed { reason } => write!(f, "Parse failed: {}", reason),
            DiscoveryError::NetworkFailed { reason } => write!(f, "Network failed: {}", reason),
            DiscoveryError::RegistryPoisoned { context } => {
                write!(f, "Registry poisoned, recovered: {}", context)
            }
            DiscoveryError::InvalidData { reason } => write!(f, "Invalid data: {}", reason),
            DiscoveryError::OperationFailed { reason } => write!(f, "Operation failed: {}", reason),
        }
    }
}

impl std::error::Error for DiscoveryError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_discovery_error_display_variants() {
        let err = DiscoveryError::ParticipantNotFound {
            guid: "GUID:001".into(),
        };
        assert_eq!(
            crate::core::string_utils::format_string(format_args!("{}", err)),
            "Participant not found: GUID:001"
        );

        let err = DiscoveryError::ParseFailed {
            reason: "bad SPDP".into(),
        };
        assert_eq!(
            crate::core::string_utils::format_string(format_args!("{}", err)),
            "Parse failed: bad SPDP"
        );

        let err = DiscoveryError::RegistryPoisoned {
            context: "ParticipantDB".into(),
        };
        assert_eq!(
            crate::core::string_utils::format_string(format_args!("{}", err)),
            "Registry poisoned, recovered: ParticipantDB"
        );

        let err = DiscoveryError::NetworkFailed {
            reason: "socket error".into(),
        };
        assert_eq!(
            crate::core::string_utils::format_string(format_args!("{}", err)),
            "Network failed: socket error"
        );

        let err = DiscoveryError::OperationFailed {
            reason: "timeout".into(),
        };
        assert_eq!(
            crate::core::string_utils::format_string(format_args!("{}", err)),
            "Operation failed: timeout"
        );
    }
}
