// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! SHM Transport Policy and Selection
//!
//! This module provides policy-based transport selection for choosing between
//! SHM (Shared Memory) and UDP transport based on configuration and capabilities.
//!
//! # Policies
//!
//! - `Prefer`: Use SHM if same-host + BestEffort QoS, fallback to UDP otherwise
//! - `Require`: Force SHM usage, fail if conditions not met
//! - `Disable`: Always use UDP, even when SHM is available

use super::{can_use_shm_transport, host_id};

/// SHM transport selection policy
///
/// Controls how the transport layer chooses between SHM and UDP.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ShmPolicy {
    /// Prefer SHM when available, fallback to UDP otherwise (default)
    ///
    /// SHM is used when:
    /// - Same host (matching host_id)
    /// - Both endpoints use BestEffort QoS
    /// - Remote advertises SHM capability
    #[default]
    Prefer,

    /// Require SHM transport, fail if conditions not met
    ///
    /// Returns error if:
    /// - Different hosts
    /// - Reliable QoS (not supported by SHM)
    /// - Remote doesn't advertise SHM capability
    Require,

    /// Disable SHM, always use UDP
    ///
    /// Useful for:
    /// - Debugging transport issues
    /// - Cross-machine deployments
    /// - When SHM overhead isn't worth it
    Disable,
}

/// Selected transport type
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportSelection {
    /// Use shared memory transport
    Shm {
        /// Host ID for verification
        host_id: u32,
    },
    /// Use UDP transport
    Udp,
}

/// Error when transport selection fails
#[derive(Debug, Clone)]
pub enum TransportSelectionError {
    /// SHM required but not available (different host)
    DifferentHost { local: u32, remote: u32 },
    /// SHM required but QoS is Reliable
    ReliableQosNotSupported,
    /// SHM required but remote doesn't advertise capability
    RemoteNoShmCapability,
    /// SHM required but remote user_data is missing
    NoUserData,
}

impl std::fmt::Display for TransportSelectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DifferentHost { local, remote } => {
                write!(
                    f,
                    "SHM required but endpoints on different hosts (local={local:08x}, remote={remote:08x})"
                )
            }
            Self::ReliableQosNotSupported => {
                write!(f, "SHM transport does not support Reliable QoS")
            }
            Self::RemoteNoShmCapability => {
                write!(
                    f,
                    "SHM required but remote endpoint doesn't advertise SHM capability"
                )
            }
            Self::NoUserData => {
                write!(f, "SHM required but remote user_data is missing")
            }
        }
    }
}

impl std::error::Error for TransportSelectionError {}

/// Select transport based on policy and endpoint capabilities.
///
/// # Arguments
///
/// * `policy` - The configured SHM policy
/// * `remote_user_data` - Remote endpoint's user_data from SEDP (contains SHM info)
/// * `local_best_effort` - Whether local endpoint uses BestEffort QoS
/// * `remote_best_effort` - Whether remote endpoint uses BestEffort QoS
///
/// # Returns
///
/// * `Ok(TransportSelection)` - Selected transport type
/// * `Err(TransportSelectionError)` - If policy is `Require` and conditions not met
///
/// # Example
///
/// ```ignore
/// use hdds::transport::shm::{ShmPolicy, select_transport};
///
/// let selection = select_transport(
///     ShmPolicy::Prefer,
///     Some("shm=1;host_id=12345678;v=1"),
///     true,  // local BestEffort
///     true,  // remote BestEffort
/// );
/// ```
pub fn select_transport(
    policy: ShmPolicy,
    remote_user_data: Option<&str>,
    local_best_effort: bool,
    remote_best_effort: bool,
) -> Result<TransportSelection, TransportSelectionError> {
    match policy {
        ShmPolicy::Disable => Ok(TransportSelection::Udp),

        ShmPolicy::Prefer => {
            // Try SHM, fallback to UDP
            match can_use_shm_transport(remote_user_data, local_best_effort, remote_best_effort) {
                Some(host) => Ok(TransportSelection::Shm { host_id: host }),
                None => Ok(TransportSelection::Udp),
            }
        }

        ShmPolicy::Require => {
            // Check QoS first
            if !local_best_effort || !remote_best_effort {
                return Err(TransportSelectionError::ReliableQosNotSupported);
            }

            // Check user_data presence
            let user_data = remote_user_data.ok_or(TransportSelectionError::NoUserData)?;

            // Parse SHM capability
            let (remote_host, _version) = super::parse_shm_user_data(user_data)
                .ok_or(TransportSelectionError::RemoteNoShmCapability)?;

            // Check same host
            let local_host = host_id();
            if remote_host != local_host {
                return Err(TransportSelectionError::DifferentHost {
                    local: local_host,
                    remote: remote_host,
                });
            }

            Ok(TransportSelection::Shm {
                host_id: local_host,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn local_shm_user_data() -> String {
        format!("shm=1;host_id={:08x};v=1", host_id())
    }

    #[test]
    fn test_policy_default_is_prefer() {
        assert_eq!(ShmPolicy::default(), ShmPolicy::Prefer);
    }

    #[test]
    fn test_disable_always_udp() {
        let result = select_transport(ShmPolicy::Disable, Some(&local_shm_user_data()), true, true);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), TransportSelection::Udp);
    }

    #[test]
    fn test_prefer_uses_shm_when_available() {
        let result = select_transport(ShmPolicy::Prefer, Some(&local_shm_user_data()), true, true);
        assert!(result.is_ok());
        match result.unwrap() {
            TransportSelection::Shm { host_id: h } => assert_eq!(h, host_id()),
            TransportSelection::Udp => panic!("Expected SHM"),
        }
    }

    #[test]
    fn test_prefer_falls_back_to_udp_reliable() {
        let result = select_transport(
            ShmPolicy::Prefer,
            Some(&local_shm_user_data()),
            false, // Reliable
            true,
        );
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), TransportSelection::Udp);
    }

    #[test]
    fn test_prefer_falls_back_to_udp_different_host() {
        let result = select_transport(
            ShmPolicy::Prefer,
            Some("shm=1;host_id=deadbeef;v=1"), // Different host
            true,
            true,
        );
        assert!(result.is_ok());
        // Only UDP if we're not on host 0xdeadbeef
        if host_id() != 0xDEAD_BEEF {
            assert_eq!(result.unwrap(), TransportSelection::Udp);
        }
    }

    #[test]
    fn test_prefer_falls_back_to_udp_no_capability() {
        let result = select_transport(
            ShmPolicy::Prefer,
            Some("other=value"), // No SHM capability
            true,
            true,
        );
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), TransportSelection::Udp);
    }

    #[test]
    fn test_prefer_falls_back_to_udp_no_user_data() {
        let result = select_transport(ShmPolicy::Prefer, None, true, true);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), TransportSelection::Udp);
    }

    #[test]
    fn test_require_succeeds_when_available() {
        let result = select_transport(ShmPolicy::Require, Some(&local_shm_user_data()), true, true);
        assert!(result.is_ok());
        match result.unwrap() {
            TransportSelection::Shm { host_id: h } => assert_eq!(h, host_id()),
            TransportSelection::Udp => panic!("Expected SHM"),
        }
    }

    #[test]
    fn test_require_fails_reliable_qos() {
        let result = select_transport(
            ShmPolicy::Require,
            Some(&local_shm_user_data()),
            false, // Reliable
            true,
        );
        assert!(result.is_err());
        match result.unwrap_err() {
            TransportSelectionError::ReliableQosNotSupported => {}
            e => panic!("Expected ReliableQosNotSupported, got: {e:?}"),
        }
    }

    #[test]
    fn test_require_fails_different_host() {
        let result = select_transport(
            ShmPolicy::Require,
            Some("shm=1;host_id=deadbeef;v=1"),
            true,
            true,
        );
        // Only fails if we're not on host 0xdeadbeef
        if host_id() != 0xDEAD_BEEF {
            assert!(result.is_err());
            match result.unwrap_err() {
                TransportSelectionError::DifferentHost { local, remote } => {
                    assert_eq!(local, host_id());
                    assert_eq!(remote, 0xDEAD_BEEF);
                }
                e => panic!("Expected DifferentHost, got: {e:?}"),
            }
        }
    }

    #[test]
    fn test_require_fails_no_capability() {
        let result = select_transport(ShmPolicy::Require, Some("other=value"), true, true);
        assert!(result.is_err());
        match result.unwrap_err() {
            TransportSelectionError::RemoteNoShmCapability => {}
            e => panic!("Expected RemoteNoShmCapability, got: {e:?}"),
        }
    }

    #[test]
    fn test_require_fails_no_user_data() {
        let result = select_transport(ShmPolicy::Require, None, true, true);
        assert!(result.is_err());
        match result.unwrap_err() {
            TransportSelectionError::NoUserData => {}
            e => panic!("Expected NoUserData, got: {e:?}"),
        }
    }

    #[test]
    fn test_transport_selection_display() {
        let shm = TransportSelection::Shm {
            host_id: 0x12345678,
        };
        let udp = TransportSelection::Udp;

        assert_eq!(format!("{shm:?}"), "Shm { host_id: 305419896 }");
        assert_eq!(format!("{udp:?}"), "Udp");
    }

    #[test]
    fn test_error_display() {
        let e1 = TransportSelectionError::DifferentHost {
            local: 0x1111,
            remote: 0x2222,
        };
        assert!(e1.to_string().contains("different hosts"));

        let e2 = TransportSelectionError::ReliableQosNotSupported;
        assert!(e2.to_string().contains("Reliable QoS"));

        let e3 = TransportSelectionError::RemoteNoShmCapability;
        assert!(e3.to_string().contains("SHM capability"));

        let e4 = TransportSelectionError::NoUserData;
        assert!(e4.to_string().contains("user_data"));
    }
}
