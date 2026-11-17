// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! SPDP Type Definitions
//!
//! Contains the core data structures used by SPDP parsing and building.
//! This includes the main SpdpData struct and CDR encapsulation constants.

use crate::core::discovery::GUID;
use std::net::SocketAddr;

// Import CDR constants from canonical location
pub(super) use super::super::constants::{
    CDR_BE, CDR_BE_VENDOR, CDR_LE, CDR_LE_VENDOR, PL_CDR2_BE, PL_CDR2_LE,
};

/// SPDP (Simple Participant Discovery Protocol) parsed data.
///
/// This structure contains all participant metadata extracted from an SPDP announcement
/// according to DDS-RTPS v2.3 Sec.8.5.4 specification.
#[derive(Debug, Clone, PartialEq)]
pub struct SpdpData {
    pub participant_guid: GUID,
    pub lease_duration_ms: u64,
    /// Domain ID for PID_DOMAIN_ID in SPDP announcements (RTPS v2.3 Table 8.73)
    pub domain_id: u32,
    /// Metatraffic unicast locators (port 7410 - for SEDP/ACKNACK)
    pub metatraffic_unicast_locators: Vec<SocketAddr>,
    /// Default unicast locators (port 7411 - for USER DATA) [MANDATORY per RTPS v2.3 Sec.8.5.3.1]
    pub default_unicast_locators: Vec<SocketAddr>,
    /// Default multicast locators (for USER DATA multicast)
    pub default_multicast_locators: Vec<SocketAddr>,
    /// Metatraffic multicast locators (port 7400 - for SPDP/SEDP multicast)
    pub metatraffic_multicast_locators: Vec<SocketAddr>,
    /// DDS Security v1.1 sec. 7.4.1.4: serialized `IdentityToken` DataHolder
    /// (PID 0x1001) carried on the wire as part of
    /// `ParticipantBuiltinTopicDataSecure`.
    pub identity_token: Option<Vec<u8>>,
    /// DDS Security v1.1 sec. 7.4.1.4: serialized `PermissionsToken` DataHolder
    /// (PID 0x1007) carried on the wire as part of
    /// `ParticipantBuiltinTopicDataSecure`.
    pub permissions_token: Option<Vec<u8>>,
    /// DDS-Security v1.1 Sec.7.4.1.4: `PID_PARTICIPANT_SECURITY_INFO`
    /// (0x1005), two u32 masks normalized to little-endian bytes when parsed.
    /// `None` defaults to two invalid masks for configuration matching.
    pub participant_security_info: Option<[u8; 8]>,
    /// RTPS `PID_VENDORID` (0x0016): the 2-byte vendor id advertised by the
    /// remote participant. Captured for per-vendor interop adaptation.
    pub vendor_id: Option<u16>,
    /// HDDS capability bitmask (`PID_HDDS_CAPABILITIES`, 0x8032): what this
    /// HDDS participant announces (local), or what the remote one announced
    /// (`None`: no such parameter, any vendor or an HDDS 1.4.x).
    pub hdds_capabilities: Option<u32>,
    /// `PID_BUILTIN_ENDPOINT_SET` (RTPS v2.5 Sec.8.5.3.1, Sec.9.3.2): the
    /// builtin endpoints the remote participant announced (`None`: no
    /// such parameter). Read on receive only: the endpoints this
    /// participant announces are its own and computed when it builds.
    pub builtin_endpoint_set: Option<u32>,
}
