// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! SPDP Type Definitions
//!
//! Contains the core data structures used by SPDP parsing and building.
//! This includes the main SpdpData struct and CDR encapsulation constants.

use crate::core::discovery::GUID;
use std::net::SocketAddr;

// v111: Import CDR constants from canonical location
pub(super) use super::super::constants::{
    CDR2_BE, CDR2_LE, CDR_BE, CDR_BE_VENDOR, CDR_LE, CDR_LE_VENDOR,
};

/// SPDP (Simple Participant Discovery Protocol) parsed data.
///
/// This structure contains all participant metadata extracted from an SPDP announcement
/// according to DDS-RTPS v2.3 Sec.8.5.4 specification.
#[derive(Debug, Clone, PartialEq)]
pub struct SpdpData {
    pub participant_guid: GUID,
    pub lease_duration_ms: u64,
    /// v208: Domain ID for PID_DOMAIN_ID in SPDP announcements (RTPS v2.3 Table 8.73)
    pub domain_id: u32,
    /// v79: Metatraffic unicast locators (port 7410 - for SEDP/ACKNACK)
    pub metatraffic_unicast_locators: Vec<SocketAddr>,
    /// v79: Default unicast locators (port 7411 - for USER DATA) [MANDATORY per RTPS v2.3 Sec.8.5.3.1]
    pub default_unicast_locators: Vec<SocketAddr>,
    /// v79: Default multicast locators (for USER DATA multicast)
    pub default_multicast_locators: Vec<SocketAddr>,
    /// v79: Metatraffic multicast locators (port 7400 - for SPDP/SEDP multicast)
    pub metatraffic_multicast_locators: Vec<SocketAddr>,
    /// DDS Security v1.1: Identity token (X.509 certificate, PEM-encoded)
    ///
    /// Present when the remote participant is using DDS Security authentication.
    /// Contains the participant's identity certificate for validation.
    pub identity_token: Option<Vec<u8>>,
}
