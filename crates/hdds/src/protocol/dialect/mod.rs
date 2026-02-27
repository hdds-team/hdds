// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! RTPS Dialect Encoders
//!
//!
//! This module provides vendor-specific RTPS packet encoding to handle
//! interoperability quirks between different DDS implementations.
//!
//! # Supported Vendors
//!
//! | Vendor ID | Name | Status |
//! |-----------|------|--------|
//! | 0x0101 | RTI Connext DDS | Active (v6/7 interop) |
//! | 0x0102 | ADLINK OpenSplice | Feature-gated |
//! | 0x0103 | OpenDDS | Active |
//! | 0x0104 | Twin Oaks CoreDX | Feature-gated |
//! | 0x0105 | InterCOM DDS | Feature-gated |
//! | 0x010F | eProsima FastDDS | Active (v41 certified) |
//! | 0x0112 | Eclipse Cyclone DDS | Active |
//! | 0x0115 | GurumDDS | Feature-gated |
//! | 0x011A | Atostek Dust DDS | Feature-gated |
//!
//! # Architecture
//!
//! Each vendor has its own module implementing the `DialectEncoder` trait.
//! The `get_encoder()` factory returns the appropriate encoder based on
//! detected dialect.
//!
//! ```text
//! +-------------------------------------------------------------+
//! |                    DialectEncoder Trait                     |
//! +-------------------------------------------------------------+
//! | build_spdp()     build_sedp()      build_heartbeat()       |
//! | build_acknack()  build_gap()       build_data()            |
//! | build_data_frag() build_info_ts()  build_info_dst()        |
//! +-------------------------------------------------------------+
//!                              |
//!        +---------------------+---------------------+
//!        v                     v                     v
//! +-------------+       +-------------+       +-------------+
//! |  FastDDS    |       |    RTI      |       |   Hybrid    |
//! |  Encoder    |       |  Encoder    |       |  Encoder    |
//! |  (v41 cert) |       |  (planned)  |       |  (fallback) |
//! +-------------+       +-------------+       +-------------+
//! ```

pub mod common;
pub mod error;

// =============================================================================
// ARCHITECTURAL CONSTRAINT: Dialect Isolation
// =============================================================================
//
// All vendor dialect modules are PRIVATE. This is enforced by the compiler.
//
// The ONLY way to access dialect functionality from outside this module is
// through the public API:
//   - get_encoder(dialect) -> Box<dyn DialectEncoder>
//   - get_encoder_for_vendor(vendor_bytes) -> Box<dyn DialectEncoder>
//
// This prevents:
//   1. Cross-dialect imports (e.g., rti using fastdds internals)
//   2. External code depending on dialect implementation details
//   3. Accidental coupling between vendor implementations
//
// If you need shared RTPS encoding logic, use: crate::protocol::rtps
//
// =============================================================================

// Vendor-specific encoders - ALL PRIVATE (no pub)
#[cfg(feature = "dialect-coredx")]
mod coredx;
mod cyclone;
#[cfg(feature = "dialect-dust")]
mod dust;
mod fastdds;
#[cfg(feature = "dialect-gurum")]
mod gurum;
mod hdds;
mod hybrid;
#[cfg(feature = "dialect-intercom")]
mod intercom;
mod opendds;
#[cfg(feature = "dialect-opensplice")]
mod opensplice;
mod rti;

pub use error::{EncodeError, EncodeResult};

use std::net::SocketAddr;

#[allow(dead_code)]
struct UnsupportedDialectEncoder {
    name: &'static str,
    vendor: [u8; 2],
}

#[allow(dead_code)]
impl UnsupportedDialectEncoder {
    const fn new(name: &'static str, vendor: [u8; 2]) -> Self {
        Self { name, vendor }
    }

    fn unsupported<T>(&self) -> EncodeResult<T> {
        Err(EncodeError::UnsupportedDialect(self.name))
    }
}

impl DialectEncoder for UnsupportedDialectEncoder {
    fn build_spdp(
        &self,
        _participant_guid: &Guid,
        _unicast_locators: &[SocketAddr],
        _multicast_locators: &[SocketAddr],
        _lease_duration_sec: u32,
    ) -> EncodeResult<Vec<u8>> {
        self.unsupported()
    }

    fn build_sedp(&self, _data: &SedpEndpointData) -> EncodeResult<Vec<u8>> {
        self.unsupported()
    }

    fn build_heartbeat(
        &self,
        _reader_id: &[u8; 4],
        _writer_id: &[u8; 4],
        _first_sn: u64,
        _last_sn: u64,
        _count: u32,
    ) -> EncodeResult<Vec<u8>> {
        self.unsupported()
    }

    fn build_acknack(
        &self,
        _reader_id: &[u8; 4],
        _writer_id: &[u8; 4],
        _base_sn: u64,
        _bitmap: &[u32],
        _count: u32,
    ) -> EncodeResult<Vec<u8>> {
        self.unsupported()
    }

    fn build_gap(
        &self,
        _reader_id: &[u8; 4],
        _writer_id: &[u8; 4],
        _gap_start: u64,
        _gap_list_base: u64,
        _gap_bitmap: &[u32],
    ) -> EncodeResult<Vec<u8>> {
        self.unsupported()
    }

    fn build_data(
        &self,
        _reader_id: &[u8; 4],
        _writer_id: &[u8; 4],
        _sequence_number: u64,
        _payload: &[u8],
        _inline_qos: Option<&QosProfile>,
    ) -> EncodeResult<Vec<u8>> {
        self.unsupported()
    }

    fn build_data_frag(
        &self,
        _reader_id: &[u8; 4],
        _writer_id: &[u8; 4],
        _sequence_number: u64,
        _fragment_starting_num: u32,
        _fragments_in_submessage: u16,
        _data_size: u32,
        _fragment_size: u16,
        _payload: &[u8],
    ) -> EncodeResult<Vec<u8>> {
        self.unsupported()
    }

    fn build_info_ts(&self, _timestamp_sec: u32, _timestamp_frac: u32) -> Vec<u8> {
        Vec::new()
    }

    fn build_info_dst(&self, _guid_prefix: &[u8; 12]) -> Vec<u8> {
        Vec::new()
    }

    fn encode_unicast_locator(
        &self,
        _addr: &SocketAddr,
        _buf: &mut [u8],
        _offset: &mut usize,
    ) -> EncodeResult<()> {
        self.unsupported()
    }

    fn encode_multicast_locator(
        &self,
        _addr: &SocketAddr,
        _buf: &mut [u8],
        _offset: &mut usize,
    ) -> EncodeResult<()> {
        self.unsupported()
    }

    fn name(&self) -> &'static str {
        self.name
    }

    fn rtps_version(&self) -> (u8, u8) {
        (2, 4)
    }

    fn vendor_id(&self) -> [u8; 2] {
        self.vendor
    }

    fn requires_type_object(&self) -> bool {
        false
    }

    fn supports_xcdr2(&self) -> bool {
        false
    }

    fn fragment_size(&self) -> usize {
        1200
    }
}

/// Known DDS vendor IDs (RTPS spec + OMG registry)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum VendorId {
    /// Unknown vendor
    Unknown = 0x0000,
    /// RTI Connext DDS
    Rti = 0x0101,
    /// ADLINK OpenSplice DDS
    OpenSplice = 0x0102,
    /// OpenDDS (OCI)
    OpenDds = 0x0103,
    /// Twin Oaks CoreDX DDS
    CoreDx = 0x0104,
    /// InterCOM DDS
    InterCom = 0x0105,
    /// eProsima FastDDS (formerly Fast-RTPS)
    FastDds = 0x010F,
    /// Eclipse Cyclone DDS
    CycloneDds = 0x0110,
    /// GurumDDS (Gurum Networks)
    GurumDds = 0x0115,
    /// Dust DDS (Atostek)
    DustDds = 0x011A,
    /// HDDS (this implementation)
    Hdds = 0x01AA,
}

impl VendorId {
    /// Parse vendor ID from 2-byte array
    // @audit-ok: Simple pattern matching (cyclo 12, cogni 1) - vendor ID dispatch table
    pub fn from_bytes(bytes: [u8; 2]) -> Self {
        let val = u16::from_be_bytes(bytes);
        match val {
            0x0101 => Self::Rti,
            0x0102 => Self::OpenSplice,
            0x0103 => Self::OpenDds,
            0x0104 => Self::CoreDx,
            0x0105 => Self::InterCom,
            0x010F => Self::FastDds,
            0x0110 => Self::CycloneDds,
            0x0115 => Self::GurumDds,
            0x011A => Self::DustDds,
            0x01AA => Self::Hdds,
            _ => Self::Unknown,
        }
    }

    /// Convert to 2-byte array
    pub fn to_bytes(self) -> [u8; 2] {
        (self as u16).to_be_bytes()
    }

    /// Human-readable name
    // @audit-ok: Simple pattern matching (cyclo 12, cogni 1) - vendor name lookup table
    pub fn name(&self) -> &'static str {
        match self {
            Self::Unknown => "Unknown",
            Self::Rti => "RTI Connext DDS",
            Self::OpenSplice => "ADLINK OpenSplice",
            Self::OpenDds => "OpenDDS",
            Self::CoreDx => "Twin Oaks CoreDX",
            Self::InterCom => "InterCOM DDS",
            Self::FastDds => "eProsima FastDDS",
            Self::CycloneDds => "Eclipse Cyclone DDS",
            Self::GurumDds => "GurumDDS",
            Self::DustDds => "Dust DDS",
            Self::Hdds => "HDDS",
        }
    }
}

/// Detected RTPS dialect for encoding decisions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Dialect {
    /// eProsima FastDDS - certified v41
    FastDds = 0,
    /// RTI Connext DDS - requires specific PIDs
    Rti = 1,
    /// Eclipse Cyclone DDS
    CycloneDds = 2,
    /// OpenDDS
    OpenDds = 3,
    /// Twin Oaks CoreDX
    CoreDx = 4,
    /// InterCOM DDS
    InterCom = 5,
    /// ADLINK OpenSplice
    OpenSplice = 6,
    /// GurumDDS
    GurumDds = 7,
    /// Dust DDS
    DustDds = 8,
    /// HDDS talking to itself
    Hdds = 9,
    /// Safe fallback - conservative encoding
    Hybrid = 10,
}

impl Dialect {
    /// Map vendor ID to dialect
    // @audit-ok: Simple pattern matching (cyclo 12, cogni 1) - vendor to dialect mapping
    pub fn from_vendor(vendor: VendorId) -> Self {
        match vendor {
            VendorId::FastDds => Self::FastDds,
            VendorId::Rti => Self::Rti,
            VendorId::CycloneDds => Self::CycloneDds,
            VendorId::OpenDds => Self::OpenDds,
            VendorId::CoreDx => Self::CoreDx,
            VendorId::InterCom => Self::InterCom,
            VendorId::OpenSplice => Self::OpenSplice,
            VendorId::GurumDds => Self::GurumDds,
            VendorId::DustDds => Self::DustDds,
            VendorId::Hdds => Self::Hdds,
            VendorId::Unknown => Self::Hybrid,
        }
    }

    /// Reconstruct dialect from ordinal value (for atomic storage).
    ///
    /// Returns `None` if the ordinal is out of range.
    // @audit-ok: Simple pattern matching (cyclo 13, cogni 1) - ordinal to dialect mapping
    pub fn from_ordinal(ordinal: u8) -> Option<Self> {
        match ordinal {
            0 => Some(Self::FastDds),
            1 => Some(Self::Rti),
            2 => Some(Self::CycloneDds),
            3 => Some(Self::OpenDds),
            4 => Some(Self::CoreDx),
            5 => Some(Self::InterCom),
            6 => Some(Self::OpenSplice),
            7 => Some(Self::GurumDds),
            8 => Some(Self::DustDds),
            9 => Some(Self::Hdds),
            10 => Some(Self::Hybrid),
            _ => None,
        }
    }

    /// Dialect name for logging
    // @audit-ok: Simple pattern matching (cyclo 12, cogni 1) - dialect name lookup table
    pub fn name(&self) -> &'static str {
        match self {
            Self::FastDds => "FastDDS",
            Self::Rti => "RTI",
            Self::CycloneDds => "CycloneDDS",
            Self::OpenDds => "OpenDDS",
            Self::CoreDx => "CoreDX",
            Self::InterCom => "InterCOM",
            Self::OpenSplice => "OpenSplice",
            Self::GurumDds => "GurumDDS",
            Self::DustDds => "DustDDS",
            Self::Hdds => "HDDS",
            Self::Hybrid => "Hybrid",
        }
    }
}

/// GUID structure for RTPS entities
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Guid {
    pub prefix: [u8; 12],
    pub entity_id: [u8; 4],
}

/// SEDP endpoint data for building announcements
pub struct SedpEndpointData<'a> {
    pub endpoint_guid: Guid,
    pub participant_guid: Guid,
    pub topic_name: &'a str,
    pub type_name: &'a str,
    pub unicast_locators: &'a [SocketAddr],
    pub multicast_locators: &'a [SocketAddr],
    pub qos: Option<&'a QosProfile>,
    pub type_object: Option<&'a [u8]>,
}

/// QoS profile for endpoint announcements
#[derive(Debug, Clone, Default)]
pub struct QosProfile {
    pub reliability_kind: u32, // 1=BEST_EFFORT, 2=RELIABLE
    pub durability_kind: u32,  // 0=VOLATILE, 1=TRANSIENT_LOCAL, 2=TRANSIENT, 3=PERSISTENT
    pub history_kind: u32,     // 0=KEEP_LAST, 1=KEEP_ALL
    pub history_depth: u32,
    pub deadline_period_sec: u32,
    pub deadline_period_nsec: u32,
    pub liveliness_kind: u32, // 0=AUTOMATIC, 1=MANUAL_BY_PARTICIPANT, 2=MANUAL_BY_TOPIC
    pub liveliness_lease_sec: u32,
    pub liveliness_lease_nsec: u32,
    pub ownership_kind: u32, // 0=SHARED, 1=EXCLUSIVE
}

impl QosProfile {
    /// Check if any non-default policies are set (for inline QoS decision)
    pub fn has_non_default_policies(&self) -> bool {
        self.reliability_kind != 2  // default is RELIABLE
            || self.durability_kind != 0  // default is VOLATILE
            || self.history_kind != 0
            || self.history_depth != 1
    }
}

/// Complete RTPS dialect encoder trait
///
/// Each vendor implementation handles all protocol encoding quirks
/// specific to that DDS implementation.
pub trait DialectEncoder: Send + Sync {
    // ===== Discovery Protocol =====

    /// Build SPDP participant announcement
    fn build_spdp(
        &self,
        participant_guid: &Guid,
        unicast_locators: &[SocketAddr],
        multicast_locators: &[SocketAddr],
        lease_duration_sec: u32,
    ) -> EncodeResult<Vec<u8>>;

    /// Build SEDP endpoint announcement
    fn build_sedp(&self, data: &SedpEndpointData) -> EncodeResult<Vec<u8>>;

    // ===== Reliable Protocol Control =====

    /// Build HEARTBEAT submessage
    fn build_heartbeat(
        &self,
        reader_id: &[u8; 4],
        writer_id: &[u8; 4],
        first_sn: u64,
        last_sn: u64,
        count: u32,
    ) -> EncodeResult<Vec<u8>>;

    /// Decide Final flag for SEDP HEARTBEAT based on endpoint.
    /// - true = "don't respond if nothing to send" (prevents loops)
    /// - false = "please respond with your DATA" (solicits publication)
    ///
    /// Default: false (standard RTPS behavior)
    fn sedp_heartbeat_final(&self, writer_entity_id: &[u8; 4]) -> bool {
        let _ = writer_entity_id;
        false
    }

    /// Build ACKNACK submessage
    fn build_acknack(
        &self,
        reader_id: &[u8; 4],
        writer_id: &[u8; 4],
        base_sn: u64,
        bitmap: &[u32],
        count: u32,
    ) -> EncodeResult<Vec<u8>>;

    /// Build GAP submessage
    fn build_gap(
        &self,
        reader_id: &[u8; 4],
        writer_id: &[u8; 4],
        gap_start: u64,
        gap_list_base: u64,
        gap_bitmap: &[u32],
    ) -> EncodeResult<Vec<u8>>;

    // ===== User Data =====

    /// Build DATA submessage with user payload
    fn build_data(
        &self,
        reader_id: &[u8; 4],
        writer_id: &[u8; 4],
        sequence_number: u64,
        payload: &[u8],
        inline_qos: Option<&QosProfile>,
    ) -> EncodeResult<Vec<u8>>;

    /// Build DATA_FRAG submessage (fragmented data)
    #[allow(clippy::too_many_arguments)] // RTPS DATA_FRAG fields per spec
    fn build_data_frag(
        &self,
        reader_id: &[u8; 4],
        writer_id: &[u8; 4],
        sequence_number: u64,
        fragment_starting_num: u32,
        fragments_in_submessage: u16,
        data_size: u32,
        fragment_size: u16,
        payload: &[u8],
    ) -> EncodeResult<Vec<u8>>;

    // ===== Info Submessages =====

    /// Build INFO_TS (timestamp) submessage
    fn build_info_ts(&self, timestamp_sec: u32, timestamp_frac: u32) -> Vec<u8>;

    /// Build INFO_DST (destination) submessage
    fn build_info_dst(&self, guid_prefix: &[u8; 12]) -> Vec<u8>;

    // ===== Locators =====

    /// Encode unicast locator PID
    fn encode_unicast_locator(
        &self,
        addr: &SocketAddr,
        buf: &mut [u8],
        offset: &mut usize,
    ) -> EncodeResult<()>;

    /// Encode multicast locator PID
    fn encode_multicast_locator(
        &self,
        addr: &SocketAddr,
        buf: &mut [u8],
        offset: &mut usize,
    ) -> EncodeResult<()>;

    // ===== Metadata =====

    /// Dialect name (for logging/metrics)
    fn name(&self) -> &'static str;

    /// RTPS version advertised by this dialect
    fn rtps_version(&self) -> (u8, u8);

    /// Vendor ID bytes
    fn vendor_id(&self) -> [u8; 2];

    /// Whether this dialect requires TypeObject in SEDP
    fn requires_type_object(&self) -> bool;

    /// Whether this dialect supports XCDR2 encoding
    fn supports_xcdr2(&self) -> bool;

    /// Default fragment size (MTU - headers)
    fn fragment_size(&self) -> usize;

    /// Default QoS profile for this dialect.
    ///
    /// When a remote endpoint sends SEDP without explicit QoS PIDs,
    /// this method provides the vendor-specific defaults to apply.
    ///
    /// # Returns
    /// QoS profile with dialect-specific defaults (reliability, history, durability, etc.)
    fn default_qos(&self) -> crate::dds::qos::QoS {
        // DDS spec defaults: RELIABLE, VOLATILE, KEEP_LAST(1)
        crate::dds::qos::QoS::default()
    }

    // ===== Discovery Timing =====

    /// Whether to skip the SPDP barrier before sending SEDP announcements.
    ///
    /// Some DDS implementations have aggressive discovery timeouts and need
    /// SEDP DATA to be sent immediately after SPDP, without waiting for
    /// multiple SPDP rounds. This is particularly important for RTI Connext
    /// which reports "SampleLost" if SEDP arrives after its timeout (~3s).
    ///
    /// # Returns
    /// - `true`: Skip SPDP barrier (send SEDP immediately)
    /// - `false`: Wait for 3 SPDP rounds before sending SEDP (default)
    fn skip_spdp_barrier(&self) -> bool {
        false
    }

    /// Whether to send immediate SPDP unicast response upon peer discovery.
    ///
    /// v132: Some DDS implementations (notably RTI Connext) require an immediate
    /// SPDP unicast response BEFORE processing discovery HEARTBEATs. Without this,
    /// RTI waits for the next periodic SPDP (~200ms) instead of responding within ~1ms.
    ///
    /// FastDDS reference behavior (frames 11-12):
    /// - Frame 11: RTI sends SPDP multicast
    /// - Frame 12 (+0.5ms): FastDDS sends SPDP unicast to RTI (BEFORE HEARTBEATs!)
    /// - Frame 15-17: FastDDS sends discovery HEARTBEATs
    /// - Frame 18+: RTI responds immediately with ACKNACKs and DATA
    ///
    /// # Returns
    /// - `true`: Send immediate SPDP unicast to peer metatraffic_unicast locators
    /// - `false`: Rely on periodic SPDP announcements (default)
    fn requires_immediate_spdp_response(&self) -> bool {
        false
    }

    // ===== Discovery Handshake =====

    /// Build vendor-specific discovery handshake packets.
    ///
    /// Some DDS implementations (notably RTI) require a handshake protocol
    /// before SEDP discovery can proceed. This method returns the packets
    /// needed for that handshake, if any.
    ///
    /// # Arguments
    /// - `our_guid_prefix`: Our participant GUID prefix (12 bytes)
    /// - `peer_guid_prefix`: Remote participant GUID prefix (12 bytes)
    ///
    /// # Returns
    /// - `Some(packets)`: List of RTPS packets to send to the peer
    /// - `None`: No handshake required for this dialect
    ///
    /// # Example (RTI)
    /// RTI requires:
    /// 1. Service-request ACKNACK (builtin participant message)
    /// 2. SEDP Publications request ACKNACK
    fn build_discovery_handshake(
        &self,
        _our_guid_prefix: &[u8; 12],
        _peer_guid_prefix: &[u8; 12],
    ) -> Option<Vec<Vec<u8>>> {
        // Default: no handshake required
        None
    }

    /// Delay (in milliseconds) before sending SEDP after receiving SPDP.
    ///
    /// Some DDS implementations (notably OpenDDS) need time to set up their
    /// SEDP infrastructure after processing SPDP. If HDDS sends SEDP DATA
    /// too quickly, the remote implementation may not be ready to receive it.
    ///
    /// # OpenDDS Issue (v180)
    ///
    /// PCAP analysis of `opendds2hdds.pcap` shows:
    /// - Frame 15: OpenDDS sends SPDP DATA(p) at 1.25s
    /// - Frame 21: HDDS sends SEDP DATA(r) at 1.25s (+2.6ms) -> NOT PROCESSED
    /// - Frame 24: OpenDDS ACKNACKs show bitmapBase=1 (hasn't received DATA(r))
    /// - Frame 64: OpenDDS sends second SPDP at 4.43s
    /// - Frame 72: OpenDDS NOW shows bitmapBase=4 -> RECEIVED DATA(r) seqs 1-3!
    /// - Frame 74: OpenDDS sends DATA(w) at 4.53s (after 3s timeout)
    ///
    /// Root cause: OpenDDS needs ~100-200ms after receiving SPDP to set up
    /// its SEDP readers. HDDS sends SEDP within 2.6ms which is too fast.
    ///
    /// # Returns
    /// - Delay in milliseconds before sending SEDP DATA
    /// - Default: 0 (no delay)
    fn sedp_setup_delay_ms(&self) -> u64 {
        0
    }

    /// Whether this dialect requires re-announcing our DATA(r) after receiving peer's DATA(w).
    ///
    /// # OpenDDS Issue (v184)
    ///
    /// OpenDDS has a peculiar SEDP state machine that requires confirmation of our
    /// Reader endpoints AFTER it sends its Writer announcements. PCAP analysis shows:
    ///
    /// 1. HDDS sends DATA(r) seq=3,4 announcing our Reader
    /// 2. OpenDDS ACKs (bitmapBase=5, meaning seq 1-4 received)
    /// 3. OpenDDS sends DATA(w) announcing its Writer
    /// 4. HDDS retries DATA(r) with SAME seq=3,4 (per RTPS spec Sec.8.4.7.5)
    /// 5. OpenDDS drops these as duplicates -> never triggers PUBLICATION_MATCHED
    ///
    /// Solution: After receiving DATA(w), send a NEW DATA(r) with incremented
    /// sequence number. This acts as a "confirmation" that triggers OpenDDS
    /// to complete its matching state machine.
    ///
    /// # Returns
    /// - `true`: Re-announce our Readers with new seq numbers after receiving Writer
    /// - `false`: Standard behavior, no re-announcement needed (default)
    fn requires_sedp_reader_confirmation(&self) -> bool {
        false
    }

    /// Build ACKNACK confirmation for received SEDP DATA(w).
    ///
    /// # OpenDDS Issue (v186)
    ///
    /// Reference PCAP (reference.pcapng, OpenDDS <-> OpenDDS) shows:
    /// - Frame 11: Publisher sends DATA(w)
    /// - Frame 13: **Subscriber sends ACKNACK** (acknowledging the DATA)
    /// - Frame 14: Subscriber sends DATA(r)
    ///
    /// HDDS currently only sends ACKNACK in response to HEARTBEATs, not DATA.
    /// Without this ACKNACK, OpenDDS's reliable delivery state machine stalls.
    ///
    /// # Arguments
    /// - `our_guid_prefix`: Our participant GUID prefix (12 bytes)
    /// - `peer_guid_prefix`: Remote participant GUID prefix (12 bytes)
    /// - `writer_entity_id`: Entity ID of the writer that sent DATA(w)
    /// - `received_seq`: Sequence number of the received DATA
    ///
    /// # Returns
    /// - `Some(packet)`: Complete RTPS packet with ACKNACK to send
    /// - `None`: No confirmation needed for this dialect (default)
    fn build_sedp_data_confirmation(
        &self,
        _our_guid_prefix: &[u8; 12],
        _peer_guid_prefix: &[u8; 12],
        _writer_entity_id: &[u8; 4],
        _received_seq: i64,
    ) -> Option<Vec<u8>> {
        None
    }

    /// v188: Whether this dialect requires INFO_DST in SEDP re-announcements.
    ///
    /// # OpenDDS Issue
    ///
    /// OpenDDS ignores RTPS packets that don't have an INFO_DST submessage
    /// specifying the destination participant. When we re-announce our Reader
    /// endpoints (v187), we need to include INFO_DST for OpenDDS to process them.
    ///
    /// PCAP analysis shows:
    /// - Frame 1046 (normal DATA(r)): has INFO_DST, INFO_TS, DATA -> OpenDDS accepts
    /// - Frame 1052 (v187 DATA(r)): only INFO_TS, DATA -> OpenDDS ignores
    ///
    /// # Returns
    /// - `true`: Include INFO_DST with peer's GUID prefix in re-announcements
    /// - `false`: No INFO_DST needed (default for most dialects)
    fn requires_info_dst_for_reannouncement(&self) -> bool {
        false
    }

    /// v191: Submessage ordering preference for SEDP DATA packets.
    ///
    /// # OpenDDS Issue
    ///
    /// OpenDDS sends submessages in order: INFO_TS -> INFO_DST -> DATA
    /// HDDS was sending: INFO_DST -> INFO_TS -> DATA
    ///
    /// PCAP analysis shows OpenDDS never acknowledges HDDS's DATA(r) when
    /// the submessage order is different. This may be a bug in OpenDDS or
    /// a strict interpretation of RTPS spec ordering.
    ///
    /// # Returns
    /// - `true`: Send INFO_TS before INFO_DST (OpenDDS style)
    /// - `false`: Send INFO_DST before INFO_TS (default, HDDS/RTI style)
    fn info_ts_before_info_dst(&self) -> bool {
        false
    }
}

/// Get encoder for a specific dialect
// @audit-ok: Simple pattern matching (cyclo 12, cogni 1) - dialect encoder dispatch table
pub fn get_encoder(dialect: Dialect) -> Box<dyn DialectEncoder> {
    match dialect {
        Dialect::FastDds => Box::new(fastdds::FastDdsEncoder),
        Dialect::Rti => Box::new(rti::RtiEncoder),
        Dialect::CycloneDds => Box::new(cyclone::CycloneEncoder),
        Dialect::OpenDds => Box::new(opendds::OpenDdsEncoder),
        Dialect::CoreDx => {
            #[cfg(feature = "dialect-coredx")]
            {
                Box::new(coredx::CoreDxEncoder)
            }
            #[cfg(not(feature = "dialect-coredx"))]
            {
                Box::new(UnsupportedDialectEncoder::new(
                    "CoreDX",
                    VendorId::CoreDx.to_bytes(),
                ))
            }
        }
        Dialect::InterCom => {
            #[cfg(feature = "dialect-intercom")]
            {
                Box::new(intercom::InterComEncoder)
            }
            #[cfg(not(feature = "dialect-intercom"))]
            {
                Box::new(UnsupportedDialectEncoder::new(
                    "InterCOM",
                    VendorId::InterCom.to_bytes(),
                ))
            }
        }
        Dialect::OpenSplice => {
            #[cfg(feature = "dialect-opensplice")]
            {
                Box::new(opensplice::OpenSpliceEncoder)
            }
            #[cfg(not(feature = "dialect-opensplice"))]
            {
                Box::new(UnsupportedDialectEncoder::new(
                    "OpenSplice",
                    VendorId::OpenSplice.to_bytes(),
                ))
            }
        }
        Dialect::GurumDds => {
            #[cfg(feature = "dialect-gurum")]
            {
                Box::new(gurum::GurumEncoder)
            }
            #[cfg(not(feature = "dialect-gurum"))]
            {
                Box::new(UnsupportedDialectEncoder::new(
                    "GurumDDS",
                    VendorId::GurumDds.to_bytes(),
                ))
            }
        }
        Dialect::DustDds => {
            #[cfg(feature = "dialect-dust")]
            {
                Box::new(dust::DustEncoder)
            }
            #[cfg(not(feature = "dialect-dust"))]
            {
                Box::new(UnsupportedDialectEncoder::new(
                    "DustDDS",
                    VendorId::DustDds.to_bytes(),
                ))
            }
        }
        Dialect::Hdds => Box::new(hdds::HddsEncoder), // HDDS native RTPS 2.3 encoder
        Dialect::Hybrid => Box::new(hybrid::HybridEncoder),
    }
}

/// Get encoder from vendor ID bytes
pub fn get_encoder_for_vendor(vendor_bytes: [u8; 2]) -> Box<dyn DialectEncoder> {
    let vendor = VendorId::from_bytes(vendor_bytes);
    let dialect = Dialect::from_vendor(vendor);
    get_encoder(dialect)
}

// ===== Convenience Functions =====

/// Build SPDP using the appropriate dialect encoder.
///
/// This is the recommended way to build SPDP messages when the target
/// dialect is known (e.g., from dialect detection).
///
/// # Example
///
/// ```ignore
/// use crate::protocol::dialect::{build_spdp_for_dialect, Dialect, Guid};
///
/// let guid = Guid { prefix: [0x01; 12], entity_id: [0x00, 0x00, 0x01, 0xc1] };
/// let payload = build_spdp_for_dialect(
///     Dialect::FastDds,
///     &guid,
///     &unicast_locators,
///     &multicast_locators,
///     100,
/// )?;
/// ```
pub fn build_spdp_for_dialect(
    dialect: Dialect,
    participant_guid: &Guid,
    unicast_locators: &[SocketAddr],
    multicast_locators: &[SocketAddr],
    lease_duration_sec: u32,
) -> EncodeResult<Vec<u8>> {
    let encoder = get_encoder(dialect);
    encoder.build_spdp(
        participant_guid,
        unicast_locators,
        multicast_locators,
        lease_duration_sec,
    )
}

/// Build SEDP using the appropriate dialect encoder.
///
/// # Example
///
/// ```ignore
/// use crate::protocol::dialect::{build_sedp_for_dialect, Dialect, SedpEndpointData};
///
/// let payload = build_sedp_for_dialect(Dialect::FastDds, &sedp_data)?;
/// ```
pub fn build_sedp_for_dialect(dialect: Dialect, data: &SedpEndpointData) -> EncodeResult<Vec<u8>> {
    let encoder = get_encoder(dialect);
    encoder.build_sedp(data)
}

/// Check if a dialect encoder is implemented (not just a placeholder).
///
/// Returns true for FastDDS, RTI, OpenDDS, and Hybrid encoders.
pub fn is_dialect_implemented(dialect: Dialect) -> bool {
    matches!(
        dialect,
        Dialect::FastDds
            | Dialect::Rti
            | Dialect::OpenDds
            | Dialect::CycloneDds
            | Dialect::Hybrid
            | Dialect::Hdds
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vendor_id_roundtrip() {
        let vendors = [
            VendorId::Rti,
            VendorId::FastDds,
            VendorId::CycloneDds,
            VendorId::OpenDds,
        ];
        for v in vendors {
            let bytes = v.to_bytes();
            let parsed = VendorId::from_bytes(bytes);
            assert_eq!(v, parsed);
        }
    }

    #[test]
    fn test_dialect_from_vendor() {
        assert_eq!(Dialect::from_vendor(VendorId::FastDds), Dialect::FastDds);
        assert_eq!(Dialect::from_vendor(VendorId::Rti), Dialect::Rti);
        assert_eq!(Dialect::from_vendor(VendorId::Unknown), Dialect::Hybrid);
    }
}
