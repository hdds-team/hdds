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
//! | 0x0101 | RTI Connext DDS | Active |
//! | 0x0102 | ADLINK OpenSplice | Feature-gated |
//! | 0x0103 | OpenDDS | Active |
//! | 0x0106 | Twin Oaks CoreDX | Feature-gated |
//! | 0x0105 | InterCOM DDS | Feature-gated |
//! | 0x010F | eProsima FastDDS | Active (v41 certified) |
//! | 0x0110 | Eclipse Cyclone DDS | Active |
//! | 0x0115 | GurumDDS | Feature-gated |
//! | 0x0114 | Dust DDS (S2E Software Systems) | Feature-gated |
//! | 0x011A | HDDS (this implementation) | Active |
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
//! |  (certified)|       |  (planned)  |       |  (fallback) |
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
// -----------------------------------------------------------------------------
// RUNTIME INVARIANT: Vendor Resolution Doctrine
// -----------------------------------------------------------------------------
//
// Vendor-specific behavior is a COLD-PATH concern:
//
//   1. Resolve the peer vendor ONCE at pairing time (SPDP/SEDP), from the
//      RTPS header vendorId or PID_VENDOR_ID.
//   2. Persist the decision as a per-peer flag on the participant/endpoint
//      record.
//   3. The data hot path reads that flag in O(1) and NEVER re-derives the
//      vendor per message: no `if vendorId == X` in per-sample code.
//   4. HDDS <-> HDDS is the reference path and must never traverse a vendor
//      branch; cross-vendor accommodations stay quarantined behind the
//      per-peer flag so the self path remains byte-clean and certifiable.
//
// Structural accommodations (accepting an unambiguous wire pattern that only
// one vendor emits, without checking who sent it) are preferred over vendorId
// checks in shared code: they are implicitly vendor-scoped and cost nothing
// for conforming peers.
//
// Deviations require maintainer sign-off and an entry in the exceptions list
// in docs/architecture.md (section 3.3, "Runtime invariant").
//
// =============================================================================

// Vendor-specific encoders - ALL PRIVATE (no pub)
pub(crate) mod close_gap;
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
pub(crate) mod retirement;
mod rti;
pub(crate) mod sequence_window;

pub use error::{EncodeError, EncodeResult};

use crate::protocol::discovery::types::TypeConsistencyEnforcement;
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
    /// Twin Oaks CoreDX DDS. OMG DDS Foundation RTPS vendor ID registry
    /// (https://www.dds-foundation.org/dds-rtps-vendor-and-product-ids/)
    /// assigns {0x01, 0x06} to "CoreDX DDS"; {0x01, 0x04} is "Mil-DDS", a
    /// different, unimplemented vendor. Confirmed against our own captures:
    /// a real CoreDX peer's RTPS header carries vendorId 0x0106 (verified
    /// with tshark on a capture of a CoreDX peer).
    CoreDx = 0x0106,
    /// InterCOM DDS
    InterCom = 0x0105,
    /// eProsima FastDDS (Fast-RTPS)
    FastDds = 0x010F,
    /// Eclipse Cyclone DDS
    CycloneDds = 0x0110,
    /// GurumDDS (Gurum Networks)
    GurumDds = 0x0115,
    /// Dust DDS (S2E Software Systems B.V.)
    DustDds = 0x0114,
    /// HDDS (this implementation). Official DDS Foundation assignment.
    Hdds = 0x011A,
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
            0x0105 => Self::InterCom,
            0x0106 => Self::CoreDx,
            0x010F => Self::FastDds,
            0x0110 => Self::CycloneDds,
            0x0115 => Self::GurumDds,
            0x0114 => Self::DustDds,
            0x011A => Self::Hdds,
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
    /// eProsima FastDDS - certified
    FastDds = 0,
    /// RTI Connext DDS (vendor id 0x0101) - dedicated PID set
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
    /// Application `UserDataQosPolicy` (DDS-RTPS Sec.9.6.2.2.1), carried into
    /// the standard PID_USER_DATA (0x002c) by whichever dialect encoder
    /// threads it through. Never an HDDS-internal capability hint -- see
    /// `hdds_shm_capability` below for that.
    pub user_data: Option<&'a str>,
    /// HDDS-proprietary SHM capability advertisement (e.g.
    /// "shm=1;host_id=XXXXXXXX;v=1"), carried into the HDDS vendor-specific
    /// `PID_HDDS_SHM_CAPABILITY` (0x8031), never into PID_USER_DATA. Only the
    /// HDDS dialect encoder (`dialect::hdds::HddsEncoder`) threads this into
    /// the wire frame it builds; every foreign-dialect encoder (FastDDS, RTI,
    /// CycloneDDS, Hybrid, ...) ignores this field so a proprietary
    /// capability hint never leaks onto a non-HDDS frame. This is the same
    /// cross-vendor isolation rule as the rest of the dialect layer: the
    /// vendor decision is made once, per encoder, not per PID.
    pub hdds_shm_capability: Option<&'a str>,
    /// True when this frame is addressed (unicast, via INFO_DST) to a peer
    /// whose GUID prefix carries the HDDS vendor id.
    ///
    /// Exists for exactly one reason: `hdds_shm_capability` has to reach an
    /// HDDS peer to be of any use, and the encoder chosen for an HDDS peer
    /// is NOT always the HDDS one -- the SEDP flush and retransmit paths
    /// encode with the Hybrid dialect even toward HDDS peers (same reason
    /// `emit_type_object_pid` exists). Without this flag the hint travels
    /// only on some copies, the pairing is resolved from whichever copy
    /// happens to arrive first, and shared memory is selected or not by a
    /// race.
    ///
    /// Gated on the DESTINATION rather than on the encoder so that a
    /// foreign vendor's bytes never change: a multicast frame (no
    /// destination) and every frame addressed to a non-HDDS peer leave this
    /// false, and the hint is omitted.
    pub hdds_peer_destination: bool,
    /// The EntityId of the endpoint's group, its Publisher or Subscriber
    /// (`SedpData::group_entity_id`): what PID_GROUP_GUID and
    /// PID_GROUP_ENTITY_ID name. `None`: the participant's default group for
    /// the endpoint's kind.
    pub group_entity_id: Option<[u8; 4]>,
    /// The local endpoint's TypeConsistencyEnforcement QoS policy. When present,
    /// dialect encoders MUST serialize this on the wire so that peers see the
    /// actual policy rather than a hardcoded permissive default. `None` falls
    /// back to the XTypes spec default (ALLOW_TYPE_COERCION, ignore bounds).
    pub type_consistency: Option<TypeConsistencyEnforcement>,
    /// Pre-computed `TypeInformation` (PID 0x0075) with populated
    /// `dependent_typeids`. When `Some`, the HDDS dialect encoder passes this
    /// through to `build_sedp` instead of re-deriving (which yields empty deps).
    /// The OpenDDS dialect encoder announces it too, through the same
    /// `protocol::discovery::sedp::build::announced_type_information`.
    /// Ignored by the other dialect encoders (FastDDS, Hybrid, RTI), which do
    /// not emit PID_TYPE_INFORMATION from this field.
    /// Only populated when feature `xtypes-structural-assignability` is active.
    #[cfg(feature = "xtypes-structural-assignability")]
    pub type_information: Option<crate::protocol::discovery::types::TypeInformation>,
    /// Emit PID_TYPE_OBJECT (0x0072) in the SEDP parameter list. HDDS encodes
    /// this PID with its INTERNAL `CompleteTypeObject` CDR2 layout (only HDDS
    /// peers decode it, see sedp/parse.rs), not the spec XTypes TypeObject a
    /// foreign reader would decode (a failed decode could yield
    /// INCONSISTENT_TOPIC). Set `false` for announcements targeting
    /// non-HDDS peers (gated on the destination GUID prefix vendor bytes in
    /// build_sedp_rtps_packet). PID_TYPE_INFORMATION (0x0075) is unaffected.
    pub emit_type_object_pid: bool,
}

#[cfg(feature = "xtypes")]
impl SedpEndpointData<'_> {
    /// The endpoint's own `CompleteTypeObject`, decoded from `type_object`
    /// (HDDS' CDR2 encoding of it, see `emit_type_object_pid`). `None` when
    /// the endpoint has no TypeObject.
    ///
    /// The bytes are OUR OWN previously-encoded TypeObject, so a decode
    /// failure means a local encode/decode mismatch, not a foreign peer
    /// sending garbage: logged at `error!` and answered `None` (the
    /// announcement goes out without the type parameters rather than not at
    /// all, which would cost the endpoint its match entirely). `dialect`
    /// names the encoder in that log line.
    pub(crate) fn decoded_type_object(
        &self,
        dialect: &str,
    ) -> Option<crate::xtypes::CompleteTypeObject> {
        use crate::Cdr2Decode;
        let bytes = self.type_object?;
        match crate::xtypes::CompleteTypeObject::decode_cdr2_le(bytes) {
            Ok((v, _)) => Some(v),
            Err(e) => {
                log::error!(
                    "[SEDP][{}] TypeObject decode failed for endpoint {:02x?}{:02x?} topic='{}' type='{}' ({} bytes): {}; type parameters omitted from this announcement",
                    dialect,
                    self.endpoint_guid.prefix,
                    self.endpoint_guid.entity_id,
                    self.topic_name,
                    self.type_name,
                    bytes.len(),
                    e
                );
                None
            }
        }
    }
}

/// An RTPS Duration_t (RTPS v2.5 Sec.9.3.2: `int32 seconds`, `uint32
/// fraction` in 2^-32 s) as it goes on the wire, little-endian: the
/// fraction rounded to the nearest 2^-32 s (100 ms is `0x1999_999A`), and a
/// duration of 0x7FFF_FFFF seconds or more is DURATION_INFINITE
/// (`0x7FFF_FFFF`, `0xFFFF_FFFF`).
#[must_use]
pub fn duration_t_le(duration: std::time::Duration) -> [u8; 8] {
    const INFINITE_SECONDS: u64 = 0x7FFF_FFFF;
    let (seconds, fraction) = if duration.as_secs() >= INFINITE_SECONDS {
        (0x7FFF_FFFFu32, 0xFFFF_FFFFu32)
    } else {
        let fraction = ((u64::from(duration.subsec_nanos()) << 32) + 500_000_000) / 1_000_000_000;
        (
            u32::try_from(duration.as_secs()).unwrap_or(0x7FFF_FFFF),
            u32::try_from(fraction).unwrap_or(u32::MAX),
        )
    };
    let mut wire = [0u8; 8];
    wire[..4].copy_from_slice(&seconds.to_le_bytes());
    wire[4..].copy_from_slice(&fraction.to_le_bytes());
    wire
}

/// Write PID_LIVELINESS (0x001b, RTPS v2.5 Table 9.12), little-endian:
/// LivelinessQosPolicy `{ kind; Duration_t lease_duration }`, AUTOMATIC 0,
/// MANUAL_BY_PARTICIPANT 1, MANUAL_BY_TOPIC 2; the endpoint's own policy,
/// AUTOMATIC with an INFINITE lease when it has none (`qos` absent).
pub(crate) fn write_liveliness_pid(
    qos: Option<&QosProfile>,
    buf: &mut [u8],
    offset: &mut usize,
) -> EncodeResult<()> {
    use crate::dds::qos::LivelinessKind;
    if *offset + 16 > buf.len() {
        return Err(error::EncodeError::BufferTooSmall);
    }
    let liveliness = qos.map_or_else(
        crate::dds::qos::Liveliness::infinite,
        QosProfile::liveliness,
    );
    let kind: u32 = match liveliness.kind {
        LivelinessKind::Automatic => 0,
        LivelinessKind::ManualByParticipant => 1,
        LivelinessKind::ManualByTopic => 2,
    };
    buf[*offset..*offset + 2].copy_from_slice(&0x001bu16.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&12u16.to_le_bytes());
    buf[*offset + 4..*offset + 8].copy_from_slice(&kind.to_le_bytes());
    buf[*offset + 8..*offset + 16].copy_from_slice(&duration_t_le(liveliness.lease_duration));
    *offset += 16;
    Ok(())
}

/// Write PID_LATENCY_BUDGET (0x0027, RTPS v2.5 Table 9.12), little-endian:
/// LatencyBudgetQosPolicy `{ Duration_t duration }`, the endpoint's own,
/// zero when it has none. With `only_if_set`, nothing for a zero budget,
/// the default a receiver applies to an absent PID.
pub(crate) fn write_latency_budget_pid(
    qos: Option<&QosProfile>,
    buf: &mut [u8],
    offset: &mut usize,
    only_if_set: bool,
) -> EncodeResult<()> {
    let budget = qos.map_or_else(
        crate::dds::qos::LatencyBudget::zero,
        QosProfile::latency_budget,
    );
    if only_if_set && budget.is_zero() {
        return Ok(());
    }
    if *offset + 12 > buf.len() {
        return Err(error::EncodeError::BufferTooSmall);
    }
    buf[*offset..*offset + 2].copy_from_slice(&0x0027u16.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&8u16.to_le_bytes());
    buf[*offset + 4..*offset + 12].copy_from_slice(&duration_t_le(budget.duration));
    *offset += 12;
    Ok(())
}

/// Write PID_PRESENTATION (0x0021, RTPS v2.5 Table 9.12), little-endian:
/// PresentationQosPolicy `{ access_scope; boolean coherent_access; boolean
/// ordered_access }`, INSTANCE 0, TOPIC 1, GROUP 2, the endpoint's own.
/// With `only_if_set`, nothing for the default (INSTANCE, neither access),
/// the value a receiver applies to an absent PID.
pub(crate) fn write_presentation_pid(
    qos: Option<&QosProfile>,
    buf: &mut [u8],
    offset: &mut usize,
    only_if_set: bool,
) -> EncodeResult<()> {
    let (scope, coherent, ordered) = qos.map_or((0, false, false), |q| {
        (
            q.presentation_access_scope,
            q.presentation_coherent,
            q.presentation_ordered,
        )
    });
    if only_if_set && scope == 0 && !coherent && !ordered {
        return Ok(());
    }
    if *offset + 12 > buf.len() {
        return Err(error::EncodeError::BufferTooSmall);
    }
    buf[*offset..*offset + 2].copy_from_slice(&0x0021u16.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&8u16.to_le_bytes());
    buf[*offset + 4..*offset + 8].copy_from_slice(&scope.to_le_bytes());
    buf[*offset + 8] = u8::from(coherent);
    buf[*offset + 9] = u8::from(ordered);
    buf[*offset + 10] = 0;
    buf[*offset + 11] = 0;
    *offset += 12;
    Ok(())
}

/// Write PID_DESTINATION_ORDER (0x0025, RTPS v2.5 Table 9.12),
/// little-endian: DestinationOrderQosPolicy `{ kind }`,
/// BY_RECEPTION_TIMESTAMP 0, BY_SOURCE_TIMESTAMP 1, the endpoint's own.
/// With `only_if_set`, nothing for BY_RECEPTION_TIMESTAMP, the default a
/// receiver applies to an absent PID.
pub(crate) fn write_destination_order_pid(
    qos: Option<&QosProfile>,
    buf: &mut [u8],
    offset: &mut usize,
    only_if_set: bool,
) -> EncodeResult<()> {
    let by_source = qos.is_some_and(|q| q.destination_order().uses_source_timestamp());
    if only_if_set && !by_source {
        return Ok(());
    }
    if *offset + 8 > buf.len() {
        return Err(error::EncodeError::BufferTooSmall);
    }
    buf[*offset..*offset + 2].copy_from_slice(&0x0025u16.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&4u16.to_le_bytes());
    buf[*offset + 4..*offset + 8].copy_from_slice(&u32::from(by_source).to_le_bytes());
    *offset += 8;
    Ok(())
}

/// QoS profile for endpoint announcements
#[derive(Debug, Clone)]
pub struct QosProfile {
    pub reliability_kind: u32, // 1=BEST_EFFORT, 2=RELIABLE
    /// RELIABILITY max_blocking_time (DDS v1.4 Sec.2.2.3.14), announced in
    /// PID_RELIABILITY; `None` announces the dialect's default.
    pub reliability_max_blocking_time: Option<std::time::Duration>,
    pub durability_kind: u32, // 0=VOLATILE, 1=TRANSIENT_LOCAL, 2=TRANSIENT, 3=PERSISTENT
    pub history_kind: u32,    // 0=KEEP_LAST, 1=KEEP_ALL
    pub history_depth: u32,
    pub deadline_period_sec: u32,
    pub deadline_period_nsec: u32,
    pub liveliness_kind: u32, // 0=AUTOMATIC, 1=MANUAL_BY_PARTICIPANT, 2=MANUAL_BY_TOPIC
    /// LIVELINESS lease_duration seconds; 0x7FFF_FFFF / 0xFFFF_FFFF =
    /// INFINITE (the default).
    pub liveliness_lease_sec: u32,
    /// LIVELINESS lease_duration nanoseconds (below 10^9 unless INFINITE).
    pub liveliness_lease_nsec: u32,
    /// LATENCY_BUDGET duration (DDS v1.4 Sec.2.2.3.8), seconds and
    /// nanoseconds; zero by default.
    pub latency_budget_sec: u32,
    pub latency_budget_nsec: u32,
    /// DESTINATION_ORDER kind (DDS v1.4 Sec.2.2.3.17):
    /// 0=BY_RECEPTION_TIMESTAMP (default), 1=BY_SOURCE_TIMESTAMP.
    pub destination_order_kind: u32,
    pub ownership_kind: u32,     // 0=SHARED, 1=EXCLUSIVE
    pub ownership_strength: i32, // Only meaningful when ownership_kind=1 (EXCLUSIVE)
    pub partition_names: Vec<String>,
    pub data_representation: Vec<u16>, // 0x0000=XCDR1, 0x0002=XCDR2; empty=default(both)
    // Lifespan: 0x7FFF_FFFF / 0xFFFF_FFFF = INFINITE (default)
    pub lifespan_sec: u32,
    pub lifespan_nsec: u32,
    // Presentation (DDS v1.4 Sec.2.2.3.6): 0=INSTANCE, 1=TOPIC, 2=GROUP
    pub presentation_access_scope: u32,
    pub presentation_coherent: bool,
    pub presentation_ordered: bool,
    // TIME_BASED_FILTER minimum_separation as RTPS Duration_t.
    // Both fields zero = filter disabled (default). When non-zero, the reader
    // has TIME_BASED_FILTER enabled and advertises the real minimum_separation
    // so that remote publishers know to throttle data delivery.
    // RTPS v2.5 sec. 9.3.2: fraction is 2^-32 seconds (NOT nanoseconds).
    pub minimum_separation_sec: u32,
    pub minimum_separation_frac: u32,
}

impl Default for QosProfile {
    /// Every field zero, empty or `None`, but LIVELINESS: AUTOMATIC with an
    /// INFINITE lease, its DDS v1.4 Sec.2.2.3 default (a zero lease would
    /// announce an endpoint whose liveliness expires at once).
    fn default() -> Self {
        Self {
            reliability_kind: 0,
            reliability_max_blocking_time: None,
            durability_kind: 0,
            history_kind: 0,
            history_depth: 0,
            deadline_period_sec: 0,
            deadline_period_nsec: 0,
            liveliness_kind: 0,
            liveliness_lease_sec: 0x7FFF_FFFF,
            liveliness_lease_nsec: 0xFFFF_FFFF,
            latency_budget_sec: 0,
            latency_budget_nsec: 0,
            destination_order_kind: 0,
            ownership_kind: 0,
            ownership_strength: 0,
            partition_names: Vec::new(),
            data_representation: Vec::new(),
            lifespan_sec: 0,
            lifespan_nsec: 0,
            presentation_access_scope: 0,
            presentation_coherent: false,
            presentation_ordered: false,
            minimum_separation_sec: 0,
            minimum_separation_frac: 0,
        }
    }
}

/// A duration as the profile's `(seconds, nanoseconds)` pair: INFINITE
/// (0x7FFF_FFFF, 0xFFFF_FFFF) for one of 0x7FFF_FFFF seconds or more.
pub(crate) fn profile_duration(duration: std::time::Duration) -> (u32, u32) {
    match u32::try_from(duration.as_secs()) {
        Ok(secs) if secs < 0x7FFF_FFFF => (secs, duration.subsec_nanos()),
        _ => (0x7FFF_FFFF, 0xFFFF_FFFF),
    }
}

/// The profile's `(seconds, nanoseconds)` pair as a duration, INFINITE as
/// `Duration::from_secs(u64::MAX)` (the policies' infinite,
/// `Liveliness::infinite`).
fn duration_of_profile(sec: u32, nsec: u32) -> std::time::Duration {
    if sec >= 0x7FFF_FFFF {
        std::time::Duration::from_secs(u64::MAX)
    } else {
        std::time::Duration::new(u64::from(sec), nsec.min(999_999_999))
    }
}

impl QosProfile {
    /// The LIVELINESS this profile announces (an unknown kind as
    /// AUTOMATIC).
    pub(crate) fn liveliness(&self) -> crate::dds::qos::Liveliness {
        use crate::dds::qos::LivelinessKind;
        let kind = match self.liveliness_kind {
            1 => LivelinessKind::ManualByParticipant,
            2 => LivelinessKind::ManualByTopic,
            _ => LivelinessKind::Automatic,
        };
        crate::dds::qos::Liveliness::new(
            kind,
            duration_of_profile(self.liveliness_lease_sec, self.liveliness_lease_nsec),
        )
    }

    /// The LATENCY_BUDGET this profile announces.
    pub(crate) fn latency_budget(&self) -> crate::dds::qos::LatencyBudget {
        crate::dds::qos::LatencyBudget::new(duration_of_profile(
            self.latency_budget_sec,
            self.latency_budget_nsec,
        ))
    }

    /// The DESTINATION_ORDER this profile announces (an unknown kind as
    /// BY_RECEPTION_TIMESTAMP).
    pub(crate) fn destination_order(&self) -> crate::dds::qos::DestinationOrder {
        match self.destination_order_kind {
            1 => crate::dds::qos::DestinationOrder::by_source_timestamp(),
            _ => crate::dds::qos::DestinationOrder::by_reception_timestamp(),
        }
    }

    /// The DDS QoS this profile announces, for the dialect encoders that
    /// write their SEDP with the generic builder
    /// (`protocol::discovery::sedp::build`): one reading, so two dialects
    /// never announce one endpoint with two QoS.
    pub(crate) fn to_qos(&self) -> crate::dds::qos::QoS {
        use crate::dds::qos::QoS;
        let q = self;
        let base = match q.reliability_kind {
            1 => QoS::best_effort(),
            _ => QoS::reliable(),
        };
        let base = match q.reliability_max_blocking_time {
            Some(max_blocking_time) => base.max_blocking_time(max_blocking_time),
            None => base,
        };
        let with_durability = match q.durability_kind {
            0 => base.volatile(),
            2 => base.transient(),
            3 => base.persistent(),
            _ => base.transient_local(),
        };
        let with_history = match q.history_kind {
            1 => with_durability.keep_all(),
            _ => with_durability.keep_last(q.history_depth),
        };
        // Ownership
        let with_ownership = match q.ownership_kind {
            1 => with_history
                .ownership_exclusive()
                .ownership_strength(q.ownership_strength),
            _ => with_history.ownership_shared(),
        };
        // Deadline
        let with_deadline =
            if q.deadline_period_sec == 0x7FFF_FFFF && q.deadline_period_nsec == 0xFFFF_FFFF {
                with_ownership // infinite deadline (default)
            } else {
                let millis = (q.deadline_period_sec as u64) * 1000
                    + (q.deadline_period_nsec as u64) / 1_000_000;
                with_ownership.deadline_millis(millis)
            };
        // Lifespan
        let with_lifespan = if q.lifespan_sec == 0x7FFF_FFFF && q.lifespan_nsec == 0xFFFF_FFFF
            || (q.lifespan_sec == 0 && q.lifespan_nsec == 0)
        {
            with_deadline // infinite lifespan (default)
        } else {
            let millis = (q.lifespan_sec as u64) * 1000 + (q.lifespan_nsec as u64) / 1_000_000;
            with_deadline.lifespan_millis(millis)
        };
        // Presentation
        let mut result = with_lifespan;
        let scope = match q.presentation_access_scope {
            1 => crate::dds::qos::PresentationAccessScope::Topic,
            2 => crate::dds::qos::PresentationAccessScope::Group,
            _ => crate::dds::qos::PresentationAccessScope::Instance,
        };
        result.presentation = crate::dds::qos::Presentation::new(
            scope,
            q.presentation_coherent,
            q.presentation_ordered,
        );
        // Partition
        if !q.partition_names.is_empty() {
            result.partition = crate::qos::partition::Partition::new(q.partition_names.clone());
        }
        // Data representation
        if !q.data_representation.is_empty() {
            result.data_representation = q.data_representation.clone();
        }
        // TIME_BASED_FILTER: restore minimum_separation from RTPS Duration_t fields.
        // RTPS v2.5 sec. 9.3.2: fraction is 2^-32 seconds.
        if q.minimum_separation_sec != 0 || q.minimum_separation_frac != 0 {
            // Rounded to the nearest nanosecond: a 2^-32 s step is under 1 ns.
            let frac_nanos = ((q.minimum_separation_frac as u64) * 1_000_000_000 + (1 << 31)) >> 32;
            let total_nanos = (q.minimum_separation_sec as u64) * 1_000_000_000 + frac_nanos;
            result.time_based_filter =
                crate::dds::qos::TimeBasedFilter::new(std::time::Duration::from_nanos(total_nanos));
        }
        result.liveliness = q.liveliness();
        result.latency_budget = q.latency_budget();
        result.destination_order = q.destination_order();
        result
    }

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
    ///
    /// This signature carries no domain id. An encoder that writes
    /// PID_DOMAIN_ID from here either omits it (RTPS 2.5 Table 9.19: absent,
    /// the receiver takes its own domain) or writes 0; use
    /// [`DialectEncoder::build_spdp_in_domain`] to announce the real one.
    fn build_spdp(
        &self,
        participant_guid: &Guid,
        unicast_locators: &[SocketAddr],
        multicast_locators: &[SocketAddr],
        lease_duration_sec: u32,
    ) -> EncodeResult<Vec<u8>>;

    /// Build SPDP participant announcement for the participant's domain.
    ///
    /// Every domain-id parameter the encoder writes carries `domain_id`.
    /// The default delegates to [`DialectEncoder::build_spdp`], for encoders
    /// that write none.
    fn build_spdp_in_domain(
        &self,
        participant_guid: &Guid,
        unicast_locators: &[SocketAddr],
        multicast_locators: &[SocketAddr],
        lease_duration_sec: u32,
        domain_id: u32,
    ) -> EncodeResult<Vec<u8>> {
        let _ = domain_id;
        self.build_spdp(
            participant_guid,
            unicast_locators,
            multicast_locators,
            lease_duration_sec,
        )
    }

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
    /// multiple SPDP rounds. Dialects that return `true` send SEDP as soon as
    /// the peer's SPDP is processed.
    ///
    /// # Returns
    /// - `true`: Skip SPDP barrier (send SEDP immediately)
    /// - `false`: Wait for 3 SPDP rounds before sending SEDP (default)
    fn skip_spdp_barrier(&self) -> bool {
        false
    }

    /// Whether to send immediate SPDP unicast response upon peer discovery.
    ///
    /// When this returns `true`, HDDS answers a newly discovered peer's
    /// SPDP with an immediate unicast SPDP to its metatraffic unicast locators,
    /// BEFORE sending discovery HEARTBEATs, instead of letting the peer learn
    /// about us from the next periodic SPDP announcement. Sequence we emit:
    /// - peer SPDP received (multicast)
    /// - HDDS sends SPDP unicast to the peer (BEFORE HEARTBEATs)
    /// - HDDS sends discovery HEARTBEATs
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
    /// Some dialects send a handshake before SEDP discovery proceeds. This
    /// method returns the packets
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
    /// # Example (RTI dialect)
    /// The RTI dialect sends:
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
    /// A remote participant may not yet have created its SEDP built-in
    /// readers for us when its SPDP DATA(p) reaches HDDS. SEDP DATA sent in
    /// that window is not acknowledged and is only recovered on the next
    /// HEARTBEAT/ACKNACK round, which delays endpoint matching. A dialect
    /// that needs it returns a short delay so HDDS waits after SPDP before
    /// sending its first SEDP DATA; reliable SEDP (RTPS 2.5 Sec.8.5.4)
    /// would recover the samples anyway, the delay only shortens matching.
    ///
    /// # Returns
    /// - Delay in milliseconds before sending SEDP DATA
    /// - Default: 0 (no delay)
    fn sedp_setup_delay_ms(&self) -> u64 {
        0
    }

    /// Whether this dialect requires re-announcing our DATA(r) after receiving peer's DATA(w).
    ///
    /// A reader announcement the peer has already acknowledged is, per the
    /// reliable protocol, never delivered to it again: a resend under the
    /// same sequence number is a duplicate the peer's reader discards
    /// (RTPS 2.5 Sec.8.4.12). When the peer only completes a match after
    /// it has announced its own writer, HDDS must therefore publish the
    /// reader again under a NEW sequence number once the peer's DATA(w)
    /// arrives, so the announcement is a new sample and is delivered.
    ///
    /// # Returns
    /// - `true`: Re-announce our Readers with new seq numbers after receiving Writer
    /// - `false`: Standard behavior, no re-announcement needed (default)
    fn requires_sedp_reader_confirmation(&self) -> bool {
        false
    }

    /// Build ACKNACK confirmation for received SEDP DATA(w).
    ///
    /// By default HDDS sends an ACKNACK only in response to a HEARTBEAT, as
    /// the reliable reader behavior requires (RTPS 2.5 Sec.8.4.12). A
    /// dialect may also acknowledge a received SEDP DATA(w) immediately, so
    /// the peer's writer learns of the delivery without waiting for its
    /// next HEARTBEAT period. The extra ACKNACK carries the same reader
    /// state a HEARTBEAT response would.
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

    /// Whether this dialect requires INFO_DST in SEDP re-announcements.
    ///
    /// When `true`, HDDS prefixes the SEDP reader re-announcement (see
    /// `requires_sedp_reader_confirmation`) with an INFO_DST naming the
    /// peer's GUID prefix, the same layout HDDS uses for its other
    /// directed SEDP DATA, so the re-announcement is addressed to that one
    /// participant rather than to any reader that receives the datagram.
    ///
    /// # Returns
    /// - `true`: Include INFO_DST with peer's GUID prefix in re-announcements
    /// - `false`: No INFO_DST needed (default for most dialects)
    fn requires_info_dst_for_reannouncement(&self) -> bool {
        false
    }

    /// Submessage ordering preference for SEDP DATA packets.
    ///
    /// RTPS allows INFO_TS and INFO_DST in either order: each only updates
    /// the receiver state applied to the submessages that follow it. HDDS
    /// emits INFO_DST -> INFO_TS -> DATA by default; a dialect returning
    /// `true` gets INFO_TS -> INFO_DST -> DATA instead.
    ///
    /// # Returns
    /// - `true`: Send INFO_TS before INFO_DST
    /// - `false`: Send INFO_DST before INFO_TS (default)
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
/// Returns true for the FastDDS, RTI, OpenDDS, CycloneDDS, Hybrid, and
/// native HDDS encoders.
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

    /// Regression test for the CoreDX vendor ID swap (0x0104 vs 0x0106).
    ///
    /// Per the OMG DDS Foundation RTPS vendor ID registry
    /// (https://www.dds-foundation.org/dds-rtps-vendor-and-product-ids/):
    ///   {0x01, 0x04} = "Mil-DDS"  (not implemented here -> must be Unknown)
    ///   {0x01, 0x06} = "CoreDX DDS" (Twin Oaks Computing)
    ///
    /// A real CoreDX participant's SPDP/SEDP RTPS header carries vendorId
    /// bytes [0x01, 0x06], captured with tshark:
    ///   guidPrefix.src = 0106ac1800020000001f0001, rtps.vendorId = 0x0106
    /// (the leading two bytes of the GUID prefix duplicate the vendorId).
    #[test]
    fn test_coredx_vendor_id_is_0x0106_per_omg_registry() {
        // The real wire byte sequence from the capture must resolve to CoreDx.
        assert_eq!(VendorId::from_bytes([0x01, 0x06]), VendorId::CoreDx);
        assert_eq!(VendorId::CoreDx.to_bytes(), [0x01, 0x06]);
        assert_eq!(Dialect::from_vendor(VendorId::CoreDx), Dialect::CoreDx);

        // 0x0104 ("Mil-DDS") must NOT be treated as CoreDX: we have no
        // dialect for it, so it must fall back to Unknown/Hybrid, not be
        // silently misread as the CoreDX peer.
        assert_eq!(VendorId::from_bytes([0x01, 0x04]), VendorId::Unknown);
        assert_eq!(
            Dialect::from_vendor(VendorId::from_bytes([0x01, 0x04])),
            Dialect::Hybrid
        );
    }

    /// Decodes a real captured CoreDX RTPS header prefix (magic + version +
    /// vendorId, as seen in a tshark capture)
    /// through `get_encoder_for_vendor`, proving the live resolution path
    /// (vendor bytes -> VendorId -> Dialect -> encoder) lands on the
    /// CoreDX dialect rather than Hybrid for a real CoreDX peer.
    #[test]
    fn test_get_encoder_for_vendor_resolves_captured_coredx_bytes() {
        let captured_vendor_id_bytes: [u8; 2] = [0x01, 0x06];
        let encoder = get_encoder_for_vendor(captured_vendor_id_bytes);
        assert_eq!(encoder.vendor_id(), captured_vendor_id_bytes);
    }
}

#[cfg(test)]
mod duration_t_tests {
    use super::duration_t_le;
    use std::time::Duration;

    fn words(wire: [u8; 8]) -> (u32, u32) {
        (
            u32::from_le_bytes(wire[..4].try_into().expect("4 bytes")),
            u32::from_le_bytes(wire[4..].try_into().expect("4 bytes")),
        )
    }

    /// RTPS v2.5 Sec.9.3.2 Duration_t: seconds, then the fraction in 2^-32 s
    /// rounded to nearest; 0x7FFF_FFFF seconds or more is DURATION_INFINITE.
    #[test]
    fn a_duration_goes_on_the_wire_as_seconds_and_a_fraction_of_2_pow_32() {
        assert_eq!(words(duration_t_le(Duration::ZERO)), (0, 0));
        assert_eq!(
            words(duration_t_le(Duration::from_millis(100))),
            (0, 0x1999_999A)
        );
        assert_eq!(
            words(duration_t_le(Duration::from_millis(2500))),
            (2, 0x8000_0000)
        );
        assert_eq!(words(duration_t_le(Duration::from_nanos(1))), (0, 4));
        assert_eq!(
            words(duration_t_le(Duration::new(0x7FFF_FFFE, 999_999_999))),
            (0x7FFF_FFFE, 0xFFFF_FFFC)
        );
        for infinite in [Duration::from_secs(0x7FFF_FFFF), Duration::MAX] {
            assert_eq!(words(duration_t_le(infinite)), (0x7FFF_FFFF, 0xFFFF_FFFF));
        }
    }
}

#[cfg(test)]
mod spdp_domain_tests {
    use super::*;

    /// PID_DOMAIN_ID (0x000f) as decoded from an emitted SPDP ParameterList.
    fn announced_domain(buf: &[u8]) -> Option<u32> {
        let mut offset = 4;
        while offset + 4 <= buf.len() {
            let pid = u16::from_le_bytes([buf[offset], buf[offset + 1]]);
            let len = usize::from(u16::from_le_bytes([buf[offset + 2], buf[offset + 3]]));
            offset += 4;
            match pid {
                0x0001 => return None,
                0x000f => {
                    return Some(u32::from_le_bytes(
                        buf[offset..offset + 4].try_into().expect("four octets"),
                    ))
                }
                _ => offset += len,
            }
        }
        panic!("no PID_SENTINEL");
    }

    /// Every encoder that writes PID_DOMAIN_ID writes the domain it is given.
    #[test]
    fn spdp_in_domain_announces_that_domain() {
        let guid = Guid {
            prefix: [0x01, 0x1a, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8],
            entity_id: [0x00, 0x00, 0x01, 0xc1],
        };
        for dialect in [
            Dialect::Rti,
            Dialect::CycloneDds,
            Dialect::OpenDds,
            Dialect::Hdds,
        ] {
            for domain in [0u32, 42, 232] {
                let buf = get_encoder(dialect)
                    .build_spdp_in_domain(&guid, &[], &[], 30, domain)
                    .expect("build");
                assert_eq!(announced_domain(&buf), Some(domain), "{dialect:?}");
            }
        }
    }
}
