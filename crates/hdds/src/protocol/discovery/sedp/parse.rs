// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! SEDP Parser - CDR decoding of SEDP endpoint discovery messages
//!
//! Handles parsing of SEDP DATA submessages containing endpoint metadata including:
//! - Topic and type names
//! - Endpoint GUIDs
//! - QoS policies (reliability, durability, history)
//! - Type information (TypeObject, compressed via ZLIB)
//! - Vendor-specific extensions (PIDs 0x8000+, DDSI-RTPS 2.5 Sec.9.4.2.11)

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::core::discovery::GUID;
use crate::protocol::discovery::constants::{
    CDR_BE, CDR_BE_VENDOR, CDR_LE, CDR_LE_VENDOR, PID_BUILTIN_ENDPOINT_SET,
    PID_DATA_REPRESENTATION, PID_DATA_TAGS, PID_DEADLINE, PID_DESTINATION_ORDER, PID_DURABILITY,
    PID_DURABILITY_SERVICE, PID_ENDPOINT_GUID, PID_ENDPOINT_SECURITY_INFO, PID_GROUP_ENTITY_ID,
    PID_GROUP_GUID, PID_HDDS_SHM_CAPABILITY, PID_HISTORY, PID_LATENCY_BUDGET, PID_LIFESPAN,
    PID_LIVELINESS, PID_METATRAFFIC_UNICAST_LOCATOR, PID_OWNERSHIP, PID_OWNERSHIP_STRENGTH,
    PID_PARTICIPANT_GUID, PID_PARTICIPANT_LEASE_DURATION, PID_PARTITION, PID_PRESENTATION,
    PID_RELIABILITY, PID_SENTINEL, PID_TOPIC_NAME, PID_TYPE_CONSISTENCY, PID_TYPE_INFORMATION,
    PID_TYPE_NAME, PID_TYPE_OBJECT, PID_TYPE_OBJECT_LB, PID_UNICAST_LOCATOR, PID_USER_DATA,
    PL_CDR2_BE, PL_CDR2_LE,
};
use crate::protocol::discovery::hash::simple_hash;
use crate::protocol::discovery::types::{
    EndpointSecurityInfo, ParseError, SedpData, TypeConsistencyEnforcement,
    TypeIdentifierWithDependencies, TypeIdentifierWithSize, TypeInformation,
};
use crate::xtypes::{
    decode_type_object_v1, decompress_type_object, CompleteTypeObject, EquivalenceHash,
};
use crate::Cdr2Decode;

/// The most data tags one announcement may carry. A permissions document
/// names a handful; a peer announcing more is refused, never read in part.
const MAX_DATA_TAGS: usize = 256;

/// Parse the value of PID_DATA_TAGS (DDS Security v1.1 Sec.7.4.1.7,
/// Sec.7.2.5): `struct DataTags { sequence<Tag> tags; }`, `struct Tag {
/// string name; string value; }`, both `@appendable`. In a PL_CDR (XCDR1)
/// parameter list an appendable struct carries no header; in PL_CDR2 (XCDR2)
/// each appendable struct, and the sequence of them, starts with a DHEADER
/// (DDS-XTypes v1.3 Sec.7.4.3.5). Alignment is relative to the value, which
/// a parameter list keeps 4-aligned (RTPS v2.5 Sec.9.4.2.11).
///
/// `None` for anything that does not read whole: a count past
/// `MAX_DATA_TAGS` or past what the value can hold, a string running past
/// it, one without its terminating NUL, or not UTF-8.
fn parse_data_tags(
    value: &[u8],
    is_little_endian: bool,
    xcdr2: bool,
) -> Option<Vec<crate::qos::data_tags::DataTag>> {
    // A 4-aligned 32-bit word at `pos`, which moves past it.
    fn word(value: &[u8], pos: &mut usize, is_little_endian: bool) -> Option<usize> {
        *pos = pos.checked_add(3)? & !3;
        let bytes: [u8; 4] = value.get(*pos..pos.checked_add(4)?)?.try_into().ok()?;
        *pos += 4;
        let word = if is_little_endian {
            u32::from_le_bytes(bytes)
        } else {
            u32::from_be_bytes(bytes)
        };
        usize::try_from(word).ok()
    }
    // A CDR string at `pos`: its length (the NUL included), its bytes.
    fn string(value: &[u8], pos: &mut usize, is_little_endian: bool) -> Option<String> {
        let length = word(value, pos, is_little_endian)?;
        let end = pos.checked_add(length)?;
        let (last, text) = value.get(*pos..end)?.split_last()?;
        if *last != 0 {
            return None;
        }
        *pos = end;
        std::str::from_utf8(text).ok().map(str::to_string)
    }
    let mut pos = 0usize;
    if xcdr2 {
        // DHEADER of DataTags, then of the sequence of Tag.
        word(value, &mut pos, is_little_endian)?;
        word(value, &mut pos, is_little_endian)?;
    }
    let count = word(value, &mut pos, is_little_endian)?;
    // Each tag takes at least two string lengths and two NULs.
    if count > MAX_DATA_TAGS || count > value.len().saturating_sub(pos) / 10 {
        return None;
    }
    let mut tags = Vec::with_capacity(count);
    for _ in 0..count {
        if xcdr2 {
            word(value, &mut pos, is_little_endian)?;
        }
        let name = string(value, &mut pos, is_little_endian)?;
        let tag_value = string(value, &mut pos, is_little_endian)?;
        tags.push(crate::qos::data_tags::DataTag {
            name,
            value: tag_value,
        });
    }
    Some(tags)
}

/// Legacy TypeObject v1 (RTI/XTypes-1.1 era) payloads always begin with the
/// same "RTI extended parameter header" prefix on their outermost
/// `TypeLibrary` member: pid16 `0x7f01` (bytes `01 7f`), little-endian. A
/// CDR2 `CompleteTypeObject` never starts this way (its first byte is a
/// `TypeKind` discriminator octet, always `<= 0x62`), so this is a cheap,
/// reliable format sniff to avoid attempting (and logging a spurious
/// failure for) a v1 decode on every ordinary CDR2 payload.
fn looks_like_legacy_type_object_v1(bytes: &[u8]) -> bool {
    bytes.len() >= 2 && bytes[0] == 0x01 && bytes[1] == 0x7f
}

/// Parse a string parameter from CDR-encoded buffer.
///
/// Format: length (u32) + string bytes + null terminator.
/// The length field uses the same endianness as the CDR payload.
pub(super) fn parse_string_parameter(
    buf: &[u8],
    offset: usize,
    length: usize,
    is_little_endian: bool,
) -> Option<String> {
    if length < 4 {
        return None;
    }

    let str_len = read_u32(buf, offset, is_little_endian) as usize;

    if offset + 4 + str_len > buf.len() || str_len == 0 {
        return None;
    }

    let bytes = &buf[offset + 4..offset + 4 + str_len - 1];
    std::str::from_utf8(bytes).ok().map(|s| s.to_string())
}

fn parse_user_data_parameter(
    buf: &[u8],
    offset: usize,
    length: usize,
    is_little_endian: bool,
) -> Option<String> {
    if length < 4 || offset + length > buf.len() {
        return None;
    }

    let len_bytes = [
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
    ];
    let data_len = if is_little_endian {
        u32::from_le_bytes(len_bytes)
    } else {
        u32::from_be_bytes(len_bytes)
    } as usize;

    if data_len == 0 || data_len + 4 > length {
        return None;
    }

    let mut data = &buf[offset + 4..offset + 4 + data_len];
    if let Some((&0, trimmed)) = data.split_last() {
        data = trimmed;
    }

    std::str::from_utf8(data).ok().map(|s| s.to_string())
}

// TypeObject decompression moved to xtypes::type_object::codec module
// Use decompress_type_object() from crate::xtypes instead

// =========================================================================
// Endianness-aware primitive readers
// =========================================================================
// CDR payload endianness is determined by the encapsulation header.
// These helpers centralize the LE/BE dispatch to avoid repeating
// if/else blocks in every PID handler.

fn read_u16(buf: &[u8], offset: usize, is_little_endian: bool) -> u16 {
    let bytes = [buf[offset], buf[offset + 1]];
    if is_little_endian {
        u16::from_le_bytes(bytes)
    } else {
        u16::from_be_bytes(bytes)
    }
}

fn read_u32(buf: &[u8], offset: usize, is_little_endian: bool) -> u32 {
    let bytes = [
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
    ];
    if is_little_endian {
        u32::from_le_bytes(bytes)
    } else {
        u32::from_be_bytes(bytes)
    }
}

fn read_i32(buf: &[u8], offset: usize, is_little_endian: bool) -> i32 {
    let bytes = [
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
    ];
    if is_little_endian {
        i32::from_le_bytes(bytes)
    } else {
        i32::from_be_bytes(bytes)
    }
}

/// Parse PID_DURABILITY_SERVICE (0x001e) from CDR-encoded buffer.
///
/// Format: cleanup_delay (Duration_t = 8 bytes) + history_kind (u32) +
///         history_depth (u32) + max_samples (i32) + max_instances (i32) +
///         max_samples_per_instance (i32) = 28 bytes total.
fn parse_durability_service(
    buf: &[u8],
    offset: usize,
    length: usize,
    is_little_endian: bool,
) -> Option<crate::dds::qos::DurabilityService> {
    if length < 28 {
        return None;
    }

    let cleanup_secs = read_u32(buf, offset, is_little_endian);
    let cleanup_fraction = read_u32(buf, offset + 4, is_little_endian);
    // history_kind at offset+8 (not used directly, DurabilityService uses KEEP_LAST)
    let history_depth = read_u32(buf, offset + 12, is_little_endian);
    let max_samples = read_i32(buf, offset + 16, is_little_endian);
    let max_instances = read_i32(buf, offset + 20, is_little_endian);
    let max_samples_per_instance = read_i32(buf, offset + 24, is_little_endian);

    // Convert RTPS Duration_t to microseconds (RTPS v2.5 sec. 9.3.2: fraction is 2^-32 sec).
    let cleanup_fraction_us = ((cleanup_fraction as u64) * 1_000_000 + (1 << 31)) >> 32;
    let cleanup_delay_us = (cleanup_secs as u64) * 1_000_000 + cleanup_fraction_us;

    let ds = crate::dds::qos::DurabilityService::new(
        cleanup_delay_us,
        history_depth,
        max_samples,
        max_instances,
        max_samples_per_instance,
    );
    log::debug!(
        "[SEDP-QOS] PID_DURABILITY_SERVICE parsed: depth={} max_samples={} max_instances={} max_spi={}",
        history_depth, max_samples, max_instances, max_samples_per_instance
    );
    Some(ds)
}

/// Parse PID_PRESENTATION (0x0021) from CDR-encoded buffer.
///
/// Format: access_scope (u32) + coherent_access (u8) + ordered_access (u8) + 2 padding = 8 bytes.
fn parse_presentation(
    buf: &[u8],
    offset: usize,
    length: usize,
    is_little_endian: bool,
) -> Option<crate::dds::qos::Presentation> {
    if length < 8 {
        return None;
    }

    let scope_kind = read_u32(buf, offset, is_little_endian);
    let coherent = buf[offset + 4] != 0;
    let ordered = buf[offset + 5] != 0;
    let access_scope = match scope_kind {
        0 => crate::dds::qos::PresentationAccessScope::Instance,
        1 => crate::dds::qos::PresentationAccessScope::Topic,
        2 => crate::dds::qos::PresentationAccessScope::Group,
        _ => crate::dds::qos::PresentationAccessScope::Instance,
    };
    log::debug!(
        "[SEDP-QOS] PID_PRESENTATION parsed: scope={} coherent={} ordered={}",
        scope_kind,
        coherent,
        ordered
    );
    Some(crate::dds::qos::Presentation::new(
        access_scope,
        coherent,
        ordered,
    ))
}

/// Parse `PID_TYPE_INFORMATION` (0x0075) per OMG DDS-XTypes v1.3 sec. 7.6.3.2.
///
/// Wire layout (mirrors the encoder at
/// `protocol::discovery::sedp::build::type_information`):
///
/// ```text
/// PARAM_LEN = 92
/// + DHEADER          u32 LE  = 88
/// + Member 0x1001 (minimal)  -- 44 bytes
/// | + EMHEADER1      u32 LE  (M=0, LC=4, MID=0x1001)
/// | + NEXTINT        u32 LE  = 36
/// | + INNER_LEN      u32 LE  = 20
/// | + EK_*           u8      = 0xF1 (minimal) or 0xF2 (complete)
/// | + hash           [u8;14]
/// | + pad            u8
/// | + size           u32 LE  (typeobject_serialized_size)
/// | + tail           [u32;3] (legacy trailing words, ignored)
/// + Member 0x1002 (complete) -- 44 bytes (same shape)
/// ```
///
/// The decoder is tolerant: any anomaly in DHEADER, EMHEADER, or member
/// length is logged and the offending member is skipped without aborting
/// the rest of the SEDP parse -- `PID_TYPE_INFORMATION` is non-critical for
/// discovery (matching falls back to `PID_TOPIC_NAME` + `PID_TYPE_NAME` +
/// QoS), so a malformed value must never poison the SEDP packet.
pub(crate) fn parse_type_information(buf: &[u8]) -> Option<TypeInformation> {
    use crate::xtypes::EquivalenceHash;

    if buf.len() < 8 {
        log::debug!(
            "[SEDP-PARSE] PID_TYPE_INFORMATION too short: {} bytes (need >= 8)",
            buf.len()
        );
        return None;
    }

    // DHEADER: TypeInformation @mutable content size. For the canonical
    // 0-dep (92-byte) format this is 88; larger values indicate deps present.
    // Divergence is logged but not fatal.
    let dheader = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    if dheader < 88 {
        log::debug!(
            "[SEDP-PARSE] PID_TYPE_INFORMATION DHEADER surprisingly small: {} (want >= 88)",
            dheader
        );
    }

    let mut info = TypeInformation::default();
    let mut member_offset = 4usize;

    // Iterate dynamically until we run out of buffer. Handles both:
    //   NEXTINT=36 => sentinel format (44 bytes/member, zero deps)
    //   NEXTINT>=40 => dep-sequence format (8 + NEXTINT bytes/member, N deps)
    while member_offset + 8 <= buf.len() {
        // EMHEADER1: M=0, LC=4, MID=member_id (lower 28 bits).
        let emheader = u32::from_le_bytes([
            buf[member_offset],
            buf[member_offset + 1],
            buf[member_offset + 2],
            buf[member_offset + 3],
        ]);
        let mid = emheader & 0x0FFF_FFFF;

        // NEXTINT: member content byte-count
        let nextint = u32::from_le_bytes([
            buf[member_offset + 4],
            buf[member_offset + 5],
            buf[member_offset + 6],
            buf[member_offset + 7],
        ]) as usize;

        let member_end = member_offset + 8 + nextint;
        if member_end > buf.len() {
            log::debug!(
                "[SEDP-PARSE] PID_TYPE_INFORMATION member 0x{:08X} truncated: \
                 need {} bytes, have {}",
                mid,
                member_end,
                buf.len()
            );
            break;
        }

        // DDS-XTypes 1.3 7.4.3.4.8: with LC=4 NEXTINT is the member length
        // and the member (a TypeIdentifierWithDependencies, opening with its
        // own DHEADER) follows it. With LC=5 NEXTINT *is* that DHEADER
        // (Dust DDS 0.16 encodes it so): the member starts at NEXTINT and is
        // four octets longer than NEXTINT says. Both end at the same octet.
        // `nextint` is rebased to the LC=4 meaning so the layouts below hold.
        let lc = (emheader >> 28) & 0x7;
        // Any other LC keeps the LC=4 reading this parser always applied.
        let (content_start, nextint) = if lc == 5 {
            (member_offset + 4, nextint + 4)
        } else {
            (member_offset + 8, nextint)
        };

        let entry = if nextint == 36 {
            // Sentinel format (Fast-DDS compat):
            //   INNER_LEN(4) + disc(1) + hash(14) + pad(1) + size(4) + TAIL(12)
            // inner_offset = content_start + 4 (skip INNER_LEN)
            let inner = content_start + 4;
            if inner + 20 > buf.len() {
                member_offset = member_end;
                continue;
            }
            let _disc = buf[inner];
            let mut hash_bytes = [0u8; 14];
            hash_bytes.copy_from_slice(&buf[inner + 1..inner + 15]);
            let hash = EquivalenceHash::from_bytes(hash_bytes);
            // pad at inner+15
            let size = u32::from_le_bytes([
                buf[inner + 16],
                buf[inner + 17],
                buf[inner + 18],
                buf[inner + 19],
            ]);
            TypeIdentifierWithDependencies {
                hash,
                typeobject_serialized_size: size,
                dependent_typeids: vec![],
            }
        } else if nextint >= 40 {
            // Dep-sequence format:
            //   DHEADER_tiwdeps(4) + DHEADER_tiws(4) + disc(1) + hash(14) + pad(1) +
            //   size(4) + dep_count(4) + seq_DHEADER(4) + seq_count(4) +
            //   N * [DHEADER_tiws_elem(4) + disc(1) + hash(14) + pad(1) + size(4)]
            if content_start + 40 > buf.len() {
                log::debug!("[SEDP-PARSE] PID_TYPE_INFORMATION dep-format member too short");
                member_offset = member_end;
                continue;
            }
            // Skip DHEADER_tiwdeps at content_start+0..4
            // Skip DHEADER_tiws at content_start+4..8
            // disc at content_start+8 (EK_MINIMAL or EK_COMPLETE; not enforced here)
            let mut hash_bytes = [0u8; 14];
            hash_bytes.copy_from_slice(&buf[content_start + 9..content_start + 23]);
            let hash = EquivalenceHash::from_bytes(hash_bytes);
            // pad at content_start+23
            let size = u32::from_le_bytes([
                buf[content_start + 24],
                buf[content_start + 25],
                buf[content_start + 26],
                buf[content_start + 27],
            ]);
            let dep_count = u32::from_le_bytes([
                buf[content_start + 28],
                buf[content_start + 29],
                buf[content_start + 30],
                buf[content_start + 31],
            ]) as usize;
            // Skip seq_DHEADER at content_start+32..36
            let seq_count = u32::from_le_bytes([
                buf[content_start + 36],
                buf[content_start + 37],
                buf[content_start + 38],
                buf[content_start + 39],
            ]) as usize;

            let actual_count = seq_count.min(dep_count);
            let elem_base = content_start + 40;
            // Each dependency is 24 octets (`elem_base + i * 24`). A count the
            // buffer cannot hold is a malformed member: refused whole, as the
            // other anomalies here skip a member, never read in part. Once it
            // fits, the allocation below is bounded by the octets present.
            let deps_fit = actual_count
                .checked_mul(24)
                .and_then(|octets| elem_base.checked_add(octets))
                .is_some_and(|end| end <= buf.len());
            if !deps_fit {
                log::debug!(
                    "[SEDP-PARSE] PID_TYPE_INFORMATION member 0x{:08X} declares {} \
                     dependencies that do not fit in {} bytes; skipping",
                    mid,
                    actual_count,
                    buf.len()
                );
                member_offset = member_end;
                continue;
            }
            let mut deps = Vec::with_capacity(actual_count);
            for i in 0..actual_count {
                let e = elem_base + i * 24;
                // DHEADER_tiws_elem at e+0..4 (always 20; skip)
                let dep_kind = buf[e + 4];
                let mut dep_hash_bytes = [0u8; 14];
                dep_hash_bytes.copy_from_slice(&buf[e + 5..e + 19]);
                let dep_hash = EquivalenceHash::from_bytes(dep_hash_bytes);
                // pad at e+19
                let dep_size =
                    u32::from_le_bytes([buf[e + 20], buf[e + 21], buf[e + 22], buf[e + 23]]);
                deps.push(TypeIdentifierWithSize {
                    kind: dep_kind,
                    hash: dep_hash,
                    typeobject_serialized_size: dep_size,
                });
            }

            TypeIdentifierWithDependencies {
                hash,
                typeobject_serialized_size: size,
                dependent_typeids: deps,
            }
        } else {
            log::debug!(
                "[SEDP-PARSE] PID_TYPE_INFORMATION member 0x{:08X} unexpected NEXTINT={}; skipping",
                mid,
                nextint
            );
            member_offset = member_end;
            continue;
        };

        match mid {
            0x1001 => info.minimal = Some(entry),
            0x1002 => info.complete = Some(entry),
            other => log::debug!(
                "[SEDP-PARSE] PID_TYPE_INFORMATION unknown member MID: 0x{:08X}",
                other
            ),
        }

        member_offset = member_end;
    }

    if info.minimal.is_none() && info.complete.is_none() {
        return None;
    }
    Some(info)
}

/// Parse SEDP DATA submessage payload.
///
/// # Arguments
/// - `buf`: RTPS payload positioned at the DATA submessage.
///
/// # Returns
/// Endpoint metadata containing topic/type names, endpoint GUID, QoS hash, and optional TypeObject.
///
/// # Errors
/// - `ParseError::TruncatedData` if the payload terminates mid-parameter.
/// - `ParseError::InvalidEncapsulation` when the encapsulation is not CDR little-endian.
/// - `ParseError::InvalidFormat` if required SEDP parameters are missing.
///
/// # Multi-Format Support
/// Accepts multiple CDR encapsulation formats for DDS interoperability:
/// - CDR_LE (0x0003): HDDS standard, little-endian
/// - CDR_BE (0x0002): PL_CDR_BE, big-endian ParameterList (DDSI-RTPS 2.5 Sec.10.3)
/// - PL_CDR2_LE (0x000B): CDR2 little-endian
/// - PL_CDR2_BE (0x000A): CDR2 big-endian
pub fn parse_sedp(buf: &[u8]) -> Result<SedpData, ParseError> {
    parse_sedp_with_vendor(buf, None)
}

/// The nanoseconds a `Duration_t` fraction (RTPS v2.5 Sec.9.3.2: units of
/// 2^-32 s) stands for, rounded to the nearest nanosecond. A 2^-32 s step is
/// shorter than a nanosecond, so rounding gives back exactly the nanoseconds
/// the sender encoded, whether its encoder truncated or rounded; flooring
/// read a sub-second value 1 ns short, and a reader requesting exactly what
/// a writer offered then looked stricter than the offer.
fn fraction_to_nanos(fraction: u32) -> u64 {
    ((fraction as u64) * 1_000_000_000 + (1 << 31)) >> 32
}

/// Convert an RTPS `Duration_t` (seconds + second-word) to nanoseconds.
///
/// Standard RTPS (PSM, v2.5 sec. 9.3.2) encodes the second word as a fraction in
/// units of 2^-32 seconds. A peer with vendorId 0x0103 (OpenDDS dialect) may
/// carry either that fraction or the DDS PIM/IDL form
/// `{ sec: int32, nanosec: uint32 }`, where the second word holds
/// nanoseconds directly, and both forms come with the identical
/// `vendorId=0x0103` / `PID_PROTOCOL_VERSION=2.4` fingerprint, so vendorId
/// alone cannot select the right interpretation.
///
/// Discriminator: a valid DDS `nanosec` field is defined to always be
/// `< 1_000_000_000` (a full second rolls into `seconds` instead). A
/// second_word `>= 1_000_000_000` is therefore never a legal nanosecond
/// count and unambiguously indicates the 2^-32 fraction encoding, regardless
/// of vendor. `opendds = true` only selects the legacy nanosecond
/// interpretation when the value is still in the range where a nanosecond
/// count is plausible; values at/above the 1s threshold always take the
/// spec path. For whole-second durations (second_word = 0) both encodings
/// agree, which is why only sub-second QoS values from such a peer are at risk.
///
/// Known residual ambiguity: a 0x0103 peer using the fraction and advertising a lifespan
/// below ~232.83ms (2^-32 fraction < 1_000_000_000) is indistinguishable
/// from a legacy nanosecond count in that same numeric range and will still
/// be misread as legacy nanoseconds. No wire-only signal currently
/// disambiguates that sub-233ms band.
fn duration_to_nanos(seconds: u32, second_word: u32, opendds: bool) -> u64 {
    const NANOS_PER_SEC: u32 = 1_000_000_000;
    let use_legacy_opendds_nanosec = opendds && second_word < NANOS_PER_SEC;
    if use_legacy_opendds_nanosec {
        (seconds as u64) * 1_000_000_000 + (second_word as u64)
    } else {
        let frac_nanos = fraction_to_nanos(second_word);
        (seconds as u64) * 1_000_000_000 + frac_nanos
    }
}

/// The RTPS `Duration_t` at `offset` (RTPS v2.5 Sec.9.3.2: `int32
/// seconds`, `uint32 fraction`) as a `Duration`: DURATION_INFINITE
/// (`seconds` 0x7fffffff) as `Duration::from_secs(u64::MAX)`, the value the
/// QoS policies take for infinite (`Liveliness::infinite`), a negative
/// `seconds` as zero. The second word is read by `duration_to_nanos`.
fn read_duration_t(
    buf: &[u8],
    offset: usize,
    is_little_endian: bool,
    opendds: bool,
) -> std::time::Duration {
    let seconds = read_u32(buf, offset, is_little_endian);
    let second_word = read_u32(buf, offset + 4, is_little_endian);
    if seconds == 0x7FFF_FFFF {
        return std::time::Duration::from_secs(u64::MAX);
    }
    if seconds > 0x7FFF_FFFF {
        return std::time::Duration::ZERO;
    }
    std::time::Duration::from_nanos(duration_to_nanos(seconds, second_word, opendds))
}

/// SEDP parser variant aware of the source participant's RTPS vendorId.
///
/// `vendor` is the 2-byte vendorId from the RTPS message header (bytes 6-7).
/// It enables vendor-specific accommodations for non-standard wire encodings
/// (currently: OpenDDS `Duration_t` nanosecond encoding for PID_LIFESPAN).
pub fn parse_sedp_with_vendor(buf: &[u8], vendor: Option<[u8; 2]>) -> Result<SedpData, ParseError> {
    let opendds_duration = vendor == Some([0x01, 0x03]);
    if buf.len() < 2 {
        return Err(ParseError::TruncatedData);
    }

    // CDR encapsulation header is ALWAYS big-endian per CDR spec
    let encapsulation = u16::from_be_bytes([buf[0], buf[1]]);

    // Accept all CDR formats (mirror SPDP parser robustness)
    // NOTE: _is_cdr2 is detected but not yet used. CDR2 (XCDR2) has different
    // encoding rules for optional members and DHEADER. PID-based parameter lists
    // are self-delimiting so CDR1/CDR2 parse identically for now, but XCDR2
    // extensions (e.g., optional members with MEMBER_ID headers) would need
    // special handling here.
    let (is_little_endian, is_cdr2) = match encapsulation {
        CDR_LE => {
            log::debug!("[sedp] [OK] CDR_LE (0x0003) detected");
            (true, false)
        }
        CDR_BE => {
            log::debug!("[sedp] [!]  PL_CDR_BE (0x0002) detected - big-endian parameter list");
            (false, false)
        }
        PL_CDR2_LE => {
            log::debug!("[sedp] [OK] PL_CDR2_LE (0x000B) detected");
            (true, true)
        }
        PL_CDR2_BE => {
            log::debug!("[sedp] [!]  PL_CDR2_BE (0x000A) detected");
            (false, true)
        }
        // FastDDS vendor-specific encapsulations
        CDR_LE_VENDOR => {
            log::debug!("[sedp] [OK] CDR_LE_VENDOR (0x8001) detected - FastDDS");
            (true, false)
        }
        CDR_BE_VENDOR => {
            log::debug!("[sedp] [!]  CDR_BE_VENDOR (0x8002) detected - FastDDS");
            (false, false)
        }
        _ => {
            log::debug!(
                "[sedp] [X] Invalid encapsulation: 0x{:04x} buf_head={:02x?}",
                encapsulation,
                &buf[..buf.len().min(16)]
            );
            return Err(ParseError::InvalidEncapsulation);
        }
    };

    // =========================================================================
    // Padding Detection Logic
    // =========================================================================
    //
    // CDR encapsulation has a 4-byte header: 2 bytes for encapsulation ID + 2 bytes options.
    // Per the CDR spec, bytes 2-3 are "options" but most implementations use them as padding.
    //
    // Standard DDS layout (HDDS, FastDDS, CycloneDDS, OpenDDS):
    //   [0-1] Encapsulation ID (e.g., 0x0003 for CDR_LE)
    //   [2-3] Options/padding (typically 0x0000)
    //   [4+]  Parameter list starts here
    //
    // Tolerated non-conformant layout (DDSI-RTPS 2.5 Sec.10.2 requires the
    // 2-byte representation_options field; we accept a payload without it):
    //   [0-1] Encapsulation ID
    //   [2+]  Parameter list starts immediately (no options field)
    //
    // Detection: If bytes 2-3 are both 0x00, assume standard 2-byte padding.
    // This heuristic works because valid PIDs are never 0x0000 (that's reserved).
    //
    // CAVEAT: In XCDR2 (PL_CDR2), bytes 2-3 are an "options" field that may be
    // non-zero (encoding flags). If a participant sends CDR2 with non-zero options,
    // this heuristic would incorrectly skip padding and shift all offsets by 2.
    // Current mitigation: PID parsing is self-delimiting (each PID carries its
    // length), so a 2-byte offset error would cause the first PID read to fail
    // and return TruncatedData/InvalidFormat rather than silently corrupt data.
    // =========================================================================
    let pid_offset = if buf.len() > 3 && buf[2] == 0x00 && buf[3] == 0x00 {
        4 // Standard padding detected
    } else {
        2 // Tolerated layout: no options field
    };

    let mut offset = pid_offset;
    let mut topic_name: Option<String> = None;
    let mut type_name: Option<String> = None;
    let mut participant_guid: Option<GUID> = None; // Parse PID_PARTICIPANT_GUID for FastDDS interop
    let mut endpoint_guid: Option<GUID> = None;
    let mut type_object: Option<CompleteTypeObject> = None;
    // Named-type (struct/union/enum/alias) dependents transitively reachable
    // from `type_object`'s members, populated only when `type_object` was
    // decoded from a legacy TypeObject v1 payload (PID_TYPE_OBJECT or
    // PID_TYPE_OBJECT_LB). Drained by DiscoveryFsm::handle_sedp into the
    // participant's structural-assignability type store so
    // TypeIdentifier::Minimal(_) member references can be resolved.
    let mut dependents: Vec<(EquivalenceHash, CompleteTypeObject)> = Vec::new();
    // True when type_object came from a legacy TypeObject v1 payload (see
    // SedpData::type_object_legacy_v1 for the lossiness rationale).
    let mut type_object_legacy_v1 = false;
    let mut type_information: Option<crate::protocol::discovery::types::TypeInformation> = None;
    let mut is_participant_data = false; // Detect ParticipantData vs Publication/Subscription

    // Build QoS from PIDs instead of throwing them away
    let mut qos_reliability: Option<crate::dds::qos::Reliability> = None;
    let mut qos_durability: Option<crate::dds::qos::Durability> = None;
    let mut qos_history: Option<crate::dds::qos::History> = None;

    // Parse PID_PRESENTATION for Presentation QoS
    let mut qos_presentation: Option<crate::dds::qos::Presentation> = None;

    // Parse PID_DURABILITY_SERVICE for DurabilityService QoS
    let mut qos_durability_service: Option<crate::dds::qos::DurabilityService> = None;

    // Parse PID_OWNERSHIP and PID_DEADLINE for interop QoS compatibility
    let mut qos_ownership: Option<crate::dds::qos::Ownership> = None;
    let mut qos_ownership_strength: Option<i32> = None;
    let mut qos_deadline: Option<crate::dds::qos::Deadline> = None;
    let mut qos_lifespan: Option<crate::dds::qos::Lifespan> = None;

    // LIVELINESS, LATENCY_BUDGET and DESTINATION_ORDER: RxO policies
    // (DDS v1.4 Sec.2.2.3.11, 2.2.3.8, 2.2.3.17) a remote endpoint announces
    // in standard PIDs (RTPS v2.5 Table 9.12), whatever its vendor.
    let mut qos_liveliness: Option<crate::dds::qos::Liveliness> = None;
    let mut qos_latency_budget: Option<crate::dds::qos::LatencyBudget> = None;
    let mut qos_destination_order: Option<crate::dds::qos::DestinationOrder> = None;

    // Partition QoS
    let mut qos_partition_names: Vec<String> = Vec::new();

    // Data representation (PID_DATA_REPRESENTATION)
    let mut qos_data_representation: Vec<u16> = Vec::new();

    // DataTagQosPolicy (PID_DATA_TAGS, DDS Security v1.1 Sec.7.4.1.7)
    let mut qos_data_tags: Option<Vec<crate::qos::data_tags::DataTag>> = None;

    // Parse PID_UNICAST_LOCATOR for OpenDDS interop - CRITICAL for knowing where to send user data
    let mut unicast_locators: Vec<SocketAddr> = Vec::new();
    let mut user_data: Option<String> = None;
    // PID_HDDS_SHM_CAPABILITY (0x8031): HDDS vendor-specific SHM capability
    // hint, kept separate from `user_data` (the application's UserDataQosPolicy,
    // PID_USER_DATA/0x002c). See PID_HDDS_SHM_CAPABILITY's doc for why these
    // must never be conflated.
    let mut shm_capability: Option<String> = None;

    // PID_ENDPOINT_SECURITY_INFO (0x1004, DDS-Security v1.1 Sec.7.2.8,
    // 7.4.1.5): unconditional, like the rest of SEDP's own parsing --
    // discovery does not depend on the `security` feature to carry what a
    // peer announced.
    let mut endpoint_security_info: Option<EndpointSecurityInfo> = None;

    // PID_TYPE_CONSISTENCY_ENFORCEMENT (0x0074): peer coercion policy for XTypes assignability.
    let mut type_consistency: Option<TypeConsistencyEnforcement> = None;

    // The endpoint's group (its Publisher or Subscriber): PID_GROUP_GUID
    // (0x0052, `WriterProxy::remoteGroupGuid`, RTPS v2.5 Sec.8.4.10.2,
    // Sec.9.6.2.2.5), its entityId; else PID_GROUP_ENTITY_ID (0x0053). A
    // GUID is an octet array: no endianness. ENTITYID_UNKNOWN names no group.
    let mut group_from_guid: Option<[u8; 4]> = None;
    let mut group_from_entity_id: Option<[u8; 4]> = None;

    // =========================================================================
    // PID (Parameter ID) Parsing Loop
    // =========================================================================
    //
    // ## CDR Encapsulation & Endianness (OMG CDR Spec)
    //
    // The CDR (Common Data Representation) spec defines a 2-level encoding:
    //   1. The encapsulation header (bytes 0-1) is ALWAYS big-endian (network order)
    //   2. The payload data uses the endianness indicated BY the header
    //
    // This is why we read the encapsulation with from_be_bytes() above (line 115),
    // but use `is_little_endian` for all PID/length/value parsing below.
    //
    // ## Why Both LE and BE Are Supported
    //
    // Different DDS vendors use different endianness in their CDR encoding:
    //   - HDDS, FastDDS, CycloneDDS: CDR_LE (0x0003) - little-endian payload
    //   - PL_CDR_BE (0x0002) - big-endian payload (DDSI-RTPS 2.5 Sec.10.3)
    //
    // For interoperability, we must handle both. The `is_little_endian` flag
    // (set from the encapsulation header) tells us how to decode each PID.
    //
    // ## PID Structure (4-byte header + variable payload)
    //
    //   Offset 0-1: Parameter ID (u16, endian-dependent)
    //   Offset 2-3: Length in bytes (u16, endian-dependent)
    //   Offset 4+:  Parameter value (length bytes, endian-dependent)
    //
    // The loop continues until PID_SENTINEL (0x0001) is encountered.
    // =========================================================================
    loop {
        // Ensure we have at least 4 bytes for the PID header (id + length)
        if offset + 4 > buf.len() {
            return Err(ParseError::TruncatedData);
        }

        // Read PID and length with correct endianness
        // NOTE: The endianness here matches the CDR payload encoding, NOT the header
        let pid = if is_little_endian {
            u16::from_le_bytes([buf[offset], buf[offset + 1]])
        } else {
            u16::from_be_bytes([buf[offset], buf[offset + 1]])
        };

        let length = if is_little_endian {
            u16::from_le_bytes([buf[offset + 2], buf[offset + 3]])
        } else {
            u16::from_be_bytes([buf[offset + 2], buf[offset + 3]])
        } as usize;

        offset += 4; // Move past PID header to parameter value

        // PID_SENTINEL marks end of parameter list
        if pid == PID_SENTINEL {
            break;
        }

        // Validate we have enough data for this parameter's value
        if offset + length > buf.len() {
            return Err(ParseError::TruncatedData);
        }

        match pid {
            PID_TOPIC_NAME => {
                topic_name = parse_string_parameter(buf, offset, length, is_little_endian);
            }
            PID_TYPE_NAME => {
                type_name = parse_string_parameter(buf, offset, length, is_little_endian);
            }
            PID_GROUP_GUID => {
                if length >= 16 {
                    let mut id = [0u8; 4];
                    id.copy_from_slice(&buf[offset + 12..offset + 16]);
                    group_from_guid = (id != [0; 4]).then_some(id);
                }
            }
            PID_GROUP_ENTITY_ID => {
                if length >= 4 {
                    let mut id = [0u8; 4];
                    id.copy_from_slice(&buf[offset..offset + 4]);
                    group_from_entity_id = (id != [0; 4]).then_some(id);
                }
            }
            PID_ENDPOINT_GUID => {
                if length >= 16 {
                    let mut guid_bytes = [0u8; 16];
                    guid_bytes.copy_from_slice(&buf[offset..offset + 16]);
                    endpoint_guid = Some(GUID::from_bytes(guid_bytes));
                }
            }
            PID_ENDPOINT_SECURITY_INFO => {
                // DDS-Security v1.1 Sec.7.2.8, 7.4.1.5: two u32 masks,
                // `endpoint_security_attributes` then
                // `plugin_endpoint_security_attributes`, in the parameter
                // list's own byte order. Shorter than 8 bytes is truncated
                // and left `None` -- the same posture as a peer that sent
                // no such PID at all.
                if length >= 8 {
                    endpoint_security_info = Some(EndpointSecurityInfo {
                        endpoint_security_attributes: read_u32(buf, offset, is_little_endian),
                        plugin_endpoint_security_attributes: read_u32(
                            buf,
                            offset + 4,
                            is_little_endian,
                        ),
                    });
                }
            }
            PID_TYPE_OBJECT => {
                if length > 0 {
                    let raw = &buf[offset..offset + length];
                    match CompleteTypeObject::decode_cdr2_le(raw) {
                        Ok((type_obj, _consumed)) => {
                            type_object = Some(type_obj);
                        }
                        Err(e) => {
                            // CDR2 decode failed. Some vendors (CoreDX observed,
                            // --type-object-version 1) carry a legacy TypeObject
                            // v1 (XCDR1) payload directly on the standard
                            // PID_TYPE_OBJECT, uncompressed. Try that before
                            // giving up -- small payloads (< ~50 bytes) are
                            // still likely bare TypeIdentifier hashes from other
                            // vendors, not a v1 TypeObject, so the format sniff
                            // keeps this from being attempted (and logged) on
                            // every such payload.
                            if looks_like_legacy_type_object_v1(raw) {
                                match decode_type_object_v1(raw) {
                                    Ok(decoded) => {
                                        type_object = Some(decoded.root);
                                        dependents.extend(decoded.dependents);
                                        type_object_legacy_v1 = true;
                                        log::debug!(
                                            "[SEDP-PARSE] [OK] Parsed legacy TypeObject v1 from PID_TYPE_OBJECT (0x0072)"
                                        );
                                    }
                                    Err(v1_err) => {
                                        log::debug!(
                                            "[SEDP-PARSE] PID_TYPE_OBJECT legacy v1 decode also failed: {:?} (length={})",
                                            v1_err,
                                            length
                                        );
                                    }
                                }
                            } else {
                                // Non-critical: TypeObject decode is best-effort.
                                log::debug!(
                                    "[SEDP-PARSE] PID_TYPE_OBJECT decode failed: {:?} (length={})",
                                    e,
                                    length
                                );
                            }
                        }
                    }
                }
            }
            PID_TYPE_INFORMATION => {
                // OMG DDS-XTypes v1.3 sec. 7.6.3.2 -- non-critical for matching
                // (name-based fallback applies); decode best-effort and
                // store on success. See `parse_type_information` docstring
                // for the wire layout + tolerance policy.
                if length > 0 {
                    type_information = parse_type_information(&buf[offset..offset + length]);
                }
            }
            PID_TYPE_CONSISTENCY => {
                // OMG DDS-XTypes v1.3 sec. 7.6.3.3.3 -- type coercion policy signalled by peer.
                // Wire layout (8-byte payload, LE):
                //   kind(u16) ignore_seq(u8) ignore_str(u8)
                //   ignore_names(u8) prevent_widening(u8) force_validation(u8) pad(u8)
                if length >= 8 {
                    let kind = read_u16(buf, offset, is_little_endian);
                    let ignore_seq_bounds = buf[offset + 2];
                    let ignore_str_bounds = buf[offset + 3];
                    let ignore_member_names = buf[offset + 4];
                    let prevent_type_widening = buf[offset + 5];
                    let force_type_validation = buf[offset + 6];
                    log::debug!(
                        "[SEDP-QOS] PID_TYPE_CONSISTENCY_ENFORCEMENT kind={} ignore_seq={} ignore_str={} ignore_names={} prevent_widening={} force_validation={}",
                        kind,
                        ignore_seq_bounds,
                        ignore_str_bounds,
                        ignore_member_names,
                        prevent_type_widening,
                        force_type_validation,
                    );
                    type_consistency = Some(TypeConsistencyEnforcement {
                        kind,
                        ignore_sequence_bounds: ignore_seq_bounds != 0,
                        ignore_string_bounds: ignore_str_bounds != 0,
                        ignore_member_names: ignore_member_names != 0,
                        prevent_type_widening: prevent_type_widening != 0,
                        force_type_validation: force_type_validation != 0,
                    });
                }
            }
            PID_RELIABILITY => {
                if length >= 4 {
                    let reliability_kind = read_u32(buf, offset, is_little_endian);
                    qos_reliability = match reliability_kind {
                        1 => Some(crate::dds::qos::Reliability::BestEffort),
                        2 => Some(crate::dds::qos::Reliability::Reliable),
                        _ => None,
                    };
                    log::debug!("[SEDP-QOS] [?] PID_RELIABILITY parsed: kind={} (1=BEST_EFFORT, 2=RELIABLE) -> {:?}",
                              reliability_kind, qos_reliability);
                }
            }
            PID_DURABILITY => {
                if length >= 4 {
                    let durability_kind = read_u32(buf, offset, is_little_endian);
                    qos_durability = match durability_kind {
                        0 => Some(crate::dds::qos::Durability::Volatile),
                        1 => Some(crate::dds::qos::Durability::TransientLocal),
                        // TRANSIENT (kind=2) mapped to TransientLocal: HDDS does not implement
                        // distributed cache (TRANSIENT requires a persistence service that
                        // outlives the DataWriter). TransientLocal is the closest behavior.
                        2 => Some(crate::dds::qos::Durability::Transient),
                        3 => Some(crate::dds::qos::Durability::Persistent),
                        _ => None,
                    };
                    log::debug!("[SEDP-QOS] [?] PID_DURABILITY parsed: kind={} (0=VOLATILE, 1=TRANSIENT_LOCAL, 2=TRANSIENT, 3=PERSISTENT) -> {:?}",
                              durability_kind, qos_durability);
                }
            }
            PID_DURABILITY_SERVICE => {
                if qos_durability_service.is_none() {
                    qos_durability_service =
                        parse_durability_service(buf, offset, length, is_little_endian);
                }
            }
            PID_HISTORY => {
                if length >= 8 {
                    let history_kind = read_u32(buf, offset, is_little_endian);
                    let history_depth = read_u32(buf, offset + 4, is_little_endian);
                    qos_history = match history_kind {
                        0 => Some(crate::dds::qos::History::KeepLast(history_depth)),
                        1 => Some(crate::dds::qos::History::KeepAll),
                        _ => None,
                    };
                    log::debug!(
                        "[SEDP-QOS] [?] PID_HISTORY parsed: kind={} depth={} (0=KEEP_LAST, 1=KEEP_ALL) -> {:?}",
                        history_kind,
                        history_depth,
                        qos_history
                    );
                }
            }
            PID_PRESENTATION => {
                if qos_presentation.is_none() {
                    qos_presentation = parse_presentation(buf, offset, length, is_little_endian);
                }
            }
            PID_OWNERSHIP => {
                if length >= 4 {
                    let ownership_kind = read_u32(buf, offset, is_little_endian);
                    qos_ownership = match ownership_kind {
                        0 => Some(crate::dds::qos::Ownership::shared()),
                        1 => Some(crate::dds::qos::Ownership::exclusive()),
                        _ => None,
                    };
                    if crate::config::env_flags::interop_diagnostics() {
                        eprintln!("[SEDP] PID_OWNERSHIP={}", ownership_kind);
                    }
                }
            }
            PID_OWNERSHIP_STRENGTH => {
                if length >= 4 {
                    let strength = read_i32(buf, offset, is_little_endian);
                    qos_ownership_strength = Some(strength);
                    if crate::config::env_flags::interop_diagnostics() {
                        eprintln!("[SEDP] PID_OWNERSHIP_STRENGTH={}", strength);
                    }
                }
            }
            PID_DEADLINE => {
                if length >= 8 {
                    let seconds = read_u32(buf, offset, is_little_endian);
                    let fraction = read_u32(buf, offset + 4, is_little_endian);
                    qos_deadline = Some(if seconds >= 0x7FFF_FFFF {
                        crate::dds::qos::Deadline::infinite()
                    } else {
                        // RTPS v2.5 sec. 9.3.2: Duration_t fraction is 2^-32 seconds.
                        let frac_nanos = fraction_to_nanos(fraction);
                        let nanos = (seconds as u64) * 1_000_000_000 + frac_nanos;
                        crate::dds::qos::Deadline::new(std::time::Duration::from_nanos(nanos))
                    });
                    log::debug!(
                        "[SEDP-QOS] [?] PID_DEADLINE parsed: {}s + {} frac -> {:?}",
                        seconds,
                        fraction,
                        qos_deadline
                    );
                }
            }
            PID_LIFESPAN => {
                if length >= 8 {
                    let seconds = read_u32(buf, offset, is_little_endian);
                    let fraction = read_u32(buf, offset + 4, is_little_endian);
                    qos_lifespan = Some(if seconds >= 0x7FFF_FFFF {
                        crate::dds::qos::Lifespan::infinite()
                    } else {
                        // RTPS v2.5 sec. 9.3.2: Duration_t second word is a 2^-32 s
                        // fraction. A 0x0103 peer may encode nanoseconds instead
                        // directly (DDS PIM form) -> see duration_to_nanos.
                        let nanos = duration_to_nanos(seconds, fraction, opendds_duration);
                        crate::dds::qos::Lifespan::new(std::time::Duration::from_nanos(nanos))
                    });
                    log::debug!(
                        "[SEDP-QOS] [?] PID_LIFESPAN parsed: {}s + {} frac -> {:?}",
                        seconds,
                        fraction,
                        qos_lifespan
                    );
                }
            }
            PID_LIVELINESS => {
                // LivelinessQosPolicy { kind; Duration_t lease_duration }:
                // AUTOMATIC 0, MANUAL_BY_PARTICIPANT 1, MANUAL_BY_TOPIC 2.
                // An unknown kind is not read as any of them.
                if length >= 12 {
                    let kind = match read_u32(buf, offset, is_little_endian) {
                        0 => Some(crate::dds::qos::LivelinessKind::Automatic),
                        1 => Some(crate::dds::qos::LivelinessKind::ManualByParticipant),
                        2 => Some(crate::dds::qos::LivelinessKind::ManualByTopic),
                        _ => None,
                    };
                    let lease =
                        read_duration_t(buf, offset + 4, is_little_endian, opendds_duration);
                    qos_liveliness = kind.map(|kind| crate::dds::qos::Liveliness::new(kind, lease));
                    log::debug!("[SEDP-QOS] PID_LIVELINESS parsed: {:?}", qos_liveliness);
                }
            }
            PID_LATENCY_BUDGET => {
                // LatencyBudgetQosPolicy { Duration_t duration }.
                if length >= 8 {
                    qos_latency_budget = Some(crate::dds::qos::LatencyBudget::new(
                        read_duration_t(buf, offset, is_little_endian, opendds_duration),
                    ));
                    log::debug!(
                        "[SEDP-QOS] PID_LATENCY_BUDGET parsed: {:?}",
                        qos_latency_budget
                    );
                }
            }
            PID_DESTINATION_ORDER => {
                // DestinationOrderQosPolicy { kind }: BY_RECEPTION_TIMESTAMP
                // 0, BY_SOURCE_TIMESTAMP 1.
                if length >= 4 {
                    qos_destination_order = match read_u32(buf, offset, is_little_endian) {
                        0 => Some(crate::dds::qos::DestinationOrder::by_reception_timestamp()),
                        1 => Some(crate::dds::qos::DestinationOrder::by_source_timestamp()),
                        _ => None,
                    };
                    log::debug!(
                        "[SEDP-QOS] PID_DESTINATION_ORDER parsed: {:?}",
                        qos_destination_order
                    );
                }
            }
            PID_PARTITION => {
                // Format: sequence_length (u32) + for each: string_length (u32) + string + NUL + padding
                if length >= 4 {
                    let seq_len = read_u32(buf, offset, is_little_endian) as usize;
                    let mut pos = offset + 4;
                    let end = offset + length;
                    for _ in 0..seq_len {
                        if pos + 4 > end {
                            break;
                        }
                        let str_len = read_u32(buf, pos, is_little_endian) as usize;
                        pos += 4;
                        if str_len == 0 || pos + str_len > end {
                            break;
                        }
                        // str_len includes NUL terminator
                        let name_len = if buf[pos + str_len - 1] == 0 {
                            str_len - 1
                        } else {
                            str_len
                        };
                        if let Ok(name) = std::str::from_utf8(&buf[pos..pos + name_len]) {
                            qos_partition_names.push(name.to_string());
                        }
                        // Advance past string + padding to 4-byte alignment
                        let padded = (str_len + 3) & !3;
                        pos += padded;
                    }
                    log::debug!(
                        "[SEDP-QOS] [?] PID_PARTITION parsed: {} partition(s): {:?}",
                        qos_partition_names.len(),
                        qos_partition_names
                    );
                }
            }
            PID_DATA_TAGS => {
                // The access control judges the endpoint on these
                // (DDS Security v1.1 Sec.9.4.1.3.2.3.1.5): an announcement
                // whose tags cannot be read is refused, never read with
                // fewer tags than it carries.
                let Some(tags) =
                    parse_data_tags(&buf[offset..offset + length], is_little_endian, is_cdr2)
                else {
                    log::warn!(
                        "[SEDP] PID_DATA_TAGS of {} byte(s) is malformed: announcement refused",
                        length
                    );
                    return Err(ParseError::InvalidFormat);
                };
                qos_data_tags = Some(tags);
            }
            PID_DATA_REPRESENTATION => {
                if length >= 4 {
                    let seq_len = read_u32(buf, offset, is_little_endian) as usize;
                    let max_items = seq_len.min((length - 4) / 2);
                    for i in 0..max_items {
                        let repr = read_u16(buf, offset + 4 + i * 2, is_little_endian);
                        qos_data_representation.push(repr);
                    }
                    log::debug!(
                        "[SEDP-QOS] [?] PID_DATA_REPRESENTATION: {:?} (0=XCDR1, 2=XCDR2)",
                        qos_data_representation
                    );
                }
            }
            PID_USER_DATA => {
                if user_data.is_none() {
                    user_data = parse_user_data_parameter(buf, offset, length, is_little_endian);
                }
            }
            // HDDS vendor-specific SHM capability hint. Uses the same
            // length-prefixed string encoding as PID_USER_DATA, but parsed
            // into its own field: this is never the application's
            // UserDataQosPolicy, see PID_HDDS_SHM_CAPABILITY's doc.
            PID_HDDS_SHM_CAPABILITY => {
                if shm_capability.is_none() {
                    shm_capability =
                        parse_user_data_parameter(buf, offset, length, is_little_endian);
                }
            }
            // Parse PID_PARTICIPANT_GUID - cross-vendor interop requirement
            // Links the endpoint to its participant
            PID_PARTICIPANT_GUID => {
                if length >= 16 {
                    let mut guid_bytes = [0u8; 16];
                    guid_bytes.copy_from_slice(&buf[offset..offset + 16]);
                    participant_guid = Some(GUID::from_bytes(guid_bytes));
                    log::debug!(
                        "[SEDP-PARSE] [*] PID_PARTICIPANT_GUID (0x0050) parsed: {:?}",
                        participant_guid
                    );
                } else {
                    log::debug!(
                        "[SEDP-PARSE] [!]  PID_PARTICIPANT_GUID has invalid length: {}",
                        length
                    );
                    is_participant_data = true; // Don't require topic_name/type_name/endpoint_guid
                }
            }
            PID_PARTICIPANT_LEASE_DURATION => {
                log::debug!("[SEDP-PARSE] [*] PID_PARTICIPANT_LEASE_DURATION (0x0002) - skipping");
                is_participant_data = true;
            }
            PID_BUILTIN_ENDPOINT_SET => {
                log::debug!("[SEDP-PARSE] [*] PID_BUILTIN_ENDPOINT_SET (0x0058) - skipping");
                is_participant_data = true;
            }
            PID_METATRAFFIC_UNICAST_LOCATOR => {
                log::debug!("[SEDP-PARSE] [*] PID_METATRAFFIC_UNICAST_LOCATOR (0x0032) - skipping");
                is_participant_data = true;
            }
            // Parse PID_UNICAST_LOCATOR (0x002f) - CRITICAL for OpenDDS interop
            // This tells HDDS where to send user data to the remote endpoint.
            // Format: kind (4 bytes) + port (4 bytes) + address (16 bytes) = 24 bytes
            PID_UNICAST_LOCATOR => {
                if length >= 24 {
                    let kind = if is_little_endian {
                        u32::from_le_bytes([
                            buf[offset],
                            buf[offset + 1],
                            buf[offset + 2],
                            buf[offset + 3],
                        ])
                    } else {
                        u32::from_be_bytes([
                            buf[offset],
                            buf[offset + 1],
                            buf[offset + 2],
                            buf[offset + 3],
                        ])
                    };

                    let port = if is_little_endian {
                        u32::from_le_bytes([
                            buf[offset + 4],
                            buf[offset + 5],
                            buf[offset + 6],
                            buf[offset + 7],
                        ])
                    } else {
                        u32::from_be_bytes([
                            buf[offset + 4],
                            buf[offset + 5],
                            buf[offset + 6],
                            buf[offset + 7],
                        ])
                    };

                    // A Locator_t port is 32 bits on the wire (RTPS v2.5
                    // Sec.9.3.2.3) but a UDP port is 16: a peer announcing a
                    // port above 65535 has sent a malformed locator, and it
                    // is dropped here rather than reduced modulo 65536 to a
                    // port nobody listens on.
                    let udp_port = u16::try_from(port).ok();
                    if udp_port.is_none() {
                        log::debug!(
                            "[SEDP-PARSE] [!]  PID_UNICAST_LOCATOR: port {} exceeds UDP range, locator ignored",
                            port
                        );
                    }

                    // Address is 16 bytes starting at offset + 8
                    // IPv4: kind=1, address in last 4 bytes (offset + 20..offset + 24)
                    // IPv6: kind=2, address in all 16 bytes
                    let socket_addr: Option<SocketAddr> = match kind {
                        1 => {
                            // LOCATOR_KIND_UDPV4 - IPv4 address in last 4 bytes
                            let ip = Ipv4Addr::new(
                                buf[offset + 20],
                                buf[offset + 21],
                                buf[offset + 22],
                                buf[offset + 23],
                            );
                            udp_port.map(|p| SocketAddr::new(IpAddr::V4(ip), p))
                        }
                        2 => {
                            // LOCATOR_KIND_UDPV6 - IPv6 address in all 16 bytes
                            let mut addr_bytes = [0u8; 16];
                            addr_bytes.copy_from_slice(&buf[offset + 8..offset + 24]);
                            let ip = Ipv6Addr::from(addr_bytes);
                            udp_port.map(|p| SocketAddr::new(IpAddr::V6(ip), p))
                        }
                        _ => {
                            log::debug!(
                                "[SEDP-PARSE] [!]  PID_UNICAST_LOCATOR: unknown kind={}",
                                kind
                            );
                            None
                        }
                    };

                    if let Some(addr) = socket_addr {
                        log::debug!(
                            "[SEDP-PARSE] [*] PID_UNICAST_LOCATOR (0x002f): {} (kind={})",
                            addr,
                            kind
                        );
                        unicast_locators.push(addr);
                    }
                } else {
                    log::debug!(
                        "[SEDP-PARSE] [!]  PID_UNICAST_LOCATOR: invalid length {} (expected 24)",
                        length
                    );
                }
            }
            // Handle a ZLIB-compressed TypeObject in vendor PID 0x8021
            // Reference: OMG RTPS v2.5 Sec.9.6.3.1, XTypes v1.3 Sec.7.3
            PID_TYPE_OBJECT_LB => {
                // The parameter payload begins with RTI's 12-byte compression
                // envelope (real Connext 7.7.0 wire, dissected identically by
                // Wireshark): u32 LE compression class id (1 = ZLIB), u32 LE
                // uncompressed length, u32 LE compressed length, then the
                // compressed stream. The zlib stream therefore starts at
                // offset + 12; feeding the envelope to the decoder fails.
                // Network input: bound the declared lengths before use so a
                // hostile envelope cannot drive allocation or overread.
                const LB_ENVELOPE_LEN: usize = 12;
                const LB_COMPRESSION_ZLIB: u32 = 1;
                const LB_MAX_UNCOMPRESSED: usize = 1 << 20;
                let envelope = (length >= LB_ENVELOPE_LEN + 2)
                    .then(|| {
                        let word = |i: usize| -> u32 {
                            let s = offset + i;
                            u32::from_le_bytes([buf[s], buf[s + 1], buf[s + 2], buf[s + 3]])
                        };
                        (word(0), word(4) as usize, word(8) as usize)
                    })
                    .filter(|&(class, uncompressed_len, compressed_len)| {
                        class == LB_COMPRESSION_ZLIB
                            && uncompressed_len <= LB_MAX_UNCOMPRESSED
                            && compressed_len <= length - LB_ENVELOPE_LEN
                    });
                let (stream_offset, stream_len, expected_len) = match envelope {
                    Some((_, uncompressed_len, compressed_len)) => (
                        offset + LB_ENVELOPE_LEN,
                        compressed_len,
                        Some(uncompressed_len),
                    ),
                    // No recognizable envelope: treat the whole parameter as
                    // the stream (previous behavior, kept as a fallback).
                    None => (offset, length, None),
                };
                match decompress_type_object(buf, stream_offset, stream_len) {
                    Ok(decompressed) if expected_len.is_some_and(|e| e != decompressed.len()) => {
                        log::debug!(
                            "[SEDP-PARSE] [!]  PID_TYPE_OBJECT_LB length mismatch: envelope says {:?}, got {}",
                            expected_len,
                            decompressed.len()
                        );
                    }
                    Ok(decompressed) => match CompleteTypeObject::decode_cdr2_le(&decompressed) {
                        Ok((type_obj, _)) => {
                            type_object = Some(type_obj);
                            log::debug!("[SEDP-PARSE] [OK] Parsed CompleteTypeObject from compressed ZLIB (0x8021)");
                        }
                        Err(_) => {
                            // CDR2 decode failed. RTI Connext in
                            // --type-object-version 1 mode compresses a legacy
                            // TypeObject v1 (XCDR1) payload rather than a
                            // CDR2 CompleteTypeObject; try that on the same
                            // decompressed bytes before giving up.
                            if looks_like_legacy_type_object_v1(&decompressed) {
                                match decode_type_object_v1(&decompressed) {
                                    Ok(decoded) => {
                                        type_object = Some(decoded.root);
                                        dependents.extend(decoded.dependents);
                                        type_object_legacy_v1 = true;
                                        log::debug!(
                                            "[SEDP-PARSE] [OK] Parsed legacy TypeObject v1 from compressed ZLIB (0x8021)"
                                        );
                                    }
                                    Err(v1_err) => {
                                        log::debug!(
                                            "[SEDP-PARSE] [!]  Failed to parse legacy TypeObject v1 from decompressed data: {:?}",
                                            v1_err
                                        );
                                    }
                                }
                            } else {
                                log::debug!("[SEDP-PARSE] [!]  Failed to parse CompleteTypeObject from decompressed data");
                            }
                        }
                    },
                    Err(_) => {
                        log::debug!(
                            "[SEDP-PARSE] [!]  Failed to decompress ZLIB data for TypeObject"
                        );
                    }
                }
            }
            _ => {
                // Log unknown PIDs so we can see what we're missing!
                // This is CRITICAL for debugging interop issues.
                // Don't fail on unknown PIDs - only fail if CRITICAL fields are missing
                if pid >= 0x8000 {
                    // Vendor-specific PID (0x8000+, any vendor)
                    log::debug!(
                        "[SEDP-PARSE] [i]  Skipping vendor-specific PID: 0x{:04x} (length={})",
                        pid,
                        length
                    );
                } else {
                    // Standard DDS PID we don't handle yet
                    log::debug!(
                        "[SEDP-PARSE] [i]  Skipping unknown standard PID: 0x{:04x} (length={})",
                        pid,
                        length
                    );
                }
            }
        }

        offset += (length + 3) & !3;
    }

    // ParticipantData SEDP doesn't have topic_name/type_name/endpoint_guid
    // Only Publication/Subscription announcements need these fields
    if is_participant_data {
        // ParticipantData - ignore and return error so caller skips it
        log::debug!(
            "[SEDP-PARSE] [i]  Ignoring ParticipantData SEDP (not a Publication/Subscription)"
        );
        return Err(ParseError::InvalidFormat);
    }

    let topic_name = topic_name.ok_or(ParseError::InvalidFormat)?;
    let type_name = type_name.ok_or(ParseError::InvalidFormat)?;
    let endpoint_guid = endpoint_guid.ok_or(ParseError::InvalidFormat)?;
    let qos_hash = simple_hash(&topic_name);

    // Derive participant_guid from endpoint_guid if not explicitly provided
    // A receiver links each endpoint to its participant through this GUID
    let final_participant_guid = participant_guid.unwrap_or_else(|| {
        // Derive from endpoint_guid: copy prefix + use participant entity ID
        let mut pguid_bytes = [0u8; 16];
        pguid_bytes[..12].copy_from_slice(&endpoint_guid.as_bytes()[..12]); // Copy prefix
        pguid_bytes[12..16].copy_from_slice(&[0x00, 0x00, 0x01, 0xC1]); // Participant entityId
        GUID::from_bytes(pguid_bytes)
    });

    // Build QoS object from parsed PIDs if ANY QoS values were found
    let qos = if qos_reliability.is_some()
        || qos_durability.is_some()
        || qos_history.is_some()
        || qos_presentation.is_some()
        || qos_durability_service.is_some()
        || qos_ownership.is_some()
        || qos_ownership_strength.is_some()
        || qos_deadline.is_some()
        || qos_lifespan.is_some()
        || qos_liveliness.is_some()
        || qos_latency_budget.is_some()
        || qos_destination_order.is_some()
        || !qos_partition_names.is_empty()
        || !qos_data_representation.is_empty()
        || qos_data_tags.is_some()
    {
        // Start with default QoS and override with parsed values
        let mut qos_obj = crate::dds::qos::QoS::default();

        if let Some(reliability) = qos_reliability {
            qos_obj.reliability = reliability;
        }
        if let Some(durability) = qos_durability {
            qos_obj.durability = durability;
        }
        if let Some(history) = qos_history {
            qos_obj.history = history;
        }
        if let Some(presentation) = qos_presentation {
            qos_obj.presentation = presentation;
        }
        if let Some(ds) = qos_durability_service {
            qos_obj.durability_service = ds;
        }
        if let Some(ownership) = qos_ownership {
            qos_obj.ownership = ownership;
        }
        if let Some(strength) = qos_ownership_strength {
            qos_obj.ownership_strength =
                crate::qos::ownership::OwnershipStrength { value: strength };
        }
        if let Some(deadline) = qos_deadline {
            qos_obj.deadline = deadline;
        }
        if let Some(lifespan) = qos_lifespan {
            qos_obj.lifespan = lifespan;
        }
        if let Some(liveliness) = qos_liveliness {
            qos_obj.liveliness = liveliness;
        }
        if let Some(latency_budget) = qos_latency_budget {
            qos_obj.latency_budget = latency_budget;
        }
        if let Some(destination_order) = qos_destination_order {
            qos_obj.destination_order = destination_order;
        }
        if !qos_partition_names.is_empty() {
            qos_obj.partition = crate::qos::partition::Partition::new(qos_partition_names);
        }
        if !qos_data_representation.is_empty() {
            qos_obj.data_representation = qos_data_representation;
        }
        if let Some(tags) = qos_data_tags {
            qos_obj.data_tags = crate::qos::data_tags::DataTags { tags };
        }

        log::debug!(
            "[SEDP-QOS] [OK] Built QoS from PIDs: reliability={:?}, durability={:?}, history={:?}, presentation={:?}, ownership={:?}, deadline={:?}, durability_service.depth={}",
            qos_obj.reliability, qos_obj.durability, qos_obj.history, qos_obj.presentation,
            qos_obj.ownership, qos_obj.deadline,
            qos_obj.durability_service.history_depth
        );
        Some(qos_obj)
    } else {
        // No QoS PIDs found - will apply vendor defaults later
        log::debug!("[SEDP-QOS] [!]  No QoS PIDs found in SEDP - will apply vendor defaults");
        None
    };

    // Log parsed unicast locators for OpenDDS interop debugging
    if !unicast_locators.is_empty() {
        log::debug!(
            "[SEDP-PARSE] [*] Parsed {} unicast locator(s): {:?}",
            unicast_locators.len(),
            unicast_locators
        );
    }

    // DDS-XTypes v1.3 sec. 7.6.3.4: TypeConsistencyEnforcement is a reader-side QoS.
    // When the wire payload omits PID_TYPE_CONSISTENCY_ENFORCEMENT (0x0074), keep
    // type_consistency as None here: the parser reports presence/absence only.
    // The ABSENT-PID semantics (XTypes v1.3 Sec 7.6.3.4.1: spec default policy
    // with ignore_member_names=false) are materialized downstream at the wire ->
    // endpoint boundary, `EndpointInfo::from_sedp`, and ONLY for READER
    // endpoints. Local endpoints that never set the policy keep the permissive
    // matcher fallback (matcher default_policy(), ignore_member_names=true).

    Ok(SedpData {
        topic_name,
        type_name,
        participant_guid: final_participant_guid, // Always populated (explicit or derived)
        endpoint_guid,
        qos_hash,
        has_explicit_reliability: qos_reliability.is_some(),
        has_explicit_ownership: qos_ownership.is_some(),
        has_ownership_strength: qos_ownership_strength.is_some(),
        qos, // Return actual QoS parsed from PIDs!
        type_object,
        dependents,
        type_object_legacy_v1,
        type_information,
        unicast_locators, // Now parsed from PID_UNICAST_LOCATOR for OpenDDS interop
        user_data,
        shm_capability,
        type_consistency,
        group_entity_id: group_from_guid.or(group_from_entity_id),
        endpoint_security_info,
    })
}

#[cfg(test)]
mod duration_tests {
    use super::duration_to_nanos;

    // PID_LIFESPAN value bytes for 250 ms in the two encodings:
    //   2^-32 fraction (RTPS PSM):  00 00 00 00 | 00 00 00 40  (0.25 * 2^32)
    //   legacy nanosec (IDL form):  00 00 00 00 | 80 b2 e6 0e  (250_000_000)
    // Both are little-endian { seconds: u32, second_word: u32 }.

    fn decode_value_bytes(v: &[u8; 8]) -> (u32, u32) {
        let seconds = u32::from_le_bytes([v[0], v[1], v[2], v[3]]);
        let second_word = u32::from_le_bytes([v[4], v[5], v[6], v[7]]);
        (seconds, second_word)
    }

    #[test]
    fn opendds_new_fraction_encoding_decodes_250ms() {
        let bytes: [u8; 8] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40];
        let (seconds, second_word) = decode_value_bytes(&bytes);
        assert_eq!(second_word, 0x4000_0000);
        // 0x40000000 >= 1e9 can never be a legal nanosec count, so the
        // OpenDDS gate must fall through to the spec fraction path.
        assert_eq!(duration_to_nanos(seconds, second_word, true), 250_000_000);
    }

    #[test]
    fn opendds_legacy_nanosec_encoding_decodes_250ms() {
        let bytes: [u8; 8] = [0x00, 0x00, 0x00, 0x00, 0x80, 0xb2, 0xe6, 0x0e];
        let (seconds, second_word) = decode_value_bytes(&bytes);
        assert_eq!(second_word, 250_000_000);
        assert_eq!(duration_to_nanos(seconds, second_word, true), 250_000_000);
    }

    #[test]
    fn non_opendds_always_decodes_spec_fraction() {
        // Same fraction bytes from a spec-conformant vendor: identical result
        // whether or not the value is below the nanosec plausibility bound.
        assert_eq!(duration_to_nanos(0, 0x4000_0000, false), 250_000_000);
        // 0x0EE6B280 as a fraction is ~58.2 ms, NOT 250 ms.
        assert_eq!(duration_to_nanos(0, 0x0EE6_B280, false), 58_207_661);
    }

    #[test]
    fn legacy_gate_boundary_is_one_second() {
        // 999_999_999 is the largest legal nanosec count: legacy path.
        assert_eq!(duration_to_nanos(0, 999_999_999, true), 999_999_999);
        // 1_000_000_000 is never a legal nanosec count: spec fraction path
        // (1e9 * 1e9 / 2^32 = 232_830_643.65 ns, rounded).
        assert_eq!(duration_to_nanos(0, 1_000_000_000, true), 232_830_644);
    }

    #[test]
    fn whole_second_durations_agree_in_both_encodings() {
        assert_eq!(duration_to_nanos(3, 0, true), 3_000_000_000);
        assert_eq!(duration_to_nanos(3, 0, false), 3_000_000_000);
    }
}

#[cfg(test)]
mod type_information_bounds_tests {
    use super::{parse_sedp, parse_type_information, ParseError};

    /// The 167-octet input of the release fuzz gate (`fuzz_rtps_sedp`, an
    /// out-of-memory). Its PID_TYPE_INFORMATION (0x0075) value, octets
    /// 10..129, holds a dependency-format member whose dependency count and
    /// sequence count are both 0x08080808 = 134744072. Sizing the vector
    /// from that count asked the allocator for 2694881440 octets.
    const SEDP_OOM_REPRODUCER: [u8; 167] = [
        0x00, 0x0a, 0x11, 0x02, 0x00, 0x00, 0x00, 0x75, 0x00, 0x77, 0x00, 0x00, 0x1c, 0x1c, 0x1c,
        0x1c, 0x00, 0x00, 0x2d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x77, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
        0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
        0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
        0x08, 0x08, 0x08, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
        0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
        0x08, 0x08, 0x08, 0x08, 0x1c, 0x1c, 0x1c, 0x1c, 0x1c, 0x1c, 0x1c, 0x1c, 0x00, 0x00, 0x00,
        0x06, 0x00,
    ];

    /// The PID_TYPE_INFORMATION value of the reproducer.
    fn reproducer_type_information() -> Vec<u8> {
        SEDP_OOM_REPRODUCER[10..129].to_vec()
    }

    /// A PID_TYPE_INFORMATION value holding one dependency-format member
    /// with id `mid`, whose dependency and sequence counts both say
    /// `declared` while `present` dependencies follow.
    fn type_info_value(mid: u32, declared: u32, present: usize) -> Vec<u8> {
        let content_len = 40 + 24 * present;
        let mut v = Vec::new();
        v.extend_from_slice(&0u32.to_le_bytes()); // DHEADER of the value
        v.extend_from_slice(&mid.to_le_bytes()); // EMHEADER1
        v.extend_from_slice(&(content_len as u32).to_le_bytes()); // NEXTINT
        v.extend_from_slice(&[0; 8]); // DHEADER_tiwdeps, DHEADER_tiws
        v.push(0xF2); // discriminator: EK_COMPLETE
        v.extend_from_slice(&[0x11; 14]); // equivalence hash
        v.push(0); // pad
        v.extend_from_slice(&1234u32.to_le_bytes()); // typeobject size
        v.extend_from_slice(&declared.to_le_bytes()); // dependent count
        v.extend_from_slice(&[0; 4]); // sequence DHEADER
        v.extend_from_slice(&declared.to_le_bytes()); // sequence count
        for i in 0..present {
            v.extend_from_slice(&20u32.to_le_bytes()); // DHEADER of the element
            v.push(0xF1); // discriminator: EK_MINIMAL
            v.extend_from_slice(&[0x22; 14]); // equivalence hash
            v.push(0); // pad
            v.extend_from_slice(&(100 + i as u32).to_le_bytes());
        }
        v
    }

    #[test]
    fn reproducer_dependency_count_past_buffer_is_refused() {
        // Refused before anything is sized from the count; the whole
        // message ends short, so the SEDP parse reports truncation.
        assert!(parse_type_information(&reproducer_type_information()).is_none());
        assert!(matches!(
            parse_sedp(&SEDP_OOM_REPRODUCER),
            Err(ParseError::TruncatedData)
        ));
    }

    #[test]
    fn oversized_dependency_count_refuses_the_member_whole() {
        // The reproducer's value with the member id set to the complete
        // TypeInformation member (0x1002). The count still asks for
        // 134744072 dependencies: no part of the member may be kept.
        let mut value = reproducer_type_information();
        value[4..8].copy_from_slice(&0x1002u32.to_le_bytes());
        assert!(parse_type_information(&value).is_none());
    }

    /// A PID_TYPE_INFORMATION value from Dust DDS 0.16 (union_bitmask16,
    /// captured on the OMG xtypes rig): both members use LC=5, where NEXTINT
    /// is the member's own DHEADER. Read as LC=4 it was shifted four octets
    /// and refused as "20 dependencies that do not fit".
    #[test]
    fn an_lc5_member_reads_its_nextint_as_the_member_dheader() {
        let value: Vec<u8> = [
            "88000000",
            "01100050",
            "3c000000",
            "14000000",
            "f1",
            "53642851ae1cbfc696265f510c70",
            "00",
            "5c000000",
            "01000000",
            "1c000000",
            "01000000",
            "14000000",
            "f1",
            "1885b47e1c4b56717434ecb47313",
            "00",
            "20000000",
            "02100050",
            "3c000000",
            "14000000",
            "f2",
            "da54ae6c5a706f23d6cc38a9340c",
            "00",
            "89000000",
            "01000000",
            "1c000000",
            "01000000",
            "14000000",
            "f2",
            "1f435b469a4df0306ef8f498ec6d",
            "00",
            "30000000",
        ]
        .concat()
        .as_bytes()
        .chunks(2)
        .map(|h| u8::from_str_radix(std::str::from_utf8(h).expect("ascii"), 16).expect("hex"))
        .collect();
        assert_eq!(value.len(), 140);
        let info = parse_type_information(&value).expect("well-formed TypeInformation");
        let minimal = info.minimal.expect("minimal member");
        assert_eq!(
            minimal.hash,
            crate::xtypes::EquivalenceHash::from_bytes([
                0x53, 0x64, 0x28, 0x51, 0xae, 0x1c, 0xbf, 0xc6, 0x96, 0x26, 0x5f, 0x51, 0x0c, 0x70
            ])
        );
        assert_eq!(minimal.typeobject_serialized_size, 0x5c);
        assert_eq!(minimal.dependent_typeids.len(), 1);
        assert_eq!(
            minimal.dependent_typeids[0].typeobject_serialized_size,
            0x20
        );
        let complete = info.complete.expect("complete member");
        assert_eq!(complete.typeobject_serialized_size, 0x89);
        assert_eq!(complete.dependent_typeids[0].kind, 0xF2);
    }

    #[test]
    fn dependency_list_that_fits_still_parses() {
        let value = type_info_value(0x1002, 2, 2);
        let info = parse_type_information(&value).expect("well-formed TypeInformation");
        let complete = info.complete.expect("complete member");
        assert_eq!(complete.typeobject_serialized_size, 1234);
        assert_eq!(complete.dependent_typeids.len(), 2);
        assert_eq!(complete.dependent_typeids[1].kind, 0xF1);
        assert_eq!(
            complete.dependent_typeids[1].typeobject_serialized_size,
            101
        );
    }

    #[test]
    fn one_dependency_past_the_buffer_is_refused() {
        // Two present, three declared: the third would start past the end.
        let value = type_info_value(0x1002, 3, 2);
        assert!(parse_type_information(&value).is_none());
    }
}
