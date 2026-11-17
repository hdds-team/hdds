// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! DATA_REPRESENTATION: what a writer offers and encodes, resolved once at
//! its creation, what an endpoint announces, and the verdict on a pair,
//! per DDS-XTypes v1.3 Sec.7.6.3.1 DataRepresentationQosPolicy.

#![allow(dead_code)]

use crate::core::discovery::multicast::fsm::EndpointKind;
use crate::core::ser::CdrError;
#[cfg(test)]
use crate::core::types::TypeDescriptor;
use crate::dds::CdrVersion;

/// DDS Table 2.60 policy ID for DATA_REPRESENTATION.
pub(crate) const POLICY_ID_DATA_REPRESENTATION: u32 =
    crate::dds::qos::policy_id::DATA_REPRESENTATION;

/// Wire code for XCDR v1 per DDS-XTypes v1.3 sec. 7.6.2.1.2.
const XCDR1_CODE: u16 = 0x0000;
/// Wire code for XCDR v2 per DDS-XTypes v1.3 sec. 7.6.2.1.2.
const XCDR2_CODE: u16 = 0x0002;

/// What an endpoint of THIS participant announces in PID_DATA_REPRESENTATION
/// (`build_sedp_rtps_packet_secured` and the legacy `build_sedp`, every
/// dialect), by the kind of the endpoint.
///
/// * A WRITER announces the one representation it offers and encodes, the
///   first element of its list: DDS-XTypes v1.3 Sec.7.6.3.1.1, "Writers offer
///   a single representation. A writer will use its offered policy to
///   communicate with its matched readers", and "this specification does not
///   specify any meaning for the representation identifiers after the
///   first". A writer of this participant never has an empty list: it is
///   resolved at creation (`resolve_writer_data_representation`). An empty
///   one, from a caller that built an announcement by hand, is the spec
///   default, `[XCDR]` ("An empty list of preferences shall be taken to be
///   equivalent to a list containing the single element XCDR").
/// * A READER announces the list it was created with, or `[XCDR, XCDR2]`
///   when it set none: what the clause asks of an XTYPES 1.2+ reader that
///   decodes XCDR ("Shall request XCDR2 encoding [...] they shall also
///   request XCDR encoding in addition to XCDR2 encoding"); its data plane
///   accepts both (`data_repr_incompatible`). A reader whose type does not
///   decode XCDR never reaches here with an empty list: it requests
///   `[XCDR2]` (`resolve_reader_data_representation`).
///
/// The one reading of a LOCAL reader's DATA_REPRESENTATION: every verdict
/// that judges a reader of this participant (the discovery match, the
/// registration catch-up, the SEDP writer-blocking gate, the in-process
/// binding) reads it through this function, so a peer and we judge the pair
/// on the same list.
pub(crate) fn announced_data_representation(kind: EndpointKind, policy: &[u16]) -> &[u16] {
    static READER_DEFAULT_ANNOUNCED: [u16; 2] = [XCDR1_CODE, XCDR2_CODE];
    static WRITER_DEFAULT_ANNOUNCED: [u16; 1] = [XCDR1_CODE];
    match (kind, policy.first()) {
        (EndpointKind::Reader, None) => &READER_DEFAULT_ANNOUNCED,
        (EndpointKind::Reader, Some(_)) => policy,
        (EndpointKind::Writer, None) => &WRITER_DEFAULT_ANNOUNCED,
        (EndpointKind::Writer, Some(_)) => &policy[..1],
    }
}

/// Resolve, once, at creation, the representation a DataWriter offers and
/// encodes, and return the version of every sample it will serialize.
///
/// DDS-XTypes v1.3 Sec.7.6.3.1.1: the policy "cannot be changed after the
/// entity in question has been enabled"; "The default value of the
/// DataRepresentationQosPolicy shall be an empty list of preferences. An
/// empty list of preferences shall be taken to be equivalent to a list
/// containing the single element XCDR".
///
/// * An empty list becomes `[XCDR]`, written into `qos` so `get_qos()`, the
///   announcement and every verdict read the representation the writer
///   encodes. Except for a type that does not encode XCDR natively
///   (`Xcdr1Encoding::refuses_xcdr1`, `DDS::encodes_xcdr1_natively`, false
///   unless the type says otherwise): it
///   becomes `[XCDR2]`, the one representation that type serializes
///   correctly (a writer of XTYPES 1.2 and later "Shall generate or include
///   run-code that can serialize using version 2 encodings").
/// * A list the writer set is kept as it is; its first element is the
///   offer.
///
/// `Err` when that first element is not a representation HDDS serializes
/// (XML, or an unknown identifier), or is XCDR1 and the type does not
/// encode it (`Xcdr1Encoding::refuses_xcdr1`): such a writer could encode
/// nothing it announces.
///
/// DDS-XTypes v1.3 Sec.7.6.3.1.1 requires the run-time code a writer offers
/// to actually exist ("Shall generate or include run-time code that can
/// serialize using version 2 encodings. Optionally may generate or include
/// run-time code that can serialize using version 1 encodings. In this
/// case, they shall offer the means to configure at run-time the encoding
/// version used"): a writer that explicitly sets `[XCDR1]` is claiming that
/// optional capability, which is false when its type refuses it. Letting
/// such a writer through would offer a representation the wire path
/// degrades silently (the writer thinks it offers XCDR1, the type encodes
/// the XCDR2 layout under an XCDR1 header) -- refused at creation instead,
/// matching the reader-side rule (`resolve_reader_data_representation`) so
/// both ends of an explicit XCDR1 pair agree trivially: neither exists
/// unless its type can actually speak it.
pub(crate) fn resolve_writer_data_representation(
    qos: &mut crate::dds::qos::QoS,
    xcdr1: Xcdr1Encoding,
) -> Result<CdrVersion, IncompatibleQos> {
    if qos.data_representation.is_empty() {
        let code = if xcdr1.refuses_xcdr1() {
            XCDR2_CODE
        } else {
            XCDR1_CODE
        };
        qos.data_representation = vec![code];
    }
    let version = code_to_version(qos.data_representation[0])?;
    if version == CdrVersion::Xcdr1 && xcdr1.refuses_xcdr1() {
        return Err(IncompatibleQos {
            policy_id: POLICY_ID_DATA_REPRESENTATION,
        });
    }
    Ok(version)
}

/// Resolve, at creation, the list a DataReader that set none requests,
/// when its type cannot decode XCDR.
///
/// DDS-XTypes v1.3 Sec.7.6.3.1.1, readers of XTYPES 1.2 and later: "Shall
/// request XCDR2 encoding. Optionally may [...] deserialize version 1
/// encodings. In this case they shall also request XCDR encoding in
/// addition to XCDR2 encoding". A reader that set no list announces
/// `[XCDR, XCDR2]` (`announced_data_representation`); a reader whose type
/// does not decode XCDR natively (`Xcdr1Encoding::refuses_xcdr1`,
/// `DDS::encodes_xcdr1_natively`) requests `[XCDR2]` alone, written into
/// `qos` so `get_qos()`, the announcement and every verdict read it. A peer
/// writer that offers XCDR then sees the incompatibility it causes (the
/// pair was refused on this side only, while the announcement accepted
/// XCDR). A list the reader set is kept as it is -- UNLESS it explicitly
/// requests XCDR1 while its type cannot decode it (`Err`): the clause's
/// request semantics are conditional on the capability ("Optionally may
/// generate or include run-time code that can deserialize version 1
/// encodings. In this case they shall also request XCDR encoding"); a
/// reader claiming that capability when its type does not have it would
/// request bytes it cannot read, is matched by a remote writer that reads
/// the announcement alone, and ends up disagreeing with that writer about
/// whether the pair is compatible (the writer sees the list, not the
/// Rust type behind it). Refusing at creation makes both ends agree
/// trivially, with no asymmetric incompatible-but-matched pair and no
/// window for a corrupt delivery.
pub(crate) fn resolve_reader_data_representation(
    qos: &mut crate::dds::qos::QoS,
    xcdr1: Xcdr1Encoding,
) -> Result<(), IncompatibleQos> {
    if qos.data_representation.is_empty() {
        if xcdr1.refuses_xcdr1() {
            qos.data_representation = vec![XCDR2_CODE];
        }
        return Ok(());
    }
    if xcdr1.refuses_xcdr1() && qos.data_representation.contains(&XCDR1_CODE) {
        return Err(IncompatibleQos {
            policy_id: POLICY_ID_DATA_REPRESENTATION,
        });
    }
    Ok(())
}

/// QoS incompatibility signal carrying the DDS policy identifier
/// per DDS v1.4 Table 2.60 (23 = DATA_REPRESENTATION).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct IncompatibleQos {
    pub policy_id: u32,
}

fn code_to_version(code: u16) -> Result<CdrVersion, IncompatibleQos> {
    CdrVersion::from_representation_code(code).ok_or(IncompatibleQos {
        policy_id: POLICY_ID_DATA_REPRESENTATION,
    })
}

/// The CdrVersion a writer's resolved offer encodes, read back from its
/// QoS (`resolve_writer_data_representation` already made this list
/// non-empty and its first element a recognized CDR version at creation
/// -- DDS-XTypes v1.3 Sec.7.6.3.1.1: "Writers offer a single
/// representation"). `None` only for a QoS built by hand outside the
/// normal writer-creation path, or whose first element this build does
/// not serialize.
///
/// A raw relay (`RawDataWriter::write_raw_with_encoding`,
/// `RawRelayWriter`) reads this to refuse writing a payload under a
/// version its underlying writer does not actually offer, rather than
/// let the wire encapsulation silently disagree with the bytes (a
/// relay over a default raw writer would mislabel its payload).
pub(crate) fn writer_offered_version(qos: &crate::dds::qos::QoS) -> Option<CdrVersion> {
    qos.data_representation
        .first()
        .and_then(|&code| code_to_version(code).ok())
}

/// The wire code for a [`CdrVersion`], the inverse of `code_to_version`,
/// for callers that build a QoS offering one version explicitly (a raw
/// relay writer created per-representation). Delegates to the public
/// [`CdrVersion::representation_code`] so the two never drift.
pub(crate) fn version_to_code(version: CdrVersion) -> u16 {
    version.representation_code()
}

/// Map a type's canonical (XCDR2) RTPS encapsulation kind to the wire
/// encapsulation kind for the negotiated CDR version, per DDS-RTPS v2.5
/// sec. 10.7 and DDS-XTypes v1.3 sec. 7.6.2.1.2 + sec. 7.6.3.1.2.
///
/// `RtpsEndpointContext::encapsulation_kind` stores the canonical XCDR2
/// form of the type's extensibility (`0x0007` for `@final`, `0x0009` for
/// `@appendable`, `0x000B` for `@mutable`). This helper degrades that
/// canonical kind to the matching XCDR1 wire code when the writer's
/// `effective_cdr_version()` resolves to `Xcdr1`, so the wire encap stays
/// consistent with the bytes produced by `T::encode(buf, version)`.
///
/// # Mappings
///
/// * `(0x0007, Xcdr2)` -> `0x0007` PLAIN_CDR2_LE
/// * `(0x0007, Xcdr1)` -> `0x0001` PLAIN_CDR_LE
/// * `(0x0009, Xcdr2)` -> `0x0009` D_CDR2_LE
/// * `(0x0009, Xcdr1)` -> `0x0001` PLAIN_CDR_LE  (XCDR1 has no `@appendable`
///   wire concept; degrades to plain CDR per back-compat).
/// * `(0x000B, Xcdr2)` -> `0x000B` PL_CDR2_LE
/// * `(0x000B, Xcdr1)` -> `0x0003` PL_CDR_LE
///
/// Any other input is passed through unchanged so legacy callers that
/// already store an XCDR1 wire code (`0x0001` or `0x0003`) keep working.
pub fn encap_kind_for_version(canonical: u16, version: CdrVersion) -> u16 {
    match (canonical, version) {
        (0x0007, CdrVersion::Xcdr2) => 0x0007,
        (0x0007, CdrVersion::Xcdr1) => 0x0001,
        (0x0009, CdrVersion::Xcdr2) => 0x0009,
        (0x0009, CdrVersion::Xcdr1) => 0x0001,
        (0x000B, CdrVersion::Xcdr2) => 0x000B,
        (0x000B, CdrVersion::Xcdr1) => 0x0003,
        (other, _) => other,
    }
}

/// Map an RTPS encapsulation `representation_id` to the matching
/// `CdrVersion` per DDS-RTPS v2.5 sec. 10.7 and DDS-XTypes v1.3 sec. 7.6.2.2.
///
/// Valid ids (big-endian u16 in the first two bytes of the
/// serializedPayload encapsulation header):
///
/// * `0x0000` CDR_BE, `0x0001` CDR_LE, `0x0002` PL_CDR_BE,
///   `0x0003` PL_CDR_LE -> XCDR v1
/// * `0x0006` PLAIN_CDR2_BE, `0x0007` PLAIN_CDR2_LE, `0x0008` D_CDR2_BE,
///   `0x0009` D_CDR2_LE, `0x000A` PL_CDR2_BE, `0x000B` PL_CDR2_LE
///   -> XCDR v2 (per OMG DDS-XTypes v1.3 sec. 7.6.3.1.2 Table 60)
/// * `0x8001` CDR_LE, `0x8003` PL_CDR_LE with FastDDS's vendor flag bit
///   (0x8000) set on the little-endian XCDR v1 forms -> XCDR v1, same body
///   encoding as `0x0001`/`0x0003`. `engine/router.rs` classifies these
///   two ids as CDR v1 in its own `is_xcdr1` match (the header is stripped
///   as v1 there); this function must agree, because rejecting them would
///   let the router's `.ok().unwrap_or(Xcdr2)` fallback silently decode
///   genuinely-XCDR1 bytes as XCDR2, corrupting any 8-byte primitive that
///   follows a variable-size member. Only the
///   little-endian vendor-flagged forms are handled: `0x8000`/`0x8002`
///   (the big-endian vendor-flagged forms) are deliberately NOT accepted
///   here, matching the router's little-endian-only `is_xcdr1` match.
///
/// Any other value indicates a malformed payload and is reported as
/// `CdrError::InvalidEncoding`.
pub(crate) fn cdr_version_from_representation_id(repr_id: u16) -> Result<CdrVersion, CdrError> {
    match repr_id {
        0x0000..=0x0003 | 0x8001 | 0x8003 => Ok(CdrVersion::Xcdr1),
        0x0006..=0x000B => Ok(CdrVersion::Xcdr2),
        _ => Err(CdrError::InvalidEncoding),
    }
}

/// A guess from the descriptor alone: a variable-size type with an 8-byte
/// alignment does not encode the XCDR1 layout.
///
/// XCDR1 aligns an 8-byte primitive at 8 where XCDR2 aligns it at 4
/// (DDS-XTypes 1.3 7.4.3.2.2, Table 37). It is not the default of
/// `DDS::encodes_xcdr1_natively`, because it misses a fixed-size
/// `{u32, f64}` encoded through the `Cdr2Encode` defaults: the default is
/// `false` (a type encodes XCDR1 natively only when it says so). Kept for
/// the tests, which build a refusing or a native `Xcdr1Encoding` from a
/// synthetic descriptor.
#[cfg(test)]
pub(crate) fn type_requires_native_xcdr1(desc: &TypeDescriptor) -> bool {
    desc.is_variable_size && desc.alignment >= 8
}

/// Whether a local endpoint's type may be matched under XCDR1, captured once
/// at registration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Xcdr1Encoding {
    native: bool,
}

impl Xcdr1Encoding {
    /// What the type `T` declares (`DDS::encodes_xcdr1_natively`).
    pub(crate) fn of<T: crate::dds::DDS>() -> Self {
        Self {
            native: T::encodes_xcdr1_natively(),
        }
    }

    /// A type that encodes XCDR1 natively (refuses nothing).
    pub(crate) fn native() -> Self {
        Self { native: true }
    }

    /// Whether a pair that negotiates XCDR1 is refused for this type.
    pub(crate) fn refuses_xcdr1(self) -> bool {
        !self.native
    }

    /// The verdict for a PAIR where both sides' own Rust type is known
    /// locally (the in-process intra bind, `domain_registry::qos_verdict`):
    /// refused if EITHER side's type refuses XCDR1. Unlike the discovery
    /// match or the registration catch-up, which judge a pair of (one
    /// local type, one remote peer whose actual type is unknowable over
    /// the wire) and so read only the local side's `Xcdr1Encoding`, an
    /// in-process writer and reader are each a real Rust type in this
    /// process -- possibly two independently compiled types that share a
    /// `MatchKey` (same type name) but differ in whether they encode
    /// XCDR1 natively. Judging the pair on one side's capability alone
    /// would let a binding through that the wire path, judging the SAME
    /// two types, would have refused.
    pub(crate) fn either_refuses(a: Self, b: Self) -> Self {
        Self {
            native: a.native && b.native,
        }
    }
}

/// The descriptor-only guess (`type_requires_native_xcdr1`), for a test
/// that holds a synthetic descriptor and no type.
#[cfg(test)]
impl From<&'static TypeDescriptor> for Xcdr1Encoding {
    fn from(desc: &'static TypeDescriptor) -> Self {
        Self {
            native: !type_requires_native_xcdr1(desc),
        }
    }
}

/// Pairwise DataRepresentation compatibility check per DDS-XTypes v1.3
/// Sec.7.6.3.1.1, matching one writer's offered sequence against one
/// reader's requested sequence, and the version the pair communicates in.
///
/// The writer offers its FIRST element and nothing else ("Writers offer a
/// single representation"; the identifiers after the first carry no
/// meaning). The pair is compatible iff the reader's sequence contains that
/// representation: "If a writer's offered representation is contained
/// within a reader's sequence, the offer satisfies the request and the
/// policies are compatible. Otherwise, they are incompatible." A later
/// element of the writer's list the reader does accept does not make the
/// pair compatible: the writer does not encode it.
///
/// An empty sequence, on either side, is `[XCDR]`: "An empty list of
/// preferences shall be taken to be equivalent to a list containing the
/// single element XCDR". That is a REMOTE endpoint that announced no list; a
/// LOCAL writer is resolved at creation (`resolve_writer_data_representation`)
/// and a LOCAL reader is passed as it announces itself
/// (`announced_data_representation`), never empty.
pub(crate) fn pair_effective_cdr_version(
    offered: &[u16],
    accepted: &[u16],
) -> Result<CdrVersion, IncompatibleQos> {
    const SPEC_DEFAULT: [u16; 1] = [XCDR1_CODE];
    let offered: &[u16] = if offered.is_empty() {
        &SPEC_DEFAULT
    } else {
        offered
    };
    let accepted: &[u16] = if accepted.is_empty() {
        &SPEC_DEFAULT
    } else {
        accepted
    };
    let representation = offered[0];
    if accepted.contains(&representation) {
        return code_to_version(representation);
    }
    Err(IncompatibleQos {
        policy_id: POLICY_ID_DATA_REPRESENTATION,
    })
}

/// RTI vendor ids announced in SPDP (OMG vendor registry): 0x0101 Connext
/// DDS, 0x010A Connext Micro. Both document a 4-byte (`Char32`) XCDR1
/// `wchar` (public RTI documentation).
const RTI_VENDOR_IDS: [u16; 2] = [crate::core::rtps_constants::RTI_VENDOR_ID_U16, 0x010A];

/// RTI documents Connext's XCDR1 `wchar` encoding as 4 bytes (`Char32`)
/// where DDS-XTypes v1.3's XCDR2 width is the conformant 2 bytes; measured,
/// a Connext writer's XCDR1 `wchar`/`wstring` samples arrive at an HDDS
/// reader with wrong values, silently, and an HDDS writer's XCDR1
/// `wchar`/`wstring` is refused by Connext. Neither side can detect the
/// mismatch from the wire alone (no mask bit, nothing announced for it), so
/// the pairing is refused outright at matching time (both directions, via
/// `match_notification::rxo_verdict`) rather than delivered wrong.
///
/// A remote endpoint's vendor alone does not decide this (a non-RTI peer's
/// XCDR1 `wchar` is unaffected by RTI's documented width; an RTI peer whose
/// pair negotiates XCDR2 is unaffected too -- XCDR2 `wchar` is the
/// conformant 2-byte width per the same RTI documentation) -- all three
/// conditions are read from facts already resolved at pairing: the peer's
/// vendor from SPDP (`DiscoveryFsm::vendor_id_for_participant`, the vendor
/// zone resolved once, on the cold path), the negotiated
/// version from the pair's own DATA_REPRESENTATION QoS
/// (`pair_effective_cdr_version`), and whether the LOCAL type contains
/// `wchar`/`wstring` transitively (`type_contains_wchar`). No per-message
/// vendor check: this is read once per pairing, like `Xcdr1Encoding`.
///
/// If the pair can use XCDR2 instead (both sides offer/accept it),
/// `pair_effective_cdr_version` already resolves to `Xcdr2` before this
/// function is even consulted (its `effective_version` parameter is
/// `Xcdr1` only when the pair actually negotiated XCDR1), so a pair that
/// CAN speak XCDR2 is matched on XCDR2, never refused by this rule.
pub(crate) fn rti_xcdr1_wchar_incompatible(
    remote_vendor: Option<u16>,
    effective_version: CdrVersion,
    local_contains_wchar: bool,
) -> bool {
    remote_vendor.is_some_and(|vendor| RTI_VENDOR_IDS.contains(&vendor))
        && effective_version == CdrVersion::Xcdr1
        && local_contains_wchar
}

/// Running count of pairings refused by [`rti_xcdr1_wchar_incompatible`].
/// Terminal, never reset: the refusal is a deterministic property of the
/// pair (its vendor and its type do not change), so it recurs on every
/// re-announcement, and a counter that only grows is what makes a
/// persistent RTI/wchar mismatch visible from outside -- the same argument
/// as `security::crypto::secure_sedp`'s `WRAP_REFUSALS`.
static RTI_XCDR1_WCHAR_REFUSALS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Record one [`rti_xcdr1_wchar_incompatible`] refusal and log the reason
/// at debug level, naming the remote vendor. Returns the running total.
pub(crate) fn note_rti_xcdr1_wchar_refusal(remote_vendor: Option<u16>) -> u64 {
    let total = RTI_XCDR1_WCHAR_REFUSALS.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
    log::debug!(
        "[RTI_WCHAR] refusing XCDR1 pairing with vendor {remote_vendor:?}: the local type \
         contains wchar/wstring, and RTI's documented XCDR1 width for it (4 bytes) disagrees \
         with XCDR2's (2 bytes, DDS-XTypes v1.3 conformant) -- refusal policy, \
         refusal #{total}"
    );
    total
}

/// The running total of [`rti_xcdr1_wchar_incompatible`] refusals.
pub(crate) fn rti_xcdr1_wchar_refusals() -> u64 {
    RTI_XCDR1_WCHAR_REFUSALS.load(std::sync::atomic::Ordering::Relaxed)
}

/// Whether `type_obj` contains `wchar` (XTypes `TK_CHAR16`) or `wstring`
/// (`TK_STRING16`) anywhere in its structure: a struct or union member's
/// own type (including a `@key` member -- this function does not read
/// member flags, so a key is walked exactly like any other member), a
/// sequence/array/map element or key, or an alias's aliased type, each
/// followed transitively.
///
/// A member identified by a `Minimal` EquivalenceHash (a named nested
/// struct/union/etc., DDS-XTypes v1.3 sec. 7.3.4.5) is followed by calling
/// `resolve`: the local type store
/// (`match_notification::MatchNotificationRegistry::resolve_type_by_minimal_hash`,
/// present under feature `xtypes-structural-assignability`) when the
/// caller has one, `|_| None` otherwise. A hash `resolve` cannot answer
/// stops the walk on that one branch only -- this reads the LOCAL type's
/// own description as far as this process can see it, and never guesses
/// about a type it cannot resolve: it prefers the LOCAL type's own
/// description and, if the local type cannot say, reports that.
/// `TypeIdentifier::Complete` and `StronglyConnected` hashes are never
/// followed, matching
/// `protocol::discovery::sedp::build::type_information::collect_type_dependencies`,
/// which resolves `Minimal` hashes against the same store and no other.
///
/// A cycle (a type that references itself, directly or through another
/// type) is cut by an internal visited-hash set: each `Minimal` hash is
/// followed at most once per call.
pub(crate) fn type_contains_wchar(
    type_obj: &crate::xtypes::CompleteTypeObject,
    resolve: &dyn Fn(&crate::xtypes::EquivalenceHash) -> Option<crate::xtypes::CompleteTypeObject>,
) -> bool {
    use crate::xtypes::{CompleteTypeObject, TypeIdentifier, TypeKind};
    use std::collections::HashSet;

    fn is_wchar_or_wstring(tid: &TypeIdentifier) -> bool {
        matches!(
            tid,
            TypeIdentifier::Primitive(TypeKind::TK_CHAR16)
                | TypeIdentifier::WStringSmall { .. }
                | TypeIdentifier::WStringLarge { .. }
        )
    }

    /// Every `TypeIdentifier` a `CompleteTypeObject` references directly
    /// (one level), per DDS-XTypes v1.3 sec. 7.3.4.5 -- mirrors
    /// `collect_type_dependencies`'s own `member_type_ids` in
    /// `protocol::discovery::sedp::build::type_information` (kept as a
    /// separate copy: that one is behind feature
    /// `xtypes-structural-assignability` and private to its module).
    fn member_type_ids(obj: &CompleteTypeObject) -> Vec<&TypeIdentifier> {
        match obj {
            CompleteTypeObject::Struct(s) => {
                let mut ids: Vec<&TypeIdentifier> = s.header.base_type.iter().collect();
                ids.extend(s.member_seq.iter().map(|m| &m.common.member_type_id));
                ids
            }
            CompleteTypeObject::Union(u) => {
                let mut ids = vec![&u.header.discriminator];
                ids.extend(u.member_seq.iter().map(|m| &m.common.member_type_id));
                ids
            }
            CompleteTypeObject::Sequence(s) => vec![&s.element.type_id],
            CompleteTypeObject::Array(a) => vec![&a.element.type_id],
            CompleteTypeObject::Map(m) => vec![&m.key.type_id, &m.element.type_id],
            CompleteTypeObject::Alias(a) => vec![&a.body.common.related_type],
            // Enum / Bitmask / Bitset / Annotation carry no complex type
            // refs (their members are plain integer labels/positions).
            _ => vec![],
        }
    }

    fn walk(
        obj: &CompleteTypeObject,
        resolve: &dyn Fn(&crate::xtypes::EquivalenceHash) -> Option<CompleteTypeObject>,
        visited: &mut HashSet<crate::xtypes::EquivalenceHash>,
    ) -> bool {
        member_type_ids(obj)
            .into_iter()
            .any(|tid| contains_in_type_id(tid, resolve, visited))
    }

    fn contains_in_type_id(
        tid: &TypeIdentifier,
        resolve: &dyn Fn(&crate::xtypes::EquivalenceHash) -> Option<CompleteTypeObject>,
        visited: &mut HashSet<crate::xtypes::EquivalenceHash>,
    ) -> bool {
        if is_wchar_or_wstring(tid) {
            return true;
        }
        match tid {
            TypeIdentifier::PlainSequenceSmall(d) => {
                contains_in_type_id(&d.element_identifier, resolve, visited)
            }
            TypeIdentifier::PlainSequenceLarge(d) => {
                contains_in_type_id(&d.element_identifier, resolve, visited)
            }
            TypeIdentifier::PlainArraySmall(d) => {
                contains_in_type_id(&d.element_identifier, resolve, visited)
            }
            TypeIdentifier::PlainArrayLarge(d) => {
                contains_in_type_id(&d.element_identifier, resolve, visited)
            }
            TypeIdentifier::PlainMapSmall(d) => {
                contains_in_type_id(&d.key_identifier, resolve, visited)
                    || contains_in_type_id(&d.element_identifier, resolve, visited)
            }
            TypeIdentifier::PlainMapLarge(d) => {
                contains_in_type_id(&d.key_identifier, resolve, visited)
                    || contains_in_type_id(&d.element_identifier, resolve, visited)
            }
            TypeIdentifier::Minimal(hash) => {
                if !visited.insert(*hash) {
                    return false;
                }
                match resolve(hash) {
                    Some(obj) => walk(&obj, resolve, visited),
                    None => false,
                }
            }
            _ => false,
        }
    }

    let mut visited = HashSet::new();
    walk(type_obj, resolve, &mut visited)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dds::qos::QoS;

    fn writer_resolved(
        list: Vec<u16>,
        xcdr1: Xcdr1Encoding,
    ) -> (Vec<u16>, Result<CdrVersion, IncompatibleQos>) {
        let mut qos = QoS {
            data_representation: list,
            ..QoS::default()
        };
        let version = resolve_writer_data_representation(&mut qos, xcdr1);
        (qos.data_representation, version)
    }

    static REFUSING: TypeDescriptor = TypeDescriptor {
        type_id: 0,
        type_name: "Synthetic",
        size_bytes: 0,
        alignment: 8,
        is_variable_size: true,
        fields: &[],
    };

    /// DDS-XTypes v1.3 Sec.7.6.3.1.1: an empty list is `[XCDR]`. Before, an
    /// empty writer list encoded XCDR2 with no reader known.
    #[test]
    fn an_empty_writer_list_resolves_to_xcdr() {
        assert_eq!(
            writer_resolved(vec![], Xcdr1Encoding::native()),
            (vec![XCDR1_CODE], Ok(CdrVersion::Xcdr1))
        );
    }

    /// A type that does not encode XCDR natively offers the XCDR2 it can
    /// serialize.
    #[test]
    fn an_empty_writer_list_of_a_type_refusing_xcdr_resolves_to_xcdr2() {
        assert_eq!(
            writer_resolved(vec![], Xcdr1Encoding::from(&REFUSING)),
            (vec![XCDR2_CODE], Ok(CdrVersion::Xcdr2))
        );
    }

    /// A list the writer set is kept; its first element is the version.
    /// Led by XCDR2, the type's XCDR1 capability is irrelevant (not the
    /// version being negotiated), so both a native and a refusing type keep
    /// the list and resolve it.
    #[test]
    fn a_writer_list_led_by_xcdr2_is_kept_regardless_of_xcdr1_capability() {
        for (list, version) in [
            (vec![XCDR2_CODE], CdrVersion::Xcdr2),
            (vec![XCDR2_CODE, XCDR1_CODE], CdrVersion::Xcdr2),
        ] {
            for xcdr1 in [Xcdr1Encoding::native(), Xcdr1Encoding::from(&REFUSING)] {
                assert_eq!(
                    writer_resolved(list.clone(), xcdr1),
                    (list.clone(), Ok(version)),
                    "{list:?}"
                );
            }
        }
    }

    /// A list led by XCDR1 is kept and resolves, but only for a type that
    /// actually encodes XCDR1.
    #[test]
    fn a_writer_list_led_by_xcdr1_is_kept_for_a_native_type() {
        for list in [vec![XCDR1_CODE], vec![XCDR1_CODE, XCDR2_CODE]] {
            assert_eq!(
                writer_resolved(list.clone(), Xcdr1Encoding::native()),
                (list.clone(), Ok(CdrVersion::Xcdr1)),
                "{list:?}"
            );
        }
    }

    /// DDS-XTypes v1.3 Sec.7.6.3.1.1: a writer offering XCDR1 is claiming
    /// the optional capability "generate or include run-time code that can
    /// serialize using version 1 encodings". A writer whose type refuses
    /// XCDR1 (`Xcdr1Encoding::refuses_xcdr1`) but explicitly sets `[XCDR1]`
    /// (or `[XCDR1, XCDR2]`, since only the first element is the offer) is
    /// claiming a capability it does not have: refused here, at creation,
    /// rather than silently encoding the XCDR2 layout under an XCDR1
    /// header. Keeping such a writer's list unchanged would match a reader
    /// that announced `[XCDR1]` (list-compatible, but equally unable to
    /// decode what this writer would actually produce) -- an
    /// asymmetric-match / corrupt-delivery outcome this gate prevents (see
    /// `resolve_reader_data_representation` for the reader side of the
    /// same rule).
    #[test]
    fn a_writer_list_led_by_xcdr1_is_refused_for_a_type_that_refuses_it() {
        for list in [vec![XCDR1_CODE], vec![XCDR1_CODE, XCDR2_CODE]] {
            assert_eq!(
                writer_resolved(list.clone(), Xcdr1Encoding::from(&REFUSING)).1,
                Err(IncompatibleQos {
                    policy_id: POLICY_ID_DATA_REPRESENTATION
                }),
                "{list:?}"
            );
        }
    }

    /// A writer whose first element is not a CDR version (XML = 1) has
    /// nothing to encode.
    #[test]
    fn a_writer_list_led_by_a_representation_hdds_does_not_serialize_is_refused() {
        assert_eq!(
            writer_resolved(vec![0x0001, XCDR2_CODE], Xcdr1Encoding::native()).1,
            Err(IncompatibleQos {
                policy_id: POLICY_ID_DATA_REPRESENTATION
            })
        );
    }

    fn reader_resolved(
        list: Vec<u16>,
        xcdr1: Xcdr1Encoding,
    ) -> (Vec<u16>, Result<(), IncompatibleQos>) {
        let mut qos = QoS {
            data_representation: list,
            ..QoS::default()
        };
        let result = resolve_reader_data_representation(&mut qos, xcdr1);
        (qos.data_representation, result)
    }

    /// DDS-XTypes v1.3 Sec.7.6.3.1.1: an empty list is "no restriction" for
    /// a native reader, and is rewritten to `[XCDR2]` for a reader whose
    /// type cannot decode XCDR1 (its unset request is never a lie about its
    /// own capability).
    #[test]
    fn an_empty_reader_list_is_kept_for_native_and_rewritten_for_refusing() {
        assert_eq!(
            reader_resolved(vec![], Xcdr1Encoding::native()),
            (vec![], Ok(()))
        );
        assert_eq!(
            reader_resolved(vec![], Xcdr1Encoding::from(&REFUSING)),
            (vec![XCDR2_CODE], Ok(()))
        );
    }

    /// A reader that explicitly requests only XCDR2 never claims the XCDR1
    /// capability, so it is kept regardless of the type.
    #[test]
    fn a_reader_list_without_xcdr1_is_kept_regardless_of_capability() {
        for xcdr1 in [Xcdr1Encoding::native(), Xcdr1Encoding::from(&REFUSING)] {
            assert_eq!(
                reader_resolved(vec![XCDR2_CODE], xcdr1),
                (vec![XCDR2_CODE], Ok(())),
                "{xcdr1:?}"
            );
        }
    }

    /// A reader that explicitly requests XCDR1 is kept when its type can
    /// actually decode it.
    #[test]
    fn a_reader_list_with_xcdr1_is_kept_for_a_native_type() {
        for list in [vec![XCDR1_CODE], vec![XCDR1_CODE, XCDR2_CODE]] {
            assert_eq!(
                reader_resolved(list.clone(), Xcdr1Encoding::native()),
                (list.clone(), Ok(())),
                "{list:?}"
            );
        }
    }

    /// DDS-XTypes v1.3 Sec.7.6.3.1.1: "Optionally may generate or include
    /// run-time code that can deserialize version 1 encodings. In this case
    /// they shall also request XCDR encoding in addition to XCDR2
    /// encoding." A reader whose type refuses XCDR1 but explicitly
    /// requests it anyway (alone, or alongside XCDR2) is claiming a
    /// capability it does not have: refused here, at creation, rather than
    /// matched by a remote writer that reads the announced list alone and
    /// disagrees with this reader about whether the pair is compatible --
    /// the asymmetric-match / corrupt-delivery outcome this rule prevents (see
    /// the sibling writer-side rule, `a_writer_list_led_by_xcdr1_is_refused_for_a_type_that_refuses_it`).
    #[test]
    fn a_reader_list_with_xcdr1_is_refused_for_a_type_that_refuses_it() {
        for list in [
            vec![XCDR1_CODE],
            vec![XCDR1_CODE, XCDR2_CODE],
            vec![XCDR2_CODE, XCDR1_CODE],
        ] {
            assert_eq!(
                reader_resolved(list.clone(), Xcdr1Encoding::from(&REFUSING)).1,
                Err(IncompatibleQos {
                    policy_id: POLICY_ID_DATA_REPRESENTATION
                }),
                "{list:?}"
            );
        }
    }

    /// A writer announces the one representation it offers, a reader the
    /// whole list, `[XCDR, XCDR2]` when it set none.
    #[test]
    fn a_writer_announces_one_representation_a_reader_its_list() {
        use EndpointKind::{Reader, Writer};
        assert_eq!(announced_data_representation(Writer, &[]), &[XCDR1_CODE]);
        assert_eq!(
            announced_data_representation(Writer, &[XCDR2_CODE]),
            &[XCDR2_CODE]
        );
        assert_eq!(
            announced_data_representation(Writer, &[XCDR2_CODE, XCDR1_CODE]),
            &[XCDR2_CODE]
        );
        assert_eq!(
            announced_data_representation(Writer, &[XCDR1_CODE, XCDR2_CODE]),
            &[XCDR1_CODE]
        );
        assert_eq!(
            announced_data_representation(Reader, &[]),
            &[XCDR1_CODE, XCDR2_CODE]
        );
        assert_eq!(
            announced_data_representation(Reader, &[XCDR2_CODE]),
            &[XCDR2_CODE]
        );
        assert_eq!(
            announced_data_representation(Reader, &[XCDR2_CODE, XCDR1_CODE]),
            &[XCDR2_CODE, XCDR1_CODE]
        );
    }

    fn desc(alignment: u8, is_variable_size: bool) -> TypeDescriptor {
        TypeDescriptor {
            type_id: 0,
            type_name: "Synthetic",
            size_bytes: 0,
            alignment,
            is_variable_size,
            fields: &[],
        }
    }

    #[test]
    fn cdr_version_from_representation_id_maps_xcdr1_codes() {
        assert_eq!(
            cdr_version_from_representation_id(0x0000),
            Ok(CdrVersion::Xcdr1)
        );
        assert_eq!(
            cdr_version_from_representation_id(0x0001),
            Ok(CdrVersion::Xcdr1)
        );
        assert_eq!(
            cdr_version_from_representation_id(0x0002),
            Ok(CdrVersion::Xcdr1)
        );
        assert_eq!(
            cdr_version_from_representation_id(0x0003),
            Ok(CdrVersion::Xcdr1)
        );
    }

    #[test]
    fn cdr_version_from_representation_id_maps_xcdr2_codes() {
        assert_eq!(
            cdr_version_from_representation_id(0x0006),
            Ok(CdrVersion::Xcdr2)
        );
        assert_eq!(
            cdr_version_from_representation_id(0x0007),
            Ok(CdrVersion::Xcdr2)
        );
        assert_eq!(
            cdr_version_from_representation_id(0x0008),
            Ok(CdrVersion::Xcdr2)
        );
        assert_eq!(
            cdr_version_from_representation_id(0x0009),
            Ok(CdrVersion::Xcdr2)
        );
        assert_eq!(
            cdr_version_from_representation_id(0x000A),
            Ok(CdrVersion::Xcdr2)
        );
        assert_eq!(
            cdr_version_from_representation_id(0x000B),
            Ok(CdrVersion::Xcdr2)
        );
    }

    #[test]
    fn cdr_version_from_representation_id_rejects_invalid_codes() {
        assert_eq!(
            cdr_version_from_representation_id(0x0004),
            Err(CdrError::InvalidEncoding)
        );
        assert_eq!(
            cdr_version_from_representation_id(0x00FF),
            Err(CdrError::InvalidEncoding)
        );
        assert_eq!(
            cdr_version_from_representation_id(0xFFFF),
            Err(CdrError::InvalidEncoding)
        );
    }

    /// `engine/router.rs`'s own `is_xcdr1` match treats
    /// these two FastDDS vendor-flagged ids as CDR v1 and strips the header
    /// accordingly; this function must agree, or the router's
    /// `.ok().unwrap_or(Xcdr2)` fallback silently decodes genuine XCDR1
    /// bytes as XCDR2.
    #[test]
    fn cdr_version_from_representation_id_maps_fastdds_vendor_flagged_xcdr1_codes() {
        assert_eq!(
            cdr_version_from_representation_id(0x8001),
            Ok(CdrVersion::Xcdr1)
        );
        assert_eq!(
            cdr_version_from_representation_id(0x8003),
            Ok(CdrVersion::Xcdr1)
        );
    }

    /// The big-endian vendor-flagged forms are deliberately NOT accepted:
    /// `engine/router.rs`'s `is_xcdr1` match handles little-endian only, and
    /// this function must keep agreeing with that, not "complete" the set.
    #[test]
    fn cdr_version_from_representation_id_still_rejects_big_endian_vendor_flagged_codes() {
        assert_eq!(
            cdr_version_from_representation_id(0x8000),
            Err(CdrError::InvalidEncoding)
        );
        assert_eq!(
            cdr_version_from_representation_id(0x8002),
            Err(CdrError::InvalidEncoding)
        );
    }

    #[test]
    fn type_requires_native_xcdr1_true_for_variable_8_byte_aligned() {
        assert!(type_requires_native_xcdr1(&desc(8, true)));
    }

    #[test]
    fn type_requires_native_xcdr1_false_for_variable_4_byte_aligned() {
        assert!(!type_requires_native_xcdr1(&desc(4, true)));
    }

    #[test]
    fn type_requires_native_xcdr1_false_for_fixed_8_byte_aligned() {
        assert!(!type_requires_native_xcdr1(&desc(8, false)));
    }

    #[test]
    fn type_requires_native_xcdr1_false_for_fixed_1_byte_aligned() {
        assert!(!type_requires_native_xcdr1(&desc(1, false)));
    }

    #[test]
    fn either_refuses_is_native_only_when_both_sides_are() {
        static REFUSING_DESC: TypeDescriptor = TypeDescriptor {
            type_id: 0,
            type_name: "Synthetic",
            size_bytes: 0,
            alignment: 8,
            is_variable_size: true,
            fields: &[],
        };
        let native = Xcdr1Encoding::native();
        let refusing = Xcdr1Encoding::from(&REFUSING_DESC);
        assert!(!Xcdr1Encoding::either_refuses(native, native).refuses_xcdr1());
        assert!(Xcdr1Encoding::either_refuses(refusing, native).refuses_xcdr1());
        assert!(Xcdr1Encoding::either_refuses(native, refusing).refuses_xcdr1());
        assert!(Xcdr1Encoding::either_refuses(refusing, refusing).refuses_xcdr1());
    }

    #[test]
    fn pair_empty_offered_empty_accepted_picks_xcdr1() {
        // Both empty -> [XCDR] per DDS-XTypes v1.3 Sec.7.6.3.1.1.
        assert_eq!(pair_effective_cdr_version(&[], &[]), Ok(CdrVersion::Xcdr1));
    }

    #[test]
    fn pair_writer_offered_empty_reader_uses_back_compat() {
        // Reader empty -> [XCDR1] (back-compat). Writer XCDR1 only -> match.
        assert_eq!(
            pair_effective_cdr_version(&[XCDR1_CODE], &[]),
            Ok(CdrVersion::Xcdr1)
        );
        // Writer XCDR2 only vs back-compat [XCDR1] reader -> incompatible.
        assert_eq!(
            pair_effective_cdr_version(&[XCDR2_CODE], &[]),
            Err(IncompatibleQos {
                policy_id: POLICY_ID_DATA_REPRESENTATION
            })
        );
    }

    #[test]
    fn pair_reader_accepted_no_writer_offered_reader_imposes() {
        assert_eq!(
            pair_effective_cdr_version(&[], &[XCDR1_CODE]),
            Ok(CdrVersion::Xcdr1)
        );
    }

    #[test]
    fn pair_both_constrained_matches_on_the_first_offered_code_only() {
        // DDS-XTypes v1.3 sec. 7.6.3.1.1: compatible iff the reader requests the
        // writer's (first) representation.
        assert_eq!(
            pair_effective_cdr_version(&[XCDR2_CODE, XCDR1_CODE], &[XCDR1_CODE]),
            Err(IncompatibleQos {
                policy_id: POLICY_ID_DATA_REPRESENTATION
            })
        );
        assert_eq!(
            pair_effective_cdr_version(&[XCDR1_CODE, XCDR2_CODE], &[XCDR2_CODE]),
            Err(IncompatibleQos {
                policy_id: POLICY_ID_DATA_REPRESENTATION
            })
        );
        assert_eq!(
            pair_effective_cdr_version(&[XCDR1_CODE, XCDR2_CODE], &[XCDR1_CODE]),
            Ok(CdrVersion::Xcdr1)
        );
        assert_eq!(
            pair_effective_cdr_version(&[XCDR2_CODE, XCDR1_CODE], &[XCDR1_CODE, XCDR2_CODE]),
            Ok(CdrVersion::Xcdr2)
        );
        assert_eq!(
            pair_effective_cdr_version(&[XCDR1_CODE, XCDR2_CODE], &[XCDR1_CODE, XCDR2_CODE]),
            Ok(CdrVersion::Xcdr1)
        );
    }

    /// An empty offer is `[XCDR]` (a remote writer that announced no
    /// list): it does not adapt to the reader (it is not `[XCDR2, XCDR1]`
    /// with the first the reader accepts).
    #[test]
    fn pair_an_empty_offer_is_xcdr_and_does_not_adapt() {
        assert_eq!(
            pair_effective_cdr_version(&[], &[XCDR2_CODE]),
            Err(IncompatibleQos {
                policy_id: POLICY_ID_DATA_REPRESENTATION
            })
        );
        assert_eq!(
            pair_effective_cdr_version(&[], &[XCDR1_CODE, XCDR2_CODE]),
            Ok(CdrVersion::Xcdr1)
        );
        assert_eq!(
            pair_effective_cdr_version(&[], &[XCDR2_CODE, XCDR1_CODE]),
            Ok(CdrVersion::Xcdr1)
        );
    }

    #[test]
    fn pair_empty_intersection_yields_incompatible_qos() {
        assert_eq!(
            pair_effective_cdr_version(&[XCDR2_CODE], &[XCDR1_CODE]),
            Err(IncompatibleQos {
                policy_id: POLICY_ID_DATA_REPRESENTATION
            })
        );
    }

    #[test]
    fn unknown_code_in_offered_is_incompatible() {
        // 0x0001 is XML, not a CDR version (Sec.7.6.2.1.2).
        assert_eq!(
            pair_effective_cdr_version(&[0x0001], &[0x0001]),
            Err(IncompatibleQos {
                policy_id: POLICY_ID_DATA_REPRESENTATION
            })
        );
    }

    #[test]
    fn encap_kind_for_version_final_xcdr2_keeps_plain_cdr2_le() {
        assert_eq!(
            encap_kind_for_version(0x0007, CdrVersion::Xcdr2),
            0x0007,
            "@final + Xcdr2 should stay PLAIN_CDR2_LE"
        );
    }

    #[test]
    fn encap_kind_for_version_final_xcdr1_degrades_to_plain_cdr_le() {
        assert_eq!(
            encap_kind_for_version(0x0007, CdrVersion::Xcdr1),
            0x0001,
            "@final + Xcdr1 should degrade to PLAIN_CDR_LE"
        );
    }

    #[test]
    fn encap_kind_for_version_appendable_xcdr2_keeps_d_cdr2_le() {
        assert_eq!(
            encap_kind_for_version(0x0009, CdrVersion::Xcdr2),
            0x0009,
            "@appendable + Xcdr2 should stay D_CDR2_LE"
        );
    }

    #[test]
    fn encap_kind_for_version_appendable_xcdr1_degrades_to_plain_cdr_le() {
        // XCDR1 has no @appendable wire concept (no DHEADER); fall back to plain.
        assert_eq!(
            encap_kind_for_version(0x0009, CdrVersion::Xcdr1),
            0x0001,
            "@appendable + Xcdr1 should degrade to PLAIN_CDR_LE"
        );
    }

    #[test]
    fn encap_kind_for_version_mutable_xcdr2_keeps_pl_cdr2_le() {
        assert_eq!(
            encap_kind_for_version(0x000B, CdrVersion::Xcdr2),
            0x000B,
            "@mutable + Xcdr2 should stay PL_CDR2_LE"
        );
    }

    #[test]
    fn encap_kind_for_version_mutable_xcdr1_degrades_to_pl_cdr_le() {
        assert_eq!(
            encap_kind_for_version(0x000B, CdrVersion::Xcdr1),
            0x0003,
            "@mutable + Xcdr1 should degrade to PL_CDR_LE"
        );
    }

    #[test]
    fn encap_kind_for_version_passes_through_legacy_xcdr1_codes() {
        // Legacy callers that already store an XCDR1 wire code keep it.
        assert_eq!(encap_kind_for_version(0x0001, CdrVersion::Xcdr1), 0x0001);
        assert_eq!(encap_kind_for_version(0x0001, CdrVersion::Xcdr2), 0x0001);
        assert_eq!(encap_kind_for_version(0x0003, CdrVersion::Xcdr1), 0x0003);
    }

    #[test]
    fn writer_offered_version_reads_the_resolved_first_element() {
        let mut qos = QoS::default();
        resolve_writer_data_representation(&mut qos, Xcdr1Encoding::native()).unwrap();
        assert_eq!(writer_offered_version(&qos), Some(CdrVersion::Xcdr1));

        let mut qos = QoS::default();
        resolve_writer_data_representation(&mut qos, Xcdr1Encoding::from(&REFUSING)).unwrap();
        assert_eq!(writer_offered_version(&qos), Some(CdrVersion::Xcdr2));
    }

    #[test]
    fn writer_offered_version_is_none_for_an_unresolved_or_unknown_code() {
        assert_eq!(writer_offered_version(&QoS::default()), None);
        let qos = QoS {
            data_representation: vec![0x0001], // XML, not a CDR version
            ..QoS::default()
        };
        assert_eq!(writer_offered_version(&qos), None);
    }

    #[test]
    fn version_to_code_is_the_inverse_of_code_to_version() {
        assert_eq!(version_to_code(CdrVersion::Xcdr1), XCDR1_CODE);
        assert_eq!(version_to_code(CdrVersion::Xcdr2), XCDR2_CODE);
        assert_eq!(
            code_to_version(version_to_code(CdrVersion::Xcdr1)),
            Ok(CdrVersion::Xcdr1)
        );
        assert_eq!(
            code_to_version(version_to_code(CdrVersion::Xcdr2)),
            Ok(CdrVersion::Xcdr2)
        );
    }

    // ------------------------------------------------------------------
    // Policy: RTI + XCDR1 + wchar/wstring refusal.
    // ------------------------------------------------------------------

    use crate::xtypes::{
        CollectionElementFlag, CollectionTypeFlag, CommonAliasBody, CommonStructMember,
        CompleteAliasBody, CompleteAliasHeader, CompleteAliasType, CompleteArrayHeader,
        CompleteArrayType, CompleteCollectionElement, CompleteCollectionHeader,
        CompleteElementDetail, CompleteMemberDetail, CompleteSequenceType, CompleteStructHeader,
        CompleteStructMember, CompleteStructType, CompleteTypeDetail, CompleteTypeObject,
        EquivalenceHash, MemberFlag, StructTypeFlag, TypeIdentifier, TypeKind, TypeRelationFlag,
    };

    const RTI: Option<u16> = Some(0x0101);
    const CYCLONE: Option<u16> = Some(0x0110);

    fn no_resolver() -> impl Fn(&EquivalenceHash) -> Option<CompleteTypeObject> {
        |_: &EquivalenceHash| None
    }

    fn struct_with_member(
        name: &'static str,
        member_type_id: TypeIdentifier,
    ) -> CompleteTypeObject {
        CompleteTypeObject::Struct(CompleteStructType {
            struct_flags: StructTypeFlag::IS_FINAL,
            header: CompleteStructHeader {
                base_type: None,
                detail: CompleteTypeDetail::new(name),
            },
            member_seq: vec![CompleteStructMember {
                common: CommonStructMember {
                    member_id: 0,
                    member_flags: MemberFlag::empty(),
                    member_type_id,
                },
                detail: CompleteMemberDetail::new("m"),
            }],
        })
    }

    #[test]
    fn rti_xcdr1_wchar_incompatible_requires_all_three_conditions() {
        assert!(rti_xcdr1_wchar_incompatible(RTI, CdrVersion::Xcdr1, true));
        // Connext Micro (0x010A) documents the same XCDR1 wchar width.
        assert!(rti_xcdr1_wchar_incompatible(
            Some(0x010A),
            CdrVersion::Xcdr1,
            true
        ));
        // Not RTI: unaffected.
        assert!(!rti_xcdr1_wchar_incompatible(
            CYCLONE,
            CdrVersion::Xcdr1,
            true
        ));
        assert!(!rti_xcdr1_wchar_incompatible(None, CdrVersion::Xcdr1, true));
        // RTI, but the pair negotiated XCDR2 (prefer XCDR2 over refusing).
        assert!(!rti_xcdr1_wchar_incompatible(RTI, CdrVersion::Xcdr2, true));
        // RTI + XCDR1, but the local type has no wchar/wstring.
        assert!(!rti_xcdr1_wchar_incompatible(RTI, CdrVersion::Xcdr1, false));
    }

    #[test]
    fn note_rti_xcdr1_wchar_refusal_counts_monotonically() {
        let before = rti_xcdr1_wchar_refusals();
        assert_eq!(note_rti_xcdr1_wchar_refusal(RTI), before + 1);
        assert_eq!(note_rti_xcdr1_wchar_refusal(RTI), before + 2);
        assert_eq!(rti_xcdr1_wchar_refusals(), before + 2);
    }

    #[test]
    fn type_contains_wchar_false_for_a_plain_struct() {
        let t = struct_with_member("Plain", TypeIdentifier::Primitive(TypeKind::TK_INT32));
        assert!(!type_contains_wchar(&t, &no_resolver()));
    }

    #[test]
    fn type_contains_wchar_true_for_a_direct_wchar_member() {
        let t = struct_with_member("HasWchar", TypeIdentifier::Primitive(TypeKind::TK_CHAR16));
        assert!(type_contains_wchar(&t, &no_resolver()));
    }

    #[test]
    fn type_contains_wchar_true_for_a_direct_wstring_member() {
        for tid in [
            TypeIdentifier::WStringSmall { bound: 32 },
            TypeIdentifier::WStringLarge { bound: 4096 },
        ] {
            let t = struct_with_member("HasWString", tid);
            assert!(type_contains_wchar(&t, &no_resolver()));
        }
    }

    #[test]
    fn type_contains_wchar_true_through_a_union_case() {
        use crate::xtypes::{
            CommonUnionMember, CompleteUnionHeader, CompleteUnionMember, CompleteUnionType,
            UnionTypeFlag,
        };
        // wchar as a union case's own type.
        let case_wchar = CompleteTypeObject::Union(CompleteUnionType {
            union_flags: UnionTypeFlag::IS_FINAL,
            header: CompleteUnionHeader {
                discriminator: TypeIdentifier::Primitive(TypeKind::TK_INT32),
                discriminator_flags: MemberFlag::empty(),
                detail: CompleteTypeDetail::new("U"),
            },
            member_seq: vec![CompleteUnionMember {
                common: CommonUnionMember {
                    member_id: 0,
                    member_flags: MemberFlag::empty(),
                    member_type_id: TypeIdentifier::Primitive(TypeKind::TK_CHAR16),
                    label_seq: vec![0],
                },
                detail: CompleteMemberDetail::new("c"),
            }],
        });
        assert!(type_contains_wchar(&case_wchar, &no_resolver()));
    }

    #[test]
    fn type_contains_wchar_true_through_a_sequence_element() {
        let t = CompleteTypeObject::Sequence(CompleteSequenceType {
            collection_flag: CollectionTypeFlag::default(),
            header: CompleteCollectionHeader {
                bound: 0,
                detail: None,
            },
            element: CompleteCollectionElement {
                flags: CollectionElementFlag::empty(),
                type_id: TypeIdentifier::WStringSmall { bound: 64 },
                detail: CompleteElementDetail::default(),
            },
        });
        assert!(type_contains_wchar(&t, &no_resolver()));
    }

    #[test]
    fn type_contains_wchar_true_through_an_array_element() {
        let t = CompleteTypeObject::Array(CompleteArrayType {
            collection_flag: CollectionTypeFlag::default(),
            header: CompleteArrayHeader {
                bound_seq: vec![8],
                detail: CompleteTypeDetail::new(""),
            },
            element: CompleteCollectionElement {
                flags: CollectionElementFlag::empty(),
                type_id: TypeIdentifier::Primitive(TypeKind::TK_CHAR16),
                detail: CompleteElementDetail::default(),
            },
        });
        assert!(type_contains_wchar(&t, &no_resolver()));
    }

    #[test]
    fn type_contains_wchar_true_through_an_alias() {
        let t = CompleteTypeObject::Alias(CompleteAliasType {
            alias_flags: crate::xtypes::AliasTypeFlag::empty(),
            header: CompleteAliasHeader {
                detail: CompleteTypeDetail::new("MyWString"),
            },
            body: CompleteAliasBody {
                common: CommonAliasBody {
                    related_flags: TypeRelationFlag::empty(),
                    related_type: TypeIdentifier::WStringLarge { bound: 1_000_000 },
                },
                ann_builtin: None,
                ann_custom: None,
            },
        });
        assert!(type_contains_wchar(&t, &no_resolver()));
    }

    /// A struct member naming a nested struct (a `Minimal` hash) that
    /// itself contains wchar, resolved through the `resolve` closure
    /// (standing in for the local type store): transitive through a named
    /// complex type, not just an inline collection/alias.
    #[test]
    fn type_contains_wchar_true_through_a_resolved_nested_struct() {
        let nested_hash = EquivalenceHash::from_bytes([7; 14]);
        let nested = struct_with_member("Nested", TypeIdentifier::Primitive(TypeKind::TK_CHAR16));
        let outer = struct_with_member("Outer", TypeIdentifier::Minimal(nested_hash));

        let resolver = move |h: &EquivalenceHash| {
            if *h == nested_hash {
                Some(nested.clone())
            } else {
                None
            }
        };
        assert!(type_contains_wchar(&outer, &resolver));
    }

    /// The local type cannot say what a hash it cannot resolve contains:
    /// the walk stops on that branch rather than guessing either way.
    #[test]
    fn type_contains_wchar_false_for_an_unresolvable_hash() {
        let unknown_hash = EquivalenceHash::from_bytes([9; 14]);
        let outer = struct_with_member("Outer", TypeIdentifier::Minimal(unknown_hash));
        assert!(!type_contains_wchar(&outer, &no_resolver()));
    }

    /// A self-referential (cyclic) nested type does not loop forever.
    #[test]
    fn type_contains_wchar_terminates_on_a_cycle_without_a_hit() {
        let self_hash = EquivalenceHash::from_bytes([3; 14]);
        let cyclic = struct_with_member("Cyclic", TypeIdentifier::Minimal(self_hash));
        let cyclic_for_resolver = cyclic.clone();
        let resolver = move |h: &EquivalenceHash| {
            if *h == self_hash {
                Some(cyclic_for_resolver.clone())
            } else {
                None
            }
        };
        assert!(!type_contains_wchar(&cyclic, &resolver));
    }

    /// `TypeIdentifier::Complete` and `StronglyConnected` hashes are never
    /// followed (matching `collect_type_dependencies`'s Minimal-only
    /// resolution): a resolver that would answer `true` for ANY hash must
    /// not be consulted for these kinds.
    #[test]
    fn type_contains_wchar_never_follows_complete_or_strongly_connected_hashes() {
        use crate::xtypes::{EquivalenceKind, StronglyConnectedComponentId};
        let any_hash = EquivalenceHash::from_bytes([5; 14]);
        let always_wchar = |_: &EquivalenceHash| {
            Some(struct_with_member(
                "W",
                TypeIdentifier::Primitive(TypeKind::TK_CHAR16),
            ))
        };
        let via_complete = struct_with_member("Outer", TypeIdentifier::Complete(any_hash));
        assert!(!type_contains_wchar(&via_complete, &always_wchar));

        let via_scc = struct_with_member(
            "Outer",
            TypeIdentifier::StronglyConnected(StronglyConnectedComponentId {
                kind: EquivalenceKind::Minimal,
                sc_component_id: any_hash,
                scc_length: 1,
                scc_index: 0,
            }),
        );
        assert!(!type_contains_wchar(&via_scc, &always_wchar));
    }
}
