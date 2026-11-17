// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Phase-0 read-only Canonical emission oracle (strangler seed).
//!
//! This is the FIRST code step of the pure-emission refactor. It adds a
//! stateless, read-only function that reconstructs the DATA submessage bytes
//! a writer emits on the Native/self path, from ONLY the values a journaled
//! `CacheChange` would carry (sequence number, verbatim serialized payload,
//! optional key hash, source timestamp) plus a minimal writer context. It
//! changes ZERO runtime behavior: nothing here is called from `write()`,
//! `replay_to()`, `on_nack()`, or any live builder. It exists solely to prove,
//! byte-for-byte, that such a pure function can reproduce the live wire bytes.
//!
//! ## Scope (grows one slice at a time)
//!
//! The eventual target factorization is:
//!
//! ```text
//! emit_canonical(change, writer_ctx) -> Canonical   // NATIVE, audience-blind; NO dialect param
//! address(&[Canonical], dest, dialect) -> wire       // later phase
//! ```
//!
//! `emit_canonical_native` reconstructs the Native/self DATA submessage for the
//! forms proven so far, dispatched by `CanonicalChangeView::form`:
//! * `EmissionForm::PlainKeyed` -- slice 1: a normal keyed sample, NOT part of a
//!   coherent set (`coherent_sn = None`, `group_sn = None`).
//! * `EmissionForm::CoherentMember` -- slice 2 (Form A): a keyed sample emitted
//!   inside a `begin/end_coherent_changes` window (`coherent_sn = Some`), TOPIC
//!   or GROUP scope.
//! * `EmissionForm::EcsClose` -- slice 2 (Form B): the End-of-Coherent-Set
//!   close marker (D=0 K=0 Q=1, no payload).
//! * `EmissionForm::Dispose` -- slice 3: a dispose / unregister lifecycle change,
//!   a KEY-only DATA (K=1, D=0) carrying PID_STATUS_INFO plus the serialized @key
//!   fields as payload.
//!
//! Fragmented (DATA_FRAG) large-payload emission is covered by the SEPARATE
//! entry point `emit_canonical_native_frags` (slice 4), which returns a
//! SEQUENCE of DATA_FRAG submessages. Fragmentation is DERIVED from the
//! serialized payload length -- it is NOT an `EmissionForm` variant -- exactly
//! as the live splitter decides it; a payload that does not exceed the
//! fragmentation threshold degenerates to the single DATA submessage
//! `emit_canonical_native` returns (the len==1 case). See that function's doc.
//!
//! ## What "Canonical" spans
//!
//! Exactly ONE submessage's logical content: the DATA submessage (its
//! submessage header + fixed body + inline QoS + serialized payload). It does
//! NOT include the message framing (the 20-byte RTPS header or the INFO_TS
//! submessage) -- that is message-assembly, a later phase. This is why
//! `source_timestamp` below is carried on the change view but NOT emitted into
//! the returned bytes: the DATA submessage is timestamp-free; the timestamp
//! only feeds the INFO_TS the message-assembly phase will prepend.
//!
//! ## Mirrored live source
//!
//! The byte layout reconstructed here mirrors, field for field, the live
//! builders:
//! * payload-carrying DATA (PlainKeyed + CoherentMember):
//!   `build_data_packet_with_context_full_keyed`
//!   (`crates/hdds/src/protocol/builder/packet.rs:374-479`), including its
//!   derivation of `publisher_entity_id` from `group_sn` (`packet.rs:417-421`);
//! * ECS close marker (EcsClose): `build_ecs_data_submessage`
//!   (`packet.rs:497-585`).
//! * dispose / unregister KEY-only DATA (Dispose):
//!   `build_dispose_packet_with_context` (`packet.rs:1043-1127`).
//! * fragmented large-payload DATA_FRAG (`emit_canonical_native_frags`):
//!   the splitter `build_data_frag_packets` (`packet.rs:922-977`), whose
//!   per-fragment submessage is built by `build_single_data_frag_packet`
//!   (`packet.rs:982-1020`) through `DialectEncoder::build_data_frag`
//!   (Hybrid/self, `dialect/hybrid/mod.rs:279-302`) which delegates to
//!   `rtps::encode_data_frag` (`crates/hdds/src/protocol/rtps/data.rs:84-158`).
//!
//! The inline QoS layout mirrors `build_inline_qos_with_topic_and_coherent`
//! (`helpers.rs:359-395`), `build_inline_qos_for_ecs` (`helpers.rs:416-441`),
//! `build_inline_qos_for_dispose` (`helpers.rs:462-537`),
//! `append_pid_topic_name` (`helpers.rs:316-338`),
//! `encode_sequence_number_pid` (`helpers.rs:253-262`), and
//! `append_pid_group_entity_id` (`helpers.rs:305-309`).
//!
//! ### Derivation asymmetry (Phase-2 collapse signal)
//!
//! `PID_GROUP_ENTITY_ID` is emitted with two DIFFERENT rules on the live paths
//! the oracle mirrors: the member-DATA builder gates it on `group_sn`
//! (`packet.rs:417`), while the ECS dispatcher hardcodes it unconditionally
//! (`coherent.rs:200`). The oracle reproduces the exact wire bytes of each
//! path, so it deliberately keeps the asymmetry (see `build_inline_qos` vs
//! `build_inline_qos_for_ecs`) rather than smoothing it over.
//!
//! ## Eventual target
//!
//! For Phase-0 the return is an owned `Vec<u8>` so the correctness proof is
//! trivial to read. The eventual target is a zero-copy `Canonical<'a>`
//! borrowing descriptor (offsets into the journaled bytes) rather than an
//! allocation on the hot path -- nobody should design against the owned-Vec
//! shape as if it were final.

// Phase-0 scaffolding: these items are exercised by the module's own tests and
// prove the read-only oracle; they are not yet wired into the live write path
// (that is a later slice), so a non-test build sees them as unused.
#![allow(dead_code)]

// Reuse the live `StatusInfoKind` (its `#[repr(u32)]` discriminants ARE the wire
// value serialized into PID_STATUS_INFO -- see `helpers.rs:447-456` and the
// dispose inline-QoS builder `helpers.rs:529-530`). It is re-exported at
// `crate::protocol::builder` (`builder/mod.rs:38`), so the oracle carries the
// SAME type the live path carries rather than mirroring a parallel copy: any
// future variant/discriminant change lands here automatically.
use crate::protocol::builder::StatusInfoKind;
// The crate's ONE sequence-number split. Two statements of one
// wire rule drift apart, so the rule is not copied into this file.
use crate::protocol::rtps::split_sequence_number;

// The DATA_FRAG oracle mirrors the SPLITTER's internal threshold. Importing the
// live const (rather than re-declaring 8192) keeps `emit_canonical_native_frags`
// in lockstep with `build_data_frag_packets` (packet.rs:944): if that value ever
// changes, the derived fragmentation decision here tracks it automatically.
use crate::protocol::builder::DEFAULT_MAX_UNFRAGMENTED_SIZE;

/// Minimal writer context needed to emit a plain keyed DATA submessage.
///
/// This is intentionally the SMALLEST set of writer-owned fields the DATA
/// submessage body actually consumes -- the reader/writer entity IDs. It reads
/// no live/mutable state and holds no clock, cache, or per-reader patch state.
///
/// Note on `reader_entity_id`: the live builder writes `ctx.reader_entity_id`
/// here (`packet.rs:463`); the per-reader entity-id patching that
/// `send_packet_to_endpoints` performs for cross-vendor interop happens LATER,
/// on the assembled datagram, and is explicitly out of the canonical (it is
/// audience-specific, i.e. dialect/addressing, not native emission).
#[derive(Clone, Copy, Debug)]
pub(crate) struct WriterEmitCtx {
    pub reader_entity_id: [u8; 4],
    pub writer_entity_id: [u8; 4],
    /// The writer's Publisher (`RtpsEndpointContext::publisher_entity_id`).
    pub publisher_entity_id: [u8; 4],
}

/// Which emission form a journaled change reconstructs.
///
/// The three Native/self forms this oracle covers differ in submessage flags,
/// payload presence, and inline-QoS composition, so a single `Option`-soup
/// descriptor cannot distinguish them unambiguously: an ECS close marker and a
/// coherent member DATA can both carry `coherent_sn = Some`, yet one has a
/// payload (flags 0x07) and the other does not (flags 0x03). A small explicit
/// discriminator keeps each form's invariants legible and lets
/// `emit_canonical_native` branch without inferring intent from field presence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EmissionForm {
    /// Plain keyed DATA (slice 1): flags 0x07, payload present, inline QoS =
    /// PID_TOPIC_NAME [+ PID_KEY_HASH] + PID_SENTINEL. Carries no coherent
    /// metadata (`coherent_sn = None`, `group_sn = None`). Mirrors
    /// `build_data_packet_with_context_full_keyed` with both coherent params
    /// `None` (`packet.rs:374-479`).
    PlainKeyed,

    /// Coherent MEMBER DATA (slice 2, Form A): a normal keyed DATA emitted
    /// inside a `begin/end_coherent_changes` window. Flags 0x07, payload
    /// present, inline QoS additionally carries PID_COHERENT_SET and -- under
    /// GROUP scope only (`group_sn = Some`) -- PID_GROUP_COHERENT_SET +
    /// PID_GROUP_ENTITY_ID. Mirrors `build_data_packet_with_context_full_keyed`
    /// with `coherent_sn = Some` (`packet.rs:374-479`).
    CoherentMember,

    /// End-of-Coherent-Set (ECS) close marker (slice 2, Form B): flags 0x03
    /// (D=0, K=0, Q=1), NO serialized payload, inline QoS = PID_TOPIC_NAME +
    /// PID_COHERENT_SET [+ PID_GROUP_COHERENT_SET] + PID_GROUP_ENTITY_ID +
    /// PID_SENTINEL (no PID_KEY_HASH, no PID_STATUS_INFO). Mirrors
    /// `build_ecs_data_submessage` / `build_inline_qos_for_ecs`
    /// (`packet.rs:497-585`, `helpers.rs:416-441`).
    /// `coherent_sn` lives HERE rather than as an `Option` on the view
    /// because an ECS marker without one is not a thing that exists: the live
    /// builder takes it as a plain `u64` (`packet.rs:501`). As an Option it
    /// had to be unwrapped at emission with a panic behind it.
    EcsClose { coherent_sn: u64 },

    /// Dispose / unregister lifecycle change (slice 3): a KEY-only DATA. Flags
    /// 0x0B (LE=1 | InlineQoS=1 | Key=1, bits 0,1,3 -- Data=0), so the
    /// serialized payload is the writer's serialized @key fields (K-payload),
    /// NOT a full sample. Inline QoS = PID_TOPIC_NAME + PID_KEY_HASH +
    /// PID_STATUS_INFO + PID_SENTINEL. Mirrors
    /// `build_dispose_packet_with_context` (`packet.rs:1043-1127`) and its inline
    /// QoS `build_inline_qos_for_dispose` (`helpers.rs:462-537`).
    ///
    /// The `status` carries which lifecycle transition this is (Disposed /
    /// Unregistered / DisposedUnregistered). It is a genuine per-change input --
    /// not derivable from any other field on the view -- because the SAME topic,
    /// key hash and payload shape can carry any of the three StatusInfo values;
    /// only the caller (`DataWriter::dispose` vs `unregister_instance`) knows
    /// which. It reuses the live `StatusInfoKind` whose `#[repr(u32)]`
    /// discriminant IS the wire value (`helpers.rs:447-456`).
    Dispose {
        status: StatusInfoKind,
        /// Same reasoning as `EcsClose::coherent_sn`: the live builder takes a
        /// non-optional `&[u8; 16]` (`packet.rs:1047`), so the key hash is part
        /// of what a dispose IS. The view's own `key_hash` stays optional for
        /// the keyed-sample forms, where it genuinely can be absent, and is not
        /// read for this form.
        key_hash: [u8; 16],
        /// PID_COHERENT_SET (0x0056) carried when this lifecycle change was
        /// emitted while the writer's publisher had an open coherent set
        /// (RTPS v2.5 SS8.7.5/SS8.7.6), `None` outside one. Mirrors
        /// `build_dispose_packet_with_context_coherent_ts`'s `coherent_sn`
        /// (`packet.rs`).
        coherent_sn: Option<u64>,
        /// PID_GROUP_COHERENT_SET_HDDS (0x8030) under GROUP access_scope
        /// only; `None` otherwise. Mirrors the same function's `group_sn`.
        group_sn: Option<u64>,
    },
}

/// Read-only view of the fields a journaled `CacheChange` would carry for a
/// Native/self DATA submessage. Every field is an INPUT; none is read from a
/// clock, lock, or cache.
///
/// Note: `publisher_entity_id` is deliberately NOT a field. It is DERIVED (from
/// `group_sn` on the member-DATA path, `packet.rs:417-421`) rather than stored,
/// which proves it is a schema fact of the writer topology, not independent
/// per-change state. See `build_inline_qos`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct CanonicalChangeView<'a> {
    /// Discriminates plain keyed vs coherent member vs ECS close. Selects the
    /// submessage flags, payload presence, and inline-QoS composition.
    pub form: EmissionForm,

    /// Writer sequence number assigned to this change (RTPS SequenceNumber_t).
    pub sequence: u64,

    /// The serialized payload stored VERBATIM, INCLUDING its 4-byte
    /// encapsulation header (`[kind_hi, kind_lo, options_hi, options_lo]` +
    /// serialized body). Storing it verbatim is the whole point of the
    /// journal: repair reproduces the exact bytes that went out live, and the
    /// encapsulation header is never re-derived from a (possibly different)
    /// default CDR version.
    ///
    /// Per form:
    /// * `PlainKeyed` / `CoherentMember`: the full serialized sample (encap
    ///   PLAIN_CDR2_LE `0x0007` + body).
    /// * `EcsClose`: MUST be empty (`&[]`) -- the close marker carries no payload
    ///   (D=0).
    /// * `Dispose`: the K-payload = the serialized @key fields framed by the
    ///   live builder exactly as a sample is (`encapsulate_serialized_payload`):
    ///   the writer's encapsulation identifier (the one its DATA carries at the
    ///   same CDR version), options counting the padding (DDS-XTypes 1.3
    ///   7.6.3.1.2), serialized_key, then zeros to a multiple of 4 octets; a
    ///   sealed key is neither padded nor counted. It is carried VERBATIM here
    ///   exactly like a sample payload: the oracle appends it byte-for-byte and
    ///   stays payload-agnostic (it does NOT re-derive the encap kind, the
    ///   options or the padding -- those are baked into the journaled bytes,
    ///   matching the "never re-derive the encapsulation" rule above).
    ///   A drop-time unregister with no `&T` journals just the bare encap header
    ///   (empty key), still non-empty.
    pub serialized_payload: &'a [u8],

    /// Topic name emitted as PID_TOPIC_NAME (0x0005) in inline QoS.
    pub topic: &'a str,

    /// Instance key hash emitted as PID_KEY_HASH (0x0070) in inline QoS.
    /// `Some` for a keyed type, `None` for a keyless type. MUST be `None` for
    /// `EmissionForm::EcsClose` (the ECS marker carries no key hash --
    /// `helpers.rs:416-441`) and MUST be `Some` for `EmissionForm::Dispose` (a
    /// dispose / unregister always names its instance -- the live builder takes a
    /// non-optional `&[u8; 16]`, `packet.rs:1047`, and the runtime always feeds
    /// `instance.compute_key()`, `runtime.rs:1209`).
    pub key_hash: Option<[u8; 16]>,

    /// Writer-scoped coherent-set SN emitted as PID_COHERENT_SET (0x0056).
    /// `None` on a plain keyed sample; `Some` for a coherent member and
    /// MANDATORY (must be `Some`) for an ECS close marker (`packet.rs:501`,
    /// `helpers.rs:429`).
    pub coherent_sn: Option<u64>,

    /// Publisher GSN emitted as PID_GROUP_COHERENT_SET_HDDS (0x8030) under GROUP
    /// scope. `Some` selects GROUP scope, which additionally arms
    /// PID_GROUP_ENTITY_ID on the member-DATA path (`packet.rs:417-421`);
    /// `None` selects TOPIC/INSTANCE scope (or a plain sample).
    pub group_sn: Option<u64>,

    /// Source timestamp `(sec, frac)` (RTPS Time_t, frac in 2^-32 s). Carried
    /// on the change so a LATER message-assembly phase can reconstruct INFO_TS
    /// deterministically. It is NOT emitted into the DATA submessage (the DATA
    /// submessage is timestamp-free), so it does not affect the bytes this
    /// function returns; it is present to keep the change descriptor complete.
    pub source_timestamp: (u32, u32),
}

/// RTPS DATA submessage ID (`packet.rs:454`/`566`, `constants.rs:211`).
const RTPS_SUBMSG_DATA: u8 = 0x15;
/// DATA submessage flags for a payload-carrying DATA on the Native/self path:
/// LE=1 | InlineQoS=1 | Data=1 (`packet.rs:455`). Used by both the plain keyed
/// slice and the coherent MEMBER DATA (Form A) -- a coherent member is a normal
/// DATA that merely carries extra coherent PIDs in its inline QoS.
const DATA_FLAGS_LE_Q_D: u8 = 0x07;
/// DATA submessage flags for an End-of-Coherent-Set (ECS) close marker:
/// LE=1 | InlineQoS=1, Data=0, Key=0 (`packet.rs:568`). No serialized payload;
/// the submessage is inline-QoS-only.
const ECS_FLAGS_LE_Q: u8 = 0x03;
/// DATA submessage flags for a dispose / unregister KEY-only DATA:
/// LE=1 | InlineQoS=1 | Key=1 (bits 0,1,3), Data=0 (`packet.rs:1103`). Unlike
/// the payload-carrying forms (D=1, flags 0x07), a dispose sets the K flag
/// instead of the D flag: the serialized payload is the @key fields, not a full
/// sample (DDS-RTPS v2.5 sec. 9.6.4.9).
const DISPOSE_FLAGS_LE_Q_K: u8 = 0x0B;
/// Standard `octetsToInlineQos` for a DATA submessage (`packet.rs:460`/`572`).
const OCTETS_TO_INLINE_QOS: u16 = 16;

/// RTPS DATA_FRAG submessage ID (`rtps/data.rs:100`).
const RTPS_SUBMSG_DATA_FRAG: u8 = 0x16;
/// DATA_FRAG submessage flags on the Native/self path: E (little-endian) ONLY
/// (`rtps/data.rs:107`). Per DDS-RTPS v2.5 Table 9.18 a DATA_FRAG has flags
/// E(0x01), Q(0x02), K(0x04), N(0x08) -- there is NO D flag (a DATA_FRAG always
/// carries data unless K is set). HDDS emits only E: no inline QoS (Q=0), no
/// key (K=0). This is why a fragmented sample carries NEITHER PID_TOPIC_NAME nor
/// PID_KEY_HASH on the wire, unlike the DATA path (see
/// `emit_canonical_native_frags`).
const DATA_FRAG_FLAGS_LE: u8 = 0x01;
/// `octetsToInlineQos` for a DATA_FRAG submessage: 28, NOT the DATA path's 16
/// (`rtps/data.rs:121`). Per DDS-RTPS v2.5 sec. 9.4.5.3.4 a DATA_FRAG carries 12
/// extra octets (fragmentStartingNum + fragmentsInSubmessage + fragmentSize +
/// sampleSize) between writerSN and the inline_qos position, so the count is
/// 16 (the DATA part) + 12 (the DATA_FRAG extension) = 28. Sending 16 makes
/// strict receivers read 12 payload bytes as garbage inline QoS.
const OCTETS_TO_INLINE_QOS_DATA_FRAG: u16 = 28;

const PID_TOPIC_NAME: u16 = 0x0005;
const PID_KEY_HASH: u16 = 0x0070;
const PID_SENTINEL: u16 = 0x0001;
/// `PID_STATUS_INFO` (0x0071) -- 4-octet `StatusInfo_t` array carrying the
/// dispose / unregister flags (`constants.rs`, used at `helpers.rs:527`).
const PID_STATUS_INFO: u16 = 0x0071;
/// `PID_COHERENT_SET` (0x0056) -- writer-scoped SequenceNumber_t of the
/// coherent set (`constants.rs:48`).
const PID_COHERENT_SET: u16 = 0x0056;
/// Publisher GSN SequenceNumber_t. HDDS keys GROUP-scope sets on the
/// vendor-specific PID 0x8030 (`PID_GROUP_COHERENT_SET_HDDS`, see
/// `constants.rs`) rather than the standard 0x0063, so classic receivers
/// never arm their group barrier on our GSN. The oracle
/// MUST track the live constant, never a literal.
const PID_GROUP_COHERENT_SET: u16 =
    crate::protocol::discovery::constants::PID_GROUP_COHERENT_SET_HDDS;
/// `PID_GROUP_ENTITY_ID` (0x0053) -- owning Publisher EntityId, 4-byte payload
/// (`helpers.rs:305-309`).
const PID_GROUP_ENTITY_ID: u16 = 0x0053;

/// The Publisher Group EntityId HDDS pins for `PID_GROUP_ENTITY_ID`:
/// entityKey=0x000001, entityKind=0x08 (USER_DEFINED_PUBLISHER_GROUP). Both the
/// member-DATA builder (`packet.rs:418`) and the ECS dispatcher
/// (`coherent.rs:200`) hardcode this exact value, so it is a derived schema
/// constant of the current single-Publisher-per-Participant topology, never
/// independent per-change state.
/// Tests only: the Publisher of the goldens' writer, not the key-1 one, so
/// a builder that names a fixed Publisher is caught.
#[cfg(test)]
const PUBLISHER_GROUP_ENTITY_ID: [u8; 4] = [0x00, 0x00, 0x21, 0x08];

/// Reconstruct the Native/self DATA submessage bytes from a journaled change,
/// dispatching on `change.form`.
///
/// Pure and read-only: no clock (the timestamp is an input), no lock, no cache
/// access, no per-reader patching, no call into the live stateful builder.
/// Returns the DATA submessage ONLY (submessage header + body + inline QoS
/// [+ serialized payload]) -- NOT the RTPS header or INFO_TS framing.
///
/// The output is byte-identical to what the corresponding live builder emits
/// for the DATA submessage portion of its packet (the live packet with its
/// leading 20-byte header + 12-byte INFO_TS stripped):
/// * PlainKeyed / CoherentMember ->
///   `build_data_packet_with_context_full_keyed(ctx, topic, seq, body, version,
///   coherent_sn, group_sn, key_hash)` (`packet.rs:374-479`);
/// * EcsClose -> `build_ecs_data_submessage(ctx, topic, seq, coherent_sn,
///   group_sn, Some([0,0,1,8]))` (`packet.rs:497-585`).
///
/// This is proven in the tests below against pinned golden vectors.
///
/// An EMPTY vector means the change cannot be framed: the topic name does not
/// fit the u16 inline-QoS parameter length, or the body does not fit the u16
/// octetsToNextHeader (RTPS v2.5 Sec.9.4.5.1.3). This is the live builders'
/// own convention (`build_data_frag_packets` returns an empty sequence on
/// failure and its callers treat it as "not built").
pub(crate) fn emit_canonical_native(change: &CanonicalChangeView, ctx: &WriterEmitCtx) -> Vec<u8> {
    // Form dispatch selects the flags byte, the inline QoS composition, and
    // whether a serialized payload is appended. The submessage header + fixed
    // body assembly below (extraFlags + octetsToInlineQos + entityIds + seq) is
    // identical for all three forms.
    let (flags, inline_qos, payload): (u8, Option<Vec<u8>>, &[u8]) = match change.form {
        EmissionForm::PlainKeyed | EmissionForm::CoherentMember => (
            DATA_FLAGS_LE_Q_D,
            build_inline_qos(
                change.topic,
                change.coherent_sn,
                change.group_sn,
                ctx.publisher_entity_id,
                change.key_hash.as_ref(),
            ),
            change.serialized_payload,
        ),
        EmissionForm::EcsClose { coherent_sn } => {
            // The ECS marker carries no payload (D=0); serialized_payload must
            // be empty for this form (see CanonicalChangeView doc). coherent_sn
            // is mandatory on an ECS marker (packet.rs:501, helpers.rs:429) and
            // the variant carries it, so there is nothing to unwrap.
            (
                ECS_FLAGS_LE_Q,
                build_inline_qos_for_ecs(
                    change.topic,
                    coherent_sn,
                    change.group_sn,
                    ctx.publisher_entity_id,
                ),
                &[][..],
            )
        }
        EmissionForm::Dispose {
            status,
            key_hash,
            coherent_sn,
            group_sn,
        } => {
            // A dispose / unregister is a KEY-only DATA (K=1, D=0). The key hash
            // is mandatory: the live builder takes a non-optional `&[u8; 16]`
            // (packet.rs:1047) fed from `instance.compute_key()`
            // (runtime.rs:1209). The serialized payload is the verbatim K-payload
            // (the writer's encap, options counting the padding, serialized_key,
            // padding: `encapsulate_serialized_payload`), appended byte-for-byte
            // like a sample payload. `coherent_sn` / `group_sn` carry the same
            // coherent-set tags a member sample gets when this lifecycle change
            // was emitted inside an open coherent set (RTPS v2.5 SS8.7.5/SS8.7.6).
            (
                DISPOSE_FLAGS_LE_Q_K,
                build_inline_qos_for_dispose(
                    change.topic,
                    &key_hash,
                    status,
                    coherent_sn,
                    group_sn,
                    ctx.publisher_entity_id,
                ),
                change.serialized_payload,
            )
        }
    };

    let Some(inline_qos) = inline_qos else {
        return Vec::new();
    };

    // DATA submessage body: extraFlags(2) + octetsToInlineQos(2) + entityIds(8)
    // + seq(8) + inline_qos [+ payload] (packet.rs:433-435 / 550-552).
    let submsg_body_len = 20 + inline_qos.len() + payload.len();
    let Ok(octets_to_next_header) = u16::try_from(submsg_body_len) else {
        return Vec::new();
    };

    let mut out = Vec::with_capacity(4 + submsg_body_len);

    // DATA submessage header (4 bytes) -- packet.rs:453-456 / 565-569.
    out.push(RTPS_SUBMSG_DATA);
    out.push(flags);
    out.extend_from_slice(&octets_to_next_header.to_le_bytes());

    // extraFlags + octetsToInlineQos -- packet.rs:458-460 / 571-572.
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&OCTETS_TO_INLINE_QOS.to_le_bytes());

    // Reader/Writer entity IDs -- packet.rs:462-464 / 574-575.
    out.extend_from_slice(&ctx.reader_entity_id);
    out.extend_from_slice(&ctx.writer_entity_id);

    // Sequence number (SequenceNumber_t = high:i32 + low:u32)
    // -- packet.rs:466-470 / 577-580.
    let (sn_high, sn_low) = split_sequence_number(change.sequence);
    out.extend_from_slice(&sn_high.to_le_bytes());
    out.extend_from_slice(&sn_low.to_le_bytes());

    // Inline QoS then, for payload-carrying forms, the verbatim serialized
    // payload -- packet.rs:472-476 / 582.
    out.extend_from_slice(&inline_qos);
    out.extend_from_slice(payload);

    out
}

/// Append a serialised PID_TOPIC_NAME (0x0005) parameter, mirroring
/// `append_pid_topic_name` (`helpers.rs:316-338`): a CDR string (u32 length
/// including the trailing NUL, then the bytes and NUL) padded up to a 4-byte
/// boundary (RTPS v2.5 sec. 9.4.2.11).
///
/// Like the live helper, refuses (returns `None`) a topic whose parameter
/// does not fit the u16 parameterLength; the check is on the ALIGNED length,
/// which is the value actually written (a 65533-byte string aligns to 65536).
fn append_pid_topic_name(qos: &mut Vec<u8>, topic: &str) -> Option<()> {
    let topic_bytes = topic.as_bytes();
    let string_len = topic_bytes.len() + 1; // + NUL
    let param_len = 4 + string_len;
    let aligned_param_len = (param_len + 3) & !3;
    let padding = aligned_param_len - param_len;
    let aligned_param_len = u16::try_from(aligned_param_len).ok()?;
    let string_len = u32::try_from(string_len).ok()?;

    qos.extend_from_slice(&PID_TOPIC_NAME.to_le_bytes());
    qos.extend_from_slice(&aligned_param_len.to_le_bytes());
    qos.extend_from_slice(&string_len.to_le_bytes());
    qos.extend_from_slice(topic_bytes);
    qos.push(0); // NUL
    qos.extend(std::iter::repeat_n(0u8, padding));
    Some(())
}

/// Encode a single SequenceNumber_t PID payload, mirroring
/// `encode_sequence_number_pid` (`helpers.rs:253-262`): pid(2) + len=8(2) +
/// high:i32 LE + low:u32 LE. Shared by PID_COHERENT_SET and
/// PID_GROUP_COHERENT_SET (both carry a SequenceNumber_t per RTPS v2.5 sec. 8.7.5).
fn encode_sequence_number_pid(pid: u16, value: u64) -> [u8; 12] {
    let mut buf = [0u8; 12];
    buf[0..2].copy_from_slice(&pid.to_le_bytes());
    buf[2..4].copy_from_slice(&8u16.to_le_bytes());
    let (sn_high, sn_low) = split_sequence_number(value);
    buf[4..8].copy_from_slice(&sn_high.to_le_bytes());
    buf[8..12].copy_from_slice(&sn_low.to_le_bytes());
    buf
}

/// Append PID_GROUP_ENTITY_ID (0x0053): a 4-byte EntityId payload, mirroring
/// `append_pid_group_entity_id` (`helpers.rs:305-309`).
fn append_pid_group_entity_id(qos: &mut Vec<u8>, entity_id: [u8; 4]) {
    qos.extend_from_slice(&PID_GROUP_ENTITY_ID.to_le_bytes());
    qos.extend_from_slice(&4u16.to_le_bytes());
    qos.extend_from_slice(&entity_id);
}

/// Build the inline QoS parameter list for a payload-carrying DATA (plain keyed
/// or coherent member), mirroring `build_inline_qos_with_topic_and_coherent`
/// (`helpers.rs:359-395`).
///
/// PID order (RTPS v2.5 sec. 9.4.2.11): PID_TOPIC_NAME, then PID_COHERENT_SET (when
/// `coherent_sn` is `Some`), then PID_GROUP_COHERENT_SET (GROUP scope only),
/// then PID_GROUP_ENTITY_ID (GROUP scope only), then PID_KEY_HASH (keyed only),
/// then PID_SENTINEL. For the plain keyed case (`coherent_sn = None`,
/// `group_sn = None`) this degenerates to exactly the slice-1 layout.
///
/// `publisher_entity_id` is DERIVED here, not taken as input: the live builder
/// computes it as `group_sn.is_some().then(|| [0,0,1,8])` (`packet.rs:417-421`),
/// so the oracle replicates the same derivation from `group_sn`. This proves
/// the Publisher Group EntityId is a schema constant gated on GROUP scope, not
/// independent per-change state.
fn build_inline_qos(
    topic: &str,
    coherent_sn: Option<u64>,
    group_sn: Option<u64>,
    publisher_entity_id: [u8; 4],
    key_hash: Option<&[u8; 16]>,
) -> Option<Vec<u8>> {
    let mut qos = Vec::with_capacity(128);

    append_pid_topic_name(&mut qos, topic)?;

    // PID_COHERENT_SET (0x0056) -- append_pid_coherent_set (helpers.rs:268-271).
    if let Some(sn) = coherent_sn {
        qos.extend_from_slice(&encode_sequence_number_pid(PID_COHERENT_SET, sn));
    }
    // PID_GROUP_COHERENT_SET_HDDS (0x8030), GROUP scope only
    // -- append_pid_group_coherent_set (helpers.rs:278-281).
    if let Some(gsn) = group_sn {
        qos.extend_from_slice(&encode_sequence_number_pid(PID_GROUP_COHERENT_SET, gsn));
    }
    // PID_GROUP_ENTITY_ID (0x0053), derived from GROUP scope -- the live builder
    // sets publisher_entity_id = group_sn.is_some().then(...) (packet.rs:417-421)
    // then append_pid_group_entity_id emits it (helpers.rs:378-380, 305-309).
    if group_sn.is_some() {
        append_pid_group_entity_id(&mut qos, publisher_entity_id);
    }
    // PID_KEY_HASH (0x0070) -- 16 raw bytes (helpers.rs:386-388).
    if let Some(hash) = key_hash {
        qos.extend_from_slice(&PID_KEY_HASH.to_le_bytes());
        qos.extend_from_slice(&16u16.to_le_bytes());
        qos.extend_from_slice(hash);
    }

    // PID_SENTINEL (0x0001, len 0) -- helpers.rs:391-392.
    qos.extend_from_slice(&PID_SENTINEL.to_le_bytes());
    qos.extend_from_slice(&0u16.to_le_bytes());

    Some(qos)
}

/// Build the inline QoS parameter list for an ECS close marker, mirroring
/// `build_inline_qos_for_ecs` (`helpers.rs:416-441`).
///
/// PID order: PID_TOPIC_NAME, PID_COHERENT_SET (mandatory), PID_GROUP_COHERENT_SET
/// (GROUP scope only), PID_GROUP_ENTITY_ID, PID_SENTINEL. No PID_KEY_HASH and no
/// PID_STATUS_INFO (so the marker does not collide with the inline-QoS-only
/// dispose form -- `helpers.rs:414`).
///
/// DIVERGENCE from `build_inline_qos` above: PID_GROUP_ENTITY_ID is emitted
/// UNCONDITIONALLY here, NOT gated on `group_sn`. The live ECS dispatcher
/// hardcodes `publisher_entity_id = Some([0,0,1,8])` regardless of scope
/// (`coherent.rs:200`), whereas the member-DATA builder gates it on `group_sn`
/// (`packet.rs:417`). The oracle reproduces the ACTUAL wire bytes of each path,
/// so it mirrors this asymmetry rather than smoothing it over -- two derivation
/// rules for the same PID is a Phase-2 collapse signal.
fn build_inline_qos_for_ecs(
    topic: &str,
    coherent_sn: u64,
    group_sn: Option<u64>,
    publisher_entity_id: [u8; 4],
) -> Option<Vec<u8>> {
    let mut qos = Vec::with_capacity(96);

    append_pid_topic_name(&mut qos, topic)?;

    // PID_COHERENT_SET (mandatory) -- helpers.rs:429.
    qos.extend_from_slice(&encode_sequence_number_pid(PID_COHERENT_SET, coherent_sn));
    // PID_GROUP_COHERENT_SET (GROUP scope only) -- helpers.rs:430-432.
    if let Some(gsn) = group_sn {
        qos.extend_from_slice(&encode_sequence_number_pid(PID_GROUP_COHERENT_SET, gsn));
    }
    // PID_GROUP_ENTITY_ID, unconditional on the live ECS path: the writer's
    // Publisher (coherent.rs `emit_ecs_data`, helpers.rs:433-435).
    append_pid_group_entity_id(&mut qos, publisher_entity_id);

    // PID_SENTINEL (0x0001, len 0) -- helpers.rs:437-438.
    qos.extend_from_slice(&PID_SENTINEL.to_le_bytes());
    qos.extend_from_slice(&0u16.to_le_bytes());

    Some(qos)
}

/// Build the inline QoS parameter list for a dispose / unregister KEY-only DATA,
/// mirroring `build_inline_qos_for_dispose_coherent` (`helpers.rs`).
///
/// PID order (RTPS v2.5 sec. 9.4.2.11): PID_TOPIC_NAME, [PID_COHERENT_SET],
/// [PID_GROUP_COHERENT_SET_HDDS], [PID_GROUP_ENTITY_ID], PID_KEY_HASH,
/// PID_STATUS_INFO, PID_SENTINEL. The coherent PIDs are present only when this
/// lifecycle change was emitted inside an open coherent set (RTPS v2.5
/// SS8.7.5/SS8.7.6: a dispose is a CacheChange like any other, and an untagged
/// one ends the set at a spec reader). PID_KEY_HASH still comes LAST before
/// PID_STATUS_INFO, unlike `build_inline_qos` (the payload-carrying forms),
/// where it comes after any coherent PIDs too but before the sentinel with no
/// PID_STATUS_INFO after it.
///
/// `group_sn.is_some()` derives `PID_GROUP_ENTITY_ID`, mirroring
/// `build_inline_qos_for_dispose_coherent`'s derivation (itself mirroring the
/// member-DATA path's `group_sn.is_some().then(...)`, `packet.rs`).
///
/// PID_STATUS_INFO SERIALIZATION (the sharp edge): the 4-octet value is written
/// BIG-ENDIAN, not little-endian. Per DDS-RTPS v2.5 sec. 9.6.4.9, StatusInfo_t is a
/// `typedef octet StatusInfo_t[4]` whose meaningful flag bits (D=Disposed,
/// U=Unregistered) live in OCTET 3 (the last byte). The live builder therefore
/// serializes the `#[repr(u32)]` discriminant with `to_be_bytes()`
/// (`helpers.rs:529-530`) so `0x01/0x02/0x03` land as `[0x00,0x00,0x00,0x0N]`.
/// Writing it LE (the pre-fix bug) put the flags in octet 0, so a receiver
/// reading octet 3, as Sec. 9.6.4.9 specifies, saw "no flags set". The oracle reproduces
/// the exact `to_be_bytes()` layout; a wire fix must decode to the same bytes.
///
/// PHASE-2 COLLAPSE SIGNAL: `append_pid_topic_name` is shared, but the
/// PID_KEY_HASH emission (pid + len=16 + 16 raw bytes) is duplicated here from
/// `build_inline_qos`, and the whole envelope order is a THIRD distinct
/// inline-QoS recipe alongside `build_inline_qos` and `build_inline_qos_for_ecs`.
/// Three hand-rolled parameter lists that only differ in which PIDs appear and
/// in what order is exactly the duplication the addressing/emission collapse is
/// meant to unify.
fn build_inline_qos_for_dispose(
    topic: &str,
    key_hash: &[u8; 16],
    status: StatusInfoKind,
    coherent_sn: Option<u64>,
    group_sn: Option<u64>,
    publisher_entity_id: [u8; 4],
) -> Option<Vec<u8>> {
    let mut qos = Vec::with_capacity(96);

    append_pid_topic_name(&mut qos, topic)?;

    // PID_COHERENT_SET (0x0056) -- same PID a member sample carries.
    if let Some(sn) = coherent_sn {
        qos.extend_from_slice(&encode_sequence_number_pid(PID_COHERENT_SET, sn));
    }
    // PID_GROUP_COHERENT_SET_HDDS (0x8030), GROUP scope only.
    if let Some(gsn) = group_sn {
        qos.extend_from_slice(&encode_sequence_number_pid(PID_GROUP_COHERENT_SET, gsn));
    }
    // PID_GROUP_ENTITY_ID (0x0053), derived from GROUP scope, same derivation
    // as `build_inline_qos` above.
    if group_sn.is_some() {
        append_pid_group_entity_id(&mut qos, publisher_entity_id);
    }

    // PID_KEY_HASH (0x0070) -- 16 raw bytes (helpers.rs:504-507).
    qos.extend_from_slice(&PID_KEY_HASH.to_le_bytes());
    qos.extend_from_slice(&16u16.to_le_bytes());
    qos.extend_from_slice(key_hash);

    // PID_STATUS_INFO (0x0071) -- 4-octet StatusInfo_t array, BIG-ENDIAN so the
    // flag bits land in octet 3. The value is the #[repr(u32)] discriminant
    // (0x01/0x02/0x03), converted where the repr is declared (`From` impl in
    // helpers.rs), not cast here.
    qos.extend_from_slice(&PID_STATUS_INFO.to_le_bytes());
    qos.extend_from_slice(&4u16.to_le_bytes());
    qos.extend_from_slice(&u32::from(status).to_be_bytes());

    // PID_SENTINEL (0x0001, len 0) -- helpers.rs:533-534.
    qos.extend_from_slice(&PID_SENTINEL.to_le_bytes());
    qos.extend_from_slice(&0u16.to_le_bytes());

    Some(qos)
}

// ============================================================================
// DATA_FRAG: large-payload fragmentation (slice 4)
// ============================================================================

/// Reconstruct the Native/self DATA_FRAG submessage SEQUENCE for a large,
/// fragmented change, mirroring the live splitter `build_data_frag_packets`
/// (`packet.rs:922-977`).
///
/// ## Why a separate entry point returning `Vec<Vec<u8>>`
///
/// A fragmented sample emits a SEQUENCE of submessages (N DATA_FRAG), one per
/// fragment, whereas `emit_canonical_native` returns exactly ONE submessage.
/// Rather than overload that signature (and its 14 pinned tests), this returns
/// `Vec<Vec<u8>>`, one entry per DATA_FRAG submessage. This aligns with the
/// locked architecture where the stage-2 `address` step consumes a SEQUENCE of
/// canonicals: emitting a single logical change is already one-to-many here.
/// The existing single-submessage `emit_canonical_native` is exactly the
/// `len == 1`, non-fragmented case (returned verbatim below).
///
/// ## Fragmentation is DERIVED, not a stored form
///
/// There is deliberately NO `EmissionForm::Fragmented` variant. Whether a
/// change fragments is a PURE function of its serialized payload length versus
/// `fragment_size`, decided here exactly as the live splitter decides it
/// (`packet.rs:941-948`): if `serialized_payload.len()
/// <= DEFAULT_MAX_UNFRAGMENTED_SIZE` the change is NOT fragmented and the writer
/// emits ONE ordinary DATA submessage, so this returns
/// `vec![emit_canonical_native(change, ctx)]`. Only a payload that EXCEEDS the
/// threshold is split. The threshold compares the FULL encapsulated blob (encap
/// header + body): that is exactly what `serialized_payload` carries here
/// (journaled verbatim, encap included -- see
/// `CanonicalChangeView::serialized_payload`) and what the live splitter's
/// internal `total_size` measures (`packet.rs:941-944`). NOTE: the runtime's
/// `should_fragment` pre-check (`packet.rs:1026`) tests the RAW body length,
/// which is 4 octets short of this encapsulated length; the two agree except in
/// a 4-octet boundary window, and it is the splitter's internal threshold
/// (mirrored here) that actually governs whether fragments are produced.
///
/// ## `fragment_size` is an explicit, fixed-const input
///
/// The live path always passes `DEFAULT_FRAGMENT_SIZE` (1024) -- fragmentation
/// is a function of a FIXED const, never a per-destination MTU (there is no
/// addressing input at this stage). It is threaded as an explicit argument so a
/// split stays reproducible and testable at other sizes; conceptually it
/// defaults to `DEFAULT_FRAGMENT_SIZE`.
///
/// ## The DATA_FRAG form is inline-QoS-blind and form-blind
///
/// Unlike the DATA path, the live DATA_FRAG submessage carries NO inline QoS
/// (flags = E only, Q=0): no PID_TOPIC_NAME, no PID_KEY_HASH, no coherent PIDs.
/// The live splitter's signature takes only `(ctx, sequence, payload,
/// fragment_size, version)`, so `change.form`, `change.topic`,
/// `change.key_hash`, and the coherent fields NEVER reach the wire when
/// fragmented; this branch reads only `serialized_payload`, `sequence`, and the
/// entity IDs. That the DATA_FRAG encoder is a wholly separate hand-roll which
/// drops all inline QoS -- rather than reusing the DATA body per fragment -- is
/// a Phase-2 collapse signal.
///
/// Pure and read-only: no clock, lock, cache, MTU, or destination. Proven
/// byte-for-byte against `build_data_frag_packets` in the tests below.
pub(crate) fn emit_canonical_native_frags(
    change: &CanonicalChangeView,
    ctx: &WriterEmitCtx,
    fragment_size_u16: u16,
) -> Vec<Vec<u8>> {
    let total_size = change.serialized_payload.len();

    // DERIVED fragmentation: mirror the live splitter's internal threshold
    // (`build_data_frag_packets`, packet.rs:944). A payload that does not exceed
    // it is NOT fragmented; the writer emits one ordinary DATA submessage.
    if total_size <= DEFAULT_MAX_UNFRAGMENTED_SIZE {
        let single = emit_canonical_native(change, ctx);
        // An empty single DATA means "cannot be framed" (see that function's
        // doc); the sequence form of the same verdict is an empty sequence.
        return if single.is_empty() {
            Vec::new()
        } else {
            vec![single]
        };
    }

    // Both header fields are CONSTANT across every fragment (the nominal
    // fragment size and the total encapsulated size); only the last fragment's
    // actual data is shorter. A sample whose size does not fit the u32
    // sampleSize field cannot be described by DATA_FRAG at all, so the
    // sequence is empty, the live splitter's own "not built" convention.
    let fragment_size = usize::from(fragment_size_u16);
    let Ok(sample_size_u32) = u32::try_from(total_size) else {
        return Vec::new();
    };

    let num_fragments = total_size.div_ceil(fragment_size);
    let mut out = Vec::with_capacity(num_fragments);

    // `chunks` yields the same slices as the live splitter (packet.rs:957):
    // full fragments then a SHORT tail when total_size is not a multiple of
    // fragment_size, whose submessage length shrinks while its fragmentSize
    // field stays nominal. Fragment numbering is 1-based FragmentNumber_t
    // (u32, packet.rs:960-962), counted in that type rather than narrowed.
    for (fragment_starting_num, frag_data) in
        (1u32..).zip(change.serialized_payload.chunks(fragment_size))
    {
        out.push(build_data_frag_submsg(
            ctx,
            change.sequence,
            fragment_starting_num,
            1, // fragments_in_submessage: 1 fragment per submessage (packet.rs:968)
            fragment_size_u16,
            sample_size_u32,
            frag_data,
        ));
    }

    out
}

/// Build ONE Native/self DATA_FRAG submessage, mirroring `rtps::encode_data_frag`
/// (`crates/hdds/src/protocol/rtps/data.rs:84-158`) -- the encoder the Hybrid/self
/// `DialectEncoder::build_data_frag` delegates to (`dialect/hybrid/mod.rs:279-302`)
/// and that `build_single_data_frag_packet` invokes (`packet.rs:1004-1016`).
///
/// Submessage layout (a 4-byte submessage header + a 32-byte fixed body = the
/// 36-byte DATA_FRAG header noted at `packet.rs:884`, then the fragment payload):
///
/// ```text
///   byte 0     : 0x16                         DATA_FRAG submessage id
///   byte 1     : 0x01                         flags = E only (no Q/K/N)
///   bytes 2-3  : octetsToNextHeader (LE u16)  = 32 + fragment_data.len()
///   +0..2      : extraFlags = 0
///   +2..4      : octetsToInlineQos (LE u16)   = 28
///   +4..8      : readerEntityId
///   +8..12     : writerEntityId
///   +12..20    : writerSN (high i32 LE, low u32 LE)
///   +20..24    : fragmentStartingNum (LE u32, 1-based)
///   +24..26    : fragmentsInSubmessage (LE u16)
///   +26..28    : fragmentSize (LE u16)        NOMINAL, constant across frags
///   +28..32    : sampleSize (LE u32)          total encapsulated size, constant
///   +32..      : fragment payload             (no inline QoS precedes it: Q=0)
/// ```
///
/// Pure and read-only, like `emit_canonical_native`: no clock, lock, or cache.
fn build_data_frag_submsg(
    ctx: &WriterEmitCtx,
    sequence: u64,
    fragment_starting_num: u32,
    fragments_in_submessage: u16,
    fragment_size: u16,
    sample_size: u32,
    fragment_data: &[u8],
) -> Vec<u8> {
    // Fixed body: extraFlags(2) + octetsToInlineQos(2) + entityIds(8) + seqNum(8)
    // + fragmentStartingNum(4) + fragmentsInSubmessage(2) + fragmentSize(2)
    // + sampleSize(4) = 32, then the fragment payload (rtps/data.rs:94-96).
    let submsg_body_len = 32 + fragment_data.len();
    // fragment_data is at most fragment_size (a u16) bytes, so 32 + len fits
    // octetsToNextHeader; the conversion is checked rather than assumed.
    let Ok(octets_to_next_header) = u16::try_from(submsg_body_len) else {
        return Vec::new();
    };

    let mut out = Vec::with_capacity(4 + submsg_body_len);

    // DATA_FRAG submessage header (4 bytes) -- rtps/data.rs:100-108.
    out.push(RTPS_SUBMSG_DATA_FRAG);
    out.push(DATA_FRAG_FLAGS_LE);
    out.extend_from_slice(&octets_to_next_header.to_le_bytes());

    // extraFlags(0) + octetsToInlineQos(28) -- rtps/data.rs:120-121.
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&OCTETS_TO_INLINE_QOS_DATA_FRAG.to_le_bytes());

    // Reader/Writer entity IDs -- rtps/data.rs:125-128.
    out.extend_from_slice(&ctx.reader_entity_id);
    out.extend_from_slice(&ctx.writer_entity_id);

    // writerSN (high i32 + low u32) -- rtps/data.rs:131-136.
    let (sn_high, sn_low) = split_sequence_number(sequence);
    out.extend_from_slice(&sn_high.to_le_bytes());
    out.extend_from_slice(&sn_low.to_le_bytes());

    // fragmentStartingNum (LE u32) -- rtps/data.rs:139.
    out.extend_from_slice(&fragment_starting_num.to_le_bytes());
    // fragmentsInSubmessage (LE u16) -- rtps/data.rs:143.
    out.extend_from_slice(&fragments_in_submessage.to_le_bytes());
    // fragmentSize (LE u16), nominal and constant across all fragments including
    // the short last one -- rtps/data.rs:147.
    out.extend_from_slice(&fragment_size.to_le_bytes());
    // sampleSize (LE u32), total encapsulated size, constant -- rtps/data.rs:151.
    out.extend_from_slice(&sample_size.to_le_bytes());

    // Fragment payload -- rtps/data.rs:155. No inline QoS precedes it (Q=0).
    out.extend_from_slice(fragment_data);

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dds::CdrVersion;
    use crate::protocol::builder::{
        build_data_frag_packets, build_data_packet_with_context_full_keyed,
        build_dispose_packet_with_context, build_dispose_packet_with_context_coherent_ts,
        build_ecs_data_submessage, RtpsEndpointContext, DEFAULT_FRAGMENT_SIZE,
    };

    // Fixed inputs for the plain keyed DATA slice. The guid_prefix only lands
    // in the RTPS header (stripped before comparison), so any value works.
    const GUID_PREFIX: [u8; 12] = [0x20; 12];
    const READER_EID: [u8; 4] = [0x00, 0x00, 0x01, 0x02];
    const WRITER_EID: [u8; 4] = [0x00, 0x00, 0x01, 0x03];
    const TOPIC: &str = "keyed/topic";
    const SEQ: u64 = 5;
    const KEY_HASH: [u8; 16] = [0x42; 16];
    // Serialized payload stored VERBATIM: PLAIN_CDR2_LE encap header
    // (0x0007 -> [0x00, 0x07, 0x00, 0x00]) + 4 body bytes.
    const SERIALIZED_PAYLOAD: [u8; 8] = [0x00, 0x07, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04];

    // RTPS header (20) + INFO_TS (12) = 32; the DATA submessage begins here.
    const DATA_SUBMSG_OFFSET: usize = 32;

    // Golden DATA submessage for the fixed inputs above, pinned as a literal.
    // Recorded from the live builder (build_data_packet_with_context_full_keyed)
    // and cross-checked by `golden_still_matches_live` below, so a future change
    // to the live wire layout fails loudly here instead of silently drifting.
    //
    // Layout (76 bytes):
    //   15 07 48 00                 DATA id, flags(LE|Q|D), octetsToNext=72
    //   00 00                       extraFlags
    //   10 00                       octetsToInlineQos=16
    //   00 00 01 02                 readerEntityId
    //   00 00 01 03                 writerEntityId
    //   00 00 00 00 05 00 00 00     writerSN (high=0, low=5)
    //   -- inline QoS (44 bytes) --
    //   05 00 10 00 0c 00 00 00     PID_TOPIC_NAME, len=16, strlen=12
    //   6b 65 79 65 64 2f 74 6f 70 69 63 00   "keyed/topic\0"
    //   70 00 10 00                 PID_KEY_HASH, len=16
    //   42 x16                      key hash
    //   01 00 00 00                 PID_SENTINEL
    //   -- payload (8 bytes) --
    //   00 07 00 00 01 02 03 04     encap header + body
    #[rustfmt::skip]
    const GOLDEN_DATA_SUBMSG: [u8; 76] = [
        0x15, 0x07, 0x48, 0x00,
        0x00, 0x00,
        0x10, 0x00,
        0x00, 0x00, 0x01, 0x02,
        0x00, 0x00, 0x01, 0x03,
        0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
        0x05, 0x00, 0x10, 0x00, 0x0c, 0x00, 0x00, 0x00,
        0x6b, 0x65, 0x79, 0x65, 0x64, 0x2f, 0x74, 0x6f, 0x70, 0x69, 0x63, 0x00,
        0x70, 0x00, 0x10, 0x00,
        0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
        0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
        0x01, 0x00, 0x00, 0x00,
        0x00, 0x07, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04,
    ];

    fn change_view() -> CanonicalChangeView<'static> {
        CanonicalChangeView {
            form: EmissionForm::PlainKeyed,
            sequence: SEQ,
            serialized_payload: &SERIALIZED_PAYLOAD,
            topic: TOPIC,
            key_hash: Some(KEY_HASH),
            coherent_sn: None,
            group_sn: None,
            // Fixed so any INFO_TS-dependent comparison is deterministic. This
            // value never reaches the DATA submessage (see struct doc), so the
            // choice is arbitrary; pinning it documents the "input, not clock"
            // contract.
            source_timestamp: (0x1122_3344, 0x5566_7788),
        }
    }

    // ---- Slice 2 fixtures (coherent MEMBER DATA + ECS close marker) --------

    /// Writer-scoped last-sample SN of the coherent set (PID_COHERENT_SET).
    const COHERENT_SN: u64 = 4;
    /// Publisher GSN of the set under GROUP scope (PID_GROUP_COHERENT_SET).
    const GROUP_SN: u64 = 9;
    /// Fresh writer SN the ECS marker consumes (distinct from the member SN).
    const ECS_SEQ: u64 = 6;

    /// Golden coherent MEMBER DATA under GROUP scope (`coherent_sn = Some(4)`,
    /// `group_sn = Some(9)`, keyed). Recorded from the live builder and guarded
    /// by `coherent_member_group_golden_still_matches_live`.
    ///
    /// Layout (108 bytes):
    ///   15 07 68 00                 DATA id, flags(LE|Q|D), octetsToNext=104
    ///   00 00 / 10 00               extraFlags / octetsToInlineQos=16
    ///   00 00 01 02 / 00 00 01 03   reader / writer entityId
    ///   00 00 00 00 05 00 00 00     writerSN (high=0, low=5)
    ///   05 00 10 00 0c 00 00 00     PID_TOPIC_NAME, len=16, strlen=12
    ///   6b 65 79 65 64 2f 74 6f 70 69 63 00   "keyed/topic\0"
    ///   56 00 08 00 00 00 00 00 04 00 00 00   PID_COHERENT_SET = 4
    ///   30 80 08 00 00 00 00 00 09 00 00 00   PID_GROUP_COHERENT_SET_HDDS = 9
    ///   53 00 04 00 00 00 01 08     PID_GROUP_ENTITY_ID = 00 00 01 08
    ///   70 00 10 00 / 42 x16        PID_KEY_HASH
    ///   01 00 00 00                 PID_SENTINEL
    ///   00 07 00 00 01 02 03 04     encap header + body
    #[rustfmt::skip]
    const GOLDEN_MEMBER_GROUP: [u8; 108] = [
        0x15, 0x07, 0x68, 0x00,
        0x00, 0x00,
        0x10, 0x00,
        0x00, 0x00, 0x01, 0x02,
        0x00, 0x00, 0x01, 0x03,
        0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
        0x05, 0x00, 0x10, 0x00, 0x0c, 0x00, 0x00, 0x00,
        0x6b, 0x65, 0x79, 0x65, 0x64, 0x2f, 0x74, 0x6f, 0x70, 0x69, 0x63, 0x00,
        0x56, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
        0x30, 0x80, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00,
        0x53, 0x00, 0x04, 0x00, 0x00, 0x00, 0x21, 0x08,
        0x70, 0x00, 0x10, 0x00,
        0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
        0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
        0x01, 0x00, 0x00, 0x00,
        0x00, 0x07, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04,
    ];

    /// Golden coherent MEMBER DATA under TOPIC scope (`coherent_sn = Some(4)`,
    /// `group_sn = None`, keyed). Proves the `publisher_entity_id` derivation:
    /// with no `group_sn`, BOTH PID_GROUP_COHERENT_SET and PID_GROUP_ENTITY_ID
    /// vanish vs the GROUP golden above. Guarded by
    /// `coherent_member_topic_golden_still_matches_live`.
    ///
    /// Layout (88 bytes): as GROUP but the two group PIDs (20 bytes) are gone;
    /// octetsToNext=0x54=84.
    #[rustfmt::skip]
    const GOLDEN_MEMBER_TOPIC: [u8; 88] = [
        0x15, 0x07, 0x54, 0x00,
        0x00, 0x00,
        0x10, 0x00,
        0x00, 0x00, 0x01, 0x02,
        0x00, 0x00, 0x01, 0x03,
        0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
        0x05, 0x00, 0x10, 0x00, 0x0c, 0x00, 0x00, 0x00,
        0x6b, 0x65, 0x79, 0x65, 0x64, 0x2f, 0x74, 0x6f, 0x70, 0x69, 0x63, 0x00,
        0x56, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
        0x70, 0x00, 0x10, 0x00,
        0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
        0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
        0x01, 0x00, 0x00, 0x00,
        0x00, 0x07, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04,
    ];

    /// Golden ECS close marker under GROUP scope (`coherent_sn = 4`,
    /// `group_sn = Some(9)`). Guarded by `ecs_close_golden_still_matches_live`.
    ///
    /// Layout (80 bytes):
    ///   15 03 4c 00                 DATA id, flags(LE|Q, D=0 K=0), octetsToNext=76
    ///   00 00 / 10 00               extraFlags / octetsToInlineQos=16
    ///   00 00 01 02 / 00 00 01 03   reader / writer entityId
    ///   00 00 00 00 06 00 00 00     writerSN (high=0, low=6) -- fresh ECS SN
    ///   05 00 10 00 0c 00 00 00     PID_TOPIC_NAME, len=16, strlen=12
    ///   6b 65 79 65 64 2f 74 6f 70 69 63 00   "keyed/topic\0"
    ///   56 00 08 00 00 00 00 00 04 00 00 00   PID_COHERENT_SET = 4
    ///   30 80 08 00 00 00 00 00 09 00 00 00   PID_GROUP_COHERENT_SET_HDDS = 9
    ///   53 00 04 00 00 00 01 08     PID_GROUP_ENTITY_ID = 00 00 01 08
    ///   01 00 00 00                 PID_SENTINEL   (NO key hash, NO payload)
    #[rustfmt::skip]
    const GOLDEN_ECS_GROUP: [u8; 80] = [
        0x15, 0x03, 0x4c, 0x00,
        0x00, 0x00,
        0x10, 0x00,
        0x00, 0x00, 0x01, 0x02,
        0x00, 0x00, 0x01, 0x03,
        0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00,
        0x05, 0x00, 0x10, 0x00, 0x0c, 0x00, 0x00, 0x00,
        0x6b, 0x65, 0x79, 0x65, 0x64, 0x2f, 0x74, 0x6f, 0x70, 0x69, 0x63, 0x00,
        0x56, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
        0x30, 0x80, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00,
        0x53, 0x00, 0x04, 0x00, 0x00, 0x00, 0x21, 0x08,
        0x01, 0x00, 0x00, 0x00,
    ];

    /// Drive the live keyed DATA builder with the fixed inputs for a coherent
    /// member and return ONLY the DATA submessage (header + INFO_TS stripped).
    /// `group_sn` selects GROUP (`Some`) vs TOPIC (`None`) scope; the runtime
    /// derives `publisher_entity_id` from it inside the builder
    /// (`packet.rs:417-421`, driven from `runtime.rs:774-785`).
    fn live_member_submsg(group_sn: Option<u64>) -> Vec<u8> {
        let ctx = RtpsEndpointContext {
            guid_prefix: GUID_PREFIX,
            reader_entity_id: READER_EID,
            writer_entity_id: WRITER_EID,
            encapsulation_kind: 0x0007, // PLAIN_CDR2_LE
            publisher_entity_id: PUBLISHER_GROUP_ENTITY_ID,
        };
        let body = [0x01, 0x02, 0x03, 0x04];
        let live = build_data_packet_with_context_full_keyed(
            &ctx,
            TOPIC,
            SEQ,
            &body,
            CdrVersion::Xcdr2,
            Some(COHERENT_SN),
            group_sn,
            Some(&KEY_HASH),
        );
        assert!(live.len() > DATA_SUBMSG_OFFSET);
        live[DATA_SUBMSG_OFFSET..].to_vec()
    }

    /// Journaled-change descriptor for a coherent member, GROUP or TOPIC scope.
    fn member_change_view(group_sn: Option<u64>) -> CanonicalChangeView<'static> {
        CanonicalChangeView {
            form: EmissionForm::CoherentMember,
            sequence: SEQ,
            serialized_payload: &SERIALIZED_PAYLOAD,
            topic: TOPIC,
            key_hash: Some(KEY_HASH),
            coherent_sn: Some(COHERENT_SN),
            group_sn,
            source_timestamp: (0x1122_3344, 0x5566_7788),
        }
    }

    /// Drive the live ECS builder exactly as the runtime does under GROUP scope
    /// (`coherent.rs:200` passes `Some([0,0,1,8])` unconditionally) and return
    /// ONLY the DATA submessage (header + INFO_TS stripped).
    fn live_ecs_submsg() -> Vec<u8> {
        let ctx = RtpsEndpointContext {
            guid_prefix: GUID_PREFIX,
            reader_entity_id: READER_EID,
            writer_entity_id: WRITER_EID,
            encapsulation_kind: 0x0007,
            publisher_entity_id: PUBLISHER_GROUP_ENTITY_ID,
        };
        let live = build_ecs_data_submessage(
            &ctx,
            TOPIC,
            ECS_SEQ,
            COHERENT_SN,
            Some(GROUP_SN),
            Some(PUBLISHER_GROUP_ENTITY_ID),
        );
        assert!(live.len() > DATA_SUBMSG_OFFSET);
        live[DATA_SUBMSG_OFFSET..].to_vec()
    }

    /// Journaled-change descriptor for a GROUP-scope ECS close marker. No
    /// payload (empty `serialized_payload`) and no key hash (`None`).
    fn ecs_change_view() -> CanonicalChangeView<'static> {
        CanonicalChangeView {
            form: EmissionForm::EcsClose {
                coherent_sn: COHERENT_SN,
            },
            sequence: ECS_SEQ,
            serialized_payload: &[],
            topic: TOPIC,
            key_hash: None,
            coherent_sn: Some(COHERENT_SN),
            group_sn: Some(GROUP_SN),
            source_timestamp: (0x1122_3344, 0x5566_7788),
        }
    }

    // ---- Form A: coherent MEMBER DATA, GROUP scope --------------------------

    #[test]
    fn coherent_member_group_golden_still_matches_live() {
        assert_eq!(
            live_member_submsg(Some(GROUP_SN)),
            GOLDEN_MEMBER_GROUP,
            "the live coherent MEMBER DATA (GROUP scope) drifted from the pinned golden"
        );
    }

    #[test]
    fn coherent_member_group_oracle_reproduces_byte_for_byte() {
        let ctx = WriterEmitCtx {
            reader_entity_id: READER_EID,
            writer_entity_id: WRITER_EID,
            publisher_entity_id: PUBLISHER_GROUP_ENTITY_ID,
        };
        let canonical = emit_canonical_native(&member_change_view(Some(GROUP_SN)), &ctx);
        assert_eq!(canonical, GOLDEN_MEMBER_GROUP);
        assert_eq!(
            canonical,
            live_member_submsg(Some(GROUP_SN)),
            "oracle must reproduce the live GROUP-scope member DATA; PID_GROUP_ENTITY_ID \
             is derived from group_sn, not stored"
        );
    }

    // ---- Form A: coherent MEMBER DATA, TOPIC scope (derivation proof) -------

    #[test]
    fn coherent_member_topic_golden_still_matches_live() {
        assert_eq!(
            live_member_submsg(None),
            GOLDEN_MEMBER_TOPIC,
            "the live coherent MEMBER DATA (TOPIC scope) drifted from the pinned golden"
        );
    }

    #[test]
    fn coherent_member_topic_oracle_reproduces_byte_for_byte() {
        let ctx = WriterEmitCtx {
            reader_entity_id: READER_EID,
            writer_entity_id: WRITER_EID,
            publisher_entity_id: PUBLISHER_GROUP_ENTITY_ID,
        };
        let canonical = emit_canonical_native(&member_change_view(None), &ctx);
        assert_eq!(canonical, GOLDEN_MEMBER_TOPIC);
        assert_eq!(
            canonical,
            live_member_submsg(None),
            "oracle must reproduce the live TOPIC-scope member DATA; with group_sn = None the \
             derived publisher_entity_id is absent, so no PID_GROUP_* is emitted"
        );
    }

    // ---- Form B: ECS close marker, GROUP scope ------------------------------

    #[test]
    fn ecs_close_golden_still_matches_live() {
        assert_eq!(
            live_ecs_submsg(),
            GOLDEN_ECS_GROUP,
            "the live ECS close marker drifted from the pinned golden"
        );
    }

    #[test]
    fn ecs_close_oracle_reproduces_byte_for_byte() {
        let ctx = WriterEmitCtx {
            reader_entity_id: READER_EID,
            writer_entity_id: WRITER_EID,
            publisher_entity_id: PUBLISHER_GROUP_ENTITY_ID,
        };
        let canonical = emit_canonical_native(&ecs_change_view(), &ctx);
        assert_eq!(canonical, GOLDEN_ECS_GROUP);
        assert_eq!(
            canonical,
            live_ecs_submsg(),
            "oracle must reproduce the live ECS close marker (flags 0x03, no payload, \
             PID_COHERENT_SET + PID_GROUP_COHERENT_SET + PID_GROUP_ENTITY_ID)"
        );
    }

    // ---- Slice 3 fixtures (dispose / unregister KEY-only DATA) --------------

    /// Fresh writer SN a dispose / unregister consumes. Note these SNs are NEVER
    /// cached in the history cache today (`runtime.rs:1186-1240` inserts nothing)
    /// -- a repair-side hole for a later phase, NOT this oracle's concern: it
    /// only mirrors the EMISSION bytes.
    const DISPOSE_SEQ: u64 = 7;
    /// Raw serialized @key fields fed to the LIVE builder (no encap header; the
    /// builder prepends D_CDR2_LE, counts the padding in the options and appends
    /// it, `encapsulate_serialized_payload`).
    /// Two bytes so the tail padding is exercised (2 key bytes -> 2 pad bytes).
    const DISPOSE_SERIALIZED_KEY: [u8; 2] = [0x0A, 0x0B];
    /// The VERBATIM K-payload the JOURNAL would carry and the oracle receives:
    /// encap D_CDR2_LE (`0x0009`) with options `00 02` (the two padding octets
    /// counted, DDS-XTypes 1.3 7.6.3.1.2) + serialized_key (`0a 0b`) + 4-octet
    /// alignment padding (`00 00`). This is what the live builder assembles
    /// internally (`encapsulate_serialized_payload`); the oracle appends it
    /// byte-for-byte.
    const DISPOSE_KEY_PAYLOAD: [u8; 8] = [0x00, 0x09, 0x00, 0x02, 0x0A, 0x0B, 0x00, 0x00];

    /// Golden dispose (Disposed) KEY-only DATA. Recorded from the live builder
    /// and guarded by `dispose_disposed_golden_still_matches_live`.
    ///
    /// Layout (84 bytes):
    ///   15 0b 50 00                 DATA id, flags(LE|Q|K, D=0), octetsToNext=80
    ///   00 00 / 10 00               extraFlags / octetsToInlineQos=16
    ///   00 00 01 02 / 00 00 01 03   reader / writer entityId
    ///   00 00 00 00 07 00 00 00     writerSN (high=0, low=7)
    ///   05 00 10 00 0c 00 00 00     PID_TOPIC_NAME, len=16, strlen=12
    ///   6b 65 79 65 64 2f 74 6f 70 69 63 00   "keyed/topic\0"
    ///   70 00 10 00 / 42 x16        PID_KEY_HASH (before PID_STATUS_INFO)
    ///   71 00 04 00 00 00 00 01     PID_STATUS_INFO, len=4, value BIG-ENDIAN = 1
    ///   01 00 00 00                 PID_SENTINEL
    ///   00 09 00 02 0a 0b 00 00     K-payload: D_CDR2_LE encap (2 padding
    ///                               octets counted) + key + pad
    #[rustfmt::skip]
    const GOLDEN_DISPOSE_DISPOSED: [u8; 84] = [
        0x15, 0x0b, 0x50, 0x00,
        0x00, 0x00,
        0x10, 0x00,
        0x00, 0x00, 0x01, 0x02,
        0x00, 0x00, 0x01, 0x03,
        0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00,
        0x05, 0x00, 0x10, 0x00, 0x0c, 0x00, 0x00, 0x00,
        0x6b, 0x65, 0x79, 0x65, 0x64, 0x2f, 0x74, 0x6f, 0x70, 0x69, 0x63, 0x00,
        0x70, 0x00, 0x10, 0x00,
        0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
        0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
        0x71, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x01, 0x00, 0x00, 0x00,
        0x00, 0x09, 0x00, 0x02, 0x0a, 0x0b, 0x00, 0x00,
    ];

    /// Golden unregister (Unregistered) KEY-only DATA. Identical to the Disposed
    /// golden except PID_STATUS_INFO octet 3 is `0x02`, proving the big-endian
    /// StatusInfo_t layout. Guarded by
    /// `dispose_unregistered_golden_still_matches_live`.
    #[rustfmt::skip]
    const GOLDEN_DISPOSE_UNREGISTERED: [u8; 84] = [
        0x15, 0x0b, 0x50, 0x00,
        0x00, 0x00,
        0x10, 0x00,
        0x00, 0x00, 0x01, 0x02,
        0x00, 0x00, 0x01, 0x03,
        0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00,
        0x05, 0x00, 0x10, 0x00, 0x0c, 0x00, 0x00, 0x00,
        0x6b, 0x65, 0x79, 0x65, 0x64, 0x2f, 0x74, 0x6f, 0x70, 0x69, 0x63, 0x00,
        0x70, 0x00, 0x10, 0x00,
        0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
        0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
        0x71, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x02,
        0x01, 0x00, 0x00, 0x00,
        0x00, 0x09, 0x00, 0x02, 0x0a, 0x0b, 0x00, 0x00,
    ];

    /// Golden combined (DisposedUnregistered) KEY-only DATA. PID_STATUS_INFO
    /// octet 3 is `0x03`. Guarded by
    /// `dispose_disposed_unregistered_golden_still_matches_live`.
    #[rustfmt::skip]
    const GOLDEN_DISPOSE_DISPOSED_UNREGISTERED: [u8; 84] = [
        0x15, 0x0b, 0x50, 0x00,
        0x00, 0x00,
        0x10, 0x00,
        0x00, 0x00, 0x01, 0x02,
        0x00, 0x00, 0x01, 0x03,
        0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00,
        0x05, 0x00, 0x10, 0x00, 0x0c, 0x00, 0x00, 0x00,
        0x6b, 0x65, 0x79, 0x65, 0x64, 0x2f, 0x74, 0x6f, 0x70, 0x69, 0x63, 0x00,
        0x70, 0x00, 0x10, 0x00,
        0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
        0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
        0x71, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x03,
        0x01, 0x00, 0x00, 0x00,
        0x00, 0x09, 0x00, 0x02, 0x0a, 0x0b, 0x00, 0x00,
    ];

    /// Drive the live dispose builder and return ONLY the DATA submessage
    /// (RTPS header + INFO_TS stripped). Mirrors the runtime send path
    /// (`runtime.rs:1219-1226`): `build_dispose_packet_with_context(ctx, topic,
    /// seq, &key_hash, &serialized_key, status)`.
    fn live_dispose_submsg(status: StatusInfoKind) -> Vec<u8> {
        let ctx = RtpsEndpointContext {
            guid_prefix: GUID_PREFIX,
            reader_entity_id: READER_EID,
            writer_entity_id: WRITER_EID,
            // An @appendable writer: its K payload is D_CDR2_LE, as pinned.
            encapsulation_kind: 0x0009,
            publisher_entity_id: PUBLISHER_GROUP_ENTITY_ID,
        };
        let live = build_dispose_packet_with_context(
            &ctx,
            TOPIC,
            DISPOSE_SEQ,
            &KEY_HASH,
            &DISPOSE_SERIALIZED_KEY,
            status,
        );
        assert!(live.len() > DATA_SUBMSG_OFFSET);
        live[DATA_SUBMSG_OFFSET..].to_vec()
    }

    /// Same as `live_dispose_submsg` but tagged with coherent-set PIDs, via
    /// `build_dispose_packet_with_context_coherent_ts` (the function
    /// `build_dispose_packet_with_context` / `_ts` delegate to with `None,
    /// None`). The timestamp is arbitrary: the DATA submessage comparison
    /// strips the leading RTPS header + INFO_TS.
    fn live_dispose_submsg_coherent(
        status: StatusInfoKind,
        coherent_sn: u64,
        group_sn: Option<u64>,
    ) -> Vec<u8> {
        let ctx = RtpsEndpointContext {
            guid_prefix: GUID_PREFIX,
            reader_entity_id: READER_EID,
            writer_entity_id: WRITER_EID,
            // An @appendable writer: its K payload is D_CDR2_LE, as pinned.
            encapsulation_kind: 0x0009,
            publisher_entity_id: PUBLISHER_GROUP_ENTITY_ID,
        };
        let live = build_dispose_packet_with_context_coherent_ts(
            &ctx,
            TOPIC,
            DISPOSE_SEQ,
            &KEY_HASH,
            &DISPOSE_SERIALIZED_KEY,
            status,
            CdrVersion::Xcdr2,
            (0x1122_3344, 0x5566_7788),
            Some(coherent_sn),
            group_sn,
            None,
            false,
        );
        assert!(live.len() > DATA_SUBMSG_OFFSET);
        live[DATA_SUBMSG_OFFSET..].to_vec()
    }

    /// Journaled-change descriptor for a dispose / unregister. `serialized_payload`
    /// is the VERBATIM K-payload (encap + key + pad); `key_hash` is mandatory;
    /// no coherent metadata (a dispose is not part of a coherent set).
    fn dispose_change_view(status: StatusInfoKind) -> CanonicalChangeView<'static> {
        CanonicalChangeView {
            form: EmissionForm::Dispose {
                status,
                key_hash: KEY_HASH,
                coherent_sn: None,
                group_sn: None,
            },
            sequence: DISPOSE_SEQ,
            serialized_payload: &DISPOSE_KEY_PAYLOAD,
            topic: TOPIC,
            key_hash: Some(KEY_HASH),
            coherent_sn: None,
            group_sn: None,
            source_timestamp: (0x1122_3344, 0x5566_7788),
        }
    }

    /// Same as `dispose_change_view` but tagged as emitted inside an open
    /// coherent set (TOPIC/INSTANCE scope: `coherent_sn` only) or, when
    /// `group_sn` is `Some`, GROUP scope.
    fn dispose_change_view_coherent(
        status: StatusInfoKind,
        coherent_sn: u64,
        group_sn: Option<u64>,
    ) -> CanonicalChangeView<'static> {
        CanonicalChangeView {
            form: EmissionForm::Dispose {
                status,
                key_hash: KEY_HASH,
                coherent_sn: Some(coherent_sn),
                group_sn,
            },
            sequence: DISPOSE_SEQ,
            serialized_payload: &DISPOSE_KEY_PAYLOAD,
            topic: TOPIC,
            key_hash: Some(KEY_HASH),
            coherent_sn: Some(coherent_sn),
            group_sn,
            source_timestamp: (0x1122_3344, 0x5566_7788),
        }
    }

    // ---- Slice 3: dispose (Disposed) ---------------------------------------

    #[test]
    fn dispose_disposed_golden_still_matches_live() {
        assert_eq!(
            live_dispose_submsg(StatusInfoKind::Disposed),
            GOLDEN_DISPOSE_DISPOSED,
            "the live dispose (Disposed) DATA drifted from the pinned golden"
        );
    }

    #[test]
    fn dispose_disposed_oracle_reproduces_byte_for_byte() {
        let ctx = WriterEmitCtx {
            reader_entity_id: READER_EID,
            writer_entity_id: WRITER_EID,
            publisher_entity_id: PUBLISHER_GROUP_ENTITY_ID,
        };
        let canonical = emit_canonical_native(&dispose_change_view(StatusInfoKind::Disposed), &ctx);
        assert_eq!(canonical, GOLDEN_DISPOSE_DISPOSED);
        assert_eq!(
            canonical,
            live_dispose_submsg(StatusInfoKind::Disposed),
            "oracle must reproduce the live Disposed KEY-only DATA (flags 0x0B, \
             PID_STATUS_INFO big-endian octet-3 = 0x01, verbatim K-payload)"
        );
    }

    // ---- Slice 3: unregister (Unregistered) --------------------------------

    #[test]
    fn dispose_unregistered_golden_still_matches_live() {
        assert_eq!(
            live_dispose_submsg(StatusInfoKind::Unregistered),
            GOLDEN_DISPOSE_UNREGISTERED,
            "the live unregister (Unregistered) DATA drifted from the pinned golden"
        );
    }

    #[test]
    fn dispose_unregistered_oracle_reproduces_byte_for_byte() {
        let ctx = WriterEmitCtx {
            reader_entity_id: READER_EID,
            writer_entity_id: WRITER_EID,
            publisher_entity_id: PUBLISHER_GROUP_ENTITY_ID,
        };
        let canonical =
            emit_canonical_native(&dispose_change_view(StatusInfoKind::Unregistered), &ctx);
        assert_eq!(canonical, GOLDEN_DISPOSE_UNREGISTERED);
        assert_eq!(
            canonical,
            live_dispose_submsg(StatusInfoKind::Unregistered),
            "oracle must reproduce the live Unregistered KEY-only DATA; only \
             PID_STATUS_INFO octet 3 changes (0x02)"
        );
    }

    // ---- Slice 3: combined (DisposedUnregistered) --------------------------

    #[test]
    fn dispose_disposed_unregistered_golden_still_matches_live() {
        assert_eq!(
            live_dispose_submsg(StatusInfoKind::DisposedUnregistered),
            GOLDEN_DISPOSE_DISPOSED_UNREGISTERED,
            "the live combined (DisposedUnregistered) DATA drifted from the pinned golden"
        );
    }

    #[test]
    fn dispose_disposed_unregistered_oracle_reproduces_byte_for_byte() {
        let ctx = WriterEmitCtx {
            reader_entity_id: READER_EID,
            writer_entity_id: WRITER_EID,
            publisher_entity_id: PUBLISHER_GROUP_ENTITY_ID,
        };
        let canonical = emit_canonical_native(
            &dispose_change_view(StatusInfoKind::DisposedUnregistered),
            &ctx,
        );
        assert_eq!(canonical, GOLDEN_DISPOSE_DISPOSED_UNREGISTERED);
        assert_eq!(
            canonical,
            live_dispose_submsg(StatusInfoKind::DisposedUnregistered),
            "oracle must reproduce the live combined KEY-only DATA; \
             PID_STATUS_INFO octet 3 = 0x03"
        );
    }

    // ---- Slice 3+: dispose / unregister tagged inside a coherent set --------
    //
    // RTPS v2.5 SS8.7.5/SS8.7.6: a dispose/unregister emitted while the
    // writer's publisher has an open coherent set is a CacheChange of that
    // set like any other, and must carry PID_COHERENT_SET (and, under GROUP
    // scope, PID_GROUP_COHERENT_SET_HDDS + PID_GROUP_ENTITY_ID) or it ends
    // the set for a spec-strict reader. These pin the golden PID layout
    // (coherent_sn.rs / helpers.rs) and prove the oracle reproduces it.

    #[test]
    fn dispose_disposed_topic_scope_coherent_oracle_reproduces_byte_for_byte() {
        let ctx = WriterEmitCtx {
            reader_entity_id: READER_EID,
            writer_entity_id: WRITER_EID,
            publisher_entity_id: PUBLISHER_GROUP_ENTITY_ID,
        };
        let canonical = emit_canonical_native(
            &dispose_change_view_coherent(StatusInfoKind::Disposed, COHERENT_SN, None),
            &ctx,
        );
        assert_eq!(
            canonical,
            live_dispose_submsg_coherent(StatusInfoKind::Disposed, COHERENT_SN, None),
            "oracle must reproduce the live TOPIC/INSTANCE-scope coherent dispose: \
             PID_TOPIC_NAME, PID_COHERENT_SET, PID_KEY_HASH, PID_STATUS_INFO, PID_SENTINEL"
        );
        // PID_COHERENT_SET (0x0056) must appear right after PID_TOPIC_NAME
        // and before PID_KEY_HASH (0x0070): decode by hand, not via our own
        // extractor.
        //
        // Offset arithmetic (RTPS v2.5 SS9.4.2.11 / SS9.4.5.3.3), independent of
        // the oracle/builder code: DATA submessage header(4) + fixed body
        // (extraFlags(2) + octetsToInlineQos(2) + entityIds(8) + writerSN(8)
        // = 20) = 24 octets before inline QoS starts. PID_TOPIC_NAME there is
        // pid(2) + len(2) + [stringLength u32(4) + "keyed/topic\0"(12 bytes,
        // already 4-aligned, no padding)] = 4 + 16 = 20 octets. So
        // PID_COHERENT_SET starts at 24 + 20 = 44.
        let topic_string_len = TOPIC.len() + 1; // + NUL
        let topic_param_len = 4 + topic_string_len; // PID_TOPIC_NAME value = stringLength(4) + string
        let topic_aligned_param_len = (topic_param_len + 3) & !3;
        let topic_pid_total = 4 + topic_aligned_param_len; // + pid(2) + len(2) header
        let coherent_set_pid_offset = 24 + topic_pid_total;
        assert_eq!(
            &canonical[coherent_set_pid_offset..coherent_set_pid_offset + 2],
            &0x0056u16.to_le_bytes(),
            "PID_COHERENT_SET must immediately follow PID_TOPIC_NAME"
        );
        let (sn_high, sn_low) = split_sequence_number(COHERENT_SN);
        assert_eq!(
            &canonical[coherent_set_pid_offset + 4..coherent_set_pid_offset + 8],
            &sn_high.to_le_bytes(),
            "PID_COHERENT_SET high word must be the set's first SN"
        );
        assert_eq!(
            &canonical[coherent_set_pid_offset + 8..coherent_set_pid_offset + 12],
            &sn_low.to_le_bytes(),
            "PID_COHERENT_SET low word must be the set's first SN"
        );
        // PID_KEY_HASH (0x0070) follows PID_COHERENT_SET(12) directly in the
        // TOPIC/INSTANCE scope (no group PIDs).
        let key_hash_offset = coherent_set_pid_offset + 12;
        assert_eq!(
            &canonical[key_hash_offset..key_hash_offset + 2],
            &0x0070u16.to_le_bytes(),
            "PID_KEY_HASH must follow PID_COHERENT_SET under TOPIC/INSTANCE scope"
        );
    }

    #[test]
    fn dispose_group_scope_coherent_oracle_reproduces_byte_for_byte() {
        let ctx = WriterEmitCtx {
            reader_entity_id: READER_EID,
            writer_entity_id: WRITER_EID,
            publisher_entity_id: PUBLISHER_GROUP_ENTITY_ID,
        };
        let canonical = emit_canonical_native(
            &dispose_change_view_coherent(StatusInfoKind::Disposed, COHERENT_SN, Some(GROUP_SN)),
            &ctx,
        );
        assert_eq!(
            canonical,
            live_dispose_submsg_coherent(StatusInfoKind::Disposed, COHERENT_SN, Some(GROUP_SN)),
            "oracle must reproduce the live GROUP-scope coherent dispose: \
             PID_TOPIC_NAME, PID_COHERENT_SET, PID_GROUP_COHERENT_SET_HDDS, \
             PID_GROUP_ENTITY_ID, PID_KEY_HASH, PID_STATUS_INFO, PID_SENTINEL"
        );
        // 0x8030 (PID_GROUP_COHERENT_SET_HDDS) and PID_GROUP_ENTITY_ID
        // (0x0053 = [0x00, 0x01]) must both be present, decoded by hand.
        // Same offset arithmetic as the TOPIC-scope test above, plus
        // PID_COHERENT_SET's own 12 octets.
        let topic_string_len = TOPIC.len() + 1;
        let topic_param_len = 4 + topic_string_len;
        let topic_aligned_param_len = (topic_param_len + 3) & !3;
        let topic_pid_total = 4 + topic_aligned_param_len;
        let group_coherent_set_offset = 24 + topic_pid_total + 12; // + PID_COHERENT_SET(12)
        assert_eq!(
            &canonical[group_coherent_set_offset..group_coherent_set_offset + 2],
            &0x8030u16.to_le_bytes(),
            "PID_GROUP_COHERENT_SET_HDDS must follow PID_COHERENT_SET"
        );
        let (gsn_high, gsn_low) = split_sequence_number(GROUP_SN);
        assert_eq!(
            &canonical[group_coherent_set_offset + 4..group_coherent_set_offset + 8],
            &gsn_high.to_le_bytes()
        );
        assert_eq!(
            &canonical[group_coherent_set_offset + 8..group_coherent_set_offset + 12],
            &gsn_low.to_le_bytes()
        );
        let group_entity_id_offset = group_coherent_set_offset + 12;
        assert_eq!(
            &canonical[group_entity_id_offset..group_entity_id_offset + 2],
            &0x0053u16.to_le_bytes(),
            "PID_GROUP_ENTITY_ID must follow PID_GROUP_COHERENT_SET_HDDS"
        );
        assert_eq!(
            &canonical[group_entity_id_offset + 4..group_entity_id_offset + 8],
            &PUBLISHER_GROUP_ENTITY_ID,
            "PID_GROUP_ENTITY_ID payload must be the pinned Publisher Group EntityId"
        );
        // PID_KEY_HASH (0x0070) must follow PID_GROUP_ENTITY_ID(8 bytes).
        let key_hash_offset = group_entity_id_offset + 8;
        assert_eq!(
            &canonical[key_hash_offset..key_hash_offset + 2],
            &0x0070u16.to_le_bytes(),
            "PID_KEY_HASH must follow the coherent/group PIDs, before PID_STATUS_INFO"
        );
    }

    #[test]
    fn dispose_outside_coherent_set_is_unchanged() {
        // `build_dispose_packet_with_context` (what `live_dispose_submsg`
        // drives) now delegates through `build_dispose_packet_with_context_ts`
        // to `_coherent_ts` with `coherent_sn = None, group_sn = None`. Calling
        // that coherent-aware entry point directly with `None, None` must
        // still match the pinned pre-existing golden byte-for-byte: adding
        // the coherent variant must not perturb the non-coherent path at all.
        let ctx = RtpsEndpointContext {
            guid_prefix: GUID_PREFIX,
            reader_entity_id: READER_EID,
            writer_entity_id: WRITER_EID,
            encapsulation_kind: 0x0009,
            publisher_entity_id: PUBLISHER_GROUP_ENTITY_ID,
        };
        let direct = build_dispose_packet_with_context_coherent_ts(
            &ctx,
            TOPIC,
            DISPOSE_SEQ,
            &KEY_HASH,
            &DISPOSE_SERIALIZED_KEY,
            StatusInfoKind::Disposed,
            CdrVersion::Xcdr2,
            (0x1122_3344, 0x5566_7788),
            None,
            None,
            None,
            false,
        );
        assert!(direct.len() > DATA_SUBMSG_OFFSET);
        assert_eq!(
            direct[DATA_SUBMSG_OFFSET..].to_vec(),
            GOLDEN_DISPOSE_DISPOSED,
            "coherent_sn=None, group_sn=None through the coherent entry point must \
             reproduce the pre-existing non-coherent golden bytes exactly"
        );
        assert_eq!(
            live_dispose_submsg(StatusInfoKind::Disposed),
            GOLDEN_DISPOSE_DISPOSED
        );
    }

    /// Drive the live builder with the fixed inputs and return ONLY the DATA
    /// submessage (header + INFO_TS stripped). The plain keyed self/Native path
    /// passes `coherent_sn = None`, `group_sn = None` and a `Some(key_hash)`
    /// for a keyed type (`runtime.rs:533`, `runtime.rs:774-785`).
    fn live_data_submsg() -> Vec<u8> {
        let ctx = RtpsEndpointContext {
            guid_prefix: GUID_PREFIX,
            reader_entity_id: READER_EID,
            writer_entity_id: WRITER_EID,
            encapsulation_kind: 0x0007, // PLAIN_CDR2_LE
            publisher_entity_id: PUBLISHER_GROUP_ENTITY_ID,
        };
        // Body only (no encap header) -- the live builder prepends the encap
        // header itself. The verbatim journal payload used by the oracle
        // therefore = [encap header] ++ this body.
        let body = [0x01, 0x02, 0x03, 0x04];
        let live = build_data_packet_with_context_full_keyed(
            &ctx,
            TOPIC,
            SEQ,
            &body,
            CdrVersion::Xcdr2,
            None, // coherent_sn: plain (non-coherent)
            None, // group_sn: plain (non-coherent)
            Some(&KEY_HASH),
        );
        assert!(
            live.len() > DATA_SUBMSG_OFFSET,
            "live packet too short to contain a DATA submessage"
        );
        live[DATA_SUBMSG_OFFSET..].to_vec()
    }

    /// Anchor guard: the pinned golden is still exactly what the live builder
    /// emits for the DATA submessage. If the live wire layout changes, this
    /// fails and forces the golden (and the oracle) to be re-examined.
    #[test]
    fn golden_still_matches_live() {
        assert_eq!(
            live_data_submsg(),
            GOLDEN_DATA_SUBMSG,
            "the live DATA builder no longer emits the pinned golden bytes; \
             the wire layout drifted and the Phase-0 oracle must be revisited"
        );
    }

    /// The Phase-0 proof: a pure, read-only reconstruction reproduces the live
    /// DATA submessage byte-for-byte from journaled inputs alone.
    #[test]
    fn oracle_reproduces_live_data_submessage_byte_for_byte() {
        let ctx = WriterEmitCtx {
            reader_entity_id: READER_EID,
            writer_entity_id: WRITER_EID,
            publisher_entity_id: PUBLISHER_GROUP_ENTITY_ID,
        };
        let canonical = emit_canonical_native(&change_view(), &ctx);

        assert_eq!(
            canonical, GOLDEN_DATA_SUBMSG,
            "emit_canonical_native must reproduce the pinned golden DATA submessage"
        );
        // And, transitively, the actual live bytes for this build.
        assert_eq!(
            canonical,
            live_data_submsg(),
            "emit_canonical_native must reproduce the live DATA submessage bytes \
             for a plain keyed sample, from journaled inputs with no clock/lock/cache"
        );
    }

    // ---- Slice 4 fixtures (DATA_FRAG large-payload fragmentation) -----------

    /// Nominal fragment size for this slice. Chosen larger than
    /// `DEFAULT_FRAGMENT_SIZE` (1024) purely to keep the fixture to 3 fragments
    /// (a 1024-byte split of a >8KB payload would need ~9 golden headers); the
    /// split logic is identical at any size. It is passed explicitly to prove
    /// `fragment_size` is a reproducible input, not a hidden per-dest MTU.
    const DATAFRAG_SIZE: usize = 4096;
    /// Writer SN the fragmented sample consumes.
    const DATAFRAG_SEQ: u64 = 11;
    /// Raw serialized body length (no encap header). 9000 + the 4-byte encap
    /// header = 9004 total, which EXCEEDS DEFAULT_MAX_UNFRAGMENTED_SIZE (8192)
    /// so the live splitter fragments, and 9004 = 4096 + 4096 + 812 yields a
    /// SHORT last fragment (the off-by-one the tail exercises).
    const DATAFRAG_BODY_LEN: usize = 9000;

    /// Deterministic raw body (no encap header) fed to the LIVE splitter.
    fn datafrag_body() -> Vec<u8> {
        (0..DATAFRAG_BODY_LEN).map(|i| (i % 251) as u8).collect()
    }

    /// The VERBATIM encapsulated blob the JOURNAL would carry and the oracle
    /// receives: PLAIN_CDR2_LE encap header (`00 07 00 00`) + raw body. This is
    /// exactly what the live splitter assembles internally as `encapsulated`
    /// before splitting (`packet.rs:935-941`); the oracle splits it directly.
    fn datafrag_encapsulated() -> Vec<u8> {
        let mut v = Vec::with_capacity(4 + DATAFRAG_BODY_LEN);
        v.extend_from_slice(&[0x00, 0x07, 0x00, 0x00]); // PLAIN_CDR2_LE
        v.extend_from_slice(&datafrag_body());
        v
    }

    /// Drive the live splitter and return each packet's DATA_FRAG submessage
    /// (RTPS header + INFO_TS stripped), mirroring the runtime send path
    /// (`runtime.rs:656-662`): `build_data_frag_packets(ctx, seq, body,
    /// DATAFRAG_SIZE, Xcdr2)`.
    fn live_datafrag_submsgs() -> Vec<Vec<u8>> {
        let ctx = RtpsEndpointContext {
            guid_prefix: GUID_PREFIX,
            reader_entity_id: READER_EID,
            writer_entity_id: WRITER_EID,
            encapsulation_kind: 0x0007, // PLAIN_CDR2_LE
            publisher_entity_id: PUBLISHER_GROUP_ENTITY_ID,
        };
        let body = datafrag_body();
        let packets =
            build_data_frag_packets(&ctx, DATAFRAG_SEQ, &body, DATAFRAG_SIZE, CdrVersion::Xcdr2);
        packets
            .into_iter()
            .map(|p| {
                assert!(p.len() > DATA_SUBMSG_OFFSET);
                p[DATA_SUBMSG_OFFSET..].to_vec()
            })
            .collect()
    }

    /// Journaled-change descriptor for the fragmented sample. `serialized_payload`
    /// is the VERBATIM encapsulated blob (encap + body); `form` / `topic` /
    /// `key_hash` are present but IGNORED by the frag branch (the DATA_FRAG wire
    /// carries no inline QoS -- see `emit_canonical_native_frags`).
    fn datafrag_change_view(encapsulated: &[u8]) -> CanonicalChangeView<'_> {
        CanonicalChangeView {
            form: EmissionForm::PlainKeyed,
            sequence: DATAFRAG_SEQ,
            serialized_payload: encapsulated,
            topic: TOPIC,
            key_hash: Some(KEY_HASH),
            coherent_sn: None,
            group_sn: None,
            source_timestamp: (0x1122_3344, 0x5566_7788),
        }
    }

    /// Fragment boundaries into the 9004-byte encapsulated blob:
    /// `[0..4096]`, `[4096..8192]`, `[8192..9004]` (last = 812-byte short tail).
    const DATAFRAG_BOUNDS: [(usize, usize); 3] = [(0, 4096), (4096, 8192), (8192, 9004)];

    // The 36-byte DATA_FRAG headers (submsg header + 32-byte fixed body) of each
    // fragment, recorded from the live splitter (build_data_frag_packets ->
    // encode_data_frag) and guarded by `datafrag_golden_still_matches_live`. The
    // fragment payloads are verbatim slices of the encapsulated blob (checked by
    // reconstruction), so only the structural headers are pinned as literals.
    //
    // Header 1 (frag 1 of 3):
    //   16 01 20 10                 DATA_FRAG id, flags(E only), octetsToNext=4128
    //   00 00 / 1c 00               extraFlags / octetsToInlineQos=28
    //   00 00 01 02 / 00 00 01 03   reader / writer entityId
    //   00 00 00 00 0b 00 00 00     writerSN (high=0, low=11)
    //   01 00 00 00                 fragmentStartingNum = 1
    //   01 00                       fragmentsInSubmessage = 1
    //   00 10                       fragmentSize = 4096 (nominal)
    //   2c 23 00 00                 sampleSize = 9004 (total encapsulated)
    #[rustfmt::skip]
    const GOLDEN_DATAFRAG_HDR_1: [u8; 36] = [
        0x16, 0x01, 0x20, 0x10,
        0x00, 0x00, 0x1c, 0x00,
        0x00, 0x00, 0x01, 0x02,
        0x00, 0x00, 0x01, 0x03,
        0x00, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00,
        0x01, 0x00,
        0x00, 0x10,
        0x2c, 0x23, 0x00, 0x00,
    ];

    /// Header 2: identical to header 1 except fragmentStartingNum = 2.
    #[rustfmt::skip]
    const GOLDEN_DATAFRAG_HDR_2: [u8; 36] = [
        0x16, 0x01, 0x20, 0x10,
        0x00, 0x00, 0x1c, 0x00,
        0x00, 0x00, 0x01, 0x02,
        0x00, 0x00, 0x01, 0x03,
        0x00, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x00, 0x00,
        0x01, 0x00,
        0x00, 0x10,
        0x2c, 0x23, 0x00, 0x00,
    ];

    /// Header LAST (frag 3, the SHORT tail): octetsToNext shrinks to 0x034c=844
    /// (32 + 812) and fragmentStartingNum = 3, but fragmentSize STAYS 0x1000=4096
    /// and sampleSize STAYS 9004 -- the off-by-one proof: only the submessage
    /// length reflects the short tail, the nominal fragment-size field does not.
    #[rustfmt::skip]
    const GOLDEN_DATAFRAG_HDR_LAST: [u8; 36] = [
        0x16, 0x01, 0x4c, 0x03,
        0x00, 0x00, 0x1c, 0x00,
        0x00, 0x00, 0x01, 0x02,
        0x00, 0x00, 0x01, 0x03,
        0x00, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00,
        0x03, 0x00, 0x00, 0x00,
        0x01, 0x00,
        0x00, 0x10,
        0x2c, 0x23, 0x00, 0x00,
    ];

    // ---- Slice 4: golden guard (live splitter still emits the pinned bytes) --

    #[test]
    fn datafrag_golden_still_matches_live() {
        let live = live_datafrag_submsgs();
        assert_eq!(live.len(), 3, "fixture must split into exactly 3 fragments");

        let encapsulated = datafrag_encapsulated();
        let goldens: [&[u8]; 3] = [
            &GOLDEN_DATAFRAG_HDR_1,
            &GOLDEN_DATAFRAG_HDR_2,
            &GOLDEN_DATAFRAG_HDR_LAST,
        ];
        for (i, (&(start, end), golden_hdr)) in
            DATAFRAG_BOUNDS.iter().zip(goldens.iter()).enumerate()
        {
            // The 36-byte DATA_FRAG header is pinned as a literal.
            assert_eq!(
                &live[i][..36],
                *golden_hdr,
                "fragment {i} DATA_FRAG header drifted from the pinned golden"
            );
            // The fragment payload is a verbatim slice of the encapsulated blob.
            assert_eq!(
                &live[i][36..],
                &encapsulated[start..end],
                "fragment {i} payload is not the expected slice of the encapsulated blob"
            );
        }
    }

    // ---- Slice 4: the Phase-0 proof (oracle reproduces each fragment) --------

    #[test]
    fn datafrag_oracle_reproduces_each_submessage_byte_for_byte() {
        let ctx = WriterEmitCtx {
            reader_entity_id: READER_EID,
            writer_entity_id: WRITER_EID,
            publisher_entity_id: PUBLISHER_GROUP_ENTITY_ID,
        };
        let encapsulated = datafrag_encapsulated();
        let oracle = emit_canonical_native_frags(
            &datafrag_change_view(&encapsulated),
            &ctx,
            u16::try_from(DATAFRAG_SIZE).expect("DATAFRAG_SIZE fits the u16 fragmentSize"),
        );
        let live = live_datafrag_submsgs();

        assert_eq!(
            oracle.len(),
            3,
            "oracle must derive 3 fragments from the payload length"
        );
        assert_eq!(oracle.len(), live.len());
        for i in 0..oracle.len() {
            assert_eq!(
                oracle[i], live[i],
                "oracle DATA_FRAG {i} must reproduce the live fragment byte-for-byte"
            );
        }

        // Reassembly completeness: the concatenated fragment payloads equal the
        // full encapsulated blob (no bytes dropped or duplicated at boundaries).
        let mut reassembled = Vec::new();
        for f in &oracle {
            reassembled.extend_from_slice(&f[36..]);
        }
        assert_eq!(
            reassembled, encapsulated,
            "fragment payloads must reassemble the blob"
        );

        // SHORT last-fragment (off-by-one) proof: the last fragment's submessage
        // shrinks to a 812-byte tail, yet its fragmentSize field stays NOMINAL
        // (4096) and its sampleSize stays the total (9004). fragmentSize sits at
        // submessage offset 30..32, sampleSize at 32..36 (4-byte submsg header +
        // 26/28-byte body offsets).
        let last = &oracle[2];
        assert_eq!(
            last.len(),
            4 + 32 + 812,
            "last fragment must be the short tail"
        );
        assert_eq!(
            last.len() - 36,
            812,
            "last fragment payload is the 812-byte tail"
        );
        assert_eq!(
            u16::from_le_bytes([last[30], last[31]]),
            DATAFRAG_SIZE as u16,
            "fragmentSize field must stay NOMINAL (4096) on the short last fragment"
        );
        assert_eq!(
            u32::from_le_bytes([last[32], last[33], last[34], last[35]]),
            encapsulated.len() as u32,
            "sampleSize must stay the total encapsulated size (9004) on every fragment"
        );
    }

    // ---- Slice 4: derived-not-stored (small payload => single DATA) ----------

    #[test]
    fn datafrag_small_payload_is_single_data_submessage() {
        let ctx = WriterEmitCtx {
            reader_entity_id: READER_EID,
            writer_entity_id: WRITER_EID,
            publisher_entity_id: PUBLISHER_GROUP_ENTITY_ID,
        };
        // The plain keyed fixture's 8-byte payload is far under the 8192-byte
        // threshold, so fragmentation is DERIVED to be off: the sequence output
        // has exactly one entry, byte-identical to the single DATA submessage
        // `emit_canonical_native` returns. This proves the split is a pure
        // function of payload length -- no `EmissionForm::Fragmented` needed.
        let frags = emit_canonical_native_frags(
            &change_view(),
            &ctx,
            u16::try_from(DEFAULT_FRAGMENT_SIZE).expect("DEFAULT_FRAGMENT_SIZE fits the u16"),
        );
        assert_eq!(frags.len(), 1, "a sub-threshold payload must not fragment");
        assert_eq!(
            frags[0],
            emit_canonical_native(&change_view(), &ctx),
            "the len==1 non-fragmented case must equal the single-DATA oracle output"
        );
        assert_eq!(frags[0], GOLDEN_DATA_SUBMSG);
    }
}
