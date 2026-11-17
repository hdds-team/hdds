// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! XTypes v1.3 type compatibility and assignability checking.
//!
//!
//! Implements DDS-XTypes type matching rules:
//! - Type name normalization (IDL: prefix handling, ROS2 namespace conventions)
//! - Structural type assignability for FINAL, APPENDABLE, and MUTABLE extensibility
//! - Key field compatibility validation
//! - TypeConsistencyEnforcement policy application (XTypes v1.3 sec. 7.6.3.4)
//!
//! # Type Assignability Rules
//!
//! - **FINAL**: Requires exact structural equivalence (EquivalenceHash match)
//! - **APPENDABLE**: Reader fields must prefix-match writer fields
//! - **MUTABLE**: Member ID-based matching with optional field handling
//!
//! # TypeConsistencyEnforcement Policy
//!
//! The effective policy is sourced from the local endpoint's QoS
//! (`MatchEntry.qos.type_consistency`) and falls back to the XTypes spec
//! default (ALLOW_TYPE_COERCION, ignore_sequence_bounds=true,
//! ignore_string_bounds=true) when no local policy is set or when the call
//! site does not have policy context. All policy-sensitive call paths accept
//! an `Option<&TypeConsistencyEnforcement>` parameter; `None` is treated as
//! the spec default.

use crate::protocol::discovery::types::TypeConsistencyEnforcement;
use crate::xtypes::{
    CompleteEnumeratedType, CompleteStructType, CompleteTypeObject, CompleteUnionMember,
    CompleteUnionType, MemberFlag, MinimalMemberDetail, MinimalStructHeader, MinimalStructMember,
    MinimalStructType, MinimalTypeDetail, MinimalTypeObject, StructTypeFlag, TypeIdentifier,
    TypeKind, UnionTypeFlag,
};
use std::borrow::Cow;
use std::collections::HashMap;

/// Resolver used by the structural-assignability feature to dereference Minimal / Complete
/// EquivalenceHash values into their corresponding CompleteTypeObject at match time.
///
/// Implement this trait on any hash->TypeObject store (e.g. a per-participant type registry
/// populated with both local and peer TypeObjects).  When the resolver is `None`, or a hash
/// is not in the registry, `type_id_assignable` falls back to the current exact-hash comparison.
///
/// Thread-safety: the resolver is borrowed immutably for the duration of the match decision;
/// no lock or interior mutability is required.
#[cfg(feature = "xtypes-structural-assignability")]
pub trait TypeObjectResolver {
    /// Return the CompleteTypeObject whose MINIMAL EquivalenceHash equals `h`.
    fn resolve_minimal(&self, h: &crate::xtypes::EquivalenceHash) -> Option<&CompleteTypeObject>;
    /// Return the CompleteTypeObject whose COMPLETE EquivalenceHash equals `h`.
    fn resolve_complete(&self, h: &crate::xtypes::EquivalenceHash) -> Option<&CompleteTypeObject>;
}

/// Returns the permissive matcher fallback used when the caller supplies no
/// TypeConsistencyEnforcement policy at all (`policy = None`).
///
/// SCOPE - this fallback only covers LOCAL endpoints that never set the
/// policy and policy-free public API calls (`Matcher::is_assignable_to`).
/// The ABSENT-PID rule for REMOTE readers is NOT handled here: XTypes v1.3
/// Sec 7.6.3.4.1 makes the absent wire policy the spec default with
/// `ignore_member_names=false`, and that is materialized at the wire ->
/// endpoint boundary (`EndpointInfo::from_sedp`), so remote-reader policies
/// arrive at the matcher as `Some(spec_default)`, never `None`.
///
/// Differences from the spec default:
/// - `ignore_member_names = true`: local name checks are opt-in strictness.
///   The OMG interop suite expects a LOCAL reader with unset policy to
///   accept name/id-divergent writer types (struct_different_ids_ok,
///   struct_different_names_ok) unless the app explicitly opts into name
///   enforcement (--check-member-names style flags).
#[inline]
fn default_policy() -> TypeConsistencyEnforcement {
    TypeConsistencyEnforcement {
        ignore_member_names: true,
        ..TypeConsistencyEnforcement::default()
    }
}

/// Check structural type compatibility between a writer and a reader.
///
/// Implements DDS-XTypes v1.3 sec. 7.5.1 structural assignability. When both
/// TypeObjects are available and both are Struct variants, delegates to
/// `is_assignable_to_with_policy` which handles FINAL/APPENDABLE/MUTABLE
/// extensibility rules. Other CompleteTypeObject variants and missing
/// TypeObjects fall back to type-name equality with IDL prefix normalization.
///
/// `policy` controls assignability behaviour per sec. 7.6.3.4. `None` applies
/// the spec default (ALLOW_TYPE_COERCION, ignore_sequence_bounds=true,
/// ignore_string_bounds=true).
pub(super) fn is_type_compatible(
    local_type_object: Option<&CompleteTypeObject>,
    remote_type_object: Option<&CompleteTypeObject>,
    local_type_name: &str,
    remote_type_name: &str,
    policy: Option<&TypeConsistencyEnforcement>,
    #[cfg(feature = "xtypes-structural-assignability")] resolver: Option<&dyn TypeObjectResolver>,
) -> bool {
    let eff = policy
        .map(Cow::Borrowed)
        .unwrap_or_else(|| Cow::Owned(default_policy()));
    let p = eff.as_ref();

    // kind == 0 means DISALLOW_TYPE_COERCION: require exact structural equivalence,
    // no extensibility relaxation. Implemented by forcing FINAL-only hash comparison
    // across the whole type tree (structural flexibility is effectively disabled).
    // Per XTypes v1.3 sec. 7.6.3.4.1: "If kind == DISALLOW_TYPE_COERCION then the
    // Writer and Reader types shall be identical."
    let disallow_coercion = p.kind == 0;

    match (local_type_object, remote_type_object) {
        (Some(local), Some(remote)) => {
            // Both TypeObjects available: use structural assignability (XTypes v1.3 sec. 7.5.1).
            match (local, remote) {
                (CompleteTypeObject::Struct(_), CompleteTypeObject::Struct(_)) => {
                    if disallow_coercion {
                        // DISALLOW: exact hash match only, no extensibility.
                        match (
                            local.compute_equivalence_hash(),
                            remote.compute_equivalence_hash(),
                        ) {
                            (Ok(lh), Ok(rh)) => lh == rh,
                            _ => false,
                        }
                    } else {
                        is_assignable_to_with_policy(
                            local,
                            remote,
                            p,
                            #[cfg(feature = "xtypes-structural-assignability")]
                            resolver,
                        )
                    }
                }
                // Enums: fast path via EquivalenceHash; when hashes differ and coercion
                // is allowed, fall back to APPENDABLE enum assignability per XTypes v1.3
                // sec. 7.5.2.8 (matching bit_bound + non-empty literal value intersection).
                (CompleteTypeObject::Enumerated(le), CompleteTypeObject::Enumerated(re)) => {
                    let lh = local.compute_equivalence_hash();
                    let rh = remote.compute_equivalence_hash();
                    match (lh, rh) {
                        (Ok(lhv), Ok(rhv)) if lhv == rhv => true,
                        _ if !disallow_coercion => is_enum_assignable(le, re),
                        _ => {
                            let local_name =
                                type_name_from_object(local).unwrap_or(local_type_name);
                            let remote_name =
                                type_name_from_object(remote).unwrap_or(remote_type_name);
                            normalize_type_name(local_name) == normalize_type_name(remote_name)
                        }
                    }
                }
                // Unions: label-based structural assignability per DDS-XTypes v1.3 sec. 7.5.1.4.
                //
                // Hash comparison is attempted first (fast path: same extensibility, same
                // discriminator, same label set and member types all encoded in the hash).
                // When hashes differ, fall back to full label-based assignability which
                // handles the APPENDABLE/MUTABLE one-common-label rule, the FINAL exact-
                // label-set rule, and member type checking per label.
                (CompleteTypeObject::Union(local_u), CompleteTypeObject::Union(remote_u)) => {
                    if disallow_coercion {
                        match (
                            local.compute_equivalence_hash(),
                            remote.compute_equivalence_hash(),
                        ) {
                            (Ok(lh), Ok(rh)) => lh == rh,
                            _ => false,
                        }
                    } else {
                        is_union_assignable(
                            local_u,
                            remote_u,
                            p,
                            #[cfg(feature = "xtypes-structural-assignability")]
                            resolver,
                        )
                    }
                }
                // Top-level Sequence: element type must be assignable; bounds handled by
                // policy.ignore_sequence_bounds per XTypes v1.3 sec. 7.5.1.5.
                (CompleteTypeObject::Sequence(ls), CompleteTypeObject::Sequence(rs)) => {
                    type_id_assignable(
                        &ls.element.type_id,
                        &rs.element.type_id,
                        p,
                        #[cfg(feature = "xtypes-structural-assignability")]
                        resolver,
                    )
                }
                // Top-level Array: element type assignable AND all dimension bounds must
                // match exactly per XTypes v1.3 sec. 7.5.1.5 (arrays are size-invariant).
                (CompleteTypeObject::Array(la), CompleteTypeObject::Array(ra)) => {
                    la.header.bound_seq == ra.header.bound_seq
                        && type_id_assignable(
                            &la.element.type_id,
                            &ra.element.type_id,
                            p,
                            #[cfg(feature = "xtypes-structural-assignability")]
                            resolver,
                        )
                }
                // Top-level Map: key and element types must be recursively assignable.
                // Bounds handled by policy (same rationale as sequences).
                (CompleteTypeObject::Map(lm), CompleteTypeObject::Map(rm)) => {
                    type_id_assignable(
                        &lm.key.type_id,
                        &rm.key.type_id,
                        p,
                        #[cfg(feature = "xtypes-structural-assignability")]
                        resolver,
                    ) && type_id_assignable(
                        &lm.element.type_id,
                        &rm.element.type_id,
                        p,
                        #[cfg(feature = "xtypes-structural-assignability")]
                        resolver,
                    )
                }
                // Bitset, Bitmask, Alias, Annotation: structural comparison not
                // implemented; fall back to name equality.
                _ => {
                    log::debug!(
                        "is_type_compatible: unsupported non-Struct top-level pair \
                         ({:?} vs {:?}); falling back to name equality",
                        std::mem::discriminant(local),
                        std::mem::discriminant(remote),
                    );
                    let local_name = type_name_from_object(local).unwrap_or(local_type_name);
                    let remote_name = type_name_from_object(remote).unwrap_or(remote_type_name);
                    normalize_type_name(local_name) == normalize_type_name(remote_name)
                }
            }
        }
        _ => {
            // At least one TypeObject absent.
            // Per DDS-XTypes v1.3 sec. 7.6.1.4.1: when force_type_validation is true,
            // BOTH endpoints must supply a TypeObject for compatibility. Reject when
            // either side lacks one: the reader requires structural validation, which
            // is impossible if the writer published no TypeObject (writer side of
            // discovery), or if the local endpoint has no TypeObject while the remote
            // reader demands it (reader side of discovery).
            if p.force_type_validation
                && (remote_type_object.is_none() || local_type_object.is_none())
            {
                return false;
            }
            // Fall back to name-based matching for interoperability with peers that
            // do not advertise a TypeObject.
            let local_name = match local_type_object {
                Some(_) if !local_type_name.is_empty() => local_type_name,
                Some(local) => type_name_from_object(local).unwrap_or(local_type_name),
                None => local_type_name,
            };
            let remote_name = match remote_type_object {
                Some(_) if !remote_type_name.is_empty() => remote_type_name,
                Some(remote) => type_name_from_object(remote).unwrap_or(remote_type_name),
                None => remote_type_name,
            };
            normalize_type_name(local_name) == normalize_type_name(remote_name)
        }
    }
}

// @audit-ok: Simple pattern matching (cyclo 11, cogni 1) - extract type_name from variant headers
fn type_name_from_object(obj: &CompleteTypeObject) -> Option<&str> {
    match obj {
        CompleteTypeObject::Struct(ty) => Some(ty.header.detail.type_name.as_str()),
        CompleteTypeObject::Union(ty) => Some(ty.header.detail.type_name.as_str()),
        CompleteTypeObject::Enumerated(ty) => Some(ty.header.detail.type_name.as_str()),
        CompleteTypeObject::Bitmask(ty) => Some(ty.header.detail.type_name.as_str()),
        CompleteTypeObject::Bitset(ty) => Some(ty.header.detail.type_name.as_str()),
        CompleteTypeObject::Sequence(ty) => ty.header.detail.as_ref().map(|d| d.type_name.as_str()),
        CompleteTypeObject::Array(ty) => Some(ty.header.detail.type_name.as_str()),
        CompleteTypeObject::Map(ty) => ty.header.detail.as_ref().map(|d| d.type_name.as_str()),
        CompleteTypeObject::Alias(ty) => Some(ty.header.detail.type_name.as_str()),
        CompleteTypeObject::Annotation(ty) => Some(ty.header.annotation_name.as_str()),
    }
}

fn normalize_type_name(name: &str) -> Cow<'_, str> {
    let stripped = if let Some(rest) = name.strip_prefix("IDL:") {
        if let Some((core, _version)) = rest.rsplit_once(':') {
            core
        } else {
            rest
        }
    } else {
        name
    };

    let normalized = if stripped.contains('/') {
        stripped.replace('/', "::")
    } else {
        stripped.to_string()
    };

    if normalized.contains("::msg::") {
        Cow::Owned(normalized.replace("::msg::", "::"))
    } else {
        Cow::Owned(normalized)
    }
}

/// Policy-unaware wrapper retained for the public `Matcher::is_assignable_to`
/// API (tests and external callers that do not hold a policy context).
/// Uses the spec default: ALLOW_TYPE_COERCION + ignore_sequence_bounds=true.
pub(super) fn is_assignable_to(
    writer_type: &CompleteTypeObject,
    reader_type: &CompleteTypeObject,
) -> bool {
    let p = default_policy();
    is_assignable_to_with_policy(
        writer_type,
        reader_type,
        &p,
        #[cfg(feature = "xtypes-structural-assignability")]
        None,
    )
}

/// Policy-aware implementation of XTypes v1.3 sec. 7.5.1 structural assignability.
///
/// Checks whether `writer_type` is assignable to `reader_type` under the
/// given `TypeConsistencyEnforcement` policy. Called from `is_type_compatible`
/// when ALLOW_TYPE_COERCION is in effect.
fn is_assignable_to_with_policy(
    writer_type: &CompleteTypeObject,
    reader_type: &CompleteTypeObject,
    policy: &TypeConsistencyEnforcement,
    #[cfg(feature = "xtypes-structural-assignability")] resolver: Option<&dyn TypeObjectResolver>,
) -> bool {
    match (writer_type, reader_type) {
        (CompleteTypeObject::Struct(w), CompleteTypeObject::Struct(r)) => {
            let writer_flags = w.struct_flags;
            let reader_flags = r.struct_flags;

            if !compatible_extensibility(writer_flags, reader_flags) {
                return false;
            }
            if !compatible_keys(
                w,
                r,
                #[cfg(feature = "xtypes-structural-assignability")]
                resolver,
            ) {
                return false;
            }
            if writer_flags.contains(StructTypeFlag::IS_FINAL) {
                is_assignable_final(
                    w,
                    r,
                    policy,
                    #[cfg(feature = "xtypes-structural-assignability")]
                    resolver,
                )
            } else if writer_flags.contains(StructTypeFlag::IS_APPENDABLE) {
                is_assignable_appendable(
                    w,
                    r,
                    policy,
                    #[cfg(feature = "xtypes-structural-assignability")]
                    resolver,
                )
            } else if writer_flags.contains(StructTypeFlag::IS_MUTABLE) {
                is_assignable_mutable(
                    w,
                    r,
                    policy,
                    #[cfg(feature = "xtypes-structural-assignability")]
                    resolver,
                )
            } else {
                is_assignable_final(
                    w,
                    r,
                    policy,
                    #[cfg(feature = "xtypes-structural-assignability")]
                    resolver,
                )
            }
        }
        (CompleteTypeObject::Union(w), CompleteTypeObject::Union(r)) => is_union_assignable(
            w,
            r,
            policy,
            #[cfg(feature = "xtypes-structural-assignability")]
            resolver,
        ),
        // XTypes 1.3 7.2.4.4.7 Table 18: bitmask assignability depends
        // on equal bounds, independently of names and identified positions.
        (CompleteTypeObject::Bitmask(w), CompleteTypeObject::Bitmask(r)) => {
            policy.kind != 0
                && (1..=64).contains(&w.header.bit_bound)
                && w.header.bit_bound == r.header.bit_bound
        }
        // Enum pairs: delegate to structural enum assignability when coercion is allowed.
        // This arm is reached when `type_id_assignable` resolves a Minimal/Complete hash
        // via the TypeObjectResolver and recurses into this function for structural check.
        (CompleteTypeObject::Enumerated(w), CompleteTypeObject::Enumerated(r)) => {
            policy.kind != 0 && is_enum_assignable(w, r)
        }
        _ => false,
    }
}

/// Check APPENDABLE enum assignability per DDS-XTypes v1.3 sec. 7.5.2.8.
///
/// Two enumerated types are assignable when ALLOW_TYPE_COERCION is in effect if:
/// 1. Both have the same bit_bound (8, 16, or 32), ensuring the on-wire integer
///    width is compatible.
/// 2. The intersection of literal values (by integer value) is non-empty --
///    both sides share at least one common value so a round-trip is meaningful.
///    Reader-side TryConstruct (DISCARD / USE_DEFAULT) handles writer values
///    absent from the reader's literal set at decode time; that is a decoding
///    concern, not a compatibility predicate.
///
/// When hashes match exactly, the caller short-circuits before calling this
/// function. This function is only reached on hash mismatch, i.e., when at
/// least one literal value or the literal count differs between the two enums.
fn is_enum_assignable(writer: &CompleteEnumeratedType, reader: &CompleteEnumeratedType) -> bool {
    if writer.header.bit_bound != reader.header.bit_bound {
        return false;
    }
    // Non-empty literal value intersection: at least one (value, value) pair
    // must exist in both writer and reader literal_seq.
    writer.literal_seq.iter().any(|wl| {
        reader
            .literal_seq
            .iter()
            .any(|rl| rl.common.value == wl.common.value)
    })
}

/// Check union assignability per DDS-XTypes v1.3 sec. 7.5.1.4.
///
/// Union assignability rules:
///
/// 1. Discriminator types must be the same (via `type_id_assignable` with exact
///    kind matching -- discriminator is never coerced).
/// 2. Extensibility flags must match: FINAL, APPENDABLE, and MUTABLE must
///    agree between writer and reader. Mixing extensibility kinds is not
///    assignable.
/// 3. Discriminator IS_KEY status must agree between writer and reader. A
///    union discriminated by a key field is a distinct semantic type from one
///    discriminated by a non-key field.
/// 4. For FINAL unions: the set of explicit discriminant labels in the writer
///    must equal the set of explicit discriminant labels in the reader exactly.
///    A default case (`IS_DEFAULT` flag) is not part of the explicit label set;
///    its presence on one side but not the other makes the sets unequal.
/// 5. For APPENDABLE and MUTABLE unions: the intersection of the writer's
///    explicit discriminant label set and the reader's explicit discriminant
///    label set must be non-empty. Default cases are not part of this
///    intersection. If no common explicit label exists the types are not
///    assignable (the reader can never produce a value the writer would
///    recognise, or vice-versa).
/// 6. For every label L that is common to both writer and reader (explicit
///    match): the type of the writer member covering L must be assignable to
///    the type of the reader member covering L under the supplied policy.
/// 7. Member id/name coherence (rule 3b in the body, DDS-XTypes v1.3 Table 19
///    UNION_TYPE): any members with the same name must have the same id, and
///    any members with the same id must have the same name. Per section 7.6.3.4.2
///    Step 1, this coherence check is only in force when ignore_member_names
///    is false; when true (the matcher's local default and the OMG suite's
///    no-flag default) two members that happen to share an auto-assigned id
///    by coincidence of declaration order are NOT required to be name- or
///    type-compatible at that id -- VALUE compatibility is established
///    exclusively by the label-based rule 6 above. A cross-id type check is
///    still applied as defense in depth when ignore_member_names=false (an
///    id-matched pair must be strongly assignable in addition to
///    same-named), matching the same coherence bullet's spirit and the
///    reference vendors' observed behaviour without affecting the suite's
///    permissive-default expectation. Fully disjoint member id sets between
///    two non-empty unions are not assignable (defense in depth; not a
///    literal Table 19 UNION_TYPE bullet, but exercised by no active OMG
///    test either way).
///
/// The `policy` parameter is forwarded to `type_id_assignable` for the
/// per-label member type checks. Discriminator type comparison always uses
/// the exact-match / no-widening form regardless of `prevent_type_widening`,
/// with one relaxation: a primitive unsigned integer discriminator and a
/// resolver-resolved BITMASK discriminator with the matching holder width are
/// strongly assignable (union_uint32_bitmask32).
fn is_union_assignable(
    writer: &CompleteUnionType,
    reader: &CompleteUnionType,
    policy: &TypeConsistencyEnforcement,
    #[cfg(feature = "xtypes-structural-assignability")] resolver: Option<&dyn TypeObjectResolver>,
) -> bool {
    // Rule 1: extensibility flags must match.
    let w_flags = writer.union_flags;
    let r_flags = reader.union_flags;
    let final_match =
        w_flags.contains(UnionTypeFlag::IS_FINAL) == r_flags.contains(UnionTypeFlag::IS_FINAL);
    let appendable_match = w_flags.contains(UnionTypeFlag::IS_APPENDABLE)
        == r_flags.contains(UnionTypeFlag::IS_APPENDABLE);
    let mutable_match =
        w_flags.contains(UnionTypeFlag::IS_MUTABLE) == r_flags.contains(UnionTypeFlag::IS_MUTABLE);
    if !(final_match && appendable_match && mutable_match) {
        return false;
    }

    // Rule 2: discriminator and member types must be "strongly assignable".
    // Per DDS-XTypes v1.3 sec. 7.5.1.4, union case assignability uses the same
    // type equivalence as the discriminator: no primitive widening allowed.
    // The XTypes tests confirm this -- int16 vs int32 in the same case label
    // is INCONSISTENT even when the calling policy has prevent_type_widening=false.
    // Use a strict copy (prevent_type_widening=true) for all type checks inside
    // this function; the policy's other settings (ignore_sequence_bounds,
    // ignore_string_bounds) are preserved so bound-only differences in
    // sequence/string member types are still respected.
    //
    // Exception: when kind != DISALLOW_TYPE_COERCION and both discriminators are
    // Minimal-hash TypeIdentifiers (opaque complex type, typically an APPENDABLE enum),
    // allow the discriminator to differ. Per XTypes sec. 7.5.2.8, APPENDABLE enum
    // discriminators with overlapping integer values are assignable; integer case
    // labels are routed by value, not by enum type identity. Primitive discriminators
    // (int32, uint32, etc.) are compared by PrimitiveKind and remain exact-match.
    let strict = TypeConsistencyEnforcement {
        prevent_type_widening: true,
        ..policy.clone()
    };
    let allow_coercion = policy.kind != 0;
    let disc_ok = match (&writer.header.discriminator, &reader.header.discriminator) {
        (TypeIdentifier::Minimal(wh), TypeIdentifier::Minimal(rh)) => wh == rh || allow_coercion,
        (TypeIdentifier::Complete(wh), TypeIdentifier::Complete(rh)) => wh == rh || allow_coercion,
        // Primitive vs hash-referenced discriminator: strongly assignable only
        // when the hash side resolves to a BITMASK whose holder integer width
        // equals the primitive kind (XTypes v1.3 Sec 7.5.1.4: an unsigned
        // integer discriminator and a bitmask discriminator with the matching
        // bit_bound holder are strongly assignable). OMG union_uint32_bitmask32
        // expects OK (uint32 vs bitmask<32>); union_uint32_bitmask16 expects
        // INCONSISTENT (uint32 vs bitmask<16>, holder uint16). Without a
        // resolver (or when the hash resolves to a non-bitmask type) this
        // stays not-assignable, matching the previous cross-variant reject.
        #[cfg(feature = "xtypes-structural-assignability")]
        (TypeIdentifier::Primitive(pk), TypeIdentifier::Minimal(h))
        | (TypeIdentifier::Minimal(h), TypeIdentifier::Primitive(pk))
            if allow_coercion =>
        {
            bitmask_holder_matches(*pk, h, false, resolver)
        }
        #[cfg(feature = "xtypes-structural-assignability")]
        (TypeIdentifier::Primitive(pk), TypeIdentifier::Complete(h))
        | (TypeIdentifier::Complete(h), TypeIdentifier::Primitive(pk))
            if allow_coercion =>
        {
            bitmask_holder_matches(*pk, h, true, resolver)
        }
        _ => type_id_assignable(
            &writer.header.discriminator,
            &reader.header.discriminator,
            &strict,
            #[cfg(feature = "xtypes-structural-assignability")]
            resolver,
        ),
    };
    if !disc_ok {
        return false;
    }

    // Rule 3: discriminator IS_KEY status must agree.
    // Find the discriminator MemberFlag from member 0 of each union. The
    // discriminator's IS_KEY bit is stored in the first member's flags for
    // unions whose discriminator is annotated @key (XTypes sec. 7.3.4.7.3).
    // A simpler and correct check: scan members of both unions; if any
    // member in writer has IS_KEY and no member in reader has IS_KEY (or
    // vice-versa), the discriminator key annotation differs.
    //
    // Unions in the OMG test suite encode IS_KEY on the member_flags of
    // every member when the discriminator is @key. Checking whether the
    // writer has at least one IS_KEY member and the reader does (or neither
    // does) is the correct approach.
    let writer_has_key = writer
        .member_seq
        .iter()
        .any(|m| m.common.member_flags.contains(MemberFlag::IS_KEY));
    let reader_has_key = reader
        .member_seq
        .iter()
        .any(|m| m.common.member_flags.contains(MemberFlag::IS_KEY));
    if writer_has_key != reader_has_key {
        return false;
    }

    // Rule 3b: member id/name coherence (DDS-XTypes v1.3 Table 19 UNION_TYPE:
    // "Any members in T1 and T2 that have the same name also have the same
    // ID and any members with the same ID also have the same name."), gated
    // per Sec 7.6.3.4.2 Step 1 where names are involved.
    //
    // Union members are related BY MEMBER ID in addition to the label-based
    // rules below. The OMG interop suite (DDS-XTypes 1.3 Sec.7.2.4.4
    // assignability rules) exercises these id-based checks:
    //
    //   - When ignore_member_names=false (union_different_ids_2,
    //     union_different_names_2): members paired by id must carry the
    //     same name, and a member name reused under a DIFFERENT id is a
    //     conflicting remapping (same rule as MUTABLE structs, XTypes v1.3
    //     Sec 7.3.1.2 name/id coherence). A same-id type check is also kept
    //     active in this branch as defense in depth (matches the reference
    //     vendors' observed behaviour); it never fires for
    //     union_different_ids_2 because the name check below rejects that
    //     pair first ("x1" paired by id with "x2").
    //   - Two non-empty unions whose member id sets are fully disjoint carry
    //     no common member at all and are not assignable (mirrors the struct
    //     no-common-member rule in Sec 7.5.1.1.2; not a literal Table 19
    //     UNION_TYPE bullet, kept as defense in depth -- no active OMG test
    //     exercises this either way).
    //
    // Members matched by id but NOT by label (e.g. union_appendable_a's x1
    // id=0 label=1 vs union_appendable_b's x11 id=0 label=11) only need type
    // assignability under ignore_member_names=false; label disjointness for
    // a given id pair is NOT an error (union_appendable_one_common_1 expects
    // OK with five such pairs under the permissive default, where this
    // cross-id check does not run at all).
    let mut common_id_count: usize = 0;
    for wm in &writer.member_seq {
        if let Some(rm) = reader
            .member_seq
            .iter()
            .find(|r| r.common.member_id == wm.common.member_id)
        {
            common_id_count += 1;
            // Cross-id type coherence is name-policy-gated, matching the
            // name check just below: with ignore_member_names=true a shared
            // id is not a claim of shared identity (see rule doc above), so
            // an incidental type mismatch at that id must not reject a pair
            // whose real (label-based) value compatibility is fine.
            if !policy.ignore_member_names
                && !type_id_assignable(
                    &wm.common.member_type_id,
                    &rm.common.member_type_id,
                    &strict,
                    #[cfg(feature = "xtypes-structural-assignability")]
                    resolver,
                )
            {
                return false;
            }
            if !policy.ignore_member_names && wm.detail.name != rm.detail.name {
                return false;
            }
        }
        if !policy.ignore_member_names {
            if let Some(rm) = reader
                .member_seq
                .iter()
                .find(|r| r.detail.name == wm.detail.name)
            {
                if rm.common.member_id != wm.common.member_id {
                    return false;
                }
            }
        }
    }
    if !writer.member_seq.is_empty() && !reader.member_seq.is_empty() && common_id_count == 0 {
        return false;
    }

    // Build explicit label sets: all labels from non-default members.
    // Default members have IS_DEFAULT flag and empty label_seq.
    let collect_explicit_labels = |u: &CompleteUnionType| -> Vec<i32> {
        u.member_seq
            .iter()
            .filter(|m| !m.common.member_flags.contains(MemberFlag::IS_DEFAULT))
            .flat_map(|m| m.common.label_seq.iter().copied())
            .collect()
    };
    let writer_labels = collect_explicit_labels(writer);
    let reader_labels = collect_explicit_labels(reader);

    // Find the reader member (explicit or default) covering a given label.
    let find_reader_member = |label: i32| -> Option<&CompleteUnionMember> {
        // Prefer explicit match.
        for m in &reader.member_seq {
            if m.common.member_flags.contains(MemberFlag::IS_DEFAULT) {
                continue;
            }
            if m.common.label_seq.contains(&label) {
                return Some(m);
            }
        }
        // Fall back to the reader's default case.
        reader
            .member_seq
            .iter()
            .find(|m| m.common.member_flags.contains(MemberFlag::IS_DEFAULT))
    };

    if w_flags.contains(UnionTypeFlag::IS_FINAL) {
        // Rule 4 (FINAL): explicit label sets must be equal.
        // Compare as sorted multisets (labels are integers; duplicates
        // shouldn't occur in well-formed unions but sort defensively).
        //
        // Coercion relaxation for enum-discriminated FINAL unions: when
        // ALLOW_TYPE_COERCION is in effect and the discriminator is a complex
        // (Minimal-hash) type such as an APPENDABLE enum, permit the reader's
        // label set to be a strict subset of the writer's. Extra writer labels
        // the reader does not cover are handled by TryConstruct at decode time.
        // This relaxation does NOT apply to primitive (integer) discriminators
        // to preserve exact label-set equality for unions like union_final_5_vs_6.
        let discriminator_is_complex = matches!(
            (&writer.header.discriminator, &reader.header.discriminator),
            (TypeIdentifier::Minimal(_), TypeIdentifier::Minimal(_))
                | (TypeIdentifier::Complete(_), TypeIdentifier::Complete(_))
        );
        let allow_subset = allow_coercion && discriminator_is_complex;
        let mut w_sorted = writer_labels.clone();
        let mut r_sorted = reader_labels.clone();
        w_sorted.sort_unstable();
        r_sorted.sort_unstable();
        let labels_ok = if w_sorted == r_sorted {
            true
        } else if allow_subset {
            // Reader labels must form a subset of writer labels.
            r_sorted.iter().all(|rl| w_sorted.contains(rl))
        } else {
            false
        };
        if !labels_ok {
            return false;
        }
        // Also check default case presence: both must have it or neither.
        let writer_has_default = writer
            .member_seq
            .iter()
            .any(|m| m.common.member_flags.contains(MemberFlag::IS_DEFAULT));
        let reader_has_default = reader
            .member_seq
            .iter()
            .any(|m| m.common.member_flags.contains(MemberFlag::IS_DEFAULT));
        if writer_has_default != reader_has_default && !allow_subset {
            return false;
        }
        // Rule 6 for FINAL: every common label (= all labels in the intersection)
        // must have assignable member types (strict: no widening per sec. 7.5.1.4).
        // Per DDS-XTypes v1.3 sec. 7.3.4.6 and sec. 7.5.1.4: FINAL union assignability
        // requires that writer and reader agree on member_id for every label, and
        // (when ignore_member_names=false) on member name as well.
        //
        // When coercion is allowed and the reader's label set is a proper subset
        // of the writer's, only check labels that exist on the reader side; writer
        // labels absent from the reader are handled by TryConstruct at decode time.
        let check_labels: Vec<i32> = if allow_subset {
            // Intersect: only labels in both writer and reader.
            writer_labels
                .iter()
                .copied()
                .filter(|l| reader_labels.contains(l))
                .collect()
        } else {
            writer_labels.clone()
        };
        for &label in &check_labels {
            let w_member = writer
                .member_seq
                .iter()
                .find(|m| m.common.label_seq.contains(&label));
            let r_member = reader
                .member_seq
                .iter()
                .find(|m| m.common.label_seq.contains(&label));
            match (w_member, r_member) {
                (Some(w), Some(r)) => {
                    // Member IDs must match for FINAL unions: the same label must
                    // map to the same member_id on both sides. For union_5 vs union_6
                    // (different declaration order, same explicit @id), this holds
                    // because the XML @id attribute fixes the member_id independently
                    // of declaration position. For union_1 vs union_2 (no explicit @id,
                    // declaration order differs), member_ids differ -> incompatible.
                    // Per DDS-XTypes v1.3 sec. 7.3.4.6: member_id is part of the Minimal
                    // encoding and must agree between compatible FINAL union pairs.
                    if w.common.member_id != r.common.member_id {
                        return false;
                    }
                    // Member names must match when ignore_member_names is false
                    // (DDS-XTypes v1.3 sec. 7.6.3.4, TypeConsistencyEnforcement).
                    if !policy.ignore_member_names && w.detail.name != r.detail.name {
                        return false;
                    }
                    if !type_id_assignable(
                        &w.common.member_type_id,
                        &r.common.member_type_id,
                        &strict,
                        #[cfg(feature = "xtypes-structural-assignability")]
                        resolver,
                    ) {
                        return false;
                    }
                }
                _ => {
                    // A label in the intersection with no matching member is
                    // a malformed type; reject.
                    return false;
                }
            }
        }
        // Check default-vs-default type when both have a default.
        if writer_has_default && reader_has_default {
            let w_def = writer
                .member_seq
                .iter()
                .find(|m| m.common.member_flags.contains(MemberFlag::IS_DEFAULT));
            let r_def = reader
                .member_seq
                .iter()
                .find(|m| m.common.member_flags.contains(MemberFlag::IS_DEFAULT));
            if let (Some(wd), Some(rd)) = (w_def, r_def) {
                if !type_id_assignable(
                    &wd.common.member_type_id,
                    &rd.common.member_type_id,
                    &strict,
                    #[cfg(feature = "xtypes-structural-assignability")]
                    resolver,
                ) {
                    return false;
                }
            }
        }
    } else {
        // Rule 5 (APPENDABLE / MUTABLE): explicit label sets must intersect.
        //
        // "Intersect" here means the sets of EXPLICIT discriminant labels (not
        // including the default case) have at least one value in common. A union
        // whose only apparent overlap with the counterpart is via a default case
        // on one or both sides is NOT considered to intersect for this rule; the
        // default case is a catch-all for unlabelled values, not a named member
        // that joins the two type spaces together.
        let common_labels: Vec<i32> = writer_labels
            .iter()
            .copied()
            .filter(|l| reader_labels.contains(l))
            .collect();
        if common_labels.is_empty() {
            return false;
        }

        // Locate the default cases (if any) for the cross-default checks below.
        let writer_default = writer
            .member_seq
            .iter()
            .find(|m| m.common.member_flags.contains(MemberFlag::IS_DEFAULT));
        let reader_default = reader
            .member_seq
            .iter()
            .find(|m| m.common.member_flags.contains(MemberFlag::IS_DEFAULT));

        // Rule 6 for APPENDABLE/MUTABLE: for each common explicit label, writer
        // member type must be assignable to reader member type (strict, no widening).
        for &label in &common_labels {
            let w_member = writer
                .member_seq
                .iter()
                .find(|m| m.common.label_seq.contains(&label));
            let r_member = find_reader_member(label);
            match (w_member, r_member) {
                (Some(w), Some(r)) => {
                    if !type_id_assignable(
                        &w.common.member_type_id,
                        &r.common.member_type_id,
                        &strict,
                        #[cfg(feature = "xtypes-structural-assignability")]
                        resolver,
                    ) {
                        return false;
                    }
                }
                _ => return false,
            }
        }

        // Rule 6b: cross-default type checks (strict, no widening).
        //
        // When the writer sends discriminant value L that has no explicit reader
        // member for L, the reader falls through to its default case. For this
        // to work the writer member for L must be type-compatible with the
        // reader's default member. The matching direction is:
        //   writer_explicit[L].type == reader_default.type
        //
        // Symmetrically, when the reader receives discriminant value L for which
        // the writer has no explicit member (but writer has a default case), the
        // value the writer sends will be typed by writer's default. The reader
        // uses its explicit member for L. We must verify:
        //   writer_default.type == reader_explicit[L].type
        //
        // Both checks apply only when the respective default case exists.
        if let Some(rd) = reader_default {
            // For writer labels not in reader's explicit set: writer sends a value
            // of the explicit writer member type, but reader's only match is its
            // default case. Check type compatibility.
            for &wl in &writer_labels {
                if !reader_labels.contains(&wl) {
                    // reader has no explicit case for wl; uses rd (default).
                    let w_member = writer
                        .member_seq
                        .iter()
                        .find(|m| m.common.label_seq.contains(&wl));
                    if let Some(wm) = w_member {
                        if !type_id_assignable(
                            &wm.common.member_type_id,
                            &rd.common.member_type_id,
                            &strict,
                            #[cfg(feature = "xtypes-structural-assignability")]
                            resolver,
                        ) {
                            return false;
                        }
                    }
                }
            }
        }
        if let Some(wd) = writer_default {
            // For reader labels not in writer's explicit set: writer has no explicit
            // case for the label, so it sends the default member type. The reader
            // reads it with its explicit member type for that label. Check compat.
            for &rl in &reader_labels {
                if !writer_labels.contains(&rl) {
                    // writer has no explicit case for rl; uses wd (default).
                    let r_member = reader
                        .member_seq
                        .iter()
                        .find(|m| m.common.label_seq.contains(&rl));
                    if let Some(rm) = r_member {
                        if !type_id_assignable(
                            &wd.common.member_type_id,
                            &rm.common.member_type_id,
                            &strict,
                            #[cfg(feature = "xtypes-structural-assignability")]
                            resolver,
                        ) {
                            return false;
                        }
                    }
                }
            }
        }

        // When both sides carry a default case, their default member types must
        // also be mutually assignable. Any runtime discriminant value that falls
        // outside ALL explicit labels of BOTH unions resolves to the default
        // member on each side; those types must therefore be wire-compatible.
        //
        // The cross-default rules above only enforce compatibility for values
        // that are explicit on one side and missing on the other. When the two
        // explicit label sets are equal (or one is a subset of the other with a
        // default present on the larger side), the default-vs-default pair is
        // never covered by the cross-rules. This gap is the root cause of the
        // OMG union_int32_default_int16_default failure.
        if let (Some(wd), Some(rd)) = (writer_default, reader_default) {
            if !type_id_assignable(
                &wd.common.member_type_id,
                &rd.common.member_type_id,
                &strict,
                #[cfg(feature = "xtypes-structural-assignability")]
                resolver,
            ) {
                return false;
            }
        }
    }

    true
}

/// Match a bitmask's unsigned holder width (XTypes 1.3 7.2.4.4.4,
/// Table 15, and 7.2.4.4.7, Table 18). Unknown references and non-bitmask
/// objects cannot establish this relation.
#[cfg(feature = "xtypes-structural-assignability")]
fn bitmask_holder_matches(
    pk: TypeKind,
    hash: &crate::xtypes::EquivalenceHash,
    complete: bool,
    resolver: Option<&dyn TypeObjectResolver>,
) -> bool {
    let Some(res) = resolver else {
        return false;
    };
    let obj = if complete {
        res.resolve_complete(hash)
    } else {
        res.resolve_minimal(hash)
    };
    let Some(CompleteTypeObject::Bitmask(b)) = obj else {
        return false;
    };
    let holder = match b.header.bit_bound {
        1..=8 => TypeKind::TK_UINT8,
        9..=16 => TypeKind::TK_UINT16,
        17..=32 => TypeKind::TK_UINT32,
        33..=64 => TypeKind::TK_UINT64,
        _ => return false,
    };
    holder == pk
}

fn compatible_extensibility(writer_flags: StructTypeFlag, reader_flags: StructTypeFlag) -> bool {
    let final_match = writer_flags.contains(StructTypeFlag::IS_FINAL)
        == reader_flags.contains(StructTypeFlag::IS_FINAL);
    let appendable_match = writer_flags.contains(StructTypeFlag::IS_APPENDABLE)
        == reader_flags.contains(StructTypeFlag::IS_APPENDABLE);
    let mutable_match = writer_flags.contains(StructTypeFlag::IS_MUTABLE)
        == reader_flags.contains(StructTypeFlag::IS_MUTABLE);
    // IS_AUTOID_HASH changes the member ID assignment scheme: explicit sequential IDs
    // and hash-derived IDs produce disjoint ID spaces that cannot match by member_id.
    // Per XTypes v1.3 sec. 7.3.1.2, mixing autoid schemes is not assignable.
    let autoid_match = writer_flags.contains(StructTypeFlag::IS_AUTOID_HASH)
        == reader_flags.contains(StructTypeFlag::IS_AUTOID_HASH);

    final_match && appendable_match && mutable_match && autoid_match
}

/// The key members of `writer` (T2) and `reader` (T1) correspond by member
/// ID and their types are assignable.
///
/// A key member's BOUND is not judged here. DDS-XTypes v1.3 Sec.7.2.4.4.8
/// Table 19 (STRUCTURE_TYPE) holds keys to theirs: "For any string key
/// member m2 in T2, the m1 member of T1 with the same member ID verifies
/// m1.type.length >= m2.type.length", and "For any sequence or map key
/// member m2 in T2, the m1 member of T1 with the same member ID verifies
/// m1.type.length >= m2.type.length". Sec.7.6.3.4.1 then says, with no
/// exception for keys: "If the option is set to TRUE (the default), string
/// bounds (maximum lengths) are not considered as part of the type
/// assignability. This means that a T2 string type with maximum length L2
/// would be assignable to a T1 string type with maximum length L1, even if
/// L2 is greater than L1. If the option is set to false, then string bounds
/// are taken into consideration for type assignability and in order for T1
/// to be assignable from T2 it is required that L1>= L2", and the same for
/// `ignore_sequence_bounds`. So a key bound counts exactly when its flag is
/// FALSE, which is the comparison the member walk (`is_assignable_final` /
/// `_appendable` / `_mutable`) already makes of every member, keys included,
/// under the caller's policy; under it a nested structure key is reached by
/// `type_id_assignable` and its own keys are walked the same way. Here the
/// key types are compared under the permissive default (`default_policy`).
///
/// Under TRUE, Table 19's Note ("The rules regarding key members ensure that
/// the key of T2 can be transformed faithfully into the key of T1 without
/// aliasing or loss of information") is kept on the receive side: a key
/// longer than the reader's bound is never trimmed nor defaulted into
/// another instance; the dynamic decoder refuses the sample
/// (`CdrDecoder::in_key`).
fn compatible_keys(
    writer: &CompleteStructType,
    reader: &CompleteStructType,
    #[cfg(feature = "xtypes-structural-assignability")] resolver: Option<&dyn TypeObjectResolver>,
) -> bool {
    let writer_keys: Vec<_> = writer
        .member_seq
        .iter()
        .filter(|m| m.common.member_flags.contains(MemberFlag::IS_KEY))
        .map(|m| (m.common.member_id, &m.common.member_type_id))
        .collect();

    let reader_keys: Vec<_> = reader
        .member_seq
        .iter()
        .filter(|m| m.common.member_flags.contains(MemberFlag::IS_KEY))
        .map(|m| (m.common.member_id, &m.common.member_type_id))
        .collect();

    if writer_keys.len() != reader_keys.len() {
        return false;
    }

    let p = default_policy();
    for (reader_id, reader_type) in &reader_keys {
        let writer_match = writer_keys
            .iter()
            .find(|(writer_id, _)| writer_id == reader_id);

        match writer_match {
            Some((_, writer_type)) => {
                if !type_id_assignable(
                    writer_type,
                    reader_type,
                    &p,
                    #[cfg(feature = "xtypes-structural-assignability")]
                    resolver,
                ) {
                    return false;
                }
                #[cfg(feature = "xtypes-structural-assignability")]
                if !enum_key_literals_fit(writer_type, reader_type, resolver) {
                    return false;
                }
            }
            None => return false,
        }
    }

    true
}

/// DDS-XTypes v1.3 Sec.7.2.4.4.8 Table 19, STRUCTURE_TYPE: "For any
/// enumerated key member m2 in T2, the m1 member of T1 with the same member
/// ID verifies that all literals in m2.type appear as literals in m1.type".
/// No flag relaxes it: a writer literal the reader lacks could only be read
/// as the reader's default literal, another instance's key. Literals are
/// compared by value, as `is_enum_assignable` compares them.
///
/// Two different enumerations are only told apart through the resolver:
/// without one, `type_id_assignable` already refused the differing hashes,
/// and equal hashes name the same literals.
#[cfg(feature = "xtypes-structural-assignability")]
fn enum_key_literals_fit(
    writer: &TypeIdentifier,
    reader: &TypeIdentifier,
    resolver: Option<&dyn TypeObjectResolver>,
) -> bool {
    let Some(res) = resolver else {
        return true;
    };
    let resolve = |id: &TypeIdentifier| match id {
        TypeIdentifier::Minimal(h) => res.resolve_minimal(h),
        TypeIdentifier::Complete(h) => res.resolve_complete(h),
        _ => None,
    };
    match (resolve(writer), resolve(reader)) {
        (Some(CompleteTypeObject::Enumerated(w)), Some(CompleteTypeObject::Enumerated(r))) => {
            w.literal_seq.iter().all(|wl| {
                r.literal_seq
                    .iter()
                    .any(|rl| rl.common.value == wl.common.value)
            })
        }
        _ => true,
    }
}

/// Sequence / map bound compatibility check for u8-typed bounds (Small variants).
///
/// Per XTypes v1.3 sec. 7.5.1.5, bound=0 encodes "unbounded" (no maximum). An
/// unbounded writer (w==0) cannot be safely assigned to a bounded reader (r>0)
/// when bounds are enforced: the writer may produce more entries than the
/// reader's declared maximum. Both unbounded (w==0, r==0) and bounded-fits
/// (0<w<=r) are compatible.
#[inline]
fn collection_bound_ok_small(w: u8, r: u8) -> bool {
    // w==0 means unbounded: only compatible when reader is also unbounded (r==0).
    // w>0 means bounded: compatible when w <= r (or r==0, reader is unbounded).
    w == 0 && r == 0 || w > 0 && (r == 0 || w <= r)
}

/// Sequence / map bound compatibility check for u32-typed bounds (Large variants
/// and cross-size comparisons after widening the Small bound to u32).
///
/// Same semantics as `collection_bound_ok_small` but for 32-bit bounds.
#[inline]
fn collection_bound_ok_large(w: u32, r: u32) -> bool {
    w == 0 && r == 0 || w > 0 && (r == 0 || w <= r)
}

/// XTypes v1.3 sec. 7.5.1.3 Table 3: allowed widening assignments for primitives
/// when `prevent_type_widening = false`.
///
/// Returns `true` if writer kind `wk` is assignable to reader kind `rk`
/// under a widening policy. Widening is unidirectional (e.g., uint8 -> uint16
/// is OK; uint16 -> uint8 is NOT). Only integer and float promotions defined
/// in Table 3 are permitted.
fn primitive_widening_allowed(wk: TypeKind, rk: TypeKind) -> bool {
    use TypeKind::*;
    // Exact match is always assignable (handled by caller, but guard here too).
    if wk == rk {
        return true;
    }
    // Signed integer widening chain: int8 <= int16 <= int32 <= int64
    let int_rank = |k: TypeKind| match k {
        TK_INT8 => Some(0u8),
        TK_INT16 => Some(1),
        TK_INT32 => Some(2),
        TK_INT64 => Some(3),
        _ => None,
    };
    if let (Some(wr), Some(rr)) = (int_rank(wk), int_rank(rk)) {
        return wr <= rr;
    }
    // Unsigned integer widening chain: uint8 <= uint16 <= uint32 <= uint64
    // Per XTypes v1.3 sec. 7.5.1.3 Table 3, TK_BYTE is NOT part of this chain.
    // TK_BYTE is a distinct opaque octet type; it does not widen to TK_UINT8
    // or any other kind. Only TK_UINT8 anchors the chain at rank 0.
    let uint_rank = |k: TypeKind| match k {
        TK_UINT8 => Some(0u8),
        TK_UINT16 => Some(1),
        TK_UINT32 => Some(2),
        TK_UINT64 => Some(3),
        _ => None,
    };
    if let (Some(wr), Some(rr)) = (uint_rank(wk), uint_rank(rk)) {
        return wr <= rr;
    }
    // Float widening: float32 <= float64 <= float128
    let float_rank = |k: TypeKind| match k {
        TK_FLOAT32 => Some(0u8),
        TK_FLOAT64 => Some(1),
        TK_FLOAT128 => Some(2),
        _ => None,
    };
    if let (Some(wr), Some(rr)) = (float_rank(wk), float_rank(rk)) {
        return wr <= rr;
    }
    false
}

/// The spec form of a string `TypeIdentifier` this crate holds in its inert form.
///
/// `TypeIdentifier::TK_STRING8` and `TK_STRING16` are kept as
/// `Primitive(TK_STRING8)` / `Primitive(TK_STRING16)` on purpose (see the
/// guardrail on those constants): every TypeObject built with them means an
/// UNBOUNDED string by them. A peer announces the same member as
/// `TI_STRING8_SMALL` with bound 0 (unbounded) or with its declared bound.
/// Compared as written, a string is matched against a "primitive" and found
/// not assignable, so a peer's `ShapeType` is refused against our own
/// (DDS-XTypes v1.3 Sec.7.2.4.4.5 Table 16: any narrow string is assignable
/// from any narrow string, and Sec.7.2.4.4.4 Table 15: a primitive only from
/// the same primitive). Reading the inert form as the string it denotes -
/// `StringSmall { bound: 0 }` / `WStringSmall { bound: 0 }`, the form
/// `TypeIdentifier::string(0)` builds - makes the verdict the one the spec
/// gives for the type the identifier stands for. The wire bytes are not
/// touched: this is the matcher's reading, not an encoding.
fn string_identifier_as_spec_form(id: &TypeIdentifier) -> Cow<'_, TypeIdentifier> {
    match id {
        TypeIdentifier::Primitive(TypeKind::TK_STRING8) => {
            Cow::Owned(TypeIdentifier::StringSmall { bound: 0 })
        }
        TypeIdentifier::Primitive(TypeKind::TK_STRING16) => {
            Cow::Owned(TypeIdentifier::WStringSmall { bound: 0 })
        }
        _ => Cow::Borrowed(id),
    }
}

/// Check whether a writer TypeIdentifier is assignable to a reader TypeIdentifier.
///
/// Implements XTypes v1.3 sec. 7.5.1.3 (primitive widening) and sec. 7.5.1.5 (collection
/// assignability) for the context of struct member type checking.
///
/// Rules applied per `policy`:
/// - **Primitives**: exact kind match when `prevent_type_widening=true`; widening
///   per sec. 7.5.1.3 Table 3 when `prevent_type_widening=false` (spec default).
/// - **Plain arrays**: element types must be recursively assignable AND all dimension
///   bounds must match exactly (sec. 7.5.1.5 -- array dimensions are invariant).
/// - **Plain sequences**: element types must be recursively assignable; bounds are
///   ignored when `ignore_sequence_bounds=true` (spec default); when false, the
///   writer bound must be <= the reader bound.
/// - **Strings / WStrings**: compatible if both are the same string width (8-bit or
///   16-bit); when `ignore_string_bounds=false`, the writer bound must be <= reader.
/// - **Hash-based (Minimal / Complete)**: exact hash equality required.
/// - **Cross-variant pairs**: not assignable.
fn type_id_assignable(
    writer: &TypeIdentifier,
    reader: &TypeIdentifier,
    policy: &TypeConsistencyEnforcement,
    #[cfg(feature = "xtypes-structural-assignability")] resolver: Option<&dyn TypeObjectResolver>,
) -> bool {
    use TypeIdentifier::*;
    let writer = string_identifier_as_spec_form(writer);
    let reader = string_identifier_as_spec_form(reader);
    match (writer.as_ref(), reader.as_ref()) {
        // Primitives: apply widening or exact match based on prevent_type_widening.
        // XTypes v1.3 sec. 7.5.1.3: when prevent_type_widening=false (default), allow
        // promotion within the signed int, unsigned int, and float chains.
        (Primitive(wk), Primitive(rk)) => {
            if wk == rk {
                return true;
            }
            if policy.prevent_type_widening {
                // Strict mode: writer and reader kinds must be identical.
                return false;
            }
            primitive_widening_allowed(*wk, *rk)
        }

        // Strings: assignable when both are the same width class.
        // When ignore_string_bounds=false (non-default), writer bound must be <= reader.
        // When ignore_string_bounds=true (default), bounds are irrelevant.
        // Per XTypes v1.3 sec. 7.5.1.3 strings are compatible across bounds by default.
        // bound==0 encodes "unbounded" (XTypes v1.3 sec. 7.5.1.5), so use the
        // unbounded-aware comparison rather than a naive `wb <= rb`: an
        // unbounded writer (wb==0) is only assignable to an unbounded reader
        // when bounds are enforced. Unbounded strings are emitted as
        // StringSmall{0}/WStringSmall{0} (the spec-conformant TI_STRING8_SMALL
        // encoding), so this arm carries the unbounded-writer case.
        (StringSmall { bound: wb }, StringSmall { bound: rb }) => {
            policy.ignore_string_bounds || collection_bound_ok_small(*wb, *rb)
        }
        // Cross-size pairs: the Small bound (u8) widened to u32, as for
        // sequences below. A bounded large writer fits an unbounded reader
        // (bound 0), whatever the size class each bound is written in.
        (StringSmall { bound: wb }, StringLarge { bound: rb }) => {
            policy.ignore_string_bounds || collection_bound_ok_large(u32::from(*wb), *rb)
        }
        (StringLarge { bound: wb }, StringSmall { bound: rb }) => {
            policy.ignore_string_bounds || collection_bound_ok_large(*wb, u32::from(*rb))
        }
        (StringLarge { bound: wb }, StringLarge { bound: rb }) => {
            policy.ignore_string_bounds || collection_bound_ok_large(*wb, *rb)
        }
        (WStringSmall { bound: wb }, WStringSmall { bound: rb }) => {
            policy.ignore_string_bounds || collection_bound_ok_small(*wb, *rb)
        }
        (WStringSmall { bound: wb }, WStringLarge { bound: rb }) => {
            policy.ignore_string_bounds || collection_bound_ok_large(u32::from(*wb), *rb)
        }
        (WStringLarge { bound: wb }, WStringSmall { bound: rb }) => {
            policy.ignore_string_bounds || collection_bound_ok_large(*wb, u32::from(*rb))
        }
        (WStringLarge { bound: wb }, WStringLarge { bound: rb }) => {
            policy.ignore_string_bounds || collection_bound_ok_large(*wb, *rb)
        }

        // Hash-based complex types: exact hash match (fast path).
        // With xtypes-structural-assignability: when hashes differ, ALLOW_TYPE_COERCION is
        // active, and a resolver can supply both TypeObjects, fall back to structural
        // assignability (XTypes v1.3 sec. 7.5.1).
        //
        // Nested types referenced by hash (e.g. a FINAL struct used as an array or
        // sequence element) are recursed into with the CALLER'S policy UNCHANGED.
        // A hash mismatch is only a fast-path miss, not proof of structural
        // inequivalence: XTypes v1.3 section 7.5.1.2 hash equality is a sufficient, not
        // necessary, condition for FINAL equivalence once ALLOW_TYPE_COERCION is in
        // effect (see is_assignable_final's own hash-miss member-by-member
        // fallback, which already gates its name check on ignore_member_names).
        // Per section 7.6.3.4.2 Step 1, the ignore_member_names relaxation applies to
        // "the_type" of the Subscription/Publication as a whole; nesting depth
        // does not reset the policy to strict. Previously this arm forced
        // ignore_member_names=false whenever both resolved types were FINAL
        // structs, which made OMG xtypes_v2_array_test_suite
        // SFinal[10]_S[20]_SFinalAlt[10]_S[20] and the matching
        // xtypes_v2_sequence_test_suite case (element structs identical except for
        // a renamed member, e.g. F_S__array20_uint32 "x1" vs
        // F_S__array20_uint32_alt "altx1") wrongly report INCONSISTENT_TOPIC under
        // the suite's default permissive policy (ignore_member_names=true). The
        // top-level FINAL struct comparison already tolerates exactly this kind of
        // name-only difference (struct_different_names_ok); nested FINAL structs
        // must be treated no differently since both are the same "the_type" the
        // policy is scoped to.
        (Minimal(wh), Minimal(rh)) => {
            if wh == rh {
                return true;
            }
            #[cfg(feature = "xtypes-structural-assignability")]
            if policy.kind != 0 {
                if let Some(res) = resolver {
                    if let (Some(w_obj), Some(r_obj)) =
                        (res.resolve_minimal(wh), res.resolve_minimal(rh))
                    {
                        return is_assignable_to_with_policy(w_obj, r_obj, policy, Some(res));
                    }
                }
            }
            false
        }
        (Complete(wh), Complete(rh)) => {
            if wh == rh {
                return true;
            }
            #[cfg(feature = "xtypes-structural-assignability")]
            if policy.kind != 0 {
                if let Some(res) = resolver {
                    if let (Some(w_obj), Some(r_obj)) =
                        (res.resolve_complete(wh), res.resolve_complete(rh))
                    {
                        return is_assignable_to_with_policy(w_obj, r_obj, policy, Some(res));
                    }
                }
            }
            false
        }

        // One side names the type by its COMPLETE hash, the other by its
        // MINIMAL hash: a peer's COMPLETE TypeObject (answered by getTypes)
        // references its member types with EK_COMPLETE identifiers, a local
        // TypeObject with EK_MINIMAL ones (DDS-XTypes v1.3 7.3.4.5). Two
        // identifiers of different kinds are not comparable as values, but
        // assignability is a relation between TYPES (7.6.3.4.2 Step 1): each
        // is resolved by its own kind and the types are compared, under the
        // same nested-FINAL name strictness as the arms above. An identifier
        // that does not resolve keeps the old answer, not assignable.
        #[cfg(feature = "xtypes-structural-assignability")]
        (Complete(wh), Minimal(rh)) if policy.kind != 0 => resolver
            .and_then(|res| Some((res.resolve_complete(wh)?, res.resolve_minimal(rh)?, res)))
            .is_some_and(|(w_obj, r_obj, res)| nested_assignable(w_obj, r_obj, policy, res)),
        #[cfg(feature = "xtypes-structural-assignability")]
        (Minimal(wh), Complete(rh)) if policy.kind != 0 => resolver
            .and_then(|res| Some((res.resolve_minimal(wh)?, res.resolve_complete(rh)?, res)))
            .is_some_and(|(w_obj, r_obj, res)| nested_assignable(w_obj, r_obj, policy, res)),

        // Preserve bitmask/integer assignability after retaining named
        // bitmask identities in struct and collection member identifiers.
        #[cfg(feature = "xtypes-structural-assignability")]
        (Primitive(pk), Minimal(hash)) | (Minimal(hash), Primitive(pk)) if policy.kind != 0 => {
            bitmask_holder_matches(*pk, hash, false, resolver)
        }
        #[cfg(feature = "xtypes-structural-assignability")]
        (Primitive(pk), Complete(hash)) | (Complete(hash), Primitive(pk)) if policy.kind != 0 => {
            bitmask_holder_matches(*pk, hash, true, resolver)
        }

        // Plain arrays: element assignable AND every dimension bound must match
        // exactly per XTypes v1.3 sec. 7.5.1.5 (arrays are NOT covariant in size).
        (PlainArraySmall(w), PlainArraySmall(r)) => {
            w.array_bound_seq == r.array_bound_seq
                && type_id_assignable(
                    &w.element_identifier,
                    &r.element_identifier,
                    policy,
                    #[cfg(feature = "xtypes-structural-assignability")]
                    resolver,
                )
        }
        (PlainArrayLarge(w), PlainArrayLarge(r)) => {
            w.array_bound_seq == r.array_bound_seq
                && type_id_assignable(
                    &w.element_identifier,
                    &r.element_identifier,
                    policy,
                    #[cfg(feature = "xtypes-structural-assignability")]
                    resolver,
                )
        }
        // Small vs Large array: dimension vectors have different element types
        // (u8 vs u32); treat as incompatible rather than converting.
        (PlainArraySmall(_), PlainArrayLarge(_)) => false,
        (PlainArrayLarge(_), PlainArraySmall(_)) => false,

        // Plain sequences: element type assignable; bounds handled by policy.
        //
        // XTypes v1.3 sec. 7.5.1.5: when ignore_sequence_bounds=false, the writer
        // bound must be <= the reader bound to prevent overflow. Bound=0 on the
        // wire encodes "unbounded" (no explicit maximum). An unbounded writer
        // (bound=0) is treated as having infinite capacity; it cannot safely be
        // assigned to a bounded reader (bound>0) when bounds are enforced,
        // because the writer may produce more elements than the reader accepts.
        //
        // Concretely: collection_bound_ok(w, r) is:
        //   - true  when ignore_sequence_bounds=true (policy default)
        //   - true  when both are unbounded (w==0, r==0)
        //   - true  when writer is bounded (w>0) and w <= r
        //   - false when writer is unbounded (w==0) and reader is bounded (r>0)
        //   - false when writer bound > reader bound and bounds are enforced
        (PlainSequenceSmall(w), PlainSequenceSmall(r)) => {
            (policy.ignore_sequence_bounds || collection_bound_ok_small(w.bound, r.bound))
                && type_id_assignable(
                    &w.element_identifier,
                    &r.element_identifier,
                    policy,
                    #[cfg(feature = "xtypes-structural-assignability")]
                    resolver,
                )
        }
        (PlainSequenceLarge(w), PlainSequenceLarge(r)) => {
            (policy.ignore_sequence_bounds || collection_bound_ok_large(w.bound, r.bound))
                && type_id_assignable(
                    &w.element_identifier,
                    &r.element_identifier,
                    policy,
                    #[cfg(feature = "xtypes-structural-assignability")]
                    resolver,
                )
        }
        // Cross-size pairs: Small bound (u8) vs Large bound (u32).
        // When bounds are ignored the only check is element assignability.
        // When bounds matter: Small.bound (u8) is widened to u32 for comparison.
        (PlainSequenceSmall(w), PlainSequenceLarge(r)) => {
            (policy.ignore_sequence_bounds
                || collection_bound_ok_large(u32::from(w.bound), r.bound))
                && type_id_assignable(
                    &w.element_identifier,
                    &r.element_identifier,
                    policy,
                    #[cfg(feature = "xtypes-structural-assignability")]
                    resolver,
                )
        }
        (PlainSequenceLarge(w), PlainSequenceSmall(r)) => {
            (policy.ignore_sequence_bounds
                || collection_bound_ok_large(w.bound, u32::from(r.bound)))
                && type_id_assignable(
                    &w.element_identifier,
                    &r.element_identifier,
                    policy,
                    #[cfg(feature = "xtypes-structural-assignability")]
                    resolver,
                )
        }

        // Plain maps: key and element types must be recursively assignable.
        // Bounds follow the same unbounded-writer (w==0) semantics as
        // sequences -- an unbounded writer cannot fit a bounded reader.
        (PlainMapSmall(w), PlainMapSmall(r)) => {
            (policy.ignore_sequence_bounds || collection_bound_ok_small(w.bound, r.bound))
                && type_id_assignable(
                    &w.key_identifier,
                    &r.key_identifier,
                    policy,
                    #[cfg(feature = "xtypes-structural-assignability")]
                    resolver,
                )
                && type_id_assignable(
                    &w.element_identifier,
                    &r.element_identifier,
                    policy,
                    #[cfg(feature = "xtypes-structural-assignability")]
                    resolver,
                )
        }
        (PlainMapLarge(w), PlainMapLarge(r)) => {
            (policy.ignore_sequence_bounds || collection_bound_ok_large(w.bound, r.bound))
                && type_id_assignable(
                    &w.key_identifier,
                    &r.key_identifier,
                    policy,
                    #[cfg(feature = "xtypes-structural-assignability")]
                    resolver,
                )
                && type_id_assignable(
                    &w.element_identifier,
                    &r.element_identifier,
                    policy,
                    #[cfg(feature = "xtypes-structural-assignability")]
                    resolver,
                )
        }
        (PlainMapSmall(w), PlainMapLarge(r)) => {
            (policy.ignore_sequence_bounds
                || collection_bound_ok_large(u32::from(w.bound), r.bound))
                && type_id_assignable(
                    &w.key_identifier,
                    &r.key_identifier,
                    policy,
                    #[cfg(feature = "xtypes-structural-assignability")]
                    resolver,
                )
                && type_id_assignable(
                    &w.element_identifier,
                    &r.element_identifier,
                    policy,
                    #[cfg(feature = "xtypes-structural-assignability")]
                    resolver,
                )
        }
        (PlainMapLarge(w), PlainMapSmall(r)) => {
            (policy.ignore_sequence_bounds
                || collection_bound_ok_large(w.bound, u32::from(r.bound)))
                && type_id_assignable(
                    &w.key_identifier,
                    &r.key_identifier,
                    policy,
                    #[cfg(feature = "xtypes-structural-assignability")]
                    resolver,
                )
                && type_id_assignable(
                    &w.element_identifier,
                    &r.element_identifier,
                    policy,
                    #[cfg(feature = "xtypes-structural-assignability")]
                    resolver,
                )
        }

        // Strongly connected components (cyclic types): per XTypes v1.3 sec. 7.3.4.5
        // SCC types are identified by the hash of the component and the index
        // within the component. Two SCC references with the same component hash
        // and the same index refer to the same type position in the same SCC.
        (StronglyConnected(w), StronglyConnected(r)) => {
            w.sc_component_id == r.sc_component_id && w.scc_index == r.scc_index
        }

        // All other cross-variant combinations are not assignable.
        _ => {
            log::debug!(
                "type_id_assignable: incompatible cross-variant pair \
                 (writer={:?}, reader={:?})",
                std::mem::discriminant(writer.as_ref()),
                std::mem::discriminant(reader.as_ref()),
            );
            false
        }
    }
}

/// Assignability of two types referenced by hash from inside other types
/// (the mixed Minimal/Complete arms of `type_id_assignable`), with the
/// CALLER'S policy unchanged, exactly like the same-kind hash arms: the
/// ignore_member_names relaxation is scoped to the topic type as a whole and
/// nesting depth does not reset it to strict. The OMG dds-xtypes suite
/// expects OK for FINAL element structs that differ only by a member name
/// (SFinal[10]_S[20]_SFinalAlt[10]_S[20], seq(SFinal,10)_seq(SFinalAlt,10)),
/// and a verdict must not depend on whether the peer referenced the element
/// type by a Minimal or a Complete hash.
#[cfg(feature = "xtypes-structural-assignability")]
fn nested_assignable(
    w_obj: &CompleteTypeObject,
    r_obj: &CompleteTypeObject,
    policy: &TypeConsistencyEnforcement,
    res: &dyn TypeObjectResolver,
) -> bool {
    is_assignable_to_with_policy(w_obj, r_obj, policy, Some(res))
}

/// A hash reference `unresolved_type_refs` could not resolve.
#[cfg(feature = "xtypes-structural-assignability")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct UnresolvedRef {
    /// The hash referenced.
    pub hash: crate::xtypes::EquivalenceHash,
    /// `true` for an EK_COMPLETE identifier, `false` for EK_MINIMAL: the
    /// kind it must be looked up by.
    pub complete: bool,
}

/// The hash-referenced types reachable from `obj` that `resolver` cannot
/// resolve, transitively, descending through plain collection identifiers,
/// each once, with its kind. Empty when the whole type graph is known.
/// Bounded: at most 4096 types are visited, and the walk stops there (what
/// it found so far is returned).
#[cfg(feature = "xtypes-structural-assignability")]
pub(crate) fn unresolved_type_refs(
    obj: &CompleteTypeObject,
    resolver: &dyn TypeObjectResolver,
) -> Vec<UnresolvedRef> {
    use std::collections::HashSet;

    fn direct_ids(obj: &CompleteTypeObject) -> Vec<&TypeIdentifier> {
        let mut ids: Vec<&TypeIdentifier> = Vec::new();
        match obj {
            CompleteTypeObject::Struct(s) => {
                ids.extend(s.header.base_type.as_ref());
                ids.extend(s.member_seq.iter().map(|m| &m.common.member_type_id));
            }
            CompleteTypeObject::Union(u) => {
                ids.push(&u.header.discriminator);
                ids.extend(u.member_seq.iter().map(|m| &m.common.member_type_id));
            }
            CompleteTypeObject::Sequence(s) => ids.push(&s.element.type_id),
            CompleteTypeObject::Array(a) => ids.push(&a.element.type_id),
            CompleteTypeObject::Map(m) => {
                ids.push(&m.key.type_id);
                ids.push(&m.element.type_id);
            }
            CompleteTypeObject::Alias(a) => ids.push(&a.body.common.related_type),
            _ => {}
        }
        ids
    }

    // (hash, is_complete) of every hash identifier inside `tid`.
    fn hash_refs(tid: &TypeIdentifier, out: &mut Vec<(crate::xtypes::EquivalenceHash, bool)>) {
        use TypeIdentifier::*;
        match tid {
            Minimal(h) => out.push((*h, false)),
            Complete(h) => out.push((*h, true)),
            PlainSequenceSmall(d) => hash_refs(&d.element_identifier, out),
            PlainSequenceLarge(d) => hash_refs(&d.element_identifier, out),
            PlainArraySmall(d) => hash_refs(&d.element_identifier, out),
            PlainArrayLarge(d) => hash_refs(&d.element_identifier, out),
            PlainMapSmall(d) => {
                hash_refs(&d.key_identifier, out);
                hash_refs(&d.element_identifier, out);
            }
            PlainMapLarge(d) => {
                hash_refs(&d.key_identifier, out);
                hash_refs(&d.element_identifier, out);
            }
            _ => {}
        }
    }

    let mut seen: HashSet<crate::xtypes::EquivalenceHash> = HashSet::new();
    let mut missing = Vec::new();
    let mut stack: Vec<&CompleteTypeObject> = vec![obj];
    let mut budget = 4096usize;
    while let Some(current) = stack.pop() {
        if budget == 0 {
            break;
        }
        budget -= 1;
        let mut refs = Vec::new();
        for tid in direct_ids(current) {
            hash_refs(tid, &mut refs);
        }
        for (hash, is_complete) in refs {
            if !seen.insert(hash) {
                continue;
            }
            let resolved = if is_complete {
                resolver.resolve_complete(&hash)
            } else {
                resolver.resolve_minimal(&hash)
            };
            match resolved {
                Some(next) => stack.push(next),
                None => missing.push(UnresolvedRef {
                    hash,
                    complete: is_complete,
                }),
            }
        }
    }
    missing
}

/// Build a `MinimalStructType` from a `CompleteStructType`.
///
/// Per XTypes v1.3 sec. 7.3.4.8, FINAL struct equivalence is determined by the
/// Minimal TypeObject hash. The Minimal representation drops the type name
/// (empty `MinimalTypeDetail`) but retains 32-bit member name hashes
/// (`MinimalMemberDetail.name_hash = MD5(member_name)[0..4]`). Member IDs,
/// flags, and member type identifiers are preserved unchanged.
fn complete_to_minimal_struct(complete: &CompleteStructType) -> MinimalStructType {
    MinimalStructType {
        struct_flags: complete.struct_flags,
        header: MinimalStructHeader {
            base_type: complete.header.base_type.clone(),
            detail: MinimalTypeDetail::new(),
        },
        member_seq: complete
            .member_seq
            .iter()
            .map(|m| MinimalStructMember {
                common: m.common.clone(),
                detail: MinimalMemberDetail::from_name(&m.detail.name),
            })
            .collect(),
    }
}

fn is_assignable_final(
    writer: &CompleteStructType,
    reader: &CompleteStructType,
    policy: &TypeConsistencyEnforcement,
    #[cfg(feature = "xtypes-structural-assignability")] resolver: Option<&dyn TypeObjectResolver>,
) -> bool {
    // Per XTypes v1.3 sec. 7.5.1.2, FINAL type equivalence uses the Minimal
    // TypeObject hash (not Complete). The Minimal hash excludes the type_name
    // but includes each member's name_hash, so types with identical structure
    // but different member names are not equivalent.
    //
    // When ALLOW_TYPE_COERCION is in effect, the TypeConsistencyEnforcement
    // policy (sec. 7.6.3.4) can relax bound-only differences: ignore_sequence_bounds
    // and ignore_string_bounds allow FINAL types whose members differ only in
    // sequence/string bound values to be considered assignable. The hash check
    // is attempted first (fast path). If hashes differ, a policy-aware member-
    // by-member comparison is attempted as a secondary check -- this correctly
    // handles cases where the hash difference is solely due to a bound value
    // that the policy elects to ignore.
    let writer_minimal = complete_to_minimal_struct(writer);
    let reader_minimal = complete_to_minimal_struct(reader);
    let writer_obj = MinimalTypeObject::Struct(writer_minimal);
    let reader_obj = MinimalTypeObject::Struct(reader_minimal);

    let writer_hash = writer_obj.compute_equivalence_hash();
    let reader_hash = reader_obj.compute_equivalence_hash();

    match (&writer_hash, &reader_hash) {
        (Ok(wh), Ok(rh)) => {
            if *wh == crate::xtypes::EquivalenceHash::zero()
                && *rh == crate::xtypes::EquivalenceHash::zero()
            {
                // Zero hashes: xtypes feature disabled or CDR encoder produced
                // no bytes. Use member-by-member comparison with the policy.
                // Force prevent_type_widening=true: in FINAL equivalence, hash
                // differences caused by primitive type changes (uint8 vs uint16)
                // are never acceptable. Only bound-only relaxations (ignore_sequence_
                // bounds / ignore_string_bounds) survive. sec. 7.5.1.2 + sec. 7.5.1.3.
                let strict = TypeConsistencyEnforcement {
                    prevent_type_widening: true,
                    ..policy.clone()
                };
                members_assignable_final_with_policy(
                    writer,
                    reader,
                    &strict,
                    #[cfg(feature = "xtypes-structural-assignability")]
                    resolver,
                )
            } else if wh == rh {
                true
            } else {
                // Hashes differ: the types are not strongly equivalent. However
                // when ALLOW_TYPE_COERCION is active and the policy ignores
                // collection bounds (ignore_sequence_bounds / ignore_string_bounds),
                // a difference that is solely due to bound values must still be
                // accepted per sec. 7.6.3.4. Fall back to a policy-aware structural
                // check that respects those relaxations while still enforcing
                // member count, member IDs (by position), and member name hashes.
                //
                // Force prevent_type_widening=true for the same reason as above:
                // primitive type changes alter structural identity and are never
                // a "bound-only" difference that sec. 7.6.3.4 relaxes.
                if policy.kind == 0 {
                    // DISALLOW_TYPE_COERCION: strict hash equality only.
                    false
                } else {
                    // FINAL structural fallback: only accept hash-different FINAL
                    // types when the difference is SOLELY in collection/string
                    // bounds (which the policy may elect to ignore per sec. 7.6.3.4).
                    // prevent_type_widening is forced ON: primitive type changes
                    // alter structural identity and are never a "bound-only" diff.
                    //
                    // NOTE: ignore_member_names is NOT forced OFF here. The policy
                    // default (ignore_member_names=true) intentionally allows FINAL
                    // structs with different member names to be compatible at the
                    // top level under ALLOW_TYPE_COERCION (see OMG test
                    // struct_different_names_ok). Name-strict enforcement for NESTED
                    // FINAL types referenced by EK_MINIMAL hash is handled in
                    // type_id_assignable (where the hash itself encodes the name).
                    let strict = TypeConsistencyEnforcement {
                        prevent_type_widening: true,
                        ..policy.clone()
                    };
                    members_assignable_final_with_policy(
                        writer,
                        reader,
                        &strict,
                        #[cfg(feature = "xtypes-structural-assignability")]
                        resolver,
                    )
                }
            }
        }
        _ => false,
    }
}

/// Policy-aware member-by-member structural comparison for FINAL types.
///
/// Used as a fallback when EquivalenceHash is unavailable (xtypes feature off)
/// or as a secondary check after a hash miss when ALLOW_TYPE_COERCION is active.
///
/// Per XTypes v1.3 sec. 7.5.1.2, FINAL types require:
///   - Identical member count (FINAL is not extensible; no extra members allowed)
///   - Same member IDs in order (positional matching for FINAL)
///   - Member name hashes must match (names are part of FINAL equivalence)
///   - Each member type assignable under the supplied policy
///
/// The policy controls whether collection bounds and string bounds are
/// checked strictly (`ignore_sequence_bounds=false`) or relaxed
/// (`ignore_sequence_bounds=true`, the spec default). Type widening is
/// controlled by `prevent_type_widening`; for FINAL the caller already
/// enforces that the policy setting is respected.
///
/// TC (TryConstruct) bits in MemberFlags annotate the reader's decoding
/// behavior and are NOT part of structural identity. They are masked out
/// before comparing member IDs to avoid false mismatches between a type
/// without TC bits (writer) and the same type with TC bits (reader).
fn members_assignable_final_with_policy(
    writer: &CompleteStructType,
    reader: &CompleteStructType,
    policy: &TypeConsistencyEnforcement,
    #[cfg(feature = "xtypes-structural-assignability")] resolver: Option<&dyn TypeObjectResolver>,
) -> bool {
    if writer.member_seq.len() != reader.member_seq.len() {
        return false;
    }
    // TC bit mask: exclude TRY_CONSTRUCT1 (0x0001) and TRY_CONSTRUCT2 (0x0002)
    // from the flags comparison. These bits annotate reader-side decoding policy
    // and must not affect the structural identity check.
    const TC_MASK: u16 = !(MemberFlag::TRY_CONSTRUCT1.0 | MemberFlag::TRY_CONSTRUCT2.0);
    for (w, r) in writer.member_seq.iter().zip(reader.member_seq.iter()) {
        // Member IDs must match in position order (FINAL positional matching).
        if w.common.member_id != r.common.member_id {
            return false;
        }
        // Member name hashes must agree when the reader's TypeConsistencyEnforcement
        // explicitly sets ignore_member_names=false. Under the matcher default policy
        // (no explicit QoS, ignore_member_names=true) name differences are accepted.
        // Per XTypes v1.3 sec. 7.6.3.4, name enforcement is an opt-in strictness.
        if !policy.ignore_member_names {
            let w_name_hash = MinimalMemberDetail::from_name(w.detail.hash_name()).name_hash;
            let r_name_hash = MinimalMemberDetail::from_name(r.detail.hash_name()).name_hash;
            if w_name_hash != r_name_hash {
                return false;
            }
        }
        // Key flag must agree: key membership is structural.
        let w_flags_struct = MemberFlag(w.common.member_flags.0 & TC_MASK);
        let r_flags_struct = MemberFlag(r.common.member_flags.0 & TC_MASK);
        let w_is_key = w_flags_struct.contains(MemberFlag::IS_KEY);
        let r_is_key = r_flags_struct.contains(MemberFlag::IS_KEY);
        if w_is_key != r_is_key {
            return false;
        }
        // Member type assignability under the policy (handles sequence/string bounds).
        if !type_id_assignable(
            &w.common.member_type_id,
            &r.common.member_type_id,
            policy,
            #[cfg(feature = "xtypes-structural-assignability")]
            resolver,
        ) {
            return false;
        }
    }
    true
}

fn is_assignable_appendable(
    writer: &CompleteStructType,
    reader: &CompleteStructType,
    policy: &TypeConsistencyEnforcement,
    #[cfg(feature = "xtypes-structural-assignability")] resolver: Option<&dyn TypeObjectResolver>,
) -> bool {
    // Per XTypes v1.3 sec. 7.5.1.1.2 (APPENDABLE assignability):
    //
    // Members are matched by member_id (not by declaration position). For each
    // reader member:
    //   - If the writer has a member with the same member_id: types must be
    //     assignable under the policy, and (when ignore_member_names=false)
    //     names must agree (XTypes v1.3 sec. 7.3.1.2 name/ID coherence).
    //   - If the writer has no member with that member_id: the member is absent
    //     on the wire; the reader fills it with its type default.
    //     IS_MUST_UNDERSTAND makes the type incompatible (sec. 7.6.2.4).
    //     prevent_type_widening=true also rejects absent-writer members.
    //
    // When both types are non-empty, at least one member_id must be shared
    // (sec. 7.5.1.1.2 preamble: types with no common member carry no overlapping
    // data and are not assignable). This mirrors MUTABLE behaviour and is
    // consistent with all major DDS vendor implementations.
    //
    // Writer members without a matching reader member_id are silently ignored.

    // Build a member_id -> writer member lookup for O(1) per-reader-member search.
    // sec. 7.5.1.1.2 matching is by member_id, not declaration order.
    let writer_id_map: HashMap<u32, &_> = writer
        .member_seq
        .iter()
        .map(|m| (m.common.member_id, m))
        .collect();

    let mut common_count: usize = 0;

    for reader_member in &reader.member_seq {
        let reader_id = reader_member.common.member_id;

        match writer_id_map.get(&reader_id) {
            Some(writer_member) => {
                common_count += 1;

                // Name consistency (sec. 7.3.1.2): when names are relevant, the
                // writer member with the same ID must carry the same name.
                if !policy.ignore_member_names
                    && writer_member.detail.name != reader_member.detail.name
                {
                    return false;
                }

                if !type_id_assignable(
                    &writer_member.common.member_type_id,
                    &reader_member.common.member_type_id,
                    policy,
                    #[cfg(feature = "xtypes-structural-assignability")]
                    resolver,
                ) {
                    return false;
                }
            }
            None => {
                // Reader member has no writer counterpart.
                // Per sec. 7.5.1.1.2 the reader fills it with the type default.
                // IS_MUST_UNDERSTAND (sec. 7.6.2.4) makes the absence incompatible.
                // prevent_type_widening (sec. 7.6.3.3) also rejects absent-writer members.
                if policy.prevent_type_widening
                    || reader_member
                        .common
                        .member_flags
                        .contains(MemberFlag::IS_MUST_UNDERSTAND)
                {
                    return false;
                }
            }
        }
    }

    // Per sec. 7.5.1.1.2: when both types have members, at least one member_id must
    // be shared. Types whose member ID sets are fully disjoint carry no common
    // data and are not assignable regardless of individual member assignability.
    if !writer.member_seq.is_empty() && !reader.member_seq.is_empty() && common_count == 0 {
        return false;
    }

    // Per sec. 7.6.2.4: each writer member flagged IS_MUST_UNDERSTAND must have a
    // corresponding reader member with the same member_id. If no such reader
    // member exists, the reader cannot understand the field it is required to
    // understand -> types are incompatible.
    for writer_member in &writer.member_seq {
        if writer_member
            .common
            .member_flags
            .contains(MemberFlag::IS_MUST_UNDERSTAND)
        {
            let has_reader_match = reader
                .member_seq
                .iter()
                .any(|r| r.common.member_id == writer_member.common.member_id);
            if !has_reader_match {
                return false;
            }
        }
    }

    true
}

fn is_assignable_mutable(
    writer: &CompleteStructType,
    reader: &CompleteStructType,
    policy: &TypeConsistencyEnforcement,
    #[cfg(feature = "xtypes-structural-assignability")] resolver: Option<&dyn TypeObjectResolver>,
) -> bool {
    // Per XTypes v1.3 sec. 7.5.2.1.1.4 (Mutable struct assignability):
    //
    // Members are matched exclusively by member_id. Order and count do not
    // matter. For each reader member:
    //
    //   - If the writer has a member with the same ID: the writer member type
    //     must be assignable to the reader member type. When `ignore_member_names`
    //     is false the names must also match (sec. 7.3.1.2: the ID/name pair is the
    //     member's canonical identity; a same-ID/different-name pair is a
    //     remapping, not an evolution, and is incompatible).
    //
    //   - If no writer member has that ID:
    //     - IS_MUST_UNDERSTAND set: incompatible.
    //     - IS_MUST_UNDERSTAND not set: compatible; reader uses default or skips.
    //
    // When `ignore_member_names=false` an additional cross-check applies:
    // if the writer contains a member whose name equals the reader member's name
    // but whose ID differs, the types are incompatible. This enforces that name
    // and ID are jointly consistent (XTypes v1.3 sec. 7.3.1.2 name/ID coherence).
    //
    // Writer members that have no matching reader member are silently ignored.
    //
    // Pre-condition (sec. 7.5.2.1.1.4 preamble): at least one member_id must be
    // shared between writer and reader when both types are non-empty. Two
    // mutable types with completely disjoint member ID sets carry no common
    // data and are not assignable. This matches the OMG reference test
    // suite's struct_no_common_ids case.
    // Empty member_seq is not checked here: the per-reader loop below handles
    // the empty-writer or empty-reader case naturally.
    if !writer.member_seq.is_empty() && !reader.member_seq.is_empty() {
        let has_common_id = writer.member_seq.iter().any(|w| {
            reader
                .member_seq
                .iter()
                .any(|r| r.common.member_id == w.common.member_id)
        });
        if !has_common_id {
            return false;
        }
    }

    for reader_member in &reader.member_seq {
        let reader_id = reader_member.common.member_id;
        let reader_name = &reader_member.detail.name;

        let writer_match = writer
            .member_seq
            .iter()
            .find(|w| w.common.member_id == reader_id);

        match writer_match {
            Some(writer_member) => {
                // Name consistency check: when names are relevant, the matched
                // writer member must carry the same name as the reader member.
                // A member pair with matching ID but different names indicates
                // a conflicting remapping (XTypes v1.3 sec. 7.3.1.2).
                if !policy.ignore_member_names && writer_member.detail.name != *reader_name {
                    return false;
                }
                if !type_id_assignable(
                    &writer_member.common.member_type_id,
                    &reader_member.common.member_type_id,
                    policy,
                    #[cfg(feature = "xtypes-structural-assignability")]
                    resolver,
                ) {
                    return false;
                }
            }
            None => {
                // Reader has a member the writer does not. Incompatible when:
                //   - The reader requires the field to be understood, OR
                //   - prevent_type_widening=true: the reader's type is
                //     evolutionarily wider than the writer's (XTypes v1.3 sec. 7.6.3.3).
                if policy.prevent_type_widening
                    || reader_member
                        .common
                        .member_flags
                        .contains(MemberFlag::IS_MUST_UNDERSTAND)
                {
                    return false;
                }
                // Per XTypes v1.3 sec. 7.5.2.1.1.4 a reader member absent from the writer
                // is filled with the type default (unless MUST_UNDERSTAND or
                // prevent_type_widening, checked above). When the reader's policy
                // explicitly enforces ignore_member_names=false, also check that the
                // writer does not carry a same-named member under a DIFFERENT ID:
                // that would indicate conflicting field identity (sec. 7.3.1.2).
                if !policy.ignore_member_names {
                    let writer_same_name = writer
                        .member_seq
                        .iter()
                        .find(|w| w.detail.name == *reader_name);
                    if let Some(w) = writer_same_name {
                        if w.common.member_id != reader_id {
                            return false;
                        }
                    }
                }
            }
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xtypes::{
        CommonStructMember, CompleteMemberDetail, CompleteStructHeader, CompleteStructMember,
        CompleteStructType, CompleteTypeDetail, StructTypeFlag, TypeIdentifier,
    };

    fn appendable_1(name: &str, id: u32) -> CompleteStructType {
        CompleteStructType {
            struct_flags: StructTypeFlag::IS_APPENDABLE,
            header: CompleteStructHeader {
                base_type: None,
                detail: CompleteTypeDetail::new("S"),
            },
            member_seq: vec![CompleteStructMember {
                common: CommonStructMember {
                    member_id: id,
                    member_flags: MemberFlag::empty(),
                    member_type_id: TypeIdentifier::TK_INT32,
                },
                detail: CompleteMemberDetail::new(name),
            }],
        }
    }

    fn appendable_2(n1: &str, id1: u32, n2: &str, id2: u32) -> CompleteStructType {
        CompleteStructType {
            struct_flags: StructTypeFlag::IS_APPENDABLE,
            header: CompleteStructHeader {
                base_type: None,
                detail: CompleteTypeDetail::new("S"),
            },
            member_seq: vec![
                CompleteStructMember {
                    common: CommonStructMember {
                        member_id: id1,
                        member_flags: MemberFlag::empty(),
                        member_type_id: TypeIdentifier::TK_INT32,
                    },
                    detail: CompleteMemberDetail::new(n1),
                },
                CompleteStructMember {
                    common: CommonStructMember {
                        member_id: id2,
                        member_flags: MemberFlag::empty(),
                        member_type_id: TypeIdentifier::TK_INT32,
                    },
                    detail: CompleteMemberDetail::new(n2),
                },
            ],
        }
    }

    fn mutable_1(name: &str, id: u32) -> CompleteStructType {
        CompleteStructType {
            struct_flags: StructTypeFlag::IS_MUTABLE,
            header: CompleteStructHeader {
                base_type: None,
                detail: CompleteTypeDetail::new("M"),
            },
            member_seq: vec![CompleteStructMember {
                common: CommonStructMember {
                    member_id: id,
                    member_flags: MemberFlag::empty(),
                    member_type_id: TypeIdentifier::TK_INT32,
                },
                detail: CompleteMemberDetail::new(name),
            }],
        }
    }

    fn mutable_2(n1: &str, id1: u32, n2: &str, id2: u32) -> CompleteStructType {
        CompleteStructType {
            struct_flags: StructTypeFlag::IS_MUTABLE,
            header: CompleteStructHeader {
                base_type: None,
                detail: CompleteTypeDetail::new("M"),
            },
            member_seq: vec![
                CompleteStructMember {
                    common: CommonStructMember {
                        member_id: id1,
                        member_flags: MemberFlag::empty(),
                        member_type_id: TypeIdentifier::TK_INT32,
                    },
                    detail: CompleteMemberDetail::new(n1),
                },
                CompleteStructMember {
                    common: CommonStructMember {
                        member_id: id2,
                        member_flags: MemberFlag::empty(),
                        member_type_id: TypeIdentifier::TK_INT32,
                    },
                    detail: CompleteMemberDetail::new(n2),
                },
            ],
        }
    }

    fn ptw_true() -> TypeConsistencyEnforcement {
        TypeConsistencyEnforcement {
            prevent_type_widening: true,
            ..Default::default()
        }
    }

    fn ptw_false() -> TypeConsistencyEnforcement {
        TypeConsistencyEnforcement {
            prevent_type_widening: false,
            ..Default::default()
        }
    }

    /// prevent_type_widening=true blocks APPENDABLE reader wider than writer.
    /// Mirrors tc_prevent_type_widening_4: writer=struct_a1 (1 member), reader=struct_a2 (2).
    #[test]
    fn appendable_ptw_true_blocks_wider_reader() {
        assert!(
            !is_assignable_appendable(
                &appendable_1("x1", 0),
                &appendable_2("x1", 0, "x2", 1),
                &ptw_true(),
                #[cfg(feature = "xtypes-structural-assignability")] None
            ),
            "APPENDABLE reader with extra member must be incompatible when prevent_type_widening=true"
        );
    }

    /// prevent_type_widening=false allows APPENDABLE reader wider than writer.
    /// Mirrors tc_prevent_type_widening_5/6.
    #[test]
    fn appendable_ptw_false_allows_wider_reader() {
        assert!(
            is_assignable_appendable(
                &appendable_1("x1", 0),
                &appendable_2("x1", 0, "x2", 1),
                &ptw_false(),
                #[cfg(feature = "xtypes-structural-assignability")] None
            ),
            "APPENDABLE reader with extra non-must-understand member must be compatible when prevent_type_widening=false"
        );
    }

    /// prevent_type_widening=true blocks MUTABLE reader wider than writer.
    /// Mirrors tc_prevent_type_widening_7: writer=struct_m1 (id=1), reader=struct_m2 (id=1,2).
    #[test]
    fn mutable_ptw_true_blocks_wider_reader() {
        assert!(
            !is_assignable_mutable(
                &mutable_1("x1", 1),
                &mutable_2("x1", 1, "x2", 2),
                &ptw_true(),
                #[cfg(feature = "xtypes-structural-assignability")]
                None
            ),
            "MUTABLE reader with extra member must be incompatible when prevent_type_widening=true"
        );
    }

    /// prevent_type_widening=false allows MUTABLE reader wider than writer.
    /// Mirrors tc_prevent_type_widening_8/9: writer=struct_m1, reader=struct_m2, PTW=false/default.
    #[test]
    fn mutable_ptw_false_allows_wider_reader() {
        assert!(
            is_assignable_mutable(
                &mutable_1("x1", 1),
                &mutable_2("x1", 1, "x2", 2),
                &ptw_false(),
                #[cfg(feature = "xtypes-structural-assignability")] None
            ),
            "MUTABLE reader with extra non-must-understand member must be compatible when prevent_type_widening=false"
        );
    }

    /// ignore_member_names=true makes same-position structs with differing names compatible.
    /// Mirrors tc_ignore_member_names_1: writer has member "x1", reader has "x2" at same index.
    #[test]
    fn appendable_ignore_names_allows_name_mismatch() {
        let policy = TypeConsistencyEnforcement {
            ignore_member_names: true,
            ..Default::default()
        };
        assert!(
            is_assignable_appendable(
                &appendable_1("x1", 0),
                &appendable_1("x2", 0),
                &policy,
                #[cfg(feature = "xtypes-structural-assignability")] None
            ),
            "APPENDABLE structs with differing names must be compatible when ignore_member_names=true"
        );
    }

    /// ignore_member_names=false rejects name mismatch at same position.
    /// Mirrors tc_ignore_member_names_2.
    #[test]
    fn appendable_enforced_names_rejects_name_mismatch() {
        let policy = TypeConsistencyEnforcement {
            ignore_member_names: false,
            ..Default::default()
        };
        assert!(
            !is_assignable_appendable(
                &appendable_1("x1", 0),
                &appendable_1("x2", 0),
                &policy,
                #[cfg(feature = "xtypes-structural-assignability")] None
            ),
            "APPENDABLE structs with differing names must be incompatible when ignore_member_names=false"
        );
    }

    /// force_type_validation = true rejects when remote TypeObject is absent,
    /// even when type names match. Spec ref: DDS-XTypes v1.3 sec. 7.6.1.4.1.
    #[test]
    fn force_type_validation_rejects_when_remote_type_object_absent() {
        let policy = TypeConsistencyEnforcement {
            force_type_validation: true,
            ..Default::default()
        };
        // Local has a TypeObject; remote only has a name and no TypeObject.
        let local_obj = CompleteTypeObject::Struct(CompleteStructType {
            struct_flags: StructTypeFlag::IS_APPENDABLE,
            header: CompleteStructHeader {
                base_type: None,
                detail: CompleteTypeDetail::new("ShapeType"),
            },
            member_seq: vec![],
        });
        // Same name on both sides, but remote TypeObject is None.
        let result = is_type_compatible(
            Some(&local_obj),
            None,
            "ShapeType",
            "ShapeType",
            Some(&policy),
            #[cfg(feature = "xtypes-structural-assignability")]
            None,
        );
        assert!(
            !result,
            "force_type_validation must reject when remote TypeObject is absent"
        );
    }

    /// force_type_validation = false (default) allows name-based fallback when
    /// remote TypeObject is absent.
    #[test]
    fn force_type_validation_false_allows_name_fallback() {
        let policy = TypeConsistencyEnforcement {
            force_type_validation: false,
            ..Default::default()
        };
        let local_obj = CompleteTypeObject::Struct(CompleteStructType {
            struct_flags: StructTypeFlag::IS_APPENDABLE,
            header: CompleteStructHeader {
                base_type: None,
                detail: CompleteTypeDetail::new("ShapeType"),
            },
            member_seq: vec![],
        });
        let result = is_type_compatible(
            Some(&local_obj),
            None,
            "ShapeType",
            "ShapeType",
            Some(&policy),
            #[cfg(feature = "xtypes-structural-assignability")]
            None,
        );
        assert!(
            result,
            "force_type_validation=false must allow name-based fallback when remote TypeObject is absent"
        );
    }
}

/// The COMPLETE-versus-MINIMAL arms of `type_id_assignable` and the walk of
/// `unresolved_type_refs`, on hand-built identifiers.
#[cfg(all(test, feature = "xtypes-structural-assignability"))]
mod cross_kind_tests {
    use super::*;
    use crate::xtypes::{
        CommonStructMember, CompleteMemberDetail, CompleteStructHeader, CompleteStructMember,
        CompleteStructType, CompleteTypeDetail, EquivalenceHash, EquivalenceKind,
        PlainCollectionHeader, PlainSequenceSElemDefn,
    };

    fn h(i: u8) -> EquivalenceHash {
        EquivalenceHash::from_bytes([i; 14])
    }

    fn final_struct(name: &str, members: Vec<(&str, TypeIdentifier)>) -> CompleteTypeObject {
        CompleteTypeObject::Struct(CompleteStructType {
            struct_flags: StructTypeFlag::IS_FINAL,
            header: CompleteStructHeader {
                base_type: None,
                detail: CompleteTypeDetail::new(name),
            },
            member_seq: members
                .into_iter()
                .enumerate()
                .map(|(i, (n, t))| CompleteStructMember {
                    common: CommonStructMember {
                        member_id: u32::try_from(i).expect("small"),
                        member_flags: MemberFlag::empty(),
                        member_type_id: t,
                    },
                    detail: CompleteMemberDetail::new(n),
                })
                .collect(),
        })
    }

    struct Map(HashMap<EquivalenceHash, CompleteTypeObject>);
    impl TypeObjectResolver for Map {
        fn resolve_minimal(&self, h: &EquivalenceHash) -> Option<&CompleteTypeObject> {
            self.0.get(h)
        }
        fn resolve_complete(&self, h: &EquivalenceHash) -> Option<&CompleteTypeObject> {
            self.0.get(h)
        }
    }

    fn resolver(entries: Vec<(EquivalenceHash, CompleteTypeObject)>) -> Map {
        Map(entries.into_iter().collect())
    }

    /// Under DISALLOW_TYPE_COERCION identifiers are compared, never the
    /// types behind them: the cross-kind arms apply only under coercion.
    #[test]
    fn a_cross_kind_pair_is_compared_by_type_only_under_coercion() {
        let inner = final_struct("I", vec![("a", TypeIdentifier::TK_INT32)]);
        let res = resolver(vec![(h(1), inner.clone()), (h(2), inner)]);
        let coercion = TypeConsistencyEnforcement::default();
        let disallow = TypeConsistencyEnforcement {
            kind: 0,
            ..TypeConsistencyEnforcement::default()
        };
        let (w, r) = (
            TypeIdentifier::Complete(h(1)),
            TypeIdentifier::Minimal(h(2)),
        );
        assert!(type_id_assignable(&w, &r, &coercion, Some(&res)));
        assert!(type_id_assignable(&r, &w, &coercion, Some(&res)));
        assert!(!type_id_assignable(&w, &r, &disallow, Some(&res)));
        assert!(!type_id_assignable(&r, &w, &disallow, Some(&res)));
    }

    /// Two FINAL structs reached by hash across identifier kinds, differing
    /// only in member names: assignable when the reader's policy ignores
    /// member names, not assignable when it does not. DDS-XTypes 1.3
    /// 7.6.3.4.2 Step 1: with ignore_member_names, "assignability checking
    /// shall ignore the member names in both Subscription and Publication
    /// types", nested types included; the OMG dds-xtypes suite expects OK
    /// for SFinal[10]_S[20]_SFinalAlt[10]_S[20]. The verdict is the same as
    /// for same-kind hash references.
    #[test]
    fn nested_final_structs_reached_across_kinds_follow_the_member_name_policy() {
        let a = final_struct("I", vec![("a", TypeIdentifier::TK_INT32)]);
        let b = final_struct("I", vec![("b", TypeIdentifier::TK_INT32)]);
        let res = resolver(vec![(h(1), a), (h(2), b)]);
        let ignore = TypeConsistencyEnforcement {
            ignore_member_names: true,
            ..TypeConsistencyEnforcement::default()
        };
        let strict = TypeConsistencyEnforcement {
            ignore_member_names: false,
            ..TypeConsistencyEnforcement::default()
        };
        let (w, r) = (
            TypeIdentifier::Complete(h(1)),
            TypeIdentifier::Minimal(h(2)),
        );
        assert!(type_id_assignable(&w, &r, &ignore, Some(&res)));
        assert!(type_id_assignable(&r, &w, &ignore, Some(&res)));
        assert!(!type_id_assignable(&w, &r, &strict, Some(&res)));
        assert!(!type_id_assignable(&r, &w, &strict, Some(&res)));
        // Same-kind references give the same verdicts.
        let (w2, r2) = (TypeIdentifier::Minimal(h(1)), TypeIdentifier::Minimal(h(2)));
        assert!(type_id_assignable(&w2, &r2, &ignore, Some(&res)));
        assert!(!type_id_assignable(&w2, &r2, &strict, Some(&res)));
    }

    /// A reference inside a plain sequence is found; one referenced twice is
    /// reported once; each with its kind.
    #[test]
    fn unresolved_refs_descend_into_collections_and_report_each_hash_once() {
        let seq_of = |inner: TypeIdentifier| {
            TypeIdentifier::PlainSequenceSmall(PlainSequenceSElemDefn {
                header: PlainCollectionHeader {
                    equiv_kind: EquivalenceKind::Complete,
                    element_flags: crate::xtypes::CollectionElementFlag(0),
                },
                bound: 4,
                element_identifier: Box::new(inner),
            })
        };
        let root = final_struct(
            "R",
            vec![
                ("x", TypeIdentifier::Complete(h(1))),
                ("x2", TypeIdentifier::Complete(h(1))),
                ("s", seq_of(TypeIdentifier::Complete(h(3)))),
                ("y", TypeIdentifier::Minimal(h(2))),
            ],
        );
        let missing = unresolved_type_refs(&root, &resolver(vec![]));
        assert_eq!(
            missing,
            vec![
                UnresolvedRef {
                    hash: h(1),
                    complete: true
                },
                UnresolvedRef {
                    hash: h(3),
                    complete: true
                },
                UnresolvedRef {
                    hash: h(2),
                    complete: false
                },
            ]
        );
    }
}
