// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! PID_TYPE_INFORMATION (0x0075) emission for SEDP discovery.
//!
//! DDS-XTypes v1.3 sec. 7.6.3.2 defines `TypeInformation` as a @mutable struct
//! carrying two `TypeIdentifierWithDependencies` members: minimal (member id
//! 0x1001) and complete (member id 0x1002). Each carries the
//! `TypeIdentifier` and `typeobject_serialized_size` for its respective
//! TypeObject view, plus optional dependent TypeIdentifiers.
//!
//! HDDS announces `PID_TYPE_INFORMATION` on its SEDP DATA(w)/DATA(r) so a
//! remote endpoint can perform the XTypes type-assignability check
//! (DDS-XTypes v1.3 Sec.7.6.3.2) from the TypeIdentifiers alone, including
//! under `TypeConsistencyEnforcement.kind = ALLOW_TYPE_COERCION`; a
//! receiver that matches on TypeInformation leaves an endpoint without it
//! unmatched even when a valid `PID_TYPE_OBJECT` is present.
//!
//! # Wire format
//!
//! `TypeIdentifierWithDependencies` is @appendable (DDS-XTypes v1.3
//! sec. 7.6.3.2.1), so under XCDR2 each member body carries its own 4-byte
//! DHEADER, and the `dependent_typeids` sequence is DHEADER-prefixed too.
//! The layout below follows the XCDR2 rules for those types. An encoding
//! with LC=5 (NEXTINT doubling as the member DHEADER) carries the same
//! content and is equivalent:
//!
//! ```text
//! PID 0x0075, PARAM_LEN = 100 (zero-dependency case)
//! + DHEADER          u32 LE  = 96   (TypeInformation @mutable content size)
//! + Member 0x1001 (minimal)
//! | + EMHEADER1      u32 LE  = 0x40001001  (M=0, LC=4, MID=0x1001)
//! | + NEXTINT        u32 LE  = 40          (member content length, per LC=4)
//! | + DHEADER_tiwd   u32 LE  = 36          (TypeIdentifierWithDependencies)
//! | + DHEADER_tiws   u32 LE  = 20          (TypeIdentifierWithSize content)
//! | + EK_MINIMAL     u8      = 0xF1        (TypeIdentifier discriminator)
//! | + hash           [u8;14]               (MD5(MinimalTypeObject)[..14])
//! | + pad            u8      = 0           (4-byte alignment)
//! | + size           u32 LE                (typeobject_serialized_size)
//! | + dep_count      u32 LE  = 0           (dependent_typeid_count, int32)
//! | + seq_DHEADER    u32 LE  = 4           (dependent_typeids seq body size)
//! | + seq_count      u32 LE  = 0           (empty dependent_typeids)
//! + Member 0x1002 (complete) -- same layout, EMHEADER MID=0x1002, EK=0xF2
//! ```
//!
//! History: earlier releases omitted `DHEADER_tiwd` and emitted a trailing
//! `(0xFFFFFFFF, 4, 0)` triple believed to be a vendor sentinel. That was
//! a misreading of the layout: without the DHEADER every later field lands
//! 4 bytes early, so `dependent_typeid_count` was read where `size` sits
//! and the "sentinel" 0xFFFFFFFF was an invalid count of -1. A strict
//! XCDR2 parser aborts on the missing delimiter and never matches the
//! writer. The RX side (`parse.rs`) keeps a `nextint == 36`
//! compatibility branch so peers running older HDDS still parse.
//!
//! # Hash computation
//!
//! `EquivalenceHash` is the MD5 of the CDR2-serialised TypeObject truncated
//! to 14 bytes (DDS-XTypes v1.3 sec. 7.3.4.8). HDDS' `TypeKind` octet values, `TypeObject` discriminator labels, and
//! `AnnotationParameterValue` discriminator labels all match the spec
//! IDL -- so the hashes computed here are spec-compliant and byte-comparable
//! with what any spec-conformant implementation would compute for
//! the same logical type.

use crate::core::ser::traits::Cdr2Encode;
use crate::protocol::discovery::types::{
    parameter_length, wire_u32, ParseError, TypeIdentifierWithDependencies, TypeIdentifierWithSize,
    TypeInformation,
};
use crate::xtypes::discriminators::{EK_COMPLETE, EK_MINIMAL};
use crate::xtypes::{CompleteTypeObject, EquivalenceHash, MinimalTypeObject};

/// PID identifier for `PID_TYPE_INFORMATION` per DDS-XTypes v1.3 sec. 7.6.3.2.
const PID_TYPE_INFORMATION: u16 = 0x0075;

/// Compute the NEXTINT (member content byte-count) for a member with `n_deps`
/// dependent TypeIdentifiers:
/// DHEADER_tiwdeps(4) + DHEADER_tiws(4) + typeid(16) + size(4) +
/// dep_count(4) + seq_DHEADER(4) + seq_count(4) + n_deps * 24 = 40 + n * 24.
///
/// `n_deps` is derived locally from our own registered type, never parsed
/// from the wire, but nothing in this module bounds it, so the count is
/// converted and the arithmetic checked: a dependency list too long for a
/// 32-bit NEXTINT is refused rather than wrapped.
#[inline]
fn member_nextint(n_deps: usize) -> Result<u32, ParseError> {
    wire_u32(n_deps)?
        .checked_mul(24)
        .and_then(|dep_bytes| dep_bytes.checked_add(40))
        .ok_or(ParseError::EncodingError)
}

/// Derive a Minimal object only when all references are already descriptive
/// or Minimal. Complete hash references require the dependency-aware path.
fn derive_minimal(complete: &CompleteTypeObject) -> Option<MinimalTypeObject> {
    crate::dynamic::complete_to_minimal_type_object(complete)
}

/// Byte count of the CDR encapsulation frame (representation id + options)
/// that prefixes a serialized TypeObject in transit.
///
/// `typeobject_serialized_size` counts the ENCAPSULATED form: 39 for a
/// TypeObject whose bare CDR2 body is 35 bytes. DDS-XTypes v1.3 does not
/// say whether the encapsulation is counted; a receiver that reads the
/// field as the encapsulated size rejects a type advertised with the bare
/// body size, so HDDS advertises body + 4, the encapsulated size.
const TYPEOBJECT_ENCAPSULATION_BYTES: u32 = 4;

/// Advertised size of a `CompleteTypeObject` for the
/// `typeobject_serialized_size` field: encapsulated CDR2 length.
fn cdr2_size_complete(complete: &CompleteTypeObject) -> Result<u32, ParseError> {
    let mut buf = vec![0u8; complete.max_cdr2_size()];
    let len = complete
        .encode_cdr2_le(&mut buf)
        .map_err(|_| ParseError::EncodingError)?;
    u32::try_from(len)
        .map(|n| n + TYPEOBJECT_ENCAPSULATION_BYTES)
        .map_err(|_| ParseError::InvalidFormat)
}

/// Advertised size of a `MinimalTypeObject` (encapsulated CDR2 length).
fn cdr2_size_minimal(minimal: &MinimalTypeObject) -> Result<u32, ParseError> {
    let mut buf = vec![0u8; minimal.max_cdr2_size()];
    let len = minimal
        .encode_cdr2_le(&mut buf)
        .map_err(|_| ParseError::EncodingError)?;
    u32::try_from(len)
        .map(|n| n + TYPEOBJECT_ENCAPSULATION_BYTES)
        .map_err(|_| ParseError::InvalidFormat)
}

/// Write a single `TypeIdentifierWithDependencies` member into the buffer.
///
/// Spec-compliant XCDR2 @appendable layout, for any dependency count
/// (`N == 0` produces an empty-but-delimited `dependent_typeids` sequence):
///   EMHEADER(4) + NEXTINT(4) + DHEADER_tiwdeps(4) + DHEADER_tiws(4) +
///   disc(1) + hash(14) + pad(1) + size(4) + dep_count(4) +
///   seq_DHEADER(4) + seq_count(4) + N*(DHEADER(4)+disc(1)+hash(14)+pad(1)+size(4))
fn write_member(
    buf: &mut [u8],
    offset: &mut usize,
    member_id: u32,
    discriminator: u8,
    hash: &EquivalenceHash,
    typeobject_serialized_size: u32,
    deps: &[TypeIdentifierWithSize],
) -> Result<(), ParseError> {
    let n_deps = deps.len();
    let dep_count = wire_u32(n_deps)?;
    let nextint = member_nextint(n_deps)?;
    let total = 8 + nextint as usize; // EMHEADER(4) + NEXTINT(4) + content
    if *offset + total > buf.len() {
        return Err(ParseError::BufferTooSmall);
    }

    // EMHEADER1: M=0, LC=4 (NEXTINT carries member length), MID=member_id
    //   -> (4 << 28) | member_id
    // Per OMG DDS-XTypes v1.3 sec. 7.4.3.4.3 Table 39: LC=4 advertises a
    // following 4-byte NEXTINT u32 with the member content length.
    let emheader: u32 = (4u32 << 28) | (member_id & 0x0FFF_FFFF);
    buf[*offset..*offset + 4].copy_from_slice(&emheader.to_le_bytes());
    *offset += 4;

    // NEXTINT (member content byte-count)
    buf[*offset..*offset + 4].copy_from_slice(&nextint.to_le_bytes());
    *offset += 4;

    // DHEADER_tiwdeps: size of all content after this DHEADER = NEXTINT - 4.
    // MUST be present even for N == 0: TypeIdentifierWithDependencies is
    // @appendable, and a strict XCDR2 parser reads the next word as this
    // delimiter (DDS-XTypes v1.3 Sec.7.4.3.4.1). Omitting it desyncs the whole member.
    let dheader_tiwdeps = nextint - 4;
    buf[*offset..*offset + 4].copy_from_slice(&dheader_tiwdeps.to_le_bytes());
    *offset += 4;

    // DHEADER_tiws: TypeIdentifierWithSize content length = 20
    buf[*offset..*offset + 4].copy_from_slice(&20u32.to_le_bytes());
    *offset += 4;

    // TypeIdentifier discriminator + 14-byte hash + 1-byte alignment pad
    buf[*offset] = discriminator;
    *offset += 1;
    buf[*offset..*offset + 14].copy_from_slice(hash.as_bytes());
    *offset += 14;
    buf[*offset] = 0;
    *offset += 1;

    // typeobject_serialized_size
    buf[*offset..*offset + 4].copy_from_slice(&typeobject_serialized_size.to_le_bytes());
    *offset += 4;

    // dep_count (i32 per spec, serialised u32 LE)
    buf[*offset..*offset + 4].copy_from_slice(&dep_count.to_le_bytes());
    *offset += 4;

    // seq_DHEADER: size of the sequence body = seq_count(4) + N*24 bytes,
    // which is NEXTINT minus the 36 bytes that precede the sequence body
    // (DHEADER_tiwdeps, DHEADER_tiws, typeid, size, dep_count, seq_DHEADER).
    let seq_dheader = nextint - 36;
    buf[*offset..*offset + 4].copy_from_slice(&seq_dheader.to_le_bytes());
    *offset += 4;

    // seq_count
    buf[*offset..*offset + 4].copy_from_slice(&dep_count.to_le_bytes());
    *offset += 4;

    // Each dep element: DHEADER_tiws_elem(4) + kind(1) + hash(14) + pad(1) + size(4) = 24 bytes
    for dep in deps {
        // DHEADER_tiws_elem = 20 (TypeIdentifierWithSize content length)
        buf[*offset..*offset + 4].copy_from_slice(&20u32.to_le_bytes());
        *offset += 4;
        buf[*offset] = dep.kind;
        *offset += 1;
        buf[*offset..*offset + 14].copy_from_slice(dep.hash.as_bytes());
        *offset += 14;
        buf[*offset] = 0; // alignment pad
        *offset += 1;
        buf[*offset..*offset + 4].copy_from_slice(&dep.typeobject_serialized_size.to_le_bytes());
        *offset += 4;
    }

    Ok(())
}

/// Derive a `TypeInformation` from a `CompleteTypeObject`. Returns `None`
/// when the type cannot produce a `MinimalTypeObject` today (see
/// `derive_minimal` for the per-kind coverage), or when the underlying
/// CDR2 encoding fails. Both fields of the returned struct are populated
/// (`minimal` + `complete`) when derivation succeeds; partial derivation
/// is currently not supported and would surface as `None` from this
/// helper.
///
/// `dependent_typeids` is always empty here; use
/// `derive_type_information_with_deps` (feature `xtypes-structural-assignability`)
/// to populate it from a type-object store.
pub(super) fn derive_type_information(type_obj: &CompleteTypeObject) -> Option<TypeInformation> {
    let minimal_obj = derive_minimal(type_obj)?;
    let complete_hash = type_obj.compute_equivalence_hash().ok()?;
    let minimal_hash = minimal_obj.compute_equivalence_hash().ok()?;
    let complete_size = cdr2_size_complete(type_obj).ok()?;
    let minimal_size = cdr2_size_minimal(&minimal_obj).ok()?;
    Some(TypeInformation {
        minimal: Some(TypeIdentifierWithDependencies {
            hash: minimal_hash,
            typeobject_serialized_size: minimal_size,
            dependent_typeids: vec![],
        }),
        complete: Some(TypeIdentifierWithDependencies {
            hash: complete_hash,
            typeobject_serialized_size: complete_size,
            dependent_typeids: vec![],
        }),
    })
}

/// Collect direct (and transitive) type dependencies of `type_obj` that are
/// resolvable in `store`, indexed by either equivalence identity.
///
/// Returns one `(minimal_tiws, complete_tiws, objects)` triple per unique
/// dependency, in BFS discovery order, where `objects` are the very objects
/// the two identifiers hash. Each output representation is deduplicated
/// later.
#[cfg(feature = "xtypes-structural-assignability")]
fn collect_type_dependencies(
    type_obj: &CompleteTypeObject,
    store: &std::collections::HashMap<EquivalenceHash, CompleteTypeObject>,
) -> Vec<(
    TypeIdentifierWithSize,
    TypeIdentifierWithSize,
    AnnouncedTypeObject,
)> {
    use crate::xtypes::TypeIdentifier;
    use std::collections::{HashSet, VecDeque};

    /// Extract all TypeIdentifier refs referenced directly by this TypeObject.
    fn member_type_ids(obj: &CompleteTypeObject) -> Vec<&TypeIdentifier> {
        let mut ids: Vec<&TypeIdentifier> = Vec::new();
        match obj {
            CompleteTypeObject::Struct(s) => {
                if let Some(b) = &s.header.base_type {
                    ids.push(b);
                }
                for m in &s.member_seq {
                    ids.push(&m.common.member_type_id);
                }
            }
            CompleteTypeObject::Union(u) => {
                ids.push(&u.header.discriminator);
                for m in &u.member_seq {
                    ids.push(&m.common.member_type_id);
                }
            }
            CompleteTypeObject::Sequence(s) => {
                ids.push(&s.element.type_id);
            }
            CompleteTypeObject::Array(a) => {
                ids.push(&a.element.type_id);
            }
            CompleteTypeObject::Map(m) => {
                ids.push(&m.key.type_id);
                ids.push(&m.element.type_id);
            }
            CompleteTypeObject::Alias(a) => {
                ids.push(&a.body.common.related_type);
            }
            // Enum / Bitmask / Bitset / Annotation: no complex type refs
            _ => {}
        }
        ids
    }

    /// Collect every hash reference reachable from a TypeIdentifier,
    /// descending through PLAIN collection identifiers. A member typed
    /// `NestedStruct[10]` or `sequence<NestedStruct>` is NOT a direct
    /// `TypeIdentifier::Minimal` -- it is a `PlainArray*`/`PlainSequence*`/
    /// `PlainMap*` whose element (and, for maps, key) identifier carries the
    /// hash one level down (DDS-XTypes v1.3 sec. 7.3.4.4). Without this descent the
    /// dependency BFS misses nested complex elements of collection members
    /// (e.g. array-of-struct), declares zero deps, and the peer never issues a
    /// getTypes for them.
    fn collect_hash_refs(tid: &TypeIdentifier, out: &mut Vec<EquivalenceHash>) {
        match tid {
            TypeIdentifier::Minimal(h) | TypeIdentifier::Complete(h) => out.push(*h),
            TypeIdentifier::PlainSequenceSmall(d) => collect_hash_refs(&d.element_identifier, out),
            TypeIdentifier::PlainSequenceLarge(d) => collect_hash_refs(&d.element_identifier, out),
            TypeIdentifier::PlainArraySmall(d) => collect_hash_refs(&d.element_identifier, out),
            TypeIdentifier::PlainArrayLarge(d) => collect_hash_refs(&d.element_identifier, out),
            TypeIdentifier::PlainMapSmall(d) => {
                collect_hash_refs(&d.key_identifier, out);
                collect_hash_refs(&d.element_identifier, out);
            }
            TypeIdentifier::PlainMapLarge(d) => {
                collect_hash_refs(&d.key_identifier, out);
                collect_hash_refs(&d.element_identifier, out);
            }
            _ => {}
        }
    }

    let mut indexed = store.clone();
    for object in store.values() {
        if let Ok(hash) = object.compute_equivalence_hash() {
            indexed.entry(hash).or_insert_with(|| object.clone());
        }
    }
    let mut seen: HashSet<EquivalenceHash> = HashSet::new();
    let mut queue: VecDeque<EquivalenceHash> = VecDeque::new();
    let mut result: Vec<(
        TypeIdentifierWithSize,
        TypeIdentifierWithSize,
        AnnouncedTypeObject,
    )> = Vec::new();

    // Seed the queue with hash refs of the root type, descending through
    // plain collections so array/sequence/map-of-complex members are followed.
    let mut root_refs: Vec<EquivalenceHash> = Vec::new();
    for tid in member_type_ids(type_obj) {
        collect_hash_refs(tid, &mut root_refs);
    }
    for h in root_refs {
        if seen.insert(h) {
            queue.push_back(h);
        }
    }

    while let Some(dependency_hash) = queue.pop_front() {
        let dep_complete = match indexed.get(&dependency_hash) {
            Some(d) => d,
            None => {
                log::debug!("[TYPE_INFO] dependency hash not in store, skipping transitive dep");
                continue;
            }
        };

        let dep_min_obj =
            match crate::dynamic::complete_to_minimal_with_dependencies(dep_complete, store) {
                Some(m) => m,
                None => {
                    log::debug!("[TYPE_INFO] complete_to_minimal failed for dep, skipping");
                    continue;
                }
            };

        let dep_min_hash = match dep_min_obj.compute_equivalence_hash() {
            Ok(h) => h,
            Err(_) => continue,
        };
        // Complete-side dep identity: hash/size of the dep's spec-correct
        // wire form (Complete member references per DDS-XTypes v1.3
        // 7.3.4.5), matching what the OMG getTypes responder serves for
        // EK_COMPLETE. Minimal dependencies are converted through the same graph.
        let dep_wire = crate::dynamic::complete_type_object_with_complete_refs(dep_complete, store);
        let dep_cmp_hash = match dep_wire.compute_equivalence_hash() {
            Ok(h) => h,
            Err(_) => continue,
        };
        let dep_min_size = match cdr2_size_minimal(&dep_min_obj) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let dep_cmp_size = match cdr2_size_complete(&dep_wire) {
            Ok(s) => s,
            Err(_) => continue,
        };

        result.push((
            TypeIdentifierWithSize {
                kind: EK_MINIMAL,
                hash: dep_min_hash,
                typeobject_serialized_size: dep_min_size,
            },
            TypeIdentifierWithSize {
                kind: EK_COMPLETE,
                hash: dep_cmp_hash,
                typeobject_serialized_size: dep_cmp_size,
            },
            AnnouncedTypeObject {
                complete: dep_wire,
                complete_hash: dep_cmp_hash,
                minimal: dep_min_obj,
                minimal_hash: dep_min_hash,
            },
        ));

        // Transitive: enqueue deps of this dep, descending plain collections.
        let mut dep_refs: Vec<EquivalenceHash> = Vec::new();
        for tid in member_type_ids(dep_complete) {
            collect_hash_refs(tid, &mut dep_refs);
        }
        for h in dep_refs {
            if seen.insert(h) {
                queue.push_back(h);
            }
        }
    }

    result
}

/// Derive a `TypeInformation` with populated `dependent_typeids` from a
/// `CompleteTypeObject` and a store of resolvable deps.
///
/// The `store` contains reachable Complete objects keyed by either identity. Use this when building SEDP DATA(w) for
/// types that reference other complex types (e.g. struct with enum member)
/// so that the peer can resolve the full type graph.
///
/// Missing Complete dependencies prevent derivation of a Minimal identity.
/// Production announces through [`derive_announced_type_graph`], which also
/// returns the objects to serve; this projection is kept for tests.
#[cfg(all(test, feature = "xtypes-structural-assignability"))]
pub(crate) fn derive_type_information_with_deps(
    type_obj: &CompleteTypeObject,
    store: &std::collections::HashMap<EquivalenceHash, CompleteTypeObject>,
) -> Option<TypeInformation> {
    derive_announced_type_graph(type_obj, store).map(|(info, _)| info)
}

/// One TypeObject an announcement names, in both representations, each
/// with the hash the announcement carries for it.
#[cfg(feature = "xtypes-structural-assignability")]
#[derive(Debug, Clone)]
pub(crate) struct AnnouncedTypeObject {
    /// The Complete object whose hash is `complete_hash` (Complete member
    /// references, DDS-XTypes v1.3 7.3.4.5): what getTypes must serve.
    pub(crate) complete: CompleteTypeObject,
    pub(crate) complete_hash: EquivalenceHash,
    pub(crate) minimal: MinimalTypeObject,
    pub(crate) minimal_hash: EquivalenceHash,
}

/// [`derive_type_information_with_deps`] together with every object the
/// returned `TypeInformation` identifies (the root first, then each
/// dependency), so the caller can make each announced identifier servable
/// from the very objects it was hashed from.
#[cfg(feature = "xtypes-structural-assignability")]
pub(crate) fn derive_announced_type_graph(
    type_obj: &CompleteTypeObject,
    store: &std::collections::HashMap<EquivalenceHash, CompleteTypeObject>,
) -> Option<(TypeInformation, Vec<AnnouncedTypeObject>)> {
    let minimal_obj = crate::dynamic::complete_to_minimal_with_dependencies(type_obj, store)?;
    // Announced EK_COMPLETE identity: hash/size of the spec-correct wire
    // form (Complete member references per DDS-XTypes v1.3 7.3.4.5), which
    // is the object the OMG getTypes responder serves for that hash. The
    // internal hybrid `type_obj` (EK_MINIMAL member refs) must NOT be
    // announced as the Complete identity: a Complete TypeObject references
    // Complete identifiers only (DDS-XTypes v1.3 7.3.4.5), so a reader that
    // walks the announced Complete graph cannot resolve Minimal refs inside
    // it and never matches. Minimal references are converted independently.
    let wire_obj = crate::dynamic::complete_type_object_with_complete_refs(type_obj, store);
    let complete_hash = wire_obj.compute_equivalence_hash().ok()?;
    let minimal_hash = minimal_obj.compute_equivalence_hash().ok()?;
    let complete_size = cdr2_size_complete(&wire_obj).ok()?;
    let minimal_size = cdr2_size_minimal(&minimal_obj).ok()?;

    let dep_pairs = collect_type_dependencies(type_obj, store);
    let mut minimal_seen = std::collections::HashSet::new();
    let mut complete_seen = std::collections::HashSet::new();
    let minimal_deps: Vec<TypeIdentifierWithSize> = dep_pairs
        .iter()
        .filter(|(m, _, _)| minimal_seen.insert(m.hash))
        .map(|(m, _, _)| m.clone())
        .collect();
    let complete_deps: Vec<TypeIdentifierWithSize> = dep_pairs
        .iter()
        .filter(|(_, c, _)| complete_seen.insert(c.hash))
        .map(|(_, c, _)| c.clone())
        .collect();
    let mut objects = Vec::with_capacity(dep_pairs.len() + 1);
    objects.push(AnnouncedTypeObject {
        complete: wire_obj,
        complete_hash,
        minimal: minimal_obj,
        minimal_hash,
    });
    objects.extend(dep_pairs.into_iter().map(|(_, _, object)| object));

    let info = TypeInformation {
        minimal: Some(TypeIdentifierWithDependencies {
            hash: minimal_hash,
            typeobject_serialized_size: minimal_size,
            dependent_typeids: minimal_deps,
        }),
        complete: Some(TypeIdentifierWithDependencies {
            hash: complete_hash,
            typeobject_serialized_size: complete_size,
            dependent_typeids: complete_deps,
        }),
    };
    Some((info, objects))
}

/// The `TypeInformation` an endpoint whose type is `type_obj` announces in
/// `PID_TYPE_INFORMATION`, whichever dialect encodes the announcement.
///
/// `precomputed` is the value built at announce time with the dependent
/// TypeIdentifiers resolved from the local type store (feature
/// `xtypes-structural-assignability`); without one, the value is derived
/// from `type_obj` alone, with empty dependency lists. `None` when the type
/// cannot produce a `MinimalTypeObject` (see `derive_minimal`): the caller
/// then announces no `TypeInformation` at all.
pub(crate) fn announced_type_information(
    type_obj: &CompleteTypeObject,
    precomputed: Option<&TypeInformation>,
) -> Option<TypeInformation> {
    match precomputed {
        Some(info) => Some(info.clone()),
        None => derive_type_information(type_obj),
    }
}

/// The complete `PID_TYPE_INFORMATION` parameter (header and value) for
/// `info`, written by `write_type_information` into a buffer of exactly
/// the size it needs. `None` when `info` lacks its minimal or complete
/// member, which `write_type_information` refuses to announce.
pub(crate) fn encode_type_information_parameter(
    info: &TypeInformation,
) -> Result<Option<Vec<u8>>, ParseError> {
    let (minimal, complete) = match (info.minimal.as_ref(), info.complete.as_ref()) {
        (Some(m), Some(c)) => (m, c),
        _ => return Ok(None),
    };
    // PID header(4) + DHEADER(4) + two members of EMHEADER(4) + NEXTINT(4)
    // + content.
    let len = 8
        + 8
        + member_nextint(minimal.dependent_typeids.len())? as usize
        + 8
        + member_nextint(complete.dependent_typeids.len())? as usize;
    let mut buf = vec![0u8; len];
    let mut offset = 0;
    if !write_type_information(info, &mut buf, &mut offset)? {
        return Ok(None);
    }
    buf.truncate(offset);
    Ok(Some(buf))
}

/// Emit `PID_TYPE_INFORMATION` (0x0075) for the given `TypeInformation`.
///
/// Both members must be present (`minimal` + `complete`). Partial
/// `TypeInformation` is rejected with a soft `Ok(false)` so the rest of
/// the SEDP packet remains intact.
///
/// Payload size is computed dynamically from the dep counts:
/// `4 + 8 + member_nextint(N_min) + 8 + member_nextint(N_cmp)` bytes
/// (zero deps per member -> 100 bytes).
pub(super) fn write_type_information(
    info: &TypeInformation,
    buf: &mut [u8],
    offset: &mut usize,
) -> Result<bool, ParseError> {
    let (minimal, complete) = match (info.minimal.as_ref(), info.complete.as_ref()) {
        (Some(m), Some(c)) => (m, c),
        _ => return Ok(false),
    };

    // Per-member total bytes: EMHEADER(4) + NEXTINT(4) + content(nextint)
    let min_member_total = 8 + member_nextint(minimal.dependent_typeids.len())? as usize;
    let cmp_member_total = 8 + member_nextint(complete.dependent_typeids.len())? as usize;

    // DHEADER covers the two member blobs
    let dheader_outer = min_member_total + cmp_member_total;
    let dheader_field = wire_u32(dheader_outer)?;
    // Payload = DHEADER(4) + dheader_outer content
    let payload_len = 4 + dheader_outer;
    let param_len = parameter_length(payload_len)?;

    let total = 4 + payload_len; // PID header (4) + payload
    if *offset + total > buf.len() {
        return Err(ParseError::BufferTooSmall);
    }

    // PID header (4 bytes): PID (2) + payload_len (2)
    buf[*offset..*offset + 2].copy_from_slice(&PID_TYPE_INFORMATION.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&param_len.to_le_bytes());
    *offset += 4;

    // DHEADER: TypeInformation @mutable content size
    buf[*offset..*offset + 4].copy_from_slice(&dheader_field.to_le_bytes());
    *offset += 4;

    // Member 0x1001: minimal
    write_member(
        buf,
        offset,
        0x1001,
        EK_MINIMAL,
        &minimal.hash,
        minimal.typeobject_serialized_size,
        &minimal.dependent_typeids,
    )?;
    // Member 0x1002: complete
    write_member(
        buf,
        offset,
        0x1002,
        EK_COMPLETE,
        &complete.hash,
        complete.typeobject_serialized_size,
        &complete.dependent_typeids,
    )?;

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xtypes::{
        CommonStructMember, CompleteMemberDetail, CompleteStructHeader, CompleteStructMember,
        CompleteStructType, CompleteTypeDetail, MemberFlag, StructTypeFlag, TypeIdentifier,
        TypeKind,
    };

    fn temperature_complete() -> CompleteTypeObject {
        CompleteTypeObject::Struct(CompleteStructType {
            struct_flags: StructTypeFlag::IS_FINAL,
            header: CompleteStructHeader {
                base_type: None,
                detail: CompleteTypeDetail::new("Temperature"),
            },
            member_seq: vec![
                CompleteStructMember {
                    common: CommonStructMember {
                        member_id: 0,
                        member_flags: MemberFlag::empty(),
                        member_type_id: TypeIdentifier::primitive(TypeKind::TK_FLOAT32),
                    },
                    detail: CompleteMemberDetail::new("value"),
                },
                CompleteStructMember {
                    common: CommonStructMember {
                        member_id: 1,
                        member_flags: MemberFlag::empty(),
                        member_type_id: TypeIdentifier::primitive(TypeKind::TK_UINT32),
                    },
                    detail: CompleteMemberDetail::new("timestamp"),
                },
            ],
        })
    }

    /// Convenience: derive the `TypeInformation` for the standard
    /// Temperature fixture used across tests below.
    fn temperature_info() -> TypeInformation {
        derive_type_information(&temperature_complete())
            .expect("Struct fixture must derive a TypeInformation")
    }

    #[test]
    fn type_information_payload_is_100_bytes() {
        let info = temperature_info();
        let mut buf = [0u8; 256];
        let mut offset = 0;

        let written = write_type_information(&info, &mut buf, &mut offset)
            .expect("write should succeed for struct types");
        assert!(written, "Struct types must emit PID_TYPE_INFORMATION");
        assert_eq!(
            offset,
            4 + 100,
            "PID header (4) + payload (100) bytes total"
        );
    }

    #[test]
    fn type_information_pid_and_length_header() {
        let info = temperature_info();
        let mut buf = [0u8; 256];
        let mut offset = 0;

        write_type_information(&info, &mut buf, &mut offset).expect("emit succeeds");

        assert_eq!(&buf[0..2], &PID_TYPE_INFORMATION.to_le_bytes());
        // Temperature has 0 deps -> payload_len = 100
        assert_eq!(&buf[2..4], &100u16.to_le_bytes());
        // DHEADER = 96
        assert_eq!(&buf[4..8], &96u32.to_le_bytes());
    }

    #[test]
    fn type_information_emheaders_are_spec_compliant() {
        let info = temperature_info();
        let mut buf = [0u8; 256];
        let mut offset = 0;

        write_type_information(&info, &mut buf, &mut offset).expect("emit succeeds");

        // Member 0x1001 EMHEADER1 starts at offset 8 (after PID header + DHEADER).
        let emheader_minimal = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
        assert_eq!(
            emheader_minimal, 0x4000_1001,
            "minimal EMHEADER must be 0x40001001 (M=0, LC=4, MID=0x1001)"
        );

        // Member 0x1002 EMHEADER1 starts at offset 8 + 48 (EMHEADER + NEXTINT + 40).
        let emheader_complete = u32::from_le_bytes([buf[56], buf[57], buf[58], buf[59]]);
        assert_eq!(
            emheader_complete, 0x4000_1002,
            "complete EMHEADER must be 0x40001002 (M=0, LC=4, MID=0x1002)"
        );
    }

    #[test]
    fn type_information_discriminators_are_spec_compliant() {
        let info = temperature_info();
        let mut buf = [0u8; 256];
        let mut offset = 0;

        write_type_information(&info, &mut buf, &mut offset).expect("emit succeeds");

        // Minimal TypeIdentifier discriminator at offset 8 + 16 = 24
        // (EMHEADER + NEXTINT + DHEADER_tiwd + DHEADER_tiws).
        assert_eq!(buf[24], EK_MINIMAL, "minimal must use EK_MINIMAL (0xF1)");
        assert_eq!(
            buf[24], 0xF1,
            "EK_MINIMAL must equal 0xF1 per spec sec. 7.3.4.4"
        );
        // Complete TypeIdentifier discriminator at offset 8 + 48 + 16 = 72.
        assert_eq!(buf[72], EK_COMPLETE, "complete must use EK_COMPLETE (0xF2)");
        assert_eq!(
            buf[72], 0xF2,
            "EK_COMPLETE must equal 0xF2 per spec sec. 7.3.4.4"
        );
    }

    #[test]
    fn derive_minimal_supports_structs_and_aliases() {
        // XTypes 1.3 7.3.4: aliases have both representations too.
        use crate::xtypes::{
            AliasTypeFlag, CommonAliasBody, CompleteAliasBody, CompleteAliasHeader,
            CompleteAliasType, TypeRelationFlag,
        };

        // Some(_) for Struct -- baseline.
        let struct_to = temperature_complete();
        assert!(
            derive_minimal(&struct_to).is_some(),
            "Struct variant must produce a MinimalTypeObject"
        );
        assert!(
            derive_type_information(&struct_to).is_some(),
            "Struct variant must produce a TypeInformation"
        );

        // A primitive alias needs no dependency graph.
        let alias_to = CompleteTypeObject::Alias(CompleteAliasType {
            alias_flags: AliasTypeFlag::empty(),
            header: CompleteAliasHeader {
                detail: CompleteTypeDetail::new("MyAlias"),
            },
            body: CompleteAliasBody {
                common: CommonAliasBody {
                    related_flags: TypeRelationFlag::empty(),
                    related_type: TypeIdentifier::primitive(TypeKind::TK_INT32),
                },
                ann_builtin: None,
                ann_custom: None,
            },
        });
        assert!(
            derive_minimal(&alias_to).is_some(),
            "Alias variant must produce a MinimalTypeObject"
        );
        assert!(
            derive_type_information(&alias_to).is_some(),
            "Alias variant must produce TypeInformation"
        );

        // The end-to-end soft-skip: a `TypeInformation` with both fields
        // missing must surface as `Ok(false)` and leave the buffer
        // untouched.
        let empty_info = TypeInformation::default();
        let mut buf = [0xAAu8; 256];
        let mut offset = 0;
        let written = write_type_information(&empty_info, &mut buf, &mut offset)
            .expect("partial TypeInformation soft-skip must not be a fatal error");
        assert!(!written, "default TypeInformation must soft-skip emission");
        assert_eq!(offset, 0, "offset must not advance on soft-skip");
        assert_eq!(buf[0], 0xAA, "buffer must remain untouched on soft-skip");
    }

    /// TX/RX symmetry: encode a TypeInformation, then decode the wire
    /// bytes (skipping the 4-byte PID header) and assert the parsed
    /// struct equals the input. Confirms the build/parse pair is a
    /// faithful round-trip of the spec @appendable layout.
    #[test]
    fn type_information_round_trip_via_parse() {
        let info = temperature_info();
        let mut buf = [0u8; 256];
        let mut offset = 0;
        let written = write_type_information(&info, &mut buf, &mut offset)
            .expect("emit succeeds for Struct fixture");
        assert!(written);

        // The PID header occupies bytes 0..4; the parser receives the
        // remaining `length` bytes (DHEADER + 2 members = 92 bytes).
        let payload = &buf[4..offset];
        let parsed = crate::protocol::discovery::sedp::parse::parse_type_information(payload)
            .expect("parser accepts well-formed wire bytes");

        assert_eq!(parsed, info, "round-trip must preserve TypeInformation");
    }

    // -------------------------------------------------------------------------
    // New tests: feature-gated deps format + structural checks
    // -------------------------------------------------------------------------

    /// Confirm that `derive_type_information` (always) + 0 deps emits exactly
    /// 100 bytes in the spec @appendable format: DHEADER_tiwd present,
    /// dep_count = 0, and an empty-but-delimited dependent_typeids sequence
    /// (seq_DHEADER = 4, seq_count = 0). This is the feature-OFF / no-dep
    /// guarantee AND the cross-vendor byte layout XCDR2 prescribes.
    #[test]
    fn type_information_zero_deps_spec_format() {
        let info = derive_type_information(&temperature_complete())
            .expect("Temperature must derive TypeInformation");
        assert!(
            info.minimal.as_ref().unwrap().dependent_typeids.is_empty(),
            "derive_type_information must produce empty dependent_typeids"
        );
        let mut buf = [0u8; 256];
        let mut offset = 0;
        write_type_information(&info, &mut buf, &mut offset).expect("emit succeeds");
        assert_eq!(
            offset,
            4 + 100,
            "zero-dep must emit exactly 104 bytes total"
        );
        // Minimal member layout from buf[8]:
        //   [8..12] EMHEADER, [12..16] NEXTINT=40, [16..20] DHEADER_tiwd=36,
        //   [20..24] DHEADER_tiws=20, [24] disc, [25..39] hash, [39] pad,
        //   [40..44] size, [44..48] dep_count, [48..52] seq_DHEADER, [52..56] seq_count
        assert_eq!(
            u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]),
            40,
            "zero-dep NEXTINT must be 40 (DHEADER_tiwd included)"
        );
        assert_eq!(
            u32::from_le_bytes([buf[16], buf[17], buf[18], buf[19]]),
            36,
            "DHEADER_tiwd must be 36 (member content after the delimiter)"
        );
        assert_eq!(
            u32::from_le_bytes([buf[44], buf[45], buf[46], buf[47]]),
            0,
            "dependent_typeid_count must be 0 (NOT the historical -1 sentinel)"
        );
        assert_eq!(
            u32::from_le_bytes([buf[48], buf[49], buf[50], buf[51]]),
            4,
            "empty dependent_typeids seq_DHEADER must be 4 (covers seq_count)"
        );
        assert_eq!(
            u32::from_le_bytes([buf[52], buf[53], buf[54], buf[55]]),
            0,
            "empty dependent_typeids seq_count must be 0"
        );
    }

    /// Helper: build a `CompleteTypeObject::Enumerated` for tests.
    #[cfg(feature = "xtypes-structural-assignability")]
    fn make_enum_obj(name: &str, literals: &[(&str, i32)]) -> CompleteTypeObject {
        use crate::xtypes::{
            CommonEnumeratedLiteral, CompleteEnumeratedHeader, CompleteEnumeratedLiteral,
            CompleteEnumeratedType, CompleteMemberDetail, CompleteTypeDetail,
            EnumeratedLiteralFlag,
        };
        CompleteTypeObject::Enumerated(CompleteEnumeratedType {
            enum_flags: crate::xtypes::StructTypeFlag::IS_APPENDABLE,
            header: CompleteEnumeratedHeader {
                bit_bound: 32,
                detail: CompleteTypeDetail::new(name),
            },
            literal_seq: literals
                .iter()
                .map(|(lit, val)| CompleteEnumeratedLiteral {
                    common: CommonEnumeratedLiteral {
                        value: *val,
                        flags: EnumeratedLiteralFlag::empty(),
                    },
                    detail: CompleteMemberDetail::new(*lit),
                })
                .collect(),
        })
    }

    /// Helper: compute the minimal EquivalenceHash of a CompleteTypeObject.
    #[cfg(feature = "xtypes-structural-assignability")]
    fn minimal_hash_of(obj: &CompleteTypeObject) -> EquivalenceHash {
        crate::dynamic::complete_to_minimal_type_object(obj)
            .expect("complete_to_minimal must succeed")
            .compute_equivalence_hash()
            .expect("compute_equivalence_hash must succeed")
    }

    /// Round-trip with 1 dependency: struct referencing an enum via
    /// TypeIdentifier::Minimal. Encodes with deps, parses back, asserts equal.
    #[cfg(feature = "xtypes-structural-assignability")]
    #[test]
    fn type_information_with_dep_round_trip() {
        let enum_obj = make_enum_obj("E2", &[("VAL0", 0), ("VAL1", 1), ("VAL2", 2), ("VAL3", 3)]);
        let min_hash_e2 = minimal_hash_of(&enum_obj);

        // Build a struct with one member referencing E2 via Minimal hash
        let struct_obj = CompleteTypeObject::Struct(CompleteStructType {
            struct_flags: StructTypeFlag::IS_FINAL,
            header: CompleteStructHeader {
                base_type: None,
                detail: CompleteTypeDetail::new("StructWithEnum"),
            },
            member_seq: vec![CompleteStructMember {
                common: CommonStructMember {
                    member_id: 0,
                    member_flags: MemberFlag::empty(),
                    member_type_id: TypeIdentifier::minimal(min_hash_e2),
                },
                detail: CompleteMemberDetail::new("color"),
            }],
        });

        // Store keyed by minimal hash of each dep CompleteTypeObject
        let mut store = std::collections::HashMap::new();
        store.insert(min_hash_e2, enum_obj);

        let info = derive_type_information_with_deps(&struct_obj, &store)
            .expect("must derive TypeInformation with deps");

        // Exactly 1 dep in both members
        assert_eq!(
            info.minimal.as_ref().unwrap().dependent_typeids.len(),
            1,
            "minimal member must have 1 dep"
        );
        assert_eq!(
            info.complete.as_ref().unwrap().dependent_typeids.len(),
            1,
            "complete member must have 1 dep"
        );

        // Encode
        let mut buf = [0u8; 512];
        let mut offset = 0;
        let written =
            write_type_information(&info, &mut buf, &mut offset).expect("emit must succeed");
        assert!(written, "must emit PID_TYPE_INFORMATION");

        // Parse back and assert round-trip equality
        let payload = &buf[4..offset];
        let parsed = crate::protocol::discovery::sedp::parse::parse_type_information(payload)
            .expect("parser must accept dep-format wire bytes");

        assert_eq!(
            parsed, info,
            "round-trip must preserve TypeInformation with deps"
        );
    }

    /// The announced EK_COMPLETE identity must be the spec-correct wire form
    /// (Complete member references per DDS-XTypes v1.3 7.3.4.5), NOT the
    /// internal hybrid whose members hold EK_MINIMAL references; the Minimal
    /// side must be byte-unchanged.
    #[cfg(feature = "xtypes-structural-assignability")]
    #[test]
    fn type_information_announces_wire_complete_identity() {
        let enum_obj = make_enum_obj("E2", &[("VAL0", 0), ("VAL1", 1)]);
        let min_hash_e2 = minimal_hash_of(&enum_obj);
        let cmp_hash_e2 = enum_obj
            .compute_equivalence_hash()
            .expect("enum complete hash");

        let struct_obj = CompleteTypeObject::Struct(CompleteStructType {
            struct_flags: StructTypeFlag::IS_FINAL,
            header: CompleteStructHeader {
                base_type: None,
                detail: CompleteTypeDetail::new("StructWithEnum"),
            },
            member_seq: vec![CompleteStructMember {
                common: CommonStructMember {
                    member_id: 0,
                    member_flags: MemberFlag::empty(),
                    member_type_id: TypeIdentifier::minimal(min_hash_e2),
                },
                detail: CompleteMemberDetail::new("color"),
            }],
        });

        let mut store = std::collections::HashMap::new();
        store.insert(min_hash_e2, enum_obj);

        let info = derive_type_information_with_deps(&struct_obj, &store)
            .expect("must derive TypeInformation with deps");

        let wire_obj = crate::dynamic::complete_type_object_with_complete_refs(&struct_obj, &store);
        let wire_hash = wire_obj.compute_equivalence_hash().expect("wire hash");
        let hybrid_hash = struct_obj.compute_equivalence_hash().expect("hybrid hash");

        let complete = info.complete.as_ref().expect("complete member");
        assert_eq!(
            complete.hash, wire_hash,
            "announced complete hash must be the wire (Complete-refs) hash"
        );
        assert_ne!(
            complete.hash, hybrid_hash,
            "announced complete hash must NOT be the hybrid identity"
        );
        assert_eq!(
            complete.typeobject_serialized_size,
            cdr2_size_complete(&wire_obj).expect("wire size"),
            "announced complete size must describe the wire object"
        );

        // Dependent complete typeid = the dep's Complete equivalence hash.
        assert_eq!(
            complete.dependent_typeids[0].hash, cmp_hash_e2,
            "dependent complete id must be the enum's Complete hash"
        );

        // Minimal side byte-unchanged vs the plain (dep-less) derivation.
        let plain = derive_type_information(&struct_obj).expect("plain derive");
        assert_eq!(
            info.minimal.as_ref().expect("minimal").hash,
            plain.minimal.as_ref().expect("plain minimal").hash,
            "minimal hash must be untouched by the wire rewrite"
        );
        assert_eq!(
            info.minimal
                .as_ref()
                .expect("minimal")
                .typeobject_serialized_size,
            plain
                .minimal
                .as_ref()
                .expect("plain minimal")
                .typeobject_serialized_size,
            "minimal size must be untouched by the wire rewrite"
        );
        // Dependent minimal typeid untouched: still the enum's Minimal hash.
        assert_eq!(
            info.minimal.as_ref().expect("minimal").dependent_typeids[0].hash,
            min_hash_e2,
            "dependent minimal id must remain the enum's Minimal hash"
        );
    }

    /// Structural byte checks for 1-dep format:
    /// - minimal member NEXTINT must be 64 (= 40 + 1*24)
    /// - dep_count must be 1
    /// - element DHEADER must be 20
    /// - dep kind in minimal member must be EK_MINIMAL
    #[cfg(feature = "xtypes-structural-assignability")]
    #[test]
    fn type_information_with_dep_structural_bytes() {
        let enum_obj = make_enum_obj("E2", &[("VAL0", 0), ("VAL1", 1), ("VAL2", 2), ("VAL3", 3)]);
        let min_hash_e2 = minimal_hash_of(&enum_obj);

        let struct_obj = CompleteTypeObject::Struct(CompleteStructType {
            struct_flags: StructTypeFlag::IS_FINAL,
            header: CompleteStructHeader {
                base_type: None,
                detail: CompleteTypeDetail::new("StructWithEnum"),
            },
            member_seq: vec![CompleteStructMember {
                common: CommonStructMember {
                    member_id: 0,
                    member_flags: MemberFlag::empty(),
                    member_type_id: TypeIdentifier::minimal(min_hash_e2),
                },
                detail: CompleteMemberDetail::new("color"),
            }],
        });

        let mut store = std::collections::HashMap::new();
        store.insert(min_hash_e2, enum_obj);

        let info = derive_type_information_with_deps(&struct_obj, &store).expect("must derive");

        let mut buf = [0u8; 512];
        let mut offset = 0;
        write_type_information(&info, &mut buf, &mut offset).expect("emit");

        // Layout (1 dep per member):
        //   [0..4]  PID header
        //   [4..8]  DHEADER outer
        //   [8..12] EMHEADER minimal (0x40001001)
        //   [12..16] NEXTINT minimal  <- must be 64
        //   [16..20] DHEADER_tiwdeps (= 60)
        //   [20..24] DHEADER_tiws (= 20)
        //   [24]    disc (EK_MINIMAL)
        //   [25..39] hash (14 bytes)
        //   [39]    pad
        //   [40..44] size
        //   [44..48] dep_count        <- must be 1
        //   [48..52] seq_DHEADER (= 28)
        //   [52..56] seq_count (= 1)
        //   element at [56]:
        //     [56..60] DHEADER_tiws_elem <- must be 20
        //     [60]    dep kind            <- must be EK_MINIMAL
        //     ...

        let nextint_min = u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]);
        assert_eq!(
            nextint_min, 64,
            "NEXTINT for 1-dep minimal member must be 64"
        );

        let dep_count = u32::from_le_bytes([buf[44], buf[45], buf[46], buf[47]]);
        assert_eq!(dep_count, 1, "dep_count must be 1");

        let elem_dheader = u32::from_le_bytes([buf[56], buf[57], buf[58], buf[59]]);
        assert_eq!(elem_dheader, 20, "element DHEADER_tiws must be 20");

        assert_eq!(
            buf[60], EK_MINIMAL,
            "dep kind in minimal member must be EK_MINIMAL"
        );
    }

    // -------------------------------------------------------------------------
    // Union wave C: PID_TYPE_INFORMATION for UNION-typed endpoints
    // -------------------------------------------------------------------------

    /// Helper: build a `CompleteTypeObject::Union` with the given
    /// discriminator identifier and a second branch of the given type. The
    /// first branch is a plain int32. Branch member ids are 1-based per
    /// DDS-XTypes v1.3 7.3.1.2.1.1 (discriminator consumes id 0).
    #[cfg(feature = "xtypes-structural-assignability")]
    fn make_union_obj(
        name: &str,
        discriminator: TypeIdentifier,
        second_branch_type: TypeIdentifier,
    ) -> CompleteTypeObject {
        use crate::xtypes::{
            CommonUnionMember, CompleteUnionHeader, CompleteUnionMember, CompleteUnionType,
            UnionTypeFlag,
        };
        CompleteTypeObject::Union(CompleteUnionType {
            union_flags: UnionTypeFlag::IS_APPENDABLE,
            header: CompleteUnionHeader {
                discriminator,
                discriminator_flags: MemberFlag::empty(),
                detail: CompleteTypeDetail::new(name),
            },
            member_seq: vec![
                CompleteUnionMember {
                    common: CommonUnionMember {
                        member_id: 1,
                        member_flags: MemberFlag::TRY_CONSTRUCT1,
                        member_type_id: TypeIdentifier::primitive(TypeKind::TK_INT32),
                        label_seq: vec![0],
                    },
                    detail: CompleteMemberDetail::new("a"),
                },
                CompleteUnionMember {
                    common: CommonUnionMember {
                        member_id: 2,
                        member_flags: MemberFlag::TRY_CONSTRUCT1,
                        member_type_id: second_branch_type,
                        label_seq: vec![1],
                    },
                    detail: CompleteMemberDetail::new("b"),
                },
            ],
        })
    }

    /// Union arm of `derive_minimal`: a union-typed endpoint must derive a
    /// `TypeInformation` whose hashes equal the bridge-computed ones (the
    /// same Minimal conversion used by `--print-typeid`).
    #[cfg(feature = "xtypes-structural-assignability")]
    #[test]
    fn union_type_information_hashes_match_bridge() {
        let enum_obj = make_enum_obj("Disc", &[("RED", 0), ("GREEN", 1), ("BLUE", 2)]);
        let disc_min_hash = minimal_hash_of(&enum_obj);
        let union_obj = make_union_obj(
            "U1",
            TypeIdentifier::minimal(disc_min_hash),
            TypeIdentifier::primitive(TypeKind::TK_FLOAT32),
        );

        let info = derive_type_information(&union_obj)
            .expect("Union variant must derive a TypeInformation");

        let expected_minimal = minimal_hash_of(&union_obj);
        let expected_complete = union_obj
            .compute_equivalence_hash()
            .expect("union complete hash must compute");

        let minimal = info.minimal.as_ref().expect("minimal member populated");
        let complete = info.complete.as_ref().expect("complete member populated");
        assert_eq!(
            minimal.hash, expected_minimal,
            "minimal hash must equal the bridge-computed Minimal EquivalenceHash"
        );
        assert_eq!(
            complete.hash, expected_complete,
            "complete hash must equal the announced TypeObject's EquivalenceHash"
        );
        // Sizes advertise the ENCAPSULATED CDR2 length (body + 4).
        assert!(
            minimal.typeobject_serialized_size > TYPEOBJECT_ENCAPSULATION_BYTES,
            "minimal typeobject_serialized_size must be non-trivial"
        );
        assert!(
            complete.typeobject_serialized_size > TYPEOBJECT_ENCAPSULATION_BYTES,
            "complete typeobject_serialized_size must be non-trivial"
        );
        // `derive_type_information` never populates deps.
        assert!(minimal.dependent_typeids.is_empty());
        assert!(complete.dependent_typeids.is_empty());
    }

    /// Union deps: an enum discriminator (Minimal indirect hash) AND a
    /// nested-struct branch must both surface in `dependent_typeids`, in
    /// BFS order (discriminator first, per `member_type_ids`), with
    /// EK_MINIMAL/EK_MINIMAL kinds on the minimal member and
    /// EK_COMPLETE on the complete member. Wire round-trip must hold.
    #[cfg(feature = "xtypes-structural-assignability")]
    #[test]
    fn union_type_information_deps_disc_and_branch() {
        let enum_obj = make_enum_obj("Disc", &[("A", 0), ("B", 1)]);
        let disc_min_hash = minimal_hash_of(&enum_obj);
        let nested_struct = temperature_complete();
        let nested_min_hash = minimal_hash_of(&nested_struct);

        let union_obj = make_union_obj(
            "U2",
            TypeIdentifier::minimal(disc_min_hash),
            TypeIdentifier::minimal(nested_min_hash),
        );

        let mut store = std::collections::HashMap::new();
        store.insert(disc_min_hash, enum_obj.clone());
        store.insert(nested_min_hash, nested_struct.clone());

        let info = derive_type_information_with_deps(&union_obj, &store)
            .expect("union with resolvable deps must derive TypeInformation");

        let min_deps = &info.minimal.as_ref().expect("minimal").dependent_typeids;
        let cmp_deps = &info.complete.as_ref().expect("complete").dependent_typeids;
        assert_eq!(min_deps.len(), 2, "discriminator + struct branch = 2 deps");
        assert_eq!(cmp_deps.len(), 2, "complete member mirrors the dep count");

        // BFS seeds the discriminator before branch members.
        assert_eq!(min_deps[0].kind, EK_MINIMAL);
        assert_eq!(
            min_deps[0].hash, disc_min_hash,
            "first minimal dep must be the enum discriminator's Minimal hash"
        );
        assert_eq!(
            min_deps[1].hash, nested_min_hash,
            "second minimal dep must be the struct branch's Minimal hash"
        );
        assert_eq!(cmp_deps[0].kind, EK_COMPLETE);
        assert_eq!(
            cmp_deps[0].hash,
            enum_obj
                .compute_equivalence_hash()
                .expect("enum complete hash"),
            "first complete dep must be the enum discriminator's Complete hash"
        );
        assert_eq!(
            cmp_deps[1].hash,
            nested_struct
                .compute_equivalence_hash()
                .expect("struct complete hash"),
            "second complete dep must be the struct branch's Complete hash"
        );

        // Wire round-trip: emit + parse must preserve the union TypeInformation.
        let mut buf = [0u8; 512];
        let mut offset = 0;
        let written = write_type_information(&info, &mut buf, &mut offset)
            .expect("emit must succeed for union TypeInformation");
        assert!(
            written,
            "union TypeInformation must emit PID_TYPE_INFORMATION"
        );
        let parsed =
            crate::protocol::discovery::sedp::parse::parse_type_information(&buf[4..offset])
                .expect("parser must accept union TypeInformation wire bytes");
        assert_eq!(
            parsed, info,
            "round-trip must preserve union TypeInformation"
        );
    }

    /// A union whose discriminator is a plain primitive (int32) and whose
    /// branches are all primitives has NO dependent typeids: the dep
    /// collector must return empty and emission must fall back to the
    /// zero-dep 100-byte layout.
    #[cfg(feature = "xtypes-structural-assignability")]
    #[test]
    fn union_type_information_primitive_disc_zero_deps() {
        let union_obj = make_union_obj(
            "U3",
            TypeIdentifier::primitive(TypeKind::TK_INT32),
            TypeIdentifier::primitive(TypeKind::TK_FLOAT64),
        );
        let store = std::collections::HashMap::new();
        let info = derive_type_information_with_deps(&union_obj, &store)
            .expect("primitive-disc union must still derive TypeInformation");
        assert!(
            info.minimal.as_ref().unwrap().dependent_typeids.is_empty(),
            "all-primitive union must have zero deps"
        );
        let mut buf = [0u8; 256];
        let mut offset = 0;
        let written = write_type_information(&info, &mut buf, &mut offset).expect("emit succeeds");
        assert!(written);
        assert_eq!(
            offset,
            4 + 100,
            "zero-dep union must emit the 100-byte payload"
        );
    }
}
