// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Bridge between XTypes TypeObject and dynamic TypeDescriptor.
//!
//! Converts discovered XTypes CompleteTypeObject to runtime TypeDescriptor
//! for dynamic CDR decoding without compile-time type knowledge.
//!
//! ## Type Resolution
//!
//! Complex XTypes fields reference nested types via [`EquivalenceHash`] inside
//! [`TypeIdentifier::Minimal`] or [`TypeIdentifier::Complete`] variants.
//! To resolve these hashes back into full type descriptors, pass a
//! [`TypeRegistry`] to [`type_descriptor_from_xtypes_with_registry`].
//!
//! Without a registry, hash-based identifiers fall back to an opaque
//! `nested` / `cyclic` placeholder (useful for quick inspection but not
//! for accurate CDR decoding of nested structs).

use crate::dynamic::{
    ArrayDescriptor, EnumDescriptor, EnumVariant, Extensibility, FieldDescriptor, PrimitiveKind,
    SequenceDescriptor, TryConstructKind, TypeDescriptor, TypeKind, UnionCase, UnionDescriptor,
};
use crate::xtypes::{
    AppliedBuiltinMemberAnnotations, BitflagFlag, CollectionElementFlag, CommonBitflag,
    CommonStructMember, CommonUnionMember, CompleteArrayType, CompleteBitflag,
    CompleteBitmaskHeader, CompleteBitmaskType, CompleteEnumeratedType, CompleteMemberDetail,
    CompleteSequenceType, CompleteStructHeader, CompleteStructMember, CompleteStructType,
    CompleteTypeDetail, CompleteTypeObject, CompleteUnionHeader, CompleteUnionMember,
    CompleteUnionType, EquivalenceHash, EquivalenceKind, MemberFlag, MinimalBitflag,
    MinimalBitmaskHeader, MinimalBitmaskType, MinimalMemberDetail, MinimalStructHeader,
    MinimalStructMember, MinimalStructType, MinimalTypeDetail, MinimalTypeObject,
    MinimalUnionHeader, MinimalUnionMember, MinimalUnionType, PlainArrayLElemDefn,
    PlainArraySElemDefn, PlainCollectionHeader, PlainSequenceLElemDefn, PlainSequenceSElemDefn,
    StructTypeFlag, TypeIdentifier, TypeKind as XTypesKind, UnionTypeFlag,
};
use std::collections::HashMap;
use std::sync::Arc;

/// `enum_flags` of every enumeration this bridge lowers.
///
/// The flag is the enum's declared extensibility (DDS-XTypes 1.3 7.2.3 Table
/// 12: final or appendable), and it is serialized, so it is part of the
/// EquivalenceHash. The dynamic model cannot declare it
/// (`TypeDescriptor::extensibility` applies to structs only), so the
/// specification's default applies: "the type shall be considered appendable"
/// (7.3.1.2.1.8). This is the value HDDS has always written here.
const DYNAMIC_ENUM_FLAGS: crate::xtypes::EnumTypeFlag = StructTypeFlag::IS_APPENDABLE;

/// Annex B declares BitmaskTypeFlag unused. Keep it empty for every
/// bitmask identity, whether referenced by a member or a discriminator.
const DYNAMIC_BITMASK_FLAGS: crate::xtypes::BitmaskTypeFlag = StructTypeFlag::empty();

// ---------------------------------------------------------------------------
// TypeRegistry trait + HashMap implementation
// ---------------------------------------------------------------------------

/// Registry that resolves XTypes [`EquivalenceHash`] values to their
/// corresponding [`CompleteTypeObject`].
///
/// This is used during XTypes-to-TypeDescriptor conversion to resolve
/// hash-based [`TypeIdentifier::Minimal`] / [`TypeIdentifier::Complete`]
/// references into full type definitions.
///
/// # Example
///
/// ```ignore
/// use hdds::dynamic::{HashMapTypeRegistry, TypeRegistry};
///
/// let mut registry = HashMapTypeRegistry::new();
/// registry.register(inner_hash, inner_type_object);
///
/// let descriptor = type_descriptor_from_xtypes_with_registry(
///     &outer_type_object,
///     Some(&registry),
/// );
/// ```
pub trait TypeRegistry {
    /// Look up a [`CompleteTypeObject`] by its equivalence hash.
    ///
    /// Returns `None` if the hash is unknown.
    fn lookup(&self, hash: &EquivalenceHash) -> Option<&CompleteTypeObject>;
}

/// Simple [`HashMap`]-backed [`TypeRegistry`].
///
/// Suitable for tests and moderate-size type systems.  For large-scale
/// deployments, consider wrapping a concurrent map (e.g. `DashMap`).
#[derive(Debug, Default)]
pub struct HashMapTypeRegistry {
    types: HashMap<EquivalenceHash, CompleteTypeObject>,
}

impl HashMapTypeRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a [`CompleteTypeObject`] under the given hash.
    pub fn register(&mut self, hash: EquivalenceHash, type_object: CompleteTypeObject) {
        self.types.insert(hash, type_object);
    }

    /// Number of registered types.
    #[must_use]
    pub fn len(&self) -> usize {
        self.types.len()
    }

    /// Returns `true` if no types are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.types.is_empty()
    }
}

impl TypeRegistry for HashMapTypeRegistry {
    fn lookup(&self, hash: &EquivalenceHash) -> Option<&CompleteTypeObject> {
        self.types.get(hash)
    }
}

// ---------------------------------------------------------------------------
// Public conversion entry points
// ---------------------------------------------------------------------------

/// Convert a [`CompleteTypeObject`] to a dynamic [`TypeDescriptor`].
///
/// This is a convenience wrapper around [`type_descriptor_from_xtypes_with_registry`]
/// that does **not** resolve hash-based nested type references.  Fields
/// whose type is identified by an [`EquivalenceHash`] will be returned as
/// an opaque `nested` placeholder.
///
/// # Example
///
/// ```ignore
/// use hdds::dynamic::type_descriptor_from_xtypes;
///
/// // Get TypeObject from discovery
/// let topics = participant.discover_topics()?;
/// if let Some(type_object) = &topics[0].type_object {
///     let descriptor = type_descriptor_from_xtypes(type_object);
///     let data = decode_dynamic(&cdr_bytes, &descriptor)?;
/// }
/// ```
pub fn type_descriptor_from_xtypes(type_object: &CompleteTypeObject) -> Arc<TypeDescriptor> {
    convert_type_object(type_object, None::<&HashMapTypeRegistry>)
}

/// Convert a [`CompleteTypeObject`] to a dynamic [`TypeDescriptor`],
/// resolving hash-based nested type references via the supplied registry.
///
/// When a field's [`TypeIdentifier`] is `Minimal(hash)` or
/// `Complete(hash)`, the registry is queried for the corresponding
/// [`CompleteTypeObject`] and the conversion recurses into it.
///
/// If the registry is `None`, or a hash is not found, the field falls
/// back to the same opaque `nested` placeholder used by
/// [`type_descriptor_from_xtypes`].
///
/// # Example
///
/// ```ignore
/// use hdds::dynamic::{type_descriptor_from_xtypes_with_registry, HashMapTypeRegistry};
///
/// let mut registry = HashMapTypeRegistry::new();
/// // Register all nested types first...
/// registry.register(inner_hash, inner_type_object);
///
/// let descriptor = type_descriptor_from_xtypes_with_registry(
///     &outer_type_object,
///     Some(&registry),
/// );
/// ```
pub fn type_descriptor_from_xtypes_with_registry<R: TypeRegistry>(
    type_object: &CompleteTypeObject,
    registry: Option<&R>,
) -> Arc<TypeDescriptor> {
    convert_type_object(type_object, registry)
}

// ---------------------------------------------------------------------------
// Internal conversion (all functions now thread the optional registry)
// ---------------------------------------------------------------------------

/// Core dispatcher -- converts any CompleteTypeObject variant.
// @audit-ok: Simple pattern matching (cyclo 11, cogni 1) - dispatch CompleteTypeObject to converters
fn convert_type_object<R: TypeRegistry>(
    type_object: &CompleteTypeObject,
    registry: Option<&R>,
) -> Arc<TypeDescriptor> {
    match type_object {
        CompleteTypeObject::Struct(s) => convert_struct(s, registry),
        CompleteTypeObject::Enumerated(e) => convert_enum(e),
        CompleteTypeObject::Union(u) => convert_union(u, registry),
        CompleteTypeObject::Sequence(s) => convert_sequence(s, registry),
        CompleteTypeObject::Array(a) => convert_array(a, registry),
        CompleteTypeObject::Bitmask(b) => convert_bitmask(b),
        // Bitset and Alias are less common - return as primitive for now
        CompleteTypeObject::Bitset(_) => {
            Arc::new(TypeDescriptor::primitive("bitset", PrimitiveKind::U64))
        }
        CompleteTypeObject::Alias(a) => {
            // Alias is just a typedef - resolve to underlying type
            type_identifier_to_descriptor(&a.body.common.related_type, registry)
        }
        CompleteTypeObject::Map(_) => {
            // Map support requires key-value pair descriptor
            Arc::new(TypeDescriptor::primitive("map", PrimitiveKind::U8))
        }
        CompleteTypeObject::Annotation(_) => {
            // Annotations are metadata, not data types
            Arc::new(TypeDescriptor::primitive("annotation", PrimitiveKind::U8))
        }
    }
}

/// Convert a CompleteStructType to TypeDescriptor.
fn convert_struct<R: TypeRegistry>(
    s: &CompleteStructType,
    registry: Option<&R>,
) -> Arc<TypeDescriptor> {
    let name = s.header.detail.type_name.clone();

    let fields: Vec<FieldDescriptor> = s
        .member_seq
        .iter()
        .map(|member| {
            let field_name = member.detail.name.clone();
            let field_type = type_identifier_to_descriptor(&member.common.member_type_id, registry);
            let is_optional = member.common.member_flags.contains(MemberFlag::IS_OPTIONAL);
            let try_construct = member_flag_to_try_construct(member.common.member_flags);

            FieldDescriptor {
                name: field_name,
                type_desc: field_type,
                id: Some(member.common.member_id),
                optional: is_optional,
                default: None,
                try_construct,
                is_key: member.common.member_flags.contains(MemberFlag::IS_KEY),
                is_must_understand: member
                    .common
                    .member_flags
                    .contains(MemberFlag::IS_MUST_UNDERSTAND),
                // When a remote TypeObject carries a @hashid annotation in
                // ann_builtin.hash_id, propagate it so that downstream code
                // (CDR mutable encode / Minimal hash) uses the alias name.
                hashid_name: member
                    .detail
                    .ann_builtin
                    .as_ref()
                    .and_then(|a| a.hash_id.clone()),
            }
        })
        .collect();

    // The declared extensibility. DDS-XTypes 1.3 Annex B (TypeFlag, spec
    // text lines 12360-12362) requires exactly one of IS_FINAL,
    // IS_APPENDABLE, IS_MUTABLE on a structure or union object. An object
    // that carries none is malformed; it is read as FINAL, deliberately, for
    // compatibility: that is how this bridge has always read it, and a
    // descriptor's default (APPENDABLE) would change how its samples decode.
    let extensibility = if s.struct_flags.contains(StructTypeFlag::IS_MUTABLE) {
        Extensibility::Mutable
    } else if s.struct_flags.contains(StructTypeFlag::IS_APPENDABLE) {
        Extensibility::Appendable
    } else {
        Extensibility::Final
    };
    let mut descriptor =
        TypeDescriptor::struct_type(name, fields).with_extensibility(extensibility);
    // IS_AUTOID_HASH is serialized in struct_flags (Annex B, TypeFlag), so it
    // is part of the EquivalenceHash: keep it for the object to lower back to
    // the one received. Every member already carries its announced id.
    if s.struct_flags.contains(StructTypeFlag::IS_AUTOID_HASH) {
        descriptor = descriptor.with_autoid_hash();
    }
    Arc::new(descriptor)
}

/// Convert a CompleteEnumeratedType to TypeDescriptor.
fn convert_enum(e: &CompleteEnumeratedType) -> Arc<TypeDescriptor> {
    let name = e.header.detail.type_name.clone();

    let variants: Vec<EnumVariant> = e
        .literal_seq
        .iter()
        .map(|lit| {
            let variant_name = lit.detail.name.clone();
            EnumVariant::new(variant_name, lit.common.value as i64)
        })
        .collect();

    // The holder is Int8, Int16 or Int32 by @bit_bound (DDS-XTypes 1.3
    // Table 40); 32 stays the U32 every enum descriptor defaults to, which
    // `enum_bit_bound` maps back to 32. A bound outside 1..=32 (7.2.2.4.1)
    // is malformed and is read as the default, 32.
    let underlying = match e.header.bit_bound {
        1..=8 => PrimitiveKind::I8,
        9..=16 => PrimitiveKind::I16,
        17..=32 => PrimitiveKind::U32,
        other => {
            log::warn!("[xtypes] enum {name}: bit_bound {other} outside 1..=32, read as 32");
            PrimitiveKind::U32
        }
    };
    Arc::new(TypeDescriptor::new(
        name,
        TypeKind::Enum(EnumDescriptor::new(variants).with_underlying(underlying)),
    ))
}

/// Convert a CompleteUnionType to TypeDescriptor.
fn convert_union<R: TypeRegistry>(
    u: &CompleteUnionType,
    registry: Option<&R>,
) -> Arc<TypeDescriptor> {
    let name = u.header.detail.type_name.clone();
    let discriminator = type_identifier_to_descriptor(&u.header.discriminator, registry);

    let mut default_case: Option<Box<UnionCase>> = None;

    let cases: Vec<UnionCase> = u
        .member_seq
        .iter()
        .map(|member| {
            let case_name = member.detail.name.clone();
            let case_type = type_identifier_to_descriptor(&member.common.member_type_id, registry);
            let labels: Vec<i64> = member.common.label_seq.iter().map(|&v| v as i64).collect();
            let is_default = member.common.member_flags.contains(MemberFlag::IS_DEFAULT);

            let try_construct = member_flag_to_try_construct(member.common.member_flags);
            let case = UnionCase {
                name: case_name,
                labels: labels.clone(),
                type_desc: case_type,
                try_construct,
                member_id: Some(member.common.member_id),
            };

            if is_default {
                default_case = Some(Box::new(case.clone()));
            }

            case
        })
        .collect();

    // Recover the discriminator TryConstruct policy and @key status from the
    // discriminator member flags retained by the CDR2 decoder in the header
    // (wire `CommonDiscriminatorMember.member_flags`, XTypes v1.3 7.3.4.6).
    // Legacy/synthetic objects with empty header flags fall back to Discard
    // (TC1=0, TC2=0 = absent = discard per 7.2.2.4.1.2) and member-mirrored
    // keyness.
    let disc_flags = u.header.discriminator_flags;
    let discriminator_try_construct = member_flag_to_try_construct(disc_flags);
    let discriminator_is_key = disc_flags.contains(MemberFlag::IS_KEY)
        || u.member_seq
            .iter()
            .any(|m| m.common.member_flags.contains(MemberFlag::IS_KEY));

    // Declaration index of the default member, when present (keeps the
    // declared slot through a descriptor round-trip).
    let default_case_index = u
        .member_seq
        .iter()
        .position(|m| m.common.member_flags.contains(MemberFlag::IS_DEFAULT));

    // The declared extensibility, as `convert_struct` reads it; a union
    // object carrying none of the three flags (malformed, Annex B requires
    // exactly one) is read as FINAL, deliberately, for compatibility: the
    // value this bridge has always given a union.
    let extensibility = if u.union_flags.contains(UnionTypeFlag::IS_MUTABLE) {
        Extensibility::Mutable
    } else if u.union_flags.contains(UnionTypeFlag::IS_APPENDABLE) {
        Extensibility::Appendable
    } else {
        Extensibility::Final
    };
    Arc::new(
        TypeDescriptor::new(
            name,
            TypeKind::Union(UnionDescriptor {
                discriminator,
                cases,
                default_case,
                default_case_index,
                discriminator_try_construct,
                discriminator_is_key,
            }),
        )
        .with_extensibility(extensibility),
    )
}

/// Convert a CompleteSequenceType to TypeDescriptor.
fn convert_sequence<R: TypeRegistry>(
    s: &CompleteSequenceType,
    registry: Option<&R>,
) -> Arc<TypeDescriptor> {
    let element_type = type_identifier_to_descriptor(&s.element.type_id, registry);
    let max_length = if s.header.bound == 0 {
        None
    } else {
        Some(s.header.bound as usize)
    };

    Arc::new(TypeDescriptor::new(
        format!("sequence<{}>", element_type.name),
        TypeKind::Sequence(SequenceDescriptor {
            element_type,
            max_length,
        }),
    ))
}

/// Convert a CompleteArrayType to TypeDescriptor.
fn convert_array<R: TypeRegistry>(
    a: &CompleteArrayType,
    registry: Option<&R>,
) -> Arc<TypeDescriptor> {
    let element_type = type_identifier_to_descriptor(&a.element.type_id, registry);

    // For multi-dimensional arrays, compute total length
    let total_length: usize = a.header.bound_seq.iter().map(|&d| d as usize).product();

    // Format name with dimensions
    let dims: String = a
        .header
        .bound_seq
        .iter()
        .map(|d| format!("[{}]", d))
        .collect::<Vec<_>>()
        .join("");

    Arc::new(TypeDescriptor::new(
        format!("{}{}", element_type.name, dims),
        TypeKind::Array(ArrayDescriptor {
            element_type,
            length: total_length,
            dims: a.header.bound_seq.to_vec(),
        }),
    ))
}

/// Convert a CompleteBitmaskType to TypeDescriptor.
///
/// Bitmask is converted to an enum-like structure where each flag is a variant.
fn convert_bitmask(b: &CompleteBitmaskType) -> Arc<TypeDescriptor> {
    let name = b.header.detail.type_name.clone();

    // Convert bit flags to enum variants (position as value)
    let variants: Vec<EnumVariant> = b
        .flag_seq
        .iter()
        .map(|flag| {
            let flag_name = flag.detail.name.clone();
            let position = flag.common.position as i64;
            EnumVariant::new(flag_name, 1i64 << position)
        })
        .collect();

    // Bitmask is represented as an enum whose variant values are the flag
    // masks, marked as a bitmask, held in UInt8 to UInt64 by @bit_bound
    // (DDS-XTypes 1.3 Table 40), the inverse of `bitmask_bit_bound`.
    // A bound outside 1..=64 (DDS-XTypes 1.3 7.2.2.4.1) is malformed and is
    // read as the default, 32, as the enum arm does: 0 is not a 64-bit holder.
    let underlying = match b.header.bit_bound {
        1..=8 => PrimitiveKind::U8,
        9..=16 => PrimitiveKind::U16,
        17..=32 => PrimitiveKind::U32,
        33..=64 => PrimitiveKind::U64,
        other => {
            log::warn!("[xtypes] bitmask {name}: bit_bound {other} outside 1..=64, read as 32");
            PrimitiveKind::U32
        }
    };
    Arc::new(TypeDescriptor::new(
        name,
        TypeKind::Enum(EnumDescriptor::new_bitmask(variants).with_underlying(underlying)),
    ))
}

/// Convert XTypes TypeIdentifier to dynamic TypeDescriptor.
///
/// When `registry` is `Some`, hash-based identifiers (Minimal / Complete)
/// are resolved to their full [`CompleteTypeObject`] and converted
/// recursively.  Without a registry (or on cache miss), these fall back
/// to an opaque `nested` placeholder.
fn type_identifier_to_descriptor<R: TypeRegistry>(
    type_id: &TypeIdentifier,
    registry: Option<&R>,
) -> Arc<TypeDescriptor> {
    match type_id {
        TypeIdentifier::Primitive(kind) => {
            let prim = xtypes_kind_to_primitive(*kind);
            Arc::new(TypeDescriptor::primitive(format!("{:?}", kind), prim))
        }
        TypeIdentifier::StringSmall { bound } => {
            let max_len = if *bound == 0 {
                None
            } else {
                Some(*bound as usize)
            };
            Arc::new(TypeDescriptor::primitive(
                "string",
                PrimitiveKind::String {
                    max_length: max_len,
                },
            ))
        }
        TypeIdentifier::StringLarge { bound } => {
            let max_len = if *bound == 0 {
                None
            } else {
                Some(*bound as usize)
            };
            Arc::new(TypeDescriptor::primitive(
                "string",
                PrimitiveKind::String {
                    max_length: max_len,
                },
            ))
        }
        TypeIdentifier::WStringSmall { bound } => {
            let max_len = if *bound == 0 {
                None
            } else {
                Some(*bound as usize)
            };
            Arc::new(TypeDescriptor::primitive(
                "wstring",
                PrimitiveKind::WString {
                    max_length: max_len,
                },
            ))
        }
        TypeIdentifier::WStringLarge { bound } => {
            let max_len = if *bound == 0 {
                None
            } else {
                Some(*bound as usize)
            };
            Arc::new(TypeDescriptor::primitive(
                "wstring",
                PrimitiveKind::WString {
                    max_length: max_len,
                },
            ))
        }
        // Hash-based types: resolve via registry when available.
        TypeIdentifier::Minimal(hash) | TypeIdentifier::Complete(hash) => {
            if let Some(reg) = registry {
                if let Some(type_object) = reg.lookup(hash) {
                    return convert_type_object(type_object, registry);
                }
            }
            // Fallback: no registry or hash not found.
            Arc::new(TypeDescriptor::primitive("nested", PrimitiveKind::U8))
        }
        // Strongly connected components (cyclic types)
        TypeIdentifier::StronglyConnected { .. } => {
            Arc::new(TypeDescriptor::primitive("cyclic", PrimitiveKind::U8))
        }
        // Plain collections -- the dynamic bridge does not yet model
        // sequences / arrays / maps as first-class TypeDescriptors;
        // fall back to an opaque `plain_collection` placeholder. The
        // full recursive descriptor synthesis is tracked separately
        // outside the scope of this module.
        TypeIdentifier::PlainSequenceSmall(_)
        | TypeIdentifier::PlainSequenceLarge(_)
        | TypeIdentifier::PlainArraySmall(_)
        | TypeIdentifier::PlainArrayLarge(_)
        | TypeIdentifier::PlainMapSmall(_)
        | TypeIdentifier::PlainMapLarge(_) => Arc::new(TypeDescriptor::primitive(
            "plain_collection",
            PrimitiveKind::U8,
        )),
    }
}

/// Convert XTypes TypeKind to dynamic PrimitiveKind.
// @audit-ok: Simple pattern matching (cyclo 18, cogni 1) - XTypes to PrimitiveKind conversion table
fn xtypes_kind_to_primitive(kind: XTypesKind) -> PrimitiveKind {
    match kind {
        XTypesKind::TK_BOOLEAN => PrimitiveKind::Bool,
        // TK_BYTE (0x02) and TK_UINT8 (0x0D) are distinct XTypes primitive kinds.
        // Per DDS-XTypes v1.3 sec. 7.5.1.3 Table 3, TK_BYTE does NOT widen to TK_UINT8.
        XTypesKind::TK_BYTE => PrimitiveKind::Byte,
        XTypesKind::TK_UINT8 => PrimitiveKind::U8,
        XTypesKind::TK_INT8 => PrimitiveKind::I8,
        XTypesKind::TK_INT16 => PrimitiveKind::I16,
        XTypesKind::TK_UINT16 => PrimitiveKind::U16,
        XTypesKind::TK_INT32 => PrimitiveKind::I32,
        XTypesKind::TK_UINT32 => PrimitiveKind::U32,
        XTypesKind::TK_INT64 => PrimitiveKind::I64,
        XTypesKind::TK_UINT64 => PrimitiveKind::U64,
        XTypesKind::TK_FLOAT32 => PrimitiveKind::F32,
        XTypesKind::TK_FLOAT64 => PrimitiveKind::F64,
        XTypesKind::TK_FLOAT128 => PrimitiveKind::LongDouble,
        XTypesKind::TK_CHAR8 => PrimitiveKind::Char,
        XTypesKind::TK_CHAR16 => PrimitiveKind::Char, // Simplified
        XTypesKind::TK_STRING8 => PrimitiveKind::String { max_length: None },
        XTypesKind::TK_STRING16 => PrimitiveKind::WString { max_length: None },
        _ => PrimitiveKind::U8, // Fallback for non-primitives
    }
}

// ---------------------------------------------------------------------------
// Reverse direction: TypeDescriptor -> CompleteTypeObject
// ---------------------------------------------------------------------------
//
// The forward direction (CompleteTypeObject -> TypeDescriptor) above is the
// receive path: it converts a remote type announcement into a runtime
// descriptor for dynamic decoding. The reverse direction is the emission
// path: it lets a runtime-built dynamic type contribute to SEDP discovery
// (`PID_TYPE_OBJECT` 0x0072 + `PID_TYPE_INFORMATION` 0x0075 emission in
// `protocol::discovery::sedp::build`).
//
// Today this conversion handles primitive (incl. string / wstring), plain
// array, plain sequence, and TypeKind::Nested struct members recursively.
// TypeKind::Nested lowers to TypeIdentifier::Minimal via the MD5 hash of the
// inner struct's MinimalTypeObject (XTypes v1.3 sec. 7.3.4.8). Fields typed as
// raw TypeKind::Struct (not wrapped in Nested) still fall through to None;
// callers must check the Option return value and gracefully skip TypeObject
// emission when the descriptor cannot be lowered.

/// Convert a primitive `PrimitiveKind` to the matching XTypes `TypeKind`
/// octet. Returns `None` for primitives that have no direct XTypes
/// counterpart (today: `LongDouble` maps to `TK_FLOAT128` only when the
/// host's `long double` width is 16 bytes; the 8-byte alias path is left
/// for the consolidation pass).
fn primitive_kind_to_xtypes_kind(prim: PrimitiveKind) -> Option<XTypesKind> {
    Some(match prim {
        PrimitiveKind::Bool => XTypesKind::TK_BOOLEAN,
        // Preserve the semantic distinction: Byte lowers to TK_BYTE (0x02),
        // U8 lowers to TK_UINT8 (0x0D). They must NOT be merged on the wire.
        PrimitiveKind::Byte => XTypesKind::TK_BYTE,
        PrimitiveKind::U8 => XTypesKind::TK_UINT8,
        PrimitiveKind::I8 => XTypesKind::TK_INT8,
        PrimitiveKind::U16 => XTypesKind::TK_UINT16,
        PrimitiveKind::I16 => XTypesKind::TK_INT16,
        PrimitiveKind::U32 => XTypesKind::TK_UINT32,
        PrimitiveKind::I32 => XTypesKind::TK_INT32,
        PrimitiveKind::U64 => XTypesKind::TK_UINT64,
        PrimitiveKind::I64 => XTypesKind::TK_INT64,
        PrimitiveKind::F32 => XTypesKind::TK_FLOAT32,
        PrimitiveKind::F64 => XTypesKind::TK_FLOAT64,
        PrimitiveKind::LongDouble => XTypesKind::TK_FLOAT128,
        PrimitiveKind::Char => XTypesKind::TK_CHAR8,
        PrimitiveKind::String { .. } | PrimitiveKind::WString { .. } => return None,
    })
}

/// Convert a dynamic `TypeDescriptor` field type to an XTypes
/// `TypeIdentifier`.
///
/// Handles primitives (including strings), plain arrays, plain sequences,
/// enums, and struct types recursively.  For struct element types (e.g. an
/// array of struct), the referenced TypeObject is serialized as XCDR2-LE
/// and MD5-hashed to produce its equivalence identifier.
///
/// Returns `None` only for shapes that have no sensible TypeIdentifier
/// representation (maps, bitsets, unions used as bare top-level identifiers
/// without a containing struct).
///
/// # Array encoding
///
/// When `ArrayDescriptor::dims` is non-empty the per-dimension sizes are
/// used for `array_bound_seq` directly (DDS-XTypes sec. 7.2.2.4.3).  Otherwise
/// the single flat `length` value is used.  The Small vs Large variant is
/// determined by whether all dimension values fit in a `u8`.
///
/// # Sequence encoding
///
/// `SequenceDescriptor::max_length` maps to the `LBound` (0 = unbounded):
/// - bound == None (unbounded) or bound <= 255: `PlainSequenceSmall` (bound 0 encodes unbounded).
/// - bound > 255: `PlainSequenceLarge`.
// reason: only called from #[cfg(test)] unit tests in this file; the
// non-test lib build has no caller, so dead_code fires without this allow.
#[allow(dead_code)]
fn descriptor_to_type_identifier(descriptor: &TypeDescriptor) -> Option<TypeIdentifier> {
    // Default (Minimal) equivalence: this is the reference used by the SEDP
    // emission path, the runtime matcher, and the HDDS<->HDDS self path, all
    // of which key on the Minimal TypeObject. Keeping this wrapper at Minimal
    // means those paths are byte-unchanged.
    descriptor_to_type_identifier_impl(descriptor, false, EquivalenceKind::Minimal)
}

/// Equivalence-aware variant of [`descriptor_to_type_identifier`].
///
/// Per DDS-XTypes v1.3 sec. 7.3.4.5 / sec. 7.3.4.8, the CompleteTypeObject of an
/// aggregated type references its hash-based members (enums, nested-struct
/// collection elements) by their **Complete** equivalence hash, while the
/// MinimalTypeObject references the same members by their **Minimal**
/// equivalence hash. `kind` selects which equivalence to emit so the two
/// outer TypeObjects carry the matching member references.
fn descriptor_to_type_identifier_kind(
    descriptor: &TypeDescriptor,
    kind: EquivalenceKind,
) -> Option<TypeIdentifier> {
    descriptor_to_type_identifier_impl(descriptor, false, kind)
}

/// Inner implementation; `in_collection` = true means this descriptor is
/// an element type inside an array or sequence.
///
/// When `in_collection=true`, string bounds are preserved in the element
/// TypeIdentifier.  If the outer struct hashes differ (because element
/// TypeIds differ), `is_assignable_final` falls through to
/// `members_assignable_final_with_policy` which calls `type_id_assignable`
/// on each member; that function applies `ignore_string_bounds` correctly.
/// Stripping the bounds here would prevent `ignore_string_bounds=false`
/// enforcement for sequence-of-string members.
/// Choose the `PlainCollectionHeader.equiv_kind` for a plain array/sequence
/// from its element TypeIdentifier, per DDS-XTypes v1.3 sec. 7.3.4.4.
///
/// When the element is referenced by an equivalence hash the header echoes
/// that equivalence (`EK_MINIMAL` / `EK_COMPLETE`). When the element is
/// fully self-describing (including collections of fully descriptive types),
/// the minimal and complete TypeObjects of the collection coincide, so the
/// header carries `EK_BOTH` (0xF3) -- the spec-conformant value. Emitting
/// `EK_COMPLETE` here was a non-conformance
/// that perturbed every collection's EquivalenceHash.
fn collection_equiv_kind(element_id: &TypeIdentifier) -> EquivalenceKind {
    use TypeIdentifier::*;
    match element_id {
        Minimal(_) => EquivalenceKind::Minimal,
        Complete(_) => EquivalenceKind::Complete,
        StronglyConnected(scc) => scc.kind,
        PlainSequenceSmall(s) => s.header.equiv_kind,
        PlainSequenceLarge(s) => s.header.equiv_kind,
        PlainArraySmall(a) => a.header.equiv_kind,
        PlainArrayLarge(a) => a.header.equiv_kind,
        PlainMapSmall(m) => m.header.equiv_kind,
        PlainMapLarge(m) => m.header.equiv_kind,
        _ => EquivalenceKind::Both,
    }
}

fn descriptor_to_type_identifier_impl(
    descriptor: &TypeDescriptor,
    in_collection: bool,
    kind: EquivalenceKind,
) -> Option<TypeIdentifier> {
    match &descriptor.kind {
        TypeKind::Primitive(prim) => match prim {
            PrimitiveKind::String { max_length } => {
                // Preserve string bound even in collection context; the
                // ignore_string_bounds policy is applied by type_id_assignable
                // when comparing element TypeIdentifiers.
                let _ = in_collection;
                if let Some(bound) = max_length {
                    // Bounded string: emit StringSmall{N} or StringLarge{N} based on size.
                    Some(TypeIdentifier::string(
                        u32::try_from(*bound).unwrap_or(u32::MAX),
                    ))
                } else {
                    // Unbounded string (bound=0 per XTypes v1.3 sec. 7.3.4.4 / sec. 7.3.4.5):
                    // the Small vs Large variant is selected purely by whether the
                    // bound fits in a u8. Bound 0 fits, so the spec-conformant
                    // encoding is TI_STRING8_SMALL (0x70) + 1-byte bound 0, so the
                    // EquivalenceHash matches other conformant implementations.
                    // The matcher preserves "unbounded writer is not assignable to a
                    // bounded reader under strict policy" via collection_bound_ok_small
                    // (bound 0 == unbounded), so emitting Small{0} here is both
                    // wire-correct and policy-correct.
                    Some(TypeIdentifier::StringSmall { bound: 0 })
                }
            }
            PrimitiveKind::WString { max_length } => {
                // Preserve wstring bound even in collection context; same
                // rationale as String above.
                let _ = in_collection;
                if let Some(bound) = max_length {
                    Some(TypeIdentifier::wstring(
                        u32::try_from(*bound).unwrap_or(u32::MAX),
                    ))
                } else {
                    // Same rationale as String above: unbounded wstring is the
                    // spec-conformant TI_STRING16_SMALL (0x72) + 1-byte bound 0
                    // (EquivalenceHash match with conformant implementations).
                    Some(TypeIdentifier::WStringSmall { bound: 0 })
                }
            }
            _ => primitive_kind_to_xtypes_kind(*prim).map(TypeIdentifier::primitive),
        },
        TypeKind::Array(arr) => {
            // Unwrap nested Array-of-Array into a flat dim list.  The XML
            // loader may produce nested ArrayDescriptors for multi-dim
            // arrays (e.g. int32[10][2]) rather than a single flat dims vec.
            // Walk the nesting here so both representations produce the same
            // PlainArray TypeIdentifier.
            let (elem_desc, flat_dims) = flatten_array_dims(arr);
            // Recurse into the innermost element type (in_collection=true).
            // Thread `kind` so a Complete outer TypeObject references a
            // hash-based element by its Complete hash (sec. 7.3.4.5).
            let element_id = descriptor_to_type_identifier_impl(&elem_desc, true, kind)?;
            let header = PlainCollectionHeader {
                equiv_kind: collection_equiv_kind(&element_id),
                // Default TryConstructKind = DISCARD (TRY_CONSTRUCT1) per
                // XTypes v1.3 section 7.2.2.4.2; HDDS sets it in every plain
                // collection header (sec. 7.3.4.4), matching struct-member flags.
                element_flags: CollectionElementFlag::TRY_CONSTRUCT1,
            };
            // Use Small variant when all bounds fit in a u8.
            if flat_dims.iter().all(|&d| d <= u32::from(u8::MAX)) {
                // u8::try_from always succeeds here: the all() guard above ensures d <= 255.
                let small_bounds: Vec<u8> = flat_dims
                    .iter()
                    .map(|&d| u8::try_from(d).unwrap_or(u8::MAX))
                    .collect();
                Some(TypeIdentifier::PlainArraySmall(PlainArraySElemDefn {
                    header,
                    array_bound_seq: small_bounds,
                    element_identifier: Box::new(element_id),
                }))
            } else {
                Some(TypeIdentifier::PlainArrayLarge(PlainArrayLElemDefn {
                    header,
                    array_bound_seq: flat_dims,
                    element_identifier: Box::new(element_id),
                }))
            }
        }
        TypeKind::Sequence(seq) => {
            // Recurse into the element type first (in_collection=true).
            // Thread `kind` (Complete vs Minimal) so the element reference
            // matches the outer TypeObject's equivalence (sec. 7.3.4.5).
            let element_id = descriptor_to_type_identifier_impl(&seq.element_type, true, kind)?;
            let header = PlainCollectionHeader {
                equiv_kind: collection_equiv_kind(&element_id),
                // Default TryConstructKind = DISCARD (TRY_CONSTRUCT1) per
                // XTypes v1.3 section 7.2.2.4.2; HDDS sets it in every plain
                // collection header (sec. 7.3.4.4), matching struct-member flags.
                element_flags: CollectionElementFlag::TRY_CONSTRUCT1,
            };
            // max_length == None means unbounded (bound = 0 on the wire).
            let bound = seq.max_length.unwrap_or(0);
            if let Ok(small_bound) = u8::try_from(bound) {
                Some(TypeIdentifier::PlainSequenceSmall(PlainSequenceSElemDefn {
                    header,
                    bound: small_bound,
                    element_identifier: Box::new(element_id),
                }))
            } else {
                Some(TypeIdentifier::PlainSequenceLarge(PlainSequenceLElemDefn {
                    header,
                    bound: u32::try_from(bound).unwrap_or(u32::MAX),
                    element_identifier: Box::new(element_id),
                }))
            }
        }
        TypeKind::Nested(inner) => {
            // Lower the inner struct/union to a CompleteTypeObject and derive
            // its Minimal hash for interop-friendly TypeIdentifier emission.
            //
            // Cycle safety: type_descriptor_to_xtypes returns None for any
            // non-Struct/Union top-level kind, including TypeKind::Nested
            // itself. A recursive chain (Nested(Nested(...))) therefore
            // terminates with None at the second level and propagates upward
            // as a graceful fallback, never recurses unboundedly.
            //
            // Hash selection: emit the STANDARD Minimal hash (sec. 7.3.4.8) for
            // the nested element regardless of its extensibility. The wire
            // TypeIdentifier referencing a nested type is the hash of that
            // type's MinimalTypeObject, which retains 32-bit member name hashes
            // (section 7.3.4.8). The standard Minimal hash is the same computation for
            // APPENDABLE/MUTABLE inner structs as for FINAL ones, so emitting it
            // here makes the EquivalenceHash match conformant implementations.
            //
            // A previous heuristic zeroed member name hashes for APPENDABLE /
            // MUTABLE inner structs (member-id-based assignability, sec. 7.5.1.1.2 /
            // sec. 7.5.2.1.1.4) so that the runtime hash-equality matcher would
            // treat two such elements differing only in member names as
            // assignable under ignore_member_names=true. That was an internal
            // matcher optimization that produced a non-conformant wire hash;
            // assignability semantics belong at comparison time, not baked into
            // the emitted TypeIdentifier (cf. the unbounded-string StringLarge
            // fix). The standard hash is therefore emitted for all
            // extensibilities.
            if kind == EquivalenceKind::Complete {
                // COMPLETE context (sec. 7.3.4.5): reference the nested type by the
                // hash of its CompleteTypeObject (which retains type_name and
                // member detail names). Build the inner Complete TypeObject with
                // Complete member references recursively so deeper nesting also
                // hashes by Complete equivalence.
                let complete_to = type_descriptor_to_xtypes_impl(inner, EquivalenceKind::Complete)?;
                let complete_hash = complete_to.compute_equivalence_hash().ok()?;
                return Some(TypeIdentifier::Complete(complete_hash));
            }
            let complete_to = type_descriptor_to_xtypes(inner)?;
            // Standard name-inclusive Minimal hash for all extensibilities
            // (sec. 7.3.4.8). See the rationale comment above.
            let minimal_hash = nested_struct_minimal_hash(&complete_to)?;
            Some(TypeIdentifier::Minimal(minimal_hash))
        }
        TypeKind::Enum(e) => {
            if e.is_bitmask {
                return bitmask_descriptor_to_type_identifier(descriptor, e, kind);
            }
            enum_descriptor_to_type_identifier(descriptor, e, kind)
        }
        // Struct / Union at the element level: no direct TypeIdentifier
        // form without a Nested wrapper. Return None so the outer descriptor
        // falls back to name-based SEDP matching.
        _ => None,
    }
}

/// Compute a TypeIdentifier for a union discriminator type.
///
/// Enums and bitmasks used as discriminators are emitted as
/// `TypeIdentifier::Minimal(hash)` (hash-based identity) rather than
/// `Primitive(underlying)` so that `is_union_assignable` can detect
/// bit-width mismatches between enum discriminators (e.g. bitmask16 vs
/// bitmask32) while still permitting APPENDABLE enum discriminator
/// coercion via the `Minimal == Minimal || allow_coercion` path.
/// Primitive discriminator types (int32, uint32, ...) are unchanged.
fn descriptor_to_discriminator_type_identifier(
    descriptor: &TypeDescriptor,
    kind: EquivalenceKind,
) -> Option<TypeIdentifier> {
    match &descriptor.kind {
        TypeKind::Enum(e) => {
            // Bitmask discriminators emit the bitmask's OWN identity, i.e. the
            // hash of its {Minimal,Complete}BitmaskType, mirroring the enum
            // discriminator path below. Collapsing the bitmask to its
            // underlying primitive made `union_bitmask32` hash identically to
            // `union_uint32` (the two Minimal hashes were byte-equal); a bitmask discriminator needs its own distinct
            // hash-based identity.
            if e.is_bitmask {
                return bitmask_descriptor_to_type_identifier(descriptor, e, kind);
            }
            // Plain enum discriminators: emit the hash of the enum's TypeObject so
            // that enum identity is preserved across the wire. The Complete outer
            // union references the enum by its Complete hash, the Minimal union by
            // the Minimal hash (sec. 7.3.4.5).
            enum_descriptor_to_type_identifier(descriptor, e, kind)
        }
        _ => descriptor_to_type_identifier_kind(descriptor, kind),
    }
}

/// Map a bitmask's underlying holder primitive to its XTypes `bit_bound`
/// (8/16/32/64). Bitmasks, unlike enums, admit a 64-bit bound (DDS-XTypes
/// v1.3 sec. 7.2.2.4.1.1).
fn bitmask_bit_bound(e: &EnumDescriptor) -> i16 {
    match e.underlying {
        PrimitiveKind::U8 | PrimitiveKind::I8 => 8,
        PrimitiveKind::U16 | PrimitiveKind::I16 => 16,
        PrimitiveKind::U64 | PrimitiveKind::I64 => 64,
        _ => 32,
    }
}

/// Bit position of a bitmask flag variant. The dynamic model stores each flag
/// as an enum variant whose value is the flag's MASK (`1 << position`, set by
/// the XML/IDL loaders), so the position is recovered as the trailing-zero
/// count. A non-positive value (malformed input) maps to position 0.
fn bitmask_flag_position(value: i64) -> u16 {
    if value <= 0 {
        return 0;
    }
    u16::try_from(value.trailing_zeros()).unwrap_or(u16::MAX)
}

/// Build the `TypeIdentifier` for a bitmask used as a union discriminator,
/// hashing its `{Minimal,Complete}BitmaskType` (DDS-XTypes v1.3 sec. 7.3.4.7 /
/// sec. 7.3.4.8) -- the bitmask analogue of
/// [`enum_descriptor_to_type_identifier`]. Flags are emitted in ascending
/// position order by the CDR2 serializer (sec. 7.3.4.5).
fn bitmask_descriptor_to_type_identifier(
    descriptor: &TypeDescriptor,
    e: &EnumDescriptor,
    kind: EquivalenceKind,
) -> Option<TypeIdentifier> {
    let bit_bound = bitmask_bit_bound(e);
    if kind == EquivalenceKind::Complete {
        let complete = CompleteTypeObject::Bitmask(CompleteBitmaskType {
            bitmask_flags: DYNAMIC_BITMASK_FLAGS,
            header: CompleteBitmaskHeader {
                bit_bound,
                detail: CompleteTypeDetail::new(&descriptor.name),
            },
            flag_seq: e
                .variants
                .iter()
                .map(|v| CompleteBitflag {
                    common: CommonBitflag {
                        position: bitmask_flag_position(v.value),
                        flags: BitflagFlag(0),
                    },
                    detail: CompleteMemberDetail::new(&v.name),
                })
                .collect(),
        });
        let hash = complete.compute_equivalence_hash().ok()?;
        return Some(TypeIdentifier::Complete(hash));
    }
    let minimal = MinimalTypeObject::Bitmask(MinimalBitmaskType {
        bitmask_flags: DYNAMIC_BITMASK_FLAGS,
        header: MinimalBitmaskHeader {
            bit_bound,
            detail: MinimalTypeDetail::new(),
        },
        flag_seq: e
            .variants
            .iter()
            .map(|v| MinimalBitflag {
                common: CommonBitflag {
                    position: bitmask_flag_position(v.value),
                    flags: BitflagFlag(0),
                },
                detail: MinimalMemberDetail::from_name(&v.name),
            })
            .collect(),
    });
    let hash = minimal.compute_equivalence_hash().ok()?;
    Some(TypeIdentifier::Minimal(hash))
}

/// Build the `TypeIdentifier` for a plain (non-bitmask) enum used as a struct
/// member, collection element, or union discriminator, selecting the
/// equivalence by `kind`:
///
/// - `Minimal` -> `Minimal(hash)` of the enum's `MinimalEnumeratedType`
///   (sec. 7.3.4.7 / sec. 7.3.4.8): drops the type name and literal detail names,
///   keeps bit_bound + each literal value + 32-bit name hash.
/// - `Complete` -> `Complete(hash)` of the enum's `CompleteEnumeratedType`
///   (sec. 7.3.4.7): retains the type name and each literal's detail name. This is
///   the reference a CompleteTypeObject must use for an enum member
///   (section 7.3.4.5).
fn enum_descriptor_to_type_identifier(
    descriptor: &TypeDescriptor,
    e: &EnumDescriptor,
    kind: EquivalenceKind,
) -> Option<TypeIdentifier> {
    if kind == EquivalenceKind::Complete {
        let complete_hash = descriptor_enum_to_xtypes(descriptor, e)
            .compute_equivalence_hash()
            .ok()?;
        return Some(TypeIdentifier::Complete(complete_hash));
    }
    enum_descriptor_to_minimal_type_identifier(e)
}

/// Build the `TypeIdentifier::Minimal(hash)` for a plain (non-bitmask) enum
/// `EnumDescriptor`, hashing its `MinimalEnumeratedType` per DDS-XTypes v1.3
/// sec. 7.3.4.7 (enumerated TypeObject) and sec. 7.3.4.8 (EquivalenceHash).
///
/// Used both for enum struct/collection-element members and for enum union
/// discriminators so the two paths produce the identical enum identity hash
/// (the spec-conformant value). The Minimal form drops the type name,
/// keeps the bit_bound and each literal's value + 32-bit name hash, with
/// literals ordered by declared value.
fn enum_descriptor_to_minimal_type_identifier(e: &EnumDescriptor) -> Option<TypeIdentifier> {
    let bit_bound = enum_bit_bound(e);
    let default_idx = enum_default_literal_index(e);
    let mut literal_seq: Vec<crate::xtypes::MinimalEnumeratedLiteral> = e
        .variants
        .iter()
        .enumerate()
        .map(|(idx, v)| crate::xtypes::MinimalEnumeratedLiteral {
            common: crate::xtypes::CommonEnumeratedLiteral {
                value: i32::try_from(v.value).unwrap_or(i32::MAX),
                flags: enum_literal_flags(idx, default_idx),
            },
            detail: MinimalMemberDetail::from_name(&v.name),
        })
        .collect();
    literal_seq.sort_by_key(|l| l.common.value);
    let minimal = crate::xtypes::MinimalEnumeratedType {
        enum_flags: DYNAMIC_ENUM_FLAGS,
        header: crate::xtypes::MinimalEnumeratedHeader {
            bit_bound,
            detail: crate::xtypes::MinimalTypeDetail::new(),
        },
        literal_seq,
    };
    let hash = MinimalTypeObject::Enumerated(minimal)
        .compute_equivalence_hash()
        .ok()?;
    Some(TypeIdentifier::Minimal(hash))
}

/// Map an enum's underlying primitive to its XTypes `bit_bound` (8/16/32).
fn enum_bit_bound(e: &EnumDescriptor) -> i16 {
    match e.underlying {
        PrimitiveKind::U8 | PrimitiveKind::I8 => 8,
        PrimitiveKind::U16 | PrimitiveKind::I16 => 16,
        _ => 32,
    }
}

/// Index of the enum's default literal: the variant marked `@default_literal`,
/// or the first declared enumerator (OMG IDL enum default semantics) when none
/// is explicitly marked.
fn enum_default_literal_index(e: &EnumDescriptor) -> usize {
    e.variants
        .iter()
        .position(|v| v.default_literal)
        .unwrap_or(0)
}

/// `EnumeratedLiteralFlag` for the literal at `idx`: IS_DEFAULT (sec. 7.2.2.4.1)
/// on the default literal, empty otherwise.
fn enum_literal_flags(idx: usize, default_idx: usize) -> crate::xtypes::EnumeratedLiteralFlag {
    if idx == default_idx {
        crate::xtypes::EnumeratedLiteralFlag::IS_DEFAULT
    } else {
        crate::xtypes::EnumeratedLiteralFlag::empty()
    }
}

/// Lower an enum `EnumDescriptor` to a `CompleteEnumeratedType` for top-level
/// enum TypeObject emission (`--print-typeid` and SEDP). Per DDS-XTypes v1.3
/// sec. 7.3.4.7: literals carry value + name + IS_DEFAULT on the default literal;
/// `enum_flags` are unused (0). Literals are CDR2-encoded in ascending value
/// order by the serializer.
fn descriptor_enum_to_xtypes(
    descriptor: &TypeDescriptor,
    e: &EnumDescriptor,
) -> CompleteTypeObject {
    let bit_bound = enum_bit_bound(e);
    let default_idx = enum_default_literal_index(e);
    let literal_seq: Vec<crate::xtypes::CompleteEnumeratedLiteral> = e
        .variants
        .iter()
        .enumerate()
        .map(|(idx, v)| crate::xtypes::CompleteEnumeratedLiteral {
            common: crate::xtypes::CommonEnumeratedLiteral {
                value: i32::try_from(v.value).unwrap_or(i32::MAX),
                flags: enum_literal_flags(idx, default_idx),
            },
            detail: CompleteMemberDetail::new(&v.name),
        })
        .collect();
    CompleteTypeObject::Enumerated(crate::xtypes::CompleteEnumeratedType {
        enum_flags: DYNAMIC_ENUM_FLAGS,
        header: crate::xtypes::CompleteEnumeratedHeader {
            bit_bound,
            detail: CompleteTypeDetail::new(&descriptor.name),
        },
        literal_seq,
    })
}

/// Compute the Minimal EquivalenceHash for a CompleteTypeObject that is used
/// as a nested element type.
///
/// Converts the Complete representation to Minimal (drops type_name, retains
/// member name hashes) then serialises and MD5-hashes per XTypes v1.3 sec. 7.3.4.8.
/// Returns None when serialisation fails (xtypes feature disabled or buffer
/// allocation error).
fn nested_struct_minimal_hash(complete: &CompleteTypeObject) -> Option<EquivalenceHash> {
    // Delegate to the shared Complete->Minimal converter: identical to the
    // previous inline Struct arm for structs, and additionally supports
    // nested UNION members (a struct member whose type is a union, e.g. the
    // OMG interop struct_key_union_* types). Unsupported variants still
    // return None so the caller falls back to name-based matching instead
    // of crashing.
    complete_to_minimal_type_object(complete)?
        .compute_equivalence_hash()
        .ok()
}

/// Compute the Minimal EquivalenceHash for a top-level `CompleteTypeObject`.
///
/// Public counterpart to `nested_struct_minimal_hash`, exposed for the OMG
/// dds-xtypes interop driver `--print-typeid` mode so it can print the Minimal
/// TypeObject V2 equivalence hash per XTypes v1.3 sec. 7.3.4.8.
///
/// Returns None for unsupported kinds or unresolved Complete dependencies.
pub fn complete_type_object_minimal_hash(complete: &CompleteTypeObject) -> Option<EquivalenceHash> {
    complete_to_minimal_type_object(complete)?
        .compute_equivalence_hash()
        .ok()
}

/// Convert a top-level `CompleteTypeObject` to its `MinimalTypeObject`
/// counterpart. Returns None for missing Complete dependencies or unsupported
/// TypeObject kinds. Use the dependency-aware conversion for named graphs.
pub(crate) fn complete_to_minimal_type_object(
    complete: &CompleteTypeObject,
) -> Option<MinimalTypeObject> {
    complete_to_minimal_with_dependencies(complete, &HashMap::new())
}

/// Convert using the reachable Complete dependency graph (XTypes 1.3 7.3.4).
/// Missing dependencies return None: a Complete hash cannot be relabeled Minimal.
pub(crate) fn complete_to_minimal_with_dependencies(
    complete: &CompleteTypeObject,
    dependencies: &HashMap<EquivalenceHash, CompleteTypeObject>,
) -> Option<MinimalTypeObject> {
    let indexed = dependencies
        .values()
        .filter_map(|object| Some((object.compute_equivalence_hash().ok()?, object)))
        .collect();
    minimal_object(complete, &indexed, &mut Vec::new(), &mut HashMap::new())
}

fn minimal_object(
    complete: &CompleteTypeObject,
    dependencies: &HashMap<EquivalenceHash, &CompleteTypeObject>,
    visiting: &mut Vec<EquivalenceHash>,
    converted: &mut HashMap<EquivalenceHash, EquivalenceHash>,
) -> Option<MinimalTypeObject> {
    let mut minimal = match complete {
        CompleteTypeObject::Struct(s) => MinimalTypeObject::Struct(complete_to_minimal_struct(s)),
        CompleteTypeObject::Enumerated(e) => {
            let literal_seq = e
                .literal_seq
                .iter()
                .map(|lit| crate::xtypes::MinimalEnumeratedLiteral {
                    common: lit.common.clone(),
                    detail: MinimalMemberDetail::from_name(lit.detail.hash_name()),
                })
                .collect();
            MinimalTypeObject::Enumerated(crate::xtypes::MinimalEnumeratedType {
                enum_flags: e.enum_flags,
                header: crate::xtypes::MinimalEnumeratedHeader {
                    bit_bound: e.header.bit_bound,
                    detail: MinimalTypeDetail::new(),
                },
                literal_seq,
            })
        }
        CompleteTypeObject::Union(u) => MinimalTypeObject::Union(complete_to_minimal_union(u)),
        CompleteTypeObject::Bitmask(b) => {
            // Minimal drops the type name and each flag's name (replaced by
            // its 32-bit name_hash); bit_bound and positions carry over.
            MinimalTypeObject::Bitmask(MinimalBitmaskType {
                bitmask_flags: b.bitmask_flags,
                header: MinimalBitmaskHeader {
                    bit_bound: b.header.bit_bound,
                    detail: MinimalTypeDetail::new(),
                },
                flag_seq: b
                    .flag_seq
                    .iter()
                    .map(|f| MinimalBitflag {
                        common: f.common.clone(),
                        detail: MinimalMemberDetail::from_name(&f.detail.name),
                    })
                    .collect(),
            })
        }
        CompleteTypeObject::Alias(a) => MinimalTypeObject::Alias(crate::xtypes::MinimalAliasType {
            alias_flags: a.alias_flags,
            header: crate::xtypes::MinimalAliasHeader {
                detail: MinimalTypeDetail::new(),
            },
            body: crate::xtypes::MinimalAliasBody {
                common: a.body.common.clone(),
            },
        }),
        _ => return None,
    };
    let mut convert = |id: &mut TypeIdentifier| -> Option<()> {
        *id = minimal_identifier(id, dependencies, visiting, converted)?;
        Some(())
    };
    match &mut minimal {
        MinimalTypeObject::Struct(s) => {
            if let Some(base) = &mut s.header.base_type {
                convert(base)?;
            }
            for member in &mut s.member_seq {
                convert(&mut member.common.member_type_id)?;
            }
        }
        MinimalTypeObject::Union(u) => {
            convert(&mut u.header.discriminator)?;
            for member in &mut u.member_seq {
                convert(&mut member.common.member_type_id)?;
            }
        }
        MinimalTypeObject::Alias(a) => {
            convert(&mut a.body.common.related_type)?;
        }
        _ => {}
    }
    Some(minimal)
}

// XTypes 1.3 7.3.4: Minimal objects contain Minimal hash references.
fn minimal_identifier(
    id: &TypeIdentifier,
    dependencies: &HashMap<EquivalenceHash, &CompleteTypeObject>,
    visiting: &mut Vec<EquivalenceHash>,
    converted: &mut HashMap<EquivalenceHash, EquivalenceHash>,
) -> Option<TypeIdentifier> {
    match id {
        TypeIdentifier::Complete(hash) => {
            if visiting.contains(hash) {
                return None;
            }
            if let Some(minimal_hash) = converted.get(hash) {
                return Some(TypeIdentifier::Minimal(*minimal_hash));
            }
            let dependency = dependencies.get(hash)?;
            visiting.push(*hash);
            let minimal = minimal_object(dependency, dependencies, visiting, converted);
            visiting.pop();
            let minimal_hash = minimal?.compute_equivalence_hash().ok()?;
            converted.insert(*hash, minimal_hash);
            Some(TypeIdentifier::Minimal(minimal_hash))
        }
        TypeIdentifier::PlainSequenceSmall(d) => {
            let mut out = d.clone();
            out.element_identifier = Box::new(minimal_identifier(
                &d.element_identifier,
                dependencies,
                visiting,
                converted,
            )?);
            out.header.equiv_kind = collection_equiv_kind(&out.element_identifier);
            Some(TypeIdentifier::PlainSequenceSmall(out))
        }
        TypeIdentifier::PlainSequenceLarge(d) => {
            let mut out = d.clone();
            out.element_identifier = Box::new(minimal_identifier(
                &d.element_identifier,
                dependencies,
                visiting,
                converted,
            )?);
            out.header.equiv_kind = collection_equiv_kind(&out.element_identifier);
            Some(TypeIdentifier::PlainSequenceLarge(out))
        }
        TypeIdentifier::PlainArraySmall(d) => {
            let mut out = d.clone();
            out.element_identifier = Box::new(minimal_identifier(
                &d.element_identifier,
                dependencies,
                visiting,
                converted,
            )?);
            out.header.equiv_kind = collection_equiv_kind(&out.element_identifier);
            Some(TypeIdentifier::PlainArraySmall(out))
        }
        TypeIdentifier::PlainArrayLarge(d) => {
            let mut out = d.clone();
            out.element_identifier = Box::new(minimal_identifier(
                &d.element_identifier,
                dependencies,
                visiting,
                converted,
            )?);
            out.header.equiv_kind = collection_equiv_kind(&out.element_identifier);
            Some(TypeIdentifier::PlainArrayLarge(out))
        }
        TypeIdentifier::PlainMapSmall(d) => {
            let mut out = d.clone();
            out.element_identifier = Box::new(minimal_identifier(
                &d.element_identifier,
                dependencies,
                visiting,
                converted,
            )?);
            out.key_identifier = Box::new(minimal_identifier(
                &d.key_identifier,
                dependencies,
                visiting,
                converted,
            )?);
            out.header.equiv_kind = collection_equiv_kind(&out.element_identifier);
            if collection_equiv_kind(&out.key_identifier) != EquivalenceKind::Both {
                out.header.equiv_kind = EquivalenceKind::Minimal;
            }
            Some(TypeIdentifier::PlainMapSmall(out))
        }
        TypeIdentifier::PlainMapLarge(d) => {
            let mut out = d.clone();
            out.element_identifier = Box::new(minimal_identifier(
                &d.element_identifier,
                dependencies,
                visiting,
                converted,
            )?);
            out.key_identifier = Box::new(minimal_identifier(
                &d.key_identifier,
                dependencies,
                visiting,
                converted,
            )?);
            out.header.equiv_kind = collection_equiv_kind(&out.element_identifier);
            if collection_equiv_kind(&out.key_identifier) != EquivalenceKind::Both {
                out.header.equiv_kind = EquivalenceKind::Minimal;
            }
            Some(TypeIdentifier::PlainMapLarge(out))
        }
        TypeIdentifier::StronglyConnected(scc) if scc.kind == EquivalenceKind::Complete => None,
        _ => Some(id.clone()),
    }
}

// Drop descriptive details here; minimal_object rewrites the identifiers
// using the reachable dependency graph before the object can be hashed.
fn complete_to_minimal_union(complete: &CompleteUnionType) -> MinimalUnionType {
    MinimalUnionType {
        union_flags: complete.union_flags,
        header: MinimalUnionHeader {
            discriminator: complete.header.discriminator.clone(),
            discriminator_flags: complete.header.discriminator_flags,
            detail: MinimalTypeDetail::new(),
        },
        member_seq: complete
            .member_seq
            .iter()
            .map(|m| MinimalUnionMember {
                common: m.common.clone(),
                detail: MinimalMemberDetail::from_name(&m.detail.name),
            })
            .collect(),
    }
}

/// DEBUG-ONLY: raw inner CDR2-LE bytes for both the Complete and the Minimal
/// TypeObject of `complete` (no outer `TypeObject` union wrapper), returned as
/// `(complete_inner, minimal_inner)`. Used by the dds-xtypes interop driver
/// `HDDS_TYPEID_DEBUG` falsification path.
#[doc(hidden)]
#[cfg(feature = "xtypes")]
pub fn debug_type_object_inner_cdr2(complete: &CompleteTypeObject) -> Option<(Vec<u8>, Vec<u8>)> {
    let minimal = complete_to_minimal_type_object(complete)?;
    let c = complete.debug_inner_cdr2_le().ok()?;
    let m = minimal.debug_inner_cdr2_le().ok()?;
    Some((c, m))
}

// Preserve structural fields and member-name hashes. minimal_object replaces
// Complete dependency identifiers with their Minimal counterparts.
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
                // The Minimal name_hash is the MD5 NameHash of the ACTUAL member
                // name (DDS-XTypes v1.3 sec. 7.3.4.6). A `@hashid` alias affects only
                // the member ID (sec. 7.3.1.2.1.1), already encoded in
                // `m.common.member_id`; it does NOT change the name_hash. Hence a
                // member `x2 @hashid("x1")` carries member_id = hash("x1") but
                // name_hash = MD5("x2"), so it hashes distinctly from a member
                // literally named `x1` (section 7.3.4.6).
                detail: MinimalMemberDetail::from_name(&m.detail.name),
            })
            .collect(),
    }
}

/// Flatten nested `Array-of-Array` into `(innermost_element_type, [dim0, dim1, ...])`.
///
/// The XML loader produces `Array { element: Array { element: T, length: d1 }, length: d0 }`
/// for `arrayDimensions="d0,d1"`.  Alternatively an `ArrayDescriptor` with a
/// non-empty `dims` field already carries all bounds; both forms are handled.
fn flatten_array_dims(arr: &ArrayDescriptor) -> (Arc<TypeDescriptor>, Vec<u32>) {
    // Fast path: dims already populated.
    if !arr.dims.is_empty() {
        return (arr.element_type.clone(), arr.dims.clone());
    }
    // Walk nested Array-of-Array.
    let mut dims: Vec<u32> = vec![u32::try_from(arr.length).unwrap_or(u32::MAX)];
    let mut elem = arr.element_type.clone();
    while let TypeKind::Array(inner) = &elem.kind {
        if !inner.dims.is_empty() {
            dims.extend_from_slice(&inner.dims);
            elem = inner.element_type.clone();
        } else {
            dims.push(u32::try_from(inner.length).unwrap_or(u32::MAX));
            elem = inner.element_type.clone();
        }
    }
    (elem, dims)
}

/// Convert a dynamic `TypeDescriptor` to a `CompleteTypeObject` for SEDP
/// emission (`PID_TYPE_OBJECT` / `PID_TYPE_INFORMATION`).
///
/// # Supported descriptors
///
/// - Struct types whose fields are primitives, strings, wstrings, arrays, or
///   sequences of any of the above (recursively).
/// - Union types whose case payload types are primitives, strings, wstrings,
///   arrays, or sequences of the above.
///
/// All field/member flags default to `MemberFlag::empty()` except `optional`
/// (struct field) and `IS_DEFAULT` (union default case). Field IDs and member
/// IDs are auto-numbered from `0` when not specified.
///
/// # Unsupported descriptors (returns `None`)
///
/// - Primitives, enums standalone
/// - Structs or unions containing fields typed as raw `TypeKind::Struct`
///   (not wrapped in `TypeKind::Nested`) -- use `TypeKind::Nested` to
///   reference inner structs by hash
///
/// Callers must check the return value and gracefully fall through to
/// emitting just `PID_TYPE_NAME`-based matching when conversion is not
/// possible.
///
/// # Spec citations
///
/// - DDS-XTypes v1.3 sec. 7.3.4.4.4 (CompleteStructType)
/// - DDS-XTypes v1.3 sec. 7.3.4.6 (CompleteUnionType)
/// - DDS-XTypes v1.3 sec. 7.3.1.2 (@autoid(SEQUENTIAL))
/// - DDS-XTypes v1.3 sec. 7.2.2.4.1 Table 9 (extensibility flags)
pub fn type_descriptor_to_xtypes(descriptor: &TypeDescriptor) -> Option<CompleteTypeObject> {
    // Minimal-equivalence references for hash-based members. This is the form
    // consumed by the SEDP emission path, the runtime matcher, and the
    // HDDS<->HDDS self path (all key on the Minimal TypeObject), so it is kept
    // byte-unchanged.
    type_descriptor_to_xtypes_impl(descriptor, EquivalenceKind::Minimal)
}

/// Like [`type_descriptor_to_xtypes`] but emits a CompleteTypeObject whose
/// hash-based members (enums, nested-struct collection elements) are
/// referenced by their **Complete** equivalence hash, per DDS-XTypes v1.3
/// sec. 7.3.4.5 / sec. 7.3.4.8.
///
/// The CompleteTypeObject built here therefore hashes to the spec-correct
/// Complete EquivalenceHash. Use this for
/// `--print-typeid` / Complete TypeObject hashing. The Minimal hash must still
/// be derived from [`type_descriptor_to_xtypes`] (Minimal references).
pub fn type_descriptor_to_xtypes_complete(
    descriptor: &TypeDescriptor,
) -> Option<CompleteTypeObject> {
    type_descriptor_to_xtypes_impl(descriptor, EquivalenceKind::Complete)
}

/// Shared lowering used by both [`type_descriptor_to_xtypes`] (Minimal refs)
/// and [`type_descriptor_to_xtypes_complete`] (Complete refs).
fn type_descriptor_to_xtypes_impl(
    descriptor: &TypeDescriptor,
    kind: EquivalenceKind,
) -> Option<CompleteTypeObject> {
    match &descriptor.kind {
        TypeKind::Struct(fields) => descriptor_struct_to_xtypes(descriptor, fields, kind),
        TypeKind::Union(u) => descriptor_union_to_xtypes(descriptor, u, kind),
        // Plain (non-bitmask) enums lower to a top-level CompleteEnumeratedType.
        // The CompleteEnumeratedType is identical regardless of `kind` (it has
        // no hash-based members), so no equivalence selection is needed here.
        TypeKind::Enum(e) if !e.is_bitmask => Some(descriptor_enum_to_xtypes(descriptor, e)),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Nested TypeObject collector (structural-assignability feature)
// ---------------------------------------------------------------------------

/// Recursively traverse a `TypeDescriptor` and populate `out` with
/// `CompleteTypeObject` for every nested enum or struct that is referenced by
/// hash in the outer TypeObject's member `TypeIdentifier`s.
///
/// # Why this exists
///
/// When `type_descriptor_to_xtypes` lowers an outer struct, enum/nested-struct
/// member types are emitted as `TypeIdentifier::Minimal(hash)`.  The hash is
/// computed but the corresponding `CompleteTypeObject` is discarded.  At
/// discovery-match time, the structural-assignability resolver needs those
/// inner TypeObjects to decide, for example, whether `enum1` (writer) is
/// assignable to `enum2` (reader) per DDS-XTypes v1.3 sec. 7.5.1.7.1.
///
/// Call this on every `TypeDescriptor` you intend to register with a
/// participant so the participant's type store can answer `resolve_minimal(h)`
/// queries for the inner types.
///
/// The caller owns the `HashMap`; repeated calls for different descriptors
/// merge into the same map. Each nested type is keyed by its Minimal hash
/// (first writer wins) and, whenever that entry is not the type's own named
/// Complete-reference object, ALSO by its Complete hash. A Minimal hash
/// excludes type names, so two structurally identical types with different
/// names share it: the Minimal entry is only good for Minimal resolution,
/// and a Complete reference to either type resolves through its Complete
/// key.
#[cfg(feature = "xtypes-structural-assignability")]
pub fn collect_nested_type_objects(
    desc: &TypeDescriptor,
    out: &mut std::collections::HashMap<
        crate::xtypes::EquivalenceHash,
        crate::xtypes::CompleteTypeObject,
    >,
) {
    collect_nested_impl(desc, out);
}

#[cfg(feature = "xtypes-structural-assignability")]
fn collect_nested_impl(
    desc: &TypeDescriptor,
    out: &mut std::collections::HashMap<
        crate::xtypes::EquivalenceHash,
        crate::xtypes::CompleteTypeObject,
    >,
) {
    match &desc.kind {
        TypeKind::Struct(fields) => {
            for field in fields {
                collect_nested_impl(&field.type_desc, out);
            }
        }
        TypeKind::Array(arr) => {
            collect_nested_impl(&arr.element_type, out);
        }
        TypeKind::Sequence(seq) => {
            collect_nested_impl(&seq.element_type, out);
        }
        TypeKind::Enum(e) if !e.is_bitmask => {
            // Compute the enum's CompleteTypeObject and store it keyed by its
            // Minimal EquivalenceHash (the hash emitted by member TypeIdentifiers).
            let to = descriptor_enum_to_xtypes(desc, e);
            if let Some(hash) = complete_type_object_minimal_hash(&to) {
                out.entry(hash).or_insert_with(|| to.clone());
                insert_complete_identity(out, hash, to);
            }
        }
        TypeKind::Enum(e) => {
            // Retain the bitmask object for members, collection elements and
            // union discriminators, all of which carry its named identity.
            let to = CompleteTypeObject::Bitmask(CompleteBitmaskType {
                bitmask_flags: DYNAMIC_BITMASK_FLAGS,
                header: CompleteBitmaskHeader {
                    bit_bound: bitmask_bit_bound(e),
                    detail: CompleteTypeDetail::new(&desc.name),
                },
                flag_seq: e
                    .variants
                    .iter()
                    .map(|v| CompleteBitflag {
                        common: CommonBitflag {
                            position: bitmask_flag_position(v.value),
                            flags: BitflagFlag(0),
                        },
                        detail: CompleteMemberDetail::new(&v.name),
                    })
                    .collect(),
            });
            if let Some(hash) = complete_type_object_minimal_hash(&to) {
                out.entry(hash).or_insert_with(|| to.clone());
                insert_complete_identity(out, hash, to);
            }
        }
        TypeKind::Nested(inner) => {
            // Compute the nested struct's TypeObject and store it.
            if let Some(to) = type_descriptor_to_xtypes(inner) {
                if let Some(hash) = complete_type_object_minimal_hash(&to) {
                    out.entry(hash).or_insert(to);
                    // The Minimal key above names no type: a structurally
                    // identical type with another name may already hold it.
                    // Keep this type's own named Complete object under its
                    // Complete hash, the identity a Complete reference to it
                    // carries (XTypes 1.3 7.3.4.5).
                    if let Some(complete) = type_descriptor_to_xtypes_complete(inner) {
                        insert_complete_identity(out, hash, complete);
                    }
                }
            }
            // Recurse into the nested type's own members.
            collect_nested_impl(inner, out);
        }
        TypeKind::Union(u) => {
            // Recurse into each union case member type.
            for case in &u.cases {
                collect_nested_impl(&case.type_desc, out);
            }
            // Recurse into the discriminator type if it is an enum.
            collect_nested_impl(&u.discriminator, out);
        }
        _ => {}
    }
}

/// Key `complete` (a named object whose references are Complete) by its own
/// Complete hash, unless the entry under its Minimal hash `minimal` already
/// is that very object. Structurally identical types with different names
/// share one Minimal hash; only the Complete hash tells them apart, so this
/// is the entry a Complete reference to the type resolves through.
#[cfg(feature = "xtypes-structural-assignability")]
fn insert_complete_identity(
    out: &mut std::collections::HashMap<
        crate::xtypes::EquivalenceHash,
        crate::xtypes::CompleteTypeObject,
    >,
    minimal: EquivalenceHash,
    complete: CompleteTypeObject,
) {
    if out.get(&minimal) == Some(&complete) {
        return;
    }
    if let Ok(hash) = complete.compute_equivalence_hash() {
        out.entry(hash).or_insert(complete);
    }
}

// ---------------------------------------------------------------------------
// Complete-reference rewrite (spec-correct wire form, XTypes 1.3 7.3.4.5)
// ---------------------------------------------------------------------------

/// Rewrite a `CompleteTypeObject` whose hash-based references are EK_MINIMAL
/// `TypeIdentifier`s (the internal hybrid form produced by
/// [`type_descriptor_to_xtypes`]) into the spec-correct wire form whose
/// references are EK_COMPLETE, per DDS-XTypes v1.3 7.3.4.5: a Complete
/// TypeObject must reference its dependencies by their Complete equivalence
/// hash. A receiver that resolves the remote Complete type graph may reject
/// a Complete object holding Minimal member references (-> permanent match
/// retry), so this form is
/// what discovery announcement and the OMG getTypes responder must carry.
///
/// `store` maps the MINIMAL `EquivalenceHash` of each nested type to that
/// type's `CompleteTypeObject` (the map built by
/// [`collect_nested_type_objects`] and registered through
/// `Participant::register_nested_type_objects`). Store values may themselves
/// be hybrid (nested structs); they are rewritten recursively before hashing
/// so deeper nesting also lands on Complete references, mirroring the
/// recursive lowering in [`type_descriptor_to_xtypes_complete`]. For any
/// descriptor `d`, `complete_type_object_with_complete_refs(
/// type_descriptor_to_xtypes(d), collected(d))` equals
/// `type_descriptor_to_xtypes_complete(d)` (asserted by unit tests).
///
/// Unresolvable references (hash absent from `store`, or hash computation
/// failure) are left untouched: the object degrades to today's hybrid form
/// for that member instead of being dropped. An object with no hash-based
/// references is returned unchanged (clone), so its EquivalenceHash is
/// byte-identical to the input's.
#[cfg(feature = "xtypes-structural-assignability")]
#[must_use]
pub fn complete_type_object_with_complete_refs(
    obj: &CompleteTypeObject,
    store: &std::collections::HashMap<crate::xtypes::EquivalenceHash, CompleteTypeObject>,
) -> CompleteTypeObject {
    let mut visiting: Vec<EquivalenceHash> = Vec::new();
    rewrite_complete_refs_obj(obj, store, &mut visiting)
}

/// Recursive object rewrite behind [`complete_type_object_with_complete_refs`].
///
/// Rewrite aggregate members and alias targets. Descriptive details are
/// preserved; this does not synthesize custom annotation dependency graphs.
#[cfg(feature = "xtypes-structural-assignability")]
fn rewrite_complete_refs_obj(
    obj: &CompleteTypeObject,
    store: &std::collections::HashMap<crate::xtypes::EquivalenceHash, CompleteTypeObject>,
    visiting: &mut Vec<EquivalenceHash>,
) -> CompleteTypeObject {
    match obj {
        CompleteTypeObject::Struct(s) => {
            let mut out = s.clone();
            if let Some(base) = out.header.base_type.take() {
                out.header.base_type = Some(rewrite_complete_refs_id(&base, store, visiting));
            }
            for member in &mut out.member_seq {
                member.common.member_type_id =
                    rewrite_complete_refs_id(&member.common.member_type_id, store, visiting);
            }
            CompleteTypeObject::Struct(out)
        }
        CompleteTypeObject::Union(u) => {
            let mut out = u.clone();
            out.header.discriminator =
                rewrite_complete_refs_id(&out.header.discriminator, store, visiting);
            for member in &mut out.member_seq {
                member.common.member_type_id =
                    rewrite_complete_refs_id(&member.common.member_type_id, store, visiting);
            }
            CompleteTypeObject::Union(out)
        }
        CompleteTypeObject::Alias(a) => {
            let mut out = a.clone();
            out.body.common.related_type =
                rewrite_complete_refs_id(&out.body.common.related_type, store, visiting);
            CompleteTypeObject::Alias(out)
        }
        other => other.clone(),
    }
}

/// Rewrite one `TypeIdentifier`: a `Minimal(h)` resolvable through `store`
/// becomes `Complete(h')` where `h'` hashes the recursively rewritten
/// dependency; plain collection identifiers descend into their element (and
/// map key) identifier and re-derive the header `equiv_kind` from the
/// rewritten element via [`collection_equiv_kind`], exactly as the Complete
/// lowering does. Every other variant is returned unchanged.
#[cfg(feature = "xtypes-structural-assignability")]
fn rewrite_complete_refs_id(
    id: &TypeIdentifier,
    store: &std::collections::HashMap<crate::xtypes::EquivalenceHash, CompleteTypeObject>,
    visiting: &mut Vec<EquivalenceHash>,
) -> TypeIdentifier {
    match id {
        TypeIdentifier::Minimal(h) => {
            // Cycle guard: a self-referential graph keeps the Minimal ref
            // rather than recursing unboundedly.
            if visiting.contains(h) {
                return id.clone();
            }
            let Some(dep) = store.get(h) else {
                return id.clone();
            };
            visiting.push(*h);
            let wire = rewrite_complete_refs_obj(dep, store, visiting);
            visiting.pop();
            match wire.compute_equivalence_hash() {
                Ok(complete_hash) => TypeIdentifier::Complete(complete_hash),
                Err(_) => id.clone(),
            }
        }
        TypeIdentifier::PlainSequenceSmall(d) => {
            let element = rewrite_complete_refs_id(&d.element_identifier, store, visiting);
            let mut out = d.clone();
            out.header.equiv_kind = collection_equiv_kind(&element);
            out.element_identifier = Box::new(element);
            TypeIdentifier::PlainSequenceSmall(out)
        }
        TypeIdentifier::PlainSequenceLarge(d) => {
            let element = rewrite_complete_refs_id(&d.element_identifier, store, visiting);
            let mut out = d.clone();
            out.header.equiv_kind = collection_equiv_kind(&element);
            out.element_identifier = Box::new(element);
            TypeIdentifier::PlainSequenceLarge(out)
        }
        TypeIdentifier::PlainArraySmall(d) => {
            let element = rewrite_complete_refs_id(&d.element_identifier, store, visiting);
            let mut out = d.clone();
            out.header.equiv_kind = collection_equiv_kind(&element);
            out.element_identifier = Box::new(element);
            TypeIdentifier::PlainArraySmall(out)
        }
        TypeIdentifier::PlainArrayLarge(d) => {
            let element = rewrite_complete_refs_id(&d.element_identifier, store, visiting);
            let mut out = d.clone();
            out.header.equiv_kind = collection_equiv_kind(&element);
            out.element_identifier = Box::new(element);
            TypeIdentifier::PlainArrayLarge(out)
        }
        TypeIdentifier::PlainMapSmall(d) => {
            // A hash-bearing map key also selects the equivalence kind.
            let element = rewrite_complete_refs_id(&d.element_identifier, store, visiting);
            let key = rewrite_complete_refs_id(&d.key_identifier, store, visiting);
            let mut out = d.clone();
            out.header.equiv_kind = if collection_equiv_kind(&key) == EquivalenceKind::Both {
                collection_equiv_kind(&element)
            } else {
                collection_equiv_kind(&key)
            };
            out.element_identifier = Box::new(element);
            out.key_identifier = Box::new(key);
            TypeIdentifier::PlainMapSmall(out)
        }
        TypeIdentifier::PlainMapLarge(d) => {
            let element = rewrite_complete_refs_id(&d.element_identifier, store, visiting);
            let key = rewrite_complete_refs_id(&d.key_identifier, store, visiting);
            let mut out = d.clone();
            out.header.equiv_kind = if collection_equiv_kind(&key) == EquivalenceKind::Both {
                collection_equiv_kind(&element)
            } else {
                collection_equiv_kind(&key)
            };
            out.element_identifier = Box::new(element);
            out.key_identifier = Box::new(key);
            TypeIdentifier::PlainMapLarge(out)
        }
        _ => id.clone(),
    }
}

/// Compute the `@autoid(HASH)` / `@hashid` member ID for a member name.
///
/// Per DDS-XTypes v1.3 sec. 7.3.1.2.1.1, when `@autoid(HASH)` is in effect (or a
/// member carries `@hashid`), the member ID equals the 28 least-significant
/// bits of the member name's `NameHash` -- i.e. the first 4 bytes of the MD5 of
/// the UTF-8 member name (or the `@hashid` alias when present). This is the SAME
/// MD5-derived value used for `MinimalMemberDetail.name_hash` (sec. 7.3.4.6), masked
/// to 28 bits. This MD5 scheme is the spec-conformant one; an FNV-1a hash
/// here produced a non-conformant member ID and EquivalenceHash.
fn hashid_member_id(name: &str) -> u32 {
    MinimalMemberDetail::from_name(name).name_hash & 0x0FFF_FFFF
}

/// Largest member id: a member id is 28 bits wide, the width of the id in
/// an XCDR2 EMHEADER1 and in an XCDR1 extended parameter header
/// (DDS-XTypes 1.3 7.4.1.2.2, 7.4.3.4.2), and the mask applied to a name
/// hash (7.3.1.2.1.1).
pub(crate) const MAX_MEMBER_ID: u32 = 0x0FFF_FFFF;

/// A member id, explicit or implied (the previous member's id plus one),
/// wider than `MAX_MEMBER_ID`: it has no representation in any encoding,
/// and masking it would make it another member's id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MemberIdTooWide(pub(crate) u32);

impl std::fmt::Display for MemberIdTooWide {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "member id {:#x} exceeds the 28-bit maximum {:#x}",
            self.0, MAX_MEMBER_ID
        )
    }
}

/// Member ids assigned `@autoid(SEQUENTIAL)` (DDS-XTypes 1.3 7.3.1.2.1.1):
/// an explicit id is kept, and an implicit one is the PREVIOUS member's id
/// plus one, the first implicit member before any explicit one taking
/// `first`. `{ a; @id(10) b; c; }` is 0, 10, 11, not the declaration
/// indexes 0, 10, 2.
///
/// This is the one door every member id goes through (struct and union,
/// TypeObject, every encoding, the KeyHash order): an id above
/// `MAX_MEMBER_ID` is refused here, so no encoder needs a mask.
fn sequential_member_ids(
    explicit: impl Iterator<Item = Option<u32>>,
    first: u32,
) -> Result<Vec<u32>, MemberIdTooWide> {
    let mut next = first;
    explicit
        .map(|id| {
            let id = id.unwrap_or(next);
            if id > MAX_MEMBER_ID {
                return Err(MemberIdTooWide(id));
            }
            next = id + 1;
            Ok(id)
        })
        .collect()
}

/// The member ids the TypeObject announces for the members of a struct, in
/// declaration order (DDS-XTypes 1.3 7.3.1.2.1.1).
///
/// - An explicit `id=N` attribute takes absolute priority.
/// - A `@hashid` member is explicitly assigned the MD5-based NameHash of its
///   `@hashid` value, or of its own name when that value is empty, whatever
///   the `@autoid` of the struct: "To assign the member ID explicitly the
///   member shall have either the @id or the @hashid annotation".
/// - Otherwise, when `autoid_hash` is set on the struct, the NameHash of the
///   member's name.
/// - Otherwise sequential: the previous member's id plus one, 0 for the
///   first member (`@autoid(SEQUENTIAL)`, the default), so the member after
///   a `@hashid` member takes its hash plus one. The struct has no base type
///   in the dynamic model, so nothing precedes the first member.
///
/// The TypeObject, the mutable encodings (EMHEADER, PL_CDR parameter id) and
/// the KeyHash order (RTPS 2.5 9.6.4.8) all read the ids from here, and an
/// id wider than 28 bits is refused here for all of them.
pub(crate) fn struct_member_ids(
    autoid_hash: bool,
    fields: &[FieldDescriptor],
) -> Result<Vec<u32>, MemberIdTooWide> {
    // A name hash is masked to 28 bits; an explicit id goes through the same
    // bound as a sequential one.
    let explicit = fields.iter().map(|f| {
        f.id.or_else(|| {
            f.hashid_name
                .as_deref()
                .map(|alias| hashid_member_id(hashid_value(alias, &f.name)))
        })
        .or_else(|| autoid_hash.then(|| hashid_member_id(&f.name)))
    });
    sequential_member_ids(explicit, 0)
}

/// The string a `@hashid` member's id is the hash of: the annotation's value,
/// or the member's own name when that value is empty (7.3.1.2.1.1: "If the
/// annotation is used without any parameter or with the empty string as a
/// parameter, then the Member ID shall be computed from the member name").
fn hashid_value<'a>(alias: &'a str, name: &'a str) -> &'a str {
    if alias.is_empty() {
        name
    } else {
        alias
    }
}

/// The cases of a union in DECLARATION order, the default case at its
/// declared slot (`default_case_index`; absent, after the labeled cases),
/// each with whether it is the default and its member id: explicit, else
/// the previous member's id plus one, the discriminator being member 0
/// (DDS-XTypes 1.3 7.2.2.4.4.3 and 7.3.1.2.1.1).
///
/// The TypeObject and the mutable union encodings read the ids from here;
/// an id wider than 28 bits is refused (`sequential_member_ids`).
pub(crate) fn union_cases_with_ids(
    u: &UnionDescriptor,
) -> Result<Vec<(&UnionCase, bool, u32)>, MemberIdTooWide> {
    let default_slot = u.default_case.as_ref().map(|_| {
        u.default_case_index
            .unwrap_or(u.cases.len())
            .min(u.cases.len())
    });
    let mut decl: Vec<(&UnionCase, bool)> =
        Vec::with_capacity(u.cases.len() + usize::from(u.default_case.is_some()));
    for (idx, case) in u.cases.iter().enumerate() {
        if default_slot == Some(idx) {
            if let Some(ref dc) = u.default_case {
                decl.push((dc.as_ref(), true));
            }
        }
        decl.push((case, false));
    }
    if default_slot == Some(u.cases.len()) {
        if let Some(ref dc) = u.default_case {
            decl.push((dc.as_ref(), true));
        }
    }
    let ids = sequential_member_ids(decl.iter().map(|(c, _)| c.member_id), 1)?;
    Ok(decl
        .into_iter()
        .zip(ids)
        .map(|((c, d), id)| (c, d, id))
        .collect())
}

/// Lower a struct `TypeDescriptor` into a `CompleteTypeObject::Struct`.
fn descriptor_struct_to_xtypes(
    descriptor: &TypeDescriptor,
    fields: &[FieldDescriptor],
    kind: EquivalenceKind,
) -> Option<CompleteTypeObject> {
    let mut member_seq: Vec<CompleteStructMember> = Vec::with_capacity(fields.len());
    // No TypeObject for a type with a member id no encoding can carry.
    let member_ids = struct_member_ids(descriptor.autoid_hash, fields).ok()?;
    for (field, member_id) in fields.iter().zip(member_ids) {
        let member_type_id = descriptor_to_type_identifier_kind(&field.type_desc, kind)?;
        // The name used for the hash-based member ID is the `@hashid` alias when
        // present, otherwise the member's own name (DDS-XTypes v1.3 sec. 7.3.1.2.1.1).
        // NOTE: the alias governs only the member ID; the Minimal name_hash is
        // always the MD5 of the ACTUAL member name (sec. 7.3.4.6), set below.
        let mut member_flags = try_construct_to_member_flag(field.try_construct);
        if field.optional {
            member_flags = MemberFlag(member_flags.0 | MemberFlag::IS_OPTIONAL.0);
        }
        if field.is_key {
            // A key member is implicitly must-understand: per DDS-XTypes v1.3
            // sec. 7.2.2.4.4.4.6 the IS_MUST_UNDERSTAND flag is always set on a
            // member that has IS_KEY set. Both bits (0x20 | 0x10) are therefore
            // required for the struct EquivalenceHash to byte-match a
            // conformant implementation's.
            member_flags = MemberFlag(
                member_flags.0 | MemberFlag::IS_KEY.0 | MemberFlag::IS_MUST_UNDERSTAND.0,
            );
        }
        if field.is_must_understand {
            member_flags = MemberFlag(member_flags.0 | MemberFlag::IS_MUST_UNDERSTAND.0);
        }

        member_seq.push(CompleteStructMember {
            common: CommonStructMember {
                member_id,
                member_flags,
                member_type_id,
            },
            // CompleteMemberDetail carries the actual field name and, for a
            // `@hashid` member, the applied annotation's value in
            // `ann_builtin.hash_id` (DDS-XTypes v1.3 Annex B,
            // AppliedBuiltinMemberAnnotations: `hash_id; // @hashid(...)`).
            // The value is the one the IDL wrote, empty for a bare `@hashid`;
            // the Complete object keeps it even though `member_id` already
            // carries its effect.
            detail: match &field.hashid_name {
                Some(value) => CompleteMemberDetail {
                    name: field.name.clone(),
                    ann_builtin: Some(AppliedBuiltinMemberAnnotations {
                        hash_id: Some(value.clone()),
                        ..AppliedBuiltinMemberAnnotations::default()
                    }),
                    ann_custom: None,
                },
                None => CompleteMemberDetail::new(&field.name),
            },
        });
    }

    // DDS-XTypes v1.3 sec. 7.2.2.4.1 Table 9.
    let mut struct_flags = match descriptor.extensibility {
        Extensibility::Final => StructTypeFlag::IS_FINAL,
        Extensibility::Appendable => StructTypeFlag::IS_APPENDABLE,
        Extensibility::Mutable => StructTypeFlag::IS_MUTABLE,
    };
    // DDS-XTypes v1.3 sec. 7.3.1.2: hash-based member IDs.
    if descriptor.autoid_hash {
        struct_flags = StructTypeFlag(struct_flags.0 | StructTypeFlag::IS_AUTOID_HASH.0);
    }

    Some(CompleteTypeObject::Struct(CompleteStructType {
        struct_flags,
        header: CompleteStructHeader {
            base_type: None,
            detail: CompleteTypeDetail::new(&descriptor.name),
        },
        member_seq,
    }))
}

/// Lower a union `TypeDescriptor` into a `CompleteTypeObject::Union`.
///
/// Returns `None` if the discriminator or any case payload type is not
/// a primitive that maps to a `TypeIdentifier` (e.g. nested struct).
fn descriptor_union_to_xtypes(
    descriptor: &TypeDescriptor,
    u: &UnionDescriptor,
    kind: EquivalenceKind,
) -> Option<CompleteTypeObject> {
    let discriminator_type_id =
        descriptor_to_discriminator_type_identifier(&u.discriminator, kind)?;

    let union_flags = match descriptor.extensibility {
        Extensibility::Final => UnionTypeFlag::IS_FINAL,
        Extensibility::Appendable => UnionTypeFlag::IS_APPENDABLE,
        Extensibility::Mutable => UnionTypeFlag::IS_MUTABLE,
    };

    // Discriminator IS_KEY: when set, every union member carries IS_KEY so
    // that the is_union_assignable check in matcher/types.rs correctly detects
    // key-vs-non-key discriminator mismatches (DDS-XTypes v1.3 sec. 7.3.4.6).
    // NOTE: this is the HDDS-INTERNAL convention only. On the wire IS_KEY
    // lives on the discriminator member flags and branch members stay
    // unflagged; the CDR2
    // encoder strips the member bit (CommonUnionMember::encode_cdr2_le_at)
    // and the decoders re-inject it.
    let key_flag = if u.discriminator_is_key {
        MemberFlag::IS_KEY
    } else {
        MemberFlag::empty()
    };

    // Emit members in DECLARATION order with the default case at its declared
    // slot (the default case keeps its declaration position and its
    // sequential member id; HDDS previously appended it last). `default_case_index` records the declaration slot;
    // absent (legacy builders) the default appends after the labeled cases,
    // which matches the previous emission for default-declared-last unions.
    let decl_cases = union_cases_with_ids(u).ok()?;

    let mut member_seq: Vec<CompleteUnionMember> = Vec::with_capacity(decl_cases.len());
    for (case, is_default, member_id) in decl_cases {
        let member_type_id = descriptor_to_type_identifier_kind(&case.type_desc, kind)?;
        // Discriminator labels stored as i64 internally; XTypes uses i32 per
        // OMG DDS-XTypes v1.3 sec. 7.3.4.6. The default member carries an EMPTY
        // label_seq (its labels field is unused) and the IS_DEFAULT flag.
        let label_seq: Vec<i32> = if is_default {
            vec![]
        } else {
            case.labels
                .iter()
                .map(|&v| i32::try_from(v).unwrap_or(i32::MAX))
                .collect()
        };
        // TryConstruct bits apply to the default member too (an unannotated
        // default case carries TRY_CONSTRUCT1 | IS_DEFAULT).
        let mut flags = try_construct_to_member_flag(case.try_construct);
        if is_default {
            flags = MemberFlag(flags.0 | MemberFlag::IS_DEFAULT.0);
        }
        flags = MemberFlag(flags.0 | key_flag.0);
        // `member_id`: the explicit @id(N) when the IDL/XML carries one,
        // otherwise the previous member's id plus one. Per DDS-XTypes v1.3
        // 7.2.2.4.4.3 the discriminator is always the first member of a union
        // and consumes member id 0, and 7.3.1.2.1.1 assigns SEQUENTIAL ids
        // (previous + 1), so branches without any @id auto-assign 1..N in
        // declaration order (the default case consumes its slot's id).
        member_seq.push(CompleteUnionMember {
            common: CommonUnionMember {
                member_id,
                member_flags: flags,
                member_type_id,
                label_seq,
            },
            detail: CompleteMemberDetail::new(&case.name),
        });
    }

    // Discriminator member flags: TryConstruct bits from the descriptor's
    // discriminator policy (DDS-XTypes v1.3 7.2.2.4.4.4.4), plus
    // IS_MUST_UNDERSTAND (added by the CDR2 encoder) and IS_KEY for a @key
    // discriminator (also derivable from the members; set here for clarity).
    let discriminator_flags =
        MemberFlag(try_construct_to_member_flag(u.discriminator_try_construct).0 | key_flag.0);

    Some(CompleteTypeObject::Union(CompleteUnionType {
        union_flags,
        header: CompleteUnionHeader {
            discriminator: discriminator_type_id,
            discriminator_flags,
            detail: CompleteTypeDetail::new(&descriptor.name),
        },
        member_seq,
    }))
}

// ---------------------------------------------------------------------------
// TryConstructKind <-> MemberFlag bit encoding helpers
// ---------------------------------------------------------------------------

/// Decode the `TRY_CONSTRUCT1` / `TRY_CONSTRUCT2` bit pair from a
/// [`MemberFlag`] into the corresponding [`TryConstructKind`].
///
/// Per DDS-XTypes v1.3 sec. 7.2.2.4.4.4.4 the `TryConstructKind` enum values are
/// `DISCARD = 1`, `USE_DEFAULT = 2`, `TRIM = 3`, stored in the low two bits of
/// the member flags. The bit pair therefore decodes as:
///   TC1=1, TC2=0 (0x0001) -> DISCARD
///   TC1=0, TC2=1 (0x0002) -> USE_DEFAULT
///   TC1=1, TC2=1 (0x0003) -> TRIM
///   TC1=0, TC2=0           -> DISCARD (no policy bits = default = DISCARD)
fn member_flag_to_try_construct(flags: MemberFlag) -> TryConstructKind {
    let tc1 = flags.contains(MemberFlag::TRY_CONSTRUCT1);
    let tc2 = flags.contains(MemberFlag::TRY_CONSTRUCT2);
    match (tc1, tc2) {
        (false, true) => TryConstructKind::UseDefault,
        (true, true) => TryConstructKind::Trim,
        _ => TryConstructKind::Discard, // (true, false) explicit or (false, false) absent
    }
}

/// Encode a [`TryConstructKind`] into the `TRY_CONSTRUCT1` / `TRY_CONSTRUCT2`
/// bit pair of a [`MemberFlag`].
///
/// Per DDS-XTypes v1.3 sec. 7.2.2.4.4.4.4 (`DISCARD = 1`, `USE_DEFAULT = 2`,
/// `TRIM = 3`):
///   DISCARD     -> TC1=1, TC2=0 (0x0001)
///   USE_DEFAULT -> TC1=0, TC2=1 (0x0002)
///   TRIM        -> TC1=1, TC2=1 (0x0003)
fn try_construct_to_member_flag(policy: TryConstructKind) -> MemberFlag {
    match policy {
        TryConstructKind::Discard => MemberFlag::TRY_CONSTRUCT1,
        TryConstructKind::UseDefault => MemberFlag::TRY_CONSTRUCT2,
        TryConstructKind::Trim => {
            MemberFlag(MemberFlag::TRY_CONSTRUCT1.0 | MemberFlag::TRY_CONSTRUCT2.0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xtypes::{
        CollectionElementFlag, CompleteCollectionElement, CompleteCollectionHeader,
    };

    /// The Cyclone DDS 0.11 idlc TypeObjects of tests/golden/typeobject:
    /// `(hash, serialized TypeObject)` of `name`'s `kind` ('C' / 'M') object.
    fn cyclone_object(name: &str, kind: char) -> (String, Vec<u8>) {
        let oracle = include_str!("../../tests/golden/typeobject/cyclone-0.11-typeobjects.txt");
        let line = oracle
            .lines()
            .find(|l| {
                let mut f = l.split_whitespace();
                f.next() == Some(name) && f.next() == Some(&kind.to_string())
            })
            .expect("type in the oracle");
        let f: Vec<&str> = line.split_whitespace().collect();
        let bytes = (0..f[3].len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&f[3][i..i + 2], 16).expect("hex"))
            .collect();
        (f[2].to_string(), bytes)
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// A union read from a TypeObject keeps the extensibility the object
    /// declares, and one that declares none is read as FINAL.
    #[test]
    fn a_union_object_keeps_its_declared_extensibility() {
        for ext in [
            Extensibility::Final,
            Extensibility::Appendable,
            Extensibility::Mutable,
        ] {
            let disc = Arc::new(TypeDescriptor::primitive("", PrimitiveKind::I32));
            let cases = vec![UnionCase::new(
                "a",
                vec![1],
                Arc::new(TypeDescriptor::primitive("", PrimitiveKind::I32)),
            )];
            let desc = TypeDescriptor::new("U", TypeKind::Union(UnionDescriptor::new(disc, cases)))
                .with_extensibility(ext);
            let mut object = type_descriptor_to_xtypes(&desc).expect("union object");
            assert_eq!(type_descriptor_from_xtypes(&object).extensibility, ext);
            if let CompleteTypeObject::Union(u) = &mut object {
                u.union_flags = UnionTypeFlag::empty();
            }
            assert_eq!(
                type_descriptor_from_xtypes(&object).extensibility,
                Extensibility::Final
            );
        }
    }

    /// An enum lowered by this bridge carries `enum_flags` IS_APPENDABLE,
    /// the specification's default extensibility (7.3.1.2.1.8), which is
    /// what `@appendable enum EApp { EA_0, EA_1 };` declares: both its
    /// objects hash exactly as Cyclone's. This also pins the value the
    /// bridge has always written, which every announced enum hash carries.
    #[test]
    fn a_dynamic_enum_hashes_as_the_oracle_appendable_enum() {
        let desc = TypeDescriptor::new(
            "EApp",
            TypeKind::Enum(EnumDescriptor::new(vec![
                EnumVariant::new("EA_0", 0),
                EnumVariant::new("EA_1", 1),
            ])),
        );
        let complete = type_descriptor_to_xtypes(&desc).expect("enum lowers");
        let minimal = complete_to_minimal_type_object(&complete).expect("minimal");
        let complete_hash = complete.compute_equivalence_hash().expect("hash");
        let minimal_hash = minimal.compute_equivalence_hash().expect("hash");
        assert_eq!(hex(complete_hash.as_bytes()), cyclone_object("EApp", 'C').0);
        assert_eq!(hex(minimal_hash.as_bytes()), cyclone_object("EApp", 'M').0);
    }

    /// A bitmask this bridge hashes (as a union discriminator's identity)
    /// carries no `bitmask_flags`, the value the bridge always wrote. It is
    /// Cyclone's `BM8` object except for that flag
    /// (Cyclone writes the declared extensibility, IS_FINAL by its default).
    #[test]
    fn a_dynamic_bitmask_is_the_oracle_bitmask_without_its_flag() {
        use crate::core::ser::traits::Cdr2Decode;
        let desc = TypeDescriptor::new(
            "BM8",
            TypeKind::Enum(
                EnumDescriptor::new_bitmask(vec![
                    EnumVariant::new("BM8_0", 1),
                    EnumVariant::new("BM8_1", 2),
                ])
                .with_underlying(PrimitiveKind::U8),
            ),
        );
        let TypeKind::Enum(e) = &desc.kind else {
            unreachable!()
        };
        for (kind, equivalence) in [
            ('C', EquivalenceKind::Complete),
            ('M', EquivalenceKind::Minimal),
        ] {
            let ours = bitmask_descriptor_to_type_identifier(&desc, e, equivalence)
                .expect("bitmask identity");
            let (_, bytes) = cyclone_object("BM8", kind);
            let mut off = 5usize;
            let theirs_without_flag = if kind == 'C' {
                let mut obj =
                    CompleteTypeObject::decode_cdr2_le_at(&bytes, &mut off).expect("decode");
                if let CompleteTypeObject::Bitmask(b) = &mut obj {
                    assert_eq!(b.bitmask_flags, StructTypeFlag::IS_FINAL);
                    b.bitmask_flags = StructTypeFlag::empty();
                }
                TypeIdentifier::Complete(obj.compute_equivalence_hash().expect("hash"))
            } else {
                let mut obj =
                    MinimalTypeObject::decode_cdr2_le_at(&bytes, &mut off).expect("decode");
                if let MinimalTypeObject::Bitmask(b) = &mut obj {
                    assert_eq!(b.bitmask_flags, StructTypeFlag::IS_FINAL);
                    b.bitmask_flags = StructTypeFlag::empty();
                }
                TypeIdentifier::Minimal(obj.compute_equivalence_hash().expect("hash"))
            };
            assert_eq!(ours, theirs_without_flag, "{kind}");
        }
    }

    #[test]
    fn test_convert_simple_struct() {
        // Build a simple struct TypeObject
        let type_object = CompleteTypeObject::Struct(CompleteStructType {
            struct_flags: StructTypeFlag::IS_FINAL,
            header: CompleteStructHeader {
                base_type: None,
                detail: CompleteTypeDetail::new("TestStruct"),
            },
            member_seq: vec![
                CompleteStructMember {
                    common: CommonStructMember {
                        member_id: 0,
                        member_flags: MemberFlag::empty(),
                        member_type_id: TypeIdentifier::TK_INT32,
                    },
                    detail: CompleteMemberDetail::new("value"),
                },
                CompleteStructMember {
                    common: CommonStructMember {
                        member_id: 1,
                        member_flags: MemberFlag::empty(),
                        member_type_id: TypeIdentifier::TK_FLOAT64,
                    },
                    detail: CompleteMemberDetail::new("temperature"),
                },
            ],
        });

        let descriptor = type_descriptor_from_xtypes(&type_object);

        assert_eq!(descriptor.name, "TestStruct");
        assert!(descriptor.is_struct());

        let fields = descriptor.fields().unwrap();
        assert_eq!(fields.len(), 2);
        assert_eq!(fields[0].name, "value");
        assert_eq!(fields[1].name, "temperature");
    }

    /// A union member's Minimal name_hash is the hash of its own name, as
    /// for a struct member (DDS-XTypes 1.3 7.3.4.6): a `@hashid` value
    /// changes the member id only, and an empty one (`@hashid` without a
    /// parameter) is not a name.
    #[test]
    fn a_union_member_name_hash_ignores_its_hashid() {
        use crate::xtypes::{
            AppliedBuiltinMemberAnnotations, CommonUnionMember, CompleteMemberDetail,
            CompleteUnionHeader, CompleteUnionMember, CompleteUnionType, MemberFlag,
            MinimalMemberDetail, MinimalTypeObject, UnionTypeFlag,
        };
        let case = |id: u32, name: &str, hash_id: &str| CompleteUnionMember {
            common: CommonUnionMember {
                member_id: id,
                member_flags: MemberFlag::empty(),
                member_type_id: TypeIdentifier::TK_INT32,
                label_seq: vec![i32::try_from(id).expect("small")],
            },
            detail: CompleteMemberDetail {
                name: name.to_string(),
                ann_builtin: Some(AppliedBuiltinMemberAnnotations {
                    hash_id: Some(hash_id.to_string()),
                    ..Default::default()
                }),
                ann_custom: None,
            },
        };
        let union = CompleteTypeObject::Union(CompleteUnionType {
            union_flags: UnionTypeFlag(UnionTypeFlag::IS_FINAL.0),
            header: CompleteUnionHeader {
                discriminator: TypeIdentifier::TK_INT32,
                discriminator_flags: MemberFlag::empty(),
                detail: CompleteTypeDetail::new("U"),
            },
            member_seq: vec![case(1, "a", ""), case(2, "b", "foo")],
        });
        let Some(MinimalTypeObject::Union(m)) = complete_to_minimal_type_object(&union) else {
            panic!("minimal union");
        };
        let hashes: Vec<u32> = m.member_seq.iter().map(|c| c.detail.name_hash).collect();
        assert_eq!(
            hashes,
            [
                MinimalMemberDetail::from_name("a").name_hash,
                MinimalMemberDetail::from_name("b").name_hash
            ]
        );
    }

    /// `hash_name` is what a `@hashid` member id is computed from: an empty
    /// `hash_id` (`@hashid` without a parameter) is the member's name.
    #[test]
    fn an_empty_hash_id_names_the_member() {
        use crate::xtypes::{AppliedBuiltinMemberAnnotations, CompleteMemberDetail};
        let detail = |hash_id: Option<&str>| CompleteMemberDetail {
            name: "x".to_string(),
            ann_builtin: Some(AppliedBuiltinMemberAnnotations {
                hash_id: hash_id.map(str::to_string),
                ..Default::default()
            }),
            ann_custom: None,
        };
        assert_eq!(detail(Some("")).hash_name(), "x");
        assert_eq!(detail(Some("foo")).hash_name(), "foo");
        assert_eq!(detail(None).hash_name(), "x");
    }

    #[test]
    fn test_convert_sequence() {
        let type_object = CompleteTypeObject::Sequence(CompleteSequenceType {
            collection_flag: crate::xtypes::CollectionTypeFlag::default(),
            header: CompleteCollectionHeader {
                bound: 100, // bounded sequence
                detail: Some(CompleteTypeDetail::new("BoundedSeq")),
            },
            element: CompleteCollectionElement {
                flags: CollectionElementFlag::empty(),
                type_id: TypeIdentifier::TK_INT32,
                detail: crate::xtypes::CompleteElementDetail::default(),
            },
        });

        let descriptor = type_descriptor_from_xtypes(&type_object);

        assert!(descriptor.name.contains("sequence"));
        if let TypeKind::Sequence(seq) = &descriptor.kind {
            assert_eq!(seq.max_length, Some(100));
        } else {
            panic!("Expected Sequence type");
        }
    }

    #[test]
    fn test_convert_array() {
        let type_object = CompleteTypeObject::Array(CompleteArrayType {
            collection_flag: crate::xtypes::CollectionTypeFlag::default(),
            header: crate::xtypes::CompleteArrayHeader {
                bound_seq: vec![3, 4], // 3x4 matrix
                detail: CompleteTypeDetail::new("Matrix"),
            },
            element: CompleteCollectionElement {
                flags: CollectionElementFlag::empty(),
                type_id: TypeIdentifier::TK_FLOAT64,
                detail: crate::xtypes::CompleteElementDetail::default(),
            },
        });

        let descriptor = type_descriptor_from_xtypes(&type_object);

        if let TypeKind::Array(arr) = &descriptor.kind {
            assert_eq!(arr.length, 12); // 3 * 4
        } else {
            panic!("Expected Array type");
        }
    }

    #[test]
    fn test_convert_union() {
        let type_object = CompleteTypeObject::Union(CompleteUnionType {
            union_flags: UnionTypeFlag::IS_FINAL,
            header: CompleteUnionHeader {
                discriminator: TypeIdentifier::TK_INT32,
                discriminator_flags: MemberFlag::empty(),
                detail: CompleteTypeDetail::new("MyUnion"),
            },
            member_seq: vec![
                CompleteUnionMember {
                    common: CommonUnionMember {
                        member_id: 0,
                        member_flags: MemberFlag::empty(),
                        member_type_id: TypeIdentifier::TK_INT32,
                        label_seq: vec![0, 1],
                    },
                    detail: CompleteMemberDetail::new("int_val"),
                },
                CompleteUnionMember {
                    common: CommonUnionMember {
                        member_id: 1,
                        member_flags: MemberFlag::empty(),
                        member_type_id: TypeIdentifier::TK_FLOAT64,
                        label_seq: vec![2],
                    },
                    detail: CompleteMemberDetail::new("float_val"),
                },
            ],
        });

        let descriptor = type_descriptor_from_xtypes(&type_object);

        assert_eq!(descriptor.name, "MyUnion");
        if let TypeKind::Union(u) = &descriptor.kind {
            assert_eq!(u.cases.len(), 2);
            assert_eq!(u.cases[0].name, "int_val");
            assert_eq!(u.cases[0].labels, vec![0, 1]);
            assert_eq!(u.cases[1].name, "float_val");
        } else {
            panic!("Expected Union type");
        }
    }

    // -- TypeRegistry tests -------------------------------------------------

    #[test]
    fn test_hash_map_registry_basics() {
        let mut registry = HashMapTypeRegistry::new();
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);

        let hash = EquivalenceHash::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]);
        let inner = CompleteTypeObject::Struct(CompleteStructType {
            struct_flags: StructTypeFlag::IS_FINAL,
            header: CompleteStructHeader {
                base_type: None,
                detail: CompleteTypeDetail::new("Inner"),
            },
            member_seq: vec![CompleteStructMember {
                common: CommonStructMember {
                    member_id: 0,
                    member_flags: MemberFlag::empty(),
                    member_type_id: TypeIdentifier::TK_FLOAT32,
                },
                detail: CompleteMemberDetail::new("x"),
            }],
        });

        registry.register(hash, inner);
        assert_eq!(registry.len(), 1);
        assert!(!registry.is_empty());
        assert!(registry.lookup(&hash).is_some());

        let miss_hash = EquivalenceHash::from_bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert!(registry.lookup(&miss_hash).is_none());
    }

    #[test]
    fn test_minimal_hash_resolved_via_registry() {
        // Create an inner struct (e.g., "Vector3" with x, y, z)
        let inner_hash = EquivalenceHash::from_bytes([
            10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130, 140,
        ]);

        let inner_type = CompleteTypeObject::Struct(CompleteStructType {
            struct_flags: StructTypeFlag::IS_FINAL,
            header: CompleteStructHeader {
                base_type: None,
                detail: CompleteTypeDetail::new("Vector3"),
            },
            member_seq: vec![
                CompleteStructMember {
                    common: CommonStructMember {
                        member_id: 0,
                        member_flags: MemberFlag::empty(),
                        member_type_id: TypeIdentifier::TK_FLOAT64,
                    },
                    detail: CompleteMemberDetail::new("x"),
                },
                CompleteStructMember {
                    common: CommonStructMember {
                        member_id: 1,
                        member_flags: MemberFlag::empty(),
                        member_type_id: TypeIdentifier::TK_FLOAT64,
                    },
                    detail: CompleteMemberDetail::new("y"),
                },
                CompleteStructMember {
                    common: CommonStructMember {
                        member_id: 2,
                        member_flags: MemberFlag::empty(),
                        member_type_id: TypeIdentifier::TK_FLOAT64,
                    },
                    detail: CompleteMemberDetail::new("z"),
                },
            ],
        });

        let mut registry = HashMapTypeRegistry::new();
        registry.register(inner_hash, inner_type);

        // Build an outer struct that references Vector3 via Minimal hash
        let outer_type = CompleteTypeObject::Struct(CompleteStructType {
            struct_flags: StructTypeFlag::IS_FINAL,
            header: CompleteStructHeader {
                base_type: None,
                detail: CompleteTypeDetail::new("Pose"),
            },
            member_seq: vec![
                CompleteStructMember {
                    common: CommonStructMember {
                        member_id: 0,
                        member_flags: MemberFlag::empty(),
                        member_type_id: TypeIdentifier::Minimal(inner_hash),
                    },
                    detail: CompleteMemberDetail::new("position"),
                },
                CompleteStructMember {
                    common: CommonStructMember {
                        member_id: 1,
                        member_flags: MemberFlag::empty(),
                        member_type_id: TypeIdentifier::TK_FLOAT64,
                    },
                    detail: CompleteMemberDetail::new("heading"),
                },
            ],
        });

        // Without registry: position is an opaque placeholder
        let desc_no_reg = type_descriptor_from_xtypes(&outer_type);
        let fields_no_reg = desc_no_reg.fields().unwrap();
        assert_eq!(fields_no_reg[0].name, "position");
        assert_eq!(fields_no_reg[0].type_desc.name, "nested");

        // With registry: position resolves to Vector3 struct
        let desc_with_reg = type_descriptor_from_xtypes_with_registry(&outer_type, Some(&registry));
        let fields_with_reg = desc_with_reg.fields().unwrap();
        assert_eq!(fields_with_reg[0].name, "position");
        assert_eq!(fields_with_reg[0].type_desc.name, "Vector3");
        assert!(fields_with_reg[0].type_desc.is_struct());

        let inner_fields = fields_with_reg[0].type_desc.fields().unwrap();
        assert_eq!(inner_fields.len(), 3);
        assert_eq!(inner_fields[0].name, "x");
        assert_eq!(inner_fields[1].name, "y");
        assert_eq!(inner_fields[2].name, "z");

        // heading is still a plain f64
        assert_eq!(fields_with_reg[1].name, "heading");
    }

    #[test]
    fn test_complete_hash_resolved_via_registry() {
        let hash = EquivalenceHash::from_bytes([1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4]);

        let inner = CompleteTypeObject::Enumerated(CompleteEnumeratedType {
            enum_flags: crate::xtypes::StructTypeFlag::IS_APPENDABLE,
            header: crate::xtypes::CompleteEnumeratedHeader {
                bit_bound: 32,
                detail: CompleteTypeDetail::new("Color"),
            },
            literal_seq: vec![
                crate::xtypes::CompleteEnumeratedLiteral {
                    common: crate::xtypes::CommonEnumeratedLiteral {
                        value: 0,
                        flags: crate::xtypes::EnumeratedLiteralFlag::empty(),
                    },
                    detail: CompleteMemberDetail::new("RED"),
                },
                crate::xtypes::CompleteEnumeratedLiteral {
                    common: crate::xtypes::CommonEnumeratedLiteral {
                        value: 1,
                        flags: crate::xtypes::EnumeratedLiteralFlag::empty(),
                    },
                    detail: CompleteMemberDetail::new("GREEN"),
                },
            ],
        });

        let mut registry = HashMapTypeRegistry::new();
        registry.register(hash, inner);

        // Struct with a Complete hash reference
        let outer = CompleteTypeObject::Struct(CompleteStructType {
            struct_flags: StructTypeFlag::IS_FINAL,
            header: CompleteStructHeader {
                base_type: None,
                detail: CompleteTypeDetail::new("Pixel"),
            },
            member_seq: vec![CompleteStructMember {
                common: CommonStructMember {
                    member_id: 0,
                    member_flags: MemberFlag::empty(),
                    member_type_id: TypeIdentifier::Complete(hash),
                },
                detail: CompleteMemberDetail::new("color"),
            }],
        });

        let desc = type_descriptor_from_xtypes_with_registry(&outer, Some(&registry));
        let fields = desc.fields().unwrap();
        assert_eq!(fields[0].name, "color");
        assert_eq!(fields[0].type_desc.name, "Color");
        if let TypeKind::Enum(e) = &fields[0].type_desc.kind {
            assert_eq!(e.variants.len(), 2);
        } else {
            panic!("Expected Enum, got {:?}", fields[0].type_desc.kind);
        }
    }

    #[test]
    fn test_hash_miss_returns_placeholder() {
        let hash = EquivalenceHash::from_bytes([0xFF; 14]);

        let registry = HashMapTypeRegistry::new(); // empty

        let outer = CompleteTypeObject::Struct(CompleteStructType {
            struct_flags: StructTypeFlag::IS_FINAL,
            header: CompleteStructHeader {
                base_type: None,
                detail: CompleteTypeDetail::new("Outer"),
            },
            member_seq: vec![CompleteStructMember {
                common: CommonStructMember {
                    member_id: 0,
                    member_flags: MemberFlag::empty(),
                    member_type_id: TypeIdentifier::Minimal(hash),
                },
                detail: CompleteMemberDetail::new("unknown_field"),
            }],
        });

        let desc = type_descriptor_from_xtypes_with_registry(&outer, Some(&registry));
        let fields = desc.fields().unwrap();
        assert_eq!(fields[0].type_desc.name, "nested");
    }

    #[test]
    fn test_sequence_of_hash_resolved() {
        let element_hash = EquivalenceHash::from_bytes([5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5]);

        let element_type = CompleteTypeObject::Struct(CompleteStructType {
            struct_flags: StructTypeFlag::IS_FINAL,
            header: CompleteStructHeader {
                base_type: None,
                detail: CompleteTypeDetail::new("Point"),
            },
            member_seq: vec![
                CompleteStructMember {
                    common: CommonStructMember {
                        member_id: 0,
                        member_flags: MemberFlag::empty(),
                        member_type_id: TypeIdentifier::TK_FLOAT32,
                    },
                    detail: CompleteMemberDetail::new("x"),
                },
                CompleteStructMember {
                    common: CommonStructMember {
                        member_id: 1,
                        member_flags: MemberFlag::empty(),
                        member_type_id: TypeIdentifier::TK_FLOAT32,
                    },
                    detail: CompleteMemberDetail::new("y"),
                },
            ],
        });

        let mut registry = HashMapTypeRegistry::new();
        registry.register(element_hash, element_type);

        // sequence<Point> via hash
        let seq_type = CompleteTypeObject::Sequence(CompleteSequenceType {
            collection_flag: crate::xtypes::CollectionTypeFlag::default(),
            header: CompleteCollectionHeader {
                bound: 0,
                detail: Some(CompleteTypeDetail::new("PointList")),
            },
            element: CompleteCollectionElement {
                flags: CollectionElementFlag::empty(),
                type_id: TypeIdentifier::Complete(element_hash),
                detail: crate::xtypes::CompleteElementDetail::default(),
            },
        });

        let desc = type_descriptor_from_xtypes_with_registry(&seq_type, Some(&registry));
        assert!(desc.name.contains("sequence"));
        assert!(desc.name.contains("Point"));

        if let TypeKind::Sequence(seq) = &desc.kind {
            assert_eq!(seq.element_type.name, "Point");
            assert!(seq.element_type.is_struct());
        } else {
            panic!("Expected Sequence type");
        }
    }

    // ---------------------------------------------------------------------
    // Reverse-direction tests: TypeDescriptor -> CompleteTypeObject
    // ---------------------------------------------------------------------

    #[test]
    fn test_descriptor_to_xtypes_primitive_struct_round_trips() {
        // Build a struct descriptor with three primitive fields and lower
        // it to a CompleteTypeObject. Then run it back through the forward
        // converter and check the field shapes match.
        let descriptor = TypeDescriptor::struct_type(
            "Temperature",
            vec![
                FieldDescriptor::new(
                    "value",
                    Arc::new(TypeDescriptor::primitive("f32", PrimitiveKind::F32)),
                )
                .with_id(0),
                FieldDescriptor::new(
                    "timestamp",
                    Arc::new(TypeDescriptor::primitive("u32", PrimitiveKind::U32)),
                )
                .with_id(1),
                FieldDescriptor::new(
                    "sensor_id",
                    Arc::new(TypeDescriptor::primitive("u64", PrimitiveKind::U64)),
                )
                .with_id(2),
            ],
        );

        let type_obj = type_descriptor_to_xtypes(&descriptor)
            .expect("primitive-field struct must lower successfully");

        let struct_type = match &type_obj {
            CompleteTypeObject::Struct(s) => s,
            _ => panic!("expected CompleteTypeObject::Struct"),
        };
        assert_eq!(struct_type.header.detail.type_name, "Temperature");
        assert_eq!(struct_type.member_seq.len(), 3);

        // Field 0: value : float32
        assert_eq!(struct_type.member_seq[0].common.member_id, 0);
        assert_eq!(struct_type.member_seq[0].detail.name, "value");
        assert_eq!(
            struct_type.member_seq[0].common.member_type_id,
            TypeIdentifier::primitive(XTypesKind::TK_FLOAT32),
        );

        // Field 1: timestamp : uint32
        assert_eq!(struct_type.member_seq[1].common.member_id, 1);
        assert_eq!(struct_type.member_seq[1].detail.name, "timestamp");
        assert_eq!(
            struct_type.member_seq[1].common.member_type_id,
            TypeIdentifier::primitive(XTypesKind::TK_UINT32),
        );

        // Field 2: sensor_id : uint64
        assert_eq!(struct_type.member_seq[2].common.member_id, 2);
        assert_eq!(struct_type.member_seq[2].detail.name, "sensor_id");
        assert_eq!(
            struct_type.member_seq[2].common.member_type_id,
            TypeIdentifier::primitive(XTypesKind::TK_UINT64),
        );

        // A descriptor that names no extensibility is appendable (DDS-XTypes
        // 1.3 7.3.1.2.1.8), and its TypeObject says so.
        assert_eq!(struct_type.struct_flags, StructTypeFlag::IS_APPENDABLE);
        assert!(struct_type.header.base_type.is_none());
    }

    #[test]
    fn test_descriptor_to_xtypes_strings_lower_to_string_identifiers() {
        let descriptor = TypeDescriptor::struct_type(
            "Greeting",
            vec![
                FieldDescriptor::new(
                    "unbounded",
                    Arc::new(TypeDescriptor::primitive(
                        "string",
                        PrimitiveKind::String { max_length: None },
                    )),
                ),
                FieldDescriptor::new(
                    "bounded64",
                    Arc::new(TypeDescriptor::primitive(
                        "string",
                        PrimitiveKind::String {
                            max_length: Some(64),
                        },
                    )),
                ),
                FieldDescriptor::new(
                    "wide",
                    Arc::new(TypeDescriptor::primitive(
                        "wstring",
                        PrimitiveKind::WString { max_length: None },
                    )),
                ),
            ],
        );

        let type_obj = type_descriptor_to_xtypes(&descriptor)
            .expect("string-only struct must lower successfully");
        let struct_type = match &type_obj {
            CompleteTypeObject::Struct(s) => s,
            _ => panic!("expected CompleteTypeObject::Struct"),
        };

        // Unbounded string lowers to StringSmall{0}: per DDS-XTypes v1.3
        // sec. 7.3.4.4/sec. 7.3.4.5 the Small-vs-Large variant is selected purely by
        // whether the bound fits in a u8, and bound 0 fits. This is the
        // TI_STRING8_SMALL (0x70) + 1-byte bound encoding, so the
        // EquivalenceHash matches conformant peers. The matcher preserves the
        // "unbounded writer not assignable to a bounded reader under strict
        // policy" semantics via collection_bound_ok_small (bound 0 == unbounded).
        assert_eq!(
            struct_type.member_seq[0].common.member_type_id,
            TypeIdentifier::StringSmall { bound: 0 },
        );
        assert_eq!(
            struct_type.member_seq[1].common.member_type_id,
            TypeIdentifier::string(64),
        );
        assert_eq!(
            struct_type.member_seq[2].common.member_type_id,
            TypeIdentifier::WStringSmall { bound: 0 },
        );
    }

    #[test]
    fn test_descriptor_to_xtypes_auto_assigns_member_ids() {
        // No explicit `with_id(...)`: the helper must auto-number from 0
        // per DDS-XTypes v1.3 sec. 7.3.1.2 (@autoid(SEQUENTIAL)).
        let descriptor = TypeDescriptor::struct_type(
            "AutoIds",
            vec![
                FieldDescriptor::new(
                    "a",
                    Arc::new(TypeDescriptor::primitive("u8", PrimitiveKind::U8)),
                ),
                FieldDescriptor::new(
                    "b",
                    Arc::new(TypeDescriptor::primitive("u8", PrimitiveKind::U8)),
                ),
                FieldDescriptor::new(
                    "c",
                    Arc::new(TypeDescriptor::primitive("u8", PrimitiveKind::U8)),
                ),
            ],
        );

        let type_obj = type_descriptor_to_xtypes(&descriptor).expect("lowering succeeds");
        let struct_type = match &type_obj {
            CompleteTypeObject::Struct(s) => s,
            _ => panic!("expected CompleteTypeObject::Struct"),
        };

        assert_eq!(struct_type.member_seq[0].common.member_id, 0);
        assert_eq!(struct_type.member_seq[1].common.member_id, 1);
        assert_eq!(struct_type.member_seq[2].common.member_id, 2);
    }

    #[test]
    fn test_descriptor_to_xtypes_optional_field_carries_flag() {
        let descriptor = TypeDescriptor::struct_type(
            "WithOptional",
            vec![
                FieldDescriptor::new(
                    "required",
                    Arc::new(TypeDescriptor::primitive("u32", PrimitiveKind::U32)),
                ),
                FieldDescriptor::new(
                    "maybe",
                    Arc::new(TypeDescriptor::primitive("u32", PrimitiveKind::U32)),
                )
                .optional(),
            ],
        );

        let type_obj = type_descriptor_to_xtypes(&descriptor).expect("lowering succeeds");
        let struct_type = match &type_obj {
            CompleteTypeObject::Struct(s) => s,
            _ => panic!("expected CompleteTypeObject::Struct"),
        };

        assert!(!struct_type.member_seq[0]
            .common
            .member_flags
            .contains(MemberFlag::IS_OPTIONAL));
        assert!(struct_type.member_seq[1]
            .common
            .member_flags
            .contains(MemberFlag::IS_OPTIONAL));
    }

    #[test]
    fn test_descriptor_to_xtypes_non_struct_top_level_returns_none() {
        // A primitive at the top level is not a valid TypeObject for SEDP
        // emission and must soft-skip.
        let primitive_desc = TypeDescriptor::primitive("u32", PrimitiveKind::U32);
        assert!(type_descriptor_to_xtypes(&primitive_desc).is_none());
    }

    #[test]
    fn test_descriptor_to_xtypes_struct_with_nested_struct_via_nested_kind_succeeds() {
        // A struct field typed as TypeKind::Nested(inner_struct) must now lower
        // successfully via the Minimal hash path added in the TypeKind::Nested arm.
        // The outer CompleteTypeObject must be Some and its member must carry a
        // TypeIdentifier::Minimal hash, not None.
        let inner = Arc::new(TypeDescriptor::struct_type(
            "Inner",
            vec![FieldDescriptor::new(
                "x",
                Arc::new(TypeDescriptor::primitive("u32", PrimitiveKind::U32)),
            )],
        ));
        // Wrap the inner struct in TypeKind::Nested so the field is a true
        // Nested reference (the path that was previously None).
        let nested_ref = Arc::new(TypeDescriptor::new("Inner", TypeKind::Nested(inner)));
        let outer = TypeDescriptor::struct_type(
            "Outer",
            vec![FieldDescriptor::new("inner_field", nested_ref).with_id(0)],
        );

        let type_obj = type_descriptor_to_xtypes(&outer)
            .expect("outer struct with TypeKind::Nested member must lower successfully");

        let struct_type = match &type_obj {
            CompleteTypeObject::Struct(s) => s,
            _ => panic!("expected CompleteTypeObject::Struct"),
        };
        assert_eq!(struct_type.header.detail.type_name, "Outer");
        assert_eq!(struct_type.member_seq.len(), 1);

        // The member must carry a Minimal hash, not a primitive TypeIdentifier.
        match &struct_type.member_seq[0].common.member_type_id {
            TypeIdentifier::Minimal(_) => {}
            other => panic!(
                "expected TypeIdentifier::Minimal for nested struct field, got {:?}",
                other
            ),
        }
    }

    #[test]
    fn test_descriptor_to_xtypes_struct_with_direct_struct_field_returns_none() {
        // A struct field whose type_desc has TypeKind::Struct directly (i.e.
        // the field is an inline struct descriptor, not wrapped in Nested) still
        // returns None because the wildcard arm is unchanged. This preserves
        // backward compatibility for callers that relied on the fallback path.
        let inner_struct_desc = Arc::new(TypeDescriptor::struct_type(
            "Inner",
            vec![FieldDescriptor::new(
                "x",
                Arc::new(TypeDescriptor::primitive("u32", PrimitiveKind::U32)),
            )],
        ));
        let outer = TypeDescriptor::struct_type(
            "Outer",
            vec![FieldDescriptor::new("inner", inner_struct_desc)],
        );

        // TypeKind::Struct at the field level hits the wildcard `_ => None` arm.
        assert!(
            type_descriptor_to_xtypes(&outer).is_none(),
            "direct-struct field (not wrapped in TypeKind::Nested) must still return None"
        );
    }

    #[test]
    fn test_descriptor_to_xtypes_round_trip_via_forward_converter() {
        // Lower a struct descriptor to xtypes and run it back through the
        // forward converter (xtypes -> descriptor). Field names + type
        // names must survive the round-trip even though the forward
        // converter prints primitive names via Debug.
        let descriptor = TypeDescriptor::struct_type(
            "Roundtrip",
            vec![
                FieldDescriptor::new(
                    "alpha",
                    Arc::new(TypeDescriptor::primitive("i32", PrimitiveKind::I32)),
                ),
                FieldDescriptor::new(
                    "beta",
                    Arc::new(TypeDescriptor::primitive("f64", PrimitiveKind::F64)),
                ),
            ],
        );

        let type_obj = type_descriptor_to_xtypes(&descriptor).expect("lowering succeeds");
        let back = type_descriptor_from_xtypes(&type_obj);

        assert_eq!(back.name, "Roundtrip");
        let back_fields = back.fields().expect("must be a struct after round-trip");
        assert_eq!(back_fields.len(), 2);
        assert_eq!(back_fields[0].name, "alpha");
        assert_eq!(back_fields[1].name, "beta");
    }

    // -- Extensibility flag emission tests ------------------------------------

    #[test]
    fn test_appendable_descriptor_emits_appendable_struct_flag() {
        // A descriptor with Extensibility::Appendable must lower to
        // IS_APPENDABLE in CompleteStructType.struct_flags, NOT IS_FINAL.
        // DDS-XTypes v1.3 sec. 7.2.2.4.1 Table 9 + sec. 7.3.4.4.4.
        use crate::dynamic::Extensibility;
        let descriptor = TypeDescriptor::struct_type(
            "AppendableType",
            vec![FieldDescriptor::new(
                "value",
                Arc::new(TypeDescriptor::primitive("u32", PrimitiveKind::U32)),
            )],
        )
        .with_extensibility(Extensibility::Appendable);

        let type_obj = type_descriptor_to_xtypes(&descriptor)
            .expect("appendable struct must lower successfully");

        let struct_type = match &type_obj {
            CompleteTypeObject::Struct(s) => s,
            _ => panic!("expected CompleteTypeObject::Struct"),
        };

        assert!(
            struct_type
                .struct_flags
                .contains(StructTypeFlag::IS_APPENDABLE),
            "expected IS_APPENDABLE in struct_flags, got {:?}",
            struct_type.struct_flags,
        );
        assert!(
            !struct_type.struct_flags.contains(StructTypeFlag::IS_FINAL),
            "IS_FINAL must NOT be set for an appendable descriptor",
        );
        assert!(
            !struct_type
                .struct_flags
                .contains(StructTypeFlag::IS_MUTABLE),
            "IS_MUTABLE must NOT be set for an appendable descriptor",
        );
    }

    #[test]
    fn test_mutable_descriptor_emits_mutable_struct_flag() {
        // A descriptor with Extensibility::Mutable must lower to IS_MUTABLE,
        // not IS_FINAL or IS_APPENDABLE.
        use crate::dynamic::Extensibility;
        let descriptor = TypeDescriptor::struct_type(
            "MutableType",
            vec![FieldDescriptor::new(
                "count",
                Arc::new(TypeDescriptor::primitive("u64", PrimitiveKind::U64)),
            )],
        )
        .with_extensibility(Extensibility::Mutable);

        let type_obj =
            type_descriptor_to_xtypes(&descriptor).expect("mutable struct must lower successfully");

        let struct_type = match &type_obj {
            CompleteTypeObject::Struct(s) => s,
            _ => panic!("expected CompleteTypeObject::Struct"),
        };

        assert!(
            struct_type
                .struct_flags
                .contains(StructTypeFlag::IS_MUTABLE),
            "expected IS_MUTABLE in struct_flags, got {:?}",
            struct_type.struct_flags,
        );
        assert!(
            !struct_type.struct_flags.contains(StructTypeFlag::IS_FINAL),
            "IS_FINAL must NOT be set for a mutable descriptor",
        );
        assert!(
            !struct_type
                .struct_flags
                .contains(StructTypeFlag::IS_APPENDABLE),
            "IS_APPENDABLE must NOT be set for a mutable descriptor",
        );
    }

    #[test]
    fn test_descriptor_to_type_identifier_emits_array_small() {
        // Array with length <= 255 must emit PlainArraySmall with a single u8 bound.
        let elem = Arc::new(TypeDescriptor::primitive("f32", PrimitiveKind::F32));
        let arr_desc =
            TypeDescriptor::new("f32[16]", TypeKind::Array(ArrayDescriptor::new(elem, 16)));
        let tid = descriptor_to_type_identifier(&arr_desc)
            .expect("small array must lower to a TypeIdentifier");
        match tid {
            TypeIdentifier::PlainArraySmall(defn) => {
                assert_eq!(defn.array_bound_seq, vec![16u8]);
                assert_eq!(*defn.element_identifier, TypeIdentifier::TK_FLOAT32);
            }
            other => panic!("expected PlainArraySmall, got {:?}", other),
        }
    }

    #[test]
    fn test_descriptor_to_type_identifier_emits_sequence_small() {
        // Bounded sequence with bound <= 255 must emit PlainSequenceSmall.
        let elem = Arc::new(TypeDescriptor::primitive("i32", PrimitiveKind::I32));
        let seq_desc = TypeDescriptor::new(
            "sequence<i32>",
            TypeKind::Sequence(SequenceDescriptor {
                element_type: elem,
                max_length: Some(100),
            }),
        );
        let tid = descriptor_to_type_identifier(&seq_desc)
            .expect("small bounded sequence must lower to a TypeIdentifier");
        match tid {
            TypeIdentifier::PlainSequenceSmall(defn) => {
                assert_eq!(defn.bound, 100u8);
                assert_eq!(*defn.element_identifier, TypeIdentifier::TK_INT32);
            }
            other => panic!("expected PlainSequenceSmall, got {:?}", other),
        }
    }

    #[test]
    fn test_struct_with_array_member_lowers_to_type_object() {
        // Full pipeline: struct with an array member must produce a
        // CompleteTypeObject::Struct with the array field encoded as
        // PlainArraySmall. Validates the emission gap fix end-to-end.
        let elem = Arc::new(TypeDescriptor::primitive("f64", PrimitiveKind::F64));
        let arr_field_type = Arc::new(TypeDescriptor::new(
            "f64[3]",
            TypeKind::Array(ArrayDescriptor::new(elem, 3)),
        ));
        let descriptor = TypeDescriptor::struct_type(
            "Point3",
            vec![
                FieldDescriptor::new("coords", arr_field_type).with_id(0),
                FieldDescriptor::new(
                    "weight",
                    Arc::new(TypeDescriptor::primitive("f64", PrimitiveKind::F64)),
                )
                .with_id(1),
            ],
        );

        let type_obj = type_descriptor_to_xtypes(&descriptor)
            .expect("struct with array member must lower successfully");

        let struct_type = match &type_obj {
            CompleteTypeObject::Struct(s) => s,
            _ => panic!("expected CompleteTypeObject::Struct"),
        };
        assert_eq!(struct_type.header.detail.type_name, "Point3");
        assert_eq!(struct_type.member_seq.len(), 2);

        // coords field: must be PlainArraySmall([3]) of f64.
        match &struct_type.member_seq[0].common.member_type_id {
            TypeIdentifier::PlainArraySmall(defn) => {
                assert_eq!(defn.array_bound_seq, vec![3u8]);
                assert_eq!(*defn.element_identifier, TypeIdentifier::TK_FLOAT64);
            }
            other => panic!("expected PlainArraySmall for coords field, got {:?}", other),
        }

        // weight field: plain f64 primitive.
        assert_eq!(
            struct_type.member_seq[1].common.member_type_id,
            TypeIdentifier::TK_FLOAT64,
        );
    }

    // -- Front 1: multi-dimensional arrays -----------------------------------

    #[test]
    fn test_multidim_array_emits_all_dims_in_bound_seq() {
        // int32[10][2] must emit PlainArraySmall with array_bound_seq = [10, 2],
        // not [20] (the flat product).  Covers the OMG test
        // array_test_suite_int32[10][2]_int32[20].
        let elem = Arc::new(TypeDescriptor::primitive("i32", PrimitiveKind::I32));
        let arr_desc = TypeDescriptor::new(
            "i32[10][2]",
            TypeKind::Array(ArrayDescriptor::multi_dim(elem, vec![10, 2])),
        );
        let tid = descriptor_to_type_identifier(&arr_desc)
            .expect("multi-dim array must lower to TypeIdentifier");
        match tid {
            TypeIdentifier::PlainArraySmall(defn) => {
                assert_eq!(
                    defn.array_bound_seq,
                    vec![10u8, 2u8],
                    "array_bound_seq must carry both dimensions"
                );
                assert_eq!(*defn.element_identifier, TypeIdentifier::TK_INT32);
            }
            other => panic!("expected PlainArraySmall, got {:?}", other),
        }
    }

    #[test]
    fn test_nested_array_of_array_flattens_to_multidim_bound_seq() {
        // Nested Array-of-Array (legacy form from the XML loader before the
        // flat-dims fix) must also flatten correctly via `flatten_array_dims`.
        let elem = Arc::new(TypeDescriptor::primitive("i32", PrimitiveKind::I32));
        // Inner: Array { element: i32, length: 2 }
        let inner = Arc::new(TypeDescriptor::new(
            "i32[2]",
            TypeKind::Array(ArrayDescriptor::new(elem, 2)),
        ));
        // Outer: Array { element: inner, length: 10 }
        let outer = TypeDescriptor::new(
            "i32[10][2]",
            TypeKind::Array(ArrayDescriptor::new(inner, 10)),
        );
        let tid = descriptor_to_type_identifier(&outer)
            .expect("nested array must flatten and lower to TypeIdentifier");
        match tid {
            TypeIdentifier::PlainArraySmall(defn) => {
                assert_eq!(defn.array_bound_seq, vec![10u8, 2u8]);
                assert_eq!(*defn.element_identifier, TypeIdentifier::TK_INT32);
            }
            other => panic!(
                "expected PlainArraySmall from nested array, got {:?}",
                other
            ),
        }
    }

    // -- Front 2: string array with bound ------------------------------------

    #[test]
    fn test_string_array_element_identifier_preserves_bound() {
        // string<10>[10] must emit PlainArraySmall with element_identifier=string(10).
        //
        // The bound is preserved in the TypeIdentifier so that the assignability
        // check in type_id_assignable can apply the TypeConsistencyEnforcement
        // ignore_string_bounds policy explicitly: cross-variant (StringSmall vs
        // StringLarge) returns the policy flag, same-variant compares bounds.
        // This is more correct than stripping bounds at lowering time.
        let elem = Arc::new(TypeDescriptor::primitive(
            "string<10>",
            PrimitiveKind::String {
                max_length: Some(10),
            },
        ));
        let arr_desc = TypeDescriptor::new(
            "string<10>[10]",
            TypeKind::Array(ArrayDescriptor::multi_dim(elem, vec![10])),
        );
        let tid = descriptor_to_type_identifier(&arr_desc)
            .expect("string array must lower to TypeIdentifier");
        match tid {
            TypeIdentifier::PlainArraySmall(defn) => {
                assert_eq!(defn.array_bound_seq, vec![10u8]);
                assert_eq!(
                    *defn.element_identifier,
                    TypeIdentifier::string(10),
                    "element_identifier preserves bound; assignability check applies policy"
                );
            }
            other => panic!("expected PlainArraySmall for string array, got {:?}", other),
        }
    }

    // -- Front 3: struct arrays (partial) ------------------------------------

    #[test]
    fn test_struct_element_in_array_returns_none_from_descriptor_to_type_identifier() {
        // Struct elements inside arrays cannot be lowered to a TypeIdentifier
        // without a hash-interning pipeline (TypeObjectBuilder) that can
        // correctly compute the EquivalenceHash respecting APPENDABLE vs FINAL
        // semantics.  The current implementation returns None, causing the outer
        // struct to also return None and fall back to name-based SEDP matching.
        //
        // Note: This means the OMG test array_test_suite_SFinal[10]_S[20] is
        // not fully fixed by this pass; fixing it cleanly requires the matcher
        // to apply APPENDABLE assignability to Minimal hash comparisons, which
        // is outside the scope of this helper.
        let inner_struct = Arc::new(TypeDescriptor::struct_type(
            "SFinal",
            vec![FieldDescriptor::new(
                "x",
                Arc::new(TypeDescriptor::primitive("i32", PrimitiveKind::I32)),
            )],
        ));
        let arr_desc = TypeDescriptor::new(
            "SFinal[10]",
            TypeKind::Array(ArrayDescriptor::multi_dim(inner_struct, vec![10])),
        );
        // Struct element -> no TypeIdentifier -> returns None for the array descriptor.
        assert!(
            descriptor_to_type_identifier(&arr_desc).is_none(),
            "struct array must return None until hash-interning is wired"
        );
    }

    // -- Front 3 (cont): nested struct TypeIdentifier emission ---------------

    #[test]
    fn test_descriptor_to_type_identifier_emits_nested_struct_as_minimal() {
        // A TypeDescriptor whose kind is TypeKind::Nested(inner_struct) must
        // produce TypeIdentifier::Minimal(hash) when lowered to a TypeIdentifier.
        // The Minimal hash must be non-zero (real struct, not placeholder) and
        // deterministic: two calls with the same inner struct descriptor must
        // return the same hash value.
        let inner = Arc::new(TypeDescriptor::struct_type(
            "SFinal",
            vec![
                FieldDescriptor::new(
                    "x",
                    Arc::new(TypeDescriptor::primitive("i32", PrimitiveKind::I32)),
                )
                .with_id(0),
                FieldDescriptor::new(
                    "y",
                    Arc::new(TypeDescriptor::primitive("i32", PrimitiveKind::I32)),
                )
                .with_id(1),
            ],
        ));

        let nested_desc = TypeDescriptor::new("SFinal", TypeKind::Nested(inner.clone()));

        let tid1 = descriptor_to_type_identifier(&nested_desc)
            .expect("TypeKind::Nested with primitive-field struct must produce a TypeIdentifier");

        let hash1 = match tid1 {
            TypeIdentifier::Minimal(h) => h,
            other => panic!("expected TypeIdentifier::Minimal, got {:?}", other),
        };

        // Must be non-zero (real MD5 of a non-empty struct).
        assert_ne!(
            hash1,
            EquivalenceHash::zero(),
            "Minimal hash must not be the zero placeholder"
        );

        // Deterministic: second call on identical input must match.
        let nested_desc2 = TypeDescriptor::new("SFinal", TypeKind::Nested(inner));
        let tid2 =
            descriptor_to_type_identifier(&nested_desc2).expect("repeated call must also succeed");
        let hash2 = match tid2 {
            TypeIdentifier::Minimal(h) => h,
            other => panic!(
                "expected TypeIdentifier::Minimal on second call, got {:?}",
                other
            ),
        };
        assert_eq!(hash1, hash2, "Minimal hash must be deterministic");
    }

    #[test]
    fn test_struct_array_with_nested_struct_lowers_to_type_object() {
        // Full pipeline: a struct containing a field of type SFinal[10] where
        // SFinal is wrapped in TypeKind::Nested must produce a CompleteTypeObject
        // whose array member carries PlainArraySmall with a Minimal hash as the
        // element TypeIdentifier.
        //
        // This directly covers the OMG test:
        //   array_test_suite_SFinal[10]_S[20]_SFinalAlt[10]_S[20]
        let s_final = Arc::new(TypeDescriptor::struct_type(
            "SFinal",
            vec![FieldDescriptor::new(
                "x",
                Arc::new(TypeDescriptor::primitive("i32", PrimitiveKind::I32)),
            )
            .with_id(0)],
        ));

        // Array element is TypeKind::Nested(SFinal).
        let nested_elem = Arc::new(TypeDescriptor::new("SFinal", TypeKind::Nested(s_final)));

        // Array of 10 nested structs.
        let arr_field_type = Arc::new(TypeDescriptor::new(
            "SFinal[10]",
            TypeKind::Array(ArrayDescriptor::multi_dim(nested_elem, vec![10])),
        ));

        let outer = TypeDescriptor::struct_type(
            "ContainsSFinalArray",
            vec![FieldDescriptor::new("items", arr_field_type).with_id(0)],
        );

        let type_obj = type_descriptor_to_xtypes(&outer)
            .expect("struct with array-of-nested-struct must lower successfully");

        let struct_type = match &type_obj {
            CompleteTypeObject::Struct(s) => s,
            _ => panic!("expected CompleteTypeObject::Struct"),
        };
        assert_eq!(struct_type.member_seq.len(), 1);

        // The array member must carry PlainArraySmall([10]) with a Minimal
        // element TypeIdentifier (not a plain primitive).
        match &struct_type.member_seq[0].common.member_type_id {
            TypeIdentifier::PlainArraySmall(defn) => {
                assert_eq!(defn.array_bound_seq, vec![10u8]);
                match defn.element_identifier.as_ref() {
                    TypeIdentifier::Minimal(_) => {}
                    other => panic!(
                        "expected Minimal element TypeIdentifier in array, got {:?}",
                        other
                    ),
                }
            }
            other => panic!(
                "expected PlainArraySmall for array-of-nested-struct field, got {:?}",
                other
            ),
        }
    }

    // -- Front 4: autoid hash ------------------------------------------------

    #[test]
    fn test_autoid_hash_descriptor_emits_is_autoid_hash_struct_flag() {
        // A descriptor built with autoid_hash=true must set IS_AUTOID_HASH
        // (0x0010) in the emitted StructTypeFlag.  Covers the OMG test
        // extensibility_test_suite_ext_autoid_1.
        let descriptor = TypeDescriptor::struct_type(
            "struct_hashid_1",
            vec![FieldDescriptor::new(
                "x1",
                Arc::new(TypeDescriptor::primitive("i32", PrimitiveKind::I32)),
            )],
        )
        .with_extensibility(Extensibility::Final)
        .with_autoid_hash();

        let type_obj = type_descriptor_to_xtypes(&descriptor)
            .expect("autoid_hash struct must lower successfully");

        let struct_type = match &type_obj {
            CompleteTypeObject::Struct(s) => s,
            _ => panic!("expected CompleteTypeObject::Struct"),
        };

        assert!(
            struct_type
                .struct_flags
                .contains(StructTypeFlag::IS_AUTOID_HASH),
            "expected IS_AUTOID_HASH in struct_flags, got {:?}",
            struct_type.struct_flags,
        );
        assert!(
            struct_type.struct_flags.contains(StructTypeFlag::IS_FINAL),
            "IS_FINAL must also be set",
        );
    }

    // -----------------------------------------------------------------------
    // String / WString TypeIdentifier emission tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_unbounded_string_emits_string_small_zero() {
        // Unbounded string (max_length=None) must lower to StringSmall{bound=0}.
        // Per DDS-XTypes v1.3 sec. 7.3.4.4/sec. 7.3.4.5 the Small-vs-Large variant is
        // chosen by whether the bound fits in a u8; bound 0 fits, so the
        // spec-conformant encoding is TI_STRING8_SMALL (0x70). The matcher
        // gates unbounded-vs-bounded assignability
        // via collection_bound_ok_small (bound 0 == unbounded), so policy
        // enforcement is preserved.
        let desc = TypeDescriptor::primitive("", PrimitiveKind::String { max_length: None });
        let tid = descriptor_to_type_identifier(&desc)
            .expect("unbounded string must lower to a TypeIdentifier");
        assert!(
            matches!(tid, TypeIdentifier::StringSmall { bound: 0 }),
            "unbounded string must emit StringSmall{{bound:0}}, got {:?}",
            tid,
        );
    }

    #[test]
    fn test_bounded_string_emits_string_small() {
        // Bounded string (max_length=Some(10)) must lower to StringSmall{bound=10}
        // because 10 fits in u8.
        let desc = TypeDescriptor::primitive(
            "",
            PrimitiveKind::String {
                max_length: Some(10),
            },
        );
        let tid = descriptor_to_type_identifier(&desc)
            .expect("bounded string must lower to a TypeIdentifier");
        assert!(
            matches!(tid, TypeIdentifier::StringSmall { bound: 10 }),
            "string<10> must emit StringSmall{{bound:10}}, got {:?}",
            tid,
        );
    }

    #[test]
    fn test_unbounded_wstring_emits_wstring_small_zero() {
        // Unbounded wstring (max_length=None) must lower to WStringSmall{bound=0}:
        // spec-conformant TI_STRING16_SMALL (0x72) per sections 7.3.4.4/7.3.4.5, so the
        // EquivalenceHash matches conformant peers.
        let desc = TypeDescriptor::primitive("", PrimitiveKind::WString { max_length: None });
        let tid = descriptor_to_type_identifier(&desc)
            .expect("unbounded wstring must lower to a TypeIdentifier");
        assert!(
            matches!(tid, TypeIdentifier::WStringSmall { bound: 0 }),
            "unbounded wstring must emit WStringSmall{{bound:0}}, got {:?}",
            tid,
        );
    }

    #[test]
    fn test_bounded_wstring_emits_wstring_small() {
        // Bounded wstring (max_length=Some(20)) must lower to WStringSmall{bound=20}.
        let desc = TypeDescriptor::primitive(
            "",
            PrimitiveKind::WString {
                max_length: Some(20),
            },
        );
        let tid = descriptor_to_type_identifier(&desc)
            .expect("bounded wstring must lower to a TypeIdentifier");
        assert!(
            matches!(tid, TypeIdentifier::WStringSmall { bound: 20 }),
            "wstring<20> must emit WStringSmall{{bound:20}}, got {:?}",
            tid,
        );
    }

    #[test]
    fn test_string_in_collection_preserves_bound() {
        // String as a collection element must preserve its bound in the
        // TypeIdentifier so that type_id_assignable can enforce
        // ignore_string_bounds=false for sequence/array-of-string members.
        // The ignore_string_bounds policy is applied at matching time, not
        // at TypeIdentifier construction time.
        let desc = TypeDescriptor::primitive(
            "",
            PrimitiveKind::String {
                max_length: Some(10),
            },
        );
        // Wrap in an array to trigger in_collection=true for the element.
        let arr_desc = TypeDescriptor::new(
            "string<10>[4]",
            TypeKind::Array(ArrayDescriptor::new(Arc::new(desc), 4)),
        );
        let tid = descriptor_to_type_identifier(&arr_desc)
            .expect("array of string<10> must lower to a TypeIdentifier");
        let elem_tid = match tid {
            TypeIdentifier::PlainArraySmall(defn) => *defn.element_identifier,
            other => panic!("expected PlainArraySmall, got {:?}", other),
        };
        assert!(
            matches!(elem_tid, TypeIdentifier::StringSmall { bound: 10 }),
            "string<10> inside array must emit StringSmall{{bound:10}}, got {:?}",
            elem_tid,
        );
    }

    // -----------------------------------------------------------------------
    // hashid / autoid(HASH) member ID tests -- ext_autoid_1 regression guards
    // -----------------------------------------------------------------------
    //
    // OMG test ext_autoid_1: struct_hashid_1 (x1, autoid=hash) pub ->
    //   struct_hashid_2 (x2 with hashid="x1", autoid=hash) sub.
    // The @hashid alias drives the member_id (MD5-based, sec. 7.3.1.2.1.1) so both
    // members carry the same member_id; the Minimal name_hash uses the ACTUAL
    // member name (section 7.3.4.6), so the two FINAL MinimalTypeObjects differ.

    #[test]
    fn test_autoid_hash_member_id_uses_md5_namehash() {
        // struct_hashid_1: member x1 with autoid=hash
        //   -> member_id = MD5("x1")[0..4] (LE) & 0x0FFF_FFFF
        let i32_type = Arc::new(TypeDescriptor::primitive("i32", PrimitiveKind::I32));
        let descriptor = TypeDescriptor::struct_type(
            "struct_hashid_1",
            vec![FieldDescriptor::new("x1", i32_type)],
        )
        .with_extensibility(Extensibility::Final)
        .with_autoid_hash();

        let type_obj =
            type_descriptor_to_xtypes(&descriptor).expect("autoid_hash struct must lower");
        let struct_type = match &type_obj {
            CompleteTypeObject::Struct(s) => s,
            _ => panic!("expected Struct"),
        };

        let member_id = struct_type.member_seq[0].common.member_id;
        // Expected: the member name's MD5 NameHash masked to 28 bits.
        let expected = hashid_member_id("x1");
        assert_eq!(
            member_id, expected,
            "member_id must be MD5(\"x1\") NameHash & 0x0FFF_FFFF"
        );
        // The member ID is the low 28 bits of the NameHash that also feeds the
        // Minimal name_hash (DDS-XTypes v1.3 sec. 7.3.1.2.1.1 / sec. 7.3.4.6).
        assert_eq!(
            member_id,
            MinimalMemberDetail::from_name("x1").name_hash & 0x0FFF_FFFF,
        );
        assert_ne!(member_id, 0, "MD5 of a non-empty string is never 0");
    }

    #[test]
    fn test_hashid_alias_member_id_matches_original_name_member_id() {
        // struct_hashid_2: member x2 with hashid="x1" and autoid=hash.
        // member_id must equal MD5("x1") NameHash & mask -- same as
        // struct_hashid_1.x1 -- while the Minimal name_hash uses the ACTUAL
        // name "x2" (not the alias), so the two structs hash distinctly.
        let i32_type = Arc::new(TypeDescriptor::primitive("i32", PrimitiveKind::I32));
        let descriptor = TypeDescriptor::struct_type(
            "struct_hashid_2",
            vec![FieldDescriptor::new("x2", i32_type).with_hashid_name("x1")],
        )
        .with_extensibility(Extensibility::Final)
        .with_autoid_hash();

        let type_obj = type_descriptor_to_xtypes(&descriptor)
            .expect("autoid_hash struct with hashid must lower");
        let struct_type = match &type_obj {
            CompleteTypeObject::Struct(s) => s,
            _ => panic!("expected Struct"),
        };

        let member = &struct_type.member_seq[0];
        assert_eq!(
            member.common.member_id,
            hashid_member_id("x1"),
            "hashid='x1' on member x2 must produce MD5(\"x1\") NameHash as member_id"
        );

        // The Complete detail carries the ACTUAL name "x2" and the applied
        // annotation's value (Annex B, AppliedBuiltinMemberAnnotations.hash_id).
        assert_eq!(member.detail.name, "x2");
        assert_eq!(
            member
                .detail
                .ann_builtin
                .as_ref()
                .and_then(|a| a.hash_id.as_deref()),
            Some("x1"),
            "Complete member detail carries @hashid(\"x1\") in ann_builtin.hash_id"
        );

        // The Minimal name_hash is the MD5 of the ACTUAL name "x2", NOT the
        // alias "x1" -- so struct_hashid_2 hashes distinctly from struct_hashid_1.
        let minimal = complete_to_minimal_struct(struct_type);
        assert_eq!(
            minimal.member_seq[0].detail.name_hash,
            MinimalMemberDetail::from_name("x2").name_hash,
            "minimal name_hash must use the actual member name \"x2\""
        );
        assert_ne!(
            minimal.member_seq[0].detail.name_hash,
            MinimalMemberDetail::from_name("x1").name_hash,
            "minimal name_hash must NOT use the alias \"x1\""
        );
    }

    // -- Byte vs U8 distinctness tests ----------------------------------------

    #[test]
    fn test_byte_and_uint8_are_distinct_types() {
        // TK_BYTE (0x02) must lower to PrimitiveKind::Byte; TK_UINT8 (0x0D) to
        // PrimitiveKind::U8. The two must not be equal so that struct
        // type-identifier comparison correctly rejects byte vs uint8 pairings.
        //
        // This exercises DDS-XTypes v1.3 sec. 7.5.1.3 Table 3: TK_BYTE is NOT in the
        // unsigned integer widening chain and is NOT assignable to TK_UINT8.
        use crate::xtypes::TypeKind as XK;

        let byte_kind = xtypes_kind_to_primitive(XK::TK_BYTE);
        let u8_kind = xtypes_kind_to_primitive(XK::TK_UINT8);

        assert_eq!(
            byte_kind,
            PrimitiveKind::Byte,
            "TK_BYTE must map to PrimitiveKind::Byte"
        );
        assert_eq!(
            u8_kind,
            PrimitiveKind::U8,
            "TK_UINT8 must map to PrimitiveKind::U8"
        );
        assert_ne!(
            byte_kind, u8_kind,
            "Byte and U8 must be distinct PrimitiveKind variants"
        );

        // Round-trip: Byte lowers to TK_BYTE, U8 lowers to TK_UINT8.
        assert_eq!(
            primitive_kind_to_xtypes_kind(PrimitiveKind::Byte),
            Some(XK::TK_BYTE),
            "PrimitiveKind::Byte must lower to TK_BYTE (0x02)"
        );
        assert_eq!(
            primitive_kind_to_xtypes_kind(PrimitiveKind::U8),
            Some(XK::TK_UINT8),
            "PrimitiveKind::U8 must lower to TK_UINT8 (0x0D)"
        );

        // TypeIdentifier pair from a byte-field struct vs a uint8-field struct
        // must produce different TypeIdentifiers (TK_BYTE vs TK_UINT8 in the
        // Primitive variant).
        let byte_id = TypeIdentifier::Primitive(XK::TK_BYTE);
        let u8_id = TypeIdentifier::Primitive(XK::TK_UINT8);
        assert_ne!(
            byte_id, u8_id,
            "TypeIdentifier(TK_BYTE) and TypeIdentifier(TK_UINT8) must be distinct"
        );
    }

    #[test]
    fn test_byte_array_lowers_to_tk_byte() {
        // A struct with a plain array of `byte` elements must produce a
        // PlainArraySmall TypeIdentifier whose element_identifier is
        // TypeIdentifier::Primitive(TK_BYTE), NOT TK_UINT8.
        //
        // This guards against the regression where both Byte and U8 were
        // aliased to U8 / TK_UINT8, causing byte[N] and uint8[N] fields to
        // produce identical TypeIdentifiers and therefore match types they
        // should not.
        use crate::xtypes::TypeKind as XK;

        let byte_type = Arc::new(TypeDescriptor::primitive("byte", PrimitiveKind::Byte));
        let arr_desc = TypeDescriptor::new("", TypeKind::Array(ArrayDescriptor::new(byte_type, 4)));
        let type_id = descriptor_to_type_identifier(&arr_desc)
            .expect("byte array must have a valid TypeIdentifier");

        match &type_id {
            TypeIdentifier::PlainArraySmall(defn) => {
                assert_eq!(
                    defn.array_bound_seq,
                    vec![4u8],
                    "array_bound_seq must be [4]"
                );
                assert_eq!(
                    *defn.element_identifier,
                    TypeIdentifier::Primitive(XK::TK_BYTE),
                    "element TypeIdentifier must be TK_BYTE (0x02), not TK_UINT8"
                );
            }
            other => panic!("expected PlainArraySmall, got {:?}", other),
        }
    }
}

// ---------------------------------------------------------------------------
// Complete-reference rewrite tests (wire form faithfulness)
// ---------------------------------------------------------------------------

#[cfg(all(test, feature = "xtypes-structural-assignability"))]
mod complete_refs_tests {
    use super::*;
    use crate::dynamic::type_descriptor::{
        EnumDescriptor, EnumVariant, FieldDescriptor, SequenceDescriptor, UnionCase,
        UnionDescriptor,
    };
    use std::collections::HashMap;
    use std::sync::Arc;

    fn enum_desc(name: &str, variants: &[(&str, i64)]) -> Arc<TypeDescriptor> {
        Arc::new(TypeDescriptor::new(
            name,
            TypeKind::Enum(EnumDescriptor::new(
                variants
                    .iter()
                    .map(|(n, v)| EnumVariant::new(*n, *v))
                    .collect(),
            )),
        ))
    }

    /// Store = what the driver registers: nested objects collected from the
    /// descriptor, plus the top-level hybrid keyed by its Minimal hash.
    fn store_for(desc: &TypeDescriptor) -> HashMap<EquivalenceHash, CompleteTypeObject> {
        let mut store = HashMap::new();
        collect_nested_type_objects(desc, &mut store);
        if let Some(to) = type_descriptor_to_xtypes(desc) {
            if let Some(h) = complete_type_object_minimal_hash(&to) {
                store.entry(h).or_insert(to);
            }
        }
        store
    }

    /// Core faithfulness contract: rewriting the hybrid through the store
    /// must reproduce the Complete lowering EXACTLY (structural equality,
    /// hence byte/hash equality) for every dep-bearing shape the dynamic
    /// path produces.
    #[test]
    fn rewrite_matches_complete_lowering_for_dep_bearing_types() {
        let e1 = enum_desc("Test::E1", &[("A", 0), ("B", 1), ("C", 2)]);

        // struct { E1 color; }
        let s_enum = TypeDescriptor::struct_type(
            "Test::StructEnum",
            vec![FieldDescriptor::new("color", e1.clone())],
        );
        // struct { sequence<E1> colors; E1 arr[3]; }
        let s_coll = TypeDescriptor::struct_type(
            "Test::StructColl",
            vec![
                FieldDescriptor::new(
                    "colors",
                    Arc::new(TypeDescriptor::new(
                        "seq_e1",
                        TypeKind::Sequence(SequenceDescriptor {
                            element_type: e1.clone(),
                            max_length: Some(10),
                        }),
                    )),
                ),
                FieldDescriptor::new(
                    "arr",
                    Arc::new(TypeDescriptor::new(
                        "arr_e1",
                        TypeKind::Array(ArrayDescriptor::new(e1.clone(), 3)),
                    )),
                ),
            ],
        );
        // union switch(E1) { case 0: int32 x; }
        let u_enum = TypeDescriptor::new(
            "Test::UnionEnumDisc",
            TypeKind::Union(UnionDescriptor::new(
                e1.clone(),
                vec![UnionCase::new(
                    "x",
                    vec![0],
                    Arc::new(TypeDescriptor::primitive("int32", PrimitiveKind::I32)),
                )],
            )),
        );
        // struct { Inner inner; } where Inner is a nested dep-bearing struct
        // (Inner itself holds an enum member: two-level Complete recursion).
        let inner = Arc::new(TypeDescriptor::struct_type(
            "Test::Inner",
            vec![FieldDescriptor::new("c", e1.clone())],
        ));
        let s_nested = TypeDescriptor::struct_type(
            "Test::Outer",
            vec![FieldDescriptor::new(
                "inner",
                Arc::new(TypeDescriptor::new("nested_inner", TypeKind::Nested(inner))),
            )],
        );

        for (label, desc) in [
            ("struct-enum", &s_enum),
            ("struct-collections", &s_coll),
            ("union-enum-disc", &u_enum),
            ("struct-nested-struct", &s_nested),
        ] {
            let hybrid = type_descriptor_to_xtypes(desc)
                .unwrap_or_else(|| panic!("{label}: hybrid lowering"));
            let expected = type_descriptor_to_xtypes_complete(desc)
                .unwrap_or_else(|| panic!("{label}: complete lowering"));
            let store = store_for(desc);
            let wire = complete_type_object_with_complete_refs(&hybrid, &store);
            assert_eq!(wire, expected, "{label}: rewrite != Complete lowering");
            assert_eq!(
                wire.compute_equivalence_hash().expect("wire hash"),
                expected.compute_equivalence_hash().expect("expected hash"),
                "{label}: wire hash != Complete lowering hash"
            );
            // Dep-bearing: the wire identity MUST differ from the hybrid's.
            assert_ne!(
                wire.compute_equivalence_hash().expect("wire hash"),
                hybrid.compute_equivalence_hash().expect("hybrid hash"),
                "{label}: dep-bearing type should change hash after rewrite"
            );
        }
    }

    /// A type without hash-based references must come back structurally
    /// unchanged (same EquivalenceHash), so no-dep types keep their identity.
    #[test]
    fn rewrite_no_dep_type_is_identity() {
        let plain = TypeDescriptor::struct_type(
            "Test::Plain",
            vec![
                FieldDescriptor::new(
                    "a",
                    Arc::new(TypeDescriptor::primitive("int32", PrimitiveKind::I32)),
                ),
                FieldDescriptor::new(
                    "b",
                    Arc::new(TypeDescriptor::primitive(
                        "string",
                        PrimitiveKind::String { max_length: None },
                    )),
                ),
            ],
        );
        let hybrid = type_descriptor_to_xtypes(&plain).expect("lowering");
        let store = store_for(&plain);
        let wire = complete_type_object_with_complete_refs(&hybrid, &store);
        assert_eq!(wire, hybrid, "no-dep type must be unchanged");
    }

    /// An unresolvable Minimal reference (hash not in the store) stays
    /// untouched instead of being dropped or mis-rewritten.
    #[test]
    fn rewrite_unresolvable_ref_kept() {
        let e1 = enum_desc("Test::E1", &[("A", 0), ("B", 1)]);
        let s = TypeDescriptor::struct_type("Test::S", vec![FieldDescriptor::new("color", e1)]);
        let hybrid = type_descriptor_to_xtypes(&s).expect("lowering");
        let empty: HashMap<EquivalenceHash, CompleteTypeObject> = HashMap::new();
        let wire = complete_type_object_with_complete_refs(&hybrid, &empty);
        assert_eq!(wire, hybrid, "unresolvable refs must degrade to hybrid");
    }
}

#[cfg(all(test, feature = "xtypes"))]
#[path = "xtypes_conformance_tests.rs"]
mod conformance_tests;
