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
    ArrayDescriptor, EnumDescriptor, EnumVariant, FieldDescriptor, PrimitiveKind,
    SequenceDescriptor, TypeDescriptor, TypeKind, UnionCase, UnionDescriptor,
};
use crate::xtypes::{
    CompleteArrayType, CompleteBitmaskType, CompleteEnumeratedType, CompleteSequenceType,
    CompleteStructType, CompleteTypeObject, CompleteUnionType, EquivalenceHash, MemberFlag,
    TypeIdentifier, TypeKind as XTypesKind,
};
use std::collections::HashMap;
use std::sync::Arc;

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

            FieldDescriptor {
                name: field_name,
                type_desc: field_type,
                id: Some(member.common.member_id),
                optional: is_optional,
                default: None,
            }
        })
        .collect();

    Arc::new(TypeDescriptor::struct_type(name, fields))
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

    Arc::new(TypeDescriptor::new(
        name,
        TypeKind::Enum(EnumDescriptor::new(variants)),
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

            let case = UnionCase {
                name: case_name,
                labels: labels.clone(),
                type_desc: case_type,
            };

            if is_default {
                default_case = Some(Box::new(case.clone()));
            }

            case
        })
        .collect();

    Arc::new(TypeDescriptor::new(
        name,
        TypeKind::Union(UnionDescriptor {
            discriminator,
            cases,
            default_case,
        }),
    ))
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
    let total_length: usize = a.bound_seq.iter().map(|&d| d as usize).product();

    // Format name with dimensions
    let dims: String = a
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

    // Bitmask is represented as an enum where values are bit positions
    Arc::new(TypeDescriptor::new(
        name,
        TypeKind::Enum(EnumDescriptor::new(variants)),
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
        // Inline type object (hdds extension): recurse directly.
        TypeIdentifier::Inline(type_object) => convert_type_object(type_object, registry),
    }
}

/// Convert XTypes TypeKind to dynamic PrimitiveKind.
// @audit-ok: Simple pattern matching (cyclo 18, cogni 1) - XTypes to PrimitiveKind conversion table
fn xtypes_kind_to_primitive(kind: XTypesKind) -> PrimitiveKind {
    match kind {
        XTypesKind::TK_BOOLEAN => PrimitiveKind::Bool,
        XTypesKind::TK_BYTE | XTypesKind::TK_UINT8 => PrimitiveKind::U8,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xtypes::{
        CollectionElementFlag, CommonStructMember, CommonUnionMember, CompleteCollectionElement,
        CompleteCollectionHeader, CompleteMemberDetail, CompleteStructHeader, CompleteStructMember,
        CompleteTypeDetail, CompleteUnionHeader, CompleteUnionMember, StructTypeFlag,
        UnionTypeFlag,
    };

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

    #[test]
    fn test_convert_sequence() {
        let type_object = CompleteTypeObject::Sequence(CompleteSequenceType {
            header: CompleteCollectionHeader {
                bound: 100, // bounded sequence
                detail: CompleteTypeDetail::new("BoundedSeq"),
            },
            element: CompleteCollectionElement {
                flags: CollectionElementFlag::empty(),
                type_id: TypeIdentifier::TK_INT32,
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
            header: CompleteCollectionHeader {
                bound: 0,
                detail: CompleteTypeDetail::new("Matrix"),
            },
            element: CompleteCollectionElement {
                flags: CollectionElementFlag::empty(),
                type_id: TypeIdentifier::TK_FLOAT64,
            },
            bound_seq: vec![3, 4], // 3x4 matrix
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
            header: CompleteCollectionHeader {
                bound: 0,
                detail: CompleteTypeDetail::new("PointList"),
            },
            element: CompleteCollectionElement {
                flags: CollectionElementFlag::empty(),
                type_id: TypeIdentifier::Complete(element_hash),
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
}
