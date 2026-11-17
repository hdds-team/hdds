// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! XTypes v1.3 - Extensible and Dynamic Topic Types for DDS
//!
//!
//! Implementation of OMG DDS-XTypes v1.3 specification for type evolution and
//! dynamic type discovery.
//!
//! # Overview
//!
//! XTypes provides:
//! - **TypeIdentifier**: Unique identification of types (hash-based or direct)
//! - **TypeObject**: Runtime type metadata (Minimal and Complete representations)
//! - **Type Evolution**: Compatibility rules for schema evolution
//! - **Dynamic Types**: Create types at runtime without IDL (the crate-level `dynamic` module, behind the `dynamic-types` feature)
//!
//! # Type Identification
//!
//! Every DDS type has a `TypeIdentifier` that uniquely identifies it:
//!
//! ```ignore
//! use hdds::xtypes::{TypeIdentifier, TypeKind};
//!
//! // Primitive types (no hashing needed)
//! let int32_id = TypeIdentifier::TK_INT32;
//! let float64_id = TypeIdentifier::TK_FLOAT64;
//!
//! // Strings (bounded)
//! let string_id = TypeIdentifier::string(256);
//!
//! // Complex types (hash-based)
//! let struct_hash = EquivalenceHash::compute(&type_object_bytes);
//! let struct_id = TypeIdentifier::minimal(struct_hash);
//! ```
//!
//! # Type Evolution
//!
//! XTypes supports schema evolution with compatibility rules:
//!
//! - **@final**: No changes allowed (exact match required)
//! - **@appendable**: Can add members at the end
//! - **@mutable**: Can add/remove members anywhere (by member_id)
//!
//! ```idl
//! @appendable
//! struct Sensor {
//!     @key long id;
//!     float temperature;
//!     // New field added in v2 (compatible!)
//!     @optional float humidity;
//! };
//! ```
//!
//! # Specification References
//!
//! - **OMG DDS-XTypes v1.3**: <https://www.omg.org/spec/DDS-XTypes/1.3/>
//! - **TypeObject IDL**: <https://www.omg.org/spec/DDS-XTypes/20190301/dds-xtypes_typeobject.idl>
//! - **DDS v1.4**: Section 2.2.3 (Type Representation)
//!
//! # Feature Flags
//!
//! - `xtypes` (default): Enable TypeIdentifier and EquivalenceHash (requires `md5` crate)
//! - `xtypes-complete` (future): Enable Complete TypeObject (additional metadata)
//!
//! # Implementation Status
//!
//! - \[OK\] TypeIdentifier (spec-compliant discriminator octets)
//! - \[OK\] EquivalenceHash (MD5, 14 bytes; cross-vendor byte-equivalent
//!   to Fast DDS 3.x for the canonical Temperature fixture)
//! - \[OK\] TypeObject (Minimal + Complete, spec-compliant discriminator
//!   labels per sec. 7.3.4.5)
//! - \[OK\] AnnotationParameterValue (every case of the Annex B union,
//!   checked against Fast DDS 3.4 and Cyclone DDS 0.11)
//! - \[OK\] PID_TYPE_INFORMATION emit + decode on SEDP
//! - \[OK\] TI_PLAIN_SEQUENCE / TI_PLAIN_ARRAY / TI_PLAIN_MAP variants
//! - \[OK\] StronglyConnectedComponent for cyclic types

/// Runtime helpers to build DDS TypeObjects from ROS 2 introspection metadata.
pub mod builder;
mod cdr2;
pub(crate) mod discriminators;
mod equivalence;
mod type_id;
mod type_kind;
mod type_object;

pub use equivalence::EquivalenceHash;
pub use type_id::{
    EquivalenceKind, PlainArrayLElemDefn, PlainArraySElemDefn, PlainCollectionHeader,
    PlainMapLTypeDefn, PlainMapSTypeDefn, PlainSequenceLElemDefn, PlainSequenceSElemDefn,
    StronglyConnectedComponentId, TypeIdentifier,
};
pub use type_kind::TypeKind;

// Captured legacy TypeObject v1 wire vectors, shared across in-crate test
// modules (the discovery pipeline tests replay them through handle_sedp).
#[cfg(test)]
pub(crate) use type_object::legacy_v1_test_vectors;
#[cfg(any(test, feature = "xtypes-structural-assignability"))]
pub(crate) use type_object::v1_projection_equivalent;

// TypeObject exports
pub use type_object::{
    // TypeObject codec (compression/decompression)
    compress_type_object,
    // Legacy TypeObject v1 (XCDR1) decoder
    decode_type_object_v1,
    decompress_type_object,
    // Flags
    AliasTypeFlag,
    AnnotationParameterFlag,
    // Annotation types
    AnnotationParameterValue,
    AnnotationTypeFlag,
    // Detail structures
    AppliedAnnotation,
    AppliedAnnotationParameter,
    AppliedBuiltinMemberAnnotations,
    AppliedBuiltinTypeAnnotations,
    AppliedVerbatimAnnotation,
    BitfieldFlag,
    BitflagFlag,
    BitmaskTypeFlag,
    BitsetTypeFlag,
    CollectionElementFlag,
    CollectionTypeFlag,
    // Alias types
    CommonAliasBody,
    CommonAnnotationParameter,
    // Bitset types
    CommonBitfield,
    // Bitmask types
    CommonBitflag,
    // Enum types
    CommonEnumeratedLiteral,
    // Struct types
    CommonStructMember,
    // Union types
    CommonUnionMember,
    CompleteAliasBody,
    CompleteAliasHeader,
    CompleteAliasType,
    CompleteAnnotationHeader,
    CompleteAnnotationParameter,
    CompleteAnnotationType,
    // Collection types
    CompleteArrayHeader,
    CompleteArrayType,
    CompleteBitfield,
    CompleteBitflag,
    CompleteBitmaskHeader,
    CompleteBitmaskType,
    CompleteBitsetHeader,
    CompleteBitsetType,
    CompleteCollectionElement,
    CompleteCollectionHeader,
    CompleteElementDetail,
    CompleteEnumeratedHeader,
    CompleteEnumeratedLiteral,
    CompleteEnumeratedType,
    CompleteMapType,
    CompleteMemberDetail,
    CompleteSequenceType,
    CompleteStructHeader,
    CompleteStructMember,
    CompleteStructType,
    CompleteTypeDetail,
    // Core TypeObject types
    CompleteTypeObject,
    CompleteUnionHeader,
    CompleteUnionMember,
    CompleteUnionType,
    DecodedTypeObjectV1,
    EnumTypeFlag,
    EnumeratedLiteralFlag,
    MemberFlag,
    MinimalAliasBody,
    MinimalAliasHeader,
    MinimalAliasType,
    MinimalAnnotationHeader,
    MinimalAnnotationParameter,
    MinimalAnnotationType,
    MinimalArrayType,
    MinimalBitfield,
    MinimalBitflag,
    MinimalBitmaskHeader,
    MinimalBitmaskType,
    MinimalBitsetHeader,
    MinimalBitsetType,
    MinimalCollectionElement,
    MinimalCollectionHeader,
    MinimalEnumeratedHeader,
    MinimalEnumeratedLiteral,
    MinimalEnumeratedType,
    MinimalMapType,
    MinimalMemberDetail,
    MinimalSequenceType,
    MinimalStructHeader,
    MinimalStructMember,
    MinimalStructType,
    MinimalTypeDetail,
    MinimalTypeObject,
    MinimalUnionHeader,
    MinimalUnionMember,
    MinimalUnionType,
    StructTypeFlag,
    TypeObject,
    TypeRelationFlag,
    UnionTypeFlag,
};

// Re-export for convenience
pub use type_id::TypeIdentifier as TypeId;

/// Module version
pub const XTYPES_VERSION: &str = "1.3";

/// XTypes implementation version (HDDS)
pub const IMPL_VERSION: &str = "0.8.0-dev";

pub use builder::{
    rosidl_message_type_support_t, rosidl_type_hash_t,
    rosidl_typesupport_introspection_c__MessageMember,
    rosidl_typesupport_introspection_c__MessageMembers, BuilderError, FieldType, MessageDescriptor,
    MessageMember, PrimitiveType, RosMessageMetadata, RosidlError, TypeObjectBuilder,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_exports() {
        // Verify all public types are accessible (compile-time check)
        let _ = TypeKind::TK_INT32;
        let _ = EquivalenceHash::zero();
        let _ = EquivalenceKind::Minimal;
        let _ = TypeIdentifier::TK_FLOAT64;
    }

    #[test]
    fn test_version_constants() {
        assert_eq!(XTYPES_VERSION, "1.3");
        assert!(IMPL_VERSION.starts_with("0.8"));
    }
}
