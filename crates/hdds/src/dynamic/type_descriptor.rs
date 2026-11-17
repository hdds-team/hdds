// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Type descriptors for runtime type information.

use crate::dynamic::{LONG_DOUBLE_ALIGN, LONG_DOUBLE_SIZE};
use std::sync::Arc;

/// Primitive type kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PrimitiveKind {
    Bool,
    /// Opaque single byte (TK_BYTE / IDL `byte`).
    ///
    /// Distinct from `U8` (TK_UINT8): the two types are not mutually assignable
    /// per DDS-XTypes v1.3 sec. 7.5.1.3 Table 3. CDR encoding is identical (1 byte,
    /// no alignment padding), but type matching must reject `byte` vs `uint8` pairs.
    Byte,
    U8,
    U16,
    U32,
    U64,
    I8,
    I16,
    I32,
    I64,
    F32,
    F64,
    LongDouble,
    Char,
    String {
        max_length: Option<usize>,
    },
    WString {
        max_length: Option<usize>,
    },
}

impl PrimitiveKind {
    /// Get the size in bytes (None for strings).
    pub fn size(&self) -> Option<usize> {
        match self {
            Self::Bool | Self::Byte | Self::U8 | Self::I8 | Self::Char => Some(1),
            Self::U16 | Self::I16 => Some(2),
            Self::U32 | Self::I32 | Self::F32 => Some(4),
            Self::U64 | Self::I64 | Self::F64 => Some(8),
            Self::LongDouble => Some(LONG_DOUBLE_SIZE),
            Self::String { .. } | Self::WString { .. } => None,
        }
    }

    /// Get CDR alignment requirement.
    pub fn alignment(&self) -> usize {
        match self {
            Self::Bool | Self::Byte | Self::U8 | Self::I8 | Self::Char => 1,
            Self::U16 | Self::I16 => 2,
            Self::U32 | Self::I32 | Self::F32 | Self::String { .. } | Self::WString { .. } => 4,
            Self::U64 | Self::I64 | Self::F64 => 8,
            Self::LongDouble => LONG_DOUBLE_ALIGN,
        }
    }
}

/// Type kind enumeration.
#[derive(Debug, Clone, PartialEq)]
pub enum TypeKind {
    /// Primitive type.
    Primitive(PrimitiveKind),
    /// Struct with named fields.
    Struct(Vec<FieldDescriptor>),
    /// Sequence (dynamic length).
    Sequence(SequenceDescriptor),
    /// Array (fixed length).
    Array(ArrayDescriptor),
    /// Enumeration.
    Enum(EnumDescriptor),
    /// Union with discriminator.
    Union(UnionDescriptor),
    /// Nested type reference.
    Nested(Arc<TypeDescriptor>),
}

/// Struct extensibility kind per DDS-XTypes v1.3 sec. 7.2.2.4.1 Table 9.
///
/// Determines the CDR encapsulation representation identifier used on the
/// wire and the `StructTypeFlag` emitted in SEDP TypeObjects:
///
/// - `Final`      -> `IS_FINAL` (0x0001), XCDR1/XCDR2 plain
/// - `Appendable` -> `IS_APPENDABLE` (0x0002), XCDR2 delimited (DHEADER)
/// - `Mutable`    -> `IS_MUTABLE` (0x0004), XCDR2 with EMHEADER per-member
///
/// The default is `Appendable`: "In the event that the representation of a
/// given type does not indicate the type's extensibility kind, the type shall
/// be considered appendable" (DDS-XTypes 1.3 7.3.1.2.1.8). HDDS 1.4.x
/// defaulted to `Final`; a descriptor that must keep that layout says so with
/// [`TypeDescriptor::with_extensibility`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Extensibility {
    /// @final -- no optional or new members; backward compatible only by value.
    Final,
    /// @appendable -- new optional members may be appended; uses DHEADER.
    #[default]
    Appendable,
    /// @mutable -- any member may change; uses EMHEADER per member.
    Mutable,
}

/// A complete type descriptor.
#[derive(Debug, Clone, PartialEq)]
pub struct TypeDescriptor {
    /// Type name.
    pub name: String,
    /// Type kind.
    pub kind: TypeKind,
    /// Extensibility kind for struct types (DDS-XTypes v1.3 sec. 7.2.2.4.1).
    ///
    /// Ignored for non-struct descriptors.  Defaults to
    /// `Extensibility::Appendable` (DDS-XTypes 1.3 7.3.1.2.1.8).
    pub extensibility: Extensibility,
    /// Use hash-based member ID assignment (`@autoid(HASH)` per DDS-XTypes
    /// v1.3 sec. 7.3.1.2).
    ///
    /// When `true` the `IS_AUTOID_HASH` bit (0x0010) is set in
    /// `StructTypeFlag` during TypeObject emission.  The XML attribute is
    /// `autoid="hash"` on a `<struct>` element.
    ///
    /// Ignored for non-struct descriptors.  Defaults to `false`.
    pub autoid_hash: bool,
}

impl TypeDescriptor {
    /// Create a new type descriptor with the specification's default
    /// extensibility, `Appendable` (DDS-XTypes 1.3 7.3.1.2.1.8).
    pub fn new(name: impl Into<String>, kind: TypeKind) -> Self {
        Self {
            name: name.into(),
            kind,
            extensibility: Extensibility::Appendable,
            autoid_hash: false,
        }
    }

    /// Create a primitive type descriptor.
    pub fn primitive(name: impl Into<String>, kind: PrimitiveKind) -> Self {
        Self::new(name, TypeKind::Primitive(kind))
    }

    /// Create a struct type descriptor with `Appendable` extensibility, the
    /// specification's default (DDS-XTypes 1.3 7.3.1.2.1.8).
    pub fn struct_type(name: impl Into<String>, fields: Vec<FieldDescriptor>) -> Self {
        Self::new(name, TypeKind::Struct(fields))
    }

    /// Set extensibility kind, consuming and returning `self` for chaining.
    pub fn with_extensibility(mut self, ext: Extensibility) -> Self {
        self.extensibility = ext;
        self
    }

    /// Enable hash-based member IDs (`@autoid(HASH)`), consuming and returning
    /// `self` for chaining.
    pub fn with_autoid_hash(mut self) -> Self {
        self.autoid_hash = true;
        self
    }

    /// Check if this is a primitive type.
    pub fn is_primitive(&self) -> bool {
        matches!(self.kind, TypeKind::Primitive(_))
    }

    /// Check if this is a struct type.
    pub fn is_struct(&self) -> bool {
        matches!(self.kind, TypeKind::Struct(_))
    }

    /// Get fields if this is a struct.
    pub fn fields(&self) -> Option<&[FieldDescriptor]> {
        match &self.kind {
            TypeKind::Struct(fields) => Some(fields),
            _ => None,
        }
    }

    /// Get field by name.
    pub fn field(&self, name: &str) -> Option<&FieldDescriptor> {
        self.fields()?.iter().find(|f| f.name == name)
    }

    /// Get field index by name.
    pub fn field_index(&self, name: &str) -> Option<usize> {
        self.fields()?.iter().position(|f| f.name == name)
    }

    /// Calculate minimum CDR size (without strings/sequences).
    pub fn min_size(&self) -> usize {
        match &self.kind {
            TypeKind::Primitive(p) => p.size().unwrap_or(4), // String: 4 bytes for length
            TypeKind::Struct(fields) => {
                let mut size = 0;
                for field in fields {
                    // Align
                    let align = field.type_desc.alignment();
                    size = (size + align - 1) & !(align - 1);
                    size += field.type_desc.min_size();
                }
                size
            }
            TypeKind::Sequence(_) => 4, // Just the length
            TypeKind::Array(arr) => arr.element_type.min_size() * arr.length,
            TypeKind::Enum(e) => e.holder_size(),
            TypeKind::Union(u) => {
                4 + u
                    .cases
                    .iter()
                    .map(|c| c.type_desc.min_size())
                    .max()
                    .unwrap_or(0)
            }
            TypeKind::Nested(inner) => inner.min_size(),
        }
    }

    /// Get alignment requirement.
    pub fn alignment(&self) -> usize {
        match &self.kind {
            TypeKind::Primitive(p) => p.alignment(),
            TypeKind::Struct(fields) => fields
                .iter()
                .map(|f| f.type_desc.alignment())
                .max()
                .unwrap_or(1),
            TypeKind::Sequence(seq) => seq.element_type.alignment().max(4),
            TypeKind::Array(arr) => arr.element_type.alignment(),
            TypeKind::Enum(e) => e.holder_size(),
            TypeKind::Union(u) => u.discriminator.alignment().max(
                u.cases
                    .iter()
                    .map(|c| c.type_desc.alignment())
                    .max()
                    .unwrap_or(1),
            ),
            TypeKind::Nested(inner) => inner.alignment(),
        }
    }
}

/// Try-construct policy for a member per DDS-XTypes v1.3 sec. 7.5.1.4.
///
/// Applied when incoming data for the member cannot be assigned to the local
/// type (e.g., sequence length exceeds local bound, string exceeds local bound,
/// or enum value is not present in the local enumeration).
///
/// Encoding in `MemberFlag` (sec. 7.2.2.4.1.2):
///   TRY_CONSTRUCT1 (bit 0) = 0x0001
///   TRY_CONSTRUCT2 (bit 1) = 0x0002
///
///   UseDefault = TC1=1, TC2=0 (0x0001)
///   Discard    = TC1=0, TC2=1 (0x0002)
///   Trim       = TC1=1, TC2=1 (0x0003)
///
/// Per DDS-XTypes v1.3 sec. 7.2.2.4.1.2 Table 9, the TC1/TC2 bit encoding is:
///   TC1=0, TC2=0 -> absent / DISCARD (both bits unset means no accommodation)
///   TC1=1, TC2=0 -> USE_DEFAULT
///   TC1=0, TC2=1 -> DISCARD (explicit)
///   TC1=1, TC2=1 -> TRIM
///
/// The Rust `Default` maps to `Discard` (both bits absent = reject).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum TryConstructKind {
    /// On bound violation: discard the entire enclosing sample.
    ///
    /// Default when no tryConstruct attribute is present (TC1=0, TC2=0).
    #[default]
    Discard,
    /// On bound violation: fill member with its type default (zero / empty).
    ///
    /// TC1=1, TC2=0.
    UseDefault,
    /// On bound violation: trim sequences/strings to the local bound;
    /// for non-collection members behaves like `UseDefault`.
    ///
    /// TC1=1, TC2=1.
    Trim,
}

/// Field descriptor for struct members.
#[derive(Debug, Clone, PartialEq)]
pub struct FieldDescriptor {
    /// Field name.
    pub name: String,
    /// Field type.
    pub type_desc: Arc<TypeDescriptor>,
    /// Field ID (for extensible types).
    pub id: Option<u32>,
    /// Is optional (@optional annotation).
    pub optional: bool,
    /// Default value (if any).
    pub default: Option<String>,
    /// Try-construct policy (DDS-XTypes v1.3 sec. 7.5.1.4).
    pub try_construct: TryConstructKind,
    /// The `@hashid` annotation's value (DDS-XTypes v1.3 7.3.1.2.1.1): when
    /// `Some`, the member id is the hash of this value, or of `name` when the
    /// value is empty (`@hashid` without a parameter), whatever the struct's
    /// `@autoid`; an explicit `id` takes priority. It changes only the member
    /// id: the Minimal TypeObject name hash is always the hash of `name`.
    ///
    /// The DDS-XML attribute is `hashid="alias"` on a `<member>` element. It
    /// allows a renamed member (`x2`) to carry the same hash-ID as the original
    /// name (`x1`), enabling type evolution without breaking ID-based matching.
    pub hashid_name: Option<String>,
    /// @key annotation: member participates in the DDS instance key.
    ///
    /// Sets `MemberFlag::IS_KEY` in the emitted TypeObject member flags.
    /// Key members must match exactly between writer and reader type (sec. 7.5.1.3).
    pub is_key: bool,
    /// @must_understand annotation: reader must understand this member.
    ///
    /// Sets `MemberFlag::IS_MUST_UNDERSTAND` in the emitted TypeObject member
    /// flags. If a writer sends data with a member marked IS_MUST_UNDERSTAND
    /// and the reader's type does not have a matching member, the types are
    /// structurally incompatible (sec. 7.5.1.1.2, sec. 7.5.1.1.3).
    pub is_must_understand: bool,
}

impl FieldDescriptor {
    /// Create a new field descriptor.
    pub fn new(name: impl Into<String>, type_desc: Arc<TypeDescriptor>) -> Self {
        Self {
            name: name.into(),
            type_desc,
            id: None,
            optional: false,
            default: None,
            // Per DDS-XTypes v1.3 sec. 7.2.2.4.1.2 Table 9, absent try-construct
            // bits (TC1=0, TC2=0) encode DISCARD.
            try_construct: TryConstructKind::Discard,
            hashid_name: None,
            is_key: false,
            is_must_understand: false,
        }
    }

    /// Set field ID.
    pub fn with_id(mut self, id: u32) -> Self {
        self.id = Some(id);
        self
    }

    /// Mark as optional.
    pub fn optional(mut self) -> Self {
        self.optional = true;
        self
    }

    /// Set default value.
    pub fn with_default(mut self, default: impl Into<String>) -> Self {
        self.default = Some(default.into());
        self
    }

    /// Set try-construct policy.
    pub fn with_try_construct(mut self, policy: TryConstructKind) -> Self {
        self.try_construct = policy;
        self
    }

    /// Set the `@hashid` alias name used for hash-based member ID computation.
    ///
    /// The member id becomes the hash of `alias`, or of the member's own name
    /// when `alias` is empty, under `@autoid(SEQUENTIAL)` as well as
    /// `@autoid(HASH)` (DDS-XTypes 1.3 7.3.1.2.1.1); the next sequential
    /// member follows it.
    pub fn with_hashid_name(mut self, alias: impl Into<String>) -> Self {
        self.hashid_name = Some(alias.into());
        self
    }

    /// Mark as a @key member.
    ///
    /// Sets `MemberFlag::IS_KEY` in the emitted TypeObject, which causes the
    /// key-compatibility check to include this member (sec. 7.5.1.3).
    pub fn with_key(mut self) -> Self {
        self.is_key = true;
        self
    }

    /// Mark as @must_understand.
    ///
    /// Sets `MemberFlag::IS_MUST_UNDERSTAND` in the emitted TypeObject. The
    /// reader must have a member with the same ID; if absent, the type pair is
    /// structurally incompatible (sec. 7.5.1.1.2, sec. 7.5.1.1.3).
    pub fn with_must_understand(mut self) -> Self {
        self.is_must_understand = true;
        self
    }
}

/// Sequence type descriptor.
#[derive(Debug, Clone, PartialEq)]
pub struct SequenceDescriptor {
    /// Element type.
    pub element_type: Arc<TypeDescriptor>,
    /// Maximum length (None = unbounded).
    pub max_length: Option<usize>,
}

impl SequenceDescriptor {
    /// Create unbounded sequence.
    pub fn unbounded(element_type: Arc<TypeDescriptor>) -> Self {
        Self {
            element_type,
            max_length: None,
        }
    }

    /// Create bounded sequence.
    pub fn bounded(element_type: Arc<TypeDescriptor>, max_length: usize) -> Self {
        Self {
            element_type,
            max_length: Some(max_length),
        }
    }
}

/// Array type descriptor.
#[derive(Debug, Clone, PartialEq)]
pub struct ArrayDescriptor {
    /// Element type.
    pub element_type: Arc<TypeDescriptor>,
    /// Total element count (product of all dimensions).
    ///
    /// For single-dimension arrays this equals `dims[0]`.  For multi-dimension
    /// arrays it equals the product of all `dims`.  All existing code that
    /// walks element count should use this field unchanged.
    pub length: usize,
    /// Per-dimension sizes for multi-dimensional arrays (DDS-XTypes sec. 7.2.2.4.3).
    ///
    /// Empty for descriptors built by legacy code that predates this field.
    /// When non-empty the outer-to-inner order matches the IDL `arrayDimensions`
    /// attribute: `arrayDimensions="10,2"` -> `dims = [10, 2]`.
    ///
    /// Used by `xtypes_bridge::descriptor_to_type_identifier` to populate
    /// `PlainArray{S,L}ElemDefn::array_bound_seq` with all dimension bounds
    /// instead of a single flat product.
    pub dims: Vec<u32>,
}

impl ArrayDescriptor {
    /// Create single-dimension array descriptor.
    pub fn new(element_type: Arc<TypeDescriptor>, length: usize) -> Self {
        Self {
            element_type,
            length,
            dims: Vec::new(),
        }
    }

    /// Create multi-dimension array descriptor.
    ///
    /// `dims` must be outer-to-inner order matching IDL `arrayDimensions`.
    /// `length` is computed as the product of all `dims`.
    pub fn multi_dim(element_type: Arc<TypeDescriptor>, dims: Vec<u32>) -> Self {
        let length: usize = dims.iter().map(|&d| d as usize).product();
        Self {
            element_type,
            length,
            dims,
        }
    }
}

/// Enumeration type descriptor.
#[derive(Debug, Clone, PartialEq)]
pub struct EnumDescriptor {
    /// Enum variants.
    pub variants: Vec<EnumVariant>,
    /// Underlying type (default u32).
    pub underlying: PrimitiveKind,
    /// True when this descriptor was constructed from a bitmask (IDL @bit_bound)
    /// rather than a plain enum. Bitmask discriminators in unions map to the
    /// underlying primitive width for TypeIdentifier comparison (DDS-XTypes v1.3
    /// sec. 7.5.2.9: bitmask is assignable from integer of same bit_bound).
    pub is_bitmask: bool,
}

impl EnumDescriptor {
    /// Create enum descriptor.
    pub fn new(variants: Vec<EnumVariant>) -> Self {
        Self {
            variants,
            underlying: PrimitiveKind::U32,
            is_bitmask: false,
        }
    }

    /// Create bitmask descriptor. Bitmask types are represented as enum
    /// internally but use the underlying primitive type for discriminator
    /// TypeIdentifier comparison (DDS-XTypes v1.3 sec. 7.5.2.9).
    pub fn new_bitmask(variants: Vec<EnumVariant>) -> Self {
        Self {
            variants,
            underlying: PrimitiveKind::U32,
            is_bitmask: true,
        }
    }

    /// Size in bytes of the integer that holds a value on the wire: the
    /// `holder_type` of DDS-XTypes 1.3 Table 40, Int8/Int16/Int32 for an enum
    /// and UInt8 to UInt64 for a bitmask, set by its `@bit_bound`.
    pub(crate) fn holder_size(&self) -> usize {
        match self.underlying {
            PrimitiveKind::I8 | PrimitiveKind::U8 | PrimitiveKind::Byte => 1,
            PrimitiveKind::I16 | PrimitiveKind::U16 => 2,
            PrimitiveKind::I64 | PrimitiveKind::U64 => 8,
            _ => 4,
        }
    }

    /// Set the underlying integer type.
    pub fn with_underlying(mut self, underlying: PrimitiveKind) -> Self {
        self.underlying = underlying;
        self
    }

    /// Get variant by name.
    pub fn variant(&self, name: &str) -> Option<&EnumVariant> {
        self.variants.iter().find(|v| v.name == name)
    }

    /// Get variant by value.
    pub fn variant_by_value(&self, value: i64) -> Option<&EnumVariant> {
        self.variants.iter().find(|v| v.value == value)
    }

    /// Get the default literal variant (the one with `defaultLiteral="true"`),
    /// or the first variant if no explicit default is set.
    ///
    /// Used by try-construct `UseDefault` to populate a member when the
    /// incoming enum value is not present in the local enumeration.
    pub fn default_variant(&self) -> Option<&EnumVariant> {
        self.variants
            .iter()
            .find(|v| v.default_literal)
            .or_else(|| self.variants.first())
    }
}

/// Enum variant.
#[derive(Debug, Clone, PartialEq)]
pub struct EnumVariant {
    /// Variant name.
    pub name: String,
    /// Variant value.
    pub value: i64,
    /// This variant is the `@default` literal (IDL `defaultLiteral` attribute).
    ///
    /// Used by try-construct `UseDefault` to pick the correct default value
    /// when an incoming enum value is not present in the local enumeration.
    pub default_literal: bool,
}

impl EnumVariant {
    /// Create enum variant.
    pub fn new(name: impl Into<String>, value: i64) -> Self {
        Self {
            name: name.into(),
            value,
            default_literal: false,
        }
    }

    /// Mark this variant as the default literal.
    pub fn with_default_literal(mut self) -> Self {
        self.default_literal = true;
        self
    }
}

/// Union type descriptor.
#[derive(Debug, Clone, PartialEq)]
pub struct UnionDescriptor {
    /// Discriminator type.
    pub discriminator: Arc<TypeDescriptor>,
    /// Union cases.
    pub cases: Vec<UnionCase>,
    /// Default case (if any).
    pub default_case: Option<Box<UnionCase>>,
    /// Declaration index of the default case among ALL cases (labeled and
    /// default) as written in the IDL/XML. The default case is stored apart
    /// from `cases`, which loses its declared slot; this records it so the
    /// TypeObject emission can keep the default member at its declaration
    /// position with its sequential member id (reference vendors assign union
    /// member ids by declaration order, default case included). `None` means
    /// "declared last" (legacy `with_default` builders), which reproduces the
    /// historical append-last emission.
    pub default_case_index: Option<usize>,
    /// Try-construct policy for the discriminator (DDS-XTypes v1.3 sec. 7.5.1.4).
    ///
    /// Applied when the incoming discriminator value is not present in the
    /// local discriminator type (e.g., enum discriminator with an unknown value).
    pub discriminator_try_construct: TryConstructKind,
    /// Whether the discriminator is annotated @key (DDS-XML `key="true"`).
    ///
    /// When true, IS_KEY is set on every member's flags in the emitted
    /// CompleteUnionType so that the IS_KEY check in `is_union_assignable`
    /// correctly rejects pairs where one side has a key discriminator and
    /// the other does not (DDS-XTypes v1.3 sec. 7.3.4.6, sec. 7.5.1.4).
    pub discriminator_is_key: bool,
}

impl UnionDescriptor {
    /// Create union descriptor.
    pub fn new(discriminator: Arc<TypeDescriptor>, cases: Vec<UnionCase>) -> Self {
        Self {
            discriminator,
            cases,
            default_case: None,
            default_case_index: None,
            // Per DDS-XTypes v1.3 sec. 7.2.2.4.1.2 Table 9, absent try-construct
            // bits (TC1=0, TC2=0) encode DISCARD.
            discriminator_try_construct: TryConstructKind::Discard,
            discriminator_is_key: false,
        }
    }

    /// Set default case (declared after all labeled cases).
    pub fn with_default(mut self, case: UnionCase) -> Self {
        self.default_case = Some(Box::new(case));
        self.default_case_index = None;
        self
    }

    /// Set default case with its declaration index among ALL cases (labeled
    /// and default) as written in the IDL/XML. Use this when the default case
    /// is not declared last so the TypeObject emission preserves its declared
    /// slot and sequential member id.
    pub fn with_default_at(mut self, case: UnionCase, declaration_index: usize) -> Self {
        self.default_case = Some(Box::new(case));
        self.default_case_index = Some(declaration_index);
        self
    }

    /// Set discriminator try-construct policy.
    pub fn with_discriminator_try_construct(mut self, policy: TryConstructKind) -> Self {
        self.discriminator_try_construct = policy;
        self
    }

    /// Mark the discriminator as @key.
    pub fn with_discriminator_key(mut self) -> Self {
        self.discriminator_is_key = true;
        self
    }

    /// Get case by discriminator value.
    pub fn case_by_discriminator(&self, value: i64) -> Option<&UnionCase> {
        self.cases
            .iter()
            .find(|c| c.labels.contains(&value))
            .or(self.default_case.as_deref())
    }
}

/// Union case.
#[derive(Debug, Clone, PartialEq)]
pub struct UnionCase {
    /// Case name.
    pub name: String,
    /// Discriminator labels for this case.
    pub labels: Vec<i64>,
    /// Case type.
    pub type_desc: Arc<TypeDescriptor>,
    /// Try-construct policy for this case's member (DDS-XTypes v1.3 sec. 7.5.1.4).
    pub try_construct: TryConstructKind,
    /// Explicit member ID from an `@id(N)` annotation or DDS-XML `id` attribute.
    /// When `None`, the 1-based positional index (declaration position + 1) is
    /// used as the member_id in the TypeObject emission: the discriminator is
    /// the first member of the union and consumes member id 0 (DDS-XTypes v1.3
    /// 7.2.2.4.4.3, sequential assignment per 7.3.1.2.1.1). When `Some(n)`, `n`
    /// overrides the positional index so declaration order does not affect
    /// type identity. Unions do not traverse the CDR EMHEADER encoder
    /// (cdr_dynamic routes unions through an id-free arm), so this id only
    /// affects the TypeObject / EquivalenceHash identity.
    pub member_id: Option<u32>,
}

impl UnionCase {
    /// Create union case without explicit member ID (positional index used).
    pub fn new(name: impl Into<String>, labels: Vec<i64>, type_desc: Arc<TypeDescriptor>) -> Self {
        Self {
            name: name.into(),
            labels,
            type_desc,
            // Per DDS-XTypes v1.3 sec. 7.2.2.4.1.2 Table 9, absent try-construct
            // bits (TC1=0, TC2=0) encode DISCARD.
            try_construct: TryConstructKind::Discard,
            member_id: None,
        }
    }

    /// Set explicit member ID, overriding the positional index.
    pub fn with_member_id(mut self, id: u32) -> Self {
        self.member_id = Some(id);
        self
    }

    /// Create single-label case without explicit member ID.
    pub fn single(name: impl Into<String>, label: i64, type_desc: Arc<TypeDescriptor>) -> Self {
        Self::new(name, vec![label], type_desc)
    }

    /// Set try-construct policy.
    pub fn with_try_construct(mut self, policy: TryConstructKind) -> Self {
        self.try_construct = policy;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_primitive_size() {
        assert_eq!(PrimitiveKind::Bool.size(), Some(1));
        assert_eq!(PrimitiveKind::U32.size(), Some(4));
        assert_eq!(PrimitiveKind::F64.size(), Some(8));
        assert_eq!(PrimitiveKind::String { max_length: None }.size(), None);
    }

    #[test]
    fn test_primitive_alignment() {
        assert_eq!(PrimitiveKind::U8.alignment(), 1);
        assert_eq!(PrimitiveKind::U16.alignment(), 2);
        assert_eq!(PrimitiveKind::U32.alignment(), 4);
        assert_eq!(PrimitiveKind::F64.alignment(), 8);
    }

    #[test]
    fn test_type_descriptor_struct() {
        let u32_type = Arc::new(TypeDescriptor::primitive("uint32", PrimitiveKind::U32));
        let f64_type = Arc::new(TypeDescriptor::primitive("float64", PrimitiveKind::F64));

        let fields = vec![
            FieldDescriptor::new("x", u32_type.clone()),
            FieldDescriptor::new("y", f64_type.clone()),
        ];

        let desc = TypeDescriptor::struct_type("Point", fields);
        assert!(desc.is_struct());
        assert_eq!(desc.fields().map(|f| f.len()), Some(2));
        assert!(desc.field("x").is_some());
        assert!(desc.field("z").is_none());
    }

    #[test]
    fn test_enum_descriptor() {
        let variants = vec![
            EnumVariant::new("RED", 0),
            EnumVariant::new("GREEN", 1),
            EnumVariant::new("BLUE", 2),
        ];
        let enum_desc = EnumDescriptor::new(variants);

        assert_eq!(enum_desc.variant("GREEN").map(|v| v.value), Some(1));
        assert_eq!(
            enum_desc.variant_by_value(2).map(|v| &v.name as &str),
            Some("BLUE")
        );
    }

    #[test]
    fn test_sequence_descriptor() {
        let u8_type = Arc::new(TypeDescriptor::primitive("uint8", PrimitiveKind::U8));

        let unbounded = SequenceDescriptor::unbounded(u8_type.clone());
        assert!(unbounded.max_length.is_none());

        let bounded = SequenceDescriptor::bounded(u8_type, 100);
        assert_eq!(bounded.max_length, Some(100));
    }
}
