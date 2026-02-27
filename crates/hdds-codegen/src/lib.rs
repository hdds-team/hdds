// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

extern crate proc_macro;

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, Data, DeriveInput, Fields, GenericArgument, PathArguments, Type};

/// Field kind for code generation
#[derive(Clone)]
enum FieldKind {
    /// Fixed-size primitive type (u8, i32, f64, etc.)
    Primitive {
        size: usize,
        alignment: usize,
        kind_tokens: proc_macro2::TokenStream,
    },
    /// String type (variable size)
    String,
    /// Vec<u8> type (variable size byte array)
    ByteVec,
}

/// `#[derive(DDS)]` macro: generates `TypeDescriptor` + encode/decode impl
///
/// Supports:
/// - Primitive types: i8, i16, i32, i64, u8, u16, u32, u64, f32, f64, bool
/// - String type: variable-length UTF-8 string
/// - Vec<u8>: variable-length byte array
///
/// # Panics
///
/// Panics if struct contains unsupported field types or unnamed fields
///
/// Example:
/// ```ignore
/// use hdds_codegen::DDS;
///
/// #[derive(DDS)]
/// struct ImageMeta {
///     image_id: u32,
///     width: u16,
///     height: u16,
///     format: String,      // Variable-length string
///     data: Vec<u8>,       // Variable-length byte array
/// }
/// ```
#[proc_macro_derive(DDS, attributes(dds))]
#[allow(clippy::too_many_lines)]
pub fn derive_dds(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    let name = &input.ident;
    let type_name = name.to_string();
    let type_id = compute_fnv1a_hash(&type_name);

    // Parse struct fields
    let fields = match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(f) => &f.named,
            _ => {
                return syn::Error::new_spanned(&input, "Only named fields are supported")
                    .to_compile_error()
                    .into()
            }
        },
        _ => {
            return syn::Error::new_spanned(&input, "Only structs are supported")
                .to_compile_error()
                .into()
        }
    };

    // Generate field info with proper CDR2 alignment
    struct FieldInfo {
        name: syn::Ident,
        ty: syn::Type,
        kind: FieldKind,
        offset: usize, // Only valid for fixed-size fields
    }

    let mut field_infos = Vec::new();
    let mut current_offset = 0usize;
    let mut max_alignment = 1usize;
    let mut has_variable_size = false;

    for field in fields {
        let Some(field_name) = field.ident.as_ref() else {
            return syn::Error::new_spanned(field, "Field must have a name")
                .to_compile_error()
                .into();
        };
        let field_type = &field.ty;

        let Some(kind) = get_field_kind(field_type) else {
            return syn::Error::new_spanned(
                field_type,
                format!("Unsupported type: {field_type:?}. Supported types: primitives, String, Vec<u8>."),
            )
            .to_compile_error()
            .into();
        };

        let (size, alignment) = match &kind {
            FieldKind::Primitive {
                size, alignment, ..
            } => (*size, *alignment),
            FieldKind::String | FieldKind::ByteVec => {
                has_variable_size = true;
                (0, 4) // Length prefix is u32, aligned to 4
            }
        };

        // Align offset to field alignment (CDR2 requirement)
        current_offset = align_to(current_offset, alignment);
        max_alignment = max_alignment.max(alignment);

        field_infos.push(FieldInfo {
            name: field_name.clone(),
            ty: field_type.clone(),
            kind,
            offset: current_offset,
        });

        if !has_variable_size {
            current_offset += size;
        }
    }

    let total_size = if has_variable_size {
        0xFFFF_FFFF_u32 // Variable size marker
    } else {
        align_to(current_offset, max_alignment) as u32
    };

    // Generate TypeDescriptor fields array
    let field_layouts: Vec<_> = field_infos
        .iter()
        .map(|f| {
            let name_str = f.name.to_string();
            let offset = f.offset as u32;

            match &f.kind {
                FieldKind::Primitive {
                    size,
                    alignment,
                    kind_tokens,
                } => {
                    let size = *size as u32;
                    let alignment = *alignment as u8;
                    quote! {
                        ::hdds::core::types::FieldLayout {
                            name: #name_str,
                            offset_bytes: #offset,
                            field_type: ::hdds::core::types::FieldType::Primitive(#kind_tokens),
                            alignment: #alignment,
                            size_bytes: #size,
                            element_type: None,
                        }
                    }
                }
                FieldKind::String => {
                    quote! {
                        ::hdds::core::types::FieldLayout {
                            name: #name_str,
                            offset_bytes: #offset,
                            field_type: ::hdds::core::types::FieldType::String,
                            alignment: 4,
                            size_bytes: 0xFFFF_FFFF, // Variable
                            element_type: None,
                        }
                    }
                }
                FieldKind::ByteVec => {
                    quote! {
                        ::hdds::core::types::FieldLayout {
                            name: #name_str,
                            offset_bytes: #offset,
                            field_type: ::hdds::core::types::FieldType::Sequence,
                            alignment: 4,
                            size_bytes: 0xFFFF_FFFF, // Variable
                            element_type: None,
                        }
                    }
                }
            }
        })
        .collect();

    // Generate encode_cdr2 implementation
    let encode_fields: Vec<_> = field_infos
        .iter()
        .map(|f| {
            let field_name = &f.name;

            match &f.kind {
                FieldKind::Primitive { alignment, .. } => {
                    quote! {
                        // Align cursor to field alignment
                        while cursor.offset() % #alignment != 0 {
                            cursor.write_u8(0)?;
                        }
                        // Write field value as little-endian
                        cursor.write_bytes(&self.#field_name.to_le_bytes())?;
                    }
                }
                FieldKind::String => {
                    quote! {
                        // Align to 4 bytes for length prefix
                        while cursor.offset() % 4 != 0 {
                            cursor.write_u8(0)?;
                        }
                        // Write string: length (u32) + bytes + null terminator
                        let str_bytes = self.#field_name.as_bytes();
                        let str_len = (str_bytes.len() + 1) as u32; // Include null terminator
                        cursor.write_bytes(&str_len.to_le_bytes())?;
                        cursor.write_bytes(str_bytes)?;
                        cursor.write_u8(0)?; // Null terminator
                    }
                }
                FieldKind::ByteVec => {
                    quote! {
                        // Align to 4 bytes for length prefix
                        while cursor.offset() % 4 != 0 {
                            cursor.write_u8(0)?;
                        }
                        // Write Vec<u8>: length (u32) + bytes
                        let vec_len = self.#field_name.len() as u32;
                        cursor.write_bytes(&vec_len.to_le_bytes())?;
                        cursor.write_bytes(&self.#field_name)?;
                    }
                }
            }
        })
        .collect();

    // Generate decode_cdr2 implementation
    let decode_fields: Vec<_> = field_infos
        .iter()
        .map(|f| {
            let field_name = &f.name;
            let field_type = &f.ty;

            match &f.kind {
                FieldKind::Primitive { size, alignment, .. } => {
                    quote! {
                        // Align cursor to field alignment
                        while cursor.offset() % #alignment != 0 {
                            let _ = cursor.read_u8()?;
                        }
                        // Read field value as little-endian
                        let #field_name = {
                            let bytes_slice = cursor.read_bytes(#size)?;
                            let mut bytes = [0u8; #size];
                            bytes.copy_from_slice(bytes_slice);
                            <#field_type>::from_le_bytes(bytes)
                        };
                    }
                }
                FieldKind::String => {
                    quote! {
                        // Align to 4 bytes for length prefix
                        while cursor.offset() % 4 != 0 {
                            let _ = cursor.read_u8()?;
                        }
                        // Read string: length (u32) + bytes + null terminator
                        let #field_name = {
                            let len_bytes = cursor.read_bytes(4)?;
                            let str_len = u32::from_le_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]]) as usize;
                            if str_len == 0 {
                                String::new()
                            } else {
                                let str_bytes = cursor.read_bytes(str_len - 1)?; // Exclude null terminator
                                let _ = cursor.read_u8()?; // Skip null terminator
                                String::from_utf8(str_bytes.to_vec())
                                    .map_err(|_| ::hdds::dds::Error::SerializationError)?
                            }
                        };
                    }
                }
                FieldKind::ByteVec => {
                    quote! {
                        // Align to 4 bytes for length prefix
                        while cursor.offset() % 4 != 0 {
                            let _ = cursor.read_u8()?;
                        }
                        // Read Vec<u8>: length (u32) + bytes
                        let #field_name = {
                            let len_bytes = cursor.read_bytes(4)?;
                            let vec_len = u32::from_le_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]]) as usize;
                            let data = cursor.read_bytes(vec_len)?;
                            data.to_vec()
                        };
                    }
                }
            }
        })
        .collect();

    let field_names: Vec<_> = field_infos.iter().map(|f| &f.name).collect();

    // Generate CompleteStructMembers for TypeObject (Phase 8b)
    let type_object_members: Vec<_> = field_infos
        .iter()
        .enumerate()
        .map(|(idx, f)| {
            let Ok(member_id) = u32::try_from(idx) else {
                return syn::Error::new_spanned(
                    &f.name,
                    format!("Struct has too many fields (index {idx} exceeds u32::MAX)"),
                )
                .to_compile_error();
            };
            let name_str = f.name.to_string();
            let type_id_const = get_type_identifier_for_kind(&f.kind);

            quote! {
                ::hdds::xtypes::CompleteStructMember {
                    common: ::hdds::xtypes::CommonStructMember {
                        member_id: #member_id,
                        member_flags: ::hdds::xtypes::MemberFlag::empty(),
                        member_type_id: #type_id_const,
                    },
                    detail: ::hdds::xtypes::CompleteMemberDetail::new(#name_str),
                }
            }
        })
        .collect();

    let max_alignment_u8 = max_alignment as u8;

    let expanded = quote! {
        impl ::hdds::api::DDS for #name {
            fn type_descriptor() -> &'static ::hdds::core::types::TypeDescriptor {
                static DESCRIPTOR: ::hdds::core::types::TypeDescriptor = ::hdds::core::types::TypeDescriptor {
                    type_id: #type_id,
                    type_name: #type_name,
                    size_bytes: #total_size,
                    alignment: #max_alignment_u8,
                    is_variable_size: #has_variable_size,
                    fields: &[#(#field_layouts),*],
                };
                &DESCRIPTOR
            }

            fn encode_cdr2(&self, buf: &mut [u8]) -> ::hdds::api::Result<usize> {
                use ::hdds::core::ser::cursor::CursorMut;

                let mut cursor = CursorMut::new(buf);

                // Encode each field with proper alignment
                #(#encode_fields)*

                Ok(cursor.offset())
            }

            fn decode_cdr2(buf: &[u8]) -> ::hdds::api::Result<Self> {
                use ::hdds::core::ser::cursor::Cursor;

                let mut cursor = Cursor::new(buf);

                // Decode each field with proper alignment
                #(#decode_fields)*

                Ok(Self {
                    #(#field_names),*
                })
            }

            /// Get XTypes v1.3 TypeObject for this type
            ///
            /// Auto-generated by #[derive(DDS)] proc-macro (Phase 8b).
            /// Returns CompleteTypeObject::Struct with all field metadata.
            ///
            /// # XTypes v1.3 Integration
            ///
            /// This enables:
            /// - Runtime type discovery via SEDP announcements
            /// - Structural type equivalence checking (EquivalenceHash)
            /// - Multi-vendor interoperability (FastDDS, RTI, etc.)
            ///
            /// # Generated Structure
            ///
            /// - Extensibility: IS_FINAL (MVP, future: @appendable/@mutable)
            /// - Members: Sequential member_id assignment (0, 1, 2, ...)
            /// - Member flags: Empty (future: @key, @optional, @must_understand)
            /// - Type IDs: Primitive TypeIdentifier constants (TK_INT32, TK_FLOAT32, etc.)
            fn get_type_object() -> Option<::hdds::xtypes::CompleteTypeObject> {
                Some(::hdds::xtypes::CompleteTypeObject::Struct(
                    ::hdds::xtypes::CompleteStructType {
                        struct_flags: ::hdds::xtypes::StructTypeFlag::IS_FINAL,
                        header: ::hdds::xtypes::CompleteStructHeader {
                            base_type: None, // No inheritance (Phase 8b MVP)
                            detail: ::hdds::xtypes::CompleteTypeDetail::new(#type_name),
                        },
                        member_seq: vec![
                            #(#type_object_members),*
                        ],
                    }
                ))
            }
        }
    };

    TokenStream::from(expanded)
}

/// Get field kind for a Rust type
///
/// Supports:
/// - Primitive types: i8, i16, i32, i64, u8, u16, u32, u64, f32, f64, bool
/// - String: variable-length UTF-8 string
/// - Vec<u8>: variable-length byte array
fn get_field_kind(ty: &syn::Type) -> Option<FieldKind> {
    if let Type::Path(type_path) = ty {
        let segment = type_path.path.segments.last()?;
        let ident_str = segment.ident.to_string();

        // Check for primitive types
        match ident_str.as_str() {
            "i8" => {
                return Some(FieldKind::Primitive {
                    size: 1,
                    alignment: 1,
                    kind_tokens: quote! { ::hdds::core::types::PrimitiveKind::I8 },
                })
            }
            "i16" => {
                return Some(FieldKind::Primitive {
                    size: 2,
                    alignment: 2,
                    kind_tokens: quote! { ::hdds::core::types::PrimitiveKind::I16 },
                })
            }
            "i32" => {
                return Some(FieldKind::Primitive {
                    size: 4,
                    alignment: 4,
                    kind_tokens: quote! { ::hdds::core::types::PrimitiveKind::I32 },
                })
            }
            "i64" => {
                return Some(FieldKind::Primitive {
                    size: 8,
                    alignment: 8,
                    kind_tokens: quote! { ::hdds::core::types::PrimitiveKind::I64 },
                })
            }
            "u8" => {
                return Some(FieldKind::Primitive {
                    size: 1,
                    alignment: 1,
                    kind_tokens: quote! { ::hdds::core::types::PrimitiveKind::U8 },
                })
            }
            "u16" => {
                return Some(FieldKind::Primitive {
                    size: 2,
                    alignment: 2,
                    kind_tokens: quote! { ::hdds::core::types::PrimitiveKind::U16 },
                })
            }
            "u32" => {
                return Some(FieldKind::Primitive {
                    size: 4,
                    alignment: 4,
                    kind_tokens: quote! { ::hdds::core::types::PrimitiveKind::U32 },
                })
            }
            "u64" => {
                return Some(FieldKind::Primitive {
                    size: 8,
                    alignment: 8,
                    kind_tokens: quote! { ::hdds::core::types::PrimitiveKind::U64 },
                })
            }
            "f32" => {
                return Some(FieldKind::Primitive {
                    size: 4,
                    alignment: 4,
                    kind_tokens: quote! { ::hdds::core::types::PrimitiveKind::F32 },
                })
            }
            "f64" => {
                return Some(FieldKind::Primitive {
                    size: 8,
                    alignment: 8,
                    kind_tokens: quote! { ::hdds::core::types::PrimitiveKind::F64 },
                })
            }
            "bool" | "boolean" => {
                return Some(FieldKind::Primitive {
                    size: 1,
                    alignment: 1,
                    kind_tokens: quote! { ::hdds::core::types::PrimitiveKind::Bool },
                })
            }
            "String" => return Some(FieldKind::String),
            "Vec" => {
                // Check if it's Vec<u8>
                if let PathArguments::AngleBracketed(args) = &segment.arguments {
                    if let Some(GenericArgument::Type(Type::Path(inner_path))) = args.args.first() {
                        if let Some(inner_segment) = inner_path.path.segments.last() {
                            if inner_segment.ident == "u8" {
                                return Some(FieldKind::ByteVec);
                            }
                        }
                    }
                }
                return None; // Vec<T> where T != u8 is not supported
            }
            _ => return None,
        }
    }
    None
}

/// Align offset to the specified alignment (round up to next multiple)
#[allow(clippy::integer_division_remainder_used, clippy::integer_division)]
const fn align_to(offset: usize, alignment: usize) -> usize {
    // div_ceil is not const stable yet (1.73+), manual implementation for older MSRV
    #[allow(clippy::arithmetic_side_effects)] // Alignment is always > 0
    #[allow(clippy::manual_div_ceil)] // div_ceil not const stable yet
    {
        (offset + alignment - 1) / alignment * alignment
    }
}

/// Compute FNV-1a hash (32-bit) for type ID
fn compute_fnv1a_hash(s: &str) -> u32 {
    let mut hash = 2_166_136_261_u32;
    for byte in s.bytes() {
        hash ^= u32::from(byte);
        hash = hash.wrapping_mul(16_777_619);
    }
    hash
}

/// Map `FieldKind` to `TypeIdentifier` constant for XTypes (Phase 8b)
///
/// # Mapping
/// - Primitives: I8 -> TK_INT8, etc.
/// - String -> TK_STRING8
/// - ByteVec -> TK_SEQUENCE (of u8)
fn get_type_identifier_for_kind(kind: &FieldKind) -> proc_macro2::TokenStream {
    match kind {
        FieldKind::Primitive { kind_tokens, .. } => {
            let prim_str = kind_tokens.to_string();
            let variant = prim_str.split("::").last().unwrap_or("").trim();

            match variant {
                "I8" => quote! { ::hdds::xtypes::TypeIdentifier::TK_INT8 },
                "I16" => quote! { ::hdds::xtypes::TypeIdentifier::TK_INT16 },
                "I32" => quote! { ::hdds::xtypes::TypeIdentifier::TK_INT32 },
                "I64" => quote! { ::hdds::xtypes::TypeIdentifier::TK_INT64 },
                "U8" => quote! { ::hdds::xtypes::TypeIdentifier::TK_UINT8 },
                "U16" => quote! { ::hdds::xtypes::TypeIdentifier::TK_UINT16 },
                "U32" => quote! { ::hdds::xtypes::TypeIdentifier::TK_UINT32 },
                "U64" => quote! { ::hdds::xtypes::TypeIdentifier::TK_UINT64 },
                "F32" => quote! { ::hdds::xtypes::TypeIdentifier::TK_FLOAT32 },
                "F64" => quote! { ::hdds::xtypes::TypeIdentifier::TK_FLOAT64 },
                "Bool" => quote! { ::hdds::xtypes::TypeIdentifier::TK_BOOLEAN },
                _ => quote! {
                    compile_error!(concat!("Internal error: unsupported primitive kind: ", #variant))
                },
            }
        }
        FieldKind::String => {
            quote! { ::hdds::xtypes::TypeIdentifier::TK_STRING8 }
        }
        FieldKind::ByteVec => {
            // Sequence of u8 - use primitive TK_SEQUENCE marker
            // Note: Full XTypes would encode element type in a PlainSequence/Sequence variant
            quote! { ::hdds::xtypes::TypeIdentifier::Primitive(::hdds::xtypes::TypeKind::TK_SEQUENCE) }
        }
    }
}
