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
    /// `bool`: 1 byte on the wire (0x00 = false, 0x01 = true). Not a
    /// `to_le_bytes`/`from_le_bytes` type like the other primitives, so it
    /// gets its own encode/decode arms instead of sharing `Primitive`'s.
    Bool,
    /// String type (variable size)
    String,
    /// Vec<u8> type (variable size byte array)
    ByteVec,
}

/// `#[derive(DDS)]` macro: generates `TypeDescriptor`, encode/decode, and
/// `get_fields` (content-filter field extraction) impls.
///
/// Supports:
/// - Primitive types: i8, i16, i32, i64, u8, u16, u32, u64, f32, f64, bool
/// - String type: variable-length UTF-8 string
/// - Vec<u8>: variable-length byte array
///
/// The type is `@appendable`, the extensibility DDS-XTypes 1.3 7.3.1.2.1.8
/// gives a type that does not indicate one: its sample is DELIMITED_CDR
/// under XCDR2 (a DHEADER, the byte count of the members that follow) and
/// PLAIN_CDR under XCDR1 (7.4.3.1, Table 35: APPENDABLE is PLAIN_CDR at
/// encoding version 1, DELIMITED_CDR at version 2), little endian, members
/// in declaration order. An 8-byte member (`i64`, `u64`, `f64`) is aligned at
/// 4 under XCDR2 and at 8 under XCDR1 (7.4.3.2.2, `MAXALIGN(VERSION2) = 4`,
/// `MAXALIGN(VERSION1) = 8`). A reader skips what follows its last member
/// inside the DHEADER, so a writer may append members.
///
/// `#[dds(final)]` on the struct makes it `@final` instead: PLAIN_CDR2 under
/// XCDR2 (no DHEADER), PLAIN_CDR under XCDR1, `IS_FINAL` in its TypeObject.
/// `#[dds(appendable)]` states the default. `#[dds(mutable)]` and any other
/// `#[dds(...)]` content are compile errors.
///
/// A field marked `#[key]` is a key member: the type then reports
/// `has_key() == true`, flags the member `IS_KEY` in its TypeObject, and
/// implements the KeyHash hook (`write_key_holder`), so that
/// `compute_key` returns the KeyHash RTPS 2.5 9.6.4.8 specifies, and
/// `encode_key`, the key-only payload of its disposes and unregisters, in
/// the encapsulation of its data (PLAIN_CDR2 or PLAIN_CDR, no DHEADER). Member ids
/// are the declaration order, so the key members are written in that order.
/// A `String` or `Vec<u8>` key is unbounded, which makes the KeyHash the MD5
/// of the serialized key.
///
/// `get_fields()` returns one entry per primitive or `String` field, keyed
/// by the Rust field name as a string. `Vec<u8>` fields are NOT included:
/// a byte array is not a filterable scalar, so it is simply absent from the
/// map (a `ContentFilteredTopic` expression naming it will fail to match,
/// same as naming any unknown field).
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
///     #[key]
///     image_id: u32,
///     width: u16,
///     height: u16,
///     format: String,      // Variable-length string
///     data: Vec<u8>,       // Variable-length byte array
/// }
/// ```
#[proc_macro_derive(DDS, attributes(dds, key))]
#[allow(clippy::too_many_lines)]
pub fn derive_dds(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    let name = &input.ident;
    let type_name = name.to_string();
    let type_id = compute_fnv1a_hash(&type_name);

    // `#[dds(final)]` / `#[dds(appendable)]` on the struct: its
    // extensibility. Without one the type is @appendable, the default of a
    // type that does not indicate one (DDS-XTypes 1.3 7.3.1.2.1.8).
    let is_final = match struct_extensibility(&input.attrs) {
        Ok(f) => f,
        Err(e) => return e.to_compile_error().into(),
    };

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

    // Field info. The offsets and the size of the `TypeDescriptor` use the
    // NATURAL alignment (8 for an 8-byte member), the layout of XCDR1 and an
    // upper bound of the XCDR2 one; the wire alignment, which depends on the
    // version, is applied by the generated `encode`/`decode`.
    struct FieldInfo {
        name: syn::Ident,
        ty: syn::Type,
        kind: FieldKind,
        offset: usize, // Only valid for fixed-size fields
        is_key: bool,
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

        let mut is_key = false;
        for attr in &field.attrs {
            if attr.path().is_ident("dds") {
                return syn::Error::new_spanned(
                    attr,
                    "#[dds(...)] applies to the struct, not to a field",
                )
                .to_compile_error()
                .into();
            }
            if attr.path().is_ident("key") {
                if !matches!(attr.meta, syn::Meta::Path(_)) {
                    return syn::Error::new_spanned(attr, "#[key] takes no arguments")
                        .to_compile_error()
                        .into();
                }
                is_key = true;
            }
        }

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
            FieldKind::Bool => (1, 1),
            FieldKind::String | FieldKind::ByteVec => {
                has_variable_size = true;
                (0, 4) // Length prefix is u32, aligned to 4
            }
        };

        // Align offset to the natural field alignment
        current_offset = align_to(current_offset, alignment);
        max_alignment = max_alignment.max(alignment);

        field_infos.push(FieldInfo {
            name: field_name.clone(),
            ty: field_type.clone(),
            kind,
            offset: current_offset,
            is_key,
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
                FieldKind::Bool => {
                    quote! {
                        ::hdds::core::types::FieldLayout {
                            name: #name_str,
                            offset_bytes: #offset,
                            field_type: ::hdds::core::types::FieldType::Primitive(::hdds::core::types::PrimitiveKind::Bool),
                            alignment: 1,
                            size_bytes: 1,
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
                    // Alignment 1 needs no padding loop: `offset % 1` is always
                    // 0, and clippy's `modulo_one` (deny by default) refuses
                    // code that computes it. An 8-byte member is aligned to
                    // `max_align`, which depends on the version (see
                    // `primitive_align_expr`).
                    let align_guard = if *alignment > 1 {
                        let align = primitive_align_expr(*alignment);
                        quote! {
                            // Align cursor to field alignment
                            while cursor.offset() % #align != 0 {
                                cursor.write_u8(0)?;
                            }
                        }
                    } else {
                        quote! {}
                    };
                    quote! {
                        #align_guard
                        // Write field value as little-endian
                        cursor.write_bytes(&self.#field_name.to_le_bytes())?;
                    }
                }
                FieldKind::Bool => {
                    quote! {
                        // bool: 1 byte, alignment 1 (no padding loop needed).
                        // 0x00 = false, 0x01 = true, the same convention as the
                        // crate's own `Cdr2Encode for bool` in core/ser/traits.rs.
                        cursor.write_u8(u8::from(self.#field_name))?;
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
                    // See the matching encode arm: alignment 1 needs no
                    // padding loop, and clippy's `modulo_one` refuses one.
                    let align_guard = if *alignment > 1 {
                        let align = primitive_align_expr(*alignment);
                        quote! {
                            // Align cursor to field alignment
                            while cursor.offset() % #align != 0 {
                                let _ = cursor.read_u8()?;
                            }
                        }
                    } else {
                        quote! {}
                    };
                    quote! {
                        #align_guard
                        // Read field value as little-endian
                        let #field_name = {
                            let bytes_slice = cursor.read_bytes(#size)?;
                            let mut bytes = [0u8; #size];
                            bytes.copy_from_slice(bytes_slice);
                            <#field_type>::from_le_bytes(bytes)
                        };
                    }
                }
                FieldKind::Bool => {
                    quote! {
                        // bool: 1 byte, alignment 1 (no padding loop needed).
                        // 0x00 = false, 0x01 = true; any other byte is a
                        // decode error rather than silently becoming true.
                        let #field_name = match cursor.read_u8()? {
                            0 => false,
                            1 => true,
                            _ => return Err(::hdds::dds::Error::SerializationError),
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

    // Generate get_fields() implementation (content-filter field extraction).
    // Vec<u8> fields are intentionally skipped: a byte array is not a
    // filterable scalar (see the FieldValue variants in
    // hdds/src/dds/filter/evaluator.rs), so `filter_map` drops them rather
    // than inserting a placeholder.
    let get_fields_inserts: Vec<_> = field_infos
        .iter()
        .filter_map(|f| {
            let field_name = &f.name;
            let name_str = f.name.to_string();

            match &f.kind {
                FieldKind::Primitive { kind_tokens, .. } => {
                    let prim_str = kind_tokens.to_string();
                    let variant = prim_str.split("::").last().unwrap_or("").trim();
                    let value_expr = match variant {
                        "I8" | "I16" | "I32" | "I64" => quote! {
                            ::hdds::dds::filter::FieldValue::from_i64(i64::from(self.#field_name))
                        },
                        "U8" | "U16" | "U32" | "U64" => quote! {
                            ::hdds::dds::filter::FieldValue::from_u64(u64::from(self.#field_name))
                        },
                        "F32" => quote! {
                            ::hdds::dds::filter::FieldValue::from_f32(self.#field_name)
                        },
                        "F64" => quote! {
                            ::hdds::dds::filter::FieldValue::from_f64(self.#field_name)
                        },
                        _ => quote! {
                            compile_error!(concat!(
                                "Internal error: unsupported primitive kind for get_fields: ",
                                #variant
                            ))
                        },
                    };
                    Some(quote! {
                        fields.insert(#name_str.to_string(), #value_expr);
                    })
                }
                FieldKind::Bool => Some(quote! {
                    fields.insert(
                        #name_str.to_string(),
                        ::hdds::dds::filter::FieldValue::from_bool(self.#field_name),
                    );
                }),
                FieldKind::String => Some(quote! {
                    fields.insert(
                        #name_str.to_string(),
                        ::hdds::dds::filter::FieldValue::from_string(self.#field_name.clone()),
                    );
                }),
                FieldKind::ByteVec => None,
            }
        })
        .collect();

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
            // Every member carries TRY_CONSTRUCT1, the DISCARD try-construct
            // behavior: the default when no @try_construct is given (DDS-XTypes
            // 1.3 7.2.2.7), and the only legal encoding of it in the
            // MemberFlag bitmask (Annex B: T2 T1 = 00 is INVALID, 01 is
            // DISCARD). A key member is also must-understand (7.2.2.4.4.4.8).
            let member_flags = if f.is_key {
                quote! {
                    ::hdds::xtypes::MemberFlag(
                        ::hdds::xtypes::MemberFlag::IS_KEY.0
                            | ::hdds::xtypes::MemberFlag::IS_MUST_UNDERSTAND.0
                            | ::hdds::xtypes::MemberFlag::TRY_CONSTRUCT1.0,
                    )
                }
            } else {
                quote! { ::hdds::xtypes::MemberFlag::TRY_CONSTRUCT1 }
            };

            quote! {
                ::hdds::xtypes::CompleteStructMember {
                    common: ::hdds::xtypes::CommonStructMember {
                        member_id: #member_id,
                        member_flags: #member_flags,
                        member_type_id: #type_id_const,
                    },
                    detail: ::hdds::xtypes::CompleteMemberDetail::new(#name_str),
                }
            }
        })
        .collect();

    let max_alignment_u8 = max_alignment as u8;

    // XCDR2 body framing: DELIMITED_CDR (a DHEADER) for @appendable,
    // PLAIN_CDR2 for @final; XCDR1 is PLAIN_CDR for both (DDS-XTypes 1.3
    // 7.4.3.1, Table 35).
    let delimited = if is_final {
        quote! { false }
    } else {
        quote! { matches!(version, ::hdds::CdrVersion::Xcdr2) }
    };
    let struct_flag = if is_final {
        quote! { ::hdds::xtypes::StructTypeFlag::IS_FINAL }
    } else {
        quote! { ::hdds::xtypes::StructTypeFlag::IS_APPENDABLE }
    };

    let key_methods = key_hash_methods(
        &delimited,
        &field_infos
            .iter()
            .filter(|f| f.is_key)
            .map(|f| (&f.name, &f.kind))
            .collect::<Vec<_>>(),
    );

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

            #key_methods

            /// `encode` and `decode` align every 8-byte member by the
            /// requested version, so XCDR1 is native.
            fn encodes_xcdr1_natively() -> bool {
                true
            }

            /// The type is @appendable, so its body is DELIMITED_CDR under
            /// XCDR2 (a DHEADER, then the members) and PLAIN_CDR under XCDR1,
            /// little endian (DDS-XTypes 1.3 7.4.3.1, Table 35). MAXALIGN is 4 under
            /// XCDR2 and 8 under XCDR1 (7.4.3.2.2, Table 37). The DHEADER is
            /// 4 bytes at offset 0, so under XCDR2 (MAXALIGN 4) a member's
            /// alignment is the same counted from the buffer or the body.
            fn encode(&self, buf: &mut [u8], version: ::hdds::CdrVersion) -> ::hdds::api::Result<usize> {
                use ::hdds::core::ser::cursor::CursorMut;

                let max_align: usize = match version {
                    ::hdds::CdrVersion::Xcdr1 => 8,
                    ::hdds::CdrVersion::Xcdr2 => 4,
                };
                let _ = max_align;
                let delimited = #delimited;
                let mut cursor = CursorMut::new(buf);
                if delimited {
                    // DHEADER placeholder, filled once the body is written.
                    cursor.write_bytes(&[0u8; 4])?;
                }

                // Encode each field with proper alignment
                #(#encode_fields)*

                let end = cursor.offset();
                if delimited {
                    let body = u32::try_from(end - 4)
                        .map_err(|_| ::hdds::dds::Error::SerializationError)?;
                    buf[..4].copy_from_slice(&body.to_le_bytes());
                }
                Ok(end)
            }

            /// Reads the layout `encode` writes at the same `version`. Under
            /// XCDR2 the members are read inside the DHEADER's bound, and
            /// whatever follows the last one there (members a newer writer
            /// appended) is skipped.
            fn decode(buf: &[u8], version: ::hdds::CdrVersion) -> ::hdds::api::Result<Self> {
                use ::hdds::core::ser::cursor::Cursor;

                let max_align: usize = match version {
                    ::hdds::CdrVersion::Xcdr1 => 8,
                    ::hdds::CdrVersion::Xcdr2 => 4,
                };
                let _ = max_align;
                let delimited = #delimited;
                let buf: &[u8] = if delimited {
                    let Some(dheader) = buf.get(..4) else {
                        return Err(::hdds::dds::Error::SerializationError);
                    };
                    let body = u32::from_le_bytes([dheader[0], dheader[1], dheader[2], dheader[3]]);
                    let end = usize::try_from(body)
                        .ok()
                        .and_then(|n| n.checked_add(4))
                        .filter(|end| *end <= buf.len())
                        .ok_or(::hdds::dds::Error::SerializationError)?;
                    &buf[..end]
                } else {
                    buf
                };
                let mut cursor = Cursor::new(buf);
                if delimited {
                    let _ = cursor.read_bytes(4)?;
                }

                // Decode each field with proper alignment
                #(#decode_fields)*

                Ok(Self {
                    #(#field_names),*
                })
            }

            /// Extract field values for content filtering.
            ///
            /// Auto-generated by #[derive(DDS)] proc-macro: one entry per
            /// primitive or `String` field, keyed by the Rust field name.
            /// `Vec<u8>` fields are not filterable scalars and are absent
            /// from the map.
            fn get_fields(&self) -> ::std::collections::HashMap<String, ::hdds::dds::filter::FieldValue> {
                let mut fields = ::std::collections::HashMap::new();
                #(#get_fields_inserts)*
                fields
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
            /// - Extensibility: IS_APPENDABLE (DDS-XTypes 1.3 7.3.1.2.1.8), or
            ///   IS_FINAL under `#[dds(final)]`
            /// - Members: Sequential member_id assignment (0, 1, 2, ...)
            /// - Member flags: Empty (future: @key, @optional, @must_understand)
            /// - Type IDs: Primitive TypeIdentifier constants (TK_INT32, TK_FLOAT32, etc.)
            fn get_type_object() -> Option<::hdds::xtypes::CompleteTypeObject> {
                Some(::hdds::xtypes::CompleteTypeObject::Struct(
                    ::hdds::xtypes::CompleteStructType {
                        struct_flags: #struct_flag,
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

/// The extensibility a `#[dds(...)]` attribute on the struct names: `true`
/// for `#[dds(final)]`, `false` for `#[dds(appendable)]` or no attribute.
/// `#[dds(mutable)]` is refused (the derive has no PL_CDR encoder), and so
/// is anything else, so an attribute never compiles to nothing.
fn struct_extensibility(attrs: &[syn::Attribute]) -> Result<bool, syn::Error> {
    let mut chosen: Option<bool> = None;
    for attr in attrs.iter().filter(|a| a.path().is_ident("dds")) {
        attr.parse_nested_meta(|meta| {
            let kind = if meta.path.is_ident("final") {
                true
            } else if meta.path.is_ident("appendable") {
                false
            } else if meta.path.is_ident("mutable") {
                return Err(meta.error(
                    "#[dds(mutable)] is not supported by #[derive(DDS)]: write a DDS impl",
                ));
            } else {
                return Err(meta.error("expected #[dds(final)] or #[dds(appendable)]"));
            };
            if chosen.replace(kind).is_some() {
                return Err(meta.error("the extensibility is given more than once"));
            }
            Ok(())
        })?;
    }
    Ok(chosen.unwrap_or(false))
}

/// The KeyHash hooks of a type whose key members are `keys`, in member-id
/// (declaration) order; nothing when it has none, so the trait defaults
/// (`has_key() == false`, all-zero KeyHash) apply.
fn key_hash_methods(
    delimited: &proc_macro2::TokenStream,
    keys: &[(&syn::Ident, &FieldKind)],
) -> proc_macro2::TokenStream {
    if keys.is_empty() {
        return quote! {};
    }
    let writes: Vec<_> = keys
        .iter()
        .map(|(name, kind)| match kind {
            FieldKind::Primitive { kind_tokens, .. } => {
                let prim_str = kind_tokens.to_string();
                let variant = prim_str.split("::").last().unwrap_or("").trim();
                let method = syn::Ident::new(
                    &format!("write_{}", variant.to_lowercase()),
                    proc_macro2::Span::call_site(),
                );
                quote! { w.#method(self.#name); }
            }
            FieldKind::Bool => quote! { w.write_bool(self.#name); },
            FieldKind::String => quote! { w.write_string(&self.#name); },
            FieldKind::ByteVec => quote! {
                w.write_u32(u32::try_from(self.#name.len()).unwrap_or(u32::MAX));
                w.write_octets(&self.#name);
            },
        })
        .collect();
    let payload_writes: Vec<_> = keys
        .iter()
        .map(|(name, kind)| {
            let align4 = quote! {
                while body.len() % 4 != 0 {
                    body.push(0);
                }
            };
            match kind {
                FieldKind::Primitive { size, .. } => {
                    // Aligned to its size, capped at `max_align` (8 in
                    // XCDR1, 4 in XCDR2). Size 1 needs no padding loop
                    // (clippy modulo_one).
                    let pad = if *size > 1 {
                        quote! {
                            let align = #size.min(max_align);
                            while body.len() % align != 0 {
                                body.push(0);
                            }
                        }
                    } else {
                        quote! {}
                    };
                    quote! {
                        #pad
                        body.extend_from_slice(&self.#name.to_le_bytes());
                    }
                }
                FieldKind::Bool => quote! { body.push(u8::from(self.#name)); },
                FieldKind::String => quote! {
                    #align4
                    let s = self.#name.as_bytes();
                    body.extend_from_slice(
                        &u32::try_from(s.len().saturating_add(1))
                            .unwrap_or(u32::MAX)
                            .to_le_bytes(),
                    );
                    body.extend_from_slice(s);
                    body.push(0);
                },
                FieldKind::ByteVec => quote! {
                    #align4
                    body.extend_from_slice(
                        &u32::try_from(self.#name.len()).unwrap_or(u32::MAX).to_le_bytes(),
                    );
                    body.extend_from_slice(&self.#name);
                },
            }
        })
        .collect();
    // The inverse of `encode_key`: each key member read back, then hashed as
    // `write_key_holder` hashes it.
    let vars: Vec<syn::Ident> = (0..keys.len())
        .map(|i| syn::Ident::new(&format!("__k{i}"), proc_macro2::Span::call_site()))
        .collect();
    let payload_reads: Vec<_> = keys
        .iter()
        .zip(&vars)
        .map(|((_, kind), var)| match kind {
            FieldKind::Primitive { kind_tokens, .. } => {
                let prim_str = kind_tokens.to_string();
                let variant = prim_str.split("::").last().unwrap_or("").trim();
                let method = syn::Ident::new(
                    &format!("read_{}", variant.to_lowercase()),
                    proc_macro2::Span::call_site(),
                );
                quote! { let #var = r.#method()?; }
            }
            FieldKind::Bool => quote! { let #var = r.read_bool()?; },
            FieldKind::String => {
                quote! { let #var = r.read_string(::core::option::Option::None)?; }
            }
            FieldKind::ByteVec => quote! {
                let #var = {
                    let n = r.read_len(::core::option::Option::None, 1)?;
                    r.read_octets(n)?
                };
            },
        })
        .collect();
    let payload_hashes: Vec<_> = keys
        .iter()
        .zip(&vars)
        .map(|((_, kind), var)| match kind {
            FieldKind::Primitive { kind_tokens, .. } => {
                let prim_str = kind_tokens.to_string();
                let variant = prim_str.split("::").last().unwrap_or("").trim();
                let method = syn::Ident::new(
                    &format!("write_{}", variant.to_lowercase()),
                    proc_macro2::Span::call_site(),
                );
                quote! { w.#method(#var); }
            }
            FieldKind::Bool => quote! { w.write_bool(#var); },
            FieldKind::String => quote! { w.write_string(&#var); },
            FieldKind::ByteVec => quote! {
                w.write_u32(u32::try_from(#var.len()).unwrap_or(u32::MAX));
                w.write_octets(#var);
            },
        })
        .collect();
    let max_size = match key_holder_max_size(keys) {
        Some(n) => quote! { ::hdds::core::key_hash::KeyMaxSize::Bounded(#n) },
        None => quote! { ::hdds::core::key_hash::KeyMaxSize::Unbounded },
    };
    quote! {
        fn has_key() -> bool {
            true
        }

        /// The pair of key hooks below travel together: `encode_key` writes
        /// a key-only payload `key_hash_of_key_payload` reads back.
        fn keys_round_trip() -> bool {
            true
        }

        fn write_key_holder(
            &self,
            w: &mut ::hdds::core::key_hash::KeyHolderWriter,
        ) -> ::core::option::Option<::hdds::core::key_hash::KeyMaxSize> {
            #(#writes)*
            ::core::option::Option::Some(#max_size)
        }

        /// The key-only payload of a dispose or unregister: the serialized
        /// key (RTPS 2.5 9.4.5.3, K=1), i.e. the type's KeyHolder (XTypes
        /// 1.3 7.2.2.4.7: the key members only, the type's own
        /// extensibility) in the writer's data representation. A derived
        /// type is @appendable, so that is DELIMITED_CDR (XCDR2, behind a
        /// DHEADER) or PLAIN_CDR (XCDR1) little endian, which is what the
        /// D_CDR2_LE or CDR_LE encapsulation of its DATA announces.
        fn encode_key(&self, version: ::hdds::CdrVersion) -> ::std::vec::Vec<u8> {
            let max_align: usize = match version {
                ::hdds::CdrVersion::Xcdr1 => 8,
                ::hdds::CdrVersion::Xcdr2 => 4,
            };
            let delimited = #delimited;
            let mut body: ::std::vec::Vec<u8> = ::std::vec::Vec::new();
            if delimited {
                body.extend_from_slice(&[0u8; 4]);
            }
            #(#payload_writes)*
            let _ = max_align;
            if delimited {
                let n = u32::try_from(body.len() - 4).unwrap_or(u32::MAX);
                body[..4].copy_from_slice(&n.to_le_bytes());
            }
            body
        }

        /// The instance a key-only payload names: the key members read back
        /// from what `encode_key` writes (any CDR version, either byte order),
        /// then hashed as `write_key_holder` hashes a sample's.
        fn key_hash_of_key_payload(payload: &[u8]) -> ::core::option::Option<[u8; 16]> {
            let mut r = ::hdds::core::key_hash::KeyPayloadReader::new(payload)?;
            let version = r.version();
            let _ = &version;
            let delimited = #delimited;
            let end = if delimited {
                ::core::option::Option::Some(r.read_dheader()?)
            } else {
                ::core::option::Option::None
            };
            #(#payload_reads)*
            if let ::core::option::Option::Some(end) = end {
                r.close(end)?;
            }
            r.finish()?;
            let mut w = ::hdds::core::key_hash::KeyHolderWriter::new();
            #(#payload_hashes)*
            ::core::option::Option::Some(w.finish(#max_size))
        }
    }
}

/// Maximum PLAIN_CDR2 size of the KeyHolder holding `keys`: each member at its
/// size, aligned to that size capped at 4 (RTPS 2.5 9.6.4.8 step 4); `None`
/// when a `String` or `Vec<u8>` makes it unbounded.
fn key_holder_max_size(keys: &[(&syn::Ident, &FieldKind)]) -> Option<usize> {
    let mut end = 0usize;
    for (_, kind) in keys {
        let size = match kind {
            FieldKind::Primitive { size, .. } => *size,
            FieldKind::Bool => 1,
            FieldKind::String | FieldKind::ByteVec => return None,
        };
        end = align_to(end, size.min(4)) + size;
    }
    Some(end)
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
            "bool" | "boolean" => return Some(FieldKind::Bool),
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

/// The alignment of a primitive member of natural `alignment` in the
/// generated `encode`/`decode`: the natural alignment capped at `max_align`,
/// the generated local that holds MAXALIGN of the requested version (8 for
/// XCDR1, 4 for XCDR2; DDS-XTypes 1.3 7.4.3.2.2, Table 37: ALIGN(N) aligns
/// to MIN(N, MAXALIGN)). Only an 8-byte member reaches the cap, so a
/// narrower one keeps its constant.
fn primitive_align_expr(alignment: usize) -> proc_macro2::TokenStream {
    if alignment > 4 {
        quote! { #alignment.min(max_align) }
    } else {
        quote! { #alignment }
    }
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
/// - String -> TI_STRING8_SMALL, bound 0 (unbounded)
/// - ByteVec -> TI_PLAIN_SEQUENCE_SMALL of uint8, bound 0 (unbounded)
///
/// A string or a sequence is not a primitive TypeIdentifier: DDS-XTypes 1.3
/// 7.3.4.4 (Annex B `union TypeIdentifier`) gives it its own discriminator
/// and a bound. `TK_STRING8` (0x20) and `TK_SEQUENCE` (0x60) are TypeKinds,
/// and a TypeObject carrying either as a member type is refused by every
/// decoder, HDDS's own included, which drops the type from the endpoint's
/// announcement.
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
                _ => quote! {
                    compile_error!(concat!("Internal error: unsupported primitive kind: ", #variant))
                },
            }
        }
        FieldKind::Bool => {
            quote! { ::hdds::xtypes::TypeIdentifier::TK_BOOLEAN }
        }
        FieldKind::String => {
            quote! { ::hdds::xtypes::TypeIdentifier::string(0) }
        }
        FieldKind::ByteVec => {
            // A primitive element is fully descriptive, so the header says
            // EK_BOTH; the element's TryConstruct is DISCARD (TRY_CONSTRUCT1).
            quote! {
                ::hdds::xtypes::TypeIdentifier::PlainSequenceSmall(
                    ::hdds::xtypes::PlainSequenceSElemDefn {
                        header: ::hdds::xtypes::PlainCollectionHeader {
                            equiv_kind: ::hdds::xtypes::EquivalenceKind::Both,
                            element_flags: ::hdds::xtypes::CollectionElementFlag::TRY_CONSTRUCT1,
                        },
                        bound: 0,
                        element_identifier: ::std::boxed::Box::new(
                            ::hdds::xtypes::TypeIdentifier::TK_UINT8,
                        ),
                    },
                )
            }
        }
    }
}
