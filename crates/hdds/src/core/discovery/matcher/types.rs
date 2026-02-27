// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! XTypes v1.3 type compatibility and assignability checking.
//!
//!
//! Implements DDS-XTypes type matching rules:
//! - Type name normalization (IDL: prefix handling, ROS2 namespace conventions)
//! - Structural type assignability for FINAL, APPENDABLE, and MUTABLE extensibility
//! - Key field compatibility validation
//!
//! # Type Assignability Rules
//!
//! - **FINAL**: Requires exact structural equivalence (EquivalenceHash match)
//! - **APPENDABLE**: Reader fields must prefix-match writer fields
//! - **MUTABLE**: Member ID-based matching with optional field handling

use crate::xtypes::{CompleteStructType, CompleteTypeObject, MemberFlag, StructTypeFlag};
use std::borrow::Cow;

pub(super) fn is_type_compatible(
    local_type_object: Option<&CompleteTypeObject>,
    remote_type_object: Option<&CompleteTypeObject>,
    local_type_name: &str,
    remote_type_name: &str,
) -> bool {
    let local_name = match local_type_object {
        Some(local) if !local_type_name.is_empty() => local_type_name,
        Some(local) => type_name_from_object(local).unwrap_or(local_type_name),
        None => local_type_name,
    };
    let remote_name = match remote_type_object {
        Some(remote) if !remote_type_name.is_empty() => remote_type_name,
        Some(remote) => type_name_from_object(remote).unwrap_or(remote_type_name),
        None => remote_type_name,
    };

    normalize_type_name(local_name) == normalize_type_name(remote_name)
}

// @audit-ok: Simple pattern matching (cyclo 11, cogni 1) - extract type_name from variant headers
fn type_name_from_object(obj: &CompleteTypeObject) -> Option<&str> {
    match obj {
        CompleteTypeObject::Struct(ty) => Some(ty.header.detail.type_name.as_str()),
        CompleteTypeObject::Union(ty) => Some(ty.header.detail.type_name.as_str()),
        CompleteTypeObject::Enumerated(ty) => Some(ty.header.detail.type_name.as_str()),
        CompleteTypeObject::Bitmask(ty) => Some(ty.header.detail.type_name.as_str()),
        CompleteTypeObject::Bitset(ty) => Some(ty.header.detail.type_name.as_str()),
        CompleteTypeObject::Sequence(ty) => Some(ty.header.detail.type_name.as_str()),
        CompleteTypeObject::Array(ty) => Some(ty.header.detail.type_name.as_str()),
        CompleteTypeObject::Map(ty) => Some(ty.header.detail.type_name.as_str()),
        CompleteTypeObject::Alias(ty) => Some(ty.header.detail.type_name.as_str()),
        CompleteTypeObject::Annotation(ty) => Some(ty.header.detail.type_name.as_str()),
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

pub(super) fn is_assignable_to(
    writer_type: &CompleteTypeObject,
    reader_type: &CompleteTypeObject,
) -> bool {
    let (writer_struct, reader_struct) = match (writer_type, reader_type) {
        (CompleteTypeObject::Struct(w), CompleteTypeObject::Struct(r)) => (w, r),
        _ => return false,
    };

    let writer_flags = writer_struct.struct_flags;
    let reader_flags = reader_struct.struct_flags;

    if !compatible_extensibility(writer_flags, reader_flags) {
        return false;
    }

    if !compatible_keys(writer_struct, reader_struct) {
        return false;
    }

    if writer_flags.contains(StructTypeFlag::IS_FINAL) {
        is_assignable_final(writer_struct, reader_struct)
    } else if writer_flags.contains(StructTypeFlag::IS_APPENDABLE) {
        is_assignable_appendable(writer_struct, reader_struct)
    } else if writer_flags.contains(StructTypeFlag::IS_MUTABLE) {
        is_assignable_mutable(writer_struct, reader_struct)
    } else {
        is_assignable_final(writer_struct, reader_struct)
    }
}

fn compatible_extensibility(writer_flags: StructTypeFlag, reader_flags: StructTypeFlag) -> bool {
    let final_match = writer_flags.contains(StructTypeFlag::IS_FINAL)
        == reader_flags.contains(StructTypeFlag::IS_FINAL);
    let appendable_match = writer_flags.contains(StructTypeFlag::IS_APPENDABLE)
        == reader_flags.contains(StructTypeFlag::IS_APPENDABLE);
    let mutable_match = writer_flags.contains(StructTypeFlag::IS_MUTABLE)
        == reader_flags.contains(StructTypeFlag::IS_MUTABLE);

    final_match && appendable_match && mutable_match
}

fn compatible_keys(writer: &CompleteStructType, reader: &CompleteStructType) -> bool {
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

    for (reader_id, reader_type) in &reader_keys {
        let writer_match = writer_keys
            .iter()
            .find(|(writer_id, _)| writer_id == reader_id);

        match writer_match {
            Some((_, writer_type)) => {
                if writer_type != reader_type {
                    return false;
                }
            }
            None => return false,
        }
    }

    true
}

fn is_assignable_final(writer: &CompleteStructType, reader: &CompleteStructType) -> bool {
    let writer_obj = CompleteTypeObject::Struct(writer.clone());
    let reader_obj = CompleteTypeObject::Struct(reader.clone());

    writer_obj.compute_equivalence_hash() == reader_obj.compute_equivalence_hash()
}

fn is_assignable_appendable(writer: &CompleteStructType, reader: &CompleteStructType) -> bool {
    for (i, reader_member) in reader.member_seq.iter().enumerate() {
        match writer.member_seq.get(i) {
            Some(writer_member) => {
                if reader_member.common.member_id != writer_member.common.member_id {
                    return false;
                }
                if reader_member.common.member_type_id != writer_member.common.member_type_id {
                    return false;
                }
            }
            None => {
                if !reader_member
                    .common
                    .member_flags
                    .contains(MemberFlag::IS_OPTIONAL)
                {
                    return false;
                }
            }
        }
    }

    true
}

fn is_assignable_mutable(writer: &CompleteStructType, reader: &CompleteStructType) -> bool {
    for reader_member in &reader.member_seq {
        let reader_id = reader_member.common.member_id;
        let reader_type = &reader_member.common.member_type_id;

        let writer_match = writer
            .member_seq
            .iter()
            .find(|w| w.common.member_id == reader_id);

        match writer_match {
            Some(writer_member) => {
                if &writer_member.common.member_type_id != reader_type {
                    return false;
                }
            }
            None => {
                if !reader_member
                    .common
                    .member_flags
                    .contains(MemberFlag::IS_OPTIONAL)
                {
                    return false;
                }
            }
        }
    }

    for writer_member in &writer.member_seq {
        if writer_member
            .common
            .member_flags
            .contains(MemberFlag::IS_OPTIONAL)
        {
            continue;
        }

        let writer_id = writer_member.common.member_id;
        let reader_match = reader
            .member_seq
            .iter()
            .find(|r| r.common.member_id == writer_id);

        if reader_match.is_none() {
            return false;
        }
    }

    true
}
