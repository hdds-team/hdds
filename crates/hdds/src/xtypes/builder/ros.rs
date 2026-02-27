// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! ROS 2 introspection interop for the TypeObject builder.
//!

use super::core::{StructArtifacts, TypeObjectBuilder};
use super::errors::{BuilderError, RosidlError};
use crate::core::types::{Distro, TypeObjectHandle, ROS_HASH_SIZE};
use crate::xtypes::{
    CompleteStructHeader, CompleteStructMember, CompleteStructType, CompleteTypeDetail,
    CompleteTypeObject, MemberFlag, MinimalStructHeader, MinimalStructMember, MinimalStructType,
    MinimalTypeDetail, MinimalTypeObject, StructTypeFlag, TypeIdentifier, TypeKind,
};
use std::convert::TryFrom;
use std::ffi::CStr;
use std::os::raw::{c_char, c_void};
use std::sync::Arc;

const ROS_TYPE_FLOAT: u8 = 1;
const ROS_TYPE_DOUBLE: u8 = 2;
const ROS_TYPE_LONG_DOUBLE: u8 = 3;
const ROS_TYPE_CHAR: u8 = 4;
const ROS_TYPE_WCHAR: u8 = 5;
const ROS_TYPE_BOOLEAN: u8 = 6;
const ROS_TYPE_OCTET: u8 = 7;
const ROS_TYPE_UINT8: u8 = 8;
const ROS_TYPE_INT8: u8 = 9;
const ROS_TYPE_UINT16: u8 = 10;
const ROS_TYPE_INT16: u8 = 11;
const ROS_TYPE_UINT32: u8 = 12;
const ROS_TYPE_INT32: u8 = 13;
const ROS_TYPE_UINT64: u8 = 14;
const ROS_TYPE_INT64: u8 = 15;
const ROS_TYPE_STRING: u8 = 16;
const ROS_TYPE_WSTRING: u8 = 17;
const ROS_TYPE_MESSAGE: u8 = 18;

type RosSizeFunction = Option<unsafe extern "C" fn(*const c_void) -> usize>;
type RosGetConstFunction = Option<unsafe extern "C" fn(*const c_void, usize) -> *const c_void>;
type RosGetFunction = Option<unsafe extern "C" fn(*mut c_void, usize) -> *mut c_void>;
type RosFetchFunction = Option<unsafe extern "C" fn(*const c_void, usize, *mut c_void)>;
type RosAssignFunction = Option<unsafe extern "C" fn(*mut c_void, usize, *const c_void)>;
type RosResizeFunction = Option<unsafe extern "C" fn(*mut c_void, usize) -> bool>;

type RosMessageTypesupportHandleFunction = Option<
    unsafe extern "C" fn(
        *const rosidl_message_type_support_t,
        *const c_char,
    ) -> *const rosidl_message_type_support_t,
>;

type RosMessageGetTypeHashFunction =
    Option<unsafe extern "C" fn(*const rosidl_message_type_support_t) -> *const rosidl_type_hash_t>;
type RosMessageGetTypeDescriptionFunction =
    Option<unsafe extern "C" fn(*const rosidl_message_type_support_t) -> *const c_void>;
type RosMessageGetTypeDescriptionSourcesFunction =
    Option<unsafe extern "C" fn(*const rosidl_message_type_support_t) -> *const c_void>;

#[repr(C)]
#[derive(Clone, Copy)]
/// ROS 2 type hash descriptor mirroring `rosidl_type_hash_t`.
pub struct rosidl_type_hash_t {
    pub version: u8,
    pub value: [u8; ROS_HASH_SIZE],
}

#[allow(non_camel_case_types)]
/// Initialization policy used by ROS 2 runtime when constructing messages.
pub type rosidl_runtime_c__message_initialization = i32;

#[repr(C)]
/// Introspection metadata for a single ROS 2 message member.
pub struct rosidl_typesupport_introspection_c__MessageMember {
    pub name_: *const c_char,
    pub type_id_: u8,
    pub string_upper_bound_: usize,
    pub members_: *const rosidl_message_type_support_t,
    pub is_array_: bool,
    pub array_size_: usize,
    pub is_upper_bound_: bool,
    pub offset_: u32,
    pub default_value_: *const c_void,
    pub size_function: RosSizeFunction,
    pub get_const_function: RosGetConstFunction,
    pub get_function: RosGetFunction,
    pub fetch_function: RosFetchFunction,
    pub assign_function: RosAssignFunction,
    pub resize_function: RosResizeFunction,
}

#[repr(C)]
/// Aggregated introspection metadata for a ROS 2 message type.
pub struct rosidl_typesupport_introspection_c__MessageMembers {
    pub message_namespace_: *const c_char,
    pub message_name_: *const c_char,
    pub member_count_: u32,
    pub size_of_: usize,
    pub members_: *const rosidl_typesupport_introspection_c__MessageMember,
    pub init_function:
        Option<unsafe extern "C" fn(*mut c_void, rosidl_runtime_c__message_initialization)>,
    pub fini_function: Option<unsafe extern "C" fn(*mut c_void)>,
}

#[repr(C)]
/// Type support entry point for ROS 2 messages exposed via `rosidl_typesupport_introspection_c`.
pub struct rosidl_message_type_support_t {
    pub typesupport_identifier: *const c_char,
    pub data: *const c_void,
    pub func: RosMessageTypesupportHandleFunction,
    pub get_type_hash_func: RosMessageGetTypeHashFunction,
    pub get_type_description_func: RosMessageGetTypeDescriptionFunction,
    pub get_type_description_sources_func: RosMessageGetTypeDescriptionSourcesFunction,
}

/// Decoded ROS metadata (namespace, name, hash).
#[derive(Clone, Debug)]
pub struct RosMessageMetadata {
    pub type_support: *const rosidl_message_type_support_t,
    pub members: *const rosidl_typesupport_introspection_c__MessageMembers,
    pub namespace: String,
    pub name: String,
    pub fqn: String,
    pub hash_version: u8,
    pub hash_value: [u8; ROS_HASH_SIZE],
}

impl RosMessageMetadata {
    /// # Safety
    ///
    /// `type_support` must be a valid pointer produced by `rosidl_typesupport_introspection_c`
    /// and remain alive (including nested metadata) for the duration of this call.
    pub unsafe fn from_type_support(
        type_support: *const rosidl_message_type_support_t,
    ) -> Result<Self, RosidlError> {
        if type_support.is_null() {
            return Err(RosidlError::NullTypeSupport);
        }

        let handle = &*type_support;
        if handle.data.is_null() {
            return Err(RosidlError::NullMembers);
        }

        let members = handle
            .data
            .cast::<rosidl_typesupport_introspection_c__MessageMembers>();
        if members.is_null() {
            return Err(RosidlError::NullMembers);
        }

        let namespace_raw = if (*members).message_namespace_.is_null() {
            ""
        } else {
            CStr::from_ptr((*members).message_namespace_).to_str()?
        };
        let namespace = normalize_namespace(namespace_raw);

        let name = if (*members).message_name_.is_null() {
            String::new()
        } else {
            CStr::from_ptr((*members).message_name_)
                .to_str()?
                .to_string()
        };

        let fqn = if namespace.is_empty() {
            name.clone()
        } else {
            format!("{namespace}::{name}")
        };

        // Hash is optional - some ROS2 type support structures (especially from
        // rosidl_typesupport_introspection_c) may not have the hash function.
        // Use zeroed hash when not available - serialization/deserialization works without it.
        let (hash_version, hash_value) = match handle.get_type_hash_func {
            Some(hash_func) => {
                let hash_ptr = hash_func(type_support);
                if hash_ptr.is_null() {
                    (0u8, [0u8; ROS_HASH_SIZE])
                } else {
                    let hash = &*hash_ptr;
                    let mut value = [0u8; ROS_HASH_SIZE];
                    value.copy_from_slice(&hash.value[..ROS_HASH_SIZE]);
                    (hash.version, value)
                }
            }
            None => (0u8, [0u8; ROS_HASH_SIZE]),
        };

        Ok(Self {
            type_support,
            members,
            namespace,
            name,
            fqn,
            hash_version,
            hash_value,
        })
    }
}

fn normalize_namespace(raw: &str) -> String {
    if raw.is_empty() {
        return String::new();
    }

    raw.split("__")
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>()
        .join("::")
}

fn convert_bound(value: usize, context: &'static str) -> Result<u32, RosidlError> {
    if value > u32::MAX as usize {
        return Err(RosidlError::BoundOverflow { context, value });
    }
    #[allow(clippy::expect_used)] // value is <= u32::MAX, checked on the line above
    Ok(u32::try_from(value).expect("value is <= u32::MAX after bound check"))
}

impl TypeObjectBuilder<'_> {
    /// # Safety
    ///
    /// The provided `metadata` must originate from valid ROS 2 introspection structures. All
    /// internal pointers (members, strings) are dereferenced under the assumption that they point
    /// to initialized data for the lifetime of this call.
    pub unsafe fn from_ros_metadata(
        distro: Distro,
        metadata: RosMessageMetadata,
    ) -> Result<TypeObjectHandle, RosidlError> {
        let mut builder = Self::new(distro);
        let artifacts = builder.build_struct_from_ros(&metadata)?;

        let fqn_arc: Arc<str> = Arc::from(metadata.fqn.as_str());
        let hash_arc: Arc<[u8; ROS_HASH_SIZE]> = Arc::new(metadata.hash_value);

        Ok(TypeObjectHandle::new(
            distro,
            fqn_arc,
            metadata.hash_version,
            hash_arc,
            CompleteTypeObject::Struct(artifacts.complete),
            MinimalTypeObject::Struct(artifacts.minimal),
            artifacts.type_id_complete,
            artifacts.type_id_minimal,
        ))
    }

    /// # Safety
    ///
    /// `type_support` must be a valid pointer to a `rosidl_message_type_support_t` generated by
    /// `rosidl_typesupport_introspection_c`. The pointer must remain alive for the duration of the
    /// call and reference fully initialized metadata.
    pub unsafe fn from_ros_type_support(
        distro: Distro,
        type_support: *const rosidl_message_type_support_t,
    ) -> Result<TypeObjectHandle, RosidlError> {
        let metadata = RosMessageMetadata::from_type_support(type_support)?;
        Self::from_ros_metadata(distro, metadata)
    }

    unsafe fn build_struct_from_ros(
        &mut self,
        metadata: &RosMessageMetadata,
    ) -> Result<StructArtifacts, RosidlError> {
        if self.stack.iter().any(|entry| entry == &metadata.fqn) {
            return Err(RosidlError::Builder(BuilderError::RecursiveType {
                fqn: metadata.fqn.clone(),
            }));
        }

        if let Some(ids) = self.interned.get(&metadata.fqn) {
            return self.rebuild_struct_from_ros(metadata, ids.clone());
        }

        self.stack.push(metadata.fqn.clone());
        let (complete_members, minimal_members) = self.build_struct_members_from_ros(metadata)?;

        let complete_struct = CompleteStructType {
            struct_flags: StructTypeFlag::IS_FINAL,
            header: CompleteStructHeader {
                base_type: None,
                detail: CompleteTypeDetail::new(metadata.fqn.clone()),
            },
            member_seq: complete_members,
        };

        let minimal_struct = MinimalStructType {
            struct_flags: StructTypeFlag::IS_FINAL,
            header: MinimalStructHeader {
                base_type: None,
                detail: MinimalTypeDetail::new(),
            },
            member_seq: minimal_members,
        };

        let complete_hash =
            CompleteTypeObject::Struct(complete_struct.clone()).compute_equivalence_hash()?;
        let minimal_hash =
            MinimalTypeObject::Struct(minimal_struct.clone()).compute_equivalence_hash()?;

        let type_id_complete = TypeIdentifier::complete(complete_hash);
        let type_id_minimal = TypeIdentifier::minimal(minimal_hash);

        self.interned.insert(
            metadata.fqn.clone(),
            (type_id_complete.clone(), type_id_minimal.clone()),
        );
        self.stack.pop();

        Ok(StructArtifacts {
            complete: complete_struct,
            minimal: minimal_struct,
            type_id_complete,
            type_id_minimal,
        })
    }

    unsafe fn rebuild_struct_from_ros(
        &mut self,
        metadata: &RosMessageMetadata,
        ids: (TypeIdentifier, TypeIdentifier),
    ) -> Result<StructArtifacts, RosidlError> {
        let (complete_members, minimal_members) = self.build_struct_members_from_ros(metadata)?;

        let complete_struct = CompleteStructType {
            struct_flags: StructTypeFlag::IS_FINAL,
            header: CompleteStructHeader {
                base_type: None,
                detail: CompleteTypeDetail::new(metadata.fqn.clone()),
            },
            member_seq: complete_members,
        };

        let minimal_struct = MinimalStructType {
            struct_flags: StructTypeFlag::IS_FINAL,
            header: MinimalStructHeader {
                base_type: None,
                detail: MinimalTypeDetail::new(),
            },
            member_seq: minimal_members,
        };

        Ok(StructArtifacts {
            complete: complete_struct,
            minimal: minimal_struct,
            type_id_complete: ids.0,
            type_id_minimal: ids.1,
        })
    }

    unsafe fn build_struct_members_from_ros(
        &mut self,
        metadata: &RosMessageMetadata,
    ) -> Result<(Vec<CompleteStructMember>, Vec<MinimalStructMember>), RosidlError> {
        if metadata.members.is_null() {
            return Err(RosidlError::NullMembers);
        }
        let members = &*metadata.members;
        let ros_members_slice =
            std::slice::from_raw_parts(members.members_, members.member_count_ as usize);

        let mut complete_members = Vec::with_capacity(ros_members_slice.len());
        let mut minimal_members = Vec::with_capacity(ros_members_slice.len());

        for (index, member) in ros_members_slice.iter().enumerate() {
            let member_type_id = self.build_member_type_identifier_from_ros(member)?;
            let name = if member.name_.is_null() {
                String::new()
            } else {
                CStr::from_ptr(member.name_).to_str()?.to_string()
            };

            let flags = MemberFlag::empty();

            #[allow(clippy::expect_used)] // index is a ROS member count, always fits in u32
            let member_id = u32::try_from(index).expect("ROS member index fits within u32");
            let common = crate::xtypes::CommonStructMember {
                member_id,
                member_flags: flags,
                member_type_id,
            };

            complete_members.push(CompleteStructMember {
                common: common.clone(),
                detail: crate::xtypes::CompleteMemberDetail::new(name.clone()),
            });
            minimal_members.push(MinimalStructMember {
                common,
                detail: crate::xtypes::MinimalMemberDetail::from_name(&name),
            });
        }

        Ok((complete_members, minimal_members))
    }

    unsafe fn ensure_ros_struct_ids(
        &mut self,
        metadata: &RosMessageMetadata,
    ) -> Result<(TypeIdentifier, TypeIdentifier), RosidlError> {
        if let Some(ids) = self.interned.get(&metadata.fqn) {
            return Ok(ids.clone());
        }

        let artifacts = self.build_struct_from_ros(metadata)?;
        Ok((artifacts.type_id_complete, artifacts.type_id_minimal))
    }

    unsafe fn build_member_type_identifier_from_ros(
        &mut self,
        member: &rosidl_typesupport_introspection_c__MessageMember,
    ) -> Result<TypeIdentifier, RosidlError> {
        let base_identifier = match member.type_id_ {
            ROS_TYPE_FLOAT => TypeIdentifier::primitive(TypeKind::TK_FLOAT32),
            ROS_TYPE_DOUBLE => TypeIdentifier::primitive(TypeKind::TK_FLOAT64),
            ROS_TYPE_LONG_DOUBLE => TypeIdentifier::primitive(TypeKind::TK_FLOAT128),
            ROS_TYPE_CHAR => TypeIdentifier::primitive(TypeKind::TK_CHAR8),
            ROS_TYPE_WCHAR => TypeIdentifier::primitive(TypeKind::TK_CHAR16),
            ROS_TYPE_BOOLEAN => TypeIdentifier::primitive(TypeKind::TK_BOOLEAN),
            ROS_TYPE_OCTET | ROS_TYPE_UINT8 => TypeIdentifier::primitive(TypeKind::TK_UINT8),
            ROS_TYPE_INT8 => TypeIdentifier::primitive(TypeKind::TK_INT8),
            ROS_TYPE_UINT16 => TypeIdentifier::primitive(TypeKind::TK_UINT16),
            ROS_TYPE_INT16 => TypeIdentifier::primitive(TypeKind::TK_INT16),
            ROS_TYPE_UINT32 => TypeIdentifier::primitive(TypeKind::TK_UINT32),
            ROS_TYPE_INT32 => TypeIdentifier::primitive(TypeKind::TK_INT32),
            ROS_TYPE_UINT64 => TypeIdentifier::primitive(TypeKind::TK_UINT64),
            ROS_TYPE_INT64 => TypeIdentifier::primitive(TypeKind::TK_INT64),
            ROS_TYPE_STRING => {
                let bound = if member.string_upper_bound_ == 0 {
                    0
                } else {
                    convert_bound(member.string_upper_bound_, "string bound")?
                };
                TypeIdentifier::string(bound)
            }
            ROS_TYPE_WSTRING => {
                let bound = if member.string_upper_bound_ == 0 {
                    0
                } else {
                    convert_bound(member.string_upper_bound_, "wstring bound")?
                };
                TypeIdentifier::wstring(bound)
            }
            ROS_TYPE_MESSAGE => {
                if member.members_.is_null() {
                    return Err(RosidlError::NullMembers);
                }
                let nested = RosMessageMetadata::from_type_support(member.members_)?;
                let (_, minimal) = self.ensure_ros_struct_ids(&nested)?;
                minimal
            }
            other => return Err(RosidlError::UnsupportedType(other)),
        };

        if member.is_array_ {
            if member.array_size_ > 0 && !member.is_upper_bound_ {
                let dim = convert_bound(member.array_size_, "array size")?;
                Self::array_type_identifier_from_element(base_identifier, &[dim])
                    .map_err(RosidlError::from)
            } else {
                let bound = if member.array_size_ > 0 {
                    Some(convert_bound(member.array_size_, "sequence bound")?)
                } else {
                    None
                };
                Self::sequence_type_identifier_from_element(base_identifier, bound)
                    .map_err(RosidlError::from)
            }
        } else {
            Ok(base_identifier)
        }
    }
}
