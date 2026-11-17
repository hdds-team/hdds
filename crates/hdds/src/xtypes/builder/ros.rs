// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! ROS 2 introspection interop for the TypeObject builder.
//!

use super::core::{StructArtifacts, TypeObjectBuilder};
use super::errors::{BuilderError, RosidlError};
use crate::core::types::{Distro, TypeObjectHandle, ROS_HASH_SIZE};
use crate::xtypes::{
    CompleteStructHeader, CompleteStructMember, CompleteStructType, CompleteTypeDetail,
    CompleteTypeObject, MinimalStructHeader, MinimalStructMember, MinimalStructType,
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

/// Which `rosidl_typesupport_introspection_c` struct layout this ROS 2
/// installation uses.
///
/// Jazzy added `@key` support to the introspection type support and inserted
/// two `bool` fields into the C structs:
///
/// ```text
/// MessageMember   ... members_, [is_key_,] is_array_, array_size_, ...
/// MessageMembers  ... size_of_, [has_any_key_member_,] members_, init_, fini_
/// ```
///
/// On x86_64 the member change costs nothing but one byte: `is_key_` and
/// `is_array_` share the padding slot after `members_`, so only `is_array_`
/// moves (offset +1) and every field from `array_size_` onwards keeps its
/// offset. The `MessageMembers` change is not free: `members_`,
/// `init_function` and `fini_function` all shift by one pointer alignment.
///
/// Reading a Jazzy struct with the pre-Jazzy layout therefore walks a garbage
/// `members_` pointer. That is exactly what happened: every ROS 2 node on
/// Jazzy segfaulted in `build_struct_members_from_ros` while registering the
/// `/rosout` publisher's type.
///
/// The layout is NEVER guessed from a distro name on the walking path. It is
/// [`RosIntrospectionLayout::detect`]ed from the C object itself and carried
/// on the [`RosMessageMetadata`] that describes that object, so a distro this
/// project has never built against is read correctly anyway.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RosIntrospectionLayout {
    /// Foxy through Iron: no key fields.
    PreJazzy,
    /// Jazzy and later: `is_key_` and `has_any_key_member_` present.
    WithKeyFields,
}

/// Any address below this is not a member array; it is a `bool` plus padding
/// read as if it were a pointer. The first page is never mapped on any target
/// this crate builds for.
const NOT_A_POINTER: usize = 4096;

impl RosIntrospectionLayout {
    /// The layout the introspection type support of `distro` emits.
    ///
    /// This is a HINT only: it seeds the fallback used when an object cannot
    /// be detected. The authority is always [`Self::detect`].
    #[must_use]
    pub fn for_distro(distro: Distro) -> Self {
        match distro {
            Distro::Humble | Distro::Iron => Self::PreJazzy,
            Distro::Jazzy => Self::WithKeyFields,
        }
    }

    /// Bytes between the offset this crate declares for `is_array_` and the
    /// offset the real C struct puts it at.
    const fn member_shift(self) -> usize {
        match self {
            Self::PreJazzy => 0,
            // is_key_ takes the byte, is_array_ moves one along.
            Self::WithKeyFields => 1,
        }
    }

    /// Bytes between the offsets this crate declares for `members_`,
    /// `init_function` and `fini_function` and the offsets the real C struct
    /// puts them at.
    ///
    /// `has_any_key_member_` is a `bool` in its own pointer-aligned slot, so
    /// the shift is ONE POINTER ALIGNMENT - 8 bytes on a 64-bit target, 4 on a
    /// 32-bit one. It is not the literal 8.
    const fn tail_shift(self) -> usize {
        match self {
            Self::PreJazzy => 0,
            Self::WithKeyFields => std::mem::align_of::<*const c_void>(),
        }
    }

    /// Read the layout out of the object instead of guessing it from a distro
    /// name.
    ///
    /// The slot this crate declares as `members_` holds `has_any_key_member_`
    /// plus padding on the key layout, so it reads back as a value no member
    /// array pointer can ever have (0 or 1, and in any case below the first
    /// page). A pre-Jazzy object has the real member array pointer there.
    ///
    /// Returns `None` when the object cannot settle the question: an empty
    /// message has no member array, so a NULL slot is ambiguous.
    ///
    /// # The assumption this rests on, stated because it is load-bearing
    ///
    /// "Reads back as 0 or 1" is true only because the padding after the
    /// `bool` is ZERO. Those bytes are real input to the comparison below, not
    /// slack. A Jazzy typesupport object is a C object of static storage
    /// duration emitted by generated code, and every mainstream toolchain
    /// zero-fills such an object's padding - but C itself leaves padding bytes
    /// unspecified, so this is a toolchain convention, not a language
    /// guarantee. If it ever fails to hold, the slot reads as garbage and this
    /// function can answer PreJazzy for a Jazzy object, which is the
    /// out-of-bounds pointer walk the whole layout fix exists to prevent.
    ///
    /// A fixture that builds the struct in Rust does NOT get that zero fill:
    /// implicit padding in a Rust struct literal is uninitialised, and
    /// MemorySanitizer reports this read as use-of-uninitialised-value. The
    /// fixtures therefore declare the padding explicitly and zero it, which
    /// models the object under test rather than the stack under the test.
    ///
    /// # Safety
    ///
    /// `members` must be non-NULL and point at a live
    /// `rosidl_typesupport_introspection_c__MessageMembers` of EITHER layout.
    /// Only the fields both layouts agree on (`member_count_`) and the eight
    /// bytes at the pre-Jazzy `members_` offset are read, and both are inside
    /// the shorter of the two structs.
    #[must_use]
    pub unsafe fn detect(
        members: *const rosidl_typesupport_introspection_c__MessageMembers,
    ) -> Option<Self> {
        if members.is_null() {
            return None;
        }
        let base = members.cast::<u8>();
        let count = base
            .add(std::mem::offset_of!(
                rosidl_typesupport_introspection_c__MessageMembers,
                member_count_
            ))
            .cast::<u32>()
            .read_unaligned();
        if count == 0 {
            // No member array to point at: a NULL slot proves nothing.
            return None;
        }
        let declared_members_slot = base
            .add(std::mem::offset_of!(
                rosidl_typesupport_introspection_c__MessageMembers,
                members_
            ))
            .cast::<usize>()
            .read_unaligned();
        if declared_members_slot < NOT_A_POINTER {
            Some(Self::WithKeyFields)
        } else {
            Some(Self::PreJazzy)
        }
    }

    /// Detect, and fall back to `hint` (with one warning) when the object
    /// cannot settle the question.
    ///
    /// # Safety
    ///
    /// As [`Self::detect`].
    #[must_use]
    pub unsafe fn resolve_for(
        members: *const rosidl_typesupport_introspection_c__MessageMembers,
        hint: Self,
    ) -> Self {
        match Self::detect(members) {
            Some(detected) => {
                if detected != hint {
                    log::debug!(
                        "[ros] introspection layout {detected:?} detected from the type support; \
                         the distro hint said {hint:?}. Trusting the object."
                    );
                }
                detected
            }
            None => hint,
        }
    }

    /// Pointer to the member array of `members`.
    ///
    /// Never read the `members_` field directly: on the key layout it sits one
    /// pointer further along and the declared offset holds
    /// `has_any_key_member_` plus padding, i.e. a near-null pointer.
    ///
    /// # Safety
    ///
    /// `members` must point at a live `MessageMembers` emitted by an
    /// introspection type support of THIS layout, i.e. the layout that
    /// [`Self::detect`] returned for it.
    #[must_use]
    pub unsafe fn members(
        self,
        members: *const rosidl_typesupport_introspection_c__MessageMembers,
    ) -> *const rosidl_typesupport_introspection_c__MessageMember {
        members
            .cast::<u8>()
            .add(
                std::mem::offset_of!(rosidl_typesupport_introspection_c__MessageMembers, members_)
                    + self.tail_shift(),
            )
            .cast::<*const rosidl_typesupport_introspection_c__MessageMember>()
            .read_unaligned()
    }

    /// The generated `init` function for this message type.
    ///
    /// # Safety
    ///
    /// As [`Self::members`].
    #[must_use]
    pub unsafe fn init_fn(
        self,
        members: *const rosidl_typesupport_introspection_c__MessageMembers,
    ) -> Option<unsafe extern "C" fn(*mut c_void, rosidl_runtime_c__message_initialization)> {
        members
            .cast::<u8>()
            .add(
                std::mem::offset_of!(
                    rosidl_typesupport_introspection_c__MessageMembers,
                    init_function
                ) + self.tail_shift(),
            )
            .cast::<Option<
                unsafe extern "C" fn(*mut c_void, rosidl_runtime_c__message_initialization),
            >>()
            .read_unaligned()
    }

    /// The generated `fini` function for this message type.
    ///
    /// # Safety
    ///
    /// As [`Self::members`].
    #[must_use]
    pub unsafe fn fini_fn(
        self,
        members: *const rosidl_typesupport_introspection_c__MessageMembers,
    ) -> Option<unsafe extern "C" fn(*mut c_void)> {
        members
            .cast::<u8>()
            .add(
                std::mem::offset_of!(
                    rosidl_typesupport_introspection_c__MessageMembers,
                    fini_function
                ) + self.tail_shift(),
            )
            .cast::<Option<unsafe extern "C" fn(*mut c_void)>>()
            .read_unaligned()
    }

    /// True when `member` is an array or sequence.
    ///
    /// Never read the `is_array_` field directly: on the key layout the byte
    /// at that offset is `is_key_` and the real flag is the byte after it.
    ///
    /// # Safety
    ///
    /// `member` must point at a live `MessageMember` emitted by an
    /// introspection type support of THIS layout.
    #[must_use]
    pub unsafe fn member_is_array(
        self,
        member: *const rosidl_typesupport_introspection_c__MessageMember,
    ) -> bool {
        member
            .cast::<u8>()
            .add(
                std::mem::offset_of!(rosidl_typesupport_introspection_c__MessageMember, is_array_)
                    + self.member_shift(),
            )
            .read()
            != 0
    }

    /// True when `member` is annotated `@key`. Always false before Jazzy,
    /// which had no way to express it.
    ///
    /// # Safety
    ///
    /// As [`Self::member_is_array`].
    #[must_use]
    pub unsafe fn member_is_key(
        self,
        member: *const rosidl_typesupport_introspection_c__MessageMember,
    ) -> bool {
        match self {
            Self::PreJazzy => false,
            Self::WithKeyFields => {
                member
                    .cast::<u8>()
                    .add(std::mem::offset_of!(
                        rosidl_typesupport_introspection_c__MessageMember,
                        is_array_
                    ))
                    .read()
                    != 0
            }
        }
    }
}

/// Process-wide fallback layout, used only when an object cannot be detected.
///
/// The value is installed by [`resolve_ros_introspection_layout_from_env`],
/// which `hdds-c`'s rmw context constructors call before any type is
/// registered, and by `hdds_participant_register_type_support`, which knows
/// the [`Distro`] its caller declared. The walker itself NEVER reads the
/// environment: a process that is not a ROS 2 node (every unit test in this
/// crate, for one) must not have its behaviour depend on an env lookup that
/// could race with another thread's `set_var`.
static ROS_INTROSPECTION_LAYOUT: std::sync::OnceLock<RosIntrospectionLayout> =
    std::sync::OnceLock::new();

/// The fallback layout. Defaults to [`RosIntrospectionLayout::PreJazzy`],
/// which is what this crate has always assumed and what every distro before
/// Jazzy uses.
///
/// This is NOT what the type walker reads. Every walker reads the layout
/// detected for the object it is walking, carried on its
/// [`RosMessageMetadata`].
#[must_use]
pub fn ros_introspection_layout() -> RosIntrospectionLayout {
    *ROS_INTROSPECTION_LAYOUT
        .get()
        .unwrap_or(&RosIntrospectionLayout::PreJazzy)
}

/// Install the fallback layout explicitly. The first call wins; later calls
/// are ignored and return the value already in force.
pub fn set_ros_introspection_layout(layout: RosIntrospectionLayout) -> RosIntrospectionLayout {
    *ROS_INTROSPECTION_LAYOUT.get_or_init(|| layout)
}

/// Resolve the fallback layout from the environment and install it. Called
/// ONCE per process from the rmw context constructors, before the first type
/// is registered.
///
/// `HDDS_ROS_INTROSPECTION_LAYOUT` (`key` or `legacy`) wins; otherwise
/// `ROS_DISTRO`. Only the three distros this project actually builds and
/// gates (Humble, Iron, Jazzy) are mapped by name; every other distro,
/// including Kilted and Rolling, keeps the pre-Jazzy fallback and is expected
/// to be settled by [`RosIntrospectionLayout::detect`] on the object itself.
/// Naming an unmeasured distro here would be a guess, and a wrong guess is a
/// jump through a pointer read out of bounds.
pub fn resolve_ros_introspection_layout_from_env() -> RosIntrospectionLayout {
    let resolved = if let Ok(forced) = std::env::var("HDDS_ROS_INTROSPECTION_LAYOUT") {
        match forced.trim().to_ascii_lowercase().as_str() {
            "key" | "jazzy" => RosIntrospectionLayout::WithKeyFields,
            "legacy" | "prejazzy" | "pre-jazzy" => RosIntrospectionLayout::PreJazzy,
            other => {
                log::warn!(
                    "[ros] HDDS_ROS_INTROSPECTION_LAYOUT='{other}' is not 'key' or 'legacy'; using the pre-Jazzy layout"
                );
                RosIntrospectionLayout::PreJazzy
            }
        }
    } else {
        match std::env::var("ROS_DISTRO")
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "jazzy" => RosIntrospectionLayout::WithKeyFields,
            "humble" | "iron" | "" => RosIntrospectionLayout::PreJazzy,
            other => {
                log::debug!(
                    "[ros] ROS_DISTRO '{other}' is not one of the gated distros: the layout will \
                     be detected from each type support, with the pre-Jazzy layout as fallback."
                );
                RosIntrospectionLayout::PreJazzy
            }
        }
    };
    set_ros_introspection_layout(resolved)
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
    /// The introspection struct layout THIS type support was emitted with,
    /// detected from the object rather than guessed from a distro name. Every
    /// walker reads it from here; nothing on a walking path consults a
    /// process-global or the environment.
    pub layout: RosIntrospectionLayout,
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

        let layout = RosIntrospectionLayout::resolve_for(members, ros_introspection_layout());

        Ok(Self {
            type_support,
            members,
            namespace,
            name,
            fqn,
            hash_version,
            hash_value,
            layout,
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

        let mut handle = TypeObjectHandle::new(
            distro,
            fqn_arc,
            metadata.hash_version,
            hash_arc,
            CompleteTypeObject::Struct(artifacts.complete),
            MinimalTypeObject::Struct(artifacts.minimal),
            artifacts.type_id_complete,
            artifacts.type_id_minimal,
        );
        handle.dependencies = builder.ros_dependencies;
        Ok(handle)
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
        let layout = metadata.layout;
        let member_count = (*metadata.members).member_count_ as usize;
        let member_array = layout.members(metadata.members);
        if member_count > 0 && member_array.is_null() {
            // A member array that is NULL while the count is not zero means the
            // layout we are reading with does not describe this object. Fail
            // instead of building a slice on a null pointer.
            return Err(RosidlError::NullMembers);
        }
        let ros_members_slice = std::slice::from_raw_parts(member_array, member_count);

        let mut complete_members = Vec::with_capacity(ros_members_slice.len());
        let mut minimal_members = Vec::with_capacity(ros_members_slice.len());

        for (index, member) in ros_members_slice.iter().enumerate() {
            let (member_type_id_complete, member_type_id_minimal) =
                self.build_member_type_identifier_from_ros(member, layout)?;
            let name = if member.name_.is_null() {
                String::new()
            } else {
                CStr::from_ptr(member.name_).to_str()?.to_string()
            };

            // ROS introspection exposes @key but no explicit TryConstruct.
            let flags =
                Self::default_member_flags(layout.member_is_key(std::ptr::from_ref(member)));

            #[allow(clippy::expect_used)] // index is a ROS member count, always fits in u32
            let member_id = u32::try_from(index).expect("ROS member index fits within u32");
            let common_complete = crate::xtypes::CommonStructMember {
                member_id,
                member_flags: flags,
                member_type_id: member_type_id_complete,
            };
            let common_minimal = crate::xtypes::CommonStructMember {
                member_id,
                member_flags: flags,
                member_type_id: member_type_id_minimal,
            };

            complete_members.push(CompleteStructMember {
                common: common_complete,
                detail: crate::xtypes::CompleteMemberDetail::new(name.clone()),
            });
            minimal_members.push(MinimalStructMember {
                common: common_minimal,
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
        let ids = (
            artifacts.type_id_complete.clone(),
            artifacts.type_id_minimal.clone(),
        );
        self.ros_dependencies.push(Arc::new(TypeObjectHandle::new(
            self.distro,
            Arc::from(metadata.fqn.as_str()),
            metadata.hash_version,
            Arc::new(metadata.hash_value),
            CompleteTypeObject::Struct(artifacts.complete),
            MinimalTypeObject::Struct(artifacts.minimal),
            artifacts.type_id_complete,
            artifacts.type_id_minimal,
        )));
        Ok(ids)
    }

    /// Builds the `TypeIdentifier` a member contributes to each
    /// representation, returned as `(complete, minimal)`.
    ///
    /// Per DDS-XTypes 1.3 7.3.4 a Complete TypeObject references a nested
    /// type by its `EK_COMPLETE` identifier and a Minimal one by its
    /// `EK_MINIMAL` identifier; the two must never be swapped or shared. For
    /// every primitive, string and wstring case the two identifiers are the
    /// same value (there is no Complete/Minimal distinction below struct
    /// granularity), so both sides of the pair are simply that one value.
    unsafe fn build_member_type_identifier_from_ros(
        &mut self,
        member: &rosidl_typesupport_introspection_c__MessageMember,
        layout: RosIntrospectionLayout,
    ) -> Result<(TypeIdentifier, TypeIdentifier), RosidlError> {
        let (complete_base, minimal_base) = match member.type_id_ {
            ROS_TYPE_FLOAT => {
                let id = TypeIdentifier::primitive(TypeKind::TK_FLOAT32);
                (id.clone(), id)
            }
            ROS_TYPE_DOUBLE => {
                let id = TypeIdentifier::primitive(TypeKind::TK_FLOAT64);
                (id.clone(), id)
            }
            ROS_TYPE_LONG_DOUBLE => {
                let id = TypeIdentifier::primitive(TypeKind::TK_FLOAT128);
                (id.clone(), id)
            }
            ROS_TYPE_CHAR => {
                let id = TypeIdentifier::primitive(TypeKind::TK_CHAR8);
                (id.clone(), id)
            }
            ROS_TYPE_WCHAR => {
                let id = TypeIdentifier::primitive(TypeKind::TK_CHAR16);
                (id.clone(), id)
            }
            ROS_TYPE_BOOLEAN => {
                let id = TypeIdentifier::primitive(TypeKind::TK_BOOLEAN);
                (id.clone(), id)
            }
            ROS_TYPE_OCTET | ROS_TYPE_UINT8 => {
                let id = TypeIdentifier::primitive(TypeKind::TK_UINT8);
                (id.clone(), id)
            }
            ROS_TYPE_INT8 => {
                let id = TypeIdentifier::primitive(TypeKind::TK_INT8);
                (id.clone(), id)
            }
            ROS_TYPE_UINT16 => {
                let id = TypeIdentifier::primitive(TypeKind::TK_UINT16);
                (id.clone(), id)
            }
            ROS_TYPE_INT16 => {
                let id = TypeIdentifier::primitive(TypeKind::TK_INT16);
                (id.clone(), id)
            }
            ROS_TYPE_UINT32 => {
                let id = TypeIdentifier::primitive(TypeKind::TK_UINT32);
                (id.clone(), id)
            }
            ROS_TYPE_INT32 => {
                let id = TypeIdentifier::primitive(TypeKind::TK_INT32);
                (id.clone(), id)
            }
            ROS_TYPE_UINT64 => {
                let id = TypeIdentifier::primitive(TypeKind::TK_UINT64);
                (id.clone(), id)
            }
            ROS_TYPE_INT64 => {
                let id = TypeIdentifier::primitive(TypeKind::TK_INT64);
                (id.clone(), id)
            }
            ROS_TYPE_STRING => {
                let bound = if member.string_upper_bound_ == 0 {
                    0
                } else {
                    convert_bound(member.string_upper_bound_, "string bound")?
                };
                let id = TypeIdentifier::string(bound);
                (id.clone(), id)
            }
            ROS_TYPE_WSTRING => {
                let bound = if member.string_upper_bound_ == 0 {
                    0
                } else {
                    convert_bound(member.string_upper_bound_, "wstring bound")?
                };
                let id = TypeIdentifier::wstring(bound);
                (id.clone(), id)
            }
            ROS_TYPE_MESSAGE => {
                if member.members_.is_null() {
                    return Err(RosidlError::NullMembers);
                }
                let nested = RosMessageMetadata::from_type_support(member.members_)?;
                self.ensure_ros_struct_ids(&nested)?
            }
            other => return Err(RosidlError::UnsupportedType(other)),
        };

        if layout.member_is_array(std::ptr::from_ref(member)) {
            if member.array_size_ > 0 && !member.is_upper_bound_ {
                let dim = convert_bound(member.array_size_, "array size")?;
                let complete = Self::array_type_identifier_from_element(complete_base, &[dim])
                    .map_err(RosidlError::from)?;
                let minimal = Self::array_type_identifier_from_element(minimal_base, &[dim])
                    .map_err(RosidlError::from)?;
                Ok((complete, minimal))
            } else {
                let bound = if member.array_size_ > 0 {
                    Some(convert_bound(member.array_size_, "sequence bound")?)
                } else {
                    None
                };
                let complete = Self::sequence_type_identifier_from_element(complete_base, bound)
                    .map_err(RosidlError::from)?;
                let minimal = Self::sequence_type_identifier_from_element(minimal_base, bound)
                    .map_err(RosidlError::from)?;
                Ok((complete, minimal))
            }
        } else {
            Ok((complete_base, minimal_base))
        }
    }
}
