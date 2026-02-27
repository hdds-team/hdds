// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Runtime TypeObject builder leveraging ROS 2 introspection metadata.
//!
//! The builder converts ROS 2 `rosidl` metadata (or the safe [`MessageDescriptor`] wrapper)
//! into fully-formed DDS XTypes `TypeObjectHandle` instances that can be cached in the
//! `TypeCache`.

mod core;
mod errors;
mod model;
mod ros;

pub use core::TypeObjectBuilder;
pub use errors::{BuilderError, RosidlError};
pub use model::{FieldType, MessageDescriptor, MessageMember, PrimitiveType};
pub use ros::{
    rosidl_message_type_support_t, rosidl_runtime_c__message_initialization, rosidl_type_hash_t,
    rosidl_typesupport_introspection_c__MessageMember,
    rosidl_typesupport_introspection_c__MessageMembers, RosMessageMetadata,
};

#[cfg(test)]
mod tests;
