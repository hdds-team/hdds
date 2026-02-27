// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! TypeObject handle stored inside the concurrent TypeCache.

use super::distro::Distro;
use crate::xtypes::{CompleteTypeDetail, CompleteTypeObject, MinimalTypeObject, TypeIdentifier};
use std::sync::Arc;

/// Size (in bytes) of the ROS 2 RIHS hash (`rosidl_type_hash_t::value`).
pub const ROS_HASH_SIZE: usize = 32;

/// Shared representation of a fully built DDS XTypes TypeObject.
#[derive(Debug)]
pub struct TypeObjectHandle {
    /// ROS 2 distribution used when resolving introspection metadata.
    pub distro: Distro,
    /// Fully-qualified ROS 2 name (`package::msg::Type`).
    pub fqn: Arc<str>,
    /// RIHS hash version retrieved from rosidl (1 for Humble/Iron/Jazzy).
    pub ros_hash_version: u8,
    /// RIHS hash value copied from rosidl introspection (32 bytes SHA-256).
    pub ros_hash: Arc<[u8; ROS_HASH_SIZE]>,
    /// Complete TypeObject (full metadata, names, annotations).
    pub complete: CompleteTypeObject,
    /// Minimal TypeObject (assignability metadata only).
    pub minimal: MinimalTypeObject,
    /// XTypes TypeIdentifier derived from the CompleteTypeObject.
    pub type_id_complete: TypeIdentifier,
    /// XTypes TypeIdentifier derived from the MinimalTypeObject.
    pub type_id_minimal: TypeIdentifier,
}

impl TypeObjectHandle {
    /// Construct a new handle from the builder outputs.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        distro: Distro,
        fqn: Arc<str>,
        ros_hash_version: u8,
        ros_hash: Arc<[u8; ROS_HASH_SIZE]>,
        complete: CompleteTypeObject,
        minimal: MinimalTypeObject,
        type_id_complete: TypeIdentifier,
        type_id_minimal: TypeIdentifier,
    ) -> Self {
        Self {
            distro,
            fqn,
            ros_hash_version,
            ros_hash,
            complete,
            minimal,
            type_id_complete,
            type_id_minimal,
        }
    }

    /// Return the type name attached to the CompleteTypeObject when available.
    #[must_use]
    // @audit-ok: Simple pattern matching (cyclo 12, cogni 1) - extract type_name from variant detail
    pub fn type_name(&self) -> Option<&str> {
        fn detail_name(detail: &CompleteTypeDetail) -> &str {
            detail.type_name.as_str()
        }

        match &self.complete {
            CompleteTypeObject::Struct(ty) => Some(detail_name(&ty.header.detail)),
            CompleteTypeObject::Union(ty) => Some(detail_name(&ty.header.detail)),
            CompleteTypeObject::Enumerated(ty) => Some(detail_name(&ty.header.detail)),
            CompleteTypeObject::Bitmask(ty) => Some(detail_name(&ty.header.detail)),
            CompleteTypeObject::Bitset(ty) => Some(detail_name(&ty.header.detail)),
            CompleteTypeObject::Sequence(ty) => Some(detail_name(&ty.header.detail)),
            CompleteTypeObject::Array(ty) => Some(detail_name(&ty.header.detail)),
            CompleteTypeObject::Map(ty) => Some(detail_name(&ty.header.detail)),
            CompleteTypeObject::Alias(ty) => Some(detail_name(&ty.header.detail)),
            CompleteTypeObject::Annotation(ty) => Some(detail_name(&ty.header.detail)),
        }
    }
}
