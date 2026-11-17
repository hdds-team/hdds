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
    /// Reachable named dependency objects, retained with their independently
    /// built Complete and Minimal forms across TypeCache hits.
    pub(crate) dependencies: Vec<Arc<TypeObjectHandle>>,
    /// Spec-correct Complete TypeObject for OMG discovery/TypeLookup wire
    /// surfaces: member/dependency references are EK_COMPLETE TypeIdentifiers
    /// per DDS-XTypes v1.3 7.3.4.5, unlike `complete` which may hold the
    /// internal hybrid form (EK_MINIMAL member references) consumed by
    /// HTLK and the HDDS self path. `None` when the registration path did
    /// not derive it; wire consumers fall back to `complete`.
    pub complete_wire: Option<CompleteTypeObject>,
    /// XTypes TypeIdentifier (EK_COMPLETE) derived from `complete_wire`.
    pub type_id_complete_wire: Option<TypeIdentifier>,
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
            dependencies: Vec::new(),
            complete_wire: None,
            type_id_complete_wire: None,
        }
    }

    /// Attach the spec-correct wire Complete TypeObject (Complete member
    /// references per DDS-XTypes v1.3 7.3.4.5) and its EK_COMPLETE
    /// TypeIdentifier. The internal `complete` / `minimal` pair and their
    /// TypeIdentifiers are untouched.
    #[must_use]
    pub fn with_complete_wire(
        mut self,
        complete_wire: CompleteTypeObject,
        type_id_complete_wire: TypeIdentifier,
    ) -> Self {
        self.complete_wire = Some(complete_wire);
        self.type_id_complete_wire = Some(type_id_complete_wire);
        self
    }

    /// Return the Complete TypeObject whose equivalence hash matches the
    /// `requested` EK_COMPLETE TypeIdentifier: the spec-correct wire form
    /// when its TypeIdentifier matches, otherwise the internal `complete`
    /// (legacy/hybrid identity). Serving the object under the exact hash a
    /// peer requested keeps a receiver that verifies the served object
    /// hashes to the requested id satisfied.
    #[must_use]
    pub fn complete_for_id(&self, requested: &TypeIdentifier) -> &CompleteTypeObject {
        match (&self.complete_wire, &self.type_id_complete_wire) {
            (Some(obj), Some(id)) if id == requested => obj,
            _ => &self.complete,
        }
    }

    /// Return the type name attached to the `CompleteTypeObject` when available.
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
            CompleteTypeObject::Sequence(ty) => ty.header.detail.as_ref().map(detail_name),
            CompleteTypeObject::Array(ty) => Some(detail_name(&ty.header.detail)),
            CompleteTypeObject::Map(ty) => ty.header.detail.as_ref().map(detail_name),
            CompleteTypeObject::Alias(ty) => Some(detail_name(&ty.header.detail)),
            CompleteTypeObject::Annotation(ty) => Some(ty.header.annotation_name.as_str()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xtypes::{
        CompleteEnumeratedHeader, CompleteEnumeratedType, CompleteTypeDetail, EquivalenceHash,
        MinimalEnumeratedHeader, MinimalEnumeratedType, MinimalTypeDetail,
    };

    fn dummy_complete(name: &str) -> CompleteTypeObject {
        CompleteTypeObject::Enumerated(CompleteEnumeratedType {
            enum_flags: crate::xtypes::StructTypeFlag::IS_APPENDABLE,
            header: CompleteEnumeratedHeader {
                bit_bound: 32,
                detail: CompleteTypeDetail::new(name),
            },
            literal_seq: vec![],
        })
    }

    fn dummy_minimal() -> MinimalTypeObject {
        MinimalTypeObject::Enumerated(MinimalEnumeratedType {
            enum_flags: crate::xtypes::StructTypeFlag::IS_APPENDABLE,
            header: MinimalEnumeratedHeader {
                bit_bound: 32,
                detail: MinimalTypeDetail::new(),
            },
            literal_seq: vec![],
        })
    }

    fn make_handle() -> TypeObjectHandle {
        TypeObjectHandle::new(
            Distro::Humble,
            std::sync::Arc::from("test"),
            0,
            std::sync::Arc::new([0u8; ROS_HASH_SIZE]),
            dummy_complete("Hybrid"),
            dummy_minimal(),
            TypeIdentifier::Complete(EquivalenceHash::from_bytes([1u8; 14])),
            TypeIdentifier::Minimal(EquivalenceHash::from_bytes([2u8; 14])),
        )
    }

    /// `new()` leaves the wire form unset; `complete_for_id` then always
    /// falls back to the internal `complete` object.
    #[test]
    fn handle_without_wire_form_falls_back_to_complete() {
        let handle = make_handle();
        assert!(handle.complete_wire.is_none());
        assert!(handle.type_id_complete_wire.is_none());
        let requested = TypeIdentifier::Complete(EquivalenceHash::from_bytes([9u8; 14]));
        assert_eq!(*handle.complete_for_id(&requested), handle.complete);
    }

    /// With a wire form attached, `complete_for_id` serves it ONLY under its
    /// own TypeIdentifier; the legacy hybrid id still serves the hybrid, and
    /// the internal complete/minimal pair is untouched.
    #[test]
    fn handle_with_wire_form_selects_by_requested_id() {
        let hybrid = dummy_complete("Hybrid");
        let wire = dummy_complete("Wire");
        let wire_id = TypeIdentifier::Complete(EquivalenceHash::from_bytes([7u8; 14]));
        let handle = make_handle().with_complete_wire(wire.clone(), wire_id.clone());

        // Internal pair untouched by the attach.
        assert_eq!(handle.complete, hybrid);
        assert_eq!(handle.minimal, dummy_minimal());
        assert_eq!(
            handle.type_id_minimal,
            TypeIdentifier::Minimal(EquivalenceHash::from_bytes([2u8; 14]))
        );

        // Wire id -> wire object.
        assert_eq!(*handle.complete_for_id(&wire_id), wire);
        // Legacy id -> hybrid object.
        let legacy_id = TypeIdentifier::Complete(EquivalenceHash::from_bytes([1u8; 14]));
        assert_eq!(*handle.complete_for_id(&legacy_id), hybrid);
    }
}
