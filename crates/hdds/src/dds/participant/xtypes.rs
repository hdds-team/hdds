// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! XTypes integration for Participant.
//!
//! Provides type registration and caching for ROS 2 type support
//! introspection and XTypes TypeObject handling.

use super::runtime::Participant;
use crate::core::types::{Distro, TypeObjectHandle};
use crate::xtypes::{rosidl_message_type_support_t, RosidlError};
#[cfg(feature = "xtypes-structural-assignability")]
use crate::xtypes::{CompleteTypeObject, EquivalenceHash, TypeIdentifier};
#[cfg(feature = "xtypes-structural-assignability")]
use std::collections::HashMap;
use std::sync::Arc;

impl Participant {
    /// Register a ROS 2 type support with the participant's type cache.
    ///
    /// # Safety
    /// `type_support` must point to a valid `rosidl_message_type_support_t`.
    pub unsafe fn register_type_from_type_support(
        &self,
        distro: Distro,
        type_support: *const rosidl_message_type_support_t,
    ) -> std::result::Result<Arc<TypeObjectHandle>, RosidlError> {
        let handle = self
            .type_cache
            .get_or_build_from_type_support(distro, type_support)?;

        Ok(self.cache_registered_type(&handle))
    }

    /// Register a ROS 2 type support using the participant default ROS distribution.
    ///
    /// # Safety
    /// `type_support` must point to a valid ROS 2 type support structure and remain alive
    /// for the duration of the registration call.
    pub unsafe fn register_type_from_type_support_default(
        &self,
        type_support: *const rosidl_message_type_support_t,
    ) -> std::result::Result<Arc<TypeObjectHandle>, RosidlError> {
        self.register_type_from_type_support(self.distro, type_support)
    }

    pub(super) fn cache_registered_type(
        &self,
        handle: &Arc<TypeObjectHandle>,
    ) -> Arc<TypeObjectHandle> {
        {
            let mut map = self.registered_types.write();
            // Key dependencies by Complete identity: different names can share
            // one Minimal identity, but both Complete objects must be served.
            for dependency in &handle.dependencies {
                if let crate::xtypes::TypeIdentifier::Complete(hash) = dependency.type_id_complete {
                    let key: String = hash.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
                    map.entry(key).or_insert_with(|| Arc::clone(dependency));
                }
            }
            map.insert(handle.fqn.to_string(), Arc::clone(handle));
            if let Some(name) = handle.type_name() {
                map.insert(name.to_string(), Arc::clone(handle));
            }
        }
        #[cfg(feature = "xtypes-structural-assignability")]
        if let Some(registry) = &self.match_registry {
            let mut objects = HashMap::new();
            for object in std::iter::once(handle).chain(handle.dependencies.iter()) {
                for identifier in [&object.type_id_complete, &object.type_id_minimal] {
                    if let TypeIdentifier::Complete(hash) | TypeIdentifier::Minimal(hash) =
                        identifier
                    {
                        objects.insert(*hash, object.complete.clone());
                    }
                }
            }
            registry.register_type_objects(objects);
        }
        Arc::clone(handle)
    }

    pub(super) fn registered_type(&self, name: &str) -> Option<Arc<TypeObjectHandle>> {
        self.registered_types.read().get(name).cloned()
    }

    pub(crate) fn register_topic_type(&self, topic: &str, handle: Arc<TypeObjectHandle>) {
        let mut map = self.topic_types.write();
        map.insert(topic.to_string(), handle);
    }

    pub(crate) fn topic_type_handle(&self, topic: &str) -> Option<Arc<TypeObjectHandle>> {
        self.topic_types.read().get(topic).cloned()
    }

    /// Look up a type this participant can SERVE to a peer that asks for it
    /// via TypeLookup. Deliberately separate from `registered_type`: see
    /// `register_served_type` for why the two maps must never merge.
    ///
    /// Production code never needs this accessor: the two responders read
    /// `served_types` directly through the `Arc` cloned into
    /// `TypeLookupConfig`. It exists for tests to observe servability
    /// without reaching into responder internals.
    #[cfg(test)]
    pub(crate) fn served_type(&self, name: &str) -> Option<Arc<TypeObjectHandle>> {
        self.served_types.read().get(name).cloned()
    }

    /// Snapshot local descriptions for dependency conversion, including
    /// registrations made without a discovery matcher.
    #[cfg(feature = "xtypes-structural-assignability")]
    pub(super) fn snapshot_local_type_objects(
        &self,
    ) -> HashMap<EquivalenceHash, CompleteTypeObject> {
        let mut objects = self
            .match_registry
            .as_ref()
            .map(|registry| registry.snapshot_type_store())
            .unwrap_or_default();
        for map in [&self.registered_types, &self.served_types] {
            let map = map.read();
            // Sorted by key: a Minimal hash is shared by structurally
            // identical types with different names, so the first holder
            // (registry entry, then key order) keeps it, never HashMap order.
            let mut handles: Vec<_> = map.iter().collect();
            handles.sort_by(|a, b| a.0.cmp(b.0));
            for (_, handle) in handles {
                if let TypeIdentifier::Complete(hash) = &handle.type_id_complete {
                    objects.insert(*hash, handle.complete.clone());
                }
                if let TypeIdentifier::Minimal(hash) = &handle.type_id_minimal {
                    objects
                        .entry(*hash)
                        .or_insert_with(|| handle.complete.clone());
                }
                if let (Some(TypeIdentifier::Complete(hash)), Some(wire)) =
                    (&handle.type_id_complete_wire, &handle.complete_wire)
                {
                    objects.insert(*hash, wire.clone());
                }
            }
        }
        objects
    }

    /// The `TypeInformation` an endpoint announces for `type_object` (under
    /// `type_name`), derived from the matcher's type store, with every
    /// Complete identifier it names made servable by the OMG getTypes
    /// responder (DDS-XTypes v1.3 7.6.3.3.4).
    ///
    /// The announcement and the served objects come from ONE derivation: a
    /// peer that receives a Complete hash in `PID_TYPE_INFORMATION` asks
    /// getTypes for exactly that hash (root and every dependency), and an
    /// identifier we announce but cannot serve leaves the peer unable to
    /// resolve the type, so it never matches. Registered into
    /// `served_types` only (read by the responders, never by announcement).
    #[cfg(feature = "xtypes-structural-assignability")]
    pub(super) fn announced_type_information(
        &self,
        type_name: &str,
        type_object: &CompleteTypeObject,
    ) -> Option<crate::protocol::discovery::types::TypeInformation> {
        use crate::core::types::ROS_HASH_SIZE;
        let registry = self.match_registry.as_ref()?;
        let store = registry.snapshot_type_store();
        let (info, objects) = crate::protocol::discovery::sedp::build::derive_announced_type_graph(
            type_object,
            &store,
        )?;
        let serves = |handle: &TypeObjectHandle, hash: &EquivalenceHash| {
            let id = TypeIdentifier::Complete(*hash);
            handle.type_id_complete == id || handle.type_id_complete_wire.as_ref() == Some(&id)
        };
        let registered_serves: Vec<bool> = {
            let registered = self.registered_types.read();
            objects
                .iter()
                .map(|o| registered.values().any(|h| serves(h, &o.complete_hash)))
                .collect()
        };
        let mut served = self.served_types.write();
        for (index, object) in objects.into_iter().enumerate() {
            let hash = object.complete_hash;
            if registered_serves[index] || served.values().any(|h| serves(h, &hash)) {
                continue;
            }
            let key: String = hash.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
            let fqn: Arc<str> = if index == 0 {
                Arc::from(type_name)
            } else {
                Arc::from(key.as_str())
            };
            let handle = Arc::new(TypeObjectHandle::new(
                self.distro,
                fqn,
                0,
                Arc::new([0u8; ROS_HASH_SIZE]),
                object.complete,
                object.minimal,
                TypeIdentifier::complete(hash),
                TypeIdentifier::minimal(object.minimal_hash),
            ));
            // The root goes under its type name, the key the security
            // serving policy judges (`DiscoveryFsm::type_lookup_serves`);
            // dependencies and a name already taken go under the hash.
            if index == 0 && !served.contains_key(type_name) {
                served.insert(type_name.to_string(), handle);
            } else {
                served.entry(key).or_insert(handle);
            }
        }
        Some(info)
    }

    /// Register `T`'s TypeObject -- and the transitive closure of the nested
    /// types it references by hash -- into `served_types`, the SERVE-ONLY map
    /// consulted by the two TypeLookup responders (the OMG `getTypes` service,
    /// DDS-XTypes v1.3 7.6.3, and the proprietary HTLK channel). Called once
    /// from writer and reader endpoint creation, because TypeLookup is
    /// participant-scoped in DDS, not writer-scoped: a read-only consumer
    /// must be able to serve too.
    ///
    /// # Why a second map instead of `registered_types`
    ///
    /// `resolve_type_info` (announce.rs) falls back to
    /// `registered_type(type_name)` when building a SEDP announcement for a
    /// type with no cached TypeObject. Putting a native type there would
    /// change what a peer receives during discovery on a vendor that lacks an
    /// EquivalenceHash and asks for the type by name instead -- a
    /// byte-neutrality break for this product's scored interop conformance.
    /// `served_types` is read only by the two responders, never by the
    /// announcement path, so registering here can never change a SEDP wire
    /// byte. `announce.rs` is untouched by this change.
    ///
    /// # Nested types: a documented no-op today
    ///
    /// A `CompleteTypeObject` references its nested struct/enum members by
    /// EquivalenceHash (DDS-XTypes v1.3 member `TypeIdentifier`); a peer that
    /// receives the root object immediately asks `getTypes` for each
    /// referenced hash, so registering the root alone would leave it just as
    /// stuck. `collect_nested_type_objects` recovers those nested objects,
    /// but only when given the ORIGINAL nesting-aware descriptor -- the one
    /// from which the root's hash-only member references were lowered in the
    /// first place. `T::get_type_object()` returns the already-lowered form,
    /// and `type_descriptor_from_xtypes` (the only public bridge back from a
    /// lowered `CompleteTypeObject`) collapses every hash-based member
    /// reference to an opaque placeholder unless given a `TypeRegistry`
    /// (see that function's own doc comment) -- which no caller here has,
    /// because the nested type has never been independently registered.
    /// Today no in-tree `#[derive(DDS)]` type can even produce a nested
    /// member reference in the first place (the proc-macro only supports
    /// primitive / String / byte-vector fields), so this call never has
    /// anything to find. It is wired up so a future nesting-aware codegen
    /// path, or a manually written `impl DDS` paired with a registry, makes
    /// it live without another change here; `build_served_handle` and its
    /// hex-of-minimal-hash keying convention are exercised directly by the
    /// unit tests below with a hand-built nested descriptor.
    #[cfg(feature = "xtypes-structural-assignability")]
    pub(crate) fn register_served_type<T: crate::dds::DDS>(&self) {
        let type_name = T::type_descriptor().type_name;

        // Do the work once per type: N writers/readers on the same type must
        // not rebuild the handle N times. The write lock below is only ever
        // taken when there is something new to insert.
        if self.served_types.read().contains_key(type_name) {
            return;
        }

        let Some(complete) = T::get_type_object() else {
            // Manual DDS impls that opt out of TypeObject have nothing to serve.
            return;
        };

        // Nested types, first from the type itself. Generated code knows its
        // members' TypeObjects: it builds each one to compute the
        // EquivalenceHash it puts in the parent, so handing them over costs it
        // nothing. Types that do not override `nested_type_objects` return an
        // empty list and the loop below is a no-op.
        let mut nested: HashMap<crate::xtypes::EquivalenceHash, CompleteTypeObject> =
            HashMap::new();
        for declared in T::nested_type_objects() {
            let Ok(hash) = declared.compute_equivalence_hash() else {
                continue;
            };
            nested.insert(hash, declared);
        }
        // Reuse dependencies registered before endpoint creation as well as
        // those declared by DDS::nested_type_objects.
        let mut complete_refs_store = self.snapshot_local_type_objects();
        complete_refs_store.extend(nested.clone());
        // Legacy dynamic objects can still refer to Minimal hashes internally.
        // Retain those lookup keys alongside every distinct Complete identity.
        let minimal_keys: Vec<_> = nested
            .values()
            .filter_map(|object| {
                let minimal = crate::dynamic::complete_to_minimal_with_dependencies(
                    object,
                    &complete_refs_store,
                )?;
                Some((minimal.compute_equivalence_hash().ok()?, object.clone()))
            })
            .collect();
        for (hash, object) in minimal_keys {
            nested.entry(hash).or_insert(object);
        }
        // Then whatever the dynamic walk can still add. It cannot resolve a
        // hash-based member reference without a registry (it collapses those to
        // an opaque placeholder, see `type_descriptor_from_xtypes`), so this
        // only contributes for inline member layouts.
        let dynamic_desc = crate::dynamic::type_descriptor_from_xtypes(&complete);
        crate::dynamic::collect_nested_type_objects(&dynamic_desc, &mut nested);
        complete_refs_store.extend(nested.clone());

        let mut to_insert: HashMap<String, Arc<TypeObjectHandle>> = HashMap::new();
        let mut dependency_objects = HashMap::new();

        if let Some(root) = build_served_handle(
            self.distro,
            Arc::from(type_name),
            &complete,
            &complete_refs_store,
        ) {
            to_insert.insert(type_name.to_string(), Arc::clone(&root));
            // Also key by the handle's own fqn, mirroring `cache_registered_type`'s
            // dual keying; for a native (non-ROS 2) type the two coincide.
            to_insert.insert(root.fqn.to_string(), root);
        }

        for (source_hash, nested_complete) in &nested {
            let key: String = source_hash
                .as_bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            if let Some(handle) = build_served_handle(
                self.distro,
                Arc::from(key.as_str()),
                nested_complete,
                &complete_refs_store,
            ) {
                let minimal_key: String = match &handle.type_id_minimal {
                    TypeIdentifier::Minimal(hash) => {
                        hash.as_bytes().iter().map(|b| format!("{b:02x}")).collect()
                    }
                    _ => continue,
                };
                for identifier in [&handle.type_id_complete, &handle.type_id_minimal] {
                    if let TypeIdentifier::Complete(hash) | TypeIdentifier::Minimal(hash) =
                        identifier
                    {
                        dependency_objects.insert(*hash, handle.complete.clone());
                    }
                }
                to_insert
                    .entry(minimal_key)
                    .or_insert_with(|| Arc::clone(&handle));
                to_insert.entry(key).or_insert(handle);
            }
        }

        if to_insert.is_empty() {
            return;
        }

        if let Some(registry) = &self.match_registry {
            // Publish dependencies for SEDP and structural resolution. The
            // root remains serve-only, as documented by register_served_type.
            registry.register_type_objects(dependency_objects);
        }
        let mut map = self.served_types.write();
        for (key, handle) in to_insert {
            map.entry(key).or_insert(handle);
        }
    }
}

/// Build a servable handle with both equivalence graphs. The dependency store
/// may be keyed by either identity; conversion indexes its Complete objects by
/// their actual hash before resolving references (XTypes 1.3 7.3.4).
#[cfg(feature = "xtypes-structural-assignability")]
fn build_served_handle(
    distro: Distro,
    fqn: Arc<str>,
    complete: &CompleteTypeObject,
    complete_refs_store: &HashMap<EquivalenceHash, CompleteTypeObject>,
) -> Option<Arc<TypeObjectHandle>> {
    use crate::core::types::ROS_HASH_SIZE;

    let minimal =
        crate::dynamic::complete_to_minimal_with_dependencies(complete, complete_refs_store)?;
    let complete_hash = complete.compute_equivalence_hash().ok()?;
    let minimal_hash = minimal.compute_equivalence_hash().ok()?;

    let handle = TypeObjectHandle::new(
        distro,
        fqn,
        0,
        Arc::new([0u8; ROS_HASH_SIZE]),
        complete.clone(),
        minimal,
        TypeIdentifier::complete(complete_hash),
        TypeIdentifier::minimal(minimal_hash),
    );

    let complete_wire =
        crate::dynamic::complete_type_object_with_complete_refs(complete, complete_refs_store);
    let handle = match complete_wire.compute_equivalence_hash() {
        Ok(wire_hash) => {
            handle.with_complete_wire(complete_wire, TypeIdentifier::complete(wire_hash))
        }
        Err(_) => handle,
    };

    Some(Arc::new(handle))
}

#[cfg(all(test, feature = "xtypes-structural-assignability"))]
mod native_type_registration_tests {
    use super::build_served_handle;
    use crate::dds::Participant;
    use crate::generated::temperature::Temperature;
    use crate::test_support::domains::unique_domain;
    use crate::xtypes::{CompleteTypeObject, EquivalenceHash, TypeIdentifier};
    use crate::TransportMode;
    use std::collections::HashMap;

    /// A participant that creates an ordinary typed endpoint must be able to
    /// serve that type to a peer that asks for it, and must do so WITHOUT
    /// changing what `resolve_type_info` (announce.rs) puts on the wire.
    ///
    /// Both TypeLookup responders read `served_types`: the OMG `getTypes`
    /// service (DDS-XTypes v1.3 7.6.3, always served, used by a peer that
    /// lacks a type's EquivalenceHash) looks the map up by hash
    /// across its values, and the proprietary HTLK channel looks it up by type
    /// name. An ordinary typed writer must write both maps, otherwise a
    /// participant built the ordinary way could not answer either question
    /// about its own type.
    #[test]
    fn a_native_typed_writer_registers_its_type_for_the_lookup_responders() {
        let domain = unique_domain();
        let participant = Participant::builder("native_type_registration_writer")
            .domain_id(domain.id())
            .with_transport(TransportMode::IntraProcess)
            .build()
            .expect("participant");
        let _writer = participant
            .topic::<Temperature>("native_type_registration/temperature")
            .expect("topic")
            .writer()
            .build()
            .expect("writer");

        let descriptor = <Temperature as crate::dds::DDS>::type_descriptor();
        assert!(
            participant.served_type(descriptor.type_name).is_some(),
            "a typed writer must register its TypeObject under the DDS type name '{}' \
             in the SERVE-ONLY map, otherwise the OMG getTypes and HTLK responders \
             have nothing to serve",
            descriptor.type_name
        );
        assert!(
            participant.registered_type(descriptor.type_name).is_none(),
            "a native type must never enter `registered_types`: that map is also read \
             as an announcement fallback (announce.rs resolve_type_info), and a native \
             type there would change what a peer receives during SEDP discovery"
        );
    }

    /// TypeLookup is participant-scoped in DDS, not writer-scoped: a
    /// read-only consumer must be able to serve its type too.
    #[test]
    fn a_native_typed_reader_registers_its_type_for_the_lookup_responders() {
        let domain = unique_domain();
        let participant = Participant::builder("native_type_registration_reader")
            .domain_id(domain.id())
            .with_transport(TransportMode::IntraProcess)
            .build()
            .expect("participant");
        let _reader = participant
            .topic::<Temperature>("native_type_registration/temperature")
            .expect("topic")
            .reader()
            .build()
            .expect("reader");

        let descriptor = <Temperature as crate::dds::DDS>::type_descriptor();
        assert!(
            participant.served_type(descriptor.type_name).is_some(),
            "a typed reader must register its TypeObject under the DDS type name '{}' \
             in the SERVE-ONLY map, otherwise the OMG getTypes and HTLK responders \
             have nothing to serve",
            descriptor.type_name
        );
        assert!(
            participant.registered_type(descriptor.type_name).is_none(),
            "a native type must never enter `registered_types`, reader side included"
        );
    }

    /// Two writers on the same type must not rebuild the handle twice: the
    /// second `register_served_type::<T>()` call is a no-op that leaves the
    /// first handle (checked by pointer identity via `Arc::ptr_eq`) in place.
    #[test]
    fn two_writers_on_the_same_type_share_one_served_handle() {
        let domain = unique_domain();
        let participant = Participant::builder("native_type_registration_dedup")
            .domain_id(domain.id())
            .with_transport(TransportMode::IntraProcess)
            .build()
            .expect("participant");

        let _writer1 = participant
            .topic::<Temperature>("native_type_registration/temperature/1")
            .expect("topic")
            .writer()
            .build()
            .expect("writer1");
        let descriptor = <Temperature as crate::dds::DDS>::type_descriptor();
        let first = participant
            .served_type(descriptor.type_name)
            .expect("first writer registers the type");

        let _writer2 = participant
            .topic::<Temperature>("native_type_registration/temperature/2")
            .expect("topic")
            .writer()
            .build()
            .expect("writer2");
        let second = participant
            .served_type(descriptor.type_name)
            .expect("type is still servable after the second writer");

        assert!(
            std::sync::Arc::ptr_eq(&first, &second),
            "a second writer on an already-registered type must reuse the existing \
             handle, not rebuild and replace it"
        );
    }

    /// `build_served_handle` is the mechanism `register_served_type` would
    /// use for a type's transitive nested closure, keyed by the hex of the
    /// nested type's MINIMAL EquivalenceHash -- exactly the convention
    /// `Participant::register_nested_type_objects` (live_capture.rs) already
    /// uses for peer-supplied nested types.
    ///
    /// This test cannot go through `register_served_type::<T>()` end to end:
    /// no `#[derive(DDS)]` type in this crate can reference a nested type in
    /// the first place (the proc-macro only supports primitive / String /
    /// byte-vector fields -- see `register_served_type`'s doc comment for why
    /// the `T::get_type_object()` bridge is a no-op today), and
    /// `crates/hdds/src/generated/` holds only the flat `Temperature` struct.
    /// So this exercises the real, un-fabricated nested-object collector
    /// (`collect_nested_type_objects`) against a hand-built nesting
    /// descriptor -- the same technique already used by the existing
    /// `structural_assignability_fix` tests -- and checks that the resulting
    /// handle lands under the expected minimal-hash key.
    /// A type that declares its nested TypeObjects gets them served too.
    ///
    /// This is the case a code generator produces: the parent's
    /// `CompleteTypeObject` names its members by `EquivalenceHash`, so the
    /// nested objects are reachable only because the type hands them over
    /// through `nested_type_objects`. The dynamic walk cannot recover them,
    /// see the note in `register_served_type`.
    #[test]
    fn a_type_that_declares_nested_objects_gets_them_served() {
        use crate::dds::DDS;
        use crate::xtypes::{
            CompleteStructHeader, CompleteStructType, CompleteTypeDetail, StructTypeFlag,
        };

        fn bare_struct(name: &str) -> CompleteTypeObject {
            CompleteTypeObject::Struct(CompleteStructType {
                struct_flags: StructTypeFlag::IS_FINAL,
                header: CompleteStructHeader {
                    base_type: None,
                    detail: CompleteTypeDetail::new(name),
                },
                member_seq: Vec::new(),
            })
        }

        struct DeclaresNested;
        impl DDS for DeclaresNested {
            fn type_descriptor() -> &'static crate::core::types::TypeDescriptor {
                static DESC: crate::core::types::TypeDescriptor =
                    crate::core::types::TypeDescriptor::new(
                        0x4e45_5354,
                        "DeclaresNested",
                        0,
                        1,
                        false,
                        &[],
                    );
                &DESC
            }
            fn get_type_object() -> Option<CompleteTypeObject> {
                Some(bare_struct("DeclaresNested"))
            }
            fn nested_type_objects() -> Vec<CompleteTypeObject> {
                vec![bare_struct("DeclaredInner")]
            }
            fn encode(
                &self,
                _buf: &mut [u8],
                _version: crate::dds::CdrVersion,
            ) -> crate::Result<usize> {
                Ok(0)
            }
            fn decode(_buf: &[u8], _version: crate::dds::CdrVersion) -> crate::Result<Self> {
                Ok(Self)
            }
        }

        let domain = unique_domain();
        let participant = Participant::builder("native_type_registration_nested")
            .domain_id(domain.id())
            .with_transport(TransportMode::IntraProcess)
            .build()
            .expect("participant");
        participant.register_served_type::<DeclaresNested>();

        assert!(
            participant.served_type("DeclaresNested").is_some(),
            "the declaring type itself must be servable"
        );

        // The key a peer asks by: hex of the nested object's MINIMAL
        // EquivalenceHash, derived here the same way `register_served_type`
        // derives it, so the test would catch a change of keying convention.
        let inner = bare_struct("DeclaredInner");
        let minimal = crate::dynamic::complete_to_minimal_type_object(&inner)
            .expect("a struct CompleteTypeObject always has a Minimal counterpart");
        let minimal_hash = minimal
            .compute_equivalence_hash()
            .expect("CDR2 encoding of a bare struct");
        let key: String = minimal_hash
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();

        let served = participant.served_type(&key).unwrap_or_else(|| {
            panic!(
                "the nested object declared through `nested_type_objects` must be \
                 servable under its minimal-hash key {key}, otherwise a consumer that \
                 receives the parent and asks for its member gets nothing"
            )
        });
        assert_eq!(
            served.type_id_minimal,
            TypeIdentifier::minimal(minimal_hash),
            "the served nested handle must carry the exact identifier a peer requests"
        );

        assert!(
            participant.registered_type("DeclaresNested").is_none(),
            "declaring nested objects must not leak the type into `registered_types`, \
             which announce.rs reads as a SEDP fallback"
        );
    }

    #[test]
    fn a_nested_type_is_registered_under_its_minimal_hash_key() {
        use crate::dynamic::{
            EnumDescriptor, EnumVariant, FieldDescriptor, TypeDescriptor, TypeKind,
        };

        let inner_enum = TypeDescriptor::new(
            "InnerEnum",
            TypeKind::Enum(EnumDescriptor::new(vec![EnumVariant::new("A", 0)])),
        );
        let outer = TypeDescriptor::struct_type(
            "OuterStruct",
            vec![FieldDescriptor::new(
                "inner",
                std::sync::Arc::new(TypeDescriptor::new(
                    "InnerEnum",
                    TypeKind::Nested(std::sync::Arc::new(inner_enum)),
                )),
            )],
        );

        let mut nested: HashMap<EquivalenceHash, CompleteTypeObject> = HashMap::new();
        crate::dynamic::collect_nested_type_objects(&outer, &mut nested);
        assert_eq!(
            nested.len(),
            1,
            "the outer struct's one nested enum member must collect exactly one entry"
        );
        let (min_hash, nested_complete) = nested.iter().next().expect("checked len == 1");

        let handle = build_served_handle(
            crate::core::types::Distro::Humble,
            std::sync::Arc::from("unused-fqn-for-this-test"),
            nested_complete,
            &nested,
        )
        .expect("a struct/enum CompleteTypeObject always has a Minimal counterpart");

        let expected_key: String = min_hash
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(
            handle.type_id_minimal,
            TypeIdentifier::minimal(*min_hash),
            "the handle must be keyed under the exact hash a peer will request"
        );
        assert_eq!(expected_key.len(), 28, "hex of a 14-byte hash is 28 chars");

        // Sanity: the helper's dependency-rewrite path must not have altered
        // the discriminant kind (the enum has no nested references of its
        // own, so the wire form is a byte-identical clone).
        assert!(matches!(handle.complete, CompleteTypeObject::Enumerated(_)));
    }
}

#[cfg(all(test, feature = "xtypes-structural-assignability"))]
#[path = "ros_type_registration_tests.rs"]
mod ros_type_registration_tests;
