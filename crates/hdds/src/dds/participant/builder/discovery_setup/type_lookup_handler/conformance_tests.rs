// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use super::*;
use crate::core::discovery::matcher::TypeObjectResolver;
use crate::core::ser::traits::Cdr2Decode;
use crate::dds::{Participant, DDS};
use crate::xtypes::*;

fn id(object: &CompleteTypeObject) -> TypeIdentifier {
    TypeIdentifier::Complete(object.compute_equivalence_hash().unwrap())
}

fn structure(name: &str, members: Vec<TypeIdentifier>) -> CompleteTypeObject {
    CompleteTypeObject::Struct(CompleteStructType {
        struct_flags: StructTypeFlag::IS_FINAL,
        header: CompleteStructHeader {
            base_type: None,
            detail: CompleteTypeDetail::new(name),
        },
        member_seq: members
            .into_iter()
            .enumerate()
            .map(|(i, member_type_id)| CompleteStructMember {
                common: CommonStructMember {
                    member_id: i as u32,
                    member_flags: MemberFlag::TRY_CONSTRUCT1,
                    member_type_id,
                },
                detail: CompleteMemberDetail::new(format!("field{i}")),
            })
            .collect(),
    })
}

fn graph() -> (CompleteTypeObject, Vec<CompleteTypeObject>) {
    let leaf = structure("Leaf", vec![TypeIdentifier::Primitive(TypeKind::TK_INT32)]);
    let renamed_leaf = structure(
        "OtherLeaf",
        vec![TypeIdentifier::Primitive(TypeKind::TK_INT32)],
    );
    let enumeration = CompleteTypeObject::Enumerated(CompleteEnumeratedType {
        enum_flags: StructTypeFlag::IS_APPENDABLE,
        header: CompleteEnumeratedHeader {
            bit_bound: 32,
            detail: CompleteTypeDetail::new("Choice"),
        },
        literal_seq: vec![CompleteEnumeratedLiteral {
            common: CommonEnumeratedLiteral {
                value: 0,
                flags: EnumeratedLiteralFlag::IS_DEFAULT,
            },
            detail: CompleteMemberDetail::new("Zero"),
        }],
    });
    let bitmask = CompleteTypeObject::Bitmask(CompleteBitmaskType {
        bitmask_flags: BitmaskTypeFlag::empty(),
        header: CompleteBitmaskHeader {
            bit_bound: 16,
            detail: CompleteTypeDetail::new("Flags"),
        },
        flag_seq: vec![CompleteBitflag {
            common: CommonBitflag {
                position: 1,
                flags: BitflagFlag(0),
            },
            detail: CompleteMemberDetail::new("Enabled"),
        }],
    });
    let union = CompleteTypeObject::Union(CompleteUnionType {
        union_flags: UnionTypeFlag::IS_FINAL,
        header: CompleteUnionHeader {
            discriminator: id(&enumeration),
            discriminator_flags: MemberFlag::TRY_CONSTRUCT1,
            detail: CompleteTypeDetail::new("Payload"),
        },
        member_seq: vec![CompleteUnionMember {
            common: CommonUnionMember {
                member_id: 1,
                member_flags: MemberFlag::TRY_CONSTRUCT1,
                member_type_id: id(&bitmask),
                label_seq: vec![0],
            },
            detail: CompleteMemberDetail::new("flags"),
        }],
    });
    let alias = CompleteTypeObject::Alias(CompleteAliasType {
        alias_flags: AliasTypeFlag::empty(),
        header: CompleteAliasHeader {
            detail: CompleteTypeDetail::new("Alias"),
        },
        body: CompleteAliasBody {
            common: CommonAliasBody {
                related_flags: TypeRelationFlag::empty(),
                related_type: id(&union),
            },
            ann_builtin: None,
            ann_custom: None,
        },
    });
    let header = PlainCollectionHeader {
        equiv_kind: EquivalenceKind::Complete,
        element_flags: CollectionElementFlag::TRY_CONSTRUCT1,
    };
    let array = TypeIdentifier::PlainArrayLarge(PlainArrayLElemDefn {
        header,
        array_bound_seq: vec![300],
        element_identifier: Box::new(id(&leaf)),
    });
    let sequence = TypeIdentifier::PlainSequenceLarge(PlainSequenceLElemDefn {
        header,
        bound: 400,
        element_identifier: Box::new(array),
    });
    let root = structure("LookupGraph", vec![id(&alias), sequence, id(&renamed_leaf)]);
    // Parents precede their dependencies: conversion must not depend on input order.
    (
        root,
        vec![alias, union, bitmask, enumeration, leaf, renamed_leaf],
    )
}

struct GeneratedGraph;
impl DDS for GeneratedGraph {
    fn type_descriptor() -> &'static crate::core::types::TypeDescriptor {
        static DESC: crate::core::types::TypeDescriptor =
            crate::core::types::TypeDescriptor::new(1, "LookupGraph", 0, 1, false, &[]);
        &DESC
    }
    fn get_type_object() -> Option<CompleteTypeObject> {
        Some(graph().0)
    }
    fn nested_type_objects() -> Vec<CompleteTypeObject> {
        graph().1
    }
    fn encode(&self, _: &mut [u8], _: crate::dds::CdrVersion) -> crate::Result<usize> {
        Ok(0)
    }
    fn decode(_: &[u8], _: crate::dds::CdrVersion) -> crate::Result<Self> {
        Ok(Self)
    }
}

struct RegisteredGraph;
impl DDS for RegisteredGraph {
    fn type_descriptor() -> &'static crate::core::types::TypeDescriptor {
        GeneratedGraph::type_descriptor()
    }
    fn get_type_object() -> Option<CompleteTypeObject> {
        GeneratedGraph::get_type_object()
    }
    fn encode(&self, _: &mut [u8], _: crate::dds::CdrVersion) -> crate::Result<usize> {
        Ok(0)
    }
    fn decode(_: &[u8], _: crate::dds::CdrVersion) -> crate::Result<Self> {
        Ok(Self)
    }
}

fn references(id: &TypeIdentifier, kind: EquivalenceKind, out: &mut Vec<EquivalenceHash>) {
    match id {
        TypeIdentifier::Complete(h) => {
            assert_eq!(kind, EquivalenceKind::Complete);
            out.push(*h);
        }
        TypeIdentifier::Minimal(h) => {
            assert_eq!(kind, EquivalenceKind::Minimal);
            out.push(*h);
        }
        TypeIdentifier::PlainSequenceLarge(d) => {
            assert_eq!(d.header.equiv_kind, kind);
            references(&d.element_identifier, kind, out);
        }
        TypeIdentifier::PlainArrayLarge(d) => {
            assert_eq!(d.header.equiv_kind, kind);
            references(&d.element_identifier, kind, out);
        }
        _ => {}
    }
}

fn complete_references(object: &CompleteTypeObject) -> Vec<EquivalenceHash> {
    let mut out = Vec::new();
    let mut visit = |id: &TypeIdentifier| references(id, EquivalenceKind::Complete, &mut out);
    match object {
        CompleteTypeObject::Struct(s) => {
            for m in &s.member_seq {
                visit(&m.common.member_type_id);
            }
        }
        CompleteTypeObject::Union(u) => {
            visit(&u.header.discriminator);
            for m in &u.member_seq {
                visit(&m.common.member_type_id);
            }
        }
        CompleteTypeObject::Alias(a) => visit(&a.body.common.related_type),
        _ => {}
    }
    out
}

// XTypes 1.3 7.3.4 and 7.6.3: two participant stores exchange the real
// getTypes request/reply bytes, without timing or transport dependencies.
#[test]
fn native_graph_type_lookup_round_trip_resolves_every_identifier() {
    let mut producer = Participant::builder("type_lookup_producer")
        .domain_id(228)
        .with_transport(crate::TransportMode::IntraProcess)
        .build()
        .unwrap();
    let mut consumer = Participant::builder("type_lookup_consumer")
        .domain_id(228)
        .with_transport(crate::TransportMode::IntraProcess)
        .build()
        .unwrap();
    let fsm = Arc::new(crate::core::discovery::multicast::DiscoveryFsm::new(
        producer.guid(),
        30_000,
    ));
    let registry = Arc::new(
        crate::dds::match_notification::MatchNotificationRegistry::new(
            &fsm,
            producer.guid().prefix,
        ),
    );
    Arc::get_mut(&mut producer).unwrap().match_registry = Some(registry);
    let consumer_fsm = Arc::new(crate::core::discovery::multicast::DiscoveryFsm::new(
        consumer.guid(),
        30_000,
    ));
    let consumer_registry = Arc::new(
        crate::dds::match_notification::MatchNotificationRegistry::new(
            &consumer_fsm,
            consumer.guid().prefix,
        ),
    );
    Arc::get_mut(&mut consumer).unwrap().match_registry = Some(consumer_registry);
    producer.register_served_type::<GeneratedGraph>();
    let root = producer.served_type("LookupGraph").unwrap();
    let registry = producer.match_registry.as_ref().unwrap();
    let store = registry.snapshot_type_store();
    assert!(registry.unresolved_type_refs(&root.complete).is_empty());
    let info = crate::protocol::discovery::sedp::build::derive_type_information_with_deps(
        &root.complete,
        &store,
    )
    .unwrap();
    let minimal = info.minimal.as_ref().unwrap();
    let complete = info.complete.as_ref().unwrap();
    assert_eq!(TypeIdentifier::Minimal(minimal.hash), root.type_id_minimal);
    assert_eq!(
        TypeIdentifier::Complete(complete.hash),
        root.type_id_complete
    );
    assert_eq!(minimal.dependent_typeids.len(), 5);
    assert_eq!(complete.dependent_typeids.len(), 6);
    let wire = crate::protocol::discovery::sedp::build::encode_type_information_parameter(&info)
        .unwrap()
        .unwrap();
    let decoded =
        crate::protocol::discovery::sedp::parse::parse_type_information(&wire[4..]).unwrap();
    assert_eq!(decoded, info);
    let TypeIdentifier::Complete(root_hash) = root.type_id_complete else {
        panic!("root id");
    };
    let mut pending = vec![root_hash];
    let mut received = HashMap::new();
    let mut minimal_hashes = Vec::new();
    let mut writer = [0; 16];
    writer[..12].copy_from_slice(&consumer.guid().prefix);
    writer[12..].copy_from_slice(&RTPS_ENTITYID_TYPELOOKUP_REQUEST_WRITER);
    let mut sequence = 0;
    while let Some(hash) = pending.pop() {
        if received.contains_key(&hash) {
            continue;
        }
        sequence += 1;
        let request =
            encode_omg_get_types_request(&writer, 0, sequence, &[(EK_COMPLETE, *hash.as_bytes())])
                .unwrap();
        let decoded = parse_omg_get_types_request(&request).unwrap();
        assert_eq!(decoded.type_ids, vec![(EK_COMPLETE, *hash.as_bytes())]);
        let (_, handle) =
            lookup_named_type_object(&producer.served_types.read(), EK_COMPLETE, *hash.as_bytes())
                .expect("every reference is served");
        let reply = encode_omg_get_types_reply(
            &writer,
            0,
            sequence,
            &[(EK_COMPLETE, *hash.as_bytes(), Arc::clone(&handle))],
        )
        .unwrap();
        let decoded = parse_omg_get_types_reply(&reply).unwrap();
        assert_eq!(decoded.pairs.len(), 1);
        let (claimed, object) = &decoded.pairs[0];
        assert_eq!(*claimed, *hash.as_bytes());
        assert_eq!(object.compute_equivalence_hash().unwrap(), hash);
        pending.extend(complete_references(object));
        received.insert(hash, object.clone());
        // Also request its Minimal identity and decode the returned outer
        // TypeObject directly; the production receive cache keeps Complete only.
        let TypeIdentifier::Minimal(min_hash) = handle.type_id_minimal else {
            panic!("minimal id");
        };
        minimal_hashes.push(min_hash);
        sequence += 1;
        let request = encode_omg_get_types_request(
            &writer,
            0,
            sequence,
            &[(EK_MINIMAL, *min_hash.as_bytes())],
        )
        .unwrap();
        let decoded = parse_omg_get_types_request(&request).unwrap();
        assert_eq!(decoded.type_ids, vec![(EK_MINIMAL, *min_hash.as_bytes())]);
        let (_, minimal_handle) = lookup_named_type_object(
            &producer.served_types.read(),
            EK_MINIMAL,
            *min_hash.as_bytes(),
        )
        .expect("Minimal identity is served");
        let reply = encode_omg_get_types_reply(
            &writer,
            0,
            sequence,
            &[(EK_MINIMAL, *min_hash.as_bytes(), minimal_handle)],
        )
        .unwrap();
        // Encapsulation + fixed reply header/sequence count + 15-byte id,
        // rounded to four, then outer TypeObject DHEADER and EK octet.
        let mut offset = 4 + 0x3c + 16;
        let size = u32::from_le_bytes(reply[offset..offset + 4].try_into().unwrap()) as usize;
        assert_eq!(reply[offset + 4], EK_MINIMAL);
        assert_eq!(
            EquivalenceHash::compute(&reply[offset..offset + 4 + size]),
            min_hash
        );
        offset += 5;
        let minimal = MinimalTypeObject::decode_cdr2_le_at(&reply, &mut offset).unwrap();
        let mut ids = Vec::new();
        match minimal {
            MinimalTypeObject::Struct(s) => {
                for m in s.member_seq {
                    references(&m.common.member_type_id, EquivalenceKind::Minimal, &mut ids);
                }
            }
            MinimalTypeObject::Union(u) => {
                references(&u.header.discriminator, EquivalenceKind::Minimal, &mut ids);
                for m in u.member_seq {
                    references(&m.common.member_type_id, EquivalenceKind::Minimal, &mut ids);
                }
            }
            MinimalTypeObject::Alias(a) => references(
                &a.body.common.related_type,
                EquivalenceKind::Minimal,
                &mut ids,
            ),
            _ => {}
        }
        for hash in ids {
            assert!(lookup_named_type_object(
                &producer.served_types.read(),
                EK_MINIMAL,
                *hash.as_bytes()
            )
            .is_some());
        }
    }
    assert_eq!(received.len(), 7);
    // Separate registrations with one shared Minimal identity must retain
    // both Complete objects for peers that request the named descriptions.
    for object in received.values().filter(|object| matches!(object,
        CompleteTypeObject::Struct(s) if s.header.detail.type_name == "Leaf" || s.header.detail.type_name == "OtherLeaf")) {
        let hash = crate::dynamic::complete_type_object_minimal_hash(object).unwrap();
        consumer.register_nested_type_objects(HashMap::from([(hash, object.clone())]));
    }
    for object in received.values().filter(|object| matches!(object,
        CompleteTypeObject::Struct(s) if s.header.detail.type_name == "Leaf" || s.header.detail.type_name == "OtherLeaf")) {
        assert!(lookup_named_type_object(&consumer.registered_types.read(), EK_COMPLETE,
            *object.compute_equivalence_hash().unwrap().as_bytes()).is_some());
    }
    // A manually implemented DDS type can supply its dependencies through
    // participant registration instead of overriding nested_type_objects.
    let dependencies = received
        .iter()
        .filter(|(hash, _)| **hash != root_hash)
        .map(|(hash, object)| (*hash, object.clone()))
        .collect();
    consumer.register_nested_type_objects(dependencies);
    // Incremental registration must resolve earlier objects even without
    // a discovery matcher (for example, on an in-process participant).
    let registry = Arc::get_mut(&mut consumer).unwrap().match_registry.take();
    consumer
        .register_nested_type_objects(HashMap::from([(root_hash, received[&root_hash].clone())]));
    assert!(lookup_named_type_object(
        &consumer.registered_types.read(),
        EK_COMPLETE,
        *root_hash.as_bytes()
    )
    .is_some());
    Arc::get_mut(&mut consumer).unwrap().match_registry = registry;
    consumer.register_served_type::<RegisteredGraph>();
    let consumer_root = consumer
        .served_type("LookupGraph")
        .expect("previously registered dependencies are reused");
    assert_eq!(consumer_root.type_id_complete, root.type_id_complete);
    assert_eq!(consumer_root.type_id_minimal, root.type_id_minimal);
    for hash in received.keys() {
        let object = lookup_named_type_object(
            &consumer.registered_types.read(),
            EK_COMPLETE,
            *hash.as_bytes(),
        )
        .or_else(|| {
            lookup_named_type_object(&consumer.served_types.read(), EK_COMPLETE, *hash.as_bytes())
        });
        assert!(object.is_some());
    }
    let resolver = consumer
        .match_registry
        .as_ref()
        .unwrap()
        .snapshot_resolver();
    assert_eq!(minimal_hashes.len(), received.len());
    for hash in minimal_hashes {
        assert!(lookup_named_type_object(
            &consumer.registered_types.read(),
            EK_MINIMAL,
            *hash.as_bytes()
        )
        .or_else(|| {
            lookup_named_type_object(&consumer.served_types.read(), EK_MINIMAL, *hash.as_bytes())
        })
        .is_some());
        if TypeIdentifier::Minimal(hash) != root.type_id_minimal {
            assert!(resolver.resolve_minimal(&hash).is_some());
        }
    }
}
