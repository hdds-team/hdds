// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Two structurally identical types with different names share one Minimal
//! hash (the Minimal TypeObject carries no type name, DDS-XTypes v1.3
//! 7.3.4.8) but have distinct Complete hashes. A member typed with one of
//! them must reference THAT type's Complete identifier, and every Complete
//! identifier announced in PID_TYPE_INFORMATION must be servable by the OMG
//! getTypes responder (7.6.3.3.4), whatever order the types were registered
//! in and whatever a HashMap iteration order happens to be.

use super::*;
use crate::dds::Participant;
use crate::dynamic::{
    collect_nested_type_objects, complete_type_object_minimal_hash, type_descriptor_to_xtypes,
    type_descriptor_to_xtypes_complete, Extensibility, FieldDescriptor, PrimitiveKind,
    SequenceDescriptor, TypeDescriptor, TypeKind,
};
use crate::xtypes::{CompleteTypeObject, EquivalenceHash, TypeIdentifier};
use std::collections::HashMap;

const OUTER: &str = "Test::F_S__seq10_F_S__seq20_uint32";

/// `@final struct <name> { sequence<uint32,20> x1; };`
fn seq20_uint32(name: &str) -> Arc<TypeDescriptor> {
    let element = Arc::new(TypeDescriptor::primitive("uint32", PrimitiveKind::U32));
    Arc::new(
        TypeDescriptor::struct_type(
            name,
            vec![FieldDescriptor::new(
                "x1",
                Arc::new(TypeDescriptor::new(
                    "",
                    TypeKind::Sequence(SequenceDescriptor::bounded(element, 20)),
                )),
            )],
        )
        .with_extensibility(Extensibility::Final),
    )
}

/// `@final struct F_S__seq10_F_S__seq20_uint32 { sequence<inner,10> x1; };`
/// with the element wrapped in `Nested`, as the XML loader builds it.
fn outer(inner: &Arc<TypeDescriptor>) -> Arc<TypeDescriptor> {
    let element = Arc::new(TypeDescriptor::new("", TypeKind::Nested(Arc::clone(inner))));
    Arc::new(
        TypeDescriptor::struct_type(
            OUTER,
            vec![FieldDescriptor::new(
                "x1",
                Arc::new(TypeDescriptor::new(
                    "",
                    TypeKind::Sequence(SequenceDescriptor::bounded(element, 10)),
                )),
            )],
        )
        .with_extensibility(Extensibility::Final),
    )
}

/// The map the dds-xtypes driver hands `register_nested_type_objects`:
/// nested objects collected from each descriptor, each top-level type keyed
/// by its Minimal hash, a differently named type of the same Minimal hash
/// parked under its Complete hash.
fn driver_store(types: &[Arc<TypeDescriptor>]) -> HashMap<EquivalenceHash, CompleteTypeObject> {
    let mut nested = HashMap::new();
    for td in types {
        collect_nested_type_objects(td, &mut nested);
        let to = type_descriptor_to_xtypes(td).unwrap();
        let hash = complete_type_object_minimal_hash(&to).unwrap();
        match nested.get(&hash) {
            None => {
                nested.insert(hash, to);
            }
            Some(existing) if existing.type_name() != to.type_name() => {
                let chash = to.compute_equivalence_hash().unwrap();
                nested.entry(chash).or_insert(to);
            }
            Some(_) => {}
        }
    }
    nested
}

fn participant_with_registry() -> Arc<Participant> {
    let mut participant = Participant::builder("nested_name_collision")
        .domain_id(228)
        .with_transport(crate::TransportMode::IntraProcess)
        .build()
        .unwrap();
    let fsm = Arc::new(crate::core::discovery::multicast::DiscoveryFsm::new(
        participant.guid(),
        30_000,
    ));
    let registry = Arc::new(
        crate::dds::match_notification::MatchNotificationRegistry::new(
            &fsm,
            participant.guid().prefix,
        ),
    );
    Arc::get_mut(&mut participant).unwrap().match_registry = Some(registry);
    participant
}

/// The single Complete hash referenced by `object`'s first member, through
/// its sequence element.
fn element_ref(object: &CompleteTypeObject) -> TypeIdentifier {
    let CompleteTypeObject::Struct(s) = object else {
        panic!("struct expected");
    };
    match &s.member_seq[0].common.member_type_id {
        TypeIdentifier::PlainSequenceSmall(d) => (*d.element_identifier).clone(),
        TypeIdentifier::PlainSequenceLarge(d) => (*d.element_identifier).clone(),
        other => panic!("sequence member expected, got {other:?}"),
    }
}

/// Serve `hash` through the getTypes lookup and reply codec, as the
/// responder does, and return the object the peer decodes.
fn serve(participant: &Participant, hash: EquivalenceHash) -> CompleteTypeObject {
    let found = lookup_named_type_object(
        &participant.registered_types.read(),
        EK_COMPLETE,
        *hash.as_bytes(),
    )
    .or_else(|| {
        lookup_named_type_object(
            &participant.served_types.read(),
            EK_COMPLETE,
            *hash.as_bytes(),
        )
    });
    let (_, handle) = found.unwrap_or_else(|| panic!("announced Complete id {hash} not servable"));
    let reply = encode_omg_get_types_reply(
        &[1; 16],
        0,
        1,
        &[(EK_COMPLETE, *hash.as_bytes(), Arc::clone(&handle))],
    )
    .unwrap();
    let decoded = parse_omg_get_types_reply(&reply).unwrap();
    assert_eq!(decoded.pairs.len(), 1);
    let (claimed, object) = &decoded.pairs[0];
    assert_eq!(*claimed, *hash.as_bytes());
    assert_eq!(object.compute_equivalence_hash().unwrap(), hash);
    object.clone()
}

/// Announce `announced` for the outer type and check every Complete
/// identifier of the announcement is served; returns the TypeInformation.
fn announce_and_serve(
    participant: &Participant,
    announced: &CompleteTypeObject,
) -> crate::protocol::discovery::types::TypeInformation {
    let info = participant
        .announced_type_information(OUTER, announced)
        .expect("type information");
    let complete = info.complete.as_ref().unwrap();
    let root = serve(participant, complete.hash);
    for dep in &complete.dependent_typeids {
        serve(participant, dep.hash);
    }
    // The root as served references only identifiers that are served too.
    if let TypeIdentifier::Complete(h) = element_ref(&root) {
        assert!(complete.dependent_typeids.iter().any(|d| d.hash == h));
        serve(participant, h);
    }
    info
}

#[test]
fn structurally_identical_nested_types_keep_their_own_complete_identity() {
    let alias_named = seq20_uint32("Test::uint32x20");
    let inner = seq20_uint32("Test::F_S__seq20_uint32");
    let topic = outer(&inner);

    let inner_complete = type_descriptor_to_xtypes_complete(&inner).unwrap();
    let inner_hash = inner_complete.compute_equivalence_hash().unwrap();
    let alias_hash = type_descriptor_to_xtypes_complete(&alias_named)
        .unwrap()
        .compute_equivalence_hash()
        .unwrap();
    assert_ne!(
        inner_hash, alias_hash,
        "names differ, Complete hashes differ"
    );
    assert_eq!(
        complete_type_object_minimal_hash(&type_descriptor_to_xtypes(&inner).unwrap()),
        complete_type_object_minimal_hash(&type_descriptor_to_xtypes(&alias_named).unwrap()),
        "same structure, same Minimal hash"
    );

    let topic_complete = type_descriptor_to_xtypes_complete(&topic).unwrap();
    assert_eq!(
        element_ref(&topic_complete),
        TypeIdentifier::Complete(inner_hash),
        "the Complete lowering names the member's own type"
    );
    let expected_root = topic_complete.compute_equivalence_hash().unwrap();
    let expected_minimal =
        complete_type_object_minimal_hash(&type_descriptor_to_xtypes(&topic).unwrap()).unwrap();

    let orders: [Vec<Arc<TypeDescriptor>>; 5] = [
        vec![alias_named.clone(), inner.clone(), topic.clone()],
        vec![inner.clone(), alias_named.clone(), topic.clone()],
        vec![topic.clone(), alias_named.clone(), inner.clone()],
        vec![alias_named.clone(), topic.clone(), inner.clone()],
        // The member's type is never registered on its own: only the
        // collector, walking the topic type, can provide it.
        vec![alias_named.clone(), topic.clone()],
    ];
    let mut first: Option<crate::protocol::discovery::types::TypeInformation> = None;
    for order in &orders {
        let mut first_hybrid: Option<crate::protocol::discovery::types::TypeInformation> = None;
        // Fresh maps and participants: each HashMap draws its own hasher
        // seed, so every round iterates in its own order.
        for _round in 0..6 {
            let participant = participant_with_registry();
            participant.register_nested_type_objects(driver_store(order));

            let info = announce_and_serve(&participant, &topic_complete);
            let complete = info.complete.as_ref().unwrap();
            assert_eq!(
                complete.hash, expected_root,
                "announced root is name-correct"
            );
            assert_eq!(
                complete
                    .dependent_typeids
                    .iter()
                    .map(|d| d.hash)
                    .collect::<Vec<_>>(),
                vec![inner_hash],
                "the one dependency is the member's own type, never its twin"
            );
            assert_eq!(info.minimal.as_ref().unwrap().hash, expected_minimal);
            let served_root = serve(&participant, expected_root);
            assert_eq!(served_root, topic_complete);
            assert_eq!(
                serve(&participant, inner_hash).type_name(),
                Some("Test::F_S__seq20_uint32")
            );
            match &first {
                None => first = Some(info),
                Some(previous) => assert_eq!(&info, previous, "deterministic announcement"),
            }

            // The legacy hybrid form (Minimal member refs) cannot carry the
            // member's type name; whatever it is resolved to, what is
            // announced for it must still be served.
            let hybrid = type_descriptor_to_xtypes(&topic).unwrap();
            let hybrid_info = announce_and_serve(&participant, &hybrid);
            match &first_hybrid {
                None => first_hybrid = Some(hybrid_info),
                Some(previous) => assert_eq!(
                    &hybrid_info, previous,
                    "one registration order, one announcement"
                ),
            }
        }
    }
}
