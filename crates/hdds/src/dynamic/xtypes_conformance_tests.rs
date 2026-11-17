// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use super::*;
use crate::core::ser::traits::{Cdr2Decode, Cdr2Encode};
use crate::core::types::{Distro, ROS_HASH_SIZE};
use crate::xtypes::builder::{
    FieldType, MessageDescriptor, MessageMember, PrimitiveType, TypeObjectBuilder,
};
use crate::xtypes::*;

fn hash(hex: &str) -> EquivalenceHash {
    let mut bytes = [0; 14];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
    }
    EquivalenceHash::from_bytes(bytes)
}

pub(super) fn leaf_and_root() -> crate::core::types::TypeObjectHandle {
    let ros_hash = [0; ROS_HASH_SIZE];
    let leaf_members = [MessageMember {
        name: "x",
        field_type: FieldType::Primitive(PrimitiveType::Int32),
        is_key: false,
    }];
    let leaf = MessageDescriptor {
        namespace: "",
        name: "Leaf",
        members: &leaf_members,
        ros_hash_version: 1,
        ros_hash: &ros_hash,
    };
    let root_members = [MessageMember {
        name: "x",
        is_key: false,
        field_type: FieldType::Sequence {
            element: Box::new(FieldType::Array {
                element: Box::new(FieldType::Nested(&leaf)),
                dimensions: vec![2],
            }),
            bound: Some(3),
        },
    }];
    let root = MessageDescriptor {
        namespace: "",
        name: "Root",
        members: &root_members,
        ros_hash_version: 1,
        ros_hash: &ros_hash,
    };
    TypeObjectBuilder::from_descriptor(Distro::Humble, &root).unwrap()
}

// DDS-XTypes 1.3 7.3.4.3-.7 and Annex B. Independent Python oracle:
// serialize outer TypeObject (DHEADER, EK, TK, flags, delimited header and
// member sequence), align u16/u32 to 2/4, NameHash=MD5(b"x")[:4], then
// hashlib.md5(stream).digest()[:14]. The reproducible encoder is in
// tests/golden/typeobject/type_graph_oracle.py. Fixtures: final Leaf { long x; },
// typedef Leaf Alias, final Root { sequence<Leaf[2], 3> x; }.
#[test]
fn safe_builder_preserves_complete_and_minimal_dependency_graphs() {
    let root = leaf_and_root();
    assert_eq!(root.dependencies.len(), 1);
    let leaf = &root.dependencies[0];
    assert_eq!(
        leaf.type_id_complete,
        TypeIdentifier::Complete(hash("da8b3039f69df61c94d0d1df0206"))
    );
    assert_eq!(
        leaf.type_id_minimal,
        TypeIdentifier::Minimal(hash("c73b470caafdb605b296425893c0"))
    );
    assert_eq!(
        root.type_id_complete,
        TypeIdentifier::Complete(hash("253a19cb953b8e858c9a833dd6b1"))
    );
    assert_eq!(
        root.type_id_minimal,
        TypeIdentifier::Minimal(hash("99786ca54a04863ceb95a1657f75"))
    );
    let store = HashMap::from([(
        leaf.complete.compute_equivalence_hash().unwrap(),
        leaf.complete.clone(),
    )]);
    let minimal = complete_to_minimal_with_dependencies(&root.complete, &store).unwrap();
    assert_eq!(minimal, root.minimal);
    // Inspect decoded bytes, including both levels of collection headers.
    let mut wire = vec![0; root.complete.max_cdr2_size()];
    let len = root.complete.encode_cdr2_le(&mut wire).unwrap();
    let (decoded, consumed) = CompleteTypeObject::decode_cdr2_le(&wire[..len]).unwrap();
    assert_eq!(consumed, len);
    assert_eq!(decoded, root.complete);
    assert!(
        complete_to_minimal_type_object(&decoded).is_none(),
        "missing dependencies must not produce a hybrid Minimal object"
    );
}

#[test]
fn aliases_convert_the_related_type_before_hashing() {
    let root = leaf_and_root();
    let leaf = &root.dependencies[0];
    let alias = CompleteTypeObject::Alias(CompleteAliasType {
        alias_flags: AliasTypeFlag(0),
        header: CompleteAliasHeader {
            detail: CompleteTypeDetail::new("Alias"),
        },
        body: CompleteAliasBody {
            common: CommonAliasBody {
                related_flags: TypeRelationFlag(0),
                related_type: leaf.type_id_complete.clone(),
            },
            ann_builtin: None,
            ann_custom: None,
        },
    });
    let store = HashMap::from([(
        leaf.minimal.compute_equivalence_hash().unwrap(),
        leaf.complete.clone(),
    )]);
    #[cfg(feature = "xtypes-structural-assignability")]
    {
        let mut hybrid = alias.clone();
        let CompleteTypeObject::Alias(a) = &mut hybrid else {
            panic!("alias");
        };
        a.body.common.related_type = leaf.type_id_minimal.clone();
        assert_eq!(
            complete_type_object_with_complete_refs(&hybrid, &store),
            alias
        );
    }
    let minimal = complete_to_minimal_with_dependencies(&alias, &store).unwrap();
    assert_eq!(
        alias.compute_equivalence_hash().unwrap(),
        hash("294f4b76c6c3438e0cae2183b896")
    );
    assert_eq!(
        minimal.compute_equivalence_hash().unwrap(),
        hash("64691d4f14a7eba09869719f4ef3")
    );
    let MinimalTypeObject::Alias(a) = minimal else {
        panic!("alias");
    };
    assert_eq!(a.body.common.related_type, leaf.type_id_minimal);
}

#[test]
fn nested_collection_headers_inherit_hash_equivalence() {
    for kind in [EquivalenceKind::Complete, EquivalenceKind::Minimal] {
        let leaf = match kind {
            EquivalenceKind::Complete => {
                TypeIdentifier::Complete(hash("da8b3039f69df61c94d0d1df0206"))
            }
            _ => TypeIdentifier::Minimal(hash("c73b470caafdb605b296425893c0")),
        };
        let id = TypeIdentifier::PlainSequenceSmall(PlainSequenceSElemDefn {
            header: PlainCollectionHeader {
                equiv_kind: kind,
                element_flags: CollectionElementFlag::TRY_CONSTRUCT1,
            },
            bound: 0,
            element_identifier: Box::new(leaf),
        });
        assert_eq!(collection_equiv_kind(&id), kind);
    }
    let bits = TypeDescriptor::new(
        "Flags",
        crate::dynamic::TypeKind::Enum(EnumDescriptor::new_bitmask(vec![EnumVariant::new("A", 1)])),
    );
    let complete = descriptor_to_type_identifier_kind(&bits, EquivalenceKind::Complete).unwrap();
    let minimal = descriptor_to_type_identifier_kind(&bits, EquivalenceKind::Minimal).unwrap();
    assert!(matches!(complete, TypeIdentifier::Complete(_)));
    assert!(matches!(minimal, TypeIdentifier::Minimal(_)));
    assert_ne!(complete, minimal);
    let bits = Arc::new(bits);
    let sequence = Arc::new(TypeDescriptor::new(
        "FlagsSeq",
        crate::dynamic::TypeKind::Sequence(SequenceDescriptor {
            element_type: Arc::clone(&bits),
            max_length: Some(4),
        }),
    ));
    let descriptor = TypeDescriptor::struct_type(
        "HasFlags",
        vec![
            FieldDescriptor::new("flags", bits),
            FieldDescriptor::new("many", sequence),
        ],
    );
    let CompleteTypeObject::Struct(object) =
        type_descriptor_to_xtypes_complete(&descriptor).unwrap()
    else {
        panic!("struct");
    };
    assert_eq!(object.member_seq[0].common.member_type_id, complete);
    let TypeIdentifier::PlainSequenceSmall(s) = &object.member_seq[1].common.member_type_id else {
        panic!("sequence");
    };
    assert_eq!(*s.element_identifier, complete);
    assert_eq!(s.header.equiv_kind, EquivalenceKind::Complete);
}

#[test]
fn every_plain_collection_and_struct_base_converts_recursively() {
    let root = leaf_and_root();
    let mut leaf = root.dependencies[0].complete.clone();
    let CompleteTypeObject::Struct(base) = &mut leaf else {
        panic!("struct");
    };
    base.struct_flags = StructTypeFlag::IS_APPENDABLE;
    let complete_id = TypeIdentifier::Complete(leaf.compute_equivalence_hash().unwrap());
    let minimal_id = TypeIdentifier::Minimal(
        complete_to_minimal_type_object(&leaf)
            .unwrap()
            .compute_equivalence_hash()
            .unwrap(),
    );
    let key_enum = CompleteTypeObject::Enumerated(CompleteEnumeratedType {
        enum_flags: StructTypeFlag::IS_APPENDABLE,
        header: CompleteEnumeratedHeader {
            bit_bound: 32,
            detail: CompleteTypeDetail::new("Key"),
        },
        literal_seq: vec![CompleteEnumeratedLiteral {
            common: CommonEnumeratedLiteral {
                value: 0,
                flags: EnumeratedLiteralFlag::IS_DEFAULT,
            },
            detail: CompleteMemberDetail::new("One"),
        }],
    });
    let key_id = TypeIdentifier::Complete(key_enum.compute_equivalence_hash().unwrap());
    let minimal_key_id = TypeIdentifier::Minimal(
        complete_to_minimal_type_object(&key_enum)
            .unwrap()
            .compute_equivalence_hash()
            .unwrap(),
    );
    let store = HashMap::from([
        (leaf.compute_equivalence_hash().unwrap(), leaf),
        (key_enum.compute_equivalence_hash().unwrap(), key_enum),
    ]);
    let header = PlainCollectionHeader {
        equiv_kind: EquivalenceKind::Complete,
        element_flags: CollectionElementFlag::TRY_CONSTRUCT1,
    };
    let element = Box::new(complete_id.clone());
    let ids = vec![
        TypeIdentifier::PlainSequenceSmall(PlainSequenceSElemDefn {
            header,
            bound: 2,
            element_identifier: element.clone(),
        }),
        TypeIdentifier::PlainSequenceLarge(PlainSequenceLElemDefn {
            header,
            bound: 300,
            element_identifier: element.clone(),
        }),
        TypeIdentifier::PlainArraySmall(PlainArraySElemDefn {
            header,
            array_bound_seq: vec![2, 3],
            element_identifier: element.clone(),
        }),
        TypeIdentifier::PlainArrayLarge(PlainArrayLElemDefn {
            header,
            array_bound_seq: vec![300],
            element_identifier: element.clone(),
        }),
        TypeIdentifier::PlainMapSmall(PlainMapSTypeDefn {
            header,
            bound: 3,
            element_identifier: Box::new(TypeIdentifier::Primitive(
                crate::xtypes::TypeKind::TK_INT32,
            )),
            key_identifier: Box::new(key_id.clone()),
            key_flags: CollectionElementFlag::TRY_CONSTRUCT1,
        }),
        TypeIdentifier::PlainMapLarge(PlainMapLTypeDefn {
            header,
            bound: 300,
            element_identifier: element.clone(),
            key_identifier: Box::new(key_id),
            key_flags: CollectionElementFlag::TRY_CONSTRUCT1,
        }),
    ];
    for id in ids {
        let CompleteTypeObject::Struct(mut object) = root.complete.clone() else {
            panic!("struct");
        };
        object.struct_flags = StructTypeFlag::IS_APPENDABLE;
        object.header.base_type = Some(complete_id.clone());
        object.member_seq[0].common.member_id = 1;
        object.member_seq[0].detail = CompleteMemberDetail::new("derived");
        object.member_seq[0].common.member_type_id = id;
        let object = CompleteTypeObject::Struct(object);
        #[cfg(feature = "xtypes-structural-assignability")]
        assert_eq!(
            complete_type_object_with_complete_refs(&object, &store),
            object
        );
        let minimal = complete_to_minimal_with_dependencies(&object, &store).unwrap();
        let mut wire = vec![0; minimal.max_cdr2_size()];
        let len = minimal.encode_cdr2_le(&mut wire).unwrap();
        let (decoded, _) = MinimalTypeObject::decode_cdr2_le(&wire[..len]).unwrap();
        let MinimalTypeObject::Struct(s) = decoded else {
            panic!("struct");
        };
        assert_eq!(s.header.base_type.as_ref(), Some(&minimal_id));
        let id = &s.member_seq[0].common.member_type_id;
        assert_eq!(collection_equiv_kind(id), EquivalenceKind::Minimal);
        let (element, key) = match id {
            TypeIdentifier::PlainSequenceSmall(d) => (&d.element_identifier, None),
            TypeIdentifier::PlainSequenceLarge(d) => (&d.element_identifier, None),
            TypeIdentifier::PlainArraySmall(d) => (&d.element_identifier, None),
            TypeIdentifier::PlainArrayLarge(d) => (&d.element_identifier, None),
            TypeIdentifier::PlainMapSmall(d) => (&d.element_identifier, Some(&d.key_identifier)),
            TypeIdentifier::PlainMapLarge(d) => (&d.element_identifier, Some(&d.key_identifier)),
            _ => panic!("collection"),
        };
        if let Some(key) = key {
            assert_eq!(**key, minimal_key_id);
        } else {
            assert_eq!(**element, minimal_id);
        }
        assert!(!matches!(**element, TypeIdentifier::Complete(_)));
    }
}
