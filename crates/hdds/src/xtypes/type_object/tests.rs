// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com
// ============================================================================
// Tests
// ============================================================================

use super::*;

#[test]
fn test_struct_type_flag() {
    let final_flag = StructTypeFlag::IS_FINAL;
    assert!(final_flag.contains(StructTypeFlag::IS_FINAL));
    assert!(!final_flag.contains(StructTypeFlag::IS_APPENDABLE));

    let appendable_flag = StructTypeFlag::IS_APPENDABLE;
    assert!(!appendable_flag.contains(StructTypeFlag::IS_FINAL));
    assert!(appendable_flag.contains(StructTypeFlag::IS_APPENDABLE));
}

#[test]
fn test_member_flag() {
    let key_flag = MemberFlag::IS_KEY;
    assert!(key_flag.contains(MemberFlag::IS_KEY));
    assert!(!key_flag.contains(MemberFlag::IS_OPTIONAL));

    let optional_flag = MemberFlag::IS_OPTIONAL;
    assert!(!optional_flag.contains(MemberFlag::IS_KEY));
    assert!(optional_flag.contains(MemberFlag::IS_OPTIONAL));
}

#[test]
fn test_complete_type_detail() {
    let detail = CompleteTypeDetail::new("MyStruct");
    assert_eq!(detail.type_name, "MyStruct");
    assert!(detail.ann_builtin.is_none());
    assert!(detail.ann_custom.is_none());
}

#[test]
fn test_minimal_type_detail() {
    let detail = MinimalTypeDetail::new();
    let detail2 = MinimalTypeDetail::default();
    assert_eq!(detail, detail2);
}

#[test]
fn test_complete_member_detail() {
    let detail = CompleteMemberDetail::new("field1");
    assert_eq!(detail.name, "field1");
    assert!(detail.ann_builtin.is_none());
    assert!(detail.ann_custom.is_none());
}

#[cfg(feature = "xtypes")]
#[test]
fn test_minimal_member_detail_hash() {
    let detail1 = MinimalMemberDetail::from_name("field1");
    let detail2 = MinimalMemberDetail::from_name("field1");
    let detail3 = MinimalMemberDetail::from_name("field2");

    // Same name = same hash
    assert_eq!(detail1.name_hash, detail2.name_hash);

    // Different name = different hash (highly likely)
    assert_ne!(detail1.name_hash, detail3.name_hash);
}

#[test]
fn test_struct_type_construction() {
    let struct_type = CompleteStructType {
        struct_flags: StructTypeFlag::IS_FINAL,
        header: CompleteStructHeader {
            base_type: None,
            detail: CompleteTypeDetail::new("Temperature"),
        },
        member_seq: vec![CompleteStructMember {
            common: CommonStructMember {
                member_id: 0,
                member_flags: MemberFlag::empty(),
                member_type_id: TypeIdentifier::TK_FLOAT32,
            },
            detail: CompleteMemberDetail::new("value"),
        }],
    };

    assert_eq!(struct_type.header.detail.type_name, "Temperature");
    assert_eq!(struct_type.member_seq.len(), 1);
    assert_eq!(struct_type.member_seq[0].detail.name, "value");
}

#[test]
fn test_enum_type_construction() {
    let enum_type = CompleteEnumeratedType {
        header: CompleteEnumeratedHeader {
            bit_bound: 32,
            detail: CompleteTypeDetail::new("Color"),
        },
        literal_seq: vec![
            CompleteEnumeratedLiteral {
                common: CommonEnumeratedLiteral {
                    value: 0,
                    flags: EnumeratedLiteralFlag::empty(),
                },
                detail: CompleteMemberDetail::new("RED"),
            },
            CompleteEnumeratedLiteral {
                common: CommonEnumeratedLiteral {
                    value: 1,
                    flags: EnumeratedLiteralFlag::empty(),
                },
                detail: CompleteMemberDetail::new("GREEN"),
            },
            CompleteEnumeratedLiteral {
                common: CommonEnumeratedLiteral {
                    value: 2,
                    flags: EnumeratedLiteralFlag::empty(),
                },
                detail: CompleteMemberDetail::new("BLUE"),
            },
        ],
    };

    assert_eq!(enum_type.header.detail.type_name, "Color");
    assert_eq!(enum_type.literal_seq.len(), 3);
    assert_eq!(enum_type.literal_seq[0].detail.name, "RED");
    assert_eq!(enum_type.literal_seq[0].common.value, 0);
}

#[test]
fn test_sequence_type_construction() {
    let seq_type = CompleteSequenceType {
        header: CompleteCollectionHeader {
            bound: 100,
            detail: CompleteTypeDetail::new(""),
        },
        element: CompleteCollectionElement {
            flags: CollectionElementFlag::empty(),
            type_id: TypeIdentifier::TK_INT32,
        },
    };

    assert_eq!(seq_type.header.bound, 100);
    assert_eq!(seq_type.element.type_id, TypeIdentifier::TK_INT32);
}

#[test]
fn test_array_type_construction() {
    let array_type = CompleteArrayType {
        header: CompleteCollectionHeader {
            bound: 0,
            detail: CompleteTypeDetail::new(""),
        },
        element: CompleteCollectionElement {
            flags: CollectionElementFlag::empty(),
            type_id: TypeIdentifier::TK_FLOAT32,
        },
        bound_seq: vec![3, 4],
    };

    assert_eq!(array_type.bound_seq, vec![3, 4]);
    assert_eq!(array_type.element.type_id, TypeIdentifier::TK_FLOAT32);
}

#[test]
fn test_type_object_enum() {
    let struct_type = CompleteStructType {
        struct_flags: StructTypeFlag::IS_FINAL,
        header: CompleteStructHeader {
            base_type: None,
            detail: CompleteTypeDetail::new("MyStruct"),
        },
        member_seq: vec![],
    };

    let type_obj = TypeObject::Complete(CompleteTypeObject::Struct(struct_type));

    // Verify the TypeObject enum structure
    assert!(matches!(
        type_obj,
        TypeObject::Complete(CompleteTypeObject::Struct(_))
    ));

    // Extract and verify the inner struct
    if let TypeObject::Complete(CompleteTypeObject::Struct(s)) = type_obj {
        assert_eq!(s.header.detail.type_name, "MyStruct");
    }
}
