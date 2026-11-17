// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Golden lock of the `EquivalenceHash` computation, against a foreign value.
//!
//! `@final struct Temperature { float value; unsigned long timestamp; };`
//! compiled by Cyclone DDS 0.11 idlc (`idlc t.idl`, then
//! `tests/golden/typeobject/extract_typeobjects.py t.c`, which checks every
//! hash against the MD5 of its object) gives
//!
//! - Minimal `00718e787ac6018e3e070bac08de`
//! - Complete `7ce9c6a6e633cb2a6781fbac5887`
//!
//! The hash is `MD5(XCDR2 LE of the TypeObject)[..14]` (DDS-XTypes 1.3
//! 7.3.4.8), so any change to the TypeObject wire layout, a TypeKind octet, a
//! discriminator label, member flags or `MinimalMemberDetail::from_name`
//! fails here. Members carry TRY_CONSTRUCT1, the default TryConstruct
//! behavior DISCARD (Annex B MemberFlag, "01 = DISCARD").
//!
//! The lock is a foreign value and the test is not `#[ignore]`d: it runs on
//! every `cargo test`, so a drift cannot go unnoticed. The whole Cyclone
//! corpus is in `typeobject_oracle.rs`.

#![cfg(feature = "xtypes")]

use hdds::xtypes::{
    CommonStructMember, CompleteMemberDetail, CompleteStructHeader, CompleteStructMember,
    CompleteStructType, CompleteTypeDetail, CompleteTypeObject, MemberFlag, MinimalMemberDetail,
    MinimalStructHeader, MinimalStructMember, MinimalStructType, MinimalTypeDetail,
    MinimalTypeObject, StructTypeFlag, TypeIdentifier, TypeKind,
};

const CYCLONE_MINIMAL: &str = "00718e787ac6018e3e070bac08de";
const CYCLONE_COMPLETE: &str = "7ce9c6a6e633cb2a6781fbac5887";

fn members() -> [(u32, TypeKind, &'static str); 2] {
    [
        (0, TypeKind::TK_FLOAT32, "value"),
        (1, TypeKind::TK_UINT32, "timestamp"),
    ]
}

fn common(member_id: u32, kind: TypeKind) -> CommonStructMember {
    CommonStructMember {
        member_id,
        member_flags: MemberFlag::TRY_CONSTRUCT1,
        member_type_id: TypeIdentifier::primitive(kind),
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn golden_minimal_temperature_equivalence_hash() {
    let obj = MinimalTypeObject::Struct(MinimalStructType {
        struct_flags: StructTypeFlag::IS_FINAL,
        header: MinimalStructHeader {
            base_type: None,
            detail: MinimalTypeDetail::new(),
        },
        member_seq: members()
            .into_iter()
            .map(|(id, kind, name)| MinimalStructMember {
                common: common(id, kind),
                detail: MinimalMemberDetail::from_name(name),
            })
            .collect(),
    });
    let hash = obj.compute_equivalence_hash().expect("encode");
    assert_eq!(hex(hash.as_bytes()), CYCLONE_MINIMAL);
}

#[test]
fn golden_complete_temperature_equivalence_hash() {
    let obj = CompleteTypeObject::Struct(CompleteStructType {
        struct_flags: StructTypeFlag::IS_FINAL,
        header: CompleteStructHeader {
            base_type: None,
            detail: CompleteTypeDetail::new("Temperature"),
        },
        member_seq: members()
            .into_iter()
            .map(|(id, kind, name)| CompleteStructMember {
                common: common(id, kind),
                detail: CompleteMemberDetail::new(name),
            })
            .collect(),
    });
    let hash = obj.compute_equivalence_hash().expect("encode");
    assert_eq!(hex(hash.as_bytes()), CYCLONE_COMPLETE);
}
