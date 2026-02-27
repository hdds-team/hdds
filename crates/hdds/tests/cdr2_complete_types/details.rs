// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use super::*;

#[test]
fn test_complete_type_detail_roundtrip() {
    let detail = CompleteTypeDetail::new("MyStruct");
    let mut buf = vec![0u8; 1024];

    let encoded_len = detail
        .encode_cdr2_le(&mut buf)
        .expect("CDR2 complete TypeDetail: encode should succeed");
    let decoded = CompleteTypeDetail::decode_cdr2_le(&buf[..encoded_len])
        .expect("CDR2 complete TypeDetail: decode should succeed");

    assert_eq!(decoded.type_name, detail.type_name);
}

#[test]
fn test_complete_member_detail_roundtrip() {
    let detail = CompleteMemberDetail::new("field1");
    let mut buf = vec![0u8; 512];

    let encoded_len = detail
        .encode_cdr2_le(&mut buf)
        .expect("CDR2 complete MemberDetail: encode should succeed");
    let decoded = CompleteMemberDetail::decode_cdr2_le(&buf[..encoded_len])
        .expect("CDR2 complete MemberDetail: decode should succeed");

    assert_eq!(decoded.name, detail.name);
}
