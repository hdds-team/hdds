// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use super::*;

#[test]
fn test_minimal_type_detail_roundtrip() {
    let detail = MinimalTypeDetail::new();
    let mut buf = vec![0u8; 16];

    let encoded_len = detail
        .encode_cdr2_le(&mut buf)
        .expect("CDR2 minimal TypeDetail: encode should succeed");
    let decoded = MinimalTypeDetail::decode_cdr2_le(&buf[..encoded_len])
        .expect("CDR2 minimal TypeDetail: decode should succeed");

    assert_eq!(encoded_len, 0);
    assert_eq!(decoded, detail);
}

#[test]
fn test_minimal_member_detail_roundtrip() {
    let detail = MinimalMemberDetail::from_name("field1");
    let mut buf = vec![0u8; 16];

    let encoded_len = detail
        .encode_cdr2_le(&mut buf)
        .expect("CDR2 minimal MemberDetail: encode should succeed");
    let decoded = MinimalMemberDetail::decode_cdr2_le(&buf[..encoded_len])
        .expect("CDR2 minimal MemberDetail: decode should succeed");

    assert_eq!(decoded.name_hash, detail.name_hash);
}
