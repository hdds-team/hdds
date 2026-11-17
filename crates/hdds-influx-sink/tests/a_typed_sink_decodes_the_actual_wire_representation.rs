// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Item 6, decode side: `SinkRunner::tick` must decode a sample under its
//! ACTUAL wire DATA_REPRESENTATION, not a hardcoded one.
//!
//! `cdr_to_json_dynamic` (vs. `cdr_to_json_dynamic_with_version`) hardcodes
//! XCDR1; paired with `try_take_raw` (vs. `try_take_raw_with_encoding`,
//! which throws the per-sample version away before the runner ever sees
//! it), an XCDR2-encoded sample would be decoded as if it were XCDR1. This is
//! the exact pair of production functions `runner.rs::tick` calls, fed
//! bytes from the SAME derive-generated `encode()` the real DDS wire path
//! uses (`Reading::encode`, which the codegen makes genuinely
//! version-dependent -- see `hdds-codegen`'s generated `encode`/`decode`,
//! alignment 8 for Xcdr1 / 4 for Xcdr2) and the SAME TypeDescriptor a
//! discovered CompleteTypeObject resolves to
//! (`hdds::dynamic::type_descriptor_from_xtypes`, fed
//! `Reading::get_type_object()` -- the same call discovery makes on a
//! received SEDP TypeObject). No DDS participant or socket needed: this
//! isolates exactly the decode call runner.rs makes, at the one point
//! item 6 touched, without timing-dependent wire mechanics in the way.

#![cfg(feature = "hdds")]

use hdds::dynamic::json::{cdr_to_json_dynamic, cdr_to_json_dynamic_with_version};
use hdds::dynamic::type_descriptor_from_xtypes;
use hdds::{CdrVersion, DdsTrait};

#[derive(hdds::DDS, Debug, Clone)]
struct Reading {
    tag: u8,
    value: i64,
}

#[test]
fn decoding_an_xcdr2_sample_with_its_real_version_recovers_the_value() {
    let sample = Reading {
        tag: 7,
        value: 0x0102_0304_0506_0708,
    };
    let mut buf = vec![0u8; 64];
    let n = sample
        .encode(&mut buf, CdrVersion::Xcdr2)
        .expect("encode should succeed");
    let bytes = &buf[..n];

    let type_object = Reading::get_type_object().expect("derive must provide a TypeObject");
    let descriptor = type_descriptor_from_xtypes(&type_object);

    let decoded_right = cdr_to_json_dynamic_with_version(bytes, &descriptor, CdrVersion::Xcdr2);
    assert_eq!(
        decoded_right["value"],
        serde_json::json!(sample.value),
        "decoding with the real version must recover the value: {decoded_right}"
    );
    assert_eq!(decoded_right["tag"], serde_json::json!(sample.tag));
}

/// `cdr_to_json_dynamic` hardcodes XCDR1 (see its doc comment). Decoding
/// genuinely-XCDR2 bytes through it must NOT silently recover the right
/// value -- if it did, a hardcoded call in runner.rs would be harmless and
/// the version-aware path would not be needed.
#[test]
fn decoding_an_xcdr2_sample_with_the_hardcoded_xcdr1_default_does_not_recover_the_value() {
    let sample = Reading {
        tag: 7,
        value: 0x0102_0304_0506_0708,
    };
    let mut buf = vec![0u8; 64];
    let n = sample
        .encode(&mut buf, CdrVersion::Xcdr2)
        .expect("encode should succeed");
    let bytes = &buf[..n];

    let type_object = Reading::get_type_object().expect("derive must provide a TypeObject");
    let descriptor = type_descriptor_from_xtypes(&type_object);

    let decoded_wrong = cdr_to_json_dynamic(bytes, &descriptor);
    let decoded_right = cdr_to_json_dynamic_with_version(bytes, &descriptor, CdrVersion::Xcdr2);
    assert_ne!(
        decoded_wrong, decoded_right,
        "a hardcoded-XCDR1 decode of genuinely-XCDR2 bytes must not match the \
         real-version decode, or this test (and the bug it documents) is moot.\n\
         wrong (hardcoded XCDR1): {decoded_wrong}\nright (real XCDR2): {decoded_right}"
    );
    // `tag` is the field that comes out wrong under the
    // mismatched version for this type's layout (`value`'s decoded
    // number happens to still match by coincidence of this particular
    // byte pattern -- the whole-object inequality above is the real
    // proof, this is the concrete symptom).
    assert_ne!(
        decoded_wrong["tag"],
        serde_json::json!(sample.tag),
        "tag should also come out wrong under the mismatched version: {decoded_wrong}"
    );
}
