// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! A governance document that requests metadata protection or whole-message
//! (RTPS) protection asks for something this release does not apply: the
//! participant is not created, and the error names the element and the kind.
//! Accepting it would leave an operator believing the submessages of the
//! domain are protected while they travel unauthenticated.
//!
//! Participant creation reads the governance through
//! `SecurityPluginSuite::new`: `signed_document::load_verified` checks the
//! envelope and returns the XML it carries, then
//! `AccessControlPlugin::from_documents_for_name` parses it with
//! `GovernanceConfig::parse`, which refuses what is not applied. A signed
//! document and an unsigned one admitted by
//! `insecure_allow_unsigned_documents` differ only in the envelope check, so
//! the documents here are unsigned.

use crate::security::test_pki::{TEST_CA_CERT_PEM, TEST_IDENTITY_CERT_PEM, TEST_IDENTITY_KEY_PEM};
use crate::security::SecurityConfig;
use crate::{Participant, TransportMode};
use std::io::Write as _;
use tempfile::NamedTempFile;

fn temp(bytes: &[u8]) -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("temp file");
    f.write_all(bytes).expect("write");
    f.flush().expect("flush");
    f
}

fn governance(rtps: &str, metadata: &str) -> String {
    format!(
        "<?xml version=\"1.0\"?><dds><domain_access_rules><domain_rule>\
         <domains><id_range><min>0</min><max>232</max></id_range></domains>\
         <allow_unauthenticated_participants>FALSE</allow_unauthenticated_participants>\
         <enable_join_access_control>TRUE</enable_join_access_control>\
         <discovery_protection_kind>NONE</discovery_protection_kind>\
         <liveliness_protection_kind>NONE</liveliness_protection_kind>\
         <rtps_protection_kind>{rtps}</rtps_protection_kind>\
         <topic_access_rules><topic_rule><topic_expression>*</topic_expression>\
         <enable_discovery_protection>FALSE</enable_discovery_protection>\
         <enable_liveliness_protection>FALSE</enable_liveliness_protection>\
         <enable_read_access_control>TRUE</enable_read_access_control>\
         <enable_write_access_control>TRUE</enable_write_access_control>\
         <metadata_protection_kind>{metadata}</metadata_protection_kind>\
         <data_protection_kind>ENCRYPT</data_protection_kind></topic_rule>\
         </topic_access_rules></domain_rule></domain_access_rules></dds>"
    )
}

const PERMISSIONS: &[u8] = b"<?xml version=\"1.0\"?><dds><permissions><grant name=\"g\">\
    <subject_name>CN=DDS Test Identity, O=HDDS Test</subject_name>\
    <validity><not_before>2020-01-01T00:00:00</not_before>\
    <not_after>2036-01-01T00:00:00</not_after></validity>\
    <allow_rule><domains><id_range><min>0</min><max>232</max></id_range></domains>\
    <publish><topics><topic>*</topic></topics></publish>\
    <subscribe><topics><topic>*</topic></topics></subscribe></allow_rule>\
    <default>DENY</default></grant></permissions></dds>";

/// Create a participant whose governance requests `rtps` and `metadata`.
fn create(rtps: &str, metadata: &str) -> crate::dds::Result<std::sync::Arc<Participant>> {
    let cert = temp(TEST_IDENTITY_CERT_PEM);
    let key = temp(TEST_IDENTITY_KEY_PEM);
    let ca = temp(TEST_CA_CERT_PEM);
    let gov = temp(governance(rtps, metadata).as_bytes());
    let perms = temp(PERMISSIONS);
    let config = SecurityConfig::builder()
        .identity_certificate(cert.path())
        .private_key(key.path())
        .ca_certificates(ca.path())
        .governance_xml(gov.path())
        .permissions_xml(perms.path())
        .insecure_allow_unsigned_documents(true)
        .build()
        .expect("config");
    Participant::builder("protection_refusal")
        .domain_id(0)
        .with_transport(TransportMode::IntraProcess)
        .with_security(config)
        .build()
}

fn assert_refused(rtps: &str, metadata: &str, element: &str, kind: &str) {
    let err = match create(rtps, metadata) {
        Ok(_) => panic!(
            "a governance requesting {} {} created a participant: the protection would be \
             silently absent",
            element, kind
        ),
        Err(e) => e.to_string(),
    };
    assert!(
        err.contains(element) && err.contains(kind),
        "the refusal must name {} and {}: {}",
        element,
        kind,
        err
    );
}

/// The same document with every refused kind at NONE creates the
/// participant: the refusals below are the kind's, not the fixture's.
#[test]
fn a_governance_at_none_creates_the_participant() {
    create("NONE", "NONE").expect("NONE requests nothing and must be accepted");
}

#[test]
fn metadata_protection_sign_is_refused_at_participant_creation() {
    assert_refused("NONE", "SIGN", "metadata_protection_kind", "SIGN");
}

#[test]
fn metadata_protection_encrypt_is_refused_at_participant_creation() {
    assert_refused("NONE", "ENCRYPT", "metadata_protection_kind", "ENCRYPT");
}

#[test]
fn rtps_protection_sign_is_refused_at_participant_creation() {
    assert_refused("SIGN", "NONE", "rtps_protection_kind", "SIGN");
}

#[test]
fn rtps_protection_encrypt_is_refused_at_participant_creation() {
    assert_refused("ENCRYPT", "NONE", "rtps_protection_kind", "ENCRYPT");
}
