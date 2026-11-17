// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Unit tests for the AWS Cloud Map backend, included as `aws::tests` by
//! `#[path]` from aws.rs.
//!
//! The tests run against the implementation in aws.rs and the in-process
//! fake Cloud Map service.

use super::*;
use crate::test_support::fake_aws::{
    FakeCloudMap, FakeInstance, FAKE_NAMESPACE_NAME, FAKE_SERVICE_ID, FAKE_SERVICE_NAME,
};
use std::collections::HashMap;

fn block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime")
        .block_on(future)
}

fn v4(a: u8, b: u8, c: u8, d: u8, port: u32) -> Locator {
    Locator {
        kind: LOCATOR_KIND_UDPV4,
        port,
        address: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, a, b, c, d],
    }
}

fn participant(guid: [u8; 16], domain_id: u32, locators: Vec<Locator>) -> ParticipantInfo {
    ParticipantInfo {
        guid,
        name: "node".to_string(),
        domain_id,
        locators,
        metadata: HashMap::new(),
    }
}

/// A backend wired to a fake endpoint, taking its credentials from the
/// fake's container-credentials route: no environment variable is read or
/// written by this test, and no secret is stored in the config.
fn backend_for(fake: &FakeCloudMap, domain_id: u32) -> AwsCloudMap {
    AwsCloudMap::with_config(
        AwsCloudMapConfig::new("hdds-namespace", FAKE_SERVICE_ID, "eu-west-3")
            .with_domain_id(domain_id)
            .with_endpoint_override(fake.base_url())
            .with_credentials(AwsCredentialSource::Container {
                uri: fake.credentials_url(),
                authorization: None,
            }),
    )
    .expect("backend builds")
}

// ============================================================================
// Configuration
// ============================================================================

#[test]
fn config_from_the_three_field_form_fills_env_derived_defaults() {
    let config = AwsCloudMapConfig::from_json(
        r#"{"namespace":"hdds-ns","service":"hdds-svc","region":"eu-west-3"}"#,
    )
    .expect("the three-field form is accepted");
    assert_eq!(config.namespace, "hdds-ns");
    assert_eq!(config.service, "hdds-svc");
    assert_eq!(config.region, "eu-west-3");
    assert_eq!(config.domain_id, 0);
    assert_eq!(config.health_status, AwsHealthStatus::All);
    assert!(matches!(
        config.credentials,
        AwsCredentialSource::DefaultChain
    ));
    assert!(config.endpoint_override.is_none());
}

#[test]
fn config_round_trips_through_json_with_every_field() {
    let config = AwsCloudMapConfig::new("ns", "srv-1", "us-east-1")
        .with_domain_id(39)
        .with_health_status(AwsHealthStatus::HealthyOrElseAll)
        .with_endpoint_override("http://127.0.0.1:1234")
        .with_credentials(AwsCredentialSource::Imds {
            endpoint: Some("http://169.254.169.254".into()),
        });
    let json = config.to_json().expect("serialises");
    let parsed = AwsCloudMapConfig::from_json(&json).expect("round trip");
    assert_eq!(parsed.domain_id, 39);
    assert_eq!(parsed.health_status, AwsHealthStatus::HealthyOrElseAll);
    assert_eq!(
        parsed.endpoint_override.as_deref(),
        Some("http://127.0.0.1:1234")
    );
    assert!(matches!(
        parsed.credentials,
        AwsCredentialSource::Imds { .. }
    ));
}

#[test]
fn the_known_service_name_is_the_name_only_when_it_is_one() {
    // A NAME is its own data-plane name.
    let by_name = AwsCloudMapConfig::new("ns", "hdds-service", "eu-west-3");
    assert_eq!(by_name.known_service_name(), Some("hdds-service"));
    // An id or an ARN is not: it needs GetService, or the explicit field.
    for service in [
        "srv-abcdef",
        "arn:aws:servicediscovery:eu-west-3:123456789012:service/srv-abcdef",
    ] {
        let config = AwsCloudMapConfig::new("ns", service, "eu-west-3");
        assert_eq!(config.known_service_name(), None, "{}", service);
        assert_eq!(
            config
                .with_service_name("hdds-service")
                .known_service_name(),
            Some("hdds-service")
        );
    }
    // A name that contradicts a NAME-form service is refused, not
    // silently preferred: registration and discovery would split.
    let contradiction = AwsCloudMapConfig::new("ns", "hdds-service", "eu-west-3")
        .with_service_name("other-service");
    assert!(contradiction.validate().is_err());
    assert!(AwsCloudMapConfig::new("ns", "srv-1", "r")
        .with_service_name("  ")
        .validate()
        .is_err());
}

/// The three-argument builder API and the typed constructor must derive
/// the same environment-fed defaults; `ecs_metadata_uri` silently did not.
#[test]
fn the_three_field_form_and_new_agree_on_every_environment_default() {
    let from_json = AwsCloudMapConfig::from_json(
        r#"{"namespace":"hdds-ns","service":"hdds-svc","region":"eu-west-3"}"#,
    )
    .expect("three-field form");
    let from_new = AwsCloudMapConfig::new("hdds-ns", "hdds-svc", "eu-west-3");
    assert_eq!(from_json.ecs_metadata_uri, from_new.ecs_metadata_uri);
    assert_eq!(from_json.ecs_metadata_uri, ecs_metadata_uri_from_env());
    assert_eq!(from_json.health_status, from_new.health_status);
    assert_eq!(from_json.service_name, from_new.service_name);
    assert_eq!(from_json.domain_id, from_new.domain_id);
    // An explicit value in the JSON still wins over the environment.
    let explicit = AwsCloudMapConfig::from_json(
        r#"{"namespace":"n","service":"s","region":"r","ecs_metadata_uri":"http://169.254.170.2"}"#,
    )
    .expect("explicit endpoint");
    assert_eq!(
        explicit.ecs_metadata_uri.as_deref(),
        Some("http://169.254.170.2")
    );
}

#[test]
fn config_fails_closed_on_empty_fields_and_illegal_endpoints() {
    for json in [
        r#"{"namespace":"","service":"s","region":"r"}"#,
        r#"{"namespace":"n","service":"  ","region":"r"}"#,
        r#"{"namespace":"n","service":"s","region":""}"#,
        r#"{"namespace":"n","service":"s"}"#,
        r#"not json"#,
    ] {
        assert!(
            AwsCloudMapConfig::from_json(json).is_err(),
            "accepted an invalid config: {}",
            json
        );
    }
    // Plaintext to a remote host is refused by construction.
    let remote = AwsCloudMapConfig::new("n", "s", "r").with_endpoint_override("http://aws.example");
    assert!(remote.validate().is_err());
    assert!(AwsCloudMap::with_config(remote).is_err());
    // A metadata endpoint outside the link-local range is refused too.
    let mut config = AwsCloudMapConfig::new("n", "s", "r");
    config.ecs_metadata_uri = Some("http://evil.example/task".into());
    assert!(config.validate().is_err());
}

#[test]
fn redacted_json_never_carries_credential_material() {
    let config = AwsCloudMapConfig::new("ns\"quoted", "srv-1", "eu-west-3")
        .with_domain_id(39)
        .with_credentials(AwsCredentialSource::Static {
            access_key_id: "AKIDEXAMPLE".into(),
            secret_access_key: "top-secret-value".into(),
            session_token: Some("session-secret-value".into()),
        });
    let redacted = config.redacted_json();
    assert!(redacted.contains("AKIDEXAMPLE"));
    assert!(redacted.contains(r#""ns\"quoted""#), "{}", redacted);
    assert!(!redacted.contains("top-secret-value"), "{}", redacted);
    assert!(!redacted.contains("session-secret-value"), "{}", redacted);
    serde_json::from_str::<serde_json::Value>(&redacted).expect("redacted form is JSON");
    // The full Debug of the config must not leak either.
    let debug = format!("{:?}", config);
    assert!(!debug.contains("top-secret-value"), "{}", debug);
}

#[test]
fn health_status_wire_values_match_the_cloud_map_api() {
    assert_eq!(AwsHealthStatus::All.as_str(), "ALL");
    assert_eq!(AwsHealthStatus::Healthy.as_str(), "HEALTHY");
    assert_eq!(
        AwsHealthStatus::HealthyOrElseAll.as_str(),
        "HEALTHY_OR_ELSE_ALL"
    );
    // ALL is the default: filtering on health without a Cloud Map health
    // check configured returns nothing at all.
    assert_eq!(AwsHealthStatus::default(), AwsHealthStatus::All);
}

// ============================================================================
// Instance identity and attribute encoding
// ============================================================================

/// Two participants on the same host in the same second share the first
/// eight GUID bytes; the instance id must use all sixteen or one
/// participant deregisters the other.
#[test]
fn instance_id_covers_the_whole_guid() {
    let fake = FakeCloudMap::start().expect("fake");
    let backend = backend_for(&fake, 0);
    let mut a = [0u8; 16];
    a[..12].copy_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 9, 9, 9, 9]);
    a[12..].copy_from_slice(&[0, 0, 1, 0xc1]);
    let mut b = a;
    b[12..].copy_from_slice(&[0, 0, 2, 0xc1]);
    assert_eq!(
        backend.instance_id(&a),
        "hdds-010203040506070809090909000001c1"
    );
    assert_ne!(backend.instance_id(&a), backend.instance_id(&b));
}

#[test]
fn locators_encode_compactly_and_decode_back() {
    let encoded = encode_locators(&[
        "192.0.2.1:7410".parse::<std::net::SocketAddrV4>().unwrap(),
        "192.0.2.2:7411".parse::<std::net::SocketAddrV4>().unwrap(),
    ]);
    assert_eq!(encoded, "192.0.2.1:7410,192.0.2.2:7411");
    assert_eq!(
        decode_locators(&encoded),
        vec![v4(192, 0, 2, 1, 7410), v4(192, 0, 2, 2, 7411)]
    );
    // Garbage entries are dropped, the rest survives.
    assert_eq!(
        decode_locators("nonsense, 192.0.2.3:7410 ,,"),
        vec![v4(192, 0, 2, 3, 7410)]
    );
    assert!(decode_locators("").is_empty());
    // The compact form is what keeps a multi-homed host inside the 5000
    // character budget: the hex form of the same two locators is longer.
    assert!(encoded.len() < 2 * (32 + 8));
}

#[test]
fn attribute_limits_are_enforced_before_anything_is_sent() {
    let mut ok = HashMap::new();
    ok.insert("AWS_INSTANCE_IPV4".to_string(), "192.0.2.1".to_string());
    for index in 0..MAX_CUSTOM_ATTRIBUTES {
        ok.insert(format!("USER_K{}", index), "v".to_string());
    }
    check_attribute_limits(&ok).expect("exactly the limit is legal");

    let mut too_many = ok.clone();
    too_many.insert("USER_ONE_MORE".to_string(), "v".to_string());
    let error = check_attribute_limits(&too_many).expect_err("31 custom attributes must fail");
    assert!(matches!(&error, Error::Config(m) if m.contains("custom attributes")));

    let mut too_long = HashMap::new();
    too_long.insert("A".to_string(), "x".repeat(MAX_ATTRIBUTE_VALUE_CHARS));
    for index in 0..6 {
        too_long.insert(
            format!("USER_K{}", index),
            "x".repeat(MAX_ATTRIBUTE_VALUE_CHARS),
        );
    }
    let error = check_attribute_limits(&too_long).expect_err("over 5000 characters must fail");
    assert!(
        matches!(&error, Error::Config(m) if m.contains("characters") && m.contains("HDDS_INTERFACE_ALLOW")),
        "unexpected error: {:?}",
        error
    );

    // Per-value limit: a multi-homed host can blow the 1024-character
    // ceiling of the single LOCATORS value while staying well under the
    // 5000-character total.
    let mut long_value = HashMap::new();
    long_value.insert(
        "LOCATORS".to_string(),
        std::iter::repeat_n("192.0.2.1:7410", 80)
            .collect::<Vec<_>>()
            .join(","),
    );
    let error = check_attribute_limits(&long_value).expect_err("a 1000+ char value must fail");
    assert!(
        matches!(&error, Error::Config(m) if m.contains("per-value limit")),
        "unexpected error: {:?}",
        error
    );

    // Charset: AWS refuses a key with a space and a value that starts or
    // ends with a blank or carries a control character.
    let bad = |key: &str, value: &str| {
        let mut map = HashMap::new();
        map.insert(key.to_string(), value.to_string());
        check_attribute_limits(&map)
    };
    assert!(bad("USER_MY KEY", "v").is_err());
    assert!(bad("USER_KEY", " leading").is_err());
    assert!(bad("USER_KEY", "trailing ").is_err());
    assert!(bad("PARTICIPANT_NAME", "node\nname").is_err());
    // A space INSIDE a value is legal, and so is an empty value.
    assert!(bad("PARTICIPANT_NAME", "my node").is_ok());
    assert!(bad("USER_KEY", "").is_ok());
}

/// A participant with no routable UDPv4 locator is not registered at all:
/// an instance nothing can reach is worse than an absent one.
#[test]
fn a_registration_without_a_routable_locator_fails_closed() {
    let fake = FakeCloudMap::start().expect("fake");
    let backend = backend_for(&fake, 39);
    let mut v6 = v4(0, 0, 0, 0, 7410);
    v6.address[0] = 0x20;
    let error = block_on(backend.register_participant(&participant([7; 16], 39, vec![v6])))
        .expect_err("no routable locator, no registration");
    assert!(matches!(&error, Error::Config(m) if m.contains("no routable UDPv4")));
    assert!(fake.registered_ids().is_empty());
}

// ============================================================================
// Instance parsing
// ============================================================================

fn instance(attributes: &[(&str, &str)]) -> DiscoveredInstance {
    DiscoveredInstance {
        instance_id: "hdds-instance".to_string(),
        namespace_name: Some("hdds-namespace".to_string()),
        service_name: Some("hdds-service".to_string()),
        health_status: Some("HEALTHY".to_string()),
        attributes: attributes
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect(),
    }
}

#[test]
fn a_full_instance_parses_into_a_participant() {
    let parsed = parse_instance(
        &instance(&[
            ("GUID", "0102030405060708090a0b0c0000 01c1".trim()),
            ("DOMAIN_ID", "39"),
            ("PARTICIPANT_NAME", "peer"),
            ("LOCATORS", "192.0.2.1:7410,192.0.2.2:7411"),
            ("AWS_INSTANCE_IPV4", "192.0.2.1"),
            ("AWS_INSTANCE_PORT", "7410"),
            ("USER_REGION", "eu-west-3"),
        ]),
        39,
    );
    // The GUID above contains a space and must NOT parse.
    assert!(parsed.is_none());

    let parsed = parse_instance(
        &instance(&[
            ("GUID", "0102030405060708090a0b0c000001c1"),
            ("DOMAIN_ID", "39"),
            ("PARTICIPANT_NAME", "peer"),
            ("LOCATORS", "192.0.2.1:7410,192.0.2.2:7411"),
            ("USER_REGION", "eu-west-3"),
        ]),
        39,
    )
    .expect("a complete instance parses");
    assert_eq!(
        parsed.guid,
        [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x00, 0x00,
            0x01, 0xc1
        ]
    );
    assert_eq!(parsed.domain_id, 39);
    assert_eq!(parsed.name, "peer");
    assert_eq!(
        parsed.locators,
        vec![v4(192, 0, 2, 1, 7410), v4(192, 0, 2, 2, 7411)]
    );
    assert_eq!(
        parsed.metadata.get("region").map(String::as_str),
        Some("eu-west-3")
    );
}

/// An instance registered by something other than HDDS (or an older
/// HDDS) carries only the AWS attributes: the A/SRV pair is the fallback.
#[test]
fn an_instance_without_locators_falls_back_to_the_aws_ipv4_and_port() {
    let parsed = parse_instance(
        &instance(&[
            ("GUID", "0102030405060708090a0b0c000001c1"),
            ("DOMAIN_ID", "39"),
            ("AWS_INSTANCE_IPV4", "198.51.100.7"),
            ("AWS_INSTANCE_PORT", "7412"),
        ]),
        39,
    )
    .expect("the fallback locator is built");
    assert_eq!(parsed.locators, vec![v4(198, 51, 100, 7, 7412)]);
    // No PARTICIPANT_NAME: the instance id stands in.
    assert_eq!(parsed.name, "hdds-instance");
}

#[test]
fn instances_of_another_domain_or_without_a_usable_guid_are_dropped() {
    let good = [
        ("GUID", "0102030405060708090a0b0c000001c1"),
        ("DOMAIN_ID", "39"),
        ("LOCATORS", "192.0.2.1:7410"),
    ];
    assert!(parse_instance(&instance(&good), 39).is_some());
    // Another domain.
    assert!(parse_instance(&instance(&good), 40).is_none());
    // No GUID at all.
    assert!(parse_instance(
        &instance(&[("DOMAIN_ID", "39"), ("LOCATORS", "192.0.2.1:7410")]),
        39
    )
    .is_none());
    // GUID of the wrong length, and non-hex.
    for guid in ["0102", "zz02030405060708090a0b0c000001c1"] {
        assert!(parse_instance(
            &instance(&[
                ("GUID", guid),
                ("DOMAIN_ID", "39"),
                ("LOCATORS", "192.0.2.1:7410")
            ]),
            39
        )
        .is_none());
    }
    // No DOMAIN_ID, and a non-numeric one.
    for attributes in [
        vec![
            ("GUID", "0102030405060708090a0b0c000001c1"),
            ("LOCATORS", "192.0.2.1:7410"),
        ],
        vec![
            ("GUID", "0102030405060708090a0b0c000001c1"),
            ("DOMAIN_ID", "not-a-number"),
            ("LOCATORS", "192.0.2.1:7410"),
        ],
    ] {
        assert!(parse_instance(&instance(&attributes), 39).is_none());
    }
    // No locator anywhere.
    assert!(parse_instance(
        &instance(&[
            ("GUID", "0102030405060708090a0b0c000001c1"),
            ("DOMAIN_ID", "39")
        ]),
        39
    )
    .is_none());
}

// ============================================================================
// Real calls against the SigV4-verifying fake
// ============================================================================

/// The named proof of the register path: a signed `RegisterInstance` on
/// the CONTROL plane whose body carries the GUID, the domain and the
/// metatraffic locators. The fake verifies the signature, so a wrongly
/// signed request would 403 instead of passing.
#[test]
fn register_sends_a_signed_register_instance_with_guid_domain_and_locators() {
    let fake = FakeCloudMap::start().expect("fake");
    let backend = backend_for(&fake, 39);
    let mut info = participant(
        [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x00, 0x00,
            0x01, 0xc1,
        ],
        39,
        vec![v4(127, 0, 0, 1, 7410), v4(127, 0, 0, 1, 7411)],
    );
    info.metadata.insert("vendor".into(), "hdds".into());

    block_on(backend.register_participant(&info)).expect("registration succeeds");

    assert!(
        fake.signature_failures().is_empty(),
        "the fake rejected a signature: {:?}",
        fake.signature_failures()
    );
    assert_eq!(
        fake.registered_ids(),
        vec!["hdds-0102030405060708090a0b0c000001c1".to_string()]
    );
    assert_eq!(
        backend.registered_instance_id().as_deref(),
        Some("hdds-0102030405060708090a0b0c000001c1")
    );

    let stored = fake.instances();
    assert_eq!(stored.len(), 1);
    let attributes = &stored[0].attributes;
    assert_eq!(stored[0].service_id, FAKE_SERVICE_ID);
    assert_eq!(
        attributes.get("GUID").map(String::as_str),
        Some("0102030405060708090a0b0c000001c1")
    );
    assert_eq!(attributes.get("DOMAIN_ID").map(String::as_str), Some("39"));
    assert_eq!(
        attributes.get("PARTICIPANT_NAME").map(String::as_str),
        Some("node")
    );
    assert_eq!(
        attributes.get("LOCATORS").map(String::as_str),
        Some("127.0.0.1:7410,127.0.0.1:7411")
    );
    assert_eq!(
        attributes.get("AWS_INSTANCE_IPV4").map(String::as_str),
        Some("127.0.0.1")
    );
    assert_eq!(
        attributes.get("AWS_INSTANCE_PORT").map(String::as_str),
        Some("7410")
    );
    assert_eq!(
        attributes.get("USER_VENDOR").map(String::as_str),
        Some("hdds")
    );

    // RegisterInstance is a CONTROL-plane operation.
    assert!(fake.targets().contains(&"RegisterInstance".to_string()));
}

/// Discovery filters on the DDS domain through `QueryParameters` and
/// rebuilds a `ParticipantInfo` from the attributes.
#[test]
fn discover_filters_the_domain_through_query_parameters() {
    let fake = FakeCloudMap::start().expect("fake");
    let backend = backend_for(&fake, 39);
    let attributes = |guid: &str, domain: &str| -> HashMap<String, String> {
        [
            ("GUID", guid),
            ("DOMAIN_ID", domain),
            ("PARTICIPANT_NAME", "peer"),
            ("LOCATORS", "192.0.2.1:7410"),
        ]
        .iter()
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect()
    };
    fake.seed_instance(FakeInstance {
        instance_id: "hdds-a".into(),
        service_id: FAKE_SERVICE_ID.into(),
        attributes: attributes("0102030405060708090a0b0c000001c1", "39"),
    });
    fake.seed_instance(FakeInstance {
        instance_id: "hdds-b".into(),
        service_id: FAKE_SERVICE_ID.into(),
        attributes: attributes("1112131415161718191a1b1c000001c1", "40"),
    });

    let peers = block_on(backend.discover_participants()).expect("discovery succeeds");
    assert_eq!(peers.len(), 1, "only the domain-39 instance may come back");
    assert_eq!(peers[0].domain_id, 39);
    assert_eq!(peers[0].locators, vec![v4(192, 0, 2, 1, 7410)]);
    assert!(fake.signature_failures().is_empty());

    let discover = fake
        .requests()
        .into_iter()
        .find(|request| {
            request.header("x-amz-target") == Some("Route53AutoNaming_v20170314.DiscoverInstances")
        })
        .expect("a DiscoverInstances request was sent");
    let body = discover.body_text();
    assert!(
        body.contains(r#""QueryParameters":{"DOMAIN_ID":"39"}"#),
        "{}",
        body
    );
    assert!(body.contains(r#""HealthStatus":"ALL""#), "{}", body);
    assert!(
        body.contains(r#""NamespaceName":"hdds-namespace""#),
        "{}",
        body
    );
    // THE asymmetry: the configured value is the srv- ID, but
    // DiscoverInstances must carry the service NAME. The fake refuses the
    // id outright, so a regression here is a failed call, not a silent
    // empty peer list.
    assert!(
        body.contains(&format!(r#""ServiceName":"{}""#, FAKE_SERVICE_NAME)),
        "{}",
        body
    );
    assert!(!body.contains(FAKE_SERVICE_ID), "{}", body);
}

/// The control plane takes the `srv-...` ID and the data plane takes the
/// NAME; one configured value must produce both, or the participant
/// registers and then discovers nobody for ever.
#[test]
fn register_uses_the_service_id_and_discover_uses_the_service_name() {
    let fake = FakeCloudMap::start().expect("fake");
    let backend = backend_for(&fake, 39);
    let guid = [8; 16];
    block_on(backend.register_participant(&participant(guid, 39, vec![v4(127, 0, 0, 1, 7410)])))
        .expect("registration");
    let peers = block_on(backend.discover_participants()).expect("discovery succeeds");
    assert_eq!(peers.len(), 1, "the participant must discover itself back");
    assert_eq!(fake.instances()[0].service_id, FAKE_SERVICE_ID);
    // GetService resolved the name exactly once for both calls.
    assert_eq!(
        fake.targets().iter().filter(|t| *t == "GetService").count(),
        1
    );
    assert!(fake.signature_failures().is_empty());
}

/// Configuring the NAME beside the id is the minimal-IAM form: no
/// `GetService`, no `ListNamespaces`, no `ListServices` at all.
#[test]
fn a_configured_service_name_removes_every_lookup() {
    let fake = FakeCloudMap::start().expect("fake");
    let backend = AwsCloudMap::with_config(
        AwsCloudMapConfig::new(FAKE_NAMESPACE_NAME, FAKE_SERVICE_ID, "eu-west-3")
            .with_service_name(FAKE_SERVICE_NAME)
            .with_domain_id(39)
            .with_endpoint_override(fake.base_url())
            .with_credentials(AwsCredentialSource::Container {
                uri: fake.credentials_url(),
                authorization: None,
            }),
    )
    .expect("backend builds");

    block_on(backend.register_participant(&participant([9; 16], 39, vec![v4(127, 0, 0, 1, 7410)])))
        .expect("registration");
    block_on(backend.discover_participants()).expect("discovery");
    let lookups = fake
        .targets()
        .iter()
        .filter(|target| {
            *target == "GetService" || *target == "ListNamespaces" || *target == "ListServices"
        })
        .count();
    assert_eq!(lookups, 0, "targets were {:?}", fake.targets());
}

/// The warm-up resolves everything the first registration would otherwise
/// resolve inside the poller's per-call budget.
#[test]
fn prepare_resolves_the_service_identity_before_any_registration() {
    let fake = FakeCloudMap::start().expect("fake");
    let backend = backend_for(&fake, 39);
    block_on(backend.prepare()).expect("warm-up succeeds");
    assert_eq!(fake.targets(), vec!["GetService".to_string()]);

    // The registration that follows is ONE Cloud Map operation.
    let before = fake.targets().len();
    block_on(backend.register_participant(&participant(
        [10; 16],
        39,
        vec![v4(127, 0, 0, 1, 7410)],
    )))
    .expect("registration");
    assert_eq!(
        fake.targets()[before..],
        ["RegisterInstance".to_string()],
        "registration must be a single operation once the backend is warm"
    );
}

/// A warm-up that cannot resolve the service says so instead of leaving
/// the poller to discover it call by call.
#[test]
fn prepare_fails_closed_when_the_service_cannot_be_resolved() {
    let fake = FakeCloudMap::start().expect("fake");
    let backend = AwsCloudMap::with_config(
        AwsCloudMapConfig::new(FAKE_NAMESPACE_NAME, "srv-does-not-exist", "eu-west-3")
            .with_domain_id(39)
            .with_endpoint_override(fake.base_url())
            .with_credentials(AwsCredentialSource::Container {
                uri: fake.credentials_url(),
                authorization: None,
            }),
    )
    .expect("backend builds");
    let error = block_on(backend.prepare()).expect_err("an unknown service must fail the warm-up");
    assert!(
        matches!(&error, Error::Config(m) if m.contains("service_name") && m.contains("ServiceNotFound")),
        "unexpected error: {:?}",
        error
    );
}

#[test]
fn deregister_removes_the_registered_instance() {
    let fake = FakeCloudMap::start().expect("fake");
    let backend = backend_for(&fake, 39);
    let guid = [0x22; 16];
    block_on(backend.register_participant(&participant(guid, 39, vec![v4(127, 0, 0, 1, 7410)])))
        .expect("registration");
    assert_eq!(fake.instances().len(), 1);

    block_on(backend.deregister_participant(guid)).expect("deregistration");
    assert_eq!(fake.deregistered_ids().len(), 1);
    assert!(fake.instances().is_empty());
    assert!(backend.registered_instance_id().is_none());
    assert!(fake.signature_failures().is_empty());
}

/// The health check is one signed `DiscoverInstances`, NOT a
/// `ListNamespaces` (which a minimal IAM policy does not grant) and NOT
/// an unauthenticated GET that reads a 403 as "healthy".
#[test]
fn health_check_is_a_signed_discover_instances_and_reports_failure_honestly() {
    let fake = FakeCloudMap::start().expect("fake");
    let backend = backend_for(&fake, 39);
    assert!(block_on(backend.health_check()).expect("health check runs"));
    assert!(fake.targets().contains(&"DiscoverInstances".to_string()));
    assert!(!fake.targets().iter().any(|t| t == "ListNamespaces"));

    fake.throttle(true);
    assert!(
        !block_on(backend.health_check()).expect("health check runs"),
        "a throttled endpoint must not report healthy"
    );
}

/// The whole point of the fake's verifier: credentials that do not match
/// what the endpoint expects produce a 403, and the backend surfaces it
/// instead of returning Ok.
#[test]
fn wrong_credentials_are_rejected_by_the_endpoint_and_surfaced() {
    let fake = FakeCloudMap::start().expect("fake");
    let backend = AwsCloudMap::with_config(
        AwsCloudMapConfig::new("hdds-namespace", FAKE_SERVICE_ID, "eu-west-3")
            .with_domain_id(39)
            .with_endpoint_override(fake.base_url())
            .with_credentials(AwsCredentialSource::Static {
                access_key_id: "AKIDEXAMPLE".into(),
                secret_access_key: "the-wrong-secret".into(),
                session_token: None,
            }),
    )
    .expect("backend builds");

    let error = block_on(backend.register_participant(&participant(
        [3; 16],
        39,
        vec![v4(127, 0, 0, 1, 7410)],
    )))
    .expect_err("a bad signature must not register");
    assert!(matches!(&error, Error::Config(m) if m.contains("InvalidSignatureException")));
    assert!(fake.registered_ids().is_empty());
    assert!(!fake.signature_failures().is_empty());
}

/// A service NAME (not a `srv-...` id) is resolved through the control
/// plane once, and the resolution is cached across calls.
#[test]
fn a_service_name_is_resolved_through_the_control_plane_once() {
    let fake = FakeCloudMap::start().expect("fake");
    let backend = AwsCloudMap::with_config(
        AwsCloudMapConfig::new("hdds-namespace", "hdds-service", "eu-west-3")
            .with_domain_id(39)
            .with_endpoint_override(fake.base_url())
            .with_credentials(AwsCredentialSource::Container {
                uri: fake.credentials_url(),
                authorization: None,
            }),
    )
    .expect("backend builds");

    let guid = [4; 16];
    block_on(backend.register_participant(&participant(guid, 39, vec![v4(127, 0, 0, 1, 7410)])))
        .expect("registration");
    block_on(backend.deregister_participant(guid)).expect("deregistration");

    let lookups = fake
        .targets()
        .iter()
        .filter(|target| *target == "ListNamespaces" || *target == "ListServices")
        .count();
    assert_eq!(lookups, 2, "the name lookup must happen exactly once");
    assert_eq!(fake.instances().len(), 0);
    assert!(fake.signature_failures().is_empty());
}

/// The ECS task IP is only advertised when it is one of the locators this
/// participant actually bound: the metadata answer is never trusted blind.
#[test]
fn the_ecs_task_ip_is_advertised_only_when_it_is_a_bound_locator() {
    let fake = FakeCloudMap::start().expect("fake");
    let mut config = AwsCloudMapConfig::new("hdds-namespace", FAKE_SERVICE_ID, "eu-west-3")
        .with_domain_id(39)
        .with_endpoint_override(fake.base_url())
        .with_credentials(AwsCredentialSource::Container {
            uri: fake.credentials_url(),
            authorization: None,
        });
    // The fake's /task route answers 127.0.0.1.
    config.ecs_metadata_uri = Some(fake.ecs_metadata_url());
    let backend = AwsCloudMap::with_config(config).expect("backend builds");

    // The bound locator is NOT 127.0.0.1: the metadata IP must be ignored.
    block_on(backend.register_participant(&participant([5; 16], 39, vec![v4(192, 0, 2, 5, 7410)])))
        .expect("registration");
    let attributes = fake.instances()[0].attributes.clone();
    assert_eq!(
        attributes.get("AWS_INSTANCE_IPV4").map(String::as_str),
        Some("192.0.2.5")
    );

    // Now 127.0.0.1 IS bound: the metadata answer is used.
    block_on(backend.register_participant(&participant(
        [6; 16],
        39,
        vec![v4(127, 0, 0, 1, 7499), v4(192, 0, 2, 5, 7410)],
    )))
    .expect("registration");
    let attributes = fake
        .instances()
        .into_iter()
        .find(|instance| instance.instance_id.ends_with("06060606"))
        .expect("second instance")
        .attributes;
    assert_eq!(
        attributes.get("AWS_INSTANCE_IPV4").map(String::as_str),
        Some("127.0.0.1")
    );
    assert_eq!(
        attributes.get("AWS_INSTANCE_PORT").map(String::as_str),
        Some("7499")
    );
}
