// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Participant-level proof of the AWS Cloud Map backend.
//!
//! Two real participants, both with multicast SPDP disabled, are given the
//! SAME Cloud Map endpoint and must find each other through it and only
//! through it: `RegisterInstance` -> `DiscoverInstances` -> `SpdpPeerSet`
//! (Cloud origin) -> SPDP announcer -> unicast `DATA(p)`.
//!
//! That a cloud-configured participant really is multicast-silent in both
//! directions is proven separately, with a multicast probe, by
//! `cloud_wiring.rs::cloud_participant_is_multicast_disabled_by_default_unless_overridden`;
//! this file relies on it rather than repeating it.
//!
//! Hermetic by construction:
//!
//! * the endpoint is `test_support::fake_aws` on `127.0.0.1:0` - no
//!   network, no TLS, no AWS account, no credentials file;
//! * credentials come from the fake's own container-credentials route, so
//!   no environment variable is read or written by these tests and no
//!   secret is stored in the participant configuration;
//! * the fake RECOMPUTES the SigV4 signature of every request it receives
//!   and answers 403 on a mismatch, so a wrongly signed client fails the
//!   test instead of passing quietly.
//!
//! Limitation, stated rather than hidden: the fake's verifier calls the
//! same `aws_sigv4` code the client does, so a SYMMETRIC canonicalisation
//! bug would satisfy both sides. The independent oracle for that is the
//! unit test `discovery::cloud::aws_sigv4::tests::
//! sigv4_matches_the_official_aws_test_suite_vectors`, which compares the
//! canonical request, the string to sign and the signature with the values
//! AWS publishes in its own SigV4 test suite.
//!
//! Validated against this hermetic fake, NOT against a live AWS account.

#![cfg(feature = "cloud-discovery")]

use hdds::discovery::cloud::{AwsCloudMapConfig, AwsCredentialSource, AwsHealthStatus};
use hdds::test_support::domains::unique_domain;
use hdds::test_support::fake_aws::{FakeCloudMap, FAKE_SERVICE_ID};
use hdds::test_support::ports::with_reserved_ports;
use hdds::{Participant, TransportMode};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// Registry poll interval for the tests (the cloud lease floor is 1 s).
const POLL_INTERVAL: Duration = Duration::from_millis(200);
const NAMESPACE: &str = "hdds-namespace";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn wait_until(timeout: Duration, mut condition: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if condition() {
            return true;
        }
        thread::sleep(Duration::from_millis(25));
    }
    condition()
}

/// The SPDP announcer merges `HDDS_SPDP_UNICAST_PEERS` into its unicast
/// destinations unconditionally. If that variable is set on the runner,
/// "B could only have learnt A through Cloud Map" is not true, and the
/// causality assertions below would be a lie. Refuse to pretend.
fn assert_no_ambient_spdp_peers() {
    for name in ["HDDS_SPDP_UNICAST_PEERS", "HDDS_PEERS"] {
        assert!(
            std::env::var_os(name).is_none(),
            "{} is set in this environment: the cloud-only causality this test asserts \
             cannot hold, because the announcer seeds those peers itself",
            name
        );
    }
}

/// A Cloud Map configuration pointed at `fake`, taking its credentials
/// from the fake's container-credentials route.
fn config_for(fake: &FakeCloudMap, domain_id: u32) -> AwsCloudMapConfig {
    let mut config = AwsCloudMapConfig::new(NAMESPACE, FAKE_SERVICE_ID, "eu-west-3")
        .with_domain_id(domain_id)
        .with_health_status(AwsHealthStatus::All)
        .with_endpoint_override(fake.base_url())
        .with_credentials(AwsCredentialSource::Container {
            uri: fake.credentials_url(),
            authorization: None,
        });
    // `AwsCloudMapConfig::new` picks ECS_CONTAINER_METADATA_URI_V4 up from
    // the environment; a runner that happens to set it must not change
    // what this participant advertises.
    config.ecs_metadata_uri = None;
    config
}

/// THE named proof: with multicast SPDP disabled on both sides, the only
/// path from A to B is the Cloud Map registry.
#[test]
fn two_multicast_disabled_participants_discover_only_through_cloud_map() {
    // ONE lease for the pair: A and B must sit on the same domain for the
    // cloud-only discovery this test asserts to mean anything. Declared
    // first so it is dropped last, after both participants' sockets close.
    let domain = unique_domain();
    assert_no_ambient_spdp_peers();

    let fake = FakeCloudMap::start().expect("fake Cloud Map endpoint");
    // Nothing is discoverable while the gate is closed: DiscoverInstances
    // answers an empty list even though both participants registered.
    fake.gate_discovery(true);

    let config = config_for(&fake, domain.id());
    let (a, b) = with_reserved_ports(
        8,
        |[mcast, a_sedp, a_user, b_sedp, b_user]: [u16; 5]| -> hdds::Result<(Arc<Participant>, Arc<Participant>)> {
            let a = Participant::builder("cloud_aws_a")
                .domain_id(domain.id())
                .with_transport(TransportMode::UdpMulticast)
                .with_discovery_ports(mcast, a_sedp, a_user)
                .participant_id(Some(0))
                .with_aws_cloud_map_config(config.clone())
                .with_cloud_poll_interval(POLL_INTERVAL)
                .build()?;
            let b = Participant::builder("cloud_aws_b")
                .domain_id(domain.id())
                .with_transport(TransportMode::UdpMulticast)
                .with_discovery_ports(mcast, b_sedp, b_user)
                .participant_id(Some(1))
                .with_aws_cloud_map_config(config.clone())
                .with_cloud_poll_interval(POLL_INTERVAL)
                .build()?;
            Ok((a, b))
        },
    )
    .expect("two cloud-configured participants build");

    let a_guid = a.guid();
    let b_guid = b.guid();

    // 1. Both participants registered themselves in Cloud Map, with their
    //    own GUID, the domain and a metatraffic port.
    assert!(
        wait_until(Duration::from_secs(10), || {
            a.cloud_discovery_status().is_some_and(|s| s.registered)
                && b.cloud_discovery_status().is_some_and(|s| s.registered)
        }),
        "one of the participants never registered: a={:?} b={:?}",
        a.cloud_discovery_status(),
        b.cloud_discovery_status()
    );
    let instances = fake.instances();
    assert_eq!(
        instances.len(),
        2,
        "expected two instances: {:?}",
        instances
    );
    for guid in [a_guid.as_bytes(), b_guid.as_bytes()] {
        let instance = instances
            .iter()
            .find(|instance| {
                instance.attributes.get("GUID").map(String::as_str) == Some(hex(&guid).as_str())
            })
            .unwrap_or_else(|| panic!("no Cloud Map instance carries GUID {}", hex(&guid)));
        assert_eq!(
            instance.attributes.get("DOMAIN_ID").map(String::as_str),
            Some(domain.id().to_string().as_str())
        );
        assert_eq!(instance.service_id, FAKE_SERVICE_ID);
        let locators = instance
            .attributes
            .get("LOCATORS")
            .expect("the instance carries its metatraffic locators");
        assert!(
            locators
                .split(',')
                .all(|entry| entry.parse::<std::net::SocketAddr>().is_ok()),
            "locator list is not a compact ip:port list: {}",
            locators
        );
        assert!(instance.attributes.contains_key("AWS_INSTANCE_IPV4"));
        assert!(instance.attributes.contains_key("AWS_INSTANCE_PORT"));
    }

    // 2. Causality: while DiscoverInstances is gated, neither participant
    //    can learn the other. Multicast is off (the cloud default), so
    //    there is no other path.
    assert!(
        wait_until(Duration::from_secs(3), || fake.discover_call_count() >= 4),
        "the poller did not reach DiscoverInstances"
    );
    for (name, participant, peer) in [("a", &a, &b_guid), ("b", &b, &a_guid)] {
        let fsm = participant.discovery().expect("discovery FSM");
        assert!(
            !fsm.has_participant(peer),
            "{} discovered its peer while DiscoverInstances was gated: only Cloud Map \
             could have taught it, so this run is not cloud-only",
            name
        );
    }

    // 3. Release the gate: each participant learns the other's metatraffic
    //    locator from Cloud Map and unicast SPDP completes discovery.
    fake.gate_discovery(false);
    assert!(
        wait_until(Duration::from_secs(30), || {
            a.discovery()
                .is_some_and(|fsm| fsm.has_participant(&b_guid))
                && b.discovery()
                    .is_some_and(|fsm| fsm.has_participant(&a_guid))
        }),
        "the participants did not discover each other through Cloud Map: \
         a={:?} b={:?} cloud_a={:?} cloud_b={:?}",
        a.discovery().map(|f| f.participant_count()),
        b.discovery().map(|f| f.participant_count()),
        a.cloud_discovery_status(),
        b.cloud_discovery_status()
    );

    // 4. Every request the client sent verified against the fake's SigV4
    //    recomputation: no unsigned or mis-signed call slipped through.
    assert!(
        fake.signature_failures().is_empty(),
        "the endpoint rejected a signature: {:?}",
        fake.signature_failures()
    );
    assert!(
        fake.targets().contains(&"RegisterInstance".to_string())
            && fake.targets().contains(&"DiscoverInstances".to_string()),
        "unexpected operation set: {:?}",
        fake.targets()
    );

    // 5. Dropping a participant deregisters it, bounded.
    let started = Instant::now();
    drop(a);
    assert!(
        wait_until(Duration::from_secs(5), || !fake
            .deregistered_ids()
            .is_empty()),
        "dropping a participant did not deregister it from Cloud Map"
    );
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "the drop was not bounded: {:?}",
        started.elapsed()
    );
    let deregistered = fake.deregistered_ids();
    assert!(
        deregistered
            .iter()
            .any(|id| id == &format!("hdds-{}", hex(&a_guid.as_bytes()))),
        "the wrong instance was deregistered: {:?}",
        deregistered
    );
    drop(b);
}

/// A registry that rejects every signature is a loud, repeated failure -
/// never a silent `Ok` and never a participant that quietly discovers
/// nobody without saying why.
#[test]
fn a_rejected_signature_surfaces_as_a_cloud_error_not_a_silent_ok() {
    // Declared first so it is dropped last, after the participant's
    // sockets are closed.
    let domain = unique_domain();
    assert_no_ambient_spdp_peers();

    let fake = FakeCloudMap::start().expect("fake Cloud Map endpoint");
    let config = AwsCloudMapConfig::new(NAMESPACE, FAKE_SERVICE_ID, "eu-west-3")
        .with_domain_id(domain.id())
        .with_endpoint_override(fake.base_url())
        // A secret the endpoint does not know: every request 403s.
        .with_credentials(AwsCredentialSource::Static {
            access_key_id: "AKIDEXAMPLE".into(),
            secret_access_key: "the-wrong-secret".into(),
            session_token: None,
        });

    let participant = with_reserved_ports(8, |[mcast, sedp, user]: [u16; 3]| {
        Participant::builder("cloud_aws_bad_signature")
            .domain_id(domain.id())
            .with_transport(TransportMode::UdpMulticast)
            .with_discovery_ports(mcast, sedp, user)
            .participant_id(Some(0))
            .with_aws_cloud_map_config(config.clone())
            .with_cloud_poll_interval(POLL_INTERVAL)
            .build()
    })
    .expect("build() succeeds: a registry failure is not a security path");

    assert!(
        wait_until(Duration::from_secs(10), || {
            participant.cloud_discovery_status().is_some_and(|status| {
                !status.registered
                    && status.register_attempts >= 1
                    && status
                        .last_error
                        .as_deref()
                        .is_some_and(|error| error.contains("InvalidSignatureException"))
            })
        }),
        "a rejected signature did not surface in the poller status: {:?}",
        participant.cloud_discovery_status()
    );
    assert!(fake.registered_ids().is_empty());
    assert!(!fake.signature_failures().is_empty());

    // The public accessor must not echo the secret it was configured with.
    let public_config = participant
        .cloud_discovery_config()
        .expect("a cloud config is set");
    assert!(
        !public_config.contains("the-wrong-secret"),
        "the public cloud config echoed a secret: {}",
        public_config
    );
    assert!(public_config.contains(NAMESPACE));
    // The redacted form must still be a config: the standalone helper
    // re-parses it (and therefore falls back to the default credential
    // chain, which is what its rustdoc says).
    let standalone = participant
        .create_aws_cloud_map()
        .expect("the redacted public config re-parses");
    assert_eq!(standalone.config().namespace, NAMESPACE);
    assert_eq!(standalone.config().domain_id, domain.id());
}

/// The string form the three-argument API writes reaches the same
/// backend: it must not need a typed configuration to work.
///
/// The string is parsed here EXACTLY as `with_aws_cloud_map` wrote it and
/// only then pointed at the fake, because a participant built straight
/// from `with_aws_cloud_map` would take the default regional endpoints
/// and its poller would open TLS to the real
/// `servicediscovery.<region>.amazonaws.com`: unsolicited authenticated
/// traffic to a third party from `cargo test`, and a test that depends on
/// DNS. That the builder writes this very string is pinned, with no
/// participant at all, by the unit test
/// `cloud_discovery_runtime::tests::the_three_argument_builder_api_writes_the_json_the_mapper_parses`.
#[test]
fn the_three_argument_string_form_reaches_the_same_backend() {
    // Declared first so it is dropped last, after the participant's
    // sockets are closed.
    let domain = unique_domain();
    assert_no_ambient_spdp_peers();

    let fake = FakeCloudMap::start().expect("fake Cloud Map endpoint");
    let written = serde_json::json!({
        "namespace": NAMESPACE,
        "service": FAKE_SERVICE_ID,
        "region": "eu-west-3",
    })
    .to_string();
    let config = AwsCloudMapConfig::from_json(&written).expect("the three-field form parses");
    // Everything else really is a default.
    assert_eq!(config.health_status, AwsHealthStatus::All);
    assert!(config.endpoint_override.is_none());
    assert!(config.service_name.is_none());

    let config = config
        .with_domain_id(domain.id())
        .with_endpoint_override(fake.base_url())
        .with_credentials(AwsCredentialSource::Container {
            uri: fake.credentials_url(),
            authorization: None,
        });

    let participant = with_reserved_ports(8, |[mcast, sedp, user]: [u16; 3]| {
        Participant::builder("cloud_aws_three_arg")
            .domain_id(domain.id())
            .with_transport(TransportMode::UdpMulticast)
            .with_discovery_ports(mcast, sedp, user)
            .participant_id(Some(0))
            .with_aws_cloud_map_config(config.clone())
            .with_cloud_poll_interval(POLL_INTERVAL)
            .build()
    })
    .expect("the three-argument AWS configuration builds a participant");

    assert_eq!(participant.cloud_discovery_provider(), Some("aws"));
    assert!(
        wait_until(Duration::from_secs(10), || participant
            .cloud_discovery_status()
            .is_some_and(|status| status.running && status.registered)),
        "the AWS poller never registered: {:?}",
        participant.cloud_discovery_status()
    );
    assert!(fake.signature_failures().is_empty());
    // The standalone backend helper rebuilds from the public config.
    let backend = participant
        .create_aws_cloud_map()
        .expect("the standalone backend rebuilds from the public config");
    assert_eq!(backend.config().namespace, NAMESPACE);
    assert_eq!(backend.config().region, "eu-west-3");
}

/// Nothing in this file may reach a host it does not own: every AWS call
/// a test makes goes to a loopback fake. A participant built with the
/// default endpoints would talk to the real regional Cloud Map endpoints,
/// so the rule is asserted rather than trusted.
#[test]
fn every_configuration_used_here_points_at_a_loopback_endpoint() {
    let fake = FakeCloudMap::start().expect("fake Cloud Map endpoint");
    let loopback_only = |config: &AwsCloudMapConfig| {
        let endpoint = config
            .endpoint_override
            .as_deref()
            .expect("a test configuration must override the AWS endpoint");
        assert!(
            endpoint.starts_with("http://127.0.0.1:"),
            "a test configuration points somewhere other than loopback: {}",
            endpoint
        );
        // The credential chain must not reach out either: a default chain
        // would try IMDS, which answers on an EC2 or EKS runner.
        assert!(
            !matches!(config.credentials, AwsCredentialSource::DefaultChain),
            "a test configuration would walk the default credential chain"
        );
    };
    // A literal domain, on purpose: this test builds no participant and
    // binds no socket, it only inspects configuration values. Leasing a
    // domain here would take a slot from the tests that do bind.
    loopback_only(&config_for(&fake, 0));
    loopback_only(
        &AwsCloudMapConfig::new(NAMESPACE, FAKE_SERVICE_ID, "eu-west-3")
            .with_endpoint_override(fake.base_url())
            .with_credentials(AwsCredentialSource::Static {
                access_key_id: "AKIDEXAMPLE".into(),
                secret_access_key: "test-only-secret".into(),
                session_token: None,
            }),
    );
}
