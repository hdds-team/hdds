// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Participant-level proofs for the Consul backend (CONSUL-1, CONSUL-2).
//!
//! Everything here goes through the PUBLIC builder API against
//! `test_support::fake_consul`, the in-process Consul agent: the
//! participant registers itself with a TTL check, refreshes it on every
//! poll, stops seeing a peer whose own check went critical, and
//! deregisters (service + KV entry) when it is dropped.
//!
//! `consul_live_agent_round_trip` is the CONSUL-2 opt-in counterpart: the
//! same chain against a REAL agent (`docker compose -f
//! tools/docker-consul/compose.yml up -d`, then
//! `HDDS_CONSUL_URL=http://127.0.0.1:8500`). It is `#[ignore]`d and is
//! evidence, never the hermetic gate.

#![cfg(feature = "cloud-discovery")]

use hdds::discovery::cloud::{CloudDiscovery, Locator, ParticipantInfo, LOCATOR_KIND_UDPV4};
// From the crate root, like `ConsulDiscovery` itself: a user following
// the existing idiom writes `use hdds::ConsulOptions;`, so the two
// re-export lists must carry the options types too.
use hdds::test_support::domains::unique_domain;
use hdds::test_support::fake_consul::{FakeConsulAgent, FakeService};
use hdds::test_support::ports::with_reserved_ports;
use hdds::{ConsulHealthPolicy, ConsulOptions};
use hdds::{Participant, TransportMode};
use std::collections::HashMap;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// Registry poll interval for these tests: the heartbeat cadence too.
const POLL_INTERVAL: Duration = Duration::from_millis(200);

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

/// A participant whose only peer source is `url`, on the domain its test
/// leased (no shared constant: a parallel test binary must not be able to
/// pick the same one).
fn participant(name: &str, url: &str, id: u8, domain: u32) -> Arc<Participant> {
    with_reserved_ports(8, |[mcast, sedp, user]: [u16; 3]| {
        Participant::builder(name)
            .domain_id(domain)
            .with_transport(TransportMode::UdpMulticast)
            .with_discovery_ports(mcast, sedp, user)
            .participant_id(Some(id))
            .with_consul(url)
            .with_cloud_poll_interval(POLL_INTERVAL)
            .build()
    })
    .expect("participant with a cloud registry builds")
}

/// A peer registered by "another node" on `domain`, with its own TTL
/// check. `domain` must be the reader's own domain, or the participant
/// filters this record out before the test can say anything about it.
fn peer_service(guid: [u8; 16], port: u16, domain: u32) -> FakeService {
    let mut address = [0u8; 16];
    address[12..].copy_from_slice(&[127, 0, 0, 1]);
    let id = format!("hdds-participant-{}", hex(&guid));
    FakeService {
        check_id: Some(format!("service:{}", id)),
        check_ttl: Some("10s".to_string()),
        check_deregister_after: Some("60s".to_string()),
        id,
        name: "hdds-participant".to_string(),
        tags: vec![format!("domain-{}", domain), "hdds".to_string()],
        address: "127.0.0.1".to_string(),
        port,
        meta: HashMap::from([
            ("guid".to_string(), hex(&guid)),
            ("domain_id".to_string(), domain.to_string()),
            ("participant_name".to_string(), "injected-peer".to_string()),
            (
                "locators".to_string(),
                format!(
                    r#"[{{"kind":1,"port":{},"address":"{}"}}]"#,
                    port,
                    hex(&address)
                ),
            ),
        ]),
    }
}

/// CONSUL-1, participant level: the shipped builder registers the
/// participant with a TTL check and REFRESHES it on every poll. Without
/// the refresh the check goes critical and every peer stops seeing this
/// participant while it is perfectly alive.
#[test]
fn consul_participant_registers_with_a_ttl_check_and_heartbeats_it() {
    // Declared first so it is dropped last, after the participant's
    // sockets are closed.
    let domain = unique_domain();
    let agent = FakeConsulAgent::start();
    let participant = participant("consul_ttl_self", &agent.url(), 0, domain.id());
    let own_hex = hex(&participant.guid().as_bytes());
    let service_id = format!("hdds-participant-{}", own_hex);
    let check_id = format!("service:{}", service_id);

    assert!(
        wait_until(Duration::from_secs(10), || {
            participant
                .cloud_discovery_status()
                .is_some_and(|status| status.registered)
        }),
        "the participant never reported itself registered"
    );

    let service = agent
        .service(&service_id)
        .expect("the participant registered under its own GUID");
    assert_eq!(service.meta.get("guid"), Some(&own_hex));
    // The tag is derived from the participant's own domain, whatever it
    // leased -- that derivation is what is under test, not the number.
    let domain_tag = format!("domain-{}", domain.id());
    assert_eq!(
        service.tags.first().map(String::as_str),
        Some(domain_tag.as_str())
    );
    assert_eq!(
        service.check_id.as_deref(),
        Some(check_id.as_str()),
        "no TTL check was registered"
    );
    assert_eq!(service.check_ttl.as_deref(), Some("10s"));

    assert!(
        wait_until(Duration::from_secs(10), || agent.check_passes(&check_id)
            >= 2),
        "the TTL check was never refreshed ({} refreshes)",
        agent.check_passes(&check_id)
    );
    assert_eq!(agent.check_status(&check_id).as_deref(), Some("passing"));
}

/// CONSUL-1, the point of the whole thing: a peer that stops refreshing
/// its check (it crashed) must LEAVE this participant's registry peer
/// set. Reading `/v1/catalog/service` instead of the health endpoint kept
/// handing the survivors a dead unicast SPDP destination for at least the
/// one minute of Consul's deregister-after floor.
#[test]
fn consul_peer_that_stops_heartbeating_leaves_the_peer_set() {
    // ONE lease: the injected peer is only a peer if it is on the
    // reader's own domain. Declared first so it is dropped last.
    let domain = unique_domain();
    let agent = FakeConsulAgent::start();
    let mut peer_guid = [0x5Au8; 16];
    peer_guid[12..].copy_from_slice(&[0, 0, 1, 0xC1]);
    let peer = peer_service(peer_guid, 7411, domain.id());
    let peer_check = peer.check_id.clone().expect("peer check id");
    agent.inject_service(peer);

    let participant = participant("consul_peer_ttl", &agent.url(), 0, domain.id());
    assert!(
        wait_until(Duration::from_secs(10), || {
            participant
                .cloud_discovery_status()
                .is_some_and(|status| status.registry_peers == 1)
        }),
        "the injected peer never reached the peer set"
    );

    // The peer crashes: its TTL runs out.
    agent.expire_check(&peer_check);
    assert!(
        wait_until(Duration::from_secs(10), || {
            participant
                .cloud_discovery_status()
                .is_some_and(|status| status.registry_peers == 0)
        }),
        "a peer whose TTL check went critical is still a registry peer"
    );
}

/// A registry agent that forgot this participant (restart, operator
/// cleanup) answers 404 to the check refresh. The poller must register
/// again instead of believing it is still in the catalog.
#[test]
fn consul_participant_re_registers_when_the_agent_forgets_its_check() {
    // Declared first so it is dropped last, after the participant's
    // sockets are closed.
    let domain = unique_domain();
    let agent = FakeConsulAgent::start();
    let participant = participant("consul_reregister", &agent.url(), 0, domain.id());
    assert!(wait_until(Duration::from_secs(10), || {
        participant
            .cloud_discovery_status()
            .is_some_and(|status| status.registered)
    }));
    let registers_before = agent.requests_to("PUT", "/v1/agent/service/register").len();

    agent.fail_route("/v1/agent/check/pass/", Some(404));
    assert!(
        wait_until(Duration::from_secs(10), || {
            participant
                .cloud_discovery_status()
                .is_some_and(|status| !status.registered)
        }),
        "a refused check refresh left the participant believing it is registered"
    );

    agent.fail_route("/v1/agent/check/pass/", None);
    assert!(
        wait_until(Duration::from_secs(10), || {
            participant
                .cloud_discovery_status()
                .is_some_and(|status| status.registered)
                && agent.requests_to("PUT", "/v1/agent/service/register").len() > registers_before
        }),
        "the participant never registered itself again"
    );
}

/// Dropping the participant removes its service AND the one KV entry it
/// wrote -- exactly one, for its own domain.
#[test]
fn consul_participant_deregisters_and_deletes_one_kv_entry_on_drop() {
    // Declared first so it is dropped last, after the participant's
    // sockets are closed.
    let domain = unique_domain();
    let agent = FakeConsulAgent::start();
    let participant = participant("consul_drop", &agent.url(), 0, domain.id());
    let own_hex = hex(&participant.guid().as_bytes());
    let service_id = format!("hdds-participant-{}", own_hex);
    let kv_key = format!("hdds/participants/domain-{}/{}", domain.id(), own_hex);

    assert!(wait_until(Duration::from_secs(10), || {
        participant
            .cloud_discovery_status()
            .is_some_and(|status| status.registered)
    }));
    assert_eq!(agent.kv_keys(), vec![kv_key.clone()]);

    drop(participant);

    assert!(
        wait_until(Duration::from_secs(10), || agent
            .service(&service_id)
            .is_none()),
        "the service is still registered after the participant was dropped"
    );
    assert_eq!(
        agent.kv_deletes(),
        vec![kv_key],
        "exactly one KV delete, for this participant's own domain"
    );
}

/// The `ConsulOptions` surface reaches the wire through the builder: the
/// ACL token on every request, the datacenter on every query, and a
/// service name of the deployment's choosing.
#[test]
fn consul_options_from_the_builder_reach_every_request() {
    // Declared first so it is dropped last, after the participant's
    // sockets are closed.
    let domain = unique_domain();
    let agent = FakeConsulAgent::start();
    agent.require_token("builder-token");
    let url = agent.url();
    let participant = with_reserved_ports(8, |[mcast, sedp, user]: [u16; 3]| {
        Participant::builder("consul_options")
            .domain_id(domain.id())
            .with_transport(TransportMode::UdpMulticast)
            .with_discovery_ports(mcast, sedp, user)
            .participant_id(Some(0))
            .with_consul_options(
                &url,
                ConsulOptions::default()
                    .with_token("builder-token")
                    .with_datacenter("dc1")
                    .with_service_prefix("fleet-hdds")
                    .with_kv_mirror(false),
            )
            .with_cloud_poll_interval(POLL_INTERVAL)
            .build()
    })
    .expect("participant builds");

    assert!(
        wait_until(Duration::from_secs(10), || {
            participant
                .cloud_discovery_status()
                .is_some_and(|status| status.registered)
        }),
        "an ACL-enabled agent refused the participant: the token never left the builder"
    );
    let service_id = format!("fleet-hdds-{}", hex(&participant.guid().as_bytes()));
    assert!(
        agent.service(&service_id).is_some(),
        "custom service prefix ignored"
    );
    assert!(agent.kv_keys().is_empty(), "the KV mirror was switched off");
    for request in agent.requests() {
        assert_eq!(
            request.header("x-consul-token"),
            Some("builder-token"),
            "{} {} went out unauthenticated",
            request.method,
            request.target
        );
        let query = request.query().unwrap_or("");
        assert!(
            query == "dc=dc1" || query.starts_with("dc=dc1&"),
            "{} {} did not carry the datacenter",
            request.method,
            request.target
        );
    }
}

/// The backend handed out by `create_consul_discovery()` is driven by
/// the CALLER, not by the poller: it must carry the builder's options
/// (an ACL-enabled agent answers 403 without the token, and a fleet
/// registered under another service name answers an empty list -- not an
/// error), and it must NOT register a TTL check nobody refreshes. Left
/// on, the service registered through this backend goes critical one TTL
/// after registration and Consul drops it, while the participant is
/// perfectly alive.
#[test]
fn create_consul_discovery_carries_the_builder_options_and_no_unrefreshed_check() {
    // Declared first so it is dropped last, after the participant's
    // sockets are closed.
    let domain = unique_domain();
    let agent = FakeConsulAgent::start();
    agent.require_token("manual-token");
    let url = agent.url();
    let participant = with_reserved_ports(8, |[mcast, sedp, user]: [u16; 3]| {
        Participant::builder("consul_manual")
            .domain_id(domain.id())
            .with_transport(TransportMode::UdpMulticast)
            .with_discovery_ports(mcast, sedp, user)
            .participant_id(Some(0))
            .with_consul_options(
                &url,
                ConsulOptions::default()
                    .with_token("manual-token")
                    .with_datacenter("dc1")
                    .with_service_prefix("fleet-hdds")
                    .with_kv_mirror(false),
            )
            .with_cloud_poll_interval(POLL_INTERVAL)
            .build()
    })
    .expect("participant builds");

    let consul = participant
        .create_consul_discovery()
        .expect("a consul backend");
    let mut address = [0u8; 16];
    address[12..].copy_from_slice(&[127, 0, 0, 1]);
    let guid = [0x7Bu8; 16];
    let info = ParticipantInfo {
        guid,
        name: "hand-registered".to_string(),
        domain_id: domain.id(),
        locators: vec![Locator {
            kind: LOCATOR_KIND_UDPV4,
            port: 7499,
            address,
        }],
        metadata: HashMap::new(),
    };

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    runtime
        .block_on(consul.register_participant(&info))
        .expect("the ACL token and the service prefix must reach a hand-built backend");

    let service_id = format!("fleet-hdds-{}", hex(&guid));
    let service = agent
        .service(&service_id)
        .expect("registered under the builder's service prefix");
    assert!(
        service.check_id.is_none(),
        "a TTL check nobody refreshes was registered: {:?}",
        service.check_id
    );
    assert!(
        agent.kv_keys().is_empty(),
        "the builder switched the KV mirror off"
    );
    // The domain and the datacenter reach the hand-built backend too:
    // the tag must carry the domain this test leased, whatever it is.
    let domain_tag = format!("domain-{}", domain.id());
    assert_eq!(
        service.tags.first().map(String::as_str),
        Some(domain_tag.as_str())
    );
    let peers = runtime
        .block_on(consul.discover_participants())
        .expect("discover");
    assert!(peers.iter().any(|p| p.guid == guid));
    for request in agent.requests() {
        let query = request.query().unwrap_or("");
        assert!(
            query == "dc=dc1" || query.starts_with("dc=dc1&"),
            "{} {} did not carry the datacenter",
            request.method,
            request.target
        );
    }
}

/// CONSUL-2: the same chain against a REAL Consul agent. Opt-in.
///
/// ```text
/// docker compose -f tools/docker-consul/compose.yml up -d
/// HDDS_CONSUL_URL=http://127.0.0.1:8500 \
///   cargo test -p hdds --all-features --test cloud_consul -- --ignored
/// ```
///
/// Skipped BY NAME (not silently) when `HDDS_CONSUL_URL` is unset, so a
/// run that proves nothing says so.
#[test]
#[ignore = "needs a real Consul agent: set HDDS_CONSUL_URL (tools/docker-consul)"]
fn consul_live_agent_round_trip() {
    // ONE lease for the pair: a and b must discover each other, so they
    // share a domain. Declared first so it is dropped last.
    let domain = unique_domain();
    let Ok(url) = std::env::var("HDDS_CONSUL_URL") else {
        println!(
            "SKIPPED consul_live_agent_round_trip: HDDS_CONSUL_URL is not set \
             (start tools/docker-consul/compose.yml first)"
        );
        return;
    };

    // A service name of this run alone: a shared agent must not mix runs.
    let prefix = format!("hdds-live-{}", std::process::id());
    let options = |extra: Option<&str>| {
        let mut options = ConsulOptions::default()
            .with_service_prefix(&prefix)
            .with_health(ConsulHealthPolicy::Ttl);
        if let Some(token) = extra {
            options = options.with_token(token);
        }
        options
    };
    let token = std::env::var("HDDS_CONSUL_TOKEN").ok();

    let (a, b) = with_reserved_ports(
        8,
        |[mcast, a_sedp, a_user, b_sedp, b_user]: [u16; 5]| -> hdds::Result<_> {
            let a = Participant::builder("consul_live_a")
                .domain_id(domain.id())
                .with_transport(TransportMode::UdpMulticast)
                .with_discovery_ports(mcast, a_sedp, a_user)
                .participant_id(Some(0))
                .with_consul_options(&url, options(token.as_deref()))
                .with_cloud_poll_interval(Duration::from_secs(1))
                .build()?;
            let b = Participant::builder("consul_live_b")
                .domain_id(domain.id())
                .with_transport(TransportMode::UdpMulticast)
                .with_discovery_ports(mcast, b_sedp, b_user)
                .participant_id(Some(1))
                .with_consul_options(&url, options(token.as_deref()))
                .with_cloud_poll_interval(Duration::from_secs(1))
                .build()?;
            Ok((a, b))
        },
    )
    .expect("two participants against the live agent");

    for (name, participant) in [("a", &a), ("b", &b)] {
        assert!(
            wait_until(Duration::from_secs(30), || participant
                .cloud_discovery_status()
                .is_some_and(|status| status.registered)),
            "participant {} never registered with {}: {:?}",
            name,
            url,
            participant.cloud_discovery_status()
        );
    }
    for (name, participant) in [("a", &a), ("b", &b)] {
        assert!(
            wait_until(Duration::from_secs(30), || participant
                .cloud_discovery_status()
                .is_some_and(|status| status.registry_peers >= 1)),
            "participant {} never discovered its peer through {}: {:?}",
            name,
            url,
            participant.cloud_discovery_status()
        );
    }

    // A clean shutdown deregisters: b must lose the peer.
    drop(a);
    assert!(
        wait_until(Duration::from_secs(30), || b
            .cloud_discovery_status()
            .is_some_and(|status| status.registry_peers == 0)),
        "the dropped participant is still listed by the live agent: {:?}",
        b.cloud_discovery_status()
    );
}
