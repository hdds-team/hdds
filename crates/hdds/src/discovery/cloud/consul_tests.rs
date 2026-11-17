// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Hermetic proofs for the Consul backend against an in-process agent.
//!
//! Every test here drives the REAL `ConsulDiscovery` (the reqwest client,
//! the real URLs, the real JSON) against
//! [`crate::test_support::fake_consul::FakeConsulAgent`], which is the
//! shared fake HTTP server with the seven Consul routes modelled on top.
//! No container, no credential, no network beyond `127.0.0.1:0`.
//!
//! The docker `hashicorp/consul` counterpart is opt-in and lives in
//! `crates/hdds/tests/cloud_consul.rs` (`HDDS_CONSUL_URL`); it is evidence,
//! never the gate.

use std::collections::HashMap;
use std::time::Duration;

use super::{
    CloudDiscovery, ConsulDiscovery, ConsulHealthPolicy, ConsulOptions, Locator, ParticipantInfo,
    LOCATOR_KIND_UDPV4,
};
use crate::test_support::fake_consul::{FakeConsulAgent, FakeService};

const DOMAIN: u32 = 39;

/// One blocking test body over a current-thread runtime, the same shape
/// the poller thread uses.
fn block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("current-thread runtime")
        .block_on(future)
}

fn locator(a: u8, b: u8, c: u8, d: u8, port: u32) -> Locator {
    Locator {
        kind: LOCATOR_KIND_UDPV4,
        port,
        address: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, a, b, c, d],
    }
}

fn guid(tail: u8) -> [u8; 16] {
    let mut guid = [0u8; 16];
    guid[..8].copy_from_slice(&[0x01, 0x1a, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]);
    guid[8..12].copy_from_slice(&[0, 0, 0, tail]);
    guid[12..].copy_from_slice(&[0, 0, 1, 0xc1]);
    guid
}

fn info(tail: u8, locators: Vec<Locator>) -> ParticipantInfo {
    ParticipantInfo {
        guid: guid(tail),
        name: format!("node-{}", tail),
        domain_id: DOMAIN,
        locators,
        metadata: HashMap::from([("vendor".to_string(), "hdds".to_string())]),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn backend(agent: &FakeConsulAgent) -> ConsulDiscovery {
    ConsulDiscovery::new(agent.url())
        .expect("loopback endpoint")
        .with_domain_id(DOMAIN)
        .with_heartbeat_interval(Duration::from_secs(5))
}

/// The whole registration life cycle, asserted on the wire the agent saw:
/// the service body, the health query URL, the KV mirror, and a single KV
/// delete for THIS domain on deregistration.
#[test]
fn register_discover_deregister_round_trip_against_fake_agent() {
    let agent = FakeConsulAgent::start();
    let consul = backend(&agent);
    let own = info(
        1,
        vec![locator(127, 0, 0, 1, 7410), locator(127, 0, 0, 1, 7411)],
    );
    let service_id = format!("hdds-participant-{}", hex(&own.guid));

    block_on(consul.register_participant(&own)).expect("register");

    // ---- what the agent stored -------------------------------------
    let stored = agent
        .service(&service_id)
        .expect("service registered by id");
    assert_eq!(stored.name, "hdds-participant");
    assert_eq!(stored.tags, vec!["domain-39", "hdds", "dds"]);
    // Address and Port come from the SAME locator.
    assert_eq!((stored.address.as_str(), stored.port), ("127.0.0.1", 7410));
    assert_eq!(stored.meta.get("guid"), Some(&hex(&own.guid)));
    assert_eq!(stored.meta.get("domain_id"), Some(&"39".to_string()));
    assert_eq!(
        stored.meta.get("participant_name"),
        Some(&"node-1".to_string())
    );
    assert_eq!(stored.meta.get("user_vendor"), Some(&"hdds".to_string()));
    // The FULL locator set travels in Meta.locators; Address/Port carry
    // only the first one.
    let locators_meta = stored.meta.get("locators").expect("Meta.locators");
    assert!(
        locators_meta.contains("\"port\":7410") && locators_meta.contains("\"port\":7411"),
        "Meta.locators lost a locator: {}",
        locators_meta
    );

    // ---- the KV mirror ---------------------------------------------
    let kv_key = format!("hdds/participants/domain-39/{}", hex(&own.guid));
    assert_eq!(agent.kv_keys(), vec![kv_key.clone()]);

    // ---- discovery reads it back ------------------------------------
    let peers = block_on(consul.discover_participants()).expect("discover");
    assert_eq!(peers.len(), 1, "expected the one registered participant");
    assert_eq!(peers[0].guid, own.guid);
    assert_eq!(peers[0].domain_id, DOMAIN);
    assert_eq!(peers[0].name, "node-1");
    assert_eq!(peers[0].locators, own.locators, "full locator set expected");
    assert_eq!(
        peers[0].metadata.get("vendor").map(String::as_str),
        Some("hdds")
    );

    let health = agent
        .requests_to("GET", "/v1/health/service/")
        .pop()
        .expect("one health query");
    assert_eq!(health.path(), "/v1/health/service/hdds-participant");
    assert_eq!(health.query(), Some("tag=domain-39&passing=true"));

    // ---- deregistration ---------------------------------------------
    block_on(consul.deregister_participant(own.guid)).expect("deregister");
    assert!(
        agent.service(&service_id).is_none(),
        "service still registered"
    );
    assert_eq!(
        agent.kv_deletes(),
        vec![kv_key],
        "exactly one KV delete, for this participant's own domain"
    );
    assert!(agent.kv_keys().is_empty());
    assert!(block_on(consul.discover_participants())
        .expect("discover after deregister")
        .is_empty());
}

/// A service ID hex-encoding `guid[0..8]` would be vendor + host_id + the
/// two HIGH bytes of the big-endian PID -- zero for any PID below 65536.
/// Every participant on the host would then share one service ID, and each
/// registration would silently replace the previous one in the catalog. The
/// fake agent replaces by ID exactly like the real one, so this test sees
/// the peer loss the moment the scheme regresses.
#[test]
fn two_participants_of_one_host_both_survive_in_the_catalog() {
    let agent = FakeConsulAgent::start();
    let consul = backend(&agent);
    let first = info(1, vec![locator(127, 0, 0, 1, 7410)]);
    let second = info(2, vec![locator(127, 0, 0, 1, 7412)]);
    assert_eq!(
        first.guid[..8],
        second.guid[..8],
        "the fixture must share the first eight GUID bytes"
    );

    block_on(consul.register_participant(&first)).expect("register first");
    block_on(consul.register_participant(&second)).expect("register second");

    assert_eq!(
        agent.services().len(),
        2,
        "one participant replaced the other"
    );
    let peers = block_on(consul.discover_participants()).expect("discover");
    let mut guids: Vec<_> = peers.iter().map(|p| p.guid).collect();
    guids.sort();
    let mut expected = vec![first.guid, second.guid];
    expected.sort();
    assert_eq!(guids, expected);
}

/// CONSUL-1: the registered check is a TTL check that starts passing, and
/// the heartbeat refreshes it. An agent that has forgotten the check
/// (restart) answers 404, which the caller turns into a re-registration.
#[test]
fn ttl_check_is_registered_passing_and_the_heartbeat_refreshes_it() {
    let agent = FakeConsulAgent::start();
    let consul = backend(&agent);
    let own = info(1, vec![locator(127, 0, 0, 1, 7410)]);
    let service_id = format!("hdds-participant-{}", hex(&own.guid));
    let check_id = format!("service:{}", service_id);

    block_on(consul.register_participant(&own)).expect("register");
    let stored = agent.service(&service_id).expect("service");
    assert_eq!(stored.check_id.as_deref(), Some(check_id.as_str()));
    // 5 s heartbeat -> 15 s TTL; grace stays at Consul's one-minute floor.
    assert_eq!(stored.check_ttl.as_deref(), Some("15s"));
    assert_eq!(stored.check_deregister_after.as_deref(), Some("60s"));
    assert_eq!(agent.check_status(&check_id).as_deref(), Some("passing"));

    block_on(consul.heartbeat(own.guid)).expect("heartbeat");
    block_on(consul.heartbeat(own.guid)).expect("heartbeat again");
    assert_eq!(agent.check_passes(&check_id), 2);
    let refresh = agent
        .requests_to("PUT", "/v1/agent/check/pass/")
        .pop()
        .expect("a check refresh");
    assert_eq!(
        refresh.path(),
        "/v1/agent/check/pass/service%3Ahdds-participant-".to_string() + &hex(&own.guid)
    );

    // The agent forgot the service: the refresh must FAIL so the caller
    // registers again instead of believing it is still in the catalog.
    block_on(consul.deregister_participant(own.guid)).expect("deregister");
    let error = block_on(consul.heartbeat(own.guid)).expect_err("404 must surface");
    assert!(
        format!("{}", error).contains("TTL check refresh failed"),
        "unexpected error: {}",
        error
    );

    // With the policy off, no check is registered and the heartbeat is a
    // no-op that never touches the agent.
    let quiet = backend(&agent)
        .with_options(ConsulOptions::default().with_health(ConsulHealthPolicy::Disabled));
    block_on(quiet.register_participant(&own)).expect("register without a check");
    assert!(agent
        .service(&service_id)
        .expect("service")
        .check_id
        .is_none());
    let refreshes = agent.requests_to("PUT", "/v1/agent/check/pass/").len();
    block_on(quiet.heartbeat(own.guid)).expect("no-op heartbeat");
    assert_eq!(
        agent.requests_to("PUT", "/v1/agent/check/pass/").len(),
        refreshes
    );
}

/// A crashed participant stops refreshing its TTL check; the check goes
/// critical and the health query must stop returning it. Asking
/// `/v1/catalog/service` instead would keep
/// handing every survivor a dead unicast SPDP destination.
#[test]
fn a_peer_whose_ttl_check_expired_is_no_longer_discovered() {
    let agent = FakeConsulAgent::start();
    let consul = backend(&agent);
    let alive = info(1, vec![locator(127, 0, 0, 1, 7410)]);
    let crashed = info(2, vec![locator(127, 0, 0, 1, 7412)]);
    block_on(consul.register_participant(&alive)).expect("register alive");
    block_on(consul.register_participant(&crashed)).expect("register crashed");
    assert_eq!(
        block_on(consul.discover_participants())
            .expect("discover")
            .len(),
        2
    );

    agent.expire_check(&format!("service:hdds-participant-{}", hex(&crashed.guid)));

    let peers = block_on(consul.discover_participants()).expect("discover");
    assert_eq!(peers.len(), 1, "the critical instance is still discovered");
    assert_eq!(peers[0].guid, alive.guid);

    // A peer that registered NO check at all is not health-filtered away:
    // nothing about it is failing.
    agent.inject_service(FakeService {
        id: "hdds-participant-checkless".to_string(),
        name: "hdds-participant".to_string(),
        tags: vec!["domain-39".to_string()],
        address: "127.0.0.1".to_string(),
        port: 7420,
        meta: HashMap::from([
            ("guid".to_string(), hex(&guid(9))),
            ("domain_id".to_string(), "39".to_string()),
        ]),
        ..FakeService::default()
    });
    let peers = block_on(consul.discover_participants()).expect("discover");
    assert_eq!(peers.len(), 2);
    assert!(peers.iter().any(|p| p.guid == guid(9)));
}

/// An ACL-enabled Consul answers 403 without a token. Every call the
/// backend makes must carry it, and no `Debug` may render it.
#[test]
fn token_is_sent_as_x_consul_token_header_on_every_request() {
    let agent = FakeConsulAgent::start();
    agent.require_token("s3cr3t-acl-token");
    let own = info(1, vec![locator(127, 0, 0, 1, 7410)]);

    // Without the token every call fails, loudly.
    let anonymous = backend(&agent);
    let error = block_on(anonymous.register_participant(&own)).expect_err("403 expected");
    assert!(
        format!("{}", error).contains("403"),
        "unexpected: {}",
        error
    );
    assert!(block_on(anonymous.discover_participants()).is_err());

    // Only the authenticated phase is asserted on below.
    agent.clear_requests();
    let consul =
        backend(&agent).with_options(ConsulOptions::default().with_token("s3cr3t-acl-token"));
    block_on(consul.register_participant(&own)).expect("register");
    block_on(consul.heartbeat(own.guid)).expect("heartbeat");
    block_on(consul.discover_participants()).expect("discover");
    assert!(block_on(consul.health_check()).expect("health check"));
    block_on(consul.deregister_participant(own.guid)).expect("deregister");

    let authenticated: Vec<_> = agent
        .requests()
        .into_iter()
        .filter(|r| r.header("x-consul-token") == Some("s3cr3t-acl-token"))
        .collect();
    assert_eq!(
        authenticated.len(),
        7,
        "register, KV put, heartbeat, health query, agent/self, deregister and KV delete \
         all carry the token"
    );
    for method_and_path in [
        ("PUT", "/v1/agent/service/register"),
        ("PUT", "/v1/kv/"),
        ("PUT", "/v1/agent/check/pass/"),
        ("GET", "/v1/health/service/"),
        ("GET", "/v1/agent/self"),
        ("PUT", "/v1/agent/service/deregister/"),
        ("DELETE", "/v1/kv/"),
    ] {
        assert!(
            agent
                .requests_to(method_and_path.0, method_and_path.1)
                .iter()
                .all(|r| r.header("x-consul-token") == Some("s3cr3t-acl-token")),
            "{} {} went out without the ACL token",
            method_and_path.0,
            method_and_path.1
        );
    }
    assert!(!format!("{:?}", consul).contains("s3cr3t-acl-token"));
}

/// `with_datacenter` must reach the lookup as well as register/deregister/KV
/// (the query URL is built by hand): a participant registered in dc1 must
/// not be looked for in the agent's default datacenter.
#[test]
fn datacenter_is_applied_to_every_request_including_the_health_query() {
    let agent = FakeConsulAgent::start();
    let consul = backend(&agent).with_datacenter("dc1");
    let own = info(1, vec![locator(127, 0, 0, 1, 7410)]);

    block_on(consul.register_participant(&own)).expect("register");
    block_on(consul.heartbeat(own.guid)).expect("heartbeat");
    block_on(consul.discover_participants()).expect("discover");
    block_on(consul.deregister_participant(own.guid)).expect("deregister");

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

/// README announces "Key-value registration": a KV write the agent
/// refuses is a FAILED registration (retried and reported by the poller),
/// not a silent hole. A deployment whose token has no `key:write` turns
/// the mirror off explicitly.
#[test]
fn kv_mirror_failure_fails_the_registration_and_can_be_switched_off() {
    let agent = FakeConsulAgent::start();
    let consul = backend(&agent);
    let own = info(1, vec![locator(127, 0, 0, 1, 7410)]);
    agent.fail_route("/v1/kv/", Some(403));

    let error = block_on(consul.register_participant(&own)).expect_err("KV failure must surface");
    let message = format!("{}", error);
    assert!(
        message.contains("KV registration failed"),
        "unexpected: {}",
        message
    );
    assert!(message.contains("403"), "unexpected: {}", message);
    assert!(
        message.contains("with_kv_mirror(false)"),
        "no way out: {}",
        message
    );
    // The service accepted a moment earlier is rolled back: a half
    // registration flaps (the poller retries it, re-PUTting Status
    // "passing" every time, and the TTL expires in between) while
    // `status.registered` never becomes true.
    assert!(
        message.contains("rolled back"),
        "the rollback is not reported: {}",
        message
    );
    assert!(
        agent.services().is_empty(),
        "a half-registered service was left in the catalog: {:?}",
        agent.services()
    );
    assert_eq!(
        agent
            .requests_to("PUT", "/v1/agent/service/deregister/")
            .len(),
        1,
        "exactly one rollback"
    );

    let without_mirror =
        backend(&agent).with_options(ConsulOptions::default().with_kv_mirror(false));
    block_on(without_mirror.register_participant(&own)).expect("register without the mirror");
    let before = agent.requests_to("PUT", "/v1/kv/").len();
    block_on(without_mirror.deregister_participant(own.guid)).expect("deregister");
    assert_eq!(agent.requests_to("PUT", "/v1/kv/").len(), before);
    assert!(agent.kv_deletes().is_empty(), "no mirror, no KV traffic");
}

/// A registry hiccup must never read as "the registry is empty": the
/// poller keeps its last peer view only because this returns `Err`.
///
/// This is a regression guard for a property that already holds.
#[test]
fn non_2xx_health_query_is_an_error_not_an_empty_registry() {
    let agent = FakeConsulAgent::start();
    let consul = backend(&agent);
    agent.fail_all(Some(503));
    let error = block_on(consul.discover_participants()).expect_err("503 must surface");
    assert!(
        format!("{}", error).contains("503"),
        "unexpected: {}",
        error
    );

    agent.fail_all(None);
    assert!(block_on(consul.discover_participants())
        .expect("recovered")
        .is_empty());
}

/// A `Meta` VALUE over 512 characters makes Consul refuse the WHOLE
/// registration (`HTTP 400 Invalid Service Meta`), and the poller then
/// retries the same refused body with backoff for the life of the
/// process. MEASURED against hashicorp/consul 1.20.2: seven locators are
/// 477 characters and register, eight are 545 and come back 400. A host
/// with eight IPv4 addresses is ordinary -- the multicast transport
/// enumerates every interface when it finds no primary one.
#[test]
fn eight_locators_still_register_because_meta_stays_under_the_512_cap() {
    let agent = FakeConsulAgent::start();
    let consul = backend(&agent);
    let locators: Vec<Locator> = (1..=8)
        .map(|i| locator(192, 168, 1, i, 7400 + i as u32))
        .collect();
    let own = info(1, locators.clone());
    let service_id = format!("hdds-participant-{}", hex(&own.guid));

    block_on(consul.register_participant(&own)).expect("eight locators must still register");

    let stored = agent.service(&service_id).expect("service registered");
    let meta = stored.meta.get("locators").expect("Meta.locators");
    assert!(
        meta.len() <= 512,
        "Meta.locators is {} characters, Consul refuses over 512: {}",
        meta.len(),
        meta
    );
    // The locator the service Address/Port came from is never the one
    // dropped: it is serialised first.
    assert!(meta.contains("\"port\":7401"), "{}", meta);
    assert_eq!(
        (stored.address.as_str(), stored.port),
        ("192.168.1.1", 7401)
    );

    let peers = block_on(consul.discover_participants()).expect("discover");
    assert_eq!(peers.len(), 1);
    assert!(
        !peers[0].locators.is_empty() && peers[0].locators.len() <= locators.len(),
        "{:?}",
        peers[0].locators
    );
    assert!(peers[0].locators.contains(&locators[0]));
}

/// One metadata key Consul refuses kills the registration for ever (the
/// poller retries the same body with backoff). MEASURED against
/// hashicorp/consul 1.20.2: `user_my.key` = `HTTP 400 Invalid Service
/// Meta ... Key contains invalid characters`. Caught here, before the
/// request, with the offending key named.
#[test]
fn metadata_consul_would_refuse_fails_before_the_request_and_names_the_key() {
    let agent = FakeConsulAgent::start();
    let consul = backend(&agent);
    let mut own = info(1, vec![locator(127, 0, 0, 1, 7410)]);
    own.metadata
        .insert("my.key".to_string(), "value".to_string());

    let error = block_on(consul.register_participant(&own)).expect_err("a bad key must not fly");
    let message = format!("{}", error);
    assert!(
        message.contains("my.key"),
        "the key is not named: {}",
        message
    );
    assert!(
        agent
            .requests_to("PUT", "/v1/agent/service/register")
            .is_empty(),
        "a body the agent would answer 400 to was sent anyway"
    );

    // An over-long value is refused the same way.
    let mut own = info(1, vec![locator(127, 0, 0, 1, 7410)]);
    own.metadata.insert("blob".to_string(), "x".repeat(513));
    let message = format!(
        "{}",
        block_on(consul.register_participant(&own)).expect_err("an over-long value must not fly")
    );
    assert!(message.contains("user_blob"), "unexpected: {}", message);
}

/// Falling back to a hard-coded `127.0.0.1:7400` because the participant
/// offered no usable unicast locator publishes an endpoint it does not
/// listen on, and every peer then unicasts SPDP into it. Note what the
/// check really is: UDPv4, non-zero port, not `0.0.0.0`, not multicast --
/// a loopback locator IS usable and does register.
#[test]
fn register_refuses_a_participant_without_a_routable_locator() {
    let agent = FakeConsulAgent::start();
    let consul = backend(&agent);
    let unspecified = Locator {
        kind: LOCATOR_KIND_UDPV4,
        port: 7410,
        address: [0; 16],
    };

    for locators in [vec![], vec![unspecified]] {
        let error = block_on(consul.register_participant(&info(1, locators)))
            .expect_err("a participant with no routable locator must not register");
        assert!(
            format!("{}", error).contains("no usable unicast IPv4"),
            "unexpected: {}",
            error
        );
    }
    assert!(agent.services().is_empty());
    assert!(
        agent
            .requests_to("PUT", "/v1/agent/service/register")
            .is_empty(),
        "nothing should have been sent"
    );
}

// ======================================================================
// Blocking queries (long polling on the Consul index)
//
// Consul carries the index in the `X-Consul-Index` RESPONSE HEADER, so
// every proof below drives the real client against a fake agent that is
// told which index to answer, and asserts on the QUERY STRING the agent
// actually received. `FakeConsulAgent` answers at once whatever `wait`
// says -- these tests are about what the client sends and what it does
// with the index, not about how long a real agent holds a socket.
// ======================================================================

/// A backend that long-polls, on a cadence slow enough that the clamp in
/// `ConsulDiscovery::blocking_wait` leaves the requested wait alone: TTL
/// is 3 x 60 s, so the ceiling is 90 s and a 30 s request survives whole.
/// That keeps the assertions about `wait=30s` and not about the clamp,
/// which has its own tests in `consul.rs`.
fn blocking_backend(agent: &FakeConsulAgent) -> ConsulDiscovery {
    ConsulDiscovery::new(agent.url())
        .expect("loopback endpoint")
        .with_domain_id(DOMAIN)
        .with_heartbeat_interval(Duration::from_secs(60))
        .with_options(ConsulOptions::default().with_blocking_queries(Duration::from_secs(30)))
}

/// The query string of every health query the agent has served, in order.
fn health_queries(agent: &FakeConsulAgent) -> Vec<String> {
    agent
        .requests_to("GET", "/v1/health/service/")
        .iter()
        .map(|request| request.query().unwrap_or("").to_string())
        .collect()
}

/// The plain query this backend has always sent, and still sends first.
const PLAIN_QUERY: &str = "tag=domain-39&passing=true";

/// Rule 7: the first query of a process has no index to wait on. Consul
/// reads `index=0` as "answer now", so sending one would be a plain read
/// wearing a long poll's clothes; the index is left off and the answer's
/// header seeds it.
#[test]
fn the_first_blocking_query_sends_no_index() {
    let agent = FakeConsulAgent::start();
    agent.set_health_index(Some(42));
    let consul = blocking_backend(&agent);

    block_on(consul.discover_participants()).expect("first query");

    assert_eq!(health_queries(&agent), vec![PLAIN_QUERY.to_string()]);
}

/// Rule 2: once an index is known, it goes on the wire as
/// `index=<N>&wait=<duration>`, with the wait rendered the way Consul
/// parses it.
#[test]
fn a_later_blocking_query_sends_the_stored_index_and_the_wait() {
    let agent = FakeConsulAgent::start();
    agent.set_health_index(Some(42));
    let consul = blocking_backend(&agent);

    block_on(consul.discover_participants()).expect("first query");
    block_on(consul.discover_participants()).expect("second query");

    assert_eq!(
        health_queries(&agent),
        vec![
            PLAIN_QUERY.to_string(),
            format!("{}&index=42&wait=30s", PLAIN_QUERY),
        ]
    );
}

/// Rule 3: an index that goes BACKWARDS means the state it counted was
/// reset under us (a restarted agent, a restored snapshot). The client
/// must drop to 0, which makes the next query a plain read that seeds a
/// fresh index -- not keep waiting on an index that refers to nothing.
#[test]
fn an_index_that_goes_backwards_resets_to_a_plain_query() {
    let agent = FakeConsulAgent::start();
    agent.set_health_index(Some(100));
    let consul = blocking_backend(&agent);

    block_on(consul.discover_participants()).expect("seeding query");
    // The agent now answers a SMALLER index than the one it handed out.
    agent.set_health_index(Some(7));
    block_on(consul.discover_participants()).expect("blocking query");
    // ... so this third one must carry no index at all.
    block_on(consul.discover_participants()).expect("query after the reset");

    assert_eq!(
        health_queries(&agent),
        vec![
            PLAIN_QUERY.to_string(),
            format!("{}&index=100&wait=30s", PLAIN_QUERY),
            PLAIN_QUERY.to_string(),
        ]
    );
}

/// Rule 4: index 0 is reserved. Stored as-is it would make every later
/// query return immediately for ever -- a hot loop at poller rate, which
/// is the opposite of what this feature is for. It is clamped to 1, and
/// the proof is that the next query blocks on `index=1` instead of
/// falling back to a plain read.
#[test]
fn an_index_below_one_is_clamped_to_one() {
    let agent = FakeConsulAgent::start();
    agent.set_health_index(Some(0));
    let consul = blocking_backend(&agent);

    block_on(consul.discover_participants()).expect("first query");
    block_on(consul.discover_participants()).expect("second query");

    assert_eq!(
        health_queries(&agent),
        vec![
            PLAIN_QUERY.to_string(),
            format!("{}&index=1&wait=30s", PLAIN_QUERY),
        ]
    );
}

/// Rule 6: a blocking query whose wait simply ran out answers 200 with
/// the SAME index and the full list. That is the common case on an idle
/// fleet -- it is a normal answer, not an error, not an empty registry,
/// and it must not disturb the stored index.
#[test]
fn a_wait_that_expires_with_an_unchanged_index_is_a_normal_answer() {
    let agent = FakeConsulAgent::start();
    agent.set_health_index(Some(55));
    agent.inject_service(FakeService {
        id: "hdds-participant-peer".to_string(),
        name: "hdds-participant".to_string(),
        tags: vec![format!("domain-{}", DOMAIN)],
        address: "192.0.2.7".to_string(),
        port: 7410,
        meta: HashMap::from([
            ("guid".to_string(), hex(&guid(9))),
            ("domain_id".to_string(), DOMAIN.to_string()),
            ("participant_name".to_string(), "peer".to_string()),
        ]),
        ..FakeService::default()
    });
    let consul = blocking_backend(&agent);

    block_on(consul.discover_participants()).expect("seeding query");
    // The agent answers the SAME index: nothing changed while it waited.
    let peers = block_on(consul.discover_participants()).expect("wait expiry is not an error");
    assert_eq!(
        peers.len(),
        1,
        "the full list comes back, as Consul sends it"
    );
    assert_eq!(peers[0].name, "peer");
    // The stored index is unchanged, so the next query waits on it again
    // instead of dropping back to a plain read.
    block_on(consul.discover_participants()).expect("third query");

    assert_eq!(
        health_queries(&agent),
        vec![
            PLAIN_QUERY.to_string(),
            format!("{}&index=55&wait=30s", PLAIN_QUERY),
            format!("{}&index=55&wait=30s", PLAIN_QUERY),
        ]
    );
}

/// The default. With the option off the request is EXACTLY the one this
/// backend sends today, every time -- even when the agent volunteers an
/// `X-Consul-Index` header. No index, no wait, and the poller is told
/// nothing that would change its cadence.
#[test]
fn with_blocking_queries_off_the_request_is_the_one_sent_today() {
    let agent = FakeConsulAgent::start();
    agent.set_health_index(Some(42));
    let consul = backend(&agent);
    assert_eq!(consul.options().blocking_queries, None);
    assert_eq!(consul.blocking_discovery_budget(), None);

    block_on(consul.discover_participants()).expect("first query");
    block_on(consul.discover_participants()).expect("second query");
    block_on(consul.discover_participants()).expect("third query");

    assert_eq!(
        health_queries(&agent),
        vec![
            PLAIN_QUERY.to_string(),
            PLAIN_QUERY.to_string(),
            PLAIN_QUERY.to_string(),
        ]
    );
}
