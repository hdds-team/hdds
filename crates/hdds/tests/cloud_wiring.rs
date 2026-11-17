// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Participant-level proofs for the cloud registry wiring (CLOUD-1..4).
//!
//! A registry stands in through `test_support::fake_http` speaking the
//! Consul catalog/agent API the in-tree client already uses, so the whole
//! chain is exercised through the PUBLIC builder API with no network,
//! container or credential: registry poll -> `SpdpPeerSet` Cloud origin ->
//! SPDP announcer -> unicast `DATA(p)` arriving on the discovered peer's
//! address. Nothing here reaches into crate internals.
//!
//! 1. A peer listed by the registry receives unicast SPDP from the
//!    participant; the participant registers itself; a registry outage
//!    (non-2xx) never empties the peer view; the public handle still sees
//!    the discovery event (CLOUD-4); dropping the participant deregisters.
//! 2. CLOUD-3: a cloud-configured participant defaults to
//!    `MulticastMode::Disabled` (multicast-silent both ways), the explicit
//!    override keeps multicast, and an explicit `ReceiveOnly` is kept.

#![cfg(feature = "cloud-discovery")]

use hdds::dds::ParticipantBuilder;
use hdds::discovery::cloud::{AwsCloudMapConfig, AwsCredentialSource, CloudEvent};
use hdds::test_support::domains::unique_domain;
use hdds::test_support::fake_http::{FakeHttpServer, FakeRequest, FakeResponse};
use hdds::test_support::ports::with_reserved_ports;
use hdds::{Participant, TransportMode, TransportOptions};
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// Registry poll interval for the tests (lease = 1 s floor).
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

/// A Consul registry on the fake HTTP server: agent register/deregister,
/// KV writes and TTL check refreshes are accepted, the health query
/// answers from `peers` (or fails with `catalog_status` when it is not
/// 200).
struct FakeConsul {
    server: FakeHttpServer,
    peers: Arc<Mutex<Vec<String>>>,
    catalog_status: Arc<AtomicU16>,
}

impl FakeConsul {
    fn start(domain_id: u32) -> Self {
        let peers: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let catalog_status = Arc::new(AtomicU16::new(200));
        let handler_peers = Arc::clone(&peers);
        let handler_status = Arc::clone(&catalog_status);
        let expected_query = format!("tag=domain-{}&passing=true", domain_id);
        let server = FakeHttpServer::start(move |request: &FakeRequest| {
            match (request.method.as_str(), request.path()) {
                ("PUT", "/v1/agent/service/register") => FakeResponse::status(200),
                ("PUT", path) if path.starts_with("/v1/agent/service/deregister/") => {
                    FakeResponse::status(200)
                }
                ("PUT" | "DELETE", path) if path.starts_with("/v1/kv/") => {
                    FakeResponse::json(200, "true")
                }
                ("PUT", path) if path.starts_with("/v1/agent/check/pass/") => {
                    FakeResponse::status(200)
                }
                ("GET", "/v1/health/service/hdds-participant") => {
                    let status = handler_status.load(Ordering::SeqCst);
                    if status != 200 {
                        return FakeResponse::text(status, "registry unavailable");
                    }
                    if request.query() != Some(expected_query.as_str()) {
                        return FakeResponse::json(200, "[]");
                    }
                    let body = format!("[{}]", handler_peers.lock().unwrap().join(","));
                    FakeResponse::json(200, &body)
                }
                _ => FakeResponse::status(404),
            }
        })
        .expect("start fake consul");
        Self {
            server,
            peers,
            catalog_status,
        }
    }

    fn url(&self) -> String {
        self.server.base_url()
    }

    /// List `guid` at `addr` in the catalog, the way the Consul client
    /// registers a participant (hex GUID and JSON locators in ServiceMeta).
    fn add_peer(&self, guid: [u8; 16], addr: SocketAddrV4, domain_id: u32) {
        let mut address = [0u8; 16];
        address[12..].copy_from_slice(&addr.ip().octets());
        let locators = format!(
            r#"[{{\"kind\":1,\"port\":{},\"address\":\"{}\"}}]"#,
            addr.port(),
            hex(&address)
        );
        let service = format!(
            concat!(
                r#"{{"Service":{{"ID":"hdds-participant-{id}","Service":"hdds-participant","#,
                r#""Address":"{ip}","Port":{port},"#,
                r#""Tags":["domain-{domain}","hdds","dds"],"#,
                r#""Meta":{{"guid":"{guid}","domain_id":"{domain}","#,
                r#""participant_name":"cloud-peer","locators":"{locators}"}}}}}}"#
            ),
            id = hex(&guid),
            ip = addr.ip(),
            port = addr.port(),
            domain = domain_id,
            guid = hex(&guid),
            locators = locators
        );
        self.peers.lock().unwrap().push(service);
    }

    fn set_catalog_status(&self, status: u16) {
        self.catalog_status.store(status, Ordering::SeqCst);
    }

    fn register_bodies(&self) -> Vec<String> {
        self.server
            .requests()
            .iter()
            .filter(|r| r.method == "PUT" && r.path() == "/v1/agent/service/register")
            .map(FakeRequest::body_text)
            .collect()
    }

    fn deregister_count(&self) -> usize {
        self.server
            .requests()
            .iter()
            .filter(|r| r.method == "PUT" && r.path().starts_with("/v1/agent/service/deregister/"))
            .count()
    }
}

/// Wait for an RTPS datagram from `prefix` on `probe` (any SPDP announce).
fn wait_for_rtps_from(probe: &UdpSocket, prefix: [u8; 12], timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    let mut buffer = [0u8; 2048];
    while Instant::now() < deadline {
        match probe.recv_from(&mut buffer) {
            Ok((len, _)) if len >= 20 => {
                if &buffer[..4] == b"RTPS" && buffer[8..20] == prefix {
                    return true;
                }
            }
            Ok(_) => {}
            Err(_) => {}
        }
    }
    false
}

fn drain(probe: &UdpSocket) {
    let mut buffer = [0u8; 2048];
    let stop = Instant::now() + Duration::from_millis(250);
    while Instant::now() < stop {
        let _ = probe.recv_from(&mut buffer);
    }
}

#[test]
fn cloud_discovered_peer_receives_unicast_spdp() {
    // ONE lease: the fake catalog only answers the query tagged with the
    // participant's OWN domain, and the peer it lists carries the same
    // one. Declared first so it is dropped last, after the sockets close.
    let domain = unique_domain();

    // The "discovered peer": a bare socket, so anything that reaches it can
    // only have come from the unicast SPDP fan-out.
    let probe = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("probe socket");
    probe
        .set_read_timeout(Some(Duration::from_millis(100)))
        .expect("probe timeout");
    let probe_addr = match probe.local_addr().expect("probe addr") {
        std::net::SocketAddr::V4(v4) => v4,
        std::net::SocketAddr::V6(_) => unreachable!("bound to an IPv4 loopback"),
    };

    let consul = FakeConsul::start(domain.id());
    let mut peer_guid = [0x5A; 16];
    peer_guid[12..].copy_from_slice(&[0, 0, 1, 0xC1]);
    consul.add_peer(peer_guid, probe_addr, domain.id());

    let url = consul.url();
    let participant = with_reserved_ports(8, |[mcast, sedp, user]: [u16; 3]| {
        Participant::builder("cloud_wiring_peer_spdp")
            .domain_id(domain.id())
            .with_transport(TransportMode::UdpMulticast)
            .with_discovery_ports(mcast, sedp, user)
            .participant_id(Some(0))
            .with_consul(&url)
            .with_cloud_poll_interval(POLL_INTERVAL)
            .build()
    })
    .expect("participant with a cloud registry builds");
    let own_guid = participant.guid();

    // 1. The registry-listed peer receives unicast SPDP from the participant.
    assert!(
        wait_for_rtps_from(&probe, own_guid.prefix, Duration::from_secs(10)),
        "no unicast SPDP reached the registry-discovered peer address {}",
        probe_addr
    );

    // 2. The participant registered itself with its own GUID and sees the peer.
    assert!(wait_until(Duration::from_secs(5), || {
        participant
            .cloud_discovery_status()
            .is_some_and(|s| s.registered && s.registry_peers == 1)
    }));
    let own_hex = hex(&own_guid.as_bytes());
    let bodies = consul.register_bodies();
    assert!(
        bodies.iter().any(|body| body.contains(&own_hex)),
        "no registration carried the participant GUID {}: {:?}",
        own_hex,
        bodies
    );

    // 3. The public handle received a COPY of the discovery event (CLOUD-4)
    //    even though the SPDP feed consumed it on the poller thread.
    let handle = participant
        .cloud_discovery_handle()
        .expect("cloud handle when configured");
    let mut events = Vec::new();
    assert!(wait_until(Duration::from_secs(5), || {
        events.extend(handle.poll());
        events.iter().any(
            |e| matches!(e, CloudEvent::ParticipantDiscovered { info } if info.guid == peer_guid),
        )
    }));

    // 4. A registry outage (non-2xx) is a failed poll: the peer view is kept
    //    and no ParticipantLost is emitted.
    consul.set_catalog_status(503);
    assert!(wait_until(Duration::from_secs(5), || {
        participant
            .cloud_discovery_status()
            .is_some_and(|s| s.consecutive_poll_failures >= 3)
    }));
    let status = participant.cloud_discovery_status().expect("status");
    assert_eq!(
        status.registry_peers, 1,
        "a failing registry must not empty the peer view: {:?}",
        status
    );
    events.extend(handle.poll());
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, CloudEvent::ParticipantLost { .. })),
        "ParticipantLost emitted during a registry outage: {:?}",
        events
    );

    // 5. Recovery: the peer keeps (or regains) unicast SPDP.
    consul.set_catalog_status(200);
    assert!(wait_until(Duration::from_secs(5), || {
        participant
            .cloud_discovery_status()
            .is_some_and(|s| s.consecutive_poll_failures == 0)
    }));
    drain(&probe);
    assert!(
        wait_for_rtps_from(&probe, own_guid.prefix, Duration::from_secs(10)),
        "unicast SPDP did not resume after the registry recovered"
    );

    // 6. Dropping the participant deregisters it (bounded).
    let started = Instant::now();
    drop(participant);
    assert!(
        wait_until(Duration::from_secs(5), || consul.deregister_count() >= 1),
        "no deregistration reached the registry: {:?}",
        consul.server.requests().len()
    );
    assert!(started.elapsed() < Duration::from_secs(10));
}

type Pair = (Arc<Participant>, Arc<Participant>);

/// Build a cloud-configured participant A (customised by `tweak`) and a
/// plain multicast-Enabled participant B on the same discovery ports.
fn build_pair(
    name: &str,
    domain_id: u32,
    consul_url: &str,
    tweak: impl Fn(ParticipantBuilder) -> ParticipantBuilder,
) -> hdds::Result<Pair> {
    with_reserved_ports(
        8,
        |[mcast, a_sedp, a_user, b_sedp, b_user]: [u16; 5]| -> hdds::Result<Pair> {
            let a = tweak(
                Participant::builder(&format!("{}_a", name))
                    .domain_id(domain_id)
                    .with_transport(TransportMode::UdpMulticast)
                    .with_discovery_ports(mcast, a_sedp, a_user)
                    .participant_id(Some(0))
                    .with_consul(consul_url)
                    .with_cloud_poll_interval(POLL_INTERVAL),
            )
            .build()?;
            let b = Participant::builder(&format!("{}_b", name))
                .domain_id(domain_id)
                .with_transport(TransportMode::UdpMulticast)
                .with_discovery_ports(mcast, b_sedp, b_user)
                .participant_id(Some(1))
                .build()?;
            Ok((a, b))
        },
    )
}

/// Can this host join the RTPS discovery multicast group at all?
///
/// Used ONCE at the top of the CLOUD-3 proof. A skip decided by an
/// explicit capability check is visible; a skip decided by "some build
/// failed" would hide a real regression in the very default it proves.
fn multicast_is_available() -> bool {
    let Ok(socket) = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)) else {
        return false;
    };
    socket
        .join_multicast_v4(&Ipv4Addr::new(239, 255, 0, 1), &Ipv4Addr::UNSPECIFIED)
        .is_ok()
}

fn knows(observer: &Participant, other: &Participant) -> bool {
    observer
        .discovery()
        .is_some_and(|fsm| fsm.has_participant(&other.guid()))
}

/// CLOUD-3: `with_consul` lowers the multicast DEFAULT to `Disabled`; the
/// explicit switch and an explicit transport mode are respected.
#[test]
fn cloud_participant_is_multicast_disabled_by_default_unless_overridden() {
    // ONE lease for every pair below: A and B must share a domain, or
    // "B never hears A" would be true for the wrong reason and the
    // override legs could never discover anything. Declared first so it
    // is dropped last, after every pair's sockets are closed.
    let domain = unique_domain();
    let consul = FakeConsul::start(domain.id()); // empty catalog: polls succeed, no peers
    let url = consul.url();

    // A host with no multicast-capable interface has nothing to prove
    // here, and it is decided ONCE, up front, by an explicit capability
    // probe: no leg below may turn a build error into a silent pass.
    if !multicast_is_available() {
        eprintln!(
            "SKIP cloud_participant_is_multicast_disabled_by_default_unless_overridden: \
             this host cannot join the RTPS discovery multicast group"
        );
        return;
    }

    // Default: A neither sends nor listens to multicast, B is Enabled.
    // With an empty registry nothing can bridge them in either direction.
    let (a, b) = build_pair("cloud_wiring_default", domain.id(), &url, |builder| builder)
        .expect("default pair builds");
    thread::sleep(Duration::from_millis(3500));
    assert!(
        !knows(&b, &a),
        "B discovered the cloud participant A over multicast: A was not Disabled by default"
    );
    assert!(
        !knows(&a, &b),
        "the cloud participant A heard B's multicast SPDP: A was not Disabled by default"
    );
    drop((a, b));

    // Explicit override keeps multicast: mutual discovery over the group.
    let (a, b) = build_pair("cloud_wiring_keep_mcast", domain.id(), &url, |builder| {
        builder.cloud_discovery_disable_multicast(false)
    })
    .expect("override pair builds");
    assert!(
        wait_until(Duration::from_secs(8), || knows(&b, &a) && knows(&a, &b)),
        "cloud_discovery_disable_multicast(false) did not keep multicast discovery"
    );
    drop((a, b));

    // An explicit ReceiveOnly is kept as configured (not lowered to
    // Disabled): A hears B over multicast and answers with unicast SPDP,
    // so B learns A too, which a Disabled A can never achieve (see above).
    let (a, b) = build_pair("cloud_wiring_recv_only", domain.id(), &url, |builder| {
        builder.with_transport_options(TransportOptions::default().receive_only())
    })
    .expect("receive-only pair builds");
    assert!(
        wait_until(Duration::from_secs(8), || knows(&a, &b) && knows(&b, &a)),
        "an explicit ReceiveOnly was not kept next to the cloud registry"
    );
    drop((a, b));
}

/// A registry endpoint carries this participant's GUID and locators, so a
/// plaintext `http://` endpoint to a remote host is refused by
/// construction: `build()` fails, no poller starts, and no flag re-opens
/// it. `https://` and a loopback agent stay legal.
#[test]
fn cloud_build_refuses_a_plaintext_remote_registry_endpoint() {
    // The refusals asserted below must be the CONFIG ones, and the last
    // leg builds a real participant. Declared first so it is dropped last.
    let domain = unique_domain();

    let build = |endpoint: &str| {
        with_reserved_ports(8, |[mcast, sedp, user]: [u16; 3]| {
            Participant::builder("cloud_wiring_endpoint")
                .domain_id(domain.id())
                .with_transport(TransportMode::UdpMulticast)
                .with_discovery_ports(mcast, sedp, user)
                .participant_id(Some(0))
                .with_consul(endpoint)
                .with_cloud_poll_interval(POLL_INTERVAL)
                .build()
        })
    };

    for endpoint in [
        "http://consul.service.consul:8500",
        "http://10.0.0.5:8500",
        "consul.service.consul:8500",
    ] {
        match build(endpoint) {
            Ok(_) => panic!("build() accepted the insecure registry endpoint {endpoint}"),
            Err(hdds::dds::Error::Config(message)) => {
                assert!(
                    message.contains(endpoint),
                    "the refusal does not name the endpoint {endpoint}: {message}"
                );
            }
            Err(other) => panic!("unexpected error for {endpoint}: {other:?}"),
        }
    }

    // The loopback agent form stays legal (nothing listens; the poller
    // only has to start, and Participant::build() never fails on a
    // registry that is down).
    let participant = build("http://127.0.0.1:8500").expect("a loopback agent endpoint is legal");
    assert!(participant.cloud_discovery_status().is_some());
    drop(participant);
}

/// Every provider the builder accepts must either HAVE a backend in this
/// build or be refused by `build()`.
///
/// `with_aws_cloud_map_config` / `with_azure_discovery` are accepted by the
/// builder, and a cloud participant has its multicast default lowered to
/// `Disabled`. If the poller then cannot construct its backend, the
/// participant is left with NO peer source in either direction from an
/// `Ok(())` build: the registry never answers and multicast is off.
/// `build()` refuses instead, naming the provider.
///
/// Both providers HAVE a backend: AWS Cloud Map and Azure Table Storage.
/// So both must BUILD here, and both pollers must come up.
#[test]
fn aws_or_azure_provider_never_leaves_the_participant_without_a_peer_source() {
    // Both legs must BUILD, so neither may fail on a domain collision.
    // Declared first so it is dropped last, after both are dropped.
    let domain = unique_domain();

    let build = |tweak: fn(ParticipantBuilder) -> ParticipantBuilder| {
        with_reserved_ports(8, |[mcast, sedp, user]: [u16; 3]| {
            tweak(
                Participant::builder("cloud_wiring_no_backend")
                    .domain_id(domain.id())
                    .with_transport(TransportMode::UdpMulticast)
                    .with_discovery_ports(mcast, sedp, user)
                    .participant_id(Some(0)),
            )
            .build()
        })
    };

    // AWS Cloud Map HAS a backend now: the same call must build, and its
    // poller must come up. The endpoint is a CLOSED loopback port, not the
    // default regional one: the assertion under test is "build() succeeds
    // and the poller comes up", and a default endpoint would make
    // `cargo test` open TLS to the real AWS Cloud Map endpoints with
    // whatever credentials the runner happens to carry.
    let aws = build(|builder| {
        builder.with_aws_cloud_map_config(
            AwsCloudMapConfig::new("ns", "srv-1", "eu-west-3")
                .with_service_name("hdds-service")
                .with_endpoint_override("http://127.0.0.1:1")
                .with_credentials(AwsCredentialSource::Static {
                    access_key_id: "AKIDEXAMPLE".into(),
                    secret_access_key: "test-only-secret".into(),
                    session_token: None,
                }),
        )
    })
    .expect("the AWS Cloud Map provider has a backend and must build");
    assert!(aws.cloud_discovery_status().is_some());
    drop(aws);

    // Azure: the Table Storage backend exists, so the participant builds.
    // The endpoint is a dead loopback port, so nothing leaves this host.
    let azure = build(|builder| {
        builder
            .with_azure_discovery(concat!(
                r#"{"account":"hddsacct","auth":{"kind":"managed_identity"},"#,
                r#""endpoint":"http://127.0.0.1:1","imds_endpoint":"http://127.0.0.1:1"}"#
            ))
            .with_cloud_poll_interval(POLL_INTERVAL)
    })
    .expect("the azure provider has a backend in this build");
    assert!(azure.cloud_discovery_status().is_some());
    drop(azure);
}

/// A cloud registry feeds the SPDP unicast destinations of a UDP
/// transport; there is none in `IntraProcess` mode, so `build()` refuses
/// rather than returning a participant whose poller can do nothing.
#[test]
fn cloud_discovery_refuses_intra_process_transport() {
    let domain = unique_domain();
    let result = Participant::builder("cloud_wiring_intra")
        .domain_id(domain.id())
        .with_transport(TransportMode::IntraProcess)
        .with_consul("http://127.0.0.1:8500")
        .with_cloud_poll_interval(POLL_INTERVAL)
        .build();
    match result {
        Ok(_) => panic!("build() accepted a cloud registry with no UDP transport"),
        Err(hdds::dds::Error::Config(message)) => {
            assert!(
                message.contains("UdpMulticast"),
                "the refusal does not name the required transport mode: {message}"
            );
        }
        Err(other) => panic!("unexpected error: {other:?}"),
    }
}

/// The poll interval reaches the registry: a sub-tick value would poll
/// on every 100 ms loop tick and shrink the peer lease onto its floor,
/// so it fails the build instead of being clamped in silence.
#[test]
fn cloud_build_refuses_a_sub_tick_poll_interval() {
    // The legal-interval leg at the end builds a real participant, so this
    // needs a domain of its own. Declared first so it is dropped last.
    let domain = unique_domain();
    let build = |interval: Duration| {
        with_reserved_ports(8, |[mcast, sedp, user]: [u16; 3]| {
            Participant::builder("cloud_wiring_interval")
                .domain_id(domain.id())
                .with_transport(TransportMode::UdpMulticast)
                .with_discovery_ports(mcast, sedp, user)
                .participant_id(Some(0))
                .with_consul("http://127.0.0.1:8500")
                .with_cloud_poll_interval(interval)
                .build()
        })
    };

    match build(Duration::ZERO) {
        Ok(_) => panic!("build() accepted a zero poll interval"),
        Err(hdds::dds::Error::Config(message)) => {
            assert!(
                message.contains("below the"),
                "the refusal does not explain the floor: {message}"
            );
        }
        Err(other) => panic!("unexpected error: {other:?}"),
    }
    drop(build(Duration::from_secs(1)).expect("a one-second poll interval is legal"));
}
