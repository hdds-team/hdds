// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Participant-level proofs for DNS-SD discovery (DNSSD-1, DNSSD-2).
//!
//! A DNS zone stands in through `test_support::fake_dns`, so the whole
//! chain runs through the PUBLIC builder API with no network, no
//! container and no `/etc/resolv.conf`: `SRV` lookup -> `A` resolution ->
//! `SpdpPeerSet` Cloud origin -> SPDP announcer -> unicast `DATA(p)`
//! arriving on the address the zone published. Nothing here reaches into
//! crate internals.
//!
//! Every DDS domain used here is LEASED from
//! `test_support::domains::unique_domain`, never hand-picked: the
//! participants bind reserved discovery ports, but a hand-picked domain id
//! can still be chosen by another test binary (or another worktree) at the
//! same time, and then the two see each other's multicast. The allocator
//! arbitrates that machine-wide, and it also keeps these tests off the
//! domains the fleet's live services own.
//!
//! Hermetic because: the nameserver is an in-process `UdpSocket` on
//! `127.0.0.1:0` passed explicitly to the participant (so the host
//! resolver is never consulted, `AddressLookup::NameserversOnly`), the
//! peer is a bare socket on an ephemeral loopback port that nothing else
//! could know, multicast is off by default for a DNS-SD participant, and
//! the negative control proves the datagram really came from the zone.

#![cfg(all(feature = "dns-sd", feature = "test-support"))]

use hdds::discovery::dnssd::{AddressLookup, DnsSdConfig};
use hdds::test_support::domains::unique_domain;
use hdds::test_support::fake_dns::{FakeDnsMode, FakeDnsServer};
use hdds::test_support::ports::with_reserved_ports;
use hdds::{Participant, TransportMode, TransportOptions};
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// Zone the tests publish into.
const ZONE: &str = "dnssd.test";
/// Lookup interval (lease = the 1 s floor).
const POLL_INTERVAL: Duration = Duration::from_millis(200);

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

/// A bare loopback socket: anything that reaches it came from the SPDP
/// unicast fan-out, and its ephemeral port is known only to the zone.
fn probe_socket() -> (UdpSocket, u16) {
    let probe = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("probe socket");
    probe
        .set_read_timeout(Some(Duration::from_millis(100)))
        .expect("probe timeout");
    let port = probe.local_addr().expect("probe addr").port();
    (probe, port)
}

/// Wait for an RTPS datagram sent by `prefix` on `probe`.
fn wait_for_rtps_from(probe: &UdpSocket, prefix: [u8; 12], timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    let mut buffer = [0u8; 2048];
    while Instant::now() < deadline {
        if let Ok((len, _)) = probe.recv_from(&mut buffer) {
            if len >= 20 && &buffer[..4] == b"RTPS" && buffer[8..20] == prefix {
                return true;
            }
        }
    }
    false
}

/// The DNS-SD configuration under test: the fake nameserver only, never
/// the host resolver.
fn dns_sd_config(server: &FakeDnsServer) -> DnsSdConfig {
    DnsSdConfig::new(ZONE)
        .with_nameservers(vec![server.addr()])
        .with_poll_interval(POLL_INTERVAL)
        .with_query_timeout(Duration::from_millis(300))
        .with_attempts(1)
        .with_address_lookup(AddressLookup::NameserversOnly)
}

/// A zone publishing one HDDS peer at `127.0.0.1:port`.
fn zone_with_peer(port: u16) -> FakeDnsServer {
    let server = FakeDnsServer::start().expect("start fake dns");
    let target = format!("node-a.{}", ZONE);
    server.add_srv(&format!("_hdds._udp.{}", ZONE), 0, 0, port, &target);
    server.add_a(&target, Ipv4Addr::LOCALHOST);
    server
}

fn build_dns_sd_participant(
    name: &str,
    domain_id: u32,
    config: DnsSdConfig,
) -> hdds::Result<Arc<Participant>> {
    with_reserved_ports(8, |[mcast, sedp, user]: [u16; 3]| {
        Participant::builder(name)
            .domain_id(domain_id)
            .with_transport(TransportMode::UdpMulticast)
            .with_discovery_ports(mcast, sedp, user)
            .participant_id(Some(0))
            .with_dns_sd(config.clone())
            .build()
    })
}

/// The named end-to-end proof: an `SRV` record plus its `A` record become
/// a unicast SPDP destination, and the record vanishing takes the peer
/// with it.
#[test]
fn dns_sd_peers_receive_unicast_spdp_without_multicast() {
    // Declared first so it is dropped last, after the participant's
    // sockets are closed.
    let domain = unique_domain();

    let (probe, probe_port) = probe_socket();
    let server = zone_with_peer(probe_port);

    let participant =
        build_dns_sd_participant("dnssd_peer_spdp", domain.id(), dns_sd_config(&server))
            .expect("a DNS-SD participant builds");
    let own_guid = participant.guid();

    // 1. The address the zone published receives unicast SPDP.
    assert!(
        wait_for_rtps_from(&probe, own_guid.prefix, Duration::from_secs(10)),
        "no unicast SPDP reached the DNS-published peer 127.0.0.1:{}",
        probe_port
    );

    // 2. The status accessor agrees on where it came from.
    let status = participant.dns_sd_status().expect("status when configured");
    assert!(status.running, "{:?}", status);
    assert!(status.successful_lookups >= 1, "{:?}", status);
    assert_eq!(status.resolved_peers, 1, "{:?}", status);
    assert_eq!(status.consecutive_lookup_failures, 0, "{:?}", status);
    assert!(status.last_error.is_none(), "{:?}", status);

    // 3. The SRV question really went to our fake nameserver, for the name
    //    the config names, and the A record was served as glue (no second
    //    question needed).
    let queries = server.queries();
    let service = format!("_hdds._udp.{}", ZONE);
    assert!(
        queries.iter().any(|q| q.name == service && q.qtype == 33),
        "no SRV question for {}: {:?}",
        service,
        queries
    );

    // 4. A zone that stops answering must NOT empty the peer view: an
    //    unanswered lookup says nothing about who is gone.
    server.set_mode(FakeDnsMode::Silent);
    assert!(
        wait_until(Duration::from_secs(6), || {
            participant
                .dns_sd_status()
                .is_some_and(|s| s.consecutive_lookup_failures >= 2)
        }),
        "the failed lookups were not counted: {:?}",
        participant.dns_sd_status()
    );
    let status = participant.dns_sd_status().expect("status");
    assert_eq!(
        status.resolved_peers, 1,
        "a failing zone emptied the peer view: {:?}",
        status
    );
    assert!(status.last_error.is_some(), "{:?}", status);

    // 5. Recovery, then an ANSWERED lookup that lists nothing: that one
    //    does remove the peer.
    server.set_mode(FakeDnsMode::Answer);
    assert!(wait_until(Duration::from_secs(6), || {
        participant
            .dns_sd_status()
            .is_some_and(|s| s.consecutive_lookup_failures == 0)
    }));
    server.clear_records();
    assert!(
        wait_until(Duration::from_secs(6), || {
            participant
                .dns_sd_status()
                .is_some_and(|s| s.resolved_peers == 0)
        }),
        "an authoritative empty answer did not retire the peer: {:?}",
        participant.dns_sd_status()
    );

    // 6. Dropping the participant stops the resolver, bounded.
    let started = Instant::now();
    drop(participant);
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "Participant::drop was not bounded by the DNS-SD thread: {:?}",
        started.elapsed()
    );
}

/// Negative control for the proof above: with a zone that answers
/// `NXDOMAIN` the SAME participant shape never reaches the same probe. If
/// this ever passes datagrams, the positive test is not measuring DNS-SD.
#[test]
fn an_unresolvable_zone_never_produces_a_peer() {
    // Declared first so it is dropped last, after the participant's
    // sockets are closed.
    let domain = unique_domain();

    let (probe, probe_port) = probe_socket();
    let server = zone_with_peer(probe_port);
    server.set_mode(FakeDnsMode::NxDomain);

    let participant =
        build_dns_sd_participant("dnssd_nxdomain", domain.id(), dns_sd_config(&server))
            .expect("build() does not fail on a zone that is merely empty");
    let own_guid = participant.guid();

    assert!(
        !wait_for_rtps_from(&probe, own_guid.prefix, Duration::from_secs(4)),
        "unicast SPDP reached 127.0.0.1:{} although the zone answered NXDOMAIN",
        probe_port
    );
    let status = participant.dns_sd_status().expect("status");
    assert_eq!(status.resolved_peers, 0, "{:?}", status);
    assert!(status.consecutive_lookup_failures >= 1, "{:?}", status);
    assert!(
        status
            .last_error
            .as_deref()
            .is_some_and(|e| e.contains("NXDOMAIN")),
        "the failure is not reported as a name error: {:?}",
        status
    );
}

/// A zone that lists a target with no address record is answered but
/// INCOMPLETE. The peers it could resolve must still be announced to, and
/// the incompleteness must be visible instead of looking like a smaller
/// deployment.
#[test]
fn an_incomplete_zone_still_reaches_the_peers_it_could_resolve() {
    // Declared first so it is dropped last, after the participant's
    // sockets are closed.
    let domain = unique_domain();

    let (probe, probe_port) = probe_socket();
    let server = zone_with_peer(probe_port);
    // A second instance whose target has no A record at all.
    server.add_srv(
        &format!("_hdds._udp.{}", ZONE),
        0,
        0,
        7411,
        &format!("gone.{}", ZONE),
    );

    let participant =
        build_dns_sd_participant("dnssd_partial", domain.id(), dns_sd_config(&server))
            .expect("a DNS-SD participant builds");
    let own_guid = participant.guid();

    assert!(
        wait_for_rtps_from(&probe, own_guid.prefix, Duration::from_secs(10)),
        "an incomplete zone stopped the peer that DID resolve from being announced to"
    );
    let status = participant.dns_sd_status().expect("status when configured");
    assert_eq!(status.resolved_peers, 1, "{:?}", status);
    assert_eq!(status.unresolved_targets, 1, "{:?}", status);
    assert!(status.partial_lookups >= 1, "{:?}", status);
    assert_eq!(
        status.consecutive_lookup_failures, 0,
        "an incomplete answer is not a failed lookup: {:?}",
        status
    );
}

/// Everything that could only be discovered by a dead background thread
/// fails `build()` instead, because a DNS-SD participant has already had
/// its multicast default lowered by the time the thread would start.
#[test]
fn dns_sd_build_refuses_a_configuration_that_could_never_resolve() {
    // Every build below must fail on its CONFIG, so none of them may be
    // able to fail on a domain collision first. Declared first so it is
    // dropped last.
    let domain = unique_domain();
    let server = FakeDnsServer::start().expect("start fake dns");

    let cases: Vec<(&str, DnsSdConfig)> = vec![
        (
            "application label",
            dns_sd_config(&server).with_service("hdds._udp"),
        ),
        (
            "transport label",
            dns_sd_config(&server).with_service("_hdds._sctp"),
        ),
        (
            "domain is empty",
            DnsSdConfig::new("")
                .with_nameservers(vec![server.addr()])
                .with_poll_interval(POLL_INTERVAL),
        ),
        (
            "below the",
            dns_sd_config(&server).with_poll_interval(Duration::from_millis(50)),
        ),
        (
            "no nameserver",
            dns_sd_config(&server).with_nameservers(Vec::new()),
        ),
    ];

    for (expected, config) in cases {
        // "no nameserver" can only be proven on a host whose
        // /etc/resolv.conf lists none; skip it by name where it does.
        if expected == "no nameserver" && !config.effective_nameservers().is_empty() {
            // Not skippable in silence: the hermetic proof of this refusal
            // is the lib test
            // discovery::dnssd::tests::a_config_without_any_nameserver_is_refused_before_a_thread_exists,
            // which uses the resolv.conf seam instead of the host's file.
            eprintln!(
                "SKIP dns_sd_build_refuses_a_configuration_that_could_never_resolve[no nameserver]: \
                 this host's /etc/resolv.conf lists {} nameserver(s), so the refusal cannot be \
                 reached through build()",
                config.effective_nameservers().len()
            );
            continue;
        }
        match build_dns_sd_participant("dnssd_bad_config", domain.id(), config) {
            Ok(_) => panic!(
                "build() accepted a DNS-SD config that mentions {:?}",
                expected
            ),
            Err(hdds::dds::Error::Config(message)) => assert!(
                message.contains(expected),
                "the refusal does not mention {:?}: {}",
                expected,
                message
            ),
            Err(other) => panic!("unexpected error kind for {:?}: {:?}", expected, other),
        }
    }

    // DNS-SD feeds the SPDP unicast destinations of a UDP transport;
    // there is none in IntraProcess mode.
    match Participant::builder("dnssd_intra")
        .domain_id(domain.id())
        .with_transport(TransportMode::IntraProcess)
        .with_dns_sd(dns_sd_config(&server))
        .build()
    {
        Ok(_) => panic!("build() accepted DNS-SD with no UDP transport"),
        Err(hdds::dds::Error::Config(message)) => assert!(
            message.contains("UdpMulticast"),
            "unexpected refusal: {}",
            message
        ),
        Err(other) => panic!("unexpected error kind: {:?}", other),
    }
}

/// A cloud registry and DNS-SD own the same leased peer origin, so a
/// participant configures one or the other.
#[cfg(feature = "cloud-discovery")]
#[test]
fn a_cloud_registry_and_dns_sd_cannot_share_one_participant() {
    // The refusal asserted below must be the CONFIG one, not an I/O error
    // from a domain collision. Declared first so it is dropped last.
    let domain = unique_domain();
    let server = FakeDnsServer::start().expect("start fake dns");
    let result = with_reserved_ports(8, |[mcast, sedp, user]: [u16; 3]| {
        Participant::builder("dnssd_and_consul")
            .domain_id(domain.id())
            .with_transport(TransportMode::UdpMulticast)
            .with_discovery_ports(mcast, sedp, user)
            .participant_id(Some(0))
            .with_consul("http://127.0.0.1:8500")
            .with_dns_sd(dns_sd_config(&server))
            .build()
    });
    match result {
        Ok(_) => panic!("build() accepted a cloud registry and DNS-SD together"),
        Err(hdds::dds::Error::Config(message)) => assert!(
            message.contains("not both"),
            "unexpected refusal: {}",
            message
        ),
        Err(other) => panic!("unexpected error kind: {:?}", other),
    }
}

/// Can this host join the RTPS discovery multicast group at all?
///
/// Decided ONCE, up front, by an explicit capability probe: a skip
/// decided by "some build failed" would hide a regression in the very
/// default this test proves.
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

/// CLOUD-3 applied to DNS-SD: `with_dns_sd` lowers the multicast DEFAULT
/// to `Disabled`; the explicit switch and an explicit transport option
/// are respected.
#[test]
fn dns_sd_participant_is_multicast_disabled_by_default_unless_overridden() {
    // ONE lease for every pair below: A and B must share a domain, or
    // "B never hears A" would be true for the wrong reason and the
    // override legs could never discover anything. Declared first so it
    // is dropped last, after every pair's sockets are closed.
    let domain = unique_domain();
    let server = FakeDnsServer::start().expect("start fake dns"); // empty zone

    if !multicast_is_available() {
        eprintln!(
            "SKIP dns_sd_participant_is_multicast_disabled_by_default_unless_overridden: \
             this host cannot join the RTPS discovery multicast group"
        );
        return;
    }

    type Pair = (Arc<Participant>, Arc<Participant>);
    let build_pair =
        |name: &str,
         tweak: &dyn Fn(hdds::dds::ParticipantBuilder) -> hdds::dds::ParticipantBuilder|
         -> hdds::Result<Pair> {
            with_reserved_ports(
                8,
                |[mcast, a_sedp, a_user, b_sedp, b_user]: [u16; 5]| -> hdds::Result<Pair> {
                    let a = tweak(
                        Participant::builder(&format!("{}_a", name))
                            .domain_id(domain.id())
                            .with_transport(TransportMode::UdpMulticast)
                            .with_discovery_ports(mcast, a_sedp, a_user)
                            .participant_id(Some(0))
                            .with_dns_sd(dns_sd_config(&server)),
                    )
                    .build()?;
                    let b = Participant::builder(&format!("{}_b", name))
                        .domain_id(domain.id())
                        .with_transport(TransportMode::UdpMulticast)
                        .with_discovery_ports(mcast, b_sedp, b_user)
                        .participant_id(Some(1))
                        .build()?;
                    Ok((a, b))
                },
            )
        };

    // Default: A neither sends nor listens to multicast, B is Enabled, and
    // the zone is empty, so nothing can bridge them in either direction.
    let (a, b) = build_pair("dnssd_default", &|builder| builder).expect("default pair builds");
    thread::sleep(Duration::from_millis(3500));
    assert!(
        !knows(&b, &a),
        "B discovered the DNS-SD participant A over multicast: A was not Disabled by default"
    );
    assert!(
        !knows(&a, &b),
        "the DNS-SD participant A heard B's multicast SPDP: A was not Disabled by default"
    );
    drop((a, b));

    // Explicit override keeps multicast.
    let (a, b) = build_pair("dnssd_keep_mcast", &|builder| {
        builder.dns_sd_disable_multicast(false)
    })
    .expect("override pair builds");
    assert!(
        wait_until(Duration::from_secs(8), || knows(&b, &a) && knows(&a, &b)),
        "dns_sd_disable_multicast(false) did not keep multicast discovery"
    );
    drop((a, b));

    // An explicit ReceiveOnly is kept as configured, not lowered.
    let (a, b) = build_pair("dnssd_recv_only", &|builder| {
        builder.with_transport_options(TransportOptions::default().receive_only())
    })
    .expect("receive-only pair builds");
    assert!(
        wait_until(Duration::from_secs(8), || knows(&a, &b) && knows(&b, &a)),
        "an explicit ReceiveOnly was not kept next to DNS-SD"
    );
    drop((a, b));
}

/// A build with DNS-SD compiled in says so: an operator reading
/// `features_summary()` must not have to guess which peer sources exist.
#[test]
fn dns_sd_is_listed_in_the_feature_summary() {
    let domain = unique_domain();
    let participant = Participant::builder("dnssd_features")
        .domain_id(domain.id())
        .with_transport(TransportMode::IntraProcess)
        .build()
        .expect("an intra-process participant builds");
    assert!(
        participant.features_summary().contains(&"dns-sd"),
        "features_summary() hides the feature this build runs on: {:?}",
        participant.features_summary()
    );
}

/// The resolver is reachable from the public API on its own, with no
/// participant: this is what an operator debugs a zone with.
#[test]
fn the_resolver_is_usable_standalone_through_the_public_api() {
    let (_probe, probe_port) = probe_socket();
    let server = zone_with_peer(probe_port);
    let resolver = dns_sd_config(&server)
        .resolver()
        .expect("the config validates");
    let peers = resolver
        .resolve_service(&format!("_hdds._udp.{}", ZONE))
        .expect("the zone answers");
    assert_eq!(
        peers,
        vec![SocketAddr::from((Ipv4Addr::LOCALHOST, probe_port))]
    );
}
