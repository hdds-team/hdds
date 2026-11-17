// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Participant-level proofs for the Azure Table Storage discovery backend
//! (AZ-1..AZ-5).
//!
//! Azure stands in through `test_support::fake_azure`: one loopback HTTP
//! server speaking the IMDS Managed Identity token route and the Table
//! Storage data-plane REST API. The whole chain runs through the PUBLIC
//! builder API with no network, no container, no Azure account and no
//! credential the test did not mint: token request -> table create ->
//! entity upsert -> OData query -> `SpdpPeerSet` Cloud origin -> SPDP
//! announcer -> unicast `DATA(p)` on the discovered peer's address.
//!
//! The fake refuses every table request that carries no token it issued,
//! so a regression that drops the `Authorization` header turns these
//! tests red rather than passing quietly.

#![cfg(feature = "cloud-discovery")]

use hdds::test_support::domains::unique_domain;
use hdds::test_support::fake_azure::{FakeAzure, TokenScript};
use hdds::test_support::ports::with_reserved_ports;
use hdds::{Participant, TransportMode};
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::thread;
use std::time::{Duration, Instant};

/// Registry poll interval for the tests (cloud peer lease = 1 s floor).
const POLL_INTERVAL: Duration = Duration::from_millis(200);
const TABLE: &str = "hddsparticipants";

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

/// Managed-Identity config pointing every endpoint at the fake.
fn managed_identity_config(url: &str) -> String {
    format!(
        r#"{{"account":"hddsacct","table":"{}","auth":{{"kind":"managed_identity"}},"endpoint":"{}","imds_endpoint":"{}"}}"#,
        TABLE, url, url
    )
}

/// One registry record as the backend writes it, for a peer that is not
/// this process.
fn peer_entity(guid: [u8; 16], addr: SocketAddrV4, domain_id: u32, last_updated: u64) -> String {
    let mut address = [0u8; 16];
    address[12..].copy_from_slice(&addr.ip().octets());
    let locators = format!(
        r#"[{{\"kind\":1,\"port\":{},\"address\":\"{}\"}}]"#,
        addr.port(),
        hex(&address)
    );
    format!(
        concat!(
            r#"{{"PartitionKey":"domain-{domain}","RowKey":"{guid}","Guid":"{guid}","#,
            r#""Name":"azure-peer","DomainId":{domain},"Locators":"{locators}","#,
            r#""Metadata":"{{}}","LastUpdated":"{updated}","LeaseSeconds":60}}"#
        ),
        domain = domain_id,
        guid = hex(&guid),
        locators = locators,
        updated = last_updated
    )
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Wait for an RTPS datagram sent by `prefix` on `probe`.
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
            Ok(_) | Err(_) => {}
        }
    }
    false
}

/// AZ-1 headline proof: a participant configured with Azure Table Storage
/// registers its own metatraffic locators over a Managed Identity bearer
/// token, discovers the peer the table lists, and unicasts SPDP to it.
#[test]
fn azure_discovered_peer_receives_unicast_spdp_from_table_storage() {
    // ONE lease: the table record the participant must discover is keyed
    // by the participant's OWN domain, so both sides share this value.
    // Declared first so it is dropped last, after the sockets close.
    let domain = unique_domain();

    // The "discovered peer": a bare socket. Anything arriving here came
    // from the unicast SPDP fan-out fed by the registry.
    let probe = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("probe socket");
    probe
        .set_read_timeout(Some(Duration::from_millis(100)))
        .expect("probe timeout");
    let probe_addr = match probe.local_addr().expect("probe addr") {
        std::net::SocketAddr::V4(v4) => v4,
        std::net::SocketAddr::V6(_) => unreachable!("bound to an IPv4 loopback"),
    };

    let azure = FakeAzure::start().expect("start fake azure");
    azure.create_table(TABLE);
    let mut peer_guid = [0x5A; 16];
    peer_guid[12..].copy_from_slice(&[0, 0, 1, 0xC1]);
    azure.put_entity(
        &format!("domain-{}", domain.id()),
        &hex(&peer_guid),
        &peer_entity(peer_guid, probe_addr, domain.id(), now_secs()),
    );

    let config = managed_identity_config(&azure.url());
    let participant = with_reserved_ports(8, |[mcast, sedp, user]: [u16; 3]| {
        Participant::builder("cloud_azure_peer_spdp")
            .domain_id(domain.id())
            .with_transport(TransportMode::UdpMulticast)
            .with_discovery_ports(mcast, sedp, user)
            .participant_id(Some(0))
            .with_azure_discovery(&config)
            .with_cloud_poll_interval(POLL_INTERVAL)
            .build()
    })
    .expect("participant with an Azure registry builds");
    let own_guid = participant.guid();

    // 1. The table-listed peer receives unicast SPDP.
    assert!(
        wait_for_rtps_from(&probe, own_guid.prefix, Duration::from_secs(10)),
        "no unicast SPDP reached the Azure-discovered peer address {}",
        probe_addr
    );

    // 2. The participant registered ITSELF, and the poller sees one peer.
    assert!(wait_until(Duration::from_secs(5), || {
        participant
            .cloud_discovery_status()
            .is_some_and(|status| status.registered && status.registry_peers == 1)
    }));

    // 3. The entity it wrote carries its GUID and its own metatraffic
    //    locators -- never an instance-metadata address.
    let own_hex = hex(&own_guid.as_bytes());
    let entities = azure.entities();
    let own_entity = entities
        .iter()
        .find(|(_, row_key, _)| *row_key == own_hex)
        .map(|(partition_key, _, body)| (partition_key.clone(), body.clone()));
    let (partition_key, body) =
        own_entity.unwrap_or_else(|| panic!("no entity for own GUID {}: {:?}", own_hex, entities));
    assert_eq!(partition_key, format!("domain-{}", domain.id()));
    assert!(
        body.contains(&own_hex) && body.contains("\"LastUpdated\""),
        "registration body is not a participant record: {}",
        body
    );

    // 4. Every table request carried a credential the fake issued.
    assert_eq!(
        azure.unauthenticated_attempts(),
        0,
        "a table request went out without an accepted credential"
    );
    assert!(azure.token_requests() >= 1, "no token was ever requested");

    // 5. A registry outage is a failed poll, not an empty registry: the
    //    peer view survives it.
    azure.set_table_status(503);
    assert!(wait_until(Duration::from_secs(5), || {
        participant
            .cloud_discovery_status()
            .is_some_and(|status| status.consecutive_poll_failures >= 3)
    }));
    let status = participant.cloud_discovery_status().expect("status");
    assert_eq!(
        status.registry_peers, 1,
        "a failing table service must not empty the peer view: {:?}",
        status
    );

    // 6. Dropping the participant deletes its entity (bounded).
    azure.set_table_status(200);
    let started = Instant::now();
    drop(participant);
    assert!(
        wait_until(Duration::from_secs(5), || !azure
            .entities()
            .iter()
            .any(|(_, row_key, _)| *row_key == own_hex)),
        "the participant's entity outlived it: {:?}",
        azure.entities()
    );
    assert!(started.elapsed() < Duration::from_secs(10));
}

/// A registry record whose lease expired is a crashed peer: it is never
/// turned into an SPDP destination, and it is never deleted by a
/// non-owner either.
#[test]
fn azure_stale_lease_entity_is_never_turned_into_a_peer() {
    // ONE lease: the stale record is keyed by the participant's OWN
    // domain, otherwise the participant would never even look at it.
    // Declared first so it is dropped last, after the sockets close.
    let domain = unique_domain();

    let probe = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("probe socket");
    probe
        .set_read_timeout(Some(Duration::from_millis(100)))
        .expect("probe timeout");
    let probe_addr = match probe.local_addr().expect("probe addr") {
        std::net::SocketAddr::V4(v4) => v4,
        std::net::SocketAddr::V6(_) => unreachable!("bound to an IPv4 loopback"),
    };

    let azure = FakeAzure::start().expect("start fake azure");
    azure.create_table(TABLE);
    let mut stale_guid = [0x7B; 16];
    stale_guid[12..].copy_from_slice(&[0, 0, 1, 0xC1]);
    // LeaseSeconds is 60 in the record; last seen two hours ago.
    azure.put_entity(
        &format!("domain-{}", domain.id()),
        &hex(&stale_guid),
        &peer_entity(stale_guid, probe_addr, domain.id(), now_secs() - 7200),
    );

    let config = managed_identity_config(&azure.url());
    let participant = with_reserved_ports(8, |[mcast, sedp, user]: [u16; 3]| {
        Participant::builder("cloud_azure_stale_lease")
            .domain_id(domain.id())
            .with_transport(TransportMode::UdpMulticast)
            .with_discovery_ports(mcast, sedp, user)
            .participant_id(Some(0))
            .with_azure_discovery(&config)
            .with_cloud_poll_interval(POLL_INTERVAL)
            .build()
    })
    .expect("participant with an Azure registry builds");

    assert!(wait_until(Duration::from_secs(5), || {
        participant
            .cloud_discovery_status()
            .is_some_and(|status| status.successful_polls >= 2)
    }));
    let status = participant.cloud_discovery_status().expect("status");
    assert_eq!(
        status.registry_peers, 0,
        "an expired lease was turned into a peer: {:?}",
        status
    );
    assert!(
        !wait_for_rtps_from(&probe, participant.guid().prefix, Duration::from_secs(1)),
        "unicast SPDP was sent to a peer whose lease had expired"
    );
    assert!(
        azure
            .entities()
            .iter()
            .any(|(_, row_key, _)| *row_key == hex(&stale_guid)),
        "a stale record was deleted by a participant that does not own it"
    );
}

/// AZ-2/AZ-3 fail-closed: with no identity to mint a token, nothing is
/// advertised. The participant still builds (a registry outage is not a
/// build failure) and no unauthenticated request is ever sent.
#[test]
fn azure_registration_fails_closed_without_a_managed_identity_token() {
    // Declared first so it is dropped last, after the participant's
    // sockets are closed.
    let domain = unique_domain();

    let azure = FakeAzure::start().expect("start fake azure");
    azure.create_table(TABLE);
    azure.set_token_script(TokenScript::Status(500));

    let config = managed_identity_config(&azure.url());
    let participant = with_reserved_ports(8, |[mcast, sedp, user]: [u16; 3]| {
        Participant::builder("cloud_azure_no_token")
            .domain_id(domain.id())
            .with_transport(TransportMode::UdpMulticast)
            .with_discovery_ports(mcast, sedp, user)
            .participant_id(Some(0))
            .with_azure_discovery(&config)
            .with_cloud_poll_interval(POLL_INTERVAL)
            .build()
    })
    .expect("a registry that cannot mint a token does not fail build()");

    assert!(
        wait_until(Duration::from_secs(5), || {
            participant
                .cloud_discovery_status()
                .is_some_and(|status| status.register_attempts >= 1)
        }),
        "registration was never attempted"
    );
    let status = participant.cloud_discovery_status().expect("status");
    assert!(
        !status.registered,
        "reported as registered without a token: {:?}",
        status
    );
    assert!(
        status.last_error.is_some(),
        "no error recorded for a token failure: {:?}",
        status
    );
    assert!(
        azure.entities().is_empty(),
        "an entity was written without a token: {:?}",
        azure.entities()
    );
    assert_eq!(
        azure.unauthenticated_attempts(),
        0,
        "a table request was sent with no credential at all"
    );
}

/// AZ-3: Shared Key (account key) authentication is refused for a
/// cert-ready product; the refusal happens at `build()`, by name.
#[test]
fn azure_build_refuses_shared_key_authentication() {
    // The refusal asserted below must be the CONFIG one; a domain
    // collision would fail the build with an I/O error instead and the
    // test would report "unexpected error kind" rather than a regression.
    let domain = unique_domain();
    let config = r#"{"account":"hddsacct","auth":{"kind":"shared_key","key":"c2VjcmV0"}}"#;
    let result = with_reserved_ports(8, |[mcast, sedp, user]: [u16; 3]| {
        Participant::builder("cloud_azure_shared_key")
            .domain_id(domain.id())
            .with_transport(TransportMode::UdpMulticast)
            .with_discovery_ports(mcast, sedp, user)
            .participant_id(Some(0))
            .with_azure_discovery(config)
            .with_cloud_poll_interval(POLL_INTERVAL)
            .build()
    });
    match result {
        Ok(_) => panic!("build() accepted Shared Key authentication"),
        Err(hdds::dds::Error::Config(message)) => {
            let lower = message.to_ascii_lowercase();
            assert!(
                lower.contains("shared key") || lower.contains("shared_key"),
                "the refusal does not name Shared Key: {}",
                message
            );
        }
        Err(other) => panic!("unexpected error kind: {:?}", other),
    }
}

/// A plaintext table endpoint pointing at a non-loopback host is refused
/// at `build()`: the request carries the participant GUID, its locators
/// and a bearer token.
#[test]
fn azure_build_refuses_a_plaintext_remote_table_endpoint() {
    // As above: the assertion is on the CONFIG refusal, so the build must
    // not be able to fail on a domain collision first.
    let domain = unique_domain();
    let config = concat!(
        r#"{"account":"hddsacct","auth":{"kind":"managed_identity"},"#,
        r#""endpoint":"http://hddsacct.table.core.windows.net"}"#
    );
    let result = with_reserved_ports(8, |[mcast, sedp, user]: [u16; 3]| {
        Participant::builder("cloud_azure_plaintext")
            .domain_id(domain.id())
            .with_transport(TransportMode::UdpMulticast)
            .with_discovery_ports(mcast, sedp, user)
            .participant_id(Some(0))
            .with_azure_discovery(config)
            .with_cloud_poll_interval(POLL_INTERVAL)
            .build()
    });
    match result {
        Ok(_) => panic!("build() accepted a plaintext remote table endpoint"),
        Err(hdds::dds::Error::Config(message)) => assert!(
            message.contains("plaintext http"),
            "the refusal does not explain the transport rule: {}",
            message
        ),
        Err(other) => panic!("unexpected error kind: {:?}", other),
    }
}

/// Opt-in round trip against a local Azurite (AZ-3 / A2: no live Azure
/// account is used anywhere in this suite).
///
/// `#[ignore]`d ON PURPOSE: it needs an Azurite container, and a test
/// that returns early would otherwise report `ok` and add a green line
/// to the suite while proving nothing. NOBODY HAS RUN IT YET.
///
/// It also needs BOTH variables set:
///
/// ```text
/// docker run -p 10002:10002 mcr.microsoft.com/azure-storage/azurite \
///     azurite-table --tableHost 0.0.0.0
/// HDDS_AZURITE_URL=http://127.0.0.1:10002/devstoreaccount1 \
/// HDDS_AZURITE_SAS='sv=...&sig=...' \
///     cargo test -p hdds --all-features --test cloud_azure -- --nocapture azurite
/// ```
///
/// Azurite is a local stand-in, not Azure: it proves the REST shapes and
/// the SAS path against an independent implementation, nothing more.
#[test]
#[ignore = "needs a local Azurite: HDDS_AZURITE_URL + HDDS_AZURITE_SAS"]
fn azure_azurite_round_trip_when_hdds_azurite_url_is_set() {
    // Declared first so it is dropped last, after the participant's
    // sockets are closed.
    let domain = unique_domain();

    let (Ok(url), Ok(sas)) = (
        std::env::var("HDDS_AZURITE_URL"),
        std::env::var("HDDS_AZURITE_SAS"),
    ) else {
        panic!("set HDDS_AZURITE_URL and HDDS_AZURITE_SAS to run the Azurite round trip");
    };

    let config = format!(
        r#"{{"account":"devstoreaccount1","table":"{}","auth":{{"kind":"sas","token":"{}"}},"endpoint":"{}"}}"#,
        TABLE, sas, url
    );
    let participant = with_reserved_ports(8, |[mcast, sedp, user]: [u16; 3]| {
        Participant::builder("cloud_azure_azurite")
            .domain_id(domain.id())
            .with_transport(TransportMode::UdpMulticast)
            .with_discovery_ports(mcast, sedp, user)
            .participant_id(Some(0))
            .with_azure_discovery(&config)
            .with_cloud_poll_interval(POLL_INTERVAL)
            .build()
    })
    .expect("participant against Azurite builds");

    assert!(
        wait_until(Duration::from_secs(15), || {
            participant
                .cloud_discovery_status()
                .is_some_and(|status| status.registered && status.successful_polls >= 1)
        }),
        "Azurite round trip failed: {:?}",
        participant.cloud_discovery_status()
    );
}
