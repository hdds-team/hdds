// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Participant-side wiring of a cloud registry poller into SPDP.
//!
//! A cloud registry (Consul, AWS Cloud Map, Azure) is a COLD-PATH peer
//! source: it only mutates the `Cloud` origin of the participant's
//! `SpdpPeerSet`, the announcer keeps reading `snapshot()` once per
//! announcement period, and normal SPDP/SEDP takes over as soon as one
//! unicast SPDP reaches the peer. The RTPS data path is untouched.
//!
//! This module owns what the builder needs to start that poller:
//! the provider-string to `CloudPollerConfig` mapping, the participant's
//! own registration record (its allowlist-filtered metatraffic locators),
//! the lease the cloud origin uses, and the [`SpdpCloudSink`] the poller
//! feeds.

use crate::core::discovery::{usable_unicast_locator, PeerOrigin, SpdpPeerSet, GUID};
use crate::dds::{Error, Result};
use crate::discovery::cloud::{
    locator_to_socket_addr, socket_addr_to_locator, AwsCloudMapConfig, CloudEvent, CloudPeerSink,
    CloudPollerConfig, CloudProvider, ConsulOptions, ParticipantInfo,
};
use crate::transport::UdpTransport;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

/// Default registry poll interval (the previous hardcoded bootstrap value).
pub(super) const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(5);
/// Lease multiplier: a cloud peer survives this many missed polls of a
/// stalled or dead poller before the announcer stops unicasting to it.
const LEASE_POLLS: u32 = 3;
const LEASE_FLOOR: Duration = Duration::from_secs(1);

/// Lease attached to every cloud peer: three poll intervals, one second
/// at least (tests poll fast; a peer must not flap between two polls).
pub(super) fn cloud_lease(poll_interval: Duration) -> Duration {
    poll_interval.saturating_mul(LEASE_POLLS).max(LEASE_FLOOR)
}

/// Floor on the registry poll interval.
///
/// The poller loop wakes on a 100 ms tick, so anything below it means
/// "poll on every tick": ten catalog requests a second against a
/// production registry, and a lease (`cloud_lease`) collapsed onto its
/// one-second floor, where a single late poll starts expiring peers.
/// Refused at build time rather than clamped silently.
pub(super) const MIN_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// The TYPED per-provider configurations the builder holds beside the
/// provider string, one field per provider.
///
/// One struct rather than one argument per provider: the next cloud
/// backend adds a field here (and a call to its own `with_` helper),
/// which leaves every existing call site of [`poller_config`] untouched.
///
/// They are separate from the `config` STRING on purpose: a typed AWS
/// configuration can carry static credentials, and the string is echoed
/// back by the public `Participant::cloud_discovery_config()`, so a
/// credential must never travel through it.
#[derive(Debug, Default, Clone, Copy)]
pub(super) struct CloudTypedConfigs<'a> {
    /// What `with_aws_cloud_map_config` stored, if anything.
    pub aws: Option<&'a AwsCloudMapConfig>,
    /// What `with_consul_options` stored, if anything.
    pub consul: Option<&'a ConsulOptions>,
}

impl<'a> CloudTypedConfigs<'a> {
    /// The AWS Cloud Map configuration to prefer over the string form.
    pub fn with_aws(mut self, aws: Option<&'a AwsCloudMapConfig>) -> Self {
        self.aws = aws;
        self
    }

    /// The Consul options (service name, datacenter, ACL token, health
    /// policy) that no config string carries.
    ///
    /// Folded here rather than kept as its own parameter: the AWS branch
    /// introduced this struct and the Consul branch added a bare
    /// `consul_options` argument beside it, two answers to one question.
    /// One typed bag scales to the next provider; one parameter per
    /// provider does not.
    pub fn with_consul(mut self, consul: Option<&'a ConsulOptions>) -> Self {
        self.consul = consul;
        self
    }
}

/// Map the builder's provider string and config string to a provider.
///
/// Fails closed on an unknown provider, a missing config, a plaintext
/// registry endpoint pointing at a non-loopback host, or an AWS JSON
/// that does not carry the three fields `with_aws_cloud_map` wrote.
fn map_provider(
    provider: &str,
    config: Option<&str>,
    typed: CloudTypedConfigs<'_>,
) -> Result<CloudProvider> {
    let config = config.ok_or_else(|| {
        Error::Config(format!(
            "cloud discovery provider {:?} configured without a config",
            provider
        ))
    })?;
    let provider = match provider {
        "consul" => {
            // Same rule as the backend constructor, applied one step
            // earlier so a plaintext remote endpoint fails `build()`
            // instead of the first poll.
            crate::discovery::cloud::check_endpoint_transport(config).map_err(Error::Config)?;
            CloudProvider::Consul {
                addr: config.to_string(),
                options: typed.consul.cloned().unwrap_or_default(),
            }
        }
        "aws" => {
            // The typed configuration wins when the user built one;
            // otherwise the three-field JSON `with_aws_cloud_map` wrote is
            // parsed into the same type, every other field defaulting.
            let aws = match typed.aws {
                Some(aws) => {
                    aws.validate()?;
                    aws.clone()
                }
                None => AwsCloudMapConfig::from_json(config)?,
            };
            CloudProvider::AwsCloudMap(Box::new(aws))
        }
        "azure" => {
            // Parsed and validated HERE, at build time: a config that is
            // refused (Shared Key, a plaintext remote table endpoint, a
            // credential that cannot be resolved) must not produce a
            // participant whose poller then dies with the multicast
            // default already lowered. The poller thread parses the same
            // text again when it constructs the backend.
            crate::discovery::cloud::AzureDiscoveryConfig::from_json(config)?;
            CloudProvider::Azure {
                config_json: config.to_string(),
            }
        }
        other => {
            return Err(Error::Config(format!(
                "unknown cloud discovery provider {:?} (expected consul, aws or azure)",
                other
            )))
        }
    };
    Ok(provider)
}

/// Map the builder's provider/config strings to a poller config, and
/// refuse at build time everything the poller could only report as an
/// error later.
///
/// On top of [`map_provider`] it enforces two build-time rules:
///
/// * the provider must have a backend IN THIS BUILD. Every provider in
///   the tree has one today (Consul, AWS Cloud Map, Azure Table Storage),
///   but the rule is kept because it is the fail-closed half of a pair:
///   the builder ALSO lowers the multicast default for a cloud
///   participant, so accepting a provider whose backend cannot be built
///   would hand back a participant with neither a registry nor multicast
///   SPDP, deaf in both directions, from an `Ok(())` build.
///   `backend_availability_matches_build_backend` pins the two halves
///   together so a future provider cannot land on the wrong side.
/// * the poll interval must not be below [`MIN_POLL_INTERVAL`].
pub(super) fn poller_config(
    provider: &str,
    config: Option<&str>,
    typed: CloudTypedConfigs<'_>,
    poll_interval: Duration,
    domain_id: u32,
) -> Result<CloudPollerConfig> {
    let provider = map_provider(provider, config, typed)?;
    if !crate::discovery::cloud::backend_is_available(&provider) {
        return Err(Error::Config(format!(
            "cloud discovery provider {:?} has no backend in this build: its registry API calls              are not implemented yet, and starting it would also disable multicast SPDP, leaving              this participant with no peer source at all",
            crate::discovery::cloud::provider_label(&provider)
        )));
    }
    if poll_interval < MIN_POLL_INTERVAL {
        return Err(Error::Config(format!(
            "cloud discovery poll interval {:?} is below the {:?} floor: the poller loop ticks at              that granularity, so a shorter interval polls the registry on every tick and shrinks              the peer lease onto its own floor",
            poll_interval, MIN_POLL_INTERVAL
        )));
    }
    // An Azure record carries a lease, so the participant writes its row
    // again every third of it; a Consul service stays until it is
    // deregistered and needs no refresh. The config was validated by
    // `map_provider` just above.
    let heartbeat_interval = match &provider {
        CloudProvider::Azure { config_json } => Some(
            crate::discovery::cloud::AzureDiscoveryConfig::from_json(config_json)?
                .heartbeat_interval(),
        ),
        // Neither Consul nor AWS Cloud Map leases its record: a Consul
        // service stays until deregistered, and a Cloud Map instance is
        // owned by the service, so neither needs a refresh.
        CloudProvider::Consul { .. }
        | CloudProvider::Aws { .. }
        | CloudProvider::AwsCloudMap(_) => None,
    };
    Ok(CloudPollerConfig {
        provider,
        poll_interval,
        domain_id,
        heartbeat_interval,
    })
}

/// The participant's own registry record: its GUID and the metatraffic
/// unicast locators SPDP itself would advertise (already filtered by the
/// interface allowlist). `None`, with an error log, when no routable IPv4
/// locator exists: registering a bogus address is worse than not
/// registering, and discovery of others keeps working either way.
pub(super) fn own_participant_info(
    guid: GUID,
    name: &str,
    domain_id: u32,
    transport: &UdpTransport,
) -> Option<ParticipantInfo> {
    own_participant_info_from(guid, name, domain_id, &transport.get_unicast_locators())
}

pub(super) fn own_participant_info_from(
    guid: GUID,
    name: &str,
    domain_id: u32,
    unicast_locators: &[SocketAddr],
) -> Option<ParticipantInfo> {
    let locators: Vec<_> = unicast_locators
        .iter()
        .filter(|addr| usable_unicast_locator(addr))
        .filter_map(socket_addr_to_locator)
        .collect();
    if locators.is_empty() {
        log::error!(
            "[CLOUD-DISCOVERY] No routable IPv4 metatraffic locator is available; \
             this participant is not registered (peers are still discovered)"
        );
        return None;
    }
    let mut metadata = HashMap::new();
    metadata.insert("vendor".to_string(), "hdds".to_string());
    metadata.insert("version".to_string(), env!("CARGO_PKG_VERSION").to_string());
    Some(ParticipantInfo {
        guid: guid.as_bytes(),
        name: name.to_string(),
        domain_id,
        locators,
        metadata,
    })
}

/// Feeds the poller's peer view into the `Cloud` origin of the SPDP peer set.
pub(super) struct SpdpCloudSink {
    peer_set: Arc<SpdpPeerSet>,
    own_prefix: [u8; 12],
    lease: Duration,
}

impl SpdpCloudSink {
    pub(super) fn new(peer_set: Arc<SpdpPeerSet>, own_prefix: [u8; 12], lease: Duration) -> Self {
        Self {
            peer_set,
            own_prefix,
            lease,
        }
    }

    /// One registry record -> (GUID prefix, routable UDPv4 locators).
    ///
    /// The own GUID is re-checked here (the poller already drops it) so a
    /// participant can never unicast SPDP to itself even if the filter
    /// upstream changes. The DOMAIN filter is NOT repeated: it lives in
    /// the polling loop (`poller_thread.rs`, `discovered != domain_id`),
    /// which is the only producer of these records.
    fn peer_view(&self, info: &ParticipantInfo) -> Option<([u8; 12], HashSet<SocketAddr>)> {
        let mut prefix = [0u8; 12];
        prefix.copy_from_slice(&info.guid[..12]);
        if prefix == self.own_prefix {
            return None;
        }
        let locators: HashSet<SocketAddr> = info
            .locators
            .iter()
            .filter_map(locator_to_socket_addr)
            .filter(usable_unicast_locator)
            .collect();
        Some((prefix, locators))
    }
}

impl CloudPeerSink for SpdpCloudSink {
    fn on_event(&mut self, event: &CloudEvent) {
        match event {
            CloudEvent::ParticipantLost { guid } => {
                let mut prefix = [0u8; 12];
                prefix.copy_from_slice(&guid[..12]);
                self.peer_set.remove_cloud(&prefix);
            }
            CloudEvent::Stopped => {
                self.peer_set.clear(PeerOrigin::Cloud);
            }
            _ => {}
        }
    }

    fn on_poll(&mut self, peers: &[ParticipantInfo]) {
        let view: Vec<_> = peers.iter().filter_map(|p| self.peer_view(p)).collect();
        if self.peer_set.sync_cloud(view, self.lease) {
            log::debug!(
                "[CLOUD-DISCOVERY] SPDP cloud peers updated: {} locators",
                self.peer_set.counts().cloud_peers
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::cloud::Locator;

    fn record(guid: [u8; 16], domain_id: u32, locators: Vec<Locator>) -> ParticipantInfo {
        ParticipantInfo {
            guid,
            name: "peer".into(),
            domain_id,
            locators,
            metadata: HashMap::new(),
        }
    }

    fn v4(a: u8, b: u8, c: u8, d: u8, port: u32) -> Locator {
        Locator {
            kind: 1,
            port,
            address: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, a, b, c, d],
        }
    }

    #[test]
    fn on_poll_maps_peers_to_cloud_origin_and_drops_unusable_locators() {
        let peer_set = Arc::new(SpdpPeerSet::new());
        let own = [0xAA; 16];
        let mut own_prefix = [0u8; 12];
        own_prefix.copy_from_slice(&own[..12]);
        let mut sink =
            SpdpCloudSink::new(Arc::clone(&peer_set), own_prefix, Duration::from_secs(5));

        let mut v6 = v4(0, 0, 0, 0, 7410);
        v6.address[0] = 0x20;
        let peers = vec![
            record(
                [1; 16],
                39,
                vec![
                    v4(192, 0, 2, 1, 7410),
                    v4(0, 0, 0, 0, 7410),    // unspecified: dropped
                    v4(192, 0, 2, 1, 0),     // port 0: dropped
                    v4(192, 0, 2, 2, 70000), // over u16: dropped
                    Locator {
                        kind: 2,
                        ..v4(192, 0, 2, 3, 7410)
                    }, // not UDPv4: dropped
                    v6,
                ],
            ),
            record(own, 39, vec![v4(192, 0, 2, 9, 7410)]), // own guid: ignored
        ];
        sink.on_poll(&peers);

        assert_eq!(
            peer_set.snapshot(),
            vec!["192.0.2.1:7410".parse::<SocketAddr>().unwrap()]
        );
        assert_eq!(peer_set.counts().cloud_peers, 1);

        // Peer 1 vanished from the registry: removed on the next poll.
        sink.on_poll(&[]);
        assert!(peer_set.snapshot().is_empty());
    }

    #[test]
    fn lost_and_stopped_events_clear_only_the_cloud_origin() {
        let peer_set = Arc::new(SpdpPeerSet::new());
        let static_peer: SocketAddr = "192.0.2.50:7410".parse().unwrap();
        peer_set.add_static(static_peer);
        let mut sink = SpdpCloudSink::new(Arc::clone(&peer_set), [0; 12], Duration::from_secs(5));

        sink.on_poll(&[
            record([1; 16], 39, vec![v4(192, 0, 2, 1, 7410)]),
            record([2; 16], 39, vec![v4(192, 0, 2, 2, 7410)]),
        ]);
        assert_eq!(peer_set.counts().cloud_peers, 2);

        sink.on_event(&CloudEvent::ParticipantLost { guid: [1; 16] });
        assert_eq!(peer_set.counts().cloud_peers, 1);

        sink.on_event(&CloudEvent::Stopped);
        assert_eq!(peer_set.counts().cloud_peers, 0);
        assert_eq!(peer_set.snapshot(), vec![static_peer]);
    }

    #[test]
    fn poller_config_maps_every_provider_and_fails_closed_on_bad_input() {
        let interval = Duration::from_millis(250);
        let consul = poller_config(
            "consul",
            Some("http://127.0.0.1:8500"),
            CloudTypedConfigs::default(),
            interval,
            39,
        )
        .unwrap();
        assert!(
            matches!(consul.provider, CloudProvider::Consul { ref addr, .. } if addr == "http://127.0.0.1:8500")
        );
        assert_eq!(consul.poll_interval, interval);
        assert_eq!(consul.domain_id, 39);

        // The three-field JSON `with_aws_cloud_map` writes maps to a full
        // AWS configuration whose other fields take their defaults.
        let aws = poller_config(
            "aws",
            Some(r#"{"namespace":"ns","service":"svc","region":"eu-west-3"}"#),
            CloudTypedConfigs::default(),
            interval,
            39,
        )
        .unwrap();
        let CloudProvider::AwsCloudMap(config) = &aws.provider else {
            panic!("unexpected provider: {:?}", aws.provider);
        };
        assert_eq!(config.namespace, "ns");
        assert_eq!(config.service, "svc");
        assert_eq!(config.region, "eu-west-3");
        assert_eq!(
            config.health_status,
            crate::discovery::cloud::AwsHealthStatus::All
        );

        // A typed configuration wins over the string form and never has
        // to travel through it.
        let typed = AwsCloudMapConfig::new("typed-ns", "srv-1", "us-east-1")
            .with_endpoint_override("http://127.0.0.1:1234");
        let aws = poller_config(
            "aws",
            Some("{}"),
            CloudTypedConfigs::default().with_aws(Some(&typed)),
            interval,
            39,
        )
        .unwrap();
        let CloudProvider::AwsCloudMap(config) = &aws.provider else {
            panic!("unexpected provider: {:?}", aws.provider);
        };
        assert_eq!(config.namespace, "typed-ns");
        assert_eq!(
            config.endpoint_override.as_deref(),
            Some("http://127.0.0.1:1234")
        );

        // Azure has a backend since its branch folded, so it goes through
        // the full `poller_config` path and not just `map_provider`.
        const AZURE_JSON: &str = r#"{"account":"hddsacct","auth":{"kind":"managed_identity"}}"#;
        let azure = poller_config(
            "azure",
            Some(AZURE_JSON),
            CloudTypedConfigs::default(),
            interval,
            39,
        )
        .unwrap();
        assert!(
            matches!(azure.provider, CloudProvider::Azure { ref config_json } if config_json == AZURE_JSON)
        );
        // A leased registry refreshes its record; Consul does not.
        assert_eq!(azure.heartbeat_interval, Some(Duration::from_secs(20)));
        assert_eq!(consul.heartbeat_interval, None);

        // An azure config that does not validate fails the BUILD, not the
        // first poll: unknown field, refused auth mode, plaintext remote
        // table endpoint.
        assert!(map_provider("azure", Some("not json"), CloudTypedConfigs::default()).is_err());
        assert!(map_provider(
            "azure",
            Some(r#"{"account":"a"}"#),
            CloudTypedConfigs::default()
        )
        .is_err());
        assert!(map_provider(
            "azure",
            Some(r#"{"account":"hddsacct","auth":{"kind":"shared_key","key":"c2VjcmV0"}}"#),
            CloudTypedConfigs::default()
        )
        .is_err());
        assert!(map_provider(
            "azure",
            Some(concat!(
                r#"{"account":"hddsacct","auth":{"kind":"managed_identity"},"#,
                r#""endpoint":"http://hddsacct.table.core.windows.net"}"#
            )),
            CloudTypedConfigs::default()
        )
        .is_err());

        assert!(
            poller_config("gcp", Some("x"), CloudTypedConfigs::default(), interval, 0).is_err()
        );
        assert!(poller_config("consul", None, CloudTypedConfigs::default(), interval, 0).is_err());
        assert!(map_provider("aws", Some("not json"), CloudTypedConfigs::default()).is_err());
        assert!(map_provider(
            "aws",
            Some(r#"{"namespace":"ns"}"#),
            CloudTypedConfigs::default(),
        )
        .is_err());
        // A typed AWS config that cannot work is refused at build time.
        let bad = AwsCloudMapConfig::new("ns", "svc", "eu-west-3")
            .with_endpoint_override("http://cloudmap.example.com");
        assert!(poller_config(
            "aws",
            Some("{}"),
            CloudTypedConfigs::default().with_aws(Some(&bad)),
            interval,
            39,
        )
        .is_err());
    }

    /// The three-argument builder API writes the JSON string this module
    /// parses back. Pinned HERE, with no participant and no poller, so
    /// that covering it never needs a test that boots a poller against the
    /// real AWS endpoint.
    #[test]
    fn the_three_argument_builder_api_writes_the_json_the_mapper_parses() {
        let builder = crate::dds::participant::ParticipantBuilder::new("cloud_three_arg")
            .with_aws_cloud_map("hdds-namespace", "srv-1", "eu-west-3");
        assert_eq!(builder.cloud_discovery_provider.as_deref(), Some("aws"));
        assert!(
            builder.cloud_aws_config.is_none(),
            "the three-argument form must not fabricate a typed config"
        );
        let written = builder
            .consul_addr
            .clone()
            .expect("the three-argument form writes a config string");

        let mapped = poller_config(
            "aws",
            Some(&written),
            CloudTypedConfigs::default(),
            Duration::from_millis(250),
            39,
        )
        .expect("the string the builder wrote must map to a backend");
        let CloudProvider::AwsCloudMap(config) = &mapped.provider else {
            panic!("unexpected provider: {:?}", mapped.provider);
        };
        assert_eq!(config.namespace, "hdds-namespace");
        assert_eq!(config.service, "srv-1");
        assert_eq!(config.region, "eu-west-3");
        // The poller's domain is the authoritative one (`build_backend`
        // stamps it on the backend), so it is asserted there, not on the
        // parsed config.
        assert_eq!(mapped.domain_id, 39);
        assert!(config.endpoint_override.is_none());
        assert!(matches!(
            config.credentials,
            crate::discovery::cloud::AwsCredentialSource::DefaultChain
        ));
    }

    /// Every provider in the tree has a backend, so `poller_config`
    /// accepts all of them. The refusal rule (a provider whose backend
    /// cannot be constructed must fail the build, because the builder has
    /// already disabled multicast for a cloud participant by then) has no
    /// subject here and is guarded by
    /// `backend_availability_matches_build_backend` instead.
    #[test]
    fn poller_config_accepts_every_provider() {
        let interval = Duration::from_millis(250);
        // Every provider in the tree has a backend: Consul, AWS Cloud
        // Map and Azure Table Storage. There is nothing to refuse here,
        // so this test pins that every provider is ACCEPTED, and removing
        // a backend fails here.
        //
        // The refusal path itself is guarded by
        // `backend_availability_matches_build_backend`, which asserts
        // `backend_is_available == build_backend(..).is_ok()` over every
        // provider variant, so the fail-closed rule keeps a test even
        // though no provider currently trips it.
        assert!(poller_config(
            "consul",
            Some("http://127.0.0.1:8500"),
            CloudTypedConfigs::default(),
            interval,
            39,
        )
        .is_ok());
        assert!(poller_config(
            "azure",
            Some(r#"{"account":"hddsacct","auth":{"kind":"managed_identity"}}"#),
            CloudTypedConfigs::default(),
            interval,
            39,
        )
        .is_ok());
        assert!(poller_config(
            "aws",
            Some(r#"{"namespace":"ns","service":"srv-1","region":"eu-west-3"}"#),
            CloudTypedConfigs::default(),
            interval,
            39
        )
        .is_ok());
    }

    /// A poll interval below the loop tick would hammer the registry and
    /// collapse the peer lease onto its floor: refused, not clamped.
    #[test]
    fn poller_config_refuses_a_poll_interval_below_the_loop_tick() {
        for interval in [
            Duration::ZERO,
            Duration::from_millis(1),
            Duration::from_millis(99),
        ] {
            let error = poller_config(
                "consul",
                Some("http://127.0.0.1:8500"),
                CloudTypedConfigs::default(),
                interval,
                39,
            )
            .expect_err("a sub-tick poll interval must fail the build");
            let Error::Config(message) = &error else {
                panic!("unexpected error kind for {:?}: {:?}", interval, error);
            };
            assert!(
                message.contains("below the"),
                "unexpected message for {:?}: {}",
                interval,
                message
            );
        }
        for interval in [MIN_POLL_INTERVAL, Duration::from_secs(5)] {
            assert!(
                poller_config(
                    "consul",
                    Some("http://127.0.0.1:8500"),
                    CloudTypedConfigs::default(),
                    interval,
                    39,
                )
                .is_ok(),
                "legal poll interval refused: {:?}",
                interval
            );
        }
    }

    #[test]
    fn poller_config_refuses_a_plaintext_remote_registry_endpoint() {
        let interval = Duration::from_millis(250);
        for endpoint in [
            "http://consul.prod:8500",
            "http://10.0.0.5:8500",
            "consul.prod:8500",
        ] {
            let error = poller_config(
                "consul",
                Some(endpoint),
                CloudTypedConfigs::default(),
                interval,
                39,
            )
            .expect_err("a plaintext remote registry endpoint must fail the build");
            assert!(
                matches!(error, Error::Config(_)),
                "unexpected error kind for {}: {:?}",
                endpoint,
                error
            );
        }
        for endpoint in [
            "https://consul.prod:8500",
            "http://127.0.0.1:8500",
            "http://localhost:8500",
        ] {
            assert!(
                poller_config(
                    "consul",
                    Some(endpoint),
                    CloudTypedConfigs::default(),
                    interval,
                    39,
                )
                .is_ok(),
                "legal registry endpoint refused: {}",
                endpoint
            );
        }
    }

    #[test]
    fn own_participant_info_uses_routable_metatraffic_locators_only() {
        let guid = GUID::new([7; 12], [0, 0, 1, 0xC1]);
        let info = own_participant_info_from(
            guid,
            "node",
            39,
            &[
                "192.0.2.10:7410".parse().unwrap(),
                "[2001:db8::1]:7410".parse().unwrap(),
                "0.0.0.0:7410".parse().unwrap(),
            ],
        )
        .expect("one routable locator");
        assert_eq!(info.guid, guid.as_bytes());
        assert_eq!(info.domain_id, 39);
        assert_eq!(info.name, "node");
        assert_eq!(info.locators, vec![v4(192, 0, 2, 10, 7410)]);
        assert_eq!(
            info.metadata.get("vendor").map(String::as_str),
            Some("hdds")
        );

        assert!(
            own_participant_info_from(guid, "node", 39, &["[::1]:7410".parse().unwrap()]).is_none()
        );
        assert!(own_participant_info_from(guid, "node", 39, &[]).is_none());
    }

    #[test]
    fn cloud_lease_is_three_polls_with_a_floor() {
        assert_eq!(cloud_lease(Duration::from_secs(5)), Duration::from_secs(15));
        assert_eq!(
            cloud_lease(Duration::from_millis(100)),
            Duration::from_secs(1)
        );
    }
}
