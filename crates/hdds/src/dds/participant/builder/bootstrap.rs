// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Participant build() orchestration.
//!
//! This module coordinates participant initialization by calling focused setup modules:
//! - entity_registry: SEDP cache and GUID generation
//! - telemetry_setup: Metrics and telemetry exporter
//! - discovery_setup: Discovery FSM, listeners, and demux router
//! - threads: Background thread spawning (SPDP announcer, lease tracker)

use super::{discovery_setup, entity_registry, telemetry_setup, threads, ParticipantBuilder};
use crate::config::RuntimeConfig;
use crate::dds::participant::runtime::{Participant, TransportMode, RTPS_ENTITYID_PARTICIPANT};
use crate::dds::{DomainRegistry, GuardCondition, Result};
use crate::transport::tcp::{TcpTransport, TransportPreference};
use crate::transport::UdpTransport;
use std::sync::atomic::{AtomicBool, AtomicU32};
use std::sync::Arc;

#[cfg(feature = "xtypes")]
use crate::core::types::TypeCache;

#[cfg(feature = "security")]
use crate::security::SecurityPluginSuite;

#[cfg(feature = "k8s")]
use crate::discovery::k8s::K8sDiscovery;

/// Default cloud registry poll interval, re-exported for the builder.
#[cfg(feature = "cloud-discovery")]
pub(super) const CLOUD_DEFAULT_POLL_INTERVAL: std::time::Duration =
    super::cloud_discovery_runtime::DEFAULT_POLL_INTERVAL;

/// The three SPDP security values carried into `SpdpSecurityTokens`: the identity
/// token, the permissions token and the participant security attributes mask.
/// Named so the `not(feature = "security")` arm can annotate its `None` triple
/// without tripping `clippy::type_complexity` on the default feature set.
#[cfg(not(feature = "security"))]
type SpdpSecurityTokenTriple = (Option<Vec<u8>>, Option<Vec<u8>>, Option<[u8; 8]>);

/// Outcome of probing whether a MULTICAST port this participant will need is
/// actually available, before the auto-assign search below commits to a
/// participant id.
///
/// Unlike the two UNICAST ports (`metatraffic_unicast`, `user_unicast`),
/// which are unique per participant and therefore worth walking `pid_guess`
/// past on a conflict, the two MULTICAST ports (`metatraffic_multicast`, and
/// `metatraffic_multicast + DATA_MULTICAST_OFFSET`) are computed from
/// `domain_id` ALONE by the RTPS v2.5 formula -- no `participant_id` term
/// appears in either (`PortMapping::calculate`). A busy multicast port is
/// therefore identical on every `pid_guess` in the loop below: there is
/// nothing to "retry" by picking a different id, only the same conflict
/// rediscovered up to 256 times.
///
/// The probe itself has to be COOPERATIVE (SO_REUSEADDR set before bind),
/// not a plain bind like the unicast probe uses. Multicast ports are meant
/// to be shared: every other HDDS participant on this domain, and every
/// major vendor, binds the same exact port with SO_REUSEADDR and the kernel
/// fans incoming multicast datagrams out to all of them. A plain probe would
/// misreport that completely normal sharing as "busy" the instant any
/// cooperative co-participant already held the port -- a false positive
/// strictly worse than today's total absence of a check. Only a
/// non-cooperative holder (an ephemeral outbound connection that happened to
/// land on the port, or a stack that never sets SO_REUSEADDR) makes a
/// SO_REUSEADDR probe fail, and that is exactly the scenario this probe handles.
enum MulticastPortProbe {
    /// Free for a cooperative binder. Carries the reservation socket; the
    /// caller keeps it in `multicast_reservation`, alive across the
    /// participant's own later official bind of the same port on Linux, and
    /// released before it everywhere else (BSD-family kernels want
    /// SO_REUSEPORT for two binders of one exact address:port, Windows'
    /// SO_REUSEADDR is one-sided).
    Reserved(std::net::UdpSocket),
    /// A non-cooperative holder occupies the port. Fatal: no participant id
    /// on this domain can avoid it, so the caller fails fast here instead of
    /// walking `pid_guess` 0..=255 to rediscover the same conflict.
    Busy(std::io::Error),
    /// Could not even ask: `SO_REUSEADDR` itself was refused (e.g. a
    /// sandboxed setsockopt filter). Rather than fall back to a plain bind --
    /// which would misreport "busy" against any cooperative co-participant,
    /// see above -- this is treated exactly like "not probed at all": the
    /// caller proceeds as build() always has, and a squatted multicast port
    /// surfaces at the transport's own bind of it.
    Inconclusive,
}

/// Probe one multicast port with a cooperative (SO_REUSEADDR-before-bind)
/// UDP bind. See [`MulticastPortProbe`] for why this cannot be a plain bind.
fn probe_multicast_port(port: u16) -> MulticastPortProbe {
    let socket2 = match socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    ) {
        Ok(s) => s,
        Err(_) => return MulticastPortProbe::Inconclusive,
    };
    if socket2.set_reuse_address(true).is_err() {
        return MulticastPortProbe::Inconclusive;
    }
    // BSD-family kernels admit a second binder of one exact address:port only
    // when both set SO_REUSEPORT, and the transport's metatraffic multicast
    // socket sets it on these platforms. Without it here, the probe of a
    // second participant on the same domain would report a cooperative
    // co-participant as a non-cooperative holder.
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    ))]
    if crate::transport::udp::set_reuseport(&socket2).is_err() {
        return MulticastPortProbe::Inconclusive;
    }
    let bind_addr: std::net::SocketAddr = (std::net::Ipv4Addr::UNSPECIFIED, port).into();
    match socket2.bind(&bind_addr.into()) {
        Ok(()) => MulticastPortProbe::Reserved(socket2.into()),
        Err(e) => MulticastPortProbe::Busy(e),
    }
}

impl ParticipantBuilder {
    /// Build and initialize a DDS participant.
    ///
    /// # Initialization Sequence
    /// 1. Initialize slab pool and telemetry
    /// 2. Calculate port mapping and generate GUID
    /// 3. Create SEDP announcements cache
    /// 4. Setup transport (if UdpMulticast mode)
    /// 5. Setup discovery subsystem (FSM, listeners, demux router)
    /// 6. Spawn background threads (telemetry, SPDP announcer, lease tracker)
    /// 7. Create type cache (if xtypes feature enabled)
    /// 8. Construct and return Participant
    ///
    /// # Returns
    /// `Result<Arc<Participant>>` or Error if initialization fails
    pub fn build(self) -> Result<Arc<Participant>> {
        log::debug!("[hdds] ParticipantBuilder::build name={}", self.name);

        // Source filtering (HDDS_SOURCE_ALLOW / HDDS_SOURCE_DENY) is not
        // applied on the receive path in this release. A security setting
        // that would have no effect is refused instead of accepted in
        // silence; no builder or transport option carries a source filter,
        // so the environment is the only way to ask for one.
        crate::transport::filter::refuse_unsupported_source_filter_env()
            .map_err(crate::dds::Error::Config)?;

        // The domain rule, applied in this one place: a domain set in code
        // always wins; else HDDS_DOMAIN_ID when it is set and valid (a value
        // that is not a decimal integer, or is out of range, is refused here
        // and never read as 0); else 0.
        let domain_id = match self.domain_id {
            Some(explicit) => explicit,
            None => crate::config::domain_id_from_env(crate::config::ENV_DOMAIN_ID)?.unwrap_or(0),
        };

        // Every thread this build starts is marked as this participant's
        // (`core::rt::shutdown::owned`), so that its drop recognises one of
        // its own threads and never waits for the thread it runs on.
        let participant_token = crate::dds::domain_registry::ParticipantToken::mint();
        let _owner = crate::core::rt::shutdown::OwnerScope::enter(participant_token.raw());

        // The domain must have an RTPS port, and above 232 it does not:
        // `PORT_BASE + DOMAIN_ID_GAIN * 233` is 65650 and does not fit a
        // u16, which is why the specification caps the domain there.
        // `MAX_DOMAIN_ID` names that limit in config.rs, and the SPDP receive
        // path clamps a REMOTE peer's domain to it. The configuration path
        // enforces it too: a participant configured with domain 240 would
        // otherwise compute a port that wraps to 1864 in a release build and
        // bind it in silence. Refused here so the caller reads a sentence
        // instead of debugging a participant that discovers nobody.
        //
        // The variant is `InvalidDomainId`, not `Config`: that typed variant
        // is the documented contract for exactly this input. `dds/mod.rs:135`
        // shows callers writing `Err(Error::InvalidDomainId(id)) =>` in a doc
        // example, and `tests/rtps_port_mapping.rs` has asserted it since the
        // 1.0.8 public release. Refusing earlier must not change WHAT the
        // caller catches. The explanation belongs in this comment; the error
        // stays the one the API promised.
        if domain_id > crate::config::MAX_DOMAIN_ID {
            return Err(crate::dds::Error::InvalidDomainId(domain_id));
        }

        // A readers' share outside its range makes every reliable pair in
        // one process able to stall (0) or every write fail at once (100),
        // or leaves writers no slot of a primary size class: refused before
        // the process-wide pool is built from it.
        self.memory_policy
            .check_reader_reserve_percent()
            .map_err(crate::dds::Error::Config)?;
        // A staging ceiling too low to hold a few large samples rejects
        // coherent sets for nothing else.
        self.memory_policy
            .check_max_staging_bytes()
            .map_err(crate::dds::Error::Config)?;

        // The SHM data path is wired (a BEST_EFFORT writer hands DATA to
        // a co-located BEST_EFFORT reader over a shared-memory ring), but
        // `ShmPolicy::Require` promises more than the wired leg delivers:
        // "no sample of mine ever goes over UDP behind my back". The wired
        // leg is the small-DATA leg; every sample past
        // DEFAULT_MAX_UNFRAGMENTED_SIZE goes out as DATA_FRAG, and that leg
        // is still UDP-only. Whether a participant will ever write such a
        // sample is a property of the samples, not of the configuration, so
        // it cannot be checked here nor refused per-peer at pairing. See
        // `shm::policy::shm_require_is_honourable`.
        if self.shm_policy == crate::transport::shm::ShmPolicy::Require
            && !crate::transport::shm::shm_require_is_honourable()
        {
            return Err(crate::dds::Error::Config(
                "ShmPolicy::Require cannot be honoured yet: the SHM data path carries \
                 unfragmented DATA only, so a sample large enough to be fragmented would go \
                 over UDP instead -- exactly what Require forbids. Use ShmPolicy::Prefer \
                 (which uses shared memory whenever the pairing supports it, and never \
                 falls back without counting and logging it) or ShmPolicy::Disable."
                    .to_string(),
            ));
        }

        // Reclaim this domain's ring segments (`/hdds_d<id>_w<guid>`) left
        // behind by a writer that crashed before its `Drop` could unlink
        // its own segment -- `kill -9`, an abort, an OOM kill. A graceful
        // shutdown already unlinks on drop (`ShmWriterTransport::drop`);
        // this is only for the case that cannot reach any `Drop` at all.
        // Scoped to this participant's own domain and to segments whose
        // sidecar owner record proves the creator is gone (see
        // `transport::shm::owner`); never to ones that might still be
        // live. Shared notify segments have no single owner; they get
        // their own last-user release below (`transport::shm::notify`).
        // Skipped when SHM is disabled outright, since nothing of this
        // participant's will ever create or depend on a ring segment.
        if self.shm_policy != crate::transport::shm::ShmPolicy::Disable {
            let reclaimed = crate::transport::shm::reclaim_dead_ring_segments(domain_id);
            if reclaimed > 0 {
                log::info!(
                    "[SHM] reclaimed {} ring segment(s) left behind by a dead owner on domain {}",
                    reclaimed,
                    domain_id
                );
            }
            // Same for the domain's shared topic notify segments whose every
            // registered user is provably dead (the last user crashed); a
            // segment with any live or unverifiable user is left alone.
            let released = crate::transport::shm::reclaim_dead_notify_segments(domain_id);
            if released > 0 {
                log::info!(
                    "[SHM] released {} notify segment(s) whose users all died on domain {}",
                    released,
                    domain_id
                );
            }
        }

        // Resolve transport options ONCE (explicit builder options win, env
        // vars are the fallback). Every downstream consumer (UDP transport,
        // listener sockets, SPDP announcer) reads this resolved struct.
        let mut transport_options = self.transport_options.resolve();
        let socket_buffer_options = self.socket_buffer_options.resolve();
        let discovery_timing = self.discovery_timing.validate()?;
        if let Some(config) = &self.discovery_server_config {
            config.validate().map_err(|error| {
                crate::dds::Error::Config(format!("invalid Discovery Server config: {}", error))
            })?;
            if self.transport_mode != TransportMode::UdpMulticast {
                return Err(crate::dds::Error::Config(
                    "Discovery Server integration requires UdpMulticast transport mode".to_string(),
                ));
            }
            // `disable_multicast` is the Discovery Server view of the
            // transport's multicast policy: ONE switch downstream (transport
            // sends and joins, listeners, SPDP locators, announcer fan-out).
            // It only lowers the default; an explicit `ReceiveOnly` or
            // `Disabled` on the transport options is kept as configured.
            if config.disable_multicast
                && transport_options.multicast == crate::transport::MulticastMode::Enabled
            {
                transport_options.multicast = crate::transport::MulticastMode::Disabled;
            }
        }
        // A cloud registry is the multicast replacement for cloud users:
        // same switch, same "only lowers the default" rule. Its config is
        // validated here so a bad provider string fails the build instead
        // of spawning a poller that can only report an error.
        #[cfg(feature = "cloud-discovery")]
        let cloud_poller_config = match &self.cloud_discovery_provider {
            Some(provider) => {
                if self.transport_mode != TransportMode::UdpMulticast {
                    return Err(crate::dds::Error::Config(
                        "cloud discovery requires UdpMulticast transport mode".to_string(),
                    ));
                }
                let config = super::cloud_discovery_runtime::poller_config(
                    provider,
                    self.consul_addr.as_deref(),
                    super::cloud_discovery_runtime::CloudTypedConfigs::default()
                        .with_aws(self.cloud_aws_config.as_deref())
                        .with_consul(self.consul_options.as_ref()),
                    self.cloud_poll_interval,
                    domain_id,
                )?;
                if self.cloud_disable_multicast
                    && transport_options.multicast == crate::transport::MulticastMode::Enabled
                {
                    transport_options.multicast = crate::transport::MulticastMode::Disabled;
                }
                Some(config)
            }
            None => None,
        };
        // DNS-SD is the same shape of peer source as a cloud registry: same
        // multicast switch, same "only lowers the default" rule, same
        // leased peer origin. That last point is why the two are mutually
        // exclusive: each owner replaces the whole origin on every poll, so
        // running both would have them delete each other's peers on
        // alternate ticks.
        #[cfg(feature = "dns-sd")]
        let dns_sd_config = match &self.dns_sd_config {
            Some(config) => {
                #[cfg(feature = "cloud-discovery")]
                if self.cloud_discovery_provider.is_some() {
                    return Err(crate::dds::Error::Config(
                        "a participant configures either a cloud registry or DNS-SD, not both: \
                         they own the same leased SPDP peer origin and would remove each other's \
                         peers on alternate polls"
                            .to_string(),
                    ));
                }
                if self.transport_mode != TransportMode::UdpMulticast {
                    return Err(crate::dds::Error::Config(format!(
                        "DNS-SD discovery requires UdpMulticast transport mode: it feeds the SPDP \
                         unicast destinations of a UDP transport, and {:?} has none",
                        self.transport_mode
                    )));
                }
                // Everything that could only be reported later (a malformed
                // service label, an unresolvable name, no nameserver at all)
                // fails the build here, because the multicast default is
                // about to be lowered for this participant: an accepted but
                // dead DNS-SD thread would leave it deaf in both directions.
                config.validate().map_err(|error| {
                    crate::dds::Error::Config(format!("invalid DNS-SD configuration: {}", error))
                })?;
                if self.dns_sd_disable_multicast
                    && transport_options.multicast == crate::transport::MulticastMode::Enabled
                {
                    transport_options.multicast = crate::transport::MulticastMode::Disabled;
                }
                Some(config.clone())
            }
            None => None,
        };

        // SPDP unicast destinations, shared by the announcer, the Discovery
        // Server runtime, the K8s discovery, the cloud registry poller and
        // (in ReceiveOnly / Disabled) the SPDP receive path that records
        // discovered participants.
        let spdp_peer_set = Arc::new(crate::core::discovery::SpdpPeerSet::new());

        // Step 1: Initialize slab pool and telemetry
        //
        // `init_slab_pool_with_policy` (not the bare `init_slab_pool`): the
        // pool is process-wide, built once from whichever participant gets
        // here first, so every `build()` must offer ITS `memory_policy` for
        // that comparison -- including a participant that never called
        // `.memory_policy()`, whose request is the default policy, not "no
        // opinion".
        let _slab_pool = crate::core::rt::init_slab_pool_with_policy(&self.memory_policy);
        let (metrics, exporter) = telemetry_setup::init_telemetry();
        let telemetry_thread = telemetry_setup::spawn_telemetry_thread(metrics.clone(), exporter);

        // Step 2: Calculate port mapping and generate GUID
        //
        // Port assignment priority (v1.0.6):
        //   1. Custom ports via with_discovery_ports() - for explicit control
        //   2. Code via .participant_id(Some(X)) - programmatic assignment
        //   3. Env via HDDS_PARTICIPANT_ID=X - deployment-time assignment (v1.0.6)
        //   4. Auto-assign - probe ports until free pair found
        //
        // For multi-process on same machine:
        //   - Leave the participant id unset: each process gets a free one
        //   - Or set a unique HDDS_PARTICIPANT_ID per process (0, 1, 2, ...)
        //   - Ports: metatraffic=7410+pid*2, userdata=7411+pid*2
        //
        // The two unicast ports are EXCLUSIVE (DDSI-RTPS 2.5 9.6.1.1: the
        // participant id exists to make them unique on the host). Auto-assign
        // binds them exclusively and KEEPS the two sockets it got: they are the
        // participant's own metatraffic and user-data unicast sockets, handed to
        // the transport and to the user-data listener below. Nothing is closed
        // and bound again, so two processes starting together cannot both see a
        // port free and then both take it. With an explicit id the same
        // exclusive bind happens in the transport, and a duplicate id fails there.
        let mut reserved_unicast: Option<(socket2::Socket, socket2::Socket)> = None;
        // Reservation of the two shared MULTICAST ports taken by the probe
        // below (auto-assign only). Kept across transport creation on Linux,
        // where it coexists with the transport's SO_REUSEADDR binds; released
        // before them elsewhere (BSD-family kernels want SO_REUSEPORT for two
        // binders of one exact address:port, Windows' SO_REUSEADDR is one-sided).
        let mut multicast_reservation: Vec<std::net::UdpSocket> = Vec::new();

        let (port_mapping, actual_participant_id) = match self.transport_mode {
            TransportMode::IntraProcess => (None, 0),
            TransportMode::UdpMulticast => {
                // Priority 1: Custom ports (if specified via with_discovery_ports())
                let (mapping, pid) = if let Some(custom) = self.custom_ports {
                    let mapping = crate::transport::PortMapping::from_custom(custom);
                    // Custom ports do not encode the participant id. The GUID
                    // prefix does not depend on it either (two participants of
                    // one process on the same custom ports with the same id
                    // would otherwise share a prefix; see
                    // `entity_registry::generate_guid`), but distinct ids
                    // are still handed out so that what reports the id
                    // tells the participants apart.
                    let pid = self
                        .participant_id
                        .unwrap_or_else(next_custom_ports_participant_id);
                    log::debug!(
                        "[hdds] Using CUSTOM ports -> spdp_multicast={}, sedp_unicast={}, user_unicast={}",
                        custom.spdp_multicast, custom.sedp_unicast, custom.user_unicast
                    );
                    (mapping, pid)
                // Priority 2: User-specified participant ID (RTPS formula)
                } else if let Some(pid) = self.participant_id {
                    // User-specified participant ID (RTPS formula)
                    let mapping = crate::transport::PortMapping::calculate(domain_id, pid)?;
                    log::debug!(
                        "[hdds] Using RTPS formula with participant_id={} -> multicast={}, unicast={}, userdata={}",
                        pid, mapping.metatraffic_multicast, mapping.metatraffic_unicast, mapping.user_unicast
                    );
                    (mapping, pid)
                // Priority 2.5: Environment variable HDDS_PARTICIPANT_ID
                } else if let Ok(pid_str) = std::env::var("HDDS_PARTICIPANT_ID") {
                    let pid: u8 = pid_str.parse().map_err(|e| {
                        log::error!(
                            "[hdds] Invalid HDDS_PARTICIPANT_ID='{}' (must be 0-119)",
                            pid_str
                        );
                        crate::dds::Error::Config(format!(
                            "HDDS_PARTICIPANT_ID='{}' is not a valid u8: {}",
                            pid_str, e
                        ))
                    })?;
                    let mapping = crate::transport::PortMapping::calculate(domain_id, pid)?;
                    log::info!(
                        "[hdds] Using HDDS_PARTICIPANT_ID={} -> unicast={}, userdata={}",
                        pid,
                        mapping.metatraffic_unicast,
                        mapping.user_unicast
                    );
                    (mapping, pid)
                } else {
                    // Priority 3: Auto-assign participant ID (try 0-255, RTPS formula)
                    //
                    // We bind BOTH metatraffic_unicast (7410) AND user_unicast (7411),
                    // exclusively, and keep the two sockets as the participant's own (see
                    // `reserved_unicast` above).
                    //
                    // Probe the two MULTICAST ports ONCE, here, before the per-pid
                    // unicast search below -- not inside its loop body. Both multicast
                    // ports are computed from domain_id alone (see MulticastPortProbe's
                    // doc), so they are IDENTICAL on every pid_guess the loop below will
                    // try: probing them per-iteration would just rebind the same two
                    // addresses up to 256 times and learn nothing new after the first.
                    // A busy multicast port is fatal for every participant id on this
                    // domain, so it is diagnosed fast, with the domain and the port
                    // named, instead of being discovered only after
                    // the unicast search commits, the transport builds and discovery
                    // setup runs, deep inside
                    // sockets.rs::create_data_multicast_socket or udp.rs's own
                    // metatraffic bind, as a bare-looking EADDRINUSE the reader had to
                    // trace back to this loop by hand.
                    //
                    // `.ok()`: an invalid domain_id is not diagnosed here on purpose --
                    // the per-pid loop below already returns the precise
                    // `InvalidDomainId` on its very first iteration (pid_guess=0), and
                    // duplicating that check here would just be two error paths for one
                    // condition.
                    if let Some(metatraffic_multicast_port) =
                        crate::transport::PortMapping::calculate(domain_id, 0)
                            .ok()
                            .map(|m| m.metatraffic_multicast)
                    {
                        let data_multicast_port =
                            metatraffic_multicast_port + crate::config::DATA_MULTICAST_OFFSET;
                        for (label, port) in [
                            ("METATRAFFIC MULTICAST", metatraffic_multicast_port),
                            ("DATA MULTICAST", data_multicast_port),
                        ] {
                            match probe_multicast_port(port) {
                                MulticastPortProbe::Reserved(sock) => {
                                    multicast_reservation.push(sock);
                                }
                                MulticastPortProbe::Busy(e) => {
                                    return Err(crate::dds::Error::IoError(std::io::Error::new(
                                        e.kind(),
                                        format!(
                                            "binding the {label} socket on port {port} \
                                             (domain {}) failed during participant-id \
                                             auto-assign: {e}. This socket sets \
                                             SO_REUSEADDR, so another process holds that \
                                             port without it. No participant id on this \
                                             domain can avoid it: unlike the unicast ports, \
                                             the multicast ports are the same for every \
                                             participant id (RTPS v2.5 formula is \
                                             domain-only)",
                                            domain_id
                                        ),
                                    )));
                                }
                                MulticastPortProbe::Inconclusive => {}
                            }
                        }
                    }

                    let mut found = None;

                    for pid_guess in 0..=255u8 {
                        let mapping =
                            match crate::transport::PortMapping::calculate(domain_id, pid_guess) {
                                Ok(m) => m,
                                // A DOMAIN that has no port is not a participant-id
                                // problem, and retrying 255 more ids cannot help. It
                                // is returned as is: folding it into the generic
                                // "all participant IDs (0-255) failed to produce a
                                // valid port mapping" error would send the caller
                                // hunting for a participant-id exhaustion that did
                                // not happen.
                                Err(error @ crate::dds::Error::InvalidDomainId(_)) => {
                                    return Err(error)
                                }
                                // A participant id that has no port on THIS domain is
                                // exactly what the loop is here to walk past.
                                Err(_) => continue,
                            };

                        // The bind IS the availability check: an exclusive bind
                        // fails while anyone holds the port, SO_REUSEADDR or not,
                        // and the socket it returns is the one the participant
                        // keeps. Any failure moves on to the next participant id,
                        // as it always has. The user port is not touched when the
                        // metatraffic port is already taken.
                        let meta = crate::transport::udp::bind_exclusive_unicast(
                            mapping.metatraffic_unicast,
                        );
                        let Ok(meta_sock) = meta else { continue };
                        let Ok(user_sock) =
                            crate::transport::udp::bind_exclusive_unicast(mapping.user_unicast)
                        else {
                            continue;
                        };
                        log::debug!(
                            "[hdds] Auto-assigned participant_id={} (RTPS formula) -> multicast={}, unicast={}, userdata={}",
                            pid_guess, mapping.metatraffic_multicast, mapping.metatraffic_unicast, mapping.user_unicast
                        );
                        reserved_unicast = Some((meta_sock, user_sock));
                        found = Some((mapping, pid_guess));
                        break;
                    }

                    // Every participant id this domain has ports for is in use.
                    // This is refused here: falling through to the last mapping with
                    // participant id 0 would leave the failure to a later bind, under
                    // a port that does not match the id reported.
                    found.ok_or_else(|| {
                        crate::dds::Error::IoError(std::io::Error::new(
                            std::io::ErrorKind::AddrInUse,
                            format!(
                                "no free participant id on domain {}: the unicast ports of \
                                 every participant id this domain has ports for are in use",
                                domain_id
                            ),
                        ))
                    })?
                };
                (Some(mapping), pid)
            }
        };

        // Step 2.5: Create runtime configuration and store port mapping
        let config = Arc::new(RuntimeConfig::new());
        if let Some(mapping) = port_mapping {
            config.set_port_mapping(mapping);
        }

        // Step 3: Create SEDP announcements cache for unicast replay (interop)
        let sedp_cache = entity_registry::create_sedp_cache();

        // Step 3.5: Initialize dialect detector (Phase 1.6 - monitoring passif)
        // Created before setup_discovery so it can be passed to SPDP callback
        let dialect_detector = Arc::new(std::sync::Mutex::new(
            crate::core::discovery::multicast::dialect_detector::DialectDetector::with_domain(
                domain_id,
            ),
        ));

        // Step 3.6: Create security suite BEFORE discovery setup (DDS Security v1.1)
        // Must be created early so AuthenticationPlugin can be connected to DiscoveryFsm
        #[cfg(feature = "security")]
        let security_suite: Option<Arc<SecurityPluginSuite>> = match self.security_config {
            Some(ref config) => Some(Arc::new(SecurityPluginSuite::new(
                config.clone(),
                domain_id,
            )?)),
            None => None,
        };

        // The participant GUID: RTPS v2.5 compliant, and with security the
        // prefix DDS-Security binds to the identity certificate (Sec.9.3.3,
        // Table 52, validate_local_identity), which a peer checks at the
        // handshake (`entity_registry::participant_guid`).
        #[cfg(feature = "security")]
        let identity_subject = match security_suite.as_ref() {
            Some(suite) => Some(suite.identity_subject_name_der().map_err(|err| {
                crate::dds::Error::Config(format!(
                    "cannot read the identity certificate's subject name: {}",
                    err
                ))
            })?),
            None => None,
        };
        #[cfg(not(feature = "security"))]
        let identity_subject: Option<Vec<u8>> = None;
        let guid = entity_registry::participant_guid(
            RTPS_ENTITYID_PARTICIPANT,
            identity_subject.as_deref(),
        );

        // Step 3.7: ask the governance whether this participant may join this
        // domain at all, BEFORE anything binds a socket or announces.
        //
        // Without this check `GovernanceConfig` would be parsed and its
        // domain rules stored with nothing reading them: a deployment could
        // hand us a governance document naming domain 12 and join domain 400,
        // and every layer above would report a secured participant.
        //
        // Deny is the right answer for a domain no rule covers: the operator
        // configured security and then joined somewhere their own policy does
        // not describe. Silently admitting them is the reading that cannot be
        // defended to a certifier.
        #[cfg(feature = "security")]
        if let Some(suite) = security_suite.as_ref() {
            if let Some(access_control) = suite.access_control() {
                access_control
                    .check_create_participant(domain_id)
                    .map_err(|err| {
                        log::error!(
                            "[security] governance refuses domain {}: {}",
                            domain_id,
                            err
                        );
                        crate::dds::Error::PermissionDenied(format!(
                            "governance does not allow this participant on domain {}: {}",
                            domain_id, err
                        ))
                    })?;
            }
        }

        // Build the participant's SPDP security payloads before discovery creates
        // its callback. The callback captures the resulting immutable context;
        // periodic announcements reuse the same bytes below.
        #[cfg(feature = "security")]
        let (identity_token, permissions_token, security_attributes_mask) =
            match security_suite.as_ref() {
                Some(suite) => {
                    let (id_tok, perm_tok) = suite.build_spdp_tokens().map_err(|err| {
                        log::error!("[security] Failed to build SPDP tokens: {}", err);
                        crate::dds::Error::Config(format!(
                            "failed to build SPDP security tokens: {}",
                            err
                        ))
                    })?;
                    (
                        Some(id_tok),
                        Some(perm_tok),
                        Some(security_attributes_mask_from(suite)),
                    )
                }
                None => (None, None, None),
            };
        #[cfg(not(feature = "security"))]
        let (identity_token, permissions_token, security_attributes_mask): SpdpSecurityTokenTriple =
            (None, None, None);

        let spdp_security_tokens = discovery_setup::SpdpSecurityTokens::new(
            identity_token.clone(),
            permissions_token.clone(),
            security_attributes_mask,
        );
        // One SPDP writer SN counter for the announcer and the replies.
        let spdp_sequence = spdp_security_tokens.sequence();

        // The participant's liveliness (DDS v1.4 Sec.2.2.3.11), given to its
        // receive path before any datagram arrives; its thread starts once
        // discovery exists (Step 10c).
        let clock = Arc::new(crate::dds::liveliness::MonotonicClock::new());
        #[cfg(test)]
        let clock: Arc<dyn crate::dds::liveliness::LivelinessClock> =
            self.liveliness_clock.clone().unwrap_or(clock);
        let liveliness_shared = crate::dds::liveliness::Shared::new(clock);

        // Step 4-5: Setup transport and discovery (if UdpMulticast mode)
        let (transport, discovery_components) = match self.transport_mode {
            TransportMode::IntraProcess => {
                // No transport or discovery for intra-process mode
                (
                    None,
                    discovery_setup::DiscoveryComponents {
                        discovery_fsm: None,
                        match_registry: None,
                        type_lookup: None,
                        registry: None,
                        router: None,
                        control_handler: None,
                        listeners: Vec::new(),
                        // Intra-process: no ring, no pool, nothing to hand a
                        // datagram to - and no Discovery Server session
                        // either, since that needs a UDP transport.
                        relay_ingress: None,
                        // Intra-process: no RTPS reliability state machine, but a
                        // registry still satisfies the struct; nothing ever reads it.
                        user_data_registry: crate::core::reader::ReaderProxyRegistry::new(),
                        // Intra-process: samples never leave the process at
                        // all, so there is nothing for a shared-memory leg to
                        // carry and no poller thread is spawned.
                        #[cfg(target_os = "linux")]
                        shm_receiver: None,
                        #[cfg(feature = "security")]
                        stateless_writer_handle: None,
                        known_sources: None,
                    },
                )
            }
            TransportMode::UdpMulticast => {
                let mapping = port_mapping.ok_or_else(|| {
                    crate::dds::Error::Config(
                        "port mapping is required for UdpMulticast transport mode".to_string(),
                    )
                })?;

                log::debug!(
                    "[hdds] Creating UDP transport domain={} pid={}",
                    domain_id,
                    actual_participant_id
                );

                // Linux keeps the multicast reservation alive through the
                // transport's own SO_REUSEADDR binds of the same ports; the
                // other kernels release it first (see its declaration).
                #[cfg(not(target_os = "linux"))]
                drop(std::mem::take(&mut multicast_reservation));
                let (reserved_metatraffic_unicast, reserved_user_unicast) =
                    match reserved_unicast.take() {
                        Some((meta, user)) => (Some(meta), Some(user)),
                        None => (None, None),
                    };
                let transport = Arc::new(
                    UdpTransport::new_with_reserved_unicast(
                        domain_id,
                        actual_participant_id,
                        mapping,
                        &transport_options,
                        &socket_buffer_options,
                        reserved_metatraffic_unicast,
                    )
                    .map_err(crate::dds::Error::IoError)?,
                );

                log::debug!("[hdds] UDP transport ready");

                #[cfg(feature = "type-lookup")]
                let type_lookup_config = discovery_setup::TypeLookupConfig {
                    registered_types: self.registered_types.clone(),
                    served_types: self.served_types.clone(),
                    dialect_detector: dialect_detector.clone(),
                };
                #[cfg(all(
                    feature = "xtypes-structural-assignability",
                    not(feature = "type-lookup")
                ))]
                let type_lookup_config = discovery_setup::TypeLookupConfig {
                    registered_types: self.registered_types.clone(),
                    served_types: self.served_types.clone(),
                };
                #[cfg(not(any(
                    feature = "type-lookup",
                    feature = "xtypes-structural-assignability"
                )))]
                let type_lookup_config = discovery_setup::TypeLookupConfig;

                // Setup discovery subsystem (FSM, listeners, demux router)
                // Phase 1.6: Pass dialect_detector for SPDP packet monitoring
                // DDS Security v1.1: Pass security_suite for AuthenticationPlugin -> DiscoveryFsm
                let components = discovery_setup::setup_discovery(
                    guid,
                    transport.clone(),
                    sedp_cache.clone(),
                    domain_id,
                    mapping,
                    dialect_detector.clone(),
                    type_lookup_config,
                    &transport_options,
                    &socket_buffer_options,
                    discovery_timing.lease_duration_ms,
                    spdp_security_tokens,
                    transport_options
                        .unicast_spdp_to_discovered()
                        .then(|| Arc::clone(&spdp_peer_set)),
                    reserved_user_unicast,
                    Arc::clone(&liveliness_shared),
                    #[cfg(feature = "security")]
                    security_suite.clone(),
                )
                .map_err(crate::dds::Error::IoError)?;

                (Some(transport), components)
            }
        };

        // Step 5.5: Register static peers (for unicast without discovery)
        // add_static_peer() is for UDP SPDP discovery. The manual TCP endpoint
        // has its own TcpConfig::initial_peers list.
        if !self.static_peers.is_empty() {
            if let Some(ref fsm) = discovery_components.discovery_fsm {
                for peer_addr in &self.static_peers {
                    println!("[hdds] Registering static peer: {}", peer_addr);
                    fsm.register_static_peer(*peer_addr);
                    spdp_peer_set.add_static(*peer_addr);
                }
            } else {
                // Provide helpful guidance based on configuration
                let has_tcp = self.tcp_config.as_ref().is_some_and(|c| c.enabled);
                if has_tcp {
                    eprintln!(
                        "[hdds] Warning: add_static_peer() requires UdpMulticast transport mode.\n\
                         For the manual TCP endpoint, use TcpConfig::initial_peers instead:\n\
                         \n\
                             .with_tcp(TcpConfig::tcp_only(vec![\"addr:port\".parse().expect(\"valid peer address\")]))\n\
                         \n\
                         Current transport mode: {:?}",
                        self.transport_mode
                    );
                } else {
                    eprintln!(
                        "[hdds] Warning: static_peers configured but no discovery FSM available.\n\
                         add_static_peer() requires TransportMode::UdpMulticast.\n\
                         Current transport mode: {:?}",
                        self.transport_mode
                    );
                }
            }
        }

        // Step 5.6: Create TCP transport (if configured)
        // Note: TCP transport is HDDS-to-HDDS only, NOT interoperable with other DDS vendors
        let tcp_transport = if let Some(tcp_config) = self.tcp_config {
            if tcp_config.enabled {
                log::info!(
                    "[hdds] Creating TCP transport (port={}, role={:?})",
                    tcp_config.listen_port,
                    tcp_config.role
                );

                match TcpTransport::new(guid.prefix, tcp_config) {
                    Ok(tcp) => {
                        log::info!("[hdds] TCP transport ready");
                        Some(Arc::new(tcp))
                    }
                    Err(e) => {
                        log::error!("[hdds] Failed to create TCP transport: {}", e);
                        // TCP is optional - continue without it
                        // For tcp_only mode, this would be an error, but we handle that gracefully
                        if self.transport_preference == TransportPreference::TcpOnly {
                            return Err(crate::dds::Error::IoError(e));
                        }
                        None
                    }
                }
            } else {
                None
            }
        } else {
            None
        };

        // Store transport preference
        let transport_preference = self.transport_preference;

        // Step 5.7: Start Kubernetes DNS discovery (if configured)
        #[cfg(feature = "k8s")]
        let k8s_discovery_handle = if let Some(k8s_config) = self.k8s_discovery_config {
            if let Some(ref fsm) = discovery_components.discovery_fsm {
                let dns_name = k8s_config.dns_name();
                let fsm_clone = Arc::clone(fsm);
                let k8s_spdp_peers = Arc::clone(&spdp_peer_set);
                let k8s_discovery = K8sDiscovery::new(k8s_config).on_peer_discovered(move |peer| {
                    log::info!("[K8s-Discovery] Registering peer: {}", peer);
                    fsm_clone.register_static_peer(peer);
                    k8s_spdp_peers.add_static(peer);
                });
                log::info!("[hdds] Starting K8s DNS discovery for service {}", dns_name);
                Some(k8s_discovery.start())
            } else {
                log::warn!(
                    "[hdds] K8s discovery configured but no discovery FSM (transport mode: {:?})",
                    self.transport_mode
                );
                None
            }
        } else {
            None
        };

        // Step 6: Spawn background threads (SPDP announcer, lease tracker)
        //
        // SPDP unicast destinations live in `spdp_peer_set`: the builder's
        // static peers (registered above), the env-configured peers (seeded
        // by the announcer) and the Discovery Server locators (runtime).
        // Multicast emission follows the transport's policy.
        #[cfg(feature = "cloud-discovery")]
        let cloud_discovery_configured = self.cloud_discovery_provider.is_some();
        #[cfg(not(feature = "cloud-discovery"))]
        let cloud_discovery_configured = false;
        let discovery_services_configured =
            self.discovery_server_config.is_some() || cloud_discovery_configured;
        #[cfg(test)]
        if let (Some(caps), Some(fsm)) = (
            self.hdds_capabilities,
            discovery_components.discovery_fsm.as_ref(),
        ) {
            fsm.set_local_capabilities(caps);
        }
        let participant_threads = threads::spawn_participant_threads(
            guid,
            metrics.clone(),
            transport.clone(),
            discovery_components.discovery_fsm.clone(),
            telemetry_thread,
            config.clone(),
            identity_token,
            permissions_token,
            security_attributes_mask,
            discovery_timing.lease_duration_ms,
            discovery_timing.announcement_period,
            Arc::clone(&spdp_peer_set),
            discovery_services_configured,
            spdp_sequence,
        );

        // Effective discovery configuration, one line, so "no hidden
        // behaviour" can be checked from a log instead of from the code:
        // the multicast mode actually in force, where the unicast SPDP
        // destinations come from, and whether a Discovery Server is driven.
        {
            let counts = spdp_peer_set.counts();
            let (rx_effective, join_error) = transport
                .as_ref()
                .map(|t| {
                    (
                        t.multicast_receive_enabled(),
                        t.multicast_join_error().unwrap_or("none").to_string(),
                    )
                })
                .unwrap_or((false, "n/a (no UDP transport)".to_string()));
            #[cfg(feature = "cloud-discovery")]
            let cloud_provider = self.cloud_discovery_provider.as_deref().unwrap_or("none");
            #[cfg(not(feature = "cloud-discovery"))]
            let cloud_provider = "none";
            // Addresses announced although nothing here is bound to them
            // (NAT mapping, relay endpoint): invisible in `ip addr`, so the
            // only place an operator can see them is this line.
            let external_locators = if transport_options.external_locators.is_empty() {
                "none".to_string()
            } else {
                transport_options
                    .external_locators
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            };
            log::info!(
                "[hdds] discovery config: multicast={:?} (tx={}, rx={}, join_error={}), unicast SPDP peers: static={} server={} discovered={} cloud={}, discovery_server={}, cloud_discovery={}, lease={}ms, period={:?}, external locators announced: {}",
                transport_options.multicast,
                transport_options.multicast_send_enabled(),
                rx_effective,
                join_error,
                counts.static_peers,
                counts.server_peers,
                counts.discovered_peers,
                counts.cloud_peers,
                self.discovery_server_config
                    .as_ref()
                    .map(|c| c.server_address.to_string())
                    .unwrap_or_else(|| "none".to_string()),
                cloud_provider,
                discovery_timing.lease_duration_ms,
                discovery_timing.announcement_period,
                external_locators,
            );
        }

        let discovery_server_runtime = match (&self.discovery_server_config, &transport) {
            (Some(server_config), Some(udp_transport)) => {
                // A Discovery Server session that cannot hand a relayed
                // datagram to anything is a session that silently loses every
                // relayed peer's discovery traffic. A transport implies the
                // receive plumbing was built, so this is an impossible state -
                // named rather than folded into the arm below, where it would
                // read as "no server configured".
                let relay_ingress =
                    discovery_components.relay_ingress.clone().ok_or_else(|| {
                        crate::dds::Error::Config(
                            "the discovery server session needs this participant's receive \
                             dispatch, and this transport mode built none"
                                .to_string(),
                        )
                    })?;
                Some(
                    super::discovery_server_runtime::DiscoveryServerRuntime::spawn(
                        server_config.clone(),
                        guid.prefix,
                        domain_id,
                        self.name.clone(),
                        discovery_server_builtin_endpoints(security_attributes_mask.is_some()),
                        udp_transport.as_ref(),
                        Arc::clone(&spdp_peer_set),
                        relay_ingress,
                    )?,
                )
            }
            _ => None,
        };

        // Step 7: Create type cache (if xtypes feature enabled)
        #[cfg(feature = "xtypes")]
        let type_cache = Arc::new(TypeCache::new(self.type_cache_capacity));

        // Step 7.5: the match notification registry (DDS spec
        // on_publication/subscription_matched). Discovery setup installed it on
        // the FSM before any discovery thread started (see `setup_discovery`),
        // so no announcement can have been handled without it.
        let match_registry = discovery_components.match_registry.clone();

        // Step 8: Get or create domain state for intra-process auto-binding
        let domain_state = DomainRegistry::global().get_or_create(domain_id);

        // Step 9: Spawn QUIC I/O thread if configured
        #[cfg(feature = "quic")]
        let quic_io_thread = if let Some(ref quic_config) = self.quic_config {
            log::info!("[QUIC] Starting QUIC I/O thread...");
            Some(crate::transport::quic::QuicIoThread::spawn(
                quic_config.clone(),
            ))
        } else {
            None
        };

        // Step 9.5: Spawn unicast routing thread if TCP or QUIC configured
        let unicast_routing_thread = {
            let has_tcp = tcp_transport.is_some();
            #[cfg(feature = "quic")]
            let has_quic = quic_io_thread.is_some();
            #[cfg(not(feature = "quic"))]
            let has_quic = false;

            if has_tcp || has_quic {
                #[cfg(feature = "quic")]
                let quic_h = quic_io_thread.as_ref().map(|q| q.handle());

                if let (Some(reg), Some(rtr)) =
                    (&discovery_components.registry, &discovery_components.router)
                {
                    Some(super::unicast_routing::spawn(
                        tcp_transport.clone(),
                        #[cfg(feature = "quic")]
                        quic_h,
                        Arc::clone(reg),
                        Arc::clone(&rtr.metrics),
                        Arc::new(AtomicBool::new(false)),
                        guid.prefix,
                        discovery_components.known_sources.clone(),
                        Arc::clone(&liveliness_shared),
                    ))
                } else {
                    None
                }
            } else {
                None
            }
        };

        // Step 10: Spawn the cloud registry poller if configured. It
        // registers this participant's metatraffic locators and feeds every
        // peer of this domain into the SPDP peer set (Cloud origin, leased),
        // so the announcer unicasts SPDP to them; SPDP/SEDP take over from
        // the first packet. The config was validated at the top of build().
        #[cfg(feature = "cloud-discovery")]
        let cloud_discovery_poller = match (cloud_poller_config, &transport) {
            (Some(config), Some(udp_transport)) => {
                let registration = super::cloud_discovery_runtime::own_participant_info(
                    guid,
                    &self.name,
                    domain_id,
                    udp_transport.as_ref(),
                );
                let sink = super::cloud_discovery_runtime::SpdpCloudSink::new(
                    Arc::clone(&spdp_peer_set),
                    guid.prefix,
                    super::cloud_discovery_runtime::cloud_lease(config.poll_interval),
                );
                let wiring = crate::discovery::cloud::CloudPollerWiring {
                    own_guid: Some(guid.as_bytes()),
                    registration,
                };
                log::info!(
                    "[CLOUD-DISCOVERY] Starting {:?} poller (poll every {:?}, domain {})",
                    config.provider,
                    config.poll_interval,
                    config.domain_id
                );
                Some(crate::discovery::cloud::CloudDiscoveryPoller::spawn_wired(
                    config, wiring, sink,
                ))
            }
            // A validated cloud config with no UDP transport must never be
            // dropped in silence: the multicast default was already lowered
            // for it, so the participant would come back with no peer source
            // at all. Unreachable today (build() refuses a cloud registry
            // outside UdpMulticast mode), this arm is what surfaces a future
            // transport refactor instead of producing a deaf participant.
            (Some(config), None) => {
                log::error!(
                    "[CLOUD-DISCOVERY] {:?} poller NOT started: no UDP transport was built; \
                     this participant has no cloud peer source",
                    config.provider
                );
                None
            }
            (None, _) => None,
        };

        // Step 10b: Start DNS-SD resolution if configured. Same contract as
        // the cloud poller above (leased Cloud origin of the SPDP peer set,
        // never the discovery FSM), so it sits here rather than beside the
        // K8s block: it needs the transport's advertised locators to keep
        // this participant out of its own peer set. The config was
        // validated at the top of build().
        #[cfg(feature = "dns-sd")]
        let dns_sd_discovery = match (dns_sd_config, &transport) {
            (Some(config), Some(udp_transport)) => {
                let sink = super::dnssd_runtime::SpdpDnsSdSink::new(
                    Arc::clone(&spdp_peer_set),
                    udp_transport.get_unicast_locators(),
                    super::dnssd_runtime::dnssd_lease(config.poll_interval),
                );
                let service_name = config.service_name();
                match crate::discovery::dnssd::DnsSdDiscovery::spawn(config, sink) {
                    Ok(discovery) => {
                        log::info!("[DNS-SD] Resolving {} for SPDP peers", service_name);
                        Some(discovery)
                    }
                    // validate() already ran at the top of build(), so the
                    // only way here is a thread that cannot be spawned.
                    Err(error) => {
                        return Err(crate::dds::Error::Config(format!(
                            "DNS-SD discovery could not start for {}: {}",
                            service_name, error
                        )))
                    }
                }
            }
            // A validated DNS-SD config with no UDP transport must never be
            // dropped in silence: the multicast default was already lowered
            // for it. Unreachable today (build() refuses DNS-SD outside
            // UdpMulticast mode); this arm surfaces a future transport
            // refactor instead of producing a deaf participant.
            (Some(config), None) => {
                log::error!(
                    "[DNS-SD] {} NOT resolved: no UDP transport was built; \
                     this participant has no DNS peer source",
                    config.service_name()
                );
                None
            }
            (None, _) => None,
        };

        // Step 10c: the participant's liveliness thread (DDS v1.4
        // Sec.2.2.3.11): the lease deadlines of the remote writers its
        // readers match, and its own assertions -- plus every reader's and writer's DEADLINE watches
        // (Sec.2.2.3.7, `crate::dds::liveliness::deadline`), which are
        // local bookkeeping and owe nothing to a transport. Always
        // started: an intra-process participant has no remote writer to
        // assert to (its `send`/`send_manual` are no-ops below), but its
        // readers and writers still need a DEADLINE scheduler.
        let liveliness = {
            let shared = liveliness_shared;
            let (send, send_manual) = match (&transport, &discovery_components.discovery_fsm) {
                (Some(udp), Some(fsm)) => {
                    let writer = crate::dds::liveliness::AssertionWriter::register(guid.prefix);
                    let writer_manual = Arc::clone(&writer);
                    let (udp, fsm) = (Arc::clone(udp), Arc::clone(fsm));
                    let (udp_manual, fsm_manual) = (Arc::clone(&udp), Arc::clone(&fsm));
                    (
                        Box::new(move || writer.assert_to_peers(&fsm, &udp))
                            as Box<dyn Fn() + Send>,
                        Box::new(move || {
                            writer_manual.assert_manual_to_peers(&fsm_manual, &udp_manual)
                        }) as Box<dyn Fn() + Send>,
                    )
                }
                _ => (
                    Box::new(|| {}) as Box<dyn Fn() + Send>,
                    Box::new(|| {}) as Box<dyn Fn() + Send>,
                ),
            };
            Some(
                crate::dds::liveliness::Scheduler::start(shared, send, send_manual)
                    .map_err(crate::dds::Error::IoError)?,
            )
        };

        // Step 11: Construct and return Participant (wrapped in Arc)
        let graph_guard = Arc::new(GuardCondition::new());

        Ok(Arc::new(Participant {
            name: self.name,
            transport_mode: self.transport_mode,
            domain_id,
            participant_id: actual_participant_id,
            participant_token,
            guid,
            port_mapping,
            transport,
            tcp_transport,
            transport_preference,
            #[cfg(feature = "quic")]
            quic_config: self.quic_config,
            lowbw_config: self.lowbw_config,
            discovery_server_config: self.discovery_server_config,
            #[cfg(feature = "cloud-discovery")]
            cloud_discovery_provider: self.cloud_discovery_provider,
            #[cfg(feature = "cloud-discovery")]
            cloud_discovery_config: self.consul_addr,
            #[cfg(feature = "cloud-discovery")]
            consul_options: self.consul_options,
            shm_policy: self.shm_policy,
            registry: discovery_components.registry,
            router: discovery_components.router,
            discovery_fsm: discovery_components.discovery_fsm,
            type_lookup: discovery_components.type_lookup,
            _spdp_announcer: participant_threads.spdp_announcer,
            discovery_server_runtime,
            lease_tracker: participant_threads.lease_tracker,
            liveliness,
            _control_handler: discovery_components.control_handler, // prevent Drop
            _listeners: discovery_components.listeners,             // prevent Drop
            #[cfg(test)]
            relay_ingress: discovery_components.relay_ingress.clone(),
            #[cfg(feature = "security")]
            _stateless_writer_handle: discovery_components.stateless_writer_handle,
            sedp_announcements: sedp_cache,
            telemetry: Some(participant_threads.telemetry),
            graph_guard,
            dialect_detector,
            next_entity_key: AtomicU32::new(0),
            implicit_publisher: std::sync::OnceLock::new(),
            domain_state,
            match_registry,
            user_data_registry: discovery_components.user_data_registry,
            #[cfg(target_os = "linux")]
            _shm_receiver: discovery_components.shm_receiver,
            #[cfg(feature = "xtypes")]
            type_cache,
            #[cfg(feature = "xtypes")]
            registered_types: self.registered_types,
            #[cfg(feature = "xtypes")]
            served_types: self.served_types,
            #[cfg(feature = "xtypes")]
            topic_types: self.topic_types,
            #[cfg(feature = "xtypes")]
            distro: self.distro,
            #[cfg(feature = "security")]
            security: security_suite,
            #[cfg(feature = "k8s")]
            k8s_discovery_handle,
            #[cfg(feature = "dns-sd")]
            dns_sd_discovery,
            #[cfg(feature = "quic")]
            quic_io_thread,
            #[cfg(feature = "cloud-discovery")]
            cloud_discovery_poller,
            _unicast_routing_thread: unicast_routing_thread,
            #[cfg(all(test, feature = "security"))]
            leaves_without_a_sealed_departure: std::sync::atomic::AtomicBool::new(false),
        }))
    }
}

/// Process-unique participant id for participants built on custom ports
/// without an explicit id: the ports do not depend on it. Wraps at the RTPS
/// participant-id range (0..=119).
fn next_custom_ports_participant_id() -> u8 {
    use std::sync::atomic::{AtomicU8, Ordering};
    static NEXT: AtomicU8 = AtomicU8::new(0);
    NEXT.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
        Some((n + 1) % 120)
    })
    .unwrap_or(0)
}

fn discovery_server_builtin_endpoints(security_enabled: bool) -> u32 {
    use crate::protocol::discovery::constants::{
        BUILTIN_ENDPOINT_SET_DEFAULT, BUILTIN_ENDPOINT_SET_SECURITY,
    };
    let mut endpoint_set = BUILTIN_ENDPOINT_SET_DEFAULT;
    if security_enabled {
        endpoint_set |= BUILTIN_ENDPOINT_SET_SECURITY;
    }
    if cfg!(feature = "type-lookup") {
        endpoint_set |= 0x0000_F000;
    }
    endpoint_set
}

/// The 8-byte `PID_PARTICIPANT_SECURITY_INFO` payload (DDS Security v1.1
/// Sec.7.2.7, Sec.7.4.1.4): `participant_security_attributes` then
/// `plugin_participant_security_attributes`, little endian.
///
/// Under a governance document, the masks of the
/// `ParticipantSecurityAttributes` its domain rule gives this participant
/// (Sec.9.4.1.2.5.2 to 9.4.1.2.5.6), with the bits of Table 28
/// (`IS_RTPS_PROTECTED` 1 << 0, `IS_DISCOVERY_PROTECTED` 1 << 1,
/// `IS_LIVELINESS_PROTECTED` 1 << 2, `IS_VALID` 1 << 31) and Table 60 for the
/// plugin mask (`IS_RTPS_ENCRYPTED` 1 << 0, `IS_DISCOVERY_ENCRYPTED` 1 << 1,
/// `IS_LIVELINESS_ENCRYPTED` 1 << 2, the three `..._ORIGIN_AUTHENTICATED` 1 << 3
/// to 1 << 5, is_valid 1 << 31 per Sec.7.2.7). "In order to communicate, two
/// DomainParticipants need to have the same ParticipantSecurityInfo"
/// (Sec.9.4.2.4): the bits are what the governance says, so two participants
/// of one governance announce the same masks.
///
/// Without a governance document there are no attributes to announce: both
/// masks say only `IS_VALID`, as before.
#[cfg(feature = "security")]
fn security_attributes_mask_from(suite: &SecurityPluginSuite) -> [u8; 8] {
    const IS_VALID: u32 = 0x8000_0000;
    if let Some(access) = suite.access_control() {
        match access.participant_attributes() {
            Ok(attributes) => return attributes.security_info_le(),
            // Unreachable once the participant was admitted to its domain
            // (`check_create_participant`): a domain no rule covers is
            // refused before the participant binds.
            Err(e) => log::error!(
                "[security] no participant security attributes ({}): announcing IS_VALID only",
                e
            ),
        }
    }
    let mut out = [0u8; 8];
    out[0..4].copy_from_slice(&IS_VALID.to_le_bytes());
    out[4..8].copy_from_slice(&IS_VALID.to_le_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// DDS-Security v1.1 Sec.7.2.7, Tables 28 and 60: under a governance
    /// document PID_PARTICIPANT_SECURITY_INFO carries the bits its domain
    /// rule gives the participant; without one, IS_VALID alone. Decoded from
    /// the 8 octets the SPDP announcer is handed.
    #[cfg(feature = "security")]
    #[test]
    fn the_participant_security_info_carries_the_governance_bits() {
        use crate::security::test_pki::{
            TEST_CA_CERT_PEM, TEST_IDENTITY_CERT_PEM, TEST_IDENTITY_KEY_PEM,
        };
        use std::io::Write;
        let file = |bytes: &[u8]| {
            let mut f = tempfile::NamedTempFile::new().expect("temp");
            f.write_all(bytes).expect("write");
            f
        };
        let (cert, key, ca) = (
            file(TEST_IDENTITY_CERT_PEM),
            file(TEST_IDENTITY_KEY_PEM),
            file(TEST_CA_CERT_PEM),
        );
        let permissions = file(
            b"<dds><permissions><grant name=\"g\"><subject_name>CN=DDS Test Identity, \
              O=HDDS Test</subject_name><validity><not_before>2020-01-01T00:00:00</not_before>\
              <not_after>2036-01-01T00:00:00</not_after></validity><allow_rule><domains>\
              <id>7</id></domains><publish><topics><topic>*</topic></topics></publish>\
              </allow_rule><default>DENY</default></grant></permissions></dds>",
        );
        let suite = |discovery: &str| {
            let governance = file(
                format!(
                    "<dds><domain_access_rules><domain_rule><domains><id>7</id></domains>\
                     <allow_unauthenticated_participants>false</allow_unauthenticated_participants>\
                     <enable_join_access_control>true</enable_join_access_control>\
                     <discovery_protection_kind>{}</discovery_protection_kind>\
                     <data_protection_kind>NONE</data_protection_kind>\
                     </domain_rule></domain_access_rules></dds>",
                    discovery
                )
                .as_bytes(),
            );
            let config = crate::security::SecurityConfig::builder()
                .identity_certificate(cert.path())
                .private_key(key.path())
                .ca_certificates(ca.path())
                .governance_xml(governance.path())
                .permissions_xml(permissions.path())
                .insecure_allow_unsigned_documents(true)
                .build()
                .expect("config");
            SecurityPluginSuite::new(config, 7).expect("suite")
        };
        for (discovery, participant, plugin) in [
            ("NONE", 0x8000_0000u32, 0x8000_0000u32),
            ("SIGN", 0x8000_0002, 0x8000_0000),
            // The WITH_ORIGIN_AUTHENTICATION kinds are refused at governance
            // load (`access::permissions::refuse_unapplied`); their masks are
            // pinned in `access::attributes`.
            ("ENCRYPT", 0x8000_0002, 0x8000_0002),
        ] {
            let info = security_attributes_mask_from(&suite(discovery));
            assert_eq!(
                u32::from_le_bytes([info[0], info[1], info[2], info[3]]),
                participant,
                "{}: ParticipantSecurityAttributesMask",
                discovery
            );
            assert_eq!(
                u32::from_le_bytes([info[4], info[5], info[6], info[7]]),
                plugin,
                "{}: PluginParticipantSecurityAttributesMask",
                discovery
            );
        }

        let ungoverned = crate::security::SecurityConfig::builder()
            .identity_certificate(cert.path())
            .private_key(key.path())
            .ca_certificates(ca.path())
            .build()
            .expect("config");
        assert_eq!(
            security_attributes_mask_from(&SecurityPluginSuite::new(ungoverned, 7).expect("suite")),
            [0, 0, 0, 0x80, 0, 0, 0, 0x80]
        );
    }
    use crate::discovery_server::DiscoveryServerConfig;
    use std::net::{Ipv4Addr, UdpSocket};
    use std::time::Duration;

    /// Every way a second socket could try to sit on `port`. On Linux a
    /// socket that set SO_REUSEADDR (or SO_REUSEPORT) is admitted beside a
    /// holder that set it too, which is exactly how two participants could
    /// share one unicast port without a word.
    fn second_binds(port: u16) -> Vec<(&'static str, std::io::Result<socket2::Socket>)> {
        use socket2::{Domain, Protocol, Socket, Type};
        let bind = |reuse_address: bool, reuse_port: bool| -> std::io::Result<Socket> {
            let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
            if reuse_address {
                socket.set_reuse_address(true)?;
            }
            #[cfg(unix)]
            if reuse_port {
                crate::transport::udp::set_reuseport(&socket)?;
            }
            #[cfg(not(unix))]
            let _ = reuse_port;
            let addr: std::net::SocketAddr = (Ipv4Addr::UNSPECIFIED, port).into();
            socket.bind(&addr.into())?;
            Ok(socket)
        };
        vec![
            ("plain", bind(false, false)),
            ("SO_REUSEADDR", bind(true, false)),
            ("SO_REUSEADDR+SO_REUSEPORT", bind(true, true)),
        ]
    }

    fn udp_participant(
        name: &str,
        domain: u32,
        participant_id: Option<u8>,
    ) -> Result<Arc<Participant>> {
        Participant::builder(name)
            .domain_id(domain)
            .with_transport(TransportMode::UdpMulticast)
            .participant_id(participant_id)
            .shm_disable()
            .build()
    }

    /// DDSI-RTPS 2.5 9.6.1.1: the unicast ports are unique on the host. Two
    /// auto-assigned participants get different ids and different ports, and
    /// while they live nobody else can bind those ports, whatever socket
    /// options the newcomer sets. The auto-assignment's exclusive bind is the
    /// participant's own socket (handed to the transport and the user-data
    /// listener), so there is no close-and-rebind to race with.
    #[test]
    fn auto_assigned_participants_hold_their_unicast_ports_exclusively() {
        let domain = crate::test_support::domains::unique_domain();
        let first = udp_participant("exclusive_a", domain.id(), None).expect("first participant");
        let second = udp_participant("exclusive_b", domain.id(), None).expect("second participant");
        assert_ne!(
            first.participant_id(),
            second.participant_id(),
            "two auto-assigned participants got the same participant id"
        );

        let mut ports = Vec::new();
        for participant in [&first, &second] {
            let mapping = participant.port_mapping().expect("UDP participant mapping");
            ports.push(mapping.metatraffic_unicast);
            ports.push(mapping.user_unicast);
        }
        let distinct: std::collections::HashSet<u16> = ports.iter().copied().collect();
        assert_eq!(
            distinct.len(),
            4,
            "unicast ports must not overlap: {ports:?}"
        );

        for port in ports {
            for (how, outcome) in second_binds(port) {
                assert_eq!(
                    outcome.as_ref().err().map(std::io::Error::kind),
                    Some(std::io::ErrorKind::AddrInUse),
                    "a {how} bind of a participant's unicast port {port} must be refused; \
                     got {outcome:?}"
                );
            }
        }
    }

    /// An explicit participant id another participant already uses is an
    /// error naming the port, not two participants silently splitting one
    /// port's traffic. The same id on another domain is a different port and
    /// is fine.
    #[test]
    fn an_explicit_participant_id_in_use_is_refused() {
        let domain = crate::test_support::domains::unique_domain();
        let other_domain = crate::test_support::domains::unique_domain();
        let first = udp_participant("explicit_a", domain.id(), Some(5)).expect("first participant");
        let port = first
            .port_mapping()
            .expect("UDP participant mapping")
            .metatraffic_unicast;

        match udp_participant("explicit_b", domain.id(), Some(5)) {
            Err(crate::dds::Error::IoError(error)) => {
                assert_eq!(error.kind(), std::io::ErrorKind::AddrInUse, "{error}");
                let message = error.to_string();
                assert!(
                    message.contains(&port.to_string()) && message.contains("participant 5"),
                    "the error must name the port and the participant id: {message}"
                );
            }
            Err(other) => panic!("expected an AddrInUse IoError, got {other}"),
            Ok(_) => panic!("a second participant was built on participant id 5's ports"),
        }

        // The refused build released whatever it had bound: the first one
        // still owns its ports, and the id stays usable elsewhere.
        let elsewhere = udp_participant("explicit_c", other_domain.id(), Some(5));
        assert!(elsewhere.is_ok(), "{:?}", elsewhere.err());
        drop(first);
        // Freed at once: UDP has no TIME_WAIT.
        let again = udp_participant("explicit_d", domain.id(), Some(5));
        assert!(again.is_ok(), "{:?}", again.err());
    }

    /// Custom ports are explicit ports: the same unicast pair twice is
    /// refused like a duplicate participant id.
    #[test]
    fn the_same_custom_unicast_ports_twice_are_refused() {
        // The leased domain's own ports, so nothing else in the suite uses them.
        let domain = crate::test_support::domains::unique_domain();
        let mapping = crate::transport::PortMapping::calculate(domain.id(), 0)
            .expect("every pool domain has a port mapping");
        let build = |name: &str| {
            Participant::builder(name)
                .domain_id(domain.id())
                .with_transport(TransportMode::UdpMulticast)
                .with_discovery_ports(
                    mapping.metatraffic_multicast,
                    mapping.metatraffic_unicast,
                    mapping.user_unicast,
                )
                .shm_disable()
                .build()
        };
        let first = build("custom_a").expect("first participant on custom ports");
        match build("custom_b") {
            Err(crate::dds::Error::IoError(error)) => {
                assert_eq!(error.kind(), std::io::ErrorKind::AddrInUse, "{error}");
            }
            Err(other) => panic!("expected an AddrInUse IoError, got {other}"),
            Ok(_) => panic!("a second participant was built on the same custom unicast ports"),
        }
        drop(first);
    }

    /// A child forked between another thread's plain reservation bind and its
    /// close keeps that port bound until the child execs or exits: fork copies
    /// the fd table, and close-on-exec only acts at exec. A bootstrap that
    /// closed its plain reservation sockets and rebound the same ports with
    /// SO_REUSEADDR a few lines later would see a copy held by a child turn
    /// that rebind into EADDRINUSE. HDDS forks during transport construction
    /// itself (`ip -4 addr show`, twice per participant), so two participants building
    /// concurrently in one process were enough. The child's pre-exec window can reach
    /// ~10 ms under load and span the probe, the close and the rebind.
    ///
    /// Typical timing on an idle host: the plain
    /// reservation is held ~0.2 ms, and the SO_REUSEADDR rebind of the same
    /// port comes ~11 ms after its close (the `ip` spawn sits in between). A
    /// child must therefore be forked inside that 0.2 ms and still be alive
    /// 11 ms later, so this is a PRESSURE test, probabilistic by construction:
    /// the deterministic pin is
    /// `auto_assigned_participants_hold_their_unicast_ports_exclusively` above
    /// (the auto-assignment never closes and rebinds at all).
    /// An unbounded form of this test (three forkers, no cap) is too
    /// aggressive. Here two threads fork without waiting, each keeping
    /// at most `OUTSTANDING_PER_FORKER` children alive (50 ms each, no exec),
    /// so the test never holds more than 24 extra processes. Only
    /// async-signal-safe calls run in the child. Children are reaped by their
    /// own pid, never with `waitpid(-1)`, which would steal the `ip` children
    /// of participants building in other tests of this binary. The forkers
    /// are stopped and joined from a guard, so a panic in the builds below
    /// cannot leave them forking for the rest of the binary's life.
    ///
    /// Ignored by default on purpose: every fork duplicates every open fd of
    /// this binary, which manufactures the very hazard for unrelated tests
    /// running beside it (three of three full lib runs with this test active
    /// had 2-5 unrelated timing and authentication failures, none of them
    /// AddrInUse). Run it alone:
    /// `cargo test -p hdds --lib participant_builds_while_other_threads_fork -- --ignored`.
    #[test]
    #[cfg(target_os = "linux")]
    #[ignore = "pressure test (~20 s, hundreds of forks) that perturbs unrelated tests in the parallel suite; run alone with --ignored"]
    fn participant_builds_while_other_threads_fork() {
        use std::sync::atomic::Ordering;

        const FORKERS: usize = 2;
        const OUTSTANDING_PER_FORKER: usize = 12;
        const CHILD_HOLD_NANOS: i64 = 50_000_000;
        const BUILDS: usize = 16;

        struct Forkers {
            stop: Arc<AtomicBool>,
            handles: Vec<std::thread::JoinHandle<()>>,
        }
        impl Drop for Forkers {
            fn drop(&mut self) {
                self.stop.store(true, Ordering::Relaxed);
                for handle in self.handles.drain(..) {
                    let _ = handle.join();
                }
            }
        }

        let domain = crate::test_support::domains::unique_domain();
        let stop = Arc::new(AtomicBool::new(false));
        let handles = (0..FORKERS)
            .map(|_| {
                let stop = Arc::clone(&stop);
                std::thread::spawn(move || {
                    let mut children: Vec<libc::pid_t> = Vec::new();
                    while !stop.load(Ordering::Relaxed) {
                        if children.len() >= OUTSTANDING_PER_FORKER {
                            let oldest = children.remove(0);
                            let mut status = 0;
                            // SAFETY: blocking waitpid on a child this thread
                            // created; its exit status is irrelevant.
                            let _ = unsafe { libc::waitpid(oldest, &mut status, 0) };
                        }
                        // SAFETY: the child runs only nanosleep and _exit,
                        // both async-signal-safe, and never returns into
                        // Rust; the parent reaps it by its own pid.
                        let pid = unsafe { libc::fork() };
                        if pid == 0 {
                            let hold = libc::timespec {
                                tv_sec: 0,
                                tv_nsec: CHILD_HOLD_NANOS,
                            };
                            unsafe {
                                libc::nanosleep(&hold, std::ptr::null_mut());
                                libc::_exit(0);
                            }
                        }
                        if pid < 0 {
                            // Out of processes: back off instead of spinning.
                            // The test then applies whatever pressure it could.
                            std::thread::sleep(Duration::from_millis(5));
                            continue;
                        }
                        children.push(pid);
                        // Reap what has already exited, without blocking.
                        children.retain(|&child| {
                            let mut status = 0;
                            // SAFETY: non-blocking waitpid on a child this
                            // thread created.
                            unsafe { libc::waitpid(child, &mut status, libc::WNOHANG) == 0 }
                        });
                    }
                    for child in children {
                        let mut status = 0;
                        // SAFETY: blocking waitpid on a child this thread
                        // created; its exit status is irrelevant.
                        let _ = unsafe { libc::waitpid(child, &mut status, 0) };
                    }
                })
            })
            .collect();
        let forkers = Forkers { stop, handles };

        let mut alive = Vec::with_capacity(BUILDS);
        let mut failures = Vec::new();
        for i in 0..BUILDS {
            match Participant::builder(&format!("fork_hold_{i}"))
                .domain_id(domain.id())
                .with_transport(TransportMode::UdpMulticast)
                .build()
            {
                Ok(participant) => alive.push(participant),
                Err(e) => failures.push(format!("build {i}: {e}")),
            }
        }
        drop(forkers);
        drop(alive);

        assert!(
            failures.is_empty(),
            "{} of {} participant builds failed while other threads forked:\n{}",
            failures.len(),
            BUILDS,
            failures.join("\n")
        );
    }

    /// A domain the RTPS port formula cannot express is refused by
    /// `build()`, with a sentence, before anything binds.
    ///
    /// Without this check the port would be computed as `domain_id as u16`
    /// FIRST, so a release build would wrap: domain 240 would bind 1864 and
    /// domain 250 would bind 4364, ports no vendor computes for any domain.
    /// The participant would then discover nobody and report nothing. The
    /// receive path clamps a REMOTE peer's domain to `MAX_DOMAIN_ID`, so the
    /// local path must be as strict about what we configure ourselves as the
    /// receive path is about what others announce.
    ///
    /// This test asserts the VARIANT, not the message: a message check
    /// cannot notice a changed variant, and `Error::InvalidDomainId` is the
    /// documented contract for this input (see also
    /// `tests/rtps_port_mapping.rs::test_invalid_domain_id`). Assert what a
    /// caller matches on; the wording is not the contract.
    #[test]
    fn build_refuses_a_domain_the_rtps_port_formula_cannot_express() {
        for domain in [
            crate::config::MAX_DOMAIN_ID + 1,
            240,
            250,
            255,
            u32::from(u16::MAX) + 1,
        ] {
            match Participant::builder("out-of-range-domain")
                .domain_id(domain)
                .build()
            {
                Err(crate::dds::Error::InvalidDomainId(reported)) => {
                    assert_eq!(
                        reported, domain,
                        "the refusal must report the domain it refused"
                    );
                }
                Err(other) => panic!(
                    "domain {} refused for the wrong reason: {:?}",
                    domain, other
                ),
                Ok(_) => panic!(
                    "build() accepted domain {}, which has no RTPS port: it would bind {} instead",
                    domain,
                    (u32::from(crate::config::PORT_BASE)
                        + u32::from(crate::config::DOMAIN_ID_GAIN) * domain)
                        % 65_536
                ),
            }
        }

        // The last domain that DOES have a port is still accepted, so the
        // check bounds the range instead of shrinking it.
        assert!(
            Participant::builder("highest-valid-domain")
                .domain_id(crate::config::MAX_DOMAIN_ID)
                .build()
                .is_ok(),
            "domain {} has a port (65400) and must still build",
            crate::config::MAX_DOMAIN_ID
        );
    }

    /// A participant registers with a discovery server under the same
    /// builtin endpoints its SPDP announcement names: the secure ones it
    /// serves, and no other (`BUILTIN_ENDPOINT_SET_SECURITY`).
    #[test]
    fn the_discovery_server_is_told_the_endpoints_the_announcement_names() {
        use crate::protocol::discovery::constants::{
            BUILTIN_ENDPOINT_SET_DEFAULT, BUILTIN_ENDPOINT_SET_SECURITY,
        };
        let typelookup = if cfg!(feature = "type-lookup") {
            0x0000_F000
        } else {
            0
        };
        assert_eq!(
            super::discovery_server_builtin_endpoints(false),
            BUILTIN_ENDPOINT_SET_DEFAULT | typelookup
        );
        assert_eq!(
            super::discovery_server_builtin_endpoints(true),
            BUILTIN_ENDPOINT_SET_DEFAULT | BUILTIN_ENDPOINT_SET_SECURITY | typelookup
        );
    }

    #[test]
    fn discovery_server_rejects_intra_process_transport() {
        let result = Participant::builder("invalid-discovery-server-transport")
            .with_transport(TransportMode::IntraProcess)
            .with_discovery_server(DiscoveryServerConfig::default())
            .build();

        match result {
            Err(crate::dds::Error::Config(message)) => assert!(
                message.contains("requires UdpMulticast"),
                "unexpected configuration error: {message}"
            ),
            Err(other) => panic!("unexpected error: {other}"),
            Ok(_) => panic!("Discovery Server accepted IntraProcess transport"),
        }
    }

    /// `ShmPolicy::Require` must refuse at `build()`, not silently fall back
    /// to UDP. A `Require` that built and sent every sample over UDP would be
    /// a fail-open lie for a policy whose entire point is to fail loudly when
    /// it cannot deliver. The SHM data path carries unfragmented DATA only
    /// (see `transport::shm::shm_require_is_honourable`), so nothing can
    /// honour the request for larger samples.
    #[test]
    fn shm_require_refuses_at_build() {
        let result = Participant::builder("shm_require_refusal")
            .with_transport(TransportMode::IntraProcess)
            .shm_policy(crate::transport::shm::ShmPolicy::Require)
            .build();

        match result {
            Err(crate::dds::Error::Config(message)) => {
                assert!(
                    message.to_ascii_lowercase().contains("shm"),
                    "the refusal must mention SHM: {message}"
                );
            }
            Err(other) => panic!("ShmPolicy::Require refused for the wrong reason: {other:?}"),
            Ok(_) => panic!(
                "build() accepted ShmPolicy::Require, which the engine cannot honour \
                 (the SHM data path is unwired) -- this used to silently fall back to UDP"
            ),
        }
    }

    /// A participant with no co-located peer runs no shared-memory poller,
    /// whether SHM is disabled or merely available: the thread starts with
    /// the first attach request, which needs a pairing.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_participant_without_a_shm_peer_runs_no_shm_poller() {
        for policy in [
            crate::transport::shm::ShmPolicy::Disable,
            crate::transport::shm::ShmPolicy::Prefer,
        ] {
            let participant = Participant::builder("shm_no_poller")
                .domain_id(231)
                .shm_policy(policy)
                .build()
                .expect("participant");
            let running = participant
                ._shm_receiver
                .as_ref()
                .is_some_and(|receiver| receiver.has_poller());
            assert!(
                !running,
                "{policy:?}: a participant with no shared-memory pairing runs a poller thread"
            );
        }
    }

    /// Control: the same shorthand accessor also refuses.
    #[test]
    fn shm_require_shorthand_refuses_at_build() {
        let result = Participant::builder("shm_require_shorthand_refusal")
            .with_transport(TransportMode::IntraProcess)
            .shm_require()
            .build();
        assert!(
            result.is_err(),
            "shm_require() shorthand must refuse at build just like shm_policy(Require)"
        );
    }

    /// Control: `Prefer` (default) and `Disable` are unaffected by the
    /// `Require` refusal and still build successfully.
    #[test]
    fn shm_prefer_and_disable_still_build() {
        assert!(
            Participant::builder("shm_prefer_still_builds")
                .with_transport(TransportMode::IntraProcess)
                .shm_policy(crate::transport::shm::ShmPolicy::Prefer)
                .build()
                .is_ok(),
            "ShmPolicy::Prefer must still build"
        );
        assert!(
            Participant::builder("shm_disable_still_builds")
                .with_transport(TransportMode::IntraProcess)
                .shm_policy(crate::transport::shm::ShmPolicy::Disable)
                .build()
                .is_ok(),
            "ShmPolicy::Disable must still build"
        );
    }

    #[test]
    fn custom_ports_participants_get_distinct_ids_by_default() {
        let a = next_custom_ports_participant_id();
        let b = next_custom_ports_participant_id();
        assert_ne!(a, b);
        assert!(a < 120 && b < 120);
    }

    #[test]
    fn seed_peer_api_emits_unicast_spdp() {
        let receiver = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let receiver_addr = receiver.local_addr().unwrap();

        let participant = crate::test_support::ports::with_reserved_ports(
            8,
            |[spdp_multicast, sedp_unicast, user_unicast]| {
                Participant::builder("seed-peer-spdp-test")
                    .domain_id(42)
                    .with_discovery_ports(spdp_multicast, sedp_unicast, user_unicast)
                    .with_seed_peers(&receiver_addr.to_string())
                    .build()
            },
        )
        .expect("build participant with seed peer");

        let mut packet = [0u8; 2048];
        let (bytes_read, _) = receiver.recv_from(&mut packet).expect("receive seed SPDP");
        assert!(bytes_read >= 20);
        assert_eq!(&packet[..4], b"RTPS");

        drop(participant);
    }

    /// The premise that motivated "probe or retry the multicast ports"
    /// -- that a different participant id could sidestep a busy multicast
    /// port -- does not hold against the actual RTPS v2.5 formula. Pin it as
    /// a test, not just a code comment: if a future change ever makes a
    /// multicast port depend on `participant_id`, this fails and whoever
    /// touched the formula finds out that `probe_multicast_port` above is
    /// hoisted OUT of the per-pid loop on the strength of exactly this fact.
    #[test]
    fn multicast_ports_do_not_vary_with_participant_id() {
        let domain = crate::test_support::domains::unique_domain();
        let first = crate::transport::PortMapping::calculate(domain.id(), 0)
            .expect("pool domain has a port mapping");
        for pid in [1u8, 2, 63, 119] {
            let mapping = crate::transport::PortMapping::calculate(domain.id(), pid)
                .unwrap_or_else(|e| panic!("pid {pid} on domain {}: {e:?}", domain.id()));
            assert_eq!(
                mapping.metatraffic_multicast, first.metatraffic_multicast,
                "metatraffic_multicast changed with participant_id={pid}: \
                 the hoisted-once-before-the-loop probe would then be wrong"
            );
            assert_eq!(
                mapping.sedp_multicast, first.sedp_multicast,
                "sedp_multicast changed with participant_id={pid}"
            );
        }
    }

    /// The diagnosable-error half of item 3: a non-cooperative holder on
    /// the METATRAFFIC multicast port (SPDP) must be caught by the auto-assign
    /// probe, fast, with a message naming the port and the domain -- not
    /// discovered later as a bare EADDRINUSE from inside `UdpTransport::new`.
    #[test]
    fn auto_assign_fails_fast_when_metatraffic_multicast_is_squatted() {
        let domain = crate::test_support::domains::unique_domain();
        let mapping = crate::transport::PortMapping::calculate(domain.id(), 0)
            .expect("pool domain has a port mapping");

        // A PLAIN bind: exactly what an ephemeral outbound connection or a
        // non-cooperative stack looks like on the wire. No SO_REUSEADDR, so
        // even the cooperative probe below must see it as busy.
        let squatter = UdpSocket::bind(("0.0.0.0", mapping.metatraffic_multicast))
            .expect("squat the metatraffic multicast port before build() gets to it");

        let result = Participant::builder("r31-metatraffic-multicast-squat")
            .domain_id(domain.id())
            .build();

        match result {
            Err(crate::dds::Error::IoError(e)) => {
                let message = e.to_string();
                assert!(
                    message.contains("METATRAFFIC MULTICAST"),
                    "error must name the socket role: {message}"
                );
                assert!(
                    message.contains(&mapping.metatraffic_multicast.to_string()),
                    "error must name the port: {message}"
                );
                assert!(
                    message.contains(&format!("domain {}", domain.id())),
                    "error must name the domain: {message}"
                );
                assert!(
                    message.contains("auto-assign"),
                    "error must come from the fast, pre-loop probe, not a later bind: {message}"
                );
            }
            Err(other) => panic!(
                "expected a diagnosable IoError from the auto-assign probe, got a different error variant: {other}"
            ),
            Ok(_) => panic!(
                "build() succeeded despite the squatted metatraffic multicast port"
            ),
        }
        drop(squatter);
    }

    /// Same as above for the DATA multicast port (the RTPS default user-data
    /// multicast port, PB + DG*domainId + d2 per DDSI-RTPS 2.5 9.6.2.2, i.e.
    /// `metatraffic_multicast + 1`). The
    /// squat is caught at auto-assign time, before the transport or discovery
    /// setup ever run, rather than deep inside
    /// `sockets.rs::create_data_multicast_socket`.
    #[test]
    fn auto_assign_fails_fast_when_data_multicast_is_squatted() {
        let domain = crate::test_support::domains::unique_domain();
        let mapping = crate::transport::PortMapping::calculate(domain.id(), 0)
            .expect("pool domain has a port mapping");
        let data_multicast_port =
            mapping.metatraffic_multicast + crate::config::DATA_MULTICAST_OFFSET;

        let squatter = UdpSocket::bind(("0.0.0.0", data_multicast_port))
            .expect("squat the data multicast port before build() gets to it");

        let result = Participant::builder("r31-data-multicast-squat")
            .domain_id(domain.id())
            .build();

        match result {
            Err(crate::dds::Error::IoError(e)) => {
                let message = e.to_string();
                assert!(
                    message.contains("DATA MULTICAST"),
                    "error must name the socket role: {message}"
                );
                assert!(
                    message.contains(&data_multicast_port.to_string()),
                    "error must name the port: {message}"
                );
                assert!(
                    message.contains(&format!("domain {}", domain.id())),
                    "error must name the domain: {message}"
                );
                assert!(
                    message.contains("auto-assign"),
                    "error must come from the fast, pre-loop probe, not a later bind: {message}"
                );
            }
            Err(other) => panic!(
                "expected a diagnosable IoError from the auto-assign probe, got a different error variant: {other}"
            ),
            Ok(_) => panic!(
                "build() succeeded despite the squatted data multicast port"
            ),
        }
        drop(squatter);
    }

    /// Control: the multicast pre-check must not disturb the
    /// unicast retry it sits in front of. With both multicast ports free but
    /// participant id 0's metatraffic_unicast port busy, auto-assign must
    /// still walk past it and build successfully on a later id.
    #[test]
    fn auto_assign_still_skips_a_busy_unicast_port_with_multicast_free() {
        let domain = crate::test_support::domains::unique_domain();
        let pid0 = crate::transport::PortMapping::calculate(domain.id(), 0)
            .expect("pool domain has a port mapping");

        let busy_unicast = UdpSocket::bind(("0.0.0.0", pid0.metatraffic_unicast))
            .expect("occupy participant id 0's metatraffic unicast port");

        let participant = Participant::builder("r31-unicast-still-retries")
            .domain_id(domain.id())
            .build()
            .expect("auto-assign must still walk past the busy unicast port");

        assert_ne!(
            participant.participant_id(),
            0,
            "participant id 0's unicast port was busy; auto-assign must have picked another id"
        );
        assert_eq!(participant.domain_id(), domain.id());

        drop(participant);
        drop(busy_unicast);
    }

    /// Cost of the probe: two extra bind+setsockopt+drop cycles per
    /// build() on the auto-assign path only (custom ports, an explicit
    /// participant_id and HDDS_PARTICIPANT_ID all skip it entirely).
    /// Measured, not guessed, rather than an intuition about "a syscall is
    /// cheap". The bound is generous on
    /// purpose: this asserts against a slowdown of orders of magnitude
    /// (e.g. a probe that starts blocking), not against normal machine
    /// noise.
    #[test]
    fn probe_multicast_port_cost_is_measured() {
        let domain = crate::test_support::domains::unique_domain();
        let mapping = crate::transport::PortMapping::calculate(domain.id(), 0)
            .expect("pool domain has a port mapping");
        const REPS: u32 = 2000;
        let start = std::time::Instant::now();
        for _ in 0..REPS {
            match probe_multicast_port(mapping.metatraffic_multicast) {
                MulticastPortProbe::Reserved(sock) => drop(sock),
                MulticastPortProbe::Busy(e) => panic!("port unexpectedly busy: {e}"),
                MulticastPortProbe::Inconclusive => {
                    panic!("SO_REUSEADDR unexpectedly refused on this host")
                }
            }
        }
        let elapsed = start.elapsed();
        let per_probe = elapsed / REPS;
        eprintln!(
            "[cost] {REPS} probes (socket+setsockopt+bind+drop) in {elapsed:?} -> {per_probe:?}/probe, \
             x2 probes per auto-assigned build()"
        );
        assert!(
            per_probe < std::time::Duration::from_millis(5),
            "a single multicast probe took {per_probe:?}, which is orders of magnitude above \
             a bind+setsockopt+drop; something regressed"
        );
    }
}
