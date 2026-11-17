// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Participant-owned Discovery Server lifecycle.

use super::relay_channel::{RelayChannel, MAX_RELAY_FRAME_BYTES};
use crate::core::discovery::multicast::fsm::has_direct_route;
use crate::core::discovery::multicast::PacketDispatch;
use crate::core::discovery::{usable_unicast_locator, PeerOrigin, SpdpPeerSet};
use crate::discovery_server::{
    ClientError, ClientEvent, DiscoveryServerClient, DiscoveryServerConfig,
};
use crate::transport::relay::{RelayEgress, RelaySink, RelayStats};
use crate::transport::relay_locator::RelayLocators;
use crate::transport::UdpTransport;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// How long a session sleeps when nothing is happening.
///
/// It is a ceiling, not a period: the socket wakes the thread when the
/// server speaks, and a [`crate::discovery_server::SessionWaker`] wakes it
/// when another thread hands it something to send. What is left is the
/// heartbeat clock and the shutdown flag, neither of which needs finer
/// resolution than this.
const IO_POLL_INTERVAL: Duration = Duration::from_millis(100);
const DROP_JOIN_TIMEOUT: Duration = Duration::from_millis(500);

/// Events one session turn dispatches before it goes back to the socket.
///
/// A fairness cap. Without it a server that keeps talking - which a relay
/// under load does - starves the outbox and the shutdown check, both of
/// which live on this same thread. Breaking out on the cap means the socket
/// was NOT drained to `WouldBlock`, so the readiness registration has to be
/// restored by hand: see `DiscoveryServerClient::rearm`.
const MAX_EVENTS_PER_TURN: usize = 64;

pub(in crate::dds::participant) struct DiscoveryServerRuntime {
    shutdown: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl DiscoveryServerRuntime {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn spawn(
        config: DiscoveryServerConfig,
        guid_prefix: [u8; 12],
        domain_id: u32,
        participant_name: String,
        builtin_endpoints: u32,
        transport: &UdpTransport,
        peer_set: Arc<SpdpPeerSet>,
        relay_ingress: Arc<PacketDispatch>,
    ) -> crate::dds::Result<Self> {
        let shutdown = Arc::new(AtomicBool::new(false));
        let thread_shutdown = Arc::clone(&shutdown);

        // Built here, not in the thread: the transport's send path needs this
        // client's waker before any DDS writer can reach a relayed peer, and
        // the client owns the readiness registry that waker belongs to.
        let client = DiscoveryServerClient::new(config.clone(), guid_prefix).map_err(|error| {
            crate::dds::Error::Config(format!(
                "invalid Discovery Server client configuration: {error}"
            ))
        })?;

        let relay = RelayState {
            locators: Arc::new(RelayLocators::new()),
            channel: Arc::new(RelayChannel::new(client.waker())),
            stats: Arc::new(RelayStats::default()),
            ingress: relay_ingress,
            enabled: config.relay,
        };

        // Installing the diversion is free and changes nothing by itself:
        // only a destination inside the reserved range is diverted, and
        // nothing produces one until this runtime hands a peer such an
        // address. What turns the relay on is the assignment, not this.
        let egress = RelayEgress::new(
            Arc::clone(&relay.locators),
            Arc::clone(&relay.channel) as Arc<dyn RelaySink>,
            Arc::clone(&relay.stats),
        );
        if transport.install_relay(egress).is_err() {
            return Err(crate::dds::Error::Config(
                "a Discovery Server relay is already installed on this transport".to_string(),
            ));
        }
        // Snapshot what the client thread needs from the transport so the
        // thread never owns the UDP sockets: a pending connect that outlives
        // `stop()` (see DROP_JOIN_TIMEOUT) must not keep the participant's
        // ports alive after the participant is gone.
        let announcement = Announcement {
            identity: LocalIdentity {
                guid_prefix,
                domain_id,
                metatraffic_port: transport.metatraffic_unicast_port(),
            },
            name: participant_name,
            builtin_endpoints,
            unicast: transport.get_unicast_locators(),
        };

        let handle = thread::Builder::new()
            .name("hdds-discovery-server".into())
            .spawn(crate::core::rt::shutdown::owned(move || {
                run_client_loop(
                    client,
                    config,
                    announcement,
                    peer_set,
                    relay,
                    thread_shutdown,
                );
            }))
            // Thread creation is a real runtime failure (RLIMIT_NPROC, memory
            // pressure), not an invariant: `expect()` here turned a resource
            // limit on the host into a panic inside `Participant::build()`,
            // which an application has no way to catch. Report it instead and
            // let the caller decide.
            .map_err(|e| {
                crate::dds::Error::Config(format!(
                    "failed to spawn the Discovery Server client thread: {e}"
                ))
            })?;

        Ok(Self {
            shutdown,
            handle: Some(handle),
        })
    }

    pub(in crate::dds::participant) fn stop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        let Some(handle) = self.handle.take() else {
            return;
        };

        let deadline = Instant::now() + DROP_JOIN_TIMEOUT;
        while !handle.is_finished() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }

        if handle.is_finished() {
            let _ = handle.join();
        } else {
            log::warn!(
                "[discovery-server] Client thread did not stop within {:?}; detaching pending connect",
                DROP_JOIN_TIMEOUT
            );
        }
    }
}

impl Drop for DiscoveryServerRuntime {
    fn drop(&mut self) {
        self.stop();
    }
}

/// The participant's own metatraffic locators, captured once at spawn.
///
/// `unicast` is the transport's advertised set, already filtered by the
/// interface allowlist (`TransportOptions::interface_allowlist` /
/// `HDDS_INTERFACE_ALLOW`), so the server can only be told addresses SPDP
/// itself would advertise.
struct Announcement {
    /// Who we are, as every decision in a session needs to know it.
    identity: LocalIdentity,
    name: String,
    builtin_endpoints: u32,
    unicast: Vec<SocketAddr>,
}

/// What this participant is, from the point of view of one session.
///
/// Grouped rather than passed as three scalars because every one of them
/// answers the same question - "is this event about us, and where should the
/// answer go?" - and carrying them apart is how a call ends up with eight
/// arguments and nobody able to say which is which.
#[derive(Clone, Copy)]
struct LocalIdentity {
    guid_prefix: [u8; 12],
    domain_id: u32,
    /// The port a synthetic locator carries when a peer announced none.
    ///
    /// Not used for routing: the relay addresses a peer by GUID prefix. It is
    /// here because a locator has a port and inventing one would put a number
    /// on the wire that means nothing.
    metatraffic_port: u16,
}

/// Everything the session thread needs to run the relay.
struct RelayState {
    /// Synthetic addresses, shared with the transport's send path.
    locators: Arc<RelayLocators>,
    /// Datagrams the transport diverted, waiting to be forwarded.
    channel: Arc<RelayChannel>,
    /// What the transport's side could not deliver.
    stats: Arc<RelayStats>,
    /// Where a datagram the server carried is handed in.
    ///
    /// The participant's own receive path, shared with every UDP listener:
    /// same ring, same pool, same discovery callback, same control channel.
    /// A relayed datagram is therefore classified and routed exactly like one
    /// off the wire, which is what makes a relayed peer discoverable at all.
    ingress: Arc<PacketDispatch>,
    /// Whether this participant may hand a peer a synthetic address.
    ///
    /// The plumbing is installed either way; this is what decides that a
    /// peer with no direct route goes through the server rather than being
    /// given an address that cannot carry a datagram.
    enabled: bool,
}

fn run_client_loop(
    mut client: DiscoveryServerClient,
    config: DiscoveryServerConfig,
    announcement: Announcement,
    peer_set: Arc<SpdpPeerSet>,
    relay: RelayState,
    shutdown: Arc<AtomicBool>,
) {
    let mut failed_attempts = 0u32;

    loop {
        if shutdown.load(Ordering::Acquire) {
            break;
        }

        if let Err(error) = client.connect() {
            failed_attempts = failed_attempts.saturating_add(1);
            log::warn!(
                "[discovery-server] Connect to {} failed: {}",
                config.server_address,
                error
            );
            if should_stop_retrying(&config, failed_attempts)
                || !sleep_interruptible(config.reconnect_delay, shutdown.as_ref())
            {
                break;
            }
            continue;
        }

        if shutdown.load(Ordering::Acquire) {
            break;
        }

        let locators = advertised_locators(&client, &announcement);
        if locators.is_empty() {
            log::error!("[discovery-server] No routable IPv4 metatraffic locator is available");
            break;
        }

        peer_set.clear(PeerOrigin::Server);
        if let Err(error) = client.announce_participant(
            announcement.identity.domain_id,
            Some(announcement.name.clone()),
            locators,
            announcement.builtin_endpoints,
        ) {
            failed_attempts = failed_attempts.saturating_add(1);
            log::warn!("[discovery-server] Participant announce failed: {}", error);
            if should_stop_retrying(&config, failed_attempts)
                || !sleep_interruptible(config.reconnect_delay, shutdown.as_ref())
            {
                break;
            }
            continue;
        }

        let outcome = run_connected_session(
            &mut client,
            announcement.identity,
            peer_set.as_ref(),
            &relay,
            shutdown.as_ref(),
            &mut failed_attempts,
        );
        report_relay_losses(&relay);

        if shutdown.load(Ordering::Acquire) {
            let _ = client.leave();
            break;
        }
        client.disconnect();

        if matches!(outcome, SessionOutcome::PermanentError)
            || should_stop_retrying(&config, failed_attempts)
            || !sleep_interruptible(config.reconnect_delay, shutdown.as_ref())
        {
            break;
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SessionOutcome {
    Disconnected,
    PermanentError,
}

fn run_connected_session(
    client: &mut DiscoveryServerClient,
    identity: LocalIdentity,
    peer_set: &SpdpPeerSet,
    relay: &RelayState,
    shutdown: &AtomicBool,
    failed_attempts: &mut u32,
) -> SessionOutcome {
    // Relayed datagrams dropped for want of a receive path. See the arm in
    // `dispatch_event`; this exists so the drop has a volume, not just a
    // first occurrence.
    let mut relayed_dropped: u64 = 0;

    loop {
        if shutdown.load(Ordering::Acquire) {
            return SessionOutcome::Disconnected;
        }

        if client.heartbeat_due() && client.send_heartbeat().is_err() {
            *failed_attempts = failed_attempts.saturating_add(1);
            return SessionOutcome::Disconnected;
        }

        // Drain what the server has to say. `read_message` promises that
        // `Ok(None)` means the socket is empty, and mio's edge-triggered
        // readiness means only a caller that reaches it may go back to sleep.
        let mut drained = false;
        for _ in 0..MAX_EVENTS_PER_TURN {
            match client.read_message() {
                Ok(Some(event)) => {
                    if let Dispatch::End(outcome) = dispatch_event(
                        event,
                        identity,
                        peer_set,
                        relay,
                        failed_attempts,
                        &mut relayed_dropped,
                    ) {
                        return outcome;
                    }
                }
                Ok(None) => {
                    drained = true;
                    break;
                }
                Err(error) => {
                    log::warn!("[discovery-server] Read failed: {}", error);
                    *failed_attempts = failed_attempts.saturating_add(1);
                    return SessionOutcome::Disconnected;
                }
            }
        }

        if !client.is_connected() {
            *failed_attempts = failed_attempts.saturating_add(1);
            return SessionOutcome::Disconnected;
        }

        if !drained {
            // Left the drain loop on the fairness cap, so the socket never
            // returned `WouldBlock` and mio has not restored its interests.
            if let Err(error) = client.rearm() {
                log::warn!("[discovery-server] Could not re-arm the session: {}", error);
                *failed_attempts = failed_attempts.saturating_add(1);
                return SessionOutcome::Disconnected;
            }
        }

        // Take what the transport diverted, then push. In that order, so a
        // datagram handed over while this turn was reading still leaves on
        // this turn rather than waiting for the next readiness event.
        if let Err(error) = pump_relay(client, &relay.channel) {
            log::warn!("[discovery-server] Relaying failed: {}", error);
            *failed_attempts = failed_attempts.saturating_add(1);
            return SessionOutcome::Disconnected;
        }

        // Push whatever is queued. This is also where a stalled outbox ends
        // the session, so it runs on every turn and not only after a send.
        if let Err(error) = client.flush() {
            log::warn!("[discovery-server] Write failed: {}", error);
            *failed_attempts = failed_attempts.saturating_add(1);
            return SessionOutcome::Disconnected;
        }

        if let Err(error) = client.wait_for_io(IO_POLL_INTERVAL) {
            log::warn!(
                "[discovery-server] Waiting on the session failed: {}",
                error
            );
            *failed_attempts = failed_attempts.saturating_add(1);
            return SessionOutcome::Disconnected;
        }
    }
}

/// Move what the transport diverted into the session's outbox.
///
/// Only takes a datagram when the outbox certainly has room for the frame it
/// becomes: popping one the outbox would then refuse drops it in the middle,
/// where nothing counts it and nothing can put it back. Leaving it on the
/// queue instead turns the same congestion into a refusal the SENDER sees,
/// which is the one place it can be counted honestly.
fn pump_relay(
    client: &mut DiscoveryServerClient,
    channel: &RelayChannel,
) -> Result<(), ClientError> {
    while client.outbox_room() >= MAX_RELAY_FRAME_BYTES {
        let Some(waiting) = channel.pop() else {
            return Ok(());
        };
        client.send_relay_data(waiting.peer, waiting.datagram)?;
    }

    Ok(())
}

/// Say what the relay carried and what it lost, in both directions.
///
/// The only place these numbers can be read. The send-side ones are produced
/// on DDS writer threads, which have no business logging in the middle of a
/// send; the receive-side ones are this session thread's own. Either way the
/// session thread is the one that knows a session just ended.
fn report_relay_losses(relay: &RelayState) {
    let unreachable_destination = relay.stats.unknown_destination();
    let queue_full = relay.channel.refused();
    let oversized = relay.channel.oversized();
    // (received, dropped, invalid, bytes, callback_errors)
    let (received, dropped, invalid, _bytes, _callback_errors) = relay.ingress.metrics().snapshot();

    if unreachable_destination == 0 && queue_full == 0 && oversized == 0 && received == 0 {
        return;
    }

    log::info!(
        "[discovery-server] relay totals since start: {} peers addressed through the server; \
         sent: {} datagrams lost to a full queue, {} addressed to no peer we relay to, {} too \
         large to carry; received: {} datagrams delivered to discovery, of which {} were not \
         RTPS and {} found no buffer",
        relay.locators.len(),
        queue_full,
        unreachable_destination,
        oversized,
        received,
        invalid,
        dropped
    );
}

/// Where this participant should send, for a peer the server just announced.
///
/// Normally the addresses the peer announced. When NOT ONE of them can be
/// reached from here - every one is on a private network that is not ours,
/// or on a range nothing routes - no datagram we send can arrive, and the
/// peer is given a synthetic address instead: the transport diverts anything
/// bound for it into the server's relay.
///
/// The port on a synthetic address is not used for routing - the relay
/// addresses a peer by GUID prefix - but a locator has one, so it is the
/// peer's own announced port rather than a number invented here.
fn destinations_for(
    relay: &RelayState,
    prefix: [u8; 12],
    announced: Vec<SocketAddr>,
    fallback_port: u16,
) -> Vec<SocketAddr> {
    let reachable = announced.iter().any(|one| has_direct_route(&[*one]));
    destinations_with(relay, prefix, announced, fallback_port, reachable)
}

/// [`destinations_for`] against an explicit verdict on reachability.
///
/// Split out so the POLICY can be tested without depending on the addresses
/// of the machine running the test - the same reason
/// `select_best_locator_among` exists next door. Whether a peer is reachable
/// is a fact about this host; what to do about it is not.
fn destinations_with(
    relay: &RelayState,
    prefix: [u8; 12],
    announced: Vec<SocketAddr>,
    fallback_port: u16,
    reachable: bool,
) -> Vec<SocketAddr> {
    if !relay.enabled || reachable {
        // Either this deployment has not asked for the relay, or the peer is
        // reachable and the announced set is what it has always been. The
        // release matters: a peer that comes back onto a network we can reach
        // must stop being addressed through the server, or it keeps a
        // synthetic address for as long as it lives.
        relay.locators.release(&prefix);
        return announced;
    }

    let port = announced.first().map_or(fallback_port, SocketAddr::port);
    let Some(address) = relay.locators.assign(prefix) else {
        log::warn!(
            "[discovery-server] the relay address range is exhausted; {:02x?} stays unreachable",
            prefix
        );
        return announced;
    };

    log::info!(
        "[discovery-server] {:02x?} announced nothing reachable from here ({} address(es)); \
         addressing it through the server at {}",
        prefix,
        announced.len(),
        address
    );
    vec![SocketAddr::new(IpAddr::V4(address), port)]
}

/// What one server event means for the session that received it.
enum Dispatch {
    /// Handled; keep the session running.
    Continue,
    /// The session is over, for this reason.
    End(SessionOutcome),
}

/// Hand a datagram the server carried to this participant's receive path.
///
/// It goes in through `PacketDispatch`, the same routing every UDP listener
/// uses, because a relayed peer's SPDP and SEDP arrive through this door and
/// through no other: classification, deduplication and the discovery callback
/// all have to run on it exactly as they would on a datagram off the wire.
///
/// # The address it arrives under
///
/// The sender's SYNTHETIC address, the very one this participant sends to
/// when it answers that peer. It has to be: metatraffic is answered at the
/// datagram's own reply address (`sedp_handler.rs`'s confirmation ACKNACK
/// prefers `Origin::reply()`, which for this door is always `Some` -- this
/// synthetic address is not behind an RTPS INFO_SRC, so it is never
/// relayed in the RTPS 2.5 8.3.8.10 sense the `Origin` type distinguishes),
/// so a relayed peer acknowledged at its real locator would be answered
/// over a route that does not exist - which is the reason it is relayed in
/// the first place.
///
/// The PORT on that address is a placeholder, and provably cannot select
/// anything: the transport diverts on the IP alone (`is_relay_address` takes
/// an `Ipv4Addr`) and the relay addresses a peer by GUID prefix, while SPDP
/// keeps only the reply address's IP and infers the port itself. It is this
/// participant's own metatraffic port, which is what the send path falls back
/// to in `destinations_for` when a peer announced nothing - one rule, stated
/// in both places.
///
/// # Why an unknown sender is refused rather than given an address here
///
/// Two reasons, both load-bearing:
///
/// - The prefix is read from bytes 8..20 of the datagram, a field the sending
///   client fills in and the server does not verify (it routes by
///   destination). Assigning on receipt would let datagrams carrying invented
///   prefixes drain a bounded address range - the range every genuinely
///   relayed peer needs to stay reachable.
/// - The mapping is created on the discovery path, in `destinations_for`,
///   which is the only place that knows whether a peer has a direct route.
///   A datagram from a peer we hold no mapping for is one we could not answer
///   anyway, and a peer discovered but unanswerable is worse than one not yet
///   discovered: it is a deaf zombie the rest of the fleet believes reachable.
///
/// The refusal is not a permanent loss. SPDP repeats, and the server announces
/// the peer over the same session, so a later copy lands once the mapping
/// exists. What is lost is one announcement, not the peer.
fn deliver_relayed(
    relay: &RelayState,
    identity: LocalIdentity,
    datagram: &[u8],
) -> Result<(), &'static str> {
    // RTPS Header: magic(4) + ProtocolVersion(2) + vendorId(2) + guidPrefix(12)
    // (DDS-RTPS v2.5 section 8.3.3.1). Below 20 bytes there is no sender to
    // attribute the datagram to, whatever else it might contain.
    const GUID_PREFIX_RANGE: std::ops::Range<usize> = 8..20;
    if datagram.len() < GUID_PREFIX_RANGE.end {
        return Err("it is shorter than an RTPS header");
    }

    if !relay.enabled {
        // Nothing is relayed FROM here, so no peer holds a synthetic address
        // and none can be answered. Said explicitly rather than reached as an
        // empty lookup, because the two are the same symptom with very
        // different causes.
        return Err("this participant does not relay");
    }

    let mut sender = [0u8; 12];
    sender.copy_from_slice(&datagram[GUID_PREFIX_RANGE]);

    let Some(address) = relay.locators.address_of(&sender) else {
        return Err("no relayed address is held for its sender");
    };

    relay.ingress.dispatch(
        datagram,
        SocketAddr::new(IpAddr::V4(address), identity.metatraffic_port),
    );
    Ok(())
}

/// Apply one event from the server to this participant's discovery state.
///
/// Split out of the session loop so that what an event DOES is separable
/// from when the loop gets to read it - the loop's own job is readiness and
/// fairness, and mixing the two is how a dispatch ends up with no test that
/// executes it.
fn dispatch_event(
    event: ClientEvent,
    identity: LocalIdentity,
    peer_set: &SpdpPeerSet,
    relay: &RelayState,
    failed_attempts: &mut u32,
    relayed_dropped: &mut u64,
) -> Dispatch {
    match event {
        ClientEvent::ParticipantAcknowledged => {
            *failed_attempts = 0;
        }
        ClientEvent::ParticipantDiscovered {
            guid_prefix,
            domain_id: remote_domain,
            unicast_locators,
            ..
        } if guid_prefix != identity.guid_prefix && remote_domain == identity.domain_id => {
            let announced: Vec<SocketAddr> = unicast_locators
                .into_iter()
                .filter(usable_unicast_locator)
                .collect();
            let destinations =
                destinations_for(relay, guid_prefix, announced, identity.metatraffic_port);
            peer_set.replace_server(guid_prefix, destinations);
        }
        ClientEvent::ParticipantLeft { guid_prefix } => {
            peer_set.remove_server(&guid_prefix);
            // The index is never handed out again, so this only forgets the
            // mapping: a datagram still in flight for the departed peer finds
            // no destination and is refused, rather than arriving at whoever
            // took its place.
            relay.locators.release(&guid_prefix);
        }
        ClientEvent::Error { code, message } => {
            log::error!(
                "[discovery-server] Server rejected client message (code {}): {}",
                code,
                message
            );
            *failed_attempts = failed_attempts.saturating_add(1);
            return Dispatch::End(if matches!(code, 1 | 3 | 4) {
                SessionOutcome::PermanentError
            } else {
                SessionOutcome::Disconnected
            });
        }
        ClientEvent::EndpointDiscovered { .. } => {
            // SEDP remains authoritative for endpoint QoS and matching.
        }
        ClientEvent::RelayDataReceived { payload } => {
            if let Err(reason) = deliver_relayed(relay, identity, &payload) {
                // Never silent: a dropped relayed datagram is indistinguishable
                // from network loss to whoever debugs it, and would send them
                // after the wrong thing entirely. Loud once, then by volume.
                *relayed_dropped = relayed_dropped.saturating_add(1);
                if *relayed_dropped == 1 {
                    log::warn!(
                        "[discovery-server] a relayed datagram of {} bytes was not delivered: \
                         {}. Further refusals are logged at debug level.",
                        payload.len(),
                        reason
                    );
                } else {
                    log::debug!(
                        "[discovery-server] refused {} relayed datagrams (last: {} bytes, {})",
                        relayed_dropped,
                        payload.len(),
                        reason
                    );
                }
            }
        }
        ClientEvent::Connected | ClientEvent::Disconnected { .. } => {}
        // A participant on another domain, or ourselves coming back to us.
        ClientEvent::ParticipantDiscovered { .. } => {}
    }

    Dispatch::Continue
}

/// Locators to register with the server.
///
/// On a multi-homed host the address the TCP session to the server was
/// routed from is the one most likely to be reachable by the other clients,
/// so it is preferred, but ONLY when it is one of the transport's advertised
/// (allowlist-filtered) locators: the server must never hand out an address
/// SPDP would not advertise. Otherwise the full advertised set is sent.
fn advertised_locators(
    client: &DiscoveryServerClient,
    announcement: &Announcement,
) -> Vec<SocketAddr> {
    let advertised: Vec<SocketAddr> = announcement
        .unicast
        .iter()
        .copied()
        .filter(usable_unicast_locator)
        .collect();
    let configured_interface = std::env::var_os("HDDS_INTERFACE").is_some()
        || std::env::var_os("HDDS_UNICAST_IF").is_some();
    if configured_interface {
        return advertised;
    }

    if let Some(SocketAddr::V4(local)) = client.local_addr() {
        let locator = SocketAddr::new(
            IpAddr::V4(*local.ip()),
            announcement.identity.metatraffic_port,
        );
        if advertised.contains(&locator) {
            return vec![locator];
        }
    }

    advertised
}

fn should_stop_retrying(config: &DiscoveryServerConfig, failed_attempts: u32) -> bool {
    !config.auto_reconnect
        || (config.max_reconnect_attempts != 0 && failed_attempts >= config.max_reconnect_attempts)
}

fn sleep_interruptible(duration: Duration, shutdown: &AtomicBool) -> bool {
    let deadline = std::time::Instant::now() + duration;
    while std::time::Instant::now() < deadline {
        if shutdown.load(Ordering::Acquire) {
            return false;
        }
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        thread::sleep(remaining.min(Duration::from_millis(50)));
    }
    !shutdown.load(Ordering::Acquire)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::discovery::multicast::PacketKind;

    fn idle_client() -> DiscoveryServerClient {
        DiscoveryServerClient::new(DiscoveryServerConfig::default(), [7; 12])
            .expect("client config")
    }

    /// The participant's receive plumbing, reduced to what a test can read:
    /// a dispatch over a real pool and ring, and a callback recording which
    /// discovery datagrams arrived and the address each arrived under.
    struct Ingress {
        dispatch: Arc<PacketDispatch>,
        seen: Arc<std::sync::Mutex<Vec<(PacketKind, crate::core::discovery::multicast::Origin)>>>,
    }

    impl Ingress {
        fn new() -> Self {
            use crate::core::discovery::multicast::{
                DiscoveryCallback, FragmentMetadata, ListenerMetrics, RxPool,
            };

            let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
            let recorder = Arc::clone(&seen);
            let callback: DiscoveryCallback = Arc::new(
                move |kind: PacketKind,
                      _packet: &[u8],
                      _offset: usize,
                      _fragment: Option<FragmentMetadata>,
                      source: crate::core::discovery::multicast::Origin| {
                    recorder
                        .lock()
                        .expect("the recorder mutex is never poisoned")
                        .push((kind, source));
                },
            );

            Self {
                dispatch: Arc::new(PacketDispatch::new(
                    Arc::new(RxPool::new(8, 1500).expect("an eight-buffer pool")),
                    Arc::new(crossbeam::queue::ArrayQueue::new(8)),
                    ListenerMetrics::new(),
                    Some(callback),
                    None,
                    None,
                    None,
                    None,
                )),
                seen,
            }
        }

        fn recorded(&self) -> Vec<(PacketKind, crate::core::discovery::multicast::Origin)> {
            self.seen
                .lock()
                .expect("the recorder mutex is never poisoned")
                .clone()
        }
    }

    fn relay_state(enabled: bool) -> RelayState {
        relay_state_receiving(enabled, &Ingress::new())
    }

    fn relay_state_receiving(enabled: bool, ingress: &Ingress) -> RelayState {
        let client = idle_client();
        RelayState {
            locators: Arc::new(RelayLocators::new()),
            channel: Arc::new(RelayChannel::new(client.waker())),
            stats: Arc::new(RelayStats::default()),
            ingress: Arc::clone(&ingress.dispatch),
            enabled,
        }
    }

    fn identity() -> LocalIdentity {
        LocalIdentity {
            guid_prefix: [7; 12],
            domain_id: 0,
            metatraffic_port: 7410,
        }
    }

    /// One SPDP announcement as its sender would have put it on the wire:
    /// Header per DDS-RTPS v2.5 s8.3.3, then a Data submessage addressed to
    /// the SPDP builtin reader. The sender's GUID prefix sits at bytes 8..20,
    /// which is where the receive path reads it from - so a test can state
    /// WHO sent it, which is the whole question on this path.
    fn spdp_from(sender: [u8; 12]) -> Vec<u8> {
        use crate::core::rtps_constants::{
            RTPS_ENTITYID_SPDP_READER, RTPS_ENTITYID_SPDP_WRITER, RTPS_VERSION_MAJOR,
            RTPS_VERSION_MINOR,
        };
        use crate::protocol::constants::HDDS_VENDOR_ID;

        let mut packet = Vec::with_capacity(48);
        packet.extend_from_slice(b"RTPS");
        packet.push(RTPS_VERSION_MAJOR);
        packet.push(RTPS_VERSION_MINOR);
        packet.extend_from_slice(&HDDS_VENDOR_ID);
        packet.extend_from_slice(&sender);
        // SubmessageHeader s8.3.3.3: DATA, E-flag set, then the 24 bytes below.
        packet.push(0x15);
        packet.push(0x01);
        packet.extend_from_slice(&24u16.to_le_bytes());
        // Data submessage s8.3.8.2.
        packet.extend_from_slice(&0u16.to_le_bytes()); // extraFlags
        packet.extend_from_slice(&16u16.to_le_bytes()); // octetsToInlineQos
        packet.extend_from_slice(&RTPS_ENTITYID_SPDP_READER);
        packet.extend_from_slice(&RTPS_ENTITYID_SPDP_WRITER);
        packet.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 1]); // writerSN = 1
        packet
    }

    fn sa(text: &str) -> SocketAddr {
        text.parse().expect("locator")
    }

    #[test]
    fn advertised_locators_stay_within_the_transport_set() {
        // A client that never connected has no local address: the advertised
        // set is the filtered transport set, IPv6 and unusable entries removed.
        let client = idle_client();
        let announcement = Announcement {
            identity: LocalIdentity {
                guid_prefix: [7; 12],
                domain_id: 0,
                metatraffic_port: 7410,
            },
            name: "test".to_string(),
            builtin_endpoints: 0,
            unicast: vec![
                sa("192.0.2.10:7410"),
                "[2001:db8::1]:7410".parse().unwrap(),
                sa("0.0.0.0:7410"),
            ],
        };
        assert_eq!(
            advertised_locators(&client, &announcement),
            vec![sa("192.0.2.10:7410")]
        );
    }

    #[test]
    fn a_reachable_peer_keeps_the_addresses_it_announced() {
        let relay = relay_state(true);
        let announced = vec![sa("192.168.1.50:7410"), sa("10.0.0.9:7410")];

        assert_eq!(
            destinations_with(&relay, [0xAA; 12], announced.clone(), 7410, true),
            announced,
            "a peer we can reach is addressed directly, relay or no relay"
        );
        assert_eq!(relay.locators.len(), 0, "and costs no synthetic address");
    }

    #[test]
    fn an_unreachable_peer_is_addressed_through_the_server() {
        let relay = relay_state(true);
        let peer = [0xBB; 12];

        let destinations = destinations_with(&relay, peer, vec![sa("10.4.4.4:7411")], 7410, false);

        assert_eq!(
            destinations.len(),
            1,
            "one address, and it is ours to route"
        );
        let SocketAddr::V4(only) = destinations[0] else {
            panic!("a synthetic locator is IPv4");
        };
        assert_eq!(
            relay.locators.peer_of(*only.ip()),
            Some(peer),
            "the address must resolve back to the peer it stands for"
        );
        assert_eq!(
            only.port(),
            7411,
            "the peer's own announced port, not a number invented here"
        );
        assert!(
            usable_unicast_locator(&destinations[0]),
            "what we push into the peer set has to survive the same filter as any locator"
        );
    }

    #[test]
    fn a_peer_that_announced_nothing_falls_back_to_our_own_port() {
        let relay = relay_state(true);

        let destinations = destinations_with(&relay, [0xCC; 12], Vec::new(), 7410, false);

        assert_eq!(destinations.len(), 1);
        assert_eq!(
            destinations[0].port(),
            7410,
            "there was no peer port to use"
        );
    }

    #[test]
    fn the_relay_stays_out_of_the_way_until_it_is_asked_for() {
        // The default deployment. An unreachable peer keeps exactly the
        // addresses it announced, because ROUTED private networks are real
        // and relaying them would break a LAN that works today.
        let relay = relay_state(false);
        let announced = vec![sa("10.4.4.4:7410")];

        assert_eq!(
            destinations_with(&relay, [0xDD; 12], announced.clone(), 7410, false),
            announced
        );
        assert_eq!(relay.locators.len(), 0, "nothing was assigned");
    }

    #[test]
    fn a_peer_that_becomes_reachable_again_gives_its_address_back() {
        let relay = relay_state(true);
        let peer = [0xEE; 12];

        destinations_with(&relay, peer, vec![sa("10.4.4.4:7410")], 7410, false);
        assert_eq!(relay.locators.len(), 1, "it was unreachable");

        // The same peer re-announces from a network we can reach - a laptop
        // coming back to the office. It must stop being relayed, or it keeps
        // a synthetic address for as long as it lives.
        let back = vec![sa("192.168.1.50:7410")];
        assert_eq!(
            destinations_with(&relay, peer, back.clone(), 7410, true),
            back
        );
        assert_eq!(
            relay.locators.len(),
            0,
            "the address went back to the table"
        );
    }

    #[test]
    fn reconnect_limit_zero_means_unbounded() {
        let config = DiscoveryServerConfig {
            max_reconnect_attempts: 0,
            ..DiscoveryServerConfig::default()
        };
        assert!(!should_stop_retrying(&config, u32::MAX));
    }

    /// The symmetry the relay rests on, asserted across both sides rather
    /// than stated in a comment: the address this participant SENDS to for a
    /// peer is the address that peer's datagrams ARRIVE under. The mapping is
    /// created here the only way production creates it - by addressing the
    /// peer - so the two halves cannot drift apart without this failing.
    #[test]
    fn a_relayed_datagram_arrives_under_the_address_its_sender_is_answered_at() {
        let ingress = Ingress::new();
        let relay = relay_state_receiving(true, &ingress);
        let sender = [0xBB; 12];

        let destinations =
            destinations_with(&relay, sender, vec![sa("10.4.4.4:7411")], 7410, false);
        let [SocketAddr::V4(answered_at)] = destinations[..] else {
            panic!("an unreachable peer is addressed through the server, at one address");
        };

        deliver_relayed(&relay, identity(), &spdp_from(sender))
            .expect("a mapped sender's datagram is delivered");

        let recorded = ingress.recorded();
        assert_eq!(recorded.len(), 1, "SPDP reaches the discovery callback");
        assert_eq!(recorded[0].0, PacketKind::SPDP);
        assert_eq!(
            recorded[0].1.from().ip(),
            IpAddr::V4(*answered_at.ip()),
            "it arrives under the very address we send that peer"
        );
    }

    /// A sender we hold no relayed address for is refused, and nothing
    /// reaches discovery. Delivering it would announce a peer this
    /// participant has no way to answer - a deaf zombie the rest of the fleet
    /// believes reachable - and assigning an address on the way in would let
    /// a field the sender controls drain a bounded range.
    #[test]
    fn a_relayed_datagram_from_a_sender_we_cannot_answer_is_refused() {
        let ingress = Ingress::new();
        let relay = relay_state_receiving(true, &ingress);

        let refusal = deliver_relayed(&relay, identity(), &spdp_from([0xCC; 12]))
            .expect_err("no address is held for this sender");
        assert!(
            refusal.contains("sender"),
            "the reason names what is missing"
        );

        assert!(ingress.recorded().is_empty(), "and discovery sees nothing");
        assert_eq!(
            relay.locators.len(),
            0,
            "a datagram must never be what hands out an address"
        );
    }

    /// With the relay off no peer ever holds a synthetic address, so nothing
    /// relayed to us can be answered. Refused by its own name rather than as
    /// an empty lookup: same symptom, very different cause.
    #[test]
    fn a_relayed_datagram_is_refused_when_this_participant_does_not_relay() {
        let ingress = Ingress::new();
        let relay = relay_state_receiving(false, &ingress);

        let refusal = deliver_relayed(&relay, identity(), &spdp_from([0xDD; 12]))
            .expect_err("a participant that does not relay cannot answer a relayed peer");
        assert!(refusal.contains("does not relay"));
        assert!(ingress.recorded().is_empty());
    }

    /// Below a full RTPS Header there is no sender to attribute the datagram
    /// to, so it is refused before bytes 8..20 are read at all. The bound is
    /// on the read, not on what the classifier would later make of it.
    #[test]
    fn a_relayed_datagram_shorter_than_an_rtps_header_is_refused() {
        let ingress = Ingress::new();
        let relay = relay_state_receiving(true, &ingress);
        let sender = [0xBB; 12];
        destinations_with(&relay, sender, vec![sa("10.4.4.4:7411")], 7410, false);

        let mut truncated = spdp_from(sender);
        truncated.truncate(19);

        let refusal = deliver_relayed(&relay, identity(), &truncated)
            .expect_err("19 bytes cannot carry a GUID prefix that ends at 20");
        assert!(refusal.contains("RTPS header"));
        assert!(ingress.recorded().is_empty());
    }
}
