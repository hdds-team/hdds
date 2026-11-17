// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Unicast routing thread for TCP and QUIC transports.
//!
//! Polls TCP and QUIC transports for incoming RTPS messages and routes them
//! through `route_raw_rtps_message()` to the `TopicRegistry`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crate::core::discovery::fragment_buffer::{FragmentBuffer, KnownSources};
use crate::core::discovery::multicast::classifier::walk::{destined_to, Destined};
use crate::core::discovery::multicast::control::renew_liveliness_from_participant_message;
use crate::core::discovery::multicast::{for_each_data_submessage, PacketKind};
use crate::dds::liveliness::Shared as LivelinessShared;
use crate::engine::{
    route_raw_rtps_message_from_stream, RouterMetrics, StreamReply, TopicRegistry,
    UnicastRouteOutcome,
};
use crate::protocol::rtps::participant_message::decode_participant_message_data;
use crate::transport::tcp::{TcpTransport, TcpTransportEvent};

#[cfg(feature = "quic")]
use crate::transport::quic::{QuicEvent, QuicIoThreadHandle};

const TCP_POLL_TIMEOUT: Duration = Duration::from_millis(50);
const NO_TRANSPORT_SLEEP: Duration = Duration::from_millis(50);
const FRAG_MAX_PENDING: usize = 64;
const FRAG_TIMEOUT_MS: u64 = 5000;

/// Unicast routing thread handle.
///
/// Automatically shuts down and joins the thread on Drop.
pub(in crate::dds::participant) struct UnicastRoutingThread {
    shutdown: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl Drop for UnicastRoutingThread {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            crate::core::rt::shutdown::join_bounded(handle, "unicast routing");
        }
    }
}

/// The TCP connection to the participant whose GUID prefix is `peer`: the
/// transport keys its connections by that prefix (`TcpTransport::send`).
struct TcpConnection<'a> {
    tcp: &'a TcpTransport,
    peer: [u8; 12],
}

impl StreamReply for TcpConnection<'_> {
    fn send_reply(&self, message: &[u8]) -> std::io::Result<()> {
        self.tcp.send(&self.peer, message)
    }
}

/// The QUIC connection to `peer`.
#[cfg(feature = "quic")]
struct QuicConnection<'a> {
    handle: &'a QuicIoThreadHandle,
    peer: std::net::SocketAddr,
}

#[cfg(feature = "quic")]
impl StreamReply for QuicConnection<'_> {
    fn send_reply(&self, message: &[u8]) -> std::io::Result<()> {
        self.handle
            .send(self.peer, message.to_vec())
            .map_err(std::io::Error::other)
    }
}

/// The RTPS header's GuidPrefix (bytes 8..20): the sender's identity,
/// independent of whatever submessage follows. TCP already carries it
/// separately (the transport keys its connections by it); QUIC's event
/// does not, so this reads it from the datagram itself, exactly as the
/// UDP multicast listener does.
#[cfg(feature = "quic")]
fn source_prefix(payload: &[u8]) -> Option<[u8; 12]> {
    if payload.len() < 20 {
        return None;
    }
    let mut prefix = [0u8; 12];
    prefix.copy_from_slice(&payload[8..20]);
    Some(prefix)
}

/// Every receive door renews a sender's AUTOMATIC liveliness on any RTPS
/// traffic from it (`Shared::heard_from`, RTPS v2.5 Sec.8.4.13.5 -- the
/// rule Cyclone DDS and Fast DDS both apply, adopted here on receive, see
/// `dds::liveliness::scheduler`'s doc), the same as the UDP multicast
/// listener (`core::discovery::multicast::listener`). A
/// `ParticipantMessageData` of kind MANUAL naming itself additionally
/// renews the sender's MANUAL_BY_PARTICIPANT writers
/// (`renew_liveliness_from_participant_message`, shared with the UDP
/// discovery dispatch): AUTOMATIC needs nothing beyond `heard_from`
/// above.
///
/// `source` is this message's sender, trusted over whatever the payload's
/// own header claims: for TCP, the connection's own identity, fixed at
/// handshake (`TcpTransportEvent`'s `GuidPrefix`); for QUIC, which has no
/// such handshake identity, `source_prefix` read from the datagram --
/// the same byte range the self-naming check below reads. On TCP, an admitted
/// peer could otherwise send, on its own connection, a datagram whose
/// header and embedded ParticipantMessageData both name a DIFFERENT
/// participant: trusting the header there would renew that other
/// participant's MANUAL_BY_PARTICIPANT lease from a connection that is
/// not its own, masking a real LIVELINESS_LOST on it.
///
/// A ParticipantMessageData's payload is a CDR struct, not a
/// ParameterList (RTPS v2.5 Sec.9.6.3.1); `classify_rtps`'s own payload
/// offset is `None` for it (nothing consumes it), so, like the UDP
/// multicast listener, this walks the datagram's DATA submessages
/// directly (`for_each_data_submessage`) to find the one offset that
/// actually describes it.
fn renew_liveliness(payload: &[u8], source: [u8; 12], liveliness: &LivelinessShared) {
    liveliness.heard_from(&source);
    // The walk below is wasted work when nothing is tracked at all (the
    // same relaxed load `heard_from` and `manual_from` each gate on
    // separately): skip it rather than parsing a ParticipantMessage no
    // watch exists to renew.
    if !liveliness.has_tracked_remotes() {
        return;
    }
    let mut pm_offset = None;
    for_each_data_submessage(payload, |data| {
        if data.kind == PacketKind::ParticipantMessage && pm_offset.is_none() {
            pm_offset = Some(data.payload_offset);
        }
    });
    let Some(message) = pm_offset
        .and_then(|offset| payload.get(offset..))
        .and_then(decode_participant_message_data)
    else {
        return;
    };
    if source != message.participant_guid_prefix {
        return;
    }
    renew_liveliness_from_participant_message(&message, liveliness);
}

/// Route the part of a received message destined to the participant whose
/// GUID prefix is `ours`: a submessage behind an INFO_DST naming another
/// participant acts on none of our endpoints (RTPS 2.5 8.3.8.8). A
/// connection normally carries only what its peer sends us, but a bridge
/// or a relay forwards whole messages; the rule is the one every other
/// receive leg applies. Answers go back on `connection`.
fn route_destined(
    payload: &[u8],
    ours: &[u8; 12],
    registry: &TopicRegistry,
    metrics: &RouterMetrics,
    fragment_buffer: &Mutex<FragmentBuffer>,
    connection: &dyn StreamReply,
) -> Option<UnicastRouteOutcome> {
    match destined_to(payload, ours) {
        Destined::Whole => Some(route_raw_rtps_message_from_stream(
            payload,
            registry,
            metrics,
            Some(fragment_buffer),
            connection,
        )),
        Destined::Part(part) => Some(route_raw_rtps_message_from_stream(
            &part,
            registry,
            metrics,
            Some(fragment_buffer),
            connection,
        )),
        Destined::Nothing => None,
    }
}

/// The reassembly buffer of the user DATA_FRAGs a connection carries.
///
/// It ranks its sources like the UDP one (`known_sources`, the
/// participant's): a prefix discovery does not know shares the pool of the
/// sources not known, and a sample larger than that pool's share is refused
/// until discovery knows it. Built with none, a connection was the one door
/// where any prefix counted as known.
fn fragment_buffer(known_sources: Option<Arc<dyn KnownSources>>) -> FragmentBuffer {
    let buffer = FragmentBuffer::new(FRAG_MAX_PENDING, FRAG_TIMEOUT_MS);
    match known_sources {
        Some(sources) => buffer.with_known_sources(sources),
        None => buffer,
    }
}

/// Spawn the unicast routing thread.
///
/// The thread polls TCP and QUIC transports, routing received RTPS messages
/// through `route_raw_rtps_message()` to the `TopicRegistry`.
///
/// Auto-starts only when at least one of TCP or QUIC is configured.
#[allow(clippy::too_many_arguments)]
pub(super) fn spawn(
    tcp: Option<Arc<TcpTransport>>,
    #[cfg(feature = "quic")] quic_handle: Option<QuicIoThreadHandle>,
    registry: Arc<TopicRegistry>,
    metrics: Arc<RouterMetrics>,
    shutdown: Arc<AtomicBool>,
    local_prefix: [u8; 12],
    known_sources: Option<Arc<dyn KnownSources>>,
    liveliness: Arc<LivelinessShared>,
) -> UnicastRoutingThread {
    let shutdown_clone = Arc::clone(&shutdown);

    #[allow(clippy::expect_used)] // thread spawn failure is unrecoverable
    let handle = thread::Builder::new()
        .name("hdds-unicast-router".into())
        .spawn(crate::core::rt::shutdown::owned(move || {
            log::info!(
                "[hdds] Unicast routing thread started (TCP={}, QUIC={})",
                tcp.is_some(),
                {
                    #[cfg(feature = "quic")]
                    {
                        quic_handle.is_some()
                    }
                    #[cfg(not(feature = "quic"))]
                    {
                        false
                    }
                },
            );

            let frag_buf = Mutex::new(fragment_buffer(known_sources));

            while !shutdown_clone.load(Ordering::Relaxed) {
                let mut had_transport = false;

                // --- TCP ---
                if let Some(ref tcp) = tcp {
                    had_transport = true;
                    for event in tcp.poll_timeout(TCP_POLL_TIMEOUT) {
                        match event {
                            TcpTransportEvent::MessageReceived { payload, from } => {
                                renew_liveliness(&payload, from, &liveliness);
                                let outcome = route_destined(
                                    &payload,
                                    &local_prefix,
                                    &registry,
                                    &metrics,
                                    &frag_buf,
                                    &TcpConnection { tcp, peer: from },
                                );
                                log::trace!("[unicast-router] TCP from {:?}: {:?}", from, outcome);
                            }
                            TcpTransportEvent::Connected {
                                remote_guid,
                                remote_addr,
                            } => {
                                log::debug!(
                                    "[unicast-router] TCP peer connected: {} (GUID {:?})",
                                    remote_addr,
                                    remote_guid
                                );
                            }
                            TcpTransportEvent::Disconnected {
                                remote_guid,
                                reason,
                            } => {
                                log::debug!(
                                    "[unicast-router] TCP peer disconnected: GUID {:?} ({})",
                                    remote_guid,
                                    reason.as_deref().unwrap_or("unknown")
                                );
                            }
                            _ => {}
                        }
                    }
                }

                // --- QUIC ---
                #[cfg(feature = "quic")]
                {
                    if let Some(ref handle) = quic_handle {
                        had_transport = true;
                        for event in handle.poll() {
                            match event {
                                QuicEvent::MessageReceived {
                                    payload,
                                    remote_addr,
                                } => {
                                    // QUIC's event carries a socket address,
                                    // not the sender's GuidPrefix (unlike
                                    // TCP's, keyed by connection): read it
                                    // from the datagram instead.
                                    if let Some(source) = source_prefix(&payload) {
                                        renew_liveliness(&payload, source, &liveliness);
                                    }
                                    let outcome = route_destined(
                                        &payload,
                                        &local_prefix,
                                        &registry,
                                        &metrics,
                                        &frag_buf,
                                        &QuicConnection {
                                            handle,
                                            peer: remote_addr,
                                        },
                                    );
                                    log::trace!(
                                        "[unicast-router] QUIC from {}: {:?}",
                                        remote_addr,
                                        outcome
                                    );
                                }
                                QuicEvent::Connected { remote_addr } => {
                                    log::debug!(
                                        "[unicast-router] QUIC peer connected: {}",
                                        remote_addr
                                    );
                                }
                                QuicEvent::Disconnected {
                                    remote_addr,
                                    reason,
                                } => {
                                    log::debug!(
                                        "[unicast-router] QUIC peer disconnected: {} ({})",
                                        remote_addr,
                                        reason.as_deref().unwrap_or("unknown")
                                    );
                                }
                                _ => {}
                            }
                        }
                    }
                }

                // Avoid busy-loop if no transport is active
                if !had_transport {
                    thread::sleep(NO_TRANSPORT_SLEEP);
                }
            }

            log::info!("[hdds] Unicast routing thread stopped");
        }))
        .expect("failed to spawn unicast routing thread");

    UnicastRoutingThread {
        shutdown,
        handle: Some(handle),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A message forwarded over a connection is routed only for what is
    /// destined to this participant (RTPS 2.5 8.3.8.8).
    /// A connection that takes every answer and keeps none.
    struct Unread;
    impl StreamReply for Unread {
        fn send_reply(&self, _: &[u8]) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_connection_routes_only_what_is_destined_here() {
        let registry = TopicRegistry::new();
        let metrics = RouterMetrics::new();
        let frag_buf = Mutex::new(FragmentBuffer::new(FRAG_MAX_PENDING, FRAG_TIMEOUT_MS));
        let ours = [0x0B; 12];
        let data = crate::protocol::builder::build_data_packet("tcp_dest", 1, b"payload");
        let destined = |prefix: [u8; 12]| {
            let mut packet = data[..20].to_vec();
            packet.extend_from_slice(&[0x0e, 0x01, 0x0c, 0x00]);
            packet.extend_from_slice(&prefix);
            packet.extend_from_slice(&data[20..]);
            packet
        };

        assert_eq!(
            route_destined(
                &destined([0x0C; 12]),
                &ours,
                &registry,
                &metrics,
                &frag_buf,
                &Unread
            ),
            None,
            "destined to another participant: not routed"
        );
        assert!(
            route_destined(
                &destined(ours),
                &ours,
                &registry,
                &metrics,
                &frag_buf,
                &Unread
            )
            .is_some(),
            "destined here: routed"
        );
    }

    /// The buffer of a connection tells the participants discovery knows
    /// from the rest, like the UDP one: an 8 MiB sample from a prefix it
    /// does not know is over the share of the sources not known (4 MiB for
    /// 64 sequences and 256 MiB) and refused at its first fragment.
    #[test]
    fn a_connection_ranks_its_fragment_sources_like_udp() {
        use crate::core::discovery::multicast::FragmentGeometry;
        use crate::core::discovery::{DiscoveredParticipants, EndpointRegistry, GUID};
        let geometry = FragmentGeometry {
            fragment_size: 60_000,
            sample_size: 8 << 20,
        };
        let stranger = GUID::new([0x0D; 12], [0, 0, 1, 2]);
        let opened = |mut buffer: FragmentBuffer| {
            let _ = buffer.insert_fragment(stranger, 1, 1, geometry, vec![0; 60_000]);
            buffer.pending_count()
        };
        let discovered = DiscoveredParticipants::new([0x0B; 12], EndpointRegistry::new());
        assert_eq!(
            opened(fragment_buffer(Some(Arc::new(discovered)))),
            0,
            "a prefix discovery does not know is not known on a connection either"
        );
        assert_eq!(opened(fragment_buffer(None)), 1);
    }

    /// RTPS v2.5 Sec.8.4.13.5: every receive door renews AUTOMATIC on any
    /// traffic from the sender, TCP/QUIC included -- there is no transport
    /// exception. If only the UDP multicast listener called `heard_from`, a
    /// TCP/QUIC-only peer's AUTOMATIC writers would never be renewed and
    /// would expire however often they wrote.
    /// Mutant: removing the `liveliness.heard_from(&source)` call from
    /// `renew_liveliness` makes this fail (automatic's renewal never
    /// moves).
    #[test]
    fn renew_liveliness_renews_automatic_on_any_traffic() {
        use crate::dds::liveliness::{MonotonicClock, Shared};

        let shared = Shared::new(Arc::new(MonotonicClock::new()));
        let prefix = [0x30; 12];
        let (automatic, _manual) = shared.remote(prefix);
        let before = automatic.last();
        std::thread::sleep(Duration::from_millis(1));

        // Any well-formed RTPS datagram works; a minimal DATA-shaped one
        // (not a ParticipantMessage) proves the renewal does not depend on
        // what follows the header.
        let packet = crate::protocol::builder::build_data_packet("x", 1, b"y");
        renew_liveliness(&packet, prefix, &shared);

        assert!(
            automatic.last() > before,
            "AUTOMATIC renews on ANY traffic, not only a ParticipantMessage"
        );
    }

    /// RTPS v2.5 Sec.8.4.13.5: a self-named ParticipantMessage of kind
    /// MANUAL renews the sender's MANUAL_BY_PARTICIPANT writers over
    /// TCP/QUIC too, through the exact function the UDP discovery dispatch
    /// calls (`renew_liveliness_from_participant_message`). A kind
    /// AUTOMATIC message renews nothing beyond the ANY-traffic rule above
    /// -- `manual` must not move for it.
    /// Mutant: swapping `KIND_MANUAL` for `KIND_AUTOMATIC` in `renew_liveliness`'s
    /// dispatch (or deleting the call to the shared function) makes the
    /// first assertion below fail.
    #[test]
    fn renew_liveliness_renews_manual_only_for_a_participant_message_of_that_kind() {
        use crate::dds::liveliness::{MonotonicClock, Shared};
        use crate::protocol::rtps::participant_message::{
            build_participant_message, KIND_AUTOMATIC, KIND_MANUAL,
        };

        let shared = Shared::new(Arc::new(MonotonicClock::new()));
        let prefix = [0x31; 12];
        let dest = [0x32; 12];
        let (_automatic, manual) = shared.remote(prefix);

        let before_manual = manual.last();
        std::thread::sleep(Duration::from_millis(1));
        let manual_pm = build_participant_message(&prefix, &dest, 1, KIND_MANUAL, 1, (0, 0))
            .expect("a manual participant message");
        renew_liveliness(&manual_pm, prefix, &shared);
        assert!(
            manual.last() > before_manual,
            "a self-named kind MANUAL ParticipantMessage renews MANUAL_BY_PARTICIPANT"
        );

        let before_manual = manual.last();
        std::thread::sleep(Duration::from_millis(1));
        let automatic_pm = build_participant_message(&prefix, &dest, 2, KIND_AUTOMATIC, 2, (0, 0))
            .expect("an automatic participant message");
        renew_liveliness(&automatic_pm, prefix, &shared);
        assert_eq!(
            manual.last(),
            before_manual,
            "a kind AUTOMATIC ParticipantMessage renews nothing beyond heard_from"
        );
    }

    /// RTPS v2.5 Sec.8.4.13.5's self-naming check must trust the
    /// TRANSPORT's own identity, never the payload's own header: an
    /// admitted peer A could otherwise send, on its OWN connection, a
    /// datagram whose RTPS header AND embedded ParticipantMessageData
    /// both claim a DIFFERENT participant B. Comparing against the
    /// payload's header would renew B's
    /// MANUAL_BY_PARTICIPANT lease from a connection that is not B's,
    /// masking a real LIVELINESS_LOST on B. `source` here stands in for
    /// what the TCP transport actually attests (fixed at handshake, never
    /// read from the forged payload) -- the scenario `renew_liveliness`'s
    /// own doc names.
    /// Mutant: comparing `payload[8..20]` instead of `source` (i.e.
    /// the header-based check) makes this fail (manual_b would move).
    #[test]
    fn renew_liveliness_refuses_a_participant_message_naming_another_connections_identity() {
        use crate::dds::liveliness::{MonotonicClock, Shared};
        use crate::protocol::rtps::participant_message::{build_participant_message, KIND_MANUAL};

        let shared = Shared::new(Arc::new(MonotonicClock::new()));
        let a = [0x40; 12]; // A's real, transport-attested identity.
        let b = [0x41; 12]; // The identity forged into the header and the PM.
        let dest = [0x42; 12];
        let (_automatic_b, manual_b) = shared.remote(b);

        let before = manual_b.last();
        std::thread::sleep(Duration::from_millis(1));
        // Built exactly as B would build its own assertion (header and PM
        // both self-consistent, both naming B); delivered as if it had
        // arrived on A's connection.
        let forged = build_participant_message(&b, &dest, 1, KIND_MANUAL, 1, (0, 0))
            .expect("a manual participant message");
        renew_liveliness(&forged, a, &shared);

        assert_eq!(
            manual_b.last(),
            before,
            "A's connection must not renew B's MANUAL_BY_PARTICIPANT lease"
        );
    }

    /// `renew_liveliness` walks the datagram's DATA submessages before
    /// looking for anything to renew: wasted work, cheap to skip, when no
    /// remote participant is tracked at all -- the same guard
    /// `heard_from`/`manual_from` apply on their own, one level in.
    /// Mutant: deleting the `has_tracked_remotes` check makes this an
    /// infinite loop impossible to tell from a passing test by its
    /// result alone, so this instead pins the OBSERVABLE contract (the
    /// walk never finds what isn't there to find) that the guard is a
    /// pure optimization over, not a behaviour change: nothing renews
    /// either way when nothing is tracked.
    #[test]
    fn renew_liveliness_does_nothing_when_nothing_is_tracked() {
        use crate::dds::liveliness::{MonotonicClock, Shared};
        use crate::protocol::rtps::participant_message::{build_participant_message, KIND_MANUAL};

        let shared = Shared::new(Arc::new(MonotonicClock::new()));
        assert!(!shared.has_tracked_remotes());
        let prefix = [0x43; 12];
        let dest = [0x44; 12];
        let packet = build_participant_message(&prefix, &dest, 1, KIND_MANUAL, 1, (0, 0))
            .expect("a manual participant message");
        // Must not panic, and must track nothing: there is nothing to
        // renew, and the early-out must not have been skipped as if
        // something were.
        renew_liveliness(&packet, prefix, &shared);
        assert!(!shared.has_tracked_remotes());
    }

    /// The real TCP routing loop (`spawn`), driven by a real socket:
    /// deleting its call to `renew_liveliness` at the top of the TCP
    /// `MessageReceived` arm leaves every other test in this file green
    /// -- nothing else exercises that call site. A raw client's very
    /// first message both establishes the connection's GuidPrefix (the
    /// TCP transport's own `extract_guid_prefix_from_rtps`) and renews
    /// it.
    /// Mutant: deleting `renew_liveliness(&payload, from, &liveliness);`
    /// from `spawn`'s TCP arm makes this fail (automatic's renewal never
    /// moves).
    #[test]
    fn the_real_tcp_routing_loop_renews_a_watched_peer() {
        use crate::dds::liveliness::{MonotonicClock, Shared};
        use crate::transport::tcp::transport::TcpTransportBuilder;
        use crate::transport::tcp::TcpRole;
        use std::time::Instant;

        let liveliness = Shared::new(Arc::new(MonotonicClock::new()));
        let peer = [0x60; 12];
        let (automatic, _manual) = liveliness.remote(peer);
        let before = automatic.last();

        let local_prefix = [0x61; 12];
        let tcp = Arc::new(
            TcpTransportBuilder::new()
                .local_guid(local_prefix)
                .port(0)
                .role(TcpRole::ServerOnly)
                .build()
                .expect("tcp transport"),
        );
        let mut addr = tcp.local_addr().expect("listening");
        if addr.ip().is_unspecified() {
            addr.set_ip(std::net::Ipv4Addr::LOCALHOST.into());
        }

        let registry = Arc::new(TopicRegistry::new());
        let metrics = Arc::new(RouterMetrics::new());
        let shutdown = Arc::new(AtomicBool::new(false));
        let _thread = spawn(
            Some(Arc::clone(&tcp)),
            #[cfg(feature = "quic")]
            None,
            Arc::clone(&registry),
            Arc::clone(&metrics),
            Arc::clone(&shutdown),
            local_prefix,
            None,
            Arc::clone(&liveliness),
        );

        let mut stream = std::net::TcpStream::connect(addr).expect("connect");
        stream.set_write_timeout(Some(Duration::from_secs(2))).ok();

        // A minimal, valid 20-byte RTPS header naming `peer`: enough for
        // the transport to associate this connection with it, and for
        // `renew_liveliness` to renew it.
        let mut packet = b"RTPS".to_vec();
        packet.extend_from_slice(&[0x02, 0x03, 0x01, 0x0F]);
        packet.extend_from_slice(&peer);
        let mut frame = (packet.len() as u32).to_be_bytes().to_vec();
        frame.extend_from_slice(&packet);
        use std::io::Write;
        stream.write_all(&frame).expect("send");
        stream.flush().ok();

        let deadline = Instant::now() + Duration::from_secs(10);
        while automatic.last() == before {
            assert!(Instant::now() < deadline, "the renewal never arrived");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// The same, over the real QUIC routing loop: deleting
    /// `renew_liveliness`'s call site in `spawn`'s QUIC arm leaves every
    /// other test in this file green too.
    /// Mutant: deleting the call to `renew_liveliness` from `spawn`'s
    /// QUIC arm makes this fail the same way.
    #[cfg(feature = "quic")]
    #[test]
    fn the_real_quic_routing_loop_renews_a_watched_peer() {
        use crate::dds::liveliness::{MonotonicClock, Shared};
        use crate::transport::quic::{QuicConfig, QuicEvent, QuicIoThread};
        use std::time::Instant;

        let liveliness = Shared::new(Arc::new(MonotonicClock::new()));
        let peer = [0x62; 12];
        let (automatic, _manual) = liveliness.remote(peer);
        let before = automatic.last();

        let server_addr = std::net::UdpSocket::bind("127.0.0.1:0")
            .and_then(|socket| socket.local_addr())
            .expect("a free UDP port");
        let server = QuicIoThread::spawn(QuicConfig {
            bind_addr: server_addr,
            ..QuicConfig::default()
        });

        let local_prefix = [0x63; 12];
        let registry = Arc::new(TopicRegistry::new());
        let metrics = Arc::new(RouterMetrics::new());
        let shutdown = Arc::new(AtomicBool::new(false));
        let _thread = spawn(
            None,
            Some(server.handle()),
            Arc::clone(&registry),
            Arc::clone(&metrics),
            Arc::clone(&shutdown),
            local_prefix,
            None,
            Arc::clone(&liveliness),
        );

        let client = QuicIoThread::spawn(QuicConfig {
            bind_addr: "127.0.0.1:0".parse().expect("literal"),
            dangerous_skip_verify: true,
            ..QuicConfig::default()
        });
        let client_handle = client.handle();

        // A minimal, valid 20-byte RTPS header naming `peer`.
        let mut packet = b"RTPS".to_vec();
        packet.extend_from_slice(&[0x02, 0x03, 0x01, 0x0F]);
        packet.extend_from_slice(&peer);

        let deadline = Instant::now() + Duration::from_secs(10);
        let mut connected = false;
        let mut sent = false;
        while !sent {
            assert!(Instant::now() < deadline, "the QUIC client never connected");
            if connected {
                client_handle
                    .send(server_addr, packet.clone())
                    .expect("send");
                sent = true;
            } else {
                let _ = client_handle.connect(server_addr);
            }
            let until = Instant::now() + Duration::from_millis(200);
            while let Some(event) =
                client_handle.wait(until.saturating_duration_since(Instant::now()))
            {
                if let QuicEvent::Connected { remote_addr } = event {
                    if remote_addr == server_addr {
                        connected = true;
                    }
                }
            }
        }

        let deadline = Instant::now() + Duration::from_secs(10);
        while automatic.last() == before {
            assert!(Instant::now() < deadline, "the renewal never arrived");
            std::thread::sleep(Duration::from_millis(20));
        }

        client_handle.shutdown();
    }
}

#[cfg(test)]
mod stream_reply_tests {
    use crate::core::discovery::multicast::control_parser::parse_all_acknack_submessages;
    use crate::dds::{Participant, QoS, TransportMode};
    use crate::generated::temperature::Temperature;
    use crate::test_support::domains::unique_domain;
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::time::{Duration, Instant};

    /// A HEARTBEAT from `writer` (RTPS 2.5 8.3.8.6, 9.4.5.7) as a whole RTPS
    /// message: readerId UNKNOWN, announcing [1, `last`].
    fn heartbeat_from(writer: [u8; 16], last: u32, count: u32) -> Vec<u8> {
        let mut message = b"RTPS".to_vec();
        message.extend_from_slice(&[0x02, 0x05]);
        message.extend_from_slice(&crate::protocol::constants::HDDS_VENDOR_ID);
        message.extend_from_slice(&writer[..12]);
        message.extend_from_slice(&[0x07, 0x01]);
        message.extend_from_slice(&28u16.to_le_bytes());
        message.extend_from_slice(&[0, 0, 0, 0]);
        message.extend_from_slice(&writer[12..]);
        message.extend_from_slice(&0i32.to_le_bytes());
        message.extend_from_slice(&1u32.to_le_bytes());
        message.extend_from_slice(&0i32.to_le_bytes());
        message.extend_from_slice(&last.to_le_bytes());
        message.extend_from_slice(&count.to_le_bytes());
        message
    }

    /// The transport's framing (`transport::tcp::frame_codec`): a 4-octet
    /// big-endian length, then the RTPS message.
    fn framed(message: &[u8]) -> Vec<u8> {
        let mut frame = u32::try_from(message.len())
            .expect("a small message")
            .to_be_bytes()
            .to_vec();
        frame.extend_from_slice(message);
        frame
    }

    fn read_frame(stream: &mut TcpStream) -> Option<Vec<u8>> {
        let mut length = [0u8; 4];
        stream.read_exact(&mut length).ok()?;
        let mut message = vec![0u8; usize::try_from(u32::from_be_bytes(length)).ok()?];
        stream.read_exact(&mut message).ok()?;
        Some(message)
    }

    /// End to end, over the TCP transport: a reliable reader's participant
    /// receives a HEARTBEAT from its matched writer over a TCP connection,
    /// and the ACKNACK that answers it comes back over that same
    /// connection. The transport routes what it receives into the normal
    /// reader machinery (`transport::tcp`, "Integration Status"), so it is
    /// the reader's answer that must reach the peer, and the peer is on
    /// the other end of the connection -- not on UDP multicast.
    #[test]
    fn a_heartbeat_received_over_tcp_is_answered_over_that_connection() {
        let domain = unique_domain();
        let subscriber = Participant::builder("tcp_reply_sub")
            .domain_id(domain.id())
            .with_transport(TransportMode::UdpMulticast)
            .with_tcp(0)
            .build()
            .expect("subscriber");
        let publisher = Participant::builder("tcp_reply_pub")
            .domain_id(domain.id())
            .with_transport(TransportMode::UdpMulticast)
            .build()
            .expect("publisher");
        let _reader = subscriber
            .topic::<Temperature>("TcpReply")
            .expect("topic")
            .reader()
            .qos(QoS::reliable().keep_all())
            .build()
            .expect("reader");
        let writer = publisher
            .topic::<Temperature>("TcpReply")
            .expect("topic")
            .writer()
            .qos(QoS::reliable().keep_all())
            .build()
            .expect("writer");
        let deadline = Instant::now() + Duration::from_secs(10);
        while writer.matched_reader_count() == 0 {
            assert!(Instant::now() < deadline, "fixture: the pair never matched");
            std::thread::sleep(Duration::from_millis(20));
        }
        let writer_guid = writer
            .endpoint_guid_for_test()
            .expect("an RTPS writer")
            .as_bytes();

        let mut address = subscriber.tcp_listen_addr().expect("a TCP listener");
        if address.ip().is_unspecified() {
            address.set_ip(std::net::Ipv4Addr::LOCALHOST.into());
        }
        let mut connection = TcpStream::connect(address).expect("connect");
        connection
            .set_read_timeout(Some(Duration::from_millis(200)))
            .expect("read timeout");

        // Sent until answered: the reader may match the writer a little
        // after the writer matched it.
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut count = 1_000_000;
        let acknack = loop {
            assert!(
                Instant::now() < deadline,
                "no ACKNACK came back over the TCP connection the HEARTBEAT arrived on"
            );
            connection
                .write_all(&framed(&heartbeat_from(writer_guid, 3, count)))
                .expect("send the HEARTBEAT");
            count += 1;
            if let Some(message) = read_frame(&mut connection) {
                if let Some(acknack) = parse_all_acknack_submessages(&message).into_iter().next() {
                    break acknack;
                }
            }
        };
        assert_eq!(acknack.writer_entity_id, writer_guid[12..]);
        assert_eq!(
            acknack.missing_ranges,
            vec![1..4],
            "nothing received, 1..=3 announced"
        );
    }

    /// The same over QUIC: the ACKNACK comes back on the QUIC connection
    /// the HEARTBEAT arrived on.
    #[cfg(feature = "quic")]
    #[test]
    fn a_heartbeat_received_over_quic_is_answered_over_that_connection() {
        use crate::transport::quic::{QuicConfig, QuicEvent, QuicIoThread};

        // A free port for the subscriber's QUIC endpoint: the routing
        // thread consumes its `Ready` event, so the address is chosen here.
        let quic_addr = std::net::UdpSocket::bind("127.0.0.1:0")
            .and_then(|socket| socket.local_addr())
            .expect("a free UDP port");
        let domain = unique_domain();
        let subscriber = Participant::builder("quic_reply_sub")
            .domain_id(domain.id())
            .with_transport(TransportMode::UdpMulticast)
            .with_quic(QuicConfig {
                bind_addr: quic_addr,
                ..QuicConfig::default()
            })
            .build()
            .expect("subscriber");
        let publisher = Participant::builder("quic_reply_pub")
            .domain_id(domain.id())
            .with_transport(TransportMode::UdpMulticast)
            .build()
            .expect("publisher");
        let _reader = subscriber
            .topic::<Temperature>("QuicReply")
            .expect("topic")
            .reader()
            .qos(QoS::reliable().keep_all())
            .build()
            .expect("reader");
        let writer = publisher
            .topic::<Temperature>("QuicReply")
            .expect("topic")
            .writer()
            .qos(QoS::reliable().keep_all())
            .build()
            .expect("writer");
        let deadline = Instant::now() + Duration::from_secs(10);
        while writer.matched_reader_count() == 0 {
            assert!(Instant::now() < deadline, "fixture: the pair never matched");
            std::thread::sleep(Duration::from_millis(20));
        }
        let writer_guid = writer
            .endpoint_guid_for_test()
            .expect("an RTPS writer")
            .as_bytes();

        let client = QuicIoThread::spawn(QuicConfig {
            bind_addr: "127.0.0.1:0".parse().expect("literal"),
            dangerous_skip_verify: true,
            ..QuicConfig::default()
        });
        let handle = client.handle();
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut connected = false;
        let mut count = 1_000_000;
        let acknack = 'answered: loop {
            assert!(
                Instant::now() < deadline,
                "no ACKNACK came back over the QUIC connection the HEARTBEAT arrived on \
                 (connected: {connected})"
            );
            if connected {
                handle
                    .send(quic_addr, heartbeat_from(writer_guid, 3, count))
                    .expect("send the HEARTBEAT");
                count += 1;
            } else {
                let _ = handle.connect(quic_addr);
            }
            let until = Instant::now() + Duration::from_millis(200);
            while let Some(event) = handle.wait(until.saturating_duration_since(Instant::now())) {
                match event {
                    QuicEvent::Connected { remote_addr } if remote_addr == quic_addr => {
                        connected = true;
                    }
                    QuicEvent::MessageReceived { payload, .. } => {
                        if let Some(acknack) =
                            parse_all_acknack_submessages(&payload).into_iter().next()
                        {
                            break 'answered acknack;
                        }
                    }
                    _ => {}
                }
            }
        };
        handle.shutdown();
        assert_eq!(acknack.writer_entity_id, writer_guid[12..]);
        assert_eq!(acknack.missing_ranges, vec![1..4]);
    }
}
