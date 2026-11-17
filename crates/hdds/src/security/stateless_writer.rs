// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Outbound RTPS writer for the `BuiltinParticipantStatelessMessageWriter`
//! (entity ID `0x000201C3`, DDS Security v1.1 sec. 7.4.5).
//!
//! This module implements the wire-emission half of the Participant-Stateless-
//! Message channel. It drains `StatelessChannel::tx_tokens` produced by the
//! `HandshakeMachine` (via `pump::drain_outgoing`) and serialises each token
//! into a complete RTPS packet:
//!
//! ```text
//! RTPS Header (20 B)
//!   INFO_DST (16 B) -- targets the remote participant GUID prefix
//!   INFO_TS  (12 B) -- current wall-clock timestamp
//!   DATA     (variable) -- CDR-encapsulated ParticipantStatelessMessage payload
//! ```
//!
//! The resulting packet is sent via `UdpTransport::send_to_endpoint` to the
//! remote peer's metatraffic unicast address, if known. When the remote
//! address is not yet in the endpoint registry the packet falls back to
//! metatraffic multicast on the SPDP/SEDP address.
//!
//! # DDS Security spec references
//!
//! - sec. 7.4.5: ParticipantStatelessMessage channel (BEST_EFFORT, VOLATILE,
//!   NO_KEY, plaintext). No ACKNACK, no retransmission.
//! - sec. 9.3.4.2: The AuthRequest is sent first by the Initiator immediately
//!   after the SPDP handshake completes, hence the writer must be ready
//!   before any SPDP callback fires.
//!
//! # Threading
//!
//! The writer runs as a background `std::thread` that sleeps for a short
//! interval between drain cycles. The interval is deliberately short (5 ms)
//! so the handshake latency stays well under the 1 s first-retry deadline
//! (sec. 9.3.4.1). The thread exits cleanly when `running` is set to `false`;
//! the drop of `StatelessWriterHandle` sets it and joins the thread.
//!
//! The thread holds no locks across drain cycles and is completely
//! independent from the multicast listener thread.
//!
//! # Second duty: hosting the handshake timers
//!
//! This thread is also the engine's only caller of `HandshakeMachine::tick`.
//! Nothing on the receive path can advance a session that is waiting for a
//! packet that was lost, so without a periodic tick the retry ladder and the
//! 30 s session deadline of sec. 9.3.4.1 never run at all. This thread is the
//! natural host: it already wakes on a fixed cadence and holds no locks
//! between cycles.
//!
//! The two duties run at different rates on purpose. Draining is latency
//! work and stays at 5 ms; ticking is timer work whose finest rung is 1 s, so
//! it runs at `TICK_INTERVAL` and does not take the handshake write lock two
//! hundred times a second for nothing.

#[cfg(feature = "security")]
pub(crate) mod inner {
    use crate::core::discovery::{EndpointRegistry, GUID};
    use crate::core::rtps_constants::{
        HDDS_VENDOR_ID, RTPS_ENTITYID_BUILTIN_PARTICIPANT_STATELESS_MESSAGE_READER,
        RTPS_ENTITYID_BUILTIN_PARTICIPANT_STATELESS_MESSAGE_WRITER,
        RTPS_ENTITYID_BUILTIN_PARTICIPANT_VOLATILE_MESSAGE_SECURE_WRITER,
        RTPS_ENTITYID_PARTICIPANT, RTPS_MAGIC, RTPS_VERSION_MAJOR, RTPS_VERSION_MINOR,
    };
    use crate::protocol::dialect::{get_encoder, Dialect};
    use crate::security::crypto::data_keys::WriterKey;
    use crate::security::crypto::secure_submessage::WriterKeyMaterial;
    use crate::security::crypto::volatile::{
        builtin_peer_entity_id, is_reader_entity_id, ParticipantKeyAnnouncement,
        ReaderKeyAnnouncement, WriterKeyAnnouncement, GUID_UNKNOWN,
    };
    use crate::security::pump::{drain_outgoing, drive_timers};
    use crate::security::stateless::StatelessChannel;
    use crate::security::volatile_channel::WriteRefusal;
    use crate::security::{SecurityError, SecurityPluginSuite};
    use crate::transport::UdpTransport;
    use std::collections::HashSet;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    /// Poll interval for the drain loop (5 ms).
    ///
    /// Keeps handshake latency well below the 1 s AuthRequest retry deadline
    /// (DDS Security v1.1 sec. 9.3.4.1) while not burning CPU on an idle host.
    const DRAIN_INTERVAL: Duration = Duration::from_millis(5);

    /// Interval between `HandshakeMachine::tick` calls (250 ms).
    ///
    /// The shortest rung of the retry ladder is 1 s, so this gives the timer
    /// four times the resolution it needs while taking the handshake write
    /// lock four times a second instead of two hundred.
    const TICK_INTERVAL: Duration = Duration::from_millis(250);

    /// Interval between volatile distribution sweeps (250 ms).
    ///
    /// A sweep finds what an authenticated peer is owed and has not been
    /// given (a key just minted, a peer just authenticated) and writes it
    /// into the reliable volatile writer; it never sends anything twice,
    /// repair being the reliable pair's own business (`volatile_channel`).
    /// The same cadence hosts the writer's HEARTBEATs.
    const DISTRIBUTE_INTERVAL: Duration = Duration::from_millis(250);

    /// Monotonically increasing sequence number for the stateless writer.
    ///
    /// The stateless channel is BEST_EFFORT: the sequence number here is
    /// advisory (receivers tolerate gaps). We use an `AtomicU64` so the writer
    /// thread can increment it without holding any lock.
    static STATELESS_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

    /// Allocate the next sequence number for the stateless writer.
    fn next_seq() -> u64 {
        STATELESS_SEQ.fetch_add(1, Ordering::Relaxed)
    }

    /// Handle returned by `spawn_stateless_writer`. Dropping this handle
    /// stops the background thread and joins it: the thread holds the
    /// participant's transport, so it must not outlive the participant.
    pub(crate) struct StatelessWriterHandle {
        running: Arc<AtomicBool>,
        thread: Option<std::thread::JoinHandle<()>>,
    }

    impl Drop for StatelessWriterHandle {
        fn drop(&mut self) {
            self.running.store(false, Ordering::Relaxed);
            log::debug!("[security::stateless_writer] shutdown signal sent to drain loop");
            if let Some(thread) = self.thread.take() {
                thread.thread().unpark();
                crate::core::rt::shutdown::join_bounded(thread, "security stateless writer");
            }
        }
    }

    /// Spawn the outbound stateless writer thread.
    ///
    /// The thread polls `channel.tx_tokens` every `DRAIN_INTERVAL`. For each
    /// pending token it:
    ///
    /// 1. Allocates the next sequence number.
    /// 2. Builds an RTPS packet (INFO_DST + INFO_TS + DATA) targeting
    ///    `remote_guid_prefix`.
    /// 3. Looks up the remote metatraffic unicast address in `endpoint_registry`.
    ///    If not found, falls back to multicast (transport.send()).
    /// 4. Sends the packet.
    ///
    /// # Arguments
    ///
    /// - `channel`: the stateless channel whose `tx_tokens` the writer drains.
    /// - `local_guid_prefix`: the local participant's 12-byte GUID prefix (for
    ///   the RTPS packet header).
    /// - `transport`: the UDP transport for sending packets.
    /// - `endpoint_registry`: the live endpoint registry for remote unicast
    ///   address lookup.
    /// - `suite`: the security plugin suite. The thread advances the retry and
    ///   expiry timers of `suite.handshakes` every `TICK_INTERVAL` (it is the
    ///   engine's only `tick` caller), and every `DISTRIBUTE_INTERVAL` it
    ///   writes what each authenticated peer is owed over the volatile
    ///   channel (`distribute`) and sends the volatile writer's HEARTBEATs.
    ///
    /// # Returns
    ///
    /// A `StatelessWriterHandle` that keeps the thread alive while held.
    /// Dropping the handle requests thread exit (within `DRAIN_INTERVAL`).
    pub(crate) fn spawn_stateless_writer(
        channel: StatelessChannel,
        local_guid_prefix: [u8; 12],
        transport: Arc<UdpTransport>,
        endpoint_registry: EndpointRegistry,
        suite: Arc<SecurityPluginSuite>,
    ) -> StatelessWriterHandle {
        let running = Arc::new(AtomicBool::new(true));
        let running_clone = running.clone();

        let spawned = std::thread::Builder::new()
            .name("hdds-stateless-writer".into())
            .spawn(crate::core::rt::shutdown::owned(move || {
                log::info!(
                    "[security::stateless_writer] writer thread started (entity BuiltinParticipantStatelessMessageWriter)"
                );
                let handshake_machine = suite.handshakes.clone();
                let mut last_tick = Instant::now();
                let mut last_distribute = Instant::now();
                let mut distributed_at_epoch = handshake_machine.state_epoch();
                let mut announced: HashSet<Owed> = HashSet::new();
                while running_clone.load(Ordering::Relaxed) {
                    // Timers first, so a retransmission decided this cycle
                    // goes out in this cycle's drain rather than the next.
                    let now = Instant::now();
                    if now.saturating_duration_since(last_tick) >= TICK_INTERVAL {
                        last_tick = now;
                        let n = drive_timers(&handshake_machine, &channel, now);
                        if n > 0 {
                            log::debug!(
                                "[security::stateless_writer] handshake timers produced {} action(s)",
                                n
                            );
                        }
                    }

                    // Key distribution rides the same thread: it needs the
                    // same peers, the same transport, and a cadence -- and a
                    // second thread would be a second copy of this loop.
                    //
                    // Also at once when a handshake changed state: a peer
                    // that has just authenticated gets our writers' key
                    // material now, not up to a sweep later, so the secure
                    // SEDP we send it right after its authentication finds
                    // the key it is protected with (`secure_sedp`, "SEDP that
                    // arrives before the writer's tokens").
                    let epoch = handshake_machine.state_epoch();
                    if now.saturating_duration_since(last_distribute) >= DISTRIBUTE_INTERVAL
                        || epoch != distributed_at_epoch
                    {
                        last_distribute = now;
                        distributed_at_epoch = epoch;
                        distribute(
                            &suite,
                            &local_guid_prefix,
                            &transport,
                            &endpoint_registry,
                            &mut announced,
                            now,
                        );
                        heartbeat_peers(
                            &suite,
                            &local_guid_prefix,
                            &transport,
                            &endpoint_registry,
                            now,
                        );
                    }

                    // CryptoTokens held for the match of their endpoints
                    // (`VolatileChannel::retry_pending`).
                    let _ = suite.volatile.retry_pending(&suite.data_keys, &suite.handshakes, now);

                    let tokens = drain_outgoing(&channel);
                    for (remote_prefix, token) in tokens {
                        let seq = next_seq();
                        // The token travels in its ParticipantStatelessMessage
                        // (DDS Security v1.1 Sec.7.4.3.3), from this writer to
                        // the remote participant.
                        let mut source = [0u8; 16];
                        source[..12].copy_from_slice(&local_guid_prefix);
                        source[12..]
                            .copy_from_slice(&RTPS_ENTITYID_BUILTIN_PARTICIPANT_STATELESS_MESSAGE_WRITER);
                        let mut destination = [0u8; 16];
                        destination[..12].copy_from_slice(&remote_prefix);
                        destination[12..].copy_from_slice(&RTPS_ENTITYID_PARTICIPANT);
                        let payload = match crate::security::generic_message::encode(
                            &source,
                            i64::try_from(seq).unwrap_or(i64::MAX),
                            &destination,
                            &token,
                        ) {
                            Ok(payload) => payload,
                            Err(e) => {
                                log::warn!(
                                    "[security::stateless_writer] token for {:02x?} not \
                                    sent: {}",
                                    remote_prefix,
                                    e
                                );
                                continue;
                            }
                        };
                        match build_stateless_packet(
                            &local_guid_prefix,
                            &remote_prefix,
                            seq,
                            &payload,
                        ) {
                            Some(packet) => {
                                send_stateless_packet(
                                    &transport,
                                    &endpoint_registry,
                                    &remote_prefix,
                                    &packet,
                                );
                            }
                            None => {
                                log::warn!(
                                    "[security::stateless_writer] payload too large for \
                                    {:02x?} (len={}), skipping",
                                    remote_prefix,
                                    payload.len()
                                );
                            }
                        }
                    }
                    // Parked rather than asleep: the handle's drop unparks us.
                    std::thread::park_timeout(DRAIN_INTERVAL);
                }
                log::debug!("[security::stateless_writer] writer thread exiting");
            }));

        let thread = match spawned {
            Ok(thread) => Some(thread),
            Err(e) => {
                log::error!(
                    "[security::stateless_writer] failed to spawn writer thread: {} -- \
                    outbound stateless tokens will accumulate in tx_tokens but not be sent",
                    e
                );
                None
            }
        };

        StatelessWriterHandle { running, thread }
    }

    // -----------------------------------------------------------------------
    //  Packet builder
    // -----------------------------------------------------------------------

    /// Build a complete RTPS packet for one outbound stateless token.
    ///
    /// Layout (per RTPS v2.5 sec. 9.4.5 and DDS Security v1.1 sec. 7.4.5):
    ///
    /// ```text
    /// RTPS header  (20 bytes)
    /// INFO_DST     (16 bytes)  -- set to remote_prefix
    /// INFO_TS      (12 bytes)  -- current wall time
    /// DATA         (variable)
    ///   writer_id  = 0x000201C3 (BuiltinParticipantStatelessMessageWriter)
    ///   reader_id  = 0x000201C4 (BuiltinParticipantStatelessMessageReader)
    ///   seq_num    = monotone counter
    ///   serialized_payload = CDR encapsulation + handshake token bytes
    /// ```
    ///
    /// Returns `None` if the payload exceeds the maximum CDR size.
    fn build_stateless_packet(
        local_prefix: &[u8; 12],
        remote_prefix: &[u8; 12],
        seq_num: u64,
        payload: &[u8],
    ) -> Option<Vec<u8>> {
        build_secure_builtin_packet(
            local_prefix,
            remote_prefix,
            seq_num,
            payload,
            &RTPS_ENTITYID_BUILTIN_PARTICIPANT_STATELESS_MESSAGE_READER,
            &RTPS_ENTITYID_BUILTIN_PARTICIPANT_STATELESS_MESSAGE_WRITER,
        )
    }

    /// Packet builder of the stateless writer (0x000201C3).
    fn build_secure_builtin_packet(
        local_prefix: &[u8; 12],
        remote_prefix: &[u8; 12],
        seq_num: u64,
        payload: &[u8],
        reader_entity_id: &[u8; 4],
        writer_entity_id: &[u8; 4],
    ) -> Option<Vec<u8>> {
        if payload.len() > (u16::MAX as usize).saturating_sub(24) {
            return None;
        }

        let encoder = get_encoder(Dialect::Hybrid);

        // INFO_DST: 1 byte ID (0x0E) + 1 byte flags (E=1, LE) + 2 bytes octetsToNextHeader (12)
        // + 12 bytes GUID prefix = 16 bytes total.
        let info_dst = encoder.build_info_dst(remote_prefix);

        // INFO_TS: build current timestamp.
        let info_ts = build_info_ts_submessage();

        // DATA submessage.
        let data_submsg = encoder
            .build_data(
                reader_entity_id,
                writer_entity_id,
                seq_num,
                payload,
                None, // no inline QoS
            )
            .ok()?;

        let mut packet =
            Vec::with_capacity(20 + info_dst.len() + info_ts.len() + data_submsg.len());

        // RTPS header (20 bytes)
        packet.extend_from_slice(RTPS_MAGIC);
        packet.push(RTPS_VERSION_MAJOR);
        packet.push(RTPS_VERSION_MINOR);
        packet.extend_from_slice(&HDDS_VENDOR_ID);
        packet.extend_from_slice(local_prefix);

        // Submessages: INFO_DST -> INFO_TS -> DATA (HDDS ordering)
        packet.extend_from_slice(&info_dst);
        packet.extend_from_slice(&info_ts);
        packet.extend_from_slice(&data_submsg);

        Some(packet)
    }

    /// Serialize a current-time INFO_TS submessage.
    ///
    /// Mirrors `rtps_packet::build_info_ts_submessage` (private there). We
    /// duplicate the ~15-line helper rather than reach into a private function.
    fn build_info_ts_submessage() -> Vec<u8> {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let sec = u32::try_from(duration.as_secs()).unwrap_or(u32::MAX);
        let frac = u32::try_from(duration.subsec_nanos() as u64 * 0x1_0000_0000 / 1_000_000_000)
            .unwrap_or(u32::MAX);
        let encoder = get_encoder(Dialect::Hybrid);
        encoder.build_info_ts(sec, frac)
    }

    // -----------------------------------------------------------------------
    //  Transmission
    // -----------------------------------------------------------------------

    /// Send one stateless packet to the remote participant.
    ///
    /// Looks up the remote peer's metatraffic unicast address from
    /// `endpoint_registry`. If none is found, falls back to the SPDP
    /// multicast group via `transport.send()` (best-effort: the remote may
    /// not see it, but the protocol is BEST_EFFORT so this is acceptable).
    fn send_stateless_packet(
        transport: &UdpTransport,
        endpoint_registry: &EndpointRegistry,
        remote_prefix: &[u8; 12],
        packet: &[u8],
    ) {
        // Build the participant GUID from the remote prefix.
        use crate::core::discovery::GUID;
        let participant_guid = GUID::new(*remote_prefix, [0x00, 0x00, 0x01, 0xC1]);

        if let Some(addr) = endpoint_registry.get(&participant_guid) {
            if let Err(e) = transport.send_to_endpoint(packet, &addr) {
                log::warn!(
                    "[security::stateless_writer] unicast send to {} failed: {}",
                    addr,
                    e
                );
            } else {
                log::debug!(
                    "[security::stateless_writer] sent {} bytes to {:02x?} (unicast {})",
                    packet.len(),
                    remote_prefix,
                    addr
                );
            }
        } else {
            // No unicast address known yet -- fall back to SPDP multicast.
            // The remote participant listens on the SPDP multicast group and
            // will process stateless messages on entity 0x000201C4 regardless.
            if let Err(e) = transport.send(packet) {
                log::warn!(
                    "[security::stateless_writer] multicast fallback send failed: {}",
                    e
                );
            } else {
                log::debug!(
                    "[security::stateless_writer] sent {} bytes for {:02x?} via multicast fallback",
                    packet.len(),
                    remote_prefix
                );
            }
        }
    }

    // -----------------------------------------------------------------------
    //  ParticipantVolatileMessageSecure writer (DDS Security v1.1 Sec.7.4.4)
    // -----------------------------------------------------------------------

    /// One message the volatile writer owes `peer`: the CryptoTokens of
    /// `source` (a local endpoint, or GUID_UNKNOWN for this participant's
    /// own ParticipantCryptoTokens) under `key_id`, addressed to
    /// `destination`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub(crate) struct Owed {
        peer: [u8; 12],
        source: [u8; 16],
        key_id: u64,
        destination: [u8; 16],
        match_generation: u64,
        refresh_generation: u64,
    }

    impl Owed {
        /// The endpoint/key/match identity, independent of its refresh age.
        fn match_identity(mut self) -> Self {
            self.refresh_generation = 0;
            self
        }

        fn is_user(&self) -> bool {
            self.source != GUID_UNKNOWN
                && builtin_peer_entity_id(GUID::from_bytes(self.source).entity_id).is_none()
        }
    }

    /// What one [`Owed`] message carries, and how it is built.
    enum Tokens<'a> {
        Writer(&'a WriterKey),
        Reader(&'a WriterKey),
        Participant(u32, &'a WriterKey),
    }

    impl Tokens<'_> {
        /// The protected DATA of this message as change `sn` of the
        /// volatile writer (`crypto::volatile`, `seal`).
        fn seal(
            &self,
            owed: &Owed,
            kx: &WriterKeyMaterial,
            local_volatile_writer: &GUID,
            sn: i64,
        ) -> Result<Vec<u8>, SecurityError> {
            let destination_participant = GUID::new(owed.peer, RTPS_ENTITYID_PARTICIPANT);
            match self {
                Tokens::Writer(material) => WriterKeyAnnouncement {
                    writer_guid: GUID::from_bytes(owed.source),
                    key_id: owed.key_id,
                    key: material.key.duplicate_for_store(),
                    master_salt: material.salt.duplicate_for_store(),
                    transformation: material.transformation,
                }
                .seal(
                    kx,
                    local_volatile_writer,
                    &destination_participant,
                    owed.destination,
                    sn,
                ),
                Tokens::Reader(material) => ReaderKeyAnnouncement {
                    reader_guid: GUID::from_bytes(owed.source),
                    key_id: owed.key_id,
                    key: material.key.duplicate_for_store(),
                    master_salt: material.salt.duplicate_for_store(),
                    transformation: material.transformation,
                }
                .seal(
                    kx,
                    local_volatile_writer,
                    &destination_participant,
                    owed.destination,
                    sn,
                ),
                Tokens::Participant(key_id, material) => ParticipantKeyAnnouncement {
                    key_id: *key_id,
                    key: material.key.duplicate_for_store(),
                    master_salt: material.salt.duplicate_for_store(),
                }
                .seal(kx, local_volatile_writer, &destination_participant, sn),
            }
        }
    }

    /// The endpoints of `peer` a CryptoTokens message of the local endpoint
    /// `source` is addressed to, one message each. A secure builtin
    /// endpoint pairs 1:1 with the peer's mirrored endpoint
    /// (`volatile::builtin_peer_entity_id`); a USER endpoint's messages go
    /// to each remote endpoint of `peer` it is matched with
    /// (DDS Security v1.1 Sec.7.4.4.6.2-3: "the GUID_t of the DataReader
    /// that should receive the CryptoToken values"). The key material may
    /// be one for all of them; the addressing is one per match.
    fn destinations(suite: &SecurityPluginSuite, source: &GUID, peer: &[u8; 12]) -> Vec<[u8; 16]> {
        match builtin_peer_entity_id(source.entity_id) {
            Some(mirrored) => vec![GUID::new(*peer, mirrored).as_bytes()],
            None => suite
                .volatile
                .user_destinations(source, peer)
                .into_iter()
                .map(|destination| destination.as_bytes())
                .collect(),
        }
    }

    /// One distribution sweep: write into the reliable volatile writer
    /// every message an authenticated peer is owed and has not been given
    /// -- the CryptoTokens of every local endpoint holding key material,
    /// one per destination ([`destinations`]), and this participant's
    /// ParticipantCryptoTokens. A loss is repaired by the reader's ACKNACK.
    /// USER tokens are also offered as fresh application messages after
    /// their installation lifetime: the receiver may have consumed them
    /// with a refusal before its own endpoint discovery caught up. This
    /// does not replay RTPS history or periodically reannounce builtin keys.
    ///
    /// `announced` is what the writer already took. An entry leaves it when
    /// the message is owed no more (its key retired, its peer gone), or when
    /// the peer's proxy started over (the peer authenticated again: what it
    /// held is protected under KxKeys nobody holds any more), so the
    /// message is written again when it is owed again. Each new USER match
    /// event also owes a fresh message, even with the same key and GUIDs:
    /// the receiver may have consumed an earlier token after hold expiry.
    /// The last successful refresh is retained until its replacement is
    /// accepted, so back-pressure preserves the pair's priority by age.
    /// A message refused for want of room is offered at the next
    /// sweep. UNICAST ONLY: a message is addressed to one peer.
    ///
    /// Returns the number of messages written.
    pub(crate) fn distribute(
        suite: &SecurityPluginSuite,
        local_prefix: &[u8; 12],
        transport: &UdpTransport,
        endpoint_registry: &EndpointRegistry,
        announced: &mut HashSet<Owed>,
        now: Instant,
    ) -> usize {
        let channel = &suite.volatile;
        let sent_generations: std::collections::HashMap<_, _> = announced
            .iter()
            .map(|owed| (owed.match_identity(), owed.refresh_generation))
            .collect();
        let peers: HashSet<[u8; 12]> = suite
            .handshakes
            .authenticated_peer_prefixes()
            .into_iter()
            .collect();
        channel.retain_peers(&peers);
        let locals = suite.data_keys.entries_with_prefix(local_prefix);
        let participant_key = suite.participant_keys.local_key_material();
        let local_volatile_writer = GUID::new(
            *local_prefix,
            RTPS_ENTITYID_BUILTIN_PARTICIPANT_VOLATILE_MESSAGE_SECURE_WRITER,
        );
        let mut owed_now: HashSet<Owed> = HashSet::new();
        let mut written = 0;
        for peer in &peers {
            let participant_guid = GUID::new(*peer, RTPS_ENTITYID_PARTICIPANT);
            let mut messages: Vec<(Owed, Tokens<'_>)> = Vec::new();
            for (source, key_id, material) in &locals {
                for destination in destinations(suite, source, peer) {
                    let match_generation = if builtin_peer_entity_id(source.entity_id).is_some() {
                        0
                    } else {
                        let Some(generation) =
                            channel.match_generation(source, &GUID::from_bytes(destination))
                        else {
                            continue;
                        };
                        generation
                    };
                    let owed = Owed {
                        match_generation,
                        refresh_generation: if builtin_peer_entity_id(source.entity_id).is_some() {
                            0
                        } else {
                            channel.token_refresh_generation(now)
                        },
                        peer: *peer,
                        source: source.as_bytes(),
                        key_id: *key_id,
                        destination,
                    };
                    let tokens = if is_reader_entity_id(source.entity_id) {
                        Tokens::Reader(material)
                    } else {
                        Tokens::Writer(material)
                    };
                    messages.push((owed, tokens));
                }
            }
            if let Some((key_id, material)) = participant_key.as_ref() {
                messages.push((
                    Owed {
                        peer: *peer,
                        source: GUID_UNKNOWN,
                        match_generation: 0,
                        refresh_generation: 0,
                        key_id: u64::from(*key_id),
                        destination: participant_guid.as_bytes(),
                    },
                    Tokens::Participant(*key_id, material),
                ));
            }
            // Builtin traffic first, new announcements before refreshes,
            // then the oldest successful refresh. Otherwise a full window
            // can repeatedly go to the same expired USER pairs.
            messages.sort_by_cached_key(|(owed, _)| {
                (
                    owed.is_user(),
                    sent_generations.get(&owed.match_identity()).copied(),
                )
            });
            owed_now.extend(messages.iter().map(|(owed, _)| owed.match_identity()));

            let served = suite.handshakes.with_volatile_key_material(peer, |kx| {
                {
                    let mut writer = channel.writer.lock();
                    writer.sync_session(*peer, kx.fingerprint(), now);
                    for reset in writer.take_resets() {
                        announced.retain(|owed| owed.peer != reset);
                    }
                }
                // The address arrives with SPDP, before the handshake that
                // gates this sweep: a peer without one is served next time.
                let Some(addr) = endpoint_registry.get(&participant_guid) else {
                    return 0;
                };
                let mut written = 0;
                for (owed, tokens) in &messages {
                    if announced.contains(owed) {
                        continue;
                    }
                    let result = channel
                        .writer
                        .lock()
                        .write(local_prefix, *peer, &kx, now, |sn| {
                            tokens.seal(owed, &kx, &local_volatile_writer, sn)
                        });
                    match result {
                        Ok(datagrams) => {
                            for datagram in &datagrams {
                                // In the history now: a lost send is
                                // repaired like a lost packet.
                                if let Err(e) = transport.send_to_endpoint(datagram, &addr) {
                                    log::debug!(
                                        "[security::volatile] send to {:02x?} failed: {}",
                                        peer,
                                        e
                                    );
                                }
                            }
                            if let Some(generation) = sent_generations.get(&owed.match_identity()) {
                                let mut previous = *owed;
                                previous.refresh_generation = *generation;
                                announced.remove(&previous);
                            }
                            announced.insert(*owed);
                            written += 1;
                            log::debug!(
                                "[security::volatile] wrote the tokens of {:02x?} (key_id={:#x}) \
                                 for {:02x?}",
                                owed.source,
                                owed.key_id,
                                owed.destination
                            );
                        }
                        Err(WriteRefusal::Full) => channel.stats.note_refused_full(),
                        Err(WriteRefusal::Seal(e)) => log::warn!(
                            "[security::volatile] the tokens of {:02x?} for {:02x?} not \
                             written: {}",
                            owed.source,
                            owed.destination,
                            e
                        ),
                    }
                }
                written
            });
            written += served.unwrap_or(0);
        }
        announced.retain(|owed| owed_now.contains(&owed.match_identity()));
        written
    }

    /// The periodic HEARTBEAT of every reader proxy due one
    /// (`volatile_channel::WriterState::tick`).
    fn heartbeat_peers(
        suite: &SecurityPluginSuite,
        local_prefix: &[u8; 12],
        transport: &UdpTransport,
        endpoint_registry: &EndpointRegistry,
        now: Instant,
    ) {
        for peer in suite.handshakes.authenticated_peer_prefixes() {
            let Some(addr) = endpoint_registry.get(&GUID::new(peer, RTPS_ENTITYID_PARTICIPANT))
            else {
                continue;
            };
            let datagrams = suite
                .handshakes
                .with_volatile_key_material(&peer, |kx| {
                    suite
                        .volatile
                        .writer
                        .lock()
                        .tick(local_prefix, peer, &kx, now)
                })
                .unwrap_or_default();
            for datagram in &datagrams {
                let _ = transport.send_to_endpoint(datagram, &addr);
            }
        }
    }
}

// ---------------------------------------------------------------------------
//  Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    // The build_stateless_packet helper uses the `security` feature path for
    // the encoder; these tests exercise the non-feature code path (plain
    // channel plumbing) only.  Full round-trip tests including the crypto
    // path live in `security::handshake::tests`.

    use crate::security::stateless::{StatelessChannel, StatelessToken};

    #[test]
    fn stateless_writer_channel_drain_on_empty_is_safe() {
        let channel = StatelessChannel::new();
        // drain_outgoing on an empty channel returns an empty Vec.
        #[cfg(feature = "security")]
        {
            use crate::security::pump::drain_outgoing;
            let result = drain_outgoing(&channel);
            assert!(
                result.is_empty(),
                "empty channel must yield empty drain result"
            );
        }
        #[cfg(not(feature = "security"))]
        {
            assert!(channel.pop_outgoing().is_none());
        }
    }

    // -----------------------------------------------------------------------
    //  The thread really does host the handshake timers (gap G14).
    //
    //  The unit tests around `HandshakeMachine::tick` and `pump::drive_timers`
    //  prove the ladder and the bridge. Neither proves that anything in a
    //  running participant ever calls them -- which is precisely the shape of
    //  the bug: a correct handler nobody invokes. This test starts the real
    //  writer thread against a handshake no peer will ever answer, and watches
    //  the retransmission arrive on a socket.
    // -----------------------------------------------------------------------

    #[cfg(feature = "security")]
    #[test]
    fn writer_thread_retransmits_a_handshake_nobody_answers() {
        use super::inner::spawn_stateless_writer;
        use crate::core::discovery::{EndpointRegistry, GUID};
        use crate::security::handshake::HandshakeAction;
        use crate::security::pump::enqueue_action;
        use crate::security::{SecurityConfig, SecurityPluginSuite};
        use crate::test_support::domains::unique_domain;
        use crate::transport::{PortMapping, UdpTransport};
        use std::io::Write;
        use std::net::UdpSocket;
        use std::sync::Arc;
        use std::time::{Duration, Instant};

        // A leased domain, declared first so it is released last -- after the
        // writer thread has stopped and the transport's sockets are closed.
        //
        // A fixed domain constant cannot guarantee this test never shares
        // metatraffic ports with the two-participant tests in
        // security::e2e_tests (same lib test binary, same participant index
        // 0); the lease can.
        let domain = unique_domain();

        /// Offset of the CDR payload in a stateless packet, summing the
        /// 20 B RTPS header, 16 B INFO_DST, 12 B INFO_TS and 24 B DATA
        /// header. Everything the writer varies between two sends of the same
        /// token -- the timestamp and the sequence number -- lives below this
        /// line.
        const CDR_OFFSET: usize = 72;

        // A probe socket standing in for the peer's metatraffic unicast
        // endpoint. Registering it makes the writer take the unicast path, so
        // every packet it emits lands here instead of on a multicast group.
        let probe = UdpSocket::bind("127.0.0.1:0").expect("bind probe socket");
        probe
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("set read timeout");
        let probe_addr = probe.local_addr().expect("probe address");

        let local_prefix = [0x01u8; 12];
        let remote_prefix = [0xFFu8; 12];
        let local_guid = GUID::new(local_prefix, [0x00, 0x00, 0x01, 0xC1]);
        let remote_guid = GUID::new(remote_prefix, [0x00, 0x00, 0x01, 0xC1]);

        let registry = EndpointRegistry::new();
        registry.register(remote_guid, probe_addr);

        let mapping = PortMapping::calculate(domain.id(), 0).expect("port mapping");
        let transport =
            Arc::new(UdpTransport::new(domain.id(), 0, mapping).expect("bind udp transport"));

        let channel = StatelessChannel::new();

        // spawn_stateless_writer takes the full suite now (it hosts the key
        // distribution sweep as well as the timers). Build one from the shared
        // test PKI; the machine under test is the suite's own.
        let write_pem = |contents: &[u8]| {
            let mut f = tempfile::NamedTempFile::new().expect("temp file");
            f.write_all(contents).expect("write PEM");
            f.flush().expect("flush PEM");
            f
        };
        let cert = write_pem(crate::security::test_pki::TEST_IDENTITY_CERT_PEM);
        let key = write_pem(crate::security::test_pki::TEST_IDENTITY_KEY_PEM);
        let ca = write_pem(crate::security::test_pki::TEST_CA_CERT_PEM);
        let config = SecurityConfig::builder()
            .identity_certificate(cert.path())
            .private_key(key.path())
            .ca_certificates(ca.path())
            .build()
            .expect("SecurityConfig from the shared test PKI must build");
        let suite = Arc::new(SecurityPluginSuite::new(config, 0).expect("suite"));
        let machine = suite.handshakes.clone();

        let action = machine
            .start(
                local_guid,
                remote_guid,
                crate::security::test_pki::TEST_IDENTITY_CERT_PEM,
                crate::security::test_pki::TEST_IDENTITY_KEY_PEM,
            )
            .expect("start must succeed")
            .expect("the lower GUID prefix takes the initiator role");
        assert!(matches!(action, HandshakeAction::SendRequest(..)));
        enqueue_action(action, &channel);

        // Handle kept alive for the duration of the test; dropping it stops
        // the thread.
        let _handle = spawn_stateless_writer(channel, local_prefix, transport, registry, suite);

        let mut buf = [0u8; 4096];
        let (n1, _) = probe
            .recv_from(&mut buf)
            .expect("the writer must emit the original AuthRequest");
        let first = buf[..n1].to_vec();

        let waiting_since = Instant::now();
        let (n2, _) = probe
            .recv_from(&mut buf)
            .expect("the retry ladder must retransmit a handshake nobody answered");
        let second = buf[..n2].to_vec();
        let waited = waiting_since.elapsed();

        assert!(
            waited >= Duration::from_millis(700),
            "the retransmission must respect the 1 s rung, not fire on every drain \
             cycle; waited only {:?}",
            waited
        );
        assert!(
            first.len() > CDR_OFFSET && second.len() > CDR_OFFSET,
            "both packets must carry a CDR payload (got {} and {} bytes)",
            first.len(),
            second.len()
        );
        // Each transmission is a message of its own (its message_identity
        // carries the writer's sequence number); the token it carries is
        // the same.
        let token = |packet: &[u8]| {
            crate::security::generic_message::decode(&packet[CDR_OFFSET..])
                .expect("a ParticipantStatelessMessage")
                .token
        };
        assert_eq!(
            token(&first),
            token(&second),
            "the retransmitted token must be byte-identical to the original"
        );
    }

    #[test]
    fn stateless_writer_channel_drain_yields_all_pending() {
        let channel = StatelessChannel::new();
        for i in 0u8..4 {
            channel.push_outgoing(StatelessToken {
                remote_guid_prefix: [i; 12],
                payload: vec![i, i],
            });
        }
        #[cfg(feature = "security")]
        {
            use crate::security::pump::drain_outgoing;
            let drained = drain_outgoing(&channel);
            assert_eq!(drained.len(), 4);
            assert_eq!(channel.outgoing_len(), 0, "all tokens must be consumed");
        }
        #[cfg(not(feature = "security"))]
        {
            let mut n = 0usize;
            while channel.pop_outgoing().is_some() {
                n += 1;
            }
            assert_eq!(n, 4);
        }
    }

    /// DDS Security v1.1 Sec.7.4.4.6.2 on the wire: a USER DataWriter's
    /// tokens go to the peer once per matched DataReader of that peer, each
    /// naming that reader as its destination_endpoint_guid -- never
    /// GUID_UNKNOWN, never a reader of another participant. An immediate
    /// second sweep writes nothing. New matches and installation lifetimes
    /// owe new identities; RTPS repairs keep the original identity.
    ///
    /// Mutants: `destinations` answering GUID_UNKNOWN for a USER writer
    /// fails the destination set; `distribute` not recording what it wrote
    /// in `announced` sends it all again on the second sweep.
    #[cfg(feature = "security")]
    #[test]
    fn a_user_writers_tokens_go_once_to_each_matched_reader_by_its_guid() {
        use super::inner::distribute;
        use crate::core::discovery::{EndpointRegistry, GUID};
        use crate::security::crypto::data_keys::WriterKey;
        use crate::security::crypto::secure_submessage::{
            decode_datawriter_submessage, first_secure_prefix, first_secure_prefix_from,
        };
        use crate::security::crypto::volatile::{decode_message, parse_data};
        use crate::security::{SecurityConfig, SecurityPluginSuite};
        use crate::test_support::domains::unique_domain;
        use crate::transport::{PortMapping, UdpTransport};
        use std::collections::{HashMap, HashSet};
        use std::io::Write;
        use std::net::UdpSocket;
        use std::sync::Arc;
        use std::time::{Duration, Instant};

        #[derive(Default)]
        struct Endpoints(
            parking_lot::Mutex<HashMap<GUID, Vec<GUID>>>,
            parking_lot::Mutex<HashMap<GUID, u64>>,
        );
        impl crate::security::volatile_channel::LocalEndpoints for Arc<Endpoints> {
            fn matched_with(&self, local: &GUID) -> Option<Vec<GUID>> {
                self.0.lock().get(local).cloned()
            }
            fn match_generation(&self, local: &GUID, remote: &GUID) -> Option<u64> {
                self.matched_with(local)?
                    .contains(remote)
                    .then(|| self.1.lock().get(remote).copied().unwrap_or(0))
            }
        }

        let domain = unique_domain();
        let write_pem = |contents: &[u8]| {
            let mut f = tempfile::NamedTempFile::new().expect("temp file");
            f.write_all(contents).expect("write PEM");
            f
        };
        let cert = write_pem(crate::security::test_pki::TEST_IDENTITY_CERT_PEM);
        let key = write_pem(crate::security::test_pki::TEST_IDENTITY_KEY_PEM);
        let ca = write_pem(crate::security::test_pki::TEST_CA_CERT_PEM);
        let config = SecurityConfig::builder()
            .identity_certificate(cert.path())
            .private_key(key.path())
            .ca_certificates(ca.path())
            .build()
            .expect("config");
        let mut ours = crate::security::test_pki::TEST_IDENTITY_PREFIX_HEAD.to_vec();
        ours.extend_from_slice(&[0x61; 6]);
        let ours: [u8; 12] = ours.try_into().expect("prefix");
        let mut peer = crate::security::test_pki::TEST_IDENTITY_PREFIX_HEAD.to_vec();
        peer.extend_from_slice(&[0x62; 6]);
        let peer: [u8; 12] = peer.try_into().expect("prefix");
        let mut suite = SecurityPluginSuite::new(config, 0).expect("suite");
        suite.handshakes =
            crate::security::test_pki::local_machine_with_completed_peer(ours, peer, None);
        let suite = Arc::new(suite);
        let kx = suite.handshakes.volatile_key_material(&peer).expect("kx");
        let now = Instant::now();

        let writer = GUID::new(ours, [0, 0, 7, 0x02]);
        let reader_one = GUID::new(peer, [0, 0, 8, 0x07]);
        let reader_two = GUID::new(peer, [0, 0, 9, 0x07]);
        let elsewhere = GUID::new([0x99; 12], [0, 0, 8, 0x07]);
        let a_writer_of_the_peer = GUID::new(peer, [0, 0, 8, 0x02]);
        let endpoints = Arc::new(Endpoints::default());
        endpoints.0.lock().insert(
            writer,
            vec![reader_two, elsewhere, reader_one, a_writer_of_the_peer],
        );
        suite
            .volatile
            .set_local_endpoints(Box::new(Arc::clone(&endpoints)));
        let (key_id, material) = WriterKey::mint().expect("mint");
        suite
            .data_keys
            .insert(writer, u64::from(key_id), material)
            .expect("key");
        let (builtin_id, builtin_key) = WriterKey::mint().expect("builtin key");
        suite
            .data_keys
            .insert(
                GUID::new(
                    ours,
                    crate::core::rtps_constants::RTPS_ENTITYID_SPDP_SECURE_WRITER,
                ),
                u64::from(builtin_id),
                builtin_key,
            )
            .expect("store builtin key");

        let probe = UdpSocket::bind("127.0.0.1:0").expect("probe");
        probe
            .set_read_timeout(Some(Duration::from_millis(300)))
            .expect("timeout");
        let registry = EndpointRegistry::new();
        registry.register(
            GUID::new(peer, [0, 0, 1, 0xC1]),
            probe.local_addr().expect("address"),
        );
        let mapping = PortMapping::calculate(domain.id(), 0).expect("port mapping");
        let transport = UdpTransport::new(domain.id(), 0, mapping).expect("transport");

        // The writer's tokens in what reaches the probe: their destinations.
        let sequences = parking_lot::Mutex::new(Vec::new());
        let all_sources = parking_lot::Mutex::new(Vec::new());
        let destinations_received = || {
            let mut destinations = Vec::new();
            let mut buf = [0u8; 65536];
            while let Ok((n, _)) = probe.recv_from(&mut buf) {
                let datagram = &buf[..n];
                let mut at = first_secure_prefix(datagram);
                while let Some(prefix) = at {
                    let decoded =
                        decode_datawriter_submessage(&kx, datagram, prefix).expect("opens");
                    if let Some(data) = parse_data(&decoded.submessage) {
                        let message = decode_message(data.payload).expect("message");
                        all_sources.lock().push(message.source_endpoint);
                        if message.source_endpoint == writer.as_bytes() {
                            let tokens = crate::security::crypto::volatile::WriterKeyAnnouncement::from_message(&message).expect("writer tokens");
                            assert_eq!(
                                tokens.key_id,
                                u64::from(key_id),
                                "refresh keeps the same key"
                            );
                            sequences.lock().push(data.sequence_number);
                            destinations.push(message.destination_endpoint);
                        }
                    }
                    at = first_secure_prefix_from(datagram, decoded.end);
                }
            }
            destinations.sort_unstable();
            destinations
        };

        let mut announced = HashSet::new();
        distribute(&suite, &ours, &transport, &registry, &mut announced, now);
        let mut expected = vec![reader_one.as_bytes(), reader_two.as_bytes()];
        expected.sort_unstable();
        assert_eq!(
            destinations_received(),
            expected,
            "one message per matched reader of the peer, each naming it"
        );

        distribute(&suite, &ours, &transport, &registry, &mut announced, now);
        assert!(
            destinations_received().is_empty(),
            "written once: a second sweep writes nothing"
        );
        // A genuine rematch of just one pair, even if the sweeper never
        // saw its absence. Same GUIDs and key, but a fresh DATA identity.
        endpoints.1.lock().insert(reader_one, 1);
        assert_eq!(
            distribute(&suite, &ours, &transport, &registry, &mut announced, now),
            1
        );
        assert_eq!(destinations_received(), vec![reader_one.as_bytes()]);
        assert_eq!(
            distribute(&suite, &ours, &transport, &registry, &mut announced, now),
            0
        );
        assert!(destinations_received().is_empty());
        assert_eq!(
            announced.len(),
            3,
            "obsolete event generations leave the announced set"
        );
        let last_identity = *sequences.lock().last().unwrap();
        // No new sender-side match. The receiver may learn the source only
        // after consuming its old hold, so it still needs a fresh message.
        let later = now + crate::security::volatile_channel::PENDING_MATCH_TIMEOUT;
        assert_eq!(
            distribute(&suite, &ours, &transport, &registry, &mut announced, later),
            2,
            "only USER pairs refresh; builtin keys keep their announcement"
        );
        assert_eq!(destinations_received(), expected);
        assert!(sequences
            .lock()
            .iter()
            .rev()
            .take(2)
            .all(|sn| *sn > last_identity));
        assert_eq!(
            distribute(&suite, &ours, &transport, &registry, &mut announced, later),
            0
        );
        assert!(destinations_received().is_empty());
        assert_eq!(announced.len(), 3, "old refresh generations are pruned");

        // Fill the retained history; these extra changes are not sent to
        // the probe. A cumulative ACK will free exactly two slots.
        {
            let mut history = suite.volatile.writer.lock();
            let spare =
                crate::security::volatile_channel::MAX_UNACKED_PER_READER - history.unacked(&peer);
            for _ in 0..spare {
                history
                    .write(&ours, peer, &kx, later, |sn| {
                        crate::security::crypto::volatile::protect_message(&kx, sn, b"held")
                    })
                    .unwrap();
            }
            history.on_acknack(&ours, peer, &kx, later, 3, &[], 1, &suite.volatile.stats);
        }
        let builtin = GUID::new(
            ours,
            crate::core::rtps_constants::RTPS_ENTITYID_SPDP_SECURE_WRITER,
        );
        let (new_builtin_id, new_builtin_key) = WriterKey::mint().unwrap();
        suite
            .data_keys
            .insert(builtin, u64::from(new_builtin_id), new_builtin_key)
            .unwrap();
        let new_writer = GUID::new(ours, [0, 0, 10, 0x02]);
        endpoints.0.lock().insert(new_writer, vec![reader_one]);
        let (new_id, new_key) = WriterKey::mint().unwrap();
        suite
            .data_keys
            .insert(new_writer, u64::from(new_id), new_key)
            .unwrap();
        all_sources.lock().clear();
        let next = later + crate::security::volatile_channel::PENDING_MATCH_TIMEOUT;
        assert_eq!(
            distribute(&suite, &ours, &transport, &registry, &mut announced, next),
            2
        );
        assert!(
            destinations_received().is_empty(),
            "refreshes cannot take the new keys' slots"
        );
        let mut delivered_sources = all_sources.lock().clone();
        delivered_sources.sort_unstable();
        let mut new_sources = vec![builtin.as_bytes(), new_writer.as_bytes()];
        new_sources.sort_unstable();
        assert_eq!(
            delivered_sources, new_sources,
            "new builtin and USER keys make progress after saturation"
        );
        assert_eq!(announced.len(), 4);

        // One original pair refreshes; the other keeps its older generation
        // while full, so it gets the next slot even in a newer lifetime.
        suite.volatile.writer.lock().on_acknack(
            &ours,
            peer,
            &kx,
            next,
            4,
            &[],
            2,
            &suite.volatile.stats,
        );
        assert_eq!(
            distribute(&suite, &ours, &transport, &registry, &mut announced, next),
            1
        );
        assert_eq!(destinations_received(), vec![reader_one.as_bytes()]);
        let newest = next + crate::security::volatile_channel::PENDING_MATCH_TIMEOUT;
        suite.volatile.writer.lock().on_acknack(
            &ours,
            peer,
            &kx,
            newest,
            5,
            &[],
            3,
            &suite.volatile.stats,
        );
        assert_eq!(
            distribute(&suite, &ours, &transport, &registry, &mut announced, newest),
            1
        );
        assert_eq!(
            destinations_received(),
            vec![reader_two.as_bytes()],
            "oldest refresh has priority"
        );
        assert_eq!(
            announced.len(),
            4,
            "one successful generation per pair is retained"
        );
    }
}
