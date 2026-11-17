// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! SHM Transport Policy and Selection
//!
//! This module provides policy-based transport selection for choosing between
//! SHM (Shared Memory) and UDP transport based on configuration and capabilities.
//!
//! # Policies
//!
//! - `Prefer`: Use SHM if same-host + BestEffort QoS, fallback to UDP otherwise
//! - `Require`: Force SHM usage, fail if conditions not met
//! - `Disable`: Always use UDP, even when SHM is available

use super::{
    can_use_shm_transport, colocation_is_provable, host_id, nonce_is_trustworthy, parse_shm_nonce,
};

/// The SHM data path IS connected to the writer/reader engine.
///
/// A local writer whose per-peer verdict is `TransportSelection::Shm` hands
/// the finished RTPS packet to its own shared-memory ring instead of calling
/// `send_user_data_unicast` for that reader (`dds/writer/runtime.rs`), and
/// the participant's SHM poller thread pushes what it pops onto the very
/// ring the Router already consumes (`transport/shm/receiver.rs`), so the
/// whole receive pipeline (dedup, reorder, filters, listeners) runs
/// unchanged and never learns where the bytes came from.
///
/// Consulted by `can_use_shm_transport` (gate 0a), which is the single place
/// SHM is ever proposed under `Prefer`. Flipping this back to `false`
/// disables SHM selection everywhere in one edit.
pub(crate) const fn shm_data_path_is_wired() -> bool {
    true
}

/// `ShmPolicy::Require` is still refused by `ParticipantBuilder::build()`.
///
/// `Require` means "never move a sample over UDP behind my back". One
/// gap remains, and it is a property of the SAMPLE, not of the
/// configuration, so it cannot be checked at build time nor refused
/// per-peer at pairing the way a cross-host peer is:
///
/// **Fragmented samples stay on UDP.** The wired leg is the small-DATA leg
/// (`send_packet_to_endpoints`). `send_packets_to_endpoints`, which carries
/// every sample past `DEFAULT_MAX_UNFRAGMENTED_SIZE` (8192) as DATA_FRAG, is
/// not wired to shared memory at all. A participant that writes only small
/// samples never touches this; one that writes a 10 KB sample silently gets
/// UDP for it, which is exactly what `Require` forbids. `build()` cannot
/// know which of the two a given participant will be.
///
/// What is NOT a reason: the slot ceiling. `SLOT_PAYLOAD_SIZE` is
/// sized to hold every packet the unfragmented leg can produce, with the
/// margin measured by
/// `tests::slot_holds_every_unfragmented_data_packet`, so the leg's size
/// guard is unreachable for that whole band rather than being a routine
/// fallback. It survives as a counted, error-logged guard
/// (`global_metrics().oversize_refused()`) against the budget being
/// outgrown, not as an expected path.
///
/// Wiring the DATA_FRAG leg is what makes `Require` honourable; flipping
/// this to `true` is the same commit.
pub(crate) const fn shm_require_is_honourable() -> bool {
    false
}

/// SHM transport selection policy
///
/// Controls how the transport layer chooses between SHM and UDP.
///
/// # Current status
///
/// The data path is wired (see [`shm_data_path_is_wired`]): a BEST_EFFORT
/// writer paired with a co-located BEST_EFFORT reader moves DATA over shared
/// memory. The control plane (HEARTBEAT, ACKNACK, NACK_FRAG, all of
/// discovery) stays on UDP by design, which costs nothing because SHM is
/// confined to BEST_EFFORT on both sides.
///
/// [`ShmPolicy::Require`] is still refused by `ParticipantBuilder::build()`
/// -- see [`shm_require_is_honourable`] for exactly what the wired leg does
/// not cover.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ShmPolicy {
    /// Advertise SHM capability over SEDP and PROPOSE shared memory for DATA
    /// whenever a pairing looks eligible: matching `host_id` (a filter, not
    /// proof -- see `super::host_id`'s doc), both sides announcing a
    /// trustworthy nonce, and both sides BEST_EFFORT. A pairing that does not
    /// qualify uses UDP, decided ONCE at pairing. This verdict is still
    /// provisional: the actual proof of co-location is the reader's nonce-
    /// authenticated segment attach, which runs afterwards and keeps
    /// the pairing on UDP, loudly, if it cannot succeed (see
    /// `transport/shm/receiver.rs`). After that proof, a sample that still
    /// cannot cross shared memory is never silently rerouted: every such
    /// case is counted in `global_metrics()` and logged.
    ///
    /// Shared memory is opt-in (the default is [`ShmPolicy::Disable`]). The
    /// following mitigations are in place:
    ///
    /// * **Silent total loss.** The writer does not treat a push into its
    ///   own ring as delivery. It keeps the UDP leg for any peer that has
    ///   not claimed an entry in the segment's presence table, so a peer that
    ///   selected shared memory and cannot attach keeps receiving samples
    ///   instead of losing them. A wrong co-location verdict degrades to
    ///   "never attaches, stays on UDP" rather than to data loss.
    /// * **Unauthenticated segment.** The segment name is derivable from
    ///   discovery and `/dev/shm` is world-writable, so the name proved
    ///   nothing about who created it. The control block carries the
    ///   owner's GUID and a per-participant nonce announced over discovery,
    ///   and a reader refuses a segment that does not match.
    /// * **Unvalidated geometry.** The object's real size is checked
    ///   before mapping and `slot_size` against the local constant on attach,
    ///   so a short or foreign segment is refused rather than turning into a
    ///   SIGBUS in the reader's poller thread.
    ///
    /// It stays opt-in because those mitigations are not yet considered
    /// complete: the presence table a writer trusts is itself unauthenticated, so
    /// forging a claim blackholes a real peer; the size check does not stop a
    /// SIGBUS because the object can be shrunk AFTER it is mapped; and the
    /// per-packet push memoisation can credit a peer with a push that happened
    /// before that peer's cursor was set, which loses a sample. It becomes the
    /// default only once those cases are closed with tests.
    Prefer,

    /// Intended to force SHM transport and fail if conditions are not met.
    /// `ParticipantBuilder::build()` refuses it: the wired leg still carries
    /// every fragmented sample over UDP, and whether a participant will ever
    /// write one is not knowable at build time. See
    /// [`shm_require_is_honourable`].
    Require,

    /// Disable SHM: do not advertise SHM capability over SEDP, and never
    /// select shared memory for any peer.
    ///
    /// Useful for:
    /// - Debugging transport issues
    /// - Cross-machine deployments
    /// - Not leaking a capability tag to peers when SHM is unwanted
    ///
    /// This is the default: see [`ShmPolicy::Prefer`] for the guarantees
    /// that are not yet complete.
    #[default]
    Disable,
}

/// Selected transport type
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportSelection {
    /// Use shared memory transport
    Shm {
        /// Host ID for verification
        host_id: u32,
    },
    /// Use UDP transport
    Udp,
}

/// Error when transport selection fails
#[derive(Debug, Clone)]
pub enum TransportSelectionError {
    /// SHM required but not available (different host)
    DifferentHost { local: u32, remote: u32 },
    /// SHM required but QoS is Reliable
    ReliableQosNotSupported,
    /// SHM required but remote doesn't advertise capability
    RemoteNoShmCapability,
    /// SHM required but remote user_data is missing
    NoUserData,
    /// SHM required but this process cannot prove which shared-memory realm
    /// it lives in (`/proc/self/ns/ipc` or `/proc/self/ns/mnt` unreadable),
    /// so a matching host id would not prove co-location.
    ColocationNotProvable,
    /// SHM required but this process drew no trustworthy nonce (see
    /// `nonce_is_trustworthy`): the segments it creates could never be
    /// authenticated by any peer, so shared memory is refused for every
    /// pairing, not just this one. Already logged at error level once, from
    /// `local_nonce()`, the moment it happened.
    LocalNonceUntrustworthy,
    /// SHM required but the remote announced no usable nonce: a
    /// `host_id` match is not proof of co-location, and without a nonce the
    /// reader could never authenticate the segment even if it did attach.
    /// Checked ahead of `DifferentHost` on purpose -- see
    /// `can_use_shm_transport`'s doc.
    RemoteNoNonce,
}

impl std::fmt::Display for TransportSelectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DifferentHost { local, remote } => {
                write!(
                    f,
                    "SHM required but endpoints on different hosts (local={local:08x}, remote={remote:08x})"
                )
            }
            Self::ReliableQosNotSupported => {
                write!(f, "SHM transport does not support Reliable QoS")
            }
            Self::RemoteNoShmCapability => {
                write!(
                    f,
                    "SHM required but remote endpoint doesn't advertise SHM capability"
                )
            }
            Self::NoUserData => {
                write!(f, "SHM required but remote user_data is missing")
            }
            Self::ColocationNotProvable => {
                write!(
                    f,
                    "SHM required but co-location cannot be proven: /proc/self/ns/ipc or \
                     /proc/self/ns/mnt is unreadable, so a matching host id does not mean \
                     the peers share a /dev/shm"
                )
            }
            Self::LocalNonceUntrustworthy => {
                write!(
                    f,
                    "SHM required but this process drew no trustworthy nonce; a segment it \
                     creates could never be authenticated by a peer"
                )
            }
            Self::RemoteNoNonce => {
                write!(
                    f,
                    "SHM required but the remote announced no usable nonce; a matching host id \
                     does not prove co-location and the segment could never be authenticated"
                )
            }
        }
    }
}

impl std::error::Error for TransportSelectionError {}

/// Select transport based on policy and endpoint capabilities.
///
/// # Arguments
///
/// * `policy` - The configured SHM policy
/// * `remote_user_data` - Remote endpoint's user_data from SEDP (contains SHM info)
/// * `local_best_effort` - Whether local endpoint uses BestEffort QoS
/// * `remote_best_effort` - Whether remote endpoint uses BestEffort QoS
///
/// # Returns
///
/// * `Ok(TransportSelection)` - Selected transport type
/// * `Err(TransportSelectionError)` - If policy is `Require` and conditions not met
///
/// # Example
///
/// ```ignore
/// use hdds::transport::shm::{ShmPolicy, select_transport};
///
/// let selection = select_transport(
///     ShmPolicy::Prefer,
///     Some("shm=1;host_id=12345678;v=1"),
///     true,  // local BestEffort
///     true,  // remote BestEffort
/// );
/// ```
pub fn select_transport(
    policy: ShmPolicy,
    remote_user_data: Option<&str>,
    local_best_effort: bool,
    remote_best_effort: bool,
) -> Result<TransportSelection, TransportSelectionError> {
    match policy {
        ShmPolicy::Disable => Ok(TransportSelection::Udp),

        ShmPolicy::Prefer => {
            // Try SHM, fallback to UDP
            match can_use_shm_transport(remote_user_data, local_best_effort, remote_best_effort) {
                Some(host) => Ok(TransportSelection::Shm { host_id: host }),
                None => Ok(TransportSelection::Udp),
            }
        }

        ShmPolicy::Require => {
            // Check QoS first
            if !local_best_effort || !remote_best_effort {
                return Err(TransportSelectionError::ReliableQosNotSupported);
            }

            // Matching host ids only mean co-location when this process can
            // prove which shared-memory realm it is in. Two containers from
            // one image share /etc/machine-id; without a readable
            // /proc/self/ns/{ipc,mnt} they would agree they are co-located
            // and open into nothing. Refuse instead of guessing.
            if !colocation_is_provable() {
                return Err(TransportSelectionError::ColocationNotProvable);
            }

            // Check user_data presence
            let user_data = remote_user_data.ok_or(TransportSelectionError::NoUserData)?;

            // Parse SHM capability
            let (remote_host, _version) = super::parse_shm_user_data(user_data)
                .ok_or(TransportSelectionError::RemoteNoShmCapability)?;

            // Nonce capability, checked AHEAD of the host_id comparison.
            // A `host_id` match is an inference, never proof (see
            // `can_use_shm_transport`'s doc); without a trustworthy nonce on
            // BOTH sides the attach that would actually prove co-location
            // can never succeed, so `Require` must refuse here rather
            // than report success for a pairing that can never really use
            // shared memory.
            if !nonce_is_trustworthy() {
                return Err(TransportSelectionError::LocalNonceUntrustworthy);
            }
            if parse_shm_nonce(user_data).is_none() {
                return Err(TransportSelectionError::RemoteNoNonce);
            }

            // Check same host
            let local_host = host_id();
            if remote_host != local_host {
                return Err(TransportSelectionError::DifferentHost {
                    local: local_host,
                    remote: remote_host,
                });
            }

            Ok(TransportSelection::Shm {
                host_id: local_host,
            })
        }
    }
}

impl ShmPolicy {
    /// Which policy an ENDPOINT runs under, given its own setting and its
    /// participant's.
    ///
    /// `endpoint` is `None` when the writer or reader never called
    /// `shm_policy()`; `participant` is `None` when the endpoint has no
    /// participant at all. The more specific setting wins, and absence of
    /// everything means no shared memory.
    ///
    /// A pure function so the rule can be TESTED. The builders each had their
    /// own copy of it, one of which read the participant unconditionally and
    /// threw the endpoint's answer away.
    #[must_use]
    pub fn resolve(endpoint: Option<Self>, participant: Option<Self>) -> Self {
        endpoint.or(participant).unwrap_or(Self::Disable)
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_support::NotifyGoneOnDrop;
    use super::*;

    /// A capability string that passes every gate `select_transport`
    /// checks, including the nonce gate: `format_shm_user_data` is what
    /// this process itself announces, so it carries a trustworthy nonce
    /// alongside a `host_id` that matches `host_id()` by construction.
    fn local_shm_user_data() -> String {
        super::super::format_shm_user_data()
    }

    /// The RTPS framing overhead a shared-memory slot has to absorb, for a
    /// given user payload. Built with the REAL builder the writer uses, so
    /// this measures rather than models.
    fn framed_len(topic: &str, payload_len: usize) -> usize {
        use crate::protocol::builder::{build_data_packet_with_context, RtpsEndpointContext};
        let ctx = RtpsEndpointContext {
            guid_prefix: [
                0x01, 0x1A, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
            ],
            reader_entity_id: [0, 0, 0, 0],
            writer_entity_id: [0, 0, 0x01, 0x02],
            encapsulation_kind: 0x0009,
            publisher_entity_id: [0x00, 0x00, 0x01, 0x08],
        };
        let payload = vec![0xABu8; payload_len];
        let packet =
            build_data_packet_with_context(&ctx, topic, 1, &payload, crate::dds::CdrVersion::Xcdr2);
        assert!(!packet.is_empty(), "builder produced no packet");
        packet.len()
    }

    /// MEASURE the framing overhead a slot has to absorb, rather than
    /// asserting a guessed number.
    ///
    /// The leg pushes the COMPLETE framed RTPS packet, so what fits is not
    /// `SLOT_PAYLOAD_SIZE` of user data: the RTPS header, the INFO_TS
    /// submessage, the DATA submessage header and the endpoint's inline QoS
    /// all come out of the same slot, and inline QoS is not a constant (it
    /// carries the topic name). This walks the real builder and prints the
    /// frontier, which is the number to quote.
    #[test]
    fn slot_capacity_frontier_is_measured_not_guessed() {
        use crate::transport::shm::SLOT_PAYLOAD_SIZE;

        let topic = "ShmDataPathProbe";
        let mut largest_fitting_payload: Option<usize> = None;
        let mut smallest_refused_payload: Option<usize> = None;
        for payload_len in 0..=SLOT_PAYLOAD_SIZE {
            if framed_len(topic, payload_len) <= SLOT_PAYLOAD_SIZE {
                largest_fitting_payload = Some(payload_len);
            } else if smallest_refused_payload.is_none() {
                smallest_refused_payload = Some(payload_len);
            }
        }

        let frontier = largest_fitting_payload.expect("no payload size fits a slot at all");
        let refused = smallest_refused_payload.expect("no payload size overflows a slot");
        let overhead = SLOT_PAYLOAD_SIZE - frontier;
        println!(
            "SHM frontier for topic '{topic}': largest user payload whose framed DATA fits one \
             {SLOT_PAYLOAD_SIZE}-byte slot = {frontier} bytes (first refused: {refused}, \
             framing overhead: {overhead} bytes)"
        );

        assert_eq!(
            refused,
            frontier + 1,
            "the fit/no-fit boundary must be a single frontier, not a ragged band"
        );
        assert!(
            overhead < 512,
            "framing overhead of {overhead} bytes is implausibly large"
        );
    }

    /// The property the writer leg actually depends on: a packet the size
    /// guard admits can NEVER produce `PayloadTooLarge`, and the guard is
    /// UNREACHABLE for every packet the UDP path emits as a single DATA.
    ///
    /// RTPS emits one unfragmented DATA up to
    /// `DEFAULT_MAX_UNFRAGMENTED_SIZE` of payload and fragments past it into
    /// `DEFAULT_FRAGMENT_SIZE` pieces, so covering `0..=8192` plus one
    /// fragment covers everything the writer can hand the SHM leg. If this
    /// test fails, the SLOT_PAYLOAD_SIZE budget has been outgrown and the
    /// leg would start falling back to UDP for large samples -- which is why
    /// the assertion is here and not a comment.
    #[test]
    fn slot_holds_every_unfragmented_data_packet() {
        use crate::protocol::builder::{DEFAULT_FRAGMENT_SIZE, DEFAULT_MAX_UNFRAGMENTED_SIZE};
        use crate::transport::shm::SLOT_PAYLOAD_SIZE;

        let topic = "ShmDataPathProbe";
        let mut worst = 0usize;
        let mut worst_payload = 0usize;
        for payload_len in 0..=DEFAULT_MAX_UNFRAGMENTED_SIZE {
            let framed = framed_len(topic, payload_len);
            if framed > worst {
                worst = framed;
                worst_payload = payload_len;
            }
        }
        println!(
            "largest framed unfragmented DATA: {worst} bytes (payload {worst_payload}) vs \
             {SLOT_PAYLOAD_SIZE} byte slot; headroom {} bytes",
            SLOT_PAYLOAD_SIZE.saturating_sub(worst)
        );
        assert!(
            worst <= SLOT_PAYLOAD_SIZE,
            "a {worst} byte framed DATA (payload {worst_payload}) does not fit the \
             {SLOT_PAYLOAD_SIZE} byte slot: the shared-memory leg would silently fall back to \
             UDP for large samples"
        );
        assert!(
            framed_len(topic, DEFAULT_FRAGMENT_SIZE) <= SLOT_PAYLOAD_SIZE,
            "a single RTPS fragment must fit a slot with room to spare"
        );

        // And the ring itself accepts them: the guard is the ring's own
        // limit, not a number that happens to look like it.
        let _notify_guard = NotifyGoneOnDrop::topic(0, "shm_frontier_probe");
        let guid = crate::core::discovery::GUID::from_bytes([0xF0; 16]);
        let mut writer =
            crate::transport::shm::ShmWriterTransport::new(0, guid, "shm_frontier_probe")
                .expect("writer transport");
        for payload_len in [0, 1, DEFAULT_FRAGMENT_SIZE, DEFAULT_MAX_UNFRAGMENTED_SIZE] {
            let payload = vec![0xABu8; payload_len];
            let packet = crate::protocol::builder::build_data_packet_with_context(
                &crate::protocol::builder::RtpsEndpointContext {
                    guid_prefix: [
                        0x01, 0x1A, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
                    ],
                    reader_entity_id: [0, 0, 0, 0],
                    writer_entity_id: [0, 0, 0x01, 0x02],
                    encapsulation_kind: 0x0009,
                    publisher_entity_id: [0x00, 0x00, 0x01, 0x08],
                },
                topic,
                1,
                &payload,
                crate::dds::CdrVersion::Xcdr2,
            );
            writer.write(&packet).unwrap_or_else(|err| {
                panic!(
                    "payload {payload_len} framed to {} bytes and was refused by the ring: {err}",
                    packet.len()
                )
            });
        }
    }

    #[test]
    fn shm_is_opt_in_while_its_guarantees_are_incomplete() {
        // The default stays `Disable` because the mitigations for silent
        // total loss, unauthenticated segments and unvalidated geometry are
        // incomplete: the presence table the writer trusts is
        // unauthenticated, the size check does not stop a SIGBUS from a
        // shrink-after-map, and the push memoisation can lose a sample at the
        // handover. Change it only together with the tests that close
        // those, and never on its own.
        assert_eq!(ShmPolicy::default(), ShmPolicy::Disable);
    }

    #[test]
    fn test_disable_always_udp() {
        let result = select_transport(ShmPolicy::Disable, Some(&local_shm_user_data()), true, true);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), TransportSelection::Udp);
    }

    #[test]
    fn test_prefer_uses_shm_when_available() {
        let result = select_transport(ShmPolicy::Prefer, Some(&local_shm_user_data()), true, true);
        assert!(result.is_ok());
        match result.unwrap() {
            TransportSelection::Shm { host_id: h } => assert_eq!(h, host_id()),
            TransportSelection::Udp => panic!("Expected SHM"),
        }
    }

    #[test]
    fn test_prefer_falls_back_to_udp_reliable() {
        let result = select_transport(
            ShmPolicy::Prefer,
            Some(&local_shm_user_data()),
            false, // Reliable
            true,
        );
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), TransportSelection::Udp);
    }

    #[test]
    fn test_prefer_falls_back_to_udp_different_host() {
        let result = select_transport(
            ShmPolicy::Prefer,
            Some("shm=1;host_id=deadbeef;v=1"), // Different host
            true,
            true,
        );
        assert!(result.is_ok());
        // @audit-ok: guard against unlikely collision with test sentinel
        if host_id() != 0xDEAD_BEEF {
            assert_eq!(result.unwrap(), TransportSelection::Udp);
        }
    }

    #[test]
    fn test_prefer_falls_back_to_udp_no_capability() {
        let result = select_transport(
            ShmPolicy::Prefer,
            Some("other=value"), // No SHM capability
            true,
            true,
        );
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), TransportSelection::Udp);
    }

    #[test]
    fn test_prefer_falls_back_to_udp_no_user_data() {
        let result = select_transport(ShmPolicy::Prefer, None, true, true);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), TransportSelection::Udp);
    }

    #[test]
    fn test_require_succeeds_when_available() {
        let result = select_transport(ShmPolicy::Require, Some(&local_shm_user_data()), true, true);
        assert!(result.is_ok());
        match result.unwrap() {
            TransportSelection::Shm { host_id: h } => assert_eq!(h, host_id()),
            TransportSelection::Udp => panic!("Expected SHM"),
        }
    }

    #[test]
    fn test_require_fails_reliable_qos() {
        let result = select_transport(
            ShmPolicy::Require,
            Some(&local_shm_user_data()),
            false, // Reliable
            true,
        );
        assert!(result.is_err());
        match result.unwrap_err() {
            TransportSelectionError::ReliableQosNotSupported => {}
            e => panic!("Expected ReliableQosNotSupported, got: {e:?}"),
        }
    }

    #[test]
    fn test_require_fails_different_host() {
        // Carries a trustworthy-looking nonce so this exercises the
        // `DifferentHost` path specifically, past the nonce gate -- see
        // `test_require_fails_no_nonce` for that gate on its own.
        let result = select_transport(
            ShmPolicy::Require,
            Some("shm=1;host_id=deadbeef;nonce=abadbabefeedface;v=1"),
            true,
            true,
        );
        // @audit-ok: guard + sentinel for different-host error path validation
        if host_id() != 0xDEAD_BEEF {
            assert!(result.is_err());
            match result.unwrap_err() {
                TransportSelectionError::DifferentHost { local, remote } => {
                    assert_eq!(local, host_id());
                    assert_eq!(remote, 0xDEAD_BEEF);
                }
                e => panic!("Expected DifferentHost, got: {e:?}"),
            }
        }
    }

    #[test]
    fn test_require_fails_no_capability() {
        let result = select_transport(ShmPolicy::Require, Some("other=value"), true, true);
        assert!(result.is_err());
        match result.unwrap_err() {
            TransportSelectionError::RemoteNoShmCapability => {}
            e => panic!("Expected RemoteNoShmCapability, got: {e:?}"),
        }
    }

    #[test]
    fn test_require_fails_no_user_data() {
        let result = select_transport(ShmPolicy::Require, None, true, true);
        assert!(result.is_err());
        match result.unwrap_err() {
            TransportSelectionError::NoUserData => {}
            e => panic!("Expected NoUserData, got: {e:?}"),
        }
    }

    /// A `host_id` match with no announced nonce must be refused
    /// BEFORE the host_id comparison is even reached, because a `host_id`
    /// match alone is an inference, never proof, and this peer could not be
    /// authenticated by an attach regardless of what `host_id` says.
    #[test]
    fn test_require_fails_no_nonce() {
        let user_data = format!("shm=1;host_id={:08x};v=1", host_id());
        let result = select_transport(ShmPolicy::Require, Some(&user_data), true, true);
        assert!(result.is_err());
        match result.unwrap_err() {
            TransportSelectionError::RemoteNoNonce => {}
            e => panic!("Expected RemoteNoNonce, got: {e:?}"),
        }
    }

    /// Same, for an explicitly-zero nonce (`parse_shm_nonce` treats zero as
    /// "no nonce", matching `nonce_is_trustworthy` on the local side).
    #[test]
    fn test_require_fails_zero_nonce() {
        let user_data = format!("shm=1;host_id={:08x};nonce=0000000000000000;v=1", host_id());
        let result = select_transport(ShmPolicy::Require, Some(&user_data), true, true);
        assert!(result.is_err());
        match result.unwrap_err() {
            TransportSelectionError::RemoteNoNonce => {}
            e => panic!("Expected RemoteNoNonce, got: {e:?}"),
        }
    }

    #[test]
    fn test_transport_selection_display() {
        // @audit-ok: arbitrary test value for Debug formatting check
        let shm = TransportSelection::Shm {
            host_id: 0x12345678,
        };
        let udp = TransportSelection::Udp;

        assert_eq!(format!("{shm:?}"), "Shm { host_id: 305419896 }");
        assert_eq!(format!("{udp:?}"), "Udp");
    }

    #[test]
    fn test_error_display() {
        let e1 = TransportSelectionError::DifferentHost {
            local: 0x1111,
            remote: 0x2222,
        };
        assert!(e1.to_string().contains("different hosts"));

        let e2 = TransportSelectionError::ReliableQosNotSupported;
        assert!(e2.to_string().contains("Reliable QoS"));

        let e3 = TransportSelectionError::RemoteNoShmCapability;
        assert!(e3.to_string().contains("SHM capability"));

        let e4 = TransportSelectionError::NoUserData;
        assert!(e4.to_string().contains("user_data"));
    }
}

#[cfg(test)]
mod endpoint_policy_tests {
    use super::ShmPolicy;

    /// The endpoint's own setting wins over the participant's, in BOTH
    /// directions: a builder reading the participant unconditionally would
    /// give an application that turned shared memory off for one writer
    /// shared memory anyway.
    #[test]
    fn an_endpoints_own_policy_overrides_its_participants() {
        assert_eq!(
            ShmPolicy::resolve(Some(ShmPolicy::Disable), Some(ShmPolicy::Prefer)),
            ShmPolicy::Disable,
            "a writer that asked for Disable must not inherit Prefer"
        );
        assert_eq!(
            ShmPolicy::resolve(Some(ShmPolicy::Prefer), Some(ShmPolicy::Disable)),
            ShmPolicy::Prefer
        );
    }

    /// Unset inherits, which is what every caller written before the override
    /// existed relies on.
    #[test]
    fn an_endpoint_that_asked_for_nothing_follows_its_participant() {
        assert_eq!(
            ShmPolicy::resolve(None, Some(ShmPolicy::Prefer)),
            ShmPolicy::Prefer
        );
        assert_eq!(
            ShmPolicy::resolve(None, Some(ShmPolicy::Disable)),
            ShmPolicy::Disable
        );
    }

    /// No participant at all means no shared memory - never the enum default,
    /// which is a different question.
    #[test]
    fn no_participant_means_no_shared_memory() {
        assert_eq!(ShmPolicy::resolve(None, None), ShmPolicy::Disable);
        assert_eq!(
            ShmPolicy::resolve(Some(ShmPolicy::Prefer), None),
            ShmPolicy::Prefer,
            "an explicit ask still stands on its own"
        );
    }
}
