// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! The reader-side effects of the HEARTBEATs and GAPs a datagram carries,
//! applied by the two doors that receive user data: the unicast door
//! (`unicast_router`, TCP and QUIC, where nothing else applies them) and the
//! UDP Router (`router`, for user writers, whose controls ride the receive
//! ring behind the DATA they follow).
//!
//! Builtin writers (SPDP, SEDP, participant message, type lookup, secure
//! builtins) keep their controls on the UDP control thread, as before.
//! `Scope` says which writers a door applies.
//!
//! Perimeter of the ordering: the order is restored within ONE receive thread
//! (one socket, one datagram, its DATA before its controls). Across two
//! sockets there is no wire order to restore, and nothing is claimed for it.
//! Known difference: a DATA and a GAP inside one datagram are applied DATA
//! first, whatever their position in the datagram. The other order would hold
//! the DATA behind a GAP that declares it irrelevant and deliver less.

use crate::core::discovery::multicast::control::{
    release_group_reorder_gate, renew_heartbeat_liveliness, seed_reorder_gate,
};
use crate::core::discovery::multicast::control_parser::scan_all_embedded_control_submessages;
use crate::core::discovery::multicast::{Origin, PacketKind};
use crate::engine::demux::TopicRegistry;
use crate::engine::router::RouterMetrics;
use crate::engine::unicast_router::Answer;
use std::sync::atomic::Ordering;

/// Which writers' controls a door applies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Scope {
    /// Every writer. The unicast door has no control thread to leave the
    /// builtin ones to.
    All,
    /// User writers only. The UDP control thread applies the builtin ones.
    UserWriters,
}

/// Whether `entity` names a user endpoint: its entityKind byte does not carry
/// both top bits (RTPS v2.5 Sec.9.3.1.2; builtin kinds are 0xc0 and up).
pub(crate) fn user_writer(entity: &[u8; 4]) -> bool {
    entity[3] & 0xC0 != 0xC0
}

fn in_scope(scope: Scope, writer_entity_id: &[u8; 4]) -> bool {
    match scope {
        Scope::All => true,
        Scope::UserWriters => user_writer(writer_entity_id),
    }
}

/// Apply every HEARTBEAT and GAP of `payload` in `scope` to the readers'
/// reorder gates, through the same two functions the UDP control loop calls
/// (`seed_reorder_gate`, `release_group_reorder_gate`), parsed by the same
/// scanner the UDP listener uses.
///
/// The order is the one of the datagram's own submessages, GAPs first unless
/// the datagram is named by a HEARTBEAT. It is not observable for a received
/// sample: a GAP crossing a never-received sequence and a HEARTBEAT past it
/// release the same samples in either order (`reorder::tests::the_order_of_a_
/// gap_and_a_heartbeat_releases_the_same_samples`), and a HEARTBEAT releases
/// every received sample below its firstSN, in order, losing none (`reorder::
/// tests::a_held_received_sample_below_first_heartbeat_is_released_in_order`).
///
/// The writer's guid prefix is the message header's (`payload[8..20]`), as on
/// the UDP door. Returns (HEARTBEATs applied, GAPs applied).
pub(crate) fn apply_writer_control(
    payload: &[u8],
    registry: &TopicRegistry,
    elected: PacketKind,
    scope: Scope,
) -> (usize, usize) {
    if payload.len() < 20 {
        return (0, 0);
    }
    let mut peer_prefix = [0u8; 12];
    peer_prefix.copy_from_slice(&payload[8..20]);
    let (gaps, heartbeats, _has_nack_frag) = scan_all_embedded_control_submessages(payload);
    let heartbeats: Vec<_> = heartbeats
        .into_iter()
        .filter(|hb| in_scope(scope, &hb.info.writer_entity_id))
        .collect();
    let gaps: Vec<_> = gaps
        .into_iter()
        .filter(|gap| in_scope(scope, &gap.info.writer_entity_id))
        .collect();

    let seed_all = || {
        for hb in &heartbeats {
            seed_reorder_gate(
                registry,
                &peer_prefix,
                &hb.info,
                hb.reader_entity_id,
                hb.group_info,
            );
            // RTPS v2.5 Sec.8.3.7.5: the Liveliness flag renews a
            // MANUAL_BY_TOPIC writer's lease. No transport exception;
            // shared with the UDP control loop (`renew_heartbeat_liveliness`'s
            // own doc) so the rule is never duplicated.
            renew_heartbeat_liveliness(registry, &peer_prefix, &hb.info);
        }
    };
    let release_all = || {
        for gap in &gaps {
            release_group_reorder_gate(
                registry,
                &peer_prefix,
                &gap.info,
                gap.reader_entity_id,
                gap.filtered_count,
                gap.group_info.is_some(),
                gap.group_info,
            );
        }
    };
    if elected == PacketKind::Heartbeat {
        seed_all();
        release_all();
    } else {
        release_all();
        seed_all();
    }
    (heartbeats.len(), gaps.len())
}

/// Controls riding in a datagram this door named after something else - a
/// DATA, a DATA_FRAG, or a GAP with HEARTBEATs behind it: apply them to the
/// reorder gates, then hand any HEARTBEAT among them to the handlers that
/// answer with an ACKNACK, exactly as a HEARTBEAT that leads its datagram is.
/// `deliver_heartbeat` decodes every HEARTBEAT in the datagram, wherever it
/// sits, so passing the whole payload is enough.
pub(crate) fn answer_piggybacked_control(
    payload: &[u8],
    registry: &TopicRegistry,
    metrics: &RouterMetrics,
    elected: PacketKind,
    answer: Answer<'_>,
    scope: Scope,
) {
    let (heartbeats, _gaps) = apply_writer_control(payload, registry, elected, scope);
    if heartbeats > 0 {
        let errors = answer.deliver_heartbeat(registry, payload);
        if errors > 0 {
            metrics
                .delivery_errors
                .fetch_add(errors as u64, Ordering::Relaxed);
        }
    }
}

/// The controls of a datagram the UDP Router routes, for its user writers:
/// their reorder-gate effects, in datagram order behind the DATA. The
/// ACKNACK answer is the control thread's when that thread received the
/// datagram (`control_answers`, `RxMeta`); without one the Router answers
/// as the unicast door does.
pub(crate) fn route_ring_controls(
    payload: &[u8],
    registry: &TopicRegistry,
    metrics: &RouterMetrics,
    elected: PacketKind,
    origin: Origin,
    control_answers: bool,
) {
    if control_answers {
        apply_writer_control(payload, registry, elected, Scope::UserWriters);
        return;
    }
    // No control thread: nobody else answers, so the Router answers every
    // HEARTBEAT of the datagram, builtin writers' included (as it did before
    // the split). Only the user writers' gate effects are applied here.
    apply_writer_control(payload, registry, elected, Scope::UserWriters);
    let carries_heartbeat = elected == PacketKind::Heartbeat
        || !scan_all_embedded_control_submessages(payload).1.is_empty();
    if carries_heartbeat {
        let errors = Answer::Origin(origin).deliver_heartbeat(registry, payload);
        if errors > 0 {
            metrics
                .delivery_errors
                .fetch_add(errors as u64, Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_writer_kinds_are_not_user_writers() {
        assert!(!user_writer(&[0x00, 0x00, 0x03, 0xC2])); // SEDP publications
        assert!(!user_writer(&[0x00, 0x01, 0x00, 0xC2])); // SPDP
        assert!(!user_writer(&[0x00, 0x00, 0x03, 0xC3])); // type lookup
        assert!(user_writer(&[0x00, 0x00, 0x01, 0x02])); // user, no key
        assert!(user_writer(&[0x00, 0x00, 0x01, 0x03])); // user, with key
        assert!(user_writer(&[0x00, 0x00, 0x01, 0x07])); // user, reader-kind byte
    }
}
