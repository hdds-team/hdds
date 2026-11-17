// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! QoS compatibility checking (RxO - Request vs Offered).
//!
//! The request/offered rules of DDS v1.4 Sec.2.2.3, in one list
//! (`first_incompatible`) that both `is_compatible` and
//! `first_incompatible_policy` read, so the verdict and the policy a status
//! reports can never disagree.
//!
//! | Policy            | Rule (offered = writer, requested = reader)          | Sec.     |
//! |-------------------|------------------------------------------------------|----------|
//! | RELIABILITY       | offered kind >= requested (BEST_EFFORT < RELIABLE)    | 2.2.3.14 |
//! | DURABILITY        | offered kind >= requested (VOLATILE < ... PERSISTENT) | 2.2.3.4  |
//! | DEADLINE          | offered period <= requested                           | 2.2.3.7  |
//! | LATENCY_BUDGET    | offered duration <= requested                         | 2.2.3.8  |
//! | OWNERSHIP         | same kind (`first_incompatible_policy` only)          | 2.2.3.9  |
//! | LIVELINESS        | offered kind >= requested, offered lease <= requested | 2.2.3.11 |
//! | DESTINATION_ORDER | offered kind >= requested (RECEPTION < SOURCE)        | 2.2.3.17 |
//! | PRESENTATION      | offered scope >= requested, coherent/ordered offered  | 2.2.3.6  |
//! | PARTITION         | the names match (not a QoS incompatibility)           | 2.2.3.13 |
//!
//! HISTORY, RESOURCE_LIMITS and TIME_BASED_FILTER are not RxO. Ownership is
//! judged by the caller (`match_notification::rxo_verdict`) on the kind as
//! the endpoint announced it; DATA_REPRESENTATION by
//! `cdr_negotiation::pair_effective_cdr_version`.

use crate::dds::qos::{policy_id, Durability, QoS, Reliability};
use log;

/// Durability kinds in the order of DDS v1.4 Sec.2.2.3.4: "VOLATILE <
/// TRANSIENT_LOCAL < TRANSIENT < PERSISTENT".
fn durability_rank(durability: Durability) -> u8 {
    match durability {
        Durability::Volatile => 0,
        Durability::TransientLocal => 1,
        Durability::Transient => 2,
        Durability::Persistent => 3,
    }
}

/// Reliability kinds in the order of DDS v1.4 Sec.2.2.3.14: "BEST_EFFORT <
/// RELIABLE".
fn reliability_rank(reliability: Reliability) -> u8 {
    match reliability {
        Reliability::BestEffort => 0,
        Reliability::Reliable => 1,
    }
}

/// Why a writer's offer does not satisfy a reader's request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Incompatibility {
    /// An RxO policy, by its QosPolicyId_t (DDS v1.4 Sec.2.3.3).
    Policy(u32),
    /// No common partition: the pair does not match, and no
    /// INCOMPATIBLE_QOS status is raised for it.
    Partition,
}

/// The first rule of DDS v1.4 Sec.2.2.3 that `writer_qos` (offered) breaks
/// against `reader_qos` (requested), `None` when it breaks none. OWNERSHIP
/// is checked only when `check_ownership` holds (see the module doc).
fn first_incompatible(
    reader_qos: &QoS,
    writer_qos: &QoS,
    check_ownership: bool,
) -> Option<Incompatibility> {
    let refuse = |id: u32| {
        log::debug!(
            "[MATCH-QOS] {} mismatch (writer={:?}, reader={:?})",
            policy_id::name(id),
            writer_qos,
            reader_qos
        );
        Some(Incompatibility::Policy(id))
    };
    // "offered kind >= requested kind", "BEST_EFFORT < RELIABLE".
    if reliability_rank(writer_qos.reliability) < reliability_rank(reader_qos.reliability) {
        return refuse(policy_id::RELIABILITY);
    }
    // "offered kind >= requested kind", "VOLATILE < TRANSIENT_LOCAL <
    // TRANSIENT < PERSISTENT".
    if durability_rank(writer_qos.durability) < durability_rank(reader_qos.durability) {
        return refuse(policy_id::DURABILITY);
    }
    // "offered deadline period <= requested deadline period".
    if !writer_qos.deadline.is_compatible_with(&reader_qos.deadline) {
        return refuse(policy_id::DEADLINE);
    }
    // "offered duration <= requested duration".
    if !writer_qos
        .latency_budget
        .is_compatible_with(&reader_qos.latency_budget)
    {
        return refuse(policy_id::LATENCY_BUDGET);
    }
    if check_ownership && writer_qos.ownership.kind != reader_qos.ownership.kind {
        return refuse(policy_id::OWNERSHIP);
    }
    // "offered kind >= requested kind", "AUTOMATIC < MANUAL_BY_PARTICIPANT <
    // MANUAL_BY_TOPIC", and "offered lease_duration <= requested
    // lease_duration".
    if !writer_qos
        .liveliness
        .is_compatible_with(&reader_qos.liveliness)
    {
        return refuse(policy_id::LIVELINESS);
    }
    // "offered kind >= requested kind", "BY_RECEPTION_TIMESTAMP <
    // BY_SOURCE_TIMESTAMP".
    if !writer_qos
        .destination_order
        .is_compatible_with(&reader_qos.destination_order)
    {
        return refuse(policy_id::DESTINATION_ORDER);
    }
    // "offered access_scope >= requested access_scope", "INSTANCE < TOPIC <
    // GROUP", and coherent_access / ordered_access requested are offered.
    if !writer_qos
        .presentation
        .is_compatible_with(&reader_qos.presentation)
    {
        return refuse(policy_id::PRESENTATION);
    }
    // PARTITION owns the DDS default normalization and wildcard semantics so
    // wire and local-registry matching cannot diverge.
    if !writer_qos
        .partition
        .is_compatible_with(&reader_qos.partition)
    {
        log::debug!(
            "[MATCH-QOS] Partition mismatch (writer={:?}, reader={:?})",
            writer_qos.partition,
            reader_qos.partition
        );
        return Some(Incompatibility::Partition);
    }
    None
}

/// Whether `writer_qos` (offered) satisfies `reader_qos` (requested) on
/// every rule of DDS v1.4 Sec.2.2.3 but OWNERSHIP (see the module doc).
pub(super) fn is_compatible(reader_qos: &QoS, writer_qos: &QoS) -> bool {
    crate::trace_fn!("qos::is_compatible");
    first_incompatible(reader_qos, writer_qos, false).is_none()
}

/// The QosPolicyId_t (DDS v1.4 Sec.2.3.3) of the first RxO policy
/// `writer_qos` breaks against `reader_qos`, OWNERSHIP included; 0
/// (`INVALID_QOS_POLICY_ID`) when none, a PARTITION mismatch included.
/// DATA_REPRESENTATION (23) is never returned here (see the module doc).
pub(super) fn first_incompatible_policy(reader_qos: &QoS, writer_qos: &QoS) -> u32 {
    match first_incompatible(reader_qos, writer_qos, true) {
        Some(Incompatibility::Policy(id)) => id,
        Some(Incompatibility::Partition) | None => policy_id::INVALID,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dds::qos::{
        Deadline, Durability, History, Liveliness, Ownership, Partition, QoS, Reliability,
    };

    #[test]
    fn test_reliability_best_effort_compatible() {
        let reader = QoS {
            reliability: Reliability::BestEffort,
            ..QoS::default()
        };
        let writer = QoS {
            reliability: Reliability::BestEffort,
            ..QoS::default()
        };
        assert!(is_compatible(&reader, &writer));
    }

    #[test]
    fn test_reliability_best_effort_writer_reliable_reader_incompatible() {
        let reader = QoS {
            reliability: Reliability::Reliable,
            ..QoS::default()
        };
        let writer = QoS {
            reliability: Reliability::BestEffort,
            ..QoS::default()
        };
        assert!(!is_compatible(&reader, &writer));
    }

    #[test]
    fn test_reliability_reliable_writer_best_effort_reader_compatible() {
        let reader = QoS {
            reliability: Reliability::BestEffort,
            ..QoS::default()
        };
        let writer = QoS {
            reliability: Reliability::Reliable,
            ..QoS::default()
        };
        assert!(is_compatible(&reader, &writer));
    }

    #[test]
    fn test_durability_volatile_compatible() {
        let reader = QoS {
            durability: Durability::Volatile,
            ..QoS::default()
        };
        let writer = QoS {
            durability: Durability::Volatile,
            ..QoS::default()
        };
        assert!(is_compatible(&reader, &writer));
    }

    #[test]
    fn test_durability_transient_writer_volatile_reader_compatible() {
        let reader = QoS {
            durability: Durability::Volatile,
            ..QoS::default()
        };
        let writer = QoS {
            durability: Durability::TransientLocal,
            ..QoS::default()
        };
        assert!(is_compatible(&reader, &writer));
    }

    #[test]
    fn test_durability_volatile_writer_transient_reader_incompatible() {
        let reader = QoS {
            durability: Durability::TransientLocal,
            ..QoS::default()
        };
        let writer = QoS {
            durability: Durability::Volatile,
            ..QoS::default()
        };
        assert!(!is_compatible(&reader, &writer));
    }

    #[test]
    fn test_history_writer_greater_compatible() {
        let reader = QoS {
            history: History::KeepLast(5),
            ..QoS::default()
        };
        let writer = QoS {
            history: History::KeepLast(10),
            ..QoS::default()
        };
        assert!(is_compatible(&reader, &writer));
    }

    #[test]
    fn test_history_writer_less_still_compatible() {
        // History is NOT an RxO policy (DDS spec Table 2.60).
        // Different history depths do not affect endpoint matching.
        let reader = QoS {
            history: History::KeepLast(10),
            ..QoS::default()
        };
        let writer = QoS {
            history: History::KeepLast(5),
            ..QoS::default()
        };
        assert!(is_compatible(&reader, &writer));
    }

    #[test]
    fn test_history_keep_all_writer_compatible() {
        let reader = QoS {
            history: History::KeepLast(10),
            ..QoS::default()
        };
        let writer = QoS {
            history: History::KeepAll,
            ..QoS::default()
        };
        assert!(is_compatible(&reader, &writer));
    }

    #[test]
    fn test_history_keep_all_reader_still_compatible() {
        // History is NOT an RxO policy (DDS spec Table 2.60).
        // KeepAll reader + KeepLast writer is still compatible.
        let reader = QoS {
            history: History::KeepAll,
            ..QoS::default()
        };
        let writer = QoS {
            history: History::KeepLast(10),
            ..QoS::default()
        };
        assert!(is_compatible(&reader, &writer));
    }

    #[test]
    fn test_history_keep_all_both_compatible() {
        let reader = QoS {
            history: History::KeepAll,
            ..QoS::default()
        };
        let writer = QoS {
            history: History::KeepAll,
            ..QoS::default()
        };
        assert!(is_compatible(&reader, &writer));
    }

    #[test]
    fn test_deadline_compatible() {
        let reader = QoS {
            deadline: Deadline::from_millis(200),
            ..QoS::default()
        };
        let writer = QoS {
            deadline: Deadline::from_millis(100),
            ..QoS::default()
        };
        assert!(is_compatible(&reader, &writer)); // Writer faster
    }

    #[test]
    fn test_deadline_incompatible() {
        let reader = QoS {
            deadline: Deadline::from_millis(100),
            ..QoS::default()
        };
        let writer = QoS {
            deadline: Deadline::from_millis(200),
            ..QoS::default()
        };
        assert!(!is_compatible(&reader, &writer)); // Writer too slow
    }

    #[test]
    fn test_ownership_shared_compatible() {
        let reader = QoS {
            ownership: Ownership::shared(),
            ..QoS::default()
        };
        let writer = QoS {
            ownership: Ownership::shared(),
            ..QoS::default()
        };
        assert!(is_compatible(&reader, &writer));
    }

    #[test]
    fn test_ownership_exclusive_compatible() {
        let reader = QoS {
            ownership: Ownership::exclusive(),
            ..QoS::default()
        };
        let writer = QoS {
            ownership: Ownership::exclusive(),
            ..QoS::default()
        };
        assert!(is_compatible(&reader, &writer));
    }

    #[test]
    fn test_ownership_mismatch_not_checked_in_is_compatible() {
        // Ownership is NOT checked in is_compatible() -- vendors omit PID_OWNERSHIP
        // from SEDP. Ownership incompatibility is detected by MatchNotificationRegistry
        // which has access to has_explicit_ownership from EndpointInfo.
        let reader = QoS {
            ownership: Ownership::shared(),
            ..QoS::default()
        };
        let writer = QoS {
            ownership: Ownership::exclusive(),
            ..QoS::default()
        };
        assert!(is_compatible(&reader, &writer));
    }

    #[test]
    fn test_liveliness_compatible() {
        let reader = QoS {
            liveliness: Liveliness::automatic_secs(10),
            ..QoS::default()
        };
        let writer = QoS {
            liveliness: Liveliness::automatic_secs(5),
            ..QoS::default()
        };
        assert!(is_compatible(&reader, &writer)); // Writer lease <= reader lease
    }

    #[test]
    fn test_liveliness_lease_incompatible() {
        let reader = QoS {
            liveliness: Liveliness::automatic_secs(5),
            ..QoS::default()
        };
        let writer = QoS {
            liveliness: Liveliness::automatic_secs(10),
            ..QoS::default()
        };
        assert!(!is_compatible(&reader, &writer)); // Writer lease > reader lease
    }

    #[test]
    fn test_partition_both_default_compatible() {
        let reader = QoS {
            partition: Partition::default(),
            ..QoS::default()
        };
        let writer = QoS {
            partition: Partition::default(),
            ..QoS::default()
        };
        assert!(is_compatible(&reader, &writer));
    }

    #[test]
    fn test_partition_default_writer_wildcard_reader_compatible() {
        let reader = QoS {
            partition: Partition::single("*"),
            ..QoS::default()
        };
        let writer = QoS {
            partition: Partition::default(),
            ..QoS::default()
        };
        assert!(is_compatible(&reader, &writer));
    }

    #[test]
    fn test_partition_two_wildcards_incompatible() {
        let reader = QoS {
            partition: Partition::single("sensor?"),
            ..QoS::default()
        };
        let writer = QoS {
            partition: Partition::single("sensor*"),
            ..QoS::default()
        };
        assert!(!is_compatible(&reader, &writer));
    }

    #[test]
    fn test_partition_same_compatible() {
        let reader = QoS {
            partition: Partition::single("sensor"),
            ..QoS::default()
        };
        let writer = QoS {
            partition: Partition::single("sensor"),
            ..QoS::default()
        };
        assert!(is_compatible(&reader, &writer));
    }

    #[test]
    fn test_partition_different_incompatible() {
        let reader = QoS {
            partition: Partition::single("sensor"),
            ..QoS::default()
        };
        let writer = QoS {
            partition: Partition::single("actuator"),
            ..QoS::default()
        };
        assert!(!is_compatible(&reader, &writer));
    }

    #[test]
    fn test_partition_intersection_compatible() {
        let reader = QoS {
            partition: Partition::new(vec!["sensor".to_string(), "actuator".to_string()]),
            ..QoS::default()
        };
        let writer = QoS {
            partition: Partition::single("actuator"),
            ..QoS::default()
        };
        assert!(is_compatible(&reader, &writer));
    }

    #[test]
    fn test_all_policies_compatible() {
        let reader = QoS {
            reliability: Reliability::BestEffort,
            durability: Durability::Volatile,
            history: History::KeepLast(10),
            deadline: Deadline::from_millis(200),
            ownership: Ownership::shared(),
            liveliness: Liveliness::automatic_secs(10),
            partition: Partition::single("sensor"),
            ..QoS::default()
        };
        let writer = QoS {
            reliability: Reliability::BestEffort,
            durability: Durability::Volatile,
            history: History::KeepLast(100),
            deadline: Deadline::from_millis(100),
            ownership: Ownership::shared(),
            liveliness: Liveliness::automatic_secs(5),
            partition: Partition::single("sensor"),
            ..QoS::default()
        };
        assert!(is_compatible(&reader, &writer));
    }

    #[test]
    fn test_multiple_policies_incompatible() {
        let reader = QoS {
            reliability: Reliability::Reliable,
            ownership: Ownership::exclusive(),
            ..QoS::default()
        };
        let writer = QoS {
            reliability: Reliability::BestEffort, // Incompatible
            ownership: Ownership::shared(),       // Incompatible
            ..QoS::default()
        };
        assert!(!is_compatible(&reader, &writer));
    }

    // Presentation QoS tests (DDS v1.4 Sec.2.2.3.6, Table 2.60): every
    // access_scope pairing (INSTANCE/TOPIC/GROUP) a reader and writer can
    // offer/request, under both ORDERED_ACCESS and COHERENT_ACCESS.
    use crate::dds::qos::{Presentation, PresentationAccessScope};

    fn make_qos(p: Presentation) -> QoS {
        QoS {
            presentation: p,
            ..QoS::default()
        }
    }

    #[test]
    fn test_presentation_instance_writer_topic_reader_incompatible() {
        // Writer INSTANCE+ordered, reader TOPIC+ordered: the offered access
        // scope is narrower than the requested one (DDS 2.2.3.6, RxO).
        let writer = make_qos(Presentation::new(
            PresentationAccessScope::Instance,
            false,
            true,
        ));
        let reader = make_qos(Presentation::new(
            PresentationAccessScope::Topic,
            false,
            true,
        ));
        assert!(!is_compatible(&reader, &writer));
        assert_eq!(
            first_incompatible_policy(&reader, &writer),
            policy_id::PRESENTATION
        );
    }

    #[test]
    fn test_presentation_instance_writer_group_reader_incompatible() {
        // Writer INSTANCE+ordered, reader GROUP+ordered: offered scope
        // narrower than requested.
        let writer = make_qos(Presentation::new(
            PresentationAccessScope::Instance,
            false,
            true,
        ));
        let reader = make_qos(Presentation::new(
            PresentationAccessScope::Group,
            false,
            true,
        ));
        assert!(!is_compatible(&reader, &writer));
    }

    #[test]
    fn test_presentation_topic_writer_group_reader_incompatible() {
        // Writer TOPIC+ordered, reader GROUP+ordered: offered scope narrower
        // than requested.
        let writer = make_qos(Presentation::new(
            PresentationAccessScope::Topic,
            false,
            true,
        ));
        let reader = make_qos(Presentation::new(
            PresentationAccessScope::Group,
            false,
            true,
        ));
        assert!(!is_compatible(&reader, &writer));
    }

    #[test]
    fn test_presentation_writer_missing_ordered_incompatible() {
        // Writer TOPIC without ordered_access, reader TOPIC+ordered: the
        // reader requests ordered_access the writer does not offer.
        let writer = make_qos(Presentation::new(
            PresentationAccessScope::Topic,
            false,
            false,
        ));
        let reader = make_qos(Presentation::new(
            PresentationAccessScope::Topic,
            false,
            true,
        ));
        assert!(!is_compatible(&reader, &writer));
    }

    #[test]
    fn test_presentation_coherent_instance_writer_topic_reader_incompatible() {
        // Writer INSTANCE+coherent, reader TOPIC+coherent: offered scope
        // narrower than requested.
        let writer = make_qos(Presentation::new(
            PresentationAccessScope::Instance,
            true,
            false,
        ));
        let reader = make_qos(Presentation::new(
            PresentationAccessScope::Topic,
            true,
            false,
        ));
        assert!(!is_compatible(&reader, &writer));
    }

    #[test]
    fn test_presentation_writer_missing_coherent_incompatible() {
        // Writer TOPIC without coherent_access, reader TOPIC+coherent: the
        // reader requests coherent_access the writer does not offer.
        let writer = make_qos(Presentation::new(
            PresentationAccessScope::Topic,
            false,
            false,
        ));
        let reader = make_qos(Presentation::new(
            PresentationAccessScope::Topic,
            true,
            false,
        ));
        assert!(!is_compatible(&reader, &writer));
    }

    #[test]
    fn test_presentation_group_writer_instance_reader_compatible() {
        // Writer offers more than requested: OK
        let writer = make_qos(Presentation::new(
            PresentationAccessScope::Group,
            true,
            true,
        ));
        let reader = make_qos(Presentation::new(
            PresentationAccessScope::Instance,
            false,
            false,
        ));
        assert!(is_compatible(&reader, &writer));
    }

    // Request/offered rules of the RxO policies (DDS v1.4 Sec.2.2.3), each
    // pinned from both sides, and the QosPolicyId_t each reports
    // (DDS v1.4 Sec.2.3.3).
    use crate::dds::qos::policy_id;
    use crate::dds::qos::{DestinationOrder, LatencyBudget};
    use std::time::Duration;

    fn verdict(writer: &QoS, reader: &QoS) -> (bool, u32) {
        (
            is_compatible(reader, writer),
            first_incompatible_policy(reader, writer),
        )
    }

    /// LIVELINESS: "offered kind >= requested kind" with "AUTOMATIC <
    /// MANUAL_BY_PARTICIPANT < MANUAL_BY_TOPIC", and "offered
    /// lease_duration <= requested lease_duration" (DDS v1.4 Sec.2.2.3.11).
    #[test]
    fn liveliness_offered_kind_at_least_requested() {
        let secs = Duration::from_secs(10);
        let auto = Liveliness::automatic(secs);
        let by_participant = Liveliness::manual_by_participant(secs);
        let by_topic = Liveliness::manual_by_topic(secs);
        let rank = [auto, by_participant, by_topic];
        for (wi, offered) in rank.iter().enumerate() {
            for (ri, requested) in rank.iter().enumerate() {
                let writer = QoS {
                    liveliness: *offered,
                    ..QoS::default()
                };
                let reader = QoS {
                    liveliness: *requested,
                    ..QoS::default()
                };
                let expected = if wi >= ri {
                    (true, 0)
                } else {
                    (false, policy_id::LIVELINESS)
                };
                assert_eq!(
                    verdict(&writer, &reader),
                    expected,
                    "offered {:?} requested {:?}",
                    offered.kind,
                    requested.kind
                );
            }
        }
    }

    #[test]
    fn liveliness_offered_lease_at_most_requested() {
        let writer = |s| QoS {
            liveliness: Liveliness::manual_by_topic(Duration::from_secs(s)),
            ..QoS::default()
        };
        let reader = |s| QoS {
            liveliness: Liveliness::automatic(Duration::from_secs(s)),
            ..QoS::default()
        };
        assert_eq!(verdict(&writer(5), &reader(5)), (true, 0));
        assert_eq!(verdict(&writer(5), &reader(6)), (true, 0));
        assert_eq!(
            verdict(&writer(6), &reader(5)),
            (false, policy_id::LIVELINESS)
        );
    }

    /// LATENCY_BUDGET: "offered duration <= requested duration"
    /// (DDS v1.4 Sec.2.2.3.8).
    #[test]
    fn latency_budget_offered_at_most_requested() {
        let qos = |ms| QoS {
            latency_budget: LatencyBudget::new(Duration::from_millis(ms)),
            ..QoS::default()
        };
        assert_eq!(verdict(&qos(10), &qos(10)), (true, 0));
        assert_eq!(verdict(&qos(10), &qos(20)), (true, 0));
        assert_eq!(verdict(&qos(0), &qos(20)), (true, 0));
        assert_eq!(
            verdict(&qos(20), &qos(10)),
            (false, policy_id::LATENCY_BUDGET)
        );
        assert_eq!(
            verdict(&qos(1), &qos(0)),
            (false, policy_id::LATENCY_BUDGET)
        );
    }

    /// DESTINATION_ORDER: "offered kind >= requested kind" with
    /// "BY_RECEPTION_TIMESTAMP < BY_SOURCE_TIMESTAMP" (DDS v1.4
    /// Sec.2.2.3.17).
    #[test]
    fn destination_order_offered_kind_at_least_requested() {
        let reception = QoS {
            destination_order: DestinationOrder::by_reception_timestamp(),
            ..QoS::default()
        };
        let source = QoS {
            destination_order: DestinationOrder::by_source_timestamp(),
            ..QoS::default()
        };
        assert_eq!(verdict(&source, &reception), (true, 0));
        assert_eq!(verdict(&source, &source), (true, 0));
        assert_eq!(verdict(&reception, &reception), (true, 0));
        assert_eq!(
            verdict(&reception, &source),
            (false, policy_id::DESTINATION_ORDER)
        );
    }

    /// Each refusal reports its policy's QosPolicyId_t (DDS v1.4
    /// Sec.2.3.3), never an internal number.
    #[test]
    fn each_refusal_reports_the_psm_policy_id() {
        let cases = [
            (
                QoS::best_effort(),
                QoS::reliable(),
                policy_id::RELIABILITY,
                11,
            ),
            (
                QoS::best_effort(),
                QoS::best_effort().transient_local(),
                policy_id::DURABILITY,
                2,
            ),
            (
                QoS::best_effort().deadline_millis(200),
                QoS::best_effort().deadline_millis(100),
                policy_id::DEADLINE,
                4,
            ),
            (
                QoS::best_effort().ownership_exclusive(),
                QoS::best_effort(),
                policy_id::OWNERSHIP,
                6,
            ),
            (
                QoS::best_effort().liveliness_automatic_secs(20),
                QoS::best_effort().liveliness_automatic_secs(10),
                policy_id::LIVELINESS,
                8,
            ),
            (
                make_qos(Presentation::new(
                    PresentationAccessScope::Topic,
                    false,
                    false,
                )),
                make_qos(Presentation::new(
                    PresentationAccessScope::Topic,
                    true,
                    false,
                )),
                policy_id::PRESENTATION,
                3,
            ),
        ];
        for (writer, reader, id, value) in cases {
            assert_eq!(id, value);
            assert_eq!(
                first_incompatible_policy(&reader, &writer),
                value,
                "{}",
                policy_id::name(value)
            );
        }
    }

    #[test]
    fn test_presentation_both_default_compatible() {
        let writer = make_qos(Presentation::default());
        let reader = make_qos(Presentation::default());
        assert!(is_compatible(&reader, &writer));
    }
}
