// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! QoS compatibility checking (RxO - Request vs Offered).
//!
//!
//! Implements DDS v1.4 Sec.2.2.3 QoS compatibility rules to determine if
//! a DataWriter can communicate with a DataReader based on their QoS policies.
//!
//! # Compatibility Rules
//!
//! | Policy      | Rule                                              |
//! |-------------|---------------------------------------------------|
//! | Reliability | Writer >= Reader (Reliable > BestEffort)           |
//! | Durability  | Writer >= Reader (Persistent > TransientLocal > Volatile) |
//! | History     | Writer depth >= Reader depth                       |
//! | Deadline    | Writer period <= Reader period                     |
//! | Ownership   | Must match exactly                                |
//! | Liveliness  | Kind must match, writer lease <= reader lease      |
//! | Partition   | Must have intersection                            |

use crate::dds::qos::{Durability, History, QoS, Reliability};
use log;

/// Check QoS compatibility between offered (writer) and requested (reader)
///
/// Implements DDS v1.4 Sec.2.2.3 Request vs Offered (RxO) QoS compatibility rules.
///
/// # Compatibility Rules (all must pass)
///
/// 1. **Reliability** - Writer kind must satisfy reader kind
///    - BEST_EFFORT writer can match BEST_EFFORT reader only
///    - RELIABLE writer can match both BEST_EFFORT and RELIABLE readers
///
/// 2. **Durability** - Writer durability >= Reader durability
///    - VOLATILE writer can match VOLATILE reader only
///    - TRANSIENT_LOCAL writer can match both VOLATILE and TRANSIENT_LOCAL readers
///
/// 3. **History**
///    - Writer KeepLast(10) can satisfy Reader KeepLast(5) [OK]
///    - Writer KeepLast(5) cannot satisfy Reader KeepLast(10) [X]
///    - Writer KeepAll can satisfy any Reader KeepLast [OK]
///    - Reader KeepAll requires Writer KeepAll [OK]
///
/// 4. **Deadline** - Writer offers <= Reader requests (faster writer OK)
///    - Writer 100ms can match Reader 200ms [OK]
///    - Writer 200ms cannot match Reader 100ms [X]
///
/// 5. **Ownership** - Kinds must match exactly
///    - SHARED matches SHARED [OK]
///    - EXCLUSIVE matches EXCLUSIVE [OK]
///    - SHARED != EXCLUSIVE [X]
///
/// 6. **Liveliness** - Kind must match AND writer lease <= reader lease
///    - Kind must be identical
///    - Writer lease duration must be <= reader lease duration
///
/// 7. **Partition** - Must have at least one common partition
///    - Empty partitions match each other [OK]
///    - Non-empty partitions must intersect [OK]
///
/// 8. **TimeBasedFilter** - Reader-side only, no compatibility check needed
///
/// 9. **ResourceLimits** - Local configuration, no compatibility check needed
///
/// # Arguments
///
/// * `reader_qos` - Reader's requested QoS
/// * `writer_qos` - Writer's offered QoS
///
/// # Returns
///
/// `true` if all policies are compatible
pub(super) fn is_compatible(reader_qos: &QoS, writer_qos: &QoS) -> bool {
    crate::trace_fn!("qos::is_compatible");
    // 1. Reliability compatibility
    let reliability_ok = match (&writer_qos.reliability, &reader_qos.reliability) {
        (Reliability::BestEffort, Reliability::BestEffort) => true,
        (Reliability::BestEffort, Reliability::Reliable) => false, // Writer too weak
        (Reliability::Reliable, Reliability::BestEffort) => true,  // Writer stronger than needed
        (Reliability::Reliable, Reliability::Reliable) => true,
    };

    if !reliability_ok {
        log::debug!(
            "[MATCH-QOS] Reliability mismatch (writer={:?}, reader={:?})",
            writer_qos.reliability,
            reader_qos.reliability
        );
        return false;
    }

    // 2. Durability compatibility
    let durability_rank = |durability: Durability| match durability {
        Durability::Volatile => 0u8,
        Durability::TransientLocal => 1u8,
        Durability::Persistent => 3u8,
    };
    let durability_ok =
        durability_rank(writer_qos.durability) >= durability_rank(reader_qos.durability);

    if !durability_ok {
        log::debug!(
            "[MATCH-QOS] Durability mismatch (writer={:?}, reader={:?})",
            writer_qos.durability,
            reader_qos.durability
        );
        return false;
    }

    // 3. History compatibility
    let history_ok = match (reader_qos.history, writer_qos.history) {
        (History::KeepLast(r_keep), History::KeepLast(w_keep)) => w_keep >= r_keep,
        (History::KeepLast(_), History::KeepAll) => true,
        (History::KeepAll, History::KeepAll) => true,
        (History::KeepAll, History::KeepLast(_)) => false,
    };

    if !history_ok {
        log::debug!(
            "[MATCH-QOS] History mismatch (writer={:?}, reader={:?})",
            writer_qos.history,
            reader_qos.history
        );
        return false;
    }

    // 4. Deadline compatibility
    // Writer period <= Reader period (faster writer can satisfy slower reader)
    if writer_qos.deadline.period > reader_qos.deadline.period {
        log::debug!(
            "[MATCH-QOS] Deadline mismatch (writer={:?}, reader={:?})",
            writer_qos.deadline,
            reader_qos.deadline
        );
        return false;
    }

    // 5. Ownership compatibility (must match exactly)
    if writer_qos.ownership.kind != reader_qos.ownership.kind {
        log::debug!(
            "[MATCH-QOS] Ownership mismatch (writer={:?}, reader={:?})",
            writer_qos.ownership,
            reader_qos.ownership
        );
        return false;
    }

    // 6. Liveliness compatibility (kind + lease duration)
    // Kind must match AND writer lease_duration <= reader lease_duration
    if writer_qos.liveliness.kind != reader_qos.liveliness.kind {
        log::debug!(
            "[MATCH-QOS] Liveliness kind mismatch (writer={:?}, reader={:?})",
            writer_qos.liveliness.kind,
            reader_qos.liveliness.kind
        );
        return false;
    }
    if writer_qos.liveliness.lease_duration > reader_qos.liveliness.lease_duration {
        log::debug!(
            "[MATCH-QOS] Liveliness lease mismatch (writer={:?}, reader={:?})",
            writer_qos.liveliness.lease_duration,
            reader_qos.liveliness.lease_duration
        );
        return false;
    }

    // 7. Partition compatibility (must intersect)
    // Both default (empty) -> compatible
    // Either default but not both -> incompatible
    // Both non-empty -> must have at least one common partition
    if writer_qos.partition.is_default() && reader_qos.partition.is_default() {
        // Both default -> compatible
    } else if writer_qos.partition.is_default() || reader_qos.partition.is_default() {
        // Only one default -> incompatible
        log::debug!(
            "[MATCH-QOS] Partition mismatch (writer={:?}, reader={:?})",
            writer_qos.partition,
            reader_qos.partition
        );
        return false;
    } else {
        // Both non-empty -> check intersection
        let has_intersection = writer_qos
            .partition
            .names
            .iter()
            .any(|w_name| reader_qos.partition.names.contains(w_name));
        if !has_intersection {
            log::debug!(
                "[MATCH-QOS] Partition mismatch (no intersection) writer={:?}, reader={:?})",
                writer_qos.partition,
                reader_qos.partition
            );
            return false;
        }
    }

    // 8. TimeBasedFilter - reader-side filtering only, no compatibility check
    // 9. ResourceLimits - local configuration, no compatibility check

    true
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
    fn test_history_writer_less_incompatible() {
        let reader = QoS {
            history: History::KeepLast(10),
            ..QoS::default()
        };
        let writer = QoS {
            history: History::KeepLast(5),
            ..QoS::default()
        };
        assert!(!is_compatible(&reader, &writer));
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
    fn test_history_keep_all_reader_requires_keep_all() {
        let reader = QoS {
            history: History::KeepAll,
            ..QoS::default()
        };
        let writer = QoS {
            history: History::KeepLast(10),
            ..QoS::default()
        };
        assert!(!is_compatible(&reader, &writer));
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
    fn test_ownership_mismatch_incompatible() {
        let reader = QoS {
            ownership: Ownership::shared(),
            ..QoS::default()
        };
        let writer = QoS {
            ownership: Ownership::exclusive(),
            ..QoS::default()
        };
        assert!(!is_compatible(&reader, &writer));
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
}
