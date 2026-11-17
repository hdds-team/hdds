// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! `QosPolicyId_t` values, the ids an INCOMPATIBLE_QOS status reports in
//! `last_policy_id` (DDS v1.4 Sec.2.2.4.1, `RequestedIncompatibleQosStatus`
//! and `OfferedIncompatibleQosStatus`).
//!
//! The values are the PSM's (DDS v1.4 Sec.2.3.3, DCPS PSM IDL):
//!
//! ```text
//! const QosPolicyId_t INVALID_QOS_POLICY_ID = 0; USERDATA 1; DURABILITY 2;
//! PRESENTATION 3; DEADLINE 4; LATENCYBUDGET 5; OWNERSHIP 6;
//! OWNERSHIPSTRENGTH 7; LIVELINESS 8; TIMEBASEDFILTER 9; PARTITION 10;
//! RELIABILITY 11; DESTINATIONORDER 12; HISTORY 13; RESOURCELIMITS 14;
//! ENTITYFACTORY 15; WRITERDATALIFECYCLE 16; READERDATALIFECYCLE 17;
//! TOPICDATA 18; GROUPDATA 19; TRANSPORTPRIORITY 20; LIFESPAN 21;
//! DURABILITYSERVICE 22
//! ```
//!
//! and DDS-XTypes v1.3 (IDL annex):
//! `const QosPolicyId_t DATA_REPRESENTATION_QOS_POLICY_ID = 23;`
//!
//! Every status, listener and C ABI value is one of these: an application
//! compares it with its own vendor's constants, which are the same.

/// `INVALID_QOS_POLICY_ID`.
pub const INVALID: u32 = 0;
/// `USERDATA_QOS_POLICY_ID`.
pub const USER_DATA: u32 = 1;
/// `DURABILITY_QOS_POLICY_ID`.
pub const DURABILITY: u32 = 2;
/// `PRESENTATION_QOS_POLICY_ID`.
pub const PRESENTATION: u32 = 3;
/// `DEADLINE_QOS_POLICY_ID`.
pub const DEADLINE: u32 = 4;
/// `LATENCYBUDGET_QOS_POLICY_ID`.
pub const LATENCY_BUDGET: u32 = 5;
/// `OWNERSHIP_QOS_POLICY_ID`.
pub const OWNERSHIP: u32 = 6;
/// `OWNERSHIPSTRENGTH_QOS_POLICY_ID`.
pub const OWNERSHIP_STRENGTH: u32 = 7;
/// `LIVELINESS_QOS_POLICY_ID`.
pub const LIVELINESS: u32 = 8;
/// `TIMEBASEDFILTER_QOS_POLICY_ID`.
pub const TIME_BASED_FILTER: u32 = 9;
/// `PARTITION_QOS_POLICY_ID`.
pub const PARTITION: u32 = 10;
/// `RELIABILITY_QOS_POLICY_ID`.
pub const RELIABILITY: u32 = 11;
/// `DESTINATIONORDER_QOS_POLICY_ID`.
pub const DESTINATION_ORDER: u32 = 12;
/// `HISTORY_QOS_POLICY_ID`.
pub const HISTORY: u32 = 13;
/// `RESOURCELIMITS_QOS_POLICY_ID`.
pub const RESOURCE_LIMITS: u32 = 14;
/// `ENTITYFACTORY_QOS_POLICY_ID`.
pub const ENTITY_FACTORY: u32 = 15;
/// `WRITERDATALIFECYCLE_QOS_POLICY_ID`.
pub const WRITER_DATA_LIFECYCLE: u32 = 16;
/// `READERDATALIFECYCLE_QOS_POLICY_ID`.
pub const READER_DATA_LIFECYCLE: u32 = 17;
/// `TOPICDATA_QOS_POLICY_ID`.
pub const TOPIC_DATA: u32 = 18;
/// `GROUPDATA_QOS_POLICY_ID`.
pub const GROUP_DATA: u32 = 19;
/// `TRANSPORTPRIORITY_QOS_POLICY_ID`.
pub const TRANSPORT_PRIORITY: u32 = 20;
/// `LIFESPAN_QOS_POLICY_ID`.
pub const LIFESPAN: u32 = 21;
/// `DURABILITYSERVICE_QOS_POLICY_ID`.
pub const DURABILITY_SERVICE: u32 = 22;
/// `DATA_REPRESENTATION_QOS_POLICY_ID` (DDS-XTypes v1.3).
pub const DATA_REPRESENTATION: u32 = 23;

/// The policy's name in upper snake case, `"UNKNOWN"` for an id the
/// table above does not hold.
#[must_use]
pub fn name(id: u32) -> &'static str {
    match id {
        INVALID => "INVALID",
        USER_DATA => "USER_DATA",
        DURABILITY => "DURABILITY",
        PRESENTATION => "PRESENTATION",
        DEADLINE => "DEADLINE",
        LATENCY_BUDGET => "LATENCY_BUDGET",
        OWNERSHIP => "OWNERSHIP",
        OWNERSHIP_STRENGTH => "OWNERSHIP_STRENGTH",
        LIVELINESS => "LIVELINESS",
        TIME_BASED_FILTER => "TIME_BASED_FILTER",
        PARTITION => "PARTITION",
        RELIABILITY => "RELIABILITY",
        DESTINATION_ORDER => "DESTINATION_ORDER",
        HISTORY => "HISTORY",
        RESOURCE_LIMITS => "RESOURCE_LIMITS",
        ENTITY_FACTORY => "ENTITY_FACTORY",
        WRITER_DATA_LIFECYCLE => "WRITER_DATA_LIFECYCLE",
        READER_DATA_LIFECYCLE => "READER_DATA_LIFECYCLE",
        TOPIC_DATA => "TOPIC_DATA",
        GROUP_DATA => "GROUP_DATA",
        TRANSPORT_PRIORITY => "TRANSPORT_PRIORITY",
        LIFESPAN => "LIFESPAN",
        DURABILITY_SERVICE => "DURABILITY_SERVICE",
        DATA_REPRESENTATION => "DATA_REPRESENTATION",
        _ => "UNKNOWN",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The values, in the PSM's order, as DDS v1.4 Sec.2.3.3 lists them
    /// (`= 0;` through `= 22;`), then DDS-XTypes v1.3's 23.
    #[test]
    fn ids_are_the_psm_values() {
        let psm = [
            INVALID,
            USER_DATA,
            DURABILITY,
            PRESENTATION,
            DEADLINE,
            LATENCY_BUDGET,
            OWNERSHIP,
            OWNERSHIP_STRENGTH,
            LIVELINESS,
            TIME_BASED_FILTER,
            PARTITION,
            RELIABILITY,
            DESTINATION_ORDER,
            HISTORY,
            RESOURCE_LIMITS,
            ENTITY_FACTORY,
            WRITER_DATA_LIFECYCLE,
            READER_DATA_LIFECYCLE,
            TOPIC_DATA,
            GROUP_DATA,
            TRANSPORT_PRIORITY,
            LIFESPAN,
            DURABILITY_SERVICE,
        ];
        for (expected, id) in psm.into_iter().enumerate() {
            assert_eq!(u32::try_from(expected).ok(), Some(id));
            assert_ne!(name(id), "UNKNOWN");
        }
        assert_eq!(DATA_REPRESENTATION, 23);
        assert_eq!(name(LIVELINESS), "LIVELINESS");
        assert_eq!(name(24), "UNKNOWN");
    }
}
