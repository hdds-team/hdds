// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! The HISTORY / RESOURCE_LIMITS consistency check, shared by DataWriter and
//! DataReader creation.
//!
//! DDS 1.4 states the rules once, for both entities (2.2.3.18, 2.2.3.19):
//!
//! > The setting of HISTORY depth must be consistent with the RESOURCE_LIMITS
//! > max_samples_per_instance. For these two QoS to be consistent, they must
//! > verify that depth <= max_samples_per_instance.
//!
//! > The setting of RESOURCE_LIMITS max_samples must be consistent with the
//! > max_samples_per_instance. For these two values to be consistent they
//! > must verify that "max_samples >= max_samples_per_instance." [...]
//! > An attempt to set this policy to inconsistent values when an entity is
//! > created of via a set_qos operation will cause the operation to fail.
//!
//! One function, so a writer and a reader can never disagree on what is
//! consistent.

use crate::dds::{Error, Result};
use crate::qos::{History, ResourceLimits};

/// A RESOURCE_LIMITS value as a limit: `None` for LENGTH_UNLIMITED, which
/// DDS 1.4 2.2.3.19 defines as the absence of that limit, so it takes part
/// in no comparison.
fn finite(value: usize) -> Option<usize> {
    (value != crate::reliability::LENGTH_UNLIMITED).then_some(value)
}

/// The consistency rules DDS 1.4 attaches to HISTORY and RESOURCE_LIMITS,
/// and only those: a KEEP_LAST depth > 0, every limit > 0 or
/// LENGTH_UNLIMITED, `depth <= max_samples_per_instance` (2.2.3.18) and
/// `max_samples >= max_samples_per_instance` (2.2.3.19). An inconsistent
/// pair makes the creation fail (the spec's INCONSISTENT_POLICY).
///
/// `what` names the entity in the error message ("DataWriter",
/// "DataReader", ...).
///
/// There is deliberately no rule on `max_samples_per_instance *
/// max_instances`: the spec has none. 2.2.2.4.2.11 describes what `write`
/// does when `max_samples` is smaller than that product, which only makes
/// sense because such a setting is legal.
///
/// A violation is the spec's INCONSISTENT_POLICY (2.2.1.1, and the
/// create_datawriter / create_datareader "if the QoS is inconsistent, the
/// operation returns INCONSISTENT_POLICY" text): `Error::InvalidQos`, not
/// `Error::InvalidState`.
pub(crate) fn check_history_and_limits(
    what: &str,
    history: History,
    limits: &ResourceLimits,
) -> Result<()> {
    if matches!(history, History::KeepLast(0)) {
        return Err(Error::InvalidQos(format!(
            "{what} History::KeepLast requires depth > 0"
        )));
    }
    for (name, value) in [
        ("max_samples", limits.max_samples),
        ("max_instances", limits.max_instances),
        ("max_samples_per_instance", limits.max_samples_per_instance),
    ] {
        if value == 0 {
            return Err(Error::InvalidQos(format!(
                "{what} RESOURCE_LIMITS.{name} must be > 0 or LENGTH_UNLIMITED"
            )));
        }
    }
    if let (Some(total), Some(per_instance)) = (
        finite(limits.max_samples),
        finite(limits.max_samples_per_instance),
    ) {
        if total < per_instance {
            return Err(Error::InvalidQos(format!(
                "{what} RESOURCE_LIMITS.max_samples ({total}) must be >= max_samples_per_instance ({per_instance})"
            )));
        }
    }
    if let (History::KeepLast(depth), Some(per_instance)) =
        (history, finite(limits.max_samples_per_instance))
    {
        let depth = usize::try_from(depth).unwrap_or(usize::MAX);
        if depth > per_instance {
            return Err(Error::InvalidQos(format!(
                "{what} HISTORY depth ({depth}) must be <= RESOURCE_LIMITS.max_samples_per_instance ({per_instance})"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reliability::LENGTH_UNLIMITED;

    fn limits(max_samples: usize, max_instances: usize, per_instance: usize) -> ResourceLimits {
        ResourceLimits {
            max_samples,
            max_instances,
            max_samples_per_instance: per_instance,
            max_quota_bytes: 100_000,
        }
    }

    fn refusal(history: History, limits: &ResourceLimits) -> String {
        check_history_and_limits("DataReader", history, limits)
            .expect_err("inconsistent")
            .to_string()
    }

    /// 2.2.3.18: "depth <= max_samples_per_instance". Pinned from both
    /// sides of the threshold.
    #[test]
    fn depth_must_not_exceed_max_samples_per_instance() {
        let msg = refusal(History::KeepLast(11), &limits(100, 1, 10));
        assert!(
            msg.contains(
                "HISTORY depth (11) must be <= RESOURCE_LIMITS.max_samples_per_instance (10)"
            ),
            "{msg}"
        );
        assert!(msg.contains("DataReader"), "{msg}");
        assert!(check_history_and_limits("r", History::KeepLast(10), &limits(100, 1, 10)).is_ok());
    }

    /// 2.2.3.19: "max_samples >= max_samples_per_instance". Pinned from
    /// both sides of the threshold.
    #[test]
    fn max_samples_must_cover_max_samples_per_instance() {
        let msg = refusal(History::KeepAll, &limits(9, 1, 10));
        assert!(
            msg.contains("max_samples (9) must be >= max_samples_per_instance (10)"),
            "{msg}"
        );
        assert!(check_history_and_limits("r", History::KeepAll, &limits(10, 1, 10)).is_ok());
    }

    /// 2.2.3.19: LENGTH_UNLIMITED is "the absence of a particular limit",
    /// so it takes part in no comparison.
    #[test]
    fn length_unlimited_is_never_compared() {
        let u = LENGTH_UNLIMITED;
        assert!(check_history_and_limits("r", History::KeepLast(1000), &limits(u, u, u)).is_ok());
        assert!(check_history_and_limits("r", History::KeepLast(1000), &limits(5, u, u)).is_ok());
        assert!(check_history_and_limits("r", History::KeepAll, &limits(u, 1, 50)).is_ok());
    }

    /// The spec has no rule on max_instances * max_samples_per_instance.
    #[test]
    fn no_rule_on_the_instances_product() {
        assert!(check_history_and_limits("r", History::KeepLast(10), &limits(100, 50, 10)).is_ok());
    }

    /// DDS 1.4 2.2.1.1 and the create_datawriter / create_datareader text
    /// name this failure INCONSISTENT_POLICY, a distinct return code from
    /// PRECONDITION_NOT_MET (`Error::InvalidState`). Every refusal in this
    /// module must carry the spec-mapped variant, `Error::InvalidQos`, not
    /// merely a message that happens to mention the right words.
    #[test]
    fn inconsistent_policy_is_invalid_qos_not_invalid_state() {
        let depth_err = check_history_and_limits("r", History::KeepLast(11), &limits(100, 1, 10))
            .expect_err("inconsistent depth");
        assert!(matches!(depth_err, Error::InvalidQos(_)), "{depth_err:?}");

        let samples_err = check_history_and_limits("r", History::KeepAll, &limits(9, 1, 10))
            .expect_err("inconsistent max_samples");
        assert!(
            matches!(samples_err, Error::InvalidQos(_)),
            "{samples_err:?}"
        );

        let zero_err = check_history_and_limits("r", History::KeepLast(0), &limits(1, 1, 1))
            .expect_err("zero depth");
        assert!(matches!(zero_err, Error::InvalidQos(_)), "{zero_err:?}");

        let zero_limit_err = check_history_and_limits("r", History::KeepAll, &limits(0, 1, 1))
            .expect_err("zero resource limit");
        assert!(
            matches!(zero_limit_err, Error::InvalidQos(_)),
            "{zero_limit_err:?}"
        );
    }

    #[test]
    fn zero_depth_and_zero_limits_are_refused() {
        let u = LENGTH_UNLIMITED;
        assert!(refusal(History::KeepLast(0), &limits(u, u, u)).contains("depth > 0"));
        assert!(refusal(History::KeepAll, &limits(0, u, u)).contains("max_samples must be > 0"));
        assert!(refusal(History::KeepAll, &limits(u, 0, u)).contains("max_instances must be > 0"));
        assert!(refusal(History::KeepAll, &limits(u, u, 0))
            .contains("max_samples_per_instance must be > 0"));
    }
}
