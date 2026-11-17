// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use crate::config::{PARTICIPANT_LEASE_DURATION_MS, SPDP_ANNOUNCEMENT_PERIOD_MS};
use crate::dds::{Error, Result};
use std::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ParticipantDiscoveryTiming {
    pub(super) lease_duration: Duration,
    pub(super) announcement_period: Duration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ValidatedParticipantDiscoveryTiming {
    pub(super) lease_duration_ms: u64,
    pub(super) announcement_period: Duration,
}

impl Default for ParticipantDiscoveryTiming {
    fn default() -> Self {
        Self {
            lease_duration: Duration::from_millis(PARTICIPANT_LEASE_DURATION_MS),
            announcement_period: Duration::from_millis(SPDP_ANNOUNCEMENT_PERIOD_MS),
        }
    }
}

impl ParticipantDiscoveryTiming {
    pub(super) fn validate(self) -> Result<ValidatedParticipantDiscoveryTiming> {
        let lease_duration_ms =
            whole_milliseconds("participant lease duration", self.lease_duration)?;
        let announcement_period_ms =
            whole_milliseconds("SPDP announcement period", self.announcement_period)?;

        if lease_duration_ms <= announcement_period_ms {
            return Err(Error::Config(format!(
                "participant lease duration ({lease_duration_ms} ms) must be greater than the SPDP announcement period ({announcement_period_ms} ms)"
            )));
        }

        if announcement_period_ms
            .checked_mul(3)
            .is_some_and(|three_periods| lease_duration_ms < three_periods)
        {
            log::warn!(
                "[SPDP] participant lease {lease_duration_ms} ms is less than three announcement periods ({announcement_period_ms} ms each); two lost announcements may expire a live peer"
            );
        }

        Ok(ValidatedParticipantDiscoveryTiming {
            lease_duration_ms,
            announcement_period: self.announcement_period,
        })
    }
}

fn whole_milliseconds(name: &str, duration: Duration) -> Result<u64> {
    if duration.is_zero() {
        return Err(Error::Config(format!("{name} must be greater than zero")));
    }
    if !duration.subsec_nanos().is_multiple_of(1_000_000) {
        return Err(Error::Config(format!(
            "{name} must be expressed as a whole number of milliseconds"
        )));
    }
    if duration.as_secs() > i32::MAX as u64 {
        return Err(Error::Config(format!(
            "{name} exceeds the RTPS Duration_t seconds range"
        )));
    }

    u64::try_from(duration.as_millis())
        .map_err(|_| Error::Config(format!("{name} does not fit in milliseconds")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_sourced_from_the_public_constants() {
        let timing = ParticipantDiscoveryTiming::default().validate().unwrap();
        assert_eq!(timing.lease_duration_ms, PARTICIPANT_LEASE_DURATION_MS);
        assert_eq!(
            timing.announcement_period,
            Duration::from_millis(SPDP_ANNOUNCEMENT_PERIOD_MS)
        );
    }

    #[test]
    fn rejects_zero_fractional_and_inverted_timing() {
        let default = ParticipantDiscoveryTiming::default();
        assert!(ParticipantDiscoveryTiming {
            lease_duration: Duration::ZERO,
            ..default
        }
        .validate()
        .is_err());
        assert!(ParticipantDiscoveryTiming {
            announcement_period: Duration::from_micros(500),
            ..default
        }
        .validate()
        .is_err());
        assert!(ParticipantDiscoveryTiming {
            lease_duration: Duration::from_secs(3),
            announcement_period: Duration::from_secs(3),
        }
        .validate()
        .is_err());
    }
}
