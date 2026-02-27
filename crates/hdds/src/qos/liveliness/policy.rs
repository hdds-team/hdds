// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use super::LivelinessKind;
use std::time::Duration;

/// LIVELINESS QoS policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Liveliness {
    pub kind: LivelinessKind,
    pub lease_duration: Duration,
}

impl Default for Liveliness {
    fn default() -> Self {
        Self {
            kind: LivelinessKind::Automatic,
            lease_duration: Duration::from_secs(u64::MAX),
        }
    }
}

impl Liveliness {
    #[must_use]
    pub fn new(kind: LivelinessKind, lease_duration: Duration) -> Self {
        Self {
            kind,
            lease_duration,
        }
    }

    #[must_use]
    pub fn automatic(lease_duration: Duration) -> Self {
        Self::new(LivelinessKind::Automatic, lease_duration)
    }

    #[must_use]
    pub fn manual_by_participant(lease_duration: Duration) -> Self {
        Self::new(LivelinessKind::ManualByParticipant, lease_duration)
    }

    #[must_use]
    pub fn manual_by_topic(lease_duration: Duration) -> Self {
        Self::new(LivelinessKind::ManualByTopic, lease_duration)
    }

    #[must_use]
    pub fn infinite() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn is_infinite(&self) -> bool {
        self.lease_duration == Duration::from_secs(u64::MAX)
    }

    #[must_use]
    pub fn is_compatible_with(&self, requested: &Liveliness) -> bool {
        if self.kind != requested.kind {
            return false;
        }
        self.lease_duration <= requested.lease_duration
    }

    // Convenience constructors from API layer (milliseconds/seconds)

    /// Create automatic liveliness from milliseconds.
    #[must_use]
    pub fn automatic_millis(ms: u64) -> Self {
        Self {
            kind: LivelinessKind::Automatic,
            lease_duration: Duration::from_millis(ms),
        }
    }

    /// Create automatic liveliness from seconds.
    #[must_use]
    pub fn automatic_secs(secs: u64) -> Self {
        Self {
            kind: LivelinessKind::Automatic,
            lease_duration: Duration::from_secs(secs),
        }
    }

    /// Create manual-by-participant liveliness from milliseconds.
    #[must_use]
    pub fn manual_participant_millis(ms: u64) -> Self {
        Self {
            kind: LivelinessKind::ManualByParticipant,
            lease_duration: Duration::from_millis(ms),
        }
    }

    /// Create manual-by-participant liveliness from seconds.
    #[must_use]
    pub fn manual_participant_secs(secs: u64) -> Self {
        Self {
            kind: LivelinessKind::ManualByParticipant,
            lease_duration: Duration::from_secs(secs),
        }
    }

    /// Create manual-by-topic liveliness from milliseconds.
    #[must_use]
    pub fn manual_topic_millis(ms: u64) -> Self {
        Self {
            kind: LivelinessKind::ManualByTopic,
            lease_duration: Duration::from_millis(ms),
        }
    }

    /// Create manual-by-topic liveliness from seconds.
    #[must_use]
    pub fn manual_topic_secs(secs: u64) -> Self {
        Self {
            kind: LivelinessKind::ManualByTopic,
            lease_duration: Duration::from_secs(secs),
        }
    }
}
