// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! QoS builder methods for reliability policies (history, durability).

use super::super::reliability::{Durability, History};
use super::structs::QoS;

impl QoS {
    /// Set RELIABILITY `max_blocking_time` (DDS v1.4 Sec.2.2.3.14): how
    /// long a RELIABLE writer's `write()` may block for room before it
    /// returns TIMEOUT. Default 100 ms; ignored by BEST_EFFORT writers.
    pub fn max_blocking_time(mut self, max_blocking_time: std::time::Duration) -> Self {
        self.reliability_max_blocking_time = max_blocking_time;
        self
    }

    /// Set KEEP_LAST history depth.
    pub fn keep_last(mut self, depth: u32) -> Self {
        self.history = History::KeepLast(depth);
        self
    }

    /// Set KEEP_ALL history policy.
    pub fn keep_all(mut self) -> Self {
        self.history = History::KeepAll;
        self
    }

    /// Set volatile durability.
    pub fn volatile(mut self) -> Self {
        self.durability = Durability::Volatile;
        self
    }

    /// Set transient-local durability.
    pub fn transient_local(mut self) -> Self {
        self.durability = Durability::TransientLocal;
        self
    }

    /// Set transient durability (requires durability service).
    pub fn transient(mut self) -> Self {
        self.durability = Durability::Transient;
        self
    }

    /// Set persistent durability.
    pub fn persistent(mut self) -> Self {
        self.durability = Durability::Persistent;
        self
    }
}

#[cfg(test)]
mod max_blocking_time_tests {
    use super::QoS;
    use std::time::Duration;

    /// DDS v1.4 Sec.2.2.3.14: "The default max_blocking_time=100ms", in
    /// every constructor; the setter replaces it.
    #[test]
    #[allow(deprecated)] // `rti_defaults` is still a constructor to check
    fn max_blocking_time_defaults_to_100_ms_and_is_set_by_the_builder() {
        for qos in [
            QoS::default(),
            QoS::best_effort(),
            QoS::reliable(),
            QoS::rti_defaults(),
        ] {
            assert_eq!(
                qos.reliability_max_blocking_time,
                Duration::from_millis(100)
            );
        }
        let qos = QoS::reliable().max_blocking_time(Duration::from_secs(3));
        assert_eq!(qos.reliability_max_blocking_time, Duration::from_secs(3));
    }
}
