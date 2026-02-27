// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Transport-related QoS policies.
//!
//! Defines policies for network priority (DSCP/ToS) mapping.

/// Transport priority policy used for DSCP/ToS mapping.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct TransportPriority {
    /// Priority value (higher = more important).
    ///
    /// Typically mapped to DSCP (0-63) or ToS (0-255) by the transport.
    /// Applications can use arbitrary values; the implementation scales them to
    /// the available network priority range.
    pub value: i32,
}

impl TransportPriority {
    /// Create TRANSPORT_PRIORITY with normal priority (0).
    pub fn normal() -> Self {
        Self { value: 0 }
    }

    /// Create TRANSPORT_PRIORITY with high priority.
    pub fn high() -> Self {
        Self { value: 50 }
    }

    /// Create TRANSPORT_PRIORITY with low priority.
    pub fn low() -> Self {
        Self { value: -50 }
    }

    /// Check if priority is normal (0).
    pub fn is_normal(&self) -> bool {
        self.value == 0
    }

    /// Check if priority is high (positive value).
    pub fn is_high(&self) -> bool {
        self.value > 0
    }

    /// Check if priority is low (negative value).
    pub fn is_low(&self) -> bool {
        self.value < 0
    }
}

impl Default for TransportPriority {
    fn default() -> Self {
        Self::normal()
    }
}
