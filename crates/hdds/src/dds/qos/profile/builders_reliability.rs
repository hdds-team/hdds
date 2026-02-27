// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! QoS builder methods for reliability policies (history, durability).

use super::super::reliability::{Durability, History};
use super::structs::QoS;

impl QoS {
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

    /// Set persistent durability.
    pub fn persistent(mut self) -> Self {
        self.durability = Durability::Persistent;
        self
    }
}
