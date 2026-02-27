// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/// LIVELINESS QoS kinds (DDS v1.4 Sec.2.2.3.10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LivelinessKind {
    /// DDS infrastructure automatically asserts liveliness.
    #[default]
    Automatic,
    /// Application must assert per participant.
    ManualByParticipant,
    /// Application must assert per writer/topic.
    ManualByTopic,
}
