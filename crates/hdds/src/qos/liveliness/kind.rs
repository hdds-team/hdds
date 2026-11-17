// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/// LIVELINESS QoS kinds (DDS v1.4 Sec.2.2.3.11).
///
/// Ordered as the request/offered rule orders them: "the values of
/// LIVELINESS kind are considered ordered such that: AUTOMATIC <
/// MANUAL_BY_PARTICIPANT < MANUAL_BY_TOPIC" (the variants are declared in
/// that order, which the derived `Ord` follows).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum LivelinessKind {
    /// DDS infrastructure automatically asserts liveliness.
    #[default]
    Automatic,
    /// Application must assert per participant.
    ManualByParticipant,
    /// Application must assert per writer/topic.
    ManualByTopic,
}
