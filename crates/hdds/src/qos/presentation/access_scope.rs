// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/// PRESENTATION access scope (DDS v1.4 Sec.2.2.3.12).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum PresentationAccessScope {
    /// Instance-level access (default).
    /// Each instance is independent. No transactional semantics.
    #[default]
    Instance = 0,
    /// Topic-level access. All instances of a topic are presented together.
    Topic = 1,
    /// Group-level access. Multiple topics can be presented as a coherent set.
    Group = 2,
}
