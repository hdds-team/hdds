// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Supported ROS 2 distributions for runtime type caching.

/// ROS 2 distribution we target when caching type metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Distro {
    /// ROS 2 Humble Hawksbill (Ubuntu 22.04 LTS).
    Humble,
    /// ROS 2 Iron Irwini.
    Iron,
    /// ROS 2 Jazzy Jalisco.
    Jazzy,
}
