// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Building blocks for the upcoming `rmw_hdds` ROS 2 integration layer.
//!
//! The modules in this namespace provide safe wrappers around internal HDDS
//! primitives so the future `rmw_hdds` crate can focus on mapping the ROS 2
//! C API without re-implementing low-level details (waitsets, guard
//! conditions, participant lifecycle, etc.).

/// Context wrapper that owns the participant, waitset and graph guard plumbing.
pub mod context;
/// Graph cache types used to expose ROS graph queries.
pub mod graph;
/// Waitset driver and condition bookkeeping for rmw integration.
pub mod waitset;
