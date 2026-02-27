// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! HDDS Recording Service
//!
//! Record and replay DDS messages with support for:
//! - Native `.hdds` format (efficient, self-contained)
//! - MCAP export (industry standard, Foxglove compatible)
//!
//! # Quick Start
//!
//! ```bash
//! # Record all topics on domain 0
//! hdds-record --domain 0 --output capture.hdds
//!
//! # Replay at 2x speed
//! hdds-replay --input capture.hdds --speed 2.0
//!
//! # Convert to MCAP (if feature enabled)
//! hdds-record --domain 0 --output capture.mcap --format mcap
//! ```
//!
//! # Format Comparison
//!
//! | Feature | .hdds | .mcap |
//! |---------|-------|-------|
//! | Self-contained | [OK] | [OK] |
//! | Indexed seeking | [OK] | [OK] |
//! | Type metadata | [OK] | [OK] |
//! | Foxglove compatible | [X] | [OK] |
//! | ROS2 compatible | [X] | [OK] |
//! | Minimal deps | [OK] | [X] |

pub mod filter;
pub mod format;
pub mod player;
pub mod recorder;
pub mod rotation;

pub use filter::{TopicFilter, TypeFilter};
pub use format::{HddsFormat, Message, RecordingMetadata};
pub use player::{PlaybackSpeed, Player, PlayerConfig};
pub use recorder::{Recorder, RecorderConfig};
pub use rotation::{RotationPolicy, RotationTrigger};

// MCAP support (requires "mcap" feature)
#[cfg(feature = "mcap")]
pub use format::{convert_hdds_to_mcap, McapError, McapExporter};
