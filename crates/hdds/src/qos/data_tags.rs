// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! DataTagQosPolicy (DDS-Security v1.1 Sec.7.2.5).
//!
//! "This specification also introduces a Qos policy called DataTagQosPolicy"
//! (Sec.7.2.5): a set of name/value tags a DataWriter or DataReader is
//! associated with, which the permissions document's `<data_tags>`
//! conditions are evaluated against (Sec.9.4.1.3.2.3.1.5, 9.4.1.3.2.3.2.5).
//! A remote endpoint's tags arrive in `PID_DATA_TAGS` (0x1003, Sec.7.4.1.7,
//! 7.4.1.8) and are read into the QoS of its discovery record.
//!
//! HDDS does not announce data tags of its own endpoints in this release:
//! an endpoint created with tags is refused (a peer would judge it as
//! untagged).

/// One data tag: a name and a value (Sec.7.2.5 `Tag`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct DataTag {
    /// The tag's name.
    pub name: String,
    /// The tag's value.
    pub value: String,
}

/// The data tags of an endpoint (Sec.7.2.5 `DataTags`, `DataTagQosPolicy`).
/// Empty by default.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DataTags {
    /// The tags, in announcement order.
    pub tags: Vec<DataTag>,
}

impl DataTags {
    /// Whether the endpoint has no tag.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tags.is_empty()
    }
}
