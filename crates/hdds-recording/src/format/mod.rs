// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Recording file formats.
//!
//! Supports:
//! - Native `.hdds` format (default)
//! - MCAP export (optional feature)

pub mod hdds;

#[cfg(feature = "mcap")]
mod mcap_export;

pub use hdds::{
    FileHeader, FormatError, HddsFormat, HddsReader, HddsWriter, IndexEntry, SegmentHeader,
    FORMAT_VERSION, MAGIC,
};

#[cfg(feature = "mcap")]
pub use mcap_export::{convert_hdds_to_mcap, McapError, McapExporter};

use serde::{Deserialize, Serialize};

/// A recorded DDS message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    /// Timestamp in nanoseconds since recording start.
    pub timestamp_nanos: u64,

    /// Topic name.
    pub topic_name: String,

    /// Type name.
    pub type_name: String,

    /// Writer GUID (hex encoded).
    pub writer_guid: String,

    /// Sequence number.
    pub sequence_number: u64,

    /// Serialized payload (CDR encoded).
    pub payload: Vec<u8>,

    /// QoS profile hash (for grouping).
    pub qos_hash: u32,
}

/// Recording metadata (stored in file header).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordingMetadata {
    /// Recording start time (ISO 8601).
    pub start_time: String,

    /// Domain ID.
    pub domain_id: u32,

    /// Recording host name.
    pub hostname: Option<String>,

    /// HDDS version used for recording.
    pub hdds_version: String,

    /// Topic list with type information.
    pub topics: Vec<TopicInfo>,

    /// Optional description.
    pub description: Option<String>,
}

/// Topic information for metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopicInfo {
    /// Topic name.
    pub name: String,

    /// Type name.
    pub type_name: String,

    /// Message count in recording.
    pub message_count: u64,

    /// QoS profile (simplified).
    pub reliability: String,
    pub durability: String,
}

impl Default for RecordingMetadata {
    fn default() -> Self {
        Self {
            start_time: chrono::Utc::now().to_rfc3339(),
            domain_id: 0,
            hostname: hostname::get().ok().and_then(|h| h.into_string().ok()),
            hdds_version: env!("CARGO_PKG_VERSION").to_string(),
            topics: Vec::new(),
            description: None,
        }
    }
}

/// Supported output formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    /// Native HDDS format (.hdds)
    Hdds,
    /// MCAP format (.mcap) - requires feature
    Mcap,
}

impl OutputFormat {
    /// Detect format from file extension.
    pub fn from_extension(path: &std::path::Path) -> Option<Self> {
        match path.extension().and_then(|e| e.to_str()) {
            Some("hdds") => Some(Self::Hdds),
            Some("mcap") => Some(Self::Mcap),
            _ => None,
        }
    }

    /// Get file extension for this format.
    pub fn extension(&self) -> &'static str {
        match self {
            Self::Hdds => "hdds",
            Self::Mcap => "mcap",
        }
    }
}

// Hostname helper (simple implementation)
mod hostname {
    pub fn get() -> std::io::Result<std::ffi::OsString> {
        #[cfg(unix)]
        {
            use std::ffi::OsString;
            use std::os::unix::ffi::OsStringExt;

            let mut buf = vec![0u8; 256];
            let ret = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut i8, buf.len()) };
            if ret == 0 {
                let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
                buf.truncate(len);
                Ok(OsString::from_vec(buf))
            } else {
                Err(std::io::Error::last_os_error())
            }
        }
        #[cfg(not(unix))]
        {
            Ok(std::ffi::OsString::from("unknown"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_output_format_from_extension() {
        use std::path::Path;

        assert_eq!(
            OutputFormat::from_extension(Path::new("test.hdds")),
            Some(OutputFormat::Hdds)
        );
        assert_eq!(
            OutputFormat::from_extension(Path::new("test.mcap")),
            Some(OutputFormat::Mcap)
        );
        assert_eq!(OutputFormat::from_extension(Path::new("test.txt")), None);
    }

    #[test]
    fn test_recording_metadata_default() {
        let meta = RecordingMetadata::default();
        assert_eq!(meta.domain_id, 0);
        assert!(meta.topics.is_empty());
    }

    #[test]
    fn test_message_serialization() {
        let msg = Message {
            timestamp_nanos: 1000,
            topic_name: "Temperature".into(),
            type_name: "sensor_msgs/Temperature".into(),
            writer_guid: "0102030405060708090a0b0c00000302".into(),
            sequence_number: 1,
            payload: vec![1, 2, 3, 4],
            qos_hash: 0x12345678,
        };

        let json = serde_json::to_string(&msg).expect("serialize");
        let decoded: Message = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(decoded.topic_name, "Temperature");
        assert_eq!(decoded.sequence_number, 1);
    }
}
