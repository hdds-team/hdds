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

    /// The DATA_REPRESENTATION wire code `payload` is actually encoded in
    /// (DDS-XTypes v1.3 Sec.7.6.2.1.2: `0x0000` XCDR1, `0x0002` XCDR2),
    /// per [`hdds::CdrVersion::representation_code`]. A replay/relay of
    /// this message must create a raw writer that OFFERS this
    /// representation (`hdds::RawRelayWriter`), never a plain writer that
    /// resolved a different one -- the wire label must always match the
    /// bytes.
    ///
    /// Stored in the `.hdds` binary format from `FORMAT_VERSION` 2
    /// onward. A file recorded under version 1 carries none, and
    /// `HddsReader` fills in `0x0002` (XCDR2) for every one of its
    /// messages by default (override with
    /// [`HddsReader::with_legacy_representation`](crate::format::hdds::HddsReader::with_legacy_representation)):
    /// every FORMAT_VERSION 1 file was written before this field existed,
    /// by hdds-record on the 1.4.x line, whose DEFAULT
    /// writers resolved and encoded XCDR2 at run time -- NOT the
    /// DDS-XTypes spec's "empty list" default (Sec.7.6.3.1.1, "shall be
    /// taken to be equivalent to a list containing the single element
    /// XCDR", i.e. XCDR1), which is what a default-QoS writer now
    /// resolves to
    /// (`crate::dds::cdr_negotiation::resolve_writer_data_representation`).
    /// The v1 default must track what version 1 files actually carry,
    /// not whatever the current build's own default happens to be. It is
    /// a documented best guess, not a recovered fact: a version-1
    /// recording of a topic whose source writer explicitly offered XCDR1
    /// was never distinguishable from one that offered XCDR2, because
    /// version 1 never stored either -- `with_legacy_representation` is
    /// the escape hatch for that rare case.
    pub representation: u16,
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
            let ret =
                unsafe { libc::gethostname(buf.as_mut_ptr().cast::<libc::c_char>(), buf.len()) };
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
            representation: ::hdds::CdrVersion::Xcdr2.representation_code(),
        };

        let json = serde_json::to_string(&msg).expect("serialize");
        let decoded: Message = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(decoded.topic_name, "Temperature");
        assert_eq!(decoded.sequence_number, 1);
        assert_eq!(
            decoded.representation,
            ::hdds::CdrVersion::Xcdr2.representation_code()
        );
    }
}
