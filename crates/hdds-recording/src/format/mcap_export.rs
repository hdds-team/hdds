// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! MCAP export support.
//!
//! Converts .hdds recordings to MCAP format for compatibility with
//! Foxglove Studio, ROS2 tools, and other MCAP-compatible software.

use super::{Message, RecordingMetadata};
use mcap::{Attachment, Channel, Schema};
use std::borrow::Cow;
use std::collections::HashMap;
use std::fs::File;
use std::io::BufWriter;
use std::path::Path;
use thiserror::Error;

/// MCAP export errors.
#[derive(Debug, Error)]
pub enum McapError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("MCAP encoding error: {0}")]
    Mcap(#[from] mcap::McapError),

    #[error("Source format error: {0}")]
    Source(String),
}

/// MCAP file exporter.
pub struct McapExporter<'a> {
    writer: mcap::Writer<'a, BufWriter<File>>,
    channels: HashMap<String, u16>,
}

impl<'a> McapExporter<'a> {
    /// Create a new MCAP exporter.
    pub fn create<P: AsRef<Path>>(
        path: P,
        metadata: &RecordingMetadata,
    ) -> Result<Self, McapError> {
        let file = File::create(path)?;
        let writer = BufWriter::new(file);

        let mut mcap_writer = mcap::Writer::new(writer)?;

        // Write metadata attachment
        let meta_json = serde_json::to_string(metadata).unwrap_or_default();
        let attachment = Attachment {
            log_time: 0,
            create_time: 0,
            name: "hdds_metadata.json".to_string(),
            media_type: "application/json".to_string(),
            data: Cow::Owned(meta_json.into_bytes()),
        };
        mcap_writer.attach(&attachment)?;

        Ok(Self {
            writer: mcap_writer,
            channels: HashMap::new(),
        })
    }

    /// Write a message to MCAP.
    pub fn write_message(&mut self, msg: &Message) -> Result<(), McapError> {
        // Get or create channel for this topic
        let channel_id = self.get_or_create_channel(&msg.topic_name, &msg.type_name)?;

        // Write message
        self.writer.write_to_known_channel(
            &mcap::records::MessageHeader {
                channel_id,
                sequence: msg.sequence_number as u32,
                log_time: msg.timestamp_nanos,
                publish_time: msg.timestamp_nanos,
            },
            &msg.payload,
        )?;

        Ok(())
    }

    /// Get or create a channel for a topic.
    fn get_or_create_channel(
        &mut self,
        topic_name: &str,
        type_name: &str,
    ) -> Result<u16, McapError> {
        if let Some(&id) = self.channels.get(topic_name) {
            return Ok(id);
        }

        // Create schema for the type
        let schema = Schema {
            name: type_name.to_string(),
            encoding: "cdr".to_string(),
            data: Cow::Borrowed(&[]), // No schema data (opaque CDR)
        };

        // Create channel with schema
        let channel = Channel {
            topic: topic_name.to_string(),
            schema: Some(schema.into()),
            message_encoding: "cdr".to_string(),
            metadata: Default::default(),
        };

        let channel_id = self.writer.add_channel(&channel)?;
        self.channels.insert(topic_name.to_string(), channel_id);
        Ok(channel_id)
    }

    /// Finalize the MCAP file.
    pub fn finalize(mut self) -> Result<(), McapError> {
        self.writer.finish()?;
        Ok(())
    }
}

/// Convert an HDDS file to MCAP format.
pub fn convert_hdds_to_mcap<P1: AsRef<Path>, P2: AsRef<Path>>(
    input_path: P1,
    output_path: P2,
) -> Result<u64, McapError> {
    use super::hdds::HddsReader;

    let reader = HddsReader::open(input_path).map_err(|e| McapError::Source(e.to_string()))?;

    let metadata = reader.metadata().clone();
    let mut exporter = McapExporter::create(output_path, &metadata)?;

    let mut count = 0u64;
    for result in reader.messages() {
        let msg = result.map_err(|e| McapError::Source(e.to_string()))?;
        exporter.write_message(&msg)?;
        count += 1;
    }

    exporter.finalize()?;
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::{HddsFormat, HddsWriter};
    use tempfile::tempdir;

    #[test]
    fn test_convert_hdds_to_mcap() {
        let dir = tempdir().expect("tempdir");
        let hdds_path = dir.path().join("test.hdds");
        let mcap_path = dir.path().join("test.mcap");

        // Create HDDS file
        {
            let metadata = RecordingMetadata::default();
            let mut writer = HddsWriter::create(&hdds_path, metadata).expect("create");

            for i in 0..10 {
                let msg = Message {
                    timestamp_nanos: i * 1_000_000,
                    topic_name: "TestTopic".into(),
                    type_name: "TestType".into(),
                    writer_guid: "01020304050607080910111213141516".into(),
                    sequence_number: i,
                    payload: vec![i as u8; 10],
                    qos_hash: 0,
                };
                writer.write_message(&msg).expect("write");
            }
            writer.finalize().expect("finalize");
        }

        // Convert to MCAP
        let count = convert_hdds_to_mcap(&hdds_path, &mcap_path).expect("convert");
        assert_eq!(count, 10);

        // Verify MCAP file exists and has content
        let mcap_size = std::fs::metadata(&mcap_path).expect("metadata").len();
        assert!(mcap_size > 0);
    }

    #[test]
    fn test_mcap_exporter_multiple_topics() {
        let dir = tempdir().expect("tempdir");
        let mcap_path = dir.path().join("multi.mcap");

        let metadata = RecordingMetadata::default();
        let mut exporter = McapExporter::create(&mcap_path, &metadata).expect("create");

        // Write messages to different topics
        for i in 0..5 {
            let msg = Message {
                timestamp_nanos: i * 1_000_000,
                topic_name: format!("Topic{}", i % 2),
                type_name: format!("Type{}", i % 2),
                writer_guid: "guid".into(),
                sequence_number: i,
                payload: vec![i as u8],
                qos_hash: 0,
            };
            exporter.write_message(&msg).expect("write");
        }

        exporter.finalize().expect("finalize");

        // Verify file
        let mcap_size = std::fs::metadata(&mcap_path).expect("metadata").len();
        assert!(mcap_size > 0);
    }
}
