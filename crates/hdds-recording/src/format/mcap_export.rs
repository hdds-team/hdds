// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! MCAP export support.
//!
//! Converts .hdds recordings to MCAP format for compatibility with
//! Foxglove Studio, ROS2 tools, and other MCAP-compatible software.

use super::{Message, RecordingMetadata};
use mcap::Attachment;
use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap};
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
pub struct McapExporter {
    writer: mcap::Writer<BufWriter<File>>,
    channels: HashMap<String, u16>,
}

impl McapExporter {
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

        // Schema for the type: opaque CDR, no schema data
        let schema_id = self.writer.add_schema(type_name, "cdr", &[])?;

        // Channel for the topic, bound to that schema
        let channel_id = self
            .writer
            .add_channel(schema_id, topic_name, "cdr", &BTreeMap::new())?;
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
                    representation: hdds::CdrVersion::Xcdr1.representation_code(),
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
                representation: hdds::CdrVersion::Xcdr1.representation_code(),
            };
            exporter.write_message(&msg).expect("write");
        }

        exporter.finalize().expect("finalize");

        // Verify file
        let mcap_size = std::fs::metadata(&mcap_path).expect("metadata").len();
        assert!(mcap_size > 0);
    }

    #[test]
    fn test_mcap_roundtrip_two_topics() {
        let dir = tempdir().expect("tempdir");
        let mcap_path = dir.path().join("roundtrip.mcap");

        // (topic, type, timestamp_nanos, sequence, payload), interleaved topics
        let inputs: Vec<(&str, &str, u64, u64, Vec<u8>)> = vec![
            ("Alpha", "AlphaType", 1_000, 1, vec![0xA1, 0xA2]),
            ("Beta", "BetaType", 2_000, 2, vec![0xB1]),
            ("Alpha", "AlphaType", 3_000, 3, vec![0xA3, 0xA4, 0xA5]),
            ("Beta", "BetaType", 4_000, 4, vec![0xB2, 0xB3]),
            ("Alpha", "AlphaType", 5_000, 5, vec![0xA6]),
        ];

        let metadata = RecordingMetadata::default();
        let mut exporter = McapExporter::create(&mcap_path, &metadata).expect("create");
        for (topic, ty, ts, seq, payload) in inputs.iter() {
            let msg = Message {
                timestamp_nanos: *ts,
                topic_name: (*topic).into(),
                type_name: (*ty).into(),
                writer_guid: "guid".into(),
                sequence_number: *seq,
                payload: payload.clone(),
                qos_hash: 0,
                representation: hdds::CdrVersion::Xcdr1.representation_code(),
            };
            exporter.write_message(&msg).expect("write");
        }
        exporter.finalize().expect("finalize");

        // Read back with the mcap crate's own reader
        let bytes = std::fs::read(&mcap_path).expect("read");
        let read_back: Vec<mcap::Message<'_>> = mcap::MessageStream::new(&bytes)
            .expect("stream")
            .map(|m| m.expect("message"))
            .collect();

        assert_eq!(read_back.len(), inputs.len(), "message count");
        for (got, (topic, ty, ts, seq, payload)) in read_back.iter().zip(inputs.iter()) {
            assert_eq!(got.channel.topic, *topic, "channel topic");
            assert_eq!(got.channel.message_encoding, "cdr", "message encoding");
            let schema = got.channel.schema.as_ref().expect("schema attached");
            assert_eq!(schema.name, *ty, "schema name");
            assert_eq!(schema.encoding, "cdr", "schema encoding");
            assert_eq!(got.log_time, *ts, "log time");
            assert_eq!(u64::from(got.sequence), *seq, "sequence");
            assert_eq!(got.data.as_ref(), payload.as_slice(), "payload bytes");
        }
    }
}
