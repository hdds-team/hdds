// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Native HDDS recording format (.hdds)
//!
//! # Format Overview
//!
//! ```text
//! +---------------------------------------------------------+
//! |                    File Header (64 bytes)                |
//! |  Magic (8) | Version (4) | Flags (4) | MetaOffset (8)   |
//! |  MetaSize (4) | IndexOffset (8) | IndexCount (4) | ...  |
//! +---------------------------------------------------------+
//! |                    Segment 0                             |
//! |  SegmentHeader (32) | Message[] | CRC32 (4)             |
//! +---------------------------------------------------------+
//! |                    Segment 1                             |
//! |  ...                                                     |
//! +---------------------------------------------------------+
//! |                    Index Table                           |
//! |  IndexEntry[] (topic_hash, segment_id, offset, count)   |
//! +---------------------------------------------------------+
//! |                    Metadata (JSON)                       |
//! |  RecordingMetadata serialized as JSON                   |
//! +---------------------------------------------------------+
//! ```
//!
//! # Message Format
//!
//! ```text
//! +---------------------------------------------------------+
//! | timestamp (8) | topic_len (2) | type_len (2) |          |
//! | guid (16) | seq (8) | qos_hash (4) | payload_len (4) |  |
//! | topic_name (var) | type_name (var) | payload (var)      |
//! +---------------------------------------------------------+
//! ```

use super::{Message, RecordingMetadata, TopicInfo};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::Path;
use thiserror::Error;

/// Magic bytes: "HDDSREC\0"
pub const MAGIC: [u8; 8] = [0x48, 0x44, 0x44, 0x53, 0x52, 0x45, 0x43, 0x00];

/// Current format version.
///
/// Version 2 adds a per-message DATA_REPRESENTATION wire code
/// ([`Message::representation`]) right after `qos_hash` in the on-disk
/// message layout. The oldest version this reader still opens is 1,
/// which has no such field; [`HddsReader::read_single_message`] fills it
/// in with the documented default (see [`Message::representation`])
/// rather than refusing the file.
pub const FORMAT_VERSION: u32 = 2;

/// The oldest format version [`HddsReader::open`] still loads.
pub const MIN_SUPPORTED_FORMAT_VERSION: u32 = 1;

/// The first format version that stores [`Message::representation`] on
/// the wire; a file whose header names an older version has that field
/// defaulted on read.
const FORMAT_VERSION_WITH_REPRESENTATION: u32 = 2;

/// Default segment size (~5 seconds worth at 1000 msg/s).
pub const DEFAULT_SEGMENT_SIZE: usize = 5000;

/// File header (64 bytes, fixed).
#[derive(Debug, Clone)]
pub struct FileHeader {
    /// Magic bytes (8).
    pub magic: [u8; 8],
    /// Format version (4).
    pub version: u32,
    /// Flags (4) - reserved.
    pub flags: u32,
    /// Metadata JSON offset (8).
    pub metadata_offset: u64,
    /// Metadata JSON size (4).
    pub metadata_size: u32,
    /// Index table offset (8).
    pub index_offset: u64,
    /// Index entry count (4).
    pub index_count: u32,
    /// Total message count (8).
    pub message_count: u64,
    /// Recording duration in nanos (8).
    pub duration_nanos: u64,
    /// Reserved (8) - padding to 64 bytes.
    pub reserved: u64,
}

impl FileHeader {
    pub const SIZE: usize = 64;

    pub fn new() -> Self {
        Self {
            magic: MAGIC,
            version: FORMAT_VERSION,
            flags: 0,
            metadata_offset: 0,
            metadata_size: 0,
            index_offset: 0,
            index_count: 0,
            message_count: 0,
            duration_nanos: 0,
            reserved: 0,
        }
    }

    pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(&self.magic)?;
        w.write_u32::<LittleEndian>(self.version)?;
        w.write_u32::<LittleEndian>(self.flags)?;
        w.write_u64::<LittleEndian>(self.metadata_offset)?;
        w.write_u32::<LittleEndian>(self.metadata_size)?;
        w.write_u64::<LittleEndian>(self.index_offset)?;
        w.write_u32::<LittleEndian>(self.index_count)?;
        w.write_u64::<LittleEndian>(self.message_count)?;
        w.write_u64::<LittleEndian>(self.duration_nanos)?;
        w.write_u64::<LittleEndian>(self.reserved)?;
        Ok(())
    }

    pub fn read<R: Read>(r: &mut R) -> io::Result<Self> {
        let mut magic = [0u8; 8];
        r.read_exact(&mut magic)?;

        if magic != MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid HDDS file magic",
            ));
        }

        Ok(Self {
            magic,
            version: r.read_u32::<LittleEndian>()?,
            flags: r.read_u32::<LittleEndian>()?,
            metadata_offset: r.read_u64::<LittleEndian>()?,
            metadata_size: r.read_u32::<LittleEndian>()?,
            index_offset: r.read_u64::<LittleEndian>()?,
            index_count: r.read_u32::<LittleEndian>()?,
            message_count: r.read_u64::<LittleEndian>()?,
            duration_nanos: r.read_u64::<LittleEndian>()?,
            reserved: r.read_u64::<LittleEndian>()?,
        })
    }
}

impl Default for FileHeader {
    fn default() -> Self {
        Self::new()
    }
}

/// Segment header (32 bytes).
#[derive(Debug, Clone)]
pub struct SegmentHeader {
    /// Segment ID.
    pub segment_id: u32,
    /// Message count in segment.
    pub message_count: u32,
    /// Uncompressed data size.
    pub data_size: u32,
    /// First timestamp in segment.
    pub first_timestamp: u64,
    /// Last timestamp in segment.
    pub last_timestamp: u64,
    /// Reserved.
    pub reserved: u32,
}

impl SegmentHeader {
    pub const SIZE: usize = 32;

    pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_u32::<LittleEndian>(self.segment_id)?;
        w.write_u32::<LittleEndian>(self.message_count)?;
        w.write_u32::<LittleEndian>(self.data_size)?;
        w.write_u64::<LittleEndian>(self.first_timestamp)?;
        w.write_u64::<LittleEndian>(self.last_timestamp)?;
        w.write_u32::<LittleEndian>(self.reserved)?;
        Ok(())
    }

    pub fn read<R: Read>(r: &mut R) -> io::Result<Self> {
        Ok(Self {
            segment_id: r.read_u32::<LittleEndian>()?,
            message_count: r.read_u32::<LittleEndian>()?,
            data_size: r.read_u32::<LittleEndian>()?,
            first_timestamp: r.read_u64::<LittleEndian>()?,
            last_timestamp: r.read_u64::<LittleEndian>()?,
            reserved: r.read_u32::<LittleEndian>()?,
        })
    }
}

/// Index entry for topic-based seeking.
#[derive(Debug, Clone)]
pub struct IndexEntry {
    /// Topic name hash (FNV-1a).
    pub topic_hash: u32,
    /// Segment ID.
    pub segment_id: u32,
    /// Offset within segment.
    pub offset: u32,
    /// Message count for this topic in segment.
    pub count: u32,
}

impl IndexEntry {
    pub const SIZE: usize = 16;

    pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_u32::<LittleEndian>(self.topic_hash)?;
        w.write_u32::<LittleEndian>(self.segment_id)?;
        w.write_u32::<LittleEndian>(self.offset)?;
        w.write_u32::<LittleEndian>(self.count)?;
        Ok(())
    }

    pub fn read<R: Read>(r: &mut R) -> io::Result<Self> {
        Ok(Self {
            topic_hash: r.read_u32::<LittleEndian>()?,
            segment_id: r.read_u32::<LittleEndian>()?,
            offset: r.read_u32::<LittleEndian>()?,
            count: r.read_u32::<LittleEndian>()?,
        })
    }
}

/// HDDS format errors.
#[derive(Debug, Error)]
pub enum FormatError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("Invalid file format: {0}")]
    InvalidFormat(String),

    #[error("Version mismatch: expected {expected}, got {got}")]
    VersionMismatch { expected: u32, got: u32 },

    #[error("CRC mismatch in segment {segment_id}")]
    CrcMismatch { segment_id: u32 },

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

/// HDDS format trait for reading/writing.
pub trait HddsFormat {
    /// Write a message.
    fn write_message(&mut self, msg: &Message) -> Result<(), FormatError>;

    /// Finalize the file (write index, metadata, update header).
    fn finalize(self) -> Result<(), FormatError>;
}

/// HDDS file writer.
pub struct HddsWriter {
    writer: BufWriter<File>,
    header: FileHeader,
    metadata: RecordingMetadata,
    current_segment: Vec<Message>,
    segment_id: u32,
    segment_offsets: Vec<u64>,
    topic_stats: HashMap<String, TopicStats>,
    first_timestamp: Option<u64>,
    last_timestamp: u64,
    message_count: u64,
}

#[derive(Default)]
struct TopicStats {
    type_name: String,
    count: u64,
}

impl HddsWriter {
    /// Create a new HDDS writer.
    pub fn create<P: AsRef<Path>>(
        path: P,
        metadata: RecordingMetadata,
    ) -> Result<Self, FormatError> {
        let file = File::create(path)?;
        let mut writer = BufWriter::new(file);

        // Write placeholder header (will be updated on finalize)
        let header = FileHeader::new();
        header.write(&mut writer)?;

        Ok(Self {
            writer,
            header,
            metadata,
            current_segment: Vec::with_capacity(DEFAULT_SEGMENT_SIZE),
            segment_id: 0,
            segment_offsets: Vec::new(),
            topic_stats: HashMap::new(),
            first_timestamp: None,
            last_timestamp: 0,
            message_count: 0,
        })
    }

    /// Flush current segment to disk.
    fn flush_segment(&mut self) -> Result<(), FormatError> {
        if self.current_segment.is_empty() {
            return Ok(());
        }

        // Record segment offset
        let offset = self.writer.stream_position()?;
        self.segment_offsets.push(offset);

        // Calculate segment stats
        let first_ts = self
            .current_segment
            .first()
            .map(|m| m.timestamp_nanos)
            .unwrap_or(0);
        let last_ts = self
            .current_segment
            .last()
            .map(|m| m.timestamp_nanos)
            .unwrap_or(0);

        // Serialize messages to buffer for CRC
        let mut data_buf = Vec::new();
        for msg in &self.current_segment {
            Self::write_message_to_buf(&mut data_buf, msg)?;
        }

        // Write segment header
        let seg_header = SegmentHeader {
            segment_id: self.segment_id,
            message_count: self.current_segment.len() as u32,
            data_size: data_buf.len() as u32,
            first_timestamp: first_ts,
            last_timestamp: last_ts,
            reserved: 0,
        };
        seg_header.write(&mut self.writer)?;

        // Write message data
        self.writer.write_all(&data_buf)?;

        // Write CRC32
        let crc = crc32fast::hash(&data_buf);
        self.writer.write_u32::<LittleEndian>(crc)?;

        // Update stats
        for msg in &self.current_segment {
            let stats = self.topic_stats.entry(msg.topic_name.clone()).or_default();
            stats.type_name = msg.type_name.clone();
            stats.count += 1;
        }

        // Clear segment buffer
        self.current_segment.clear();
        self.segment_id += 1;

        Ok(())
    }

    /// Write a single message to buffer.
    fn write_message_to_buf(buf: &mut Vec<u8>, msg: &Message) -> Result<(), FormatError> {
        buf.write_u64::<LittleEndian>(msg.timestamp_nanos)?;
        buf.write_u16::<LittleEndian>(msg.topic_name.len() as u16)?;
        buf.write_u16::<LittleEndian>(msg.type_name.len() as u16)?;

        // Writer GUID (16 bytes from hex)
        let guid_bytes = hex_decode(&msg.writer_guid).unwrap_or_else(|| vec![0u8; 16]);
        let mut guid_arr = [0u8; 16];
        let copy_len = guid_bytes.len().min(16);
        guid_arr[..copy_len].copy_from_slice(&guid_bytes[..copy_len]);
        buf.write_all(&guid_arr)?;

        buf.write_u64::<LittleEndian>(msg.sequence_number)?;
        buf.write_u32::<LittleEndian>(msg.qos_hash)?;
        // Added in FORMAT_VERSION 2 (FORMAT_VERSION_WITH_REPRESENTATION):
        // see Message::representation for what this is and why a reader
        // of an older file defaults it instead of refusing the file.
        buf.write_u16::<LittleEndian>(msg.representation)?;
        buf.write_u32::<LittleEndian>(msg.payload.len() as u32)?;

        buf.write_all(msg.topic_name.as_bytes())?;
        buf.write_all(msg.type_name.as_bytes())?;
        buf.write_all(&msg.payload)?;

        Ok(())
    }
}

impl HddsFormat for HddsWriter {
    fn write_message(&mut self, msg: &Message) -> Result<(), FormatError> {
        // Track timestamps
        if self.first_timestamp.is_none() {
            self.first_timestamp = Some(msg.timestamp_nanos);
        }
        self.last_timestamp = msg.timestamp_nanos;
        self.message_count += 1;

        // Add to current segment
        self.current_segment.push(msg.clone());

        // Flush if segment is full
        if self.current_segment.len() >= DEFAULT_SEGMENT_SIZE {
            self.flush_segment()?;
        }

        Ok(())
    }

    fn finalize(mut self) -> Result<(), FormatError> {
        // Flush remaining messages
        self.flush_segment()?;

        // Build index (simplified: one entry per topic per segment)
        let index_offset = self.writer.stream_position()?;
        let mut index_entries = Vec::new();

        for (topic, stats) in &self.topic_stats {
            let hash = fnv1a_hash(topic);
            index_entries.push(IndexEntry {
                topic_hash: hash,
                segment_id: 0, // Simplified: all in "segment 0" conceptually
                offset: 0,
                count: stats.count as u32,
            });
        }

        for entry in &index_entries {
            entry.write(&mut self.writer)?;
        }

        // Write metadata JSON
        let mut metadata = self.metadata;
        metadata.topics = self
            .topic_stats
            .iter()
            .map(|(name, stats)| TopicInfo {
                name: name.clone(),
                type_name: stats.type_name.clone(),
                message_count: stats.count,
                reliability: "RELIABLE".into(), // FIXME(#recording-qos): track actual QoS from writer
                durability: "VOLATILE".into(), // FIXME(#recording-qos): track actual QoS from writer
            })
            .collect();

        let metadata_offset = self.writer.stream_position()?;
        let metadata_json = serde_json::to_vec(&metadata)?;
        self.writer.write_all(&metadata_json)?;

        // Update header
        self.header.metadata_offset = metadata_offset;
        self.header.metadata_size = metadata_json.len() as u32;
        self.header.index_offset = index_offset;
        self.header.index_count = index_entries.len() as u32;
        self.header.message_count = self.message_count;
        self.header.duration_nanos = self.last_timestamp - self.first_timestamp.unwrap_or(0);

        // Seek back and write final header
        self.writer.seek(SeekFrom::Start(0))?;
        self.header.write(&mut self.writer)?;

        self.writer.flush()?;

        Ok(())
    }
}

/// HDDS file reader.
pub struct HddsReader {
    reader: BufReader<File>,
    header: FileHeader,
    metadata: RecordingMetadata,
    messages_remaining_in_segment: u32,
    segment_data_end: u64,
    /// The representation [`Self::read_message`] fills in for a message
    /// from a file older than `FORMAT_VERSION_WITH_REPRESENTATION` (see
    /// [`Message::representation`]). Defaults to XCDR2 at [`Self::open`]
    /// (what a 1.4.x default writer -- the only kind of writer a
    /// FORMAT_VERSION 1 file could have recorded -- actually encoded);
    /// override with [`Self::with_legacy_representation`] for the rare
    /// recording whose source writer explicitly set `[XCDR1]`.
    legacy_representation: u16,
}

impl HddsReader {
    /// Open an HDDS file for reading.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, FormatError> {
        let file = File::open(path)?;
        let mut reader = BufReader::new(file);

        // Read header
        let header = FileHeader::read(&mut reader)?;

        // Accept every version from MIN_SUPPORTED_FORMAT_VERSION up to
        // (and including) the current one: an older file is missing
        // fields added since (Message::representation, added at
        // FORMAT_VERSION_WITH_REPRESENTATION), which read_single_message
        // fills in with their documented defaults rather than this open()
        // refusing a file HDDS itself wrote.
        if header.version < MIN_SUPPORTED_FORMAT_VERSION || header.version > FORMAT_VERSION {
            return Err(FormatError::VersionMismatch {
                expected: FORMAT_VERSION,
                got: header.version,
            });
        }

        // Read metadata
        reader.seek(SeekFrom::Start(header.metadata_offset))?;
        let mut meta_buf = vec![0u8; header.metadata_size as usize];
        reader.read_exact(&mut meta_buf)?;
        let metadata: RecordingMetadata = serde_json::from_slice(&meta_buf)?;

        // Seek back to first segment
        reader.seek(SeekFrom::Start(FileHeader::SIZE as u64))?;

        Ok(Self {
            reader,
            header,
            metadata,
            messages_remaining_in_segment: 0,
            segment_data_end: 0,
            legacy_representation: hdds::CdrVersion::Xcdr2.representation_code(),
        })
    }

    /// Override the representation filled in for every message of a file
    /// older than `FORMAT_VERSION_WITH_REPRESENTATION` (default: XCDR2 --
    /// see [`Self::legacy_representation`]'s doc). Use this only for a
    /// recording known to have come from a source writer that explicitly
    /// set `data_representation([XCDR1])`: an unstated default writer
    /// never did.
    #[must_use]
    pub fn with_legacy_representation(mut self, version: hdds::CdrVersion) -> Self {
        self.legacy_representation = version.representation_code();
        self
    }

    /// Get recording metadata.
    pub fn metadata(&self) -> &RecordingMetadata {
        &self.metadata
    }

    /// Get total message count.
    pub fn message_count(&self) -> u64 {
        self.header.message_count
    }

    /// Get recording duration in nanoseconds.
    pub fn duration_nanos(&self) -> u64 {
        self.header.duration_nanos
    }

    /// Read next message.
    pub fn read_message(&mut self) -> Result<Option<Message>, FormatError> {
        loop {
            // Check if we need to read a new segment header
            if self.messages_remaining_in_segment == 0 {
                let pos = self.reader.stream_position()?;
                if pos >= self.header.index_offset {
                    return Ok(None); // Reached index, no more messages
                }

                // Read segment header
                let seg_header = SegmentHeader::read(&mut self.reader)?;
                self.messages_remaining_in_segment = seg_header.message_count;
                self.segment_data_end =
                    self.reader.stream_position()? + seg_header.data_size as u64;

                if seg_header.message_count == 0 {
                    // Skip empty segment + CRC
                    self.reader.seek(SeekFrom::Current(4))?; // Skip CRC
                    continue;
                }
            }

            // Read message from current segment
            match Self::read_single_message(
                &mut self.reader,
                self.header.version,
                self.legacy_representation,
            ) {
                Ok(msg) => {
                    self.messages_remaining_in_segment -= 1;

                    // If segment exhausted, skip CRC
                    if self.messages_remaining_in_segment == 0 {
                        // Skip past CRC (4 bytes)
                        self.reader
                            .seek(SeekFrom::Start(self.segment_data_end + 4))?;
                    }

                    return Ok(Some(msg));
                }
                Err(FormatError::Io(e)) if e.kind() == io::ErrorKind::UnexpectedEof => {
                    return Ok(None);
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// `format_version` is the FILE's header version (`FileHeader::version`),
    /// not necessarily the crate's current `FORMAT_VERSION`: it decides
    /// whether this message carries the `representation` field at all.
    /// `legacy_representation` is the wire code filled in when it does
    /// not (see [`Self::legacy_representation`]'s doc).
    fn read_single_message<R: Read>(
        r: &mut R,
        format_version: u32,
        legacy_representation: u16,
    ) -> Result<Message, FormatError> {
        let timestamp_nanos = r.read_u64::<LittleEndian>()?;
        let topic_len = r.read_u16::<LittleEndian>()? as usize;
        let type_len = r.read_u16::<LittleEndian>()? as usize;

        let mut guid_bytes = [0u8; 16];
        r.read_exact(&mut guid_bytes)?;
        let writer_guid = hex_encode(&guid_bytes);

        let sequence_number = r.read_u64::<LittleEndian>()?;
        let qos_hash = r.read_u32::<LittleEndian>()?;
        // See Message::representation for the documented default a
        // pre-FORMAT_VERSION_WITH_REPRESENTATION file gets here, and why.
        let representation = if format_version >= FORMAT_VERSION_WITH_REPRESENTATION {
            r.read_u16::<LittleEndian>()?
        } else {
            legacy_representation
        };
        let payload_len = r.read_u32::<LittleEndian>()? as usize;

        let mut topic_buf = vec![0u8; topic_len];
        r.read_exact(&mut topic_buf)?;
        let topic_name = String::from_utf8_lossy(&topic_buf).to_string();

        let mut type_buf = vec![0u8; type_len];
        r.read_exact(&mut type_buf)?;
        let type_name = String::from_utf8_lossy(&type_buf).to_string();

        let mut payload = vec![0u8; payload_len];
        r.read_exact(&mut payload)?;

        Ok(Message {
            timestamp_nanos,
            topic_name,
            type_name,
            writer_guid,
            sequence_number,
            payload,
            qos_hash,
            representation,
        })
    }

    /// Iterate over all messages.
    pub fn messages(self) -> MessageIterator {
        MessageIterator { reader: self }
    }
}

/// Iterator over messages in an HDDS file.
pub struct MessageIterator {
    reader: HddsReader,
}

impl Iterator for MessageIterator {
    type Item = Result<Message, FormatError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.reader.read_message() {
            Ok(Some(msg)) => Some(Ok(msg)),
            Ok(None) => None,
            Err(e) => Some(Err(e)),
        }
    }
}

// Helper functions

fn fnv1a_hash(s: &str) -> u32 {
    let mut hash: u32 = 0x811c9dc5;
    for byte in s.bytes() {
        hash ^= byte as u32;
        hash = hash.wrapping_mul(0x01000193);
    }
    hash
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_file_header_roundtrip() {
        let mut buf = Vec::new();
        let header = FileHeader::new();
        header.write(&mut buf).expect("write header");
        assert_eq!(buf.len(), FileHeader::SIZE);

        let mut cursor = std::io::Cursor::new(buf);
        let read_header = FileHeader::read(&mut cursor).expect("read header");

        assert_eq!(read_header.magic, MAGIC);
        assert_eq!(read_header.version, FORMAT_VERSION);
    }

    #[test]
    fn test_segment_header_roundtrip() {
        let mut buf = Vec::new();
        let header = SegmentHeader {
            segment_id: 42,
            message_count: 100,
            data_size: 5000,
            first_timestamp: 1000,
            last_timestamp: 2000,
            reserved: 0,
        };
        header.write(&mut buf).expect("write");

        let mut cursor = std::io::Cursor::new(buf);
        let read = SegmentHeader::read(&mut cursor).expect("read");

        assert_eq!(read.segment_id, 42);
        assert_eq!(read.message_count, 100);
    }

    #[test]
    fn test_write_read_messages() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("test.hdds");

        // Write
        {
            let metadata = RecordingMetadata {
                domain_id: 0,
                ..Default::default()
            };
            let mut writer = HddsWriter::create(&path, metadata).expect("create");

            for i in 0..100 {
                // Alternate representation per message: the roundtrip
                // must carry each one through, not just whichever is
                // written most often.
                let representation = if i % 2 == 0 {
                    hdds::CdrVersion::Xcdr1.representation_code()
                } else {
                    hdds::CdrVersion::Xcdr2.representation_code()
                };
                let msg = Message {
                    timestamp_nanos: i * 1000,
                    topic_name: "TestTopic".into(),
                    type_name: "TestType".into(),
                    writer_guid: "0102030405060708090a0b0c00000302".into(),
                    sequence_number: i,
                    payload: vec![i as u8; 10],
                    qos_hash: 0x12345678,
                    representation,
                };
                writer.write_message(&msg).expect("write message");
            }

            writer.finalize().expect("finalize");
        }

        // Read
        {
            let reader = HddsReader::open(&path).expect("open");
            assert_eq!(reader.message_count(), 100);
            assert_eq!(reader.metadata().domain_id, 0);

            let messages: Vec<_> = reader.messages().collect();
            assert_eq!(messages.len(), 100);

            let first = messages[0].as_ref().expect("first msg");
            assert_eq!(first.topic_name, "TestTopic");
            assert_eq!(first.sequence_number, 0);
            assert_eq!(
                first.representation,
                hdds::CdrVersion::Xcdr1.representation_code()
            );
            let second = messages[1].as_ref().expect("second msg");
            assert_eq!(
                second.representation,
                hdds::CdrVersion::Xcdr2.representation_code()
            );
        }
    }

    /// A file recorded under FORMAT_VERSION 1 (no per-message
    /// representation field at all) must still load, with
    /// `Message::representation` filled in to its documented default
    /// (XCDR2: what a 1.4.x default writer -- the only kind of
    /// writer a FORMAT_VERSION 1 file could have recorded -- actually
    /// encoded) rather than this read refusing the file.
    #[test]
    fn a_version_1_file_loads_with_the_documented_representation_default() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("v1.hdds");

        // Hand-build a minimal, valid version-1 file: one segment, one
        // message, written in the pre-FORMAT_VERSION_WITH_REPRESENTATION
        // layout (no representation u16 between qos_hash and payload_len).
        let topic_name = b"V1Topic";
        let type_name = b"V1Type";
        let payload = [0xAAu8, 0xBB, 0xCC];

        let mut body = Vec::new();
        body.write_u64::<LittleEndian>(0).unwrap(); // timestamp_nanos
        body.write_u16::<LittleEndian>(topic_name.len() as u16)
            .unwrap();
        body.write_u16::<LittleEndian>(type_name.len() as u16)
            .unwrap();
        body.write_all(&[0u8; 16]).unwrap(); // writer_guid
        body.write_u64::<LittleEndian>(7).unwrap(); // sequence_number
        body.write_u32::<LittleEndian>(0xdead_beef).unwrap(); // qos_hash
                                                              // NOTE: no representation field here -- this IS the v1 layout.
        body.write_u32::<LittleEndian>(payload.len() as u32)
            .unwrap();
        body.write_all(topic_name).unwrap();
        body.write_all(type_name).unwrap();
        body.write_all(&payload).unwrap();

        let mut segment = Vec::new();
        let seg_header = SegmentHeader {
            segment_id: 0,
            message_count: 1,
            data_size: body.len() as u32,
            first_timestamp: 0,
            last_timestamp: 0,
            reserved: 0,
        };
        seg_header.write(&mut segment).unwrap();
        segment.write_all(&body).unwrap();
        segment.write_u32::<LittleEndian>(0).unwrap(); // CRC (unchecked here)

        let metadata = RecordingMetadata::default();
        let metadata_json = serde_json::to_vec(&metadata).unwrap();

        let mut file = Vec::new();
        let mut header = FileHeader::new();
        header.version = 1;
        header.write(&mut file).unwrap();
        file.write_all(&segment).unwrap();
        let index_offset = file.len() as u64;
        // index_count = 0: no index entries needed for this test.
        let metadata_offset = file.len() as u64;
        file.write_all(&metadata_json).unwrap();

        header.metadata_offset = metadata_offset;
        header.metadata_size = metadata_json.len() as u32;
        header.index_offset = index_offset;
        header.index_count = 0;
        header.message_count = 1;
        header.duration_nanos = 0;
        let mut final_header = Vec::new();
        header.write(&mut final_header).unwrap();
        file[..FileHeader::SIZE].copy_from_slice(&final_header);

        std::fs::write(&path, &file).unwrap();

        let reader = HddsReader::open(&path).expect("a v1 file must still open");
        let messages: Vec<_> = reader.messages().collect();
        assert_eq!(messages.len(), 1);
        let msg = messages[0].as_ref().expect("v1 message should decode");
        assert_eq!(msg.topic_name, "V1Topic");
        assert_eq!(msg.sequence_number, 7);
        assert_eq!(msg.payload, payload);
        assert_eq!(
            msg.representation,
            hdds::CdrVersion::Xcdr2.representation_code(),
            "a v1 file has no stored representation; it must default to XCDR2, \
             the representation the 1.4.x default writer actually sent"
        );
    }

    /// [`HddsReader::with_legacy_representation`] overrides the v1 default
    /// for the rare recording whose source writer explicitly set
    /// `[XCDR1]`.
    #[test]
    fn with_legacy_representation_overrides_the_v1_default() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("v1.hdds");

        let topic_name = b"V1Topic";
        let type_name = b"V1Type";
        let payload = [0xAAu8, 0xBB, 0xCC];

        let mut body = Vec::new();
        body.write_u64::<LittleEndian>(0).unwrap();
        body.write_u16::<LittleEndian>(topic_name.len() as u16)
            .unwrap();
        body.write_u16::<LittleEndian>(type_name.len() as u16)
            .unwrap();
        body.write_all(&[0u8; 16]).unwrap();
        body.write_u64::<LittleEndian>(7).unwrap();
        body.write_u32::<LittleEndian>(0xdead_beef).unwrap();
        body.write_u32::<LittleEndian>(payload.len() as u32)
            .unwrap();
        body.write_all(topic_name).unwrap();
        body.write_all(type_name).unwrap();
        body.write_all(&payload).unwrap();

        let mut segment = Vec::new();
        let seg_header = SegmentHeader {
            segment_id: 0,
            message_count: 1,
            data_size: body.len() as u32,
            first_timestamp: 0,
            last_timestamp: 0,
            reserved: 0,
        };
        seg_header.write(&mut segment).unwrap();
        segment.write_all(&body).unwrap();
        segment.write_u32::<LittleEndian>(0).unwrap();

        let metadata = RecordingMetadata::default();
        let metadata_json = serde_json::to_vec(&metadata).unwrap();

        let mut file = Vec::new();
        let mut header = FileHeader::new();
        header.version = 1;
        header.write(&mut file).unwrap();
        file.write_all(&segment).unwrap();
        let index_offset = file.len() as u64;
        let metadata_offset = file.len() as u64;
        file.write_all(&metadata_json).unwrap();

        header.metadata_offset = metadata_offset;
        header.metadata_size = metadata_json.len() as u32;
        header.index_offset = index_offset;
        header.index_count = 0;
        header.message_count = 1;
        header.duration_nanos = 0;
        let mut final_header = Vec::new();
        header.write(&mut final_header).unwrap();
        file[..FileHeader::SIZE].copy_from_slice(&final_header);

        std::fs::write(&path, &file).unwrap();

        let reader = HddsReader::open(&path)
            .expect("open")
            .with_legacy_representation(hdds::CdrVersion::Xcdr1);
        let messages: Vec<_> = reader.messages().collect();
        assert_eq!(messages.len(), 1);
        let msg = messages[0].as_ref().expect("v1 message should decode");
        assert_eq!(
            msg.representation,
            hdds::CdrVersion::Xcdr1.representation_code(),
            "with_legacy_representation(Xcdr1) must override the XCDR2 default"
        );
    }

    #[test]
    fn test_fnv1a_hash() {
        // Consistent hash
        assert_eq!(fnv1a_hash("Temperature"), fnv1a_hash("Temperature"));
        // Different strings -> different hashes
        assert_ne!(fnv1a_hash("Temperature"), fnv1a_hash("Pressure"));
    }

    #[test]
    fn test_hex_encode_decode() {
        let bytes = [0xde, 0xad, 0xbe, 0xef];
        let hex = hex_encode(&bytes);
        assert_eq!(hex, "deadbeef");

        let decoded = hex_decode(&hex).expect("decode");
        assert_eq!(decoded, bytes);
    }
}
