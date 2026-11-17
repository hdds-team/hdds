// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! DDS Bridge - Connects WebSocket clients to DDS topics.
//!
//! Manages a DomainParticipant and creates dynamic readers/writers
//! for topics requested by WebSocket clients.

use crate::protocol::{SampleInfo, TopicInfo};
use dashmap::DashMap;
use hdds::dds::{Participant, RawDataReader, RawDataWriter, TransportMode};
use hdds::dynamic::json::{cdr_to_json_dynamic_with_version, raw_cdr_to_json};
use hdds::dynamic::TypeDescriptor;
use hdds::DiscoveredEndpointKind;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::SystemTime;
use tokio::sync::{broadcast, Mutex};
use tracing::{debug, info, warn};

/// A sample received from DDS
#[derive(Debug, Clone)]
pub struct BridgeSample {
    pub topic: String,
    pub data: serde_json::Value,
    pub info: Option<SampleInfo>,
}

/// Active subscription state
struct Subscription {
    /// Kept alive for proper shutdown (reader dropped = DDS reader unregistered).
    _reader: Arc<RawDataReader>,
    sender: broadcast::Sender<BridgeSample>,
    /// TypeDescriptor for dynamic CDR decoding (discovered via XTypes)
    /// Stored here to keep the Arc alive for the subscription's lifetime.
    _type_descriptor: Option<Arc<TypeDescriptor>>,
}

/// DDS Bridge - manages participant and topic subscriptions
pub struct DdsBridge {
    domain_id: u32,
    participant: Arc<Participant>,
    /// Active subscriptions: topic_name -> Subscription. Wrapped in `Arc` so
    /// the per-topic reader task can self-remove its entry on exit (when the
    /// last WebSocket client for a topic goes away, see `reader_task`'s
    /// grace-period exit).
    subscriptions: Arc<DashMap<String, Subscription>>,
    /// Writers for publishing: topic_name -> RawDataWriter (wrapped in Mutex for thread safety)
    writers: DashMap<String, Arc<Mutex<RawDataWriter>>>,
    /// Sequence counter for published messages
    publish_seq: AtomicU64,
}

/// Use the same dependency-aware path for initial and late subscriptions.
fn resolve_topic_descriptor(
    participant: &Participant,
    topic_name: &str,
) -> Option<Arc<TypeDescriptor>> {
    let endpoints = participant.discover_endpoints().ok()?;
    for endpoint in endpoints {
        if endpoint.topic_name == topic_name && endpoint.kind == DiscoveredEndpointKind::Writer {
            match participant.resolve_type_descriptor(&endpoint.endpoint_guid) {
                Ok(Some(descriptor)) => return Some(descriptor),
                Ok(None) => {}
                Err(error) => debug!("Cannot resolve layout for '{}': {}", topic_name, error),
            }
        }
    }
    None
}

impl DdsBridge {
    /// Create a new DDS bridge
    pub async fn new(
        domain_id: u32,
        name: &str,
        transport: &str,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let transport_mode = match transport {
            "udp" | "multicast" => TransportMode::UdpMulticast,
            "intra" | "intraprocess" => TransportMode::IntraProcess,
            other => {
                warn!("Unknown transport '{}', defaulting to UDP multicast", other);
                TransportMode::UdpMulticast
            }
        };

        info!(
            "Creating DDS participant '{}' on domain {} with {:?} transport",
            name, domain_id, transport_mode
        );

        let participant = Participant::builder(name)
            .domain_id(domain_id)
            .with_transport(transport_mode)
            .build()?;

        Ok(Self {
            domain_id,
            participant,
            subscriptions: Arc::new(DashMap::new()),
            writers: DashMap::new(),
            publish_seq: AtomicU64::new(0),
        })
    }

    /// Get domain ID
    pub fn domain_id(&self) -> u32 {
        self.domain_id
    }

    /// Subscribe to a topic, returns a receiver for samples
    pub async fn subscribe(
        &self,
        topic_name: &str,
    ) -> Result<broadcast::Receiver<BridgeSample>, Box<dyn std::error::Error + Send + Sync>> {
        // Fast path: an existing subscription for this topic -- just hand out
        // another broadcast::Receiver. No DashMap::entry() here to avoid
        // contending the shard lock with concurrent subscribe() calls.
        if let Some(sub) = self.subscriptions.get(topic_name) {
            debug!("Reusing existing subscription for topic '{}'", topic_name);
            return Ok(sub.sender.subscribe());
        }

        // Slow path: no entry yet. Use `entry()` so the check-then-insert is
        // atomic across concurrent subscribe() calls for the *same* topic.
        // Without this, two near-simultaneous subscribers both saw the
        // vacant state, both called `create_raw_reader`, both inserted, and
        // one winner's subscription was silently overwritten -- leaving an
        // orphan DDS reader attached to the participant.
        match self.subscriptions.entry(topic_name.to_string()) {
            dashmap::mapref::entry::Entry::Occupied(e) => {
                debug!(
                    "Another task created subscription for '{}' between our get() and entry() -- reusing",
                    topic_name
                );
                Ok(e.get().sender.subscribe())
            }
            dashmap::mapref::entry::Entry::Vacant(v) => {
                info!("Creating subscription for topic '{}'", topic_name);

                // Try to discover TypeObject for this topic (XTypes dynamic
                // decoding). Safe to do under the entry lock -- it's a read
                // against the participant's discovery cache, not an
                // await-point.
                let type_descriptor = self.discover_type_descriptor(topic_name);
                if type_descriptor.is_some() {
                    info!(
                        "Discovered TypeObject for '{}' - enabling dynamic CDR decoding",
                        topic_name
                    );
                } else {
                    debug!(
                        "No TypeObject found for '{}' - using fallback decoding",
                        topic_name
                    );
                }

                // Create DDS raw reader
                let reader = self.participant.create_raw_reader(topic_name, None)?;
                let reader = Arc::new(reader);

                // Create broadcast channel for this topic
                let (tx, rx) = broadcast::channel(256);

                // Insert; the returned RefMut drops at statement end, releasing
                // the shard lock before we spawn.
                v.insert(Subscription {
                    _reader: reader.clone(),
                    sender: tx.clone(),
                    _type_descriptor: type_descriptor.clone(),
                });

                // Spawn task to read from DDS and forward to broadcast.
                // The task is passed an Arc clone of the subscriptions map so
                // it can remove its own entry when the last receiver goes
                // away -- this avoids the "zombie reader_task" leak where
                // unsubscribed topics kept a DDS reader + a tokio task
                // running for the life of the process.
                let topic = topic_name.to_string();
                let tx_clone = tx;
                let reader_clone = reader;
                let desc_clone = type_descriptor;
                let participant_clone = self.participant.clone();
                let subs_clone = Arc::clone(&self.subscriptions);

                tokio::spawn(async move {
                    Self::reader_task(
                        topic,
                        reader_clone,
                        tx_clone,
                        desc_clone,
                        participant_clone,
                        subs_clone,
                    )
                    .await;
                });

                Ok(rx)
            }
        }
    }

    /// Try to discover TypeObject for a topic and convert to TypeDescriptor
    fn discover_type_descriptor(&self, topic_name: &str) -> Option<Arc<TypeDescriptor>> {
        resolve_topic_descriptor(&self.participant, topic_name)
    }

    /// Reader task - reads from DDS and forwards to broadcast channel.
    ///
    /// If `type_descriptor` is `None` on startup (TypeObject not yet discovered),
    /// the task retries discovery on each poll until successful.
    ///
    /// # Lifecycle
    ///
    /// The task exits when the last WebSocket client has disconnected from
    /// this topic for `RECEIVER_GRACE_TICKS` consecutive iterations (~300 ms
    /// of idle). On exit it removes its own entry from `subscriptions`, so
    /// a future `subscribe(topic)` call re-creates a fresh reader rather than
    /// reusing a closed sender. The grace window tolerates brief reconnects
    /// and per-client task-spawn delays.
    async fn reader_task(
        topic_name: String,
        reader: Arc<RawDataReader>,
        tx: broadcast::Sender<BridgeSample>,
        initial_descriptor: Option<Arc<TypeDescriptor>>,
        participant: Arc<Participant>,
        subscriptions: Arc<DashMap<String, Subscription>>,
    ) {
        /// Number of consecutive idle ticks with zero broadcast receivers
        /// before the task self-terminates. Deliberately counted in ticks,
        /// not wall-clock: depending on the adaptive sleep cadence below,
        /// 30 ticks maps to ~300 ms when hot or ~3 s when cold. Both are
        /// reasonable grace windows and neither blocks shutdown.
        const RECEIVER_GRACE_TICKS: u32 = 30;
        /// Consecutive empty polls before we back off to the slow cadence.
        const IDLE_BACKOFF_TICKS: u32 = 5;
        /// Fast poll interval while samples are flowing.
        const ACTIVE_POLL_MS: u64 = 10;
        /// Slow poll interval when no data has arrived for a while -- keeps
        /// CPU cost low on ARM / embedded hosts where 100 wakeups/s-per-topic
        /// adds up (7 topics x 100 Hz = 700 wakeups/s).
        const IDLE_POLL_MS: u64 = 100;

        info!(
            "Reader for '{}' started (dynamic decoding: {})",
            topic_name,
            initial_descriptor.is_some()
        );

        let mut type_descriptor = initial_descriptor;
        let mut next_type_lookup = tokio::time::Instant::now();
        let mut idle_ticks: u32 = 0;
        let mut empty_poll_ticks: u32 = 0;

        loop {
            // Self-terminate when no WebSocket clients have been listening
            // for RECEIVER_GRACE_TICKS consecutive iterations. This replaces
            // the previous forever-loop which kept the DDS reader (and this
            // task) alive for the lifetime of the process even after every
            // client had disconnected.
            if tx.receiver_count() == 0 {
                idle_ticks = idle_ticks.saturating_add(1);
                if idle_ticks >= RECEIVER_GRACE_TICKS {
                    info!(
                        "Reader for '{}' idle {} ticks, self-terminating and removing subscription",
                        topic_name, idle_ticks
                    );
                    // Drop our entry so the next subscribe() creates a fresh
                    // reader+sender pair rather than handing out a closed one.
                    subscriptions.remove(&topic_name);
                    break;
                }
            } else {
                idle_ticks = 0;
            }

            // Retry the complete dependency closure, not just the root.
            if type_descriptor.is_none() && tokio::time::Instant::now() >= next_type_lookup {
                next_type_lookup =
                    tokio::time::Instant::now() + std::time::Duration::from_millis(250);
                type_descriptor = resolve_topic_descriptor(&participant, &topic_name);
                if type_descriptor.is_some() {
                    info!(
                        "Resolved complete layout for '{}' - enabling dynamic CDR decoding",
                        topic_name
                    );
                }
            }

            // Poll for data
            let mut samples_in_batch = 0usize;
            match reader.try_take_raw_with_encoding() {
                Ok(samples) => {
                    for (raw_sample, cdr_version) in samples {
                        samples_in_batch += 1;
                        // Convert raw CDR to JSON
                        let json_value = if let Some(ref desc) = type_descriptor {
                            // Use XTypes dynamic decoding
                            cdr_to_json_dynamic_with_version(&raw_sample.payload, desc, cdr_version)
                        } else {
                            // Fallback to basic decoding
                            raw_cdr_to_json(&raw_sample.payload)
                        };

                        let sample = BridgeSample {
                            topic: topic_name.clone(),
                            data: json_value,
                            info: Some(SampleInfo {
                                source_timestamp_ms: system_time_to_ms(raw_sample.source_timestamp),
                                reception_timestamp_ms: system_time_to_ms(
                                    raw_sample.reception_timestamp,
                                ),
                                sequence: raw_sample.sequence_number,
                                writer_guid: Some(format!("{:?}", raw_sample.writer_guid)),
                            }),
                        };

                        // Send to all WebSocket clients (ignore if no receivers)
                        let _ = tx.send(sample);
                    }
                }
                Err(e) => {
                    warn!("Read error on '{}': {}", topic_name, e);
                }
            }

            // Adaptive poll cadence: 10 ms while data is flowing (keep
            // WebSocket-visible latency sharp), 100 ms once the topic has
            // been quiet for IDLE_BACKOFF_TICKS ticks (cuts wakeups/s by
            // 10x per topic on idle workloads, which dominates the CPU
            // budget on embedded hosts).
            if samples_in_batch > 0 {
                empty_poll_ticks = 0;
            } else {
                empty_poll_ticks = empty_poll_ticks.saturating_add(1);
            }
            let sleep_ms = if empty_poll_ticks < IDLE_BACKOFF_TICKS {
                ACTIVE_POLL_MS
            } else {
                IDLE_POLL_MS
            };
            tokio::time::sleep(tokio::time::Duration::from_millis(sleep_ms)).await;
        }
    }

    /// Publish data to a topic
    pub async fn publish(
        &self,
        topic_name: &str,
        data: serde_json::Value,
    ) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
        // Get or create writer
        let writer = if let Some(w) = self.writers.get(topic_name) {
            w.clone()
        } else {
            info!("Creating writer for topic '{}'", topic_name);
            // json_to_raw_cdr RE-ENCODES from scratch (it does not pass
            // through opaque captured bytes), so this writer must offer
            // the representation that encoder actually implements rather
            // than whatever an unset DATA_REPRESENTATION happens to
            // resolve to. json_to_raw_cdr only ever emits a single
            // top-level string member (len:u32 + bytes + NUL): XCDR1 and
            // XCDR2 encode that identically, so the choice carries no
            // observable difference today, but leaving it to the
            // implicit default (which happens to also be XCDR1, since
            // RawBytes::encodes_xcdr1_natively() is true) is exactly the
            // "label whatever we were given" pattern item 6 fixed
            // elsewhere. Pin it explicitly: XCDR1, matching what a
            // default-QoS writer of a plain derived type (e.g. a
            // std_msgs::String-shaped struct) offers elsewhere in HDDS,
            // so a peer expecting that convention is not surprised.
            let qos = hdds::QoS::default().data_representation_xcdr1();
            let writer = self.participant.create_raw_writer(topic_name, Some(qos))?;
            let writer = Arc::new(Mutex::new(writer));
            self.writers.insert(topic_name.to_string(), writer.clone());
            writer
        };

        // Convert JSON to CDR bytes
        let cdr_bytes = json_to_raw_cdr(&data)?;

        // Publish (lock the writer)
        {
            let writer_guard = writer.lock().await;
            writer_guard.write_raw(&cdr_bytes)?;
        }

        let seq = self.publish_seq.fetch_add(1, Ordering::Relaxed);
        debug!("Published to '{}' (seq={})", topic_name, seq);

        Ok(seq)
    }

    /// Unsubscribe from a topic -- force-removes the bridge-side entry.
    ///
    /// NOTE: This does NOT directly cancel the associated `reader_task`.
    /// The task exits via its own grace-period check in `reader_task`
    /// (see `RECEIVER_GRACE_TICKS`), once the dropped `sender` leads to
    /// `tx.receiver_count() == 0` for long enough. The normal unsubscribe
    /// path is `ClientSession::handle_unsubscribe`, which aborts the
    /// per-session forwarding task -- its broadcast receiver drops,
    /// `reader_task` eventually sees zero receivers, and self-cleans. This
    /// method is retained for admin / force-cleanup scenarios only.
    #[allow(dead_code)]
    pub fn unsubscribe(&self, topic_name: &str) {
        if self.subscriptions.remove(topic_name).is_some() {
            info!("Unsubscribed from topic '{}'", topic_name);
        }
    }

    /// List discovered topics
    pub fn list_topics(&self) -> Vec<TopicInfo> {
        match self.participant.discover_topics() {
            Ok(topics) => topics
                .into_iter()
                .map(|t| TopicInfo {
                    name: t.name,
                    type_name: t.type_name,
                    subscribers: t.subscriber_count as u32,
                    publishers: t.publisher_count as u32,
                })
                .collect(),
            Err(e) => {
                warn!("Failed to discover topics: {}", e);
                Vec::new()
            }
        }
    }
}

/// Convert JSON to raw CDR bytes
///
/// Simple conversion for demo purposes.
fn json_to_raw_cdr(
    value: &serde_json::Value,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    // If the value has a "data" field (ROS2 std_msgs/String style)
    if let Some(data) = value.get("data") {
        if let Some(s) = data.as_str() {
            // Encode as ROS2 string: 4-byte length + string + null terminator
            let bytes = s.as_bytes();
            let len = (bytes.len() + 1) as u32; // +1 for null terminator
            let mut cdr = Vec::with_capacity(4 + bytes.len() + 1);
            cdr.extend_from_slice(&len.to_le_bytes());
            cdr.extend_from_slice(bytes);
            cdr.push(0); // null terminator
            return Ok(cdr);
        }
    }

    // If there's a _raw field with base64, decode it
    if let Some(raw) = value.get("_raw") {
        if let Some(b64) = raw.as_str() {
            return base64_decode(b64);
        }
    }

    // Fallback: serialize JSON as string
    let json_str = serde_json::to_string(value)?;
    let bytes = json_str.as_bytes();
    let len = (bytes.len() + 1) as u32;
    let mut cdr = Vec::with_capacity(4 + bytes.len() + 1);
    cdr.extend_from_slice(&len.to_le_bytes());
    cdr.extend_from_slice(bytes);
    cdr.push(0);
    Ok(cdr)
}

/// Convert SystemTime to milliseconds since epoch
fn system_time_to_ms(time: SystemTime) -> Option<u64> {
    time.duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_millis() as u64)
}

/// Decode standard base64 with padding into the original bytes.
///
/// Returns `Err` on any byte outside the ASCII base64 alphabet, rather than
/// folding it into the output (the `-1` sentinel was cast to `u8 = 255` and
/// fed into arithmetic).
fn base64_decode(input: &str) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    const DECODE: [i8; 128] = [
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1,
        -1, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1, -1, 0, 1, 2, 3, 4,
        5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1,
        -1, -1, -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45,
        46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
    ];

    // Validated lookup: byte must be ASCII (< 128) AND the table entry must
    // be non-negative (a real base64 char). `=` padding is stripped earlier.
    fn lookup(byte: u8, decode: &[i8; 128]) -> Result<u8, String> {
        if byte >= 128 {
            return Err(format!("non-ASCII byte 0x{byte:02x} in base64 input"));
        }
        let v = decode[byte as usize];
        u8::try_from(v).map_err(|_| format!("invalid base64 char 0x{byte:02x}"))
    }

    let input = input.trim_end_matches('=');
    let mut result = Vec::with_capacity((input.len() * 3) / 4);

    let chars: Vec<u8> = input.bytes().collect();
    for chunk in chars.chunks(4) {
        if chunk.len() < 2 {
            break;
        }

        let b0 = lookup(chunk[0], &DECODE)?;
        let b1 = lookup(chunk[1], &DECODE)?;
        result.push((b0 << 2) | (b1 >> 4));

        if chunk.len() > 2 && chunk[2] != b'=' {
            let b2 = lookup(chunk[2], &DECODE)?;
            result.push((b1 << 4) | (b2 >> 2));

            if chunk.len() > 3 && chunk[3] != b'=' {
                let b3 = lookup(chunk[3], &DECODE)?;
                result.push((b2 << 6) | b3);
            }
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    // Only the tests encode; importing it at module scope leaves it unused in a
    // non-test build, which `-D warnings` refuses.
    use hdds::dynamic::json::base64_encode;

    #[test]
    fn test_base64_roundtrip() {
        let data = b"Hello, DDS!";
        let encoded = base64_encode(data);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(data.as_slice(), decoded.as_slice());
    }

    #[test]
    fn test_ros2_string_encoding() {
        let json = serde_json::json!({"data": "Hello"});
        let cdr = json_to_raw_cdr(&json).unwrap();

        // Should be: 6 (length with null) + "Hello" + null
        assert_eq!(cdr.len(), 4 + 5 + 1);
        assert_eq!(&cdr[0..4], &6u32.to_le_bytes());
        assert_eq!(&cdr[4..9], b"Hello");
        assert_eq!(cdr[9], 0);
    }

    #[test]
    fn test_ros2_string_decoding() {
        // ROS2 std_msgs/String: length + "test" + null
        let cdr = [5, 0, 0, 0, b't', b'e', b's', b't', 0];
        let json = raw_cdr_to_json(&cdr);

        assert_eq!(json["data"], "test");
    }

    /// Non-ASCII bytes in base64 input previously panicked via
    /// `DECODE[byte as usize]` on an array of only 128 entries. The
    /// validated lookup now returns Err instead.
    #[test]
    fn test_base64_decode_rejects_non_ascii() {
        // "cafe" with a U+00E9 on the end -- it encodes to 0xC3 0xA9,
        // and both bytes are >= 128
        let input = "caf\u{00e9}";
        let err = base64_decode(input).expect_err("non-ASCII must error, not panic");
        let msg = err.to_string();
        assert!(
            msg.contains("non-ASCII"),
            "error should mention non-ASCII, got: {msg}"
        );
    }

    /// ASCII characters that aren't part of the base64 alphabet (the
    /// `-1` sentinel entries in DECODE) previously cast to 255 and silently
    /// produced garbage output. They now return Err.
    #[test]
    fn test_base64_decode_rejects_invalid_ascii() {
        // '!' (0x21) is ASCII but not a base64 char
        let err = base64_decode("!A==").expect_err("invalid char must error");
        let msg = err.to_string();
        assert!(
            msg.contains("invalid base64 char"),
            "error should mention invalid base64, got: {msg}"
        );
    }

    /// Empty input must decode to empty output without panicking.
    #[test]
    fn test_base64_decode_empty() {
        assert_eq!(base64_decode("").unwrap(), Vec::<u8>::new());
        assert_eq!(base64_decode("====").unwrap(), Vec::<u8>::new());
    }

    /// Full ASCII-alphabet roundtrip to make sure the validated path still
    /// accepts every legitimate base64 character.
    #[test]
    fn test_base64_all_chars_roundtrip() {
        // Data that exercises every 6-bit slot of the base64 alphabet.
        let data: Vec<u8> = (0u8..=255u8).collect();
        let encoded = base64_encode(&data);
        let decoded = base64_decode(&encoded).expect("must roundtrip");
        assert_eq!(data, decoded);
    }

    /// Real path: `DdsBridge::publish` must create a writer that actually
    /// OFFERS XCDR1 (see the comment at its call site), not leave it to an
    /// implicit default that happens to agree today. Proven the only way
    /// that is provable from outside: a native reader that REQUESTS only
    /// XCDR1 matches and receives the published bytes; a native reader
    /// that requests only XCDR2 never matches at all.
    #[tokio::test]
    async fn publish_creates_a_writer_that_offers_xcdr1() {
        let domain = hdds::test_support::domains::unique_domain();
        let domain_id = domain.id();
        std::mem::forget(domain);
        let topic = "ws_publish_offers_xcdr1";

        let bridge = DdsBridge::new(domain_id, "ws-publish-probe", "udp")
            .await
            .expect("bridge should start");

        let native = hdds::Participant::builder("ws-publish-probe-native")
            .domain_id(domain_id)
            .with_transport(hdds::TransportMode::UdpMulticast)
            .build()
            .expect("native participant");
        let xcdr1_reader = native
            .create_raw_reader_with_type(
                topic,
                "RawBytes",
                Some(hdds::QoS::default().data_representation_xcdr1()),
                None,
                None,
            )
            .expect("xcdr1 reader");
        let xcdr2_reader = native
            .create_raw_reader_with_type(
                topic,
                "RawBytes",
                Some(hdds::QoS::default().data_representation_xcdr2()),
                None,
                None,
            )
            .expect("xcdr2 reader");

        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        bridge
            .publish(topic, serde_json::json!({"data": "hello"}))
            .await
            .expect("publish");

        let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(5);
        let mut xcdr1_got = Vec::new();
        while tokio::time::Instant::now() < deadline && xcdr1_got.is_empty() {
            xcdr1_got = xcdr1_reader.try_take_raw().expect("xcdr1 take");
            if xcdr1_got.is_empty() {
                tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;
            }
        }

        assert!(
            !xcdr1_got.is_empty(),
            "an XCDR1-only reader must receive the published sample"
        );
        assert_eq!(
            xcdr1_got[0].payload,
            json_to_raw_cdr(&serde_json::json!({"data": "hello"})).unwrap()
        );

        let xcdr2_got = xcdr2_reader.try_take_raw().expect("xcdr2 take");
        assert!(
            xcdr2_got.is_empty(),
            "an XCDR2-only reader must never match a writer that offers XCDR1: got {xcdr2_got:?}"
        );
    }
}
