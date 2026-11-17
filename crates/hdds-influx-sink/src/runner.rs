// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! The DDS half of the sink (feature `hdds`).
//!
//! One participant, one raw reader per configured topic, samples projected to
//! JSON through [`hdds::dynamic::json`], mapped to Line Protocol by
//! [`DdsSink`], batched, and POSTed to InfluxDB by [`InfluxHttpClient`].
//!
//! Type discovery is best effort and retried: a topic whose TypeObject has
//! not been discovered yet decodes through the raw fallback, and the runner
//! upgrades to dynamic decoding as soon as discovery catches up. It never
//! drops the sample while waiting.
//!
//! Fail-closed on credentials: once InfluxDB refuses the token, the runner
//! stops rather than looping forever on a write that will not succeed.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use hdds::dds::{Participant, RawDataReader, TransportMode};
use hdds::dynamic::json::{cdr_to_json_dynamic_with_version, raw_cdr_to_json};
use hdds::dynamic::{type_descriptor_from_xtypes, TypeDescriptor};

use crate::config::SinkConfig;
use crate::http::{InfluxError, InfluxHttpClient};
use crate::recorder::DdsSink;

/// Shortest interval between two topic-discovery attempts.
const MIN_DISCOVERY_BACKOFF: Duration = Duration::from_millis(100);

/// Longest interval between two topic-discovery attempts.
const MAX_DISCOVERY_BACKOFF: Duration = Duration::from_secs(5);

/// Ceiling on lines held back while InfluxDB is unavailable. Past it the
/// oldest go: keeping every sample of an outage that never ends is just a
/// slower way to run out of memory.
const MAX_PENDING_LINES: usize = 100_000;

/// Errors from the DDS runner.
#[derive(Debug)]
pub enum RunnerError {
    /// The DDS layer refused an operation.
    Dds(String),
    /// The InfluxDB client refused to start or to write.
    Influx(InfluxError),
    /// The configuration cannot be run.
    Config(String),
}

impl std::fmt::Display for RunnerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Dds(m) => write!(f, "DDS error: {}", m),
            Self::Influx(e) => write!(f, "InfluxDB error: {}", e),
            Self::Config(m) => write!(f, "configuration error: {}", m),
        }
    }
}

impl std::error::Error for RunnerError {}

impl From<InfluxError> for RunnerError {
    fn from(e: InfluxError) -> Self {
        Self::Influx(e)
    }
}

struct TopicReader {
    topic: String,
    reader: RawDataReader,
    descriptor: Option<Arc<TypeDescriptor>>,
}

/// Subscribes to the configured topics and writes them to InfluxDB.
pub struct SinkRunner {
    participant: Arc<Participant>,
    readers: Vec<TopicReader>,
    sink: DdsSink,
    client: InfluxHttpClient,
    last_flush: Instant,
    flush_interval: Duration,
    lines_written: u64,
    /// Lines drained from the buffers that InfluxDB has not accepted yet.
    /// They are carried to the next flush, because the write client's stated
    /// policy is that a 5xx KEEPS the batch.
    pending: Vec<String>,
    /// When topic discovery may be attempted again, and how long the current
    /// back-off is.
    next_discovery: Instant,
    discovery_backoff: Duration,
}

impl SinkRunner {
    /// Build a runner: one participant on `domain_id`, one reader per sink.
    pub fn new(
        config: SinkConfig,
        domain_id: u32,
        participant_name: &str,
    ) -> Result<Self, RunnerError> {
        if config.sinks.is_empty() {
            return Err(RunnerError::Config("no sinks configured".to_string()));
        }
        let client = InfluxHttpClient::from_config(&config.influxdb)?;
        let participant = Participant::builder(participant_name)
            .domain_id(domain_id)
            .with_transport(TransportMode::UdpMulticast)
            .build()
            .map_err(|e| RunnerError::Dds(e.to_string()))?;

        let mut readers = Vec::with_capacity(config.sinks.len());
        for sink in &config.sinks {
            // A raw reader given no type name announces the one the topic's
            // writers already announce (when exactly one is known at creation),
            // else "RawBytes", which only meets another raw endpoint. A sink
            // started before its writer is discovered would keep "RawBytes", so
            // the YAML can carry the writer's own type name.
            let reader = match &sink.type_name {
                Some(type_name) => participant.create_raw_reader_with_type(
                    &sink.topic,
                    type_name,
                    None,
                    None,
                    None,
                ),
                None => participant.create_raw_reader(&sink.topic, None),
            }
            .map_err(|e| RunnerError::Dds(e.to_string()))?;
            readers.push(TopicReader {
                topic: sink.topic.clone(),
                reader,
                descriptor: None,
            });
        }
        let flush_interval = Duration::from_millis(
            config
                .sinks
                .iter()
                .filter_map(|s| s.flush_interval_ms)
                .min()
                .unwrap_or(1000),
        );

        Ok(Self {
            participant,
            readers,
            sink: DdsSink::from_config(config),
            client,
            last_flush: Instant::now(),
            flush_interval,
            lines_written: 0,
            pending: Vec::new(),
            next_discovery: Instant::now(),
            discovery_backoff: MIN_DISCOVERY_BACKOFF,
        })
    }

    /// Topics this runner subscribes to.
    pub fn topics(&self) -> Vec<&str> {
        self.readers.iter().map(|r| r.topic.as_str()).collect()
    }

    /// Line Protocol lines successfully written so far.
    pub fn lines_written(&self) -> u64 {
        self.lines_written
    }

    /// Samples recorded into the batch buffers.
    pub fn samples_recorded(&self) -> u64 {
        self.sink.samples_recorded()
    }

    /// Poll every reader once, record what arrived, and flush when the
    /// interval has elapsed. Returns how many samples were taken.
    pub fn tick(&mut self) -> Result<usize, RunnerError> {
        let mut taken = 0;
        let discovered: HashMap<String, Arc<TypeDescriptor>> = self.discover_descriptors();

        for entry in &mut self.readers {
            if entry.descriptor.is_none() {
                if let Some(descriptor) = discovered.get(&entry.topic) {
                    entry.descriptor = Some(Arc::clone(descriptor));
                }
            }
            // try_take_raw_with_encoding, never try_take_raw: the latter
            // drops the per-sample DATA_REPRESENTATION, and
            // cdr_to_json_dynamic (vs. ..._with_version) hardcodes XCDR1,
            // silently misdecoding any XCDR2 sample (item 6's pattern, on
            // the decode side rather than a relay's write side).
            let samples = entry
                .reader
                .try_take_raw_with_encoding()
                .map_err(|e| RunnerError::Dds(e.to_string()))?;
            for (sample, version) in samples {
                taken += 1;
                let json = match &entry.descriptor {
                    Some(descriptor) => {
                        cdr_to_json_dynamic_with_version(&sample.payload, descriptor, version)
                    }
                    None => raw_cdr_to_json(&sample.payload),
                };
                let timestamp_ns = sample
                    .source_timestamp
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos() as u64;
                if let Err(e) = self.sink.record_sample(&entry.topic, &json, timestamp_ns) {
                    log::warn!("sample on {} not recorded: {}", entry.topic, e);
                }
            }
        }

        if self.last_flush.elapsed() >= self.flush_interval {
            self.flush()?;
        }
        Ok(taken)
    }

    /// Push everything buffered to InfluxDB.
    ///
    /// `flush_all` DRAINS the buffers, so the drained lines are held here
    /// until InfluxDB accepts them. Without that, a 5xx would empty the sink
    /// and drop the vector on the way out of this function - and the write
    /// client's whole point is that a restarting InfluxDB does not eat
    /// samples. The held batch is bounded: past `MAX_PENDING_LINES` the
    /// OLDEST lines go, because an unbounded retry buffer is just a slower
    /// way to die.
    pub fn flush(&mut self) -> Result<usize, RunnerError> {
        self.last_flush = Instant::now();
        self.pending.append(&mut self.sink.flush_all());
        if self.pending.len() > MAX_PENDING_LINES {
            let dropped = self.pending.len() - MAX_PENDING_LINES;
            log::warn!(
                "dropping {} oldest buffered lines: InfluxDB has been unavailable too long",
                dropped
            );
            self.pending.drain(..dropped);
        }
        if self.pending.is_empty() {
            return Ok(0);
        }
        let count = self.pending.len();
        match self.client.write_lines(&self.pending) {
            Ok(crate::http::WriteOutcome::Accepted) => {
                self.pending.clear();
                self.lines_written += count as u64;
                Ok(count)
            }
            // The batch is kept: the server is down, not the data bad.
            Err(e @ (InfluxError::ServerUnavailable { .. } | InfluxError::Unauthorized(_))) => {
                Err(RunnerError::Influx(e))
            }
            // A rejected batch would loop forever; it goes.
            Err(e) => {
                self.pending.clear();
                Err(RunnerError::Influx(e))
            }
        }
    }

    /// Lines drained from the buffers that InfluxDB has not accepted yet.
    pub fn pending_lines(&self) -> usize {
        self.pending.len()
    }

    /// Run until `deadline`, or forever when it is `None`.
    ///
    /// Stops immediately on a terminal InfluxDB failure (a refused token):
    /// carrying on would mean discarding measurements against a server that
    /// will never accept them.
    pub fn run(&mut self, deadline: Option<Instant>) -> Result<(), RunnerError> {
        loop {
            if let Some(end) = deadline {
                if Instant::now() >= end {
                    self.flush()?;
                    return Ok(());
                }
            }
            self.tick()?;
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// Ask the participant for the type objects the readers are still
    /// missing.
    ///
    /// Backed off: a topic whose TypeObject never arrives (a raw-bytes
    /// writer, a vendor that publishes none) must not make a background sink
    /// rebuild the whole discovered-topic map two hundred times a second for
    /// the lifetime of the process.
    fn discover_descriptors(&mut self) -> HashMap<String, Arc<TypeDescriptor>> {
        let mut out = HashMap::new();
        if self.readers.iter().all(|r| r.descriptor.is_some()) {
            return out;
        }
        if Instant::now() < self.next_discovery {
            return out;
        }
        self.next_discovery = Instant::now() + self.discovery_backoff;
        self.discovery_backoff = (self.discovery_backoff * 2).min(MAX_DISCOVERY_BACKOFF);
        match self.participant.discover_topics() {
            Ok(topics) => {
                for topic in topics {
                    if let Some(ref type_object) = topic.type_object {
                        out.insert(topic.name.clone(), type_descriptor_from_xtypes(type_object));
                    }
                }
            }
            Err(e) => log::debug!("topic discovery failed: {}", e),
        }
        if !out.is_empty() {
            // Something answered; start over from the short interval.
            self.discovery_backoff = MIN_DISCOVERY_BACKOFF;
        }
        out
    }
}

/// Wall-clock nanoseconds, for callers that record their own timestamps.
pub fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}
