// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! HDDS side of the cross-vendor interop smoke test (scripts/interop-smoke/).
//!
//! Publishes or subscribes `InteropPing` samples against a peer (CycloneDDS,
//! Fast DDS or OpenDDS, each in its own container) over plain RTPS/UDP
//! multicast discovery. The orchestration script in scripts/interop-smoke/
//! drives this binary from both sides and reads the printed lines below to
//! compute the verdict for each matrix cell; it never greps for "PASSED".
//!
//! IDL (scripts/interop-smoke/idl/InteropPing.idl):
//! ```idl
//! @final
//! struct InteropPing {
//!     @key long key;
//!     unsigned long seq;
//!     octet payload[32];
//! };
//! ```
//!
//! CLI:
//!   interop_smoke --mode pub|sub --domain <200-230> [--topic InteropSmoke]
//!                 --reliability reliable|best_effort [--count 100]
//!                 [--key 42] [--timeout 30] [--challenge 0-255]
//!   interop_smoke --build-info   (prints provenance JSON and exits, no other
//!                                 flags needed)
//!
//! `--challenge` only changes what a publisher writes into the payload
//! (default 0): `payload[i] = (seq + i + challenge) % 256`. A subscriber
//! reports the raw bytes it saw either way -- the orchestrator, which
//! generated the per-cell challenge, is what recomputes the expected pattern
//! and compares, so a fake subscriber would have to guess a value it was
//! never given, and a fake publisher's claimed writes still have to show up
//! correctly on a real subscriber's wire-read samples.
//!
//! Contract lines on stdout (one per line, flushed immediately):
//!   EVENT matched | EVENT no_match
//!   SENT seq=<n>                                   (pub only, successful writes only)
//!   SAMPLE seq=<n> key=<k> payload=<64 hex chars>   (sub only)
//!   DONE sent=<n>                                   (pub; n = successful writes, not --count)
//!   DONE received=<n> distinct=<n>                  (sub)
//!   DONE timeout_forced                             (watchdog, either side)
//!
//! Exit codes: 0 = ran to completion, 2 = setup failed, 3 = no_match.
//!
//! Readiness settle: after EVENT matched and before the first write, a
//! publisher sleeps `INTEROP_SMOKE_SETTLE_MS` (env var, default 500, set to
//! 0 to disable) milliseconds. This is the same disclosed, symmetric
//! warm-up barrier used by all four interop-smoke apps -- see
//! scripts/interop-smoke/README.md for why it exists and what was measured
//! without it.

use hdds::core::ser::cursor::{Cursor, CursorMut};
use hdds::core::ser::{Cdr2Decode, Cdr2Encode, CdrError};
use hdds::core::types::{FieldLayout, FieldType, PrimitiveKind, TypeDescriptor};
use hdds::{Participant, QoS, TransportMode};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::io::Write;
use std::time::{Duration, Instant};

const PAYLOAD_LEN: usize = 32;

#[derive(Debug, Clone, PartialEq)]
struct InteropPing {
    key: i32,
    seq: u32,
    payload: [u8; PAYLOAD_LEN],
}

impl InteropPing {
    fn expected_payload(seq: u32, challenge: u8) -> [u8; PAYLOAD_LEN] {
        let mut p = [0u8; PAYLOAD_LEN];
        for (i, b) in p.iter_mut().enumerate() {
            *b = ((seq as usize + i + challenge as usize) % 256) as u8;
        }
        p
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

// ---------------------------------------------------------------------------
// Manual DDS impl: InteropPing is @final with two fixed 4-byte members and a
// fixed 32-octet array, so the CDR1 and CDR2 bodies are byte-identical (no
// DHEADER, no variable-length member) -- same pattern as the Temperature
// type build.rs generates. The derive(DDS) macro only covers primitive
// fields today, not fixed byte arrays, so this type is hand-written.
// ---------------------------------------------------------------------------
impl hdds::dds::DDS for InteropPing {
    fn type_descriptor() -> &'static TypeDescriptor {
        static DESC: TypeDescriptor = TypeDescriptor {
            type_id: 0x494E_5450, // arbitrary fixed id ("INTP"), not FNV-derived: hand-written type
            type_name: "InteropPing",
            size_bytes: 40,
            alignment: 4,
            is_variable_size: false,
            fields: &[
                FieldLayout {
                    name: "key",
                    offset_bytes: 0,
                    field_type: FieldType::Primitive(PrimitiveKind::I32),
                    alignment: 4,
                    size_bytes: 4,
                    element_type: None,
                },
                FieldLayout {
                    name: "seq",
                    offset_bytes: 4,
                    field_type: FieldType::Primitive(PrimitiveKind::U32),
                    alignment: 4,
                    size_bytes: 4,
                    element_type: None,
                },
                FieldLayout {
                    name: "payload",
                    offset_bytes: 8,
                    field_type: FieldType::Array,
                    alignment: 1,
                    size_bytes: PAYLOAD_LEN as u32,
                    element_type: None,
                },
            ],
        };
        &DESC
    }

    fn encode(&self, buf: &mut [u8], _version: hdds::CdrVersion) -> hdds::dds::Result<usize> {
        self.encode_cdr2_le(buf).map_err(|e| match e {
            CdrError::BufferTooSmall => hdds::Error::BufferTooSmall,
            _ => hdds::Error::SerializationError,
        })
    }

    fn decode(buf: &[u8], _version: hdds::CdrVersion) -> hdds::dds::Result<Self> {
        Self::decode_cdr2_le(buf)
            .map(|(v, _)| v)
            .map_err(|_| hdds::Error::SerializationError)
    }

    /// @final, fixed-size, no 8-byte member, no DHEADER: the body is the
    /// same under XCDR1 and XCDR2.
    fn encodes_xcdr1_natively() -> bool {
        true
    }

    fn has_key() -> bool {
        true
    }

    fn write_key_holder(
        &self,
        w: &mut hdds::core::key_hash::KeyHolderWriter,
    ) -> Option<hdds::core::key_hash::KeyMaxSize> {
        w.write_i32(self.key);
        Some(hdds::core::key_hash::KeyMaxSize::Bounded(4))
    }

    /// The key is the single leading 4-byte member of an @final type: no
    /// DHEADER under either version, so `encode_key` is the body of `encode`
    /// truncated at the key.
    fn encode_key(&self, _version: hdds::CdrVersion) -> Vec<u8> {
        self.key.to_le_bytes().to_vec()
    }

    fn key_hash_of_key_payload(payload: &[u8]) -> Option<[u8; 16]> {
        let mut r = hdds::core::key_hash::KeyPayloadReader::new(payload)?;
        let key = r.read_i32()?;
        r.finish()?;
        let mut w = hdds::core::key_hash::KeyHolderWriter::new();
        w.write_i32(key);
        Some(w.finish(hdds::core::key_hash::KeyMaxSize::Bounded(4)))
    }

    fn keys_round_trip() -> bool {
        true
    }
}

impl Cdr2Encode for InteropPing {
    fn encode_cdr2_le(&self, buf: &mut [u8]) -> Result<usize, CdrError> {
        let mut cursor = CursorMut::new(buf);
        cursor
            .write_bytes(&self.key.to_le_bytes())
            .map_err(|_| CdrError::BufferTooSmall)?;
        cursor
            .write_bytes(&self.seq.to_le_bytes())
            .map_err(|_| CdrError::BufferTooSmall)?;
        cursor
            .write_bytes(&self.payload)
            .map_err(|_| CdrError::BufferTooSmall)?;
        Ok(cursor.offset())
    }

    fn max_cdr2_size(&self) -> usize {
        4 + 4 + PAYLOAD_LEN
    }

    fn encode_cdr2_le_at(&self, dst: &mut [u8], offset: &mut usize) -> Result<(), CdrError> {
        let n = self.encode_cdr2_le(&mut dst[*offset..])?;
        *offset += n;
        Ok(())
    }
}

impl Cdr2Decode for InteropPing {
    fn decode_cdr2_le(buf: &[u8]) -> Result<(Self, usize), CdrError> {
        let mut cursor = Cursor::new(buf);
        let key_bytes = cursor.read_bytes(4).map_err(|_| CdrError::UnexpectedEof)?;
        let seq_bytes = cursor.read_bytes(4).map_err(|_| CdrError::UnexpectedEof)?;
        let payload_bytes = cursor
            .read_bytes(PAYLOAD_LEN)
            .map_err(|_| CdrError::UnexpectedEof)?;
        let key = i32::from_le_bytes(key_bytes.try_into().unwrap());
        let seq = u32::from_le_bytes(seq_bytes.try_into().unwrap());
        let mut payload = [0u8; PAYLOAD_LEN];
        payload.copy_from_slice(payload_bytes);
        Ok((Self { key, seq, payload }, 4 + 4 + PAYLOAD_LEN))
    }

    fn decode_cdr2_le_at(src: &[u8], offset: &mut usize) -> Result<Self, CdrError> {
        let (value, consumed) = Self::decode_cdr2_le(&src[*offset..])?;
        *offset += consumed;
        Ok(value)
    }
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------
struct Args {
    mode: Mode,
    domain: u32,
    topic: String,
    reliable: bool,
    count: u32,
    key: i32,
    timeout: u64,
    challenge: u8,
}

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Pub,
    Sub,
}

fn parse_args() -> Args {
    let argv: Vec<String> = std::env::args().collect();
    let mut mode = None;
    let mut domain = None;
    let mut topic = "InteropSmoke".to_string();
    let mut reliable = None;
    let mut count: u32 = 100;
    let mut key: i32 = 42;
    let mut timeout: u64 = 30;
    let mut challenge: u8 = 0;

    let mut i = 1;
    while i < argv.len() {
        let flag = argv[i].as_str();
        let value = argv.get(i + 1).map(|s| s.as_str());
        match flag {
            "--mode" => {
                mode = match value {
                    Some("pub") => Some(Mode::Pub),
                    Some("sub") => Some(Mode::Sub),
                    other => {
                        eprintln!("invalid --mode: {other:?}");
                        std::process::exit(2);
                    }
                };
                i += 2;
            }
            "--domain" => {
                domain = value.and_then(|v| v.parse::<u32>().ok());
                i += 2;
            }
            "--topic" => {
                if let Some(v) = value {
                    topic = v.to_string();
                }
                i += 2;
            }
            "--reliability" => {
                reliable = match value {
                    Some("reliable") => Some(true),
                    Some("best_effort") => Some(false),
                    other => {
                        eprintln!("invalid --reliability: {other:?}");
                        std::process::exit(2);
                    }
                };
                i += 2;
            }
            "--count" => {
                if let Some(v) = value.and_then(|v| v.parse().ok()) {
                    count = v;
                }
                i += 2;
            }
            "--key" => {
                if let Some(v) = value.and_then(|v| v.parse().ok()) {
                    key = v;
                }
                i += 2;
            }
            "--timeout" => {
                if let Some(v) = value.and_then(|v| v.parse().ok()) {
                    timeout = v;
                }
                i += 2;
            }
            "--challenge" => {
                if let Some(v) = value.and_then(|v| v.parse().ok()) {
                    challenge = v;
                }
                i += 2;
            }
            other => {
                eprintln!("unknown flag: {other}");
                std::process::exit(2);
            }
        }
    }

    let mode = mode.unwrap_or_else(|| {
        eprintln!("--mode pub|sub is required");
        std::process::exit(2);
    });
    let domain = domain.unwrap_or_else(|| {
        eprintln!("--domain is required");
        std::process::exit(2);
    });
    let reliable = reliable.unwrap_or_else(|| {
        eprintln!("--reliability reliable|best_effort is required");
        std::process::exit(2);
    });

    Args {
        mode,
        domain,
        topic,
        reliable,
        count,
        key,
        timeout,
        challenge,
    }
}

fn println_flush(line: &str) {
    println!("{line}");
    let _ = std::io::stdout().flush();
}

/// Hard watchdog: match-wait and the send/receive phase are each budgeted
/// up to `timeout` seconds (sequentially, not concurrently), so the backstop
/// must cover both plus margin -- the same `2*timeout + N` shape the other
/// three interop-smoke apps use (fastdds_app.cpp's `arm_watchdog`, and the
/// re-armed alarms in interop_app.c / opendds_app.cpp). A single `timeout +
/// 10` here (the previous value) could fire mid-receive on a run that was
/// simply slow to match, not stuck.
fn install_watchdog(timeout: u64) {
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(2 * timeout + 10));
        println!("DONE timeout_forced");
        let _ = std::io::stdout().flush();
        std::process::exit(0);
    });
}

/// Readiness settle placement and duration, shared with the other three
/// interop-smoke apps: see the module doc comment and README.md.
fn settle_duration() -> Duration {
    let ms = std::env::var("INTEROP_SMOKE_SETTLE_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(500);
    Duration::from_millis(ms)
}

/// `--build-info`: provenance for the binary actually running, not just
/// whatever commit happens to be checked out beside it. Printed as one JSON
/// line and nothing else, so a caller can run `interop_smoke --build-info`
/// in isolation from any cell.
fn print_build_info_and_exit() {
    let exe_sha256 = std::env::current_exe()
        .ok()
        .and_then(|p| std::fs::read(p).ok())
        .map(|bytes| {
            let mut hasher = Sha256::new();
            hasher.update(&bytes);
            let digest: [u8; 32] = hasher.finalize().into();
            hex_encode(&digest)
        })
        .unwrap_or_else(|| "unknown".to_string());
    println!(
        "{{\"binary\":\"interop_smoke\",\"cargo_pkg_version\":\"{}\",\"git_sha\":\"{}\",\"git_dirty\":\"{}\",\"sha256\":\"{}\"}}",
        env!("CARGO_PKG_VERSION"),
        env!("HDDS_BUILD_GIT_SHA"),
        env!("HDDS_BUILD_GIT_DIRTY"),
        exe_sha256,
    );
    std::process::exit(0);
}

fn main() {
    if std::env::args().any(|a| a == "--build-info") {
        print_build_info_and_exit();
    }
    let args = parse_args();
    install_watchdog(args.timeout);

    let qos = if args.reliable {
        QoS::reliable().keep_last(args.count.max(1))
    } else {
        QoS::best_effort().keep_last(args.count.max(1))
    };

    let participant = match Participant::builder("interop_smoke")
        .domain_id(args.domain)
        .with_transport(TransportMode::UdpMulticast)
        .build()
    {
        Ok(p) => p,
        Err(e) => {
            eprintln!("participant setup failed: {e:?}");
            std::process::exit(2);
        }
    };

    let topic = match participant.topic::<InteropPing>(&args.topic) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("topic setup failed: {e:?}");
            std::process::exit(2);
        }
    };

    match args.mode {
        Mode::Pub => run_pub(&topic, &qos, &args),
        Mode::Sub => run_sub(&topic, &qos, &args),
    }
}

fn run_pub(topic: &hdds::dds::Topic<InteropPing>, qos: &QoS, args: &Args) {
    let writer = match topic.writer().qos(qos.clone()).build() {
        Ok(w) => w,
        Err(e) => {
            eprintln!("writer setup failed: {e:?}");
            std::process::exit(2);
        }
    };

    let deadline = Instant::now() + Duration::from_secs(args.timeout);
    while writer.matched_reader_count() == 0 {
        if Instant::now() >= deadline {
            println_flush("EVENT no_match");
            std::process::exit(3);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    println_flush("EVENT matched");

    // Disclosed, symmetric readiness settle -- see the module doc comment.
    std::thread::sleep(settle_duration());

    let mut sent_count: u32 = 0;
    for seq in 0..args.count {
        let sample = InteropPing {
            key: args.key,
            seq,
            payload: InteropPing::expected_payload(seq, args.challenge),
        };
        match writer.write(&sample) {
            Ok(()) => {
                sent_count += 1;
                println_flush(&format!("SENT seq={seq}"));
            }
            Err(e) => eprintln!("write failed for seq={seq}: {e:?}"),
        }
        std::thread::sleep(Duration::from_millis(3));
    }

    std::thread::sleep(Duration::from_secs(2));
    // sent_count, not args.count: DONE reports only the writes that actually
    // succeeded, so the orchestrator's exact-set check sees the truth even
    // when some write() call failed.
    println_flush(&format!("DONE sent={sent_count}"));
    std::process::exit(0);
}

fn run_sub(topic: &hdds::dds::Topic<InteropPing>, qos: &QoS, args: &Args) {
    let reader = match topic.reader().qos(qos.clone()).build() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("reader setup failed: {e:?}");
            std::process::exit(2);
        }
    };

    let match_deadline = Instant::now() + Duration::from_secs(args.timeout);
    while reader.get_matched_publications().is_empty() {
        if Instant::now() >= match_deadline {
            println_flush("EVENT no_match");
            std::process::exit(3);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    println_flush("EVENT matched");

    let mut distinct: HashSet<u32> = HashSet::new();
    let mut total: u64 = 0;
    let recv_deadline = Instant::now() + Duration::from_secs(args.timeout);
    while distinct.len() < args.count as usize && Instant::now() < recv_deadline {
        match reader.take() {
            Ok(Some(sample)) => {
                total += 1;
                distinct.insert(sample.seq);
                println_flush(&format!(
                    "SAMPLE seq={} key={} payload={}",
                    sample.seq,
                    sample.key,
                    hex_encode(&sample.payload)
                ));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(5)),
            Err(e) => {
                eprintln!("take failed: {e:?}");
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    }

    println_flush(&format!(
        "DONE received={} distinct={}",
        total,
        distinct.len()
    ));
    std::process::exit(0);
}
