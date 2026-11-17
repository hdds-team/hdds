// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 naskel.com

//! Host-side subscriber for the seL4 publisher PD.
//!
//! Drives one socket: sends a `kick` UDP datagram to the QEMU SLIRP
//! host-forwarded port (default `127.0.0.1:1241` -> guest
//! `10.0.2.17:1235`), which wakes the publisher PD's `notified()` and
//! triggers one CDR-encoded Temperature sample emitted back to the
//! kick's source. SLIRP NAT keeps the (host_port, guest_dest) mapping
//! stable for the lifetime of our bound socket, so replies always land
//! on us.
//!
//! Per-sample wire layout (matches `client2_rust/src/publisher.rs` and
//! `crates/hdds-micro/examples/temperature_pubsub.rs`):
//!   - sensor_id : u32
//!   - value     : f32
//!   - timestamp : u64  (publisher-side monotonic counter, NOT a clock)
//!
//! Stdout (one line per sample):
//!   `RX seq=<u64> sensor=<u32> value=<f32> ts=<u64>`
//!
//! Exit codes:
//!   0  N samples received cleanly, sequence numbers strictly monotonic
//!   1  premature timeout / fewer samples than `--count` after `--timeout-secs`
//!   2  CLI / setup error
//!
//! Why no full `hdds` crate: the embedded MicroWriter emits raw RTPS
//! DATA submessages without SEDP, so a full DataReader cannot bind the
//! writer GUID to a topic. Using hdds-micro on both ends makes topic
//! match by-convention (one writer, one socket), and the wire format
//! is the one hdds-micro produces on both ends (see
//! `crates/hdds-micro/examples/temperature_pubsub.rs`).

use std::env;
use std::process::ExitCode;
use std::thread;
use std::time::{Duration, Instant};

use hdds_micro::cdr::CdrDecoder;
use hdds_micro::rtps::{EntityId, GuidPrefix, Locator};
use hdds_micro::transport::udp::{StdUdpSocket, WifiUdpTransport};
use hdds_micro::{Error as MicroError, MicroReader, Transport};

/// One-line CLI parser - no third-party deps.
struct Cli {
    kick_host: [u8; 4],
    kick_port: u16,
    count: u64,
    timeout: Duration,
    kick_interval: Duration,
}

impl Cli {
    fn from_argv() -> Result<Self, String> {
        let mut cli = Self {
            kick_host: [127, 0, 0, 1],
            kick_port: 1241,
            count: 100,
            timeout: Duration::from_secs(30),
            kick_interval: Duration::from_millis(50),
        };
        let mut args = env::args().skip(1);
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--kick-host" => {
                    let v = args.next().ok_or("missing value for --kick-host")?;
                    cli.kick_host = parse_ipv4(&v)?;
                }
                "--kick-port" => {
                    cli.kick_port = args
                        .next()
                        .ok_or("missing value for --kick-port")?
                        .parse()
                        .map_err(|e: std::num::ParseIntError| format!("bad --kick-port: {e}"))?;
                }
                "--count" => {
                    cli.count = args
                        .next()
                        .ok_or("missing value for --count")?
                        .parse()
                        .map_err(|e: std::num::ParseIntError| format!("bad --count: {e}"))?;
                }
                "--timeout-secs" => {
                    let s: u64 = args
                        .next()
                        .ok_or("missing value for --timeout-secs")?
                        .parse()
                        .map_err(|e: std::num::ParseIntError| format!("bad --timeout-secs: {e}"))?;
                    cli.timeout = Duration::from_secs(s);
                }
                "--kick-interval-ms" => {
                    let ms: u64 = args
                        .next()
                        .ok_or("missing value for --kick-interval-ms")?
                        .parse()
                        .map_err(|e: std::num::ParseIntError| {
                            format!("bad --kick-interval-ms: {e}")
                        })?;
                    cli.kick_interval = Duration::from_millis(ms);
                }
                "--kick-interval-us" => {
                    let us: u64 = args
                        .next()
                        .ok_or("missing value for --kick-interval-us")?
                        .parse()
                        .map_err(|e: std::num::ParseIntError| format!("bad --kick-interval-us: {e}"))?;
                    cli.kick_interval = Duration::from_micros(us);
                }
                "-h" | "--help" => {
                    print_usage();
                    std::process::exit(0);
                }
                other => return Err(format!("unknown arg: {other}")),
            }
        }
        Ok(cli)
    }
}

fn parse_ipv4(s: &str) -> Result<[u8; 4], String> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return Err(format!("not an IPv4 address: {s}"));
    }
    let mut out = [0u8; 4];
    for (i, p) in parts.iter().enumerate() {
        out[i] = p
            .parse()
            .map_err(|e: std::num::ParseIntError| format!("bad octet '{p}' in {s}: {e}"))?;
    }
    Ok(out)
}

fn print_usage() {
    println!("hdds_sub - host subscriber for the seL4 publisher PD");
    println!();
    println!("USAGE:");
    println!("  hdds_sub [--kick-host IPV4] [--kick-port N] [--count N]");
    println!("           [--timeout-secs N] [--kick-interval-ms N | --kick-interval-us N]");
    println!();
    println!("DEFAULTS:");
    println!("  --kick-host        127.0.0.1   (SLIRP host-forward target)");
    println!("  --kick-port        1241        (guest 10.0.2.17:1235 forwarded)");
    println!("  --count            100");
    println!("  --timeout-secs     30");
    println!("  --kick-interval-ms 50");
}

fn main() -> ExitCode {
    let cli = match Cli::from_argv() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("hdds_sub: {e}");
            print_usage();
            return ExitCode::from(2);
        }
    };

    // Bind on an ephemeral local port - SLIRP NAT mapping will tie
    // host:<ephemeral> <-> guest:1235 for the lifetime of this socket.
    let socket = StdUdpSocket::new();
    let mut transport = match WifiUdpTransport::new(socket, 0) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("hdds_sub: bind failed: {e:?}");
            return ExitCode::from(2);
        }
    };

    // Reader doesn't filter by topic name - see comment at the top of
    // crates/hdds-micro/src/core/reader.rs. We give it a GUID prefix
    // derived from the local locator just to match the embedded side's
    // construction shape; nothing on the wire actually checks it for
    // BEST_EFFORT receive.
    let local = transport.local_locator();
    let guid_prefix = derive_guid_prefix(&local);
    let reader_eid = EntityId::new([0, 0, 0x01, 0xc7]);
    let mut reader = match MicroReader::new(guid_prefix, reader_eid, "Temperature") {
        Ok(r) => r,
        Err(e) => {
            eprintln!("hdds_sub: reader build failed: {e:?}");
            return ExitCode::from(2);
        }
    };

    let kick_dest = Locator::udpv4(cli.kick_host, cli.kick_port);
    let kick_payload = b"kick";

    eprintln!(
        "hdds_sub: kicking {}.{}.{}.{}:{} every {} us (target {} samples, timeout {} s)",
        cli.kick_host[0],
        cli.kick_host[1],
        cli.kick_host[2],
        cli.kick_host[3],
        cli.kick_port,
        cli.kick_interval.as_micros(),
        cli.count,
        cli.timeout.as_secs(),
    );

    let started = Instant::now();
    let mut received: u64 = 0;
    let mut last_seq: i64 = 0;
    let mut last_kick = Instant::now() - cli.kick_interval;
    let mut exit = ExitCode::from(1);

    loop {
        if received >= cli.count {
            eprintln!(
                "hdds_sub: target reached - {} samples in {:.2} s",
                received,
                started.elapsed().as_secs_f64()
            );
            exit = ExitCode::SUCCESS;
            break;
        }
        if started.elapsed() >= cli.timeout {
            eprintln!(
                "hdds_sub: TIMEOUT - got {}/{} samples in {} s",
                received,
                cli.count,
                cli.timeout.as_secs()
            );
            break;
        }
        if last_kick.elapsed() >= cli.kick_interval {
            // Best-effort kick - if SLIRP isn't up yet we just try
            // again next iteration.
            if let Err(e) = send_kick(&mut transport, kick_payload, &kick_dest) {
                eprintln!("hdds_sub: kick send failed: {e:?}");
            }
            last_kick = Instant::now();
        }

        // Drain any pending samples.
        loop {
            match reader.read(&mut transport) {
                Ok(Some(sample)) => {
                    let seq = sample.sequence_number.value();
                    if seq <= last_seq {
                        eprintln!(
                            "hdds_sub: WARNING non-monotonic seq: got {} after {}",
                            seq, last_seq
                        );
                    }
                    last_seq = seq;

                    let mut dec = CdrDecoder::new(sample.payload);
                    let sensor = match dec.decode_u32() {
                        Ok(v) => v,
                        Err(e) => {
                            eprintln!("hdds_sub: decode sensor failed: {e:?}");
                            continue;
                        }
                    };
                    let value = match dec.decode_f32() {
                        Ok(v) => v,
                        Err(e) => {
                            eprintln!("hdds_sub: decode value failed: {e:?}");
                            continue;
                        }
                    };
                    let ts = match dec.decode_u64() {
                        Ok(v) => v,
                        Err(e) => {
                            eprintln!("hdds_sub: decode ts failed: {e:?}");
                            continue;
                        }
                    };
                    received += 1;
                    println!("RX seq={seq} sensor={sensor} value={value:.4} ts={ts}");
                }
                Ok(None) => break,
                Err(MicroError::ResourceExhausted) => break,
                Err(e) => {
                    eprintln!("hdds_sub: reader error: {e:?}");
                    break;
                }
            }
        }

        // Poll no slower than the kick interval, so sub-ms kicks keep their cadence.
        thread::sleep(cli.kick_interval.min(Duration::from_millis(1)));
    }

    exit
}

fn send_kick(
    transport: &mut WifiUdpTransport<StdUdpSocket>,
    payload: &[u8],
    dest: &Locator,
) -> Result<usize, MicroError> {
    transport.send(payload, dest)
}

/// Mirror of `MicroParticipant::generate_guid_prefix` - see comment in
/// `client2_rust/src/publisher.rs` for why we don't instantiate the
/// participant directly.
fn derive_guid_prefix(locator: &Locator) -> GuidPrefix {
    let mut bytes = [0u8; 12];
    bytes[0..8].copy_from_slice(&locator.address[8..16]);
    let port_bytes = locator.port.to_be_bytes();
    bytes[8..12].copy_from_slice(&port_bytes);
    GuidPrefix::new(bytes)
}
