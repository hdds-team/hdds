// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 naskel.com

//! Host-side publisher for the seL4 subscriber PD.
//!
//! Sends N CDR-encoded `Temperature` samples as RTPS DATA submessages
//! to the QEMU SLIRP host-forwarded port (default `127.0.0.1:1241` ->
//! guest `10.0.2.17:1235`). Mirror of `host-tools/hdds_sub` for the
//! opposite role: same wire format (it has to be - the PD's
//! `MicroReader` decodes whatever the embedded `MicroWriter` would
//! have emitted), no kicks, no replies.
//!
//! Per-sample wire layout matches `client2_rust/src/publisher.rs`:
//!   - sensor_id : u32
//!   - value     : f32
//!   - timestamp : u64  (publisher-side monotonic counter)
//!
//! Exit codes:
//!   0  N samples sent successfully
//!   1  send error mid-stream
//!   2  CLI / setup error

use std::env;
use std::process::ExitCode;
use std::thread;
use std::time::Duration;

use hdds_micro::cdr::CdrEncoder;
use hdds_micro::rtps::{EntityId, GuidPrefix, Locator};
use hdds_micro::transport::udp::{StdUdpSocket, WifiUdpTransport};
use hdds_micro::{MicroWriter, Transport};

struct Cli {
    dest_host: [u8; 4],
    dest_port: u16,
    count: u64,
    interval: Duration,
    sensor_id: u32,
}

impl Cli {
    fn from_argv() -> Result<Self, String> {
        let mut cli = Self {
            dest_host: [127, 0, 0, 1],
            dest_port: 1241,
            count: 200,
            interval: Duration::from_millis(50),
            sensor_id: 42,
        };
        let mut args = env::args().skip(1);
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--dest-host" => {
                    let v = args.next().ok_or("missing value for --dest-host")?;
                    cli.dest_host = parse_ipv4(&v)?;
                }
                "--dest-port" => {
                    cli.dest_port = args
                        .next()
                        .ok_or("missing value for --dest-port")?
                        .parse()
                        .map_err(|e: std::num::ParseIntError| format!("bad --dest-port: {e}"))?;
                }
                "--count" => {
                    cli.count = args
                        .next()
                        .ok_or("missing value for --count")?
                        .parse()
                        .map_err(|e: std::num::ParseIntError| format!("bad --count: {e}"))?;
                }
                "--interval-ms" => {
                    let ms: u64 = args
                        .next()
                        .ok_or("missing value for --interval-ms")?
                        .parse()
                        .map_err(|e: std::num::ParseIntError| format!("bad --interval-ms: {e}"))?;
                    cli.interval = Duration::from_millis(ms);
                }
                "--interval-us" => {
                    let us: u64 = args
                        .next()
                        .ok_or("missing value for --interval-us")?
                        .parse()
                        .map_err(|e: std::num::ParseIntError| format!("bad --interval-us: {e}"))?;
                    cli.interval = Duration::from_micros(us);
                }
                "--sensor-id" => {
                    cli.sensor_id = args
                        .next()
                        .ok_or("missing value for --sensor-id")?
                        .parse()
                        .map_err(|e: std::num::ParseIntError| format!("bad --sensor-id: {e}"))?;
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
    println!("hdds_pub - host publisher for the seL4 subscriber PD");
    println!();
    println!("USAGE:");
    println!("  hdds_pub [--dest-host IPV4] [--dest-port N] [--count N]");
    println!("           [--interval-ms N | --interval-us N] [--sensor-id N]");
    println!();
    println!("DEFAULTS:");
    println!("  --dest-host    127.0.0.1   (SLIRP host-forward target)");
    println!("  --dest-port    1241        (guest 10.0.2.17:1235 forwarded)");
    println!("  --count        200");
    println!("  --interval-ms  50");
    println!("  --sensor-id    42");
}

fn main() -> ExitCode {
    let cli = match Cli::from_argv() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("hdds_pub: {e}");
            print_usage();
            return ExitCode::from(2);
        }
    };

    let socket = StdUdpSocket::new();
    let mut transport = match WifiUdpTransport::new(socket, 0) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("hdds_pub: bind failed: {e:?}");
            return ExitCode::from(2);
        }
    };

    let local = transport.local_locator();
    let guid_prefix = derive_guid_prefix(&local);
    let writer_eid = EntityId::new([0, 0, 0x01, 0xc2]);
    let dest = Locator::udpv4(cli.dest_host, cli.dest_port);

    let mut writer = match MicroWriter::new(guid_prefix, writer_eid, "Temperature", dest) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("hdds_pub: writer build failed: {e:?}");
            return ExitCode::from(2);
        }
    };

    eprintln!(
        "hdds_pub: sending {} samples to {}.{}.{}.{}:{} every {} us",
        cli.count,
        cli.dest_host[0],
        cli.dest_host[1],
        cli.dest_host[2],
        cli.dest_host[3],
        cli.dest_port,
        cli.interval.as_micros(),
    );

    for i in 1..=cli.count {
        let value = 20.0 + ((i % 200) as f32) * 0.05;
        let ts = i;

        let mut buf = [0u8; 64];
        let mut enc = CdrEncoder::new(&mut buf);
        if let Err(e) = enc.encode_u32(cli.sensor_id) {
            eprintln!("hdds_pub: encode sensor_id failed: {e:?}");
            return ExitCode::from(1);
        }
        if let Err(e) = enc.encode_f32(value) {
            eprintln!("hdds_pub: encode value failed: {e:?}");
            return ExitCode::from(1);
        }
        if let Err(e) = enc.encode_u64(ts) {
            eprintln!("hdds_pub: encode ts failed: {e:?}");
            return ExitCode::from(1);
        }
        let payload = enc.finish();

        if let Err(e) = writer.write(payload, &mut transport) {
            eprintln!("hdds_pub: write failed at sample {i}: {e:?}");
            return ExitCode::from(1);
        }

        // Light cadence - gives the PD time to drain notifications
        // without batching too many DATA submessages per Microkit
        // wake-up. Same 50 ms default as hdds_sub for symmetry.
        thread::sleep(cli.interval);
    }

    eprintln!("hdds_pub: done ({} samples sent)", cli.count);
    ExitCode::SUCCESS
}

fn derive_guid_prefix(locator: &Locator) -> GuidPrefix {
    let mut bytes = [0u8; 12];
    bytes[0..8].copy_from_slice(&locator.address[8..16]);
    let port_bytes = locator.port.to_be_bytes();
    bytes[8..12].copy_from_slice(&port_bytes);
    GuidPrefix::new(bytes)
}
