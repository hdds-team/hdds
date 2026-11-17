// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! The HDDS DDS-XRCE agent.
//!
//! Bridges XRCE clients (MCUs over UDP, TCP or serial) onto a DDS domain.
//! Admission is a ClientKey list: without `--client-key` or an explicit
//! `--open`, the agent refuses to start rather than accept anyone.

use std::net::IpAddr;
use std::sync::Arc;

use clap::Parser;
use hdds_xrce::bridge_hdds::HddsBridge;
use hdds_xrce::transport::{TcpTransport, UdpTransport, XrceTransport};
use hdds_xrce::{SerialTransport, XrceAgent, XrceAgentConfig};

#[derive(Parser, Debug)]
#[command(name = "hdds-xrce-agent", about = "HDDS DDS-XRCE agent")]
struct Args {
    /// Address the listeners bind to. Defaults to loopback. A wildcard
    /// address here is refused; use --bind-any to say it out loud.
    #[arg(long, default_value = "127.0.0.1")]
    bind: IpAddr,

    /// Listen on EVERY interface. An XRCE agent is a write path into a DDS
    /// domain, so serving the whole network is opt-in, never a default.
    #[arg(long)]
    bind_any: bool,

    /// UDP port (the DDS-XRCE default is 2019).
    #[arg(long, default_value_t = 2019)]
    udp_port: u16,

    /// Listen on TCP instead of UDP.
    #[arg(long)]
    tcp_port: Option<u16>,

    /// Listen on a serial device instead of a socket. Configure the line
    /// externally, e.g. stty -F /dev/ttyUSB0 115200 raw -echo.
    #[arg(long)]
    serial: Option<String>,

    /// Force every client onto this DDS domain instead of the one it asks for.
    #[arg(long)]
    domain: Option<u32>,

    /// A ClientKey allowed to open a session, as 8 hex digits (repeatable).
    #[arg(long = "client-key")]
    client_keys: Vec<String>,

    /// Accept any ClientKey. Required when no --client-key is given.
    #[arg(long)]
    open: bool,

    /// Participant name announced on the DDS side.
    #[arg(long, default_value = "hdds-xrce-agent")]
    participant_name: String,
}

fn parse_key(text: &str) -> Result<[u8; 4], String> {
    let cleaned = text.trim_start_matches("0x");
    if cleaned.len() != 8 || !cleaned.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!("{} is not 8 hex digits", text));
    }
    let mut key = [0u8; 4];
    for (i, slot) in key.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&cleaned[i * 2..i * 2 + 2], 16)
            .map_err(|e| format!("{}: {}", text, e))?;
    }
    Ok(key)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let mut accepted = Vec::new();
    for key in &args.client_keys {
        accepted.push(parse_key(key)?);
    }

    let config = XrceAgentConfig {
        bind_address: args.bind,
        udp_port: args.udp_port,
        tcp_port: args.tcp_port,
        serial_device: args.serial.clone(),
        accepted_client_keys: accepted,
        open_admission: args.open,
        ..XrceAgentConfig::default()
    };
    // validate() is where the fail-closed admission rule bites.
    config.validate()?;

    let bridge = match args.domain {
        Some(domain) => HddsBridge::with_domain(&args.participant_name, domain),
        None => HddsBridge::new(&args.participant_name),
    };
    let mut agent = XrceAgent::new(config.clone(), Arc::new(bridge))?;

    if args.bind_any {
        println!("WARNING: --bind-any listens on every interface");
    }

    let mut transport: Box<dyn XrceTransport> = if let Some(device) = &args.serial {
        println!("hdds-xrce-agent on serial {}", device);
        Box::new(SerialTransport::open(device)?)
    } else if let Some(port) = args.tcp_port {
        let t = if args.bind_any {
            TcpTransport::bind_any(port)?
        } else {
            TcpTransport::bind_on(args.bind, port)?
        }
        // The agent reads into a buffer of config.max_message_size, so the
        // transport must refuse anything longer instead of handing back a
        // frame the agent cannot hold.
        .with_max_message_size(config.max_message_size);
        println!("hdds-xrce-agent on tcp://{}", t.local_addr()?);
        Box::new(t)
    } else if args.bind_any {
        let t = UdpTransport::bind_any(args.udp_port)?;
        println!("hdds-xrce-agent on udp://{}", t.local_addr()?);
        Box::new(t)
    } else {
        let t = UdpTransport::bind_on(args.bind, args.udp_port)?;
        println!("hdds-xrce-agent on udp://{}", t.local_addr()?);
        Box::new(t)
    };

    if config.open_admission {
        println!("WARNING: --open accepts any ClientKey; every client gets DDS write access");
    }

    loop {
        agent.tick(transport.as_mut())?;
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
}
