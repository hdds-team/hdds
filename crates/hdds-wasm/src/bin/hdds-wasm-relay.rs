// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! The native relay for the HDDS WASM SDK.
//!
//! Browsers connect over WebSocket at `/ws` and become real DDS endpoints.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use clap::Parser;
use hdds_wasm::relay_server::RelayServer;

#[derive(Parser, Debug)]
#[command(
    name = "hdds-wasm-relay",
    about = "WebSocket relay for the HDDS WASM SDK"
)]
struct Args {
    /// Address to bind. Defaults to loopback.
    #[arg(long, default_value = "127.0.0.1")]
    bind: IpAddr,

    /// TCP port to listen on.
    #[arg(long, default_value_t = 9000)]
    port: u16,

    /// DDS domain the relay joins.
    #[arg(long, default_value_t = 0)]
    domain: u32,

    /// Participant name announced on the DDS side.
    #[arg(long, default_value = "hdds-wasm-relay")]
    participant_name: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let relay = RelayServer::new(args.domain, &args.participant_name)?;
    let addr = SocketAddr::new(args.bind, args.port);
    if addr.ip() == IpAddr::V4(Ipv4Addr::UNSPECIFIED) {
        println!("WARNING: binding every interface; the relay gives any client DDS write access");
    }
    println!(
        "hdds-wasm-relay on ws://{}/ws, DDS domain {}",
        addr, args.domain
    );
    relay.serve(addr).await?;
    Ok(())
}
