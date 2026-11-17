// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! The HDDS schema registry server.
//!
//! Loads the on-disk registry, serves the REST API, and persists every
//! registration before acknowledging it. It binds loopback unless told
//! otherwise: a schema registry accepts writes from anyone who can reach it,
//! so the wildcard bind is an explicit operator choice.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use clap::Parser;
use hdds_schema_registry::persistence::FilePersistence;
use hdds_schema_registry::registry::SchemaRegistry;
use hdds_schema_registry::server::SchemaRegistryApi;
use hdds_schema_registry::{router, ServerState};

#[derive(Parser, Debug)]
#[command(name = "hdds-schema-registry", about = "HDDS schema registry server")]
struct Args {
    /// Address to bind. Defaults to loopback.
    #[arg(long, default_value = "127.0.0.1")]
    bind: IpAddr,

    /// TCP port to listen on.
    #[arg(long, default_value_t = 8081)]
    port: u16,

    /// Directory holding the JSON schema files. Omit to stay in memory.
    #[arg(long)]
    data_dir: Option<PathBuf>,

    /// DDS domain to announce registrations on (requires the dds feature).
    #[arg(long)]
    domain: Option<u32>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let (registry, persistence) = match &args.data_dir {
        Some(dir) => {
            let persistence = FilePersistence::new(dir.clone())?;
            let registry = persistence.load()?;
            println!(
                "loaded {} schema(s) from {}",
                registry.schema_count(),
                dir.display()
            );
            (registry, Some(persistence))
        }
        None => {
            println!("no --data-dir: registrations are kept in memory only");
            (SchemaRegistry::new(), None)
        }
    };

    let api = SchemaRegistryApi::new(Arc::new(RwLock::new(registry)));
    let mut state = match persistence {
        Some(p) => ServerState::with_persistence(api, p),
        None => ServerState::in_memory(api),
    };

    #[cfg(feature = "dds")]
    if let Some(domain) = args.domain {
        let announcer = hdds_schema_registry::distribution::SchemaAnnouncer::new(
            domain,
            "hdds-schema-registry",
        )?;
        println!("announcing registrations on DDS domain {}", domain);
        state.announcer = Some(std::sync::Mutex::new(announcer));
    }
    #[cfg(not(feature = "dds"))]
    if args.domain.is_some() {
        return Err(
            "--domain needs the `dds` feature (cargo build -p hdds-schema-registry \
             --features server,dds)"
                .into(),
        );
    }

    let addr = SocketAddr::new(args.bind, args.port);
    if addr.ip() == IpAddr::V4(Ipv4Addr::UNSPECIFIED) {
        println!("WARNING: binding every interface; the registry accepts writes from any peer");
    }
    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("hdds-schema-registry listening on http://{}", addr);
    axum::serve(listener, router(Arc::new(state))).await?;
    Ok(())
}
