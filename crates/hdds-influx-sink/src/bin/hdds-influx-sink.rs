// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Streams DDS topics into InfluxDB.
//!
//! Reads the YAML sink configuration, subscribes to every configured topic on
//! a DDS domain, and POSTs batches of Line Protocol to InfluxDB v2.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use clap::Parser;
use hdds_influx_sink::config::SinkConfig;
use hdds_influx_sink::runner::SinkRunner;

#[derive(Parser, Debug)]
#[command(name = "hdds-influx-sink", about = "Stream DDS topics into InfluxDB")]
struct Args {
    /// YAML sink configuration.
    #[arg(long)]
    config: PathBuf,

    /// DDS domain to subscribe on.
    #[arg(long, default_value_t = 0)]
    domain: u32,

    /// Participant name announced on the DDS side.
    #[arg(long, default_value = "hdds-influx-sink")]
    participant_name: String,

    /// Stop after this many seconds instead of running forever.
    #[arg(long)]
    seconds: Option<u64>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let config = SinkConfig::from_file(&args.config)?;
    let mut runner = SinkRunner::new(config, args.domain, &args.participant_name)?;
    println!(
        "hdds-influx-sink on domain {} subscribing to {:?}",
        args.domain,
        runner.topics()
    );
    let deadline = args
        .seconds
        .map(|s| Instant::now() + Duration::from_secs(s));
    let result = runner.run(deadline);
    println!(
        "recorded {} sample(s), wrote {} line(s)",
        runner.samples_recorded(),
        runner.lines_written()
    );
    result?;
    Ok(())
}
