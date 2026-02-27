// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use hdds::{Participant, QoS, TransportMode};

fn main() -> hdds::Result<()> {
    let participant = Participant::builder("persist_example")
        .with_transport(TransportMode::UdpMulticast)
        .domain_id(0)
        .build()?;

    let qos = QoS::reliable()
        .persistent()
        .keep_all()
        .durability_service_keep_last(100, 1000, 1, 1000);

    let writer = participant.create_raw_writer("State/Example", Some(qos.clone()))?;
    let reader = participant.create_raw_reader("State/Example", Some(qos))?;

    writer.write_raw(b"state=ready")?;

    for sample in reader.try_take_raw()? {
        println!("Replay: {} bytes", sample.payload.len());
    }

    Ok(())
}
