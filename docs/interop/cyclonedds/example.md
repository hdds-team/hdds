# CycloneDDS Interoperability Example

Working example of HDDS and CycloneDDS communicating.

## Shared IDL

Both sides must use the same type definition:

```c
// sensor_data.idl
module sensors {
    @appendable
    struct SensorData {
        @key unsigned long sensor_id;
        float value;
        unsigned long long timestamp;
    };
};
```

## Generate Types

### For CycloneDDS

```bash
idlc -l c sensor_data.idl
```

Generated files:
- `sensor_data.c`
- `sensor_data.h`

### For HDDS

```bash
hdds-gen -l rust sensor_data.idl
```

Generated file:
- `src/sensor_data.rs`

## HDDS Publisher

```rust
// hdds_publisher.rs
use hdds::{Participant, QoS, DDS, TransportMode};
use std::time::Duration;

#[derive(Debug, Clone, DDS)]
struct SensorData {
    #[key]
    sensor_id: u32,
    value: f32,
    timestamp: u64,
}

fn main() -> Result<(), hdds::Error> {
    // Create participant on domain 0
    let participant = Participant::builder("hdds_publisher")
        .domain_id(0)
        .with_transport(TransportMode::UdpMulticast)
        .build()?;

    // Create topic and writer with reliable QoS
    let topic = participant.topic::<SensorData>("SensorTopic")?;
    let writer = topic
        .writer()
        .qos(QoS::reliable().keep_last(10).transient_local())
        .build()?;

    println!("HDDS Publisher started. Waiting for CycloneDDS subscriber...");

    // Wait for subscriber
    while writer.matched_subscriptions().is_empty() {
        std::thread::sleep(Duration::from_millis(100));
    }
    println!("Subscriber connected!");

    // Publish samples
    for i in 0..100 {
        let sample = SensorData {
            sensor_id: 1,
            value: 20.0 + (i as f32 * 0.5),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64,
        };

        writer.write(&sample)?;
        println!("Published: sensor_id={}, value={:.1}", sample.sensor_id, sample.value);

        std::thread::sleep(Duration::from_millis(100));
    }

    Ok(())
}
```

## CycloneDDS Subscriber

```c
// cyclone_subscriber.c
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <dds/dds.h>
#include "sensor_data.h"

static volatile int running = 1;

void sigint_handler(int sig) { running = 0; }

int main(int argc, char *argv[]) {
    signal(SIGINT, sigint_handler);

    // Create participant
    dds_entity_t participant = dds_create_participant(0, NULL, NULL);
    if (participant < 0) {
        fprintf(stderr, "Failed to create participant: %s\n", dds_strretcode(participant));
        return 1;
    }

    // Create topic
    dds_entity_t topic = dds_create_topic(
        participant, &sensors_SensorData_desc, "SensorTopic", NULL, NULL);
    if (topic < 0) {
        fprintf(stderr, "Failed to create topic: %s\n", dds_strretcode(topic));
        return 1;
    }

    // Create reader with matching QoS
    dds_qos_t *qos = dds_create_qos();
    dds_qset_reliability(qos, DDS_RELIABILITY_RELIABLE, DDS_MSECS(100));
    dds_qset_durability(qos, DDS_DURABILITY_TRANSIENT_LOCAL);
    dds_qset_history(qos, DDS_HISTORY_KEEP_LAST, 10);

    dds_entity_t reader = dds_create_reader(participant, topic, qos, NULL);
    dds_delete_qos(qos);

    if (reader < 0) {
        fprintf(stderr, "Failed to create reader: %s\n", dds_strretcode(reader));
        return 1;
    }

    printf("CycloneDDS Subscriber started. Waiting for HDDS publisher...\n");

    // Read loop
    sensors_SensorData *samples[10];
    dds_sample_info_t infos[10];
    void *raw_samples[10];

    for (int i = 0; i < 10; i++) {
        samples[i] = sensors_SensorData__alloc();
        raw_samples[i] = samples[i];
    }

    while (running) {
        int n = dds_take(reader, raw_samples, infos, 10, 10);
        if (n < 0) {
            fprintf(stderr, "Read error: %s\n", dds_strretcode(n));
            break;
        }

        for (int i = 0; i < n; i++) {
            if (infos[i].valid_data) {
                printf("Received from HDDS: sensor_id=%u, value=%.1f\n",
                       samples[i]->sensor_id, samples[i]->value);
            }
        }

        dds_sleepfor(DDS_MSECS(10));
    }

    // Cleanup
    for (int i = 0; i < 10; i++) {
        sensors_SensorData_free(samples[i], DDS_FREE_ALL);
    }
    dds_delete(participant);

    printf("Subscriber stopped.\n");
    return 0;
}
```

## HDDS Subscriber

```rust
// hdds_subscriber.rs
use hdds::{Participant, QoS, DDS, TransportMode};
use std::time::Duration;
use std::thread;

#[derive(Debug, Clone, DDS)]
struct SensorData {
    #[key]
    sensor_id: u32,
    value: f32,
    timestamp: u64,
}

fn main() -> Result<(), hdds::Error> {
    let participant = Participant::builder("hdds_subscriber")
        .domain_id(0)
        .with_transport(TransportMode::UdpMulticast)
        .build()?;

    let topic = participant.topic::<SensorData>("SensorTopic")?;
    let reader = topic
        .reader()
        .qos(QoS::reliable().keep_last(100).transient_local())
        .build()?;

    println!("HDDS Subscriber started. Waiting for CycloneDDS publisher...");

    loop {
        while let Some(sample) = reader.try_take()? {
            println!("Received from CycloneDDS: sensor_id={}, value={:.1}",
                     sample.sensor_id, sample.value);
        }
        thread::sleep(Duration::from_millis(10));
    }
}
```

## CycloneDDS Publisher

```c
// cyclone_publisher.c
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>
#include <dds/dds.h>
#include "sensor_data.h"

static volatile int running = 1;

void sigint_handler(int sig) { running = 0; }

int main(int argc, char *argv[]) {
    signal(SIGINT, sigint_handler);

    dds_entity_t participant = dds_create_participant(0, NULL, NULL);
    dds_entity_t topic = dds_create_topic(
        participant, &sensors_SensorData_desc, "SensorTopic", NULL, NULL);

    dds_qos_t *qos = dds_create_qos();
    dds_qset_reliability(qos, DDS_RELIABILITY_RELIABLE, DDS_MSECS(100));
    dds_qset_durability(qos, DDS_DURABILITY_TRANSIENT_LOCAL);
    dds_qset_history(qos, DDS_HISTORY_KEEP_LAST, 10);

    dds_entity_t writer = dds_create_writer(participant, topic, qos, NULL);
    dds_delete_qos(qos);

    printf("CycloneDDS Publisher started. Waiting for HDDS subscriber...\n");

    // Wait for match
    dds_publication_matched_status_t status;
    do {
        dds_sleepfor(DDS_MSECS(100));
        dds_get_publication_matched_status(writer, &status);
    } while (status.current_count == 0 && running);

    printf("Subscriber connected!\n");

    // Publish
    sensors_SensorData sample = { .sensor_id = 2, .value = 0.0, .timestamp = 0 };
    int count = 0;

    while (running && count < 100) {
        sample.value = 25.0 + (float)(count % 20);
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        sample.timestamp = (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;

        dds_return_t ret = dds_write(writer, &sample);
        if (ret >= 0) {
            printf("Published: sensor_id=%u, value=%.1f\n",
                   sample.sensor_id, sample.value);
        }

        count++;
        dds_sleepfor(DDS_MSECS(100));
    }

    dds_delete(participant);
    return 0;
}
```

## Build Instructions

### CycloneDDS (CMake)

```cmake
# CMakeLists.txt
cmake_minimum_required(VERSION 3.16)
project(cyclone_interop)

find_package(CycloneDDS REQUIRED)

idlc_generate(TARGET sensor_data FILES sensor_data.idl)

add_executable(cyclone_publisher cyclone_publisher.c)
target_link_libraries(cyclone_publisher CycloneDDS::ddsc sensor_data)

add_executable(cyclone_subscriber cyclone_subscriber.c)
target_link_libraries(cyclone_subscriber CycloneDDS::ddsc sensor_data)
```

```bash
mkdir build && cd build
cmake ..
make
```

### HDDS (Cargo)

```toml
# Cargo.toml
[package]
name = "hdds_interop"
version = "0.1.0"
edition = "2021"

[dependencies]
hdds = "1.0"

[build-dependencies]
hdds-gen = "1.0"
```

```bash
cargo build --release
```

## Running the Example

### Terminal 1: CycloneDDS Subscriber

```bash
export CYCLONEDDS_URI=file:///path/to/cyclonedds.xml
./build/cyclone_subscriber
```

### Terminal 2: HDDS Publisher

```bash
./target/release/hdds_publisher
```

Expected output (CycloneDDS):
```
CycloneDDS Subscriber started. Waiting for HDDS publisher...
Received from HDDS: sensor_id=1, value=20.0
Received from HDDS: sensor_id=1, value=20.5
Received from HDDS: sensor_id=1, value=21.0
...
```

## Troubleshooting

### No Connection

```bash
# Check HDDS discovery
export RUST_LOG=hdds::discovery=debug
./target/release/hdds_publisher

# Check CycloneDDS discovery
export CYCLONEDDS_URI='<CycloneDDS><Domain><Tracing><Verbosity>finest</Verbosity></Tracing></Domain></CycloneDDS>'
./build/cyclone_subscriber
```

### Type Mismatch

Ensure both sides use identical IDL:
- Same struct name and module
- Same field names and types
- Same `@key` annotations

## Next Steps

- [Setup](../../interop/cyclonedds/setup.md) - Configuration details
- [QoS Mapping](../../interop/cyclonedds/qos-mapping.md) - QoS translation
- [FastDDS Example](../../interop/fastdds/example.md) - FastDDS interop
