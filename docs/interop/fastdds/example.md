# FastDDS Interoperability Example

Working example of HDDS and FastDDS (eProsima Fast DDS) communicating.

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

### For FastDDS

```bash
fastddsgen -typeros2 sensor_data.idl
```

Generated files:
- `sensor_data.cxx` / `sensor_data.hpp`
- `sensor_dataPubSubTypes.cxx` / `sensor_dataPubSubTypes.hpp`

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

    println!("HDDS Publisher started. Waiting for FastDDS subscriber...");

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

## FastDDS Subscriber

```cpp
// fastdds_subscriber.cpp
#include <fastdds/dds/domain/DomainParticipantFactory.hpp>
#include <fastdds/dds/domain/DomainParticipant.hpp>
#include <fastdds/dds/subscriber/Subscriber.hpp>
#include <fastdds/dds/subscriber/DataReader.hpp>
#include <fastdds/dds/subscriber/DataReaderListener.hpp>
#include <fastdds/dds/subscriber/SampleInfo.hpp>
#include <fastdds/dds/topic/Topic.hpp>

#include "sensor_dataPubSubTypes.hpp"
#include "sensor_data.hpp"

#include <iostream>
#include <csignal>
#include <atomic>

using namespace eprosima::fastdds::dds;

std::atomic<bool> running{true};

void sigint_handler(int) { running = false; }

class SensorListener : public DataReaderListener {
public:
    void on_data_available(DataReader* reader) override {
        sensors::SensorData sample;
        SampleInfo info;

        while (reader->take_next_sample(&sample, &info) == RETCODE_OK) {
            if (info.valid_data) {
                std::cout << "Received from HDDS: sensor_id=" << sample.sensor_id()
                          << ", value=" << sample.value() << std::endl;
            }
        }
    }

    void on_subscription_matched(DataReader*, const SubscriptionMatchedStatus& status) override {
        if (status.current_count_change > 0) {
            std::cout << "Publisher matched!" << std::endl;
        } else {
            std::cout << "Publisher unmatched." << std::endl;
        }
    }
};

int main() {
    signal(SIGINT, sigint_handler);

    // Create participant
    DomainParticipantQos pqos;
    pqos.name("FastDDS_Subscriber");
    DomainParticipant* participant = DomainParticipantFactory::get_instance()
        ->create_participant(0, pqos);

    if (!participant) {
        std::cerr << "Failed to create participant" << std::endl;
        return 1;
    }

    // Register type
    TypeSupport type(new sensors::SensorDataPubSubType());
    type.register_type(participant);

    // Create topic
    Topic* topic = participant->create_topic("SensorTopic", type.get_type_name(), TOPIC_QOS_DEFAULT);

    // Create subscriber
    Subscriber* subscriber = participant->create_subscriber(SUBSCRIBER_QOS_DEFAULT);

    // Create reader with matching QoS
    DataReaderQos rqos = DATAREADER_QOS_DEFAULT;
    rqos.reliability().kind = RELIABLE_RELIABILITY_QOS;
    rqos.reliability().max_blocking_time = {0, 100000000};
    rqos.durability().kind = TRANSIENT_LOCAL_DURABILITY_QOS;
    rqos.history().kind = KEEP_LAST_HISTORY_QOS;
    rqos.history().depth = 100;

    SensorListener listener;
    DataReader* reader = subscriber->create_datareader(topic, rqos, &listener);

    std::cout << "FastDDS Subscriber started. Waiting for HDDS publisher..." << std::endl;

    while (running) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    // Cleanup
    participant->delete_contained_entities();
    DomainParticipantFactory::get_instance()->delete_participant(participant);

    std::cout << "Subscriber stopped." << std::endl;
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

    println!("HDDS Subscriber started. Waiting for FastDDS publisher...");

    loop {
        while let Some(sample) = reader.try_take()? {
            println!("Received from FastDDS: sensor_id={}, value={:.1}",
                     sample.sensor_id, sample.value);
        }
        thread::sleep(Duration::from_millis(10));
    }
}
```

## FastDDS Publisher

```cpp
// fastdds_publisher.cpp
#include <fastdds/dds/domain/DomainParticipantFactory.hpp>
#include <fastdds/dds/domain/DomainParticipant.hpp>
#include <fastdds/dds/publisher/Publisher.hpp>
#include <fastdds/dds/publisher/DataWriter.hpp>
#include <fastdds/dds/publisher/DataWriterListener.hpp>
#include <fastdds/dds/topic/Topic.hpp>

#include "sensor_dataPubSubTypes.hpp"
#include "sensor_data.hpp"

#include <iostream>
#include <chrono>
#include <csignal>
#include <atomic>

using namespace eprosima::fastdds::dds;

std::atomic<bool> running{true};
std::atomic<bool> matched{false};

void sigint_handler(int) { running = false; }

class PubListener : public DataWriterListener {
public:
    void on_publication_matched(DataWriter*, const PublicationMatchedStatus& status) override {
        matched = (status.current_count > 0);
        if (status.current_count_change > 0) {
            std::cout << "Subscriber matched!" << std::endl;
        } else {
            std::cout << "Subscriber unmatched." << std::endl;
        }
    }
};

int main() {
    signal(SIGINT, sigint_handler);

    // Create participant
    DomainParticipantQos pqos;
    pqos.name("FastDDS_Publisher");
    DomainParticipant* participant = DomainParticipantFactory::get_instance()
        ->create_participant(0, pqos);

    // Register type
    TypeSupport type(new sensors::SensorDataPubSubType());
    type.register_type(participant);

    // Create topic
    Topic* topic = participant->create_topic("SensorTopic", type.get_type_name(), TOPIC_QOS_DEFAULT);

    // Create publisher
    Publisher* publisher = participant->create_publisher(PUBLISHER_QOS_DEFAULT);

    // Create writer with QoS
    DataWriterQos wqos = DATAWRITER_QOS_DEFAULT;
    wqos.reliability().kind = RELIABLE_RELIABILITY_QOS;
    wqos.reliability().max_blocking_time = {0, 100000000};
    wqos.durability().kind = TRANSIENT_LOCAL_DURABILITY_QOS;
    wqos.history().kind = KEEP_LAST_HISTORY_QOS;
    wqos.history().depth = 10;

    PubListener listener;
    DataWriter* writer = publisher->create_datawriter(topic, wqos, &listener);

    std::cout << "FastDDS Publisher started. Waiting for HDDS subscriber..." << std::endl;

    // Wait for match
    while (!matched && running) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    // Publish
    sensors::SensorData sample;
    sample.sensor_id(2);

    for (int i = 0; i < 100 && running; ++i) {
        sample.value(25.0f + static_cast<float>(i % 20));
        auto now = std::chrono::system_clock::now().time_since_epoch();
        sample.timestamp(std::chrono::duration_cast<std::chrono::nanoseconds>(now).count());

        if (writer->write(&sample) == RETCODE_OK) {
            std::cout << "Published: sensor_id=" << sample.sensor_id()
                      << ", value=" << sample.value() << std::endl;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    // Cleanup
    participant->delete_contained_entities();
    DomainParticipantFactory::get_instance()->delete_participant(participant);

    return 0;
}
```

## Build Instructions

### FastDDS (CMake)

```cmake
# CMakeLists.txt
cmake_minimum_required(VERSION 3.16)
project(fastdds_interop)

find_package(fastcdr REQUIRED)
find_package(fastdds REQUIRED)

# Generate types from IDL
add_custom_command(
    OUTPUT sensor_data.cxx sensor_data.hpp
           sensor_dataPubSubTypes.cxx sensor_dataPubSubTypes.hpp
    COMMAND fastddsgen -typeros2 ${CMAKE_SOURCE_DIR}/sensor_data.idl
    DEPENDS sensor_data.idl
)

add_library(sensor_data_types
    sensor_data.cxx
    sensor_dataPubSubTypes.cxx
)
target_link_libraries(sensor_data_types fastcdr fastdds)

add_executable(fastdds_publisher fastdds_publisher.cpp)
target_link_libraries(fastdds_publisher sensor_data_types)

add_executable(fastdds_subscriber fastdds_subscriber.cpp)
target_link_libraries(fastdds_subscriber sensor_data_types)
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

```rust
// build.rs
fn main() {
    hdds_gen::compile(&["sensor_data.idl"]).unwrap();
}
```

```bash
cargo build --release
```

## Configuration for Interop

### Disable Data Sharing (Important!)

For cross-vendor interop, disable FastDDS data sharing:

```cpp
// In code
DataWriterQos wqos;
wqos.data_sharing().off();
```

Or via XML:
```xml
<data_sharing>
    <kind>OFF</kind>
</data_sharing>
```

## Running the Example

### Terminal 1: FastDDS Subscriber

```bash
export FASTDDS_DEFAULT_PROFILES_FILE=DEFAULT_FASTDDS_PROFILES.xml
./build/fastdds_subscriber
```

### Terminal 2: HDDS Publisher

```bash
./target/release/hdds_publisher
```

Expected output (FastDDS):
```
FastDDS Subscriber started. Waiting for HDDS publisher...
Publisher matched!
Received from HDDS: sensor_id=1, value=20
Received from HDDS: sensor_id=1, value=20.5
Received from HDDS: sensor_id=1, value=21
...
```

### Reverse Direction

Terminal 1: HDDS Subscriber
```bash
./target/release/hdds_subscriber
```

Terminal 2: FastDDS Publisher
```bash
./build/fastdds_publisher
```

## Troubleshooting

### No Discovery

```bash
# Check FastDDS discovery
export FASTDDS_STATISTICS="DISCOVERY_TOPIC"
./build/fastdds_subscriber

# Check HDDS discovery
export RUST_LOG=hdds::discovery=debug
./target/release/hdds_publisher
```

### Type Hash Mismatch

FastDDS uses TypeObject/TypeIdentifier. Ensure:
- Same IDL file used for both sides
- Same `@appendable` or `@final` annotation
- Regenerate types after IDL changes

### Data Sharing Conflict

FastDDS data sharing is NOT compatible with other vendors:

```cpp
// MUST disable for interop
wqos.data_sharing().off();
rqos.data_sharing().off();
```

## Next Steps

- [Setup](../../interop/fastdds/setup.md) - Configuration details
- [QoS Mapping](../../interop/fastdds/qos-mapping.md) - QoS translation
- [CycloneDDS Example](../../interop/cyclonedds/example.md) - CycloneDDS interop
