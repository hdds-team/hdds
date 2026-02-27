# RTI Connext Interoperability Example

Working example of HDDS and RTI Connext DDS communicating.

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

### For RTI Connext

```bash
rtiddsgen -language C++11 -d gen sensor_data.idl
```

Generated files:
- `gen/sensor_data.cxx` / `gen/sensor_data.hpp`
- `gen/sensor_dataPlugin.cxx` / `gen/sensor_dataPlugin.hpp`

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

    println!("HDDS Publisher started. Waiting for RTI Connext subscriber...");

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

## RTI Connext Subscriber (Modern C++)

```cpp
// rti_subscriber.cxx
#include <iostream>
#include <dds/dds.hpp>
#include "sensor_data.hpp"

using namespace dds::core;
using namespace dds::domain;
using namespace dds::topic;
using namespace dds::sub;

int main() {
    // Create participant
    DomainParticipant participant(0);

    // Create topic
    Topic<sensors::SensorData> topic(participant, "SensorTopic");

    // Create subscriber
    Subscriber subscriber(participant);

    // Create reader with matching QoS
    DataReaderQos rqos = subscriber.default_datareader_qos();
    rqos << dds::core::policy::Reliability::Reliable(
            dds::core::Duration::from_millisecs(100))
         << dds::core::policy::Durability::TransientLocal()
         << dds::core::policy::History::KeepLast(100);

    DataReader<sensors::SensorData> reader(subscriber, topic, rqos);

    std::cout << "RTI Connext Subscriber started. Waiting for HDDS publisher..." << std::endl;

    // Read loop
    while (true) {
        LoanedSamples<sensors::SensorData> samples = reader.take();

        for (const auto& sample : samples) {
            if (sample.info().valid()) {
                std::cout << "Received from HDDS: sensor_id="
                          << sample.data().sensor_id()
                          << ", value=" << sample.data().value()
                          << std::endl;
            }
        }

        rti::util::sleep(dds::core::Duration::from_millisecs(10));
    }

    return 0;
}
```

## RTI Connext Subscriber (Traditional C++)

```cpp
// rti_subscriber_traditional.cxx
#include <iostream>
#include <ndds/ndds_cpp.h>
#include "sensor_data.h"
#include "sensor_dataSupport.h"

int main() {
    // Create participant
    DDSDomainParticipant* participant =
        DDSTheParticipantFactory->create_participant(
            0, DDS_PARTICIPANT_QOS_DEFAULT, NULL, DDS_STATUS_MASK_NONE);

    // Register type
    sensors_SensorDataTypeSupport::register_type(
        participant, sensors_SensorDataTypeSupport::get_type_name());

    // Create topic
    DDSTopic* topic = participant->create_topic(
        "SensorTopic",
        sensors_SensorDataTypeSupport::get_type_name(),
        DDS_TOPIC_QOS_DEFAULT, NULL, DDS_STATUS_MASK_NONE);

    // Create subscriber
    DDSSubscriber* subscriber = participant->create_subscriber(
        DDS_SUBSCRIBER_QOS_DEFAULT, NULL, DDS_STATUS_MASK_NONE);

    // Create reader with matching QoS
    DDS_DataReaderQos rqos;
    subscriber->get_default_datareader_qos(rqos);
    rqos.reliability.kind = DDS_RELIABLE_RELIABILITY_QOS;
    rqos.reliability.max_blocking_time.sec = 0;
    rqos.reliability.max_blocking_time.nanosec = 100000000;
    rqos.durability.kind = DDS_TRANSIENT_LOCAL_DURABILITY_QOS;
    rqos.history.kind = DDS_KEEP_LAST_HISTORY_QOS;
    rqos.history.depth = 100;

    DDSDataReader* reader_base = subscriber->create_datareader(
        topic, rqos, NULL, DDS_STATUS_MASK_NONE);
    sensors_SensorDataDataReader* reader =
        sensors_SensorDataDataReader::narrow(reader_base);

    std::cout << "RTI Connext Subscriber started." << std::endl;

    // Read loop
    sensors_SensorDataSeq data_seq;
    DDS_SampleInfoSeq info_seq;

    while (true) {
        DDS_ReturnCode_t retcode = reader->take(
            data_seq, info_seq, DDS_LENGTH_UNLIMITED,
            DDS_ANY_SAMPLE_STATE, DDS_ANY_VIEW_STATE, DDS_ANY_INSTANCE_STATE);

        if (retcode == DDS_RETCODE_OK) {
            for (int i = 0; i < data_seq.length(); i++) {
                if (info_seq[i].valid_data) {
                    std::cout << "Received: sensor_id=" << data_seq[i].sensor_id
                              << ", value=" << data_seq[i].value << std::endl;
                }
            }
            reader->return_loan(data_seq, info_seq);
        }

        NDDSUtility::sleep(DDS_Duration_t{0, 10000000});
    }

    return 0;
}
```

## HDDS Subscriber

```rust
// hdds_subscriber.rs
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
    let participant = Participant::builder("hdds_subscriber")
        .domain_id(0)
        .with_transport(TransportMode::UdpMulticast)
        .build()?;

    let topic = participant.topic::<SensorData>("SensorTopic")?;
    let reader = topic
        .reader()
        .qos(QoS::reliable().keep_last(100).transient_local())
        .build()?;

    println!("HDDS Subscriber started. Waiting for RTI Connext publisher...");

    loop {
        while let Some(sample) = reader.try_take()? {
            println!("Received from RTI: sensor_id={}, value={:.1}",
                     sample.sensor_id, sample.value);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
```

## RTI Connext Publisher (Modern C++)

```cpp
// rti_publisher.cxx
#include <iostream>
#include <chrono>
#include <dds/dds.hpp>
#include "sensor_data.hpp"

using namespace dds::core;
using namespace dds::domain;
using namespace dds::topic;
using namespace dds::pub;

int main() {
    // Create participant
    DomainParticipant participant(0);

    // Create topic
    Topic<sensors::SensorData> topic(participant, "SensorTopic");

    // Create publisher
    Publisher publisher(participant);

    // Create writer with QoS
    DataWriterQos wqos = publisher.default_datawriter_qos();
    wqos << dds::core::policy::Reliability::Reliable(
            dds::core::Duration::from_millisecs(100))
         << dds::core::policy::Durability::TransientLocal()
         << dds::core::policy::History::KeepLast(10);

    DataWriter<sensors::SensorData> writer(publisher, topic, wqos);

    std::cout << "RTI Connext Publisher started. Waiting for HDDS subscriber..." << std::endl;

    // Wait for match
    while (writer.publication_matched_status().current_count() == 0) {
        rti::util::sleep(dds::core::Duration::from_millisecs(100));
    }
    std::cout << "Subscriber connected!" << std::endl;

    // Publish
    sensors::SensorData sample;
    sample.sensor_id(2);

    for (int i = 0; i < 100; i++) {
        sample.value(25.0f + static_cast<float>(i % 20));
        auto now = std::chrono::system_clock::now().time_since_epoch();
        sample.timestamp(std::chrono::duration_cast<std::chrono::nanoseconds>(now).count());

        writer.write(sample);
        std::cout << "Published: sensor_id=" << sample.sensor_id()
                  << ", value=" << sample.value() << std::endl;

        rti::util::sleep(dds::core::Duration::from_millisecs(100));
    }

    return 0;
}
```

## Build Instructions

### RTI Connext (CMake)

```cmake
# CMakeLists.txt
cmake_minimum_required(VERSION 3.16)
project(rti_interop)

# RTI Connext
set(CONNEXTDDS_DIR $ENV{NDDSHOME})
list(APPEND CMAKE_MODULE_PATH "${CONNEXTDDS_DIR}/resource/cmake")
find_package(RTIConnextDDS REQUIRED)

# Generate types
connextdds_rtiddsgen_run(
    IDL_FILE sensor_data.idl
    OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/gen
    LANG C++11
)

add_executable(rti_publisher rti_publisher.cxx ${GENERATED_SRC})
target_link_libraries(rti_publisher RTIConnextDDS::cpp2_api)
target_include_directories(rti_publisher PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/gen)

add_executable(rti_subscriber rti_subscriber.cxx ${GENERATED_SRC})
target_link_libraries(rti_subscriber RTIConnextDDS::cpp2_api)
target_include_directories(rti_subscriber PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/gen)
```

```bash
source $NDDSHOME/resource/scripts/rtisetenv_x64Linux4gcc7.3.0.bash
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

## Configuration

### RTI Connext XML Profile

Create `USER_QOS_PROFILES.xml`:

```xml
<?xml version="1.0"?>
<dds xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
     xsi:noNamespaceSchemaLocation="http://community.rti.com/schema/current/rti_dds_qos_profiles.xsd">

    <qos_library name="InteropLibrary">
        <qos_profile name="InteropProfile" is_default_qos="true">

            <!-- Standard RTPS for interop -->
            <participant_qos>
                <transport_builtin>
                    <mask>UDPv4</mask>
                </transport_builtin>
                <discovery>
                    <initial_peers>
                        <element>builtin.udpv4://239.255.0.1</element>
                    </initial_peers>
                </discovery>
            </participant_qos>

            <datawriter_qos>
                <reliability>
                    <kind>RELIABLE_RELIABILITY_QOS</kind>
                </reliability>
                <durability>
                    <kind>TRANSIENT_LOCAL_DURABILITY_QOS</kind>
                </durability>
                <history>
                    <kind>KEEP_LAST_HISTORY_QOS</kind>
                    <depth>10</depth>
                </history>
            </datawriter_qos>

            <datareader_qos>
                <reliability>
                    <kind>RELIABLE_RELIABILITY_QOS</kind>
                </reliability>
                <durability>
                    <kind>TRANSIENT_LOCAL_DURABILITY_QOS</kind>
                </durability>
                <history>
                    <kind>KEEP_LAST_HISTORY_QOS</kind>
                    <depth>100</depth>
                </history>
            </datareader_qos>

        </qos_profile>
    </qos_library>
</dds>
```

### Environment Setup

```bash
# RTI Connext license
export RTI_LICENSE_FILE=/path/to/rti_license.dat

# RTI environment
source $NDDSHOME/resource/scripts/rtisetenv_x64Linux4gcc7.3.0.bash

# QoS profile
export NDDS_QOS_PROFILES=USER_QOS_PROFILES.xml
```

## Running the Example

### Terminal 1: RTI Connext Subscriber

```bash
source $NDDSHOME/resource/scripts/rtisetenv_x64Linux4gcc7.3.0.bash
./build/rti_subscriber
```

### Terminal 2: HDDS Publisher

```bash
./target/release/hdds_publisher
```

Expected output (RTI Connext):
```
RTI Connext Subscriber started. Waiting for HDDS publisher...
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

Terminal 2: RTI Connext Publisher
```bash
./build/rti_publisher
```

## Troubleshooting

### No Discovery

```bash
# Enable RTI Connext discovery logging
export NDDS_DISCOVERY_PEERS=builtin.udpv4://239.255.0.1

# Check RTI Admin Console
$NDDSHOME/bin/rtiadminconsole
```

### License Issues

```bash
# Verify license
$NDDSHOME/bin/rtilmutil -check

# Set license path
export RTI_LICENSE_FILE=/path/to/rti_license.dat
```

### Type Mismatch

Ensure type compatibility:

```bash
# Regenerate with type consistency
rtiddsgen -language C++11 -typeCheckingOnMatch sensor_data.idl
```

RTI Connext XML for type consistency:

```xml
<type_consistency>
    <kind>ALLOW_TYPE_COERCION</kind>
    <ignore_sequence_bounds>true</ignore_sequence_bounds>
    <ignore_string_bounds>true</ignore_string_bounds>
</type_consistency>
```

### Wire Protocol Issues

Ensure standard RTPS wire protocol:

```xml
<participant_qos>
    <wire_protocol>
        <rtps_auto_id_kind>RTPS_AUTO_ID_FROM_UUID</rtps_auto_id_kind>
    </wire_protocol>
</participant_qos>
```

## RTI Admin Console

Use RTI Admin Console for debugging:

```bash
$NDDSHOME/bin/rtiadminconsole
```

Features:
- View discovered participants
- Monitor topics and endpoints
- Inspect QoS policies
- Capture data samples

## Performance Tuning

### Shared Memory (Same Host)

RTI Connext shared memory is not compatible with HDDS. For same-host:

```xml
<participant_qos>
    <transport_builtin>
        <!-- Use UDP loopback for cross-vendor -->
        <mask>UDPv4</mask>
    </transport_builtin>
</participant_qos>
```

### Large Data

For large samples:

```xml
<datawriter_qos>
    <publish_mode>
        <kind>ASYNCHRONOUS_PUBLISH_MODE_QOS</kind>
    </publish_mode>
</datawriter_qos>
```

## Next Steps

- [Setup](../../interop/rti-connext/setup.md) - Configuration details
- [QoS Mapping](../../interop/rti-connext/qos-mapping.md) - QoS translation
- [FastDDS Example](../../interop/fastdds/example.md) - FastDDS interop
