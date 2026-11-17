# RTI Connext Interoperability

HDDS speaks standard RTPS, and RTI Connext is an RTPS implementation too. This guide lists the settings to check when you pair them. No interoperability results for RTI Connext are published here; the steps below assume your own RTI Connext installation and licence.

## Requirements

- Your own RTI Connext installation and licence
- Same domain ID on both ends
- Compatible QoS policies

## Quick Test

### HDDS Publisher

```rust
use hdds::{Participant, QoS, DDS, TransportMode};

#[derive(Debug, Clone, DDS)]
struct SensorData {
    #[key]
    sensor_id: i32,
    value: f32,
}

fn main() -> Result<(), hdds::Error> {
    let participant = Participant::builder("hdds_publisher")
        .domain_id(0)
        .with_transport(TransportMode::UdpMulticast)
        .build()?;

    let topic = participant.topic::<SensorData>("SensorTopic")?;
    let writer = topic.writer().qos(QoS::reliable()).build()?;

    for i in 0.. {
        writer.write(&SensorData {
            sensor_id: 1,
            value: i as f32 * 0.1,
        })?;
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    Ok(())
}
```

### RTI Connext Subscriber (C++)

```cpp
#include <dds/dds.hpp>

int main() {
    dds::domain::DomainParticipant participant(0);
    dds::topic::Topic<SensorData> topic(participant, "SensorTopic");
    dds::sub::Subscriber subscriber(participant);
    dds::sub::DataReader<SensorData> reader(subscriber, topic);

    while (true) {
        auto samples = reader.take();
        for (const auto& sample : samples) {
            if (sample.info().valid()) {
                std::cout << "Sensor " << sample.data().sensor_id()
                          << ": " << sample.data().value() << std::endl;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}
```

## IDL Type Definition

Both sides must be generated from the same IDL:

```idl
// SensorData.idl
struct SensorData {
    @key long sensor_id;
    float value;
};
```

Generate for RTI Connext (with your own installation):
```bash
rtiddsgen -language C++11 SensorData.idl
```

Generate for HDDS (`hddsgen` 2.0 comes from the separate `hdds_gen` repository;
build it with `git clone https://git.hdds.io/hdds/hdds_gen.git && cargo install --path hdds_gen`):
```bash
hddsgen gen rust SensorData.idl -o src/sensor_data.rs
```

The `#[derive(DDS)]` struct in the quick test above is convenient for a program
that only talks to HDDS. For a type shared with another vendor, use the
generated code, so that the type name, the keys and the extensibility are
exactly the ones the IDL declares.

## Encapsulation Format

HDDS reads both big-endian and little-endian encapsulations (CDR_BE / CDR_LE,
PL_CDR_BE / PL_CDR_LE) on discovery and user data, as the RTPS and XTypes
specifications allow a writer to choose either byte order.

## QoS Configuration

### RTI Connext (XML)

```xml
<?xml version="1.0"?>
<dds>
    <qos_library name="HddsInterop">
        <qos_profile name="Default">
            <datawriter_qos>
                <reliability>
                    <kind>RELIABLE_RELIABILITY_QOS</kind>
                    <max_blocking_time>
                        <sec>1</sec>
                        <nanosec>0</nanosec>
                    </max_blocking_time>
                </reliability>
                <durability>
                    <kind>TRANSIENT_LOCAL_DURABILITY_QOS</kind>
                </durability>
                <history>
                    <kind>KEEP_LAST_HISTORY_QOS</kind>
                    <depth>100</depth>
                </history>
            </datawriter_qos>
        </qos_profile>
    </qos_library>
</dds>
```

### HDDS (Rust)

```rust
use hdds::QoS;

let qos = QoS::reliable().keep_last(100).transient_local();
```

## Network Configuration

### Multicast (Default)

Standard RTPS multicast works out of the box:

```
Discovery: 239.255.0.1:7400 (domain 0)
```

### Unicast/WAN Configuration

**HDDS:**
```bash
# each peer's metatraffic unicast port: 7410 + 250 x domain + 2 x participant index
export HDDS_SPDP_UNICAST_PEERS="192.168.1.50:7410,192.168.1.51:7410"
```

**RTI Connext (XML):**
```xml
<participant_qos>
    <discovery>
        <initial_peers>
            <element>192.168.1.50</element>
            <element>192.168.1.51</element>
        </initial_peers>
    </discovery>
</participant_qos>
```

## HDDS Behaviour Relevant to Interop

### SPDP Fragmentation

HDDS reassembles SPDP and SEDP announcements sent as DATA_FRAG submessages.

### TypeObject Compression

HDDS decompresses ZLIB-compressed TypeObject data.

## RTI Admin Console

To monitor HDDS participants in RTI Admin Console:

1. Open Admin Console
2. Connect to domain (matching domain ID)
3. HDDS participants appear under "Participants"
4. Topics, endpoints visible in tree view

## Troubleshooting

### RTI Doesn't See HDDS

1. Check domain ID matches
2. Enable HDDS diagnostics:
   ```bash
   export HDDS_INTEROP_DIAGNOSTICS=1
   export RUST_LOG=hdds=debug
   ```
3. Check RTI Distributed Logger for errors

### HDDS Doesn't See RTI

1. Verify RTI is publishing on expected multicast
2. Check the firewall allows the UDP ports of your domain (`7400 + 250 x D` to `7649 + 250 x D`)
3. Try unicast peers instead of multicast

### Data Not Received

1. Verify QoS compatibility (reliability, durability)
2. Check type names match exactly (case-sensitive)
3. Verify key fields match (`@key` annotation)

### Timestamp Issues

With `BY_SOURCE_TIMESTAMP` destination order, samples are ordered by the writer's
source timestamp, so ensure system clocks are synchronized on both hosts.

## Performance Validation

The interop suite validates behavior, not a reference-grade RTI-to-HDDS
performance baseline. Measure both directions with the exact vendor versions,
QoS, payload, topology, build, machine, delivery counts, and raw artifacts
before publishing latency or throughput.

## Next Steps

- [QoS Mapping](../../interop/rti-connext/qos-mapping.md) - Detailed QoS translation
- [Example](../../interop/rti-connext/example.md) - Complete working example
