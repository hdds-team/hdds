# RTI Connext Interoperability

HDDS is **certified compatible** with RTI Connext DDS 6.x and 7.x.

:::tip Tested Configurations
- **RTI Connext 6.1.0**: 50/50 samples (RTPS 2.3)
- **RTI Connext 7.3.0**: 49/50 samples (RTPS 2.5)
:::

## Version Differences

| Aspect | RTI 6.x | RTI 7.x |
|--------|---------|---------|
| RTPS Version | 2.3 | **2.5** |
| Wire Format | Standard | Enhanced |
| Vendor PIDs | Standard | Additional |

HDDS handles both versions automatically without code changes.

## Requirements

- RTI Connext DDS 6.0+ or 7.x (Professional or Micro)
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

RTI Connext uses its own code generator:

```idl
// SensorData.idl
struct SensorData {
    @key long sensor_id;
    float value;
};
```

Generate for RTI Connext:
```bash
rtiddsgen -language C++11 SensorData.idl
```

Generate for HDDS:
```bash
hdds-gen gen --target rust SensorData.idl
```

## Encapsulation Format

RTI Connext typically uses **PL_CDR_BE** (big-endian):

| Phase | RTI Format | HDDS Support |
|-------|------------|--------------|
| SPDP | PL_CDR_BE (0x0002) | ✅ |
| SEDP | PL_CDR_BE (0x0002) | ✅ |
| User Data | CDR_BE / PL_CDR_BE | ✅ |

HDDS automatically handles big-endian format from RTI.

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
export HDDS_SPDP_UNICAST_PEERS="192.168.1.50:7400,192.168.1.51:7400"
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

## Known Differences

### SPDP Fragmentation

RTI Connext may fragment SPDP announcements across multiple DATA_FRAG submessages. HDDS handles this automatically.

### TypeObject Compression

RTI uses ZLIB compression for TypeObject data. HDDS supports decompression.

### Parameter Ordering

RTI expects specific parameter ordering in SEDP. HDDS follows RTI's expected order for maximum compatibility.

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
2. Check firewall allows UDP on ports 7400-7500
3. Try unicast peers instead of multicast

### Data Not Received

1. Verify QoS compatibility (reliability, durability)
2. Check type names match exactly (case-sensitive)
3. Verify key fields match (`@key` annotation)

### Timestamp Issues

RTI uses source timestamps heavily. Ensure system clocks are synchronized if using `BY_SOURCE_TIMESTAMP` ordering.

## Performance Benchmarks

Testing on same machine, domain 0:

| Metric | RTI → HDDS | HDDS → RTI |
|--------|------------|------------|
| Discovery | ~1.5s | ~1.5s |
| Latency (1KB) | 0.8 ms | 1.2 ms |
| Throughput | 50K msg/s | 45K msg/s |

## Next Steps

- [QoS Mapping](../../interop/rti-connext/qos-mapping.md) - Detailed QoS translation
- [Example](../../interop/rti-connext/example.md) - Complete working example
