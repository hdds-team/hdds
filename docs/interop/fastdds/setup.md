# FastDDS Interoperability

HDDS is **certified compatible** with eProsima FastDDS.

:::tip Tested Configuration
**FastDDS 3.1.x** bidirectional interop: 50/50 samples in both directions.
:::

## Requirements

- FastDDS 3.x (tested with 3.1.x) or FastDDS 2.10+
- Same domain ID on both ends
- Compatible QoS policies
- RTPS 2.3 wire protocol

## Quick Test

### HDDS Publisher

```rust
use hdds::{Participant, QoS, DDS, TransportMode};

#[derive(Debug, Clone, DDS)]
struct HelloWorld {
    message: String,
}

fn main() -> Result<(), hdds::Error> {
    let participant = Participant::builder("hdds_publisher")
        .domain_id(0)
        .with_transport(TransportMode::UdpMulticast)
        .build()?;

    let topic = participant.topic::<HelloWorld>("HelloWorldTopic")?;
    let writer = topic.writer().qos(QoS::reliable()).build()?;

    loop {
        writer.write(&HelloWorld {
            message: "Hello from HDDS!".to_string(),
        })?;
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}
```

### FastDDS Subscriber (C++)

```cpp
#include <fastdds/dds/domain/DomainParticipantFactory.hpp>
#include <fastdds/dds/subscriber/Subscriber.hpp>
#include <fastdds/dds/subscriber/DataReader.hpp>

int main() {
    auto factory = DomainParticipantFactory::get_instance();
    auto participant = factory->create_participant(0, PARTICIPANT_QOS_DEFAULT);

    // Register type
    TypeSupport type(new HelloWorldPubSubType());
    type.register_type(participant);

    auto topic = participant->create_topic("HelloWorldTopic", "HelloWorld", TOPIC_QOS_DEFAULT);
    auto subscriber = participant->create_subscriber(SUBSCRIBER_QOS_DEFAULT);
    auto reader = subscriber->create_datareader(topic, DATAREADER_QOS_DEFAULT);

    // Read loop
    HelloWorld sample;
    SampleInfo info;
    while (true) {
        if (reader->take_next_sample(&sample, &info) == ReturnCode_t::RETCODE_OK) {
            std::cout << "Received: " << sample.message() << std::endl;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}
```

## IDL Type Definition

Both sides must use matching types:

```idl
// HelloWorld.idl
struct HelloWorld {
    string message;
};
```

Generate for FastDDS:
```bash
fastddsgen HelloWorld.idl
```

Generate for HDDS:
```bash
hdds-gen gen --target rust HelloWorld.idl
```

## QoS Compatibility

### Verified Profiles

| Profile | Reliability | Durability | History | Status |
|---------|-------------|------------|---------|--------|
| Sensor Streaming | best_effort() | volatile() | keep_last(1) | ✅ |
| State Sync | reliable() | transient_local() | keep_last(10) | ✅ |
| Event Log | reliable() | transient_local() | keep_all() | ✅ |

### FastDDS QoS (XML)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<dds>
    <profiles>
        <data_writer_qos profile_name="hdds_interop">
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
        </data_writer_qos>
    </profiles>
</dds>
```

### HDDS QoS (Rust)

```rust
use hdds::QoS;

let qos = QoS::reliable().keep_last(10).transient_local();
```

## Encapsulation Format

FastDDS uses **PL_CDR_LE** (0x0003) for discovery and **DL_CDR2_LE** for user data:

| Phase | FastDDS Format | HDDS Support |
|-------|----------------|--------------|
| SPDP | PL_CDR_LE | ✅ |
| SEDP | PL_CDR_LE | ✅ |
| User Data | DL_CDR2_LE / CDR_LE | ✅ |

## Network Configuration

### Multicast (Default)

No configuration needed. Both use standard RTPS multicast:

```
Multicast: 239.255.0.1:7400 (domain 0)
```

### Unicast Only

If multicast is disabled:

**HDDS:**
```bash
export HDDS_SPDP_UNICAST_PEERS="192.168.1.100:7400"
```

**FastDDS (XML):**
```xml
<participant profile_name="unicast_participant">
    <rtps>
        <builtin>
            <initialPeersList>
                <locator>
                    <udpv4>
                        <address>192.168.1.100</address>
                        <port>7400</port>
                    </udpv4>
                </locator>
            </initialPeersList>
        </builtin>
    </rtps>
</participant>
```

## Troubleshooting

### Discovery Fails

1. **Check domain ID**: Must match on both sides
2. **Check firewall**: UDP ports 7400-7500 open
3. **Check multicast**: `ping 239.255.0.1`

### Type Mismatch

Ensure IDL matches exactly:
- Same field names
- Same field types
- Same field order

### QoS Incompatible

Most common issues:
- HDDS best_effort() writer → FastDDS Reliable reader (fails)
- HDDS volatile() → FastDDS TransientLocal reader (fails)

## Performance Notes

| Metric | Value |
|--------|-------|
| Discovery time | < 2 seconds |
| Message latency | < 1 ms (same host) |
| Throughput | 100K+ msg/s |

## Next Steps

- [QoS Mapping](../../interop/fastdds/qos-mapping.md) - Detailed QoS mapping
- [Example](../../interop/fastdds/example.md) - Complete working example
