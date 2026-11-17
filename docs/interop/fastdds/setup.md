# FastDDS Interoperability

HDDS interoperates with eProsima FastDDS over standard RTPS. The steps below assume your own FastDDS installation.

## Requirements

- Fast DDS 3.x (the interoperability results use 3.6.2)
- Same domain ID on both ends
- Compatible QoS policies
- RTPS 2.4 wire protocol

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

Generate for HDDS (`hddsgen` 2.0 comes from the separate `hdds_gen` repository;
build it with `git clone https://git.hdds.io/hdds/hdds_gen.git && cargo install --path hdds_gen`):
```bash
hddsgen gen rust HelloWorld.idl -o src/hello_world.rs
```

The `#[derive(DDS)]` struct in the quick test above is convenient for a program
that only talks to HDDS. For a type shared with another vendor, use the
generated code, so that the type name (`HelloWorld` here), the keys and the
extensibility are exactly the ones the IDL declares.

## QoS Compatibility

### Common Profiles

| Profile | Reliability | Durability | History |
|---------|-------------|------------|---------|
| Sensor Streaming | best_effort() | volatile() | keep_last(1) |
| State Sync | reliable() | transient_local() | keep_last(10) |
| Event Log | reliable() | transient_local() | keep_all() |

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

Discovery data is **PL_CDR_LE** (0x0003) per the RTPS specification. User data
uses the encapsulation selected by the data representation QoS and the type's
extensibility. HDDS reads all of them:

| Phase | Encapsulation | HDDS Support |
|-------|---------------|--------------|
| SPDP | PL_CDR_LE | Yes |
| SEDP | PL_CDR_LE | Yes |
| User Data | CDR_LE (XCDR1) / CDR2_LE, D_CDR2_LE, PL_CDR2_LE (XCDR2) | Yes |

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
# the peer's metatraffic unicast port: 7410 + 250 x domain + 2 x participant index
export HDDS_SPDP_UNICAST_PEERS="192.168.1.100:7410"
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
                        <port>7410</port>
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
2. **Check firewall**: the UDP ports of your domain are open (`7400 + 250 x D` to `7649 + 250 x D`)
3. **Check multicast**: `ping 239.255.0.1`

### Type Mismatch

Ensure IDL matches exactly:
- Same field names
- Same field types
- Same field order

### QoS Incompatible

Most common issues:
- HDDS best_effort() writer -> FastDDS Reliable reader (fails)
- HDDS volatile() -> FastDDS TransientLocal reader (fails)

## Performance Notes

The interop suite validates behavior, not a reference-grade FastDDS-to-HDDS
performance baseline. Measure the exact vendor versions, QoS, payload,
topology, build, machine, delivery counts, and raw artifacts before publishing
discovery, latency, or throughput results.

## Next Steps

- [QoS Mapping](../../interop/fastdds/qos-mapping.md) - Detailed QoS mapping
- [Example](../../interop/fastdds/example.md) - Complete working example
