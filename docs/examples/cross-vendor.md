# Cross-Vendor Example

Demonstrates HDDS interoperability with FastDDS, RTI Connext, and CycloneDDS.

## Overview

HDDS implements RTPS 2.4, enabling communication with any compliant DDS implementation:
- **FastDDS** (eProsima)
- **RTI Connext DDS**
- **CycloneDDS** (Eclipse)
- **OpenDDS**

## Common IDL Definition

All vendors must use the same IDL:

```c title="Interop.idl"
module interop {
    @topic
    struct Message {
        @key uint32 sender_id;
        uint64 sequence;
        string<256> content;
        float values[4];
    };
};
```

## HDDS Publisher

```rust title="hdds_publisher.rs"
use hdds::{Participant, QoS, DDS, TransportMode};
use interop::Message;
use std::time::Duration;

#[derive(Debug, Clone, DDS)]
struct Message {
    #[key]
    sender_id: u32,
    sequence: u64,
    content: String,
    values: [f32; 4],
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let participant = Participant::builder("hdds_publisher")
        .domain_id(0)
        .with_transport(TransportMode::UdpMulticast)
        .build()?;

    let topic = participant.topic::<Message>("InteropTopic")?;

    // Use standard QoS for maximum compatibility
    let writer = topic
        .writer()
        .qos(QoS::reliable().keep_last(10).transient_local())
        .build()?;

    for seq in 1..=100 {
        let msg = Message {
            sender_id: 1,  // HDDS sender
            sequence: seq,
            content: format!("Hello from HDDS #{}", seq),
            values: [1.0, 2.0, 3.0, 4.0],
        };

        writer.write(&msg)?;
        println!("HDDS sent: {}", msg.content);
        std::thread::sleep(Duration::from_millis(100));
    }

    Ok(())
}
```

## FastDDS Subscriber (C++)

```cpp title="fastdds_subscriber.cpp"
#include <fastdds/dds/domain/DomainParticipantFactory.hpp>
#include <fastdds/dds/subscriber/Subscriber.hpp>
#include <fastdds/dds/subscriber/DataReader.hpp>
#include "InteropPubSubTypes.h"

using namespace eprosima::fastdds::dds;

class MessageListener : public DataReaderListener {
public:
    void on_data_available(DataReader* reader) override {
        interop::Message msg;
        SampleInfo info;

        while (reader->take_next_sample(&msg, &info) == ReturnCode_t::RETCODE_OK) {
            if (info.valid_data) {
                std::cout << "FastDDS received: " << msg.content()
                          << " (seq=" << msg.sequence() << ")" << std::endl;
            }
        }
    }
};

int main() {
    auto factory = DomainParticipantFactory::get_instance();
    auto participant = factory->create_participant(0, PARTICIPANT_QOS_DEFAULT);

    // Register type
    TypeSupport type(new interop::MessagePubSubType());
    type.register_type(participant);

    // Create subscriber
    auto subscriber = participant->create_subscriber(SUBSCRIBER_QOS_DEFAULT);
    auto topic = participant->create_topic("InteropTopic", "interop::Message",
                                           TOPIC_QOS_DEFAULT);

    // QoS must match HDDS
    DataReaderQos reader_qos = DATAREADER_QOS_DEFAULT;
    reader_qos.reliability().kind = RELIABLE_RELIABILITY_QOS;
    reader_qos.durability().kind = TRANSIENT_LOCAL_DURABILITY_QOS;
    reader_qos.history().kind = KEEP_LAST_HISTORY_QOS;
    reader_qos.history().depth = 10;

    MessageListener listener;
    auto reader = subscriber->create_datareader(topic, reader_qos, &listener);

    std::cout << "FastDDS waiting for messages..." << std::endl;
    std::this_thread::sleep_for(std::chrono::seconds(60));

    return 0;
}
```

## RTI Connext Subscriber (C++)

```cpp title="connext_subscriber.cpp"
#include <dds/dds.hpp>
#include "Interop.hpp"

int main() {
    dds::domain::DomainParticipant participant(0);
    dds::topic::Topic<interop::Message> topic(participant, "InteropTopic");

    // QoS matching HDDS
    dds::sub::qos::DataReaderQos reader_qos;
    reader_qos << dds::core::policy::Reliability::Reliable()
               << dds::core::policy::Durability::TransientLocal()
               << dds::core::policy::History::KeepLast(10);

    dds::sub::Subscriber subscriber(participant);
    dds::sub::DataReader<interop::Message> reader(subscriber, topic, reader_qos);

    std::cout << "RTI Connext waiting for messages..." << std::endl;

    while (true) {
        auto samples = reader.take();
        for (const auto& sample : samples) {
            if (sample.info().valid()) {
                std::cout << "Connext received: " << sample.data().content()
                          << " (seq=" << sample.data().sequence() << ")"
                          << std::endl;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}
```

## CycloneDDS Subscriber (C)

```c title="cyclone_subscriber.c"
#include "dds/dds.h"
#include "Interop.h"

int main(void) {
    dds_entity_t participant = dds_create_participant(0, NULL, NULL);
    dds_entity_t topic = dds_create_topic(
        participant, &interop_Message_desc, "InteropTopic", NULL, NULL);

    // QoS matching HDDS
    dds_qos_t *qos = dds_create_qos();
    dds_qset_reliability(qos, DDS_RELIABILITY_RELIABLE, DDS_SECS(1));
    dds_qset_durability(qos, DDS_DURABILITY_TRANSIENT_LOCAL);
    dds_qset_history(qos, DDS_HISTORY_KEEP_LAST, 10);

    dds_entity_t reader = dds_create_reader(participant, topic, qos, NULL);
    dds_delete_qos(qos);

    printf("CycloneDDS waiting for messages...\n");

    interop_Message *msg = interop_Message__alloc();
    dds_sample_info_t info;

    while (1) {
        void *samples[1] = { msg };
        int32_t n = dds_take(reader, samples, &info, 1, 1);

        if (n > 0 && info.valid_data) {
            printf("Cyclone received: %s (seq=%lu)\n",
                   msg->content, msg->sequence);
        }
        dds_sleepfor(DDS_MSECS(10));
    }

    return 0;
}
```

## Wire-Level Compatibility

### RTPS Protocol

All implementations use RTPS 2.4:

| Component | Standard | HDDS Support |
|-----------|----------|--------------|
| Discovery | SPDP/SEDP | Full |
| Reliability | RTPS ACK/NACK | Full |
| Fragmentation | DATA_FRAG | Full |
| Multicast | 239.255.0.1:7400 | Configurable |

### Serialization Formats

```rust
// HDDS supports all standard encodings
// CDR2/XCDR2 used by default for maximum compatibility
```

| Format | PID | HDDS | FastDDS | Connext | Cyclone |
|--------|-----|------|---------|---------|---------|
| CDR1 | 0x0000 | Read | Yes | Yes | Yes |
| CDR2 | 0x0001 | Yes | Yes | Yes | Yes |
| XCDR2 | 0x0002 | Yes | Yes | Yes | Yes |

## Troubleshooting Interop

### Discovery Issues

```bash
# Check multicast connectivity
ping -c 3 239.255.0.1

# Verify RTPS traffic
tcpdump -i any -n udp port 7400

# Enable HDDS discovery debug
export RUST_LOG=hdds::discovery=debug
```

### QoS Mismatch

Common incompatibilities:

| Issue | Symptom | Solution |
|-------|---------|----------|
| Reliability mismatch | No data received | Match Reliable/BestEffort |
| Durability mismatch | Late joiner gets no data | Writer durability >= Reader |
| History type | Memory issues | Align KeepLast/KeepAll |

### Type Mismatch

```bash
# Check type compatibility
hdds-viewer --show-types capture.hddscap

# Verify IDL hash matches
hdds-gen --print-typehash Interop.idl
```

## Vendor-Specific Notes

### FastDDS

- Default discovery: OK
- Large data: Enable DATA_FRAG
- Security: DDS-Security 1.1 compatible

### RTI Connext

- May use big-endian by default
- SPDP fragmentation for large user data
- Enable interoperability mode if issues

### CycloneDDS

- Excellent RTPS compliance
- Default multicast compatible
- Shared memory disabled for interop

## Environment Variables

```bash
# HDDS
export HDDS_DOMAIN_ID=0
export RUST_LOG=hdds=info

# FastDDS
export FASTRTPS_DEFAULT_PROFILES_FILE=config.xml

# RTI Connext
export NDDS_DISCOVERY_PEERS=builtin.udpv4://239.255.0.1

# CycloneDDS
export CYCLONEDDS_URI=file://cyclone.xml
```

## Network Configuration

For cross-machine interop:

```xml title="hdds_config.xml"
<hdds>
    <discovery>
        <multicast_address>239.255.0.1</multicast_address>
        <multicast_port>7400</multicast_port>
    </discovery>
    <transport>
        <!-- Disable shared memory for network interop -->
        <shared_memory enabled="false"/>
    </transport>
</hdds>
```

## Testing Interoperability

1. Start subscriber (any vendor)
2. Start publisher (different vendor)
3. Verify messages received
4. Check sequence numbers for gaps

```bash
# Run HDDS publisher
cargo run --bin hdds_publisher

# In another terminal, run FastDDS subscriber
./fastdds_subscriber
```

## Next Steps

- [Wire Compatibility](../interop/wire-compatibility.md) - Protocol details
- [FastDDS Setup](../interop/fastdds/setup.md) - FastDDS configuration
- [RTI Connext Setup](../interop/rti-connext/setup.md) - Connext configuration
- [CycloneDDS Setup](../interop/cyclonedds/setup.md) - CycloneDDS configuration
