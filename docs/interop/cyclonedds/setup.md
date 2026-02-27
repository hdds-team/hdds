# CycloneDDS Setup

Configure CycloneDDS to communicate with HDDS participants.

:::tip Tested Configuration
**CycloneDDS 0.10.x** bidirectional interop: 50/50 samples in both directions.
:::

## Installation

### Ubuntu/Debian

```bash
sudo apt install cyclonedds-dev cyclonedds-tools
```

### From Source

```bash
git clone https://github.com/eclipse-cyclonedds/cyclonedds.git
cd cyclonedds
mkdir build && cd build
cmake -DCMAKE_INSTALL_PREFIX=/usr/local ..
make -j$(nproc)
sudo make install
```

### ROS2 (Already Installed)

```bash
# CycloneDDS is bundled with ROS2
source /opt/ros/$ROS_DISTRO/setup.bash
```

## Basic Configuration

### Minimal Interop Configuration

Create `cyclonedds.xml`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<CycloneDDS xmlns="https://cdds.io/config">
    <Domain id="any">
        <General>
            <AllowMulticast>true</AllowMulticast>
        </General>
    </Domain>
</CycloneDDS>
```

Apply configuration:

```bash
export CYCLONEDDS_URI=file:///path/to/cyclonedds.xml
```

### Network Interface Selection

```xml
<CycloneDDS xmlns="https://cdds.io/config">
    <Domain id="any">
        <General>
            <NetworkInterfaceAddress>eth0</NetworkInterfaceAddress>
            <!-- Or by IP -->
            <!-- <NetworkInterfaceAddress>192.168.1.100</NetworkInterfaceAddress> -->
        </General>
    </Domain>
</CycloneDDS>
```

## Discovery Configuration

### Multicast Discovery (Default)

```xml
<CycloneDDS xmlns="https://cdds.io/config">
    <Domain id="any">
        <General>
            <AllowMulticast>spdp</AllowMulticast>
        </General>
    </Domain>
</CycloneDDS>
```

### Unicast Discovery (No Multicast)

```xml
<CycloneDDS xmlns="https://cdds.io/config">
    <Domain id="any">
        <General>
            <AllowMulticast>false</AllowMulticast>
        </General>
        <Discovery>
            <Peers>
                <Peer address="192.168.1.100"/>  <!-- HDDS participant -->
                <Peer address="192.168.1.101"/>
            </Peers>
        </Discovery>
    </Domain>
</CycloneDDS>
```

### Domain ID

```xml
<CycloneDDS xmlns="https://cdds.io/config">
    <Domain id="42">
        <!-- Configuration for domain 42 -->
    </Domain>
</CycloneDDS>
```

Or via environment:

```bash
export ROS_DOMAIN_ID=42
```

## Transport Configuration

### Socket Buffers

```xml
<CycloneDDS xmlns="https://cdds.io/config">
    <Domain id="any">
        <Internal>
            <SocketReceiveBufferSize min="4MB"/>
            <SocketSendBufferSize min="4MB"/>
        </Internal>
    </Domain>
</CycloneDDS>
```

### Shared Memory (Iceoryx)

```xml
<CycloneDDS xmlns="https://cdds.io/config">
    <Domain id="any">
        <SharedMemory>
            <Enable>true</Enable>
            <SubId>0</SubId>
            <LogLevel>warning</LogLevel>
        </SharedMemory>
    </Domain>
</CycloneDDS>
```

Note: CycloneDDS shared memory uses Iceoryx and is not directly compatible with HDDS built-in shared memory. For same-host interop, use UDP loopback.

## Debugging

### Enable Tracing

```xml
<CycloneDDS xmlns="https://cdds.io/config">
    <Domain id="any">
        <Tracing>
            <Verbosity>finest</Verbosity>
            <OutputFile>cyclone.log</OutputFile>
            <Category>discovery</Category>
        </Tracing>
    </Domain>
</CycloneDDS>
```

### Check Discovery

```bash
# List discovered participants
ddsperf -D0 ping

# Monitor topic traffic
ddsperf sub MySensorTopic
```

## Type Definition

CycloneDDS and HDDS must use identical type definitions.

### IDL File

```c
// sensor_data.idl
module sensors {
    struct SensorData {
        unsigned long sensor_id;  // @key
        float value;
        unsigned long long timestamp;
    };
};
```

### Generate CycloneDDS Types

```bash
idlc -l c sensor_data.idl
# Generates: sensor_data.c, sensor_data.h
```

### Generate HDDS Types

```bash
hdds-gen -l rust sensor_data.idl
# Generates: sensor_data.rs
```

## Verification

### Test Connectivity

**CycloneDDS Publisher:**

```c
#include <dds/dds.h>
#include "sensor_data.h"

int main() {
    dds_entity_t participant = dds_create_participant(0, NULL, NULL);
    dds_entity_t topic = dds_create_topic(
        participant, &sensors_SensorData_desc, "SensorTopic", NULL, NULL);
    dds_entity_t writer = dds_create_writer(participant, topic, NULL, NULL);

    sensors_SensorData sample = { .sensor_id = 1, .value = 25.5, .timestamp = 0 };
    dds_write(writer, &sample);

    dds_delete(participant);
    return 0;
}
```

**HDDS Subscriber:**

```rust
use hdds::{Participant, QoS, TransportMode};

fn main() -> Result<(), hdds::Error> {
    let participant = Participant::builder("hdds_subscriber")
        .domain_id(0)
        .with_transport(TransportMode::UdpMulticast)
        .build()?;
    let topic = participant.topic::<SensorData>("SensorTopic")?;
    let reader = topic.reader().qos(QoS::reliable()).build()?;

    loop {
        while let Some(sample) = reader.try_take()? {
            println!("Received from CycloneDDS: {:?}", sample);
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}
```

### Common Issues

| Issue | Solution |
|-------|----------|
| No discovery | Check domain ID matches, check network interface |
| Type mismatch | Use same IDL, regenerate types |
| No data | Check QoS compatibility |

## Full Example Configuration

```xml
<?xml version="1.0" encoding="UTF-8"?>
<CycloneDDS xmlns="https://cdds.io/config">
    <Domain id="0">
        <General>
            <NetworkInterfaceAddress>auto</NetworkInterfaceAddress>
            <AllowMulticast>spdp</AllowMulticast>
            <MaxMessageSize>65500B</MaxMessageSize>
        </General>

        <Discovery>
            <ParticipantIndex>auto</ParticipantIndex>
            <MaxAutoParticipantIndex>100</MaxAutoParticipantIndex>
        </Discovery>

        <Internal>
            <SocketReceiveBufferSize min="4MB"/>
            <SocketSendBufferSize min="4MB"/>
        </Internal>

        <Tracing>
            <Verbosity>warning</Verbosity>
        </Tracing>
    </Domain>
</CycloneDDS>
```

## Next Steps

- [QoS Mapping](../../interop/cyclonedds/qos-mapping.md) - QoS configuration
- [Example](../../interop/cyclonedds/example.md) - Complete interop example
- [Wire Compatibility](../../interop/wire-compatibility.md) - Protocol details
