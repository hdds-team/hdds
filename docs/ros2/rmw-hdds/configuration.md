# rmw_hdds Configuration

Configure HDDS behavior in ROS2 applications.

## Configuration Methods

HDDS can be configured via:
1. **Environment variables** - Quick runtime changes
2. **XML configuration file** - Detailed settings
3. **ROS2 parameters** - Node-specific tuning

## Environment Variables

### Core Settings

```bash
# RMW implementation (required)
export RMW_IMPLEMENTATION=rmw_hdds_cpp

# Domain ID - HDDS_DOMAIN_ID takes priority over ROS_DOMAIN_ID
export ROS_DOMAIN_ID=42
# or
export HDDS_DOMAIN_ID=42

# Participant ID (optional, auto-generated if not set)
export HDDS_PARTICIPANT_ID=1

# HDDS log level (trace, debug, info, warn, error)
export HDDS_LOG_LEVEL=info

# QoS profile file path (XML or YAML)
export HDDS_QOS_PROFILE_PATH=/path/to/qos_profiles.yaml
```

### Transport Settings

```bash
# Network interface for multicast
export HDDS_INTERFACE=eth0

# Custom multicast address
export HDDS_MULTICAST_ADDRESS=239.255.0.100

# Static discovery peers (unicast)
export HDDS_DISCOVERY_PEERS=192.168.1.100:7400,192.168.1.101:7400
# or alias
export HDDS_INITIAL_PEERS=192.168.1.100:7400

# Disable multicast discovery (use static peers only)
export HDDS_MULTICAST_DISABLE=true

# Disable shared memory transport
export HDDS_SHM_DISABLE=true

# Custom discovery port
export HDDS_DISCOVERY_PORT=7400

# HDDS configuration file path
export HDDS_CONFIG_FILE=/etc/hdds/config.xml
```

:::note
Additional transport settings (multicast address, ports) are configured via the [HDDS core environment variables](../../reference/environment-vars.md).
:::

### Security Settings

```bash
# Enable DDS Security (HDDS style)
export HDDS_SECURITY_ENABLE=true
export HDDS_SECURITY_IDENTITY_CERT=/etc/hdds/certs/participant.pem
export HDDS_SECURITY_IDENTITY_KEY=/etc/hdds/certs/participant_key.pem
export HDDS_SECURITY_CA_CERT=/etc/hdds/certs/ca.pem
export HDDS_SECURITY_PERMISSIONS=/etc/hdds/security/permissions.xml
export HDDS_SECURITY_GOVERNANCE=/etc/hdds/security/governance.xml

# Or ROS 2 style (compatible)
export ROS_SECURITY_ENABLE=true
export ROS_SECURITY_STRATEGY=Enforce
export ROS_SECURITY_KEYSTORE=/path/to/keystore
export ROS_SECURITY_ENCLAVE=/my_enclave
```

## QoS Profile Configuration

### File Location

```bash
# Specify QoS profile path
export HDDS_QOS_PROFILE_PATH=/path/to/qos_profiles.yaml
```

### Basic Configuration

```xml
<?xml version="1.0" encoding="UTF-8"?>
<hdds>
    <domain id="0">
        <participant name="ros2_node">
            <!-- Discovery settings -->
            <discovery>
                <initial_announcements count="5" period_ms="100"/>
                <lease_duration_sec>10</lease_duration_sec>
            </discovery>

            <!-- Transport configuration -->
            <transport>
                <udp enabled="true">
                    <interface>eth0</interface>
                    <port_base>7400</port_base>
                </udp>
                <shared_memory enabled="true">
                    <segment_size_mb>64</segment_size_mb>
                </shared_memory>
            </transport>
        </participant>
    </domain>
</hdds>
```

### QoS Profiles

```xml
<?xml version="1.0" encoding="UTF-8"?>
<hdds>
    <qos_profiles>
        <!-- High-throughput sensor profile -->
        <profile name="sensor_data">
            <reliability kind="BEST_EFFORT"/>
            <durability kind="VOLATILE"/>
            <history kind="KEEP_LAST" depth="1"/>
        </profile>

        <!-- Reliable command profile -->
        <profile name="command">
            <reliability kind="RELIABLE" max_blocking_ms="100"/>
            <durability kind="TRANSIENT_LOCAL"/>
            <history kind="KEEP_LAST" depth="10"/>
        </profile>

        <!-- Service profile -->
        <profile name="service">
            <reliability kind="RELIABLE" max_blocking_ms="5000"/>
            <durability kind="VOLATILE"/>
            <history kind="KEEP_ALL"/>
        </profile>
    </qos_profiles>
</hdds>
```

### Transport Tuning

```xml
<hdds>
    <transport>
        <!-- UDP configuration -->
        <udp enabled="true">
            <interface>eth0</interface>
            <send_buffer_size>4194304</send_buffer_size>
            <receive_buffer_size>4194304</receive_buffer_size>
            <multicast>
                <enabled>true</enabled>
                <address>239.255.0.1</address>
                <ttl>1</ttl>
            </multicast>
        </udp>

        <!-- Shared memory for same-host -->
        <shared_memory enabled="true">
            <segment_size_mb>256</segment_size_mb>
            <max_message_size_kb>64</max_message_size_kb>
        </shared_memory>
    </transport>
</hdds>
```

### Discovery Configuration

```xml
<hdds>
    <discovery>
        <!-- Fast discovery -->
        <initial_announcements count="10" period_ms="50"/>

        <!-- Lease duration -->
        <lease_duration_sec>30</lease_duration_sec>

        <!-- Static peers (no multicast) -->
        <static_peers>
            <peer>192.168.1.100:7400</peer>
            <peer>192.168.1.101:7400</peer>
        </static_peers>

        <!-- Ignore specific participants -->
        <ignore_participants>
            <pattern>debug_*</pattern>
        </ignore_participants>
    </discovery>
</hdds>
```

## ROS2 Parameters

### Per-Node Configuration

```python
# Python launch file
from launch import LaunchDescription
from launch_ros.actions import Node

def generate_launch_description():
    return LaunchDescription([
        Node(
            package='my_package',
            executable='my_node',
            parameters=[{
                'hdds.reliability': 'reliable',
                'hdds.history_depth': 100,
                'hdds.deadline_ms': 50,
            }]
        )
    ])
```

### YAML Parameter File

```yaml
# config/hdds_params.yaml
/**:
  ros__parameters:
    hdds:
      reliability: reliable
      durability: transient_local
      history_depth: 100
      deadline_ms: 100
      liveliness_lease_ms: 1000
```

```bash
ros2 run my_package my_node --ros-args --params-file config/hdds_params.yaml
```

## Topic-Specific QoS

### QoS Override File

```yaml
# qos_overrides.yaml
/sensor/imu:
  reliability: best_effort
  history:
    kind: keep_last
    depth: 1
  durability: volatile

/robot/cmd_vel:
  reliability: reliable
  history:
    kind: keep_last
    depth: 10
  durability: transient_local
  deadline:
    sec: 0
    nsec: 100000000  # 100ms

/diagnostics:
  reliability: reliable
  history:
    kind: keep_all
  lifespan:
    sec: 10
    nsec: 0
```

### Apply QoS Overrides

```bash
export ROS_QOS_OVERRIDE_FILE=/path/to/qos_overrides.yaml
ros2 run my_package my_node
```

## Common Configurations

### Low-Latency Configuration

```xml
<hdds>
    <transport>
        <shared_memory enabled="true" prefer="true"/>
        <udp>
            <send_buffer_size>1048576</send_buffer_size>
            <receive_buffer_size>1048576</receive_buffer_size>
        </udp>
    </transport>

    <qos_profiles>
        <profile name="default">
            <reliability kind="BEST_EFFORT"/>
            <history kind="KEEP_LAST" depth="1"/>
        </profile>
    </qos_profiles>
</hdds>
```

### High-Throughput Configuration

```xml
<hdds>
    <transport>
        <udp>
            <send_buffer_size>16777216</send_buffer_size>
            <receive_buffer_size>16777216</receive_buffer_size>
        </udp>
        <shared_memory>
            <segment_size_mb>512</segment_size_mb>
        </shared_memory>
    </transport>

    <qos_profiles>
        <profile name="default">
            <history kind="KEEP_LAST" depth="1000"/>
        </profile>
    </qos_profiles>
</hdds>
```

### Multi-Robot Configuration

```xml
<hdds>
    <domain id="0">
        <participant name="robot_${ROBOT_ID}">
            <discovery>
                <static_peers>
                    <peer>${BASE_STATION_IP}:7400</peer>
                </static_peers>
            </discovery>
        </participant>
    </domain>
</hdds>
```

```bash
export ROBOT_ID=robot_01
export BASE_STATION_IP=192.168.1.1
ros2 run my_package robot_node
```

### Isolated Network Configuration

```xml
<hdds>
    <transport>
        <udp>
            <interface>192.168.100.0/24</interface>
            <multicast>
                <enabled>false</enabled>
            </multicast>
        </udp>
        <shared_memory enabled="false"/>
    </transport>

    <discovery>
        <static_peers>
            <peer>192.168.100.10:7400</peer>
            <peer>192.168.100.11:7400</peer>
        </static_peers>
    </discovery>
</hdds>
```

## Debugging Configuration

### Enable Debug Logging

```bash
export HDDS_LOG_LEVEL=debug
export RUST_LOG=hdds=debug
ros2 run my_package my_node
```

### Trace Discovery

```bash
export HDDS_LOG_LEVEL=trace
export HDDS_LOG_DISCOVERY=1
ros2 run my_package my_node 2>&1 | grep -i discovery
```

### Network Diagnostics

```bash
# Check active endpoints
ros2 topic info /my_topic -v

# Check node connections
ros2 node info /my_node

# HDDS-specific diagnostics (requires hdds-admin tool)
hdds-admin status        # Full system status
hdds-admin mesh          # List discovered participants
hdds-admin topics        # List active topics
hdds-admin watch         # Continuous monitoring
```

:::tip
Install HDDS CLI tools with `cargo install --path tools/hdds-admin` from the HDDS source tree.
:::

## Validation

### Check Configuration

```bash
# Validate XML/YAML syntax
xmllint --noout /path/to/qos_profiles.xml

# Test configuration loading
HDDS_QOS_PROFILE_PATH=/path/to/qos_profiles.yaml \
HDDS_LOG_LEVEL=debug \
ros2 run demo_nodes_cpp talker
```

### System Status

```bash
# Print health, mesh, and metrics
hdds-admin status

# Or for real-time metrics stream
hddsctl 127.0.0.1:4242
```

## Next Steps

- [Installation](../../ros2/rmw-hdds/installation.md) - Install rmw_hdds
- [Performance](../../ros2/performance.md) - Performance optimization
- [Migration from FastDDS](../../ros2/migration/from-fastdds.md) - Migration guide
