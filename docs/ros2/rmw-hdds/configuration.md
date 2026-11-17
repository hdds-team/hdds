# rmw_hdds Configuration

Configure HDDS behavior in ROS2 applications.

`rmw_hdds` is configured through environment variables, through the standard
ROS 2 QoS profiles of your publishers and subscriptions, and through the build
options in [Installation](installation.md). It reads no XML or YAML
configuration file and defines no ROS 2 parameters of its own.

The authoritative table of what the adapter applies is at the top of
`crates/rmw-hdds/src/env_config.rs`.

## Environment Variables

### Core Settings

```bash
# RMW implementation (required)
export RMW_IMPLEMENTATION=rmw_hdds

# Domain ID - HDDS_DOMAIN_ID takes priority over ROS_DOMAIN_ID, and only
# when rcl passed no explicit domain. A value that is not a decimal id in
# 0..=232 fails the node's init instead of using 0.
export ROS_DOMAIN_ID=42
# or
export HDDS_DOMAIN_ID=42

# Participant ID within the domain (0-119), read by the HDDS engine
export HDDS_PARTICIPANT_ID=1

# Log level: sets RUST_LOG when RUST_LOG is not already set
# (trace, debug, info, warn, error; default info)
export HDDS_LOG_LEVEL=info
```

### Transport and Discovery

```bash
# Network interface (read by the HDDS engine for every participant):
# an interface name or an IPv4 address
export HDDS_INTERFACE=eth0

# Static discovery peers (unicast): the peers' metatraffic unicast ports,
# 7410 + 250 x domain + 2 x participant index
export HDDS_DISCOVERY_PEERS=192.168.1.100:7410,192.168.1.101:7410
# or the alias
export HDDS_INITIAL_PEERS=192.168.1.100:7410

# Turn multicast discovery off (peers only)
export HDDS_MULTICAST_DISABLE=true

# Transport: udp (default) or intra_process
export HDDS_TRANSPORT=udp
```

`HDDS_TRANSPORT` accepts `udp` or `udp_multicast`, and `intra` or
`intra_process`; any other value is refused at startup by name. Other engine
settings are listed in the [HDDS core environment variables](../../reference/environment-vars.md).

`HDDS_MULTICAST_ADDRESS`, `HDDS_SHM_DISABLE`, `HDDS_DISCOVERY_PORT`,
`HDDS_CONFIG_FILE` and `HDDS_QOS_PROFILE_PATH` are parsed by the adapter but
not applied in this release: setting them changes nothing.

### Security Settings

`rmw_hdds` does not enable DDS Security in this release.
`ROS_SECURITY_STRATEGY=Enforce` makes the adapter refuse to start, so a node
never runs unprotected while you believe it is protected. The
`HDDS_SECURITY_*` variables and `ROS_SECURITY_ENABLE` / `ROS_SECURITY_ENCLAVE`
are parsed but not applied. DDS Security is available from the Rust API
(`with_security`); see the [security guide](../../security-guide.md).

## QoS

Set QoS the standard ROS 2 way, on the publisher or subscription:

```python
from rclpy.qos import QoSProfile, ReliabilityPolicy, DurabilityPolicy, HistoryPolicy

qos = QoSProfile(
    reliability=ReliabilityPolicy.RELIABLE,
    durability=DurabilityPolicy.TRANSIENT_LOCAL,
    history=HistoryPolicy.KEEP_LAST,
    depth=10,
)
self.create_publisher(String, 'topic', qos)
```

The mapping from ROS 2 QoS profiles to HDDS QoS is in the
[ROS 2 integration guide](../../ros2-integration.md#5-qos-mapping).

## Common Configurations

### Same Host

```bash
export HDDS_INTERFACE=lo
```

### Multi-Robot, Static Peers

```bash
export HDDS_MULTICAST_DISABLE=true
export HDDS_DISCOVERY_PEERS=192.168.1.1:7410
ros2 run my_package robot_node
```

### Containers Without Multicast

```bash
export HDDS_MULTICAST_DISABLE=true
export HDDS_DISCOVERY_PEERS=172.18.0.2:7410,172.18.0.3:7410
```

## Debugging Configuration

### Enable Debug Logging

```bash
export HDDS_LOG_LEVEL=debug
# or a per-module filter
export RUST_LOG=hdds=debug
ros2 run my_package my_node
```

### Network Diagnostics

```bash
# Check endpoints and the graph
ros2 topic info /my_topic -v
ros2 node info /my_node
ros2 node list --spin-time 10
```

## Next Steps

- [Installation](../../ros2/rmw-hdds/installation.md) - Build rmw_hdds
- [Performance](../../ros2/performance.md) - Performance optimization
- [Migration from FastDDS](../../ros2/migration/from-fastdds.md) - Migration guide
