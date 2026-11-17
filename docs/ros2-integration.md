# HDDS ROS 2 Integration Guide

This document describes how to use HDDS as a ROS 2 middleware via `rmw_hdds`, the RMW (ROS Middleware) implementation for HDDS.

---

## 1. Overview

`rmw_hdds` is a ROS 2 middleware layer that replaces the default DDS implementation (typically CycloneDDS or FastDDS) with HDDS. It implements the `rmw` C API that the ROS 2 `rcl` layer calls into.

### Architecture

```
+-------------------------------------------+
|            ROS 2 Application              |
|  rclcpp / rclpy / rclrs                   |
+-------------------------------------------+
|                rcl (C)                    |
+-------------------------------------------+
|              rmw_hdds (C)                 |
|  rmw_init.c | rmw_publisher.c |          |
|  rmw_subscription.c | rmw_wait.c |       |
|  rmw_node.c | rmw_guard_condition.c      |
+-------------------------------------------+
|           hdds_cpp bridge (C++)           |
|  bridge.cpp | codecs.hpp                  |
+-------------------------------------------+
|           hdds-c FFI (C ABI)             |
|  crates/hdds-c/                           |
+-------------------------------------------+
|     rmw-hdds safe wrappers (Rust)        |
|  crates/rmw-hdds/                         |
+-------------------------------------------+
|           hdds core (Rust)               |
|  crates/hdds/                             |
+-------------------------------------------+
```

The integration spans these layers:

| Layer | Language | Location | Purpose |
|-------|----------|----------|---------|
| `rmw_hdds` | C | `rmw_hdds/src/` | Implements the ROS 2 `rmw` C API. This is what ROS 2 loads. |
| `hdds_cpp` bridge | C++ | `rmw_hdds/src/cpp/` | CDR encoding/decoding for ROS 2 message types via `rosidl_typesupport`. |
| `rmw-hdds` crate | Rust | `crates/rmw-hdds/` | Safe Rust wrappers around `hdds-c` FFI for context, waitset, and graph operations. |
| `hdds-c` crate | Rust/C | `crates/hdds-c/` | C FFI bindings generated via cbindgen. Exports `hdds_rmw_context_*` functions. |
| `hdds::rmw` module | Rust | `crates/hdds/src/rmw/` | Internal building blocks: `RmwContext`, `RmwWaitSet`, `GraphCache`. |

### Key Rust Types

| Type | Module | Description |
|------|--------|-------------|
| `RmwContext` | `hdds::rmw::context` | Owns a `Participant`, `RmwWaitSet`, graph guard, and `GraphCache`. Entry point for all rmw operations. |
| `RmwWaitSet` | `hdds::rmw::waitset` | Condition-based wait mechanism mapping to `rmw_wait` semantics. Tracks `ConditionKey` to `ConditionHandle` mappings. |
| `GraphCache` | `hdds::rmw::graph` | Maintains the local ROS 2 graph: nodes, publishers, subscribers, topics. Used for `ros2 node list`, `ros2 topic list`, etc. |
| `Context` | `rmw_hdds::Context` | Safe RAII wrapper around `HddsRmwContext*` FFI pointer. Provides `create_reader()`, `create_writer()`, `wait_for()`. |
| `WaitSet` | `rmw_hdds::WaitSet` | Safe RAII wrapper around `HddsRmwWaitSet*`. Provides `wait()`, `wait_indices()`, `wait_for()`. |

---

## 2. Installation

`rmw_hdds` is not distributed as a binary or apt package: it is built from
the HDDS source tree with colcon.

### Prerequisites

- A ROS 2 distribution: Humble, Iron or Jazzy (a per-distro build and test gate is in [`tools/docker-ros2`](../tools/docker-ros2/README.md))
- A recent stable Rust toolchain with `cargo` on the `PATH`; 1.90 builds this release, 1.85 does not
- CMake 3.16+ (the Humble and Iron images ship 3.22)
- colcon build tools

### Building rmw_hdds

The CMake build of `rmw_hdds` runs `cargo build -p rmw-hdds` itself, so no
separate Cargo step is needed.

```bash
# Clone the HDDS repository
git clone https://git.hdds.io/hdds/hdds.git ~/hdds

# Build the ROS 2 package in a workspace
mkdir -p ~/ros2_ws && cd ~/ros2_ws
source /opt/ros/$ROS_DISTRO/setup.bash
colcon build --packages-select rmw_hdds --base-paths ~/hdds/rmw_hdds \
    --cmake-args -DCMAKE_BUILD_TYPE=Release
```

### Verifying the Build

```bash
source ~/ros2_ws/install/setup.bash
RMW_IMPLEMENTATION=rmw_hdds ros2 run demo_nodes_cpp talker
```

---

## 3. Configuration

### Setting the RMW Implementation

Set the `RMW_IMPLEMENTATION` environment variable before launching any ROS 2 node:

```bash
export RMW_IMPLEMENTATION=rmw_hdds
```

To make it persistent, add it to your shell profile:

```bash
echo 'export RMW_IMPLEMENTATION=rmw_hdds' >> ~/.bashrc
```

### Verifying the Active RMW

```bash
ros2 doctor --report | grep middleware
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `RMW_IMPLEMENTATION` | `rmw_fastrtps_cpp` on a stock install | Must be set to `rmw_hdds` to use HDDS. |
| `HDDS_DOMAIN_ID` | `0` | DDS domain ID, ahead of `ROS_DOMAIN_ID`, and only when rcl passed no explicit domain. A value that is not a decimal domain id in `0`-`232` makes the node fail to start (no silent `0`). |
| `HDDS_LOG_LEVEL` | `info` | Log level (`trace`, `debug`, `info`, `warn`, `error`); sets `RUST_LOG` when `RUST_LOG` is not already set. |
| `HDDS_TRANSPORT` | unset | Unset: UDP multicast, falling back to intra-process if UDP is unavailable. `udp` or `udp_multicast`: UDP multicast, fail if unavailable. `intra` or `intra_process`: in-process only, no sockets. Any other value is refused at startup by name. |
| `HDDS_INTERFACE` | unset | Network interface name or IPv4 address, read by the engine for every participant. |
| `HDDS_DISCOVERY_PEERS` | unset | Static peers, `host:port` of each peer's metatraffic unicast port (`7410 + 250 x domain + 2 x participant index`). `HDDS_INITIAL_PEERS` is an alias. |
| `HDDS_MULTICAST_DISABLE` | unset | `1` or `true`: unicast-only discovery. |
| `HDDS_EXPORTER_DISABLE` | unset | Set to `1` to disable telemetry export. |

`HDDS_MULTICAST_ADDRESS`, `HDDS_SHM_DISABLE`, `HDDS_DISCOVERY_PORT`,
`HDDS_CONFIG_FILE`, `HDDS_QOS_PROFILE_PATH` and the `HDDS_SECURITY_*`
variables are parsed by the adapter but not applied in this release. See
[rmw_hdds Configuration](ros2/rmw-hdds/configuration.md).

---

## 4. Launch Files

### Basic Launch (Python)

```python
import launch
from launch_ros.actions import Node

def generate_launch_description():
    return launch.LaunchDescription([
        # Set RMW for all nodes in this launch
        launch.actions.SetEnvironmentVariable(
            'RMW_IMPLEMENTATION', 'rmw_hdds'
        ),
        launch.actions.SetEnvironmentVariable(
            'HDDS_LOG_LEVEL', 'info'
        ),
        Node(
            package='demo_nodes_cpp',
            executable='talker',
            name='talker',
        ),
        Node(
            package='demo_nodes_cpp',
            executable='listener',
            name='listener',
        ),
    ])
```

### XML Launch

```xml
<launch>
  <set_env name="RMW_IMPLEMENTATION" value="rmw_hdds"/>
  <node pkg="demo_nodes_cpp" exec="talker" name="talker"/>
  <node pkg="demo_nodes_cpp" exec="listener" name="listener"/>
</launch>
```

---

## 5. QoS Mapping

`rmw_hdds` converts the `rmw_qos_profile_t` that rcl hands it into an HDDS QoS
(`rmw_hdds/src/rmw_qos.c`). The ROS 2 profiles (SensorData, Services,
ParameterEvents, ...) are defined by ROS 2 and are passed through field by
field. A policy left at `SYSTEM_DEFAULT` keeps the HDDS default (best-effort,
volatile, keep-last 100).

### Individual QoS Policy Mapping

| ROS 2 QoS Policy | HDDS QoS | Notes |
|-------------------|----------|-------|
| `ReliabilityPolicy::Reliable` | `QoS::reliable()` | HEARTBEAT + ACKNACK retransmission |
| `ReliabilityPolicy::BestEffort` | `QoS::best_effort()` | Fire-and-forget, no retransmission |
| `DurabilityPolicy::Volatile` | `Durability::Volatile` | No persistence |
| `DurabilityPolicy::TransientLocal` | `Durability::TransientLocal` | Cache for late-joining readers |
| Transient / Persistent (where the distro defines them) | `Durability::Persistent` | |
| `HistoryPolicy::KeepLast(N)` | `History::KeepLast(N)` | Bounded sample cache; depth 0 keeps the default history |
| `HistoryPolicy::KeepAll` | `History::KeepAll` | Bounded by resource limits |
| `Deadline(duration)` | `Deadline { period }` | Zero or infinite is ignored |
| `Lifespan(duration)` | `Lifespan { duration }` | Zero or infinite is ignored |
| `Liveliness::Automatic` | `Liveliness::Automatic` | Lease from `liveliness_lease_duration` |
| `Liveliness::ManualByNode` (where defined) | Manual by participant | |
| `Liveliness::ManualByTopic` | `Liveliness::ManualByTopic` | Per-topic liveliness assertion |

### QoS Compatibility Rules

The same DDS QoS compatibility rules apply. Endpoints only match if their QoS policies are compatible:

| Writer QoS | Reader QoS | Compatible? |
|-------------|------------|-------------|
| Reliable | Reliable | Yes |
| Reliable | Best-effort | Yes |
| Best-effort | Reliable | **No** -- reader requires reliability writer cannot provide |
| Best-effort | Best-effort | Yes |
| Transient-local | Transient-local | Yes |
| Transient-local | Volatile | Yes |
| Volatile | Transient-local | **No** -- reader requires durability writer cannot provide |

---

## 6. Performance

A measured RMW comparison is published in [ROS 2 Performance](ros2/performance.md),
with its runner shipped in the repository. No ROS 2 application, UDP or shared-memory
figure is published. See [Benchmarks](guides/performance/benchmarks.md) for each
published core figure with its regime and its reproducer.

---

## 7. Limitations

### What the Gate Exercises

The per-distro gate in [`tools/docker-ros2`](../tools/docker-ros2/README.md)
builds `rmw_hdds`, checks the exported `rmw_*` symbols against the list
`rmw_implementation` resolves, and runs these cases across two containers:
publish/subscribe in both start orders, static peers, `ros2 topic pub` and
`echo`, graph queries (`ros2 node list`, `ros2 topic list`, `ros2 topic
info`), an rclcpp talker to an rclpy listener, an `add_two_ints` service call,
the security refusal and permissive cases, `HDDS_DOMAIN_ID` over
`ROS_DOMAIN_ID`, `RUST_LOG`, and `rmw_take_sequence`.

### Not Supported

| Feature | Behaviour |
|---------|-----------|
| Security (SROS2) | `rmw_hdds` does not enable DDS Security. `ROS_SECURITY_STRATEGY=Enforce` makes `rmw_init` refuse to start; with `Permissive` the node starts unsecured. |
| Message loans | Publishers and subscriptions report `can_loan_messages = false`. |
| Message info sequence numbers | `rmw_feature_supported` returns false for the publication and reception sequence number features. |
| Discovery Server selection | The HDDS core supports a Discovery Server, but `rmw_hdds` does not expose configuration that selects it. If UDP setup fails, the RMW context falls back to intra-process transport and logs a warning. |

### Known Differences from Other RMWs

1. **GUID format:** HDDS uses its own GUID prefix format. Mixed-vendor deployments should be tested with `HDDS_INTEROP_DIAGNOSTICS=1`.

2. **Type discovery:** HDDS includes XTypes v1.3 type objects in SEDP announcements by default. This is compatible with other XTypes-capable implementations but may cause warnings in implementations that do not support XTypes.

---

## 8. Troubleshooting

### No Communication Between Nodes

```bash
# Verify RMW is set
echo $RMW_IMPLEMENTATION
# Should print: rmw_hdds

# Verify domain ID matches
echo $ROS_DOMAIN_ID $HDDS_DOMAIN_ID

# Enable debug logging
export HDDS_LOG_LEVEL=debug
ros2 run demo_nodes_cpp talker

# Check multicast connectivity
ros2 multicast receive
ros2 multicast send
```

### Discovery Is Slow or Incomplete

`ros2 node list` and `ros2 topic list` answer after `--spin-time` seconds
(default 1), which is shorter than an SPDP period. Give discovery time:

```bash
ros2 node list --spin-time 10
```

### Discovery Issues in Docker/Kubernetes

```bash
# Option 1: Use host networking
docker run --network=host my_ros2_image

# Option 2: Configure static peers (metatraffic unicast port of each peer)
export HDDS_MULTICAST_DISABLE=true
export HDDS_DISCOVERY_PEERS=192.168.1.10:7410,192.168.1.11:7410
```
