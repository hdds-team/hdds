# HDDS ROS 2 Integration Guide

> Version 1.0.5 | Last updated: 2026-02-13

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

The integration spans three layers:

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
| `WaitSet` | `rmw_hdds::WaitSet` | Safe RAII wrapper around `HddsRmwWaitSet*`. Provides `attach_reader()`, `wait()`. |

---

## 2. Installation

### Prerequisites

- ROS 2 Jazzy or later (Ubuntu 24.04+)
- Rust toolchain (1.75+)
- CMake 3.22+
- colcon build tools

### Building rmw_hdds

```bash
# Clone the HDDS repository
git clone https://github.com/naskel/hdds.git
cd hdds

# Build the Rust libraries first
cargo build --release -p hdds -p hdds-c -p rmw-hdds --features "hdds-c/rmw"

# Build the ROS 2 package
cd rmw_hdds
source /opt/ros/jazzy/setup.bash
colcon build --packages-select rmw_hdds
```

### Verifying the Build

```bash
source rmw_hdds/install/setup.bash
ros2 doctor --report | grep rmw
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
# Expected output: middleware name    : rmw_hdds
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `RMW_IMPLEMENTATION` | `rmw_fastrtps_cpp` | Must be set to `rmw_hdds` to use HDDS. |
| `HDDS_DOMAIN_ID` | `0` | DDS domain ID (also settable via `ROS_DOMAIN_ID`). |
| `HDDS_LOG_LEVEL` | `warn` | Log level: `off`, `error`, `warn`, `info`, `debug`, `trace`. |
| `HDDS_TRANSPORT` | `udp_multicast` | Transport mode: `udp_multicast`, `intra_process`. |
| `HDDS_SHM_POLICY` | `prefer` | Shared memory: `prefer`, `require`, `disable`. |
| `HDDS_EXPORTER_DISABLE` | unset | Set to `1` to disable telemetry export. |

### XML QoS Configuration

HDDS supports loading QoS profiles from XML files compatible with the OMG DDS QoS XML format:

```bash
export HDDS_QOS_FILE=/path/to/qos_profile.xml
```

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

### Launch with Custom QoS (Python)

```python
import launch
from launch_ros.actions import Node

def generate_launch_description():
    return launch.LaunchDescription([
        launch.actions.SetEnvironmentVariable(
            'RMW_IMPLEMENTATION', 'rmw_hdds'
        ),
        launch.actions.SetEnvironmentVariable(
            'HDDS_LOG_LEVEL', 'info'
        ),
        Node(
            package='my_robot',
            executable='sensor_publisher',
            name='sensor_pub',
            parameters=[{
                'qos_overrides': {
                    '/sensors/lidar': {
                        'reliability': 'reliable',
                        'history_depth': 10,
                    }
                }
            }],
        ),
    ])
```

### Launch with Shared Memory (Python)

```python
import launch
from launch_ros.actions import Node

def generate_launch_description():
    return launch.LaunchDescription([
        launch.actions.SetEnvironmentVariable(
            'RMW_IMPLEMENTATION', 'rmw_hdds'
        ),
        launch.actions.SetEnvironmentVariable(
            'HDDS_SHM_POLICY', 'prefer'
        ),
        Node(
            package='image_pipeline',
            executable='image_publisher',
            name='camera',
        ),
        Node(
            package='image_pipeline',
            executable='image_viewer',
            name='viewer',
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

### ROS 2 QoS Profiles to HDDS QoS

| ROS 2 QoS Profile | HDDS Mapping | Notes |
|-------------------|--------------|-------|
| `SystemDefault` | `QoS::default()` | Best-effort, volatile, keep-last(1) |
| `SensorData` | Best-effort, volatile, keep-last(5) | Low-latency sensor streams |
| `ParameterEvents` | Reliable, volatile, keep-last(1000) | Parameter change notifications |
| `Services` | Reliable, volatile, keep-last(10) | Service request/response |
| `Parameters` | Reliable, volatile, keep-last(1000) | Parameter storage |
| `ActionStatus` | Reliable, transient-local, keep-last(1) | Action server status |

### Individual QoS Policy Mapping

| ROS 2 QoS Policy | HDDS QoS Type | Values |
|-------------------|---------------|--------|
| `ReliabilityPolicy::Reliable` | `QoS::reliable()` | HEARTBEAT + ACKNACK retransmission |
| `ReliabilityPolicy::BestEffort` | `QoS::best_effort()` | Fire-and-forget, no retransmission |
| `DurabilityPolicy::Volatile` | `Durability::Volatile` | No persistence |
| `DurabilityPolicy::TransientLocal` | `Durability::TransientLocal` | Cache for late-joining readers |
| `HistoryPolicy::KeepLast(N)` | `History::KeepLast(N)` | Bounded sample cache |
| `HistoryPolicy::KeepAll` | `History::KeepAll` | Unbounded (use with caution) |
| `Deadline(duration)` | `Deadline { period }` | Maximum inter-sample delay |
| `Lifespan(duration)` | `Lifespan { duration }` | Sample expiration time |
| `Liveliness::Automatic` | `Liveliness::Automatic` | Participant-level liveliness |
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

### Latency Comparison

Measured on Ubuntu 24.04, Intel Core i9-13900K, 64GB RAM, localhost loopback.

| Metric | HDDS | CycloneDDS | FastDDS |
|--------|------|------------|---------|
| Intra-process (1 byte) | ~257 ns | ~1.2 us | ~2.5 us |
| UDP loopback (256 bytes) | ~12 us | ~18 us | ~25 us |
| UDP loopback (64 KB) | ~45 us | ~62 us | ~85 us |
| Shared memory (1 MB) | ~8 us | ~15 us | N/A |

### Throughput Comparison

| Message Size | HDDS | CycloneDDS | FastDDS |
|-------------|------|------------|---------|
| 256 bytes | 1.8M msg/s | 1.2M msg/s | 0.8M msg/s |
| 4 KB | 850K msg/s | 580K msg/s | 420K msg/s |
| 64 KB | 95K msg/s | 72K msg/s | 55K msg/s |
| 1 MB (SHM) | 12K msg/s | 8K msg/s | N/A |

### Memory Usage

| Scenario | HDDS | CycloneDDS | FastDDS |
|----------|------|------------|---------|
| Idle participant | ~2.1 MB | ~4.5 MB | ~8.2 MB |
| 10 topics, 1 writer + 1 reader each | ~3.8 MB | ~7.2 MB | ~14.5 MB |
| 100 topics | ~8.5 MB | ~18 MB | ~35 MB |

### Key Performance Features

- **Zero-copy shared memory** -- Uses Linux futex-based ring buffers for inter-process delivery without serialization copies.
- **Lock-free routing** -- The `RxRing` (crossbeam `ArrayQueue`) and relaxed-ordering atomic metrics avoid contention on the hot path.
- **Spin + condvar wake** -- The router thread uses a 200-iteration spin loop followed by condvar wait, achieving sub-10us wake latency.
- **Deduplication cache** -- Prevents double delivery when the same packet arrives via multicast and unicast simultaneously.
- **CDR2 encoding** -- Native Rust CDR2 encoder avoids the overhead of C++ serialization libraries.

---

## 7. Limitations

### Fully Supported

| Feature | Status | Notes |
|---------|--------|-------|
| Publishers / Subscribers | Supported | Full `rmw_create_publisher` / `rmw_create_subscription` |
| Services (request/reply) | Supported | Via DDS-RPC topic mapping |
| Actions | Supported | Via standard action topic conventions |
| WaitSet | Supported | `rmw_wait` with subscriptions and guard conditions |
| Graph queries | Supported | `ros2 node list`, `ros2 topic list`, `ros2 topic info` |
| QoS profiles | Supported | All standard ROS 2 QoS profiles |
| Namespace remapping | Supported | Standard ROS 2 remapping rules |
| Node registration | Supported | `register_node` / `unregister_node` in graph cache |
| Parameter events | Supported | Via `ParameterEvents` QoS profile |
| Lifecycle nodes | Supported | Standard lifecycle state machine |

### Partially Supported

| Feature | Status | Notes |
|---------|--------|-------|
| Security (SROS2) | In progress | DDS Security v1.1 is implemented in HDDS core, but SROS2 keystore integration is pending. |
| Content-filtered topics | Core only | Implemented in HDDS core (`ContentFilteredTopic`), not yet exposed via rmw API. |
| DDS-RPC | Core only | Request/reply pattern implemented, rmw service mapping in progress. |

### Not Yet Supported

| Feature | Status | Notes |
|---------|--------|-------|
| `rmw_get_serialization_format` | Planned | Custom serialization format negotiation. |
| `rmw_take_loaned_message` | Planned | Zero-copy message loans for shared memory. |
| Network events (`rmw_event`) | Planned | QoS event callbacks (deadline missed, liveliness changed). |
| Multi-domain bridging | N/A | Use `hdds-gateway` crate for cross-domain communication. |

### Known Differences from Other RMWs

1. **Multicast fallback:** If UDP multicast is unavailable (e.g., in Docker without `--network=host`), HDDS falls back to intra-process transport and logs a warning. Configure static peers or use Discovery Server mode for containerized deployments.

2. **GUID format:** HDDS uses its own GUID prefix format. Interoperability with other DDS implementations is handled by the dialect detection system, but mixed-vendor deployments should be tested with `HDDS_INTEROP_DIAGNOSTICS=1`.

3. **Type discovery:** HDDS includes XTypes v1.3 type objects in SEDP announcements by default. This is compatible with other XTypes-capable implementations but may cause warnings in implementations that do not support XTypes.

---

## 8. Troubleshooting

### No Communication Between Nodes

```bash
# Verify RMW is set
echo $RMW_IMPLEMENTATION
# Should print: rmw_hdds

# Verify domain ID matches
echo $ROS_DOMAIN_ID

# Enable debug logging
export HDDS_LOG_LEVEL=debug
ros2 run demo_nodes_cpp talker

# Check multicast connectivity
ros2 multicast receive
ros2 multicast send
```

### High Latency

```bash
# Enable shared memory for same-host communication
export HDDS_SHM_POLICY=prefer

# Check if multicast is causing issues
export HDDS_TRANSPORT=intra_process  # For same-process testing

# Enable interop diagnostics
export HDDS_INTEROP_DIAGNOSTICS=1
```

### Discovery Issues in Docker/Kubernetes

```bash
# Option 1: Use host networking
docker run --network=host my_ros2_image

# Option 2: Configure Discovery Server
export HDDS_DISCOVERY_SERVER=hdds-ds://discovery-server:11811

# Option 3: Configure static peers
export HDDS_STATIC_PEERS=192.168.1.10:7400,192.168.1.11:7400

# Option 4: Use Kubernetes discovery
export HDDS_K8S_DISCOVERY=1
export HDDS_K8S_SERVICE=my-robot-service
```
