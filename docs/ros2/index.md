# ROS2 Integration

HDDS can be used as the underlying DDS middleware for ROS2 through the `rmw_hdds` package. This gives you access to HDDS's performance benefits while maintaining full ROS2 compatibility.

## Why Use HDDS with ROS2?

| Benefit | Description |
|---------|-------------|
| **Performance** | HDDS core figures are published in [Benchmarks](../guides/performance/benchmarks.md); no ROS 2 application figure is published |
| **Debugging** | Use hdds_viewer to debug ROS2 traffic |
| **Interop** | Connect ROS2 nodes with native DDS applications |

## Quick Start

### Installation

`rmw_hdds` is not distributed as a binary package. It is an `ament_cmake`
package in the HDDS source tree (`rmw_hdds/`), built with colcon; the build
runs Cargo itself. See [rmw_hdds Installation](../ros2/rmw-hdds/installation.md)
for the prerequisites.

```bash
git clone https://git.hdds.io/hdds/hdds.git ~/hdds
mkdir -p ~/ros2_ws && cd ~/ros2_ws
source /opt/ros/$ROS_DISTRO/setup.bash
colcon build --packages-select rmw_hdds --base-paths ~/hdds/rmw_hdds \
    --cmake-args -DCMAKE_BUILD_TYPE=Release
source install/setup.bash

# Set HDDS as the middleware
export RMW_IMPLEMENTATION=rmw_hdds
```

### Verify Installation

```bash
# Check the active RMW implementation
ros2 doctor --report | grep middleware

# Run talker/listener with HDDS
ros2 run demo_nodes_cpp talker &
ros2 run demo_nodes_cpp listener
```

## Performance Measurement

A measured RMW comparison is published in [ROS 2 Performance](performance.md): ten
rounds of Apex.AI `performance_test`, with the runner shipped as
`rmw_hdds/scripts/bench_rmw.sh`. The HDDS core figures, which do not include the RMW
layer, are in [Benchmarks](../guides/performance/benchmarks.md), each with its regime.

## Migration Guides

Already using a different middleware? Follow our migration guides:

- [Migrate from FastDDS](../ros2/migration/from-fastdds.md)
- [Migrate from CycloneDDS](../ros2/migration/from-cyclonedds.md)

## Detailed Documentation

- [rmw_hdds Installation](../ros2/rmw-hdds/installation.md)
- [Configuration Options](../ros2/rmw-hdds/configuration.md)
- [Performance Tuning](../ros2/performance.md)
- [Debugging ROS2 Traffic](../ros2/debugging.md) - ML-powered traffic analysis

## Compatibility

`rmw_hdds` is built and exercised for ROS 2 Humble, Iron and Jazzy by a
per-distro gate in a pinned container image (see
[tools/docker-ros2](../../tools/docker-ros2/README.md)). The gate builds the
package against the tree, checks the exported `rmw_*` symbols against the
list `rmw_implementation` resolves for that distro, and runs two-container
publish/subscribe, CLI, graph, service, domain-id and security-refusal cases.
