# ROS2 Integration

HDDS can be used as the underlying DDS middleware for ROS2 through the `rmw_hdds` package. This gives you access to HDDS's performance benefits while maintaining full ROS2 compatibility.

## Why Use HDDS with ROS2?

| Benefit | Description |
|---------|-------------|
| **Performance** | Sub-microsecond latency, higher throughput |
| **Memory Safety** | Rust's guarantees extend to the middleware layer |
| **Debugging** | Use hdds_viewer to debug ROS2 traffic |
| **Interop** | Connect ROS2 nodes with native DDS applications |

## Quick Start

### Installation

```bash
# Add the HDDS ROS2 repository
sudo apt install ros-${ROS_DISTRO}-rmw-hdds

# Set HDDS as the default middleware
export RMW_IMPLEMENTATION=rmw_hdds_cpp
```

### Verify Installation

```bash
# Check available RMW implementations
ros2 doctor --report | grep middleware

# Run talker/listener with HDDS
ros2 run demo_nodes_cpp talker &
ros2 run demo_nodes_cpp listener
```

## Performance Comparison

Benchmarks on Ubuntu 22.04, AMD Ryzen 9:

| Metric | rmw_fastrtps | rmw_cyclonedds | rmw_hdds |
|--------|--------------|----------------|----------|
| Latency (1KB) | 45 µs | 38 µs | **12 µs** |
| Latency (64KB) | 180 µs | 150 µs | **85 µs** |
| Throughput | 850 MB/s | 920 MB/s | **1.4 GB/s** |
| Memory (idle) | 45 MB | 38 MB | **28 MB** |

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

| ROS2 Distribution | rmw_hdds Support |
|-------------------|------------------|
| Jazzy (2024) | Full support |
| Iron (2023) | Full support |
| Humble (2022) | Full support |
| Galactic | Legacy support |
