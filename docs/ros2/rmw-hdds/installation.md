# rmw_hdds Installation

Guide to installing the HDDS ROS2 middleware layer (rmw_hdds).

## Prerequisites

### ROS2 Distribution

rmw_hdds supports:
- ROS2 Jazzy (recommended)
- ROS2 Iron
- ROS2 Humble

### System Requirements

| Component | Requirement |
|-----------|-------------|
| OS | Ubuntu 22.04+, Debian 12+ |
| Architecture | x86_64, aarch64 |
| Memory | 2 GB RAM minimum |
| Disk | 500 MB for installation |

## Installation Methods

### From Package Repository (Recommended)

```bash
# Add HDDS repository
sudo curl -fsSL https://repo.hdds.io/gpg.key | sudo gpg --dearmor -o /usr/share/keyrings/hdds-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/hdds-archive-keyring.gpg] https://repo.hdds.io/apt stable main" | sudo tee /etc/apt/sources.list.d/hdds.list

# Update and install
sudo apt update
sudo apt install ros-$ROS_DISTRO-rmw-hdds
```

### From Source (Colcon Workspace)

```bash
# Create workspace
mkdir -p ~/ros2_ws/src
cd ~/ros2_ws/src

# Clone repositories
git clone https://git.hdds.io/hdds/hdds.git
git clone https://git.hdds.io/hdds/rmw_hdds.git

# Install dependencies
cd ~/ros2_ws
rosdep install --from-paths src --ignore-src -r -y

# Build
source /opt/ros/$ROS_DISTRO/setup.bash
colcon build --cmake-args -DCMAKE_BUILD_TYPE=Release

# Source workspace
source ~/ros2_ws/install/setup.bash
```

### Using Docker

```dockerfile
FROM ros:jazzy

# Install rmw_hdds
RUN apt-get update && apt-get install -y \
    ros-jazzy-rmw-hdds \
    && rm -rf /var/lib/apt/lists/*

# Set as default RMW
ENV RMW_IMPLEMENTATION=rmw_hdds_cpp
```

```bash
# Build and run
docker build -t ros2-hdds .
docker run -it ros2-hdds
```

## Setting HDDS as Default RMW

### Temporary (Current Session)

```bash
export RMW_IMPLEMENTATION=rmw_hdds_cpp
```

### Permanent (Shell Configuration)

```bash
# Add to ~/.bashrc or ~/.zshrc
echo 'export RMW_IMPLEMENTATION=rmw_hdds_cpp' >> ~/.bashrc
source ~/.bashrc
```

### Per-Launch Configuration

```bash
# Single command
RMW_IMPLEMENTATION=rmw_hdds_cpp ros2 run demo_nodes_cpp talker

# Launch file
ros2 launch my_package my_launch.py --ros-args --enclave /my_enclave
```

## Verification

### Check Available RMW Implementations

```bash
ros2 doctor --report | grep rmw
```

Expected output:
```
middleware name    : rmw_hdds_cpp
```

### Test Communication

Terminal 1:
```bash
export RMW_IMPLEMENTATION=rmw_hdds_cpp
ros2 run demo_nodes_cpp talker
```

Terminal 2:
```bash
export RMW_IMPLEMENTATION=rmw_hdds_cpp
ros2 run demo_nodes_cpp listener
```

### Verify HDDS Status

```bash
# Using hdds-admin CLI tool
hdds-admin info
hdds-admin health
```

Example output:
```
Gateway Info
  Name:        hdds-gateway
  Version:     1.0.0
  API Version: v1

HDDS Health Status
  Status:  ok
  Uptime:  5m 32s
  Version: 1.0.0
```

:::note
Install hdds-admin with `cargo install --path tools/hdds-admin` from the HDDS source tree.
:::

## Build Options

### CMake Options

```bash
colcon build --cmake-args \
    -DCMAKE_BUILD_TYPE=Release \
    -DRMW_HDDS_WITH_SECURITY=ON \
    -DRMW_HDDS_WITH_SHM=ON \
    -DRMW_HDDS_WITH_TRACING=OFF
```

| Option | Default | Description |
|--------|---------|-------------|
| `RMW_HDDS_WITH_SECURITY` | ON | DDS Security support |
| `RMW_HDDS_WITH_SHM` | ON | Shared memory transport |
| `RMW_HDDS_WITH_TRACING` | OFF | LTTng/ROS 2 tracing support |
| `RMW_HDDS_DEFAULT_DOMAIN_ID` | 0 | Default domain ID |
| `RMW_HDDS_DEFAULT_LOG_LEVEL` | INFO | Default log level (TRACE, DEBUG, INFO, WARN, ERROR) |
| `HDDS_STATIC_LINK` | OFF | Static linking |

### Legacy Options (Deprecated)

| Old Option | New Option |
|------------|------------|
| `HDDS_ENABLE_SECURITY` | `RMW_HDDS_WITH_SECURITY` |
| `HDDS_ENABLE_SHM` | `RMW_HDDS_WITH_SHM` |
| `HDDS_ENABLE_LOGGING` | `RMW_HDDS_DEFAULT_LOG_LEVEL` |

### Optimized Build

```bash
# Maximum performance
colcon build --cmake-args \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_CXX_FLAGS="-O3 -march=native" \
    -DHDDS_ENABLE_LOGGING=OFF
```

## Dependencies

### Runtime Dependencies

```bash
# Automatically installed with package
libhdds1        # Core HDDS library
libhdds-cpp1    # C++ bindings
```

### Build Dependencies (Source Build)

```bash
sudo apt install \
    build-essential \
    cmake \
    cargo \
    rustc \
    libssl-dev
```

## Troubleshooting Installation

### Package Not Found

```
E: Unable to locate package ros-jazzy-rmw-hdds
```

**Solution**: Add the HDDS repository:
```bash
sudo curl -fsSL https://repo.hdds.io/gpg.key | sudo gpg --dearmor -o /usr/share/keyrings/hdds-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/hdds-archive-keyring.gpg] https://repo.hdds.io/apt stable main" | sudo tee /etc/apt/sources.list.d/hdds.list
sudo apt update
```

### Build Fails: Rust Not Found

```
CMake Error: Could not find Rust compiler
```

**Solution**: Install Rust via rustup:
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
```

### RMW Not Loading

```
[ERROR] [rmw_implementation]: Failed to load rmw implementation
```

**Solution**: Ensure library path is set:
```bash
export LD_LIBRARY_PATH=/opt/ros/$ROS_DISTRO/lib:$LD_LIBRARY_PATH
```

### Shared Memory Permission Error

```
[WARN] [hdds]: Failed to create shared memory segment
```

**Solution**: Check shared memory limits:
```bash
# Increase limits
sudo sysctl -w kernel.shmmax=268435456
sudo sysctl -w kernel.shmall=65536

# Make permanent
echo "kernel.shmmax=268435456" | sudo tee -a /etc/sysctl.conf
echo "kernel.shmall=65536" | sudo tee -a /etc/sysctl.conf
```

## Uninstallation

### Package Installation

```bash
sudo apt remove ros-$ROS_DISTRO-rmw-hdds
```

### Source Installation

```bash
cd ~/ros2_ws
rm -rf build/rmw_hdds install/rmw_hdds
colcon build
```

## Next Steps

- [Configuration](../../ros2/rmw-hdds/configuration.md) - Configure rmw_hdds
- [Migration from FastDDS](../../ros2/migration/from-fastdds.md) - Switch from FastDDS
- [Performance](../../ros2/performance.md) - ROS2 performance tuning
