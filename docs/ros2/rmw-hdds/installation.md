# rmw_hdds Installation

Guide to building the HDDS ROS2 middleware layer (rmw_hdds) from source.

`rmw_hdds` is not distributed as a binary or apt package. It is an
`ament_cmake` package that lives in the HDDS source tree (`rmw_hdds/`) and is
built with colcon. The CMake build runs Cargo itself to build the Rust
libraries it links (`rmw-hdds` and `hdds-c`), so no separate Cargo step is
needed.

## Prerequisites

### ROS2 Distribution

`rmw_hdds` is built and exercised for ROS2 Humble, Iron and Jazzy by the
per-distro gate described in [tools/docker-ros2](../../../tools/docker-ros2/README.md).

### Build Tools

| Component | Requirement |
|-----------|-------------|
| ROS 2 | A Humble, Iron or Jazzy installation (sourced) |
| Rust | A recent stable Rust toolchain, with `cargo` on the `PATH`; 1.90 builds this release, 1.85 does not |
| CMake | 3.16 or newer (the Humble and Iron images ship 3.22) |
| colcon | `colcon-common-extensions` |
| Compiler | A C11 and C++ compiler |

## Building

```bash
# Get the HDDS source tree
git clone https://git.hdds.io/hdds/hdds.git ~/hdds

# Create a workspace; the package is picked up from the source tree
mkdir -p ~/ros2_ws && cd ~/ros2_ws
source /opt/ros/$ROS_DISTRO/setup.bash
colcon build --packages-select rmw_hdds --base-paths ~/hdds/rmw_hdds \
    --cmake-args -DCMAKE_BUILD_TYPE=Release

# Source the workspace
source ~/ros2_ws/install/setup.bash
```

The Cargo output goes to `<hdds tree>/target` by default. Pass
`-DHDDS_CARGO_TARGET_ROOT=<dir>` (or set `CARGO_TARGET_DIR`) to put it
elsewhere, for example when the source tree is read only.

## Setting HDDS as Default RMW

The RMW implementation name is `rmw_hdds`.

### Temporary (Current Session)

```bash
export RMW_IMPLEMENTATION=rmw_hdds
```

### Permanent (Shell Configuration)

```bash
# Add to ~/.bashrc or ~/.zshrc
echo 'export RMW_IMPLEMENTATION=rmw_hdds' >> ~/.bashrc
source ~/.bashrc
```

### Single Command

```bash
RMW_IMPLEMENTATION=rmw_hdds ros2 run demo_nodes_cpp talker
```

## Verification

### Test Communication

Terminal 1:
```bash
export RMW_IMPLEMENTATION=rmw_hdds
ros2 run demo_nodes_cpp talker
```

Terminal 2:
```bash
export RMW_IMPLEMENTATION=rmw_hdds
ros2 run demo_nodes_cpp listener
```

### Check the Graph

```bash
ros2 node list
ros2 topic list
ros2 topic info /chatter
```

## Build Options

```bash
colcon build --packages-select rmw_hdds --base-paths ~/hdds/rmw_hdds \
    --cmake-args \
    -DCMAKE_BUILD_TYPE=Release \
    -DRMW_HDDS_WITH_SECURITY=ON
```

These are the options `rmw_hdds/CMakeLists.txt` defines:

| Option | Default | Description |
|--------|---------|-------------|
| `RMW_HDDS_WITH_SECURITY` | OFF | Builds `hdds-c` with its `security` feature (pure Rust: ring, x509-parser, pem, webpki; no OpenSSL). The adapter does not enable DDS Security for ROS 2 nodes either way (see [Configuration](configuration.md)) |
| `RMW_HDDS_WITH_SHM` | ON | Informational: the shared-memory shim is built in on Linux regardless |
| `RMW_HDDS_WITH_LOGGING` | OFF | Builds the `hdds/logging` Cargo feature (extended logging) |
| `RMW_HDDS_WITH_TRACING` | OFF | Builds the `hdds/telemetry` Cargo feature |
| `RMW_HDDS_DEFAULT_DOMAIN_ID` | 0 | Default domain ID, printed by CMake at configure time |
| `RMW_HDDS_DEFAULT_LOG_LEVEL` | info | Default log level, printed by CMake at configure time |
| `RMW_HDDS_CARGO_LOCKED` | ON | Pass `--locked` to Cargo |
| `RMW_HDDS_CARGO_OFFLINE` | OFF | Pass `--offline` to Cargo |
| `HDDS_CARGO_TARGET_ROOT` | `<hdds tree>/target` | Cargo target directory |

## Troubleshooting Installation

### Build Fails: Rust Not Found

```
cargo: command not found
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

**Solution**: Check that the workspace is sourced and that the name is
`rmw_hdds`:
```bash
source ~/ros2_ws/install/setup.bash
echo $RMW_IMPLEMENTATION
```

## Uninstallation

```bash
cd ~/ros2_ws
rm -rf build/rmw_hdds install/rmw_hdds
unset RMW_IMPLEMENTATION
```

## Next Steps

- [Configuration](../../ros2/rmw-hdds/configuration.md) - Configure rmw_hdds
- [Migration from FastDDS](../../ros2/migration/from-fastdds.md) - Switch from FastDDS
- [Performance](../../ros2/performance.md) - ROS2 performance tuning
