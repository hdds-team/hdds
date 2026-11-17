---
sidebar_position: 1
title: Linux Installation
description: Build and install HDDS from source on Linux
---

# Installing HDDS on Linux

This guide covers installing HDDS from source on Linux.

## Prerequisites

- **A current stable Rust toolchain. The project declares no `rust-version`; the dependencies of the default workspace require Rust 1.89 or newer, and 1.90 is the version this release is built and tested with (1.85 does not work)** (install via [rustup](https://rustup.rs/)) -- **required even for C++ projects**: the HDDS core is written in Rust
- **Git**
- **A C compiler** (`gcc` or `clang`): some dependencies build C code, and it is needed to compile C programs against HDDS
- **CMake 3.16+** and **g++** or **clang++** (required for the C++ SDK only)

HDDS is not distributed as a distribution package (`.deb`, `.rpm`): build it from source as shown below. On Debian or Ubuntu, `sudo apt install build-essential git cmake` provides the tools above except Rust.

```bash
# Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Verify the toolchain
rustc --version
```

## Clone and Build

```bash
# Clone the repository
git clone https://git.hdds.io/hdds/hdds.git
cd hdds

# Build in release mode
cargo build --release

# Run tests to verify
cargo test
```

`cargo build --release` builds the default workspace members: the `hdds` crate,
the C and micro libraries, the services and the command-line tools. The
libraries land in `target/release/`.

:::warning Using the C, Python or TypeScript SDK
Run `cargo build --release -p hdds-c` after any workspace-wide build. A
workspace build also builds the ROS 2 middleware crate, which makes cargo
resolve `hdds-c` with its `rmw` feature; the resulting `libhdds_c` then carries
undefined `rosidl_runtime_c__*` symbols and loading it fails with
`undefined symbol: rosidl_runtime_c__U16String__assignn`. Building `-p hdds-c`
relinks it without them.
:::

## Using HDDS in Your Project

:::info Use a path dependency
The versions published on crates.io may lag this repository. To get the code
documented here, use a path dependency on your clone.
:::

Add HDDS as a path dependency in your project's `Cargo.toml`:

```toml
[dependencies]
hdds = { path = "/path/to/hdds/crates/hdds" }
```

With optional features:

```toml
[dependencies]
hdds = { path = "/path/to/hdds/crates/hdds", features = ["xtypes", "security"] }
```

### Available Features

| Feature | Description |
|---------|-------------|
| `xtypes` | XTypes type system (default) |
| `qos-loaders` | QoS loading from XML and YAML (default) |
| `security` | DDS Security 1.1 support |
| `tcp-tls` | TLS encryption for TCP transport |
| `quic` | QUIC transport |
| `cloud-discovery` | AWS/Azure/Consul discovery |
| `dns-sd` | DNS-SD peer discovery |
| `k8s` | Kubernetes discovery |
| `rpc` | DDS-RPC Request/Reply |
| `telemetry` | Metrics collection |
| `lowbw-lz4` | LZ4 compression for the low-bandwidth transport |

The full list is in the `[features]` table of `crates/hdds/Cargo.toml`.

## Code Generator (hddsgen)

```bash
# Clone hddsgen
git clone https://git.hdds.io/hdds/hdds_gen.git
cd hdds_gen

# Build and install (into ~/.cargo/bin)
cargo install --path .

# Put ~/.cargo/bin on PATH if it is not already there
export PATH="$HOME/.cargo/bin:$PATH"

# Verify: must print hddsgen 2.0.0 or later
hddsgen --version
```

HDDS 1.5 needs hddsgen 2.0 or later. To install next to an older `hddsgen`
instead of replacing it, see [hdds_gen Installation](../../tools/hdds-gen/installation.md).

## Verify Installation

```bash
# Run the test suite
cargo test --release
```

The Hello World sample needs the generated sample types (they are not checked
in), then two terminals:

```bash
# From the root of the hdds clone
sdk/samples/scripts/generate.sh
cd sdk/samples/01_basics/rust
cargo run --bin hello_world           # Terminal 1: subscriber, waits for data
cargo run --bin hello_world -- pub    # Terminal 2: publisher
```

For the full walkthrough, see the [Hello World tutorial](../hello-world-rust.md).

## Firewall Configuration

DDS uses UDP multicast. Configure your firewall:

Domain `D` uses the UDP ports of the RTPS port mapping (RTPS 2.5 Sec. 9.6.1.1):

| Port | Use |
|------|-----|
| `7400 + 250 x D` | discovery multicast (SPDP) |
| `7401 + 250 x D` | user data multicast |
| `7410 + 250 x D + 2 x i` | discovery unicast, participant index `i` (0 to 119) |
| `7411 + 250 x D + 2 x i` | user data unicast, participant index `i` (0 to 119) |

So domain `D` needs the 250 ports from `7400 + 250 x D` to `7649 + 250 x D`:
7400-7649 for domain 0, 17900-18149 for domain 42. Open the range of every
domain you use, for example domain 42:

```bash
# UFW (Ubuntu), domain 42
sudo ufw allow 17900:18149/udp

# firewalld (Fedora/RHEL), domain 42
sudo firewall-cmd --permanent --add-port=17900-18149/udp
sudo firewall-cmd --reload

# iptables, domain 42
sudo iptables -A INPUT -p udp --dport 17900:18149 -j ACCEPT
```

## Multicast Configuration

Ensure multicast routing is enabled:

```bash
# Check multicast support
ip maddr show

# Add multicast route if needed
sudo ip route add 239.255.0.0/16 dev eth0
```

## Troubleshooting

### "Multicast not working"

```bash
# Check if multicast is enabled on your interface
ip link show eth0 | grep MULTICAST

# Enable if needed
sudo ip link set eth0 multicast on
```

### "Permission denied on /dev/shm"

```bash
# For shared memory transport
sudo chmod 1777 /dev/shm
```

## Next Steps

- [Hello World C++](../hello-world-cpp.md) - C++ pub/sub tutorial
- [Hello World Rust](../hello-world-rust.md) - Rust pub/sub tutorial
- [hddsgen Overview](../../tools/hdds-gen/overview.md) - Code generator usage
