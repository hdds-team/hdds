---
sidebar_position: 1
title: Linux Installation
description: Install HDDS on Ubuntu, Debian, Fedora, or Arch Linux
---

# Installing HDDS on Linux

This guide covers installing HDDS from source on Linux.

## Prerequisites

- **Rust 1.75+** (install via [rustup](https://rustup.rs/)) -- **required even for C++ projects** (HDDS core is written in Rust)
- **Git**
- **GCC/Clang** (for C/C++ bindings, optional)
- **CMake 3.16+** and **g++** or **clang++** (required for C++ SDK)

```bash
# Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Verify Rust version
rustc --version  # Should be 1.75.0 or higher
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

## Using HDDS in Your Project

:::info Pre-release
HDDS will be published on crates.io with the 1.0 stable release. For now, use a path dependency.
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
| `security` | DDS Security 1.1 support |
| `tcp-tls` | TLS encryption for TCP transport |
| `cloud-discovery` | AWS/Azure/Consul discovery |
| `k8s` | Kubernetes discovery |
| `rpc` | DDS-RPC Request/Reply |
| `telemetry` | Metrics collection |

## Code Generator (hddsgen)

```bash
# Clone hddsgen
git clone https://git.hdds.io/hdds/hdds_gen.git
cd hdds_gen

# Build and install
cargo install --path .

# Verify
hddsgen --version
```

## Verify Installation

```bash
# Run the test suite
cargo test --release
```

:::tip Two terminals required
The Hello World sample uses `UdpMulticast` transport. To see pub/sub in action, open **two terminals**:
- Terminal 1: `cargo run --bin hello_world` (starts subscriber, waits for data)
- Terminal 2: `cargo run --bin hello_world -- pub` (sends 10 messages)

For the full walkthrough, see [Hello World tutorial](/getting-started/hello-world-rust).
:::

## Firewall Configuration

DDS uses UDP multicast. Configure your firewall:

```bash
# UFW (Ubuntu)
sudo ufw allow 7400:7500/udp

# firewalld (Fedora/RHEL)
sudo firewall-cmd --permanent --add-port=7400-7500/udp
sudo firewall-cmd --reload

# iptables
sudo iptables -A INPUT -p udp --dport 7400:7500 -j ACCEPT
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

- [Hello World C++](/getting-started/hello-world-cpp) - C++ pub/sub tutorial
- [Hello World Rust](/getting-started/hello-world-rust) - Rust pub/sub tutorial
- [hddsgen Overview](/tools/hdds-gen/overview) - Code generator usage
