# 11_embedded - Embedded ARM64 Samples

This directory contains samples optimized for **embedded ARM64 platforms** like:
- **Owasys OWA5X** (industrial gateway)
- Raspberry Pi 4/5
- NVIDIA Jetson Nano/Xavier
- BeagleBone AI-64

## Samples

| Sample | Description |
|--------|-------------|
| `arm64_hello` | Minimal pub/sub for ARM64 verification |
| `arm64_latency` | Round-trip latency benchmark |

## Cross-Compilation Setup

### Prerequisites

```bash
# Install Rust ARM64 target
rustup target add aarch64-unknown-linux-gnu

# Install cross-compiler toolchain (Ubuntu/Debian)
sudo apt install gcc-aarch64-linux-gnu

# Optional: Install cross for easier builds
cargo install cross
```

### Build for ARM64

```bash
cd rust

# Option 1: Direct cargo build
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
cargo build --release --target aarch64-unknown-linux-gnu

# Option 2: Using cross (recommended)
cross build --release --target aarch64-unknown-linux-gnu
```

### Deploy to OWA5X

```bash
# Copy binaries to device
scp target/aarch64-unknown-linux-gnu/release/arm64_hello <USERNAME>@<DEVICE_IP>:/tmp/
scp target/aarch64-unknown-linux-gnu/release/arm64_latency <USERNAME>@<DEVICE_IP>:/tmp/

# SSH to device
ssh <USERNAME>@<DEVICE_IP>
```

## Running on OWA5X

### Hello World Test

```bash
# Make executable
chmod +x /tmp/arm64_hello

# Terminal 1 - Subscriber
/tmp/arm64_hello

# Terminal 2 - Publisher
/tmp/arm64_hello pub
```

### Latency Benchmark

```bash
# Terminal 1 - Echo server
/tmp/arm64_latency echo

# Terminal 2 - Benchmark client
/tmp/arm64_latency
```

## Expected Output

### Hello World
```
==================================================
HDDS ARM64 Hello World
Platform: linux / aarch64
==================================================

[OK] Participant created: ARM64Demo
[OK] Domain ID: 0

[ARM64] Creating subscriber...
[ARM64] Waiting for messages...

  [SUB] counter=0, msg="Hello from ARM64 #0"
  [SUB] counter=1, msg="Hello from ARM64 #1"
  ...
```

### Latency Benchmark
```
==================================================
HDDS ARM64 Latency Benchmark Results
==================================================

Samples: 1000 / 1000

Round-Trip Time (RTT):
  Min:     120.3 µs
  Avg:     198.7 µs
  P50:     185.2 µs
  P90:     312.4 µs
  P99:     487.6 µs
  Max:     892.1 µs

One-way latency (RTT/2):
  Avg:      99.4 µs
  P99:     243.8 µs
==================================================
```

## OWA5X Specifications

| Spec | Value |
|------|-------|
| CPU | NXP i.MX8M Plus (Cortex-A53 quad-core) |
| RAM | 2-4 GB DDR4 |
| OS | Linux (Yocto-based) |
| Network | 2x Gigabit Ethernet |
| Target | Industrial IoT gateway |

## Performance Comparison

Expected results on OWA5X (same-device loopback):

| Metric | HDDS | FastDDS | Improvement |
|--------|------|---------|-------------|
| RTT Avg | ~200 µs | ~350 µs | 43% faster |
| RTT P99 | ~500 µs | ~900 µs | 44% faster |
| Memory | ~2 MB | ~8 MB | 75% smaller |
| Binary | ~3 MB | ~12 MB | 75% smaller |

## Troubleshooting

### "cannot execute binary file"
- Verify architecture: `file /tmp/arm64_hello`
- Should show: `ELF 64-bit LSB executable, ARM aarch64`

### "libgcc_s.so.1: cannot open"
Use musl target for fully static binary:
```bash
rustup target add aarch64-unknown-linux-musl
cargo build --release --target aarch64-unknown-linux-musl
```

### No discovery between devices
- Check firewall: `sudo iptables -L`
- Verify multicast: `ip maddr show`
- Use same domain ID (default: 0)

## Integration with OWA5X SDK

For production deployments, HDDS can be integrated into Owasys Yocto builds:

```bitbake
# In your Yocto recipe
DEPENDS += "rust-bin"
SRC_URI = "git://github.com/user/hdds.git;branch=main"
CARGO_BUILD_FLAGS = "--release --target aarch64-unknown-linux-gnu"
```

See Owasys documentation for complete Yocto integration instructions.
