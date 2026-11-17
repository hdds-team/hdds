# Common Issues

Quick solutions to frequently encountered HDDS problems.

## Discovery Issues

### No Participants Found

**Symptom**: Participants don't see each other, no matched endpoints.

**Diagnosis**:
```bash
# Check SPDP traffic
tcpdump -i any -n udp port 7400

# Enable discovery logging
export RUST_LOG=hdds=debug
```

**Solutions**:

| Cause | Solution |
|-------|----------|
| Different domain ID | Use same `ROS_DOMAIN_ID` or domain parameter |
| Firewall blocking | Open the UDP ports of your domain: 7400 + 250 x D to 7649 + 250 x D |
| Multicast disabled | Enable multicast or use static discovery |
| Wrong interface | Set `HDDS_INTERFACE=eth0` |

```bash
# Force the interface every network operation uses (name or IPv4 address)
export HDDS_INTERFACE=eth0
```

In code, restrict the interfaces a participant uses with a transport option:

```rust
use hdds::{Participant, TransportMode, TransportOptions};
use hdds::transport::InterfaceFilter;

let participant = Participant::builder("app")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .with_transport_options(
        TransportOptions::default()
            .with_interface_allowlist(InterfaceFilter::only_names(&["eth0"])),
    )
    .build()?;
```

### Endpoints Not Matching

**Symptom**: Participants discovered but no writer/reader matches.

**Diagnosis**:
```bash
# Check endpoint details
export RUST_LOG=hdds=trace
```

**Solutions**:

| Cause | Solution |
|-------|----------|
| Topic name mismatch | Check spelling, case sensitivity |
| Type name mismatch | Use identical IDL definitions |
| QoS incompatible | Writer reliability >= Reader |
| Partition mismatch | Same partition or empty |

```rust
use hdds::QoS;

// Verify QoS compatibility
// Writer reliable can match reliable readers
let writer_qos = QoS::reliable();

// But reader reliable won't match best-effort writer
let reader_qos = QoS::best_effort();  // Compatible with any writer
```

### Slow Discovery

**Symptom**: Takes several seconds to discover participants.

**Solutions**:
```rust
use hdds::{Participant, TransportMode};
use std::time::Duration;

let participant = Participant::builder("app")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    // Announce more often than the 3 s default
    .with_spdp_announcement_period(Duration::from_millis(500))
    // Shorter lease (must be longer than the announcement period)
    .with_participant_lease_duration(Duration::from_secs(10))
    .build()?;
```

For known peers:
```rust
use hdds::{Participant, TransportMode};

let participant = Participant::builder("app")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .add_static_peer("192.168.1.100:7410") // the peer's metatraffic unicast port
    .build()?;
```

## Communication Issues

### Messages Not Received

**Symptom**: Writer succeeds but reader receives nothing.

**Diagnosis**:
```bash
# Check if data reaches network
tcpdump -i any -n udp port 7410   # domain 0, participant 0 unicast

# Check reader matched status
```

```rust
println!("Matched readers: {}", writer.matched_reader_count());
```

**Solutions**:

| Cause | Solution |
|-------|----------|
| No match | Check discovery issues |
| History full | Increase history depth |
| Deadline missed | Check timing requirements |
| Network loss | Enable reliability |

### Data Loss / Gaps

**Symptom**: Some messages missing, sequence gaps in received data.

**Solutions**:
```rust
use hdds::QoS;

// Use reliable delivery
let writer_qos = QoS::reliable().keep_last(100);

// Matching reader
let reader_qos = QoS::reliable().keep_last(100);
```

### Writer Blocks / Timeout

**Symptom**: `write()` blocks or returns `Error::WriteTimeout`.

**Causes**:
1. Reliable delivery, reader not acknowledging
2. History cache full
3. Network congestion

**Solutions**:
```rust
use hdds::QoS;

// Increase history depth
let qos = QoS::reliable().keep_last(1000);

// Or use best effort for high-rate data
let qos = QoS::best_effort().keep_last(1);
```

### Late Joiner Misses Data

**Symptom**: Subscriber that starts late doesn't receive historical data.

**Solution**: Use TransientLocal durability:
```rust
use hdds::QoS;

// Writer
let writer_qos = QoS::reliable().keep_last(10).transient_local();

// Reader
let reader_qos = QoS::reliable().keep_last(10).transient_local();
```

## Type Issues

### Type Mismatch Error

**Symptom**: the endpoints are discovered but do not match, or `Error::TypeMismatch`.

**Solutions**:

1. Regenerate types from same IDL:
```bash
hddsgen gen rust my_types.idl -o src/my_types.rs
```

2. Use compatible extensibility:
```c
@appendable  // Or @mutable
struct SensorData {
    uint32 sensor_id;
    float value;
};
```

3. Relax the type consistency check (ALLOW_TYPE_COERCION, string and sequence bounds ignored):
```rust
use hdds::{QoS, TypeConsistencyEnforcement};

let mut qos = QoS::reliable();
qos.type_consistency = Some(TypeConsistencyEnforcement::default());
```

### Serialization Error

**Symptom**: `Error::SerializationError`, `Error::EndianMismatch` or `Error::BufferTooSmall`.

**Causes**:
- Incompatible types between writer and reader
- Corrupted network data
- Endianness mismatch

**Solutions**:
```bash
# Enable debug logging
export RUST_LOG=hdds=debug
```

## Memory Issues

### Out of Memory

**Symptom**: Process crashes with OOM, or `Error::OutOfMemory` / `Error::ResourceLimitExceeded`.

**Diagnosis**:
```bash
# Monitor memory usage
watch -n 1 'ps -o rss,vsz,pid,cmd -p $(pgrep my_app)'
```

**Solutions**:
```rust
use hdds::QoS;

// Limit resource usage
let mut qos = QoS::reliable().keep_last(10);
qos.resource_limits = hdds::qos::ResourceLimits {
    max_samples: 1000,
    max_instances: 100,
    max_samples_per_instance: 10,
    ..Default::default()
};
```

### Memory Leak

**Symptom**: Gradual memory growth over time.

**Common causes**:
1. History grows unbounded (`keep_all()`)
2. Instances not disposed
3. Listeners holding references

**Solutions**:
```rust
use hdds::QoS;

// Use keep_last instead of keep_all
let qos = QoS::reliable().keep_last(100);

// Dispose instances when done
writer.dispose(&sample)?;

// Unregister instances
writer.unregister_instance(&sample)?;
```

## QoS Issues

### Incompatible QoS

**Symptom**: `Error::QosIncompatible`, or no match.

**Rules**:
| Policy | Compatibility |
|--------|---------------|
| Reliability | Writer >= Reader |
| Durability | Writer >= Reader |
| Deadline | Writer period <= Reader period |
| Ownership | Writer = Reader |

**Example fix**:
```rust
use hdds::QoS;

// Reliable writer can match both reliable and best-effort readers
let writer_qos = QoS::reliable();

// But best-effort writer cannot match reliable reader
// This reader will NOT match a best-effort writer:
let reader_qos = QoS::reliable();
```

### Deadline Missed

**Symptom**: `on_offered_deadline_missed` or `on_requested_deadline_missed` listener callbacks.

**Solutions**:
```rust
use hdds::QoS;

// Increase deadline period
let qos = QoS::reliable().deadline_millis(200);  // Was 100ms

// Or remove deadline constraint
let qos = QoS::reliable();  // No deadline
```

### Liveliness Lost

**Symptom**: `LivelinessLost` callback, reader thinks writer is gone.

**Solutions**:
```rust
use hdds::QoS;
use std::time::Duration;

// Use automatic liveliness
let qos = QoS::reliable().liveliness_automatic_secs(10);

// For manual liveliness, assert regularly
loop {
    writer.assert_liveliness()?;
    std::thread::sleep(Duration::from_millis(500));
}
```

## Network Issues

### Multicast Not Working

**Symptom**: Same-host works, cross-host fails.

**Diagnosis**:
```bash
# Test multicast
ping -c 3 239.255.0.1

# Check route
ip route show | grep multicast
```

**Solutions**:
```bash
# Add multicast route
sudo ip route add 239.0.0.0/8 dev eth0

# Or specify interface explicitly
export HDDS_INTERFACE=eth0

# For unicast-only discovery, use HDDS_SPDP_UNICAST_PEERS
# (each peer's metatraffic unicast port, 7410 for domain 0 participant 0)
# See /reference/environment-vars for details
```

### Firewall Blocking

**Symptom**: No network traffic seen.

**Solutions**:
```bash
# Open the discovery and data ports of domain D: 7400 + 250 x D to 7649 + 250 x D
# (domain 0: 7400-7649; domain 42: 17900-18149)
sudo ufw allow 17900:18149/udp

# Or with iptables
sudo iptables -A INPUT -p udp --dport 17900:18149 -j ACCEPT
```

## Build Issues

### hddsgen Not Found

```bash
# The command is `hddsgen`, from the separate hdds_gen repository
git clone https://git.hdds.io/hdds/hdds_gen.git
cargo install --path hdds_gen
hddsgen --version     # 2.0 or later for HDDS 1.5
# (crates.io `hdds-gen` is a different tool)
```

### Rust Version Too Old

**Symptom**: Compilation errors about missing features.

**Solution**:
```bash
# Update Rust
rustup update stable

# Check version (1.90 builds this release, 1.85 does not)
rustc --version
```

### Missing OpenSSL

**Symptom**: `Cannot find -lssl`.

**Solution**: it does not come from HDDS. The workspace links no OpenSSL, with or without the `security` feature (that stack is pure Rust: ring, x509-parser, pem, webpki), and `Cargo.lock` contains no `openssl` crate. Look at the crates you added on top of HDDS and follow their own instructions; the commands below are what such a crate usually asks for.
```bash
# Debian/Ubuntu
sudo apt install libssl-dev

# Fedora
sudo dnf install openssl-devel

# macOS
brew install openssl
export OPENSSL_DIR=$(brew --prefix openssl)
```

## Runtime Issues

### Panic: Already Borrowed

**Symptom**: `RefCell` borrow panic in callback.

**Solution**: Don't hold references across callbacks:
```rust
// Bad: holding reference during callback
let data = some_data.borrow();
reader.take();  // May panic

// Good: drop before callback
{
    let data = some_data.borrow();
    // use data
}  // dropped here
reader.take();  // Safe
```

### Thread Panic

**Symptom**: `thread panicked` message.

**Diagnosis**:
```bash
export RUST_BACKTRACE=1
./my_app
```

## Error Codes Reference

The Rust API returns `hdds::Error`; the C API returns `HddsError` codes. Both
are listed, with causes and resolutions, in [Error Codes](../reference/error-codes.md).

## Next Steps

- [Debug Guide](../troubleshooting/debug-guide.md) - Detailed debugging
- [Performance Issues](../troubleshooting/performance-issues.md) - Performance problems
- [Error Codes](../reference/error-codes.md) - Complete error reference
