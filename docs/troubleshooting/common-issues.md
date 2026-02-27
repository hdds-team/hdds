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
export RUST_LOG=hdds::discovery=debug
```

**Solutions**:

| Cause | Solution |
|-------|----------|
| Different domain ID | Use same `ROS_DOMAIN_ID` or domain parameter |
| Firewall blocking | Open UDP 7400-7500 |
| Multicast disabled | Enable multicast or use static discovery |
| Wrong interface | Set `HDDS_INTERFACE=eth0` |

```rust
use hdds::{Participant, TransportMode};

// Force specific interface
let participant = Participant::builder("app")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .interface("192.168.1.0/24")
    .build()?;
```

### Endpoints Not Matching

**Symptom**: Participants discovered but no writer/reader matches.

**Diagnosis**:
```bash
# Check endpoint details
export RUST_LOG=hdds::discovery=trace
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
    // Faster initial announcements
    .discovery_interval(Duration::from_millis(50))
    // Shorter lease
    .lease_duration(Duration::from_secs(10))
    .build()?;
```

For known peers:
```rust
use hdds::{Participant, TransportMode};

let participant = Participant::builder("app")
    .domain_id(0)
    .with_transport(TransportMode::UdpMulticast)
    .add_static_peer("192.168.1.100:7400")
    .build()?;
```

## Communication Issues

### Messages Not Received

**Symptom**: Writer succeeds but reader receives nothing.

**Diagnosis**:
```bash
# Check if data reaches network
tcpdump -i any -n udp port 7410

# Check reader matched status
```

```rust
let matched = writer.matched_subscriptions();
println!("Matched readers: {}", matched.len());
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

**Symptom**: `write()` blocks or returns timeout error.

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

**Symptom**: `TypeConsistency check failed` error.

**Solutions**:

1. Regenerate types from same IDL:
```bash
hdds-gen -l rust my_types.idl
```

2. Use compatible extensibility:
```c
@appendable  // Or @mutable
struct SensorData {
    uint32 sensor_id;
    float value;
};
```

3. Enable type coercion:
```rust
use hdds::QoS;

let qos = QoS::reliable().type_coercion(true);
```

### Serialization Error

**Symptom**: `Serialization failed` or `Invalid CDR data`.

**Causes**:
- Incompatible types between writer and reader
- Corrupted network data
- Endianness mismatch

**Solutions**:
```bash
# Check wire format
export RUST_LOG=hdds::serialization=debug

# Verify type hash matches
hdds-gen -l rust --show-type-hash my_types.idl
```

## Memory Issues

### Out of Memory

**Symptom**: Process crashes with OOM or `OutOfResources` error.

**Diagnosis**:
```bash
# Monitor memory usage
watch -n 1 'ps -o rss,vsz,pid,cmd -p $(pgrep my_app)'
```

**Solutions**:
```rust
use hdds::QoS;

// Limit resource usage
let qos = QoS::reliable()
    .keep_last(10)
    .max_samples(1000)
    .max_instances(100)
    .max_samples_per_instance(10);
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

**Symptom**: `InconsistentQosPolicy` error or no match.

**Rules**:
| Policy | Compatibility |
|--------|---------------|
| Reliability | Writer ≥ Reader |
| Durability | Writer ≥ Reader |
| Deadline | Writer period ≤ Reader period |
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

**Symptom**: `OfferedDeadlineMissed` or `RequestedDeadlineMissed` callbacks.

**Solutions**:
```rust
use hdds::QoS;
use std::time::Duration;

// Increase deadline period
let qos = QoS::reliable().deadline(Duration::from_millis(200));  // Was 100ms

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
let qos = QoS::reliable().liveliness_automatic(Duration::from_secs(10));

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
# See /reference/environment-vars for details
```

### Firewall Blocking

**Symptom**: No network traffic seen.

**Solutions**:
```bash
# Open discovery ports
sudo ufw allow 7400:7500/udp

# Or with iptables
sudo iptables -A INPUT -p udp --dport 7400:7500 -j ACCEPT
```

## Build Issues

### hdds-gen Not Found

```bash
# Install from cargo
cargo install hdds-gen

# Or build from source
cargo build --release -p hdds-gen
export PATH=$PATH:./target/release
```

### Rust Version Too Old

**Symptom**: Compilation errors about missing features.

**Solution**:
```bash
# Update Rust
rustup update stable

# Check version (need 1.75+)
rustc --version
```

### Missing OpenSSL

**Symptom**: `Cannot find -lssl`.

**Solution**:
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
reader.try_take();  // May panic

// Good: drop before callback
{
    let data = some_data.borrow();
    // use data
}  // dropped here
reader.try_take();  // Safe
```

### Thread Panic

**Symptom**: `thread panicked` message.

**Diagnosis**:
```bash
export RUST_BACKTRACE=1
./my_app
```

## Error Codes Reference

| Error | Meaning | Solution |
|-------|---------|----------|
| `AlreadyDeleted` | Entity was deleted | Check lifecycle |
| `BadParameter` | Invalid argument | Check inputs |
| `ImmutablePolicy` | Can't change QoS | Set before enable |
| `InconsistentPolicy` | QoS conflict | Check QoS rules |
| `NotEnabled` | Entity not enabled | Call `enable()` |
| `OutOfResources` | Memory/limit hit | Increase limits |
| `PreconditionNotMet` | Invalid state | Check entity state |
| `Timeout` | Operation timed out | Increase timeout |
| `Unsupported` | Feature not available | Check feature flags |

## Next Steps

- [Debug Guide](../troubleshooting/debug-guide.md) - Detailed debugging
- [Performance Issues](../troubleshooting/performance-issues.md) - Performance problems
- [Error Codes](../reference/error-codes.md) - Complete error reference
