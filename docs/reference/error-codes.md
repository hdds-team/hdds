# Error Codes

Reference for HDDS error types and resolution steps.

## Rust Error Type

The Rust API returns `hdds::Error` (`hdds::Result<T>`). Its variants, as
defined in `crates/hdds/src/dds/mod.rs`:

| Group | Variants |
|-------|----------|
| Configuration | `Config(String)`, `InvalidQos(String)`, `ConfigFileNotFound(String)` |
| Entity | `InvalidDomainId(u32)`, `InvalidParticipantId(u8)`, `NoAvailableParticipantId`, `ParticipantNotFound`, `RegistrationFailed`, `InvalidState(String)` |
| Transport | `Io` (deprecated), `IoError(std::io::Error)`, `TransportError` (deprecated), `BindFailed(String)`, `MulticastJoinFailed(String)`, `SendFailed(String)` |
| Data | `TypeMismatch`, `QosIncompatible`, `EndianMismatch`, `SerializationError`, `BufferTooSmall` |
| Resource | `WouldBlock`, `ResourceLimitExceeded(String)`, `OutOfMemory`, `WriteTimeout`, `DiscoveryTimeout`, `AcknowledgmentTimeout` |
| Other | `Unsupported`; with the `security` feature: `PermissionDenied(String)`, `EncryptionUnavailable(String)` |

## C API Error Codes

The C API returns these `HddsError` values (`sdk/c/include/hdds.h`). The numbers
and meanings are the header's; the same table is on the C API and C tutorial pages.
The Rust variants in the sections below are the Rust error type and have no
numeric value in C.

| Name | Value | Meaning (hdds.h) |
|------|-------|------------------|
| `HDDS_OK` | 0 | Success |
| `HDDS_INVALID_ARGUMENT` | 1 | Invalid argument provided (null pointer, invalid value) |
| `HDDS_NOT_FOUND` | 2 | Requested resource not found |
| `HDDS_OPERATION_FAILED` | 3 | Generic operation failure |
| `HDDS_OUT_OF_MEMORY` | 4 | Memory allocation failed |
| `HDDS_CONFIG_ERROR` | 10 | Invalid configuration settings |
| `HDDS_INVALID_DOMAIN_ID` | 11 | Invalid domain ID (must be 0-232) |
| `HDDS_INVALID_PARTICIPANT_ID` | 12 | Invalid participant ID (must be 0-119) |
| `HDDS_NO_AVAILABLE_PARTICIPANT_ID` | 13 | No available participant ID (all 120 ports occupied) |
| `HDDS_INVALID_STATE` | 14 | Invalid entity state for requested operation |
| `HDDS_IO_ERROR` | 20 | Generic I/O error |
| `HDDS_TRANSPORT_ERROR` | 21 | UDP transport send/receive failed |
| `HDDS_REGISTRATION_FAILED` | 22 | Topic registration failed |
| `HDDS_WOULD_BLOCK` | 23 | Operation would block but non-blocking mode requested |
| `HDDS_TIMEOUT` | 24 | Operation did not complete before the requested timeout |
| `HDDS_TYPE_MISMATCH` | 30 | Type mismatch between writer and reader |
| `HDDS_SERIALIZATION_ERROR` | 31 | CDR serialization failed |
| `HDDS_BUFFER_TOO_SMALL` | 32 | Buffer too small for encoding |
| `HDDS_ENDIAN_MISMATCH` | 33 | CDR endianness mismatch |
| `HDDS_QOS_INCOMPATIBLE` | 40 | QoS policies are incompatible between endpoints |
| `HDDS_UNSUPPORTED` | 41 | Requested feature or operation is not supported |
| `HDDS_PERMISSION_DENIED` | 50 | Permission denied by access control (DDS Security) |
| `HDDS_AUTHENTICATION_FAILED` | 51 | Authentication failed |

## Configuration Errors

### InvalidDomainId

```
Error: InvalidDomainId(234)
```

**Cause**: Domain ID out of valid range (0-232)

**Resolution**: Use domain ID between 0 and 232

### InvalidQos

```
Error: InvalidQos("History depth must be > 0")
```

**Cause**: QoS policy has invalid value

**Resolution**: Check QoS configuration:
- `KeepLast` depth > 0
- `max_samples >= max_samples_per_instance` and `KeepLast` depth <= `max_samples_per_instance` (DataWriter and DataReader creation)
- `deadline.period > 0`

### ConfigFileNotFound

```
Error: ConfigFileNotFound("/path/to/config.xml")
```

**Cause**: Referenced file doesn't exist

**Resolution**: Verify file path and permissions

## Discovery Errors

### ParticipantNotFound

```
Error: ParticipantNotFound
```

**Cause**: Referenced participant is not known

**Resolution**:
- Check participant has joined domain
- Verify domain IDs match
- Check network connectivity

### TypeMismatch

```
Error: TypeMismatch
```

**Cause**: Type name or schema doesn't match between endpoints

**Resolution**: Ensure IDL type names match exactly

### QosIncompatible

```
Error: QosIncompatible
```

**Cause**: Writer/reader QoS policies don't match (for example a
best-effort writer and a reliable reader)

**Resolution**: See [QoS compatibility rules](../guides/qos-policies/overview.md#qos-compatibility)

## Transport Errors

### BindFailed

```
Error: BindFailed("... Address already in use")
```

**Cause**: Port is already in use

**Resolution**:
```bash
# Find process using port
lsof -i :7400
# Kill or change domain ID
```

### MulticastJoinFailed

```
Error: MulticastJoinFailed("...")
```

**Cause**: Cannot join multicast group

**Resolution**:
```bash
# Check multicast routing
ip route show | grep 239.255

# Add route if missing
sudo ip route add 239.255.0.0/16 dev eth0
```

### SendFailed

```
Error: SendFailed("Network is unreachable")
```

**Cause**: Network interface down or no route

**Resolution**:
```bash
# Check interface status
ip link show

# Check routing
ip route show
```

## Security Errors

These variants exist only when the `security` Cargo feature is enabled.

### PermissionDenied

```
Error: PermissionDenied("...")
```

**Cause**: Participant doesn't have permission for the operation

**Resolution**: Update permissions.xml to allow access

### EncryptionUnavailable

```
Error: EncryptionUnavailable("...")
```

**Cause**: Encryption was requested but could not be applied to a sample, so
the write was refused instead of being sent in cleartext

**Resolution**: Check that the participant has a usable key; see the [security guide](../security-guide.md)

## Resource Errors

### ResourceLimitExceeded

```
Error: ResourceLimitExceeded("...")
```

**Cause**: ResourceLimits quota exceeded

**Resolution**: Increase limit or consume samples faster

### OutOfMemory

```
Error: OutOfMemory
```

**Cause**: System memory exhausted

**Resolution**:
- Reduce `max_samples` / `max_quota_bytes`
- Use `KeepLast` instead of `KeepAll`
- Increase system memory

## Timeout Errors

### WriteTimeout

```
Error: WriteTimeout
```

**Cause**: `max_blocking_time` exceeded

**Resolution**:
- Increase `max_blocking_time`
- Check if readers are consuming
- Increase history depth

### DiscoveryTimeout

```
Error: DiscoveryTimeout
```

**Cause**: No other participants discovered

**Resolution**:
- Check network connectivity
- Verify domain IDs match
- Check the firewall allows the UDP ports of your domain (`7400 + 250 x D` to `7649 + 250 x D`)

## CLI Exit Codes

### hdds-viewer

| Code | Meaning |
|------|---------|
| 0 | No issues detected |
| 1 | Low severity anomalies |
| 2 | Medium severity anomalies |
| 3 | High severity anomalies |
| 4 | Critical issues or file errors |

### hddsgen

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Error (unreadable input, lexer or parse error, validation or generation failure) |
| 2 | No subcommand given |

## Debugging

### Enable Debug Logging

```bash
# All HDDS debug output
export RUST_LOG=hdds=debug

# Specific modules
export RUST_LOG=hdds=trace,hdds::transport=debug

# Security debugging
export RUST_LOG=hdds::security=debug
```

### Network Diagnostics

```bash
# Enable UDP logging
export HDDS_LOG_UDP=1

# Enable interop diagnostics
export HDDS_INTEROP_DIAGNOSTICS=1
```

### Common Debug Commands

```bash
# Check RTPS multicast
tcpdump -i any -n udp port 7400

# Check participant discovery
tcpdump -i any -n udp portrange 7400-7649 | grep RTPS

# Monitor network interfaces
ip -s link show
```

## See Also

- [Troubleshooting](../troubleshooting/common-issues.md)
- [Environment Variables](../reference/environment-vars.md)
- [System Limits](../reference/limits.md)
