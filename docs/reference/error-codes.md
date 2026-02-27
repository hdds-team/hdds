# Error Codes

Reference for HDDS error types and resolution steps.

## Error Categories

| Category | Description |
|----------|-------------|
| `Config` | Configuration errors |
| `Discovery` | Participant/endpoint discovery issues |
| `QoS` | QoS policy violations |
| `Transport` | Network communication errors |
| `Security` | Authentication/authorization failures |
| `Resource` | Resource limit exceeded |
| `Timeout` | Operation timed out |

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
- `max_samples >= max_samples_per_instance × max_instances`
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
Error: ParticipantNotFound(guid)
```

**Cause**: Referenced participant is not known

**Resolution**:
- Check participant has joined domain
- Verify domain IDs match
- Check network connectivity

### TopicMismatch

```
Error: TopicMismatch { expected: "SensorData", found: "SensorReading" }
```

**Cause**: Type name doesn't match between endpoints

**Resolution**: Ensure IDL type names match exactly

### QosIncompatible

```
Error: QosIncompatible {
    writer: "BestEffort",
    reader: "Reliable"
}
```

**Cause**: Writer/reader QoS policies don't match

**Resolution**: See [QoS compatibility rules](../guides/qos-policies/overview#qos-compatibility.md)

## Transport Errors

### BindFailed

```
Error: BindFailed {
    address: "0.0.0.0:7400",
    reason: "Address already in use"
}
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
Error: MulticastJoinFailed {
    group: "239.255.0.1",
    interface: "eth0"
}
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
Error: SendFailed { reason: "Network is unreachable" }
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

### CertificateInvalid

```
Error: CertificateInvalid("Malformed PEM data")
```

**Cause**: Certificate file is corrupted or wrong format

**Resolution**:
```bash
# Validate certificate
openssl x509 -in cert.pem -text -noout
```

### CertificateExpired

```
Error: CertificateExpired
```

**Cause**: Certificate's notAfter date has passed

**Resolution**: Issue new certificate with extended validity

### AuthenticationFailed

```
Error: AuthenticationFailed("Signature verification failed")
```

**Cause**: Cannot verify peer's identity

**Resolution**:
- Check CA certificates match
- Verify certificate chain is complete
- Check clock synchronization

### PermissionDenied

```
Error: PermissionDenied {
    operation: "publish",
    topic: "admin/config"
}
```

**Cause**: Participant doesn't have permission

**Resolution**: Update permissions.xml to allow access

## Resource Errors

### ResourceLimitExceeded

```
Error: ResourceLimitExceeded {
    resource: "max_samples",
    limit: 1000,
    requested: 1001
}
```

**Cause**: ResourceLimits quota exceeded

**Resolution**: Increase limit or consume samples faster

### OutOfMemory

```
Error: OutOfMemory("Failed to allocate sample buffer")
```

**Cause**: System memory exhausted

**Resolution**:
- Reduce `max_samples` / `max_quota_bytes`
- Use `KeepLast` instead of `KeepAll`
- Increase system memory

## Timeout Errors

### WriteTimeout

```
Error: Timeout("Write blocked for 1000ms")
```

**Cause**: `max_blocking_time` exceeded

**Resolution**:
- Increase `max_blocking_time`
- Check if readers are consuming
- Increase history depth

### DiscoveryTimeout

```
Error: DiscoveryTimeout("No participants found in 10s")
```

**Cause**: No other participants discovered

**Resolution**:
- Check network connectivity
- Verify domain IDs match
- Check firewall allows UDP 7400-7500

## CLI Exit Codes

### hdds-viewer

| Code | Meaning |
|------|---------|
| 0 | No issues detected |
| 1 | Low severity anomalies |
| 2 | Medium severity anomalies |
| 3 | High severity anomalies |
| 4 | Critical issues or file errors |

### hdds-gen

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Parse error in IDL |
| 2 | Validation error |
| 3 | Code generation error |
| 4 | File I/O error |

## Debugging

### Enable Debug Logging

```bash
# All HDDS debug output
export RUST_LOG=hdds=debug

# Specific modules
export RUST_LOG=hdds::discovery=trace,hdds::transport=debug

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
tcpdump -i any -n udp portrange 7400-7500 | grep RTPS

# Monitor network interfaces
ip -s link show
```

## See Also

- [Troubleshooting](../troubleshooting/common-issues.md)
- [Environment Variables](../reference/environment-vars.md)
- [System Limits](../reference/limits.md)
