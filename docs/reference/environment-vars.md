# Environment Variables

HDDS can be configured via environment variables. All variables are prefixed with `HDDS_`.

## Discovery & Networking

| Variable | Purpose | Example |
|----------|---------|---------|
| `HDDS_SPDP_UNICAST_PEERS` | Manual unicast peer list | `192.168.1.100:7400,192.168.1.101:7400` |
| `HDDS_LOG_UDP` | Enable UDP debug logging | `1` |
| `HDDS_INTEROP_DIAGNOSTICS` | Enable interop diagnostics | `1` |
| `HDDS_FORCE_DATA_MC` | Route DATA to multicast | `1` |
| `HDDS_DISABLE_TYPE_OBJECT` | Disable TypeObject announcement | `1` |

## Network Interface Control

| Variable | Purpose | Format |
|----------|---------|--------|
| `HDDS_MULTICAST_IF` | Force multicast interface | IPv4 address (e.g., `192.168.1.5`) |
| `HDDS_UNICAST_IF` | Force unicast interface | IPv4 address |
| `HDDS_INTERFACE_ALLOW` | Allow specific interfaces | CIDR list: `eth0,192.168.1.0/24` |

## TTL (Time-To-Live) Configuration

| Variable | Purpose | Range |
|----------|---------|-------|
| `HDDS_TTL` | Set both multicast & unicast TTL | 1-255 |
| `HDDS_MULTICAST_TTL` | Multicast TTL only | 1-255 |
| `HDDS_UNICAST_TTL` | Unicast TTL only | 1-255 |

## Source Filtering

| Variable | Purpose | Format |
|----------|---------|--------|
| `HDDS_SOURCE_ALLOW` | Allowed source CIDRs | `192.168.1.0/24,10.0.0.0/8` |
| `HDDS_SOURCE_DENY` | Denied source CIDRs | `192.168.0.0/16` |

## QoS & Traffic Control

| Variable | Purpose | Format |
|----------|---------|--------|
| `HDDS_DSCP` | DSCP code points | `18,46,26` (AF21, EF, AF31) |

## Observability

| Variable | Purpose | Values |
|----------|---------|--------|
| `HDDS_EXPORTER_DISABLE` | Disable telemetry export | `1`, `true`, or `yes` |

## Participant Configuration

| Variable | Purpose | Example |
|----------|---------|---------|
| `HDDS_PARTICIPANT_ID` | Override auto-generated participant ID | `42` |
| `HDDS_MULTICAST_ADDRESS` | Custom multicast address | `239.255.0.100` |
| `HDDS_DISCOVERY_PEERS` | Static discovery peer list | `192.168.1.100:7400,192.168.1.101:7400` |
| `HDDS_INITIAL_PEERS` | Initial peers (alias for DISCOVERY_PEERS) | `192.168.1.100:7400` |
| `HDDS_DISCOVERY_PORT` | Custom discovery port | `7400` |
| `HDDS_CONFIG_FILE` | Path to HDDS configuration file | `/etc/hdds/config.xml` |

## Transport Control

| Variable | Purpose | Values |
|----------|---------|--------|
| `HDDS_MULTICAST_DISABLE` | Disable multicast discovery | `1`, `true` |
| `HDDS_SHM_DISABLE` | Disable shared memory transport | `1`, `true` |

## Security

### HDDS Security Variables

| Variable | Purpose | Example |
|----------|---------|---------|
| `HDDS_SECURITY_ENABLE` | Enable DDS Security | `1`, `true` |
| `HDDS_SECURITY_IDENTITY_CERT` | Path to participant X.509 certificate | `/etc/hdds/cert.pem` |
| `HDDS_SECURITY_IDENTITY_KEY` | Path to participant private key | `/etc/hdds/key.pem` |
| `HDDS_SECURITY_CA_CERT` | Path to CA certificate(s) | `/etc/hdds/ca.pem` |
| `HDDS_SECURITY_PERMISSIONS` | Path to permissions file | `/etc/hdds/permissions.xml` |
| `HDDS_SECURITY_GOVERNANCE` | Path to governance rules | `/etc/hdds/governance.xml` |
| `HDDS_AUDIT_LOG_PATH` | Path to security audit log | `/var/log/hdds/audit.log` |
| `HDDS_REQUIRE_AUTH` | Require all participants to authenticate | `1`, `true` |

### Legacy Security Variables (Deprecated)

| Variable | Replacement |
|----------|-------------|
| `HDDS_IDENTITY_CERT` | `HDDS_SECURITY_IDENTITY_CERT` |
| `HDDS_PRIVATE_KEY` | `HDDS_SECURITY_IDENTITY_KEY` |
| `HDDS_CA_CERTS` | `HDDS_SECURITY_CA_CERT` |
| `HDDS_PERMISSIONS_XML` | `HDDS_SECURITY_PERMISSIONS` |
| `HDDS_GOVERNANCE_XML` | `HDDS_SECURITY_GOVERNANCE` |

### ROS 2 Security Compatibility

| Variable | Purpose | Example |
|----------|---------|---------|
| `ROS_SECURITY_ENABLE` | Enable security (ROS 2 compatible) | `true` |
| `ROS_SECURITY_ENCLAVE` | Security enclave path | `/my_robot/my_node` |
| `ROS_SECURITY_STRATEGY` | Security strategy | `Enforce`, `Permissive` |
| `ROS_SECURITY_KEYSTORE` | Path to security keystore | `/etc/ros/security` |

### Security Example

```bash
# Enable full DDS Security (new style)
export HDDS_SECURITY_ENABLE=true
export HDDS_SECURITY_IDENTITY_CERT=/etc/hdds/certs/participant.pem
export HDDS_SECURITY_IDENTITY_KEY=/etc/hdds/certs/participant_key.pem
export HDDS_SECURITY_CA_CERT=/etc/hdds/certs/ca.pem
export HDDS_SECURITY_PERMISSIONS=/etc/hdds/security/permissions.xml
export HDDS_SECURITY_GOVERNANCE=/etc/hdds/security/governance.xml
export HDDS_AUDIT_LOG_PATH=/var/log/hdds/audit.log
./my_dds_app
```

```bash
# ROS 2 compatible security configuration
export ROS_SECURITY_ENABLE=true
export ROS_SECURITY_STRATEGY=Enforce
export ROS_SECURITY_ENCLAVE=/my_robot/sensor_node
export ROS_SECURITY_KEYSTORE=/etc/ros/security
./my_ros2_node
```

## Logging

Standard Rust logging via `RUST_LOG`:

```bash
# Enable debug logging for HDDS
RUST_LOG=hdds=debug ./my_app

# Trace-level for discovery
RUST_LOG=hdds::discovery=trace ./my_app

# Multiple filters
RUST_LOG=hdds=debug,hdds::transport=trace ./my_app
```

## Examples

### Static Peer Discovery

```bash
# Disable multicast, use unicast peers only
export HDDS_SPDP_UNICAST_PEERS="10.0.0.1:7400,10.0.0.2:7400"
./my_dds_app
```

### Network Interface Selection

```bash
# Force specific network interface
export HDDS_MULTICAST_IF="192.168.1.100"
export HDDS_UNICAST_IF="192.168.1.100"
./my_dds_app
```

### TTL for Multi-Hop Networks

```bash
# Increase TTL for WAN scenarios
export HDDS_TTL=32
./my_dds_app
```

### Debug Interoperability

```bash
# Enable verbose interop logging
export HDDS_INTEROP_DIAGNOSTICS=1
export RUST_LOG=hdds=debug
./my_dds_app
```

### Firewall-Friendly Setup

```bash
# Disable multicast, use unicast only
export HDDS_SPDP_UNICAST_PEERS="peer1.example.com:7400"
export HDDS_FORCE_DATA_MC=0
./my_dds_app
```
