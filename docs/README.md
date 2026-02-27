# HDDS Documentation

High-performance DDS implementation in pure Rust.

## Table of Contents

### Getting Started
- [Introduction](./getting-started/introduction.md)
- [What is DDS?](./getting-started/what-is-dds.md)
- [What is RTPS?](./getting-started/what-is-rtps.md)
- **Installation**
  - [Linux](./getting-started/installation/linux.md)
  - [macOS](./getting-started/installation/macos.md)
  - [Windows](./getting-started/installation/windows.md)
  - [From Source](./getting-started/installation/from-source.md)
- **Hello World**
  - [Rust](./getting-started/hello-world-rust.md)
  - [C](./getting-started/hello-world-c.md)
  - [C++](./getting-started/hello-world-cpp.md)
  - [Python](./getting-started/hello-world-python.md)

### Concepts
- [Architecture](./concepts/architecture.md)
- [Participants](./concepts/participants.md)
- [Topics](./concepts/topics.md)
- [Publishers & Subscribers](./concepts/publishers-subscribers.md)
- [Discovery](./concepts/discovery.md)
- [QoS Overview](./concepts/qos-overview.md)

### API Reference
- [Rust API](./api/rust.md)
- [C API](./api/c.md)
- [C++ API](./api/cpp.md)
- [Python API](./api/python.md)
- [HDDS-Micro](./api/hdds-micro.md)

### Guides

#### QoS Policies
- [Overview](./guides/qos-policies/overview.md)
- [Reliability](./guides/qos-policies/reliability.md)
- [Durability](./guides/qos-policies/durability.md)
- [History](./guides/qos-policies/history.md)
- [Deadline](./guides/qos-policies/deadline.md)
- [Liveliness](./guides/qos-policies/liveliness.md)

#### Performance
- [Benchmarks](./guides/performance/benchmarks.md)
- [Tuning Latency](./guides/performance/tuning-latency.md)
- [Tuning Throughput](./guides/performance/tuning-throughput.md)

#### Security
- [Overview](./guides/security/overview.md)
- [Authentication](./guides/security/authentication.md)
- [Encryption](./guides/security/encryption.md)
- [Access Control](./guides/security/access-control.md)

#### Serialization
- [CDR2 Overview](./guides/serialization/cdr2-overview.md)
- [XTypes](./guides/serialization/xtypes.md)

### Interoperability
- [Overview](./interop/index.md)
- [Wire Compatibility](./interop/wire-compatibility.md)
- [QoS Translation Matrix](./interop/qos-translation-matrix.md)
- **FastDDS**
  - [Setup](./interop/fastdds/setup.md)
  - [QoS Mapping](./interop/fastdds/qos-mapping.md)
  - [Example](./interop/fastdds/example.md)
- **RTI Connext**
  - [Setup](./interop/rti-connext/setup.md)
  - [QoS Mapping](./interop/rti-connext/qos-mapping.md)
  - [Example](./interop/rti-connext/example.md)
- **CycloneDDS**
  - [Setup](./interop/cyclonedds/setup.md)
  - [QoS Mapping](./interop/cyclonedds/qos-mapping.md)
  - [Example](./interop/cyclonedds/example.md)

### Tools
- [Overview](./tools/index.md)
- **hdds-gen (Code Generator)**
  - [Overview](./tools/hdds-gen/overview.md)
  - [Installation](./tools/hdds-gen/installation.md)
  - [CLI Reference](./tools/hdds-gen/cli-reference.md)
  - **IDL Syntax**
    - [Basic Types](./tools/hdds-gen/idl-syntax/basic-types.md)
    - [Structs](./tools/hdds-gen/idl-syntax/structs.md)
    - [Enums](./tools/hdds-gen/idl-syntax/enums.md)
    - [Sequences](./tools/hdds-gen/idl-syntax/sequences.md)
    - [Annotations](./tools/hdds-gen/idl-syntax/annotations.md)

### ROS2 Integration
- [Overview](./ros2/index.md)
- [Performance](./ros2/performance.md)
- [Debugging](./ros2/debugging.md)
- **rmw-hdds**
  - [Installation](./ros2/rmw-hdds/installation.md)
  - [Configuration](./ros2/rmw-hdds/configuration.md)
- **Migration**
  - [From FastDDS](./ros2/migration/from-fastdds.md)
  - [From CycloneDDS](./ros2/migration/from-cyclonedds.md)

### Examples
- [Overview](./examples/index.md)
- [Temperature Sensor](./examples/temperature-sensor.md)
- [Reliable Delivery](./examples/reliable-delivery.md)
- [Multi-Topic](./examples/multi-topic.md)
- [Key/Instance](./examples/key-instance.md)
- [Cross-Vendor](./examples/cross-vendor.md)

### Reference
- [QoS Cheatsheet](./reference/qos-cheatsheet.md)
- [Environment Variables](./reference/environment-vars.md)
- [Error Codes](./reference/error-codes.md)
- [Limits](./reference/limits.md)

### Troubleshooting
- [Common Issues](./troubleshooting/common-issues.md)
- [Debug Guide](./troubleshooting/debug-guide.md)
- [Performance Issues](./troubleshooting/performance-issues.md)

### Community
- [Contributing](./community/contributing.md)
- [Code of Conduct](./community/code-of-conduct.md)

### [Changelog](./changelog.md)

---

## Quick Links

| Resource | Link |
|----------|------|
| Source Code | [git.hdds.io/hdds/hdds](https://git.hdds.io/hdds/hdds) |
| Issues | [git.hdds.io/hdds/hdds/issues](https://git.hdds.io/hdds/hdds/issues) |
| License | Apache 2.0 |
