# Introduction to HDDS

**HDDS** (High-performance DDS) is a modern, open-source implementation of the Data Distribution Service (DDS) standard, written entirely in Rust. It provides a publish-subscribe middleware that enables real-time, scalable, and reliable data exchange between distributed applications.

## Key Features

### Pure Rust Implementation

HDDS is written from scratch in Rust, providing:

- **Memory safety** without garbage collection
- **Thread safety** guaranteed at compile time
- **Zero-cost abstractions** for maximum performance
- **No undefined behavior** by design

### Standards Compliant

HDDS implements the following OMG standards:

- **DDS 1.4** - Data Distribution Service specification
- **RTPS 2.5** - Real-Time Publish Subscribe wire protocol
- **XTypes 1.3** - Extensible Types for dynamic type support
- **DDS Security 1.1** - Authentication, encryption, and access control

### High Performance

Designed for demanding real-time applications:

- **Sub-microsecond latency** with zero-copy data paths
- **Millions of messages per second** throughput
- **Lock-free data structures** for predictable performance
- **NUMA-aware memory allocation** for multi-socket systems

### Interoperability

HDDS can communicate with other DDS implementations:

- FastDDS (eProsima)
- RTI Connext DDS
- CycloneDDS (Eclipse)
- OpenDDS

See our [Interoperability Guide](../interop.md) for detailed setup instructions.

## Use Cases

HDDS is ideal for:

| Domain | Use Case |
|--------|----------|
| **Robotics** | ROS2 middleware, swarm coordination, sensor fusion |
| **Autonomous Vehicles** | V2X communication, sensor data distribution |
| **Industrial IoT** | Factory automation, predictive maintenance |
| **Aerospace & Defense** | Mission-critical systems, real-time telemetry |
| **Financial Services** | Low-latency market data, order routing |
| **Simulation** | Distributed simulation, digital twins |

## Architecture

HDDS follows a layered architecture:

```
┌─────────────────────────────────────────────────────────┐
│                    Application Layer                     │
│              (Your Code, ROS2, Custom Apps)             │
├─────────────────────────────────────────────────────────┤
│                       DCPS Layer                         │
│  (DomainParticipant, Publisher, Subscriber, Topic, QoS) │
├─────────────────────────────────────────────────────────┤
│                       RTPS Layer                         │
│    (Discovery, Writers, Readers, History Cache)         │
├─────────────────────────────────────────────────────────┤
│                    Transport Layer                       │
│              (UDP, TCP, Shared Memory)                  │
└─────────────────────────────────────────────────────────┘
```

## Getting Started

Ready to dive in? Here's your path:

1. **[What is DDS?](../getting-started/what-is-dds.md)** - Learn the fundamentals
2. **[Installation](../getting-started/installation/linux.md)** - Get HDDS on your system
3. **[Hello World C++](../getting-started/hello-world-cpp.md)** - C++ pub/sub tutorial
4. **[Hello World Rust](../getting-started/hello-world-rust.md)** - Rust pub/sub tutorial

## License

HDDS is licensed under the **Apache License 2.0**, making it suitable for both commercial and open-source projects.

## Support

- **Issues**: [git.hdds.io/hdds/hdds/issues](https://git.hdds.io/hdds/hdds/issues)
- **Contact**: [contact@hdds.io](mailto:contact@hdds.io)
- **Documentation**: You're already here!
