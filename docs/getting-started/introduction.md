# Introduction to HDDS

**HDDS** (High-performance DDS) is a modern, open-source implementation of the Data Distribution Service (DDS) standard, whose core is written in Rust. It provides a publish-subscribe middleware that enables real-time, scalable, and reliable data exchange between distributed applications.

## Key Features

### Pure Rust Implementation

HDDS is written from scratch in Rust, providing:

- **Memory safety** without garbage collection, in the safe Rust code that makes up most of the library
- **Data-race freedom** for that safe code, checked at compile time

The library also contains `unsafe` code where it has to (for example shared
memory and the C FFI layer).

### Standards Compliant

HDDS implements the following OMG standards:

- **DDS 1.4** - Data Distribution Service specification
- **RTPS** - Real-Time Publish Subscribe wire protocol (announced as 2.4 on the wire)
- **XTypes 1.3** - Extensible Types (TypeObject and type compatibility)
- **DDS Security 1.1** - Authentication, encryption, and access control, between HDDS participants

### High Performance

Designed for demanding real-time applications:

- **One-thread intra-process `write(16-byte POD) -> take()`:** 180 ns p50 (default build, BEST_EFFORT, KEEP_LAST(1), pinned core, `HDDS_INTERFACE=lo`) on the benchmark host (Intel i9-9900KF, performance governor); this is neither a UDP nor a cross-process figure

See [Performance Benchmarks](../guides/performance/benchmarks.md) for the exact
regime, reproducer, and exclusions attached to each figure.

### Interoperability

HDDS can communicate with other DDS implementations:

- FastDDS (eProsima)
- RTI Connext DDS (with your own installation and licence)
- CycloneDDS (Eclipse)
- OpenDDS

See our [Interoperability Guide](../interop/index.md) for detailed setup instructions.

## Use Cases

Typical DDS use cases:

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
+---------------------------------------------------------+
|                    Application Layer                     |
|              (Your Code, ROS2, Custom Apps)             |
+---------------------------------------------------------+
|                       DCPS Layer                         |
|  (DomainParticipant, Publisher, Subscriber, Topic, QoS) |
+---------------------------------------------------------+
|                       RTPS Layer                         |
|    (Discovery, Writers, Readers, History Cache)         |
+---------------------------------------------------------+
|                    Transport Layer                       |
|              (UDP, TCP, Shared Memory)                  |
+---------------------------------------------------------+
```

## Getting Started

Ready to dive in? Here's your path:

1. **[What is DDS?](../getting-started/what-is-dds.md)** - Learn the fundamentals
2. **[Installation](../getting-started/installation/linux.md)** - Get HDDS on your system
3. **[Hello World C++](../getting-started/hello-world-cpp.md)** - C++ pub/sub tutorial
4. **[Hello World Rust](../getting-started/hello-world-rust.md)** - Rust pub/sub tutorial

## License

HDDS is licensed under **Apache-2.0 OR MIT**, at your option, which makes it suitable for both commercial and open-source projects.

## Support

- **Issues**: [git.hdds.io/hdds/hdds/issues](https://git.hdds.io/hdds/hdds/issues)
- **Contact**: [contact@hdds.io](mailto:contact@hdds.io)
- **Documentation**: You're already here!
