<p align="center">
  <img src="hdds-logo.png" alt="HDDS" width="160">
</p>
# HDDS

[![CI](https://git.hdds.io/hdds/hdds/actions/workflows/ci.yml/badge.svg)](https://git.hdds.io/hdds/hdds/actions)
[![Audit](https://git.hdds.io/hdds/hdds/actions/workflows/extreme-audit.yml/badge.svg)](https://git.hdds.io/hdds/hdds/actions)
[![License](https://img.shields.io/badge/license-Apache--2.0%20OR%20MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)
[![DDS](https://img.shields.io/badge/DDS-v1.4-green.svg)](https://www.omg.org/spec/DDS/)
[![RTPS](https://img.shields.io/badge/RTPS-v2.5-green.svg)](https://www.omg.org/spec/DDSI-RTPS/)
[![XTypes](https://img.shields.io/badge/XTypes-v1.3-green.svg)](https://www.omg.org/spec/DDS-XTypes/)
[![Security](https://img.shields.io/badge/DDS--Security-v1.1-green.svg)](https://www.omg.org/spec/DDS-SECURITY/)
[![no_std](https://img.shields.io/badge/no__std-hdds--micro-purple.svg)](#embedded-support-hdds-micro)
[![Tests](https://img.shields.io/badge/tests-2100+_passing-brightgreen)](#test)

Implementation haute performance du standard DDS (Data Distribution Service) en Rust, avec des SDKs natifs **C**, **C++**, **Python** et **TypeScript**.

HDDS est une implementation complete des specifications OMG DDS et RTPS (Real-Time Publish-Subscribe), concue pour la distribution de donnees deterministe et a faible latence dans les systemes distribues et embarques.

| | Langages | Plateformes |
|---|---|---|
| **SDKs** | Rust, C, C++, Python, TypeScript | Linux, macOS, Windows |
| **Embarque** | Rust (`no_std`), C (header-only) | ESP32, RP2040, STM32, ARM64 |
| **ROS 2** | couche rmw (C) | Humble, Iron, Jazzy |
| **Codegen IDL** | Rust, C, C++, Python, TypeScript, Rust-micro, C-micro | Tous |

### Specifications implementees

- **DDS v1.4** -- API publish-subscribe complete avec DataReader/DataWriter types
- **RTPS v2.5** -- Protocole filaire avec support complet des sous-messages
- **XTypes v1.3** -- Decouverte dynamique de types et verification de compatibilite
- **DDS Security v1.1** -- Authentification, chiffrement et controle d'acces

### Interoperabilite

Compatible et teste avec les implementations DDS du marche :

- **RTI Connext DDS** -- leader industriel (defense, aeronautique)
- **eProsima Fast DDS** -- implementation de reference ROS 2
- **Eclipse Cyclone DDS** -- open source, certifie safety
- **OpenDDS** -- open source (OCI)

> **Documentation complete :** **[docs.hdds.io](https://docs.hdds.io)** | **[C'est quoi DDS ?](https://docs.hdds.io/fr/getting-started/what-is-dds)**

**Demarrage rapide par langage :** [Rust](#demarrage-rapide) | [C++](#demarrage-rapide-c) | [Python](https://docs.hdds.io/fr/getting-started/hello-world-python) | [Embarque](https://docs.hdds.io/fr/getting-started/hello-world-embedded)

### Demarrage rapide

```bash
# Cloner et compiler
git clone https://git.hdds.io/hdds/hdds.git && cd hdds
cargo build --release

# Installer le generateur de code (types pour Rust, C, C++, Python, TypeScript, embarque)
git clone https://git.hdds.io/hdds/hdds_gen.git && cargo install --path hdds_gen

# Lancer le Hello World (deux terminaux)
cd sdk/samples/01_basics/rust
cargo run --bin hello_world           # Terminal 1 : subscriber
cargo run --bin hello_world -- pub    # Terminal 2 : publisher
```

### Demarrage rapide (C++)

```bash
# 1. Compiler le SDK C++ (build auto hdds-c + wrappers C++)
cd hdds
make sdk-cxx

# 2. Compiler les samples
make samples-cpp

# 3. Lancer (deux terminaux)
cd sdk/samples/01_basics/cpp/build
./hello_world          # Terminal 1 : subscriber
./hello_world pub      # Terminal 2 : publisher
```

Dans votre propre projet :

```cpp
#include <hdds.hpp>
#include "MonType.hpp"  // genere par : hddsgen gen cpp MonType.idl -o MonType.hpp

hdds::Participant participant("mon_app");
auto writer = participant.create_writer<MonType>("topic");
writer->write(MonType{42, "bonjour"});
```

```cmake
find_package(hdds REQUIRED)
target_link_libraries(myapp PRIVATE hdds::hdds)
# cmake .. -DCMAKE_PREFIX_PATH=/path/to/hdds/sdk/cmake
```

> **Tutorial complet :** [Hello World C++](https://docs.hdds.io/getting-started/hello-world-cpp)

---

*[English version below](#english-version)*

---

# English version

High-performance Data Distribution Service implementation in pure Rust, with native SDKs for **C**, **C++**, **Python**, and **TypeScript**.

HDDS is a from-scratch implementation of the OMG DDS (Data Distribution Service) and RTPS (Real-Time Publish-Subscribe) specifications, engineered for deterministic, low-latency data distribution across embedded and distributed systems.

| | Languages | Platforms |
|---|---|---|
| **SDKs** | Rust, C, C++, Python, TypeScript | Linux, macOS, Windows |
| **Embedded** | Rust (`no_std`), C (header-only) | ESP32, RP2040, STM32, ARM64 |
| **ROS 2** | rmw layer (C) | Humble, Iron, Jazzy |
| **IDL Codegen** | Rust, C, C++, Python, TypeScript, Rust-micro, C-micro | All |

> **New to DDS?** Read [What is DDS?](https://docs.hdds.io/getting-started/what-is-dds) for a beginner-friendly introduction.

**Quick Start by language:** [Rust](#quick-start) | [C++](#quick-start-c) | [Python](https://docs.hdds.io/getting-started/hello-world-python) | [Embedded](https://docs.hdds.io/getting-started/hello-world-embedded)

## Quick Start

> **Pre-release (v1.0.11):** `cargo add hdds` and crates.io publishing are coming with the stable release.
> For now, clone the repo and use a path dependency. Full documentation: **[docs.hdds.io](https://docs.hdds.io)**

```bash
# Clone and build
git clone https://git.hdds.io/hdds/hdds.git && cd hdds
cargo build --release

# Install the code generator (generates types for Rust, C, C++, Python, TypeScript, embedded)
git clone https://git.hdds.io/hdds/hdds_gen.git && cargo install --path hdds_gen

# Run the Hello World sample (two terminals needed)
cd sdk/samples/01_basics/rust
cargo run --bin hello_world           # Terminal 1: subscriber
cargo run --bin hello_world -- pub    # Terminal 2: publisher
```

```toml
# In your project's Cargo.toml
[dependencies]
hdds = { path = "../hdds/crates/hdds" }
```

### Quick Start (C++)

```bash
# 1. Build C++ SDK (auto-builds hdds-c + C++ wrappers)
cd hdds
make sdk-cxx

# 2. Build samples
make samples-cpp

# 3. Run (two terminals)
cd sdk/samples/01_basics/cpp/build
./hello_world          # Terminal 1: subscriber
./hello_world pub      # Terminal 2: publisher
```

In your own project:

```cpp
#include <hdds.hpp>
#include "MyType.hpp"  // generated by: hddsgen gen cpp MyType.idl -o MyType.hpp

hdds::Participant participant("my_app");
auto writer = participant.create_writer<MyType>("topic");
writer->write(MyType{42, "hello"});
```

```cmake
cmake_minimum_required(VERSION 3.16)
project(myapp CXX)
set(CMAKE_CXX_STANDARD 17)
find_package(hdds REQUIRED)
add_executable(myapp main.cpp)
target_link_libraries(myapp PRIVATE hdds::hdds)
```

```bash
# CMAKE_PREFIX_PATH tells CMake where to find hddsConfig.cmake
# (shipped in sdk/cmake/ -- provides the hdds::hdds imported target)
cmake .. -DCMAKE_PREFIX_PATH=/path/to/hdds/sdk/cmake
```

> **Full tutorial:** [Hello World C++](https://docs.hdds.io/getting-started/hello-world-cpp)

---

## Core Specifications

- **DDS v1.4** - Full publish-subscribe API with typed DataReader/DataWriter
- **RTPS v2.5** - Wire protocol with complete submessage support
- **XTypes v1.3** - Dynamic type discovery and type compatibility checking
- **DDS Security v1.1** - Authentication, encryption, and access control

---

## Protocol Implementation

### RTPS Wire Protocol

Complete implementation of the Real-Time Publish-Subscribe protocol:

- Full RTPS message header parsing and construction (GuidPrefix, Version, VendorId)
- All core submessages: DATA, HEARTBEAT, ACKNACK, GAP, INFO_TS, INFO_DST, INFO_REPLY, INFO_SRC
- Inline QoS parameter extraction and encoding
- Writer GUID to topic routing with SEDP metadata integration
- Sequence number tracking with 64-bit overflow handling
- ParameterList CDR encoding/decoding for discovery payloads

### CDR Serialization

Two-tier CDR implementation:

**Native Encoding: CDR2 (crates/hdds)**
- CDR2 v2 Little-Endian encoding (magic 0xCACE, version 0x02)
- PL_CDR2 (Parameter List CDR2) for extensible types
- Compile-time type descriptor generation via derive macro
- Zero-copy deserialization where possible

**Interop Decoding (reception only)**
- XCDR1 encapsulations: 0x0001, 0x0003, 0x8001, 0x8003 (CDR v1 from legacy vendors)
- XCDR2 encapsulations: 0x0006, 0x0007 (CDR v2 non-delimited)
- D_CDR2 encapsulations: 0x0008, 0x0009 (Delimited CDR v2 with DHEADER)

**CDR Micro (crates/hdds-micro)**
- Fixed-buffer encoder/decoder with no heap allocations
- CDR2 subset optimized for embedded (no XCDR1)
- Const-generic buffer sizing for compile-time guarantees

### XTypes v1.3

Runtime type system with full specification compliance:

- **TypeIdentifier** - MD5-based equivalence hashing (14-byte truncated)
- **TypeObject** - Complete and Minimal representations
- Structural type compatibility rules (@final, @appendable, @mutable)
- Member ID tracking for extensible struct evolution
- Bitset, bitmask, enum, union, and alias type support
- Type compression/decompression for wire efficiency
- SEDP integration for automatic type announcement

---

## Quality of Service

All 22 standard DDS QoS policies implemented (per DDS v1.4 specification).

### Implemented QoS Policies

| Policy | Description |
|--------|-------------|
| **Reliability** | BEST_EFFORT and RELIABLE with NACK-driven retransmission |
| **History** | KEEP_LAST(n) and KEEP_ALL with bounded depth |
| **Durability** | VOLATILE, TRANSIENT_LOCAL, PERSISTENT |
| **Durability Service** | History cleanup and service state management |
| **Deadline** | Periodic publication/subscription deadlines with miss detection |
| **Latency Budget** | Delivery latency hints for transport optimization |
| **Liveliness** | AUTOMATIC, MANUAL_BY_PARTICIPANT, MANUAL_BY_TOPIC |
| **Lifespan** | Sample expiration with automatic cleanup |
| **Ownership** | SHARED and EXCLUSIVE with strength arbitration |
| **Ownership Strength** | Writer priority for EXCLUSIVE ownership |
| **Partition** | Logical publisher/subscriber isolation |
| **Presentation** | Access scope (INSTANCE, TOPIC, GROUP) with coherent/ordered flags |
| **Destination Order** | BY_RECEPTION_TIMESTAMP and BY_SOURCE_TIMESTAMP |
| **Time-Based Filter** | Minimum separation between samples |
| **Transport Priority** | DSCP/PCP mapping for network QoS |
| **Resource Limits** | max_samples, max_instances, max_samples_per_instance, max_quota_bytes |
| **Entity Factory** | Auto-enable control for entities |
| **Writer Data Lifecycle** | Autodispose on unregister behavior |
| **Reader Data Lifecycle** | Autopurge disposed/no-writers delays |
| **User Data** | Opaque participant/writer/reader metadata |
| **Topic Data** | Opaque topic metadata |
| **Group Data** | Opaque publisher/subscriber metadata |

### QoS Loaders

| Format | Loader | Description |
|--------|--------|-------------|
| FastDDS XML | `FastDdsLoader` | eProsima FastDDS profiles (`<data_writer>`, `<data_reader>`) |
| YAML | `YamlLoader` | HDDS native format with profile inheritance |
| Auto-detect | `ProfileLoader` | Extension-based format detection (.xml, .yaml, .yml) |

Requires `qos-loaders` feature flag.

---

## Discovery

### Standard Discovery

- **SPDP** (Simple Participant Discovery Protocol) - Multicast participant announcement
- **SEDP** (Simple Endpoint Discovery Protocol) - Topic, reader, and writer discovery
- Writer GUID to topic name mapping for data routing
- Participant lease duration monitoring with automatic cleanup

### Discovery Server

Standalone discovery server for environments without multicast:

- TCP-based relay for NAT traversal
- Connection-oriented participant registry
- Domain isolation and multi-domain support
- Designed for Kubernetes/cloud deployments

### Cloud Discovery

Native cloud provider integration:

| Provider | Features |
|----------|----------|
| **AWS Cloud Map** | ECS task metadata, service registration, DNS-SD |
| **Azure Service Discovery** | Azure VNet integration, managed identity |
| **Consul** | Key-value registration, health checking |

---

## Transport Layer

### UDP Transport

- IPv4 and IPv6 unicast with automatic interface binding
- Multicast group management with IGMP/MLD support
- RTPS v2.5 port mapping algorithm (domain/participant ID based)
- Custom port mapping overrides for firewall traversal
- Source and destination filtering (whitelist/blacklist)
- Interface filtering by name, index, or IP range

### TCP Transport

For environments where UDP is blocked or unreliable:

- Length-prefixed framing (4-byte header)
- Connection pooling with automatic reconnection
- Non-blocking I/O via mio event loop
- Connection state machine (Connecting, Connected, Draining)
- TLS 1.2/1.3 support with certificate validation (tcp-tls feature)
- Configurable roles: Client, Server, Auto

### Shared Memory Transport (Linux)

Zero-copy inter-process communication:

- POSIX shared memory segments with deterministic naming
- Lock-free ring buffer with 64-byte cache line alignment
- Futex-based notification for sub-microsecond wakeup
- Writer push latency target: < 200 ns
- Reader poll latency target: < 100 ns
- End-to-end latency (with wake): < 1 microsecond
- Automatic SHM capability negotiation via SEDP user_data
- Host ID matching for same-machine detection

### Time-Sensitive Networking (Linux)

IEEE 802.1 TSN support for deterministic Ethernet:

- SO_PRIORITY to traffic class mapping (mqprio)
- VLAN PCP (Priority Code Point) tagging
- SO_TXTIME / SCM_TXTIME for scheduled transmission
- ETF and TAPRIO qdisc integration
- Hardware timestamping support
- Runtime TSN capability detection

### Low-Bandwidth Transport

Optimized HDDS-to-HDDS protocol for constrained links:

- Designed for 9.6 kbps to 2 Mbps throughput
- 100 ms to 2 second RTT tolerance
- 10-30% packet loss resilience
- Minimal overhead: 3-6 bytes per record, 6-10 bytes per frame
- ULEB128 varint encoding for compact integers
- LZ4 compression (optional, lowbw-lz4 feature)
- Delta encoding for telemetry streams
- Priority-based scheduling (P0 reliable, P1 batched, P2 droppable)
- Session management with HELLO/MAP/ACK handshake
- CRC-16/CCITT-FALSE integrity checking

### IP Mobility

Automatic handling of IP address changes:

- Poll-based or Netlink-based change detection (Linux)
- Locator tracking with hold-down timers
- SPDP burst reannouncement on locator change
- Interface hot-plug support

---

## Reliability Protocol

### Writer Side

- Heartbeat transmission with configurable period and jitter
- Gap submessage generation for non-contiguous sequences
- History cache for sample retransmission
- NACK processing with selective repair
- Writer retransmit handler with exponential backoff

### Reader Side

- Heartbeat reception and processing
- NACK scheduling with coalescing delay
- Gap tracking for missing sample detection
- Out-of-order sample buffering
- Reader retransmit request generation

### Reliability Metrics

Comprehensive observability:

- Heartbeats sent/received counters
- NACKs sent/received counters
- Gap detection and max gap size
- Out-of-order delivery statistics
- Retransmission success/failure rates

---

## Congestion Control

Adaptive congestion management:

- **Token Bucket** - Per-writer rate limiting with configurable budget
- **Priority Queues** - P0 (critical), P1 (normal), P2 (background)
- **AIMD** - Additive Increase / Multiplicative Decrease rate adaptation
- **P2 Coalescing** - "Last value wins" by instance key
- **RTT Estimation** - EWMA-based round-trip time tracking
- **ECN** - Explicit Congestion Notification processing
- **WFQ** - Weighted Fair Queuing across writers
- **Budget Allocator** - P0 reserve with P1/P2 distribution
- **NACK Coalescing** - Batched repair requests

---

## Security (DDS Security v1.1)

### Authentication Plugin

- X.509 certificate-based identity verification
- Certificate chain validation with CA trust anchors
- Certificate expiration and revocation checking
- Identity token exchange during discovery handshake

### Cryptographic Plugin

- AES-256-GCM encryption for data confidentiality
- ECDH P-256 key exchange for session key establishment
- HKDF session key derivation
- SecuredPayload submessage format (RTPS v2.5)
- Nonce generation with cryptographic RNG

### Access Control Plugin

- Permissions XML parsing and validation
- Topic-level allow/deny rules
- Partition-based access control
- Participant identity to permissions mapping

### Audit Logging

- Security event trail generation
- File-based log backend
- Syslog integration support

---

## Embedded Support (hdds-micro)

No-std DDS implementation for microcontrollers and constrained devices.

### Features

- **no_std compatible** - Works on bare metal embedded systems
- **Minimal footprint** - ~600 KB static binary on ARM
- **Cross-platform** - Supports aarch64, armv6, armv7, x86_64, Xtensa
- **Multiple transports** - UDP, LoRa, HC-12, NRF24L01, CC1101
- **Mesh networking** - Multi-hop relay with TTL-based flooding
- **RTPS compatible** - Interoperates with standard DDS implementations

### Resource Constraints

- Flash target: 60-80 KB (< 100 KB max)
- RAM target: 30-40 KB (< 50 KB max)
- No heap allocations in core (const generics for fixed buffers)
- No floating point in core path

### Validated Hardware

| Platform | Architecture | Transport | Binary Size |
|----------|--------------|-----------|-------------|
| Linux PC | x86_64 | WiFi UDP | - |
| Raspberry Pi Zero 2 W | aarch64 | WiFi UDP | 602 KB |
| Raspberry Pi Zero v1 | armv6 | WiFi UDP | 635 KB static |
| ESP32-WROOM-32 | Xtensa | WiFi UDP | 976 KB firmware |
| ESP32-WROVER-E | Xtensa | WiFi UDP | 976 KB firmware |
| ESP32 + HC-12 | Xtensa | 433 MHz Radio | - |

### Radio Modules

| Module | Frequency | Data Rate | Range | Use Case |
|--------|-----------|-----------|-------|----------|
| LoRa SX1276/78 | 868/915 MHz | 0.3-37.5 kbps | 10+ km | Long range, low power |
| HC-12 | 433 MHz | 1.2-236.8 kbps | 1 km | Simple serial radio |
| NRF24L01+ | 2.4 GHz | 250k-2M bps | 100 m | High speed, short range |
| CC1101 | 315/433/868/915 MHz | 1.2-500 kbps | 500 m | Multi-band, versatile |

### LoRa Features

- Configurable spreading factor (SF7-SF12)
- Bandwidth: 125/250/500 kHz
- Coding rate: 4/5 to 4/8
- TX power: -4 to +20 dBm
- Packet fragmentation for payloads > 255 bytes
- RSSI and SNR monitoring

### Mesh Networking

Multi-hop message relay:

- Controlled flooding with TTL
- Duplicate detection via sequence cache
- RSSI-based neighbor tracking
- Configurable relay behavior
- Maximum 7 hops

### Gateway

LoRa to WiFi/UDP bridge (requires `std` feature):

- Transparent protocol translation
- Per-stream routing configuration
- Statistics and monitoring

### Hardware Test Results

Cross-architecture communication validated:

```
Pi Zero 2 W (aarch64) <--WiFi UDP--> Pi Zero v1 (armv6)
Result: 10/10 messages, 0% loss

Linux PC (x86_64) --> ESP32-WROOM-32 (Xtensa)
Result: 10/10 messages, 0% loss

Pi Zero v1 (armv6) --> ESP32-WROOM-32 (Xtensa)
Result: 9/10 messages (1 lost during ESP32 boot)

ESP32-WROVER-E --> ESP32-WROOM-32 (different vendors)
Result: 25/25 messages, 0% loss

ESP32 + HC-12 --> ESP32 + HC-12 (433 MHz radio)
Result: 18/18 messages, 0% loss
```

### Architecture

```
hdds-micro/
+-- src/
|   +-- lib.rs              # no_std entry point
|   +-- cdr/                # CDR serialization
|   +-- rtps/               # RTPS protocol types
|   +-- core/               # Participant, Reader, Writer
|   +-- gateway/            # LoRa-WiFi bridge (std only)
|   +-- transport/
|       +-- udp.rs          # WiFi/Ethernet UDP
|       +-- lora/           # LoRa SX1276/78
|       +-- hc12/           # HC-12 433 MHz
|       +-- nrf24/          # NRF24L01 2.4 GHz
|       +-- cc1101/         # CC1101 multi-band
|       +-- mesh/           # Multi-hop relay
+-- examples/
|   +-- temperature_pubsub.rs
+-- scripts/
|   +-- esp32_publisher.py
|   +-- esp32_monitor.py
+-- esp32-example/          # ESP32 firmware project
```

### Quick Start

```bash
# Cross-compile for Pi Zero 2 W (aarch64)
cargo build --example temperature_pubsub --features std \
  --target aarch64-unknown-linux-gnu --release

# Cross-compile for Pi Zero v1 (armv6, static musl)
cargo build --example temperature_pubsub --features std \
  --target arm-unknown-linux-musleabihf --release

# Run subscriber
./temperature_pubsub sub

# Run publisher (set destination IP)
HDDS_DEST_IP=192.168.0.100 ./temperature_pubsub pub
```

---

## Tooling

### hddsgen

IDL to source code generator:

- Rust output with derive macros
- C/C++ output with type support
- Python bindings generation
- Embedded-optimized output (no-std compatible)
- Tera template-based code generation

### hddsctl

Command-line administration tool for DDS domains.

### hdds-admin

Administration API server:

- HTTP REST interface
- Participant/topic/endpoint introspection
- Metrics export

### hdds-debugger

Live DDS traffic analyzer and debugger.

### hdds-convert-qos

QoS profile conversion utility (XML to YAML and vice versa).

### RTPS Debug Tools (tools/)

Python utilities for protocol analysis and interop debugging:

| Tool | Description |
|------|-------------|
| `analyze_rtps.py` | RTPS packet analyzer with submessage and CDR parsing |
| `validate_sedp.py` | SEDP packet validator for interop debugging (FastDDS/RTI) |
| `dump_pcap.py` | PCAP file parser for DDS/RTPS traffic |
| `dump_pcapng.py` | PCAPNG file parser with detailed packet analysis |
| `compare_captures.py` | Diff two capture files to identify traffic differences |

Usage:
```bash
python3 tools/validate_sedp.py /tmp/capture.pcap --verbose
python3 tools/dump_pcapng.py /tmp/capture.pcapng
python3 tools/compare_captures.py capture1.pcap capture2.pcap
```

---

## Services

### hdds-persistence

TRANSIENT and PERSISTENT durability service:

- SQLite backend (default)
- RocksDB backend (optional)
- Sample storage and retrieval
- Late joiner sample replay

### hdds-recording

Recording and replay service:

- Topic recording to file
- MCAP format support (optional)
- Time-synchronized replay
- Topic filtering

### hdds-router

Domain bridging and topic transformation:

- Multi-domain routing
- Topic name remapping
- Data transformation via regex
- QoS adaptation

### hdds-gateway

REST API gateway with web UI:

- HTTP/REST to DDS bridging
- CORS support for web applications
- Embedded static file serving

### hdds-logger

Centralized DDS logging service:

- Topic-based log aggregation
- Filtering by topic, participant, or content
- Multiple output formats

---

## Observability

### Telemetry

- Thread-safe metrics collection with atomic counters
- Latency histogram tracking
- Binary frame encoding (HDMX format)
- Live telemetry streaming server

### Admin API

- Epoch-based state snapshots
- Lock-free reads for zero data-plane impact
- Binary protocol on TCP port 4243
- Mesh topology introspection
- Participant, topic, and endpoint views

### Metrics Export

- Prometheus format export
- Labeled metrics with tags
- Counter, gauge, and histogram types

---

## Language Bindings & SDKs

| SDK | Location | API Functions | Samples |
|-----|----------|:------------:|:-------:|
| **Rust** (native) | `crates/hdds/` | Full typed API | 12 categories |
| **C** | `sdk/c/` + `crates/hdds-c/` | 99+ FFI functions | 11 categories |
| **C++** | `sdk/cxx/` | RAII wrappers over C FFI | 10 categories |
| **Python** | `sdk/python/` | ctypes bindings | 10 categories |
| **TypeScript** | `sdk/typescript/` | Node.js native bindings | 1 category |
| **ROS 2 RMW** | `rmw_hdds/` | Full rmw layer | ros2 samples |

### Embedded SDKs

| SDK | Location | Target Platforms |
|-----|----------|-----------------|
| **hdds-micro** (Rust `no_std`) | `crates/hdds-micro/` | ESP32, RP2040, STM32, ARM64 (Pi Zero) |
| **C-Micro** (header-only) | via `hddsgen gen c-micro` | STM32, AVR, PIC, ESP32 |

Embedded transports: WiFi UDP, LoRa SX1276/78, HC-12 433 MHz, NRF24L01+ 2.4 GHz, CC1101, mesh relay.

### IDL Code Generator (hddsgen)

Separate repository: [hdds_gen](https://git.hdds.io/hdds/hdds_gen.git)

```bash
hddsgen gen <target> input.idl [--example] [--out-dir ./project]
```

| Target | Output | Notes |
|--------|--------|-------|
| `rust` | Typed structs + DDS traits | `--serde` for JSON/MessagePack |
| `c` | C89/C99/C11 structs + CDR codec | `--c-standard c11` |
| `cpp` | C++ structs + type support | `--fastdds-compat` for interop |
| `python` | Python classes + CDR2 serialization | |
| `typescript` | TypeScript types + CDR2 codec | alias: `ts` |
| `micro` | Rust `no_std` types for hdds-micro | |
| `c-micro` | Header-only C for MCUs | No malloc, fixed buffers |

---

## Vendor Interoperability

Tested compatibility with:

- Fast DDS (eProsima)
- RTI Connext DDS
- OpenDDS
- Eclipse Cyclone DDS

Dialect support for vendor-specific wire format quirks:

- dialect-coredx
- dialect-dust
- dialect-gurum
- dialect-intercom
- dialect-opensplice

---

## Build

```bash
cargo build --release
```

### Private Maintainer Tooling

For private release/ops scripts managed as a submodule under `maintainer/`, see:
`docs/MAINTAINER_SUBMODULE.md`

Quick commands:

```bash
make maintainer-init
make maintainer-status
make release-validate
```

### Feature Flags

| Feature | Description |
|---------|-------------|
| `xtypes` | XTypes v1.3 type discovery (default) |
| `qos-loaders` | XML/YAML QoS profile loading (default) |
| `security` | DDS Security v1.1 plugins |
| `tcp-tls` | TLS support for TCP transport |
| `cloud-discovery` | AWS/Azure/Consul discovery backends |
| `lowbw-lz4` | LZ4 compression for low-bandwidth transport |
| `telemetry` | Telemetry collection and export |
| `logging` | Compile-time logging |
| `trace` | Detailed tracing (requires logging) |

### Embedded Build (hdds-micro)

```bash
cd crates/hdds-micro/esp32-example
cargo build --release --target xtensa-esp32-espidf
```

---

## Test

```bash
cargo test
```

### Test Coverage

- Unit tests for all core modules
- Integration tests for QoS policies
- RTPS port mapping validation
- Serialization roundtrip tests
- Reliable repair protocol tests
- Mobility end-to-end tests
- Publisher/subscriber integration tests
- Late joiner (TRANSIENT_LOCAL) tests

---

## Benchmarks

```bash
cargo bench
```

Available benchmarks:

- `runtime` - Core runtime performance
- `discovery_latency` - SPDP/SEDP discovery timing
- `telemetry` - Metrics collection overhead
- `reliable_qos` - Reliability protocol throughput
- `demux_latency` - Packet routing latency
- `rtps` - Wire protocol encoding/decoding
- `stress_multi_node` - Multi-participant stress test
- `stress_phase7a` - High-load congestion scenarios

---

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT License ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

Copyright (c) 2025-2026 naskel.com

---

## Repository

https://git.hdds.io
