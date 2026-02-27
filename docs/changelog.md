# Changelog

All notable changes to HDDS are documented here.

## [Unreleased]

### Added
- Python async/await support
- Shared memory transport (experimental)
- Content-filtered topics
- Listener API for callback-based data notifications
  - `DataReaderListener` trait with `on_data_available()`, `on_subscription_matched()`, etc.
  - `DataWriterListener` trait with `on_sample_written()`, `on_publication_matched()`, etc.
  - `ClosureListener<T, F>` for simple closure-based callbacks
  - Builder pattern: `.with_listener(Arc::new(MyListener))`
- **QUIC Transport** for modern connectivity (feature `quic`)
  - NAT traversal and firewall-friendly (UDP-based)
  - 0-RTT connection establishment for known peers
  - Connection migration (IP change without disconnect)
  - Built-in TLS 1.3 encryption
  - Self-signed certificates for HDDS-to-HDDS

### Changed
- Improved discovery performance by 40%

### Fixed
- Memory leak in long-running subscribers
- Multicast route detection on macOS
- **DATA_FRAG payload offset** - Fixed fragment payload extraction for large messages (>8KB)
  - Root cause: DATA_FRAG has 12 extra bytes of fragment metadata vs DATA
  - Payload offset corrected from +24 to +36 bytes
  - Added CDR encapsulation header stripping in reassembly path
  - Tested: 16KB (~1.1ms), 64KB (~2.3ms) - max 64KB per RTPS spec (u16 length field)

---

## [1.0.0] - 2024-12-01

### First Stable Release

HDDS 1.0.0 marks the first production-ready release with full DDS 1.4 and RTPS 2.5 compliance.

### Features

- **Core DDS API**
  - DomainParticipant, Publisher, Subscriber
  - Topic, DataWriter, DataReader
  - Full QoS policy support (22 policies)

- **Multi-Language Support**
  - Rust (native)
  - C bindings (FFI)
  - C++ bindings (RAII wrapper)
  - Python bindings (PyO3)

- **RTPS 2.5 Compliance**
  - SPDP/SEDP discovery
  - Reliable and best-effort transport
  - Large data fragmentation
  - Participant redundancy

- **Interoperability**
  - Tested with FastDDS, RTI Connext, CycloneDDS
  - Wire-compatible with RTPS 2.3+ implementations

- **Tools**
  - hdds_gen code generator
  - hdds_viewer network analyzer
  - hdds_studio visual IDL editor

### Known Limitations

- DDS Security is feature-complete but not yet FIPS certified
- Shared memory transport is experimental
- Windows ARM64 not yet supported

---

## [0.9.0] - 2024-10-15

### Release Candidate

- Feature freeze for 1.0
- Security audit completed
- Performance benchmarks published

---

## [0.8.0] - 2024-08-01

### Beta Release

- C++ bindings added
- QoS XML profile support
- hdds_studio initial release

---

## Migration Guides

### Migrating from 0.x to 1.0

Breaking changes in 1.0:

```rust
// 0.x API
let writer = participant.create_datawriter(&topic)?;

// 1.0 API - renamed for clarity
let writer = participant.create_writer(&topic)?;
```
