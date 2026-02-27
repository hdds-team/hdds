# 08_interop - Cross-Vendor DDS Interoperability

This directory contains samples demonstrating **HDDS interoperability** with other DDS implementations (FastDDS, CycloneDDS, RTI Connext).

## Samples

| Sample | Description |
|--------|-------------|
| `string_interop` | Basic pub/sub interop using StringMsg type |
| `discovery_test` | Cross-vendor SPDP/SEDP discovery verification |

## Interoperability Overview

DDS implementations following the RTPS standard can communicate regardless of vendor:

```
HDDS Publisher ──────────────┐
                             │
FastDDS Publisher ───────────┤   DDS Topic: "InteropTopic"
                             ├──────────────────────────────► Any DDS Subscriber
CycloneDDS Publisher ────────┤
                             │
RTI Connext Publisher ───────┘
```

### Requirements for Interop

| Requirement | Value |
|-------------|-------|
| Domain ID | Must match (default: 0) |
| Topic Name | Must match exactly |
| Type Name | Must match (CDR-encoded) |
| QoS | Must be compatible (or use defaults) |

## Running the Samples

### Prerequisites

- HDDS built and installed
- (Optional) FastDDS, CycloneDDS, or RTI Connext for cross-vendor testing

### Rust

```bash
cd rust

# Terminal 1 - HDDS Subscriber
cargo run --bin string_interop

# Terminal 2 - HDDS Publisher
cargo run --bin string_interop -- pub

# Alternative: Use another DDS implementation on "InteropTopic"
```

### Discovery Test

```bash
# Start HDDS discovery test
cargo run --bin discovery_test

# In another terminal, start a participant from another DDS vendor
# Check HDDS logs for discovered peers (RUST_LOG=debug)
```

## Expected Output

### String Interop - Publisher
```
============================================================
HDDS DDS Interoperability Sample
Topic: InteropTopic | Type: hdds_interop::StringMsg
============================================================

DDS Participant created:
  Name: InteropTest
  Domain: 0
  Transport: UDP Multicast (RTPS standard)

Publishing StringMsg messages...
  [00] Published: "Hello from HDDS Rust #0"
  [01] Published: "Hello from HDDS Rust #1"
  ...
```

### String Interop - Subscriber
```
Waiting for messages from any DDS vendor...
  [00] Received: "Hello from HDDS Rust #0"
  [01] Received: "Hello from HDDS Rust #1"
  ...
```

## Key Concepts

1. **RTPS Protocol**: Wire-level interop standard (v2.3 implemented by HDDS)

2. **SPDP/SEDP**: Automatic discovery protocols for finding peers

3. **CDR Encoding**: Standard serialization format for DDS types

4. **Topic & Type Matching**: Both sides must agree on topic name and type definition

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Peers not discovered | Check domain ID, firewall, multicast routing |
| Type mismatch | Ensure IDL definitions match across implementations |
| QoS incompatible | Use compatible QoS (e.g., both RELIABLE or both BEST_EFFORT) |
| Network issues | Verify UDP multicast (239.255.0.1) is allowed |
