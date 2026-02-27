# HDDS on OWA5X — Technical Brief

> **Date:** January 2026  
> **Contact:** HDDS Team — contact@hdds.io  
> **Project:** HDDS — European DDS Middleware in Rust

---

## Executive Summary

We have successfully ported **HDDS**, a high-performance DDS middleware written in Rust, to the **Owasys OWA5X** platform. This document presents benchmark results and proposes a technical partnership to position OWA5X as a reference platform for European sovereign middleware in automotive and defense markets.

---

## Benchmark Results — OWA5X

| Metric | Value |
|--------|-------|
| **Platform** | OWA5X (NXP i.MX8 Cortex-A53 Quad-Core @ 1.6GHz) |
| **OS** | Debian 12 (Bookworm) / musl libc |
| **Transport** | UDP Multicast |
| **Test** | Ping-pong RTT, 1000 samples, 64-byte payload |

### Latency Results

| Percentile | RTT | One-Way (estimated) |
|------------|-----|---------------------|
| **P50** | 682 μs | **~341 μs** |
| **Avg** | 791 μs | ~396 μs |
| **P99** | 3.07 ms | ~1.5 ms |

*Measured out-of-the-box, no kernel tuning, no RT patches.*

---

## HDDS Overview

### What is HDDS?

HDDS is a **DDS (Data Distribution Service) middleware** implementation targeting:
- **Defense** (NATO STANAG compatibility, IGI-1300 compliance roadmap)
- **Automotive** (AUTOSAR Adaptive, SOME/IP bridge planned)
- **Robotics** (ROS2 RMW layer included)

### Key Differentiators

| Feature | HDDS | Traditional DDS (RTI, FastDDS) |
|---------|------|-------------------------------|
| **Language** | Rust (memory-safe) | C++ |
| **x86 Latency** | 257 ns write | 500+ ns |
| **Binary Size** | ~2 MB | 10-50 MB |
| **Dependencies** | Zero (pure Rust) | OpenSSL, Boost, etc. |
| **Origin** | 🇪🇺 European (France) | 🇺🇸 US-based |

### Multi-Vendor Interoperability

HDDS interoperates with all major DDS implementations:
- ✅ RTI Connext DDS
- ✅ eProsima FastDDS  
- ✅ Eclipse CycloneDDS
- ✅ OpenDDS

---

## Technical Contributions — OWA5X Port

During the port, we contributed fixes relevant to embedded Linux:

### 1. musl libc Compatibility
OWA5X uses musl instead of glibc. We fixed type casting issues in low-level socket code.

### 2. Network Alias Handling
OWA5X exposes `eth1` and `eth1:0` (alias) as separate interfaces. Our multicast join logic now handles `EADDRINUSE` gracefully when joining the same group on aliased interfaces.

### 3. Port Reservation Race Condition
Fixed a drop-order issue causing socket bind failures on resource-constrained devices.

*These fixes benefit all embedded Linux targets, not just OWA5X.*

---

## Partnership Proposal

### What We Offer

1. **OWA5X as Reference Platform**  
   HDDS documentation and samples will feature OWA5X as the recommended ARM64 target for automotive/telematics use cases.

2. **Continuous Validation**  
   OWA5X included in our CI matrix for ongoing compatibility.

3. **Co-Marketing**  
   Joint technical blog post / case study on DDS performance on OWA5X.

4. **Bug Fixes**  
   Any issues discovered on OWA5X are fixed upstream and shared.

### What We Need

1. **Hardware Access**  
   1-2 additional OWA5X units for long-term testing and CI integration.

2. **Technical Contact**  
   Direct line to Owasys engineering for BSP/kernel questions.

3. **Logo Usage** (optional)  
   Permission to reference Owasys/OWA5X in HDDS marketing materials.

---

## Market Alignment

| Segment | Owasys Strength | HDDS Strength |
|---------|-----------------|---------------|
| **Fleet Management** | OWA5X deployed in 50+ countries | Real-time pub/sub |
| **Defense** | Rugged hardware | NATO/ANSSI compliance |
| **Automotive** | CAN/J1939 support | AUTOSAR Adaptive roadmap |
| **European Sovereignty** | 🇪🇸 Spanish company | 🇫🇷 French project |

**Together:** A fully European stack for sovereign connected vehicles.

---

## Next Steps

1. **Demo Call** — Live demonstration of HDDS on OWA5X (30 min)
2. **Hardware Discussion** — CI integration requirements
3. **Partnership MOU** — Formalize reference platform status

---

## Contact

**HDDS Team**
HDDS Project
📧 contact@hdds.io
🌐 https://hdds.io

---

*HDDS is dual-licensed: MIT for open-source, Commercial for enterprise support.*
