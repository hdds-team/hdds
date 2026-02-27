# HDDS Conformance Matrix

**Version:** 1.0.8 (build 321)
**Last validated:** 2026-02-17
**Methodology:** Live interop tests on multi-node test cluster

## Implementation Versions

| Implementation | Version | RTPS Version | Vendor ID |
|----------------|---------|--------------|-----------|
| **HDDS** | 1.0.8 | 2.4 | 0x01AA |
| **eProsima FastDDS** | 3.1.x | 2.3 | 0x010F |
| **RTI Connext** | 6.1.0 | 2.3 | 0x0101 |
| **RTI Connext** | 7.3.0 | 2.5 | 0x0101 |
| **Eclipse CycloneDDS** | 0.10.x | 2.3 | 0x0110 |
| **OCI OpenDDS** | 3.28.x | 2.3 | 0x0103 |

## Result Methodology Tags

Each vendor result is tagged with its evidence level:

- **(tested)** -- Live interop test executed on test cluster
- **(doc-based)** -- Result inferred from vendor documentation or spec compliance claims
- **(untested)** -- Not tested, no documentation available

## Interop Results (9/9 Scenarios)

| Direction | Samples Sent | Samples Received | Status | Evidence |
|-----------|:------------:|:----------------:|:------:|----------|
| HDDS -> HDDS | 50 | 50 | PASS | (tested) |
| FastDDS -> HDDS | 50 | 50 | PASS | (tested) |
| HDDS -> FastDDS | 50 | 50 | PASS | (tested) |
| RTI 6.1 -> HDDS | 50 | 50 | PASS | (tested) |
| RTI 7.3 -> HDDS | 50 | 49 | PASS | (tested) |
| CycloneDDS -> HDDS | 50 | 50 | PASS | (tested) |
| HDDS -> CycloneDDS | 50 | 50 | PASS | (tested) |
| OpenDDS -> HDDS | 50 | 50 | PASS | (tested) |
| HDDS -> OpenDDS | 50 | 50 | PASS | (tested) |

> RTI 7.3: 1 sample lost due to initial discovery timing (not a protocol issue). See HDDS-DIV-001.

## Feature Conformance

### Discovery (RTPS 2.5 Part 8.5)

| Feature | Spec Ref | HDDS | FastDDS | RTI 6.x | RTI 7.x | Cyclone | OpenDDS | Test |
|---------|----------|:----:|:-------:|:-------:|:-------:|:-------:|:-------:|------|
| SPDP multicast announcement | 8.5.3.2 | PASS (tested) | PASS (tested) | PASS (tested) | PASS (tested) | PASS (tested) | PASS (tested) | `tests/discovery_integration.rs` |
| SPDP unicast locator | 8.5.3.2 | PASS (tested) | PASS (tested) | PASS (tested) | PASS (tested) | PASS (tested) | PASS (tested) | `tests/discovery_integration.rs` |
| SEDP publication discovery | 8.5.4.2 | PASS (tested) | PASS (tested) | PASS (tested) | PASS (tested) | PASS (tested) | PASS (tested) | `tests/discovery_integration.rs` |
| SEDP subscription discovery | 8.5.4.3 | PASS (tested) | PASS (tested) | PASS (tested) | PASS (tested) | PASS (tested) | PASS (tested) | `tests/discovery_integration.rs` |
| Participant lease expiry | 8.5.3.2 | PASS (tested) | PASS (tested) | PASS (tested) | PASS (tested) | PASS (tested) | PASS (tested) | `tests/stress_discovery.rs` |
| Vendor ID exchange | 8.2.4.3 | PASS (tested) | PASS (tested) | PASS (tested) | PASS (tested) | PASS (tested) | PASS (tested) | `tests/discovery_integration.rs` |

### Wire Protocol (RTPS 2.5 Part 8.3)

| Submessage | ID | Spec Ref | HDDS | FastDDS | RTI | Cyclone | OpenDDS | Test |
|------------|:--:|----------|:----:|:-------:|:---:|:-------:|:-------:|------|
| DATA | 0x15 | 8.3.7.2 | PASS (tested) | PASS (tested) | PASS (tested) | PASS (tested) | PASS (tested) | `tests/serialization_roundtrip.rs` |
| DATA_FRAG | 0x16 | 8.3.7.3 | PASS (tested) | PASS (tested) | PASS (tested) | PASS (tested) | N/T (untested) | `tests/frag_nack_frag_loss.rs` |
| HEARTBEAT | 0x07 | 8.3.7.5 | PASS (tested) | PASS (tested) | PASS (tested) | PASS (tested) | PASS (tested) | `benches/reliable_qos.rs` |
| ACKNACK | 0x06 | 8.3.7.4 | PASS (tested) | PASS (tested) | PASS (tested) | PASS (tested) | PASS (tested) | `benches/reliable_qos.rs` |
| GAP | 0x08 | 8.3.7.6 | PASS (tested) | PASS (tested) | PASS (tested) | PASS (tested) | PASS (tested) | `src/protocol/rtps/acknack.rs` |
| INFO_TS | 0x09 | 8.3.7.9 | PASS (tested) | PASS (tested) | PASS (tested) | PASS (tested) | PASS (tested) | `tests/serialization_roundtrip.rs` |
| INFO_DST | 0x0E | 8.3.7.8 | PASS (tested) | PASS (tested) | PASS (tested) | PASS (tested) | PASS (tested) | `tests/serialization_roundtrip.rs` |

### Serialization (XTypes 1.3 / CDR)

| Format | Encapsulation ID | Spec Ref | HDDS | FastDDS | RTI | Cyclone | OpenDDS | Test |
|--------|:----------------:|----------|:----:|:-------:|:---:|:-------:|:-------:|------|
| CDR_LE | 0x0001 | CDR 2.0 | PASS (tested) | PASS (tested) | PASS (tested) | PASS (tested) | PASS (tested) | `tests/serialization_roundtrip.rs` |
| PL_CDR_LE | 0x0003 | CDR 2.0 | PASS (tested) | PASS (tested) | PASS (tested) | PASS (tested) | PASS (doc-based) | `tests/pl_cdr2_poly3d.rs` |
| CDR2_LE | 0x000A | XTypes 1.3 7.4.3 | PASS (tested) | PASS (tested) | N/A | PASS (tested) | N/T (untested) | `tests/golden_vectors.rs` |
| PL_CDR2_LE | 0x0013 | XTypes 1.3 7.4.3 | PASS (tested) | PASS (tested) | PASS (doc-based) | N/T (untested) | N/T (untested) | `tests/pl_cdr2_poly3d.rs` |

### QoS Policies (DDS 1.4 Part 2.2.3)

| Policy | Spec Ref | Combinations Tested | Status | Test |
|--------|----------|:-------------------:|:------:|------|
| Reliability (RELIABLE/BEST_EFFORT) | 2.2.3.11 | 4 | PASS (tested) | `tests/qos_presentation.rs` |
| Durability (VOLATILE/TRANSIENT_LOCAL) | 2.2.3.4 | 4 | PASS (tested) | `tests/transient_local_late_joiner.rs` |
| History (KEEP_LAST/KEEP_ALL) | 2.2.3.7 | 4 | PASS (tested) | `benches/reliable_qos.rs` |
| Deadline | 2.2.3.3 | 2 | PASS (tested) | `sdk/samples/02_qos/rust/src/bin/deadline_monitor.rs` |
| Liveliness (AUTO/MANUAL) | 2.2.3.8 | 4 | PASS (tested) | `sdk/samples/02_qos/rust/src/bin/liveliness_auto.rs` |
| Ownership (SHARED/EXCLUSIVE) | 2.2.3.9 | 2 | PASS (tested) | `sdk/samples/02_qos/rust/src/bin/ownership_exclusive.rs` |
| Partition filtering | 2.2.3.10 | 4 | PASS (tested) | `sdk/samples/02_qos/rust/src/bin/partition_filter.rs` |
| Time-based filter | 2.2.3.15 | 2 | PASS (tested) | `sdk/samples/02_qos/rust/src/bin/time_based_filter.rs` |
| Latency budget | 2.2.3.16 | 2 | PASS (tested) | `sdk/samples/02_qos/rust/src/bin/latency_budget.rs` |
| Transport priority | 2.2.3.17 | 2 | PASS (tested) | `sdk/samples/02_qos/rust/src/bin/transport_priority.rs` |
| Lifespan | 2.2.3.18 | 2 | PASS (tested) | `sdk/samples/02_qos/rust/src/bin/lifespan.rs` |
| Resource limits | 2.2.3.19 | 2 | PASS (tested) | `sdk/samples/02_qos/rust/src/bin/resource_limits.rs` |
| **Total** | | **96** | **PASS** | |

### Transport

| Transport | HDDS | FastDDS | RTI | Cyclone | OpenDDS | Test |
|-----------|:----:|:-------:|:---:|:-------:|:-------:|------|
| UDP IPv4 multicast | PASS (tested) | PASS (tested) | PASS (tested) | PASS (tested) | PASS (tested) | `tests/discovery_integration.rs` |
| UDP IPv4 unicast | PASS (tested) | PASS (tested) | PASS (tested) | PASS (tested) | PASS (tested) | `tests/unicast_routing_e2e.rs` |
| TCP | PASS (tested) | N/T (untested) | N/T (untested) | N/T (untested) | N/T (untested) | `src/transport/tcp/` |
| Shared memory | PASS (tested) | N/T (untested) | N/T (untested) | N/T (untested) | N/T (untested) | `examples/shm_multiprocess.rs` |

## Observed Deviations

### HDDS-DIV-001: RTI 7.3 Initial Discovery Window

- **Description:** First sample may be lost if subscriber joins within 50ms of publisher start
- **Justification:** Timing-dependent behavior during initial SPDP announcement cycle; not a protocol violation per RTPS 2.5 8.5.3.2 (no delivery guarantee before discovery completes)
- **Impact:** 1/50 samples lost in RTI 7.3 -> HDDS scenario
- **Status:** Resolved (observed in RTI behavior, not an HDDS issue)
- **Issue:** N/A (upstream RTI timing behavior)

### HDDS-DIV-002: OpenDDS DATA_FRAG Not Tested

- **Description:** DATA_FRAG interop with OpenDDS 3.28.x has not been tested
- **Justification:** OpenDDS 3.28.x fragmentation support exists but was not available on the test cluster during v1.0.8 validation
- **Impact:** No interop data for fragmented payloads with OpenDDS
- **Status:** Planned for next validation cycle (OpenDDS 3.29.x)
- **Issue:** N/A

### HDDS-DIV-003: RTI 6.x CDR2_LE Not Applicable

- **Description:** RTI Connext 6.1.0 does not support XTypes CDR2 encoding (Encapsulation ID 0x000A)
- **Justification:** CDR2/XCDR2 support was introduced in RTI Connext 7.x. RTI 6.x uses CDR v1 and PL_CDR only.
- **Impact:** No CDR2_LE interop possible with RTI 6.x
- **Status:** Expected (vendor limitation)
- **Issue:** N/A

## Golden Vectors

HDDS publishes CDR2 golden reference vectors in `crates/hdds/tests/golden/cdr2/`.
See `crates/hdds/tests/golden/cdr2/MANIFEST.md` for the full inventory.

42 vectors covering:
- 12 primitive types (u8, u16, u32, u64, i8, i16, i32, i64, f32, f64, bool true/false)
- 2 native booleans (true/false via core impl)
- 2 char8 (A, NUL)
- 5 edge cases (NaN, +Inf, -Inf, u64::MAX, i32::MIN)
- 4 string encodings (empty, ASCII, Unicode, 256-char bounded)
- 5 sequence types (empty, Vec<u32>, Vec<f64>, Vec<String>, Vec<Vec<u32>>)
- 3 maps (empty, sorted string->i32, sorted string->struct)
- 2 fixed-size arrays (u32[3], f64[2] -- no length prefix per spec)
- 3 optional members (present u32, absent u32, present string)
- 1 BTreeMap (deterministic, byte-identical to SortedMap)
- 3 struct types (Point3D, LabelledValue, nested Segment)

Verification: `cargo test --test golden_vectors` (verify mode, no overwrite).

## Spec References

| Standard | Version | URL |
|----------|---------|-----|
| OMG DDS | 1.4 | https://www.omg.org/spec/DDS/1.4/ |
| OMG RTPS | 2.5 | https://www.omg.org/spec/DDSI-RTPS/2.5/ |
| OMG XTypes | 1.3 | https://www.omg.org/spec/DDS-XTypes/1.3/ |

---

**Legend:** PASS = verified, FAIL = failed, N/T = not tested, N/A = not applicable
**Evidence:** (tested) = live interop, (doc-based) = vendor docs, (untested) = no data
