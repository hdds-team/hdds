# HDDS Conformance Matrix

**Version:** 1.5.0
**Methodology:** each row names the automated tests that exercise the feature in the HDDS repository and the result of running them. A row is not a certification: it says which tests exist and that they passed in that run. Paths are relative to `crates/hdds/` in the HDDS repository.

## Implementations HDDS Interoperates With

HDDS announces vendor ID `0x011A` and RTPS protocol version 2.4. Interoperability with other implementations is reported by a separate, reproducible harness (`scripts/interop-smoke/`), with the versions tested, the results and the commands to rerun them, in the [interoperability guide](interop/index.md). It is a report of HDDS's own interoperability, not a ranking.

## How to rerun this page

Run from the repository root. The discovery tests marked "needs multicast" are ignored by default; they were run with `HDDS_INTERFACE=lo`.

```bash
HDDS_INTERFACE=lo cargo test -p hdds --test rtps_conformance --test golden_vectors \
    --test serialization_roundtrip --test pl_cdr2_poly3d --test frag_data_frag \
    --test frag_nack_frag --test frag_nack_frag_loss --test frag_user_data_e2e \
    --test reliable_repair --test transient_local_late_joiner \
    --test writer_history_is_per_instance --test rtps_port_mapping \
    --test multicast_mode_v2 --test shm_data_path --test unicast_routing_e2e \
    --test qos_deadline --test qos_destination_order --test qos_durability_service \
    --test qos_entity_factory --test qos_latency_budget --test qos_lifespan \
    --test qos_liveliness --test qos_ownership --test qos_partition \
    --test qos_presentation --test qos_reader_data_lifecycle \
    --test qos_resource_limits --test qos_time_based_filter \
    --test qos_transport_priority --test qos_writer_data_lifecycle --test qos_metadata \
    -- --test-threads=1
HDDS_INTERFACE=lo cargo test -p hdds --test discovery_integration \
    --test stress_discovery -- --ignored --test-threads=1
cargo test -p hdds --lib -- spdp_peers transport::tcp --test-threads=1
```

## Feature Conformance

Section references are to the specification part that defines the feature: RTPS 2.5 Sec. 8.5 (discovery), RTPS 2.5 Sec. 8.3.7 (submessages), XTypes 1.3 Sec. 7.4 (data representation), DDS 1.4 Sec. 2.2.3 (QoS policies).

### Discovery (RTPS 2.5 Sec. 8.5)

| Feature | HDDS | Test |
|---------|:----:|------|
| SPDP over multicast, several participants discover each other | PASS | `tests/discovery_integration.rs::test_multi_participant_spdp_discovery` (needs multicast) |
| SEDP endpoint announcement between two participants | PASS | `tests/discovery_integration.rs::test_sedp_endpoint_announcement` (needs multicast) |
| Participant lease expiry | PASS | `src/core/discovery/spdp_peers.rs`, `discovered_peer_expires_after_lease` (unit test) |
| Many participants joining, intra-process | PASS | `tests/stress_discovery.rs` (ignored by default) |

### Wire Protocol (RTPS 2.5 Sec. 8.3)

| Submessage | ID | HDDS | Test |
|------------|:--:|:----:|------|
| RTPS header, vendor ID | - | PASS | `tests/rtps_conformance.rs` (`test_rtps_header_format`, `test_vendor_id`) |
| DATA | 0x15 | PASS | `tests/rtps_conformance.rs` (`test_data_submessage_format`) |
| DATA_FRAG | 0x16 | PASS | `tests/frag_data_frag.rs`, `tests/frag_nack_frag_loss.rs`, `tests/frag_user_data_e2e.rs` |
| NACK_FRAG | 0x12 | PASS | `tests/frag_nack_frag.rs` |
| HEARTBEAT | 0x07 | PASS | `tests/rtps_conformance.rs` (`test_heartbeat_submessage_format`) |
| ACKNACK | 0x06 | PASS | `tests/rtps_conformance.rs` (`test_acknack_submessage_format`) |
| GAP | 0x08 | PASS | `tests/rtps_conformance.rs` (`test_gap_submessage_format`) |
| INFO_TS | 0x09 | PASS | `tests/rtps_conformance.rs` (`test_info_ts_format`) |
| INFO_DST | 0x0E | PASS | `tests/rtps_conformance.rs` (`test_info_dst_format`) |
| Reliable repair of a lost burst | - | PASS | `tests/reliable_repair.rs` |
| Port mapping | - | PASS | `tests/rtps_port_mapping.rs` |

### Serialization (XTypes 1.3 / CDR)

| Representation | HDDS | Test |
|----------------|:----:|------|
| CDR2 little-endian: primitives, strings, sequences round trip | PASS | `tests/serialization_roundtrip.rs` |
| CDR2 little-endian: fixed byte vectors | PASS | `tests/golden_vectors.rs` (see Golden Vectors below) |
| PL_CDR2 mutable struct with an optional member | PASS | `tests/pl_cdr2_poly3d.rs` |

### QoS Policies (DDS 1.4 Sec. 2.2.3)

Whether each of the 22 policies changes runtime behaviour or is only accepted by the API and checked at discovery matching is stated policy by policy in the [QoS guide](qos-guide.md), table "Implementation Status". This matrix does not repeat it: a passing test file below is not a claim that the policy is enforced at runtime.

Every policy has its own test file; all of them passed in the run above. They exercise the policy types, builders, compatibility rules and, for the policies the QoS guide lists as enforced, the runtime behaviour.

| Policy | Test file | Tests |
|--------|-----------|------:|
| Deadline | `tests/qos_deadline.rs` | 8 |
| Destination order | `tests/qos_destination_order.rs` | 22 |
| Durability service | `tests/qos_durability_service.rs` | 31 |
| Entity factory | `tests/qos_entity_factory.rs` | 22 |
| Latency budget | `tests/qos_latency_budget.rs` | 25 |
| Lifespan | `tests/qos_lifespan.rs` | 19 |
| Liveliness | `tests/qos_liveliness.rs` | 13 |
| Ownership | `tests/qos_ownership.rs` | 33 |
| Partition | `tests/qos_partition.rs` | 16 |
| Presentation | `tests/qos_presentation.rs` | 29 |
| Reader data lifecycle | `tests/qos_reader_data_lifecycle.rs` | 27 |
| Resource limits | `tests/qos_resource_limits.rs` | 10 |
| Time-based filter | `tests/qos_time_based_filter.rs` | 21 |
| Transport priority | `tests/qos_transport_priority.rs` | 37 |
| Writer data lifecycle | `tests/qos_writer_data_lifecycle.rs` | 28 |
| Durability (TRANSIENT_LOCAL late joiner) | `tests/transient_local_late_joiner.rs` | 5 |
| History (per-instance KEEP_LAST / KEEP_ALL) | `tests/writer_history_is_per_instance.rs` | 6 |
| User, topic and group data | `tests/qos_metadata.rs` | 33 |

### Transport

| Transport | HDDS | Test |
|-----------|:----:|------|
| UDP IPv4 multicast | PASS | `tests/discovery_integration.rs` (needs multicast), `tests/multicast_mode_v2.rs` |
| Shared memory | PASS | `tests/shm_data_path.rs` |
| TCP | partial | `tests/unicast_routing_e2e.rs` and `src/transport/tcp/` unit tests cover the TCP listener and framing. `DataWriter::write` still sends over UDP, so DDS traffic does not flow over TCP; see the README, section "TCP Transport" |

## Golden Vectors

HDDS ships 42 CDR2 golden vectors in `crates/hdds/tests/golden/cdr2/`. They pin the output of
`encode_cdr2_le` so that a refactor cannot change the bytes without a test failing. They are NOT an
XCDR2 conformance oracle: seven of them do not carry a conformant layout (optional alignment, and a
missing DHEADER before non-primitive sequences and maps). See
`crates/hdds/tests/golden/cdr2/MANIFEST.md`, section Scope, for the inventory and the deviations.

Verification: `cargo test -p hdds --test golden_vectors` (verify mode, no overwrite).

## Spec References

| Standard | Version | URL |
|----------|---------|-----|
| OMG DDS | 1.4 | https://www.omg.org/spec/DDS/1.4/ |
| OMG RTPS | 2.5 | https://www.omg.org/spec/DDSI-RTPS/2.5/ |
| OMG XTypes | 1.3 | https://www.omg.org/spec/DDS-XTypes/1.3/ |

---

**Legend:** PASS = the cited tests passed in the run above, partial = see the note, N/T = no automated test cited.
