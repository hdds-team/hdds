# System Limits

This page documents the hard limits and recommended values for HDDS configuration.

## Domain & Participant Limits

| Limit | Value | Notes |
|-------|-------|-------|
| Domain ID range | 0-232 | 233 domains max (RTPS spec) |
| Participants per domain | 0-119 | 120 participants max |
| Total participants | 27,960 | 233 x 120 |

## Port Ranges

| Port Type | Formula | Domain 0, Participant 0 |
|-----------|---------|-------------------------|
| SPDP Multicast | 7400 + (250 x domainId) | 7400 |
| SEDP Unicast | 7410 + (250 x domainId) + (2 x participantId) | 7410 |
| User Unicast | 7411 + (250 x domainId) + (2 x participantId) | 7411 |
| Data Multicast | 7401 + (250 x domainId) | 7401 |

**Port range per domain:** 250 ports, `7400 + 250 x D` to `7649 + 250 x D` (the offsets in use go from 0 and 1 up to 10 + 2 x 119 + 1 = 249)

### Domains 102-214 collide with the Linux ephemeral port range

On Linux the kernel hands out short-lived source ports from
`/proc/sys/net/ipv4/ip_local_port_range`, whose default is **32768-60999**. Applying the formula
above, **domains 102 through 214 -- 113 of the 233 that exist -- have their RTPS ports inside that
range**. Any unrelated process on the host (a browser, a `curl`, a database client) can therefore be
handed a port that an HDDS participant on those domains needs, and the participant will fail to
bind. The kernel has no way to know RTPS wanted it.

Two things sharpen this:

- The participant-id search probes only the two UNICAST ports before committing to a mapping. The
  two MULTICAST ports are not probed and not retried, so a squatter on one of them is a hard
  failure rather than a move to the next participant id.
- HDDS sets `SO_REUSEADDR` on its sockets, so a conflict means the other holder did not. The bind
  error names the port and says so.

**Mitigations, in order of preference:**

1. Choose a domain outside the range. Domains **1-101** and **215-232** are unaffected by the
   default setting.
2. Reserve the ports the deployment uses so the kernel stops allocating them:
   `sysctl -w net.ipv4.ip_local_reserved_ports=<list or ranges>` (persist it in
   `/etc/sysctl.d/`). Reserve the whole 250-port block of each domain in use.
3. Narrow the ephemeral range itself with `net.ipv4.ip_local_port_range`, if the host's other
   workloads tolerate it.

Check the host's actual range first -- it is a tunable, and a hardened or containerised host may
already differ from the default:

```bash
cat /proc/sys/net/ipv4/ip_local_port_range
```

## Resource Limits (Default)

| Resource | Default | Maximum |
|----------|---------|---------|
| max_samples | LENGTH_UNLIMITED | Platform memory |
| max_instances | LENGTH_UNLIMITED | Platform memory |
| max_samples_per_instance | LENGTH_UNLIMITED | <= max_samples, >= KEEP_LAST depth |
| max_quota_bytes | 100 MB | Platform memory |

## Message Size Limits

| Limit | Value | Notes |
|-------|-------|-------|
| Max CDR payload | 16 MB | Per message |
| Max UDP datagram | 65,507 bytes | Fragmented if larger |
| Largest unfragmented payload | 8192 bytes | Larger payloads are sent as DATA_FRAG |
| RTPS fragment size | 1024 bytes | Default fragmentation |

## Discovery Timing

| Parameter | Default | Adjustable |
|-----------|---------|------------|
| SPDP announcement period | 3 seconds | Yes |
| SPDP startup burst | faster than the period | Internal |
| Participant lease duration | 30 seconds | Yes |

## History Limits

| Configuration | Constraint |
|---------------|------------|
| KEEP_LAST depth | > 0 |
| KEEP_ALL | Limited by ResourceLimits |
| Queue validation | max_samples >= max_samples_per_instance >= KEEP_LAST depth (writers and readers) |

## Shared Memory Transport

:::info Connected to the data path, and opt-in, with conditions
The shared memory transport carries real samples. When two endpoints pair,
the transport is selected, and a writer whose verdict is shared memory pushes
framed packets into its own ring. The test `crates/hdds/tests/shm_data_path.rs`
asserts the ring's own write and read counters rather than the arrival of the
sample: on the same host UDP would deliver it just as well, so arrival alone
cannot tell the two transports apart.

**It is on by default.** `ParticipantBuilder` initialises `shm_policy` to
`ShmPolicy::Prefer`, so every participant built through the normal API offers
shared memory unless you call `.shm_policy(ShmPolicy::Disable)`. The `Default`
impl on the enum itself says `Disable`, but the builder does not consult it.
A practical consequence: the capability hint below goes on the wire, to every
peer, by default.

It is narrow, though. All of the following must hold, or the pairing silently uses UDP:

- the policy is not `ShmPolicy::Disable` - it is `Prefer` unless you say otherwise,
- **both** endpoints are `BestEffort` - a `Reliable` endpoint never gets a shared-memory leg,
- the peer advertises the capability in the HDDS vendor PID (which HDDS itself
  announces as `shm=1;host_id=<8 hex>;nonce=<16 hex>;v=1` in a vendor-reserved
  parameter, emitted for every `BestEffort` endpoint), and
- co-location is provable: same host id, and the nonce exchange succeeds.

`ShmPolicy::Require` is refused by `ParticipantBuilder::build()` in this release, with a
configuration error that says why: the shared-memory leg carries unfragmented DATA only, so a
sample large enough to be fragmented would go over UDP, which is what `Require` forbids. Whether a
participant will ever write such a sample is a property of the samples, not of the configuration,
so it cannot be decided at build time nor per peer. Use `ShmPolicy::Prefer`, which takes shared
memory whenever a pairing supports it and never falls back without counting and logging it, or
`ShmPolicy::Disable`. With `Prefer`, a pairing that cannot use shared memory is counted under the
condition that was not met (reliable QoS, co-location not provable, a different host, or the nonce
cases). A segment that cannot be created retires the leg once and the writer returns to UDP,
rather than retrying per packet.

Linux only: `transport::shm` is a stub on every other target, where `Require` is refused outright.
:::

| Parameter | Default |
|-----------|---------|
| Ring buffer slots | 256 (power of 2) |
| Payload size per slot | 12288 bytes (8192 bytes of unfragmented payload plus 4096 bytes of framing) |

### SHM Limitations

| Limitation | Description |
|------------|-------------|
| **QoS Support** | BestEffort only - no ACK/NACK/retransmission |
| **Platforms** | Linux only (POSIX shm_open, futex); a stub elsewhere |
| **Data Loss** | Possible overrun if reader is slow (lock-free ring buffer) |
| **Cross-Vendor** | No interop with other vendors' shared-memory transports (RTPS over UDP is used for cross-vendor traffic) |
| **Security** | CryptoPlugin bypassed on SHM path |

### When to Use SHM

**Good for:**
- High-frequency sensor data (same host)
- BestEffort acceptable scenarios
- Low-overhead same-host delivery
- Single-process / intra-process communication

**Not for:**
- Reliable delivery requirements
- Cross-host communication
- Mixed vendor environments
- Security-critical data

## Performance Benchmarks

The published figures, each with its regime and its reproducer, are on the
[Benchmarks](../guides/performance/benchmarks.md) page. They are
operation-specific results, not universal limits.

## Recommended Practices

### High Frequency Topics (> 1000 Hz)

```rust
use hdds::QoS;

let qos = QoS::best_effort().keep_last(1);
```

### Large Messages (> 64 KB)

```rust
use hdds::QoS;
use std::time::Duration;

let mut qos = QoS::reliable().max_blocking_time(Duration::from_secs(5));
qos.resource_limits.max_quota_bytes = 500 * 1024 * 1024; // 500 MB
```

### Many Instances (> 1000)

```rust
use hdds::QoS;

let mut qos = QoS::reliable();
qos.resource_limits = hdds::qos::ResourceLimits {
    max_samples: 100_000,
    max_instances: 10_000,
    max_samples_per_instance: 10,
    ..Default::default()
};
```
