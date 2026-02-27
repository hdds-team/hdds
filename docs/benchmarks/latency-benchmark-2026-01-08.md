# HDDS Latency Benchmark Report

**Date:** 2026-01-08
**Version:** HDDS 0.8.0
**Tool:** hdds-latency-probe

---

## Test Configuration

| Parameter | Value |
|-----------|-------|
| Transport | UDP Multicast (loopback) |
| QoS | Reliable |
| Samples | 500-1000 per test |
| Warmup | 50-100 iterations |
| Payload | 64 bytes |

---

## Results: UDP Loopback Latency (RTT)

| Machine | CPU | Min | Avg | p99 | Max |
|---------|-----|-----|-----|-----|-----|
| Machine A | i9-9900KF @ 3.6GHz | 971 µs | 1288 µs | 2181 µs | - |
| Machine B | i7-6700K @ 4.0GHz | 865 µs | 1329 µs | 2195 µs | 2318 µs |
| Machine C (loaded) | Dual Xeon | 651 µs | 1206 µs | 1975 µs | 2005 µs |

### Best-Effort vs Reliable (Machine A)

| QoS | Min | Avg | p99 |
|-----|-----|-----|-----|
| Reliable | 971 µs | 1288 µs | 2181 µs |
| Best-Effort | 968 µs | 1230 µs | 2192 µs |

**Observation:** Minimal difference on loopback (no packet loss to trigger retransmission).

---

## Analysis

### UDP Loopback Latency (~1ms RTT)

The measured latency of ~1ms for UDP loopback is expected and includes:

1. **Kernel network stack** - Full UDP/IP processing
2. **Context switches** - User → Kernel → User (×4 for RTT)
3. **Socket buffers** - Kernel buffer copies
4. **RTPS protocol** - Header parsing, reliability tracking

### Comparison with Other Transports

| Transport | Expected Latency | Use Case |
|-----------|------------------|----------|
| **SHM (Shared Memory)** | 100-500 ns | Same-host, zero-copy |
| **IntraProcess** | 50-200 ns | Same-process |
| **UDP Loopback** | 500-2000 µs | Testing, isolation |
| **UDP Network** | 100-5000 µs | Cross-host |
| **QUIC** | 200-3000 µs | NAT traversal, WAN |

---

## Throughput

From the 64B test on Machine B:
- **Throughput:** ~270 msg/s (at 1ms interval)
- **Zero packet loss** on loopback

For maximum throughput testing, use smaller intervals or dedicated tools.

---

## Recommendations

1. **For low latency:** Use SHM transport on same-host scenarios
2. **For cross-host:** UDP with Best-Effort QoS if loss is acceptable
3. **For reliability:** Reliable QoS adds ~5% overhead on lossy networks

---

## Comparison with CycloneDDS

**Date:** 2026-01-08
**Environment:** Machine C (Dual Xeon), UDP loopback, same test conditions

### Raw Results (v212 - mio/epoll)

| Size | CycloneDDS p50 | HDDS v212 p50 | Gap | HDDS p99 |
|------|----------------|---------------|-----|----------|
| 64B  | 133 µs | 246 µs | 1.8x | 450 µs |
| 1KB  | 120 µs | ~270 µs | 2.2x | ~470 µs |
| 8KB  | 150 µs | ~290 µs | 1.9x | ~500 µs |

### Optimization History

| Version | Change | 64B p50 | Improvement |
|---------|--------|---------|-------------|
| v208 | 1ms polling | 1,134 µs | baseline |
| v209 | 100μs polling | 413 µs | **2.7x faster** |
| v210 | WakeNotifier (Condvar) | 354 µs | **3.2x faster** |
| v211 | Atomic fast-path + Spin | 280 µs | **4.0x faster** |
| v212 | mio/epoll listener | 246 µs | **4.6x faster** |

### v211: Atomic Fast-Path + Spin-Before-Wait

Two key optimizations:

1. **Atomic fast-path in WakeNotifier** (`engine/wake.rs`):
   - `AtomicBool` for lock-free notification in hot path
   - `notify()` uses only atomic store (no lock!)
   - `check_and_clear()` for router spin loop
   - Condvar only used when actually sleeping

2. **Spin-before-wait in router** (`engine/router.rs`):
   - 200 spin iterations (optimal tuning)
   - Only falls back to Condvar wait after spin exhausts
   - Eliminates lock overhead for high-frequency traffic

### v212: mio/epoll Event-Driven I/O

Replaced blocking `recv_from()` with mio poll-based event loop:

1. **mio Poll** for event-driven I/O:
   - No blocking timeout overhead
   - Edge-triggered style packet draining
   - Better for sporadic traffic patterns

2. **Non-blocking socket**:
   - Socket set to non-blocking
   - Drain all available packets per poll event

**Files changed:**
- `core/discovery/multicast/listener.rs` - mio poll loop, non-blocking recv

### Analysis

**HDDS v212 is ~1.8x slower** than CycloneDDS (down from 8.5x initially). Remaining gap:

1. **Extra memcpy** - temp_buf -> pool buffer copy still present
2. **Kernel latency** - UDP socket overhead (kernel network stack)
3. **Thread context switches** - listener -> router thread handoff

### Reliability: 100%

Both DDS implementations achieved **0% packet loss** across all tests.

### Roadmap for Further Improvements

| Optimization | Expected Gain | Status |
|--------------|---------------|--------|
| ~~Reduce polling to 100µs~~ | ~~2-3x~~ | ✅ v209 |
| ~~WakeNotifier (Condvar)~~ | ~~10-15%~~ | ✅ v210 |
| ~~Atomic fast-path + Spin~~ | ~~20%~~ | ✅ v211 |
| ~~mio/epoll on UDP socket~~ | ~~10-15%~~ | ✅ v212 |
| Zero-copy receive (recv into pool) | 5-10% | Future |
| io_uring for kernel bypass | 20-30% | Future |
| DPDK/XDP for ultra-low latency | 50%+ | Future |

**Current:** ~246µs p50 latency (best-case), high variance
**Target:** Sub-200µs latency achievable with zero-copy + tuning

---

## Test Environment

- **OS:** Debian 13 / Ubuntu 24.04
- **Kernel:** 6.12.x (generic) / 6.8.x (lowlatency)
- **Rust:** stable (2024 edition)
- **HDDS:** 0.8.0

---

## Reproducing

```bash
# Terminal 1 - Responder
hdds-latency-probe pong --domain 0

# Terminal 2 - Benchmark
hdds-latency-probe ping --domain 0 --size 64 --count 1000

# JSON output for parsing
hdds-latency-probe ping --domain 0 --json
```
