# hdds-micro-sel4

seL4 / Microkit transport for `hdds-micro`, the embedded subset of HDDS.

This crate is standalone. It is not a member of the parent workspace: it
declares its own empty `[workspace]` table and reaches `hdds-micro` by path
(`../hdds-micro`). The parent workspace lists its members explicitly,
so it does not pick this crate up.

## Perimeter

What this tree is: `hdds-micro` (the embedded subset) running inside seL4
Microkit protection domains (PDs), exchanging RTPS over sDDF network queues.

| Piece | Where |
|---|---|
| Packet ring over sDDF queues (`Sel4Ring`), ARP, minimal UDP/IPv4 stack | `src/sel4_ring/` |
| `PacketRing` trait, `Sel4UdpTransport` (implements `hdds_micro::transport::Transport`) | `src/ring.rs`, `src/transport.rs` |
| Host-only mock ring for tests | `src/mock_ring.rs` (feature `std`) |
| PD staticlib: publisher, subscriber and echo modes | `client2_rust/` |
| Microkit system description, C wrappers, loopback driver PD | `microkit/` |
| Build and QEMU gate scripts | `scripts/` |
| Linux-side pub/sub peers built on `hdds-micro` | `host-tools/` |

## What is verified, and where

Every line below was measured on the tree at this commit, or is quoted from
an evidence log with its source named. Nothing here is a projection.

| Claim | How it was checked | Result |
|---|---|---|
| Host tests pass against current `hdds-micro` | `cargo test` in `crates/hdds-micro-sel4/` | 77 pass: 74 unit tests in the library, 3 integration tests in `tests/host_pubsub.rs` |
| Strict clippy (host, all targets) | `cargo clippy --all-targets -- -D warnings` | clean |
| `no_std` build (host target) | `cargo build --no-default-features` | builds |
| Microkit library build | `cargo build --no-default-features --features microkit --target aarch64-unknown-none` | builds |
| Microkit library, strict clippy | same as above with `cargo clippy ... -- -D warnings` | clean |
| PD staticlib, five feature sets (none, `publisher`, `subscriber`, `publisher,intra-guest`, `subscriber,intra-guest`) | `cargo build --release --target aarch64-unknown-none` in `client2_rust/` | all build, strict clippy clean |
| Host tools against current `hdds-micro` | `cargo build` in `host-tools/hdds_pub` and `host-tools/hdds_sub` | build |
| Raspberry Pi 4, intra-guest publisher and subscriber PDs, loopback driver PD in place of a NIC | `evidence/rpi4-inguest-20261004.log` in the maintainers' evidence archive (not in this tree; see `EVIDENCE.md`) | 102325 `RX seq=` lines, 102325 distinct values, the set is 1..102325 (counted from the log) |
| Raspberry Pi 4 8 GB, networking on silicon: sDDF genet NIC driver, publisher and subscriber PDs on the LAN (domain 205, port 58650), a Linux hdds-micro peer on the same segment, both directions, unicast, no discovery | `scripts/run-net-lan.sh`; evidence in the maintainers' archive, available on request. sha256: `uart.txt` `ce0f81d6e86dba1fa8c36b5abb2498a602135804185eaaa1d85088c762b50c85`, `lan.pcap` `2add86109dd2ab131a1789e08d0016e3467ea16155ca4b6a2130aeed0abaf06d`, `logs/linux-sub.log` `00226851d30501cab61fc6af22ddbb69f9d6a14cb51d70c16aa4cf86687840da`, `logs/linux-pub.log` `1368fb60fc457d51c2f311f43f97f86aef41f262f38d7ae296bd028cf217cb59`, image `loader.img` `6c1a0b48a830e91e05ecc2ed32c48e2c173b95df7c6d64f351b281cd78f38add` | U-Boot fetched the image over TFTP (3298580 bytes) and the seL4 PDs initialised. seL4 to Linux: 100 samples, 100 distinct, sequence 1..100, no warning. Linux to seL4: 100 samples, 100 distinct, sequence 1..100 (UART), no warning. The publisher PD answered ARP from its own MAC and sent 100 DATA datagrams to the peer. |
| QEMU `qemu_virt_aarch64`, intra-guest pub/sub, on this tree, Microkit SDK 2.3.1 | `scripts/test-inguest.sh` (seal check and RX count) | PASS: 758 `RX seq=` lines, 758 distinct, the set is 1..758; no fault, warning or decode failure (counted from the log) |
| QEMU `qemu_virt_aarch64`, three directions (seL4 to Linux, Linux to seL4, intra-guest) | logs under `evidence/logs-20260901/` in the maintainers' evidence archive; see `EVIDENCE.md` | run of 2026-09-01 on an earlier revision of the code; not re-run here |

The QEMU and Pi logs are kept by the maintainers and available on request.
They were produced by an earlier revision of the GUID prefix
derivation (see below). They are provenance, not a result for this tree.

## What is NOT verified

1. **Networking on silicon, beyond the unicast exchange above.** Not run: a
   full HDDS (`crates/hdds`) peer. hdds-micro has no SPDP or SEDP, and the full
   reader binds only writers that SEDP has discovered; the crate has no API to
   declare a remote writer by hand. Not run: SPDP multicast, sustained or long
   runs, and throughput.
2. **DMA cache maintenance.** The tree still contains no cache maintenance
   operations (a search of `src/`, `client2_rust/`, `microkit/` and `scripts/`
   for `dc cvac`, `dc civac` and `dc ivac` finds none). The Pi 4 GENET is not
   DMA-coherent (no `dma-coherent` in the firmware DTB), and the sDDF genet
   driver performs no cache maintenance either. The DMA-boundary operations
   come from sDDF's virtualisers (`cache_clean` in `virt_tx`,
   `cache_clean_and_invalidate` in `virt_rx`). The run in the table moved 200
   samples with no decode error. It is not a stress test.
3. **Throughput.** Received samples are printed to the kernel debug UART
   (`microkit_dbg_puts`), so the serial line bounds the observable rate. No
   throughput figure has been measured.
4. **Multicast discovery (SPDP).** Discovery is unicast only. The evidence
   notes record that the stock sDDF `virt_rx` path drops multicast MAC frames
   that do not match the driver's filter. That observation is quoted from
   `evidence/sel4-microkit-20260901.md` in the maintainers' archive and was not re-checked
   against the sDDF sources here.
5. **Time.** A PD cannot read the Arm generic timer. seL4 traps
   `mrs cntvct_el0` from EL0: the first QEMU run of this tree faulted both
   PDs on that read (fault ESR class 0x18, a trapped system-register
   access). ARP retries are therefore paced by notifications, not by time:
   `tick_arp` is called once per notification, and `ARP_REQUEST_DEADLINE_TICKS`
   and `ARP_FAILED_BACKOFF_TICKS` count notifications. Their values (16 and
   256) are a judgment, not measured. A lost ARP reply is retried only when the
   next notification arrives. Wall-clock pacing needs a timer driver PD, which
   is not wired.
6. **Per-boot GUID instance.** Each PD passes a constant instance value to
   `MicroParticipant::with_instance` (`PD_INSTANCE` in `client2_rust/src`).
   The PD has no per-boot entropy source, so the GUID prefix repeats across
   reboots. Wiring a boot counter or hardware random value is open.
7. **GUID derivation changed.** The PD used to derive its GUID prefix with a
   local copy of a scheme that differed from `hdds-micro`'s derivation (it
   carried no vendor id and no instance value). It now uses
   `MicroParticipant::with_instance`, so the derivation is `hdds-micro`'s own.
   The QEMU and Pi runs in the evidence used the old prefix. This tree has
   not been re-run on QEMU or on the Pi since the change.
8. **Other integration gates.** Only the intra-guest gate (`scripts/test-inguest.sh`)
   was run on this tree. The two interop gates (`scripts/test-interop-sel4-to-linux.sh`,
   `scripts/test-interop-linux-to-sel4.sh`) need a
   host-side subscriber and publisher setup that was not run here.
9. **Cold-start receive gap (vendored driver, not patched).** The client PDs
   print their ready markers before the genet driver has finished
   initialising. `sddf/drivers/network/genet/ethernet.c` (sDDF 99034b4,
   unmodified here) busy-waits for PHY auto-negotiation at line 317, arms
   the RX descriptors only after it (line 436), sets `CMD_RX_EN` at line 446
   and unmasks the RX interrupt at line 453. Frames that arrive earlier are
   dropped by the MAC. Measured on the Pi: the NIC starts receiving 3.1 to
   3.4 s after the ready markers (three cold boots lost 157 and 18 samples
   when traffic started at ready and ready+3 s, and none at ready+10 s).
   The cause is inferred from the code, not timed. Harness mitigation: wait
   5 s after the ready markers before sending traffic. Evidence: the
   cold-start analysis in the maintainers' archive, available on request.
10. **Oversized frames.** The transport consumes a frame that does not fit
   the caller's buffer (`Sel4UdpTransport::try_recv`, scratch of `SLOT_MTU`
   octets). A frame larger than `SLOT_MTU` (1472 octets, the UDP payload of a
   1500-octet Ethernet frame) could not be consumed and would stall the
   drain. The genet MTU rules this out; a jumbo-frame driver must revisit it.

## Build and test

```bash
# Host build and all tests (default feature: std)
cargo test --manifest-path crates/hdds-micro-sel4/Cargo.toml

# no_std compile check
cargo build --manifest-path crates/hdds-micro-sel4/Cargo.toml --no-default-features

# Microkit library, strict clippy
cargo clippy --manifest-path crates/hdds-micro-sel4/Cargo.toml --no-default-features \
    --features microkit --target aarch64-unknown-none -- -D warnings

# Microkit PD staticlib (publisher mode shown)
cargo build --manifest-path crates/hdds-micro-sel4/client2_rust/Cargo.toml \
    --target aarch64-unknown-none --release --features publisher
```

Features of `hdds-micro-sel4`:

- `std` (default): host build, enables `MockRing` and the host tests.
- `microkit`: the seL4 / Microkit backend (`Sel4Ring`). Off by default.
- `intra-guest`: the intra-guest pair. It moves `LOCAL_PORT` from 1235 to 33650,
  which is the base port of domain 105 under the RTPS port formula
  (7400 + 250 x 105). The feature name is kept because the scripts and the
  Makefiles select it by name.

## Design notes

- **Layout.** The crate sits under `crates/hdds-micro-sel4/` with
  its own `[workspace]`, so the parent workspace, whose members are listed
  explicitly, does not see it.
- **MTU.** The transport asks the ring for its MTU (`ring.slot_mtu()`), so
  the sDDF binding reports the value the driver negotiated. `MockRing`
  defaults to 1472.
- **`Transport::recv` under `no_std`.** It returns an error instead of
  spinning, because a bare PD must drive RX with `try_recv` and its own
  notification wait.
- **Debug output.** `client2_rust/src/dbg.rs` writes lines through
  `microkit_dbg_puts`; the test harnesses read them from the QEMU serial.

## Layout

- `src/ring.rs`: `PacketRing` trait, the contract between the transport and
  whatever sits behind it (a mock, or sDDF).
- `src/mock_ring.rs`: host-only `MockRing` and the `mock_pair()` helper.
- `src/locator.rs`: `Locator` to `(ipv4, port)` conversions.
- `src/transport.rs`: `Sel4UdpTransport<R: PacketRing>`.
- `src/sel4_ring/`: the sDDF-backed ring, ARP and the queue layout.
- `tests/host_pubsub.rs`: two `MicroParticipant`s exchanging samples over
  `MockRing`.
- `client2_rust/`: the PD staticlib, one mode per feature.
- `microkit/`: system description (`*.mk`, `meta*.py`, `single_core.json`),
  C wrappers and the loopback driver PD.
- `scripts/`: build and gate scripts. `docs/`: environment notes and mock
  limitations. `EVIDENCE.md`: where the recorded runs are and their checksums.
