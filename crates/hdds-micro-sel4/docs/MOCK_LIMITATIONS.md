# MockRing - known deviations vs. a real sDDF net ring

`MockRing` exists for host testing. It is deliberately less strict
than the real seL4 / sDDF binding (`Sel4Ring`). The deviations are
listed here.

## Not enforced by the mock

1. **Destination routing.** `enqueue_tx(..., dest_ip, dest_port)` ignores
   the two addressing fields - a paired `MockRing` is a direct pipe
   between two peers, so every packet reaches the other side
   regardless. `Sel4Ring` honors these fields (it resolves `dest_ip`
   through ARP and stamps `dest_port` in the UDP header); a multi-PD
   deployment with three or more endpoints cannot be driven by
   `MockRing` alone.

2. **Buffer ownership.** sDDF uses a free-list / active-list pair of
   shared-memory queues with strict ownership transitions (client <->
   virtualizer <-> driver). `MockRing` just clones bytes via `Vec::to_vec`.
   `Sel4Ring` copies the datagram into a claimed TX slot inside
   `enqueue_tx` and publishes the slot to the active queue; the caller
   never holds a reference into shared memory.

3. **Zero-copy TX.** Real sDDF offers zero-copy semantics (the caller
   writes into a slot already mapped in shared memory). The `PacketRing`
   trait as defined in `ring.rs` copies. A zero-copy path would need a
   new `reserve_tx_slot() -> &mut [u8]` style method, which does not
   exist.

4. **Backpressure fidelity.** `MockRing` with `capacity = 0` is
   unbounded; with `capacity > 0` it rejects enqueue when full. Real
   sDDF backpressure is governed by the free-list being empty - the
   numbers are what the system designer provisioned. Any code that
   relies on "this many packets will fit" must read from `slot_mtu()`
   and from the capacity configured by the `.system` file, not guess.

5. **Multicast.** Not modelled. `MockRing` carries unicast only. sDDF
   net does not natively multicast either - RTPS multicast on seL4
   will need either a kernel-side demux or a fan-out component.

## What the mock *does* get right

- FIFO ordering per lane.
- Separate RX / TX lanes (no self-loop).
- `TooLarge` on oversized enqueue; on RX a too-small caller buffer does
  **not** drop the packet (it is pushed back to the head of the queue).
- Capacity enforcement when configured, returning `RingError::Full` -
  same variant the real binding surfaces.

Anything outside this list is "nice coincidence", not a contract.
