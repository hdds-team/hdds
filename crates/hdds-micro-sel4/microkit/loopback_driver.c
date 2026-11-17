/*
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 * Copyright (c) 2026 naskel.com
 *
 * hdds-micro-sel4 intra-guest: loopback "driver" PD.
 *
 * Acts as a drop-in replacement for the real sDDF Ethernet driver
 * from `net_virt_tx.elf` and `net_virt_rx.elf`'s point of view, but
 * never touches hardware. Instead, every TX buffer the virt_tx mux
 * publishes is `memcpy`'d into a freshly-acquired RX buffer and
 * enqueued onto rx_drv.active, where virt_rx then demuxes by
 * destination MAC and routes the bytes to the appropriate client PD.
 *
 * Net result: two seL4 client PDs running the same DDS stack can
 * exchange UDP datagrams without their packets ever leaving the
 * guest (no SLIRP, no virtio-net, no host data plane).
 *
 * Policies: data regions are exposed through `.device_resources`
 * (see below), a TX frame is dropped when no RX buffer is free, the
 * accepted length range is 14..2048, a bad paddr is FATAL, and MAC
 * policy is delegated to virt_rx. Risk classes handled:
 *
 * - `tx_buf.len < 14`  : runt, virt_rx.c:90 reads Ethernet header
 *                        unconditionally => drop + counter.
 * - `tx_buf.len > 2048`: oversize, would overrun `memcpy` =>
 *                        drop + counter.
 * - bad `tx_buf.io_or_offset`: config corruption, virt_tx's
 *                        `extract_offset` asserts on the same
 *                        condition (virt_tx.c:80-95). We assert
 *                        eagerly to give a clearer abort message.
 * - rx_drv.free empty : drop + counter, no head-of-line stash.
 *                        virt_rx signals us when buffers return
 *                        (virt_rx.c:132,208).
 * - unknown destination MAC: not our problem. virt_rx already
 *                        handles exact-match / broadcast / drop
 *                        (virt_rx.c:40-64, 91-117).
 */

#include <os/sddf.h>
#include <sddf/network/queue.h>
#include <sddf/network/config.h>
#include <sddf/network/constants.h>
#include <sddf/resources/device.h>
#include <sddf/util/util.h>
#include <sddf/util/printf.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* sdfgen fills these at load time with the validated config blobs. */
__attribute__((__section__(".net_driver_config"))) net_driver_config_t config;
__attribute__((__section__(".device_resources")))  device_resources_t   device_resources;

/*
 * ABI choice: data regions are exposed through
 * `.device_resources` as fake `device_region_resource_t` slots
 * (no real MMIO).
 *
 *   slot 0    = RX data region (one shared MR, read-write).
 *   slots 1..N = TX client data regions (one MR per client, read-only).
 *
 * The 64-region ceiling of `device_resources_t` translates into a
 * hard cap of 63 TX clients in this driver. The system has 2 clients
 * (pub + sub) so the cap is comfortably above practical needs; if a
 * future build exceeds 63 clients, the ABI would have to move to a
 * custom `.loopback_driver_config` section.
 */
#define LOOPBACK_RX_SLOT_IDX        0
#define LOOPBACK_MAX_TX_CLIENTS     (DEVICE_MAX_REGIONS - 1)
#define LOOPBACK_MIN_FRAME_LEN      14  /* sizeof(struct ethernet_header) */

typedef struct tx_client {
    uintptr_t data_vaddr;   /* base of this client's TX data MR in our AS */
    uintptr_t io_addr;      /* base paddr; descriptors live in [io_addr, io_addr+size) */
    uint64_t  size;         /* MR size; must be a multiple of NET_BUFFER_SIZE */
} tx_client_t;

typedef struct loopback_state {
    net_queue_handle_t tx_queue_drv;
    net_queue_handle_t rx_queue_drv;

    tx_client_t tx_clients[LOOPBACK_MAX_TX_CLIENTS];
    uint8_t     tx_num_clients;

    uintptr_t rx_data_vaddr;
    uintptr_t rx_data_io_addr;
    uint64_t  rx_data_size;

    /* Observability - surfaced via `sddf_dprintf` in debug builds. */
    uint64_t drops_bad_length;
    uint64_t drops_no_rx_slot;
} loopback_state_t;

static loopback_state_t state;

/*
 * Walk the TX client table to translate a driver-side paddr into the
 * (client_index, vaddr) pair we need for memcpy. O(N) with N <= 63;
 * negligible at the traffic level of two clients. A binary search or
 * per-MR mapping table would only be warranted with many clients.
 *
 * Returns the client index, or -1 if the paddr is outside every
 * known region. Callers MUST treat -1 as fatal: a paddr we cannot
 * route would also fail virt_tx's `extract_offset` on the way back
 * (`virt_tx.c:80-95` asserts), so the system is already corrupt at
 * that point - better to abort here with a clear cause.
 */
static int tx_client_for_paddr(uintptr_t paddr, uintptr_t *out_vaddr)
{
    for (uint8_t i = 0; i < state.tx_num_clients; i++) {
        uintptr_t base = state.tx_clients[i].io_addr;
        uint64_t  size = state.tx_clients[i].size;
        if (paddr >= base && paddr < base + size) {
            *out_vaddr = state.tx_clients[i].data_vaddr + (paddr - base);
            return (int)i;
        }
    }
    return -1;
}

/*
 * Map an RX driver-side paddr (as carried in net_buff_desc_t.io_or_offset
 * after `net_buffers_init`) back to a vaddr in our address space.
 * The mapping is a simple linear offset: net_buffers_init seeds
 * descriptors with `(NET_BUFFER_SIZE * i) + base_addr`.
 *
 * The caller passes the descriptor's
 * io_or_offset plus the post-copy length; both must fall inside the
 * RX data region. A bad paddr from a malicious or drifted virt_rx
 * config would otherwise turn `memcpy(rx_vaddr, ...)` into an out-of-
 * bounds write before any downstream assertion fires. We treat the
 * mismatch as FATAL for the same reason `tx_client_for_paddr`
 * does - there is no clean recovery and silently dropping would
 * just defer the symptom.
 */
static uintptr_t rx_paddr_to_vaddr(uintptr_t paddr, uint32_t len)
{
    uintptr_t base = state.rx_data_io_addr;
    uint64_t  size = state.rx_data_size;
    if (paddr < base || paddr - base > size || (uint64_t)len > size - (paddr - base)) {
        sddf_dprintf("LOOPBACK|FATAL: RX paddr 0x%lx len %u outside region [0x%lx, +0x%lx)\n",
                     paddr, (unsigned)len, base, (uint64_t)size);
        assert(false && "loopback: RX paddr is outside the RX data region");
    }
    return state.rx_data_vaddr + (paddr - base);
}

/*
 * Core dance: drain tx_drv.active, reflect each buffer into rx_drv.active,
 * return the TX descriptor to tx_drv.free. Idempotent + cheap when both
 * queues are empty (single bounded loop).
 *
 * Notification batching follows the same "request signal then re-check"
 * pattern as `virt_tx.c:64-71`: we set the signal-bit only after the
 * inner loop drains, and re-check the queue to avoid the well-known
 * sDDF lost-wake-up race.
 */
static void loopback_drain_tx(void)
{
    bool reprocess               = true;
    bool need_signal_rx_active   = false;
    bool need_signal_tx_free     = false;

    while (reprocess) {
        while (!net_queue_empty_active(&state.tx_queue_drv)) {
            net_buff_desc_t tx_buf;
            int err = net_dequeue_active(&state.tx_queue_drv, &tx_buf);
            assert(!err);

            /* ---- 1. Length guard.
             *
             * `virt_tx` only checks offset alignment + bounds
             * (`virt_tx.c:46-48`); it does NOT cap `buf.len`. A
             * malicious or buggy client could publish a descriptor
             * with `len = 0xFFFFFFFF` or `len < 14`. Either case
             * is unsafe: `memcpy` would walk off the TX data region,
             * and `virt_rx` parses `struct ethernet_header`
             * unconditionally (`virt_rx.c:90`) so runts would
             * later read past the Eth header. Drop both. */
            if (tx_buf.len < LOOPBACK_MIN_FRAME_LEN
                || tx_buf.len > NET_BUFFER_SIZE) {
                state.drops_bad_length++;
                err = net_enqueue_free(&state.tx_queue_drv, tx_buf);
                assert(!err);
                need_signal_tx_free = true;
                continue;
            }

            /* ---- 2. paddr -> vaddr translation.
             *
             * Bad paddr is config corruption (a client region
             * mismatch, or sdfgen drift between net_virt_tx and
             * the loopback). Cannot recover cleanly: feeding the
             * descriptor back to tx_drv.free would just defer the
             * abort to virt_tx's `tx_return -> extract_offset`
             * assert (`virt_tx.c:80-95`). Fail fast here. */
            uintptr_t tx_vaddr = 0;
            int       client   = tx_client_for_paddr(tx_buf.io_or_offset,
                                                     &tx_vaddr);
            if (client < 0) {
                sddf_dprintf("LOOPBACK|FATAL: TX paddr 0x%lx outside all client regions\n",
                             tx_buf.io_or_offset);
                assert(false && "loopback: TX paddr is outside all known client regions");
            }

            /* ---- 3. Acquire an RX-free buffer (drop if empty).
             *
             * Drop-on-no-free is BEST_EFFORT semantics, consistent
             * with the existing `copy.c` shortage path
             * (`copy.c:27-28,58-64`). When virt_rx returns buffers
             * to free, it notifies us (`virt_rx.c:132,208`) which
             * re-runs this drain on the next `notified()` cycle. */
            if (net_queue_empty_free(&state.rx_queue_drv)) {
                state.drops_no_rx_slot++;
                err = net_enqueue_free(&state.tx_queue_drv, tx_buf);
                assert(!err);
                need_signal_tx_free = true;
                continue;
            }

            net_buff_desc_t rx_buf;
            err = net_dequeue_free(&state.rx_queue_drv, &rx_buf);
            assert(!err);

            /* ---- 4. memcpy TX payload into the RX slot.
             *
             * No cache maintenance: virt_tx's `cache_clean()` and
             * virt_rx's `cache_clean_and_invalidate()` exist for
             * DMA boundaries against a real NIC. Our `memcpy` is
             * CPU<->CPU inside the same coherent memory model
             * (single-core PIPT on QEMU virt_aarch64; hardware
             * coherency for normal cacheable memory on multi-core
             * ARMv8). On a non-coherent SoC this must be revisited. */
            uintptr_t rx_vaddr = rx_paddr_to_vaddr(rx_buf.io_or_offset, tx_buf.len);
            memcpy((void *)rx_vaddr, (void *)tx_vaddr, tx_buf.len);

            /* ---- 5. Publish the filled RX buffer.
             *
             * `virt_rx` will inspect the Ethernet destination MAC
             * field (`virt_rx.c:40-64`) and demux to the matching
             * client, fan out broadcast, or return the buffer to
             * driver-free for unknown MACs (`virt_rx.c:91-117`).
             * Loopback does NOT short-circuit unknown-MAC frames
             * - virt_rx is the single source of truth for MAC
             * policy, and duplicating that logic here would invite
             * drift. */
            rx_buf.len = tx_buf.len;
            err = net_enqueue_active(&state.rx_queue_drv, rx_buf);
            assert(!err);
            need_signal_rx_active = true;

            (void)client;

            /* ---- 6. Return the TX descriptor to driver-free.
             *
             * virt_tx's next `tx_return()` (`virt_tx.c:80-113`)
             * extracts the client index from this paddr and
             * routes the descriptor back to that client's free
             * queue. The descriptor MUST carry the same
             * io_or_offset we dequeued; we never modify it. */
            err = net_enqueue_free(&state.tx_queue_drv, tx_buf);
            assert(!err);
            need_signal_tx_free = true;
        }

        /* Standard sDDF "request signal then re-check" idiom - mirrors
         * `virt_tx.c:64-71`. The fences embedded in
         * `net_request_signal_active` / `net_queue_empty_active`
         * (`queue.h:243-249,74-79`) close the lost-wake-up window.
         * Note: these are release fences (`fence.h:31-39`), not
         * full SeqCst - sufficient because we are the sole consumer
         * of tx_drv.active and the sole producer for rx_drv.active. */
        net_request_signal_active(&state.tx_queue_drv);
        reprocess = false;
        if (!net_queue_empty_active(&state.tx_queue_drv)) {
            net_cancel_signal_active(&state.tx_queue_drv);
            reprocess = true;
        }
    }

    /* Batched notifications - one per channel, regardless of how
     * many packets passed through this drain cycle.
     *
     * IMPORTANT: Microkit's `deferred_notify` keeps a single pending
     * channel per PD entry; calling it twice for different channels
     * silently overwrites the first slot. That would wedge the
     * system: the virt_rx notify would be lost behind a virt_tx one
     * and the broadcast ARP would never reach the copiers. The imx
     * eth driver (drivers/network/imx/ethernet.c)
     * uses `sddf_notify` (immediate) for both edges; we follow the
     * same pattern. */
    if (need_signal_rx_active
        && net_require_signal_active(&state.rx_queue_drv)) {
        net_cancel_signal_active(&state.rx_queue_drv);
        sddf_notify(config.virt_rx.id);
    }
    if (need_signal_tx_free
        && net_require_signal_free(&state.tx_queue_drv)) {
        net_cancel_signal_free(&state.tx_queue_drv);
        sddf_notify(config.virt_tx.id);
    }
}

void notified(sddf_channel ch)
{
    /* Both channels drive the same TX->RX reflect loop:
     *
     *  - virt_tx.id : new TX work in tx_drv.active.
     *  - virt_rx.id : RX free buffers returned, retry any stalled TX.
     *
     * Other channel ids are unexpected (no IRQ wiring, no extra
     * peers) - we silently ignore them rather than aborting, so a
     * future system-spec extension that adds a benign signal
     * doesn't crash the PD. */
    if (ch == config.virt_tx.id || ch == config.virt_rx.id) {
        loopback_drain_tx();
    }
}

/*
 * Read the device_resources blob into state.tx_clients[] /
 * state.rx_data_*. Asserts each invariant the spec (and meta.py)
 * promised.
 */
static void parse_device_resources(void)
{
    assert(device_resources_check_magic(&device_resources));
    assert(device_resources.num_irqs == 0
           && "loopback driver does not consume IRQs");
    assert(device_resources.num_regions >= 1
           && "loopback driver needs at least 1 region (RX data)");
    assert(device_resources.num_regions <= 1 + LOOPBACK_MAX_TX_CLIENTS
           && "loopback driver: too many TX client regions (cap=63)");

    /* Slot 0 = RX data region. */
    state.rx_data_vaddr   = (uintptr_t)device_resources
                                       .regions[LOOPBACK_RX_SLOT_IDX]
                                       .region.vaddr;
    state.rx_data_io_addr = device_resources.regions[LOOPBACK_RX_SLOT_IDX].io_addr;
    state.rx_data_size    = device_resources.regions[LOOPBACK_RX_SLOT_IDX].region.size;
    assert(state.rx_data_size >= config.virt_rx.num_buffers * (uint64_t)NET_BUFFER_SIZE
           && "loopback driver: RX data region too small for virt_rx.num_buffers");

    /* Slots 1..N = TX client data regions. */
    state.tx_num_clients = device_resources.num_regions - 1;
    for (uint8_t i = 0; i < state.tx_num_clients; i++) {
        const device_region_resource_t *r =
            &device_resources.regions[i + 1];
        state.tx_clients[i].data_vaddr = (uintptr_t)r->region.vaddr;
        state.tx_clients[i].io_addr    = r->io_addr;
        state.tx_clients[i].size       = r->region.size;
        assert(state.tx_clients[i].size % NET_BUFFER_SIZE == 0
               && "loopback driver: TX client region size must be a multiple of NET_BUFFER_SIZE");
    }
}

void init(void)
{
    assert(net_config_check_magic(&config));
    parse_device_resources();

    net_queue_init(&state.tx_queue_drv,
                   config.virt_tx.free_queue.vaddr,
                   config.virt_tx.active_queue.vaddr,
                   config.virt_tx.num_buffers);
    net_queue_init(&state.rx_queue_drv,
                   config.virt_rx.free_queue.vaddr,
                   config.virt_rx.active_queue.vaddr,
                   config.virt_rx.num_buffers);

    /*
     * rx_drv.free is seeded by
     * virt_rx itself (virt_rx.c:206 calls net_buffers_init on the
     * same shared queue, with paddrs derived from its own
     * config.data.io_addr). A second seed here would either overflow
     * the free queue or duplicate descriptors; either way virt_rx's
     * subsequent operations corrupt. virt_rx notifies us when the
     * free queue gains content (virt_rx.c:207-209), so we can rely
     * on its post-init kick rather than seeding ourselves.
     */
    state.drops_bad_length = 0;
    state.drops_no_rx_slot = 0;

    sddf_dprintf("LOOPBACK|INIT: %u TX clients, RX cap=%u, TX cap=%u\n",
                 state.tx_num_clients,
                 config.virt_rx.num_buffers,
                 config.virt_tx.num_buffers);
}
