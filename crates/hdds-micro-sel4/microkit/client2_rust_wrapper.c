/*
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 * Copyright (c) 2026 naskel.com
 *
 * Microkit PD C entry stub for the Rust client. Validates
 * the sDDF .net_client_config blob, builds a Sel4RingInit struct
 * matching the Rust binding's repr(C) layout, and hands control to
 * the Rust staticlib (libclient2_rust.a).
 *
 * Single source of truth for the sDDF ABI is the upstream header
 * <sddf/network/config.h>; the Rust mirror is in
 * crates/hdds-micro-sel4/src/sel4_ring/mod.rs::Sel4RingInit, with a compile-time
 * size_of==88 lock matching the _Static_assert below.
 */

#include <microkit.h>
#include <sddf/network/config.h>
#include <sddf/util/util.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* sdfgen fills this section at load time with the validated config blob */
__attribute__((__section__(".net_client_config")))
net_client_config_t net_config;

/*
 * Mirror of Rust's `Sel4RingInit` (crates/hdds-micro-sel4/src/sel4_ring/mod.rs).
 * Both sides hold size_of == 88; if either side drifts, the
 * _Static_assert below or the Rust `const _: () = ...` will fail
 * the build, before any boot misbehavior can happen.
 */
struct sel4_ring_init {
    uint8_t  mac[6];                /* off 0  */
    uint8_t  _pad0[2];              /* off 6  */

    void    *rx_free_header;        /* off 8  */
    void    *rx_active_header;      /* off 16 */
    void    *rx_data_vaddr;         /* off 24 */
    uint64_t rx_data_size;          /* off 32 */
    uint16_t rx_num_buffers;        /* off 40 */
    uint8_t  rx_channel_id;         /* off 42 */
    uint8_t  _pad1;                 /* off 43 */
                                    /* off 44..47 IMPLICIT pad to align next ptr */
    void    *tx_free_header;        /* off 48 */
    void    *tx_active_header;      /* off 56 */
    void    *tx_data_vaddr;         /* off 64 */
    uint64_t tx_data_size;          /* off 72 */
    uint16_t tx_num_buffers;        /* off 80 */
    uint8_t  tx_channel_id;         /* off 82 */
    uint8_t  _pad2;                 /* off 83 */

    uint8_t  local_ip[4];           /* off 84 */
};
_Static_assert(sizeof(struct sel4_ring_init) == 88,
               "Sel4RingInit ABI drift - does not match Rust side");

extern void rust_init(const struct sel4_ring_init *init);
extern void rust_notified(uint32_t ch);

/*
 * `microkit_notify` is `static inline` in <microkit.h>, so it does not
 * exist as a linker symbol. Expose it under a Rust-friendly name that
 * does. The Rust binding's `extern "C"` declaration targets this name.
 */
void hdds_microkit_notify(uint32_t ch)
{
    microkit_notify((microkit_channel)ch);
}

/*
 * Same trampoline for the kernel debug putchar path. `microkit_dbg_puts`
 * is a `static inline` in <microkit.h> (debug builds only), so we expose
 * a linker-visible wrapper for Rust callers. The subscriber
 * uses this to log "RX seq=N ..." lines straight to the QEMU serial,
 * without depending on a serial-PD client wiring.
 *
 * The kernel debug UART is only available in the `debug` Microkit
 * configuration (CONFIG_PRINTING in the seL4 kernel). Release builds
 * link against a no-op variant.
 */
void hdds_dbg_puts(const char *s)
{
    microkit_dbg_puts(s);
}

/*
 * Hard-coded local IPv4. SLIRP hands out 10.0.2.{15, 16, ...}
 * to the existing clients (client0 / client1 lwIP); client2_rust gets
 * 10.0.2.17. There is no DHCP client in this PD.
 */
/* Overridable at build time (network build passes the LAN address). */
#ifndef HDDS_LOCAL_IP_OCTETS
#define HDDS_LOCAL_IP_OCTETS 10, 0, 2, 17
#endif
static const uint8_t LOCAL_IP[4] = { HDDS_LOCAL_IP_OCTETS };

void init(void)
{
    /* The same magic check every sDDF C component runs - gates against
     * sdfgen-side wire-format drift before any pointer is dereferenced. */
    assert(net_config_check_magic(&net_config));

    struct sel4_ring_init init = {
        .mac = {
            net_config.mac_addr[0], net_config.mac_addr[1],
            net_config.mac_addr[2], net_config.mac_addr[3],
            net_config.mac_addr[4], net_config.mac_addr[5],
        },
        ._pad0 = { 0, 0 },

        .rx_free_header   = net_config.rx.free_queue.vaddr,
        .rx_active_header = net_config.rx.active_queue.vaddr,
        .rx_data_vaddr    = net_config.rx_data.vaddr,
        .rx_data_size     = net_config.rx_data.size,
        .rx_num_buffers   = net_config.rx.num_buffers,
        .rx_channel_id    = net_config.rx.id,
        ._pad1            = 0,

        .tx_free_header   = net_config.tx.free_queue.vaddr,
        .tx_active_header = net_config.tx.active_queue.vaddr,
        .tx_data_vaddr    = net_config.tx_data.vaddr,
        .tx_data_size     = net_config.tx_data.size,
        .tx_num_buffers   = net_config.tx.num_buffers,
        .tx_channel_id    = net_config.tx.id,
        ._pad2            = 0,

        .local_ip = { LOCAL_IP[0], LOCAL_IP[1], LOCAL_IP[2], LOCAL_IP[3] },
    };

    rust_init(&init);
}

void notified(microkit_channel ch)
{
    rust_notified((uint32_t)ch);
}
