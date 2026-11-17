/*
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 * Copyright (c) 2026 naskel.com
 *
 * Microkit PD C entry stub for the intra-guest Rust subscriber client.
 *
 * Mirror of `client2_rust_wrapper.c`. Only differences:
 *
 *   - `LOCAL_IP` is `10.0.2.18` (vs `10.0.2.17` for the publisher PD)
 *     so virt_rx demuxes inbound RTPS to the right PD by IP.
 *   - Links against a Rust staticlib built with `--features subscriber`
 *     (the publisher and the subscriber share the same `client2_rust`
 *     crate; the Cargo feature selects publisher vs subscriber mode
 *     at compile time, and `echo_loopback.mk` builds two .a artifacts in
 *     separate target-dirs to avoid a feature-mutex compile_error).
 *
 * The struct layout, magic-check call, and Rust entry-point names
 * (`rust_init`, `rust_notified`) are identical to client2_rust:
 * Microkit gives each PD its own ELF + address space, so the
 * duplicated `rust_init` symbol does not clash at link time.
 *
 * Single source of truth for the sDDF ABI is the upstream header
 * `<sddf/network/config.h>`; the Rust mirror lives in
 * `crates/hdds-micro-sel4/src/sel4_ring/mod.rs::Sel4RingInit`, with a
 * compile-time `size_of == 88` lock matching the `_Static_assert`
 * below.
 */

#include <microkit.h>
#include <sddf/network/config.h>
#include <sddf/util/util.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

__attribute__((__section__(".net_client_config")))
net_client_config_t net_config;

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

void hdds_microkit_notify(uint32_t ch)
{
    microkit_notify((microkit_channel)ch);
}

void hdds_dbg_puts(const char *s)
{
    microkit_dbg_puts(s);
}

/*
 * Local IPv4: the loopback driver's MAC-demux means each
 * client PD must have a distinct IP. PD_A (publisher / client2_rust)
 * keeps 10.0.2.17; PD_B (subscriber / client3_rust) takes 10.0.2.18.
 */
/* Overridable at build time (network build passes the LAN address). */
#ifndef HDDS_LOCAL_IP_OCTETS
#define HDDS_LOCAL_IP_OCTETS 10, 0, 2, 18
#endif
static const uint8_t LOCAL_IP[4] = { HDDS_LOCAL_IP_OCTETS };

void init(void)
{
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
