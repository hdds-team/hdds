# Copyright 2026, naskel.com
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""
hdds-micro-sel4 intra-guest meta program.

Builds an SDF where two Rust client PDs exchange UDP datagrams over a
loopback "driver" PD, with zero host-side data plane. Bypasses
`Sddf.Net` entirely because the closed-source `libcsdfgen.so` does not
expose the per-client TX data MRs that the loopback driver needs to
map into its own AS for `memcpy`. We hand-wire all MRs, channels,
maps and serialise the four `net_*_config_t` plus `device_resources_t`
blobs ourselves; the binary layouts come straight from
`include/sddf/network/config.h` and `include/sddf/resources/device.h`
of the sDDF checkout.

System topology:

      client2_rust (PD_A, publisher, 10.0.2.17)
        |   ^
        v   |
   c2_copier (RX side only - TX is direct to virt_tx)
        |   ^
        v   |
       virt_rx  virt_tx
         ^      |
         |      v
       loopback_driver
         |      ^
         v      |
       virt_rx  virt_tx
         ^      |
         |      v
   c3_copier
        |   ^
        v   |
      client3_rust (PD_B, subscriber, 10.0.2.18)

(virt_rx is shared between both copiers, same for virt_tx aggregating
TX from both clients. virt_rx demuxes incoming frames by destination
MAC to the matching copier-then-client chain.)
"""

import argparse
import os
import struct
import subprocess
import sys

from sdfgen import SystemDescription, DeviceTree

ProtectionDomain = SystemDescription.ProtectionDomain
MemoryRegion = SystemDescription.MemoryRegion
Map = SystemDescription.Map
Channel = SystemDescription.Channel

# ----- sDDF constants (mirror include/sddf/network/ of the sDDF checkout) -----
SDDF_NET_MAGIC = b"sDDF\x05"
DEVICE_MAGIC = b"sDDF\x01"
SDDF_NET_MAX_CLIENTS = 64
DEVICE_MAX_REGIONS = 64
DEVICE_MAX_IRQS = 64
NET_BUFFER_SIZE = 2048

# Per-client tunables matching the stock sDDF echo_server build.
# 512 buffers x 2 KiB = 1 MiB data MR (matches `DATA_MR_SIZE`).
#
# IMPORTANT: the driver-side RX num_buffers
# MUST NOT exceed `DATA_MR_SIZE / NET_BUFFER_SIZE`. virt_rx.c:206
# seeds rx_drv.free with paddrs `(NET_BUFFER_SIZE * i) + base_paddr`
# for i in [0, num_buffers). Any i >= 512 would point past the
# shared RX data MR (and bleed into PADDR_CLIENT2_TX = base+0x100000),
# triggering a page fault on the first overflow buffer. So we fix
# driver-side RX num_buffers = NUM_BUFFERS_PER_CLIENT (512).
#
# The driver-side TX num_buffers does not have the same constraint
# (tx_data is per-client, each in its own MR), but we keep it at 512
# too for symmetry - the 0x7000 queue MR has headroom for up to ~1700
# entries, so we are nowhere near a queue-capacity ceiling either.
NUM_BUFFERS_PER_CLIENT = 512
NUM_BUFFERS_DRIVER = NUM_BUFFERS_PER_CLIENT  # see IMPORTANT note above
QUEUE_MR_SIZE_PER_CLIENT = 0x3000   # free queue + active queue each
QUEUE_MR_SIZE_DRIVER = 0x7000        # aggregated; same as echo_server
DATA_MR_SIZE = 0x100000               # 1 MiB per data region
BUFFER_METADATA_MR_SIZE = 0x1000      # >= 4 * driver_num_buffers

# Pre-assigned physical addresses for the DMA-facing data MRs. Live in
# the same 0x5f000000-0x60000000 band Microkit's loader picked for the
# stock echo_server build, so we know the kernel/loader leaves it
# free on qemu_virt_aarch64.
PADDR_RX_DATA       = 0x5F000000
PADDR_CLIENT2_TX    = 0x5F100000
PADDR_CLIENT3_TX    = 0x5F200000

# Statically assigned client MAC addresses. Distinct from each other
# (virt_rx demuxes by exact-match) and not in the upstream
# echo_server's pool to avoid confusion if both builds run in
# succession on the same host.
MAC_CLIENT2 = (0x52, 0x54, 0x01, 0x00, 0x00, 0x17)  # 10.0.2.17
MAC_CLIENT3 = (0x52, 0x54, 0x01, 0x00, 0x00, 0x18)  # 10.0.2.18


# ----- Struct packers --------------------------------------------------
# All sizes come from sizeof() of the matching C structs in config.h /
# device.h, hand-computed under the SysV ARM64 rules (every aggregate
# is naturally aligned to its largest member). Tests at the bottom of
# this file (see __main__ assertions) lock these sizes against
# loopback_driver.c's `_Static_assert` markers.

def _pad(data: bytes, total: int) -> bytes:
    assert len(data) <= total, f"struct too large: {len(data)} > {total}"
    return data + b"\x00" * (total - len(data))


def pack_region(vaddr: int, size: int) -> bytes:
    """region_resource_t - 16 bytes."""
    return struct.pack("<QQ", vaddr, size)


def pack_device_region(vaddr: int, size: int, io_addr: int) -> bytes:
    """device_region_resource_t - 24 bytes."""
    return pack_region(vaddr, size) + struct.pack("<Q", io_addr)


def pack_conn(free_vaddr: int, active_vaddr: int, queue_size: int,
              num_buffers: int, ch_id: int) -> bytes:
    """net_connection_resource_t - 40 bytes."""
    body = (pack_region(free_vaddr, queue_size)
            + pack_region(active_vaddr, queue_size)
            + struct.pack("<HB", num_buffers, ch_id))
    return _pad(body, 40)


def pack_driver_config(virt_rx_conn: bytes, virt_tx_conn: bytes) -> bytes:
    """net_driver_config_t - 88 bytes."""
    body = _pad(SDDF_NET_MAGIC, 8) + virt_rx_conn + virt_tx_conn
    assert len(body) == 88, len(body)
    return body


def pack_virt_tx_client(conn: bytes, data_vaddr: int, data_size: int,
                        data_io_addr: int) -> bytes:
    """net_virt_tx_client_config_t - 64 bytes."""
    return conn + pack_device_region(data_vaddr, data_size, data_io_addr)


def pack_virt_tx_config(driver_conn: bytes, clients: list) -> bytes:
    """net_virt_tx_config_t - 4152 bytes."""
    body = _pad(SDDF_NET_MAGIC, 8) + driver_conn
    for c in clients:
        body += c
    # Pad clients array to SDDF_NET_MAX_CLIENTS * 64 bytes.
    body += b"\x00" * (64 * (SDDF_NET_MAX_CLIENTS - len(clients)))
    body += struct.pack("<B", len(clients))
    return _pad(body, 4152)


def pack_virt_rx_client(conn: bytes, mac: tuple) -> bytes:
    """net_virt_rx_config_client_t - 48 bytes."""
    body = conn + struct.pack("<6B", *mac)
    return _pad(body, 48)


def pack_virt_rx_config(driver_conn: bytes,
                        data_vaddr: int, data_size: int, data_io_addr: int,
                        bufmeta_vaddr: int, bufmeta_size: int,
                        clients: list) -> bytes:
    """net_virt_rx_config_t - 3168 bytes."""
    body = (_pad(SDDF_NET_MAGIC, 8)
            + driver_conn
            + pack_device_region(data_vaddr, data_size, data_io_addr)
            + pack_region(bufmeta_vaddr, bufmeta_size))
    for c in clients:
        body += c
    body += b"\x00" * (48 * (SDDF_NET_MAX_CLIENTS - len(clients)))
    body += struct.pack("<B", len(clients))
    return _pad(body, 3168)


def pack_copy_config(virt_rx_conn: bytes,
                     device_data_vaddr: int, device_data_size: int,
                     client_conn: bytes,
                     client_data_vaddr: int, client_data_size: int) -> bytes:
    """net_copy_config_t - 120 bytes."""
    body = (_pad(SDDF_NET_MAGIC, 8)
            + virt_rx_conn
            + pack_region(device_data_vaddr, device_data_size)
            + client_conn
            + pack_region(client_data_vaddr, client_data_size))
    assert len(body) == 120, len(body)
    return body


def pack_client_config(rx_conn: bytes,
                       rx_data_vaddr: int, rx_data_size: int,
                       tx_conn: bytes,
                       tx_data_vaddr: int, tx_data_size: int,
                       mac: tuple) -> bytes:
    """net_client_config_t - 128 bytes."""
    body = (_pad(SDDF_NET_MAGIC, 8)
            + rx_conn
            + pack_region(rx_data_vaddr, rx_data_size)
            + tx_conn
            + pack_region(tx_data_vaddr, tx_data_size)
            + struct.pack("<6B", *mac))
    return _pad(body, 128)


def pack_device_resources(regions: list) -> bytes:
    """device_resources_t - 1608 bytes."""
    assert len(regions) <= DEVICE_MAX_REGIONS
    header = struct.pack("<5sBBx", DEVICE_MAGIC, len(regions), 0)
    region_bytes = b"".join(regions)
    region_bytes += b"\x00" * (24 * (DEVICE_MAX_REGIONS - len(regions)))
    irq_bytes = b"\x00" * (1 * DEVICE_MAX_IRQS)
    body = header + region_bytes + irq_bytes
    return _pad(body, 1608)


# ----- vaddr allocator --------------------------------------------------
# Each PD has its own monotonic vaddr cursor starting at 0x20000000.
# We hand out vaddrs at the natural alignment of the MR size, mirroring
# what sdfgen does internally.

class VAddrCursor:
    """Per-PD vaddr allocator (monotonic, page-aligned)."""

    def __init__(self, base: int = 0x20000000):
        self._next = base

    def alloc(self, size: int) -> int:
        # Page-align both base and end. sdfgen output uses 4 KiB pages.
        page = 0x1000
        self._next = (self._next + page - 1) & ~(page - 1)
        v = self._next
        self._next += (size + page - 1) & ~(page - 1)
        return v


def add_map(pd: ProtectionDomain, mr: MemoryRegion, cursor: VAddrCursor,
            perms: str, *, size: int) -> int:
    """Allocate vaddr and attach a Map; returns the assigned vaddr."""
    vaddr = cursor.alloc(size)
    pd.add_map(Map(mr, vaddr, perms))
    return vaddr


# ----- Build pipeline --------------------------------------------------

def generate(args, board_paddr_top: int):
    sdf = SystemDescription(SystemDescription.Arch.AARCH64, board_paddr_top)

    # ----- PDs -----
    loopback_driver = ProtectionDomain(
        "loopback_driver", "loopback_driver.elf",
        priority=101, budget=100, period=400)
    virt_tx = ProtectionDomain(
        "net_virt_tx", "network_virt_tx.elf",
        priority=100, budget=20000)
    virt_rx = ProtectionDomain(
        "net_virt_rx", "network_virt_rx.elf",
        priority=99)
    client2 = ProtectionDomain(
        "client2_rust", "client2_rust.elf",
        priority=97, budget=20000)
    c2_copier = ProtectionDomain(
        "client2_rust_net_copier", "network_copy2.elf",
        priority=98, budget=20000)
    client3 = ProtectionDomain(
        "client3_rust", "client3_rust.elf",
        priority=97, budget=20000)
    c3_copier = ProtectionDomain(
        "client3_rust_net_copier", "network_copy3.elf",
        priority=98, budget=20000)

    for pd in (loopback_driver, virt_tx, virt_rx,
               c2_copier, client2, c3_copier, client3):
        sdf.add_pd(pd)

    # ----- Memory regions ----------------------------------------------
    # Queue MRs (no paddr - pure shared virtual memory).
    mr_drv_rx_free   = MemoryRegion(sdf, "net/queue/drv/rx/free",   QUEUE_MR_SIZE_DRIVER)
    mr_drv_rx_active = MemoryRegion(sdf, "net/queue/drv/rx/active", QUEUE_MR_SIZE_DRIVER)
    mr_drv_tx_free   = MemoryRegion(sdf, "net/queue/drv/tx/free",   QUEUE_MR_SIZE_DRIVER)
    mr_drv_tx_active = MemoryRegion(sdf, "net/queue/drv/tx/active", QUEUE_MR_SIZE_DRIVER)
    mr_bufmeta       = MemoryRegion(sdf, "net/rx/virt_metadata",     BUFFER_METADATA_MR_SIZE)

    # virt_rx <-> copier and copier <-> client queues (per-client).
    mr_vrx_c2cop_free   = MemoryRegion(sdf, "net/queue/vrx/c2_copier/free",   QUEUE_MR_SIZE_PER_CLIENT)
    mr_vrx_c2cop_active = MemoryRegion(sdf, "net/queue/vrx/c2_copier/active", QUEUE_MR_SIZE_PER_CLIENT)
    mr_c2cop_c2_free    = MemoryRegion(sdf, "net/queue/c2_copier/c2/free",    QUEUE_MR_SIZE_PER_CLIENT)
    mr_c2cop_c2_active  = MemoryRegion(sdf, "net/queue/c2_copier/c2/active",  QUEUE_MR_SIZE_PER_CLIENT)

    mr_vrx_c3cop_free   = MemoryRegion(sdf, "net/queue/vrx/c3_copier/free",   QUEUE_MR_SIZE_PER_CLIENT)
    mr_vrx_c3cop_active = MemoryRegion(sdf, "net/queue/vrx/c3_copier/active", QUEUE_MR_SIZE_PER_CLIENT)
    mr_c3cop_c3_free    = MemoryRegion(sdf, "net/queue/c3_copier/c3/free",    QUEUE_MR_SIZE_PER_CLIENT)
    mr_c3cop_c3_active  = MemoryRegion(sdf, "net/queue/c3_copier/c3/active",  QUEUE_MR_SIZE_PER_CLIENT)

    # virt_tx <-> client queues (per-client).
    mr_vtx_c2_free   = MemoryRegion(sdf, "net/queue/vtx/c2/free",   QUEUE_MR_SIZE_PER_CLIENT)
    mr_vtx_c2_active = MemoryRegion(sdf, "net/queue/vtx/c2/active", QUEUE_MR_SIZE_PER_CLIENT)
    mr_vtx_c3_free   = MemoryRegion(sdf, "net/queue/vtx/c3/free",   QUEUE_MR_SIZE_PER_CLIENT)
    mr_vtx_c3_active = MemoryRegion(sdf, "net/queue/vtx/c3/active", QUEUE_MR_SIZE_PER_CLIENT)

    # Data MRs. Shared RX and per-client TX go through DMA paddrs (they
    # appear in `device_resources.regions[].io_addr` and the matching
    # `net_virt_tx_config.clients[].data.io_addr`). Per-client RX data
    # rides the copier path and never crosses a paddr boundary.
    mr_rx_data    = MemoryRegion(sdf, "net/rx/data/device", DATA_MR_SIZE, paddr=PADDR_RX_DATA)
    mr_c2_tx_data = MemoryRegion(sdf, "net/tx/data/client/c2", DATA_MR_SIZE, paddr=PADDR_CLIENT2_TX)
    mr_c3_tx_data = MemoryRegion(sdf, "net/tx/data/client/c3", DATA_MR_SIZE, paddr=PADDR_CLIENT3_TX)
    mr_c2_rx_data = MemoryRegion(sdf, "net/rx/data/client/c2", DATA_MR_SIZE)
    mr_c3_rx_data = MemoryRegion(sdf, "net/rx/data/client/c3", DATA_MR_SIZE)

    for mr in (mr_drv_rx_free, mr_drv_rx_active, mr_drv_tx_free, mr_drv_tx_active,
               mr_bufmeta,
               mr_vrx_c2cop_free, mr_vrx_c2cop_active, mr_c2cop_c2_free, mr_c2cop_c2_active,
               mr_vrx_c3cop_free, mr_vrx_c3cop_active, mr_c3cop_c3_free, mr_c3cop_c3_active,
               mr_vtx_c2_free, mr_vtx_c2_active, mr_vtx_c3_free, mr_vtx_c3_active,
               mr_rx_data, mr_c2_tx_data, mr_c3_tx_data, mr_c2_rx_data, mr_c3_rx_data):
        sdf.add_mr(mr)

    # ----- Maps + vaddr capture -----------------------------------------
    # Each PD gets its own cursor; we capture every map's vaddr to feed
    # the config blobs below.

    # --- loopback_driver ---
    lb = VAddrCursor()
    lb_drv_rx_free   = add_map(loopback_driver, mr_drv_rx_free,   lb, "rw", size=QUEUE_MR_SIZE_DRIVER)
    lb_drv_rx_active = add_map(loopback_driver, mr_drv_rx_active, lb, "rw", size=QUEUE_MR_SIZE_DRIVER)
    lb_drv_tx_free   = add_map(loopback_driver, mr_drv_tx_free,   lb, "rw", size=QUEUE_MR_SIZE_DRIVER)
    lb_drv_tx_active = add_map(loopback_driver, mr_drv_tx_active, lb, "rw", size=QUEUE_MR_SIZE_DRIVER)
    lb_rx_data       = add_map(loopback_driver, mr_rx_data,       lb, "rw", size=DATA_MR_SIZE)
    lb_c2_tx_data    = add_map(loopback_driver, mr_c2_tx_data,    lb, "r",  size=DATA_MR_SIZE)
    lb_c3_tx_data    = add_map(loopback_driver, mr_c3_tx_data,    lb, "r",  size=DATA_MR_SIZE)

    # --- virt_tx ---
    vtx = VAddrCursor()
    vtx_drv_free   = add_map(virt_tx, mr_drv_tx_free,   vtx, "rw", size=QUEUE_MR_SIZE_DRIVER)
    vtx_drv_active = add_map(virt_tx, mr_drv_tx_active, vtx, "rw", size=QUEUE_MR_SIZE_DRIVER)
    vtx_c2_free    = add_map(virt_tx, mr_vtx_c2_free,   vtx, "rw", size=QUEUE_MR_SIZE_PER_CLIENT)
    vtx_c2_active  = add_map(virt_tx, mr_vtx_c2_active, vtx, "rw", size=QUEUE_MR_SIZE_PER_CLIENT)
    vtx_c2_tx_data = add_map(virt_tx, mr_c2_tx_data,    vtx, "r",  size=DATA_MR_SIZE)
    vtx_c3_free    = add_map(virt_tx, mr_vtx_c3_free,   vtx, "rw", size=QUEUE_MR_SIZE_PER_CLIENT)
    vtx_c3_active  = add_map(virt_tx, mr_vtx_c3_active, vtx, "rw", size=QUEUE_MR_SIZE_PER_CLIENT)
    vtx_c3_tx_data = add_map(virt_tx, mr_c3_tx_data,    vtx, "r",  size=DATA_MR_SIZE)

    # --- virt_rx ---
    vrx = VAddrCursor()
    vrx_drv_free       = add_map(virt_rx, mr_drv_rx_free,       vrx, "rw", size=QUEUE_MR_SIZE_DRIVER)
    vrx_drv_active     = add_map(virt_rx, mr_drv_rx_active,     vrx, "rw", size=QUEUE_MR_SIZE_DRIVER)
    vrx_rx_data        = add_map(virt_rx, mr_rx_data,           vrx, "r",  size=DATA_MR_SIZE)
    vrx_bufmeta        = add_map(virt_rx, mr_bufmeta,           vrx, "rw", size=BUFFER_METADATA_MR_SIZE)
    vrx_c2cop_free     = add_map(virt_rx, mr_vrx_c2cop_free,    vrx, "rw", size=QUEUE_MR_SIZE_PER_CLIENT)
    vrx_c2cop_active   = add_map(virt_rx, mr_vrx_c2cop_active,  vrx, "rw", size=QUEUE_MR_SIZE_PER_CLIENT)
    vrx_c3cop_free     = add_map(virt_rx, mr_vrx_c3cop_free,    vrx, "rw", size=QUEUE_MR_SIZE_PER_CLIENT)
    vrx_c3cop_active   = add_map(virt_rx, mr_vrx_c3cop_active,  vrx, "rw", size=QUEUE_MR_SIZE_PER_CLIENT)

    # --- c2_copier ---
    c2c = VAddrCursor()
    c2cop_vrx_free    = add_map(c2_copier, mr_vrx_c2cop_free,    c2c, "rw", size=QUEUE_MR_SIZE_PER_CLIENT)
    c2cop_vrx_active  = add_map(c2_copier, mr_vrx_c2cop_active,  c2c, "rw", size=QUEUE_MR_SIZE_PER_CLIENT)
    c2cop_c2_free     = add_map(c2_copier, mr_c2cop_c2_free,     c2c, "rw", size=QUEUE_MR_SIZE_PER_CLIENT)
    c2cop_c2_active   = add_map(c2_copier, mr_c2cop_c2_active,   c2c, "rw", size=QUEUE_MR_SIZE_PER_CLIENT)
    c2cop_device_data = add_map(c2_copier, mr_rx_data,           c2c, "rw", size=DATA_MR_SIZE)
    c2cop_client_data = add_map(c2_copier, mr_c2_rx_data,        c2c, "rw", size=DATA_MR_SIZE)

    # --- c3_copier ---
    c3c = VAddrCursor()
    c3cop_vrx_free    = add_map(c3_copier, mr_vrx_c3cop_free,    c3c, "rw", size=QUEUE_MR_SIZE_PER_CLIENT)
    c3cop_vrx_active  = add_map(c3_copier, mr_vrx_c3cop_active,  c3c, "rw", size=QUEUE_MR_SIZE_PER_CLIENT)
    c3cop_c3_free     = add_map(c3_copier, mr_c3cop_c3_free,     c3c, "rw", size=QUEUE_MR_SIZE_PER_CLIENT)
    c3cop_c3_active   = add_map(c3_copier, mr_c3cop_c3_active,   c3c, "rw", size=QUEUE_MR_SIZE_PER_CLIENT)
    c3cop_device_data = add_map(c3_copier, mr_rx_data,           c3c, "rw", size=DATA_MR_SIZE)
    c3cop_client_data = add_map(c3_copier, mr_c3_rx_data,        c3c, "rw", size=DATA_MR_SIZE)

    # --- client2 ---
    c2 = VAddrCursor()
    c2_rx_free   = add_map(client2, mr_c2cop_c2_free,   c2, "rw", size=QUEUE_MR_SIZE_PER_CLIENT)
    c2_rx_active = add_map(client2, mr_c2cop_c2_active, c2, "rw", size=QUEUE_MR_SIZE_PER_CLIENT)
    c2_rx_data   = add_map(client2, mr_c2_rx_data,      c2, "rw", size=DATA_MR_SIZE)
    c2_tx_free   = add_map(client2, mr_vtx_c2_free,     c2, "rw", size=QUEUE_MR_SIZE_PER_CLIENT)
    c2_tx_active = add_map(client2, mr_vtx_c2_active,   c2, "rw", size=QUEUE_MR_SIZE_PER_CLIENT)
    c2_tx_data   = add_map(client2, mr_c2_tx_data,      c2, "rw", size=DATA_MR_SIZE)

    # --- client3 ---
    c3 = VAddrCursor()
    c3_rx_free   = add_map(client3, mr_c3cop_c3_free,   c3, "rw", size=QUEUE_MR_SIZE_PER_CLIENT)
    c3_rx_active = add_map(client3, mr_c3cop_c3_active, c3, "rw", size=QUEUE_MR_SIZE_PER_CLIENT)
    c3_rx_data   = add_map(client3, mr_c3_rx_data,      c3, "rw", size=DATA_MR_SIZE)
    c3_tx_free   = add_map(client3, mr_vtx_c3_free,     c3, "rw", size=QUEUE_MR_SIZE_PER_CLIENT)
    c3_tx_active = add_map(client3, mr_vtx_c3_active,   c3, "rw", size=QUEUE_MR_SIZE_PER_CLIENT)
    c3_tx_data   = add_map(client3, mr_c3_tx_data,      c3, "rw", size=DATA_MR_SIZE)

    # ----- Channels -----------------------------------------------------
    # We pick stable Microkit channel IDs per PD via a_id/b_id kwargs
    # so the C config blobs can reference them by integer.
    ch_drv_vrx       = Channel(loopback_driver, virt_rx, a_id=0, b_id=0)  # virt_rx <-> driver
    ch_drv_vtx       = Channel(loopback_driver, virt_tx, a_id=1, b_id=0)  # virt_tx <-> driver
    ch_vrx_c2cop     = Channel(virt_rx, c2_copier, a_id=1, b_id=0)
    ch_c2cop_c2      = Channel(c2_copier, client2,  a_id=1, b_id=0)
    ch_vtx_c2        = Channel(virt_tx, client2,   a_id=1, b_id=1)
    ch_vrx_c3cop     = Channel(virt_rx, c3_copier, a_id=2, b_id=0)
    ch_c3cop_c3      = Channel(c3_copier, client3,  a_id=1, b_id=0)
    ch_vtx_c3        = Channel(virt_tx, client3,   a_id=2, b_id=1)

    for ch in (ch_drv_vrx, ch_drv_vtx,
               ch_vrx_c2cop, ch_c2cop_c2, ch_vtx_c2,
               ch_vrx_c3cop, ch_c3cop_c3, ch_vtx_c3):
        sdf.add_channel(ch)

    # ----- Serialise config blobs --------------------------------------
    out = args.output

    # loopback_driver: .net_driver_config (queues from driver's POV) +
    # .device_resources (abused to carry data region paddrs).
    drv_vrx_conn = pack_conn(lb_drv_rx_free, lb_drv_rx_active,
                             QUEUE_MR_SIZE_DRIVER,
                             NUM_BUFFERS_DRIVER,
                             ch_drv_vrx.pd_a_id)
    drv_vtx_conn = pack_conn(lb_drv_tx_free, lb_drv_tx_active,
                             QUEUE_MR_SIZE_DRIVER,
                             NUM_BUFFERS_DRIVER,
                             ch_drv_vtx.pd_a_id)
    drv_cfg = pack_driver_config(drv_vrx_conn, drv_vtx_conn)
    with open(os.path.join(out, "net_driver.data"), "wb") as f:
        f.write(drv_cfg)

    dev_regions = [
        pack_device_region(lb_rx_data,     DATA_MR_SIZE, PADDR_RX_DATA),
        pack_device_region(lb_c2_tx_data,  DATA_MR_SIZE, PADDR_CLIENT2_TX),
        pack_device_region(lb_c3_tx_data,  DATA_MR_SIZE, PADDR_CLIENT3_TX),
    ]
    with open(os.path.join(out, "loopback_device_resources.data"), "wb") as f:
        f.write(pack_device_resources(dev_regions))

    # virt_tx: .net_virt_tx_config
    vtx_drv_conn = pack_conn(vtx_drv_free, vtx_drv_active,
                             QUEUE_MR_SIZE_DRIVER,
                             NUM_BUFFERS_DRIVER,
                             ch_drv_vtx.pd_b_id)
    vtx_c2_conn  = pack_conn(vtx_c2_free, vtx_c2_active,
                             QUEUE_MR_SIZE_PER_CLIENT,
                             NUM_BUFFERS_PER_CLIENT,
                             ch_vtx_c2.pd_a_id)
    vtx_c3_conn  = pack_conn(vtx_c3_free, vtx_c3_active,
                             QUEUE_MR_SIZE_PER_CLIENT,
                             NUM_BUFFERS_PER_CLIENT,
                             ch_vtx_c3.pd_a_id)
    vtx_clients = [
        pack_virt_tx_client(vtx_c2_conn, vtx_c2_tx_data, DATA_MR_SIZE, PADDR_CLIENT2_TX),
        pack_virt_tx_client(vtx_c3_conn, vtx_c3_tx_data, DATA_MR_SIZE, PADDR_CLIENT3_TX),
    ]
    with open(os.path.join(out, "net_virt_tx.data"), "wb") as f:
        f.write(pack_virt_tx_config(vtx_drv_conn, vtx_clients))

    # virt_rx: .net_virt_rx_config
    vrx_drv_conn = pack_conn(vrx_drv_free, vrx_drv_active,
                             QUEUE_MR_SIZE_DRIVER,
                             NUM_BUFFERS_DRIVER,
                             ch_drv_vrx.pd_b_id)
    vrx_c2cop_conn = pack_conn(vrx_c2cop_free, vrx_c2cop_active,
                               QUEUE_MR_SIZE_PER_CLIENT,
                               NUM_BUFFERS_PER_CLIENT,
                               ch_vrx_c2cop.pd_a_id)
    vrx_c3cop_conn = pack_conn(vrx_c3cop_free, vrx_c3cop_active,
                               QUEUE_MR_SIZE_PER_CLIENT,
                               NUM_BUFFERS_PER_CLIENT,
                               ch_vrx_c3cop.pd_a_id)
    vrx_clients = [
        pack_virt_rx_client(vrx_c2cop_conn, MAC_CLIENT2),
        pack_virt_rx_client(vrx_c3cop_conn, MAC_CLIENT3),
    ]
    with open(os.path.join(out, "net_virt_rx.data"), "wb") as f:
        f.write(pack_virt_rx_config(vrx_drv_conn,
                                     vrx_rx_data, DATA_MR_SIZE, PADDR_RX_DATA,
                                     vrx_bufmeta, BUFFER_METADATA_MR_SIZE,
                                     vrx_clients))

    # c2_copier + c3_copier: .net_copy_config (per-copier)
    cop2_vrx_conn = pack_conn(c2cop_vrx_free, c2cop_vrx_active,
                              QUEUE_MR_SIZE_PER_CLIENT,
                              NUM_BUFFERS_PER_CLIENT,
                              ch_vrx_c2cop.pd_b_id)
    cop2_client_conn = pack_conn(c2cop_c2_free, c2cop_c2_active,
                                 QUEUE_MR_SIZE_PER_CLIENT,
                                 NUM_BUFFERS_PER_CLIENT,
                                 ch_c2cop_c2.pd_a_id)
    with open(os.path.join(out, "net_copy_client2_rust_net_copier.data"), "wb") as f:
        f.write(pack_copy_config(cop2_vrx_conn,
                                 c2cop_device_data, DATA_MR_SIZE,
                                 cop2_client_conn,
                                 c2cop_client_data, DATA_MR_SIZE))

    cop3_vrx_conn = pack_conn(c3cop_vrx_free, c3cop_vrx_active,
                              QUEUE_MR_SIZE_PER_CLIENT,
                              NUM_BUFFERS_PER_CLIENT,
                              ch_vrx_c3cop.pd_b_id)
    cop3_client_conn = pack_conn(c3cop_c3_free, c3cop_c3_active,
                                 QUEUE_MR_SIZE_PER_CLIENT,
                                 NUM_BUFFERS_PER_CLIENT,
                                 ch_c3cop_c3.pd_a_id)
    with open(os.path.join(out, "net_copy_client3_rust_net_copier.data"), "wb") as f:
        f.write(pack_copy_config(cop3_vrx_conn,
                                 c3cop_device_data, DATA_MR_SIZE,
                                 cop3_client_conn,
                                 c3cop_client_data, DATA_MR_SIZE))

    # client2 + client3: .net_client_config
    c2_rx_conn = pack_conn(c2_rx_free, c2_rx_active,
                           QUEUE_MR_SIZE_PER_CLIENT,
                           NUM_BUFFERS_PER_CLIENT,
                           ch_c2cop_c2.pd_b_id)
    c2_tx_conn = pack_conn(c2_tx_free, c2_tx_active,
                           QUEUE_MR_SIZE_PER_CLIENT,
                           NUM_BUFFERS_PER_CLIENT,
                           ch_vtx_c2.pd_b_id)
    with open(os.path.join(out, "net_client_client2_rust.data"), "wb") as f:
        f.write(pack_client_config(c2_rx_conn, c2_rx_data, DATA_MR_SIZE,
                                    c2_tx_conn, c2_tx_data, DATA_MR_SIZE,
                                    MAC_CLIENT2))

    c3_rx_conn = pack_conn(c3_rx_free, c3_rx_active,
                           QUEUE_MR_SIZE_PER_CLIENT,
                           NUM_BUFFERS_PER_CLIENT,
                           ch_c3cop_c3.pd_b_id)
    c3_tx_conn = pack_conn(c3_tx_free, c3_tx_active,
                           QUEUE_MR_SIZE_PER_CLIENT,
                           NUM_BUFFERS_PER_CLIENT,
                           ch_vtx_c3.pd_b_id)
    with open(os.path.join(out, "net_client_client3_rust.data"), "wb") as f:
        f.write(pack_client_config(c3_rx_conn, c3_rx_data, DATA_MR_SIZE,
                                    c3_tx_conn, c3_tx_data, DATA_MR_SIZE,
                                    MAC_CLIENT3))

    # ----- XML SDF -----
    with open(os.path.join(out, args.sdf), "w") as f:
        f.write(sdf.render())


# ----- main -----------------------------------------------------------

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sddf", required=True)  # unused but kept for echo.mk compat
    parser.add_argument("--board", required=True)
    parser.add_argument("--dtb", required=False)  # unused on loopback path
    parser.add_argument("--output", required=True)
    parser.add_argument("--sdf", required=True)
    parser.add_argument("--objcopy", required=True)  # unused (Makefile drives objcopy)
    parser.add_argument("--smp", required=False)     # unused: single-core only
    args = parser.parse_args()

    # qemu_virt_aarch64 paddr_top (matches the value SDDF's
    # tools/meta/board.py advertises for the same board).
    #
    # rpi4b_8gb: the fixed data paddrs (0x5F000000..0x5F2FFFFF) fall in
    # the BCM2711 DRAM bank [0x40000000..0xFC000000) that seL4 reports at
    # boot on the 8 GB board, so the same constants hold there. The top
    # of that bank is used as paddr_top. rpi4b_2gb (the size QEMU's
    # raspi4b machine emulates) holds the same constants below 0x80000000.
    paddr_tops = {
        "qemu_virt_aarch64": 0xa0000000,
        "rpi4b_8gb": 0xfc000000,
        "rpi4b_2gb": 0x80000000,
    }
    if args.board not in paddr_tops:
        print(f"meta_loopback.py: unsupported board {args.board}", file=sys.stderr)
        sys.exit(2)

    generate(args, paddr_tops[args.board])


if __name__ == "__main__":
    # Sanity-check struct sizes against the C `_Static_assert` markers
    # in loopback_driver.c / Sel4RingInit (offsets locked in
    # config.h / device.h).
    assert len(pack_conn(0, 0, 0, 0, 0)) == 40
    assert len(pack_driver_config(pack_conn(0, 0, 0, 0, 0),
                                  pack_conn(0, 0, 0, 0, 0))) == 88
    assert len(pack_virt_tx_config(pack_conn(0, 0, 0, 0, 0), [])) == 4152
    assert len(pack_virt_rx_config(pack_conn(0, 0, 0, 0, 0),
                                    0, 0, 0, 0, 0, [])) == 3168
    assert len(pack_device_resources([])) == 1608

    main()
