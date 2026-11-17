# Copyright 2026, naskel.com
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""
hdds-micro-sel4 network meta program (Raspberry Pi 4 Ethernet, genet driver).

Builds an SDF in which the two Rust client PDs (publisher and subscriber)
share the board's real NIC through the stock sDDF network stack:

    client2_rust <-> copier <-> net_virt_rx <-> ethernet_driver (genet)
    client2_rust <-> net_virt_tx <-> ethernet_driver (genet)
    (and the same chain for client3_rust)

The genet driver needs the sDDF bcm2835 timer driver (its sleep_us() is
timer-paced) and the VideoCore mailbox window (its MAC address and CPU
clock are read through it), as on the rpi4b_1gb board of sDDF.

Device regions and IRQs come from the DTB passed with --dtb, in the form
sdfgen parses: sDDF's dts/rpi4b_1gb.dts compiled with dtc. The Pi firmware
DTB is not accepted by that parser; its genet and timer nodes carry the same
register and interrupt values.

Wiring is delegated to sdfgen's Sddf.Net and Sddf.Timer, as in the stock
sDDF echo_server meta program. The client MACs are fixed here so that a
capture on the wire can be matched to the PD that sent it.
"""

import argparse
import os
import sys

from sdfgen import SystemDescription, Sddf, DeviceTree

ProtectionDomain = SystemDescription.ProtectionDomain
MemoryRegion = SystemDescription.MemoryRegion
Map = SystemDescription.Map

# sdfgen allocates the driver's mailbox message buffer and its DMA buffers
# top-down from paddr_top. The genet driver hands the VideoCore the plain
# physical address of the mailbox buffer (io_addr | 0x8), so the buffer must
# lie in the first GiB; the top of the first usable RAM bank that seL4
# reports at boot (0x3b400000) is used. A top in the second bank put the
# buffer at 0xfbfe8000 and the VideoCore never answered.
PADDR_TOP = {
    "rpi4b_8gb": 0x3B400000,
}

# Device-tree paths (BCM2711 firmware DTB).
ETHERNET_NODE = "scb/ethernet@7d580000"
TIMER_NODE = "soc/timer@7e003000"

# VideoCore mailbox, mapped at the address the genet driver expects
# (mbox_regs = 0x3000880 in ethernet.c, so the window starts at 0x3000000).
MBOX_PADDR = 0xFE00B000
MBOX_VADDR = 0x3000000

# Locally administered MACs for the two HDDS PDs.
MAC_CLIENT2 = "02:00:00:00:00:17"
MAC_CLIENT3 = "02:00:00:00:00:18"


def generate(sdf_file, output_dir, paddr_top, dtb):
    sdf = SystemDescription(SystemDescription.Arch.AARCH64, paddr_top)

    timer_driver = ProtectionDomain("timer_driver", "timer_driver.elf", priority=102)
    timer_system = Sddf.Timer(sdf, dtb.node(TIMER_NODE), timer_driver)

    ethernet_driver = ProtectionDomain(
        "ethernet_driver", "eth_driver.elf", priority=101, budget=100, period=400
    )
    timer_system.add_client(ethernet_driver)
    mbox = MemoryRegion(sdf, "mbox", 0x10_000, paddr=MBOX_PADDR)
    sdf.add_mr(mbox)
    ethernet_driver.add_map(Map(mbox, MBOX_VADDR, perms="rw", cached=False))

    net_virt_tx = ProtectionDomain("net_virt_tx", "network_virt_tx.elf", priority=100)
    net_virt_rx = ProtectionDomain("net_virt_rx", "network_virt_rx.elf", priority=99)
    net_system = Sddf.Net(
        sdf, dtb.node(ETHERNET_NODE), ethernet_driver, net_virt_tx, net_virt_rx
    )

    client2 = ProtectionDomain(
        "client2_rust", "client2_rust.elf", priority=97, budget=20000
    )
    client2_copier = ProtectionDomain(
        "client2_rust_net_copier", "network_copy2.elf", priority=98, budget=20000
    )
    client3 = ProtectionDomain(
        "client3_rust", "client3_rust.elf", priority=97, budget=20000
    )
    client3_copier = ProtectionDomain(
        "client3_rust_net_copier", "network_copy3.elf", priority=98, budget=20000
    )
    net_system.add_client_with_copier(client2, client2_copier, mac_addr=MAC_CLIENT2)
    net_system.add_client_with_copier(client3, client3_copier, mac_addr=MAC_CLIENT3)

    for pd in (timer_driver, ethernet_driver, net_virt_tx, net_virt_rx,
               client2, client2_copier, client3, client3_copier):
        sdf.add_pd(pd)

    assert net_system.connect()
    assert net_system.serialise_config(output_dir)
    assert timer_system.connect()
    assert timer_system.serialise_config(output_dir)

    with open(os.path.join(output_dir, sdf_file), "w") as f:
        f.write(sdf.render())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sddf", required=True)
    parser.add_argument("--board", required=True)
    parser.add_argument("--dtb", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--sdf", required=True)
    parser.add_argument("--objcopy", required=True)  # the Makefile drives objcopy
    parser.add_argument("--smp", required=False)     # unused: single core
    args = parser.parse_args()

    if args.board not in PADDR_TOP:
        print(f"meta_net.py: unsupported board {args.board}", file=sys.stderr)
        sys.exit(2)

    Sddf(args.sddf)
    with open(args.dtb, "rb") as f:
        dtb = DeviceTree(f.read())
    generate(args.sdf, args.output, PADDR_TOP[args.board], dtb)


if __name__ == "__main__":
    main()
