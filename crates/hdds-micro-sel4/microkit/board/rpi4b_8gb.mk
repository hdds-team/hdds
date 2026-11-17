#
# Copyright 2026, naskel.com
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# Board make snippet for the Raspberry Pi 4 (8 GB) network build, in the
# format of sDDF's tools/make/board/rpi4b_1gb.mk. The 1 GB snippet is the
# reference: the BCM2711 peripherals are the same on both boards.
# Installed over sDDF's tools/make/board/rpi4b_8gb.mk by
# scripts/build-net-board.sh.
#
NET_DRIV_DIR := genet
ETH_DRIV := eth_driver_genet.elf
UART_DRIV_DIR := ns16550a
TIMER_DRIV_DIR := bcm2835
CPU := cortex-a72
