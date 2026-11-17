#
# Copyright 2026, naskel.com
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# hdds-micro-sel4 intra-guest pub/sub Makefile.
#
# Overlay onto the upstream sDDF echo_server build tree. Differences
# from echo.mk:
#   * METAPROGRAM = meta_loopback.py (full Path B manual wiring).
#   * Drops: eth_driver, timer_driver, lwip, benchmark, idle, stock
#     client0/client1, serial. The loopback "driver" is a custom PD
#     in this directory, and the two Rust clients write debug output
#     straight to the kernel UART via microkit_dbg_puts.
#   * Builds TWO Rust staticlibs from the same crate using distinct
#     Cargo features (publisher vs subscriber) and distinct
#     --target-dir trees, then links them into client2_rust.elf
#     (PD_A) and client3_rust.elf (PD_B) via two C wrappers.
#

MICROKIT_TOOL ?= $(MICROKIT_SDK)/bin/microkit
ECHO_SERVER := ${SDDF}/examples/echo_server

# rpi4b_8gb: the loopback system touches no device, so it runs unchanged
# on the Pi 4 (BCM2711, cortex-a72); only the board make snippet differs.
# rpi4b_2gb matches the 2 GB that QEMU's raspi4b machine emulates, so the
# Pi 4 platform path can be booted in emulation before going to silicon.
SUPPORTED_BOARDS := qemu_virt_aarch64 rpi4b_8gb rpi4b_2gb

TOOLCHAIN ?= clang
MICROKIT_CONFIG ?= debug
SYSTEM_FILE := loopback.system
IMAGE_FILE := loader.img
REPORT_FILE := report.txt

include ${SDDF}/tools/make/board/common.mk

METAPROGRAM := $(ECHO_SERVER)/meta_loopback.py
UTIL := $(SDDF)/util
NETWORK_COMPONENTS := $(SDDF)/network/components

SDDF_CUSTOM_LIBC := 1

# hdds-micro-sel4 paths. SEL4_CRATE_DIR must be set (the scripts under
# crates/hdds-micro-sel4/scripts pass it) to the hdds-micro-sel4 directory of the checkout.
SEL4_CRATE_DIR ?=
ifeq ($(strip $(SEL4_CRATE_DIR)),)
$(error SEL4_CRATE_DIR is not set; pass the path of the hdds-micro-sel4 directory)
endif
RUST_CLIENT_DIR := $(SEL4_CRATE_DIR)/microkit
RUST_STATICLIB_DIR := $(SEL4_CRATE_DIR)/client2_rust

# Each Cargo feature builds in its own target-dir so the two .a
# artifacts coexist without rebuild churn.
RUST_PUB_TARGET_DIR := $(RUST_STATICLIB_DIR)/target-pub
RUST_SUB_TARGET_DIR := $(RUST_STATICLIB_DIR)/target-sub
RUST_PUB_ARTIFACT := $(RUST_PUB_TARGET_DIR)/aarch64-unknown-none/release/libclient2_rust.a
RUST_SUB_ARTIFACT := $(RUST_SUB_TARGET_DIR)/aarch64-unknown-none/release/libclient2_rust.a

vpath %.c ${SDDF} $(RUST_CLIENT_DIR)

IMAGES := loopback_driver.elf \
          network_virt_rx.elf network_virt_tx.elf \
          network_copy2.elf network_copy3.elf \
          client2_rust.elf client3_rust.elf

CFLAGS += \
        -Wno-unused-function \
        -I$(BOARD_DIR)/include \
        -I$(SDDF)/include/microkit \
        -I$(SDDF)/include \
        -MP

LDFLAGS := -L$(BOARD_DIR)/lib
LIBS := --start-group -lmicrokit -Tmicrokit.ld libsddf_util_debug.a --end-group

all: $(IMAGE_FILE)

# ----- loopback_driver -------------------------------------------------
loopback_driver.o: $(RUST_CLIENT_DIR)/loopback_driver.c | libsddf_util_debug.a
	$(CC) $(CFLAGS) -c -o $@ $<

loopback_driver.elf: loopback_driver.o | libsddf_util_debug.a
	$(LD) $(LDFLAGS) loopback_driver.o $(LIBS) -o $@

# ----- Rust staticlibs (two flavours) ---------------------------------
# Cargo is FORCE-built; its fingerprint cache + per-target-dir
# separation keep no-op rebuilds cheap. The `cd` is essential - Cargo
# resolves relative paths against the workspace root, which lives in
# the Rust crate, not the Microkit build dir.
.PHONY: FORCE
FORCE:

$(RUST_PUB_ARTIFACT): FORCE
	cd $(RUST_STATICLIB_DIR) && \
	cargo build --target aarch64-unknown-none --release \
	    --target-dir $(RUST_PUB_TARGET_DIR) --features publisher,intra-guest

$(RUST_SUB_ARTIFACT): FORCE
	cd $(RUST_STATICLIB_DIR) && \
	cargo build --target aarch64-unknown-none --release \
	    --target-dir $(RUST_SUB_TARGET_DIR) --features subscriber,intra-guest

libclient2_rust_pub.a: $(RUST_PUB_ARTIFACT)
	cp $< $@

libclient2_rust_sub.a: $(RUST_SUB_ARTIFACT)
	cp $< $@

# ----- client2_rust.elf (PD_A, publisher) ------------------------------
# The echo.mk pattern lists `libsddf_util.a` as an ordinary prereq,
# which `$^` expands into the link line WHILE `$(LIBS)` also drags in
# `libsddf_util_debug.a` via --start-group/--end-group. The linker
# would then see two archives defining the same symbols
# (sddf_dprintf, ...) and resolve against whichever comes first -
# typically the non-debug stub, muting the loopback driver's
# diagnostics in debug builds. Here the debug archive is an
# order-only `|` dep, and the link passes explicit args instead of
# `$^`.
client2_rust_wrapper.o: $(RUST_CLIENT_DIR)/client2_rust_wrapper.c
	$(CC) $(CFLAGS) -c -o $@ $<

client2_rust.elf: client2_rust_wrapper.o libclient2_rust_pub.a | libsddf_util_debug.a
	$(LD) $(LDFLAGS) client2_rust_wrapper.o libclient2_rust_pub.a $(LIBS) -o $@

# ----- client3_rust.elf (PD_B, subscriber) -----------------------------
client3_rust_wrapper.o: $(RUST_CLIENT_DIR)/client3_rust_wrapper.c
	$(CC) $(CFLAGS) -c -o $@ $<

client3_rust.elf: client3_rust_wrapper.o libclient2_rust_sub.a | libsddf_util_debug.a
	$(LD) $(LDFLAGS) client3_rust_wrapper.o libclient2_rust_sub.a $(LIBS) -o $@

# ----- network_copy fan-out --------------------------------------------
# meta_loopback.py emits a system that names two separate copier
# binaries (network_copy2.elf and network_copy3.elf) so each can carry
# its own .net_copy_config section. We just duplicate the base ELF
# after it is built by network_components.mk.
network_copy2.elf: network_copy.elf
	cp $< $@

network_copy3.elf: network_copy.elf
	cp $< $@

${IMAGES}: libsddf_util_debug.a

# ----- SDF generation + objcopy section injection ---------------------
$(SYSTEM_FILE): $(METAPROGRAM) $(IMAGES)
	$(PYTHON) $(METAPROGRAM) \
	    --sddf $(SDDF) --board $(MICROKIT_BOARD) \
	    --output . --sdf $(SYSTEM_FILE) --objcopy $(OBJCOPY)
	$(OBJCOPY) --update-section .net_driver_config=net_driver.data loopback_driver.elf
	$(OBJCOPY) --update-section .device_resources=loopback_device_resources.data loopback_driver.elf
	$(OBJCOPY) --update-section .net_virt_rx_config=net_virt_rx.data network_virt_rx.elf
	$(OBJCOPY) --update-section .net_virt_tx_config=net_virt_tx.data network_virt_tx.elf
	$(OBJCOPY) --update-section .net_copy_config=net_copy_client2_rust_net_copier.data network_copy2.elf
	$(OBJCOPY) --update-section .net_copy_config=net_copy_client3_rust_net_copier.data network_copy3.elf
	$(OBJCOPY) --update-section .net_client_config=net_client_client2_rust.data client2_rust.elf
	$(OBJCOPY) --update-section .net_client_config=net_client_client3_rust.data client3_rust.elf
	touch $@

${IMAGE_FILE} $(REPORT_FILE): $(IMAGES) $(SYSTEM_FILE)
	$(MICROKIT_TOOL) $(SYSTEM_FILE) --search-path $(BUILD_DIR) \
	    --board $(MICROKIT_BOARD) --config $(MICROKIT_CONFIG) \
	    -o $(IMAGE_FILE) -r $(REPORT_FILE)

include ${SDDF}/util/util.mk
include ${SDDF}/network/components/network_components.mk

qemu:
	@echo "[echo_loopback.mk] 'make qemu' is disabled for the intra-guest system because"
	@echo "  it would re-attach -netdev user + virtio-net-device and break"
	@echo "  the in-guest data-plane seal. Launch the system via"
	@echo "  crates/hdds-micro-sel4/scripts/run-inguest.sh (or test-inguest.sh"
	@echo "  for the full check including the seal verification)."
	@exit 1

clean::
	${RM} -f *.elf .depend* libclient2_rust_*.a
	find . -name \*.[do] | xargs --no-run-if-empty rm

clobber:: clean
	rm -f ${IMAGE_FILE} ${REPORT_FILE} ${SYSTEM_FILE} *.data
	rm -rf $(RUST_PUB_TARGET_DIR) $(RUST_SUB_TARGET_DIR)
