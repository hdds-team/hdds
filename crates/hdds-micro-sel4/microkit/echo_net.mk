#
# Copyright 2026, naskel.com
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# hdds-micro-sel4 network Makefile (Raspberry Pi 4 genet NIC).
#
# Overlay onto the sDDF echo_server build tree, replacing echo.mk. The
# two Rust client PDs (publisher, subscriber) are wired to the stock
# genet driver through meta_net.py, with the stock virtualisers and
# copiers. Nothing here is lwIP, benchmark, serial or the stock clients.
#
# Required variables (passed on the make command line):
#   SEL4_CRATE_DIR      hdds-micro-sel4 directory of the checkout
#   DTB_FILE           device tree in sdfgen's form (sDDF dts/rpi4b_1gb.dts
#                      compiled with dtc)
#   PUB_IP_OCTETS      publisher PD IPv4, "a,b,c,d"
#   SUB_IP_OCTETS      subscriber PD IPv4, "a,b,c,d"
#

MICROKIT_TOOL ?= $(MICROKIT_SDK)/bin/microkit
ECHO_SERVER := ${SDDF}/examples/echo_server

SUPPORTED_BOARDS := rpi4b_8gb

TOOLCHAIN ?= clang
MICROKIT_CONFIG ?= debug
SYSTEM_FILE := net.system
IMAGE_FILE := loader.img
REPORT_FILE := report.txt

include ${SDDF}/tools/make/board/common.mk

METAPROGRAM := $(ECHO_SERVER)/meta_net.py
UTIL := $(SDDF)/util
NETWORK_COMPONENTS := $(SDDF)/network/components

SDDF_CUSTOM_LIBC := 1

SEL4_CRATE_DIR ?=
ifeq ($(strip $(SEL4_CRATE_DIR)),)
$(error SEL4_CRATE_DIR is not set; pass the path of the hdds-micro-sel4 directory)
endif
DTB_FILE ?=
ifeq ($(strip $(DTB_FILE)),)
$(error DTB_FILE is not set; pass the device tree compiled from sDDF dts/rpi4b_1gb.dts)
endif
PUB_IP_OCTETS ?=
SUB_IP_OCTETS ?=
ifeq ($(strip $(PUB_IP_OCTETS)),)
$(error PUB_IP_OCTETS is not set)
endif
ifeq ($(strip $(SUB_IP_OCTETS)),)
$(error SUB_IP_OCTETS is not set)
endif

RUST_CLIENT_DIR := $(SEL4_CRATE_DIR)/microkit
RUST_STATICLIB_DIR := $(SEL4_CRATE_DIR)/client2_rust

# Each feature set builds in its own target-dir so the two .a artifacts
# coexist without rebuild churn.
RUST_PUB_TARGET_DIR := $(RUST_STATICLIB_DIR)/target-pub-lan
RUST_SUB_TARGET_DIR := $(RUST_STATICLIB_DIR)/target-sub-lan
# Subscriber feature set. Default: per-sample UART output. The measurement
# build sets SUB_FEATURES=subscriber,lan,stats (cumulative STAT lines).
SUB_FEATURES ?= subscriber,lan
RUST_PUB_ARTIFACT := $(RUST_PUB_TARGET_DIR)/aarch64-unknown-none/release/libclient2_rust.a
RUST_SUB_ARTIFACT := $(RUST_SUB_TARGET_DIR)/aarch64-unknown-none/release/libclient2_rust.a

vpath %.c ${SDDF} $(RUST_CLIENT_DIR)

IMAGES := eth_driver.elf timer_driver.elf \
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

# ----- Drivers --------------------------------------------------------------
# timer_driver.mk builds timer_driver.elf for the bcm2835 system timer.
include ${SDDF}/drivers/timer/${TIMER_DRIV_DIR}/timer_driver.mk

${IMAGES}: libsddf_util_debug.a

# ----- Rust staticlibs (two flavours) -----------------------------------
# Cargo is FORCE-built; its fingerprint cache + per-target-dir separation
# keep no-op rebuilds cheap. The `cd` is essential: cargo resolves paths
# against the crate's workspace root.
.PHONY: FORCE
FORCE:

$(RUST_PUB_ARTIFACT): FORCE
	cd $(RUST_STATICLIB_DIR) && \
	cargo build --target aarch64-unknown-none --release \
	    --target-dir $(RUST_PUB_TARGET_DIR) --features publisher,lan

$(RUST_SUB_ARTIFACT): FORCE
	cd $(RUST_STATICLIB_DIR) && \
	cargo build --target aarch64-unknown-none --release \
	    --target-dir $(RUST_SUB_TARGET_DIR) --features $(SUB_FEATURES)

libclient2_rust_pub.a: $(RUST_PUB_ARTIFACT)
	cp $< $@

libclient2_rust_sub.a: $(RUST_SUB_ARTIFACT)
	cp $< $@

# ----- client2_rust.elf (publisher PD) ----------------------------------
# The debug archive is an order-only prerequisite and the link passes
# explicit arguments, so the debug sddf_dprintf is the one that resolves
# (see echo_loopback.mk for the same reasoning).
client2_rust_wrapper.o: $(RUST_CLIENT_DIR)/client2_rust_wrapper.c
	$(CC) $(CFLAGS) -DHDDS_LOCAL_IP_OCTETS=$(PUB_IP_OCTETS) -c -o $@ $<

client2_rust.elf: client2_rust_wrapper.o libclient2_rust_pub.a | libsddf_util_debug.a
	$(LD) $(LDFLAGS) client2_rust_wrapper.o libclient2_rust_pub.a $(LIBS) -o $@

# ----- client3_rust.elf (subscriber PD) ---------------------------------
client3_rust_wrapper.o: $(RUST_CLIENT_DIR)/client3_rust_wrapper.c
	$(CC) $(CFLAGS) -DHDDS_LOCAL_IP_OCTETS=$(SUB_IP_OCTETS) -c -o $@ $<

client3_rust.elf: client3_rust_wrapper.o libclient2_rust_sub.a | libsddf_util_debug.a
	$(LD) $(LDFLAGS) client3_rust_wrapper.o libclient2_rust_sub.a $(LIBS) -o $@

# ----- network_copy fan-out ---------------------------------------------
# meta_net.py gives each client its own copier PD; each copier needs its
# own .net_copy_config section, so the base ELF is duplicated.
network_copy2.elf: network_copy.elf
	cp $< $@

network_copy3.elf: network_copy.elf
	cp $< $@

# ----- SDF generation + section injection -------------------------------
$(SYSTEM_FILE): $(METAPROGRAM) $(IMAGES)
	$(PYTHON) $(METAPROGRAM) \
	    --sddf $(SDDF) --board $(MICROKIT_BOARD) --dtb $(DTB_FILE) \
	    --output . --sdf $(SYSTEM_FILE) --objcopy $(OBJCOPY)
	$(OBJCOPY) --update-section .device_resources=ethernet_driver_device_resources.data eth_driver.elf
	$(OBJCOPY) --update-section .net_driver_config=net_driver.data eth_driver.elf
	$(OBJCOPY) --update-section .timer_client_config=timer_client_ethernet_driver.data eth_driver.elf
	$(OBJCOPY) --update-section .device_resources=timer_driver_device_resources.data timer_driver.elf
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

# ----- genet NIC driver -------------------------------------------------------
# Built here instead of with sDDF's eth_driver.mk. That snippet links
# libsddf_util.a, whose sddf_dprintf writes to a serial client queue; this
# image has no serial client, so the first debug print in the driver
# dereferenced a NULL queue. The debug archive writes through
# microkit_dbg_puts, as the other components of this image do. The driver
# image is ETH_DRIV, copied to eth_driver.elf by common.mk.
GENET_DRIVER_DIR := ${SDDF}/drivers/network/${NET_DRIV_DIR}

network/genet/ethernet.o: ${GENET_DRIVER_DIR}/ethernet.c
	mkdir -p network/genet
	${CC} -c ${CFLAGS} ${CFLAGS_network} -I ${GENET_DRIVER_DIR} -o $@ $<

eth_driver_genet.elf: network/genet/ethernet.o libsddf_util_debug.a
	$(LD) $(LDFLAGS) network/genet/ethernet.o $(LIBS) -o $@

qemu:
	@echo "[echo_net.mk] 'make qemu' is not wired for the network build; boot the"
	@echo "  image on the Pi (crates/hdds-micro-sel4/scripts/build-net-board.sh)."
	@exit 1

clean::
	${RM} -f *.elf .depend* libclient2_rust_*.a
	find . -name \*.[do] | xargs --no-run-if-empty rm

clobber:: clean
	rm -f ${IMAGE_FILE} ${REPORT_FILE} ${SYSTEM_FILE} *.data
	rm -rf $(RUST_PUB_TARGET_DIR) $(RUST_SUB_TARGET_DIR)
