#
# Copyright 2022, UNSW
#
# SPDX-License-Identifier: BSD-2-Clause
#
# This Makefile is copied into the build directory
# and operated on from there.
#


MICROKIT_TOOL ?= $(MICROKIT_SDK)/bin/microkit
ECHO_SERVER:=${SDDF}/examples/echo_server

SUPPORTED_BOARDS := \
		    imx8mm_evk \
		    imx8mp_evk \
			imx8mq_evk \
		    imx8mp_iotgate \
			maaxboard \
			odroidc2 \
			odroidc4 \
			qemu_virt_aarch64 \
		    qemu_virt_riscv64 \
			rock3b \
			star64 \
			x86_64_generic \
			rpi4b_1gb

TOOLCHAIN ?= clang
MICROKIT_CONFIG ?= debug
SYSTEM_FILE := echo_server.system
IMAGE_FILE := loader.img
REPORT_FILE := report.txt

include ${SDDF}/tools/make/board/common.mk

ECHO_SERVER := ${SDDF}/examples/echo_server
METAPROGRAM := $(ECHO_SERVER)/meta.py
LWIPDIR := network/ipstacks/lwip/src
BENCHMARK := $(SDDF)/benchmark
UTIL := $(SDDF)/util
ETHERNET_DRIVER := $(SDDF)/drivers/network/$(NET_DRIV_DIR)
SERIAL_COMPONENTS := $(SDDF)/serial/components
UART_DRIVER := $(SDDF)/drivers/serial/$(UART_DRIV_DIR)
TIMER_DRIVER := $(SDDF)/drivers/timer/$(TIMER_DRIV_DIR)
NETWORK_COMPONENTS := $(SDDF)/network/components

SDDF_CUSTOM_LIBC := 1

# hdds-micro-sel4 additions -------------------------------------------------
# Paths to the Rust staticlib + the C wrapper that owns the PD entry
# points. SEL4_CRATE_DIR must be set (the scripts under crates/hdds-micro-sel4/scripts
# pass it) to the hdds-micro-sel4 directory of the checkout.
SEL4_CRATE_DIR ?=
ifeq ($(strip $(SEL4_CRATE_DIR)),)
$(error SEL4_CRATE_DIR is not set; pass the path of the hdds-micro-sel4 directory)
endif
RUST_CLIENT_DIR := $(SEL4_CRATE_DIR)/microkit
RUST_STATICLIB_DIR := $(SEL4_CRATE_DIR)/client2_rust
RUST_STATICLIB_OUT := $(RUST_STATICLIB_DIR)/target/aarch64-unknown-none/release/libclient2_rust.a

# Comma-separated Cargo feature list forwarded to the Rust build.
# The echo build leaves it empty; the publisher build is triggered by
# scripts/run-hdds-pub.sh setting CARGO_FEATURES=publisher.
CARGO_FEATURES ?=
# ---------------------------------------------------------------------

vpath %.c ${SDDF} ${ECHO_SERVER} $(RUST_CLIENT_DIR)

IMAGES := eth_driver.elf echo.elf benchmark.elf idle.elf \
	  network_virt_rx.elf network_virt_tx.elf network_copy.elf \
	  timer_driver.elf serial_driver.elf serial_virt_tx.elf \
	  client2_rust.elf


CFLAGS += \
	  -Wno-unused-function \
	  -I$(BOARD_DIR)/include \
	  -I$(SDDF)/include/microkit \
	  -I$(SDDF)/include \
	  -I${ECHO_INCLUDE}/lwip \
	  -I$(LWIPDIR)/include \
	  -I$(LWIPDIR)/include/ipv4 \
	  -I $(ECHO_SERVER)/include \
	  -MP


# Suppress warning from lwIP
CFLAGS += -Wno-tautological-constant-out-of-range-compare

LDFLAGS := -L$(BOARD_DIR)/lib
LIBS := --start-group -lmicrokit -Tmicrokit.ld libsddf_util_debug.a \
	--end-group

ECHO_OBJS := echo.o utilization_socket.o \
	     udp_echo_socket.o tcp_echo_socket.o

DEPS := $(ECHO_OBJS:.o=.d)

all: loader.img

echo.elf: $(ECHO_OBJS) libsddf_util.a lib_sddf_lwip_echo.a
	$(LD) $(LDFLAGS) $^ $(LIBS) -o $@

# hdds-micro-sel4 Rust staticlib ----------------------------------------------
# Build the Rust staticlib via cargo, then copy into the Microkit build
# dir. CARGO_FEATURES selects between echo (default, empty), publisher
# (`publisher`) and subscriber (`subscriber`).
#
# Cargo invocation is FORCE-d so feature-set changes between runs (e.g.
# swapping run-echo-rust.sh -> run-hdds-pub.sh against the same build
# tree) always trigger a rebuild. Cargo's own incremental + feature-
# aware fingerprinting makes the no-op case cheap; src-only changes
# under the same feature set take a couple of seconds at most.
.PHONY: FORCE
FORCE:

$(RUST_STATICLIB_OUT): FORCE
	cd $(RUST_STATICLIB_DIR) && \
	cargo build --target aarch64-unknown-none --release \
	    $(if $(strip $(CARGO_FEATURES)),--features $(CARGO_FEATURES))

libclient2_rust.a: $(RUST_STATICLIB_OUT)
	cp $< $@

client2_rust.elf: client2_rust_wrapper.o libclient2_rust.a libsddf_util.a
	$(LD) $(LDFLAGS) $^ $(LIBS) -o $@
# -----------------------------------------------------------------------

# Need to build libsddf_util_debug.a because it's included in LIBS
# for the unimplemented libc dependencies
${IMAGES}: libsddf_util_debug.a

$(SYSTEM_FILE): $(METAPROGRAM) $(IMAGES) $(DTB)
ifneq ($(strip $(DTS)),)
	$(PYTHON)\
	    $(METAPROGRAM) --sddf $(SDDF) --board $(MICROKIT_BOARD) \
	    --dtb $(DTB) --output . --sdf $(SYSTEM_FILE) --objcopy $(OBJCOPY) --smp $(SMP_CONFIG) \
		$(if $(BENCH_PMU_EVENTS), --bench_pmu_events $(BENCH_PMU_EVENTS))
else
	$(PYTHON)\
	    $(METAPROGRAM) --sddf $(SDDF) --board $(MICROKIT_BOARD) \
	    --output . --sdf $(SYSTEM_FILE) --objcopy $(OBJCOPY) --smp $(SMP_CONFIG) \
		$(if $(BENCH_PMU_EVENTS), --bench_pmu_events $(BENCH_PMU_EVENTS))
endif
	$(OBJCOPY) --update-section .device_resources=serial_driver_device_resources.data serial_driver.elf
	$(OBJCOPY) --update-section .serial_driver_config=serial_driver_config.data serial_driver.elf
	$(OBJCOPY) --update-section .serial_virt_tx_config=serial_virt_tx.data serial_virt_tx.elf
	$(OBJCOPY) --update-section .device_resources=ethernet_driver_device_resources.data eth_driver.elf
	$(OBJCOPY) --update-section .net_driver_config=net_driver.data eth_driver.elf
	$(OBJCOPY) --update-section .net_virt_rx_config=net_virt_rx.data network_virt_rx.elf
	$(OBJCOPY) --update-section .net_virt_tx_config=net_virt_tx.data network_virt_tx.elf
	$(OBJCOPY) --update-section .net_copy_config=net_copy_client0_net_copier.data network_copy.elf network_copy0.elf
	$(OBJCOPY) --update-section .net_copy_config=net_copy_client1_net_copier.data network_copy.elf network_copy1.elf
	$(OBJCOPY) --update-section .net_copy_config=net_copy_client2_rust_net_copier.data network_copy.elf network_copy2.elf
	$(OBJCOPY) --update-section .device_resources=timer_driver_device_resources.data timer_driver.elf
	$(OBJCOPY) --update-section .timer_client_config=timer_client_client0.data echo0.elf
	$(OBJCOPY) --update-section .net_client_config=net_client_client0.data echo0.elf
	$(OBJCOPY) --update-section .serial_client_config=serial_client_client0.data echo0.elf
	$(OBJCOPY) --update-section .timer_client_config=timer_client_client1.data echo1.elf
	$(OBJCOPY) --update-section .net_client_config=net_client_client1.data echo1.elf
	$(OBJCOPY) --update-section .serial_client_config=serial_client_client1.data echo1.elf
	$(OBJCOPY) --update-section .lib_sddf_lwip_config=lib_sddf_lwip_config_client0.data echo0.elf
	$(OBJCOPY) --update-section .lib_sddf_lwip_config=lib_sddf_lwip_config_client1.data echo1.elf
	$(OBJCOPY) --update-section .net_client_config=net_client_client2_rust.data client2_rust.elf
	touch $@

${IMAGE_FILE} $(REPORT_FILE): $(IMAGES) $(SYSTEM_FILE)
	$(MICROKIT_TOOL) $(SYSTEM_FILE) --search-path $(BUILD_DIR) \
	--board $(MICROKIT_BOARD) --config $(MICROKIT_CONFIG) \
	-o $(IMAGE_FILE) -r $(REPORT_FILE)


include ${SDDF}/util/util.mk
include ${SDDF}/network/components/network_components.mk
include ${SDDF}/network/lib_sddf_lwip/lib_sddf_lwip.mk
include ${ETHERNET_DRIVER}/eth_driver.mk
include ${BENCHMARK}/benchmark.mk
include ${TIMER_DRIVER}/timer_driver.mk
include ${UART_DRIVER}/serial_driver.mk
include ${SERIAL_COMPONENTS}/serial_components.mk

qemu: $(IMAGE_FILE)
	$(QEMU) $(QEMU_ARCH_ARGS) $(QEMU_NET_ARGS) \
		-nographic \
		-netdev user,id=netdev0,\
hostfwd=udp::1235-10.0.2.15:1235,\
hostfwd=tcp::1236-10.0.2.15:1236,\
hostfwd=tcp::1237-10.0.2.15:1237,\
hostfwd=udp::1238-10.0.2.16:1235,\
hostfwd=tcp::1239-10.0.2.16:1236,\
hostfwd=tcp::1240-10.0.2.16:1237,\
hostfwd=udp::1241-10.0.2.17:1235 \
		-global virtio-mmio.force-legacy=false \
		-d guest_errors -smp 4

clean::
	${RM} -f *.elf .depend* $
	find . -name \*.[do] |xargs --no-run-if-empty rm

clobber:: clean
	rm -f ${IMAGE_FILE} ${REPORT_FILE}

-include $(DEPS)
