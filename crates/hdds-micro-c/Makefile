# Makefile for hdds-micro-c
# Build static library for various embedded targets
#
# Usage:
#   make esp32      - Build for ESP32 (Xtensa)
#   make esp32c3    - Build for ESP32-C3 (RISC-V)
#   make aarch64    - Build for ARM64 (Pi Zero 2)
#   make clean      - Clean build artifacts
#   make install-esp32 - Install to Arduino library

# ESP Toolchain paths
ESP_TOOLCHAIN := $(HOME)/.rustup/toolchains/esp
ESP_CARGO := $(ESP_TOOLCHAIN)/bin/cargo
ESP_RUSTC := $(ESP_TOOLCHAIN)/bin/rustc
LIBCLANG_PATH := $(ESP_TOOLCHAIN)/xtensa-esp32-elf-clang/esp-18.1.2_20240912/esp-clang/lib

# Check if ESP toolchain is available
ESP_AVAILABLE := $(shell test -x "$(ESP_CARGO)" && echo yes || echo no)

# Output directories
TARGET_DIR := target
ARDUINO_LIB := ../../demos/hdds-remote-sensor/sensor-node-arduino/lib/hdds-micro

# Build flags
RELEASE_FLAGS := --release
ESP32_TARGET := xtensa-esp32-espidf
ESP32C3_TARGET := riscv32imc-esp-espidf

.PHONY: all esp32 esp32c3 aarch64 clean install-esp32 check-esp

all: esp32

check-esp:
ifeq ($(ESP_AVAILABLE),no)
	@echo "ERROR: ESP toolchain not found at $(ESP_TOOLCHAIN)"
	@echo "Install with: espup install"
	@exit 1
endif

esp32: check-esp
	@echo "Building hdds-micro-c for ESP32 (Xtensa)..."
	@echo "This requires the ESP-IDF environment to be sourced."
	@echo "Run: . ~/export-esp.sh  or  . ~/.espressif/esp-idf/export.sh"
	RUSTUP_TOOLCHAIN=esp \
	LIBCLANG_PATH=$(LIBCLANG_PATH) \
	cargo build $(RELEASE_FLAGS) --target $(ESP32_TARGET) -Zbuild-std=std,panic_abort
	@echo "Build complete: $(TARGET_DIR)/$(ESP32_TARGET)/release/libhdds_micro_c.a"

esp32c3: check-esp
	@echo "Building hdds-micro-c for ESP32-C3 (RISC-V)..."
	LIBCLANG_PATH=$(LIBCLANG_PATH) $(ESP_CARGO) build $(RELEASE_FLAGS) \
		--target $(ESP32C3_TARGET) \
		-Zbuild-std=std,panic_abort
	@echo "Build complete: $(TARGET_DIR)/$(ESP32C3_TARGET)/release/libhdds_micro_c.a"

aarch64:
	@echo "Building hdds-micro-c for ARM64..."
	cargo build $(RELEASE_FLAGS) --target aarch64-unknown-linux-gnu
	@echo "Build complete: $(TARGET_DIR)/aarch64-unknown-linux-gnu/release/libhdds_micro_c.a"

install-esp32: esp32
	@echo "Installing to Arduino library: $(ARDUINO_LIB)"
	@mkdir -p $(ARDUINO_LIB)
	cp $(TARGET_DIR)/$(ESP32_TARGET)/release/libhdds_micro_c.a $(ARDUINO_LIB)/
	cp include/hdds_micro.h $(ARDUINO_LIB)/
	@echo "Installed! Now rebuild Arduino project with: pio run"

clean:
	cargo clean
	@echo "Cleaned."

# Print version info
version:
	@echo "ESP Cargo: $(ESP_CARGO)"
	@$(ESP_RUSTC) --version 2>/dev/null || echo "ESP rustc not available"
	@cargo --version

# Help
help:
	@echo "hdds-micro-c Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  esp32        Build static library for ESP32 (Xtensa)"
	@echo "  esp32c3      Build static library for ESP32-C3 (RISC-V)"
	@echo "  aarch64      Build static library for ARM64"
	@echo "  install-esp32  Build and install to Arduino lib"
	@echo "  clean        Clean build artifacts"
	@echo "  version      Print toolchain versions"
	@echo ""
	@echo "ESP toolchain: $(ESP_TOOLCHAIN)"
	@echo "ESP available: $(ESP_AVAILABLE)"
