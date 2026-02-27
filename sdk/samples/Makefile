# HDDS SDK Samples - Top-level Makefile (g++ direct, no CMake)
#
# Usage:
#   make              - Build all C samples
#   make c            - Build all C samples
#   make cpp          - Build C++ samples (01_basics, 02_qos, 04_discovery)
#   make clean        - Remove build artifacts
#   make help         - Show this help
#
# For samples that need generated headers or extra deps (03_types, 05-07),
# use CMake via the root Makefile: make samples-cpp-all
#
# Prerequisites:
#   - libhdds_c.a must be built: cd /path/to/hdds && make release
#   - libhdds_cxx.a must be built (for C++): make sdk-cxx
#   - GCC/G++ for C/C++ samples

# Configuration
HDDS_ROOT ?= $(shell cd ../.. && pwd)
HDDS_C_INC := $(HDDS_ROOT)/sdk/c/include
HDDS_CXX_INC := $(HDDS_ROOT)/sdk/cxx/include
HDDS_C_LIB := $(HDDS_ROOT)/target/release/libhdds_c.a
HDDS_CXX_LIB := $(HDDS_ROOT)/sdk/cxx/build/libhdds_cxx.a

# Compiler flags
CC := gcc
CXX := g++
CFLAGS := -Wall -Wextra -O2 -I$(HDDS_C_INC)
CXXFLAGS := -Wall -Wextra -O2 -std=c++17 -I$(HDDS_CXX_INC) -I$(HDDS_C_INC)
C_LDFLAGS := $(HDDS_C_LIB) -lpthread -ldl -lm
CXX_LDFLAGS := $(HDDS_CXX_LIB) $(HDDS_C_LIB) -lpthread -ldl -lm

# Output directory
BUILD_DIR := build

# Find C samples (exclude 03_types: standalone serialization demos)
C_SAMPLES := $(filter-out 03_types/%, $(wildcard */c/*.c))
C_TARGETS := $(patsubst %.c,$(BUILD_DIR)/%,$(C_SAMPLES))

# Find C++ samples -- only categories that work with g++ direct
# 03_types, 05_security, 06_performance, 07_advanced need cmake (generated headers, OpenSSL, etc.)
CXX_SAMPLES := $(wildcard 01_basics/cpp/*.cpp 02_qos/cpp/*.cpp 04_discovery/cpp/*.cpp)
CXX_TARGETS := $(patsubst %.cpp,$(BUILD_DIR)/%,$(CXX_SAMPLES))

.PHONY: all c cpp clean help

all: c

c: $(C_TARGETS)
	@echo ""
	@echo "=== C samples built successfully ==="
	@echo "Run samples from $(BUILD_DIR)/"

cpp: $(CXX_TARGETS)
	@echo ""
	@echo "=== C++ samples built successfully ==="
	@echo "Run samples from $(BUILD_DIR)/"

# Build C samples
$(BUILD_DIR)/%: %.c
	@mkdir -p $(dir $@)
	@echo "Building $<..."
	@$(CC) $(CFLAGS) -I$(dir $<) $< $(C_LDFLAGS) -o $@

# Build C++ samples
$(BUILD_DIR)/%: %.cpp
	@mkdir -p $(dir $@)
	@echo "Building $<..."
	@$(CXX) $(CXXFLAGS) -I$(dir $<) $< $(CXX_LDFLAGS) -o $@

clean:
	rm -rf $(BUILD_DIR)
	@echo "Build artifacts removed"

help:
	@echo "HDDS SDK Samples Build System (g++ direct)"
	@echo ""
	@echo "Usage:"
	@echo "  make              Build all C samples"
	@echo "  make c            Build all C samples"
	@echo "  make cpp          Build C++ samples (01_basics, 02_qos, 04_discovery)"
	@echo "  make clean        Remove build artifacts"
	@echo ""
	@echo "For all categories including 03_types, 05-07 (need cmake):"
	@echo "  cd $(HDDS_ROOT) && make samples-cpp-all"
	@echo ""
	@echo "Environment:"
	@echo "  HDDS_ROOT=$(HDDS_ROOT)"
	@echo ""
	@echo "Prerequisites:"
	@echo "  1. Build HDDS: cd $(HDDS_ROOT) && make release sdk-cxx"
	@echo "  2. Run make (or make cpp) in this directory"
	@echo ""
	@echo "Running samples:"
	@echo "  ./$(BUILD_DIR)/01_basics/cpp/hello_world pub"
	@echo "  ./$(BUILD_DIR)/01_basics/cpp/hello_world sub"
