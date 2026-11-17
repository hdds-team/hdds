# Makefile for HDDS (High-Performance DDS)
# Provides convenient shortcuts for common tasks

include tools/git-hooks/Makefile.hooks

.PHONY: all build release build-quick release-quick test test-all clean fmt fmt-check clippy clippy-fix doc doc-quiet help
.PHONY: bench bench-runtime bench-discovery bench-write-latency bench-read-latency bench-throughput
.PHONY: check validate ci pre-commit dev-setup watch watch-test update outdated audit stats version
.PHONY: test-coverage extrem-audit-scan extrem-audit-quick
.PHONY: sdk-cxx samples-cpp samples-cpp-qos samples-cpp-types samples-cpp-discovery samples-cpp-security samples-cpp-perf samples-cpp-advanced samples-cpp-all install
.PHONY: sdk-c install-c test-c-install

# Default target
all: build

# Build the project (debug mode)
build:
	@echo "Building HDDS (debug mode)..."
	cargo build --all

# Build release version (optimized)
release:
	@echo "Building HDDS (release mode)..."
	cargo build --all --release

# Aliases (legacy)
build-quick: build
release-quick: release

# Cargo output directory: CARGO_TARGET_DIR when set (same precedence as
# sdk/cmake/hdds-config.cmake), else target/.
TARGET_DIR ?= $(or $(CARGO_TARGET_DIR),target)

# Build the C SDK: libhdds_c.{a,so} in $(TARGET_DIR)/release, header in sdk/c/include
# Standalone hdds-c (default features, no ROS 2 symbols)
# Always delegate to cargo: it is the incremental build system, and it is the only
# thing that knows WHICH feature set produced the archive. A timestamp test cannot:
# a workspace-wide `cargo build --release` resolves hdds-c with the `rmw` feature
# (rmw-hdds asks for it), so target/release/libhdds_c.a then carries undefined
# references to the ROS 2 runtime (rosidl_runtime_c__*). Skipping cargo on mtime
# alone handed that archive to the C tutorial, which then failed to link.
sdk-c:
	@echo "Building hdds-c (standalone, no ROS 2)..."
	cargo build --release -p hdds-c

# Build the C++ SDK (RAII wrappers on top of libhdds_c)
sdk-cxx: sdk-c
	@echo "Building C++ SDK..."
	@mkdir -p sdk/cxx/build
	@if [ ! -f sdk/cxx/build/Makefile ]; then \
		cd sdk/cxx/build && cmake .. -DCMAKE_BUILD_TYPE=Release -DBUILD_EXAMPLES=OFF -DBUILD_TESTS=OFF; \
	fi
	@cd sdk/cxx/build && make -j$$(nproc)
	@echo "[OK] C++ SDK built: sdk/cxx/build/libhdds_cxx.a"
	@echo ""
	@echo "Next steps:"
	@echo "  make samples-cpp      - Build hello_world sample"
	@echo "  make samples-cpp-all  - Build all C++ samples"
	@echo "  make help             - See all available targets"

# Build C++ samples (requires sdk-cxx)
samples-cpp: sdk-cxx
	@echo "Building C++ hello_world sample..."
	@mkdir -p sdk/samples/01_basics/cpp/build
	@cd sdk/samples/01_basics/cpp/build && cmake .. -DCMAKE_PREFIX_PATH=$(CURDIR)/sdk/cmake && make -j$$(nproc)
	@echo "[OK] C++ samples built in sdk/samples/01_basics/cpp/build/"
	@echo "   Terminal 1 (subscriber first): ./sdk/samples/01_basics/cpp/build/hello_world"
	@echo "   Terminal 2 (publisher):        ./sdk/samples/01_basics/cpp/build/hello_world pub"

# Build C++ QoS samples (requires sdk-cxx)
samples-cpp-qos: sdk-cxx
	@echo "Building C++ QoS samples..."
	@mkdir -p sdk/samples/02_qos/cpp/build
	@cd sdk/samples/02_qos/cpp/build && cmake .. -DCMAKE_PREFIX_PATH=$(CURDIR)/sdk/cmake && make -j$$(nproc)
	@echo "[OK] C++ QoS samples built in sdk/samples/02_qos/cpp/build/"
	@echo "   Run: ./sdk/samples/02_qos/cpp/build/reliable_delivery pub"

# Build C++ type samples (requires sdk-cxx)
samples-cpp-types: sdk-cxx
	@echo "Building C++ type samples..."
	@mkdir -p sdk/samples/03_types/cpp/build
	@cd sdk/samples/03_types/cpp/build && cmake .. -DCMAKE_PREFIX_PATH=$(CURDIR)/sdk/cmake && make -j$$(nproc)
	@echo "[OK] C++ type samples built in sdk/samples/03_types/cpp/build/"

# Build C++ discovery samples (requires sdk-cxx)
samples-cpp-discovery: sdk-cxx
	@echo "Building C++ discovery samples..."
	@mkdir -p sdk/samples/04_discovery/cpp/build
	@cd sdk/samples/04_discovery/cpp/build && cmake .. -DCMAKE_PREFIX_PATH=$(CURDIR)/sdk/cmake && make -j$$(nproc)
	@echo "[OK] C++ discovery samples built in sdk/samples/04_discovery/cpp/build/"

# Build C++ security samples (requires sdk-cxx)
samples-cpp-security: sdk-cxx
	@echo "Building C++ security samples..."
	@mkdir -p sdk/samples/05_security/cpp/build
	@cd sdk/samples/05_security/cpp/build && cmake .. -DCMAKE_PREFIX_PATH=$(CURDIR)/sdk/cmake && make -j$$(nproc)
	@echo "[OK] C++ security samples built in sdk/samples/05_security/cpp/build/"

# Build C++ performance samples (requires sdk-cxx)
samples-cpp-perf: sdk-cxx
	@echo "Building C++ performance samples..."
	@mkdir -p sdk/samples/06_performance/cpp/build
	@cd sdk/samples/06_performance/cpp/build && cmake .. -DCMAKE_PREFIX_PATH=$(CURDIR)/sdk/cmake && make -j$$(nproc)
	@echo "[OK] C++ performance samples built in sdk/samples/06_performance/cpp/build/"

# Build C++ advanced samples (requires sdk-cxx)
samples-cpp-advanced: sdk-cxx
	@echo "Building C++ advanced samples..."
	@mkdir -p sdk/samples/07_advanced/cpp/build
	@cd sdk/samples/07_advanced/cpp/build && cmake .. -DCMAKE_PREFIX_PATH=$(CURDIR)/sdk/cmake && make -j$$(nproc)
	@echo "[OK] C++ advanced samples built in sdk/samples/07_advanced/cpp/build/"

# Build ALL C++ samples (all categories)
samples-cpp-all: samples-cpp samples-cpp-qos samples-cpp-types samples-cpp-discovery samples-cpp-security samples-cpp-perf samples-cpp-advanced
	@echo "[OK] All C++ sample categories built!"

# Install the HDDS C SDK to a prefix (default: /usr/local)
# Usage: make install-c PREFIX=/opt/hdds
# Installs hdds.h, libhdds_c.a, libhdds_c.so, lib/pkgconfig/hdds_c.pc and the
# CMake config (find_package(hdds REQUIRED COMPONENTS c)).
PREFIX ?= /usr/local
HDDS_VERSION := $(shell awk '/^\[workspace\.package\]/{f=1;next} /^\[/{f=0} f && /^version *= */{sub(/^[^"]*"/,""); sub(/".*$$/,""); print; exit}' Cargo.toml)
install-c: sdk-c
	@test -n "$(HDDS_VERSION)" || { echo "Error: could not read the workspace version from Cargo.toml"; exit 1; }
	@echo "Installing HDDS C SDK $(HDDS_VERSION) to $(PREFIX)..."
	@mkdir -p $(PREFIX)/include $(PREFIX)/lib/pkgconfig $(PREFIX)/lib/cmake/hdds
	@cp sdk/c/include/hdds.h $(PREFIX)/include/
	@cp $(TARGET_DIR)/release/libhdds_c.a $(PREFIX)/lib/
	@for lib in libhdds_c.so libhdds_c.dylib; do \
		if [ -f $(TARGET_DIR)/release/$$lib ]; then cp $(TARGET_DIR)/release/$$lib $(PREFIX)/lib/; fi; \
	done
	@sed -e 's|@PREFIX@|$(PREFIX)|' -e 's|@VERSION@|$(HDDS_VERSION)|' \
		sdk/c/hdds_c.pc.in > $(PREFIX)/lib/pkgconfig/hdds_c.pc
	@cp sdk/cmake/hdds-config.cmake sdk/cmake/hdds-config-version.cmake $(PREFIX)/lib/cmake/hdds/
	@echo "Installed to $(PREFIX)"
	@echo "   Header:     $(PREFIX)/include/hdds.h"
	@echo "   Libs:       $(PREFIX)/lib/libhdds_c.a, libhdds_c.so"
	@echo "   pkg-config: PKG_CONFIG_PATH=$(PREFIX)/lib/pkgconfig pkg-config --cflags --libs hdds_c"
	@echo "   CMake:      find_package(hdds REQUIRED COMPONENTS c) with -DCMAKE_PREFIX_PATH=$(PREFIX)"
	@echo "   Running against libhdds_c.so outside a system lib dir needs LD_LIBRARY_PATH=$(PREFIX)/lib"

# Install HDDS C++ SDK (and the C SDK it wraps) to a prefix (default: /usr/local)
# Usage: make install PREFIX=/opt/hdds
install: install-c sdk-cxx
	@echo "Installing HDDS C++ SDK to $(PREFIX)..."
	@cp sdk/cxx/include/hdds.hpp $(PREFIX)/include/
	@cp sdk/cxx/include/hdds_listener.hpp $(PREFIX)/include/ 2>/dev/null || true
	@cp sdk/cxx/build/libhdds_cxx.a $(PREFIX)/lib/
	@echo "Installed to $(PREFIX)"
	@echo "   Headers: $(PREFIX)/include/hdds.hpp, hdds.h"
	@echo "   Libs:    $(PREFIX)/lib/libhdds_cxx.a, libhdds_c.a"
	@echo "   CMake:   $(PREFIX)/lib/cmake/hdds/"
	@echo ""
	@echo "Usage: cmake .. -DCMAKE_PREFIX_PATH=$(PREFIX)"

# Install the C SDK to a temporary prefix and build/run a program against it
# through pkg-config (shared and static) and CMake (COMPONENTS c)
test-c-install: sdk-c
	@./scripts/test-c-install.sh

# Run unit tests (lib only, fast)
test:
	@echo "Running unit tests..."
	cargo test --lib

# Run ALL tests (lib + integration + doc tests)
# Excludes: hdds-c (C FFI), hdds-micro (embedded no_std)
# Note: --lib --tests to skip examples (some have compilation issues)
test-all:
	@echo "Running all tests (lib + integration + doc)..."
	cargo test --workspace --exclude hdds-c --exclude hdds-micro --lib --tests

# Run tests with coverage (requires cargo-tarpaulin)
test-coverage:
	@echo "Running tests with coverage..."
	@if command -v cargo-tarpaulin > /dev/null; then \
		cargo tarpaulin --out Html --output-dir coverage; \
		echo "Coverage report generated in coverage/"; \
	else \
		echo "[FAIL] cargo-tarpaulin not installed. Run: cargo install cargo-tarpaulin"; \
	fi

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	cargo clean
	@rm -rf coverage/
	@rm -rf sdk/cxx/build/
	@rm -rf sdk/samples/01_basics/cpp/build/
	@rm -rf sdk/samples/02_qos/cpp/build/
	@rm -rf sdk/samples/03_types/cpp/build/
	@rm -rf sdk/samples/04_discovery/cpp/build/
	@rm -rf sdk/samples/05_security/cpp/build/
	@rm -rf sdk/samples/06_performance/cpp/build/
	@rm -rf sdk/samples/07_advanced/cpp/build/
	@rm -rf rmw_hdds/build/
	@rm -rf fuzz/target/
	@rm -rf crates/hdds/fuzz/target/
	@rm -rf tools/hdds-gen/fuzz/target/
	@echo "[OK] Clean complete"

# Format code with rustfmt
fmt:
	@echo "Formatting code..."
	cargo fmt --all

# Check code formatting
fmt-check:
	@echo "Checking code formatting..."
	cargo fmt --all -- --check

# Run clippy linter (CI strictness: warnings allowed, errors fail)
# Excludes: hdds-c (C FFI), hdds-micro (embedded no_std), hdds-admin/hdds-gateway (CLI tools)
# Note: --lib only to avoid test/example compilation issues during cleanup
clippy:
	@echo "Running clippy linter..."
	@# --all-targets and -D warnings, because "clean" has to mean the same
	@# thing here as in scripts/gates.sh.
	cargo clippy --workspace --exclude hdds-c --exclude hdds-micro --exclude hdds-admin --exclude hdds-gateway --all-targets --all-features -- -D warnings

# Fix clippy warnings automatically where possible
clippy-fix:
	@echo "Fixing clippy warnings..."
	cargo clippy --all --fix

# Generate documentation
doc:
	@echo "Generating documentation..."
	cargo doc --no-deps --open

# Generate documentation without opening browser
doc-quiet:
	@echo "Generating documentation..."
	cargo doc --no-deps

# Check for outdated dependencies
outdated:
	@echo "Checking for outdated dependencies..."
	@if command -v cargo-outdated > /dev/null; then \
		cargo outdated; \
	else \
		echo "[FAIL] cargo-outdated not installed. Run: cargo install cargo-outdated"; \
	fi

# Update dependencies
update:
	@echo "^ Updating dependencies..."
	cargo update

# Audit dependencies for security vulnerabilities
audit:
	@echo "Auditing dependencies..."
	@if command -v cargo-audit > /dev/null; then \
		cargo audit; \
	else \
		echo "[FAIL] cargo-audit not installed. Run: cargo install cargo-audit"; \
	fi

# EXTREME AUDIT - Military-grade quality scan (ZERO TOLERANCE)
# This runs ALL possible checks with maximum strictness
# Exit code = number of violations found (0 = perfect code)
extrem-audit-scan:
	@echo ""
	@echo " EXTREME AUDIT SCAN - Military Grade Quality Check"
	@echo "==================================================="
	@echo "This will run 14 audit layers with ZERO tolerance:"
	@echo "  * Anti-stub enforcement (TODO/FIXME/HACK/XXX)"
	@echo "  * Type safety (dangerous casts)"
	@echo "  * Unsafe code (ANSSI/IGI-1300)"
	@echo "  * Complexity analysis"
	@echo "  * Panic/unwrap audit"
	@echo "  * Memory patterns"
	@echo "  * Dependency security"
	@echo "  * Clippy pedantic+nursery"
	@echo "  * Documentation coverage"
	@echo "  * Concurrency safety"
	@echo "  * License compliance"
	@echo "  * Performance antipatterns"
	@echo "  * RTPS/DDS compliance"
	@echo "  * Test coverage (>90%)"
	@echo "==================================================="
	@bash scripts/extrem-audit-scan.sh

# Quick extreme audit (for pre-commit)
extrem-audit-quick: fmt-check
	@echo "Quick extreme audit (essential checks only)..."
	@bash scripts/audit-unsafe.sh
	@bash scripts/audit-casts.sh
	@bash scripts/audit-silent-wildcards.sh
	@bash tools/git-hooks/pre-commit-stubs-check-final codebase
	@# --lib, and only the shipped crate. With --all-targets this would refuse
	@# the entire test corpus: no clippy.toml sets allow-expect-in-tests, so
	@# every .expect in every test is an error.
	cargo clippy -p hdds --lib --all-features -- \
		-D warnings \
		-W clippy::pedantic \
		-D clippy::unwrap_used \
		-D clippy::expect_used \
		-D clippy::panic

# Run benchmarks
bench:
	@echo "Running benchmarks..."
	cargo bench

# Run specific benchmark
bench-runtime:
	@echo "Running runtime benchmark..."
	cargo bench -p hdds --bench runtime

bench-discovery:
	@echo "Running discovery benchmark..."
	cargo bench -p hdds --bench discovery

bench-write-latency:
	@echo "Running write latency benchmark..."
	cargo bench -p hdds --bench write_latency

bench-read-latency:
	@echo "Running read latency benchmark..."
	cargo bench -p hdds --bench read_latency

bench-throughput:
	@echo "Running throughput benchmark..."
	cargo bench -p hdds --bench throughput

# Check project for errors without building
check:
	@echo "Checking project..."
	cargo check --all

# Full validation: format check + clippy + all tests
validate: fmt-check clippy test-all
	@echo "[OK] Full validation passed!"

# CI quality gate (STRICT - blocks PR if fails)
ci: fmt-check clippy test-all audit doc-quiet
	@echo ""
	@echo "==================================================="
	@echo "[OK] CI QUALITY GATE PASSED - Ready for merge!"
	@echo "==================================================="
	@echo ""
	@echo "Checks completed:"
	@echo "  [OK] Code formatting (rustfmt)"
	@echo "  [OK] Linting (clippy -D warnings)"
	@echo "  [OK] Tests (unit + integration + doc)"
	@echo "  [OK] Security audit (cargo-audit)"
	@echo "  [OK] Documentation (cargo doc)"
	@echo ""

# Pre-commit hook: run before every commit.
#
# CONTRIBUTING.md tells contributors to run `bash scripts/gates.sh --quick`,
# which is the one enforced definition of clean; this target is the same
# three lanes for people who type `make`.
pre-commit: fmt clippy test
	@echo "[OK] Pre-commit checks passed!"

# Development setup: install useful tools
dev-setup:
	@echo "Setting up development environment..."
	@echo "Installing useful cargo tools..."
	@cargo install cargo-watch 2>/dev/null || true
	@cargo install cargo-tarpaulin 2>/dev/null || true
	@cargo install cargo-outdated 2>/dev/null || true
	@cargo install cargo-audit 2>/dev/null || true
	@cargo install ripgrep 2>/dev/null || true
	@echo "[OK] Development setup complete"

# Watch for changes and rebuild automatically (requires cargo-watch)
watch:
	@echo "Watching for changes..."
	@if command -v cargo-watch > /dev/null; then \
		cargo watch -x build -x test; \
	else \
		echo "[FAIL] cargo-watch not installed. Run: cargo install cargo-watch"; \
	fi

# Watch and run tests on changes
watch-test:
	@echo "Watching for changes (running tests)..."
	@if command -v cargo-watch > /dev/null; then \
		cargo watch -x test; \
	else \
		echo "[FAIL] cargo-watch not installed. Run: cargo install cargo-watch"; \
	fi

# Show project statistics (lines of code, etc.)
stats:
	@echo "HDDS Project Statistics"
	@echo "=========================="
	@echo "Lines of Rust code:"
	@find crates -name "*.rs" -exec wc -l {} + | tail -1
	@echo ""
	@echo "Number of test files:"
	@find crates -name "*.rs" -path "*/tests/*" 2>/dev/null | wc -l
	@echo ""
	@echo "Number of examples:"
	@find examples -name "*.rs" 2>/dev/null | wc -l || echo "0"
	@echo ""
	@echo "Dependencies (hdds):"
	@cd crates/hdds && cargo tree --depth 1 | grep -v "+--" | grep -v "+--" | wc -l

# Show version
version:
	@echo "HDDS version: $(shell cd crates/hdds && cargo pkgid | cut -d'#' -f2 || echo 'unknown')"

# Help target - shows all available commands
help:
	@echo "HDDS (High-Performance DDS) - Available Make Targets"
	@echo "===================================================="
	@echo ""
	@echo "Building:"
	@echo "  make build          - Build all crates (debug mode)"
	@echo "  make release        - Build all crates (release mode, optimized)"
	@echo "  make sdk-c          - Build C SDK ($(TARGET_DIR)/release/libhdds_c.{a,so})"
	@echo "  make sdk-cxx        - Build C++ SDK (libhdds_cxx.a)"
	@echo "  make samples-cpp    - Build C++ basics samples (hello_world, etc.)"
	@echo "  make samples-cpp-qos - Build C++ QoS samples (15 samples)"
	@echo "  make samples-cpp-all - Build ALL C++ samples (all 7 categories)"
	@echo "  make install-c      - Install C SDK + hdds_c.pc to PREFIX (default: /usr/local)"
	@echo "  make install        - Install C and C++ SDKs to PREFIX (default: /usr/local)"
	@echo "  make check          - Check for errors without building"
	@echo ""
	@echo "Testing:"
	@echo "  make test           - Run unit tests (lib only, fast)"
	@echo "  make test-all       - Run ALL tests (lib + integration + doc)"
	@echo "  make test-c-install - Install the C SDK to a temp prefix, build via pkg-config/CMake"
	@echo "  make test-coverage  - Run tests with coverage report"
	@echo "  make validate       - Full validation (fmt + clippy + all tests)"
	@echo "  make ci             - CI quality gate (STRICT - blocks merge if fails)"
	@echo "  make pre-commit     - Pre-commit checks (fmt + clippy + test)"
	@echo ""
	@echo "Code Quality:"
	@echo "  make fmt            - Format code with rustfmt"
	@echo "  make fmt-check      - Check code formatting"
	@echo "  make clippy         - Run clippy linter"
	@echo "  make clippy-fix     - Auto-fix clippy warnings"
	@echo "  make audit          - Audit dependencies for vulnerabilities"
	@echo "  make extrem-audit-scan -  EXTREME military-grade audit (14 layers)"
	@echo "  make extrem-audit-quick - Quick extreme audit (essential checks)"
	@echo ""
	@echo "Documentation:"
	@echo "  make doc            - Generate and open documentation"
	@echo "  make doc-quiet      - Generate documentation (no browser)"
	@echo ""
	@echo "Benchmarking:"
	@echo "  make bench          - Run all benchmarks"
	@echo "  make bench-runtime       - Run runtime benchmark"
	@echo "  make bench-discovery     - Run discovery benchmark"
	@echo "  make bench-write-latency - Run write latency benchmark"
	@echo "  make bench-read-latency  - Run read latency benchmark"
	@echo "  make bench-throughput    - Run throughput benchmark"
	@echo ""
	@echo "Dependencies:"
	@echo "  make update         - Update dependencies"
	@echo "  make outdated       - Check for outdated dependencies"
	@echo "  make audit          - Audit dependencies for vulnerabilities"
	@echo ""
	@echo "Development:"
	@echo "  make dev-setup      - Install development tools"
	@echo "  make watch          - Watch for changes and rebuild"
	@echo "  make watch-test     - Watch for changes and run tests"
	@echo "  make clean          - Remove all build artifacts (cargo, cmake, fuzz)"
	@echo ""
	@echo "Information:"
	@echo "  make stats          - Show project statistics"
	@echo "  make version        - Show version"
	@echo "  make help           - Show this help message"
	@echo ""
	@echo "Common workflows:"
	@echo "  make                - Same as 'make build'"
	@echo "  make test-all       - Run all tests"
	@echo "  make validate       - Full pre-commit validation"
	@echo "  make ci             - CI quality gate (strict)"
	@echo "  make extrem-audit-scan - Military-grade quality check"
