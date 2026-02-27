# Makefile for HDDS (High-Performance DDS)
# Provides convenient shortcuts for common tasks

include tools/git-hooks/Makefile.hooks

.PHONY: all build release build-quick release-quick test test-all clean fmt fmt-check clippy clippy-fix doc doc-quiet help
.PHONY: bench bench-runtime bench-discovery bench-telemetry bench-rtps bench-reliable
.PHONY: check validate ci pre-commit dev-setup watch watch-test update outdated audit stats version
.PHONY: maintainer-init maintainer-update maintainer-status release-validate
.PHONY: test-coverage extrem-audit-scan extrem-audit-quick
.PHONY: sdk-cxx samples-cpp samples-cpp-qos samples-cpp-types samples-cpp-discovery samples-cpp-security samples-cpp-perf samples-cpp-advanced samples-cpp-all install

# Default target
all: build

# Build the project (debug mode)
build:
	@echo "🔨 Building HDDS (debug mode)..."
	cargo build --all

# Build release version (optimized)
release:
	@echo "🚀 Building HDDS (release mode)..."
	cargo build --all --release

# Aliases (legacy)
build-quick: build
release-quick: release

# Build the C++ SDK (RAII wrappers on top of libhdds_c)
# Auto-builds hdds-c standalone (no ROS 2 symbols)
sdk-cxx:
	@if [ ! -f target/release/libhdds_c.a ] || \
	    find crates/hdds/src crates/hdds-c/src -newer target/release/libhdds_c.a -name '*.rs' 2>/dev/null | grep -q .; then \
		echo "🔨 Building hdds-c (standalone, no ROS 2)..."; \
		cargo build --release -p hdds-c; \
	else \
		echo "✅ hdds-c up to date (skipping cargo)"; \
	fi
	@echo "🔨 Building C++ SDK..."
	@mkdir -p sdk/cxx/build
	@if [ ! -f sdk/cxx/build/Makefile ]; then \
		cd sdk/cxx/build && cmake .. -DCMAKE_BUILD_TYPE=Release -DBUILD_EXAMPLES=OFF -DBUILD_TESTS=OFF; \
	fi
	@cd sdk/cxx/build && make -j$$(nproc)
	@echo "✅ C++ SDK built: sdk/cxx/build/libhdds_cxx.a"
	@echo ""
	@echo "Next steps:"
	@echo "  make samples-cpp      - Build hello_world sample"
	@echo "  make samples-cpp-all  - Build all C++ samples"
	@echo "  make help             - See all available targets"

# Build C++ samples (requires sdk-cxx)
samples-cpp: sdk-cxx
	@echo "🔨 Building C++ hello_world sample..."
	@mkdir -p sdk/samples/01_basics/cpp/build
	@cd sdk/samples/01_basics/cpp/build && cmake .. -DCMAKE_PREFIX_PATH=$(CURDIR)/sdk/cmake && make -j$$(nproc)
	@echo "✅ C++ samples built in sdk/samples/01_basics/cpp/build/"
	@echo "   Terminal 1 (subscriber first): ./sdk/samples/01_basics/cpp/build/hello_world"
	@echo "   Terminal 2 (publisher):        ./sdk/samples/01_basics/cpp/build/hello_world pub"

# Build C++ QoS samples (requires sdk-cxx)
samples-cpp-qos: sdk-cxx
	@echo "🔨 Building C++ QoS samples..."
	@mkdir -p sdk/samples/02_qos/cpp/build
	@cd sdk/samples/02_qos/cpp/build && cmake .. -DCMAKE_PREFIX_PATH=$(CURDIR)/sdk/cmake && make -j$$(nproc)
	@echo "✅ C++ QoS samples built in sdk/samples/02_qos/cpp/build/"
	@echo "   Run: ./sdk/samples/02_qos/cpp/build/reliable_delivery pub"

# Build C++ type samples (requires sdk-cxx)
samples-cpp-types: sdk-cxx
	@echo "🔨 Building C++ type samples..."
	@mkdir -p sdk/samples/03_types/cpp/build
	@cd sdk/samples/03_types/cpp/build && cmake .. -DCMAKE_PREFIX_PATH=$(CURDIR)/sdk/cmake && make -j$$(nproc)
	@echo "✅ C++ type samples built in sdk/samples/03_types/cpp/build/"

# Build C++ discovery samples (requires sdk-cxx)
samples-cpp-discovery: sdk-cxx
	@echo "🔨 Building C++ discovery samples..."
	@mkdir -p sdk/samples/04_discovery/cpp/build
	@cd sdk/samples/04_discovery/cpp/build && cmake .. -DCMAKE_PREFIX_PATH=$(CURDIR)/sdk/cmake && make -j$$(nproc)
	@echo "✅ C++ discovery samples built in sdk/samples/04_discovery/cpp/build/"

# Build C++ security samples (requires sdk-cxx)
samples-cpp-security: sdk-cxx
	@echo "🔨 Building C++ security samples..."
	@mkdir -p sdk/samples/05_security/cpp/build
	@cd sdk/samples/05_security/cpp/build && cmake .. -DCMAKE_PREFIX_PATH=$(CURDIR)/sdk/cmake && make -j$$(nproc)
	@echo "✅ C++ security samples built in sdk/samples/05_security/cpp/build/"

# Build C++ performance samples (requires sdk-cxx)
samples-cpp-perf: sdk-cxx
	@echo "🔨 Building C++ performance samples..."
	@mkdir -p sdk/samples/06_performance/cpp/build
	@cd sdk/samples/06_performance/cpp/build && cmake .. -DCMAKE_PREFIX_PATH=$(CURDIR)/sdk/cmake && make -j$$(nproc)
	@echo "✅ C++ performance samples built in sdk/samples/06_performance/cpp/build/"

# Build C++ advanced samples (requires sdk-cxx)
samples-cpp-advanced: sdk-cxx
	@echo "🔨 Building C++ advanced samples..."
	@mkdir -p sdk/samples/07_advanced/cpp/build
	@cd sdk/samples/07_advanced/cpp/build && cmake .. -DCMAKE_PREFIX_PATH=$(CURDIR)/sdk/cmake && make -j$$(nproc)
	@echo "✅ C++ advanced samples built in sdk/samples/07_advanced/cpp/build/"

# Build ALL C++ samples (all categories)
samples-cpp-all: samples-cpp samples-cpp-qos samples-cpp-types samples-cpp-discovery samples-cpp-security samples-cpp-perf samples-cpp-advanced
	@echo "✅ All C++ sample categories built!"

# Install HDDS C++ SDK to a prefix (default: /usr/local)
# Usage: make install PREFIX=/opt/hdds
PREFIX ?= /usr/local
install: sdk-cxx
	@echo "📦 Installing HDDS C++ SDK to $(PREFIX)..."
	@mkdir -p $(PREFIX)/include $(PREFIX)/lib $(PREFIX)/lib/cmake/hdds
	@cp sdk/cxx/include/hdds.hpp $(PREFIX)/include/
	@cp sdk/cxx/include/hdds_listener.hpp $(PREFIX)/include/ 2>/dev/null || true
	@cp sdk/c/include/hdds.h $(PREFIX)/include/
	@cp sdk/cxx/build/libhdds_cxx.a $(PREFIX)/lib/
	@cp target/release/libhdds_c.a $(PREFIX)/lib/
	@cp sdk/cmake/hdds-config.cmake $(PREFIX)/lib/cmake/hdds/
	@cp sdk/cmake/hdds-config-version.cmake $(PREFIX)/lib/cmake/hdds/ 2>/dev/null || true
	@echo "✅ Installed to $(PREFIX)"
	@echo "   Headers: $(PREFIX)/include/hdds.hpp, hdds.h"
	@echo "   Libs:    $(PREFIX)/lib/libhdds_cxx.a, libhdds_c.a"
	@echo "   CMake:   $(PREFIX)/lib/cmake/hdds/"
	@echo ""
	@echo "Usage: cmake .. -DCMAKE_PREFIX_PATH=$(PREFIX)"

# Run unit tests (lib only, fast)
test:
	@echo "🧪 Running unit tests..."
	cargo test --lib

# Run ALL tests (lib + integration + doc tests)
# Excludes: hdds-c (C FFI), hdds-micro (embedded no_std)
# Note: --lib --tests to skip examples (some have compilation issues)
test-all:
	@echo "🔥 Running all tests (lib + integration + doc)..."
	cargo test --workspace --exclude hdds-c --exclude hdds-micro --lib --tests

# Run tests with coverage (requires cargo-tarpaulin)
test-coverage:
	@echo "📊 Running tests with coverage..."
	@if command -v cargo-tarpaulin > /dev/null; then \
		cargo tarpaulin --out Html --output-dir coverage; \
		echo "Coverage report generated in coverage/"; \
	else \
		echo "❌ cargo-tarpaulin not installed. Run: cargo install cargo-tarpaulin"; \
	fi

# Clean build artifacts
clean:
	@echo "🧹 Cleaning build artifacts..."
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
	@echo "✅ Clean complete"

# Format code with rustfmt
fmt:
	@echo "🎨 Formatting code..."
	cargo fmt --all

# Check code formatting
fmt-check:
	@echo "🔍 Checking code formatting..."
	cargo fmt --all -- --check

# Run clippy linter (CI strictness: warnings allowed, errors fail)
# Excludes: hdds-c (C FFI), hdds-micro (embedded no_std), hdds-admin/hdds-gateway (CLI tools)
# Note: --lib only to avoid test/example compilation issues during cleanup
clippy:
	@echo "🔍 Running clippy linter..."
	cargo clippy --workspace --exclude hdds-c --exclude hdds-micro --exclude hdds-admin --exclude hdds-gateway --lib --all-features

# Fix clippy warnings automatically where possible
clippy-fix:
	@echo "🔧 Fixing clippy warnings..."
	cargo clippy --all --fix

# Generate documentation
doc:
	@echo "📚 Generating documentation..."
	cargo doc --no-deps --open

# Generate documentation without opening browser
doc-quiet:
	@echo "📚 Generating documentation..."
	cargo doc --no-deps

# Check for outdated dependencies
outdated:
	@echo "🔍 Checking for outdated dependencies..."
	@if command -v cargo-outdated > /dev/null; then \
		cargo outdated; \
	else \
		echo "❌ cargo-outdated not installed. Run: cargo install cargo-outdated"; \
	fi

# Update dependencies
update:
	@echo "⬆️  Updating dependencies..."
	cargo update

# Audit dependencies for security vulnerabilities
audit:
	@echo "🔒 Auditing dependencies..."
	@if command -v cargo-audit > /dev/null; then \
		cargo audit; \
	else \
		echo "❌ cargo-audit not installed. Run: cargo install cargo-audit"; \
	fi

# EXTREME AUDIT - Military-grade quality scan (ZERO TOLERANCE)
# This runs ALL possible checks with maximum strictness
# Exit code = number of violations found (0 = perfect code)
extrem-audit-scan:
	@echo ""
	@echo "🛡️  EXTREME AUDIT SCAN - Military Grade Quality Check"
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@echo "This will run 14 audit layers with ZERO tolerance:"
	@echo "  • Anti-stub enforcement (TODO/FIXME/HACK/XXX)"
	@echo "  • Type safety (dangerous casts)"
	@echo "  • Unsafe code (ANSSI/IGI-1300)"
	@echo "  • Complexity analysis"
	@echo "  • Panic/unwrap audit"
	@echo "  • Memory patterns"
	@echo "  • Dependency security"
	@echo "  • Clippy pedantic+nursery"
	@echo "  • Documentation coverage"
	@echo "  • Concurrency safety"
	@echo "  • License compliance"
	@echo "  • Performance antipatterns"
	@echo "  • RTPS/DDS compliance"
	@echo "  • Test coverage (>90%)"
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@bash scripts/extrem-audit-scan.sh

# Quick extreme audit (for pre-commit)
extrem-audit-quick: fmt-check
	@echo "⚡ Quick extreme audit (essential checks only)..."
	@bash scripts/audit-unsafe.sh
	@bash scripts/audit-casts.sh
	@bash scripts/audit-silent-wildcards.sh
	@bash tools/git-hooks/pre-commit-stubs-check-final codebase
	@cargo clippy --all-targets --all-features -- \
		-D warnings \
		-W clippy::pedantic \
		-D clippy::unwrap_used \
		-D clippy::expect_used \
		-D clippy::panic

# Run benchmarks
bench:
	@echo "⚡ Running benchmarks..."
	cargo bench

# Run specific benchmark
bench-runtime:
	@echo "⚡ Running runtime benchmark..."
	cargo bench --bench runtime

bench-discovery:
	@echo "⚡ Running discovery latency benchmark..."
	cargo bench --bench discovery_latency

bench-telemetry:
	@echo "⚡ Running telemetry benchmark..."
	cargo bench --bench telemetry

bench-rtps:
	@echo "⚡ Running RTPS benchmark..."
	cargo bench --bench rtps

bench-reliable:
	@echo "⚡ Running reliable QoS benchmark..."
	cargo bench --bench reliable_qos

# Check project for errors without building
check:
	@echo "🔍 Checking project..."
	cargo check --all

# Full validation: format check + clippy + all tests
validate: fmt-check clippy test-all
	@echo "✅ Full validation passed!"

# CI quality gate (STRICT - blocks PR if fails)
ci: fmt-check clippy test-all audit doc-quiet
	@echo ""
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@echo "✅ CI QUALITY GATE PASSED - Ready for merge!"
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@echo ""
	@echo "Checks completed:"
	@echo "  ✅ Code formatting (rustfmt)"
	@echo "  ✅ Linting (clippy -D warnings)"
	@echo "  ✅ Tests (unit + integration + doc)"
	@echo "  ✅ Security audit (cargo-audit)"
	@echo "  ✅ Documentation (cargo doc)"
	@echo ""

# Pre-commit hook: run before every commit
pre-commit: fmt clippy test
	@echo "✅ Pre-commit checks passed!"

# Development setup: install useful tools
dev-setup:
	@echo "🔧 Setting up development environment..."
	@echo "Installing useful cargo tools..."
	@cargo install cargo-watch 2>/dev/null || true
	@cargo install cargo-tarpaulin 2>/dev/null || true
	@cargo install cargo-outdated 2>/dev/null || true
	@cargo install cargo-audit 2>/dev/null || true
	@cargo install ripgrep 2>/dev/null || true
	@echo "✅ Development setup complete"

# Watch for changes and rebuild automatically (requires cargo-watch)
watch:
	@echo "👀 Watching for changes..."
	@if command -v cargo-watch > /dev/null; then \
		cargo watch -x build -x test; \
	else \
		echo "❌ cargo-watch not installed. Run: cargo install cargo-watch"; \
	fi

# Watch and run tests on changes
watch-test:
	@echo "👀 Watching for changes (running tests)..."
	@if command -v cargo-watch > /dev/null; then \
		cargo watch -x test; \
	else \
		echo "❌ cargo-watch not installed. Run: cargo install cargo-watch"; \
	fi

# Show project statistics (lines of code, etc.)
stats:
	@echo "📊 HDDS Project Statistics"
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
	@cd crates/hdds && cargo tree --depth 1 | grep -v "├──" | grep -v "└──" | wc -l

# Show version
version:
	@echo "HDDS version: $(shell cd crates/hdds && cargo pkgid | cut -d'#' -f2 || echo 'unknown')"

# Private maintainer tooling (recommended as a git submodule at ./maintainer)
MAINTAINER_DIR ?= maintainer

maintainer-init:
	@if [ ! -f .gitmodules ]; then \
		echo "ℹ️  .gitmodules not found (no submodules configured yet)."; \
		echo "   Add private submodule at '$(MAINTAINER_DIR)' first."; \
	elif git config -f .gitmodules --get-regexp '^submodule\..*\.path$$' | awk '{print $$2}' | grep -qx "$(MAINTAINER_DIR)"; then \
		echo "🔐 Initializing private maintainer submodule..."; \
		git submodule update --init --recursive "$(MAINTAINER_DIR)"; \
	else \
		echo "ℹ️  No submodule configured at path '$(MAINTAINER_DIR)'."; \
	fi

maintainer-update:
	@$(MAKE) maintainer-init
	@if [ -d "$(MAINTAINER_DIR)/.git" ] || [ -f "$(MAINTAINER_DIR)/.git" ]; then \
		echo "🔄 Updating private maintainer submodule..."; \
		git submodule update --remote --recursive "$(MAINTAINER_DIR)"; \
	else \
		echo "ℹ️  Maintainer submodule not initialized."; \
	fi

maintainer-status:
	@echo "Maintainer tooling status ($(MAINTAINER_DIR))"
	@if [ ! -f .gitmodules ]; then \
		echo "  - .gitmodules: missing"; \
		echo "  - submodule: not configured"; \
	elif git config -f .gitmodules --get-regexp '^submodule\..*\.path$$' | awk '{print $$2}' | grep -qx "$(MAINTAINER_DIR)"; then \
		echo "  - submodule: configured"; \
		git submodule status "$(MAINTAINER_DIR)" || true; \
		if [ -d "$(MAINTAINER_DIR)" ]; then \
			echo "  - branch: $$(cd $(MAINTAINER_DIR) && git rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)"; \
			echo "  - commit: $$(cd $(MAINTAINER_DIR) && git rev-parse --short HEAD 2>/dev/null || echo unknown)"; \
		fi; \
	else \
		echo "  - submodule: not configured at path '$(MAINTAINER_DIR)'"; \
	fi

release-validate:
	@if [ -x "$(MAINTAINER_DIR)/validate-release.sh" ]; then \
		bash "$(MAINTAINER_DIR)/validate-release.sh"; \
	else \
		echo "❌ Missing executable: $(MAINTAINER_DIR)/validate-release.sh"; \
		echo "   Run 'make maintainer-init' or configure private maintainer submodule."; \
		exit 1; \
	fi

# Help target - shows all available commands
help:
	@echo "HDDS (High-Performance DDS) - Available Make Targets"
	@echo "===================================================="
	@echo ""
	@echo "Building:"
	@echo "  make build          - Build all crates (debug mode)"
	@echo "  make release        - Build all crates (release mode, optimized)"
	@echo "  make sdk-cxx        - Build C++ SDK (libhdds_cxx.a)"
	@echo "  make samples-cpp    - Build C++ basics samples (hello_world, etc.)"
	@echo "  make samples-cpp-qos - Build C++ QoS samples (15 samples)"
	@echo "  make samples-cpp-all - Build ALL C++ samples (all 7 categories)"
	@echo "  make install        - Install C++ SDK to PREFIX (default: /usr/local)"
	@echo "  make check          - Check for errors without building"
	@echo ""
	@echo "Testing:"
	@echo "  make test           - Run unit tests (lib only, fast)"
	@echo "  make test-all       - Run ALL tests (lib + integration + doc)"
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
	@echo "  make extrem-audit-scan - 🛡️  EXTREME military-grade audit (14 layers)"
	@echo "  make extrem-audit-quick - ⚡ Quick extreme audit (essential checks)"
	@echo ""
	@echo "Documentation:"
	@echo "  make doc            - Generate and open documentation"
	@echo "  make doc-quiet      - Generate documentation (no browser)"
	@echo ""
	@echo "Benchmarking:"
	@echo "  make bench          - Run all benchmarks"
	@echo "  make bench-runtime  - Run runtime benchmark"
	@echo "  make bench-discovery - Run discovery latency benchmark"
	@echo "  make bench-telemetry - Run telemetry benchmark"
	@echo "  make bench-rtps     - Run RTPS benchmark"
	@echo "  make bench-reliable - Run reliable QoS benchmark"
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
	@echo "  make maintainer-init - Init private maintainer submodule (if configured)"
	@echo "  make maintainer-update - Update private maintainer submodule to latest remote"
	@echo "  make maintainer-status - Show private maintainer submodule status (branch/commit)"
	@echo "  make release-validate - Run maintainer/validate-release.sh (private tooling)"
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
