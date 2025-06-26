# SPDX-License-Identifier: Apache-2.0
# VPP + eBPF Firewall: Root Makefile
# Production-grade build orchestration

.PHONY: all build clean test install uninstall setup \
        check-deps check-build verify debug \
        gui-setup gui-dev gui-build gui-start gui-stop \
        help info docker

# Configuration
PROJECT_NAME := vppebpf-firewall
VERSION := 1.0.0
BUILD_DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# Colors for output
GREEN := \033[0;32m
YELLOW := \033[1;33m
RED := \033[0;31m
BLUE := \033[0;34m
NC := \033[0m

# Default target
all: build

# Build everything
build: check-deps
	@echo -e "$(BLUE)[BUILD]$(NC) Building $(PROJECT_NAME) v$(VERSION)"
	@echo -e "$(BLUE)[BUILD]$(NC) Commit: $(GIT_COMMIT), Date: $(BUILD_DATE)"
	$(MAKE) -C ebpf
	$(MAKE) -C userspace
	@echo -e "$(GREEN)[SUCCESS]$(NC) Build completed successfully"

# Clean all build artifacts
clean:
	@echo -e "$(YELLOW)[CLEAN]$(NC) Cleaning build artifacts..."
	$(MAKE) -C ebpf clean
	$(MAKE) -C userspace clean
	rm -rf logs/*.log
	rm -rf /tmp/vppebpf-*.log
	@echo -e "$(GREEN)[SUCCESS]$(NC) Clean completed"

# Run comprehensive tests
test: build
	@echo -e "$(BLUE)[TEST]$(NC) Running test suite..."
	@if [ "$$(id -u)" -ne 0 ]; then \
		echo -e "$(RED)[ERROR]$(NC) Tests require root privileges"; \
		echo "Run: sudo make test"; \
		exit 1; \
	fi
	python3 ebpf/test_xdp.py
	@echo -e "$(GREEN)[SUCCESS]$(NC) All tests passed"

# Install system-wide (requires root)
install: build
	@echo -e "$(BLUE)[INSTALL]$(NC) Installing $(PROJECT_NAME)..."
	@if [ "$$(id -u)" -ne 0 ]; then \
		echo -e "$(RED)[ERROR]$(NC) Installation requires root privileges"; \
		echo "Run: sudo make install"; \
		exit 1; \
	fi
	$(MAKE) -C ebpf install
	$(MAKE) -C userspace install
	@echo -e "$(GREEN)[SUCCESS]$(NC) Installation completed"

# Uninstall system files
uninstall:
	@echo -e "$(YELLOW)[UNINSTALL]$(NC) Removing $(PROJECT_NAME)..."
	@if [ "$$(id -u)" -ne 0 ]; then \
		echo -e "$(RED)[ERROR]$(NC) Uninstallation requires root privileges"; \
		echo "Run: sudo make uninstall"; \
		exit 1; \
	fi
	rm -rf /opt/vppebpf/
	rm -f /etc/security/limits.d/99-ebpf.conf
	rm -f /etc/sysctl.d/99-vppebpf.conf
	@echo -e "$(GREEN)[SUCCESS]$(NC) Uninstallation completed"

# Setup development environment
setup:
	@echo -e "$(BLUE)[SETUP]$(NC) Setting up development environment..."
	@if [ "$$(id -u)" -eq 0 ]; then \
		echo -e "$(RED)[ERROR]$(NC) Don't run setup as root!"; \
		exit 1; \
	fi
	./scripts/setup.sh
	@echo -e "$(GREEN)[SUCCESS]$(NC) Development environment ready"

# Check dependencies
check-deps:
	@echo -e "$(BLUE)[CHECK]$(NC) Verifying dependencies..."
	@command -v clang >/dev/null || (echo -e "$(RED)[ERROR]$(NC) clang not found" && exit 1)
	@command -v bpftool >/dev/null || (echo -e "$(RED)[ERROR]$(NC) bpftool not found" && exit 1)
	@pkg-config --exists libbpf || (echo -e "$(RED)[ERROR]$(NC) libbpf-devel not found" && exit 1)
	@pkg-config --exists libxdp || (echo -e "$(RED)[ERROR]$(NC) libxdp-devel not found" && exit 1)
	@echo -e "$(GREEN)[SUCCESS]$(NC) All dependencies satisfied"

# Verify build integrity
check-build: build
	@echo -e "$(BLUE)[VERIFY]$(NC) Verifying build integrity..."
	@test -f ebpf/xdp_filter.o || (echo -e "$(RED)[ERROR]$(NC) eBPF program missing" && exit 1)
	@test -x userspace/af_xdp_loader || (echo -e "$(RED)[ERROR]$(NC) Userspace loader missing" && exit 1)
	@if command -v bpftool >/dev/null; then \
		bpftool prog load ebpf/xdp_filter.o /sys/fs/bpf/verify_test 2>/dev/null && \
		rm -f /sys/fs/bpf/verify_test && \
		echo -e "$(GREEN)[SUCCESS]$(NC) eBPF program verified" || \
		echo -e "$(YELLOW)[WARNING]$(NC) eBPF verification failed"; \
	fi

# Debug build with additional flags
debug:
	@echo -e "$(BLUE)[DEBUG]$(NC) Building debug version..."
	$(MAKE) -C userspace debug
	@echo -e "$(GREEN)[SUCCESS]$(NC) Debug build completed"

# Continuous integration target
ci: check-deps build check-build
	@echo -e "$(GREEN)[CI]$(NC) Continuous integration checks passed"

# Development convenience targets
dev-start: build
	@echo -e "$(BLUE)[DEV]$(NC) Starting development session..."
	sudo userspace/af_xdp_loader -v -i lo

dev-stop:
	@echo -e "$(YELLOW)[DEV]$(NC) Stopping development session..."
	sudo pkill -f af_xdp_loader || true

# Performance benchmarking
benchmark: build
	@echo -e "$(BLUE)[BENCHMARK]$(NC) Running performance tests..."
	@echo "Benchmark target not yet implemented"

# Security audit
audit: build
	@echo -e "$(BLUE)[AUDIT]$(NC) Running security audit..."
	@if command -v cppcheck >/dev/null; then \
		cppcheck --enable=all --std=c11 userspace/af_xdp_loader.c; \
	else \
		echo -e "$(YELLOW)[WARNING]$(NC) cppcheck not found, skipping static analysis"; \
	fi

# Show project information
info:
	@echo "==============================================="
	@echo "           $(PROJECT_NAME) v$(VERSION)"
	@echo "==============================================="
	@echo "Build Date:    $(BUILD_DATE)"
	@echo "Git Commit:    $(GIT_COMMIT)"
	@echo "Architecture:  $(shell uname -m)"
	@echo "Kernel:        $(shell uname -r)"
	@echo "OS:            $(shell uname -o)"
	@echo "Compiler:      $(shell clang --version | head -1)"
	@echo "==============================================="
	@echo "Components:"
	@echo "  • eBPF XDP filter:     ebpf/xdp_filter.c"
	@echo "  • AF_XDP userspace:    userspace/af_xdp_loader.c"
	@echo "  • Test framework:      ebpf/test_xdp.py"
	@echo "  • Setup script:        scripts/setup.sh"
	@echo "==============================================="

# GUI Management
gui-setup:
	@echo -e "$(BLUE)[GUI-SETUP]$(NC) Setting up GUI development environment..."
	@if [ "$$(id -u)" -eq 0 ]; then \
		echo -e "$(RED)[ERROR]$(NC) Don't run GUI setup as root!"; \
		exit 1; \
	fi
	./gui/setup-gui.sh
	@echo -e "$(GREEN)[SUCCESS]$(NC) GUI environment ready"

gui-dev: gui-setup
	@echo -e "$(BLUE)[GUI-DEV]$(NC) Starting GUI in development mode..."
	@echo "Open http://localhost:3000 for frontend"
	@echo "Open http://localhost:8080/api/docs for backend API"
	cd gui && ./start-backend.sh & ./start-frontend-dev.sh

gui-build: gui-setup
	@echo -e "$(BLUE)[GUI-BUILD]$(NC) Building GUI for production..."
	cd gui/frontend && npm run build
	cd gui/backend && source venv/bin/activate && python -m pytest
	@echo -e "$(GREEN)[SUCCESS]$(NC) GUI build completed"

gui-start: gui-build
	@echo -e "$(BLUE)[GUI-START]$(NC) Starting GUI with Docker..."
	cd gui && ./start-docker.sh
	@echo -e "$(GREEN)[SUCCESS]$(NC) GUI started - http://localhost:3000"

gui-stop:
	@echo -e "$(YELLOW)[GUI-STOP]$(NC) Stopping GUI services..."
	docker-compose -f gui/docker/docker-compose.yml down
	pkill -f "uvicorn main:app" || true
	pkill -f "npm run dev" || true
	@echo -e "$(GREEN)[SUCCESS]$(NC) GUI services stopped"

# Docker development environment
docker: gui-start
	@echo -e "$(GREEN)[DOCKER]$(NC) Full stack started with Docker"

# Show help
help:
	@echo "$(PROJECT_NAME) v$(VERSION) - Production eBPF Firewall"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Build Targets:"
	@echo "  all, build     Build all components"
	@echo "  clean          Clean build artifacts"
	@echo "  debug          Build with debug flags"
	@echo ""
	@echo "Development:"
	@echo "  setup          Setup development environment"
	@echo "  check-deps     Verify dependencies"
	@echo "  check-build    Verify build integrity"
	@echo "  test           Run test suite (requires root)"
	@echo ""
	@echo "GUI Management:"
	@echo "  gui-setup      Setup GUI development environment"
	@echo "  gui-dev        Start GUI in development mode"
	@echo "  gui-build      Build GUI for production"
	@echo "  gui-start      Start GUI with Docker"
	@echo "  gui-stop       Stop GUI services"
	@echo ""
	@echo "Deployment:"
	@echo "  install        Install system-wide (requires root)"
	@echo "  uninstall      Remove system files (requires root)"
	@echo ""
	@echo "Utilities:"
	@echo "  info           Show project information"
	@echo "  audit          Run security audit"
	@echo "  dev-start      Start development session"
	@echo "  dev-stop       Stop development session"
	@echo "  ci             Continuous integration checks"
	@echo "  docker         Start full stack with Docker"
	@echo "  help           Show this help message"
	@echo ""
	@echo "Examples:"
	@echo "  make setup     # First-time environment setup"
	@echo "  make build     # Build everything"
	@echo "  sudo make test # Run comprehensive tests"
	@echo "  make info      # Show project details" 