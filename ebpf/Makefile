# SPDX-License-Identifier: Apache-2.0
# eBPF Makefile: Production-grade build system

# Compiler and tools
CC := clang
LLVM_STRIP := llvm-strip

# eBPF compilation flags
CFLAGS := -O2 -g -Wall -Wextra \
          -target bpf \
          -D__TARGET_ARCH_x86 \
          -I/usr/include/bpf \
          -I/usr/include \
          -fno-stack-protector

# Source and object files
PROG := xdp_filter
SRC := $(PROG).c
OBJ := $(PROG).o

# TC firewall program
TC_PROG := tc_firewall
TC_SRC := $(TC_PROG).c
TC_OBJ := $(TC_PROG).o

# LIVE mode XDP engine
LIVE_PROG := xdp_live_engine
LIVE_SRC := $(LIVE_PROG).c
LIVE_OBJ := $(LIVE_PROG).o

# APT-Shield anti-reconnaissance engine
APT_PROG := apt_antiscan
APT_SRC := $(APT_PROG).c
APT_OBJ := $(APT_PROG).o

# UNIFIED ENGINE (Primary target - replaces all above)
UNIFIED_PROG := unified_engine
UNIFIED_SRC := $(UNIFIED_PROG).c
UNIFIED_OBJ := $(UNIFIED_PROG).o

# Default target
.PHONY: all clean install check apt-shield unified deploy status live simulation unload

# PRIMARY TARGET: Unified engine
all: $(UNIFIED_OBJ)

# Legacy compatibility target
legacy: $(OBJ) $(TC_OBJ) $(LIVE_OBJ) $(APT_OBJ)

# Compile eBPF program
$(OBJ): $(SRC)
	@echo "🔨 Compiling eBPF program: $(SRC) -> $(OBJ)"
	$(CC) $(CFLAGS) -c -o $@ $<
	@echo "🧹 Stripping debug info..."
	$(LLVM_STRIP) -g $@
	@echo "✅ Build complete: $(OBJ)"

# Compile TC eBPF program
$(TC_OBJ): $(TC_SRC)
	@echo "🔨 Compiling TC eBPF program: $(TC_SRC) -> $(TC_OBJ)"
	$(CC) $(CFLAGS) -c -o $@ $<
	@echo "🧹 Stripping debug info..."
	$(LLVM_STRIP) -g $@
	@echo "✅ Build complete: $(TC_OBJ)"

# Compile LIVE mode XDP engine
$(LIVE_OBJ): $(LIVE_SRC)
	@echo "🔨 Compiling LIVE mode XDP engine: $(LIVE_SRC) -> $(LIVE_OBJ)"
	$(CC) $(CFLAGS) -c -o $@ $<
	@echo "🧹 Stripping debug info..."
	$(LLVM_STRIP) -g $@
	@echo "✅ Build complete: $(LIVE_OBJ)"

# Compile APT-Shield anti-reconnaissance engine
$(APT_OBJ): $(APT_SRC)
	@echo "🛡️ Compiling APT-Shield anti-reconnaissance engine: $(APT_SRC) -> $(APT_OBJ)"
	$(CC) $(CFLAGS) -c -o $@ $<
	@echo "🧹 Stripping debug info..."
	$(LLVM_STRIP) -g $@
	@echo "✅ Build complete: $(APT_OBJ)"

# Compile UNIFIED ENGINE (primary target)
$(UNIFIED_OBJ): $(UNIFIED_SRC)
	@echo "🚀 Compiling Cerberus-V Unified eBPF Engine: $(UNIFIED_SRC) -> $(UNIFIED_OBJ)"
	$(CC) $(CFLAGS) -DUNIFIED_ENGINE=1 -c -o $@ $<
	@echo "🧹 Stripping debug info..."
	$(LLVM_STRIP) -g $@
	@echo "✅ Unified engine build complete: $(UNIFIED_OBJ)"

# Unified target
unified: $(UNIFIED_OBJ)
	@echo "🎯 Cerberus-V Unified Engine compiled successfully"

# APT-Shield compilation target (legacy)
apt-shield: $(APT_OBJ)
	@echo "🛡️ APT-Shield eBPF program compiled successfully"

# Verify eBPF program
check: $(OBJ)
	@echo "🔍 Verifying eBPF program..."
	@bpftool prog load $(OBJ) /sys/fs/bpf/test_prog 2>/dev/null && \
		echo "✅ eBPF program verification passed" && \
		rm -f /sys/fs/bpf/test_prog || \
		(echo "❌ eBPF program verification failed" && exit 1)

# Install to system location (requires root)
install: $(OBJ) check
	@echo "📦 Installing eBPF program..."
	sudo mkdir -p /opt/vppebpf/ebpf
	sudo cp $(OBJ) /opt/vppebpf/ebpf/
	sudo chmod 644 /opt/vppebpf/ebpf/$(OBJ)
	@echo "✅ Installed to /opt/vppebpf/ebpf/"

# Clean build artifacts
clean:
	@echo "🧹 Cleaning up..."
	rm -f $(OBJ) $(TC_OBJ) $(LIVE_OBJ) $(APT_OBJ) $(UNIFIED_OBJ)
	@sudo rm -f /sys/fs/bpf/test_prog 2>/dev/null || true

# Deploy unified engine safely
deploy: $(UNIFIED_OBJ)
	@echo "🚀 Deploying Cerberus-V Unified Engine..."
	sudo ../scripts/deploy_unified_engine.sh

# Show current status
status:
	@echo "📊 Cerberus-V Status:"
	@if [[ -f "/sys/fs/bpf/cerberus_unified" ]]; then \
		echo "✅ Unified engine loaded"; \
		sudo ../scripts/cerberus-mode-switch.sh status; \
	else \
		echo "❌ Unified engine not loaded"; \
		echo "Run 'make deploy' to deploy the unified engine"; \
	fi

# Switch to LIVE mode
live:
	@sudo ../scripts/cerberus-mode-switch.sh live

# Switch to SIMULATION mode
simulation:
	@sudo ../scripts/cerberus-mode-switch.sh simulation

# Unload all programs
unload:
	@echo "🛑 Unloading all Cerberus eBPF programs..."
	@sudo ip link show | grep -E "xdp|xdpgeneric" | cut -d: -f2 | awk '{print $$1}' | while read iface; do \
		echo "Detaching XDP from $$iface"; \
		sudo ip link set dev "$$iface" xdpgeneric off 2>/dev/null || true; \
	done
	@sudo rm -f /sys/fs/bpf/cerberus_*
	@echo "✅ All programs unloaded"

# Show build info
info:
	@echo "📊 Build Information:"
	@echo "  Compiler: $(CC)"
	@echo "  Primary:  $(UNIFIED_SRC) -> $(UNIFIED_OBJ)"
	@echo "  Legacy:   $(SRC) -> $(OBJ)"
	@echo "  Flags:    $(CFLAGS)"
	@echo ""
	@echo "🎯 Available targets:"
	@echo "  all         - Build unified engine (primary)"
	@echo "  deploy      - Deploy unified engine safely"
	@echo "  status      - Show current system status"
	@echo "  live        - Switch to LIVE mode"
	@echo "  simulation  - Switch to SIMULATION mode"
	@echo "  unload      - Unload all programs" 