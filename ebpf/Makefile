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

# Default target
.PHONY: all clean install check

all: $(OBJ)

# Compile eBPF program
$(OBJ): $(SRC)
	@echo "🔨 Compiling eBPF program: $(SRC) -> $(OBJ)"
	$(CC) $(CFLAGS) -c -o $@ $<
	@echo "🧹 Stripping debug info..."
	$(LLVM_STRIP) -g $@
	@echo "✅ Build complete: $(OBJ)"

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
	rm -f $(OBJ)
	@sudo rm -f /sys/fs/bpf/test_prog 2>/dev/null || true

# Show build info
info:
	@echo "📊 Build Information:"
	@echo "  Compiler: $(CC)"
	@echo "  Source:   $(SRC)"
	@echo "  Object:   $(OBJ)"
	@echo "  Flags:    $(CFLAGS)" 