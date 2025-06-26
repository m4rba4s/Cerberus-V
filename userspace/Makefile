# SPDX-License-Identifier: Apache-2.0
# Userspace Makefile: Production-grade build system

# Compiler and tools
CC := gcc
PKG_CONFIG := pkg-config

# Binary and source
TARGET := af_xdp_loader
SRC := af_xdp_loader.c
OBJ := $(SRC:.c=.o)

# Compiler flags
CFLAGS := -std=c11 -O2 -g -Wall -Wextra -Wpedantic \
          -D_GNU_SOURCE \
          $(shell $(PKG_CONFIG) --cflags libbpf libxdp 2>/dev/null)

# Linker flags and libraries
LDFLAGS := $(shell $(PKG_CONFIG) --libs libbpf libxdp 2>/dev/null)
ifeq ($(LDFLAGS),)
    # Fallback if pkg-config fails
    LDFLAGS := -lbpf -lxdp
endif

# Default target
.PHONY: all clean install check test debug

all: $(TARGET)

# Build main binary
$(TARGET): $(OBJ)
	@echo "🔗 Linking $(TARGET)..."
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)
	@echo "✅ Build complete: $(TARGET)"

# Compile object file
$(OBJ): $(SRC)
	@echo "🔨 Compiling $(SRC)..."
	$(CC) $(CFLAGS) -c -o $@ $<

# Check dependencies
check:
	@echo "🔍 Checking dependencies..."
	@which clang >/dev/null || (echo "❌ clang not found" && exit 1)
	@which bpftool >/dev/null || (echo "❌ bpftool not found" && exit 1)
	@$(PKG_CONFIG) --exists libbpf || (echo "❌ libbpf-devel not found" && exit 1)
	@$(PKG_CONFIG) --exists libxdp || (echo "❌ libxdp-devel not found" && exit 1)
	@echo "✅ All dependencies satisfied"

# Test build (requires eBPF program)
test: $(TARGET)
	@echo "🧪 Testing build..."
	@test -f ../ebpf/xdp_filter.o || (echo "❌ eBPF program not found, run 'make -C ../ebpf' first" && exit 1)
	@./$(TARGET) -h >/dev/null 2>&1 && echo "✅ Binary runs correctly"

# Debug build
debug: CFLAGS += -DDEBUG -fsanitize=address -fsanitize=undefined
debug: LDFLAGS += -fsanitize=address -fsanitize=undefined
debug: $(TARGET)
	@echo "🐛 Debug build complete"

# Install to system location (requires root)
install: $(TARGET) check
	@echo "📦 Installing userspace loader..."
	sudo mkdir -p /opt/vppebpf/bin
	sudo cp $(TARGET) /opt/vppebpf/bin/
	sudo chmod 755 /opt/vppebpf/bin/$(TARGET)
	@echo "✅ Installed to /opt/vppebpf/bin/"

# Clean build artifacts
clean:
	@echo "🧹 Cleaning up..."
	rm -f $(TARGET) $(OBJ)

# Show build info
info:
	@echo "📊 Build Information:"
	@echo "  Compiler: $(CC)"
	@echo "  Target:   $(TARGET)"
	@echo "  Source:   $(SRC)"
	@echo "  CFLAGS:   $(CFLAGS)"
	@echo "  LDFLAGS:  $(LDFLAGS)" 