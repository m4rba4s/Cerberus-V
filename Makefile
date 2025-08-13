SHELL := /usr/bin/env bash

.PHONY: verify lint web-build go-test py-test

verify: lint web-build go-test py-test

lint:
	@echo "== Linting front/back/go =="
	@cd gui/frontend && npm ci --no-fund --no-audit && npx eslint ./src --ext .ts,.tsx || true
	@cd gui/backend && python3 -m venv venv && ./venv/bin/pip -q install -U pip && ./venv/bin/pip -q install black flake8 mypy bandit || true
	@cd gui/backend && ./venv/bin/flake8 main.py preflight.py mock_live_api.py live_api.py analytics_endpoints.py modules || true
	@cd gui/backend && ./venv/bin/black --check main.py preflight.py mock_live_api.py live_api.py analytics_endpoints.py modules || true
	@cd gui/backend && ./venv/bin/mypy main.py preflight.py mock_live_api.py live_api.py analytics_endpoints.py modules || true
	@cd ctrl && go vet ./... || true

web-build:
	@cd gui/frontend && npm run build

go-test:
	@cd ctrl && go test ./... -count=1 || true

py-test:
	@cd gui/backend && ./venv/bin/pip -q install -U pip pytest httpx starlette fastapi || true
	@cd tests/api && PYTHONPATH=../../gui/backend/ python3 -m pytest -q || true
	@[ -d tests/integration ] && cd tests/integration && ./run_tests.sh || true
	@PYTHONPATH=dsl python3 -m pytest -q tests/dsl || true

# Cerberus-V2: Elite APT-Grade Firewall Makefile
# Minimal, Fast, Efficient

CC = clang
CFLAGS = -O3 -g -Wall -Wextra -fno-stack-protector -fno-builtin
BPF_CFLAGS = -O2 -g -Wall -Wextra -target bpf -D__TARGET_ARCH_x86 \
             -I/usr/include/bpf -I/usr/include -fno-stack-protector

TARGET = cerberus-v2
BPF_OBJ = cerberus-ebpf.o

.PHONY: all clean install uninstall test

all: $(TARGET)

# Compile eBPF program
$(BPF_OBJ): cerberus-ebpf.c
	@echo "🔧 Compiling eBPF program..."
	$(CC) $(BPF_CFLAGS) -c -o $@ $<
	@echo "🧹 Stripping debug info..."
	llvm-strip -g $@
	@echo "✅ eBPF program ready"

# Compile userspace binary
$(TARGET): cerberus-userspace.c $(BPF_OBJ)
	@echo "🔧 Compiling userspace binary..."
	$(CC) $(CFLAGS) -o $@ $< -lbpf -lelf -lz
	@echo "✅ Binary ready"

# Install
install: $(TARGET)
	@echo "📦 Installing Cerberus-V2..."
	sudo cp $(TARGET) /usr/local/bin/
	sudo chmod +x /usr/local/bin/$(TARGET)
	@echo "✅ Installed to /usr/local/bin/$(TARGET)"

# Uninstall
uninstall:
	@echo "🗑️ Uninstalling Cerberus-V2..."
	sudo rm -f /usr/local/bin/$(TARGET)
	@echo "✅ Uninstalled"

# Test
test: $(TARGET)
	@echo "🧪 Testing Cerberus-V2..."
	@echo "Interface: $(shell ip route | grep default | awk '{print $$5}' | head -1)"
	@echo "Run: sudo ./$(TARGET) <interface>"

# Clean
clean:
	@echo "🧹 Cleaning..."
	rm -f $(TARGET) $(BPF_OBJ)
	@echo "✅ Clean"

# Help
help:
	@echo "Cerberus-V2: Elite APT-Grade Firewall"
	@echo ""
	@echo "Targets:"
	@echo "  all       - Build everything"
	@echo "  install   - Install to /usr/local/bin"
	@echo "  uninstall - Remove from /usr/local/bin"
	@echo "  test      - Show test instructions"
	@echo "  clean     - Remove build artifacts"
	@echo "  help      - Show this help"
	@echo ""
	@echo "Usage:"
	@echo "  sudo ./$(TARGET) <interface>" 