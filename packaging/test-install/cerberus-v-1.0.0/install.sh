#!/bin/bash
# Cerberus-V Installation Script

set -e

PREFIX="${PREFIX:-/usr/local}"
SYSTEMD_DIR="${SYSTEMD_DIR:-/etc/systemd/system}"

echo "Installing Cerberus-V to $PREFIX..."

# Create directories
mkdir -p "$PREFIX/bin" "$PREFIX/lib/cerberus-v" "$PREFIX/share/cerberus-v"

# Install binaries
cp bin/* "$PREFIX/bin/" 2>/dev/null || true

# Install libraries
cp -r lib/* "$PREFIX/lib/cerberus-v/" 2>/dev/null || true

# Install documentation
cp -r share/* "$PREFIX/share/cerberus-v/" 2>/dev/null || true

# Install systemd units (if systemd is available)
if command -v systemctl >/dev/null 2>&1; then
    echo "Installing systemd units..."
    cp systemd/*.service systemd/*.target systemd/*.timer "$SYSTEMD_DIR/" 2>/dev/null || true
    systemctl daemon-reload
fi

echo "✅ Cerberus-V installed successfully!"
echo "📖 Documentation: $PREFIX/share/cerberus-v/"
echo "🚀 Start with: systemctl enable --now cerberus.target"
