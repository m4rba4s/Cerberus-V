#!/bin/bash
# Fixed Cursor launcher with proper permissions

# Kill any existing Cursor processes
pkill -f "cursor" 2>/dev/null || true
sleep 2

# Clean up mount points
sudo umount /tmp/.mount_Cursor* 2>/dev/null || true
sudo rm -rf /tmp/.mount_Cursor* 2>/dev/null || true

# Set proper permissions
sudo chown -R outspoken:outspoken /home/outspoken/Cerberus-V
chmod -R 755 /home/outspoken/Cerberus-V

# Set environment variables for AppImage
export ELECTRON_NO_ATTACH_CONSOLE=1
export ELECTRON_RUN_AS_NODE=0
export ELECTRON_NO_SANDBOX=1

# Start Cursor with AppImage
echo "Starting Cursor with fixed permissions..."
/home/outspoken/Загрузки/Cursor-1.3.6-x86_64.AppImage --no-sandbox --disable-gpu-sandbox --disable-dev-shm-usage 