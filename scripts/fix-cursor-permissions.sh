#!/usr/bin/env bash
# Fix Cursor permissions and restart
# Автор: Λήθη (Lethe) - для Cerberus-V проекта

set -euo pipefail

echo "🔧 Fixing Cursor permissions hell..."

# Исправляем owner на все файлы проекта
echo "📁 Fixing file ownership..."
find /home/outspoken/Cerberus-V/ -not -user outspoken -exec sudo chown outspoken:outspoken {} \;

# Исправляем права доступа
echo "🔐 Fixing permissions..."
chmod -R 755 /home/outspoken/Cerberus-V/

# Очищаем Cursor кэш
echo "🧹 Cleaning Cursor cache..."
rm -rf ~/.config/Cursor/logs/* ~/.config/Cursor/CachedData/* ~/.config/Cursor/Cache/* ~/.config/Cursor/GPUCache/* 2>/dev/null || true

# Убиваем все процессы Cursor
echo "💀 Killing Cursor processes..."
pkill -f cursor 2>/dev/null || true
pkill -f Cursor 2>/dev/null || true

sleep 2

# Перезапускаем Cursor
echo "🚀 Restarting Cursor..."
nohup /home/outspoken/Загрузки/Cursor-1.3.6-x86_64.AppImage > /dev/null 2>&1 &

echo "✅ Done! Cursor should work now without permission errors."
echo "💡 If still having issues, check SELinux: sudo ausearch -m avc -ts recent"