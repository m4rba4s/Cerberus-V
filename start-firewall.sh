#!/bin/bash
# 🛡️ Cerberus-V - Только фаервол (быстрый запуск)

echo "🛡️ CERBERUS-V FIREWALL"
echo "====================="

cd "$(dirname "$0")"

# Убиваем старые процессы
lsof -ti:50051 2>/dev/null | xargs kill -9 2>/dev/null || true

echo "🚀 Starting firewall..."
cd ctrl
go run . &

echo "⏳ Waiting for startup..."
sleep 3

if curl -s --max-time 2 http://localhost:50051/health >/dev/null; then
    echo "✅ Firewall is running!"
    echo "📊 API: http://localhost:50051"
    echo "🧪 Test: curl http://localhost:50051/stats"
else
    echo "❌ Failed to start"
    exit 1
fi

echo "🎯 Firewall active. Press Ctrl+C to stop."
wait 