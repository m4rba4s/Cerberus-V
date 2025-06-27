#!/bin/bash
# 🛡️ Cerberus-V - Единый скрипт запуска
# Запускает весь firewall + GUI одной командой

set -e

echo "🛡️ CERBERUS-V FIREWALL STARTUP"
echo "=============================="
echo "Starting all components..."
echo

# Переходим в корневую директорию проекта
cd "$(dirname "$0")"

# Функция для проверки порта
check_port() {
    local port=$1
    if netstat -tuln 2>/dev/null | grep -q ":$port "; then
        echo "⚠️  Port $port is busy, killing process..."
        lsof -ti:$port 2>/dev/null | xargs kill -9 2>/dev/null || true
        sleep 1
    fi
}

# Функция остановки всех процессов
cleanup() {
    echo
    echo "🛑 Stopping all Cerberus-V processes..."
    
    # Останавливаем Docker контейнеры
    cd docker 2>/dev/null && ./manage.sh -e monitoring down 2>/dev/null || true
    
    # Убиваем процессы на портах
    for port in 50051 8000 8001 8002 8003 8004 5173 5174 5175; do
        lsof -ti:$port 2>/dev/null | xargs kill -9 2>/dev/null || true
    done
    
    echo "✅ All processes stopped"
    exit 0
}

# Обработка Ctrl+C
trap cleanup SIGINT SIGTERM

# Освобождаем порты
echo "🧹 Cleaning up ports..."
check_port 50051  # Control Plane
check_port 8000   # GUI Backend
check_port 8004   # GUI Backend alt
check_port 5173   # GUI Frontend
check_port 5174   # GUI Frontend alt

echo "✅ Ports cleaned"
echo

# 1. Запускаем Control Plane (Firewall)
echo "1️⃣ Starting Control Plane (Firewall)..."
cd ctrl
go run . > ../control.log 2>&1 &
CTRL_PID=$!
echo "✅ Control Plane started (PID: $CTRL_PID)"
echo "   Logs: control.log"
cd ..

# Ждем запуска Control Plane
sleep 3

# Проверяем что Control Plane запустился
if curl -s --max-time 2 http://localhost:50051/health >/dev/null; then
    echo "✅ Control Plane is healthy"
else
    echo "❌ Control Plane failed to start"
    exit 1
fi

# 2. Запускаем Monitoring (опционально)
echo
echo "2️⃣ Starting Monitoring Stack..."
cd docker
./manage.sh -e monitoring up >/dev/null 2>&1 &
echo "✅ Monitoring started (Prometheus: :9090, Grafana: :3005)"
cd ..

# 3. Запускаем GUI Backend
echo
echo "3️⃣ Starting GUI Backend..."
cd gui/backend
# Пробуем разные порты для backend
for port in 8000 8001 8002 8003 8004; do
    if ! netstat -tuln 2>/dev/null | grep -q ":$port "; then
        sed -i "s/port=[0-9]*/port=$port/g" main.py 2>/dev/null || true
        python3 main.py > ../../gui-backend.log 2>&1 &
        GUI_BACKEND_PID=$!
        echo "✅ GUI Backend started on port $port (PID: $GUI_BACKEND_PID)"
        echo "   Logs: gui-backend.log"
        break
    fi
done
cd ../..

# 4. Запускаем GUI Frontend
echo
echo "4️⃣ Starting GUI Frontend..."
cd gui/frontend
# Пробуем разные порты для frontend
for port in 5173 5174 5175; do
    if ! netstat -tuln 2>/dev/null | grep -q ":$port "; then
        npm run dev -- --port $port > ../../gui-frontend.log 2>&1 &
        GUI_FRONTEND_PID=$!
        echo "✅ GUI Frontend started on port $port (PID: $GUI_FRONTEND_PID)"
        echo "   Logs: gui-frontend.log"
        GUI_PORT=$port
        break
    fi
done
cd ../..

# Ждем полного запуска
echo
echo "⏳ Waiting for all services to start..."
sleep 5

# Финальная проверка
echo
echo "🔍 Final health check..."
if curl -s --max-time 2 http://localhost:50051/health >/dev/null; then
    echo "✅ Control Plane: OK"
else
    echo "❌ Control Plane: FAILED"
fi

echo
echo "🎉 CERBERUS-V STARTED SUCCESSFULLY!"
echo "=================================="
echo
echo "🌐 Access URLs:"
echo "• 🛡️  Firewall API:  http://localhost:50051"
echo "• 📊 Prometheus:     http://localhost:9090"
echo "• 📈 Grafana:        http://localhost:3005 (admin/monitoring123)"
echo "• 🎨 GUI Frontend:   http://localhost:${GUI_PORT:-5173}"
echo "• 🔧 GUI Backend:    http://localhost:${port:-8000}"
echo
echo "📋 Quick Tests:"
echo "curl http://localhost:50051/health"
echo "curl http://localhost:50051/stats"
echo
echo "📁 Logs:"
echo "• Control Plane: control.log"
echo "• GUI Backend:   gui-backend.log"
echo "• GUI Frontend:  gui-frontend.log"
echo
echo "🛑 To stop: Press Ctrl+C or run: pkill -f 'cerberus\|go run'"
echo
echo "⏳ Running... (Press Ctrl+C to stop)"

# Держим скрипт активным
while true; do
    sleep 30
    # Проверяем что процессы еще живы
    if ! kill -0 $CTRL_PID 2>/dev/null; then
        echo "❌ Control Plane died, restarting..."
        cd ctrl && go run . > ../control.log 2>&1 &
        CTRL_PID=$!
        cd ..
    fi
    
    # Показываем статистику каждые 30 сек
    echo "📊 $(date): Firewall active, $(curl -s http://localhost:50051/stats 2>/dev/null | grep -o '"TotalPackets":[0-9]*' | cut -d: -f2 || echo 0) packets processed"
done 