#!/bin/bash
# Quick health check for Cerberus-V

BACKEND_URL="http://localhost:8000/api/health"
FRONTEND_URL="http://localhost:3000"

echo "🔍 Cerberus-V Health Check"
echo "=========================="

# Check backend
if curl -s --max-time 5 "$BACKEND_URL" > /dev/null; then
    echo "✅ Backend: HEALTHY"
else
    echo "❌ Backend: UNHEALTHY"
fi

# Check frontend
if curl -s --max-time 5 "$FRONTEND_URL" > /dev/null; then
    echo "✅ Frontend: HEALTHY"
else
    echo "❌ Frontend: UNHEALTHY"
fi

# Check eBPF
if command -v bpftool >/dev/null 2>&1; then
    PROGRAMS=$(bpftool prog list 2>/dev/null | wc -l)
    echo "📊 eBPF Programs: $PROGRAMS"
else
    echo "⚠️  bpftool not available"
fi

# Check system resources
CPU=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)
MEM=$(free | grep Mem | awk '{printf("%.1f", $3/$2 * 100.0)}')
echo "💻 CPU Usage: ${CPU}%"
echo "🧠 Memory Usage: ${MEM}%"
