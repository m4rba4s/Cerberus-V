#!/bin/bash
# Cerberus-V System Monitor & Auto-Recovery
# Elite-Mode APT-Grade Stability

set -euo pipefail

# Configuration
BACKEND_URL="http://localhost:8000/api/health"
FRONTEND_URL="http://localhost:3000"
CHECK_INTERVAL=30
MAX_FAILURES=3
LOG_FILE="/var/log/cerberus-monitor.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Health check function
check_health() {
    local url=$1
    local service=$2
    
    if curl -s --max-time 5 "$url" > /dev/null 2>&1; then
        log "${GREEN}✅ $service HEALTHY${NC}"
        return 0
    else
        log "${RED}❌ $service UNHEALTHY${NC}"
        return 1
    fi
}

# Restart service function
restart_service() {
    local service=$1
    local dir=$2
    local cmd=$3
    
    log "${YELLOW}🔄 Restarting $service...${NC}"
    
    # Kill existing process
    pkill -f "$cmd" || true
    sleep 2
    
    # Start new process
    cd "$dir"
    nohup $cmd > "/var/log/cerberus-$service.log" 2>&1 &
    
    log "${GREEN}✅ $service restarted${NC}"
}

# Main monitoring loop
main() {
    log "${BLUE}🚀 Starting Cerberus-V System Monitor${NC}"
    log "Backend URL: $BACKEND_URL"
    log "Frontend URL: $FRONTEND_URL"
    log "Check interval: ${CHECK_INTERVAL}s"
    
    local backend_failures=0
    local frontend_failures=0
    
    while true; do
        # Check backend
        if ! check_health "$BACKEND_URL" "Backend"; then
            ((backend_failures++))
            log "${YELLOW}⚠️  Backend failures: $backend_failures/$MAX_FAILURES${NC}"
            
            if [ $backend_failures -ge $MAX_FAILURES ]; then
                log "${RED}🚨 Backend failed $MAX_FAILURES times, restarting...${NC}"
                restart_service "backend" "/home/outspoken/Cerberus-V/gui/backend" "python3 main.py"
                backend_failures=0
            fi
        else
            backend_failures=0
        fi
        
        # Check frontend
        if ! check_health "$FRONTEND_URL" "Frontend"; then
            ((frontend_failures++))
            log "${YELLOW}⚠️  Frontend failures: $frontend_failures/$MAX_FAILURES${NC}"
            
            if [ $frontend_failures -ge $MAX_FAILURES ]; then
                log "${RED}🚨 Frontend failed $MAX_FAILURES times, restarting...${NC}"
                restart_service "frontend" "/home/outspoken/Cerberus-V/gui/frontend" "npm run dev"
                frontend_failures=0
            fi
        else
            frontend_failures=0
        fi
        
        # Check system resources
        local cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)
        local mem_usage=$(free | grep Mem | awk '{printf("%.1f", $3/$2 * 100.0)}')
        
        if (( $(echo "$cpu_usage > 80" | bc -l) )); then
            log "${YELLOW}⚠️  High CPU usage: ${cpu_usage}%${NC}"
        fi
        
        if (( $(echo "$mem_usage > 80" | bc -l) )); then
            log "${YELLOW}⚠️  High memory usage: ${mem_usage}%${NC}"
        fi
        
        # Check eBPF programs
        if command -v bpftool >/dev/null 2>&1; then
            local ebpf_programs=$(bpftool prog list 2>/dev/null | wc -l)
            if [ "$ebpf_programs" -eq 0 ]; then
                log "${YELLOW}⚠️  No eBPF programs loaded${NC}"
            else
                log "${GREEN}📊 eBPF programs: $ebpf_programs${NC}"
            fi
        fi
        
        sleep $CHECK_INTERVAL
    done
}

# Signal handlers
cleanup() {
    log "${BLUE}🛑 Stopping Cerberus-V System Monitor${NC}"
    exit 0
}

trap cleanup SIGINT SIGTERM

# Check if running as root for system-level operations
if [ "$EUID" -ne 0 ]; then
    log "${YELLOW}⚠️  Running without root privileges. Some features may be limited.${NC}"
fi

# Start monitoring
main 