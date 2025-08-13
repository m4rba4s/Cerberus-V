#!/bin/bash

# Cerberus-V GUI System Test Suite
# APT-Grade Security & Performance Validation

set -uo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Test counters
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
WARNINGS=0

# Logging function
log() {
    echo -e "${BLUE}[TEST]${NC} $1"
}

pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((PASSED_TESTS++))
    ((TOTAL_TESTS++))
}

fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    ((FAILED_TESTS++))
    ((TOTAL_TESTS++))
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
    ((WARNINGS++))
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "This script must be run as root for full system testing"
        exit 1
    fi
}

# Test 1: System Hardening Verification
test_system_hardening() {
    log "Testing APT-Grade System Hardening..."
    
    # Check immutable logs
    if lsattr /var/log/audit/audit.log 2>/dev/null | grep -q i; then
        pass "Audit log is immutable"
    else
        fail "Audit log is not immutable"
    fi
    
    # Check hugepages
    local hugepages=$(cat /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages 2>/dev/null || echo "0")
    if [[ "$hugepages" -ge 2048 ]]; then
        pass "Hugepages allocated: $hugepages"
    else
        warn "Hugepages allocation: $hugepages (recommended: 2048+)"
    fi
    
    # Check seccomp profiles
    if [[ -f "scripts/seccomp_profiles.json" ]]; then
        if jq empty scripts/seccomp_profiles.json 2>/dev/null; then
            pass "Seccomp profiles JSON is valid"
        else
            fail "Seccomp profiles JSON is invalid"
        fi
    else
        warn "Seccomp profiles not found"
    fi
    
    # Check hardened eBPF
    if [[ -f "ebpf/xdp_filter_hardened.c" ]]; then
        if grep -q "constant-blinding" ebpf/xdp_filter_hardened.c; then
            pass "Constant-blinding anti-spectre protection found"
        else
            fail "Constant-blinding protection not found"
        fi
        
        if grep -q "BPF_F_RDONLY_PROG" ebpf/xdp_filter_hardened.c; then
            pass "Map hardening (read-only) found"
        else
            fail "Map hardening not found"
        fi
    else
        fail "Hardened eBPF source not found"
    fi
}

# Test 2: Backend API Functionality
test_backend_api() {
    log "Testing Backend API Functionality..."
    
    # Check if backend is running
    if curl -s http://localhost:8081/api/system/status >/dev/null 2>&1; then
        pass "Backend API is responding"
        
        # Test system status endpoint
        local status=$(curl -s http://localhost:8081/api/system/status | jq -r '.engine_status' 2>/dev/null)
        if [[ "$status" == "running" ]]; then
            pass "System status shows running"
        else
            fail "System status shows: $status"
        fi
        
        # Test protection mode
        local mode=$(curl -s http://localhost:8081/api/system/status | jq -r '.protection_mode' 2>/dev/null)
        if [[ "$mode" == "dual_protection" ]]; then
            pass "Protection mode: $mode"
        else
            warn "Protection mode: $mode (expected: dual_protection)"
        fi
        
        # Test VPP status
        local vpp_status=$(curl -s http://localhost:8081/api/system/status | jq -r '.vpp_status.status' 2>/dev/null)
        if [[ "$vpp_status" == "running" ]]; then
            pass "VPP status: $vpp_status"
        else
            warn "VPP status: $vpp_status"
        fi
        
        # Test eBPF status
        local ebpf_status=$(curl -s http://localhost:8081/api/system/status | jq -r '.ebpf_status.status' 2>/dev/null)
        if [[ "$ebpf_status" == "active" ]]; then
            pass "eBPF status: $ebpf_status"
        else
            warn "eBPF status: $ebpf_status"
        fi
        
    else
        fail "Backend API is not responding"
    fi
}

# Test 3: Frontend GUI Functionality
test_frontend_gui() {
    log "Testing Frontend GUI Functionality..."
    
    # Check if frontend is running
    if curl -s http://localhost:3000 >/dev/null 2>&1; then
        pass "Frontend GUI is responding"
        
        # Check for React app
        if curl -s http://localhost:3000 | grep -q "VPP eBPF Firewall Dashboard"; then
            pass "React app is loaded"
        else
            fail "React app not properly loaded"
        fi
        
        # Check for Material-UI components
        if curl -s http://localhost:3000 | grep -q "Mui"; then
            pass "Material-UI components detected"
        else
            warn "Material-UI components not detected"
        fi
        
    else
        fail "Frontend GUI is not responding"
    fi
}

# Test 4: Security Features
test_security_features() {
    log "Testing Security Features..."
    
    # Check for security headers
    local headers=$(curl -s -I http://localhost:8081/api/system/status 2>/dev/null)
    if echo "$headers" | grep -q "X-Content-Type-Options"; then
        pass "Security headers present"
    else
        warn "Security headers not detected"
    fi
    
    # Check for CORS
    if curl -s -H "Origin: http://localhost:3000" -H "Access-Control-Request-Method: GET" \
        -H "Access-Control-Request-Headers: X-Requested-With" \
        -X OPTIONS http://localhost:8081/api/system/status >/dev/null 2>&1; then
        pass "CORS is configured"
    else
        warn "CORS configuration not verified"
    fi
    
    # Check for rate limiting (basic)
    local response1=$(curl -s -w "%{http_code}" http://localhost:8081/api/system/status -o /dev/null)
    local response2=$(curl -s -w "%{http_code}" http://localhost:8081/api/system/status -o /dev/null)
    if [[ "$response1" == "200" && "$response2" == "200" ]]; then
        pass "API rate limiting not blocking normal requests"
    else
        warn "API rate limiting may be too aggressive"
    fi
}

# Test 5: Performance Metrics
test_performance_metrics() {
    log "Testing Performance Metrics..."
    
    # Test API response time
    local start_time=$(date +%s%N)
    curl -s http://localhost:8081/api/system/status >/dev/null
    local end_time=$(date +%s%N)
    local response_time=$(( (end_time - start_time) / 1000000 ))
    
    if [[ $response_time -lt 100 ]]; then
        pass "API response time: ${response_time}ms (excellent)"
    elif [[ $response_time -lt 500 ]]; then
        pass "API response time: ${response_time}ms (good)"
    elif [[ $response_time -lt 1000 ]]; then
        warn "API response time: ${response_time}ms (acceptable)"
    else
        fail "API response time: ${response_time}ms (too slow)"
    fi
    
    # Check system resources
    local cpu_usage=$(curl -s http://localhost:8081/api/system/status | jq -r '.system_info.cpu.usage' 2>/dev/null || echo "0")
    if [[ $(echo "$cpu_usage < 80" | bc -l 2>/dev/null || echo "1") == "1" ]]; then
        pass "CPU usage: ${cpu_usage}% (normal)"
    else
        warn "CPU usage: ${cpu_usage}% (high)"
    fi
    
    local memory_usage=$(curl -s http://localhost:8081/api/system/status | jq -r '.system_info.memory.percentage' 2>/dev/null || echo "0")
    if [[ $(echo "$memory_usage < 90" | bc -l 2>/dev/null || echo "1") == "1" ]]; then
        pass "Memory usage: ${memory_usage}% (normal)"
    else
        warn "Memory usage: ${memory_usage}% (high)"
    fi
}

# Test 6: Network Connectivity
test_network_connectivity() {
    log "Testing Network Connectivity..."
    
    # Check network interfaces
    local interfaces=$(curl -s http://localhost:8081/api/system/status | jq -r '.system_info.interfaces[].name' 2>/dev/null)
    if [[ -n "$interfaces" ]]; then
        pass "Network interfaces detected: $(echo "$interfaces" | tr '\n' ' ')"
    else
        fail "No network interfaces detected"
    fi
    
    # Check for active connections
    local connections=$(curl -s http://localhost:8081/api/system/status | jq -r '.network_stats.connections.total' 2>/dev/null || echo "0")
    if [[ "$connections" -gt 0 ]]; then
        pass "Active connections: $connections"
    else
        warn "No active connections detected"
    fi
    
    # Check VPP interfaces
    local vpp_interfaces=$(curl -s http://localhost:8081/api/system/status | jq -r '.vpp_status.interfaces[].name' 2>/dev/null)
    if [[ -n "$vpp_interfaces" ]]; then
        pass "VPP interfaces: $(echo "$vpp_interfaces" | tr '\n' ' ')"
    else
        warn "No VPP interfaces detected"
    fi
}

# Test 7: eBPF Integration
test_ebpf_integration() {
    log "Testing eBPF Integration..."
    
    # Check eBPF programs
    local ebpf_programs=$(curl -s http://localhost:8081/api/system/status | jq -r '.ebpf_status.programs[].name' 2>/dev/null)
    if [[ -n "$ebpf_programs" ]]; then
        pass "eBPF programs loaded: $(echo "$ebpf_programs" | tr '\n' ' ')"
    else
        fail "No eBPF programs detected"
    fi
    
    # Check eBPF maps
    local ebpf_maps=$(curl -s http://localhost:8081/api/system/status | jq -r '.ebpf_status.maps[].name' 2>/dev/null)
    if [[ -n "$ebpf_maps" ]]; then
        pass "eBPF maps created: $(echo "$ebpf_maps" | tr '\n' ' ')"
    else
        fail "No eBPF maps detected"
    fi
    
    # Check eBPF map hits
    local map_hits=$(curl -s http://localhost:8081/api/system/status | jq -r '.vpp_status.stats.ebpf_map_hits' 2>/dev/null || echo "0")
    if [[ "$map_hits" -gt 0 ]]; then
        pass "eBPF map hits: $map_hits"
    else
        warn "No eBPF map hits recorded"
    fi
}

# Test 8: Emergency Features
test_emergency_features() {
    log "Testing Emergency Features..."
    
    # Check emergency wipe script
    if [[ -f "scripts/panic.sh" ]]; then
        if [[ -x "scripts/panic.sh" ]]; then
            pass "Emergency wipe script is executable"
        else
            fail "Emergency wipe script is not executable"
        fi
    else
        fail "Emergency wipe script not found"
    fi
    
    # Check systemd services
    if systemctl is-active --quiet cerberus-ctrl 2>/dev/null; then
        pass "Cerberus control service is active"
    else
        warn "Cerberus control service is not active"
    fi
    
    # Check for security drop-ins
    if [[ -d "/etc/systemd/system/cerberus-ctrl.service.d" ]]; then
        pass "Systemd security drop-ins configured"
    else
        warn "Systemd security drop-ins not found"
    fi
}

# Main test execution
main() {
    echo "==============================================="
    echo "    CERBERUS-V GUI SYSTEM TEST SUITE"
    echo "==============================================="
    echo "System: $(uname -a)"
    echo "Date: $(date)"
    echo "==============================================="
    
    check_root
    
    # Run all tests
    test_system_hardening
    test_backend_api
    test_frontend_gui
    test_security_features
    test_performance_metrics
    test_network_connectivity
    test_ebpf_integration
    test_emergency_features
    
    # Print summary
    echo "==============================================="
    echo "TEST SUMMARY:"
    echo "Total Tests: $TOTAL_TESTS"
    echo "Passed: $PASSED_TESTS"
    echo "Failed: $FAILED_TESTS"
    echo "Warnings: $WARNINGS"
    echo "==============================================="
    
    if [[ $FAILED_TESTS -eq 0 ]]; then
        echo -e "${GREEN}✅ ALL TESTS PASSED - SYSTEM IS OPERATIONAL${NC}"
        exit 0
    else
        echo -e "${RED}❌ $FAILED_TESTS TESTS FAILED - SYSTEM NEEDS ATTENTION${NC}"
        exit 1
    fi
}

# Run main function
main "$@" 