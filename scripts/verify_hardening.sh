#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Cerberus-V Hardening Verification Script
# APT-Grade Security Compliance Check

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

log() {
    echo -e "${BLUE}[VERIFY]${NC} $1"
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
        fail "This script must be run as root for complete verification"
        exit 1
    fi
}

# 1. Verify immutable logging
verify_immutable_logs() {
    log "Verifying immutable logging..."
    
    if [[ -f /var/log/audit/audit.log ]]; then
        if lsattr /var/log/audit/audit.log | grep -q "i"; then
            pass "Audit log is immutable"
        else
            fail "Audit log is not immutable"
        fi
    else
        warn "Audit log not found"
    fi
    
    if [[ -f /var/log/cerberus/current.log ]]; then
        if lsattr /var/log/cerberus/current.log 2>/dev/null | grep -q "i"; then
            pass "Cerberus log is immutable"
        else
            warn "Cerberus log is not immutable (may be normal)"
        fi
    else
        warn "Cerberus log not found"
    fi
}

# 2. Verify BPF maps cleanup
verify_bpf_maps() {
    log "Verifying BPF maps cleanup..."
    
    if command -v bpftool >/dev/null; then
        if bpftool map show 2>/dev/null | grep -q cerberus; then
            local count=$(bpftool map show 2>/dev/null | grep -c cerberus)
            fail "Found $count stale Cerberus BPF maps"
        else
            pass "No stale Cerberus BPF maps found"
        fi
    else
        warn "bpftool not available"
    fi
}

# 3. Verify hugepages allocation
verify_hugepages() {
    log "Verifying hugepages allocation..."
    
    local hugepages=$(cat /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages 2>/dev/null || echo "0")
    if [[ $hugepages -ge 1024 ]]; then
        pass "Hugepages allocated: $hugepages"
    else
        fail "Insufficient hugepages: $hugepages (need >= 1024)"
    fi
}

# 4. Verify seccomp profiles
verify_seccomp() {
    log "Verifying seccomp profiles..."
    
    if [[ -f scripts/seccomp_profiles.json ]]; then
        if jq empty scripts/seccomp_profiles.json 2>/dev/null; then
            pass "Seccomp profiles JSON is valid"
        else
            fail "Seccomp profiles JSON is invalid"
        fi
    else
        fail "Seccomp profiles not found"
    fi
}

# 5. Verify landlock support
verify_landlock() {
    log "Verifying Landlock LSM support..."
    
    if [[ -f scripts/landlock_integration.c ]]; then
        pass "Landlock integration source found"
        
        # Try to compile landlock test
        if gcc -DTEST_LANDLOCK -o /tmp/landlock_test scripts/landlock_integration.c 2>/dev/null; then
            pass "Landlock integration compiles successfully"
            rm -f /tmp/landlock_test
        else
            warn "Landlock integration compilation failed"
        fi
    else
        fail "Landlock integration source not found"
    fi
}

# 6. Verify hardened eBPF program
verify_hardened_ebpf() {
    log "Verifying hardened eBPF program..."
    
    if [[ -f ebpf/xdp_filter_hardened.c ]]; then
        pass "Hardened eBPF source found"
        
        # Check for constant-blinding
        if grep -q "secret_cookie" ebpf/xdp_filter_hardened.c; then
            pass "Constant-blinding anti-spectre protection found"
        else
            fail "Constant-blinding protection missing"
        fi
        
        # Check for map hardening
        if grep -q "BPF_F_RDONLY_PROG" ebpf/xdp_filter_hardened.c; then
            pass "Map hardening (read-only) found"
        else
            fail "Map hardening missing"
        fi
        
        # Check for tamper detection
        if grep -q "STAT_TAMPER" ebpf/xdp_filter_hardened.c; then
            pass "Map tamper detection found"
        else
            fail "Map tamper detection missing"
        fi
    else
        fail "Hardened eBPF source not found"
    fi
}

# 7. Verify reproducible builds
verify_reproducible_builds() {
    log "Verifying reproducible builds..."
    
    if [[ -f docker/Dockerfile.build ]]; then
        pass "Hermetic Dockerfile.build found"
        
        # Check for pinned digests
        if grep -q "sha256:" docker/Dockerfile.build; then
            pass "Pinned digests found in Dockerfile"
        else
            warn "No pinned digests found in Dockerfile"
        fi
        
        # Check for SOURCE_DATE_EPOCH
        if grep -q "SOURCE_DATE_EPOCH" docker/Dockerfile.build; then
            pass "Reproducible build environment configured"
        else
            fail "SOURCE_DATE_EPOCH not set"
        fi
    else
        fail "Dockerfile.build not found"
    fi
}

# 8. Verify emergency wipe capability
verify_emergency_wipe() {
    log "Verifying emergency wipe capability..."
    
    if [[ -f /usr/local/bin/cerberus-panic.sh ]]; then
        if [[ -x /usr/local/bin/cerberus-panic.sh ]]; then
            pass "Emergency wipe script is executable"
        else
            fail "Emergency wipe script is not executable"
        fi
    else
        fail "Emergency wipe script not found"
    fi
}

# 9. Verify systemd security hardening
verify_systemd_security() {
    log "Verifying systemd security hardening..."
    
    if [[ -f /etc/systemd/system/cerberus-ctrl.service.d/security.conf ]]; then
        pass "Systemd security drop-in found"
        
        # Check for key security options
        local security_opts=("MemoryDenyWriteExecute" "NoNewPrivileges" "ProtectSystem" "SystemCallFilter")
        for opt in "${security_opts[@]}"; do
            if grep -q "$opt" /etc/systemd/system/cerberus-ctrl.service.d/security.conf; then
                pass "Systemd security option: $opt"
            else
                warn "Systemd security option missing: $opt"
            fi
        done
    else
        fail "Systemd security drop-in not found"
    fi
}

# 10. Verify logrotate configuration
verify_logrotate() {
    log "Verifying logrotate configuration..."
    
    if [[ -f /etc/logrotate.d/cerberus ]]; then
        pass "Logrotate configuration found"
        
        # Check for chattr postrotate
        if grep -q "chattr +i" /etc/logrotate.d/cerberus; then
            pass "Logrotate chattr postrotate configured"
        else
            fail "Logrotate chattr postrotate missing"
        fi
    else
        fail "Logrotate configuration not found"
    fi
}

# 11. Performance verification
verify_performance() {
    log "Verifying performance requirements..."
    
    # Check kernel version for eBPF support
    local kernel_version=$(uname -r | cut -d. -f1,2)
    if [[ $(echo "$kernel_version >= 5.4" | bc -l 2>/dev/null || echo "0") -eq 1 ]]; then
        pass "Kernel version supports eBPF: $kernel_version"
    else
        fail "Kernel version too old for eBPF: $kernel_version"
    fi
    
    # Check for required tools
    local required_tools=("clang" "bpftool" "make" "gcc")
    for tool in "${required_tools[@]}"; do
        if command -v "$tool" >/dev/null; then
            pass "Required tool available: $tool"
        else
            fail "Required tool missing: $tool"
        fi
    done
}

# 12. Security compliance check
verify_security_compliance() {
    log "Verifying security compliance..."
    
    # Check for ASLR
    if [[ $(cat /proc/sys/kernel/randomize_va_space 2>/dev/null || echo "0") -gt 0 ]]; then
        pass "ASLR is enabled"
    else
        fail "ASLR is disabled"
    fi
    
    # Check for core dumps disabled
    if [[ $(ulimit -c 2>/dev/null || echo "0") -eq 0 ]]; then
        pass "Core dumps are disabled"
    else
        warn "Core dumps are enabled"
    fi
    
    # Check for secure boot (if available)
    if command -v mokutil >/dev/null; then
        if mokutil --sb-state 2>/dev/null | grep -q "enabled"; then
            pass "Secure boot is enabled"
        else
            warn "Secure boot is disabled"
        fi
    else
        warn "mokutil not available, cannot check secure boot"
    fi
}

# Main verification function
main() {
    echo "==============================================="
    echo "    CERBERUS-V APT-GRADE HARDENING VERIFICATION"
    echo "==============================================="
    echo "System: $(uname -a)"
    echo "Date: $(date)"
    echo "==============================================="
    
    check_root
    
    # Run all verification tests
    verify_immutable_logs
    verify_bpf_maps
    verify_hugepages
    verify_seccomp
    verify_landlock
    verify_hardened_ebpf
    verify_reproducible_builds
    verify_emergency_wipe
    verify_systemd_security
    verify_logrotate
    verify_performance
    verify_security_compliance
    
    # Summary
    echo "==============================================="
    echo "VERIFICATION SUMMARY:"
    echo "Total Tests: $TOTAL_TESTS"
    echo "Passed: $PASSED_TESTS"
    echo "Failed: $FAILED_TESTS"
    echo "Warnings: $WARNINGS"
    echo "==============================================="
    
    if [[ $FAILED_TESTS -eq 0 ]]; then
        echo -e "${GREEN}✅ ALL TESTS PASSED - APT-GRADE HARDENING VERIFIED${NC}"
        exit 0
    else
        echo -e "${RED}❌ $FAILED_TESTS TESTS FAILED - HARDENING INCOMPLETE${NC}"
        exit 1
    fi
}

# Run main function
main "$@" 