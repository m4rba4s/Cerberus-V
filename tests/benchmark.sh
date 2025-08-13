#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Author: funcybot@gmail.com  Date: 2025-06-26
# Cerberus-V Performance Benchmarking Script

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
RESULTS_DIR="$SCRIPT_DIR/benchmarks"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Create results directory
mkdir -p "$RESULTS_DIR"

# Test configuration
DURATION=10  # seconds
PACKET_SIZE=64  # bytes
TARGET_PPS=1000000  # 1M packets per second

log_info "Starting Cerberus-V Performance Benchmarks"
log_info "Duration: ${DURATION}s, Packet Size: ${PACKET_SIZE}B, Target PPS: ${TARGET_PPS}"

# Check for required tools
check_tools() {
    local missing_tools=()
    
    for tool in iperf3 netperf ping hping3; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done
    
    if [ ${#missing_tools[@]} -gt 0 ]; then
        log_warning "Missing tools: ${missing_tools[*]}"
        log_info "Installing missing tools..."
        
        # Try to install missing tools
        if command -v apt-get &> /dev/null; then
            sudo apt-get update
            sudo apt-get install -y "${missing_tools[@]}" || log_warning "Failed to install some tools"
        elif command -v yum &> /dev/null; then
            sudo yum install -y "${missing_tools[@]}" || log_warning "Failed to install some tools"
        else
            log_error "Cannot install tools automatically. Please install: ${missing_tools[*]}"
        fi
    fi
}

# Basic networking benchmarks
run_network_benchmarks() {
    log_info "Running basic network benchmarks..."
    
    # Ping latency test
    log_info "Testing ping latency to localhost..."
    ping -c 10 127.0.0.1 > "$RESULTS_DIR/ping_localhost.txt" 2>&1 || log_warning "Ping test failed"
    
    # iperf3 throughput test
    if command -v iperf3 &> /dev/null; then
        log_info "Testing TCP throughput with iperf3..."
        
        # Start iperf3 server in background
        iperf3 -s -D -p 5201 > /dev/null 2>&1
        sleep 2
        
        # Run client test
        iperf3 -c 127.0.0.1 -p 5201 -t "$DURATION" -J > "$RESULTS_DIR/iperf3_tcp.json" 2>&1 || log_warning "iperf3 TCP test failed"
        
        # UDP test
        iperf3 -c 127.0.0.1 -p 5201 -u -b 1G -t "$DURATION" -J > "$RESULTS_DIR/iperf3_udp.json" 2>&1 || log_warning "iperf3 UDP test failed"
        
        # Stop iperf3 server
        pkill -f "iperf3 -s" || true
    fi
}

# eBPF performance simulation
run_ebpf_benchmarks() {
    log_info "Running eBPF performance simulation..."
    
    local ebpf_object="$PROJECT_ROOT/ebpf/xdp_filter.o"
    
    if [ ! -f "$ebpf_object" ]; then
        log_warning "eBPF object not found: $ebpf_object"
        log_info "Building eBPF object..."
        cd "$PROJECT_ROOT/ebpf"
        make clean && make || {
            log_error "Failed to build eBPF object"
            return 1
        }
        cd - > /dev/null
    fi
    
    # Simulate packet processing performance
    log_info "Simulating XDP packet processing..."
    
    cat > "$RESULTS_DIR/ebpf_simulation.py" << 'EOF'
#!/usr/bin/env python3
import time
import random
import json

def simulate_packet_processing(packets_per_second, duration):
    """Simulate XDP packet processing"""
    start_time = time.time()
    processed = 0
    dropped = 0
    redirected = 0
    
    target_interval = 1.0 / packets_per_second
    
    while time.time() - start_time < duration:
        # Simulate packet processing decision
        packet_type = random.randint(1, 100)
        
        if packet_type <= 5:  # 5% ICMP - drop
            dropped += 1
        elif packet_type <= 50:  # 45% TCP - redirect to AF_XDP
            redirected += 1
        else:  # 50% other - pass
            processed += 1
            
        # Simulate processing time
        time.sleep(target_interval * 0.001)  # 0.1% of target interval
        
        if (processed + dropped + redirected) % 100000 == 0:
            print(f"Processed {processed + dropped + redirected} packets...")
    
    end_time = time.time()
    actual_duration = end_time - start_time
    total_packets = processed + dropped + redirected
    actual_pps = total_packets / actual_duration
    
    return {
        "duration": actual_duration,
        "total_packets": total_packets,
        "processed": processed,
        "dropped": dropped,
        "redirected": redirected,
        "packets_per_second": actual_pps,
        "drop_rate": (dropped / total_packets) * 100 if total_packets > 0 else 0
    }

if __name__ == "__main__":
    result = simulate_packet_processing(1000000, 10)  # 1M PPS for 10 seconds
    print(json.dumps(result, indent=2))
EOF
    
    python3 "$RESULTS_DIR/ebpf_simulation.py" > "$RESULTS_DIR/ebpf_performance.json" 2>&1 || log_warning "eBPF simulation failed"
}

# Memory and CPU benchmarks
run_system_benchmarks() {
    log_info "Running system performance benchmarks..."
    
    # CPU info
    log_info "Collecting CPU information..."
    lscpu > "$RESULTS_DIR/cpu_info.txt" 2>&1 || log_warning "Failed to collect CPU info"
    
    # Memory info
    log_info "Collecting memory information..."
    free -h > "$RESULTS_DIR/memory_info.txt" 2>&1 || log_warning "Failed to collect memory info"
    cat /proc/meminfo > "$RESULTS_DIR/meminfo.txt" 2>&1 || log_warning "Failed to collect detailed memory info"
    
    # Network interfaces
    log_info "Collecting network interface information..."
    ip link show > "$RESULTS_DIR/network_interfaces.txt" 2>&1 || log_warning "Failed to collect network info"
    
    # Kernel version
    log_info "Collecting kernel information..."
    uname -a > "$RESULTS_DIR/kernel_info.txt" 2>&1 || log_warning "Failed to collect kernel info"
    
    # Load average during test
    log_info "Monitoring system load..."
    for i in {1..10}; do
        echo "Sample $i: $(uptime)" >> "$RESULTS_DIR/load_average.txt"
        sleep 1
    done
}

# Generate performance report
generate_report() {
    log_info "Generating performance report..."
    
    local report_file="$RESULTS_DIR/performance_report.md"
    
    cat > "$report_file" << EOF
# Cerberus-V Performance Benchmark Report

**Generated:** $(date)
**Test Duration:** ${DURATION} seconds
**Target PPS:** ${TARGET_PPS}
**Packet Size:** ${PACKET_SIZE} bytes

## System Information

### CPU
\`\`\`
$(cat "$RESULTS_DIR/cpu_info.txt" 2>/dev/null || echo "CPU info not available")
\`\`\`

### Memory
\`\`\`
$(cat "$RESULTS_DIR/memory_info.txt" 2>/dev/null || echo "Memory info not available")
\`\`\`

### Kernel
\`\`\`
$(cat "$RESULTS_DIR/kernel_info.txt" 2>/dev/null || echo "Kernel info not available")
\`\`\`

## Network Performance

### iperf3 TCP Results
\`\`\`json
$(cat "$RESULTS_DIR/iperf3_tcp.json" 2>/dev/null || echo "TCP test not available")
\`\`\`

### iperf3 UDP Results
\`\`\`json
$(cat "$RESULTS_DIR/iperf3_udp.json" 2>/dev/null || echo "UDP test not available")
\`\`\`

## eBPF Performance Simulation

\`\`\`json
$(cat "$RESULTS_DIR/ebpf_performance.json" 2>/dev/null || echo "eBPF simulation not available")
\`\`\`

## Ping Latency
\`\`\`
$(cat "$RESULTS_DIR/ping_localhost.txt" 2>/dev/null || echo "Ping test not available")
\`\`\`

## Load Average During Test
\`\`\`
$(cat "$RESULTS_DIR/load_average.txt" 2>/dev/null || echo "Load average not available")
\`\`\`

---
*Report generated by Cerberus-V benchmark suite*
EOF

    log_success "Performance report generated: $report_file"
}

# Main execution
main() {
    log_info "Cerberus-V Performance Benchmark Suite"
    log_info "Results will be saved to: $RESULTS_DIR"
    
    # Check prerequisites
    check_tools
    
    # Run benchmark suites
    run_system_benchmarks
    run_network_benchmarks
    run_ebpf_benchmarks
    
    # Generate report
    generate_report
    
    log_success "Benchmarks completed successfully!"
    log_info "View results with: cat $RESULTS_DIR/performance_report.md"
}

# Run main function
main "$@" 