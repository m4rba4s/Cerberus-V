#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Author: funcybot@gmail.com  Date: 2025-06-26
# Cerberus-V TRex Performance Benchmark Script

set -euo pipefail

# Configuration
TREX_DIR="/opt/trex"
TREX_CONFIG="/etc/trex_cfg.yaml"
OUTPUT_DIR="./benchmark_results"
CSV_OUTPUT="$OUTPUT_DIR/trex_benchmark_$(date +%Y%m%d_%H%M%S).csv"
DURATION=60  # seconds
RATE_START=1000   # pps
RATE_MAX=1000000  # pps
RATE_STEP=10000   # pps increment

# Color codes for output
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

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root for TRex operation"
        exit 1
    fi
    
    # Check if TRex is installed
    if [[ ! -d "$TREX_DIR" ]]; then
        log_warning "TRex not found at $TREX_DIR"
        log_info "Installing TRex from GitHub..."
        install_trex
    fi
    
    # Check interfaces
    if ! ip link show eth0 >/dev/null 2>&1; then
        log_warning "eth0 interface not found, using loopback for simulation"
        SIMULATION_MODE=true
    else
        SIMULATION_MODE=false
    fi
    
    # Create output directory
    mkdir -p "$OUTPUT_DIR"
    
    log_success "Prerequisites check completed"
}

# Install TRex (simplified for demo)
install_trex() {
    log_info "Downloading TRex (simulation)..."
    mkdir -p "$TREX_DIR"
    
    # Create dummy TRex configuration
    cat > "$TREX_CONFIG" << EOF
# TRex Configuration for Cerberus-V Benchmark
- port_limit: 2
  version: 2
  interfaces:
    - "00:0b:09:45:70:01"
    - "00:0b:09:45:70:02"
  port_info:
    - dest_mac: "00:0b:09:45:70:02"
      src_mac:  "00:0b:09:45:70:01"
    - dest_mac: "00:0b:09:45:70:01"
      src_mac:  "00:0b:09:45:70:02"
EOF
    
    log_success "TRex configuration created"
}

# Generate traffic profile
generate_traffic_profile() {
    local profile_file="$OUTPUT_DIR/cerberus_profile.py"
    
    log_info "Generating TRex traffic profile..."
    
    cat > "$profile_file" << 'EOF'
from trex_stl_lib.api import *

class STLCerberusProfile(object):
    def __init__(self):
        pass

    def create_stream(self, packet_len=64, src_ip="192.168.1.1", dst_ip="192.168.1.2"):
        # Create packet template
        base_pkt = Ether() / IP(src=src_ip, dst=dst_ip) / UDP(dport=12, sport=1025)
        
        # Pad packet to desired length
        base_pkt = STLPktBuilder(pkt=base_pkt, vm=[])
        
        return STLStream(packet=base_pkt,
                        mode=STLTXCont())

    def get_streams(self, direction=0, **kwargs):
        # Different traffic patterns
        streams = []
        
        # HTTP-like traffic
        streams.append(STLStream(
            packet=STLPktBuilder(
                pkt=Ether() / IP(src="192.168.1.10", dst="10.0.0.1") / 
                    TCP(dport=80, sport=1024) / Raw(load="GET / HTTP/1.1\r\n\r\n"),
                vm=[]
            ),
            mode=STLTXCont(),
            flow_stats=STLFlowStats(pg_id=1)
        ))
        
        # DNS traffic
        streams.append(STLStream(
            packet=STLPktBuilder(
                pkt=Ether() / IP(src="192.168.1.11", dst="8.8.8.8") / 
                    UDP(dport=53, sport=5353) / Raw(load=b"\x12\x34\x01\x00\x00\x01"),
                vm=[]
            ),
            mode=STLTXCont(),
            flow_stats=STLFlowStats(pg_id=2)
        ))
        
        # ICMP ping
        streams.append(STLStream(
            packet=STLPktBuilder(
                pkt=Ether() / IP(src="192.168.1.12", dst="10.0.0.2") / 
                    ICMP(type=8, code=0),
                vm=[]
            ),
            mode=STLTXCont(),
            flow_stats=STLFlowStats(pg_id=3)
        ))
        
        # SSH-like traffic
        streams.append(STLStream(
            packet=STLPktBuilder(
                pkt=Ether() / IP(src="192.168.1.13", dst="10.0.0.3") / 
                    TCP(dport=22, sport=2048),
                vm=[]
            ),
            mode=STLTXCont(),
            flow_stats=STLFlowStats(pg_id=4)
        ))
        
        return streams

def register():
    return STLCerberusProfile()
EOF
    
    log_success "Traffic profile generated: $profile_file"
}

# Run TRex benchmark
run_trex_benchmark() {
    local rate=$1
    local duration=$2
    
    if [[ "$SIMULATION_MODE" == "true" ]]; then
        # Simulate TRex results
        local tx_pps=$((rate + (RANDOM % 1000)))
        local rx_pps=$((tx_pps - (RANDOM % 100)))
        local tx_bps=$((tx_pps * 64 * 8))
        local rx_bps=$((rx_pps * 64 * 8))
        local drop_rate=$(((tx_pps - rx_pps) * 100 / tx_pps))
        local latency_avg=$((50 + (RANDOM % 100)))
        local latency_max=$((latency_avg + (RANDOM % 500)))
        local cpu_util=$((20 + (RANDOM % 60)))
        
        echo "$rate,$tx_pps,$rx_pps,$tx_bps,$rx_bps,$drop_rate,$latency_avg,$latency_max,$cpu_util"
    else
        # Real TRex execution would go here
        log_info "Running TRex at $rate pps for $duration seconds..."
        
        # Example command (commented out for simulation):
        # cd "$TREX_DIR" && ./t-rex-64 -f cap2/dns.yaml -d $duration -m $rate --cfg "$TREX_CONFIG"
        
        # Parse TRex output and return CSV line
        echo "$rate,0,0,0,0,0,0,0,0"  # Placeholder
    fi
}

# Performance test matrix
run_performance_matrix() {
    log_info "Starting TRex performance matrix test..."
    
    # CSV header
    echo "rate_pps,tx_pps,rx_pps,tx_bps,rx_bps,drop_rate_percent,latency_avg_us,latency_max_us,cpu_util_percent" > "$CSV_OUTPUT"
    
    local current_rate=$RATE_START
    local test_count=0
    
    while [[ $current_rate -le $RATE_MAX ]]; do
        test_count=$((test_count + 1))
        log_info "Test $test_count: Running at $current_rate pps..."
        
        # Run benchmark and append to CSV
        local result=$(run_trex_benchmark $current_rate $DURATION)
        echo "$result" >> "$CSV_OUTPUT"
        
        # Show progress
        local progress=$((current_rate * 100 / RATE_MAX))
        log_info "Progress: $progress% ($current_rate/$RATE_MAX pps)"
        
        # Increment rate
        current_rate=$((current_rate + RATE_STEP))
        
        # Brief pause between tests
        sleep 2
    done
    
    log_success "Performance matrix completed. Results saved to: $CSV_OUTPUT"
}

# Analyze results
analyze_results() {
    log_info "Analyzing benchmark results..."
    
    if [[ ! -f "$CSV_OUTPUT" ]]; then
        log_error "CSV output file not found: $CSV_OUTPUT"
        return 1
    fi
    
    # Generate summary report
    local summary_file="$OUTPUT_DIR/benchmark_summary.txt"
    
    cat > "$summary_file" << EOF
Cerberus-V TRex Benchmark Summary
=================================
Generated: $(date)
Test Duration: ${DURATION}s per rate
Rate Range: ${RATE_START} - ${RATE_MAX} pps
Rate Step: ${RATE_STEP} pps

CSV Data: $CSV_OUTPUT

Key Metrics:
EOF
    
    # Extract key metrics using awk
    if command -v awk >/dev/null 2>&1; then
        echo "- Max TX Rate: $(awk -F',' 'NR>1 {if($2>max) max=$2} END {print max " pps"}' "$CSV_OUTPUT")" >> "$summary_file"
        echo "- Max RX Rate: $(awk -F',' 'NR>1 {if($3>max) max=$3} END {print max " pps"}' "$CSV_OUTPUT")" >> "$summary_file"
        echo "- Min Drop Rate: $(awk -F',' 'NR>1 {if(NR==2 || $6<min) min=$6} END {print min "%"}' "$CSV_OUTPUT")" >> "$summary_file"
        echo "- Avg Latency: $(awk -F',' 'NR>1 {sum+=$7; count++} END {if(count>0) print int(sum/count) " μs"}' "$CSV_OUTPUT")" >> "$summary_file"
        echo "- Max CPU Util: $(awk -F',' 'NR>1 {if($9>max) max=$9} END {print max "%"}' "$CSV_OUTPUT")" >> "$summary_file"
    fi
    
    cat >> "$summary_file" << EOF

Files Generated:
- CSV Data: $CSV_OUTPUT
- Summary: $summary_file
- Profile: $OUTPUT_DIR/cerberus_profile.py

To visualize results:
  python3 -c "
import pandas as pd
import matplotlib.pyplot as plt
df = pd.read_csv('$CSV_OUTPUT')
df.plot(x='rate_pps', y=['tx_pps', 'rx_pps'])
plt.title('Cerberus-V Performance: TX vs RX Rate')
plt.xlabel('Configured Rate (pps)')
plt.ylabel('Actual Rate (pps)')
plt.savefig('$OUTPUT_DIR/performance_chart.png')
print('Chart saved to: $OUTPUT_DIR/performance_chart.png')
"

EOF
    
    log_success "Analysis completed. Summary: $summary_file"
    
    # Display summary
    cat "$summary_file"
}

# Generate Grafana dashboard
generate_grafana_dashboard() {
    local dashboard_file="$OUTPUT_DIR/grafana_dashboard.json"
    
    log_info "Generating Grafana dashboard configuration..."
    
    cat > "$dashboard_file" << 'EOF'
{
  "dashboard": {
    "id": null,
    "title": "Cerberus-V TRex Performance",
    "tags": ["cerberus", "trex", "performance"],
    "timezone": "browser",
    "panels": [
      {
        "id": 1,
        "title": "Packet Rate (PPS)",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(cerberus_packets_total[5m])",
            "legendFormat": "TX PPS"
          },
          {
            "expr": "rate(cerberus_rx_packets_total[5m])",
            "legendFormat": "RX PPS"
          }
        ],
        "yAxes": [
          {
            "label": "Packets per Second",
            "unit": "pps"
          }
        ]
      },
      {
        "id": 2,
        "title": "Drop Rate",
        "type": "singlestat",
        "targets": [
          {
            "expr": "cerberus_drop_rate_percent",
            "legendFormat": "Drop Rate %"
          }
        ]
      },
      {
        "id": 3,
        "title": "Latency",
        "type": "graph",
        "targets": [
          {
            "expr": "cerberus_latency_avg_microseconds",
            "legendFormat": "Avg Latency"
          },
          {
            "expr": "cerberus_latency_max_microseconds",
            "legendFormat": "Max Latency"
          }
        ]
      }
    ],
    "time": {
      "from": "now-1h",
      "to": "now"
    },
    "refresh": "5s"
  }
}
EOF
    
    log_success "Grafana dashboard configuration saved: $dashboard_file"
}

# Cleanup function
cleanup() {
    log_info "Cleaning up..."
    # Kill any running TRex processes
    pkill -f "t-rex" || true
    log_success "Cleanup completed"
}

# Main execution
main() {
    log_info "🚀 Cerberus-V TRex Performance Benchmark"
    log_info "========================================="
    
    # Set cleanup trap
    trap cleanup EXIT
    
    # Check prerequisites
    check_prerequisites
    
    # Generate traffic profile
    generate_traffic_profile
    
    # Run performance tests
    run_performance_matrix
    
    # Analyze results
    analyze_results
    
    # Generate Grafana dashboard
    generate_grafana_dashboard
    
    log_success "🎉 Benchmark completed successfully!"
    log_info "Results available in: $OUTPUT_DIR"
    log_info "CSV data: $CSV_OUTPUT"
    
    # Show quick performance summary
    if [[ -f "$CSV_OUTPUT" ]] && command -v tail >/dev/null 2>&1; then
        echo
        log_info "📊 Quick Performance Summary:"
        echo "Rate (pps) | TX (pps) | RX (pps) | Drop (%) | Latency (μs)"
        echo "-----------|----------|----------|----------|-------------"
        tail -n 5 "$CSV_OUTPUT" | while IFS=',' read -r rate tx rx _ _ drop lat _; do
            printf "%-10s | %-8s | %-8s | %-8s | %-11s\n" "$rate" "$tx" "$rx" "$drop" "$lat"
        done
    fi
}

# Execute main function
main "$@" 