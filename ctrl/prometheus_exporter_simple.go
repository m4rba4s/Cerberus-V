// SPDX-License-Identifier: Apache-2.0
// Simplified Prometheus exporter for testing

package main

import (
	"fmt"
	"log"
	"net/http"
	"time"
)

// PrometheusExporter manages metrics collection and export
type PrometheusExporter struct {
	bpfManager *BPFMapManager
	server     *Server
	startTime  time.Time
}

// NewPrometheusExporter creates a new Prometheus exporter
func NewPrometheusExporter(bpfManager *BPFMapManager, server *Server) *PrometheusExporter {
	return &PrometheusExporter{
		bpfManager: bpfManager,
		server:     server,
		startTime:  time.Now(),
	}
}

// Start starts the Prometheus HTTP server
func (pe *PrometheusExporter) Start(port int) error {
	// Setup HTTP handler
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", pe.handleMetrics)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// Start server
	addr := fmt.Sprintf(":%d", port)
	log.Printf("Prometheus exporter listening on %s", addr)
	
	return http.ListenAndServe(addr, mux)
}

// handleMetrics serves Prometheus metrics
func (pe *PrometheusExporter) handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	
	// Get current stats
	var stats *FirewallStats
	if pe.bpfManager != nil {
		stats, _ = pe.bpfManager.GetStats()
	} else {
		stats = &FirewallStats{Pass: 1000, Drop: 10, Redirect: 50, Error: 1}
	}
	
	// Calculate uptime
	uptime := time.Since(pe.startTime).Seconds()
	
	// Active rules count
	var activeRules int
	if pe.server != nil {
		pe.server.mutex.RLock()
		activeRules = len(pe.server.rules)
		pe.server.mutex.RUnlock()
	}
	
	// Generate Prometheus metrics
	metrics := fmt.Sprintf(`# HELP cerberus_uptime_seconds System uptime in seconds
# TYPE cerberus_uptime_seconds gauge
cerberus_uptime_seconds %.2f

# HELP cerberus_active_rules Number of active firewall rules  
# TYPE cerberus_active_rules gauge
cerberus_active_rules %d

# HELP cerberus_packets_total Total number of packets processed
# TYPE cerberus_packets_total counter
cerberus_packets_total{action="pass"} %d
cerberus_packets_total{action="drop"} %d
cerberus_packets_total{action="redirect"} %d
cerberus_packets_total{action="error"} %d

# HELP cerberus_bytes_total Total number of bytes processed (estimated)
# TYPE cerberus_bytes_total counter
cerberus_bytes_total{action="pass"} %d
cerberus_bytes_total{action="drop"} %d

# HELP cerberus_performance_latency_microseconds Processing latency
# TYPE cerberus_performance_latency_microseconds histogram
cerberus_performance_latency_microseconds_bucket{component="ebpf",le="10"} 100
cerberus_performance_latency_microseconds_bucket{component="ebpf",le="50"} 300
cerberus_performance_latency_microseconds_bucket{component="ebpf",le="100"} 500
cerberus_performance_latency_microseconds_bucket{component="ebpf",le="+Inf"} 500
cerberus_performance_latency_microseconds_sum{component="ebpf"} 15000
cerberus_performance_latency_microseconds_count{component="ebpf"} 500

# HELP cerberus_build_info Build information
# TYPE cerberus_build_info gauge
cerberus_build_info{version="1.0.0",mode="test"} 1
`,
		uptime,
		activeRules,
		stats.Pass, stats.Drop, stats.Redirect, stats.Error,
		stats.Pass*64, stats.Drop*64,
	)
	
	w.Write([]byte(metrics))
} 