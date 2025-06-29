// SPDX-License-Identifier: Apache-2.0
// Prometheus Metrics Exporter for Cerberus-V

package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type PrometheusExporter struct {
	server *http.Server
	
	// Metrics
	packetsProcessed *prometheus.CounterVec
	packetsDropped   *prometheus.CounterVec
	packetsAllowed   *prometheus.CounterVec
	bytesProcessed   *prometheus.CounterVec
	activeConnections prometheus.Gauge
	ruleCount        prometheus.Gauge
	systemLoad       prometheus.Gauge
	memoryUsage      prometheus.Gauge
	
	// VPP specific metrics
	vppPacketsRx     *prometheus.CounterVec
	vppPacketsTx     *prometheus.CounterVec
	vppDrops         *prometheus.CounterVec
	vppPunts         *prometheus.CounterVec
	
	// eBPF specific metrics
	ebpfMapEntries   *prometheus.GaugeVec
	ebpfPrograms     prometheus.Gauge
	ebpfCpuUsage     prometheus.Gauge
}

func NewPrometheusExporter(port int) *PrometheusExporter {
	pe := &PrometheusExporter{}
	
	// Initialize metrics
	pe.packetsProcessed = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cerberus_packets_processed_total",
			Help: "Total number of packets processed",
		},
		[]string{"interface", "direction"},
	)
	
	pe.packetsDropped = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cerberus_packets_dropped_total",
			Help: "Total number of packets dropped",
		},
		[]string{"interface", "reason"},
	)
	
	pe.packetsAllowed = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cerberus_packets_allowed_total",
			Help: "Total number of packets allowed",
		},
		[]string{"interface", "protocol"},
	)
	
	pe.bytesProcessed = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cerberus_bytes_processed_total",
			Help: "Total bytes processed",
		},
		[]string{"interface", "direction"},
	)
	
	pe.activeConnections = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "cerberus_active_connections",
			Help: "Number of active connections",
		},
	)
	
	pe.ruleCount = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "cerberus_firewall_rules_count",
			Help: "Number of active firewall rules",
		},
	)
	
	pe.systemLoad = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "cerberus_system_load",
			Help: "System load average",
		},
	)
	
	pe.memoryUsage = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "cerberus_memory_usage_bytes",
			Help: "Memory usage in bytes",
		},
	)
	
	// VPP metrics
	pe.vppPacketsRx = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cerberus_vpp_packets_rx_total",
			Help: "VPP packets received",
		},
		[]string{"interface", "worker"},
	)
	
	pe.vppPacketsTx = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cerberus_vpp_packets_tx_total",
			Help: "VPP packets transmitted",
		},
		[]string{"interface", "worker"},
	)
	
	pe.vppDrops = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cerberus_vpp_drops_total",
			Help: "VPP packet drops",
		},
		[]string{"interface", "reason"},
	)
	
	pe.vppPunts = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cerberus_vpp_punts_total",
			Help: "VPP packet punts",
		},
		[]string{"interface", "reason"},
	)
	
	// eBPF metrics
	pe.ebpfMapEntries = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "cerberus_ebpf_map_entries",
			Help: "Number of entries in eBPF maps",
		},
		[]string{"map_name"},
	)
	
	pe.ebpfPrograms = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "cerberus_ebpf_programs_loaded",
			Help: "Number of loaded eBPF programs",
		},
	)
	
	pe.ebpfCpuUsage = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "cerberus_ebpf_cpu_usage_percent",
			Help: "eBPF CPU usage percentage",
		},
	)
	
	// Register metrics
	prometheus.MustRegister(
		pe.packetsProcessed,
		pe.packetsDropped,
		pe.packetsAllowed,
		pe.bytesProcessed,
		pe.activeConnections,
		pe.ruleCount,
		pe.systemLoad,
		pe.memoryUsage,
		pe.vppPacketsRx,
		pe.vppPacketsTx,
		pe.vppDrops,
		pe.vppPunts,
		pe.ebpfMapEntries,
		pe.ebpfPrograms,
		pe.ebpfCpuUsage,
	)
	
	// Setup HTTP server
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/health", pe.healthHandler)
	
	pe.server = &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: mux,
	}
	
	return pe
}

func (pe *PrometheusExporter) Start() error {
	log.Printf("🚀 Starting Prometheus exporter on port %s", pe.server.Addr)
	
	go func() {
		if err := pe.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("❌ Prometheus exporter error: %v", err)
		}
	}()
	
	return nil
}

func (pe *PrometheusExporter) Stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	return pe.server.Shutdown(ctx)
}

func (pe *PrometheusExporter) healthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// Update metrics with current statistics
func (pe *PrometheusExporter) UpdateMetrics(stats *SystemStats) {
	// Basic packet statistics
	pe.packetsProcessed.WithLabelValues(stats.Interface, "rx").Add(float64(stats.PacketsRx))
	pe.packetsProcessed.WithLabelValues(stats.Interface, "tx").Add(float64(stats.PacketsTx))
	pe.packetsDropped.WithLabelValues(stats.Interface, "firewall").Add(float64(stats.PacketsDropped))
	pe.packetsAllowed.WithLabelValues(stats.Interface, "tcp").Add(float64(stats.TCPConnections))
	pe.packetsAllowed.WithLabelValues(stats.Interface, "udp").Add(float64(stats.UDPConnections))
	
	// Bytes processed
	pe.bytesProcessed.WithLabelValues(stats.Interface, "rx").Add(float64(stats.BytesRx))
	pe.bytesProcessed.WithLabelValues(stats.Interface, "tx").Add(float64(stats.BytesTx))
	
	// System metrics
	pe.activeConnections.Set(float64(stats.ActiveConnections))
	pe.ruleCount.Set(float64(stats.FirewallRules))
	pe.systemLoad.Set(stats.SystemLoad)
	pe.memoryUsage.Set(float64(stats.MemoryUsage))
	
	// VPP specific metrics
	pe.vppPacketsRx.WithLabelValues(stats.Interface, "0").Add(float64(stats.VPP.PacketsRx))
	pe.vppPacketsTx.WithLabelValues(stats.Interface, "0").Add(float64(stats.VPP.PacketsTx))
	pe.vppDrops.WithLabelValues(stats.Interface, "acl").Add(float64(stats.VPP.Drops))
	pe.vppPunts.WithLabelValues(stats.Interface, "unknown").Add(float64(stats.VPP.Punts))
	
	// eBPF metrics
	pe.ebpfMapEntries.WithLabelValues("firewall_rules").Set(float64(stats.eBPF.MapEntries))
	pe.ebpfPrograms.Set(float64(stats.eBPF.ProgramsLoaded))
	pe.ebpfCpuUsage.Set(stats.eBPF.CPUUsage)
}

// Custom metrics for threat detection
func (pe *PrometheusExporter) RecordThreatDetection(threatType, severity, sourceIP string) {
	threatCounter := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cerberus_threats_detected_total",
			Help: "Total threats detected",
		},
		[]string{"type", "severity", "source_ip"},
	)
	
	// Register if not already registered
	prometheus.MustRegister(threatCounter)
	threatCounter.WithLabelValues(threatType, severity, sourceIP).Inc()
}

// Performance metrics
func (pe *PrometheusExporter) RecordPerformanceMetrics(latency time.Duration, throughput float64) {
	latencyHist := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "cerberus_processing_latency_seconds",
			Help: "Processing latency in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"component"},
	)
	
	throughputGauge := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "cerberus_throughput_pps",
			Help: "Throughput in packets per second",
		},
		[]string{"component"},
	)
	
	prometheus.MustRegister(latencyHist, throughputGauge)
	
	latencyHist.WithLabelValues("firewall").Observe(latency.Seconds())
	throughputGauge.WithLabelValues("firewall").Set(throughput)
}

// System statistics structure
type SystemStats struct {
	Interface         string
	PacketsRx         uint64
	PacketsTx         uint64
	PacketsDropped    uint64
	BytesRx           uint64
	BytesTx           uint64
	ActiveConnections int
	TCPConnections    uint64
	UDPConnections    uint64
	FirewallRules     int
	SystemLoad        float64
	MemoryUsage       uint64
	
	VPP struct {
		PacketsRx uint64
		PacketsTx uint64
		Drops     uint64
		Punts     uint64
	}
	
	eBPF struct {
		MapEntries      int
		ProgramsLoaded  int
		CPUUsage        float64
	}
} 