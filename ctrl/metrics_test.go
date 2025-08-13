package main

import (
    "net/http"
    "net/http/httptest"
    "strings"
    "testing"
    "time"

    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promhttp"
)

func withFreshRegistry(t *testing.T, fn func()) {
    reg := prometheus.NewRegistry()
    oldReg := prometheus.DefaultRegisterer
    oldGather := prometheus.DefaultGatherer
    prometheus.DefaultRegisterer = reg
    prometheus.DefaultGatherer = reg
    t.Cleanup(func() {
        prometheus.DefaultRegisterer = oldReg
        prometheus.DefaultGatherer = oldGather
    })
    fn()
}

func TestPrometheusExporter_ExposesCompatibilityMetrics(t *testing.T) {
    withFreshRegistry(t, func() {
        pe := NewPrometheusExporter(0)
        // Seed some values
        pe.uptimeSeconds.Set(1)
        pe.activeRules.Set(2)
        pe.packetsTotal.Add(3)
        pe.bytesTotal.Add(4)

        rr := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/metrics", nil)

        handler := promhttp.Handler()
        handler.ServeHTTP(rr, req)

        body := rr.Body.String()
        for _, want := range []string{
            "cerberus_uptime_seconds",
            "cerberus_active_rules",
            "cerberus_packets_total",
            "cerberus_bytes_total",
        } {
            if !strings.Contains(body, want) {
                t.Fatalf("expected metric %s in output", want)
            }
        }
    })
}

func TestPrometheusExporter_UpdateMetrics(t *testing.T) {
    withFreshRegistry(t, func() {
        pe := NewPrometheusExporter(0)
        stats := &SystemStats{
            Interface:         "lo",
            PacketsRx:         10,
            PacketsTx:         5,
            PacketsDropped:    1,
            BytesRx:           100,
            BytesTx:           50,
            ActiveConnections: 1,
            TCPConnections:    2,
            UDPConnections:    3,
            FirewallRules:     4,
            SystemLoad:        0.1,
            MemoryUsage:       1234,
        }
        pe.UpdateMetrics(stats)

        rr := httptest.NewRecorder()
        req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
        handler := promhttp.Handler()
        handler.ServeHTTP(rr, req)
        out := rr.Body.String()
        if !strings.Contains(out, "cerberus_firewall_rules_count") {
            t.Fatal("missing firewall rules gauge")
        }
    })
}

func TestBPFMapManager_SimStats(t *testing.T) {
    bm, err := NewBPFMapManager()
    if err != nil {
        t.Fatalf("init: %v", err)
    }
    t.Cleanup(func() { _ = bm.Close() })

    s1, err := bm.GetStats()
    if err != nil {
        t.Fatalf("stats1: %v", err)
    }
    time.Sleep(5 * time.Millisecond)
    s2, err := bm.GetStats()
    if err != nil {
        t.Fatalf("stats2: %v", err)
    }
    if s2.Pass == 0 || s1.Pass == 0 {
        t.Fatal("sim stats must be non-zero")
    }
}


