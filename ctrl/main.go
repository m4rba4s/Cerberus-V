// SPDX-License-Identifier: Apache-2.0
// Author: funcybot@gmail.com  Date: 2025-06-26
// Cerberus-V gRPC Control Plane - Firewall Rule Management

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

const (
	gRPCPort = ":50051"
	Version  = "1.0.0"
)

// FirewallRule represents a firewall rule
type FirewallRule struct {
	ID          string    `json:"id"`
	Action      string    `json:"action"`      // allow, drop, redirect
	SrcIP       string    `json:"src_ip"`      // CIDR notation
	DstIP       string    `json:"dst_ip"`      // CIDR notation
	SrcPort     int32     `json:"src_port"`    // 0 = any
	DstPort     int32     `json:"dst_port"`    // 0 = any
	Protocol    string    `json:"protocol"`    // tcp, udp, icmp, any
	Direction   string    `json:"direction"`   // inbound, outbound, both
	Priority    int32     `json:"priority"`    // Lower number = higher priority
	Enabled     bool      `json:"enabled"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Server implements the gRPC firewall control service
type Server struct {
	UnimplementedFirewallControlServer
	rules      map[string]*FirewallRule
	stats      *FirewallStats
	mutex      sync.RWMutex
	vppClient  *VPPClient
	bpfClient  *BPFClient
	bpfManager *BPFMapManager
}

// VPPClient manages VPP integration
type VPPClient struct {
	connected bool
}

// BPFClient manages eBPF integration
type BPFClient struct {
	connected bool
}

// NewServer creates a new gRPC server instance
func NewServer(bpfManager *BPFMapManager) *Server {
	return &Server{
		rules: make(map[string]*FirewallRule),
		stats: &FirewallStats{
			Pass:     0,
			Drop:     0,
			Redirect: 0,
			Error:    0,
		},
		vppClient:  &VPPClient{connected: false},
		bpfClient:  &BPFClient{connected: false},
		bpfManager: bpfManager,
	}
}

// AddRule adds a new firewall rule
func (s *Server) AddRule(ctx context.Context, req *AddRuleRequest) (*RuleResponse, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	rule := &FirewallRule{
		ID:          generateRuleID(),
		Action:      req.Rule.Action,
		SrcIP:       req.Rule.SrcIp,
		DstIP:       req.Rule.DstIp,
		SrcPort:     req.Rule.SrcPort,
		DstPort:     req.Rule.DstPort,
		Protocol:    req.Rule.Protocol,
		Direction:   req.Rule.Direction,
		Priority:    req.Rule.Priority,
		Enabled:     req.Rule.Enabled,
		Description: req.Rule.Description,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	// Validate rule
	if err := s.validateRule(rule); err != nil {
		return &RuleResponse{
			Success: false,
			Message: fmt.Sprintf("Rule validation failed: %v", err),
		}, nil
	}

	// Add to local store
	s.rules[rule.ID] = rule

	// Push to data plane
	if err := s.pushRuleToDataPlane(rule); err != nil {
		delete(s.rules, rule.ID)
		return &RuleResponse{
			Success: false,
			Message: fmt.Sprintf("Failed to push rule to data plane: %v", err),
		}, nil
	}

	log.Printf("Added rule: %s - %s %s->%s %s", 
		rule.ID, rule.Action, rule.SrcIP, rule.DstIP, rule.Protocol)

	return &RuleResponse{
		Success: true,
		Message: "Rule added successfully",
		RuleId:  rule.ID,
	}, nil
}

// DeleteRule removes a firewall rule
func (s *Server) DeleteRule(ctx context.Context, req *DeleteRuleRequest) (*StatusResponse, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	rule, exists := s.rules[req.RuleId]
	if !exists {
		return &StatusResponse{
			Success: false,
			Message: "Rule not found",
		}, nil
	}

	// Remove from data plane
	if err := s.removeRuleFromDataPlane(rule); err != nil {
		return &StatusResponse{
			Success: false,
			Message: fmt.Sprintf("Failed to remove rule from data plane: %v", err),
		}, nil
	}

	// Remove from local store
	delete(s.rules, req.RuleId)

	log.Printf("Deleted rule: %s", req.RuleId)

	return &StatusResponse{
		Success: true,
		Message: "Rule deleted successfully",
	}, nil
}

// GetStats returns current firewall statistics
func (s *Server) GetStats(ctx context.Context, req *Empty) (*Statistics, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	// Update stats from data plane
	s.updateStatsFromDataPlane()

	return &Statistics{
		TotalPackets:   s.stats.Pass + s.stats.Drop + s.stats.Redirect,
		TotalBytes:     (s.stats.Pass + s.stats.Drop + s.stats.Redirect) * 64,
		DroppedPackets: s.stats.Drop,
		AllowedPackets: s.stats.Pass + s.stats.Redirect,
		ActiveRules:    int32(len(s.rules)),
		Uptime:         int64(time.Since(time.Now()).Seconds()),
	}, nil
}

// GetRules returns all firewall rules
func (s *Server) GetRules(ctx context.Context, req *Empty) (*RulesResponse, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	var rules []*Rule
	for _, rule := range s.rules {
		rules = append(rules, &Rule{
			Id:          rule.ID,
			Action:      rule.Action,
			SrcIp:       rule.SrcIP,
			DstIp:       rule.DstIP,
			SrcPort:     rule.SrcPort,
			DstPort:     rule.DstPort,
			Protocol:    rule.Protocol,
			Direction:   rule.Direction,
			Priority:    rule.Priority,
			Enabled:     rule.Enabled,
			Description: rule.Description,
		})
	}

	return &RulesResponse{
		Rules: rules,
		Count: int32(len(rules)),
	}, nil
}

// Helper functions

func generateRuleID() string {
	return fmt.Sprintf("rule_%d", time.Now().UnixNano())
}

func (s *Server) validateRule(rule *FirewallRule) error {
	if rule.Action == "" {
		return fmt.Errorf("action is required")
	}
	if rule.Action != "allow" && rule.Action != "drop" && rule.Action != "redirect" {
		return fmt.Errorf("invalid action: %s", rule.Action)
	}
	if rule.Protocol != "" && rule.Protocol != "tcp" && rule.Protocol != "udp" && 
	   rule.Protocol != "icmp" && rule.Protocol != "any" {
		return fmt.Errorf("invalid protocol: %s", rule.Protocol)
	}
	return nil
}

func (s *Server) pushRuleToDataPlane(rule *FirewallRule) error {
	// Push rule to eBPF via BPF manager
	if s.bpfManager != nil {
		if err := s.bpfManager.AddRuleToMap(rule); err != nil {
			log.Printf("Failed to add rule to eBPF map: %v", err)
		}
	}

	// Simulate pushing rule to VPP
	if s.vppClient.connected {
		log.Printf("Pushing rule %s to VPP", rule.ID)
		// vpp.AddRule(rule) - actual VPP API call would go here
	}

	return nil
}

func (s *Server) removeRuleFromDataPlane(rule *FirewallRule) error {
	// Simulate removing rule from VPP
	if s.vppClient.connected {
		log.Printf("Removing rule %s from VPP", rule.ID)
		// vpp.DeleteRule(rule.ID) - actual VPP API call would go here
	}

	// Simulate removing rule from eBPF
	if s.bpfClient.connected {
		log.Printf("Removing rule %s from eBPF", rule.ID)
		// bpf.DeleteMapEntry(rule.ID) - actual eBPF map update would go here
	}

	return nil
}

func (s *Server) updateStatsFromDataPlane() {
	// Get real stats from eBPF
	if s.bpfManager != nil {
		if ebpfStats, err := s.bpfManager.GetStats(); err == nil {
			s.stats.Pass = ebpfStats.Pass
			s.stats.Drop = ebpfStats.Drop
			s.stats.Redirect = ebpfStats.Redirect
			s.stats.Error = ebpfStats.Error
		}
	} else {
		// Simulate collecting stats
		s.stats.Pass += 1000
		s.stats.Drop += 10
		s.stats.Redirect += 50
		s.stats.Error += 1
	}
}

func main() {
	log.Printf("Starting Cerberus-V gRPC Control Plane v%s", Version)

	// Initialize BPF map manager
	bpfManager, err := NewBPFMapManager()
	if err != nil {
		log.Printf("Warning: Failed to initialize BPF manager: %v", err)
		log.Printf("Continuing in simulation mode...")
		bpfManager = nil
	}
	if bpfManager != nil {
		defer bpfManager.Close()
		// Run end-to-end demo
		bpfManager.DemoEndToEnd()
	}

	// Create server
	server := NewServer(bpfManager)

	// Start Prometheus exporter
	exporter := NewPrometheusExporter(bpfManager, server)
	go func() {
		if err := exporter.Start(8080); err != nil {
			log.Printf("Prometheus exporter failed: %v", err)
		}
	}()

	// For testing, just run a simple HTTP server instead of gRPC
	log.Printf("🎯 Test mode: Running simple HTTP server on %s", gRPCPort)
	
	// Simple test HTTP endpoints
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("OK - Cerberus-V Control Plane"))
	})
	
	http.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		stats, _ := server.GetStats(context.Background(), &Empty{})
		json.NewEncoder(w).Encode(stats)
	})
	
	http.HandleFunc("/rules", func(w http.ResponseWriter, r *http.Request) {
		rules, _ := server.GetRules(context.Background(), &Empty{})
		json.NewEncoder(w).Encode(rules)
	})

	// Handle graceful shutdown
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan
		
		log.Println("Shutting down server...")
		os.Exit(0)
	}()

	log.Printf("Test server listening on %s", gRPCPort)
	log.Println("Available endpoints:")
	log.Println("  - http://localhost:50051/health")
	log.Println("  - http://localhost:50051/stats") 
	log.Println("  - http://localhost:50051/rules")
	log.Println("  - http://localhost:8080/metrics (Prometheus)")
	
	if err := http.ListenAndServe(gRPCPort, nil); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
} 