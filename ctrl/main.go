// SPDX-License-Identifier: Apache-2.0
// Author: funcybot@gmail.com  Date: 2025-06-26
// Cerberus-V gRPC Control Plane - Firewall Rule Management

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
	pb "github.com/m4rba4s/Cerberus-V/proto"
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

// FirewallStats represents firewall statistics
type FirewallStats struct {
	TotalPackets    uint64            `json:"total_packets"`
	TotalBytes      uint64            `json:"total_bytes"`
	DroppedPackets  uint64            `json:"dropped_packets"`
	AllowedPackets  uint64            `json:"allowed_packets"`
	RuleStats      map[string]uint64  `json:"rule_stats"`
	InterfaceStats map[string]uint64  `json:"interface_stats"`
	LastUpdated    time.Time         `json:"last_updated"`
}

// Server implements the gRPC firewall control service
type Server struct {
	pb.UnimplementedFirewallControlServer
	rules     map[string]*FirewallRule
	stats     *FirewallStats
	mutex     sync.RWMutex
	vppClient *VPPClient
	bpfClient *BPFClient
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
func NewServer() *Server {
	return &Server{
		rules: make(map[string]*FirewallRule),
		stats: &FirewallStats{
			RuleStats:      make(map[string]uint64),
			InterfaceStats: make(map[string]uint64),
			LastUpdated:    time.Now(),
		},
		vppClient: &VPPClient{connected: false},
		bpfClient: &BPFClient{connected: false},
	}
}

// AddRule adds a new firewall rule
func (s *Server) AddRule(ctx context.Context, req *pb.AddRuleRequest) (*pb.RuleResponse, error) {
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
		return &pb.RuleResponse{
			Success: false,
			Message: fmt.Sprintf("Rule validation failed: %v", err),
		}, nil
	}

	// Add to local store
	s.rules[rule.ID] = rule

	// Push to data plane
	if err := s.pushRuleToDataPlane(rule); err != nil {
		delete(s.rules, rule.ID)
		return &pb.RuleResponse{
			Success: false,
			Message: fmt.Sprintf("Failed to push rule to data plane: %v", err),
		}, nil
	}

	log.Printf("Added rule: %s - %s %s->%s %s", 
		rule.ID, rule.Action, rule.SrcIP, rule.DstIP, rule.Protocol)

	return &pb.RuleResponse{
		Success: true,
		Message: "Rule added successfully",
		RuleId:  rule.ID,
	}, nil
}

// DeleteRule removes a firewall rule
func (s *Server) DeleteRule(ctx context.Context, req *pb.DeleteRuleRequest) (*pb.StatusResponse, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	rule, exists := s.rules[req.RuleId]
	if !exists {
		return &pb.StatusResponse{
			Success: false,
			Message: "Rule not found",
		}, nil
	}

	// Remove from data plane
	if err := s.removeRuleFromDataPlane(rule); err != nil {
		return &pb.StatusResponse{
			Success: false,
			Message: fmt.Sprintf("Failed to remove rule from data plane: %v", err),
		}, nil
	}

	// Remove from local store
	delete(s.rules, req.RuleId)

	log.Printf("Deleted rule: %s", req.RuleId)

	return &pb.StatusResponse{
		Success: true,
		Message: "Rule deleted successfully",
	}, nil
}

// GetStats returns current firewall statistics
func (s *Server) GetStats(ctx context.Context, req *pb.Empty) (*pb.Statistics, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	// Update stats from data plane
	s.updateStatsFromDataPlane()

	return &pb.Statistics{
		TotalPackets:   s.stats.TotalPackets,
		TotalBytes:     s.stats.TotalBytes,
		DroppedPackets: s.stats.DroppedPackets,
		AllowedPackets: s.stats.AllowedPackets,
		ActiveRules:    int32(len(s.rules)),
		Uptime:         int64(time.Since(s.stats.LastUpdated).Seconds()),
	}, nil
}

// StreamEvents streams firewall events
func (s *Server) StreamEvents(req *pb.Empty, stream pb.FirewallControl_StreamEventsServer) error {
	// Create event channel
	eventChan := make(chan *pb.Event, 100)
	
	// Start event generator
	go s.generateEvents(eventChan)

	// Stream events to client
	for {
		select {
		case event := <-eventChan:
			if err := stream.Send(event); err != nil {
				log.Printf("Error streaming event: %v", err)
				return err
			}
		case <-stream.Context().Done():
			log.Println("Client disconnected from event stream")
			return nil
		}
	}
}

// GetRules returns all firewall rules
func (s *Server) GetRules(ctx context.Context, req *pb.Empty) (*pb.RulesResponse, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	var rules []*pb.Rule
	for _, rule := range s.rules {
		rules = append(rules, &pb.Rule{
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

	return &pb.RulesResponse{
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
	// Simulate pushing rule to VPP
	if s.vppClient.connected {
		log.Printf("Pushing rule %s to VPP", rule.ID)
		// vpp.AddRule(rule) - actual VPP API call would go here
	}

	// Simulate pushing rule to eBPF
	if s.bpfClient.connected {
		log.Printf("Pushing rule %s to eBPF", rule.ID)
		// bpf.UpdateMap(rule) - actual eBPF map update would go here
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
	// Simulate collecting stats from VPP and eBPF
	s.stats.TotalPackets += 1000
	s.stats.TotalBytes += 64000
	s.stats.DroppedPackets += 10
	s.stats.AllowedPackets += 990
	s.stats.LastUpdated = time.Now()
}

func (s *Server) generateEvents(eventChan chan<- *pb.Event) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	eventTypes := []string{"RULE_MATCH", "PACKET_DROP", "CONNECTION_NEW", "THREAT_DETECTED"}
	
	for {
		select {
		case <-ticker.C:
			// Generate sample event
			event := &pb.Event{
				Id:        fmt.Sprintf("event_%d", time.Now().UnixNano()),
				Type:      eventTypes[time.Now().UnixNano()%int64(len(eventTypes))],
				Timestamp: time.Now().Unix(),
				Source:    "192.168.1.100",
				Target:    "10.0.0.1",
				Protocol:  "tcp",
				Port:      80,
				Message:   "Sample firewall event",
				Severity:  "info",
			}
			
			select {
			case eventChan <- event:
			default:
				// Channel full, drop event
			}
		}
	}
}

func main() {
	log.Printf("Starting Cerberus-V gRPC Control Plane v%s", Version)

	// Create server
	server := NewServer()

	// Setup gRPC server
	lis, err := net.Listen("tcp", gRPCPort)
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	grpcServer := grpc.NewServer()
	pb.RegisterFirewallControlServer(grpcServer, server)
	
	// Enable reflection for debugging
	reflection.Register(grpcServer)

	// Handle graceful shutdown
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan
		
		log.Println("Shutting down gRPC server...")
		grpcServer.GracefulStop()
	}()

	log.Printf("gRPC server listening on %s", gRPCPort)
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
} 