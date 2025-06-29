// SPDX-License-Identifier: Apache-2.0
// BPF Integration for Cerberus-V Control Plane

package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

type BPFManager struct {
	program *ebpf.Program
	link    link.Link
	maps    map[string]*ebpf.Map
}

// Initialize BPF subsystem
func NewBPFManager() (*BPFManager, error) {
	// Remove memory limit for eBPF
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("failed to remove memlock: %v", err)
	}

	bm := &BPFManager{
		maps: make(map[string]*ebpf.Map),
	}

	return bm, nil
}

// Load XDP program
func (bm *BPFManager) LoadXDPProgram(programPath string) error {
	// Load pre-compiled XDP program
	spec, err := ebpf.LoadCollectionSpec(programPath)
	if err != nil {
		return fmt.Errorf("failed to load XDP program spec: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("failed to create collection: %v", err)
	}

	// Get the XDP program
	program, exists := coll.Programs["xdp_filter"]
	if !exists {
		return fmt.Errorf("XDP program 'xdp_filter' not found")
	}

	bm.program = program

	// Store maps for later use
	for name, m := range coll.Maps {
		bm.maps[name] = m
	}

	log.Printf("✅ XDP program loaded successfully")
	return nil
}

// Attach XDP program to interface
func (bm *BPFManager) AttachXDP(interfaceName string) error {
	if bm.program == nil {
		return fmt.Errorf("no XDP program loaded")
	}

	// Attach to interface
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   bm.program,
		Interface: interfaceName,
	})
	if err != nil {
		return fmt.Errorf("failed to attach XDP program: %v", err)
	}

	bm.link = l
	log.Printf("✅ XDP program attached to interface %s", interfaceName)
	return nil
}

// Update BPF map with firewall rules
func (bm *BPFManager) UpdateFirewallRules(rules []FirewallRule) error {
	firewallMap, exists := bm.maps["firewall_rules"]
	if !exists {
		return fmt.Errorf("firewall_rules map not found")
	}

	// Clear existing rules
	var key, nextKey uint32
	for {
		err := firewallMap.NextKey(&key, &nextKey)
		if err != nil {
			break
		}
		firewallMap.Delete(&nextKey)
		key = nextKey
	}

	// Add new rules
	for i, rule := range rules {
		key := uint32(i)
		bpfRule := BPFFirewallRule{
			SrcIP:    rule.SourceIP,
			DstIP:    rule.DestIP,
			SrcPort:  rule.SourcePort,
			DstPort:  rule.DestPort,
			Protocol: rule.Protocol,
			Action:   rule.Action,
		}

		err := firewallMap.Put(&key, &bpfRule)
		if err != nil {
			return fmt.Errorf("failed to update rule %d: %v", i, err)
		}
	}

	log.Printf("✅ Updated %d firewall rules in BPF map", len(rules))
	return nil
}

// Get statistics from BPF maps
func (bm *BPFManager) GetStatistics() (*BPFStatistics, error) {
	statsMap, exists := bm.maps["stats"]
	if !exists {
		return nil, fmt.Errorf("stats map not found")
	}

	var stats BPFStatistics
	key := uint32(0)
	err := statsMap.Lookup(&key, &stats)
	if err != nil {
		return nil, fmt.Errorf("failed to read statistics: %v", err)
	}

	return &stats, nil
}

// Cleanup BPF resources
func (bm *BPFManager) Close() error {
	if bm.link != nil {
		bm.link.Close()
	}

	if bm.program != nil {
		bm.program.Close()
	}

	for _, m := range bm.maps {
		m.Close()
	}

	log.Printf("✅ BPF resources cleaned up")
	return nil
}

// BPF data structures
type BPFFirewallRule struct {
	SrcIP    uint32
	DstIP    uint32
	SrcPort  uint16
	DstPort  uint16
	Protocol uint8
	Action   uint8
}

type BPFStatistics struct {
	PacketsProcessed uint64
	PacketsDropped   uint64
	PacketsAllowed   uint64
	BytesProcessed   uint64
	LastUpdate       uint64
}

// Helper function to convert IP string to uint32
func ipToUint32(ip string) uint32 {
	// Simple conversion - in production use proper IP parsing
	return 0
}

// Pin BPF maps to filesystem
func (bm *BPFManager) PinMaps(pinPath string) error {
	if err := os.MkdirAll(pinPath, 0755); err != nil {
		return fmt.Errorf("failed to create pin directory: %v", err)
	}

	for name, m := range bm.maps {
		mapPath := filepath.Join(pinPath, name)
		if err := m.Pin(mapPath); err != nil {
			return fmt.Errorf("failed to pin map %s: %v", name, err)
		}
	}

	log.Printf("✅ BPF maps pinned to %s", pinPath)
	return nil
}

// Load pinned maps
func (bm *BPFManager) LoadPinnedMaps(pinPath string) error {
	entries, err := os.ReadDir(pinPath)
	if err != nil {
		return fmt.Errorf("failed to read pin directory: %v", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		mapPath := filepath.Join(pinPath, entry.Name())
		m, err := ebpf.LoadPinnedMap(mapPath, nil)
		if err != nil {
			log.Printf("⚠️ Failed to load pinned map %s: %v", entry.Name(), err)
			continue
		}

		bm.maps[entry.Name()] = m
	}

	log.Printf("✅ Loaded %d pinned BPF maps", len(bm.maps))
	return nil
} 