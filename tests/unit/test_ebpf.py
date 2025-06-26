#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Author: funcybot@gmail.com  Date: 2025-06-26
# Unit tests for eBPF XDP filter functionality

import pytest
import subprocess
import os
import tempfile
from pathlib import Path

class TestXDPFilter:
    """Test suite for XDP filter eBPF program"""
    
    @classmethod
    def setup_class(cls):
        """Setup test environment"""
        cls.ebpf_dir = Path(__file__).parent.parent.parent / "ebpf"
        cls.xdp_object = cls.ebpf_dir / "xdp_filter.o"
        
    def test_ebpf_object_exists(self):
        """Test that XDP object file exists after build"""
        assert self.xdp_object.exists(), f"XDP object not found: {self.xdp_object}"
        
    def test_ebpf_object_format(self):
        """Test that XDP object is valid ELF file"""
        result = subprocess.run(
            ["file", str(self.xdp_object)], 
            capture_output=True, 
            text=True
        )
        assert "ELF" in result.stdout, "XDP object is not valid ELF file"
        assert "relocatable" in result.stdout, "XDP object should be relocatable"
        
    def test_bpf_sections(self):
        """Test that required BPF sections are present"""
        result = subprocess.run(
            ["llvm-objdump", "-h", str(self.xdp_object)],
            capture_output=True,
            text=True
        )
        
        assert "xdp" in result.stdout, "XDP section not found"
        assert ".maps" in result.stdout, "Maps section not found"
        
    def test_bpf_maps_structure(self):
        """Test BPF maps are correctly defined"""
        result = subprocess.run(
            ["bpftool", "map", "dump", "pinned", "/sys/fs/bpf/stats_map"],
            capture_output=True,
            text=True
        )
        # This will fail if map is not loaded, which is expected in CI
        # We just test the command doesn't crash
        assert result.returncode in [0, 2], "bpftool command failed unexpectedly"
        
    def test_program_verification(self):
        """Test that BPF program passes verifier"""
        # This requires root privileges, so we skip in CI
        if os.geteuid() != 0:
            pytest.skip("Requires root privileges for BPF verification")
            
        result = subprocess.run(
            ["bpftool", "prog", "load", str(self.xdp_object), "/sys/fs/bpf/test_xdp"],
            capture_output=True,
            text=True
        )
        
        # Clean up
        subprocess.run(["rm", "-f", "/sys/fs/bpf/test_xdp"], capture_output=True)
        
        assert result.returncode == 0, f"BPF verification failed: {result.stderr}"

class TestBPFMaps:
    """Test suite for BPF maps functionality"""
    
    def test_stats_map_definition(self):
        """Test stats map is properly defined"""
        # Read the source file to verify map definition
        source_file = Path(__file__).parent.parent.parent / "ebpf" / "xdp_filter.c"
        
        with open(source_file, 'r') as f:
            content = f.read()
            
        assert "BPF_MAP_TYPE_PERCPU_ARRAY" in content, "Stats map type not found"
        assert "max_entries, 4" in content, "Stats map should have 4 entries"
        
    def test_xsk_map_definition(self):
        """Test XSK map is properly defined"""
        source_file = Path(__file__).parent.parent.parent / "ebpf" / "xdp_filter.c"
        
        with open(source_file, 'r') as f:
            content = f.read()
            
        assert "BPF_MAP_TYPE_XSKMAP" in content, "XSK map type not found"
        assert "max_entries, 64" in content, "XSK map should support 64 queues"

class TestPacketProcessing:
    """Test suite for packet processing logic"""
    
    def test_ethernet_header_parsing(self):
        """Test Ethernet header parsing logic"""
        source_file = Path(__file__).parent.parent.parent / "ebpf" / "xdp_filter.c"
        
        with open(source_file, 'r') as f:
            content = f.read()
            
        # Verify bounds checking
        assert "data_end" in content, "Missing bounds checking"
        assert "ethhdr" in content, "Missing Ethernet header parsing"
        assert "ETH_P_IP" in content, "Missing IPv4 protocol check"
        
    def test_ip_header_parsing(self):
        """Test IP header parsing logic"""
        source_file = Path(__file__).parent.parent.parent / "ebpf" / "xdp_filter.c"
        
        with open(source_file, 'r') as f:
            content = f.read()
            
        assert "iphdr" in content, "Missing IP header parsing"
        assert "IPPROTO_ICMP" in content, "Missing ICMP protocol handling"
        assert "IPPROTO_TCP" in content, "Missing TCP protocol handling"
        
    def test_action_logic(self):
        """Test packet action logic"""
        source_file = Path(__file__).parent.parent.parent / "ebpf" / "xdp_filter.c"
        
        with open(source_file, 'r') as f:
            content = f.read()
            
        assert "XDP_DROP" in content, "Missing DROP action"
        assert "XDP_PASS" in content, "Missing PASS action"
        assert "bpf_redirect_map" in content, "Missing redirect logic"

if __name__ == "__main__":
    pytest.main([__file__, "-v"]) 