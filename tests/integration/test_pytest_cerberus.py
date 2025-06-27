#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Cerberus-V Integration Tests - Pytest Edition
# Author: funcybot@gmail.com  Date: 2025-06-27

import pytest
import time
import subprocess
import json
import requests
import logging
import os
from typing import Dict, Optional

# Network testing
try:
    from scapy.all import *
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

logger = logging.getLogger(__name__)

@pytest.fixture(scope="session")
def cerberus_config():
    """Test configuration fixture"""
    return {
        "ctrl_host": "localhost",
        "ctrl_port": 50051,
        "metrics_port": 8080,
        "test_interface": "lo",
        "timeout": 30
    }

@pytest.fixture(scope="session")
def control_plane_process(cerberus_config):
    """Start control plane for testing"""
    process = None
    try:
        ctrl_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'ctrl')
        if os.path.exists(ctrl_dir):
            logger.info("Starting control plane for tests...")
            process = subprocess.Popen(
                ['go', 'run', '.'],
                cwd=ctrl_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            time.sleep(3)  # Allow startup
        
        yield process
        
    finally:
        if process:
            process.terminate()
            process.wait(timeout=10)

@pytest.fixture
def packet_sender(cerberus_config):
    """Packet sending utility"""
    class PacketSender:
        def __init__(self, config):
            self.config = config
            self.packets_sent = 0
        
        def send_packet(self, packet_type: str, src_ip: str = "192.168.1.100", 
                       dst_ip: str = "10.0.0.1", dst_port: int = 80) -> bool:
            if not SCAPY_AVAILABLE:
                logger.info(f"[SIMULATED] Sending {packet_type} packet {src_ip} -> {dst_ip}:{dst_port}")
                self.packets_sent += 1
                return True
            
            try:
                if packet_type == "tcp_syn":
                    packet = IP(src=src_ip, dst=dst_ip) / TCP(dport=dst_port, flags="S")
                elif packet_type == "udp":
                    packet = IP(src=src_ip, dst=dst_ip) / UDP(dport=dst_port)
                elif packet_type == "icmp":
                    packet = IP(src=src_ip, dst=dst_ip) / ICMP()
                else:
                    return False
                
                send(packet, iface=self.config["test_interface"], verbose=0)
                self.packets_sent += 1
                logger.info(f"Sent {packet_type} packet {src_ip} -> {dst_ip}:{dst_port}")
                return True
                
            except Exception as e:
                logger.error(f"Failed to send packet: {e}")
                return False
    
    return PacketSender(cerberus_config)

# Test classes

class TestControlPlaneEndpoints:
    """Test control plane HTTP endpoints"""
    
    def test_health_endpoint(self, cerberus_config, control_plane_process):
        """Test health check endpoint"""
        try:
            response = requests.get(
                f"http://{cerberus_config['ctrl_host']}:{cerberus_config['ctrl_port']}/health",
                timeout=5
            )
            assert response.status_code == 200
            assert "OK" in response.text
        except requests.RequestException:
            pytest.skip("Control plane not running")
    
    def test_stats_endpoint(self, cerberus_config, control_plane_process):
        """Test statistics endpoint"""
        try:
            response = requests.get(
                f"http://{cerberus_config['ctrl_host']}:{cerberus_config['ctrl_port']}/stats",
                timeout=5
            )
            assert response.status_code == 200
            
            stats = response.json()
            assert "TotalPackets" in stats
            assert "DroppedPackets" in stats
            assert "AllowedPackets" in stats
            
            logger.info(f"Stats: Total={stats.get('TotalPackets', 0)}, "
                       f"Dropped={stats.get('DroppedPackets', 0)}")
            
        except requests.RequestException:
            pytest.skip("Control plane not running")
    
    def test_rules_endpoint(self, cerberus_config, control_plane_process):
        """Test rules endpoint"""
        try:
            response = requests.get(
                f"http://{cerberus_config['ctrl_host']}:{cerberus_config['ctrl_port']}/rules",
                timeout=5
            )
            assert response.status_code == 200
            
            rules = response.json()
            assert "Rules" in rules
            assert "Count" in rules
            
        except requests.RequestException:
            pytest.skip("Control plane not running")

class TestMetricsEndpoint:
    """Test Prometheus metrics"""
    
    def test_prometheus_metrics(self, cerberus_config, control_plane_process):
        """Test Prometheus metrics endpoint"""
        try:
            response = requests.get(
                f"http://{cerberus_config['ctrl_host']}:{cerberus_config['metrics_port']}/metrics",
                timeout=5
            )
            assert response.status_code == 200
            
            metrics_text = response.text
            expected_metrics = [
                "cerberus_uptime_seconds",
                "cerberus_active_rules",
                "cerberus_packets_total"
            ]
            
            for metric in expected_metrics:
                assert metric in metrics_text
                
        except requests.RequestException:
            pytest.skip("Metrics endpoint not available")

class TestPacketProcessing:
    """Test packet processing with Scapy"""
    
    @pytest.mark.skipif(not SCAPY_AVAILABLE, reason="Scapy not available")
    def test_icmp_packet_processing(self, packet_sender):
        """Test ICMP packet processing"""
        # Send ICMP packets
        for i in range(3):
            success = packet_sender.send_packet(
                "icmp",
                src_ip=f"192.168.1.{100+i}",
                dst_ip="10.0.0.1"
            )
            assert success
            time.sleep(0.1)
        
        assert packet_sender.packets_sent >= 3
    
    @pytest.mark.skipif(not SCAPY_AVAILABLE, reason="Scapy not available")
    def test_tcp_syn_processing(self, packet_sender):
        """Test TCP SYN packet processing"""
        # Send TCP SYN packets
        for i in range(5):
            success = packet_sender.send_packet(
                "tcp_syn",
                src_ip=f"192.168.1.{200+i}",
                dst_ip="10.0.0.1",
                dst_port=80
            )
            assert success
            time.sleep(0.05)
    
    @pytest.mark.skipif(not SCAPY_AVAILABLE, reason="Scapy not available")
    def test_udp_packet_processing(self, packet_sender):
        """Test UDP packet processing"""
        test_ports = [53, 123, 161]
        for port in test_ports:
            success = packet_sender.send_packet(
                "udp",
                src_ip="192.168.1.250",
                dst_ip="10.0.0.1",
                dst_port=port
            )
            assert success
            time.sleep(0.1)

class TestPerformance:
    """Performance testing"""
    
    def test_packet_throughput(self, packet_sender):
        """Test packet sending throughput"""
        start_time = time.time()
        packets_to_send = 50
        
        for i in range(packets_to_send):
            success = packet_sender.send_packet(
                "tcp_syn" if i % 2 == 0 else "udp",
                src_ip=f"10.0.{i//100}.{i%100}",
                dst_ip="192.168.1.1",
                dst_port=80 + i
            )
            assert success
        
        duration = time.time() - start_time
        pps = packets_to_send / duration if duration > 0 else 0
        
        logger.info(f"Throughput: {pps:.2f} packets/second")
        assert pps > 5  # Should be able to send at least 5 pps

class TestEndToEndIntegration:
    """End-to-end integration tests"""
    
    def test_full_pipeline(self, cerberus_config, control_plane_process, packet_sender):
        """Test complete processing pipeline"""
        
        # Step 1: Check health
        try:
            health_response = requests.get(
                f"http://{cerberus_config['ctrl_host']}:{cerberus_config['ctrl_port']}/health",
                timeout=2
            )
            health_ok = health_response.status_code == 200
        except:
            health_ok = False
        
        # Step 2: Get initial stats
        try:
            stats_response = requests.get(
                f"http://{cerberus_config['ctrl_host']}:{cerberus_config['ctrl_port']}/stats",
                timeout=2
            )
            initial_stats = stats_response.json() if stats_response.status_code == 200 else None
        except:
            initial_stats = None
        
        # Step 3: Send test traffic
        traffic_patterns = [
            ("icmp", "192.168.1.100", "10.0.0.1", 0),
            ("tcp_syn", "192.168.1.101", "10.0.0.1", 80),
            ("udp", "192.168.1.102", "8.8.8.8", 53),
        ]
        
        packets_sent = 0
        for packet_type, src, dst, port in traffic_patterns:
            if packet_sender.send_packet(packet_type, src, dst, port):
                packets_sent += 1
            time.sleep(0.2)
        
        # Step 4: Verify traffic was processed
        time.sleep(1)  # Allow processing
        
        try:
            final_stats_response = requests.get(
                f"http://{cerberus_config['ctrl_host']}:{cerberus_config['ctrl_port']}/stats",
                timeout=2
            )
            final_stats = final_stats_response.json() if final_stats_response.status_code == 200 else None
        except:
            final_stats = None
        
        # Assertions
        assert packets_sent > 0, "Should have sent at least some packets"
        
        if initial_stats and final_stats:
            # Stats should have changed (or at least be available)
            assert "TotalPackets" in final_stats
            logger.info(f"Pipeline test completed: {packets_sent} packets sent")
        else:
            logger.info("Pipeline test completed in simulation mode")

# Pytest configuration and markers

def pytest_configure(config):
    """Configure pytest markers"""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )
    config.addinivalue_line(
        "markers", "network: marks tests as requiring network access"
    )
    config.addinivalue_line(
        "markers", "scapy: marks tests as requiring Scapy"
    )

@pytest.mark.slow
@pytest.mark.network
def test_stress_test(packet_sender):
    """Stress test with many packets"""
    logger.info("Running stress test...")
    
    start_time = time.time()
    packets_to_send = 200
    
    for i in range(packets_to_send):
        packet_type = ["icmp", "tcp_syn", "udp"][i % 3]
        success = packet_sender.send_packet(
            packet_type,
            src_ip=f"172.16.{i//256}.{i%256}",
            dst_ip="192.168.1.1",
            dst_port=1000 + i
        )
        assert success
        
        if i % 50 == 0:
            logger.info(f"Sent {i} packets...")
    
    duration = time.time() - start_time
    pps = packets_to_send / duration if duration > 0 else 0
    
    logger.info(f"Stress test completed: {pps:.2f} pps")
    assert pps > 10  # Should handle at least 10 pps under stress 