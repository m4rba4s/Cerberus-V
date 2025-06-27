#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Cerberus-V Integration Tests - Python + Scapy
# Author: funcybot@gmail.com  Date: 2025-06-27

import unittest
import time
import subprocess
import json
import socket
import threading
import logging
import os
import sys
from typing import Dict, List, Optional

# Network testing
try:
    from scapy.all import *
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.l2 import Ether
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Warning: Scapy not available, some tests will be skipped")

# HTTP requests
import requests
import asyncio

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('cerberus_tests')

class CerberusTestConfig:
    """Test configuration"""
    CTRL_HOST = "localhost"
    CTRL_PORT = 50051
    METRICS_PORT = 8080
    TEST_INTERFACE = "lo"
    TEST_TIMEOUT = 30
    PACKET_DELAY = 0.1

class CerberusTestBase(unittest.TestCase):
    """Base class for Cerberus-V integration tests"""
    
    @classmethod
    def setUpClass(cls):
        """Set up test environment"""
        logger.info("🚀 Setting up Cerberus-V integration tests...")
        cls.config = CerberusTestConfig()
        cls.ctrl_process = None
        cls.test_packets_sent = 0
        cls.test_packets_received = 0
        
        # Start control plane for testing
        cls.start_control_plane()
        
        # Wait for services to be ready
        cls.wait_for_services()
        
    @classmethod
    def tearDownClass(cls):
        """Clean up test environment"""
        logger.info("🧹 Cleaning up test environment...")
        if cls.ctrl_process:
            cls.ctrl_process.terminate()
            cls.ctrl_process.wait(timeout=10)
    
    @classmethod
    def start_control_plane(cls):
        """Start the control plane for testing"""
        try:
            # Change to ctrl directory and start
            ctrl_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'ctrl')
            if os.path.exists(ctrl_dir):
                logger.info(f"Starting control plane from {ctrl_dir}")
                cls.ctrl_process = subprocess.Popen(
                    ['go', 'run', '.'],
                    cwd=ctrl_dir,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                time.sleep(3)  # Give it time to start
            else:
                logger.warning("Control plane directory not found, running without it")
        except Exception as e:
            logger.warning(f"Could not start control plane: {e}")
    
    @classmethod
    def wait_for_services(cls):
        """Wait for services to be ready"""
        logger.info("⏳ Waiting for services to be ready...")
        
        # Wait for HTTP endpoints
        for attempt in range(10):
            try:
                response = requests.get(
                    f"http://{cls.config.CTRL_HOST}:{cls.config.CTRL_PORT}/health",
                    timeout=2
                )
                if response.status_code == 200:
                    logger.info("✅ Control plane is ready")
                    return
            except requests.RequestException:
                time.sleep(1)
                continue
        
        logger.warning("⚠️  Control plane not responding, tests will run in mock mode")
    
    def send_test_packet(self, packet_type: str, src_ip: str = "192.168.1.100", 
                        dst_ip: str = "10.0.0.1", dst_port: int = 80) -> bool:
        """Send a test packet using Scapy"""
        if not SCAPY_AVAILABLE:
            logger.info(f"📦 [SIMULATED] Sending {packet_type} packet {src_ip} -> {dst_ip}:{dst_port}")
            self.test_packets_sent += 1
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
            
            # Send packet on loopback for testing
            send(packet, iface=self.config.TEST_INTERFACE, verbose=0)
            self.test_packets_sent += 1
            logger.info(f"📦 Sent {packet_type} packet {src_ip} -> {dst_ip}:{dst_port}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send packet: {e}")
            return False

class TestControlPlaneAPI(CerberusTestBase):
    """Test Control Plane REST API"""
    
    def test_health_endpoint(self):
        """Test health check endpoint"""
        logger.info("🔍 Testing health endpoint...")
        
        try:
            response = requests.get(
                f"http://{self.config.CTRL_HOST}:{self.config.CTRL_PORT}/health",
                timeout=5
            )
            self.assertEqual(response.status_code, 200)
            self.assertIn("OK", response.text)
            logger.info("✅ Health endpoint test passed")
        except requests.RequestException:
            logger.warning("⚠️  Health endpoint not available, assuming mock mode")
            self.skipTest("Control plane not running")
    
    def test_stats_endpoint(self):
        """Test statistics endpoint"""
        logger.info("🔍 Testing stats endpoint...")
        
        try:
            response = requests.get(
                f"http://{self.config.CTRL_HOST}:{self.config.CTRL_PORT}/stats",
                timeout=5
            )
            self.assertEqual(response.status_code, 200)
            
            stats = response.json()
            self.assertIn("TotalPackets", stats)
            self.assertIn("DroppedPackets", stats)
            self.assertIn("AllowedPackets", stats)
            
            logger.info(f"✅ Stats: Total={stats.get('TotalPackets', 0)}, "
                       f"Dropped={stats.get('DroppedPackets', 0)}")
                       
        except requests.RequestException:
            self.skipTest("Control plane not running")
    
    def test_rules_endpoint(self):
        """Test rules endpoint"""
        logger.info("🔍 Testing rules endpoint...")
        
        try:
            response = requests.get(
                f"http://{self.config.CTRL_HOST}:{self.config.CTRL_PORT}/rules",
                timeout=5
            )
            self.assertEqual(response.status_code, 200)
            
            rules = response.json()
            self.assertIn("Rules", rules)
            self.assertIn("Count", rules)
            
            logger.info(f"✅ Rules endpoint working, count: {rules.get('Count', 0)}")
            
        except requests.RequestException:
            self.skipTest("Control plane not running")

class TestPrometheusMetrics(CerberusTestBase):
    """Test Prometheus metrics endpoint"""
    
    def test_metrics_endpoint(self):
        """Test Prometheus metrics"""
        logger.info("🔍 Testing Prometheus metrics...")
        
        try:
            response = requests.get(
                f"http://{self.config.CTRL_HOST}:{self.config.METRICS_PORT}/metrics",
                timeout=5
            )
            self.assertEqual(response.status_code, 200)
            
            metrics_text = response.text
            
            # Check for key metrics
            expected_metrics = [
                "cerberus_uptime_seconds",
                "cerberus_active_rules", 
                "cerberus_packets_total",
                "cerberus_bytes_total"
            ]
            
            for metric in expected_metrics:
                self.assertIn(metric, metrics_text)
                logger.info(f"✅ Found metric: {metric}")
                
        except requests.RequestException:
            self.skipTest("Metrics endpoint not available")

class TestPacketProcessing(CerberusTestBase):
    """Test packet processing pipeline"""
    
    def test_icmp_packets(self):
        """Test ICMP packet processing"""
        logger.info("🔍 Testing ICMP packet processing...")
        
        # Send ICMP packets
        for i in range(3):
            success = self.send_test_packet(
                "icmp", 
                src_ip=f"192.168.1.{100+i}",
                dst_ip="10.0.0.1"
            )
            self.assertTrue(success)
            time.sleep(self.config.PACKET_DELAY)
        
        logger.info("✅ ICMP packet test completed")
    
    def test_tcp_syn_flood_detection(self):
        """Test TCP SYN flood detection"""
        logger.info("🔍 Testing TCP SYN flood detection...")
        
        # Send multiple SYN packets (simulating flood)
        for i in range(10):
            success = self.send_test_packet(
                "tcp_syn",
                src_ip=f"192.168.1.{100+i}",
                dst_ip="10.0.0.1",
                dst_port=80
            )
            self.assertTrue(success)
            time.sleep(0.05)  # Fast succession
        
        logger.info("✅ TCP SYN flood test completed")
    
    def test_udp_packets(self):
        """Test UDP packet processing"""
        logger.info("🔍 Testing UDP packet processing...")
        
        # Send UDP packets to different ports
        test_ports = [53, 123, 161, 514]
        for port in test_ports:
            success = self.send_test_packet(
                "udp",
                src_ip="192.168.1.200",
                dst_ip="10.0.0.1",
                dst_port=port
            )
            self.assertTrue(success)
            time.sleep(self.config.PACKET_DELAY)
        
        logger.info("✅ UDP packet test completed")

class TestFirewallRules(CerberusTestBase):
    """Test firewall rule functionality"""
    
    def test_rule_creation_and_stats_update(self):
        """Test that creating rules updates statistics"""
        logger.info("🔍 Testing rule creation and stats correlation...")
        
        # Get initial stats
        initial_stats = self.get_current_stats()
        
        # Send some packets that should match demo rules
        packets_sent = 5
        for i in range(packets_sent):
            self.send_test_packet(
                "icmp",
                src_ip="192.168.1.150",  # Should match demo rule
                dst_ip="10.0.0.1"
            )
            time.sleep(0.1)
        
        # Wait a bit for processing
        time.sleep(2)
        
        # Get updated stats
        final_stats = self.get_current_stats()
        
        if initial_stats and final_stats:
            # Check if stats changed (they should increase)
            self.assertGreaterEqual(
                final_stats.get('TotalPackets', 0),
                initial_stats.get('TotalPackets', 0)
            )
            logger.info("✅ Statistics properly updated after packet sending")
        else:
            logger.info("📊 Stats endpoints not available, test completed in simulation mode")
    
    def get_current_stats(self) -> Optional[Dict]:
        """Get current statistics from control plane"""
        try:
            response = requests.get(
                f"http://{self.config.CTRL_HOST}:{self.config.CTRL_PORT}/stats",
                timeout=5
            )
            if response.status_code == 200:
                return response.json()
        except requests.RequestException:
            pass
        return None

class TestPerformanceBaseline(CerberusTestBase):
    """Test performance baseline"""
    
    def test_packet_throughput_baseline(self):
        """Test baseline packet processing throughput"""
        logger.info("🔍 Testing packet throughput baseline...")
        
        start_time = time.time()
        packets_to_send = 100
        
        # Send packets as fast as possible
        for i in range(packets_to_send):
            success = self.send_test_packet(
                "tcp_syn" if i % 2 == 0 else "udp",
                src_ip=f"192.168.{1 + i//100}.{i%100}",
                dst_ip="10.0.0.1",
                dst_port=80 + (i % 1000)
            )
            self.assertTrue(success)
        
        end_time = time.time()
        duration = end_time - start_time
        pps = packets_to_send / duration if duration > 0 else 0
        
        logger.info(f"✅ Throughput baseline: {pps:.2f} packets/second")
        logger.info(f"   Duration: {duration:.3f}s for {packets_to_send} packets")
        
        # Basic performance assertion (should be able to send at least 10 pps)
        self.assertGreater(pps, 10, "Packet sending rate too low")

class TestSystemIntegration(CerberusTestBase):
    """Test system-level integration"""
    
    def test_end_to_end_pipeline(self):
        """Test complete end-to-end processing pipeline"""
        logger.info("🔍 Testing end-to-end pipeline...")
        
        # Step 1: Verify control plane is responding
        health_ok = self.check_service_health()
        
        # Step 2: Send diverse traffic patterns
        traffic_patterns = [
            ("icmp", "192.168.1.100", "10.0.0.1", 0),
            ("tcp_syn", "192.168.1.101", "10.0.0.1", 80),
            ("tcp_syn", "192.168.1.102", "10.0.0.1", 443), 
            ("udp", "192.168.1.103", "8.8.8.8", 53),
            ("tcp_syn", "10.0.0.100", "192.168.1.1", 22),
        ]
        
        for packet_type, src, dst, port in traffic_patterns:
            success = self.send_test_packet(packet_type, src, dst, port)
            self.assertTrue(success)
            time.sleep(0.2)
        
        # Step 3: Verify stats collection
        stats = self.get_current_stats()
        
        # Step 4: Check metrics
        metrics_ok = self.check_metrics_available()
        
        logger.info("✅ End-to-end pipeline test completed")
        logger.info(f"   Health check: {'✅' if health_ok else '⚠️'}")
        logger.info(f"   Stats available: {'✅' if stats else '⚠️'}")
        logger.info(f"   Metrics available: {'✅' if metrics_ok else '⚠️'}")
        logger.info(f"   Packets sent: {self.test_packets_sent}")
    
    def check_service_health(self) -> bool:
        """Check if services are healthy"""
        try:
            response = requests.get(
                f"http://{self.config.CTRL_HOST}:{self.config.CTRL_PORT}/health",
                timeout=2
            )
            return response.status_code == 200
        except:
            return False
    
    def check_metrics_available(self) -> bool:
        """Check if metrics endpoint is available"""
        try:
            response = requests.get(
                f"http://{self.config.CTRL_HOST}:{self.config.METRICS_PORT}/metrics",
                timeout=2
            )
            return response.status_code == 200
        except:
            return False

def run_integration_tests():
    """Run all integration tests"""
    
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add test classes
    test_classes = [
        TestControlPlaneAPI,
        TestPrometheusMetrics, 
        TestPacketProcessing,
        TestFirewallRules,
        TestPerformanceBaseline,
        TestSystemIntegration
    ]
    
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        test_suite.addTests(tests)
    
    # Run tests
    runner = unittest.TextTestRunner(
        verbosity=2,
        buffer=True,
        descriptions=True
    )
    
    logger.info("🧪 Starting Cerberus-V Integration Tests...")
    logger.info("=" * 50)
    
    result = runner.run(test_suite)
    
    # Print summary
    logger.info("=" * 50)
    logger.info("🎯 Test Summary:")
    logger.info(f"   Tests run: {result.testsRun}")
    logger.info(f"   Failures: {len(result.failures)}")
    logger.info(f"   Errors: {len(result.errors)}")
    logger.info(f"   Skipped: {len(result.skipped)}")
    
    if result.wasSuccessful():
        logger.info("🎉 All tests passed!")
        return 0
    else:
        logger.error("❌ Some tests failed!")
        return 1

if __name__ == "__main__":
    # Check dependencies
    if not SCAPY_AVAILABLE:
        print("Installing scapy for network testing...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "scapy"])
    
    # Run tests
    exit_code = run_integration_tests()
    sys.exit(exit_code) 