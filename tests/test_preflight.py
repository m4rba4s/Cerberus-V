#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Cerberus-V Preflight Unit Tests
import unittest
from unittest.mock import patch, MagicMock
import sys
import os

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'gui', 'backend'))

from preflight import RuleValidator, ShadowCopy, PreflightManager, FirewallRule

class TestRuleValidator(unittest.TestCase):
    """Test RuleValidator class."""
    
    def setUp(self):
        self.validator = RuleValidator()
    
    def test_validate_ip_valid(self):
        """Test valid IP addresses."""
        valid_ips = [
            "192.168.1.1",
            "10.0.0.0/8",
            "172.16.0.0/12",
            "0.0.0.0/0",
            "255.255.255.255"
        ]
        for ip in valid_ips:
            with self.subTest(ip=ip):
                self.assertTrue(RuleValidator.validate_ip(ip))
    
    def test_validate_ip_invalid(self):
        """Test invalid IP addresses."""
        invalid_ips = [
            "256.1.2.3",
            "192.168.1",
            "192.168.1.1/33",
            "192.168.1.1/",
            "abc.def.ghi.jkl",
            "192.168.1.1/abc"
        ]
        for ip in invalid_ips:
            with self.subTest(ip=ip):
                self.assertFalse(RuleValidator.validate_ip(ip))
    
    def test_validate_port_valid(self):
        """Test valid port specifications."""
        valid_ports = [
            "any",
            "80",
            "443",
            "8080",
            "1-65535",
            "1024-65535"
        ]
        for port in valid_ports:
            with self.subTest(port=port):
                self.assertTrue(RuleValidator.validate_port(port))
    
    def test_validate_port_invalid(self):
        """Test invalid port specifications."""
        invalid_ports = [
            "65536",
            "0-65536",
            "abc",
            "80-",
            "-80",
            "80-70"
        ]
        for port in invalid_ports:
            with self.subTest(port=port):
                self.assertFalse(RuleValidator.validate_port(port))
    
    def test_validate_protocol_valid(self):
        """Test valid protocols."""
        valid_protocols = ["any", "tcp", "udp", "icmp"]
        for protocol in valid_protocols:
            with self.subTest(protocol=protocol):
                self.assertTrue(RuleValidator.validate_protocol(protocol))
    
    def test_validate_protocol_invalid(self):
        """Test invalid protocols."""
        invalid_protocols = ["http", "https", "ftp", "ssh", ""]
        for protocol in invalid_protocols:
            with self.subTest(protocol=protocol):
                self.assertFalse(RuleValidator.validate_protocol(protocol))
    
    def test_validate_rule_valid(self):
        """Test valid rule validation."""
        rule = FirewallRule(
            id="test-rule-1",
            action="allow",
            src_ip="192.168.1.0/24",
            dst_ip="10.0.0.1",
            src_port="any",
            dst_port="80",
            protocol="tcp",
            description="Test rule"
        )
        is_valid, message = RuleValidator.validate_rule(rule)
        self.assertTrue(is_valid)
        self.assertEqual(message, "OK")
    
    def test_validate_rule_invalid_action(self):
        """Test rule with invalid action."""
        rule = FirewallRule(
            id="test-rule-1",
            action="invalid",
            src_ip="192.168.1.1",
            dst_ip="10.0.0.1"
        )
        is_valid, message = RuleValidator.validate_rule(rule)
        self.assertFalse(is_valid)
        self.assertIn("Action must be", message)
    
    def test_validate_rule_invalid_ip(self):
        """Test rule with invalid IP."""
        rule = FirewallRule(
            id="test-rule-1",
            action="allow",
            src_ip="256.1.2.3",
            dst_ip="10.0.0.1"
        )
        is_valid, message = RuleValidator.validate_rule(rule)
        self.assertFalse(is_valid)
        self.assertIn("Invalid source IP", message)

class TestShadowCopy(unittest.TestCase):
    """Test ShadowCopy class."""
    
    def setUp(self):
        self.shadow = ShadowCopy()
        self.test_rules = [
            FirewallRule(
                id="rule-1",
                action="allow",
                src_ip="192.168.1.1",
                dst_ip="10.0.0.1"
            ),
            FirewallRule(
                id="rule-2", 
                action="drop",
                src_ip="0.0.0.0/0",
                dst_ip="192.168.1.1"
            )
        ]
    
    def test_create_shadow(self):
        """Test shadow copy creation."""
        success = self.shadow.create_shadow(self.test_rules)
        self.assertTrue(success)
        self.assertTrue(self.shadow.has_shadow())
        self.assertIsNotNone(self.shadow.backup_timestamp)
    
    def test_get_shadow(self):
        """Test getting shadow copy."""
        self.shadow.create_shadow(self.test_rules)
        shadow_rules = self.shadow.get_shadow()
        
        self.assertEqual(len(shadow_rules), 2)
        self.assertEqual(shadow_rules[0].id, "rule-1")
        self.assertEqual(shadow_rules[1].id, "rule-2")
    
    def test_has_shadow_empty(self):
        """Test has_shadow when empty."""
        self.assertFalse(self.shadow.has_shadow())
    
    def test_has_shadow_with_data(self):
        """Test has_shadow when data exists."""
        self.shadow.create_shadow(self.test_rules)
        self.assertTrue(self.shadow.has_shadow())
    
    def test_clear_shadow(self):
        """Test clearing shadow copy."""
        self.shadow.create_shadow(self.test_rules)
        self.assertTrue(self.shadow.has_shadow())
        
        self.shadow.clear_shadow()
        self.assertFalse(self.shadow.has_shadow())
        self.assertIsNone(self.shadow.backup_timestamp)

class TestPreflightManager(unittest.TestCase):
    """Test PreflightManager class."""
    
    def setUp(self):
        self.manager = PreflightManager()
    
    def test_protect_baseline_rule(self):
        """Test baseline rule protection."""
        baseline_id = "00000000-0000-0000-0000-000000000000"
        other_id = "test-rule-1"
        
        self.assertTrue(self.manager.protect_baseline_rule(baseline_id))
        self.assertFalse(self.manager.protect_baseline_rule(other_id))
    
    def test_get_mode_default(self):
        """Test default mode."""
        mode = self.manager.get_mode()
        self.assertEqual(mode, "simulation")
    
    def test_set_mode_valid(self):
        """Test setting valid modes."""
        # Test simulation mode
        success, message = self.manager.set_mode("simulation")
        self.assertTrue(success)
        self.assertEqual(self.manager.get_mode(), "simulation")
        
        # Test live mode (should pass preflight)
        success, message = self.manager.set_mode("live")
        self.assertTrue(success)
        self.assertEqual(self.manager.get_mode(), "live")
    
    def test_set_mode_invalid(self):
        """Test setting invalid mode."""
        success, message = self.manager.set_mode("invalid")
        self.assertFalse(success)
        self.assertIn("Invalid mode", message)
    
    def test_get_current_rules(self):
        """Test getting current rules."""
        rules = self.manager.get_current_rules()
        self.assertIsInstance(rules, list)
        self.assertGreater(len(rules), 0)
        
        # Should have baseline rule
        baseline_found = any(rule["id"] == "00000000-0000-0000-0000-000000000000" for rule in rules)
        self.assertTrue(baseline_found)
    
    def test_dry_run_rules_valid(self):
        """Test dry-run with valid rules."""
        test_rules = [
            {
                "id": "test-rule-1",
                "action": "allow",
                "src_ip": "192.168.1.0/24",
                "dst_ip": "10.0.0.1",
                "src_port": "any",
                "dst_port": "80",
                "protocol": "tcp",
                "description": "Test rule"
            }
        ]
        
        success, message, details = self.manager.dry_run_rules(test_rules)
        self.assertTrue(success)
        self.assertIn("successful", message)
        self.assertIn("rules_count", details)
    
    def test_dry_run_rules_invalid(self):
        """Test dry-run with invalid rules."""
        test_rules = [
            {
                "id": "test-rule-1",
                "action": "invalid",
                "src_ip": "192.168.1.1",
                "dst_ip": "10.0.0.1"
            }
        ]
        
        success, message, details = self.manager.dry_run_rules(test_rules)
        self.assertFalse(success)
        self.assertIn("validation failed", message)
    
    def test_dry_run_baseline_modification(self):
        """Test dry-run attempting to modify baseline rule."""
        test_rules = [
            {
                "id": "00000000-0000-0000-0000-000000000000",
                "action": "drop",
                "src_ip": "127.0.0.1/32",
                "dst_ip": "127.0.0.1/32"
            }
        ]
        
        success, message, details = self.manager.dry_run_rules(test_rules)
        self.assertFalse(success)
        self.assertIn("Cannot modify baseline rule", message)
    
    def test_apply_rules_valid(self):
        """Test applying valid rules."""
        test_rules = [
            {
                "id": "test-rule-1",
                "action": "allow",
                "src_ip": "192.168.1.0/24",
                "dst_ip": "10.0.0.1",
                "src_port": "any",
                "dst_port": "80",
                "protocol": "tcp",
                "description": "Test rule"
            }
        ]
        
        success, message = self.manager.apply_rules(test_rules)
        self.assertTrue(success)
        self.assertIn("successfully", message)
        
        # Check that rules were applied
        current_rules = self.manager.get_current_rules()
        rule_ids = [rule["id"] for rule in current_rules]
        self.assertIn("test-rule-1", rule_ids)
        self.assertIn("00000000-0000-0000-0000-000000000000", rule_ids)  # Baseline
    
    def test_rollback_rules(self):
        """Test rollback functionality."""
        # First apply some rules
        test_rules = [
            {
                "id": "test-rule-1",
                "action": "allow",
                "src_ip": "192.168.1.1",
                "dst_ip": "10.0.0.1"
            }
        ]
        self.manager.apply_rules(test_rules)
        
        # Check rules are applied
        current_rules = self.manager.get_current_rules()
        rule_ids = [rule["id"] for rule in current_rules]
        self.assertIn("test-rule-1", rule_ids)
        
        # Rollback
        success, message = self.manager.rollback_rules()
        self.assertTrue(success)
        
        # Check rollback worked
        current_rules = self.manager.get_current_rules()
        rule_ids = [rule["id"] for rule in current_rules]
        self.assertNotIn("test-rule-1", rule_ids)
        self.assertIn("00000000-0000-0000-0000-000000000000", rule_ids)  # Baseline preserved
    
    def test_rollback_no_shadow(self):
        """Test rollback when no shadow exists."""
        success, message = self.manager.rollback_rules()
        self.assertFalse(success)
        self.assertIn("No shadow copy available", message)

if __name__ == "__main__":
    unittest.main() 