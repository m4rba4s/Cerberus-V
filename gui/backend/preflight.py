#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Cerberus-V Preflight Logic: Dry-Run, Shadow Copy, Rollback
import json
import logging
from typing import Dict, List, Optional, Tuple
import subprocess
import os
from dataclasses import dataclass, asdict
from datetime import datetime, UTC
import re

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class FirewallRule:
    id: str
    action: str  # "allow", "drop", "limit"
    src_ip: str
    dst_ip: str = "0.0.0.0/0"
    src_port: str = "any"
    dst_port: str = "any"
    protocol: str = "any"
    description: str = ""
    enabled: bool = True
    log: bool = False
    log_prefix: str = ""
    rate_limit: Optional[str] = None
    created_at: str = ""
    updated_at: str = ""

class RuleValidator:
    """Validates firewall rules for safety and correctness."""
    
    # ReDoS-proof regex patterns
    IPV4_PATTERN = re.compile(r'^(?:(?:25[0-5]|2[0-4]\d|1?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|1?\d\d?)(?:/\d{1,2})?$')
    PORT_PATTERN = re.compile(r'^(?:any|\d{1,5}(?:-\d{1,5})?)$')
    PROTOCOL_PATTERN = re.compile(r'^(?:any|tcp|udp|icmp)$')
    
    @staticmethod
    def validate_ip(ip: str) -> bool:
        """Validate IPv4 address or CIDR notation."""
        if not RuleValidator.IPV4_PATTERN.match(ip):
            return False
        
        # Check CIDR range
        if '/' in ip:
            try:
                addr, cidr = ip.split('/')
                cidr_num = int(cidr)
                if cidr_num < 0 or cidr_num > 32:
                    return False
            except ValueError:
                return False
        
        return True
    
    @staticmethod
    def validate_port(port: str) -> bool:
        """Validate port specification."""
        if port == "any":
            return True
        
        if not RuleValidator.PORT_PATTERN.match(port):
            return False
        
        # Check single port
        if '-' not in port:
            try:
                port_num = int(port)
                return 1 <= port_num <= 65535
            except ValueError:
                return False
        
        # Check port range
        try:
            start, end = port.split('-')
            start_num = int(start)
            end_num = int(end)
            return 1 <= start_num <= 65535 and 1 <= end_num <= 65535 and start_num <= end_num
        except ValueError:
            return False
    
    @staticmethod
    def validate_protocol(protocol: str) -> bool:
        """Validate protocol specification."""
        return bool(RuleValidator.PROTOCOL_PATTERN.match(protocol))
    
    @staticmethod
    def validate_rule(rule: FirewallRule) -> Tuple[bool, str]:
        """Validate a single firewall rule."""
        errors = []
        
        # Check required fields
        if not rule.id:
            errors.append("Rule ID is required")
        if not rule.action in ["allow", "drop", "limit"]:
            errors.append("Action must be 'allow', 'drop', or 'limit'")
        
        # Validate IP addresses
        if not RuleValidator.validate_ip(rule.src_ip):
            errors.append(f"Invalid source IP: {rule.src_ip}")
        if not RuleValidator.validate_ip(rule.dst_ip):
            errors.append(f"Invalid destination IP: {rule.dst_ip}")
        
        # Validate ports
        if not RuleValidator.validate_port(rule.src_port):
            errors.append(f"Invalid source port: {rule.src_port}")
        if not RuleValidator.validate_port(rule.dst_port):
            errors.append(f"Invalid destination port: {rule.dst_port}")
        
        # Validate protocol
        if not RuleValidator.validate_protocol(rule.protocol):
            errors.append(f"Invalid protocol: {rule.protocol}")
        
        return len(errors) == 0, "; ".join(errors) if errors else "OK"

class ShadowCopy:
    """Manages shadow copies of firewall rules for safe rollback."""
    
    def __init__(self):
        self.shadow_rules: List[FirewallRule] = []
        self.backup_timestamp: Optional[str] = None
    
    def create_shadow(self, rules: List[FirewallRule]) -> bool:
        """Create a shadow copy of current rules."""
        try:
            self.shadow_rules = [FirewallRule(**asdict(rule)) for rule in rules]
            self.backup_timestamp = datetime.now(UTC).isoformat()
            logger.info(f"Shadow copy created at {self.backup_timestamp}")
            return True
        except Exception as e:
            logger.error(f"Failed to create shadow copy: {e}")
            return False
    
    def get_shadow(self) -> List[FirewallRule]:
        """Get the shadow copy of rules."""
        return self.shadow_rules.copy()
    
    def has_shadow(self) -> bool:
        """Check if shadow copy exists."""
        return len(self.shadow_rules) > 0
    
    def clear_shadow(self) -> None:
        """Clear the shadow copy."""
        self.shadow_rules.clear()
        self.backup_timestamp = None
        logger.info("Shadow copy cleared")

class PreflightManager:
    """Manages preflight checks, dry-runs, and rollback operations."""
    
    def __init__(self):
        self.current_rules: List[FirewallRule] = []
        self.shadow_copy = ShadowCopy()
        self.validator = RuleValidator()
        self.mode: str = "simulation"  # "simulation" or "live"
        
        # Initialize with baseline rule
        self._initialize_baseline_rule()
    
    def _initialize_baseline_rule(self) -> None:
        """Initialize the immutable baseline rule."""
        baseline_rule = FirewallRule(
            id="00000000-0000-0000-0000-000000000000",
            action="allow",
            src_ip="127.0.0.1/32",
            dst_ip="127.0.0.1/32",
            description="IMMUTABLE — rescue loopback",
            enabled=True,
            log=True,
            log_prefix="[BASELINE LOOPBACK]",
            created_at=datetime.now(UTC).isoformat(),
            updated_at=datetime.now(UTC).isoformat()
        )
        self.current_rules = [baseline_rule]
        logger.info("Baseline rule initialized")
    
    def protect_baseline_rule(self, rule_id: str) -> bool:
        """Check if rule is the baseline rule (protected from modification)."""
        return rule_id == "00000000-0000-0000-0000-000000000000"
    
    def dry_run_rules(self, new_rules: List[Dict]) -> Tuple[bool, str, Dict]:
        """Perform a dry-run of rule changes."""
        try:
            logger.info("Starting dry-run of rule changes")
            
            # Create shadow copy of current rules
            if not self.shadow_copy.create_shadow(self.current_rules):
                return False, "Failed to create shadow copy", {}
            
            # Validate all new rules
            validated_rules = []
            for rule_data in new_rules:
                rule = FirewallRule(**rule_data)
                
                # Check if trying to modify baseline rule
                if self.protect_baseline_rule(rule.id):
                    return False, f"Cannot modify baseline rule: {rule.id}", {}
                
                # Validate rule
                is_valid, error_msg = self.validator.validate_rule(rule)
                if not is_valid:
                    return False, f"Rule validation failed: {error_msg}", {}
                
                validated_rules.append(rule)
            
            # Check for duplicates
            rule_ids = [rule.id for rule in validated_rules]
            if len(rule_ids) != len(set(rule_ids)):
                return False, "Duplicate rule IDs found", {}
            
            # Mock: Simulate rule application
            logger.info("Dry-run completed successfully")
            
            return True, "Dry-run successful", {
                "rules_count": len(validated_rules),
                "validation_passed": True,
                "baseline_protected": True
            }
            
        except Exception as e:
            logger.error(f"Dry-run failed: {e}")
            return False, f"Dry-run failed: {str(e)}", {}
    
    def apply_rules(self, new_rules: List[Dict]) -> Tuple[bool, str]:
        """Apply new rules (after successful dry-run)."""
        try:
            logger.info("Applying new rules")
            
            # Create shadow copy before applying (for rollback capability)
            if not self.shadow_copy.create_shadow(self.current_rules):
                return False, "Failed to create shadow copy for rollback"
            
            # Convert to FirewallRule objects
            rules = [FirewallRule(**rule_data) for rule_data in new_rules]
            
            # Add baseline rule if not present
            baseline_present = any(self.protect_baseline_rule(rule.id) for rule in rules)
            if not baseline_present:
                baseline_rule = FirewallRule(
                    id="00000000-0000-0000-0000-000000000000",
                    action="allow",
                    src_ip="127.0.0.1/32",
                    dst_ip="127.0.0.1/32",
                    description="IMMUTABLE — rescue loopback",
                    enabled=True,
                    log=True,
                    log_prefix="[BASELINE LOOPBACK]",
                    created_at=datetime.now(UTC).isoformat(),
                    updated_at=datetime.now(UTC).isoformat()
                )
                rules.insert(0, baseline_rule)
            
            # Apply rules (mock: just update in-memory)
            self.current_rules = rules
            
            # Shadow copy is kept for potential rollback
            logger.info("Rules applied successfully")
            return True, "Rules applied successfully"
            
        except Exception as e:
            logger.error(f"Failed to apply rules: {e}")
            return False, f"Failed to apply rules: {str(e)}"
    
    def rollback_rules(self) -> Tuple[bool, str]:
        """Rollback to previous state using shadow copy."""
        try:
            logger.info("Rolling back to previous state")
            
            if not self.shadow_copy.has_shadow():
                return False, "No shadow copy available for rollback"
            
            # Restore from shadow copy
            self.current_rules = self.shadow_copy.get_shadow()
            self.shadow_copy.clear_shadow()
            
            logger.info("Rollback completed successfully")
            return True, "Rollback completed successfully"
            
        except Exception as e:
            logger.error(f"Rollback failed: {e}")
            return False, f"Rollback failed: {str(e)}"
    
    def get_current_rules(self) -> List[Dict]:
        """Get current rules as dictionaries."""
        return [asdict(rule) for rule in self.current_rules]
    
    def get_mode(self) -> str:
        """Get current mode."""
        return self.mode
    
    def set_mode(self, mode: str) -> Tuple[bool, str]:
        """Set mode (simulation/live) with preflight check."""
        if mode not in ["simulation", "live"]:
            return False, "Invalid mode: must be 'simulation' or 'live'"
        
        if mode == "live":
            # Preflight check for live mode - validate current rules without creating shadow
            logger.info("Preflight check for live mode")
            current_rules = self.get_current_rules()
            
            # Validate all current rules (baseline rule is allowed for live mode)
            for rule_data in current_rules:
                rule = FirewallRule(**rule_data)
                
                # Baseline rule is allowed for live mode (it's the rescue rule)
                if self.protect_baseline_rule(rule.id):
                    logger.info(f"Baseline rule {rule.id} is allowed for live mode")
                    continue
                
                # Validate rule
                is_valid, error_msg = self.validator.validate_rule(rule)
                if not is_valid:
                    return False, f"Preflight check failed for live mode: {error_msg}"
            
            # Check for duplicates
            rule_ids = [rule["id"] for rule in current_rules]
            if len(rule_ids) != len(set(rule_ids)):
                return False, "Preflight check failed: duplicate rule IDs found"

            # Extra safety checks for LIVE
            # 1) Ensure a usable network interface exists (prefer default route iface)
            iface = os.getenv("XDP_INTERFACE") or self._detect_default_interface()
            if not iface:
                return False, "Preflight failed: could not detect a usable network interface"
            if not self._is_interface_up(iface):
                return False, f"Preflight failed: interface '{iface}' is not UP"

            # 2) Optional: if bpftool present, ensure BPF fs is mounted and accessible
            if self._has_command("bpftool") and not self._is_bpf_fs_ready():
                return False, "Preflight failed: /sys/fs/bpf is not mounted or accessible"
        
        self.mode = mode
        logger.info(f"Mode changed to: {mode}")
        return True, f"Mode changed to: {mode}"

    # --- helpers ---
    @staticmethod
    def _run(cmd: List[str]) -> Tuple[int, str, str]:
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
            return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
        except Exception as exc:
            return 1, "", str(exc)

    @classmethod
    def _detect_default_interface(cls) -> Optional[str]:
        code, out, _ = cls._run(["ip", "route", "show", "default"])
        if code != 0 or not out:
            return None
        # default via ... dev eth0
        for tok1, tok2 in zip(out.split(), out.split()[1:]):
            if tok1 == "dev":
                return tok2
        # fallback: last word
        parts = out.split()
        return parts[-1] if parts else None

    @classmethod
    def _is_interface_up(cls, iface: str) -> bool:
        code, out, _ = cls._run(["ip", "-o", "link", "show", iface])
        if code != 0 or not out:
            return False
        # look for state UP
        return " state UP " in f" {out} "

    @staticmethod
    def _has_command(name: str) -> bool:
        code, _, _ = PreflightManager._run(["bash", "-lc", f"command -v {name}"])
        return code == 0

    @classmethod
    def _is_bpf_fs_ready(cls) -> bool:
        # Check mountpoint
        code, _, _ = cls._run(["bash", "-lc", "mountpoint -q /sys/fs/bpf"])
        if code != 0:
            return False
        # Writable test (non-invasive): list directory
        code, _, _ = cls._run(["bash", "-lc", "test -r /sys/fs/bpf && test -w /sys/fs/bpf"])
        return code == 0

# Global instance
preflight_manager = PreflightManager() 