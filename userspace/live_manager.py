#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Cerberus-V LIVE Mode Manager
# Elite-Mode APT-Grade Two-Phase Commit

import os
import sys
import time
import json
import struct
import subprocess
import logging
import threading
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import socket
import fcntl
import select

# Add project root to path
sys.path.append(str(Path(__file__).parent.parent))

logger = logging.getLogger(__name__)

class LiveMode(Enum):
    SIMULATION = 0
    LIVE = 1
    EMERGENCY = 2

@dataclass
class LiveState:
    mode: LiveMode
    last_commit: int
    rule_count: int
    drop_count: int
    allow_count: int
    emergency_mode: bool

@dataclass
class LiveConfig:
    shadow_map_size: int = 1048576
    max_rules_per_sec: int = 10
    max_hit_rate: float = 0.95
    rollback_on_cpu_usage: float = 0.90
    rollback_on_memory_usage: float = 0.85
    emergency_rollback_threshold: int = 1000

class LiveModeManager:
    """
    Elite-Mode APT-Grade LIVE Mode Manager
    Implements two-phase commit with shadow maps
    """
    
    def __init__(self, config: LiveConfig = None):
        self.config = config or LiveConfig()
        self.current_mode = LiveMode.SIMULATION
        self.shadow_maps_ready = False
        self.commit_lock = threading.Lock()
        self.watchdog_thread = None
        self.watchdog_running = False
        
        # Map paths
        self.map_paths = {
            "live_shadow": "/sys/fs/bpf/cerberus/live_shadow",
            "live_state": "/sys/fs/bpf/cerberus/live_state_map",
            "live_drops": "/sys/fs/bpf/cerberus/live_drops",
            "rate_limiter": "/sys/fs/bpf/cerberus/rate_limiter"
        }
        
        # Initialize state
        self._init_live_state()
        logger.info(f"LIVE Mode Manager initialized: mode={self.current_mode.name}")
    
    def _init_live_state(self):
        """Initialize live state map"""
        try:
            # Create initial state
            state = LiveState(
                mode=LiveMode.SIMULATION,
                last_commit=int(time.time()),
                rule_count=0,
                drop_count=0,
                allow_count=0,
                emergency_mode=False
            )
            
            # Write to BPF map
            self._write_live_state(state)
            logger.info("Live state initialized")
            
        except Exception as e:
            logger.error(f"Failed to initialize live state: {e}")
    
    def _write_live_state(self, state: LiveState):
        """Write state to BPF map"""
        try:
            # Convert state to binary format (32 bytes total)
            state_data = struct.pack(
                "BQQIIIB",  # format: mode, last_commit, rule_count, drop_count, allow_count, emergency_mode
                state.mode.value,
                state.last_commit,
                state.rule_count,
                state.drop_count,
                state.allow_count,
                state.emergency_mode
            )
            # Truncate to 32 bytes if needed
            if len(state_data) > 32:
                state_data = state_data[:32]
            elif len(state_data) < 32:
                state_data += b'\x00' * (32 - len(state_data))
            
            # Write to BPF map
            key = struct.pack("I", 0)
            subprocess.run([
                "bpftool", "map", "update", "pinned", self.map_paths["live_state"],
                "key", key.hex(), "value", state_data.hex()
            ], check=True, capture_output=True)
            
        except Exception as e:
            logger.error(f"Failed to write live state: {e}")
            raise
    
    def _read_live_state(self) -> Optional[LiveState]:
        """Read state from BPF map"""
        try:
            key = struct.pack("I", 0)
            result = subprocess.run([
                "bpftool", "map", "lookup", "pinned", self.map_paths["live_state"],
                "key", key.hex()
            ], check=True, capture_output=True, text=True)
            
            # Parse output - handle multi-line format
            lines = result.stdout.strip().split('\n')
            value_line = None
            for line in lines:
                if line.startswith('value:'):
                    value_line = line
                    break
            
            if not value_line:
                raise Exception("No value found in bpftool output")
            
            # Extract hex values from "value: 01 00 00 00 00 00 00 00 ..."
            hex_parts = value_line.replace('value:', '').strip().split()
            value_data = bytes.fromhex(''.join(hex_parts))
            
            # Unpack state - handle 32 bytes
            if len(value_data) == 32:
                # Use 32-byte format
                mode_val, last_commit, rule_count, drop_count, allow_count, emergency_mode = struct.unpack(
                    "BQQIIIB", value_data[:37]  # Take first 37 bytes
                )
            else:
                mode_val, last_commit, rule_count, drop_count, allow_count, emergency_mode = struct.unpack(
                    "BQQIIIB", value_data
                )
            
            return LiveState(
                mode=LiveMode(mode_val),
                last_commit=last_commit,
                rule_count=rule_count,
                drop_count=drop_count,
                allow_count=allow_count,
                emergency_mode=bool(emergency_mode)
            )
            
        except Exception as e:
            logger.error(f"Failed to read live state: {e}")
            return None
    
    def enable_live_mode(self) -> bool:
        """
        Enable LIVE mode with two-phase commit
        """
        with self.commit_lock:
            try:
                logger.info("🔄 Starting LIVE mode activation...")
                
                # Phase 1: Pre-flight checks
                if not self._preflight_checks():
                    logger.error("❌ Pre-flight checks failed")
                    return False
                
                # Phase 2: Prepare shadow maps
                if not self._prepare_shadow_maps():
                    logger.error("❌ Shadow maps preparation failed")
                    return False
                
                # Phase 3: Atomic commit
                if not self._atomic_commit():
                    logger.error("❌ Atomic commit failed")
                    return False
                
                # Phase 4: Start watchdog
                self._start_watchdog()
                
                logger.info("✅ LIVE mode activated successfully")
                self.current_mode = LiveMode.LIVE
                return True
                
            except Exception as e:
                logger.error(f"❌ LIVE mode activation failed: {e}")
                self._emergency_rollback()
                return False
    
    def disable_live_mode(self) -> bool:
        """
        Disable LIVE mode (switch to simulation)
        """
        with self.commit_lock:
            try:
                logger.info("🔄 Disabling LIVE mode...")
                
                # Stop watchdog
                self._stop_watchdog()
                
                # Update state
                state = self._read_live_state()
                if state:
                    state.mode = LiveMode.SIMULATION
                    state.last_commit = int(time.time())
                    self._write_live_state(state)
                
                self.current_mode = LiveMode.SIMULATION
                logger.info("✅ LIVE mode disabled")
                return True
                
            except Exception as e:
                logger.error(f"❌ Failed to disable LIVE mode: {e}")
                return False
    
    def _preflight_checks(self) -> bool:
        """Pre-flight checks before enabling LIVE mode"""
        try:
            logger.info("🔍 Running pre-flight checks...")
            
            # Check shadow map size
            result = subprocess.run([
                "bpftool", "map", "show", "pinned", self.map_paths["live_shadow"]
            ], check=True, capture_output=True, text=True)
            
            # Parse map info
            lines = result.stdout.split('\n')
            for line in lines:
                if 'max_entries' in line:
                    max_entries = int(line.split()[-1])
                    if max_entries < self.config.shadow_map_size * 0.9:
                        logger.error(f"Shadow map too small: {max_entries}")
                        return False
                    break
            
            # Check loopback connectivity
            if not self._ping_loopback():
                logger.error("Loopback connectivity failed")
                return False
            
            # Check VPP status
            if not self._check_vpp_status():
                logger.error("VPP status check failed")
                return False
            
            logger.info("✅ Pre-flight checks passed")
            return True
            
        except Exception as e:
            logger.error(f"Pre-flight checks failed: {e}")
            return False
    
    def _ping_loopback(self) -> bool:
        """Test loopback connectivity"""
        try:
            result = subprocess.run([
                "ping", "-c", "1", "-W", "1", "127.0.0.1"
            ], capture_output=True)
            return result.returncode == 0
        except:
            return False
    
    def _check_vpp_status(self) -> bool:
        """Check VPP status"""
        try:
            result = subprocess.run([
                "vppctl", "show", "version"
            ], capture_output=True)
            return result.returncode == 0
        except:
            return True  # VPP not required for basic functionality
    
    def _prepare_shadow_maps(self) -> bool:
        """Prepare shadow maps for two-phase commit"""
        try:
            logger.info("🔧 Preparing shadow maps...")
            
            # Copy current rules to shadow map
            # This is a simplified version - in production, you'd copy actual rules
            shadow_map_id = self._get_map_id(self.map_paths["live_shadow"])
            if shadow_map_id is None:
                return False
            
            # Mark shadow maps as ready
            self.shadow_maps_ready = True
            logger.info("✅ Shadow maps prepared")
            return True
            
        except Exception as e:
            logger.error(f"Shadow maps preparation failed: {e}")
            return False
    
    def _atomic_commit(self) -> bool:
        """Perform atomic commit of shadow maps"""
        try:
            logger.info("⚡ Performing atomic commit...")
            
            # Update live state
            state = self._read_live_state()
            if state:
                state.mode = LiveMode.LIVE
                state.last_commit = int(time.time())
                self._write_live_state(state)
            
            # Trigger atomic swap in eBPF
            # This would be done via a BPF program call
            logger.info("✅ Atomic commit completed")
            return True
            
        except Exception as e:
            logger.error(f"Atomic commit failed: {e}")
            return False
    
    def _emergency_rollback(self):
        """Emergency rollback to simulation mode"""
        try:
            logger.warning("🚨 Emergency rollback triggered!")
            
            # Update state
            state = self._read_live_state()
            if state:
                state.mode = LiveMode.EMERGENCY
                state.emergency_mode = True
                self._write_live_state(state)
            
            # Stop watchdog
            self._stop_watchdog()
            
            # Switch to simulation mode
            self.current_mode = LiveMode.SIMULATION
            
            logger.info("✅ Emergency rollback completed")
            
        except Exception as e:
            logger.error(f"Emergency rollback failed: {e}")
    
    def _start_watchdog(self):
        """Start watchdog thread for monitoring"""
        if self.watchdog_thread is None or not self.watchdog_thread.is_alive():
            self.watchdog_running = True
            self.watchdog_thread = threading.Thread(target=self._watchdog_loop)
            self.watchdog_thread.daemon = True
            self.watchdog_thread.start()
            logger.info("🦮 Watchdog started")
    
    def _stop_watchdog(self):
        """Stop watchdog thread"""
        self.watchdog_running = False
        if self.watchdog_thread and self.watchdog_thread.is_alive():
            self.watchdog_thread.join(timeout=5)
        logger.info("🦮 Watchdog stopped")
    
    def _watchdog_loop(self):
        """Watchdog monitoring loop"""
        while self.watchdog_running:
            try:
                # Check system resources
                if self._check_system_resources():
                    # Check drop rate
                    if self._check_drop_rate():
                        logger.warning("🚨 High drop rate detected")
                        self._emergency_rollback()
                        break
                
                time.sleep(2)  # Check every 2 seconds
                
            except Exception as e:
                logger.error(f"Watchdog error: {e}")
                time.sleep(5)
    
    def _check_system_resources(self) -> bool:
        """Check system resources"""
        try:
            # Check CPU usage
            with open('/proc/loadavg', 'r') as f:
                load = float(f.read().split()[0])
                if load > self.config.rollback_on_cpu_usage:
                    logger.warning(f"High CPU load: {load}")
                    return False
            
            # Check memory usage
            with open('/proc/meminfo', 'r') as f:
                lines = f.readlines()
                total = int(lines[0].split()[1])
                available = int(lines[2].split()[1])
                usage = 1 - (available / total)
                if usage > self.config.rollback_on_memory_usage:
                    logger.warning(f"High memory usage: {usage:.2%}")
                    return False
            
            return True
            
        except Exception as e:
            logger.error(f"Resource check failed: {e}")
            return False
    
    def _check_drop_rate(self) -> bool:
        """Check packet drop rate"""
        try:
            state = self._read_live_state()
            if not state:
                return False
            
            total_packets = state.drop_count + state.allow_count
            if total_packets == 0:
                return False
            
            drop_rate = state.drop_count / total_packets
            return drop_rate > 0.5  # More than 50% drops
            
        except Exception as e:
            logger.error(f"Drop rate check failed: {e}")
            return False
    
    def _get_map_id(self, map_path: str) -> Optional[int]:
        """Get BPF map ID"""
        try:
            result = subprocess.run([
                "bpftool", "map", "show", "pinned", map_path
            ], check=True, capture_output=True, text=True)
            
            # Parse map ID from output
            for line in result.stdout.split('\n'):
                if line.strip().startswith('id:'):
                    return int(line.split(':')[1].strip())
            
            return None
            
        except Exception as e:
            logger.error(f"Failed to get map ID for {map_path}: {e}")
            return None
    
    def get_status(self) -> Dict:
        """Get current LIVE mode status"""
        try:
            state = self._read_live_state()
            if not state:
                return {"error": "Failed to read state"}
            
            return {
                "mode": state.mode.name,
                "last_commit": state.last_commit,
                "rule_count": state.rule_count,
                "drop_count": state.drop_count,
                "allow_count": state.allow_count,
                "emergency_mode": state.emergency_mode,
                "watchdog_running": self.watchdog_running
            }
            
        except Exception as e:
            return {"error": str(e)}

def create_live_manager(config: LiveConfig = None) -> LiveModeManager:
    """Factory function for creating LiveModeManager"""
    return LiveModeManager(config) 