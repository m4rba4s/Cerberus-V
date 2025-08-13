#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Cerberus-V Simple LIVE Mode Manager
# Elite-Mode APT-Grade Simplified Version

import os
import sys
import time
import json
import subprocess
import logging
import threading
from pathlib import Path
from typing import Dict, Optional
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)

class LiveMode(Enum):
    SIMULATION = 0
    LIVE = 1
    EMERGENCY = 2

@dataclass
class SimpleLiveState:
    mode: LiveMode
    timestamp: int
    drop_count: int
    allow_count: int

class SimpleLiveManager:
    """
    Simplified LIVE Mode Manager for testing
    """
    
    def __init__(self):
        self.current_mode = LiveMode.SIMULATION
        self.map_path = "/sys/fs/bpf/cerberus/live_state_map"
        
        # Initialize state
        self._init_state()
        logger.info(f"Simple LIVE Manager initialized: mode={self.current_mode.name}")
    
    def _init_state(self):
        """Initialize simple state"""
        try:
            # Write initial state (simulation mode) - pad to 32 bytes
            state_data = struct.pack("BIII", 0, int(time.time()), 0, 0)  # mode, timestamp, drops, allows
            # Pad to 32 bytes
            state_data += b'\x00' * (32 - len(state_data))
            key = struct.pack("I", 0)
            
            subprocess.run([
                "bpftool", "map", "update", "pinned", self.map_path,
                "key", key.hex(), "value", state_data.hex()
            ], check=True, capture_output=True)
            
            logger.info("Simple live state initialized")
            
        except Exception as e:
            logger.error(f"Failed to initialize simple state: {e}")
    
    def _read_state(self) -> Optional[SimpleLiveState]:
        """Read simple state from BPF map"""
        try:
            key = struct.pack("I", 0)
            result = subprocess.run([
                "bpftool", "map", "lookup", "pinned", self.map_path,
                "key", key.hex()
            ], check=True, capture_output=True, text=True)
            
            # Parse output
            lines = result.stdout.strip().split('\n')
            value_line = None
            for line in lines:
                if line.startswith('value:'):
                    value_line = line
                    break
            
            if not value_line:
                raise Exception("No value found in bpftool output")
            
            # Extract hex values
            hex_parts = value_line.replace('value:', '').strip().split()
            value_data = bytes.fromhex(''.join(hex_parts))
            
            # Unpack state (BIII = 13 bytes)
            if len(value_data) >= 13:
                mode_val, timestamp, drop_count, allow_count = struct.unpack("BIII", value_data[:13])
            else:
                # Fallback
                mode_val, timestamp, drop_count, allow_count = 0, int(time.time()), 0, 0
            
            return SimpleLiveState(
                mode=LiveMode(mode_val),
                timestamp=timestamp,
                drop_count=drop_count,
                allow_count=allow_count
            )
            
        except Exception as e:
            logger.error(f"Failed to read simple state: {e}")
            return None
    
    def _write_state(self, state: SimpleLiveState):
        """Write simple state to BPF map"""
        try:
            state_data = struct.pack("BIII", 
                state.mode.value,
                state.timestamp,
                state.drop_count,
                state.allow_count
            )
            # Pad to 32 bytes
            state_data += b'\x00' * (32 - len(state_data))
            
            key = struct.pack("I", 0)
            subprocess.run([
                "bpftool", "map", "update", "pinned", self.map_path,
                "key", key.hex(), "value", state_data.hex()
            ], check=True, capture_output=True)
            
        except Exception as e:
            logger.error(f"Failed to write simple state: {e}")
            raise
    
    def enable_live_mode(self) -> bool:
        """Enable LIVE mode"""
        try:
            logger.info("🔄 Enabling LIVE mode...")
            
            state = self._read_state()
            if state:
                state.mode = LiveMode.LIVE
                state.timestamp = int(time.time())
                self._write_state(state)
                self.current_mode = LiveMode.LIVE
                logger.info("✅ LIVE mode enabled")
                return True
            else:
                logger.error("❌ Failed to read state")
                return False
                
        except Exception as e:
            logger.error(f"❌ Failed to enable LIVE mode: {e}")
            return False
    
    def disable_live_mode(self) -> bool:
        """Disable LIVE mode"""
        try:
            logger.info("🔄 Disabling LIVE mode...")
            
            state = self._read_state()
            if state:
                state.mode = LiveMode.SIMULATION
                state.timestamp = int(time.time())
                self._write_state(state)
                self.current_mode = LiveMode.SIMULATION
                logger.info("✅ LIVE mode disabled")
                return True
            else:
                logger.error("❌ Failed to read state")
                return False
                
        except Exception as e:
            logger.error(f"❌ Failed to disable LIVE mode: {e}")
            return False
    
    def get_status(self) -> Dict:
        """Get current status"""
        try:
            state = self._read_state()
            if not state:
                return {"error": "Failed to read state"}
            
            return {
                "mode": state.mode.name.lower(),
                "timestamp": state.timestamp,
                "drop_count": state.drop_count,
                "allow_count": state.allow_count,
                "emergency_mode": False,
                "watchdog_running": False
            }
            
        except Exception as e:
            return {"error": str(e)}

# Import struct at the top
import struct

def create_simple_live_manager() -> SimpleLiveManager:
    """Factory function for creating SimpleLiveManager"""
    return SimpleLiveManager() 