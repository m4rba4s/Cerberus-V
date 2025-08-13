#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Cerberus-V eBPF Firewall Manager
# Elite-Mode APT-Grade Rule Management

import os
import sys
import time
import json
import struct
import subprocess
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

# Add project root to path
sys.path.append(str(Path(__file__).parent.parent))

logger = logging.getLogger(__name__)

class RuleAction(Enum):
    DROP = 0
    ALLOW = 1
    LOG = 2

class Protocol(Enum):
    ANY = 0
    ICMP = 1
    TCP = 6
    UDP = 17

@dataclass
class FirewallRule:
    id: int
    action: RuleAction
    protocol: Protocol
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    enabled: bool = True
    priority: int = 100
    hit_count: int = 0
    description: str = ""

@dataclass
class FirewallStats:
    packets_processed: int = 0
    packets_dropped: int = 0
    packets_allowed: int = 0
    bytes_processed: int = 0
    rules_checked: int = 0
    cache_hits: int = 0
    cache_misses: int = 0

class EbpfFirewallManager:
    """
    eBPF Firewall Manager для управления правилами и статистикой
    """
    
    def __init__(self, interface: str = "eth0", demo_mode: bool = False):
        self.interface = interface
        self.demo_mode = demo_mode
        self.program_loaded = False
        self.rules: Dict[int, FirewallRule] = {}
        self.stats = FirewallStats()
        self.next_rule_id = 1
        
        # BPF map paths
        self.map_paths = {
            "firewall_rules": "/sys/fs/bpf/firewall_rules",
            "session_table": "/sys/fs/bpf/session_table", 
            "stats_map": "/sys/fs/bpf/stats_map",
            "blacklist": "/sys/fs/bpf/blacklist",
            "whitelist": "/sys/fs/bpf/whitelist"
        }
        
        # Program paths
        self.program_path = Path(__file__).parent / "firewall_engine.o"
        
        logger.info(f"eBPF Firewall Manager initialized: interface={interface}, demo_mode={demo_mode}")
    
    def load_program(self) -> bool:
        """Загрузка eBPF программы в ядро"""
        if self.demo_mode:
            logger.info("Demo mode: simulating eBPF program load")
            self.program_loaded = True
            return True
        
        try:
            # Compile eBPF program
            if not self._compile_program():
                return False
            
            # Load program with bpftool
            cmd = [
                "bpftool", "prog", "load", str(self.program_path),
                "/sys/fs/bpf/firewall_engine"
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                logger.error(f"Failed to load eBPF program: {result.stderr}")
                return False
            
            # Attach to interface
            cmd = [
                "bpftool", "net", "attach", "xdp", "id",
                self._get_program_id(), "dev", self.interface
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                logger.error(f"Failed to attach program to interface: {result.stderr}")
                return False
            
            self.program_loaded = True
            logger.info(f"eBPF program loaded and attached to {self.interface}")
            return True
            
        except Exception as e:
            logger.error(f"Error loading eBPF program: {e}")
            return False
    
    def unload_program(self) -> bool:
        """Выгрузка eBPF программы"""
        if self.demo_mode:
            logger.info("Demo mode: simulating eBPF program unload")
            self.program_loaded = False
            return True
        
        try:
            # Detach from interface
            cmd = ["bpftool", "net", "detach", "xdp", "dev", self.interface]
            subprocess.run(cmd, capture_output=True)
            
            # Unload program
            cmd = ["bpftool", "prog", "unload", "/sys/fs/bpf/firewall_engine"]
            subprocess.run(cmd, capture_output=True)
            
            self.program_loaded = False
            logger.info("eBPF program unloaded")
            return True
            
        except Exception as e:
            logger.error(f"Error unloading eBPF program: {e}")
            return False
    
    def add_rule(self, rule: FirewallRule) -> bool:
        """Добавление правила в eBPF map"""
        if not self.program_loaded:
            logger.error("eBPF program not loaded")
            return False
        
        rule.id = self.next_rule_id
        self.next_rule_id += 1
        self.rules[rule.id] = rule
        
        if self.demo_mode:
            logger.info(f"Demo mode: added rule {rule.id}")
            return True
        
        try:
            # Convert rule to binary format
            rule_data = self._rule_to_binary(rule)
            
            # Update BPF map
            cmd = [
                "bpftool", "map", "update", "pinned", self.map_paths["firewall_rules"],
                "key", str(rule.id), "value", rule_data
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                logger.error(f"Failed to add rule to BPF map: {result.stderr}")
                return False
            
            logger.info(f"Rule {rule.id} added to eBPF map")
            return True
            
        except Exception as e:
            logger.error(f"Error adding rule: {e}")
            return False
    
    def remove_rule(self, rule_id: int) -> bool:
        """Удаление правила из eBPF map"""
        if rule_id not in self.rules:
            logger.error(f"Rule {rule_id} not found")
            return False
        
        if self.demo_mode:
            del self.rules[rule_id]
            logger.info(f"Demo mode: removed rule {rule_id}")
            return True
        
        try:
            # Delete from BPF map
            cmd = [
                "bpftool", "map", "delete", "pinned", self.map_paths["firewall_rules"],
                "key", str(rule_id)
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                logger.error(f"Failed to remove rule from BPF map: {result.stderr}")
                return False
            
            del self.rules[rule_id]
            logger.info(f"Rule {rule_id} removed from eBPF map")
            return True
            
        except Exception as e:
            logger.error(f"Error removing rule: {e}")
            return False
    
    def update_rule(self, rule_id: int, rule: FirewallRule) -> bool:
        """Обновление правила в eBPF map"""
        if rule_id not in self.rules:
            logger.error(f"Rule {rule_id} not found")
            return False
        
        rule.id = rule_id
        self.rules[rule_id] = rule
        
        if self.demo_mode:
            logger.info(f"Demo mode: updated rule {rule_id}")
            return True
        
        try:
            # Convert rule to binary format
            rule_data = self._rule_to_binary(rule)
            
            # Update BPF map
            cmd = [
                "bpftool", "map", "update", "pinned", self.map_paths["firewall_rules"],
                "key", str(rule_id), "value", rule_data
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                logger.error(f"Failed to update rule in BPF map: {result.stderr}")
                return False
            
            logger.info(f"Rule {rule_id} updated in eBPF map")
            return True
            
        except Exception as e:
            logger.error(f"Error updating rule: {e}")
            return False
    
    def get_stats(self) -> FirewallStats:
        """Получение статистики из eBPF map"""
        if self.demo_mode:
            # Simulate some stats
            self.stats.packets_processed += 1000
            self.stats.packets_dropped += 50
            self.stats.packets_allowed += 950
            self.stats.bytes_processed += 50000
            return self.stats
        
        try:
            # Read stats from BPF map
            cmd = [
                "bpftool", "map", "lookup", "pinned", self.map_paths["stats_map"],
                "key", "0"
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                # Parse stats from output
                stats_data = self._parse_stats_output(result.stdout)
                self.stats = stats_data
            
            return self.stats
            
        except Exception as e:
            logger.error(f"Error getting stats: {e}")
            return self.stats
    
    def add_to_blacklist(self, ip: str) -> bool:
        """Добавление IP в черный список"""
        try:
            ip_int = self._ip_to_int(ip)
            key = (ip_int << 32) | 32  # /32 prefix
            
            if self.demo_mode:
                logger.info(f"Demo mode: added {ip} to blacklist")
                return True
            
            cmd = [
                "bpftool", "map", "update", "pinned", self.map_paths["blacklist"],
                "key", str(key), "value", "1"
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            return result.returncode == 0
            
        except Exception as e:
            logger.error(f"Error adding to blacklist: {e}")
            return False
    
    def add_to_whitelist(self, ip: str) -> bool:
        """Добавление IP в белый список"""
        try:
            ip_int = self._ip_to_int(ip)
            key = (ip_int << 32) | 32  # /32 prefix
            
            if self.demo_mode:
                logger.info(f"Demo mode: added {ip} to whitelist")
                return True
            
            cmd = [
                "bpftool", "map", "update", "pinned", self.map_paths["whitelist"],
                "key", str(key), "value", "1"
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            return result.returncode == 0
            
        except Exception as e:
            logger.error(f"Error adding to whitelist: {e}")
            return False
    
    def get_rules(self) -> List[FirewallRule]:
        """Получение всех правил"""
        return list(self.rules.values())
    
    def get_rule(self, rule_id: int) -> Optional[FirewallRule]:
        """Получение конкретного правила"""
        return self.rules.get(rule_id)
    
    def is_loaded(self) -> bool:
        """Проверка загрузки программы"""
        return self.program_loaded
    
    def _compile_program(self) -> bool:
        """Компиляция eBPF программы"""
        try:
            source_path = Path(__file__).parent / "firewall_engine.c"
            if not source_path.exists():
                logger.error(f"Source file not found: {source_path}")
                return False
            
            cmd = [
                "clang", "-O2", "-g", "-Wall", "-target", "bpf",
                "-c", str(source_path), "-o", str(self.program_path)
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                logger.error(f"Compilation failed: {result.stderr}")
                return False
            
            logger.info("eBPF program compiled successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error compiling program: {e}")
            return False
    
    def _get_program_id(self) -> str:
        """Получение ID загруженной программы"""
        try:
            cmd = ["bpftool", "prog", "list", "--json"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                programs = json.loads(result.stdout)
                for prog in programs:
                    if "firewall_engine" in prog.get("name", ""):
                        return str(prog["id"])
            
            return "1"  # Default fallback
            
        except Exception as e:
            logger.error(f"Error getting program ID: {e}")
            return "1"
    
    def _rule_to_binary(self, rule: FirewallRule) -> str:
        """Конвертация правила в бинарный формат"""
        src_ip = self._ip_to_int(rule.src_ip) if rule.src_ip != "0.0.0.0" else 0
        dst_ip = self._ip_to_int(rule.dst_ip) if rule.dst_ip != "0.0.0.0" else 0
        
        # Pack rule structure: id(4) + action(1) + protocol(1) + src_ip(4) + dst_ip(4) + src_port(2) + dst_port(2) + enabled(1) + priority(1) + hit_count(4)
        rule_bytes = struct.pack("<IBBIIHHBB", 
            rule.id, rule.action.value, rule.protocol.value,
            src_ip, dst_ip, rule.src_port, rule.dst_port,
            rule.enabled, rule.priority, rule.hit_count
        )
        
        return rule_bytes.hex()
    
    def _parse_stats_output(self, output: str) -> FirewallStats:
        """Парсинг статистики из вывода bpftool"""
        try:
            # Parse hex output from bpftool
            lines = output.strip().split('\n')
            if len(lines) >= 2:
                hex_data = lines[1].split()[1:]  # Skip "value:"
                if len(hex_data) >= 8:
                    # Unpack stats structure
                    stats_bytes = bytes.fromhex(''.join(hex_data))
                    stats = struct.unpack("<QQQQQQQ", stats_bytes)
                    
                    return FirewallStats(
                        packets_processed=stats[0],
                        packets_dropped=stats[1],
                        packets_allowed=stats[2],
                        bytes_processed=stats[3],
                        rules_checked=stats[4],
                        cache_hits=stats[5],
                        cache_misses=stats[6]
                    )
        except Exception as e:
            logger.error(f"Error parsing stats: {e}")
        
        return FirewallStats()
    
    def _ip_to_int(self, ip: str) -> int:
        """Конвертация IP адреса в integer"""
        parts = ip.split('.')
        return (int(parts[0]) << 24) | (int(parts[1]) << 16) | (int(parts[2]) << 8) | int(parts[3])

def create_firewall_manager(interface: str = "eth0", demo_mode: bool = False) -> EbpfFirewallManager:
    """Фабричная функция для создания firewall manager"""
    return EbpfFirewallManager(interface, demo_mode) 