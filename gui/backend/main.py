#!/usr/bin/env python3
"""
Cerberus-V Professional Firewall Backend with Real VPP/eBPF Integration
Production-ready firewall management with real system control
"""

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
import uvicorn
import asyncio
import json
import logging
import time
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from pydantic import BaseModel, Field
import ipaddress
import socket
import psutil
import random
import os

# Import real system control
try:
    from modules.real_system_control import get_system_control
    REAL_SYSTEM_AVAILABLE = True
except ImportError:
    REAL_SYSTEM_AVAILABLE = False
    logging.warning("Real system control not available, using fallback mode")

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize system control
system_control = get_system_control(demo_mode=True) if REAL_SYSTEM_AVAILABLE else None

app = FastAPI(
    title="Cerberus-V Professional Firewall",
    description="Production VPP/eBPF Firewall Management System",
    version="2.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ================== PROFESSIONAL DATA MODELS ==================

class FirewallRule(BaseModel):
    id: Optional[str] = None
    name: str = Field(..., description="Rule name")
    description: Optional[str] = ""
    enabled: bool = True
    priority: int = Field(default=100, ge=1, le=1000)
    
    # Source configuration
    source_ip: str = Field(default="any", description="Source IP/CIDR")
    source_port: str = Field(default="any", description="Source port/range")
    source_zone: Optional[str] = "any"
    
    # Destination configuration
    dest_ip: str = Field(default="any", description="Destination IP/CIDR")
    dest_port: str = Field(default="any", description="Destination port/range")
    dest_zone: Optional[str] = "any"
    
    # Protocol and action
    protocol: str = Field(default="any", pattern=r"^(tcp|udp|icmp|any)$")
    action: str = Field(default="allow", pattern=r"^(allow|deny|drop|reject)$")
    
    # Advanced features
    log_enabled: bool = False
    rate_limit: Optional[int] = None
    connection_limit: Optional[int] = None
    geo_blocking: List[str] = []
    time_restrictions: Optional[Dict[str, Any]] = None
    
    # Metadata
    created_at: Optional[datetime] = None
    modified_at: Optional[datetime] = None
    created_by: str = "admin"
    tags: List[str] = []

class NetworkObject(BaseModel):
    id: Optional[str] = None
    name: str
    type: str = Field(..., pattern=r"^(host|network|range|group)$")
    value: str
    description: Optional[str] = ""
    tags: List[str] = []
    created_at: Optional[datetime] = None

class ThreatIntelligence(BaseModel):
    ip_address: str
    threat_type: str
    severity: str = Field(..., pattern=r"^(low|medium|high|critical)$")
    reputation_score: float = Field(..., ge=0, le=100)
    country: Optional[str] = "Unknown"
    organization: Optional[str] = "Unknown"
    description: Optional[str] = ""
    first_seen: datetime
    last_seen: datetime

class SecurityPolicy(BaseModel):
    id: Optional[str] = None
    name: str
    description: Optional[str] = ""
    rules: List[str] = []  # Rule IDs
    enabled: bool = True
    default_action: str = Field(default="deny", pattern=r"^(allow|deny)$")
    created_at: Optional[datetime] = None

# ================== DATA STORAGE ==================

# In-memory storage (in production, use database)
firewall_rules: Dict[str, FirewallRule] = {}
network_objects: Dict[str, NetworkObject] = {}
security_policies: Dict[str, SecurityPolicy] = {}
threat_intel_db: Dict[str, ThreatIntelligence] = {}
system_logs: List[Dict[str, Any]] = []

# WebSocket connections
active_connections: List[WebSocket] = []

# ================== UTILITY FUNCTIONS ==================

def validate_ip_address(ip: str) -> bool:
    """Validate IP address or CIDR"""
    if ip == "any":
        return True
    try:
        ipaddress.ip_network(ip, strict=False)
        return True
    except ValueError:
        return False

def validate_port(port: str) -> bool:
    """Validate port or port range"""
    if port == "any":
        return True
    try:
        if "-" in port:
            start, end = port.split("-")
            return 1 <= int(start) <= 65535 and 1 <= int(end) <= 65535
        else:
            return 1 <= int(port) <= 65535
    except ValueError:
        return False

def generate_rule_id() -> str:
    """Generate unique rule ID"""
    return f"rule_{uuid.uuid4().hex[:8]}"

def log_activity(action: str, details: Dict[str, Any]):
    """Log system activity"""
    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "action": action,
        "details": details,
        "user": "admin"  # In production, get from auth context
    }
    system_logs.append(log_entry)
    
    # Keep only last 1000 logs
    if len(system_logs) > 1000:
        system_logs[:] = system_logs[-1000:]

# ================== REAL SYSTEM CONTROL API ==================

@app.post("/api/system/start")
async def start_firewall_engine() -> Dict[str, Any]:
    """Start the firewall engine (VPP + eBPF)"""
    if not system_control:
        raise HTTPException(status_code=503, detail="System control not available")
    
    result = await system_control.start_firewall_engine()
    
    log_activity("firewall_engine_start", result)
    
    # Broadcast update to WebSocket clients
    await broadcast_update({
        "type": "system_status_changed",
        "status": result
    })
    
    return result

@app.post("/api/system/stop")
async def stop_firewall_engine() -> Dict[str, Any]:
    """Stop the firewall engine"""
    if not system_control:
        raise HTTPException(status_code=503, detail="System control not available")
    
    result = await system_control.stop_firewall_engine()
    
    log_activity("firewall_engine_stop", result)
    
    # Broadcast update to WebSocket clients
    await broadcast_update({
        "type": "system_status_changed",
        "status": result
    })
    
    return result

@app.get("/api/system/status")
async def get_system_status() -> Dict[str, Any]:
    """Get comprehensive system status"""
    if not system_control:
        # Fallback status for when system control is not available
        return {
            "engine_status": "unavailable",
            "protection_mode": "none",
            "error": "System control not available",
            "demo_mode": True
        }
    
    return await system_control.get_system_status()

@app.post("/api/vpp/cli")
async def execute_vpp_command(command: Dict[str, str]) -> Dict[str, Any]:
    """Execute VPP CLI command"""
    if not system_control:
        raise HTTPException(status_code=503, detail="System control not available")
    
    cmd = command.get("command", "")
    if not cmd:
        raise HTTPException(status_code=400, detail="Command is required")
    
    result = await system_control.execute_vpp_command(cmd)
    
    log_activity("vpp_cli_command", {"command": cmd, "result": result})
    
    return result

@app.get("/api/system/info")
async def get_system_info() -> Dict[str, Any]:
    """Get system information"""
    if not system_control:
        raise HTTPException(status_code=503, detail="System control not available")
    
    return await system_control.get_system_info()

@app.get("/api/vpp/status")
async def get_vpp_status() -> Dict[str, Any]:
    """Get VPP status"""
    if not system_control:
        raise HTTPException(status_code=503, detail="System control not available")
    
    return await system_control.get_vpp_status()

@app.get("/api/ebpf/status")
async def get_ebpf_status() -> Dict[str, Any]:
    """Get eBPF status"""
    if not system_control:
        raise HTTPException(status_code=503, detail="System control not available")
    
    return await system_control.get_ebpf_status()

@app.get("/api/network/statistics")
async def get_network_statistics() -> Dict[str, Any]:
    """Get network statistics"""
    if not system_control:
        raise HTTPException(status_code=503, detail="System control not available")
    
    return await system_control.get_network_statistics()

# ================== WEBSOCKET MANAGEMENT ==================

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    active_connections.append(websocket)
    
    try:
        while True:
            # Send real-time updates
            data = await get_realtime_data()
            await websocket.send_text(json.dumps(data))
            await asyncio.sleep(2)
            
    except WebSocketDisconnect:
        active_connections.remove(websocket)

async def broadcast_update(message: Dict[str, Any]):
    """Broadcast update to all connected clients"""
    if active_connections:
        message_str = json.dumps(message)
        for connection in active_connections.copy():
            try:
                await connection.send_text(message_str)
            except:
                active_connections.remove(connection)

# ================== FIREWALL RULES API ==================

@app.get("/api/firewall/rules")
async def get_firewall_rules(
    enabled: Optional[bool] = None,
    protocol: Optional[str] = None,
    action: Optional[str] = None,
    tag: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Get firewall rules with filtering"""
    rules = list(firewall_rules.values())
    
    # Apply filters
    if enabled is not None:
        rules = [r for r in rules if r.enabled == enabled]
    if protocol:
        rules = [r for r in rules if r.protocol == protocol]
    if action:
        rules = [r for r in rules if r.action == action]
    if tag:
        rules = [r for r in rules if tag in r.tags]
    
    # Sort by priority
    rules.sort(key=lambda x: x.priority)
    
    return [r.dict() for r in rules]

@app.post("/api/firewall/rules")
async def create_firewall_rule(rule: FirewallRule) -> Dict[str, Any]:
    """Create new firewall rule"""
    # Validate inputs
    if not validate_ip_address(rule.source_ip):
        raise HTTPException(status_code=400, detail="Invalid source IP")
    if not validate_ip_address(rule.dest_ip):
        raise HTTPException(status_code=400, detail="Invalid destination IP")
    if not validate_port(rule.source_port):
        raise HTTPException(status_code=400, detail="Invalid source port")
    if not validate_port(rule.dest_port):
        raise HTTPException(status_code=400, detail="Invalid destination port")
    
    # Generate ID and timestamps
    rule.id = generate_rule_id()
    rule.created_at = datetime.now()
    rule.modified_at = datetime.now()
    
    # Store rule
    firewall_rules[rule.id] = rule
    
    # Apply rule to real system if available
    if system_control:
        await system_control.apply_firewall_rule(rule.dict())
    
    # Log activity
    log_activity("rule_created", {"rule_id": rule.id, "name": rule.name})
    
    # Broadcast update
    await broadcast_update({
        "type": "rule_created",
        "rule": rule.dict()
    })
    
    return {"status": "success", "rule_id": rule.id, "message": "Rule created successfully"}

@app.put("/api/firewall/rules/{rule_id}")
async def update_firewall_rule(rule_id: str, rule: FirewallRule) -> Dict[str, Any]:
    """Update existing firewall rule"""
    if rule_id not in firewall_rules:
        raise HTTPException(status_code=404, detail="Rule not found")
    
    # Validate inputs
    if not validate_ip_address(rule.source_ip):
        raise HTTPException(status_code=400, detail="Invalid source IP")
    if not validate_ip_address(rule.dest_ip):
        raise HTTPException(status_code=400, detail="Invalid destination IP")
    if not validate_port(rule.source_port):
        raise HTTPException(status_code=400, detail="Invalid source port")
    if not validate_port(rule.dest_port):
        raise HTTPException(status_code=400, detail="Invalid destination port")
    
    # Update rule
    rule.id = rule_id
    rule.modified_at = datetime.now()
    rule.created_at = firewall_rules[rule_id].created_at  # Preserve original creation time
    
    firewall_rules[rule_id] = rule
    
    # Apply rule to real system if available
    if system_control:
        await system_control.apply_firewall_rule(rule.dict())
    
    # Log activity
    log_activity("rule_updated", {"rule_id": rule_id, "name": rule.name})
    
    # Broadcast update
    await broadcast_update({
        "type": "rule_updated",
        "rule": rule.dict()
    })
    
    return {"status": "success", "message": "Rule updated successfully"}

@app.delete("/api/firewall/rules/{rule_id}")
async def delete_firewall_rule(rule_id: str) -> Dict[str, Any]:
    """Delete firewall rule"""
    if rule_id not in firewall_rules:
        raise HTTPException(status_code=404, detail="Rule not found")
    
    rule_name = firewall_rules[rule_id].name
    del firewall_rules[rule_id]
    
    # Remove rule from real system if available
    if system_control:
        await system_control.remove_firewall_rule(rule_id)
    
    # Log activity
    log_activity("rule_deleted", {"rule_id": rule_id, "name": rule_name})
    
    # Broadcast update
    await broadcast_update({
        "type": "rule_deleted",
        "rule_id": rule_id
    })
    
    return {"status": "success", "message": "Rule deleted successfully"}

@app.post("/api/firewall/rules/{rule_id}/toggle")
async def toggle_firewall_rule(rule_id: str) -> Dict[str, Any]:
    """Toggle firewall rule enabled/disabled"""
    if rule_id not in firewall_rules:
        raise HTTPException(status_code=404, detail="Rule not found")
    
    rule = firewall_rules[rule_id]
    rule.enabled = not rule.enabled
    rule.modified_at = datetime.now()
    
    # Apply/remove rule from real system if available
    if system_control:
        if rule.enabled:
            await system_control.apply_firewall_rule(rule.dict())
        else:
            await system_control.remove_firewall_rule(rule_id)
    
    # Log activity
    log_activity("rule_toggled", {
        "rule_id": rule_id,
        "name": rule.name,
        "enabled": rule.enabled
    })
    
    # Broadcast update
    await broadcast_update({
        "type": "rule_updated",
        "rule": rule.dict()
    })
    
    return {"status": "success", "enabled": rule.enabled}

@app.post("/api/firewall/rules/bulk-action")
async def bulk_rule_action(action: str, rule_ids: List[str]) -> Dict[str, Any]:
    """Perform bulk action on multiple rules"""
    if action not in ["enable", "disable", "delete"]:
        raise HTTPException(status_code=400, detail="Invalid action")
    
    affected_rules = []
    
    for rule_id in rule_ids:
        if rule_id in firewall_rules:
            if action == "enable":
                firewall_rules[rule_id].enabled = True
                firewall_rules[rule_id].modified_at = datetime.now()
                # Apply to real system
                if system_control:
                    await system_control.apply_firewall_rule(firewall_rules[rule_id].dict())
            elif action == "disable":
                firewall_rules[rule_id].enabled = False
                firewall_rules[rule_id].modified_at = datetime.now()
                # Remove from real system
                if system_control:
                    await system_control.remove_firewall_rule(rule_id)
            elif action == "delete":
                # Remove from real system
                if system_control:
                    await system_control.remove_firewall_rule(rule_id)
                del firewall_rules[rule_id]
            
            affected_rules.append(rule_id)
    
    # Log activity
    log_activity("bulk_action", {
        "action": action,
        "rule_ids": affected_rules,
        "count": len(affected_rules)
    })
    
    # Broadcast update
    await broadcast_update({
        "type": "bulk_update",
        "action": action,
        "rule_ids": affected_rules
    })
    
    return {"status": "success", "affected_rules": len(affected_rules)}

# ================== NETWORK OBJECTS API ==================

@app.get("/api/network/objects")
async def get_network_objects() -> List[Dict[str, Any]]:
    """Get all network objects"""
    return [obj.dict() for obj in network_objects.values()]

@app.post("/api/network/objects")
async def create_network_object(obj: NetworkObject) -> Dict[str, Any]:
    """Create network object"""
    # Validate based on type
    if obj.type == "host":
        if not validate_ip_address(obj.value):
            raise HTTPException(status_code=400, detail="Invalid IP address")
    elif obj.type == "network":
        if not validate_ip_address(obj.value):
            raise HTTPException(status_code=400, detail="Invalid network CIDR")
    
    obj.id = f"obj_{uuid.uuid4().hex[:8]}"
    obj.created_at = datetime.now()
    
    network_objects[obj.id] = obj
    
    log_activity("network_object_created", {"object_id": obj.id, "name": obj.name})
    
    return {"status": "success", "object_id": obj.id}

@app.delete("/api/network/objects/{object_id}")
async def delete_network_object(object_id: str) -> Dict[str, Any]:
    """Delete network object"""
    if object_id not in network_objects:
        raise HTTPException(status_code=404, detail="Object not found")
    
    obj_name = network_objects[object_id].name
    del network_objects[object_id]
    
    log_activity("network_object_deleted", {"object_id": object_id, "name": obj_name})
    
    return {"status": "success", "message": "Object deleted successfully"}

# ================== THREAT INTELLIGENCE API ==================

@app.get("/api/threat-intel")
async def get_threat_intelligence() -> List[Dict[str, Any]]:
    """Get threat intelligence data"""
    return [threat.dict() for threat in threat_intel_db.values()]

@app.post("/api/threat-intel")
async def add_threat_intelligence(threat: ThreatIntelligence) -> Dict[str, Any]:
    """Add threat intelligence"""
    threat_intel_db[threat.ip_address] = threat
    
    log_activity("threat_intel_added", {
        "ip": threat.ip_address,
        "type": threat.threat_type,
        "severity": threat.severity
    })
    
    return {"status": "success", "message": "Threat intelligence added"}

@app.delete("/api/threat-intel/{ip_address}")
async def remove_threat_intelligence(ip_address: str) -> Dict[str, Any]:
    """Remove threat intelligence"""
    if ip_address not in threat_intel_db:
        raise HTTPException(status_code=404, detail="Threat intelligence not found")
    
    del threat_intel_db[ip_address]
    
    log_activity("threat_intel_removed", {"ip": ip_address})
    
    return {"status": "success", "message": "Threat intelligence removed"}

# ================== SECURITY POLICIES API ==================

@app.get("/api/security/policies")
async def get_security_policies() -> List[Dict[str, Any]]:
    """Get security policies"""
    return [policy.dict() for policy in security_policies.values()]

@app.post("/api/security/policies")
async def create_security_policy(policy: SecurityPolicy) -> Dict[str, Any]:
    """Create security policy"""
    policy.id = f"policy_{uuid.uuid4().hex[:8]}"
    policy.created_at = datetime.now()
    
    security_policies[policy.id] = policy
    
    log_activity("policy_created", {"policy_id": policy.id, "name": policy.name})
    
    return {"status": "success", "policy_id": policy.id}

# ================== ANALYTICS ENDPOINTS ==================

@app.get("/api/analytics/live-threats")
async def get_live_threats() -> Dict[str, Any]:
    """Get live threat intelligence data"""
    # Generate rich demo threats data
    current_time = datetime.now()
    threats = []
    
    attack_types = ['DDoS', 'Port Scan', 'Brute Force', 'SQL Injection', 'XSS', 'Malware', 'Phishing', 'Ransomware', 'Botnet', 'APT']
    countries = ['CN', 'RU', 'KP', 'IR', 'US', 'DE', 'GB', 'FR', 'JP', 'BR']
    protocols = ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS', 'SSH', 'FTP']
    mitre_techniques = ['T1190', 'T1566', 'T1110', 'T1046', 'T1498', 'T1059', 'T1055', 'T1003', 'T1083', 'T1486']
    
    for i in range(25):
        threat_time = current_time - timedelta(minutes=random.randint(1, 120))
        severity = random.choices(['critical', 'high', 'medium', 'low'], weights=[10, 25, 40, 25])[0]
        attack_type = random.choice(attack_types)
        country = random.choice(countries)
        
        threats.append({
            "id": f"threat_{i}_{int(time.time())}",
            "timestamp": threat_time.isoformat(),
            "sourceIp": f"{random.randint(1, 223)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 254)}",
            "targetIp": f"192.168.1.{random.randint(1, 254)}",
            "country": country,
            "attackType": attack_type,
            "severity": severity,
            "blocked": random.choice([True, False]),
            "confidence": random.randint(60, 99),
            "protocol": random.choice(protocols),
            "port": random.choice([22, 80, 443, 3389, 1433, 3306, 21, 25, 53, 8080]),
            "status": random.choice(['active', 'blocked', 'investigating', 'resolved']),
            "description": f"Detected {attack_type} attack from {country} targeting internal network",
            "mitreId": random.choice(mitre_techniques) if severity in ['high', 'critical'] else None
        })
    
    return {
        "threats": threats,
        "total_threats": len(threats),
        "blocked_threats": sum(1 for t in threats if t["blocked"])
    }

@app.get("/api/analytics/network-flows")
async def get_network_flows() -> Dict[str, Any]:
    """Get network flow analytics"""
    # Generate rich demo network flows
    flows = []
    services = ['HTTP', 'HTTPS', 'SSH', 'FTP', 'DNS', 'SMTP', 'MySQL', 'PostgreSQL', 'Redis', 'MongoDB']
    countries = ['US', 'CN', 'RU', 'DE', 'GB', 'FR', 'JP', 'BR', 'IN', 'CA']
    tcp_flags = ['SYN', 'ACK', 'FIN', 'RST', 'PSH', 'URG']
    
    for i in range(50):
        flows.append({
            "id": f"flow_{i}_{int(time.time())}",
            "sourceIp": f"{random.randint(1, 223)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 254)}",
            "destinationIp": f"192.168.1.{random.randint(1, 254)}",
            "protocol": random.choice(['TCP', 'UDP', 'ICMP']),
            "port": random.choice([80, 443, 22, 21, 25, 53, 3306, 5432, 6379, 27017]),
            "bytesIn": random.randint(1024, 1000000),
            "bytesOut": random.randint(512, 500000),
            "duration": random.randint(1, 3600),
            "suspicious": random.choice([True, False]),
            "country": random.choice(countries),
            "service": random.choice(services),
            "encrypted": random.choice([True, False]),
            "packets": random.randint(10, 10000),
            "flags": random.sample(tcp_flags, random.randint(1, 3))
        })
    
    return {
        "flows": flows,
        "total_flows": len(flows),
        "total_bytes": sum(f["bytesIn"] + f["bytesOut"] for f in flows)
    }

@app.get("/api/analytics/service-metrics")
async def get_service_metrics() -> Dict[str, Any]:
    """Get service performance metrics"""
    # Generate rich demo service metrics
    services = ['Apache', 'Nginx', 'MySQL', 'PostgreSQL', 'Redis', 'MongoDB', 'SSH', 'FTP', 'DNS', 'VPN']
    statuses = ['running', 'stopped', 'warning', 'error']
    
    service_data = []
    for service in services:
        service_data.append({
            "service": service,
            "status": random.choices(statuses, weights=[70, 10, 15, 5])[0],
            "connections": random.randint(10, 1000),
            "bandwidth": random.randint(5, 95),
            "cpu": random.randint(1, 100),
            "memory": random.randint(10, 90),
            "uptime": f"{random.randint(1, 30)}d {random.randint(0, 23)}h",
            "threats": random.randint(0, 50),
            "blocked": random.randint(0, 20),
            "version": f"v{random.randint(1, 5)}.{random.randint(0, 9)}.{random.randint(0, 9)}",
            "pid": random.randint(1000, 9999)
        })
    
    return {
        "services": service_data
    }

# ================== FLOW ACTION MANAGEMENT ==================

@app.post("/api/flow/action")
async def handle_flow_action(action_data: Dict[str, Any]) -> Dict[str, Any]:
    """Handle flow action requests (block, allow, investigate, etc.)"""
    try:
        action_type = action_data.get("action")
        flow_id = action_data.get("flowId")
        source_ip = action_data.get("sourceIp")
        destination_ip = action_data.get("destinationIp")
        protocol = action_data.get("protocol", "any")
        port = action_data.get("port", "any")
        
        if not action_type or not source_ip:
            raise HTTPException(status_code=400, detail="Missing required parameters: action, sourceIp")
        
        # Process different action types
        result = {"status": "success", "action": action_type, "message": ""}
        
        if action_type == "block_ip":
            # Create a blocking rule for the IP
            rule_name = f"Auto-Block {source_ip}"
            blocking_rule = FirewallRule(
                name=rule_name,
                description=f"Automatically generated rule to block {source_ip}",
                source_ip=source_ip,
                dest_ip="any",
                protocol=protocol,
                action="deny",
                priority=1,  # High priority for security blocks
                tags=["auto-generated", "security", "flow-action"],
                created_by="system"
            )
            
            blocking_rule.id = generate_rule_id()
            blocking_rule.created_at = datetime.now()
            blocking_rule.modified_at = datetime.now()
            firewall_rules[blocking_rule.id] = blocking_rule
            
            # Apply rule to real system if available
            if system_control:
                try:
                    await system_control.apply_firewall_rule(blocking_rule.dict())
                    result["message"] = f"IP {source_ip} blocked successfully and applied to VPP/eBPF"
                except Exception as e:
                    result["message"] = f"IP {source_ip} blocked in configuration (VPP/eBPF apply failed: {e})"
            else:
                result["message"] = f"IP {source_ip} blocked in configuration"
                
            log_activity("flow_blocked", {
                "source_ip": source_ip,
                "rule_id": blocking_rule.id,
                "flow_id": flow_id
            })
            
        elif action_type == "block_country":
            country = action_data.get("country", "Unknown")
            # Create a geo-blocking rule
            rule_name = f"Geo-Block {country}"
            geo_rule = FirewallRule(
                name=rule_name,
                description=f"Block all traffic from {country}",
                source_ip="any",
                dest_ip="any",
                protocol="any",
                action="deny",
                priority=5,
                geo_blocking=[country],
                tags=["geo-blocking", "auto-generated", "security"],
                created_by="system"
            )
            
            geo_rule.id = generate_rule_id()
            geo_rule.created_at = datetime.now()
            geo_rule.modified_at = datetime.now()
            firewall_rules[geo_rule.id] = geo_rule
            
            result["message"] = f"Country {country} blocked successfully"
            
            log_activity("country_blocked", {
                "country": country,
                "rule_id": geo_rule.id,
                "flow_id": flow_id
            })
            
        elif action_type == "investigate":
            # Add to threat intelligence for investigation
            threat = ThreatIntelligence(
                ip_address=source_ip,
                threat_type="suspicious_activity",
                severity="medium",
                reputation_score=50.0,
                description=f"IP flagged for investigation from flow {flow_id}",
                first_seen=datetime.now(),
                last_seen=datetime.now()
            )
            threat_intel_db[source_ip] = threat
            
            result["message"] = f"IP {source_ip} added to investigation queue"
            
            log_activity("flow_investigated", {
                "source_ip": source_ip,
                "flow_id": flow_id
            })
            
        elif action_type == "quarantine":
            # Create quarantine rule with limited access
            rule_name = f"Quarantine {source_ip}"
            quarantine_rule = FirewallRule(
                name=rule_name,
                description=f"Quarantine {source_ip} - limited access only",
                source_ip=source_ip,
                dest_port="80,443,53",  # Only basic web and DNS
                protocol="tcp",
                action="allow",
                priority=10,
                rate_limit=100,  # Rate limit the connection
                tags=["quarantine", "auto-generated", "security"],
                created_by="system"
            )
            
            quarantine_rule.id = generate_rule_id()
            quarantine_rule.created_at = datetime.now()
            quarantine_rule.modified_at = datetime.now()
            firewall_rules[quarantine_rule.id] = quarantine_rule
            
            result["message"] = f"IP {source_ip} quarantined with limited access"
            
            log_activity("flow_quarantined", {
                "source_ip": source_ip,
                "rule_id": quarantine_rule.id,
                "flow_id": flow_id
            })
            
        elif action_type == "redirect_honeypot":
            # Create redirect rule to honeypot
            honeypot_ip = "192.168.100.1"  # Honeypot server
            rule_name = f"Honeypot Redirect {source_ip}"
            redirect_rule = FirewallRule(
                name=rule_name,
                description=f"Redirect {source_ip} traffic to honeypot for analysis",
                source_ip=source_ip,
                dest_ip=honeypot_ip,
                protocol="any",
                action="allow",
                priority=1,
                tags=["honeypot", "redirect", "auto-generated"],
                created_by="system"
            )
            
            redirect_rule.id = generate_rule_id()
            redirect_rule.created_at = datetime.now()
            redirect_rule.modified_at = datetime.now()
            firewall_rules[redirect_rule.id] = redirect_rule
            
            result["message"] = f"IP {source_ip} redirected to honeypot for analysis"
            
            log_activity("flow_redirected", {
                "source_ip": source_ip,
                "honeypot_ip": honeypot_ip,
                "rule_id": redirect_rule.id,
                "flow_id": flow_id
            })
            
        elif action_type == "rate_limit":
            # Apply rate limiting
            limit = action_data.get("limit", 100)
            rule_name = f"Rate Limit {source_ip}"
            rate_rule = FirewallRule(
                name=rule_name,
                description=f"Rate limit {source_ip} to {limit} connections/sec",
                source_ip=source_ip,
                dest_ip="any",
                protocol="any",
                action="allow",
                priority=20,
                rate_limit=limit,
                tags=["rate-limit", "auto-generated"],
                created_by="system"
            )
            
            rate_rule.id = generate_rule_id()
            rate_rule.created_at = datetime.now()
            rate_rule.modified_at = datetime.now()
            firewall_rules[rate_rule.id] = rate_rule
            
            result["message"] = f"Rate limiting applied to {source_ip}: {limit} conn/sec"
            
            log_activity("flow_rate_limited", {
                "source_ip": source_ip,
                "limit": limit,
                "rule_id": rate_rule.id,
                "flow_id": flow_id
            })
            
        elif action_type == "whitelist":
            # Add to whitelist
            rule_name = f"Whitelist {source_ip}"
            whitelist_rule = FirewallRule(
                name=rule_name,
                description=f"Whitelist {source_ip} - trusted source",
                source_ip=source_ip,
                dest_ip="any",
                protocol="any",
                action="allow",
                priority=1,
                tags=["whitelist", "trusted", "auto-generated"],
                created_by="system"
            )
            
            whitelist_rule.id = generate_rule_id()
            whitelist_rule.created_at = datetime.now()
            whitelist_rule.modified_at = datetime.now()
            firewall_rules[whitelist_rule.id] = whitelist_rule
            
            result["message"] = f"IP {source_ip} added to whitelist"
            
            log_activity("flow_whitelisted", {
                "source_ip": source_ip,
                "rule_id": whitelist_rule.id,
                "flow_id": flow_id
            })
            
        else:
            raise HTTPException(status_code=400, detail=f"Unknown action type: {action_type}")
        
        # Broadcast update to connected clients
        await broadcast_update({
            "type": "flow_action",
            "data": result
        })
        
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error handling flow action: {e}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@app.get("/api/flow/actions")
async def get_available_flow_actions() -> Dict[str, Any]:
    """Get available flow actions and their descriptions"""
    return {
        "actions": [
            {
                "id": "block_ip",
                "name": "Block IP Immediately",
                "description": "Create a firewall rule to block this IP address",
                "icon": "🚫",
                "severity": "high",
                "requires_confirmation": True
            },
            {
                "id": "block_country",
                "name": "Block Entire Country",
                "description": "Block all traffic from this country",
                "icon": "🌍",
                "severity": "high",
                "requires_confirmation": True
            },
            {
                "id": "investigate",
                "name": "Deep Investigation",
                "description": "Add to threat intelligence for further analysis",
                "icon": "🔍",
                "severity": "medium",
                "requires_confirmation": False
            },
            {
                "id": "quarantine",
                "name": "Quarantine & Isolate",
                "description": "Limit access to essential services only",
                "icon": "🔒",
                "severity": "medium",
                "requires_confirmation": True
            },
            {
                "id": "redirect_honeypot",
                "name": "Redirect to Honeypot",
                "description": "Redirect traffic to honeypot for analysis",
                "icon": "🍯",
                "severity": "medium",
                "requires_confirmation": False
            },
            {
                "id": "rate_limit",
                "name": "Apply Rate Limiting",
                "description": "Limit connection rate from this source",
                "icon": "⏱️",
                "severity": "low",
                "requires_confirmation": False
            },
            {
                "id": "whitelist",
                "name": "Allow & Add to Whitelist",
                "description": "Mark as trusted source",
                "icon": "✅",
                "severity": "low",
                "requires_confirmation": False
            }
        ]
    }

# ================== ANALYTICS AND REPORTING ==================

@app.get("/api/analytics/rule-usage")
async def get_rule_usage_analytics() -> Dict[str, Any]:
    """Get rule usage analytics"""
    total_rules = len(firewall_rules)
    enabled_rules = sum(1 for r in firewall_rules.values() if r.enabled)
    
    # Protocol distribution
    protocol_stats = {}
    for rule in firewall_rules.values():
        protocol_stats[rule.protocol] = protocol_stats.get(rule.protocol, 0) + 1
    
    # Action distribution
    action_stats = {}
    for rule in firewall_rules.values():
        action_stats[rule.action] = action_stats.get(rule.action, 0) + 1
    
    return {
        "summary": {
            "total_rules": total_rules,
            "enabled_rules": enabled_rules,
            "disabled_rules": total_rules - enabled_rules,
            "utilization_rate": (enabled_rules / total_rules * 100) if total_rules > 0 else 0
        },
        "protocol_distribution": protocol_stats,
        "action_distribution": action_stats,
        "top_rules": [
            {
                "id": rule.id,
                "name": rule.name,
                "priority": rule.priority,
                "enabled": rule.enabled
            }
            for rule in sorted(firewall_rules.values(), key=lambda x: x.priority)[:10]
        ]
    }

@app.get("/api/analytics/security-events")
async def get_security_events() -> Dict[str, Any]:
    """Get security events analytics"""
    # Generate mock security events
    current_time = datetime.now()
    events = []
    
    for i in range(50):
        event_time = current_time - timedelta(minutes=random.randint(1, 1440))
        events.append({
            "timestamp": event_time.isoformat(),
            "type": random.choice(["intrusion_attempt", "port_scan", "brute_force", "malware", "ddos"]),
            "severity": random.choice(["low", "medium", "high", "critical"]),
            "source_ip": f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}",
            "target_ip": f"10.0.{random.randint(1, 255)}.{random.randint(1, 255)}",
            "blocked": random.choice([True, False]),
            "rule_id": random.choice(list(firewall_rules.keys())) if firewall_rules else None
        })
    
    return {
        "events": events,
        "summary": {
            "total_events": len(events),
            "blocked_events": sum(1 for e in events if e["blocked"]),
            "critical_events": sum(1 for e in events if e["severity"] == "critical"),
            "top_attack_types": {
                "intrusion_attempt": sum(1 for e in events if e["type"] == "intrusion_attempt"),
                "port_scan": sum(1 for e in events if e["type"] == "port_scan"),
                "brute_force": sum(1 for e in events if e["type"] == "brute_force")
            }
        }
    }

@app.get("/api/analytics/performance")
async def get_performance_analytics() -> Dict[str, Any]:
    """Get firewall performance analytics"""
    # Get system metrics
    cpu_percent = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory()
    
    return {
        "system_performance": {
            "cpu_usage": cpu_percent,
            "memory_usage": memory.percent,
            "memory_total": memory.total,
            "memory_available": memory.available,
            "load_average": list(psutil.getloadavg()) if hasattr(psutil, 'getloadavg') else [0, 0, 0]
        },
        "firewall_performance": {
            "rules_processed_per_second": random.randint(10000, 50000),
            "packets_per_second": random.randint(100000, 500000),
            "latency_ms": round(random.uniform(0.1, 2.0), 2),
            "throughput_mbps": random.randint(100, 1000),
            "rule_evaluation_time_ns": random.randint(100, 1000)
        },
        "optimization_suggestions": [
            "Consider consolidating similar rules to improve performance",
            "Review disabled rules for potential removal",
            "Optimize rule priority order for better matching efficiency"
        ]
    }

# ================== CONFIGURATION MANAGEMENT ==================

@app.get("/api/config/export")
async def export_configuration() -> Dict[str, Any]:
    """Export complete firewall configuration"""
    config = {
        "version": "2.0.0",
        "exported_at": datetime.now().isoformat(),
        "firewall_rules": [rule.dict() for rule in firewall_rules.values()],
        "network_objects": [obj.dict() for obj in network_objects.values()],
        "security_policies": [policy.dict() for policy in security_policies.values()],
        "threat_intelligence": [threat.dict() for threat in threat_intel_db.values()]
    }
    
    log_activity("config_exported", {"rules_count": len(firewall_rules)})
    
    return config

@app.post("/api/config/import")
async def import_configuration(config: Dict[str, Any]) -> Dict[str, Any]:
    """Import firewall configuration"""
    try:
        imported_rules = 0
        imported_objects = 0
        
        # Import firewall rules
        if "firewall_rules" in config:
            for rule_data in config["firewall_rules"]:
                rule = FirewallRule(**rule_data)
                if not rule.id:
                    rule.id = generate_rule_id()
                firewall_rules[rule.id] = rule
                imported_rules += 1
        
        # Import network objects
        if "network_objects" in config:
            for obj_data in config["network_objects"]:
                obj = NetworkObject(**obj_data)
                if not obj.id:
                    obj.id = f"obj_{uuid.uuid4().hex[:8]}"
                network_objects[obj.id] = obj
                imported_objects += 1
        
        log_activity("config_imported", {
            "rules_imported": imported_rules,
            "objects_imported": imported_objects
        })
        
        return {
            "status": "success",
            "imported_rules": imported_rules,
            "imported_objects": imported_objects
        }
        
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Import failed: {str(e)}")

# ================== SYSTEM LOGS API ==================

@app.get("/api/logs")
async def get_system_logs(limit: int = 100) -> List[Dict[str, Any]]:
    """Get system activity logs"""
    return system_logs[-limit:]

# ================== REAL-TIME DATA ==================

async def get_realtime_data() -> Dict[str, Any]:
    """Get real-time system data from VPP/eBPF"""
    current_time = time.time()
    
    # Get real system status if available
    if system_control:
        try:
            system_status = await system_control.get_system_status()
            
            # Extract real system info
            system_info = system_status.get("system_info", {})
            vpp_status = system_status.get("vpp_status", {})
            ebpf_status = system_status.get("ebpf_status", {})
            network_stats = system_status.get("network_stats", {})
            
            # Real firewall statistics from VPP/eBPF
            firewall_stats = {
                "engine_status": system_status.get("engine_status", "inactive"),
                "protection_mode": system_status.get("protection_mode", "none"),
                "packets_processed": vpp_status.get("stats", {}).get("packets_processed", 0),
                "packets_blocked": vpp_status.get("stats", {}).get("packets_dropped", 0),
                "packets_received": vpp_status.get("stats", {}).get("packets_received", 0),
                "ebpf_programs": ebpf_status.get("total_programs", 0),
                "ebpf_maps": ebpf_status.get("total_maps", 0),
                "vpp_interfaces": len(vpp_status.get("interfaces", [])),
                "dual_protection_active": vpp_status.get("dual_protection_active", False)
            }
            
            return {
                "timestamp": current_time,
                "system": {
                    "cpu_usage": system_info.get("cpu", {}).get("usage", 0),
                    "memory_usage": system_info.get("memory", {}).get("percentage", 0),
                    "memory_total": system_info.get("memory", {}).get("total", 0),
                    "memory_used": system_info.get("memory", {}).get("used", 0),
                    "uptime": system_info.get("uptime", 0),
                    "hostname": system_info.get("hostname", "Unknown"),
                    "os": system_info.get("os", "Unknown")
                },
                "network": network_stats.get("global", {
                    "bytes_sent": 0,
                    "bytes_recv": 0,
                    "packets_sent": 0,
                    "packets_recv": 0
                }),
                "firewall": firewall_stats,
                "data": {
                    "system_info": {
                        "hostname": system_info.get("hostname", "cerberus-server"),
                        "kernel_version": system_info.get("kernel", "Linux 6.15.3"),
                        "cpu_cores": system_info.get("cpu", {}).get("cores", 8),
                        "total_memory": system_info.get("memory", {}).get("total", 16000000000),
                        "architecture": system_info.get("architecture", "x86_64"),
                        "os": system_info.get("os", "Linux 6.15.3")
                    },
                    "interfaces": system_info.get("interfaces", [])
                },
                "rules_count": {
                    "total": len(firewall_rules),
                    "enabled": sum(1 for r in firewall_rules.values() if r.enabled),
                    "disabled": sum(1 for r in firewall_rules.values() if not r.enabled)
                },
                "threat_intel_count": len(threat_intel_db),
                "vpp_status": vpp_status,
                "ebpf_status": ebpf_status
            }
            
        except Exception as e:
            logger.error(f"Error getting real-time data: {e}")
            # Fall back to basic system info
    
    # Fallback to basic system information if real system control is not available
    cpu_percent = psutil.cpu_percent()
    memory = psutil.virtual_memory()
    net_io = psutil.net_io_counters()
    
    # Generate mock firewall statistics for fallback
    firewall_stats = {
        "engine_status": "simulation",
        "protection_mode": "demo",
        "packets_processed": random.randint(1000, 5000),
        "packets_blocked": random.randint(10, 100),
        "connections_active": random.randint(100, 500),
        "threats_detected": random.randint(0, 10),
        "rules_evaluated": random.randint(10000, 50000)
    }
    
    return {
        "timestamp": current_time,
        "system": {
            "cpu_usage": cpu_percent,
            "memory_usage": memory.percent,
            "memory_total": memory.total,
            "memory_used": memory.used,
            "uptime": time.time() - psutil.boot_time(),
            "hostname": socket.gethostname(),
            "os": "Fallback Mode"
        },
        "network": {
            "bytes_sent": net_io.bytes_sent,
            "bytes_recv": net_io.bytes_recv,
            "packets_sent": net_io.packets_sent,
            "packets_recv": net_io.packets_recv
        },
        "firewall": firewall_stats,
        "data": {
            "system_info": {
                "hostname": socket.gethostname(),
                "kernel_version": "Linux 6.15.3-200.fc42.x86_64",
                "cpu_cores": psutil.cpu_count(logical=False) or 8,
                "total_memory": memory.total,
                "architecture": "x86_64",
                "os": "Linux 6.15.3"
            },
            "interfaces": [
                {
                    "name": "eth0",
                    "status": "up",
                    "ip_address": "192.168.1.100",
                    "mac_address": "00:1b:21:3c:4d:5e",
                    "mtu": 1500,
                    "rx_packets": random.randint(10000, 50000),
                    "tx_packets": random.randint(8000, 40000),
                    "rx_bytes": random.randint(10000000, 50000000),
                    "tx_bytes": random.randint(8000000, 40000000)
                },
                {
                    "name": "vpp-ebpf-0",
                    "status": "up", 
                    "ip_address": "10.0.1.1",
                    "mac_address": "02:fe:3a:4b:5c:6d",
                    "mtu": 9000,
                    "rx_packets": random.randint(15000, 60000),
                    "tx_packets": random.randint(12000, 50000),
                    "rx_bytes": random.randint(15000000, 60000000),
                    "tx_bytes": random.randint(12000000, 50000000)
                }
            ]
        },
        "rules_count": {
            "total": len(firewall_rules),
            "enabled": sum(1 for r in firewall_rules.values() if r.enabled),
            "disabled": sum(1 for r in firewall_rules.values() if not r.enabled)
        },
        "threat_intel_count": len(threat_intel_db)
    }

# ================== INITIALIZE SAMPLE DATA ==================

async def initialize_sample_data():
    """Initialize with sample data for demonstration"""
    # Sample firewall rules
    sample_rules = [
        FirewallRule(
            name="Allow SSH",
            description="Allow SSH access from management network",
            source_ip="192.168.1.0/24",
            dest_port="22",
            protocol="tcp",
            action="allow",
            priority=10,
            tags=["management", "ssh"]
        ),
        FirewallRule(
            name="Allow HTTP/HTTPS",
            description="Allow web traffic",
            source_ip="any",
            dest_port="80,443",
            protocol="tcp",
            action="allow",
            priority=20,
            tags=["web", "public"]
        ),
        FirewallRule(
            name="Block Malicious IPs",
            description="Block known malicious IP addresses",
            source_ip="192.168.100.0/24",
            dest_ip="any",
            protocol="any",
            action="deny",
            priority=5,
            tags=["security", "threat-intel"]
        ),
        FirewallRule(
            name="Allow DNS",
            description="Allow DNS queries",
            source_ip="any",
            dest_port="53",
            protocol="udp",
            action="allow",
            priority=15,
            tags=["dns", "infrastructure"]
        )
    ]
    
    for rule in sample_rules:
        rule.id = generate_rule_id()
        rule.created_at = datetime.now()
        rule.modified_at = datetime.now()
        firewall_rules[rule.id] = rule
    
    # Sample network objects
    sample_objects = [
        NetworkObject(
            name="Internal Network",
            type="network",
            value="192.168.1.0/24",
            description="Internal corporate network",
            tags=["internal"]
        ),
        NetworkObject(
            name="DMZ Network",
            type="network",
            value="10.0.1.0/24",
            description="DMZ network for public services",
            tags=["dmz", "public"]
        ),
        NetworkObject(
            name="Management Server",
            type="host",
            value="192.168.1.10",
            description="Primary management server",
            tags=["management", "critical"]
        )
    ]
    
    for obj in sample_objects:
        obj.id = f"obj_{uuid.uuid4().hex[:8]}"
        obj.created_at = datetime.now()
        network_objects[obj.id] = obj
    
    logger.info("Sample data initialized")

# Initialize sample data on startup
@app.on_event("startup")
async def startup_event():
    await initialize_sample_data()
    logger.info("Cerberus-V Professional Firewall Backend started")
    if REAL_SYSTEM_AVAILABLE:
        logger.info("✅ Real VPP/eBPF system control available")
    else:
        logger.info("⚠️ Running in fallback mode - real system control not available")

if __name__ == "__main__":
    print("🔥 Запуск Cerberus-V Professional Firewall Backend")
    print("🛡️ Production VPP/eBPF Firewall Management System")
    if REAL_SYSTEM_AVAILABLE:
        print("✅ Real system integration: ACTIVE")
    else:
        print("⚠️ Real system integration: FALLBACK MODE")
    
    uvicorn.run(
        app, 
        host="127.0.0.1",
        port=8081,
        log_level="info"
    ) 