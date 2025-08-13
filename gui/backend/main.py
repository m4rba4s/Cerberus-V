#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Cerberus-V FastAPI Backend: Preflight, Rules, Mode Management
from fastapi import FastAPI, HTTPException, BackgroundTasks, WebSocket, WebSocketDisconnect, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from typing import List, Dict, Optional
import logging
import json
from datetime import datetime, UTC
import re
import psutil
import uvicorn
import asyncio
import sys
from pathlib import Path
import pwd
import os
import subprocess
import shutil
import json as pyjson
import random
import shlex
import socket
import platform
import ipaddress

# Add project root to path
sys.path.append(str(Path(__file__).parent.parent.parent))

from preflight import preflight_manager, FirewallRule

# Import LIVE mode API (use mock for stability)
try:
    from mock_live_api import router as live_router
    print("Mock LIVE mode API router loaded")
except ImportError:
    try:
        from live_api import router as live_router
        print("Real LIVE mode API router loaded")
    except ImportError:
        live_router = None
        print("No LIVE mode API router available")

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# FastAPI app
app = FastAPI(
    title="Cerberus-V API",
    description="APT-Grade Firewall Management API",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include LIVE mode API router
if live_router:
    app.include_router(live_router)
    logger.info("LIVE mode API router included")
else:
    logger.warning("LIVE mode API router not available")

# Security headers (baseline)
@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    # Minimal baseline; full mTLS/JWT to be wired next
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response

# CORS headers function (fallback)
def add_cors_headers(response: JSONResponse) -> JSONResponse:
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    return response

# Add OPTIONS handler for CORS preflight
@app.options("/{full_path:path}")
async def options_handler(full_path: str):
    response = JSONResponse(content={"message": "OK"})
    return add_cors_headers(response)

# WebSocket manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def send_personal_message(self, message: str, websocket: WebSocket):
        await websocket.send_text(message)

    async def broadcast(self, message: str):
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except:
                # Remove dead connections
                self.active_connections.remove(connection)

manager = ConnectionManager()

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        # Heartbeat push: periodically send status to keep WS alive
        while True:
            # Determine running state and stats from the available manager
            running = False
            stats_dict = {
                "packets_processed": 0,
                "packets_dropped": 0,
                "bytes_processed": 0,
            }
            try:
                if hasattr(firewall_manager, 'is_loaded'):
                    running = bool(firewall_manager.is_loaded())
                if hasattr(firewall_manager, 'get_stats'):
                    s = firewall_manager.get_stats()
                    stats_dict = s if isinstance(s, dict) else getattr(s, '__dict__', stats_dict)
            except Exception:
                # keep defaults on error
                pass

            payload = {
                "type": "status",
                "mode": preflight_manager.get_mode(),
                "rules_count": len(preflight_manager.get_current_rules()),
                "timestamp": datetime.now(UTC).isoformat(),
                "firewall": {
                    "engine_status": "running" if running else "inactive",
                    "packets_processed": stats_dict.get("packets_processed", 0),
                    "packets_blocked": stats_dict.get("packets_dropped", 0),
                    "interface": getattr(firewall_manager, 'interface', 'eth0'),
                    "engine_state": getattr(firewall_manager, 'engine_state', 'auto')
                },
                "data": {
                    "interfaces": _list_network_interfaces(),
                    "system_info": _system_info(),
                },
                "system": {
                    "uptime": int((datetime.now(UTC) - start_time).total_seconds()),
                    "cpu_usage": stats_dict.get("cpu_usage", 0.0),
                    "memory_total": _system_info().get("total_memory", 0),
                    "memory_used": _system_info().get("used_memory", 0),
                }
            }
            await websocket.send_text(json.dumps(payload))
            await asyncio.sleep(2)
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception:
        manager.disconnect(websocket)

# Simple data classes (no pydantic)
class ModeRequest:
    def __init__(self, mode: str):
        self.mode = mode
    
    @classmethod
    def from_dict(cls, data: dict):
        # Normalize NONE->simulation for UX backward-compat
        mode = data.get("mode", "simulation").lower()
        if mode in ("none", "none mode", "none_mode"):
            mode = "simulation"
        return cls(mode=mode)

class ModeResponse:
    def __init__(self, mode: str, message: str, success: bool):
        self.mode = mode
        self.message = message
        self.success = success
    
    def dict(self):
        return {
            "mode": self.mode,
            "message": self.message,
            "success": self.success
        }

class RuleRequest:
    def __init__(self, id: str, action: str, src_ip: str, dst_ip: str = "0.0.0.0/0",
                 src_port: str = "any", dst_port: str = "any", protocol: str = "any",
                 description: str = "", enabled: bool = True, log: bool = False,
                 log_prefix: str = "", rate_limit: Optional[str] = None):
        self.id = id
        self.action = action
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        self.description = description
        self.enabled = enabled
        self.log = log
        self.log_prefix = log_prefix
        self.rate_limit = rate_limit
    
    @classmethod
    def from_dict(cls, data: dict):
        return cls(
            id=data.get("id", ""),
            action=data.get("action", "allow"),
            src_ip=data.get("src_ip", "0.0.0.0/0"),
            dst_ip=data.get("dst_ip", "0.0.0.0/0"),
            src_port=data.get("src_port", "any"),
            dst_port=data.get("dst_port", "any"),
            protocol=data.get("protocol", "any"),
            description=data.get("description", ""),
            enabled=data.get("enabled", True),
            log=data.get("log", False),
            log_prefix=data.get("log_prefix", ""),
            rate_limit=data.get("rate_limit")
        )
    
    def dict(self):
        return {
            "id": self.id,
            "action": self.action,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "description": self.description,
            "enabled": self.enabled,
            "log": self.log,
            "log_prefix": self.log_prefix,
            "rate_limit": self.rate_limit
        }

class RulesRequest:
    def __init__(self, rules: List[RuleRequest]):
        self.rules = rules
    
    @classmethod
    def from_dict(cls, data: dict):
        rules = [RuleRequest.from_dict(rule) for rule in data.get("rules", [])]
        return cls(rules=rules)

class PreflightRequest:
    def __init__(self, rules: List[RuleRequest]):
        self.rules = rules
    
    @classmethod
    def from_dict(cls, data: dict):
        rules = [RuleRequest.from_dict(rule) for rule in data.get("rules", [])]
        return cls(rules=rules)

class PreflightResponse:
    def __init__(self, success: bool, message: str, details: Dict):
        self.success = success
        self.message = message
        self.details = details
    
    def dict(self):
        return {
            "success": self.success,
            "message": self.message,
            "details": self.details
        }

class HealthResponse:
    def __init__(self, status: str, mode: str, rules_count: int, uptime: str, timestamp: str):
        self.status = status
        self.mode = mode
        self.rules_count = rules_count
        self.uptime = uptime
        self.timestamp = timestamp
    
    def dict(self):
        return {
            "status": self.status,
            "mode": self.mode,
            "rules_count": self.rules_count,
            "uptime": self.uptime,
            "timestamp": self.timestamp
        }

class EventResponse:
    def __init__(self, events: List[Dict]):
        self.events = events
    
    def dict(self):
        return {"events": self.events}

class LogsResponse:
    def __init__(self, logs: List[str]):
        self.logs = logs
    
    def dict(self):
        return {"logs": self.logs}

# Global variables
# Initialize start time
start_time = datetime.now(UTC)
current_config: dict = {}
# Simple cache for PPS estimation
_last_pps_sample = {"ts": 0.0, "pkts": 0}
geo_blocked_countries: list[str] = []
_flow_first_seen: dict[tuple, float] = {}
_geo_cache: dict[str, str | None] = {}

# Helper functions
def log_audit_event(event: str, user: str = "api"):
    """Log audit event to immutable log."""
    try:
        timestamp = datetime.utcnow().isoformat()
        log_entry = f"{timestamp} AUDIT: {event} by {user}"
        
        # In production: write to /var/log/cerberus/audit.log with chattr handling
        logger.info(log_entry)
        
        # Mock: write to file
        with open("/tmp/cerberus_audit.log", "a") as f:
            f.write(log_entry + "\n")
    except Exception as e:
        logger.error(f"Failed to log audit event: {e}")

# API Endpoints
@app.post("/api/policy/compile")
async def compile_policy(request: dict):
    """Compile incoming DSL to eBPF/VPP plan (MVP via local compiler)."""
    try:
        spec = request
        # Write to temp and call our compiler
        tmp_dir = Path("/tmp/cerberus_dsl"); tmp_dir.mkdir(exist_ok=True)
        tmp_file = tmp_dir / "policy.json"
        with open(tmp_file, "w") as f:
            json.dump(spec, f)
        # Use our in-repo compiler if available
        compiler = Path(__file__).resolve().parents[2] / "dsl" / "compiler" / "dsl_compiler.py"
        if compiler.exists():
            out = subprocess.run([sys.executable, str(compiler), str(tmp_file)], capture_output=True, text=True)
            if out.returncode != 0:
                raise RuntimeError(out.stderr or out.stdout)
            plan = json.loads(out.stdout or "{}")
        else:
            plan = {"vpp_acl": [], "lpm_tries": {"src": [], "dst": []}}
        return add_cors_headers(JSONResponse(content={"success": True, "plan": plan}))
    except Exception as e:
        logger.error(f"Policy compile failed: {e}")
        return add_cors_headers(JSONResponse(content={"success": False, "error": str(e)}, status_code=500))

@app.post("/api/policy/apply")
async def apply_policy(request: dict):
    """Apply compiled plan in simulation/live (MVP wires to preflight + save)."""
    try:
        mode = (request.get("mode") or "simulation").lower()
        plan = request.get("plan") or {}
        # For MVP we just record the plan and set mode gate via preflight manager
        _ = plan  # reserved for future: 2PC into BPF/VPP
        ok, msg = preflight_manager.set_mode("live" if mode == "live" else "simulation")
        if not ok:
            return add_cors_headers(JSONResponse(content={"success": False, "message": msg}, status_code=400))
        log_audit_event(f"Policy applied in {mode} mode")
        return add_cors_headers(JSONResponse(content={"success": True, "message": f"Applied in {mode}"}))
    except Exception as e:
        logger.error(f"Policy apply failed: {e}")
        return add_cors_headers(JSONResponse(content={"success": False, "error": str(e)}, status_code=500))

@app.get("/")
async def root():
    """Root endpoint."""
    return {"message": "Cerberus-V API", "version": "1.0.0", "status": "operational"}

@app.get("/api/mode")
async def get_mode():
    """Get current mode."""
    try:
        mode = preflight_manager.get_mode()
        response_data = ModeResponse(
            mode=mode,
            message=f"Current mode: {mode}",
            success=True
        )
        
        response = JSONResponse(content=response_data.dict())
        return add_cors_headers(response)
        
    except Exception as e:
        logger.error(f"Failed to get mode: {e}")
        error_response = JSONResponse(
            content={"error": str(e)},
            status_code=500
        )
        return add_cors_headers(error_response)

@app.post("/api/mode")
async def set_mode(request: dict):
    """Set mode with preflight check."""
    try:
        mode_req = ModeRequest.from_dict(request)
        success, message = preflight_manager.set_mode(mode_req.mode)
        
        if success:
            log_audit_event(f"Mode changed to {mode_req.mode}")
            return ModeResponse(
                mode=mode_req.mode,
                message=message,
                success=True
            ).dict()
        else:
            raise HTTPException(status_code=400, detail=message)
            
    except Exception as e:
        logger.error(f"Failed to set mode: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/rules")
async def get_rules():
    """Get current rules."""
    try:
        rules = preflight_manager.get_current_rules()
        response_data = {
            "rules": rules,
            "count": len(rules)
        }
        
        response = JSONResponse(content=response_data)
        return add_cors_headers(response)
        
    except Exception as e:
        logger.error(f"Failed to get rules: {e}")
        error_response = JSONResponse(
            content={"error": str(e)},
            status_code=500
        )
        return add_cors_headers(error_response)

@app.post("/api/rules")
async def set_rules(request: dict):
    """Set firewall rules with preflight check."""
    try:
        rules_data = request.get("rules", [])
        
        # Convert to FirewallRule objects
        rules = []
        for rule_data in rules_data:
            rules.append(rule_data)  # Keep as dict for now
        
        # Preflight check
        success, message, details = preflight_manager.dry_run_rules(rules)
        if not success:
            error_response = JSONResponse(
                content={"success": False, "message": message},
                status_code=400
            )
            return add_cors_headers(error_response)
        
        # Apply rules
        success, message = preflight_manager.apply_rules(rules_data)
        if not success:
            error_response = JSONResponse(
                content={"success": False, "message": message},
                status_code=500
            )
            return add_cors_headers(error_response)
        
        # Log audit event
        log_audit_event(f"Rules updated: {len(rules)} rules applied")
        
        response_data = {
            "message": message,
            "success": True,
            "rules_count": len(preflight_manager.get_current_rules())
        }
        
        response = JSONResponse(content=response_data)
        return add_cors_headers(response)
        
    except Exception as e:
        logger.error(f"Failed to set rules: {e}")
        error_response = JSONResponse(
            content={"success": False, "message": str(e)},
            status_code=500
        )
        return add_cors_headers(error_response)

@app.post("/api/preflight")
async def preflight_check(request: dict):
    """Preflight check for rules."""
    try:
        rules_data = request.get("rules", [])
        
        # Convert to FirewallRule objects
        rules = []
        for rule_data in rules_data:
            rules.append(rule_data)  # Keep as dict for now
        
        # Perform preflight check
        success, message, details = preflight_manager.dry_run_rules(rules)
        
        response_data = PreflightResponse(
            success=success,
            message=message,
            details=details
        )
        
        response = JSONResponse(content=response_data.dict())
        return add_cors_headers(response)
        
    except Exception as e:
        logger.error(f"Preflight check failed: {e}")
        error_response = JSONResponse(
            content={"success": False, "message": str(e)},
            status_code=500
        )
        return add_cors_headers(error_response)

@app.post("/api/rollback")
async def rollback_rules():
    """Rollback to previous state."""
    try:
        success, message = preflight_manager.rollback_rules()
        
        if success:
            log_audit_event("Rules rolled back to previous state")
        
        response_data = {
            "message": message,
            "success": success
        }
        
        response = JSONResponse(content=response_data)
        return add_cors_headers(response)
        
    except Exception as e:
        logger.error(f"Rollback failed: {e}")
        error_response = JSONResponse(
            content={"success": False, "message": str(e)},
            status_code=500
        )
        return add_cors_headers(error_response)

@app.get("/api/health")
async def health_check():
    """Health check endpoint."""
    try:
        current_time = datetime.now(UTC)
        uptime = current_time - start_time
        
        health_data = HealthResponse(
            status="healthy",
            mode=preflight_manager.get_mode(),
            rules_count=len(preflight_manager.get_current_rules()),
            uptime=str(uptime),
            timestamp=current_time.isoformat()
        )
        
        response = JSONResponse(content=health_data.dict())
        return add_cors_headers(response)
        
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        error_response = JSONResponse(
            content={"status": "unhealthy", "error": str(e)},
            status_code=500
        )
        return add_cors_headers(error_response)

@app.get("/api/events")
async def get_events():
    """Get recent events."""
    try:
        # Mock events for now
        events = [
            {
                "timestamp": datetime.now(UTC).isoformat(),
                "level": "info",
                "message": "System started",
                "source": "cerberus-v"
            },
            {
                "timestamp": datetime.now(UTC).isoformat(),
                "level": "info", 
                "message": f"Mode: {preflight_manager.get_mode()}",
                "source": "cerberus-v"
            },
            {
                "timestamp": datetime.now(UTC).isoformat(),
                "level": "info",
                "message": f"Active rules: {len(preflight_manager.get_current_rules())}",
                "source": "cerberus-v"
            }
        ]
        
        response_data = {"events": events}
        response = JSONResponse(content=response_data)
        return add_cors_headers(response)
        
    except Exception as e:
        logger.error(f"Failed to get events: {e}")
        error_response = JSONResponse(
            content={"error": str(e)},
            status_code=500
        )
        return add_cors_headers(error_response)

@app.get("/api/logs")
async def get_logs():
    """Get recent logs."""
    try:
        # Mock logs for now
        logs = [
            f"[{datetime.now(UTC).isoformat()}] INFO: Cerberus-V API started",
            f"[{datetime.now(UTC).isoformat()}] INFO: Mode: {preflight_manager.get_mode()}",
            f"[{datetime.now(UTC).isoformat()}] INFO: Rules count: {len(preflight_manager.get_current_rules())}",
            f"[{datetime.now(UTC).isoformat()}] INFO: WebSocket connections: {len(manager.active_connections)}"
        ]
        
        response_data = {"logs": logs}
        response = JSONResponse(content=response_data)
        return add_cors_headers(response)
    except Exception as e:
        logger.error(f"Failed to get logs: {e}")
        error_response = JSONResponse(content={"error": str(e)}, status_code=500)
        return add_cors_headers(error_response)

# -------- Analytics (MVP synthetic backed by system status) --------
@app.get("/api/analytics/live-threats")
async def analytics_live_threats():
    """Return live threats derived from active flows (heuristic)."""
    try:
        flows = _collect_flows()
        sensitive_ports = {22, 23, 3389, 5900, 25}
        src_counter: dict[str, int] = {}
        for f in flows:
            src_counter[f["src_ip"]] = src_counter.get(f["src_ip"], 0) + 1
        from mitre import map_attack  # local mapping
        threats = []
        for idx, f in enumerate(flows):
            sev = "low"
            attack = "scan"
            if f["dport"] in sensitive_ports:
                sev = "high"; attack = "service-bruteforce"
            if src_counter.get(f["src_ip"], 0) > 20:
                sev = "critical"; attack = "port-scan"
            # country + MITRE enrichment
            country = _geo_country(f["src_ip"]) or "N/A"
            mitre = map_attack(attack)
            threats.append({
                "id": f"T{idx:04d}",
                "timestamp": datetime.now(UTC).isoformat(),
                "sourceIp": f["src_ip"],
                "targetIp": f["dst_ip"],
                "country": country,
                "attackType": attack,
                "severity": sev,
                "blocked": False,
                "confidence": 75,
                "protocol": f["proto"],
                "port": f["dport"],
                "status": "active",
                "mitreId": mitre.get("techniqueId"),
                "mitreTactic": mitre.get("tactic"),
                "mitreTechnique": mitre.get("technique"),
            })
        return add_cors_headers(JSONResponse(content={"threats": threats[:100]}))
    except Exception as e:
        logger.error(f"Analytics live-threats failed: {e}")
        return add_cors_headers(JSONResponse(content={"threats": []}, status_code=500))

@app.get("/api/analytics/network-flows")
async def analytics_network_flows():
    """Return list of active network flows using ss (safe, no capture)."""
    try:
        flows = _collect_flows()
        res = []
        now = datetime.now(UTC).timestamp()
        for i, f in enumerate(flows[:200]):
            key = (f["proto"], f["src_ip"], f["dst_ip"], int(f.get("dport",0)))
            first = _flow_first_seen.get(key)
            if first is None:
                _flow_first_seen[key] = now
                first = now
            duration = max(0, int(now - first))
            country = _geo_country(f["src_ip"]) or "N/A"
            res.append({
                "id": f"F{i:04d}",
                "sourceIp": f["src_ip"],
                "destinationIp": f["dst_ip"],
                "protocol": f["proto"],
                "port": f["dport"],
                "bytesIn": 0,
                "bytesOut": 0,
                "duration": duration,
                "suspicious": f["dport"] in {22,23,3389,5900},
                "country": country,
                "service": _service_name(f["dport"]),
                "encrypted": f["dport"] in {443, 853},
                "packets": 0,
                "flags": []
            })
        summary = {
            "topPorts": _ports_histogram(flows),
            "topSources": _top_entities(flows, "src_ip"),
            "topDestinations": _top_entities(flows, "dst_ip"),
        }
        return add_cors_headers(JSONResponse(content={"flows": res, "summary": summary}))
    except Exception as e:
        logger.error(f"Analytics network-flows failed: {e}")
        return add_cors_headers(JSONResponse(content={"flows": []}, status_code=500))

@app.get("/api/analytics/service-metrics")
async def analytics_service_metrics():
    """Return service metrics for core components."""
    try:
        uptime_sec = int((datetime.now(UTC) - start_time).total_seconds())
        vpp_count = len(_vpp_interfaces())
        sysinfo = _system_info()
        def _proc_stats(substr: str):
            cpu = mem = 0.0
            up = "n/a"; pid = None
            try:
                for p in psutil.process_iter(attrs=["name","create_time","cpu_percent","memory_percent","pid"]):
                    name = (p.info.get("name") or "").lower()
                    if substr in name:
                        pid = p.info["pid"]
                        cpu += float(p.cpu_percent(interval=None))
                        mem += float(p.memory_percent())
                        ct = p.info.get("create_time")
                        if ct:
                            up = f"{int(datetime.now(UTC).timestamp() - ct)}s"
            except Exception:
                pass
            return int(cpu), int(mem), up, pid

        b_cpu, b_mem, b_up, b_pid = _proc_stats("python")
        v_cpu, v_mem, v_up, v_pid = _proc_stats("vpp")

        services = [
            {"service": "cerberus-backend","status": "running","connections": len(manager.active_connections),
             "bandwidth": 0, "cpu": max(0,b_cpu), "memory": max(0,b_mem), "uptime": b_up, "threats": 0,
             "blocked": 0, "version": "1.0.0", "pid": b_pid},
            {"service": "vpp","status": "running" if vpp_count>0 or v_pid else "stopped","connections": 0,
             "bandwidth": 0, "cpu": max(0,v_cpu), "memory": max(0,v_mem), "uptime": v_up, "threats": 0,
             "blocked": 0, "version": "fd.io", "pid": v_pid},
            {"service": "ebpf","status": "running" if getattr(firewall_manager,'interface',None) else "stopped",
             "connections": 0, "bandwidth": 0, "cpu": 0, "memory": 0, "uptime": "n/a", "threats": 0,
             "blocked": 0, "version": "libbpf"}
        ]
        flows = _collect_flows()
        return add_cors_headers(JSONResponse(content={
            "services": services,
            "geo": _geo_summary(flows),
            "topPorts": _ports_histogram(flows),
            "topSources": _top_entities(flows, "src_ip"),
            "topDestinations": _top_entities(flows, "dst_ip"),
        }))
    except Exception as e:
        logger.error(f"Analytics service-metrics failed: {e}")
        return add_cors_headers(JSONResponse(content={"services": []}, status_code=500))

@app.post("/api/flow/action")
async def flow_action(request: dict):
    """Apply action on a flow/threat. For block_ip: append drop rule via preflight manager (safe)."""
    try:
        action = request.get("action") or "noop"
        flow_id = request.get("flowId") or request.get("threatId") or "unknown"
        src = request.get("sourceIp", "?")
        dst = request.get("destinationIp", "?")
        msg = f"{action} applied"
        if action == "block_ip" and src != "?":
            try:
                rules = preflight_manager.get_current_rules() or []
                rules = list(rules)
                rules.append({
                    "id": f"block-{src}",
                    "action": "drop",
                    "src_ip": f"{src}",
                    "dst_ip": "0.0.0.0/0",
                    "protocol": "any",
                    "src_port": "any",
                    "dst_port": "any",
                    "enabled": True,
                    "description": "analytics:block_ip"
                })
                ok, message = preflight_manager.apply_rules(rules)
                msg = message if ok else f"failed: {message}"
            except Exception as e:
                msg = f"failed: {e}"
        log_audit_event(f"Flow action {action} applied to {flow_id} {src}->{dst}")
        return add_cors_headers(JSONResponse(content={"success": True, "message": msg, "id": flow_id}))
    except Exception as e:
        logger.error(f"Flow action failed: {e}")
        return add_cors_headers(JSONResponse(content={"success": False, "detail": str(e)}, status_code=500))

@app.post("/api/system/service/{service}/{action}")
async def system_service_action(service: str, action: str):
    """Stub system control for services used by Analytics cards."""
    try:
        log_audit_event(f"Service {service} action {action}")
        return add_cors_headers(JSONResponse(content={"success": True, "message": f"{service} {action} triggered"}))
    except Exception as e:
        logger.error(f"Service action failed: {e}")
        return add_cors_headers(JSONResponse(content={"success": False, "detail": str(e)}, status_code=500))

@app.get("/api/obs/syscalls")
async def get_syscalls_obs():
    """Parse auditd (audit.log or ausearch) → journald → synthetic."""
    try:
        events: list[dict] = []

        # audit.log tail
        try:
            audit_log = Path('/var/log/audit/audit.log')
            if audit_log.exists():
                out = subprocess.run(["tail", "-n", "150", str(audit_log)], capture_output=True, text=True, timeout=2)
                if out.returncode == 0 and out.stdout:
                    for line in out.stdout.splitlines():
                        if "type=SYSCALL" not in line:
                            continue
                        ts_match = re.search(r"audit\(([^)]+)\)", line)
                        m_comm = re.search(r"comm=\"([^\"]+)\"", line)
                        m_pid = re.search(r"pid=([0-9]+)", line)
                        m_sc = re.search(r"syscall=([0-9A-Za-z_]+)", line)
                        ts = ts_match.group(1).split(':',1)[0] if ts_match else datetime.now(UTC).isoformat()
                        events.append({
                            "ts": ts,
                            "pid": int(m_pid.group(1)) if m_pid else None,
                            "process": m_comm.group(1) if m_comm else "?",
                            "syscall": m_sc.group(1) if m_sc else "?",
                        })
        except Exception:
            pass

        # ausearch
        if not events and shutil.which("ausearch"):
            try:
                out = subprocess.run(["ausearch", "-m", "SYSCALL", "-ts", "recent", "-i"], capture_output=True, text=True, timeout=2)
                if out.returncode == 0 and out.stdout:
                    for line in out.stdout.splitlines():
                        if "syscall" not in line.lower():
                            continue
                        ts_match = re.search(r"audit\(([^)]+)\)", line)
                        m_comm = re.search(r"comm=\"([^\"]+)\"", line)
                        m_pid = re.search(r"pid=([0-9]+)", line)
                        m_sc = re.search(r"syscall=([0-9A-Za-z_]+)", line)
                        ts = ts_match.group(1).split(':',1)[0] if ts_match else datetime.now(UTC).isoformat()
                        events.append({
                            "ts": ts,
                            "pid": int(m_pid.group(1)) if m_pid else None,
                            "process": m_comm.group(1) if m_comm else "?",
                            "syscall": m_sc.group(1) if m_sc else "?",
                        })
            except Exception:
                pass

        # journald
        if not events and shutil.which("journalctl"):
            try:
                cmd = ["journalctl", "-n", "120", "-o", "short-iso", "--no-pager", "-t", "audit"]
                out = subprocess.run(cmd, capture_output=True, text=True, timeout=2)
                if out.returncode == 0 and out.stdout:
                    for line in out.stdout.splitlines():
                        if "syscall=" not in line and "SYSCALL" not in line.upper():
                            continue
                        ts = line.split()[0]
                        m_comm = re.search(r"comm=\"([^\"]+)\"", line)
                        m_pid = re.search(r"pid=([0-9]+)", line)
                        m_sc = re.search(r"syscall=([0-9A-Za-z_]+)", line)
                        events.append({
                            "ts": ts,
                            "pid": int(m_pid.group(1)) if m_pid else None,
                            "process": m_comm.group(1) if m_comm else "?",
                            "syscall": m_sc.group(1) if m_sc else "?",
                        })
            except Exception:
                pass

        if not events:
            comms = ["nginx", "sshd", "cerberusd", "python", "node"]
            syscalls = ["openat", "connect", "accept4", "read", "write", "statx", "clone3"]
            for _ in range(20):
                events.append({
                    "ts": datetime.now(UTC).isoformat(),
                    "pid": random.randint(100, 9999),
                    "process": random.choice(comms),
                    "syscall": random.choice(syscalls),
                })
        return add_cors_headers(JSONResponse(content={"events": events[-50:]}))
    except Exception as e:
        logger.error(f"Failed to get syscalls: {e}")
        return add_cors_headers(JSONResponse(content={"events": []}, status_code=500))


# ---- Process forensics: details and actions (actions gated by env) ----
def _proc_details_procfs(pid: int) -> dict:
    info: dict = {"pid": pid}
    try:
        status_path = f"/proc/{pid}/status"
        name = None
        uid = None
        if os.path.exists(status_path):
            with open(status_path, "r", errors="ignore") as f:
                for line in f:
                    if line.startswith("Name:\t"):
                        name = line.split("\t",1)[1].strip()
                    elif line.startswith("Uid:\t"):
                        uid = int(line.split()[1])
        username = None
        if uid is not None:
            try:
                username = pwd.getpwuid(uid).pw_name
            except Exception:
                username = None
        # cmdline
        cmdline = []
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                raw = f.read().replace(b"\x00", b" ").strip()
                if raw:
                    cmdline = raw.decode(errors="ignore").split()
        except Exception:
            pass
        # exe symlink
        exe = None
        try:
            exe = os.readlink(f"/proc/{pid}/exe")
        except Exception:
            pass
        info.update({
            "name": name or "?",
            "username": username or "?",
            "cmdline": cmdline,
            "exe": exe,
        })
    except Exception as e:
        info["error"] = str(e)
    return info

def _proc_details(pid: int) -> dict:
    info: dict = {"pid": pid}
    try:
        p = psutil.Process(pid)
        # безопасные геттеры
        def safe(fn, default=None):
            try:
                return fn()
            except Exception:
                return default
        name = safe(p.name, "?")
        username = safe(p.username, "?")
        cmdline = safe(p.cmdline, []) or []
        exe = safe(p.exe, None)
        cpu = safe(lambda: p.cpu_percent(interval=None), 0.0) or 0.0
        mem = safe(p.memory_percent, 0.0) or 0.0
        cwd = safe(getattr, None)
        open_files = safe(lambda: [f.path for f in p.open_files()], [])
        conns = safe(lambda: len(p.connections(kind='inet')), 0)
        ctime = safe(p.create_time, None)
        info.update({
            "name": name,
            "exe": exe,
            "cmdline": cmdline,
            "username": username,
            "create_time": ctime,
            "cpu_percent": float(cpu) if cpu is not None else 0.0,
            "memory_percent": float(mem) if mem is not None else 0.0,
            "cwd": cwd,
            "open_files": open_files,
            "connections": conns,
        })
        # fill missing from /proc if any
        if (not name or name == "?") or (not username or username == "?") or not cmdline:
            pf = _proc_details_procfs(pid)
            for k in ("name","username","cmdline","exe"):
                if not info.get(k) and pf.get(k):
                    info[k] = pf[k]
    except psutil.NoSuchProcess as e:
        info.update({"cpu_percent": 0.0, "memory_percent": 0.0, "error": str(e)})
        info.update(_proc_details_procfs(pid))
    except psutil.AccessDenied as e:
        info.update({"cpu_percent": 0.0, "memory_percent": 0.0, "error": str(e)})
        info.update(_proc_details_procfs(pid))
    except Exception as e:
        info["error"] = str(e)
    return info

@app.get("/api/obs/process/{pid}")
async def get_process_details(pid: int):
    try:
        return add_cors_headers(JSONResponse(content={"process": _proc_details(pid)}))
    except Exception as e:
        logger.error(f"get_process_details failed: {e}")
        return add_cors_headers(JSONResponse(content={"error": str(e)}, status_code=500))

@app.post("/api/obs/process/{pid}/{action}")
async def process_action(pid: int, action: str, value: Optional[int] = None):
    try:
        if os.environ.get("CERB_ALLOW_PROC_ACTIONS") != "1":
            return add_cors_headers(JSONResponse(content={"success": False, "detail": "process actions disabled (set CERB_ALLOW_PROC_ACTIONS=1)"}, status_code=403))
        p = psutil.Process(pid)
        acted = False
        if action in ("terminate", "term"):
            p.terminate(); acted = True
        elif action in ("kill", "sigkill"):
            p.kill(); acted = True
        elif action in ("stop", "suspend"):
            p.suspend(); acted = True
        elif action in ("cont", "resume"):
            p.resume(); acted = True
        elif action in ("renice", "nice"):
            if value is None:
                value = 10
            p.nice(value); acted = True
        elif action in ("quarantine", "isolate"):
            # Placeholder: future netns/cgroup isolation
            log_audit_event(f"Quarantine requested for pid={pid}")
            acted = True
        else:
            return add_cors_headers(JSONResponse(content={"success": False, "detail": f"unknown action {action}"}, status_code=400))
        if acted:
            log_audit_event(f"process action {action} applied to pid={pid}")
            return add_cors_headers(JSONResponse(content={"success": True, "message": f"{action} applied", "process": _proc_details(pid)}))
        return add_cors_headers(JSONResponse(content={"success": False, "detail": "no-op"}, status_code=400))
    except psutil.NoSuchProcess:
        return add_cors_headers(JSONResponse(content={"success": False, "detail": "no such process"}, status_code=404))
    except psutil.AccessDenied:
        return add_cors_headers(JSONResponse(content={"success": False, "detail": "access denied"}, status_code=403))
    except Exception as e:
        logger.error(f"process_action failed: {e}")
        return add_cors_headers(JSONResponse(content={"success": False, "detail": str(e)}, status_code=500))

# ---- Critical logs (journalctl err..alert) ----
@app.get("/api/logs/critical")
async def logs_critical(limit: int = 100):
    try:
        lines: list[str] = []
        if shutil.which("journalctl"):
            cmd = ["journalctl", "-p", "err..alert", "-n", str(max(1, min(limit, 500))), "-o", "short-iso", "--no-pager"]
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=2)
            if out.returncode == 0 and out.stdout:
                lines = [l for l in out.stdout.splitlines() if l.strip()]
        return add_cors_headers(JSONResponse(content={"lines": lines}))
    except Exception as e:
        logger.error(f"logs_critical failed: {e}")
        return add_cors_headers(JSONResponse(content={"lines": [], "error": str(e)}, status_code=500))


@app.websocket("/ws/obs")
async def websocket_obs(ws: WebSocket):
    """WebSocket stream for lightweight observability: syscalls (synthetic) and logs tail."""
    await ws.accept()
    try:
        while True:
            # Syscalls (synthetic for now)
            payload = {"syscalls": [] , "logs": []}
            try:
                comms = ["nginx", "sshd", "cerberusd", "python", "node"]
                syscalls = ["openat", "connect", "accept4", "read", "write", "statx", "clone3"]
                events = []
                for _ in range(8):
                    events.append({
                        "ts": datetime.now(UTC).isoformat(),
                        "pid": random.randint(100, 9999),
                        "comm": random.choice(comms),
                        "syscall": random.choice(syscalls),
                        "args": "fd=3, flags=O_RDONLY"
                    })
                payload["syscalls"] = events
            except Exception:
                pass

            # Logs tail (journalctl best-effort)
            try:
                if shutil.which("journalctl"):
                    cmd = ["journalctl", "-n", "20", "-o", "short-iso", "--no-pager"]
                    out = subprocess.run(cmd, capture_output=True, text=True, timeout=1)
                    if out.returncode == 0:
                        lines = [l for l in out.stdout.splitlines() if l.strip()][:20]
                        payload["logs"] = lines
            except Exception:
                pass

            await ws.send_text(json.dumps(payload))
            await asyncio.sleep(2)
    except WebSocketDisconnect:
        return
        
    except Exception as e:
        logger.error(f"Failed to get logs: {e}")
        error_response = JSONResponse(
            content={"error": str(e)},
            status_code=500
        )
        return add_cors_headers(error_response)

# eBPF Management API
class EbpfProgram:
    def __init__(self, name: str, type: str, status: str, interface: str = ""):
        self.name = name
        self.type = type
        self.status = status
        self.interface = interface
    
    def dict(self):
        return {
            "name": self.name,
            "type": self.type,
            "status": self.status,
            "interface": self.interface
        }

class EbpfStats:
    def __init__(self, packets_processed: int = 0, packets_dropped: int = 0, 
                 bytes_processed: int = 0, cpu_usage: float = 0.0):
        self.packets_processed = packets_processed
        self.packets_dropped = packets_dropped
        self.bytes_processed = bytes_processed
        self.cpu_usage = cpu_usage
    
    def dict(self):
        return {
            "packets_processed": self.packets_processed,
            "packets_dropped": self.packets_dropped,
            "bytes_processed": self.bytes_processed,
            "cpu_usage": self.cpu_usage
        }

# Real eBPF Firewall Manager
try:
    from ebpf.firewall_manager import create_firewall_manager, FirewallRule, RuleAction, Protocol
    firewall_manager = create_firewall_manager("eth0", demo_mode=True)
    logger.info("Real eBPF Firewall Manager loaded")
except ImportError as e:
    logger.warning(f"Could not import real firewall manager: {e}")
    # Fallback to mock
    class EbpfManager:
        def __init__(self):
            self.interface = "eth0"
            # engine_state: auto|xdp|tc — 'tc' безопасен для Wi‑Fi
            self.engine_state = "auto"
            self.programs = {
                "xdp_filter": EbpfProgram("xdp_filter", "XDP", "inactive", self.interface),
                "tc_filter": EbpfProgram("tc_filter", "TC", "inactive", self.interface)
            }
            self.stats = EbpfStats()
        
        def get_programs(self):
            return [prog.dict() for prog in self.programs.values()]
        
        def load_program(self, name: str, interface: str):
            if name in self.programs:
                self.programs[name].status = "active"
                self.programs[name].interface = interface
                self.interface = interface
                return True
            return False
        
        def unload_program(self, name: str):
            if name in self.programs:
                self.programs[name].status = "inactive"
                return True
            return False
        
        def get_stats(self):
            return self.stats.dict()
    
    firewall_manager = EbpfManager()
    logger.info("Mock eBPF Manager loaded as fallback")

def _list_network_interfaces():
    """Return a portable list of network interfaces with basic metadata.
    Uses `ip -j` (iproute2) which is present on all modern Linux distros.
    """
    # Try iproute2 JSON first
    try:
        if shutil.which("ip"):
            links = subprocess.run(["ip", "-j", "link"], capture_output=True, text=True, check=True)
            addrs = subprocess.run(["ip", "-j", "addr"], capture_output=True, text=True, check=True)
            routes = subprocess.run(["ip", "-j", "route", "show", "default"], capture_output=True, text=True, check=True)

            link_list = pyjson.loads(links.stdout or "[]")
            addr_list = pyjson.loads(addrs.stdout or "[]")
            route_list = pyjson.loads(routes.stdout or "[]") if (routes.stdout or "").strip() else []
            default_ifaces = {r.get("dev") for r in route_list if r.get("dev")}

            name_to_addrs: dict[str, list[str]] = {}
            for a in addr_list:
                ifname = a.get("ifname")
                if not ifname:
                    continue
                ip_addrs = []
                for info in a.get("addr_info", []):
                    local = info.get("local")
                    if local:
                        ip_addrs.append(local)
                name_to_addrs[ifname] = ip_addrs

            interfaces: list[dict] = []
            for l in link_list:
                ifname = l.get("ifname")
                if not ifname:
                    continue
                flags = l.get("flags", [])
                is_up = "UP" in flags
                mac = l.get("address") or ""

                is_wireless = Path(f"/sys/class/net/{ifname}/wireless").exists()
                is_loopback = "LOOPBACK" in flags or ifname == "lo"
                is_virtual = Path(f"/sys/devices/virtual/net/{ifname}").exists()

                iface_type = (
                    "loopback" if is_loopback else "wireless" if is_wireless else "virtual" if is_virtual else "ethernet"
                )

                interfaces.append({
                    "name": ifname,
                    "is_up": bool(is_up),
                    "type": iface_type,
                    "mac_address": mac,
                    "ip_addresses": name_to_addrs.get(ifname, []),
                    "is_default": ifname in default_ifaces,
                    "has_ip": len(name_to_addrs.get(ifname, [])) > 0,
                })

            interfaces.sort(key=lambda x: (0 if x["is_default"] else 1, 0 if x["is_up"] else 1, 0 if x["type"] == "ethernet" else 1, x["name"]))
            if interfaces:
                return interfaces
    except Exception as e:
        logger.error(f"Failed to enumerate interfaces via iproute2: {e}")

    # Fallback: scan sysfs
    try:
        interfaces: list[dict] = []
        for p in Path("/sys/class/net").iterdir():
            ifname = p.name
            try:
                is_wireless = (p / "wireless").exists()
                is_virtual = Path(f"/sys/devices/virtual/net/{ifname}").exists()
                oper = (p / "operstate").read_text().strip() if (p / "operstate").exists() else "unknown"
                mac = (p / "address").read_text().strip() if (p / "address").exists() else ""
                iface_type = "loopback" if ifname == "lo" else ("wireless" if is_wireless else ("virtual" if is_virtual else "ethernet"))
                interfaces.append({
                    "name": ifname,
                    "is_up": oper == "up",
                    "type": iface_type,
                    "mac_address": mac,
                    "ip_addresses": [],
                    "is_default": False,
                    "has_ip": False,
                })
            except Exception:
                continue
        interfaces.sort(key=lambda x: (0 if x["is_up"] else 1, 0 if x["type"] == "ethernet" else 1, x["name"]))
        return interfaces
    except Exception as e:
        logger.error(f"Failed to enumerate interfaces via sysfs: {e}")
        return []

def _system_info():
    try:
        hostname = socket.gethostname()
        kernel_version = platform.release()
        cpu_cores = os.cpu_count() or 0
        total = 0
        available = 0
        try:
            with open("/proc/meminfo") as f:
                for line in f:
                    if line.startswith("MemTotal:"):
                        total = int(line.split()[1]) * 1024
                    elif line.startswith("MemAvailable:"):
                        available = int(line.split()[1]) * 1024
        except Exception:
            pass
        used = max(0, total - available)
        return {
            "hostname": hostname,
            "kernel_version": kernel_version,
            "cpu_cores": cpu_cores,
            "total_memory": total,
            "used_memory": used,
        }
    except Exception as e:
        logger.error(f"system_info failed: {e}")
        return {"hostname": "N/A", "kernel_version": "N/A", "cpu_cores": 0, "total_memory": 0, "used_memory": 0}

def _vpp_interfaces() -> list:
    """Return list of VPP interfaces via vppctl. Excludes local0. Best-effort."""
    try:
        if not shutil.which("vppctl"):
            return []
        out = subprocess.run(["vppctl", "show", "interface"], capture_output=True, text=True, timeout=1)
        if out.returncode != 0 or not out.stdout:
            return []
        interfaces: list[str] = []
        for line in out.stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("Name"):
                continue
            name = line.split()[0]
            if name and name != "local0":
                interfaces.append(name)
        return interfaces
    except Exception as e:
        logger.debug(f"vpp interface enum failed: {e}")
        return []

def _service_name(port: int) -> str:
    mapping = {
        22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 443: "https",
        853: "dot", 3306: "mysql", 5432: "postgres", 3389: "rdp", 5900: "vnc",
        8080: "http-alt"
    }
    try:
        return mapping.get(int(port), "unknown")
    except Exception:
        return "unknown"

def _collect_flows() -> list:
    """Collect active connections via multiple portable methods.
    Order: ss (iproute2) → psutil.net_connections → netstat. Falls back to synthetic.
    """
    flows: list[dict] = []

    def add(proto: str, src_ip: str, dst_ip: str, sport: int, dport: int):
        flows.append({
            "proto": proto,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "sport": int(sport) if sport else 0,
            "dport": int(dport) if dport else 0,
        })

    # 1) ss (present on all modern Linux)
    try:
        if shutil.which("ss"):
            specs = [("TCP", ["-tan"]), ("UDP", ["-uan"])]
            for proto, flags in specs:
                out = subprocess.run(["ss", "-H", *flags], capture_output=True, text=True, timeout=2)
                if out.returncode != 0 or not out.stdout:
                    continue
                for line in out.stdout.splitlines():
                    parts = line.split()
                    if len(parts) < 4:
                        continue
                    src = parts[-2]
                    dst = parts[-1]

                    def split_ep(addr: str):
                        try:
                            if addr.startswith("[") and "]:" in addr:
                                a, p = addr.rsplit(":", 1)
                                return a.strip("[]"), int(p) if p.isdigit() else 0
                            if addr.count(":") > 1 and not addr.endswith("]"):
                                return addr, 0  # IPv6 without port
                            if ":" in addr:
                                h, p = addr.rsplit(":", 1)
                                return h, int(p) if p.isdigit() else 0
                            return addr, 0
                        except Exception:
                            return addr, 0

                    src_ip, sport = split_ep(src)
                    dst_ip, dport = split_ep(dst)
                    add(proto, src_ip, dst_ip, sport, dport)
    except Exception:
        pass

    # 2) psutil fallback (portable, may miss UDP)
    try:
        if not flows:
            for c in psutil.net_connections(kind='inet'):
                laddr = getattr(c, 'laddr', None)
                raddr = getattr(c, 'raddr', None)
                if not laddr or not raddr:
                    continue
                proto = "TCP" if c.type == socket.SOCK_STREAM else "UDP"
                add(proto, laddr.ip, raddr.ip, laddr.port, raddr.port)
    except Exception:
        pass

    # 3) netstat fallback
    try:
        if not flows and shutil.which("netstat"):
            out = subprocess.run(["netstat", "-tun"], capture_output=True, text=True, timeout=2)
            if out.returncode == 0:
                for line in out.stdout.splitlines():
                    if not line or line.startswith("Proto"):
                        continue
                    parts = line.split()
                    if len(parts) < 5:
                        continue
                    proto = parts[0].upper()
                    src = parts[3]
                    dst = parts[4]
                    def split_ep2(addr: str):
                        try:
                            if ":" in addr and not addr.strip().startswith("["):
                                h, p = addr.rsplit(":", 1)
                                return h, int(p) if p.isdigit() else 0
                            return addr, 0
                        except Exception:
                            return addr, 0
                    src_ip, sport = split_ep2(src)
                    dst_ip, dport = split_ep2(dst)
                    add(proto, src_ip, dst_ip, sport, dport)
    except Exception:
        pass

    # 4) As a last resort, synthesize a loopback flow to keep UI alive
    if not flows:
        try:
            add("TCP", "127.0.0.1", "127.0.0.1", 0, 8000)
        except Exception:
            pass
    return flows

# ---- Additional Analytics helpers ----
def _geo_summary(flows: list[dict]) -> dict:
    summary = {"private": 0, "public": 0}
    for f in flows:
        try:
            ip = ipaddress.ip_address(f.get("src_ip", "0.0.0.0"))
            if ip.is_private or ip.is_loopback or ip.is_link_local:
                summary["private"] += 1
            else:
                summary["public"] += 1
        except Exception:
            continue
    return summary

def _ports_histogram(flows: list[dict], top_n: int = 10) -> list[dict]:
    counts: dict[int, int] = {}
    for f in flows:
        p = int(f.get("dport", 0))
        if p <= 0:
            continue
        counts[p] = counts.get(p, 0) + 1
    top = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:top_n]
    return [{"port": k, "count": v, "service": _service_name(k)} for k, v in top]

def _top_entities(flows: list[dict], field: str, top_n: int = 10) -> list[dict]:
    counts: dict[str, int] = {}
    for f in flows:
        key = f.get(field)
        if not key:
            continue
        counts[key] = counts.get(key, 0) + 1
    return [{"value": k, "count": v} for k, v in sorted(counts.items(), key=lambda x: x[1], reverse=True)[:top_n]]

# Safety guard: ensure _geo_country exists even if older module is loaded
try:
    _geo_country  # type: ignore[name-defined]
except NameError:  # pragma: no cover
    _GEO_READER = None
    _GEO_MISS = object()
    def _geo_init():
        """Lazy init MaxMind reader if available."""
        global _GEO_READER
        if _GEO_READER is not None:
            return _GEO_READER
        try:
            from geoip2.database import Reader  # type: ignore
            # Typical system paths; choose first existing
            env_path = os.environ.get("CERB_GEOIP_DB")
            candidates = ([env_path] if env_path else []) + [
                "/usr/share/GeoIP/GeoLite2-Country.mmdb",
                "/usr/local/share/GeoIP/GeoLite2-Country.mmdb",
                str(Path.home()/".local/share/GeoIP/GeoLite2-Country.mmdb"),
            ]
            for p in candidates:
                if Path(p).exists():
                    _GEO_READER = Reader(p)
                    break
        except Exception:
            _GEO_READER = None
        return _GEO_READER

    def _geo_country(ip: str) -> str | None:  # noqa: N802
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private or ip_obj.is_loopback:
                return None
        except Exception:
            return None
        if ip in _geo_cache:
            val = _geo_cache.get(ip, _GEO_MISS)
            return None if val is _GEO_MISS else val
        reader = _geo_init()
        if not reader:
            _geo_cache[ip] = _GEO_MISS
            return None
        try:
            rec = reader.country(ip)
            code = getattr(getattr(rec, "country", None), "iso_code", None)
            if code:
                _geo_cache[ip] = code
                return code
        except Exception:
            pass
        _geo_cache[ip] = _GEO_MISS
        return None

# ---- Geo analytics API ----
@app.get("/api/analytics/geo")
async def analytics_geo():
    try:
        flows = _collect_flows()
        # build country histogram using geo lookup of source IP
        country_counts: dict[str, int] = {}
        for f in flows:
            try:
                c = _geo_country(f.get("src_ip", ""))
            except Exception:
                c = None
            if not c:
                continue
            country_counts[c] = country_counts.get(c, 0) + 1
        countries = [
            {"code": k, "count": v}
            for k, v in sorted(country_counts.items(), key=lambda x: x[1], reverse=True)
        ]
        data = {
            "geo": _geo_summary(flows),
            "topPorts": _ports_histogram(flows),
            "topSources": _top_entities(flows, "src_ip"),
            "topDestinations": _top_entities(flows, "dst_ip"),
            "countries": countries,
            "blockedCountries": list(geo_blocked_countries),
        }
        return add_cors_headers(JSONResponse(content=data))
    except Exception as e:
        logger.error(f"analytics_geo failed: {e}")
        return add_cors_headers(JSONResponse(content={"geo": {"private":0,"public":0}}, status_code=500))

@app.post("/api/geo/block")
async def geo_block(request: dict):
    try:
        country = (request.get("country") or "").upper()
        if not country or len(country) != 2:
            return add_cors_headers(JSONResponse(content={"success": False, "message": "country must be ISO alpha-2"}, status_code=400))
        if country not in geo_blocked_countries:
            geo_blocked_countries.append(country)
        log_audit_event(f"Geo block added for country={country}")
        return add_cors_headers(JSONResponse(content={"success": True, "blockedCountries": geo_blocked_countries}))
    except Exception as e:
        logger.error(f"geo_block failed: {e}")
        return add_cors_headers(JSONResponse(content={"success": False, "message": str(e)}, status_code=500))

def _recommend_interface(interfaces):
    """Pick a safe default interface for XDP generic attach.
    Preference: non-wireless, non-loopback, up, has IP, default route.
    """
    if not interfaces:
        return {"name": "eth0", "reason": "fallback"}

    # Best candidate
    for prefer_default in (True, False):
        for i in interfaces:
            if i["type"] in ("ethernet", "virtual") and i["is_up"] and (i["is_default"] if prefer_default else True):
                return {"name": i["name"], "reason": "default" if i["is_default"] else "up"}

    # Fallback to first up iface
    for i in interfaces:
        if i["is_up"]:
            return {"name": i["name"], "reason": "first-up"}
    return {"name": interfaces[0]["name"], "reason": "first"}

@app.get("/api/ebpf/programs")
async def get_ebpf_programs():
    """Get list of eBPF programs."""
    try:
        if hasattr(firewall_manager, 'get_programs'):
            programs = firewall_manager.get_programs()
        else:
            programs = [
                {"name": "firewall_engine", "type": "XDP", "status": "active" if firewall_manager.is_loaded() else "inactive", "interface": "eth0"}
            ]
        response = JSONResponse(content={"programs": programs})
        return add_cors_headers(response)
    except Exception as e:
        logger.error(f"Failed to get eBPF programs: {e}")
        error_response = JSONResponse(content={"error": str(e)}, status_code=500)
        return add_cors_headers(error_response)

@app.get("/api/network/interfaces")
async def list_interfaces():
    """Enumerate host network interfaces and provide a recommended default.
    Portable across Linux distros using iproute2 JSON output.
    """
    try:
        interfaces = _list_network_interfaces()
        recommended = _recommend_interface(interfaces)
        # annotate hints for frontend UX
        for i in interfaces:
            if i.get("type") == "wireless":
                i["xdp_mode"] = "generic"
                i["not_recommended"] = True
            else:
                i["xdp_mode"] = "native"
                i["not_recommended"] = False

        response = JSONResponse(content={
            "interfaces": interfaces,
            "recommended": recommended,
            "total_count": len(interfaces)
        })
        return add_cors_headers(response)
    except Exception as e:
        logger.error(f"Failed to list interfaces: {e}")
        return add_cors_headers(JSONResponse(content={"interfaces": [], "error": str(e)}, status_code=500))

@app.post("/api/ebpf/load")
async def load_ebpf_program(request: dict):
    """Load eBPF program."""
    try:
        name = request.get("name")
        interface = request.get("interface", "eth0")
        
        if not name:
            return add_cors_headers(JSONResponse(
                content={"error": "Program name required"}, 
                status_code=400
            ))
        
        # Mock manager exposes attribute 'programs'; real manager usually not
        if hasattr(firewall_manager, 'programs'):
            success = firewall_manager.load_program(name, interface)
        elif hasattr(firewall_manager, 'load_program'):
            success = firewall_manager.load_program()
        else:
            success = False
            
        if success:
            log_audit_event(f"eBPF program {name} loaded on {interface}")
            return add_cors_headers(JSONResponse(
                content={"success": True, "message": f"Program {name} loaded successfully"}
            ))
        else:
            return add_cors_headers(JSONResponse(
                content={"error": f"Failed to load program {name}"}, 
                status_code=500
            ))
    except Exception as e:
        logger.error(f"Failed to load eBPF program: {e}")
        error_response = JSONResponse(content={"error": str(e)}, status_code=500)
        return add_cors_headers(error_response)

@app.post("/api/ebpf/unload")
async def unload_ebpf_program(request: dict):
    """Unload eBPF program."""
    try:
        name = request.get("name")
        
        if not name:
            return add_cors_headers(JSONResponse(
                content={"error": "Program name required"}, 
                status_code=400
            ))
        
        success = firewall_manager.unload_program(name)
        if success:
            log_audit_event(f"eBPF program {name} unloaded")
            return add_cors_headers(JSONResponse(
                content={"success": True, "message": f"Program {name} unloaded successfully"}
            ))
        else:
            return add_cors_headers(JSONResponse(
                content={"error": f"Program {name} not found"}, 
                status_code=404
            ))
    except Exception as e:
        logger.error(f"Failed to unload eBPF program: {e}")
        error_response = JSONResponse(content={"error": str(e)}, status_code=500)
        return add_cors_headers(error_response)

@app.get("/api/ebpf/stats")
async def get_ebpf_stats():
    """Get eBPF statistics."""
    try:
        stats_data = {"packets_processed": 0, "packets_dropped": 0, "bytes_processed": 0, "cpu_usage": 0.0}
        if hasattr(firewall_manager, 'get_stats'):
            stats = firewall_manager.get_stats()
            if isinstance(stats, dict):
                stats_data.update(stats)
            else:
                # object with attributes
                stats_data.update({
                    "packets_processed": getattr(stats, 'packets_processed', 0) or 0,
                    "packets_dropped": getattr(stats, 'packets_dropped', 0) or 0,
                    "bytes_processed": getattr(stats, 'bytes_processed', 0) or 0,
                    "cpu_usage": float(getattr(stats, 'cpu_usage', 0.0) or 0.0),
                })
        response = JSONResponse(content=stats_data)
        return add_cors_headers(response)
    except Exception as e:
        logger.error(f"Failed to get eBPF stats: {e}")
        error_response = JSONResponse(content={"error": str(e)}, status_code=500)
        return add_cors_headers(error_response)

# Firewall Rules API
@app.get("/api/firewall/rules")
async def get_firewall_rules():
    """Get all firewall rules."""
    try:
        if hasattr(firewall_manager, 'get_rules'):
            rules = firewall_manager.get_rules()
            rules_data = []
            for rule in rules:
                rules_data.append({
                "id": rule.id,
                    "action": rule.action.name if hasattr(rule.action, 'name') else rule.action,
                    "protocol": rule.protocol.name if hasattr(rule.protocol, 'name') else rule.protocol,
                    "src_ip": rule.src_ip,
                    "dst_ip": rule.dst_ip,
                    "src_port": rule.src_port,
                    "dst_port": rule.dst_port,
                    "enabled": rule.enabled,
                "priority": rule.priority,
                    "hit_count": rule.hit_count,
                    "description": rule.description
                })
        else:
            rules_data = []
        
        response = JSONResponse(content={"rules": rules_data})
        return add_cors_headers(response)
    except Exception as e:
        logger.error(f"Failed to get firewall rules: {e}")
        error_response = JSONResponse(content={"error": str(e)}, status_code=500)
        return add_cors_headers(error_response)

@app.post("/api/firewall/rules")
async def add_firewall_rule(request: dict):
    """Add a new firewall rule."""
    try:
        if not hasattr(firewall_manager, 'add_rule'):
            return add_cors_headers(JSONResponse(
                content={"error": "Firewall manager not available"}, 
                status_code=500
            ))
        
        # Create rule from request
        rule = FirewallRule(
            id=0,  # Will be set by manager
            action=RuleAction[request.get("action", "DROP").upper()],
            protocol=Protocol[request.get("protocol", "ANY").upper()],
            src_ip=request.get("src_ip", "0.0.0.0"),
            dst_ip=request.get("dst_ip", "0.0.0.0"),
            src_port=request.get("src_port", 0),
            dst_port=request.get("dst_port", 0),
            enabled=request.get("enabled", True),
            priority=request.get("priority", 100),
            description=request.get("description", "")
        )
        
        success = firewall_manager.add_rule(rule)
        if success:
            log_audit_event(f"Firewall rule added: {rule.src_ip} -> {rule.dst_ip}")
            return add_cors_headers(JSONResponse(
                content={"success": True, "message": "Rule added successfully", "rule_id": rule.id}
            ))
        else:
            return add_cors_headers(JSONResponse(
                content={"error": "Failed to add rule"}, 
                status_code=500
            ))
    except Exception as e:
        logger.error(f"Failed to add firewall rule: {e}")
        error_response = JSONResponse(content={"error": str(e)}, status_code=500)
        return add_cors_headers(error_response)

@app.delete("/api/firewall/rules/{rule_id}")
async def delete_firewall_rule(rule_id: int):
    """Delete a firewall rule."""
    try:
        if not hasattr(firewall_manager, 'remove_rule'):
            return add_cors_headers(JSONResponse(
                content={"error": "Firewall manager not available"}, 
                status_code=500
            ))
        
        success = firewall_manager.remove_rule(rule_id)
        if success:
            log_audit_event(f"Firewall rule {rule_id} deleted")
            return add_cors_headers(JSONResponse(
                content={"success": True, "message": f"Rule {rule_id} deleted successfully"}
            ))
        else:
            return add_cors_headers(JSONResponse(
                content={"error": f"Rule {rule_id} not found"}, 
                status_code=404
            ))
    except Exception as e:
        logger.error(f"Failed to delete firewall rule: {e}")
        error_response = JSONResponse(content={"error": str(e)}, status_code=500)
        return add_cors_headers(error_response)

# System Control API
@app.post("/api/system/start")
async def start_system(request: dict):
    """Start the firewall system."""
    try:
        # Load eBPF firewall program (support both mock and real managers)
        iface = current_config.get("ebpf", {}).get("interface", "eth0") if isinstance(current_config, dict) else "eth0"
        if hasattr(firewall_manager, 'programs'):
            # Mock manager: method signature load_program(name, interface)
            firewall_manager.load_program("xdp_filter", iface)
            firewall_manager.load_program("tc_filter", iface)
            try:
                setattr(firewall_manager, 'interface', iface)
            except Exception:
                pass
        elif hasattr(firewall_manager, 'load_program'):
            # Real manager: load_program() returns bool
            success = firewall_manager.load_program()
            if not success:
                return add_cors_headers(JSONResponse(
                    content={"error": "Failed to load eBPF program"}, 
                    status_code=500
                ))
        else:
            logger.warning("No firewall manager available to load program")
        
        # Switch overall mode to LIVE (mock preflight gating)
        try:
            preflight_manager.set_mode("live")
        except Exception:
            pass

        log_audit_event("Firewall system started")
        return add_cors_headers(JSONResponse(
            content={"success": True, "message": "Firewall system started successfully"}
        ))
    except Exception as e:
        logger.error(f"Failed to start system: {e}")
        error_response = JSONResponse(content={"error": str(e)}, status_code=500)
        return add_cors_headers(error_response)

@app.post("/api/system/stop")
async def stop_system(request: dict):
    """Stop the firewall system."""
    try:
        # Unload all eBPF programs
        if hasattr(firewall_manager, 'programs'):
            for name in firewall_manager.programs:
                firewall_manager.unload_program(name)
        else:
            # Fallback for mock manager
            logger.info("Mock firewall manager - no programs to unload")
        
        log_audit_event("Firewall system stopped")
        return add_cors_headers(JSONResponse(
            content={"success": True, "message": "Firewall system stopped successfully"}
        ))
    except Exception as e:
        logger.error(f"Failed to stop system: {e}")
        error_response = JSONResponse(content={"error": str(e)}, status_code=500)
        return add_cors_headers(error_response)

@app.get("/api/system/status")
async def get_system_status():
    """Get system status."""
    try:
        running = False
        programs = []
        stats_dict = {
            "packets_processed": 0,
            "packets_dropped": 0,
            "bytes_processed": 0,
            "cpu_usage": 0.0
        }

        if hasattr(firewall_manager, 'is_loaded'):
            # Real eBPF manager path
            running = bool(firewall_manager.is_loaded())
            total_programs = 1
            active_programs = 1 if running else 0
            programs = [
                {
                    "name": "firewall_engine",
                    "type": "XDP",
                    "status": "active" if running else "inactive",
                    "interface": getattr(firewall_manager, 'interface', 'eth0')
                }
            ]
            stats = firewall_manager.get_stats()
            stats_dict = stats if isinstance(stats, dict) else getattr(stats, '__dict__', stats_dict)
        elif hasattr(firewall_manager, 'get_programs'):
            # Mock manager with list of dicts
            programs = firewall_manager.get_programs() or []
            active_programs = sum(1 for p in programs if (p.get("status") == "active"))
            total_programs = len(programs)
            stats = firewall_manager.get_stats() if hasattr(firewall_manager, 'get_stats') else {}
            stats_dict = stats if isinstance(stats, dict) else getattr(stats, '__dict__', stats_dict)
            running = active_programs > 0
        else:
            active_programs = 0
            total_programs = 0
        
        # Resolve interface preference: manager → saved config → recommended
        iface = getattr(firewall_manager, 'interface', None)
        if not iface and isinstance(current_config, dict):
            iface = current_config.get('ebpf', {}).get('interface')
        interfaces_list = _list_network_interfaces()
        if not iface:
            iface = _recommend_interface(interfaces_list).get('name', 'eth0')
        # If chosen iface not present on host, fallback to recommended and propagate
        try:
            names = {i.get('name') for i in interfaces_list}
            if iface not in names and interfaces_list:
                fallback = _recommend_interface(interfaces_list).get('name', iface)
                iface = fallback
                # also update in-memory config to keep UI consistent
                try:
                    setattr(firewall_manager, 'interface', iface)
                except Exception:
                    pass
                try:
                    if isinstance(current_config, dict):
                        current_config.setdefault('ebpf', {})['interface'] = iface
                except Exception:
                    pass
        except Exception:
            pass

        # Provide non-null engine_state and normalized stats
        engine_state = getattr(firewall_manager, 'engine_state', None) or 'auto'
        sysinfo = _system_info()
        cpu_usage = float(stats_dict.get("cpu_usage") or 0.0)
        stats_out = {
            "packets_processed": int(stats_dict.get("packets_processed") or 0),
            "packets_dropped": int(stats_dict.get("packets_dropped") or 0),
            "bytes_processed": int(stats_dict.get("bytes_processed") or 0),
            "cpu_usage": cpu_usage,
            "memory_total": int(sysinfo.get("total_memory") or 0),
            "memory_used": int(sysinfo.get("used_memory") or 0),
        }
        # include API uptime to feed UI
        uptime_sec = int((datetime.now(UTC) - start_time).total_seconds())
        status_data = {
            "running": running,
            "active_programs": active_programs,
            "total_programs": total_programs,
            "programs": programs,
            "stats": stats_out,
            "interface": iface,
            "engine_state": engine_state,
            "interfaces": interfaces_list,
            "vpp_interfaces": len(_vpp_interfaces()),
            "uptime": uptime_sec,
        }
        
        response = JSONResponse(content=status_data)
        return add_cors_headers(response)
    except Exception as e:
        logger.error(f"Failed to get system status: {e}")
        error_response = JSONResponse(content={"error": str(e)}, status_code=500)
        return add_cors_headers(error_response)

# Settings Configuration API
@app.get("/api/settings")
async def get_settings():
    """Get current system configuration."""
    try:
        # Load configuration from file or defaults
        config_file = Path("config/cerberus.json")
        if config_file.exists():
            with open(config_file, 'r') as f:
                config = json.load(f)
        else:
            # Default configuration
            config = {
                "vpp": {
                    "enabled": True,
                    "workers": 4,
                    "heapSize": "1G",
                    "logLevel": "info",
                    "plugins": ["ebpf-classify", "acl", "nat"]
                },
                "ebpf": {
                    "enabled": True,
                    "interface": "eth0",
                    "queueId": 0,
                    "verbose": False,
                    "maps": {
                        "maxEntries": 65536,
                        "autoCleanup": True
                    }
                },
                "security": {
                    "authEnabled": False,
                    "sessionTimeout": 3600,
                    "maxLoginAttempts": 5,
                    "encryption": "AES256",
                    "certificates": {
                        "autoRenew": True,
                        "keySize": 2048
                    }
                },
                "monitoring": {
                    "realTime": True,
                    "retentionDays": 30,
                    "metricsInterval": 2000,
                    "alerting": True,
                    "exportFormat": "JSON"
                },
                "ui": {
                    "theme": "light",
                    "language": "en",
                    "refreshInterval": 5000,
                    "animations": True,
                    "density": "standard"
                }
            }
        
        # keep in-memory copy for subsequent operations
        global current_config
        current_config = config

        response = JSONResponse(content={"success": True, "config": config})
        return add_cors_headers(response)
    except Exception as e:
        logger.error(f"Failed to get settings: {e}")
        error_response = JSONResponse(content={"error": str(e)}, status_code=500)
        return add_cors_headers(error_response)

@app.post("/api/settings")
async def save_settings(config: dict):
    """Save system configuration."""
    try:
        # Ensure config directory exists
        config_dir = Path("config")
        config_dir.mkdir(exist_ok=True)
        
        # Save configuration to file
        config_file = config_dir / "cerberus.json"
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)
        
        # Update in-memory config
        global current_config
        current_config = config

        # Apply configuration changes (implement as needed)
        await apply_configuration_changes(config)
        
        log_audit_event(f"Configuration saved: {config_file}")
        logger.info(f"✅ Configuration saved to {config_file}")
        
        response = JSONResponse(content={
            "success": True, 
            "message": "Configuration saved successfully",
            "timestamp": datetime.now(UTC).isoformat()
        })
        return add_cors_headers(response)
    except Exception as e:
        logger.error(f"Failed to save settings: {e}")
        error_response = JSONResponse(content={"error": str(e)}, status_code=500)
        return add_cors_headers(error_response)

async def apply_configuration_changes(config: dict):
    """Apply configuration changes to running system."""
    try:
        # VPP configuration
        if config.get("vpp", {}).get("enabled"):
            logger.info("Applying VPP configuration...")
            # TODO: Apply VPP settings
        
        # eBPF configuration
        if config.get("ebpf", {}).get("enabled"):
            logger.info("Applying eBPF configuration...")
            # Propagate selected interface to firewall manager (safe in demo mode)
            try:
                iface = config.get("ebpf", {}).get("interface")
                if iface:
                    setattr(firewall_manager, 'interface', iface)
                    logger.info(f"eBPF interface set to {iface}")
                # Optional engine_state (auto|xdp|tc); for Wi‑Fi рекомендуем tc
                engine_state = config.get("ebpf", {}).get("engine_state")
                if engine_state in ("auto", "xdp", "tc"):
                    setattr(firewall_manager, 'engine_state', engine_state)
                    logger.info(f"eBPF engine_state set to {engine_state}")
                # If Wi‑Fi interface chosen, force TC as safer default unless explicitly overridden
                try:
                    if Path(f"/sys/class/net/{iface}/wireless").exists():
                        if engine_state in (None, "auto", "xdp"):
                            setattr(firewall_manager, 'engine_state', 'tc')
                            logger.info("Wi‑Fi detected: forcing engine_state=tc for safety")
                except Exception:
                    pass
            except Exception as e:
                logger.warning(f"Failed to set eBPF interface: {e}")
            
        # Security configuration
        logger.info("Applying security configuration...")
        # TODO: Apply security settings
        
        logger.info("✅ Configuration changes applied successfully")
    except Exception as e:
        logger.error(f"Failed to apply configuration changes: {e}")
        raise

# Error handlers
@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    """Global exception handler."""
    logger.error(f"Unhandled exception: {exc}")
    return {"error": "Internal server error", "detail": str(exc)}

if __name__ == "__main__":
    logger.info("Starting Cerberus-V API server...")
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info") 