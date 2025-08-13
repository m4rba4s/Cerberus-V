#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Cerberus-V Mock LIVE Mode API
# Elite-Mode APT-Grade Mock for Stability

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Dict
import logging
import time

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/live", tags=["live"])

# Mock state
mock_state = {
    "mode": "simulation",
    "timestamp": int(time.time()),
    "drop_count": 0,
    "allow_count": 0,
    "emergency_mode": False,
    "watchdog_running": False
}

class ModeRequest(BaseModel):
    mode: str

class ModeResponse(BaseModel):
    success: bool
    message: str
    mode: str = None

class StatusResponse(BaseModel):
    mode: str
    timestamp: int
    drop_count: int
    allow_count: int
    emergency_mode: bool
    watchdog_running: bool

# Keep SIM/LIVE in sync with preflight manager so WS shows correct mode
try:
    from preflight import preflight_manager  # type: ignore
except Exception:
    preflight_manager = None

def _set_mode_globally(mode: str):
    try:
        if preflight_manager is not None:
            # Ignore message; we assume mock always succeeds
            preflight_manager.set_mode(mode)
    except Exception:
        pass

@router.get("/status", response_model=StatusResponse)
async def get_live_status():
    """Get current LIVE mode status (mock)"""
    try:
        logger.info("Mock LIVE status requested")
        # Reflect preflight mode if available
        if preflight_manager is not None:
            try:
                # trust mock_state if explicitly set to live
                cur = preflight_manager.get_mode()
                if mock_state["mode"] != cur:
                    mock_state["mode"] = cur
            except Exception:
                pass
        return StatusResponse(**mock_state)
    except Exception as e:
        logger.error(f"Mock LIVE status error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/mode", response_model=ModeResponse)
async def switch_live_mode(request: ModeRequest):
    """Switch between simulation and LIVE modes (mock)"""
    try:
        logger.info(f"Mock LIVE mode switch requested: {request.mode}")
        
        if request.mode.lower() == "live":
            mock_state["mode"] = "live"
            mock_state["timestamp"] = int(time.time())
            _set_mode_globally("live")
            logger.info("Mock LIVE mode enabled")
            return ModeResponse(
                success=True,
                message="Mock: LIVE mode enabled successfully",
                mode="live"
            )
        elif request.mode.lower() == "simulation":
            mock_state["mode"] = "simulation"
            mock_state["timestamp"] = int(time.time())
            _set_mode_globally("simulation")
            logger.info("Mock LIVE mode disabled")
            return ModeResponse(
                success=True,
                message="Mock: LIVE mode disabled successfully",
                mode="simulation"
            )
        else:
            raise HTTPException(status_code=400, detail="Invalid mode. Use 'live' or 'simulation'")
            
    except Exception as e:
        logger.error(f"Mock LIVE mode switch error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/emergency-rollback")
async def emergency_rollback():
    """Trigger emergency rollback to simulation mode (mock)"""
    try:
        logger.warning("Mock emergency rollback triggered")
        mock_state["mode"] = "simulation"
        mock_state["emergency_mode"] = True
        mock_state["timestamp"] = int(time.time())
        return {"success": True, "message": "Mock: Emergency rollback completed"}
    except Exception as e:
        logger.error(f"Mock emergency rollback error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/health")
async def live_health_check():
    """Health check for LIVE mode system (mock)"""
    try:
        return {"status": "healthy", "mode": mock_state["mode"]}
    except Exception as e:
        logger.error(f"Mock health check error: {e}")
        return {"status": "unhealthy", "error": str(e)}

@router.get("/stats")
async def get_live_stats():
    """Get detailed LIVE mode statistics (mock)"""
    try:
        total_packets = mock_state["drop_count"] + mock_state["allow_count"]
        drop_rate = (mock_state["drop_count"] / total_packets * 100) if total_packets > 0 else 0
        
        return {
            "mode": mock_state["mode"],
            "packets": {
                "total": total_packets,
                "dropped": mock_state["drop_count"],
                "allowed": mock_state["allow_count"],
                "drop_rate": round(drop_rate, 2)
            },
            "rules": 0,
            "uptime": mock_state["timestamp"],
            "emergency_mode": mock_state["emergency_mode"],
            "watchdog_running": mock_state["watchdog_running"]
        }
    except Exception as e:
        logger.error(f"Mock stats error: {e}")
        raise HTTPException(status_code=500, detail=str(e)) 