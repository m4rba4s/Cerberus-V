#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Cerberus-V LIVE Mode API
# Elite-Mode APT-Grade REST Endpoints

from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import Dict, Optional
import logging
import sys
from pathlib import Path

# Add project root to path
sys.path.append(str(Path(__file__).parent.parent.parent))

try:
    from userspace.simple_live_manager import SimpleLiveManager as LiveModeManager, LiveMode
    LiveConfig = None  # Not needed for simple manager
except ImportError:
    # Fallback for development
    LiveModeManager = None
    LiveConfig = None
    LiveMode = None

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/live", tags=["live"])

# Global live manager instance
live_manager: Optional[LiveModeManager] = None

class ModeRequest(BaseModel):
    mode: str

class ModeResponse(BaseModel):
    success: bool
    message: str
    mode: Optional[str] = None

class StatusResponse(BaseModel):
    mode: str
    last_commit: int
    rule_count: int
    drop_count: int
    allow_count: int
    emergency_mode: bool
    watchdog_running: bool

def get_live_manager() -> LiveModeManager:
    """Get or create live manager instance"""
    global live_manager
    
    if live_manager is None:
        if LiveModeManager is None:
            raise HTTPException(status_code=503, detail="LIVE mode manager not available")
        
        live_manager = LiveModeManager()  # Simple manager doesn't need config
    
    return live_manager

@router.get("/status", response_model=StatusResponse)
async def get_live_status():
    """Get current LIVE mode status"""
    try:
        manager = get_live_manager()
        status = manager.get_status()
        
        if "error" in status:
            raise HTTPException(status_code=500, detail=status["error"])
        
        return StatusResponse(**status)
        
    except Exception as e:
        logger.error(f"Failed to get live status: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/mode", response_model=ModeResponse)
async def switch_live_mode(request: ModeRequest, background_tasks: BackgroundTasks):
    """Switch between simulation and LIVE modes"""
    try:
        manager = get_live_manager()
        
        if request.mode.lower() == "live":
            # Enable LIVE mode
            success = manager.enable_live_mode()
            if success:
                logger.info("LIVE mode enabled successfully")
                return ModeResponse(
                    success=True,
                    message="LIVE mode enabled successfully",
                    mode="live"
                )
            else:
                logger.error("Failed to enable LIVE mode")
                return ModeResponse(
                    success=False,
                    message="Failed to enable LIVE mode - check system resources"
                )
                
        elif request.mode.lower() == "simulation":
            # Disable LIVE mode
            success = manager.disable_live_mode()
            if success:
                logger.info("LIVE mode disabled successfully")
                return ModeResponse(
                    success=True,
                    message="LIVE mode disabled successfully",
                    mode="simulation"
                )
            else:
                logger.error("Failed to disable LIVE mode")
                return ModeResponse(
                    success=False,
                    message="Failed to disable LIVE mode"
                )
        else:
            raise HTTPException(status_code=400, detail="Invalid mode. Use 'live' or 'simulation'")
            
    except Exception as e:
        logger.error(f"Failed to switch live mode: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/emergency-rollback")
async def emergency_rollback():
    """Trigger emergency rollback to simulation mode"""
    try:
        manager = get_live_manager()
        
        # This would trigger the emergency rollback
        # For now, we'll just disable live mode
        success = manager.disable_live_mode()
        
        if success:
            logger.warning("Emergency rollback triggered")
            return {"success": True, "message": "Emergency rollback completed"}
        else:
            logger.error("Emergency rollback failed")
            return {"success": False, "message": "Emergency rollback failed"}
            
    except Exception as e:
        logger.error(f"Emergency rollback error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/health")
async def live_health_check():
    """Health check for LIVE mode system"""
    try:
        manager = get_live_manager()
        status = manager.get_status()
        
        if "error" in status:
            return {"status": "unhealthy", "error": status["error"]}
        
        # Check if watchdog is running
        if status.get("mode") == "live" and not status.get("watchdog_running"):
            return {"status": "warning", "message": "LIVE mode active but watchdog not running"}
        
        return {"status": "healthy", "mode": status.get("mode")}
        
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return {"status": "unhealthy", "error": str(e)}

@router.get("/stats")
async def get_live_stats():
    """Get detailed LIVE mode statistics"""
    try:
        manager = get_live_manager()
        status = manager.get_status()
        
        if "error" in status:
            raise HTTPException(status_code=500, detail=status["error"])
        
        # Calculate additional stats
        total_packets = status["drop_count"] + status["allow_count"]
        drop_rate = (status["drop_count"] / total_packets * 100) if total_packets > 0 else 0
        
        return {
            "mode": status["mode"],
            "packets": {
                "total": total_packets,
                "dropped": status["drop_count"],
                "allowed": status["allow_count"],
                "drop_rate": round(drop_rate, 2)
            },
            "rules": status["rule_count"],
            "uptime": status["last_commit"],
            "emergency_mode": status["emergency_mode"],
            "watchdog_running": status["watchdog_running"]
        }
        
    except Exception as e:
        logger.error(f"Failed to get live stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Mock endpoints for development when live_manager is not available
if LiveModeManager is None:
    @router.get("/status", response_model=StatusResponse)
    async def get_live_status_mock():
        """Mock LIVE mode status for development"""
        return StatusResponse(
            mode="simulation",
            last_commit=0,
            rule_count=0,
            drop_count=0,
            allow_count=0,
            emergency_mode=False,
            watchdog_running=False
        )
    
    @router.post("/mode", response_model=ModeResponse)
    async def switch_live_mode_mock(request: ModeRequest):
        """Mock mode switching for development"""
        logger.warning("LIVE mode manager not available - using mock")
        return ModeResponse(
            success=True,
            message=f"Mock: Switched to {request.mode} mode",
            mode=request.mode
        ) 