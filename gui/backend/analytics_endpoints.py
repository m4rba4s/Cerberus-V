# SPDX-License-Identifier: Apache-2.0
# Analytics API Endpoints for Cerberus-V

from fastapi import APIRouter, HTTPException, Query
from typing import Dict, List, Any, Optional
import logging
from datetime import datetime, timedelta
import asyncio

from .enhanced_analytics import (
    EnhancedAnalytics, 
    ThreatIntelligence, 
    TrafficPattern, 
    SecurityEvent
)

logger = logging.getLogger(__name__)

# Global analytics instance
analytics = EnhancedAnalytics()

# Create router
router = APIRouter(prefix="/api/analytics", tags=["analytics"])

@router.get("/threat-intelligence")
async def get_threat_intelligence() -> Dict[str, Any]:
    """Get comprehensive threat intelligence analysis"""
    try:
        return await analytics.analyze_threat_intelligence()
    except Exception as e:
        logger.error(f"Error getting threat intelligence: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/traffic-patterns")
async def get_traffic_patterns() -> Dict[str, Any]:
    """Get network traffic pattern analysis"""
    try:
        return await analytics.analyze_traffic_patterns()
    except Exception as e:
        logger.error(f"Error analyzing traffic patterns: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/security-report")
async def get_security_report() -> Dict[str, Any]:
    """Get comprehensive security report"""
    try:
        return await analytics.generate_security_report()
    except Exception as e:
        logger.error(f"Error generating security report: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/performance-metrics")
async def get_performance_metrics() -> Dict[str, Any]:
    """Get system performance metrics"""
    try:
        current_time = datetime.now()
        
        # Generate mock performance data
        metrics = {
            "timestamp": current_time.isoformat(),
            "vpp_performance": {
                "packets_per_second": 1250000 + (hash(str(current_time)) % 100000),
                "cpu_utilization": 35.2 + (hash(str(current_time)) % 20),
                "memory_usage": 2048 + (hash(str(current_time)) % 512),
                "worker_threads": 4,
                "active_interfaces": 2,
                "forwarding_rate": 99.97,
                "drops_per_second": 125 + (hash(str(current_time)) % 50)
            },
            "ebpf_performance": {
                "xdp_processing_rate": 2100000 + (hash(str(current_time)) % 200000),
                "map_operations_per_sec": 50000 + (hash(str(current_time)) % 10000),
                "program_execution_time_ns": 250 + (hash(str(current_time)) % 100),
                "memory_footprint_kb": 1024 + (hash(str(current_time)) % 256),
                "active_programs": 3,
                "map_utilization": 67.8 + (hash(str(current_time)) % 20)
            },
            "system_performance": {
                "cpu_load": [1.2, 1.5, 1.8],
                "memory_total": 16777216,  # 16GB in KB
                "memory_available": 8388608,  # 8GB in KB
                "disk_io_read": 125.6 + (hash(str(current_time)) % 50),
                "disk_io_write": 87.3 + (hash(str(current_time)) % 30),
                "network_rx_bytes": 1048576000 + (hash(str(current_time)) % 100000000),
                "network_tx_bytes": 524288000 + (hash(str(current_time)) % 50000000)
            },
            "comparison": {
                "vpp_vs_traditional": {
                    "performance_improvement": 8.7,
                    "latency_reduction": 65.3,
                    "cpu_efficiency": 23.4
                },
                "ebpf_vs_iptables": {
                    "performance_improvement": 12.3,
                    "memory_efficiency": 45.6,
                    "rule_processing_speed": 89.2
                }
            }
        }
        
        return metrics
    except Exception as e:
        logger.error(f"Error getting performance metrics: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/geolocation-data")
async def get_geolocation_data() -> Dict[str, Any]:
    """Get geolocation-based threat analysis"""
    try:
        current_time = datetime.now()
        
        # Generate mock geolocation data
        geo_data = {
            "timestamp": current_time.isoformat(),
            "threat_map": [
                {"country": "China", "lat": 35.8617, "lng": 104.1954, "threats": 1247, "severity": "high"},
                {"country": "Russia", "lat": 61.5240, "lng": 105.3188, "threats": 892, "severity": "high"},
                {"country": "North Korea", "lat": 40.3399, "lng": 127.5101, "threats": 567, "severity": "critical"},
                {"country": "Iran", "lat": 32.4279, "lng": 53.6880, "threats": 423, "severity": "medium"},
                {"country": "Brazil", "lat": -14.2350, "lng": -51.9253, "threats": 234, "severity": "medium"},
                {"country": "India", "lat": 20.5937, "lng": 78.9629, "threats": 189, "severity": "low"},
                {"country": "United States", "lat": 37.0902, "lng": -95.7129, "threats": 156, "severity": "low"},
                {"country": "Turkey", "lat": 38.9637, "lng": 35.2433, "threats": 134, "severity": "medium"},
                {"country": "Vietnam", "lat": 14.0583, "lng": 108.2772, "threats": 98, "severity": "low"},
                {"country": "Ukraine", "lat": 48.3794, "lng": 31.1656, "threats": 87, "severity": "medium"}
            ],
            "top_countries": [
                {"country": "China", "code": "CN", "threats": 1247, "percentage": 32.1},
                {"country": "Russia", "code": "RU", "threats": 892, "percentage": 23.0},
                {"country": "North Korea", "code": "KP", "threats": 567, "percentage": 14.6},
                {"country": "Iran", "code": "IR", "threats": 423, "percentage": 10.9},
                {"country": "Brazil", "code": "BR", "threats": 234, "percentage": 6.0}
            ],
            "attack_vectors": {
                "port_scanning": 45.3,
                "brute_force": 23.7,
                "malware": 15.2,
                "ddos": 8.9,
                "phishing": 4.1,
                "other": 2.8
            },
            "blocked_connections": {
                "last_hour": 1247,
                "last_24h": 28934,
                "last_week": 187562,
                "total": 2847391
            }
        }
        
        return geo_data
    except Exception as e:
        logger.error(f"Error getting geolocation data: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/advanced-metrics")
async def get_advanced_metrics() -> Dict[str, Any]:
    """Get advanced analytics metrics"""
    try:
        current_time = datetime.now()
        
        metrics = {
            "timestamp": current_time.isoformat(),
            "machine_learning": {
                "anomaly_detection": {
                    "model_accuracy": 94.7,
                    "false_positive_rate": 2.3,
                    "threats_detected": 147,
                    "model_last_trained": (current_time - timedelta(hours=6)).isoformat()
                },
                "behavioral_analysis": {
                    "baseline_established": True,
                    "deviation_threshold": 3.5,
                    "anomalous_connections": 23,
                    "learning_mode": False
                }
            },
            "threat_intelligence": {
                "feed_sources": 12,
                "indicators_processed": 1247893,
                "last_update": (current_time - timedelta(minutes=15)).isoformat(),
                "reputation_scores": {
                    "high_risk": 2847,
                    "medium_risk": 8934,
                    "low_risk": 15672,
                    "unknown": 89234
                }
            },
            "network_forensics": {
                "packet_capture_rate": 99.97,
                "deep_packet_inspection": True,
                "protocol_analysis": {
                    "http": 45.6,
                    "https": 32.1,
                    "dns": 12.3,
                    "ssh": 4.2,
                    "other": 5.8
                },
                "suspicious_patterns": 34
            },
            "compliance": {
                "pci_dss": {"status": "compliant", "score": 98.2},
                "gdpr": {"status": "compliant", "score": 96.7},
                "hipaa": {"status": "compliant", "score": 94.3},
                "sox": {"status": "compliant", "score": 97.1}
            }
        }
        
        return metrics
    except Exception as e:
        logger.error(f"Error getting advanced metrics: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/ingest/threat")
async def ingest_threat_data(threat_data: Dict[str, Any]) -> Dict[str, str]:
    """Ingest threat intelligence data"""
    try:
        threat = ThreatIntelligence(
            ip_address=threat_data["ip_address"],
            threat_type=threat_data["threat_type"],
            severity=threat_data["severity"],
            reputation_score=threat_data["reputation_score"],
            first_seen=datetime.fromisoformat(threat_data["first_seen"]),
            last_seen=datetime.fromisoformat(threat_data["last_seen"]),
            country=threat_data.get("country", "Unknown"),
            organization=threat_data.get("organization", "Unknown"),
            description=threat_data.get("description", "")
        )
        
        await analytics.add_threat_intelligence(threat)
        return {"status": "success", "message": "Threat data ingested successfully"}
    except Exception as e:
        logger.error(f"Error ingesting threat data: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/ingest/traffic")
async def ingest_traffic_data(traffic_data: Dict[str, Any]) -> Dict[str, str]:
    """Ingest traffic pattern data"""
    try:
        pattern = TrafficPattern(
            timestamp=datetime.fromisoformat(traffic_data["timestamp"]),
            protocol=traffic_data["protocol"],
            src_ip=traffic_data["src_ip"],
            dst_ip=traffic_data["dst_ip"],
            src_port=traffic_data["src_port"],
            dst_port=traffic_data["dst_port"],
            bytes_transferred=traffic_data["bytes_transferred"],
            packets_count=traffic_data["packets_count"],
            duration=traffic_data["duration"]
        )
        
        await analytics.add_traffic_pattern(pattern)
        return {"status": "success", "message": "Traffic data ingested successfully"}
    except Exception as e:
        logger.error(f"Error ingesting traffic data: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/ingest/security-event")
async def ingest_security_event(event_data: Dict[str, Any]) -> Dict[str, str]:
    """Ingest security event data"""
    try:
        event = SecurityEvent(
            timestamp=datetime.fromisoformat(event_data["timestamp"]),
            event_type=event_data["event_type"],
            severity=event_data["severity"],
            source_ip=event_data["source_ip"],
            target_ip=event_data["target_ip"],
            description=event_data["description"],
            rule_id=event_data.get("rule_id", ""),
            action_taken=event_data.get("action_taken", "")
        )
        
        await analytics.add_security_event(event)
        return {"status": "success", "message": "Security event ingested successfully"}
    except Exception as e:
        logger.error(f"Error ingesting security event: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/export/{data_type}")
async def export_analytics_data(
    data_type: str,
            format: str = Query("json", pattern="^(json|csv|xml)$"),
    start_date: Optional[str] = None,
    end_date: Optional[str] = None
) -> Dict[str, Any]:
    """Export analytics data in various formats"""
    try:
        if data_type == "threat-intelligence":
            data = await analytics.analyze_threat_intelligence()
        elif data_type == "traffic-patterns":
            data = await analytics.analyze_traffic_patterns()
        elif data_type == "security-report":
            data = await analytics.generate_security_report()
        else:
            raise HTTPException(status_code=400, detail="Invalid data type")
        
        # Add export metadata
        export_data = {
            "export_timestamp": datetime.now().isoformat(),
            "data_type": data_type,
            "format": format,
            "filters": {
                "start_date": start_date,
                "end_date": end_date
            },
            "data": data
        }
        
        return export_data
    except Exception as e:
        logger.error(f"Error exporting analytics data: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/health")
async def analytics_health_check() -> Dict[str, Any]:
    """Health check for analytics service"""
    try:
        return {
            "status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "analytics_engine": "operational",
            "cache_size": len(analytics.analytics_cache),
            "threat_intel_entries": len(analytics.threat_intel_db),
            "traffic_patterns": len(analytics.traffic_patterns),
            "security_events": len(analytics.security_events)
        }
    except Exception as e:
        logger.error(f"Analytics health check failed: {e}")
        return {
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }

# Background task to generate sample data
async def generate_sample_data():
    """Generate sample data for demonstration"""
    while True:
        try:
            current_time = datetime.now()
            
            # Generate sample threat intelligence
            sample_threat = ThreatIntelligence(
                ip_address=f"192.168.{hash(str(current_time)) % 255}.{hash(str(current_time + timedelta(seconds=1))) % 255}",
                threat_type="malware",
                severity="high",
                reputation_score=85.7,
                first_seen=current_time - timedelta(hours=2),
                last_seen=current_time,
                country="Unknown",
                organization="Unknown",
                description="Suspicious activity detected"
            )
            await analytics.add_threat_intelligence(sample_threat)
            
            # Generate sample traffic pattern
            sample_traffic = TrafficPattern(
                timestamp=current_time,
                protocol="TCP",
                src_ip=f"10.0.{hash(str(current_time)) % 255}.{hash(str(current_time + timedelta(seconds=2))) % 255}",
                dst_ip=f"172.16.{hash(str(current_time)) % 255}.{hash(str(current_time + timedelta(seconds=3))) % 255}",
                src_port=hash(str(current_time)) % 65535,
                dst_port=80,
                bytes_transferred=1024 + hash(str(current_time)) % 10240,
                packets_count=10 + hash(str(current_time)) % 100,
                duration=0.5 + (hash(str(current_time)) % 1000) / 1000
            )
            await analytics.add_traffic_pattern(sample_traffic)
            
            # Clean up cache periodically
            analytics.cleanup_cache()
            
            await asyncio.sleep(30)  # Generate new data every 30 seconds
            
        except Exception as e:
            logger.error(f"Error generating sample data: {e}")
            await asyncio.sleep(60)

# Start background task
asyncio.create_task(generate_sample_data()) 