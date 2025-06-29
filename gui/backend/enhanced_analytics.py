# SPDX-License-Identifier: Apache-2.0
# Enhanced Analytics Module for Cerberus-V

import asyncio
import json
import logging
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
import numpy as np
from collections import defaultdict, deque
import geoip2.database
import geoip2.errors

logger = logging.getLogger(__name__)

@dataclass
class ThreatIntelligence:
    ip_address: str
    threat_type: str
    severity: str
    reputation_score: float
    first_seen: datetime
    last_seen: datetime
    country: str
    organization: str
    description: str

@dataclass
class TrafficPattern:
    timestamp: datetime
    protocol: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    bytes_transferred: int
    packets_count: int
    duration: float

@dataclass
class SecurityEvent:
    timestamp: datetime
    event_type: str
    severity: str
    source_ip: str
    target_ip: str
    description: str
    rule_id: str
    action_taken: str

class EnhancedAnalytics:
    def __init__(self):
        self.threat_intel_db = {}
        self.traffic_patterns = deque(maxlen=10000)
        self.security_events = deque(maxlen=5000)
        self.geo_db = None
        self.analytics_cache = {}
        self.cache_ttl = 300  # 5 minutes
        
        # Initialize GeoIP database
        try:
            self.geo_db = geoip2.database.Reader('/usr/share/GeoIP/GeoLite2-City.mmdb')
        except Exception as e:
            logger.warning(f"GeoIP database not available: {e}")
    
    async def analyze_threat_intelligence(self) -> Dict[str, Any]:
        """Generate comprehensive threat intelligence analysis"""
        current_time = datetime.now()
        cache_key = f"threat_intel_{int(current_time.timestamp() // 300)}"
        
        if cache_key in self.analytics_cache:
            return self.analytics_cache[cache_key]
        
        # Generate threat intelligence data
        threat_data = {
            "summary": {
                "total_threats": len(self.threat_intel_db),
                "high_severity": sum(1 for t in self.threat_intel_db.values() if t.severity == "high"),
                "medium_severity": sum(1 for t in self.threat_intel_db.values() if t.severity == "medium"),
                "low_severity": sum(1 for t in self.threat_intel_db.values() if t.severity == "low"),
                "last_updated": current_time.isoformat()
            },
            "top_threats": self._get_top_threats(),
            "threat_trends": self._analyze_threat_trends(),
            "geographic_distribution": self._analyze_geographic_threats(),
            "threat_categories": self._categorize_threats()
        }
        
        self.analytics_cache[cache_key] = threat_data
        return threat_data
    
    def _get_top_threats(self) -> List[Dict[str, Any]]:
        """Get top threats by reputation score"""
        sorted_threats = sorted(
            self.threat_intel_db.values(),
            key=lambda x: x.reputation_score,
            reverse=True
        )[:10]
        
        return [
            {
                "ip": threat.ip_address,
                "type": threat.threat_type,
                "severity": threat.severity,
                "score": threat.reputation_score,
                "country": threat.country,
                "last_seen": threat.last_seen.isoformat(),
                "description": threat.description
            }
            for threat in sorted_threats
        ]
    
    def _analyze_threat_trends(self) -> Dict[str, Any]:
        """Analyze threat trends over time"""
        now = datetime.now()
        periods = {
            "last_hour": now - timedelta(hours=1),
            "last_24h": now - timedelta(days=1),
            "last_week": now - timedelta(weeks=1)
        }
        
        trends = {}
        for period_name, start_time in periods.items():
            period_threats = [
                t for t in self.threat_intel_db.values()
                if t.last_seen >= start_time
            ]
            
            trends[period_name] = {
                "count": len(period_threats),
                "high_severity": sum(1 for t in period_threats if t.severity == "high"),
                "types": self._count_threat_types(period_threats)
            }
        
        return trends
    
    def _analyze_geographic_threats(self) -> Dict[str, Any]:
        """Analyze threats by geographic location"""
        country_counts = defaultdict(int)
        country_severity = defaultdict(lambda: {"high": 0, "medium": 0, "low": 0})
        
        for threat in self.threat_intel_db.values():
            country_counts[threat.country] += 1
            country_severity[threat.country][threat.severity] += 1
        
        # Sort by threat count
        top_countries = sorted(
            country_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )[:15]
        
        return {
            "top_countries": [
                {
                    "country": country,
                    "count": count,
                    "severity_breakdown": dict(country_severity[country])
                }
                for country, count in top_countries
            ],
            "total_countries": len(country_counts)
        }
    
    def _categorize_threats(self) -> Dict[str, int]:
        """Categorize threats by type"""
        categories = defaultdict(int)
        for threat in self.threat_intel_db.values():
            categories[threat.threat_type] += 1
        return dict(categories)
    
    def _count_threat_types(self, threats: List[ThreatIntelligence]) -> Dict[str, int]:
        """Count threat types in a list"""
        types = defaultdict(int)
        for threat in threats:
            types[threat.threat_type] += 1
        return dict(types)
    
    async def analyze_traffic_patterns(self) -> Dict[str, Any]:
        """Analyze network traffic patterns"""
        current_time = datetime.now()
        cache_key = f"traffic_patterns_{int(current_time.timestamp() // 60)}"
        
        if cache_key in self.analytics_cache:
            return self.analytics_cache[cache_key]
        
        # Analyze recent traffic (last hour)
        recent_traffic = [
            pattern for pattern in self.traffic_patterns
            if pattern.timestamp >= current_time - timedelta(hours=1)
        ]
        
        analysis = {
            "summary": {
                "total_connections": len(recent_traffic),
                "total_bytes": sum(p.bytes_transferred for p in recent_traffic),
                "total_packets": sum(p.packets_count for p in recent_traffic),
                "avg_duration": np.mean([p.duration for p in recent_traffic]) if recent_traffic else 0,
                "analysis_time": current_time.isoformat()
            },
            "protocol_distribution": self._analyze_protocols(recent_traffic),
            "top_talkers": self._get_top_talkers(recent_traffic),
            "port_analysis": self._analyze_ports(recent_traffic),
            "traffic_timeline": self._generate_traffic_timeline(recent_traffic),
            "anomalies": self._detect_traffic_anomalies(recent_traffic)
        }
        
        self.analytics_cache[cache_key] = analysis
        return analysis
    
    def _analyze_protocols(self, traffic: List[TrafficPattern]) -> Dict[str, Any]:
        """Analyze protocol distribution"""
        protocol_stats = defaultdict(lambda: {"count": 0, "bytes": 0, "packets": 0})
        
        for pattern in traffic:
            stats = protocol_stats[pattern.protocol]
            stats["count"] += 1
            stats["bytes"] += pattern.bytes_transferred
            stats["packets"] += pattern.packets_count
        
        total_bytes = sum(stats["bytes"] for stats in protocol_stats.values())
        
        return {
            "distribution": [
                {
                    "protocol": protocol,
                    "count": stats["count"],
                    "bytes": stats["bytes"],
                    "packets": stats["packets"],
                    "percentage": (stats["bytes"] / total_bytes * 100) if total_bytes > 0 else 0
                }
                for protocol, stats in protocol_stats.items()
            ]
        }
    
    def _get_top_talkers(self, traffic: List[TrafficPattern]) -> List[Dict[str, Any]]:
        """Get top talking IP addresses"""
        ip_stats = defaultdict(lambda: {"bytes_sent": 0, "bytes_received": 0, "connections": 0})
        
        for pattern in traffic:
            src_stats = ip_stats[pattern.src_ip]
            dst_stats = ip_stats[pattern.dst_ip]
            
            src_stats["bytes_sent"] += pattern.bytes_transferred
            src_stats["connections"] += 1
            
            dst_stats["bytes_received"] += pattern.bytes_transferred
        
        # Calculate total bytes for each IP
        for ip, stats in ip_stats.items():
            stats["total_bytes"] = stats["bytes_sent"] + stats["bytes_received"]
        
        # Sort by total bytes
        top_ips = sorted(
            ip_stats.items(),
            key=lambda x: x[1]["total_bytes"],
            reverse=True
        )[:10]
        
        return [
            {
                "ip": ip,
                "total_bytes": stats["total_bytes"],
                "bytes_sent": stats["bytes_sent"],
                "bytes_received": stats["bytes_received"],
                "connections": stats["connections"],
                "country": self._get_country_for_ip(ip)
            }
            for ip, stats in top_ips
        ]
    
    def _analyze_ports(self, traffic: List[TrafficPattern]) -> Dict[str, Any]:
        """Analyze port usage"""
        port_stats = defaultdict(lambda: {"count": 0, "bytes": 0})
        
        for pattern in traffic:
            dst_port_stats = port_stats[pattern.dst_port]
            dst_port_stats["count"] += 1
            dst_port_stats["bytes"] += pattern.bytes_transferred
        
        # Get top ports
        top_ports = sorted(
            port_stats.items(),
            key=lambda x: x[1]["bytes"],
            reverse=True
        )[:20]
        
        return {
            "top_ports": [
                {
                    "port": port,
                    "count": stats["count"],
                    "bytes": stats["bytes"],
                    "service": self._get_service_name(port)
                }
                for port, stats in top_ports
            ]
        }
    
    def _generate_traffic_timeline(self, traffic: List[TrafficPattern]) -> List[Dict[str, Any]]:
        """Generate traffic timeline (5-minute intervals)"""
        timeline = defaultdict(lambda: {"bytes": 0, "packets": 0, "connections": 0})
        
        for pattern in traffic:
            # Round to 5-minute intervals
            interval = pattern.timestamp.replace(
                minute=pattern.timestamp.minute // 5 * 5,
                second=0,
                microsecond=0
            )
            
            stats = timeline[interval]
            stats["bytes"] += pattern.bytes_transferred
            stats["packets"] += pattern.packets_count
            stats["connections"] += 1
        
        # Convert to list and sort by time
        timeline_list = [
            {
                "timestamp": interval.isoformat(),
                "bytes": stats["bytes"],
                "packets": stats["packets"],
                "connections": stats["connections"]
            }
            for interval, stats in timeline.items()
        ]
        
        return sorted(timeline_list, key=lambda x: x["timestamp"])
    
    def _detect_traffic_anomalies(self, traffic: List[TrafficPattern]) -> List[Dict[str, Any]]:
        """Detect traffic anomalies"""
        anomalies = []
        
        if not traffic:
            return anomalies
        
        # Calculate statistics
        bytes_values = [p.bytes_transferred for p in traffic]
        duration_values = [p.duration for p in traffic]
        
        bytes_mean = np.mean(bytes_values)
        bytes_std = np.std(bytes_values)
        duration_mean = np.mean(duration_values)
        duration_std = np.std(duration_values)
        
        # Detect anomalies (values > 3 standard deviations from mean)
        for pattern in traffic:
            if abs(pattern.bytes_transferred - bytes_mean) > 3 * bytes_std:
                anomalies.append({
                    "type": "unusual_bytes",
                    "timestamp": pattern.timestamp.isoformat(),
                    "src_ip": pattern.src_ip,
                    "dst_ip": pattern.dst_ip,
                    "value": pattern.bytes_transferred,
                    "threshold": bytes_mean + 3 * bytes_std,
                    "description": f"Unusual byte transfer: {pattern.bytes_transferred} bytes"
                })
            
            if abs(pattern.duration - duration_mean) > 3 * duration_std:
                anomalies.append({
                    "type": "unusual_duration",
                    "timestamp": pattern.timestamp.isoformat(),
                    "src_ip": pattern.src_ip,
                    "dst_ip": pattern.dst_ip,
                    "value": pattern.duration,
                    "threshold": duration_mean + 3 * duration_std,
                    "description": f"Unusual connection duration: {pattern.duration:.2f} seconds"
                })
        
        return anomalies[:10]  # Return top 10 anomalies
    
    def _get_country_for_ip(self, ip: str) -> str:
        """Get country for IP address using GeoIP"""
        if not self.geo_db:
            return "Unknown"
        
        try:
            response = self.geo_db.city(ip)
            return response.country.name or "Unknown"
        except geoip2.errors.AddressNotFoundError:
            return "Unknown"
        except Exception:
            return "Unknown"
    
    def _get_service_name(self, port: int) -> str:
        """Get service name for port"""
        well_known_ports = {
            80: "HTTP",
            443: "HTTPS",
            22: "SSH",
            21: "FTP",
            25: "SMTP",
            53: "DNS",
            110: "POP3",
            143: "IMAP",
            993: "IMAPS",
            995: "POP3S",
            3389: "RDP",
            1433: "MSSQL",
            3306: "MySQL",
            5432: "PostgreSQL",
            6379: "Redis",
            27017: "MongoDB"
        }
        return well_known_ports.get(port, f"Port {port}")
    
    async def generate_security_report(self) -> Dict[str, Any]:
        """Generate comprehensive security report"""
        current_time = datetime.now()
        
        # Get recent security events (last 24 hours)
        recent_events = [
            event for event in self.security_events
            if event.timestamp >= current_time - timedelta(days=1)
        ]
        
        report = {
            "report_timestamp": current_time.isoformat(),
            "summary": {
                "total_events": len(recent_events),
                "critical_events": sum(1 for e in recent_events if e.severity == "critical"),
                "high_events": sum(1 for e in recent_events if e.severity == "high"),
                "medium_events": sum(1 for e in recent_events if e.severity == "medium"),
                "low_events": sum(1 for e in recent_events if e.severity == "low")
            },
            "event_timeline": self._generate_event_timeline(recent_events),
            "top_attackers": self._get_top_attackers(recent_events),
            "attack_patterns": self._analyze_attack_patterns(recent_events),
            "recommendations": self._generate_recommendations(recent_events)
        }
        
        return report
    
    def _generate_event_timeline(self, events: List[SecurityEvent]) -> List[Dict[str, Any]]:
        """Generate security event timeline"""
        timeline = defaultdict(lambda: defaultdict(int))
        
        for event in events:
            hour = event.timestamp.replace(minute=0, second=0, microsecond=0)
            timeline[hour][event.severity] += 1
        
        timeline_list = [
            {
                "timestamp": hour.isoformat(),
                "critical": counts.get("critical", 0),
                "high": counts.get("high", 0),
                "medium": counts.get("medium", 0),
                "low": counts.get("low", 0),
                "total": sum(counts.values())
            }
            for hour, counts in timeline.items()
        ]
        
        return sorted(timeline_list, key=lambda x: x["timestamp"])
    
    def _get_top_attackers(self, events: List[SecurityEvent]) -> List[Dict[str, Any]]:
        """Get top attacking IP addresses"""
        attacker_stats = defaultdict(lambda: {"count": 0, "severities": defaultdict(int)})
        
        for event in events:
            stats = attacker_stats[event.source_ip]
            stats["count"] += 1
            stats["severities"][event.severity] += 1
        
        top_attackers = sorted(
            attacker_stats.items(),
            key=lambda x: x[1]["count"],
            reverse=True
        )[:10]
        
        return [
            {
                "ip": ip,
                "count": stats["count"],
                "severities": dict(stats["severities"]),
                "country": self._get_country_for_ip(ip)
            }
            for ip, stats in top_attackers
        ]
    
    def _analyze_attack_patterns(self, events: List[SecurityEvent]) -> Dict[str, Any]:
        """Analyze attack patterns"""
        pattern_stats = defaultdict(int)
        
        for event in events:
            pattern_stats[event.event_type] += 1
        
        return {
            "attack_types": [
                {"type": attack_type, "count": count}
                for attack_type, count in sorted(
                    pattern_stats.items(),
                    key=lambda x: x[1],
                    reverse=True
                )
            ]
        }
    
    def _generate_recommendations(self, events: List[SecurityEvent]) -> List[str]:
        """Generate security recommendations based on events"""
        recommendations = []
        
        # Count events by type
        event_types = defaultdict(int)
        for event in events:
            event_types[event.event_type] += 1
        
        # Generate recommendations based on patterns
        if event_types.get("brute_force", 0) > 10:
            recommendations.append("Consider implementing rate limiting for authentication attempts")
        
        if event_types.get("port_scan", 0) > 5:
            recommendations.append("Implement port scan detection and blocking")
        
        if event_types.get("malware", 0) > 0:
            recommendations.append("Update antivirus signatures and perform system scan")
        
        if len([e for e in events if e.severity == "critical"]) > 0:
            recommendations.append("Review and investigate all critical security events immediately")
        
        return recommendations
    
    # Data ingestion methods
    async def add_threat_intelligence(self, threat: ThreatIntelligence):
        """Add threat intelligence data"""
        self.threat_intel_db[threat.ip_address] = threat
    
    async def add_traffic_pattern(self, pattern: TrafficPattern):
        """Add traffic pattern data"""
        self.traffic_patterns.append(pattern)
    
    async def add_security_event(self, event: SecurityEvent):
        """Add security event"""
        self.security_events.append(event)
    
    def cleanup_cache(self):
        """Clean up expired cache entries"""
        current_time = time.time()
        expired_keys = [
            key for key, data in self.analytics_cache.items()
            if hasattr(data, 'timestamp') and current_time - data.timestamp > self.cache_ttl
        ]
        
        for key in expired_keys:
            del self.analytics_cache[key] 