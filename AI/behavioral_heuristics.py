#!/usr/bin/env python3
"""
Behavioral Heuristics Engine
Tracks per-IP and per-entity metrics to generate behavior-based risk scores.

PRIVACY: All metrics stay LOCAL - never shared with relay.
NO content inspection - only traffic patterns and metadata.

Metrics Tracked:
- Connection rate (connections/min)
- Retry frequency (failed connection attempts)
- Authentication failure ratios
- Port entropy (Shannon entropy of accessed ports)
- Timing variance (request interval consistency)
- Fan-out (unique destination IPs contacted)
- Fan-in (unique source ports used)
- Protocol distribution
- Payload size patterns
"""

import time
import math
import json
import os
from datetime import datetime, timedelta
from collections import defaultdict, deque
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
import logging

from AI.path_helper import get_json_dir

logger = logging.getLogger(__name__)


@dataclass
class BehaviorMetrics:
    """Behavioral metrics for a single entity (IP/device/user)"""
    entity_id: str
    
    # Connection patterns
    connection_count_1min: int = 0
    connection_count_5min: int = 0
    connection_count_15min: int = 0
    
    # Retry behavior
    retry_count: int = 0
    retry_frequency: float = 0.0  # retries per minute
    
    # Authentication
    auth_attempts: int = 0
    auth_failures: int = 0
    auth_failure_ratio: float = 0.0
    
    # Port diversity
    unique_ports: int = 0
    port_entropy: float = 0.0
    
    # Timing patterns
    avg_interval: float = 0.0
    timing_variance: float = 0.0
    
    # Network behavior
    fan_out: int = 0  # Unique destination IPs
    fan_in: int = 0   # Unique source ports
    
    # Protocol distribution
    tcp_count: int = 0
    udp_count: int = 0
    icmp_count: int = 0
    
    # Payload patterns
    avg_payload_size: float = 0.0
    payload_variance: float = 0.0
    
    # Timestamps
    first_seen: float = 0.0
    last_seen: float = 0.0
    
    # Risk assessment
    # heuristic_score is the internal continuous score (0.0-1.0)
    # risk_score mirrors heuristic_score for external consumers (0.0-1.0)
    heuristic_score: float = 0.0  # 0.0 (benign) to 1.0 (malicious)
    risk_score: float = 0.0
    risk_factors: List[str] = None
    
    # APT-specific indicators
    low_and_slow_score: float = 0.0  # Sustained low-rate activity
    living_off_land_score: float = 0.0  # Legitimate tools used maliciously
    off_hours_activity: bool = False  # Activity during unusual hours
    credential_reuse_attempts: int = 0  # Same creds across services
    
    def __post_init__(self):
        if self.risk_factors is None:
            self.risk_factors = []


class BehavioralHeuristics:
    """
    Behavioral heuristics engine for network security.
    Tracks entity behavior using rolling time windows.
    """
    
    def __init__(self, storage_dir: Optional[str] = None):
        # Use centralized JSON directory helper by default
        default_dir = get_json_dir()
        self.storage_dir = storage_dir or default_dir
        os.makedirs(self.storage_dir, exist_ok=True)
        self.metrics_file = os.path.join(self.storage_dir, 'behavioral_metrics.json')
        
        # Entity tracking
        self.entities: Dict[str, BehaviorMetrics] = {}
        
        # Time-windowed event buffers (for rolling metrics)
        self.connection_events = defaultdict(lambda: deque(maxlen=1000))
        self.auth_events = defaultdict(lambda: deque(maxlen=500))
        self.timing_events = defaultdict(lambda: deque(maxlen=100))
        self.port_events = defaultdict(lambda: deque(maxlen=500))
        self.destination_ips = defaultdict(set)
        self.source_ports = defaultdict(set)
        self.payload_sizes = defaultdict(lambda: deque(maxlen=100))
        
        # APT-specific tracking
        self.apt_indicators = {}  # entity_id -> APT behavior patterns
        
        # Thresholds for risk scoring
        self.thresholds = {
            'connection_rate_1min': 60,      # >60 conn/min suspicious
            'connection_rate_5min': 200,     # >200 conn/5min suspicious
            'retry_frequency': 10,           # >10 retries/min suspicious
            'auth_failure_ratio': 0.5,       # >50% auth failures suspicious
            'port_entropy': 4.0,             # >4.0 entropy indicates scanning
            'timing_variance': 0.8,          # High variance = inconsistent behavior
            'fan_out': 50,                   # Contacting >50 IPs suspicious
            'fan_in': 20,                    # Using >20 source ports suspicious
            'avg_payload_large': 10000,      # Average payload >10KB suspicious (possible exfil)
            'payload_variance_high': 20000,  # Very bursty payload sizes suspicious
        }
        
        # Cleanup interval
        self.last_cleanup = time.time()
        self.cleanup_interval = 300  # 5 minutes
        
        # Load existing metrics
        self.load_metrics()
    
    def track_connection(self, entity_id: str, dest_ip: str = None, 
                        dest_port: int = None, src_port: int = None,
                        protocol: str = 'tcp', payload_size: int = 0) -> None:
        """
        Track a connection event for behavioral analysis.
        
        Args:
            entity_id: IP address or device identifier
            dest_ip: Destination IP (for fan-out tracking)
            dest_port: Destination port (for entropy calculation)
            src_port: Source port (for fan-in tracking)
            protocol: Protocol type (tcp/udp/icmp)
            payload_size: Request payload size in bytes
        """
        now = time.time()
        
        # Initialize entity if new
        if entity_id not in self.entities:
            self.entities[entity_id] = BehaviorMetrics(
                entity_id=entity_id,
                first_seen=now,
                last_seen=now
            )
        
        entity = self.entities[entity_id]
        entity.last_seen = now
        
        # Track connection event
        self.connection_events[entity_id].append(now)
        
        # Track timing intervals
        if len(self.timing_events[entity_id]) > 0:
            interval = now - self.timing_events[entity_id][-1]
            self.timing_events[entity_id].append(now)
        else:
            self.timing_events[entity_id].append(now)
        
        # Track port access
        if dest_port:
            self.port_events[entity_id].append(dest_port)
        
        # Track destination IPs (fan-out)
        if dest_ip:
            self.destination_ips[entity_id].add(dest_ip)
        
        # Track source ports (fan-in)
        if src_port:
            self.source_ports[entity_id].add(src_port)
        
        # Track protocol
        if protocol.lower() == 'tcp':
            entity.tcp_count += 1
        elif protocol.lower() == 'udp':
            entity.udp_count += 1
        elif protocol.lower() == 'icmp':
            entity.icmp_count += 1
        
        # Track payload size
        if payload_size > 0:
            self.payload_sizes[entity_id].append(payload_size)
        
        # Update metrics
        self._update_metrics(entity_id)
    
    def track_retry(self, entity_id: str) -> None:
        """Track a connection retry (failed attempt)"""
        if entity_id not in self.entities:
            self.track_connection(entity_id)
        
        self.entities[entity_id].retry_count += 1
        self._update_metrics(entity_id)
    
    def track_auth_attempt(self, entity_id: str, success: bool) -> None:
        """Track an authentication attempt"""
        now = time.time()
        
        if entity_id not in self.entities:
            self.track_connection(entity_id)
        
        entity = self.entities[entity_id]
        entity.auth_attempts += 1
        
        if not success:
            entity.auth_failures += 1
        
        self.auth_events[entity_id].append((now, success))
        self._update_metrics(entity_id)
    
    def _update_metrics(self, entity_id: str) -> None:
        """Recalculate all metrics for an entity"""
        entity = self.entities[entity_id]
        now = time.time()
        
        # Connection rate (rolling windows)
        conn_events = self.connection_events[entity_id]
        entity.connection_count_1min = sum(1 for t in conn_events if now - t <= 60)
        entity.connection_count_5min = sum(1 for t in conn_events if now - t <= 300)
        entity.connection_count_15min = sum(1 for t in conn_events if now - t <= 900)
        
        # Retry frequency
        if entity.retry_count > 0 and len(conn_events) > 0:
            time_span = now - entity.first_seen
            entity.retry_frequency = (entity.retry_count / max(time_span / 60, 1))
        
        # Authentication failure ratio
        if entity.auth_attempts > 0:
            entity.auth_failure_ratio = entity.auth_failures / entity.auth_attempts
        
        # Port entropy (Shannon entropy)
        ports = list(self.port_events[entity_id])
        if len(ports) > 1:
            entity.unique_ports = len(set(ports))
            entity.port_entropy = self._calculate_entropy(ports)
        
        # Timing variance
        timing_events = list(self.timing_events[entity_id])
        if len(timing_events) > 2:
            intervals = [timing_events[i] - timing_events[i-1] 
                        for i in range(1, len(timing_events))]
            entity.avg_interval = sum(intervals) / len(intervals)
            entity.timing_variance = self._calculate_variance(intervals)
        
        # Fan-out and fan-in
        entity.fan_out = len(self.destination_ips[entity_id])
        entity.fan_in = len(self.source_ports[entity_id])
        
        # Payload statistics
        payloads = list(self.payload_sizes[entity_id])
        if len(payloads) > 0:
            entity.avg_payload_size = sum(payloads) / len(payloads)
            entity.payload_variance = self._calculate_variance(payloads)
        
        # Calculate heuristic risk score
        entity.heuristic_score = self._calculate_risk_score(entity)
        # Expose the same value via risk_score for external consumers
        entity.risk_score = entity.heuristic_score
    
    def _calculate_entropy(self, values: List[int]) -> float:
        """Calculate Shannon entropy of a list of values"""
        if not values:
            return 0.0
        
        freq = defaultdict(int)
        for val in values:
            freq[val] += 1
        
        total = len(values)
        entropy = 0.0
        
        for count in freq.values():
            p = count / total
            if p > 0:
                entropy -= p * math.log2(p)
        
        return entropy
    
    def _calculate_variance(self, values: List[float]) -> float:
        """Calculate variance of a list of values"""
        if len(values) < 2:
            return 0.0
        
        mean = sum(values) / len(values)
        variance = sum((x - mean) ** 2 for x in values) / len(values)
        return math.sqrt(variance)  # Return standard deviation
    
    def _calculate_risk_score(self, entity: BehaviorMetrics) -> float:
        """
        Calculate heuristic risk score (0.0 to 1.0) based on behavioral metrics.
        Multiple weak signals must agree for high score.
        """
        risk_factors = []
        score = 0.0
        
        # Connection rate analysis
        if entity.connection_count_1min > self.thresholds['connection_rate_1min']:
            score += 0.15
            risk_factors.append(f"High conn rate: {entity.connection_count_1min}/min")
        
        if entity.connection_count_5min > self.thresholds['connection_rate_5min']:
            score += 0.10
            risk_factors.append(f"Sustained high rate: {entity.connection_count_5min}/5min")
        
        # Retry behavior
        if entity.retry_frequency > self.thresholds['retry_frequency']:
            score += 0.15
            risk_factors.append(f"High retry rate: {entity.retry_frequency:.1f}/min")
        
        # Authentication failures
        if entity.auth_failure_ratio > self.thresholds['auth_failure_ratio']:
            score += 0.20
            risk_factors.append(f"Auth failures: {entity.auth_failure_ratio*100:.0f}%")
        
        # Port scanning indicator
        if entity.port_entropy > self.thresholds['port_entropy']:
            score += 0.15
            risk_factors.append(f"Port scanning: entropy {entity.port_entropy:.2f}")
        
        # Timing inconsistency
        if entity.timing_variance > self.thresholds['timing_variance']:
            score += 0.05
            risk_factors.append(f"Inconsistent timing: {entity.timing_variance:.2f}")
        
        # Fan-out (lateral movement indicator)
        if entity.fan_out > self.thresholds['fan_out']:
            score += 0.10
            risk_factors.append(f"High fan-out: {entity.fan_out} destinations")
        
        # Fan-in (port hopping)
        if entity.fan_in > self.thresholds['fan_in']:
            score += 0.10
            risk_factors.append(f"Port hopping: {entity.fan_in} source ports")

        # Payload-based indicators (possible exfiltration or scanning via large/bursty traffic)
        if entity.avg_payload_size > self.thresholds['avg_payload_large']:
            score += 0.10
            risk_factors.append(f"Large avg payload: {entity.avg_payload_size:.0f} bytes")

        if entity.payload_variance > self.thresholds['payload_variance_high']:
            score += 0.05
            risk_factors.append(f"Bursty payload sizes: σ≈{entity.payload_variance:.0f}")

        # Multi-signal agreement bonus: require several weak signals instead of any single one
        if len(risk_factors) >= 3:
            score += 0.10
            risk_factors.append(f"Multi-signal agreement ({len(risk_factors)-1} factors)")
        
        # Normalize to 0-1 range
        score = min(score, 1.0)
        
        entity.risk_factors = risk_factors
        return score
    
    def get_entity_metrics(self, entity_id: str) -> Optional[BehaviorMetrics]:
        """Get metrics for a specific entity"""
        return self.entities.get(entity_id)
    
    def get_high_risk_entities(self, threshold: float = 0.7) -> List[BehaviorMetrics]:
        """Get all entities with heuristic score >= threshold"""
        return [
            entity for entity in self.entities.values()
            if entity.heuristic_score >= threshold
        ]
    
    def get_stats(self) -> Dict:
        """Get overall statistics"""
        if not self.entities:
            return {
                'total_entities': 0,
                'high_risk_entities': 0,
                'avg_risk_score': 0.0
            }
        
        scores = [e.heuristic_score for e in self.entities.values()]
        high_risk = sum(1 for s in scores if s >= 0.7)
        
        return {
            'total_entities': len(self.entities),
            'high_risk_entities': high_risk,
            'avg_risk_score': sum(scores) / len(scores),
            'entities_tracked': list(self.entities.keys())[:10]  # Sample
        }
    
    def cleanup_old_entities(self, max_age_seconds: int = 3600) -> int:
        """Remove entities not seen in max_age_seconds"""
        now = time.time()
        removed = 0
        
        for entity_id in list(self.entities.keys()):
            entity = self.entities[entity_id]
            if now - entity.last_seen > max_age_seconds:
                del self.entities[entity_id]
                # Clean up buffers
                if entity_id in self.connection_events:
                    del self.connection_events[entity_id]
                if entity_id in self.auth_events:
                    del self.auth_events[entity_id]
                if entity_id in self.timing_events:
                    del self.timing_events[entity_id]
                if entity_id in self.port_events:
                    del self.port_events[entity_id]
                if entity_id in self.destination_ips:
                    del self.destination_ips[entity_id]
                if entity_id in self.source_ports:
                    del self.source_ports[entity_id]
                if entity_id in self.payload_sizes:
                    del self.payload_sizes[entity_id]
                removed += 1
        
        logger.info(f"[BEHAVIORAL] Cleaned up {removed} old entities")
        return removed
    
    def save_metrics(self) -> bool:
        """Save metrics to disk (for persistence)"""
        try:
            # Convert to serializable format
            data = {
                'entities': {
                    entity_id: asdict(entity)
                    for entity_id, entity in self.entities.items()
                },
                'last_updated': datetime.now().isoformat()
            }
            
            with open(self.metrics_file, 'w') as f:
                json.dump(data, f, indent=2)
            
            return True
        except Exception as e:
            logger.error(f"[BEHAVIORAL] Failed to save metrics: {e}")
            return False
    
    def load_metrics(self) -> bool:
        """Load metrics from disk"""
        try:
            if not os.path.exists(self.metrics_file):
                return False
            
            with open(self.metrics_file, 'r') as f:
                data = json.load(f)
            
            # Restore entities
            for entity_id, entity_data in data.get('entities', {}).items():
                self.entities[entity_id] = BehaviorMetrics(**entity_data)
            
            logger.info(f"[BEHAVIORAL] Loaded {len(self.entities)} entities from disk")
            return True
        except Exception as e:
            logger.error(f"[BEHAVIORAL] Failed to load metrics: {e}")
            return False


# Global instance
_behavioral_heuristics = None


def get_behavioral_heuristics() -> BehavioralHeuristics:
    """Get or create global behavioral heuristics instance"""
    global _behavioral_heuristics
    if _behavioral_heuristics is None:
        _behavioral_heuristics = BehavioralHeuristics()
    return _behavioral_heuristics


# Convenience functions
def track_connection(entity_id: str, **kwargs) -> None:
    """Track a connection event"""
    get_behavioral_heuristics().track_connection(entity_id, **kwargs)


def track_retry(entity_id: str) -> None:
    """Track a retry event"""
    get_behavioral_heuristics().track_retry(entity_id)


def track_auth_attempt(entity_id: str, success: bool) -> None:
    """Track an authentication attempt"""
    get_behavioral_heuristics().track_auth_attempt(entity_id, success)


def detect_low_and_slow(entity_id: str, time_window_hours: int = 24) -> float:
    """Detect low-and-slow APT attacks"""
    heuristics = get_behavioral_heuristics()
    
    if entity_id not in heuristics.entities:
        return 0.0
    
    metrics = heuristics.entities[entity_id]
    
    # Calculate sustained connection rate over extended period
    if metrics.connection_count_15min == 0:
        return 0.0
    
    # Very low rate (< 5 connections per 15 min) sustained = suspicious
    if metrics.connection_count_15min < 5 and (time.time() - metrics.first_seen) > 7200:
        # Higher score for longer sustained periods
        sustained_hours = (time.time() - metrics.first_seen) / 3600
        score = min(0.3 + (sustained_hours / 48) * 0.5, 0.8)  # Cap at 0.8
        return score
    
    return 0.0


def detect_off_hours_activity(entity_id: str, target_timezone: str = 'UTC') -> bool:
    """Detect activity during off-hours (common APT tactic)"""
    import pytz
    from datetime import datetime
    
    try:
        tz = pytz.timezone(target_timezone)
    except:
        tz = pytz.UTC
    
    now = datetime.now(tz)
    hour = now.hour
    
    # Off-hours: 22:00 - 06:00
    # In production, would track per-entity activity patterns
    return hour >= 22 or hour < 6


def detect_credential_reuse(entity_id: str, auth_pattern: str) -> int:
    """Track credential reuse across multiple services"""
    heuristics = get_behavioral_heuristics()
    
    if entity_id not in heuristics.apt_indicators:
        heuristics.apt_indicators[entity_id] = {
            'credential_patterns': defaultdict(int),
            'services_targeted': set()
        }
    
    heuristics.apt_indicators[entity_id]['credential_patterns'][auth_pattern] += 1
    return heuristics.apt_indicators[entity_id]['credential_patterns'][auth_pattern]


def get_entity_risk_score(entity_id: str) -> float:
    """Get risk score for an entity"""
    entity = get_behavioral_heuristics().get_entity_metrics(entity_id)
    return entity.heuristic_score if entity else 0.0


def get_stats() -> Dict:
    """Get behavioral heuristics statistics"""
    return get_behavioral_heuristics().get_stats()
