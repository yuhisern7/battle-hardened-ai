#!/usr/bin/env python3
"""
Trust Degradation Graph - Signal #20

Zero-trust enforcement engine that tracks persistent entity trust scores across
sessions. Implements non-linear trust degradation where each attack permanently
reduces trust, preventing "try again later" evasion strategies.

Trust Model:
- Entity types: IP addresses, devices, user accounts, services, APIs, cloud roles
- Trust score: 0-100 per entity
- Initial trust: Internal=100, External=60 (configurable)
- Degradation: Event-weighted penalties (minor=-5, attack=-25, lateral=-30, integrity=-40)
- Recovery: +1 trust per 24h without incident (slow, capped at baseline)
- Persistence: Trust state survives across IP changes via behavioral fingerprinting

Trust Thresholds:
- ≥80: Normal operation
- 60-79: Increased monitoring
- 40-59: Rate limiting enforced
- 20-39: Isolation, deny-by-default
- <20: Automatic quarantine + SOC alert

Integration Points:
- Feeds from Historical Reputation (Signal #14)
- Influenced by Behavioral (Signal #6), Graph Intelligence (Signal #10)
- Modulates Stage 4 response severity

Privacy:
- Entity IDs are SHA-256 hashed
- No PII or credentials stored
- Trust scores are statistical only

Author: Battle-Hardened AI Team
Version: 1.0.0
"""

import json
import os
import hashlib
import logging
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional, Tuple, Any
from datetime import datetime, timedelta, timezone
from enum import Enum
from collections import defaultdict

from AI.path_helper import get_json_dir

logger = logging.getLogger(__name__)


class EntityType(Enum):
    """Types of tracked entities"""
    IP_ADDRESS = "ip"
    DEVICE = "device"
    USER_ACCOUNT = "user"
    SERVICE = "service"
    API = "api"
    CLOUD_ROLE = "cloud_role"
    CONTAINER = "container"


class TrustAction(Enum):
    """Recommended actions based on trust level"""
    ALLOW = "allow"
    MONITOR = "monitor"
    RATE_LIMIT = "rate_limit"
    ISOLATE = "isolate"
    QUARANTINE = "quarantine"


class TrustState(Enum):
    """High-level trust state buckets used by callers.

    These map directly to score-based buckets in get_trust_score and are
    exposed primarily for convenience when interpreting trust state in
    orchestration layers.
    """

    TRUSTED = "TRUSTED"
    NORMAL = "NORMAL"
    DEGRADED = "DEGRADED"
    SUSPICIOUS = "SUSPICIOUS"
    HOSTILE = "HOSTILE"


@dataclass
class TrustStateUpdate:
    """Trust state update for an entity"""
    entity_id: str  # SHA-256 hashed identifier
    entity_type: EntityType
    previous_trust: float
    current_trust: float
    reasons: List[str]  # List of events that modified trust
    recommended_action: TrustAction
    timestamp: str
    
    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            "entity_id": self.entity_id,
            "entity_type": self.entity_type.value,
            "previous_trust": self.previous_trust,
            "current_trust": self.current_trust,
            "reasons": self.reasons,
            "recommended_action": self.recommended_action.value,
            "timestamp": self.timestamp
        }


class TrustDegradationGraph:
    """
    Trust Degradation Graph - Layer 20
    
    Persistent entity trust tracking with non-linear degradation model.
    Enforces zero-trust principles where trust never fully recovers.
    """
    
    def __init__(self, json_dir: str = "server/json"):
        """
        Initialize trust graph.
        
        Args:
            json_dir: Directory for trust graph persistence
        """
        # Use central JSON directory by default, but honor explicit overrides
        if json_dir == "server/json":
            self.json_dir = get_json_dir()
        else:
            self.json_dir = json_dir
        self.trust_graph_path = os.path.join(self.json_dir, "trust_graph.json")
        
        # Trust score configuration
        self.initial_trust_internal = 100.0  # Internal entities start at max trust
        self.initial_trust_external = 60.0   # External entities start lower
        self.max_trust = 100.0
        self.min_trust = 0.0
        
        # Event-weighted penalties
        self.penalties = {
            "minor_anomaly": -5.0,
            "failed_auth": -10.0,
            "suspicious_behavior": -15.0,
            "confirmed_attack": -25.0,
            "lateral_movement": -30.0,
            "data_exfiltration": -35.0,
            "integrity_breach": -40.0,
            "repeated_attack": -50.0  # Exponential penalty for recidivism
        }
        
        # Recovery rate: +1 trust per 24h clean behavior
        self.recovery_rate_per_day = 1.0
        self.recovery_cap_multiplier = 0.8  # Can only recover to 80% of baseline
        
        # Trust thresholds for actions
        self.thresholds = {
            TrustAction.ALLOW: 80.0,
            TrustAction.MONITOR: 60.0,
            TrustAction.RATE_LIMIT: 40.0,
            TrustAction.ISOLATE: 20.0,
            TrustAction.QUARANTINE: 0.0
        }
        
        # Load persistent trust state
        self.trust_graph = self._load_trust_graph()
        
        logger.info("[TRUST_GRAPH] Engine initialized with %d tracked entities", len(self.trust_graph))
    
    def get_entity_trust(
        self,
        entity_id: str,
        entity_type: EntityType,
        is_internal: bool = False
    ) -> float:
        """
        Get current trust score for entity.
        
        Args:
            entity_id: Entity identifier (will be hashed)
            entity_type: Type of entity
            is_internal: Whether entity is internal to organization
            
        Returns:
            Current trust score (0.0-100.0)
        """
        hashed_id = self._hash_entity_id(entity_id)
        
        if hashed_id not in self.trust_graph:
            # New entity - initialize with baseline trust
            baseline = self.initial_trust_internal if is_internal else self.initial_trust_external
            self.trust_graph[hashed_id] = {
                "entity_type": entity_type.value,
                "trust_score": baseline,
                "baseline_trust": baseline,
                "is_internal": is_internal,
                "first_seen": datetime.now(timezone.utc).isoformat(),
                "last_updated": datetime.now(timezone.utc).isoformat(),
                "last_clean_behavior": datetime.now(timezone.utc).isoformat(),
                "event_history": []
            }
            self._save_trust_graph()
        
        return self.trust_graph[hashed_id]["trust_score"]
    
    def update_trust(
        self,
        entity_id: str,
        entity_type: EntityType,
        event_type: str,
        event_details: Optional[Dict] = None,
        is_internal: bool = False
    ) -> TrustStateUpdate:
        """
        Update entity trust based on observed event.
        
        Args:
            entity_id: Entity identifier
            entity_type: Type of entity
            event_type: Type of event (maps to penalty)
            event_details: Additional event context
            is_internal: Whether entity is internal
            
        Returns:
            TrustStateUpdate with trust change details
        """
        hashed_id = self._hash_entity_id(entity_id)
        
        # Get current trust (initializes if new)
        previous_trust = self.get_entity_trust(entity_id, entity_type, is_internal)
        
        # Apply natural recovery for time elapsed since last event
        entity_data = self.trust_graph[hashed_id]
        recovered_trust = self._apply_natural_recovery(entity_data)
        
        # Apply penalty for current event
        penalty = self.penalties.get(event_type, -10.0)  # Default penalty
        
        # Check for recidivism (repeated attacks increase penalty)
        if self._is_recidivist(entity_data):
            penalty = self.penalties["repeated_attack"]
            logger.warning(f"[TRUST_GRAPH] Recidivist detected: {hashed_id[:16]}...")
        
        # Calculate new trust score
        new_trust = max(self.min_trust, min(self.max_trust, recovered_trust + penalty))
        
        # Update graph
        entity_data["trust_score"] = new_trust
        entity_data["last_updated"] = datetime.now(timezone.utc).isoformat()
        
        # Record event in history
        event_record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "penalty_applied": penalty,
            "trust_before": recovered_trust,
            "trust_after": new_trust,
            "details": event_details or {}
        }
        entity_data["event_history"].append(event_record)
        
        # Keep only last 100 events per entity
        if len(entity_data["event_history"]) > 100:
            entity_data["event_history"] = entity_data["event_history"][-100:]
        
        # If clean event, update last clean behavior timestamp
        if penalty >= 0:
            entity_data["last_clean_behavior"] = datetime.now(timezone.utc).isoformat()
        
        self._save_trust_graph()
        
        # Determine recommended action
        recommended_action = self._get_recommended_action(new_trust)
        
        reasons = [f"{event_type} (penalty: {penalty})"]
        if recovered_trust != previous_trust:
            recovery = recovered_trust - previous_trust
            reasons.append(f"Natural recovery: +{recovery:.1f}")
        
        result = TrustStateUpdate(
            entity_id=hashed_id,
            entity_type=entity_type,
            previous_trust=previous_trust,
            current_trust=new_trust,
            reasons=reasons,
            recommended_action=recommended_action,
            timestamp=datetime.now(timezone.utc).isoformat()
        )
        
        logger.info(
            f"[TRUST_GRAPH] {entity_type.value} {hashed_id[:16]}... trust: "
            f"{previous_trust:.1f} → {new_trust:.1f} (action: {recommended_action.value})"
        )
        
        return result
    
    def _apply_natural_recovery(self, entity_data: Dict) -> float:
        """Apply natural trust recovery based on time since last incident."""
        current_trust = entity_data["trust_score"]
        baseline_trust = entity_data["baseline_trust"]
        recovery_cap = baseline_trust * self.recovery_cap_multiplier
        
        # Can't recover past the cap
        if current_trust >= recovery_cap:
            return current_trust
        
        # Calculate time since last clean behavior
        last_clean = datetime.fromisoformat(entity_data["last_clean_behavior"].replace('Z', '+00:00'))
        now = datetime.now(timezone.utc)
        days_clean = (now - last_clean).total_seconds() / 86400
        
        # Apply recovery: +1 per day, capped
        recovery = days_clean * self.recovery_rate_per_day
        recovered_trust = min(recovery_cap, current_trust + recovery)
        
        return recovered_trust
    
    def _is_recidivist(self, entity_data: Dict) -> bool:
        """Check if entity is a repeat offender."""
        event_history = entity_data.get("event_history", [])
        
        if len(event_history) < 2:
            return False
        
        # Count attacks in last 7 days
        now = datetime.now(timezone.utc)
        seven_days_ago = now - timedelta(days=7)
        
        recent_attacks = 0
        for event in event_history[-20:]:  # Check last 20 events
            event_time = datetime.fromisoformat(event["timestamp"].replace('Z', '+00:00'))
            if event_time > seven_days_ago:
                if event["penalty_applied"] <= -20:  # Significant attack
                    recent_attacks += 1
        
        return recent_attacks >= 3  # 3+ attacks in 7 days = recidivist
    
    def _get_recommended_action(self, trust_score: float) -> TrustAction:
        """Get recommended action based on trust score."""
        if trust_score >= self.thresholds[TrustAction.ALLOW]:
            return TrustAction.ALLOW
        elif trust_score >= self.thresholds[TrustAction.MONITOR]:
            return TrustAction.MONITOR
        elif trust_score >= self.thresholds[TrustAction.RATE_LIMIT]:
            return TrustAction.RATE_LIMIT
        elif trust_score >= self.thresholds[TrustAction.ISOLATE]:
            return TrustAction.ISOLATE
        else:
            return TrustAction.QUARANTINE
    
    def _hash_entity_id(self, entity_id: str) -> str:
        """Hash entity ID for privacy."""
        return hashlib.sha256(entity_id.encode()).hexdigest()
    
    def _load_trust_graph(self) -> Dict:
        """Load persistent trust graph from disk."""
        try:
            if os.path.exists(self.trust_graph_path):
                with open(self.trust_graph_path, 'r') as f:
                    data = json.load(f)
                    logger.info(f"[TRUST_GRAPH] Loaded {len(data)} entities from disk")
                    return data
        except Exception as e:
            logger.error(f"[TRUST_GRAPH] Failed to load trust graph: {e}")
        
        return {}
    
    def _save_trust_graph(self):
        """Save trust graph to disk."""
        try:
            os.makedirs(self.json_dir, exist_ok=True)
            
            with open(self.trust_graph_path, 'w') as f:
                json.dump(self.trust_graph, f, indent=2)
            
            logger.debug(f"[TRUST_GRAPH] Saved {len(self.trust_graph)} entities to disk")
        
        except Exception as e:
            logger.error(f"[TRUST_GRAPH] Failed to save trust graph: {e}")
    
    def get_low_trust_entities(self, threshold: float = 40.0, limit: int = 100) -> List[Dict]:
        """Get entities with trust below threshold."""
        low_trust = []
        
        for entity_id, data in self.trust_graph.items():
            if data["trust_score"] < threshold:
                low_trust.append({
                    "entity_id": entity_id[:16] + "...",  # Truncated for display
                    "entity_type": data["entity_type"],
                    "trust_score": data["trust_score"],
                    "baseline_trust": data["baseline_trust"],
                    "is_internal": data["is_internal"],
                    "first_seen": data["first_seen"],
                    "last_updated": data["last_updated"],
                    "event_count": len(data["event_history"])
                })
        
        # Sort by trust score (lowest first)
        low_trust.sort(key=lambda x: x["trust_score"])
        
        return low_trust[:limit]
    
    def get_trust_statistics(self) -> Dict:
        """Get overall trust statistics."""
        if not self.trust_graph:
            return {
                "total_entities": 0,
                "avg_trust": 0.0,
                "low_trust_count": 0,
                "quarantine_count": 0
            }
        
        trust_scores = [data["trust_score"] for data in self.trust_graph.values()]
        
        return {
            "total_entities": len(self.trust_graph),
            "avg_trust": sum(trust_scores) / len(trust_scores),
            "low_trust_count": sum(1 for score in trust_scores if score < 40.0),
            "quarantine_count": sum(1 for score in trust_scores if score < 20.0),
            "trust_distribution": {
                "high (≥80)": sum(1 for score in trust_scores if score >= 80),
                "normal (60-79)": sum(1 for score in trust_scores if 60 <= score < 80),
                "degraded (40-59)": sum(1 for score in trust_scores if 40 <= score < 60),
                "low (20-39)": sum(1 for score in trust_scores if 20 <= score < 40),
                "critical (<20)": sum(1 for score in trust_scores if score < 20)
            }
        }


# Singleton instance
_trust_graph_instance = None


def get_trust_graph() -> TrustDegradationGraph:
    """Get singleton trust degradation graph instance."""
    global _trust_graph_instance
    if _trust_graph_instance is None:
        _trust_graph_instance = TrustDegradationGraph()
    return _trust_graph_instance


def track_entity(entity_id: str, event_type: str, event_data: Dict,
                entity_type: EntityType = EntityType.IP_ADDRESS) -> None:
    """Convenience function to track entity behavior.
    
    Args:
        entity_id: Entity identifier (e.g., IP address)
        event_type: Type of event for penalty mapping
        event_data: Event details
        entity_type: Type of entity (default: IP_ADDRESS)
    """
    graph = get_trust_graph()
    graph.update_trust(
        entity_id=entity_id,
        entity_type=entity_type,
        event_type=event_type,
        event_details=event_data
    )


def get_trust_score(entity_id: str) -> Optional[Dict]:
    """Get trust score for an entity.
    
    Returns:
        Dict with keys: trust_score, state, total_events, threat_events
        None if entity not found
    """
    graph = get_trust_graph()
    entity_data = graph.get_entity_trust(entity_id, EntityType.IP_ADDRESS)
    
    if entity_data is None:
        return None
    
    # entity_data is just a float trust score from get_entity_trust
    # We need to construct a full dict
    trust_score = entity_data if isinstance(entity_data, float) else 60.0
    
    # Determine state from score
    if trust_score >= 80.0:
        state = 'TRUSTED'
    elif trust_score >= 60.0:
        state = 'NORMAL'
    elif trust_score >= 40.0:
        state = 'DEGRADED'
    elif trust_score >= 20.0:
        state = 'SUSPICIOUS'
    else:
        state = 'HOSTILE'
    
    return {
        'trust_score': trust_score,
        'state': state,
        'total_events': 0,  # TODO: Track this in trust graph
        'threat_events': 0   # TODO: Track this in trust graph
    }


def get_low_trust_entities(threshold: float = 40.0, limit: int = 100) -> List[Dict]:
    """Get entities with low trust scores."""
    graph = get_trust_graph()
    return graph.get_low_trust_entities(threshold, limit)
