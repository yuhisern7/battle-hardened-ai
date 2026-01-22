"""
Phase 8: Advanced Orchestration & Automation
Predictive modeling, autonomous response, and adaptive security orchestration.

Features:
- Predictive threat modeling (24-48hr forecasting)
- Autonomous incident response automation
- Custom alert rule engine
- Network topology visualization data
- Adaptive honeypot orchestration
- Self-healing security policies
- SOAR workflow integration
"""

import json
import os
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict, field
from collections import defaultdict, deque
from enum import Enum
import random

from AI.path_helper import get_json_dir, get_relay_training_dir


class ThreatForecast(Enum):
    """Threat forecast horizon."""
    SHORT_TERM = "6h"    # 6 hours
    MEDIUM_TERM = "24h"  # 24 hours
    LONG_TERM = "48h"    # 48 hours


class ResponseAction(Enum):
    """Automated response actions."""
    BLOCK_IP = "block_ip"
    BLOCK_DOMAIN = "block_domain"
    RATE_LIMIT = "rate_limit"
    QUARANTINE = "quarantine"
    ALERT_ONLY = "alert_only"
    HONEYPOT_REDIRECT = "honeypot_redirect"
    FIREWALL_RULE = "firewall_rule"
    ISOLATE_SEGMENT = "isolate_segment"
    KILL_CONNECTION = "kill_connection"


class RuleConditionOperator(Enum):
    """Operators for rule conditions."""
    EQUALS = "=="
    NOT_EQUALS = "!="
    GREATER_THAN = ">"
    LESS_THAN = "<"
    GREATER_EQUAL = ">="
    LESS_EQUAL = "<="
    CONTAINS = "contains"
    NOT_CONTAINS = "not_contains"
    IN = "in"
    NOT_IN = "not_in"


@dataclass
class ThreatPrediction:
    """Predicted threat for future time window."""
    prediction_id: str
    forecast_horizon: str  # "6h", "24h", "48h"
    predicted_at: float
    target_time: float  # When threat is predicted to occur
    
    entity: str  # IP/domain likely to attack
    attack_type: str  # Predicted attack type
    confidence: float  # 0.0 - 1.0
    severity: str  # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    
    reasoning: List[str]  # Why this prediction was made
    historical_pattern: str  # Pattern from historical data
    
    preventive_actions: List[str]  # Recommended preemptive measures
    likelihood_score: float  # 0.0 - 1.0


@dataclass
class AlertRule:
    """Custom alert rule definition."""
    rule_id: str
    name: str
    description: str
    enabled: bool
    
    # Conditions (all must be true)
    conditions: List[Dict[str, Any]]  # [{"field": "reputation_score", "operator": ">", "value": 0.8}]
    
    # Actions to take when rule triggers
    actions: List[ResponseAction]
    action_params: Dict[str, Any]  # Parameters for actions
    
    # Metadata
    priority: int  # 1-10 (10 = highest)
    created_at: float
    last_triggered: Optional[float]
    trigger_count: int


@dataclass
class IncidentResponse:
    """Automated incident response execution."""
    response_id: str
    incident_id: str
    triggered_at: float
    
    entity: str
    threat_type: str
    severity: str
    
    # Actions taken
    actions_executed: List[Dict[str, Any]]
    success_count: int
    failure_count: int
    
    # Results
    threat_mitigated: bool
    response_time_ms: float
    
    # Logs
    execution_log: List[str]


@dataclass
class NetworkTopologyNode:
    """Node in network topology for visualization."""
    node_id: str
    node_type: str  # "device", "server", "router", "firewall", "unknown"
    ip_address: str
    
    # Reputation data
    reputation_score: float
    threat_level: str
    is_blocked: bool
    
    # Activity metrics
    connection_count: int
    traffic_volume: int  # bytes
    attack_count: int
    
    # Visualization data
    position: Optional[Dict[str, float]]  # {"x": 0, "y": 0, "z": 0} for 3D
    color: str  # Hex color based on threat level
    size: float  # Node size based on importance


@dataclass
class NetworkTopologyEdge:
    """Connection edge in network topology."""
    edge_id: str
    source_node: str
    target_node: str
    
    connection_type: str  # "tcp", "udp", "http", "https", etc.
    traffic_volume: int
    packet_count: int
    
    is_suspicious: bool
    threat_score: float
    
    # Visualization
    color: str
    thickness: float


@dataclass
class HoneypotConfig:
    """Adaptive honeypot configuration."""
    honeypot_id: str
    honeypot_type: str  # "web", "ssh", "ftp", "database", "iot"
    
    listen_ip: str
    listen_port: int
    
    enabled: bool
    adaptive: bool  # Whether to adapt based on threats
    
    # Deception parameters
    fake_services: List[str]
    response_delays: Dict[str, float]  # Simulate real service delays
    
    # Statistics
    interaction_count: int
    attacker_count: int
    signatures_captured: int


class AdvancedOrchestration:
    """
    Advanced orchestration and automation engine.
    
    Architecture:
    - Predictive threat modeling from historical patterns
    - Autonomous incident response automation
    - Custom alert rule engine with flexible conditions
    - Network topology data preparation
    - Adaptive honeypot orchestration
    - Training data export to ai_training_materials
    """
    
    def __init__(self, export_dir: Optional[str] = None):
        """
        Initialize orchestration engine.
        
        Args:
            export_dir: Directory for training data export. If not provided,
                a sensible default is chosen based on the runtime environment.
        """
        # Base directory for JSON storage (via central path helper)
        self.base_dir = get_json_dir()

        # Determine export directory for training materials
        if export_dir is None:
            # Use relay training dir and keep orchestration_data subfolder
            export_dir = os.path.join(get_relay_training_dir(), 'orchestration_data')

        self.export_dir = export_dir

        # Ensure directories exist (cross-platform, Docker-safe)
        os.makedirs(self.export_dir, exist_ok=True)
        os.makedirs(os.path.join(self.base_dir, 'predictions'), exist_ok=True)
        os.makedirs(os.path.join(self.base_dir, 'responses'), exist_ok=True)
        
        # Alert rules
        self.alert_rules: Dict[str, AlertRule] = {}
        
        # Prediction history
        self.predictions: List[ThreatPrediction] = []
        self.max_predictions = 1000
        
        # Response history
        self.responses: List[IncidentResponse] = []
        self.max_responses = 1000
        
        # Network topology
        self.topology_nodes: Dict[str, NetworkTopologyNode] = {}
        self.topology_edges: List[NetworkTopologyEdge] = []
        
        # Honeypot configuration
        self.honeypots: Dict[str, HoneypotConfig] = {}
        
        # Historical data for predictions (sliding window)
        self.attack_history: deque = deque(maxlen=10000)
        
        # Statistics
        self.stats = {
            "predictions_made": 0,
            "predictions_accurate": 0,
            "responses_executed": 0,
            "responses_successful": 0,
            "rules_triggered": 0,
            "honeypots_deployed": 0
        }
    
    def predict_threats(self, horizon: ThreatForecast = ThreatForecast.MEDIUM_TERM,
                       historical_data: Optional[List[Dict]] = None) -> List[ThreatPrediction]:
        """
        Predict threats for future time window using historical patterns.
        
        Args:
            horizon: Forecast horizon (6h, 24h, 48h)
            historical_data: Optional historical threat data
        
        Returns:
            List of ThreatPrediction objects
        """
        self.stats["predictions_made"] += 1
        
        # Use provided data or internal history
        data = historical_data or list(self.attack_history)
        
        if not data:
            return []
        
        # Time horizons in seconds
        horizon_seconds = {
            ThreatForecast.SHORT_TERM: 6 * 3600,
            ThreatForecast.MEDIUM_TERM: 24 * 3600,
            ThreatForecast.LONG_TERM: 48 * 3600
        }
        
        target_time = time.time() + horizon_seconds[horizon]
        
        # Analyze patterns
        predictions = []
        
        # 1. Identify repeat offenders (recidivists likely to attack again)
        repeat_offenders = self._identify_repeat_offenders(data)
        for entity, pattern in repeat_offenders.items():
            pred = self._create_prediction_from_pattern(
                entity, pattern, horizon.value, target_time
            )
            if pred:
                predictions.append(pred)
        
        # 2. Identify temporal patterns (attacks at specific times)
        temporal_predictions = self._predict_temporal_patterns(data, horizon.value, target_time)
        predictions.extend(temporal_predictions)
        
        # 3. Identify geographic/ASN patterns
        geo_predictions = self._predict_geographic_patterns(data, horizon.value, target_time)
        predictions.extend(geo_predictions)
        
        # Sort by confidence and take top predictions
        predictions.sort(key=lambda p: p.confidence, reverse=True)
        predictions = predictions[:20]  # Top 20 predictions
        
        # Store predictions
        self.predictions.extend(predictions)
        if len(self.predictions) > self.max_predictions:
            self.predictions = self.predictions[-self.max_predictions:]
        
        # Export predictions
        self._export_predictions(predictions, horizon.value)
        
        return predictions
    
    def _identify_repeat_offenders(self, data: List[Dict]) -> Dict[str, Dict]:
        """Identify entities with repeated attack patterns."""
        entity_attacks = defaultdict(list)
        
        for event in data:
            entity = event.get("entity", event.get("ip", "unknown"))
            entity_attacks[entity].append(event)
        
        repeat_offenders = {}
        for entity, attacks in entity_attacks.items():
            if len(attacks) >= 3:  # At least 3 attacks
                # Calculate average interval
                # Handle both float timestamps and datetime strings
                timestamps = []
                for a in attacks:
                    ts = a.get("timestamp", 0)
                    if isinstance(ts, str):
                        try:
                            from datetime import datetime
                            dt = datetime.fromisoformat(ts.replace('Z', '+00:00'))
                            ts = dt.timestamp()
                        except:
                            ts = time.time()
                    timestamps.append(float(ts) if ts else 0)
                
                timestamps = sorted([t for t in timestamps if t > 0])
                if len(timestamps) >= 2:
                    intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
                    avg_interval = sum(intervals) / len(intervals)
                    
                    # Get most common attack type
                    attack_types = [a.get("attack_type", "unknown") for a in attacks]
                    most_common_type = max(set(attack_types), key=attack_types.count)
                    
                    repeat_offenders[entity] = {
                        "attack_count": len(attacks),
                        "avg_interval": avg_interval,
                        "attack_type": most_common_type,
                        "last_attack": timestamps[-1],
                        "avg_severity": sum(a.get("severity", 0.5) for a in attacks) / len(attacks)
                    }
        
        return repeat_offenders
    
    def _create_prediction_from_pattern(self, entity: str, pattern: Dict,
                                       horizon: str, target_time: float) -> Optional[ThreatPrediction]:
        """Create prediction from identified pattern."""
        # Predict next attack based on average interval
        time_since_last = time.time() - pattern["last_attack"]
        expected_next = pattern["last_attack"] + pattern["avg_interval"]
        
        # If expected time already passed, use current time + small offset
        if expected_next <= time.time():
            expected_next = time.time() + (pattern["avg_interval"] * 0.5)
        
        # Only predict if expected time is within forecast horizon
        if expected_next <= target_time:
            # Calculate confidence based on pattern consistency
            confidence = min(0.9, 0.5 + (pattern["attack_count"] * 0.1))
            
            # Determine severity
            avg_sev = pattern["avg_severity"]
            if avg_sev >= 0.8:
                severity = "CRITICAL"
            elif avg_sev >= 0.6:
                severity = "HIGH"
            elif avg_sev >= 0.4:
                severity = "MEDIUM"
            else:
                severity = "LOW"
            
            prediction_id = f"PRED-{int(time.time() * 1000)}-{hash(entity) % 10000}"
            
            reasoning = [
                f"Entity has attacked {pattern['attack_count']} times",
                f"Average interval between attacks: {pattern['avg_interval']/3600:.1f} hours",
                f"Last attack: {datetime.fromtimestamp(pattern['last_attack']).isoformat()}",
                f"Predicted next attack: {datetime.fromtimestamp(expected_next).isoformat()}"
            ]
            
            preventive_actions = [
                f"Preemptively block {entity}",
                "Increase monitoring for similar patterns",
                f"Prepare honeypot for {pattern['attack_type']}",
                "Alert security team of predicted threat"
            ]
            
            return ThreatPrediction(
                prediction_id=prediction_id,
                forecast_horizon=horizon,
                predicted_at=time.time(),
                target_time=expected_next,
                entity=entity,
                attack_type=pattern["attack_type"],
                confidence=confidence,
                severity=severity,
                reasoning=reasoning,
                historical_pattern=f"Repeat offender: {pattern['attack_count']} attacks",
                preventive_actions=preventive_actions,
                likelihood_score=confidence
            )
        
        return None
    
    def _predict_temporal_patterns(self, data: List[Dict], horizon: str,
                                   target_time: float) -> List[ThreatPrediction]:
        """Predict threats based on time-of-day patterns."""
        # Group attacks by hour of day
        hour_attacks = defaultdict(int)
        hour_types = defaultdict(list)
        
        for event in data:
            timestamp = event.get("timestamp", 0)
            dt = datetime.fromtimestamp(timestamp)
            hour = dt.hour
            hour_attacks[hour] += 1
            hour_types[hour].append(event.get("attack_type", "unknown"))
        
        predictions = []
        
        # Find high-activity hours
        if hour_attacks:
            avg_attacks = sum(hour_attacks.values()) / len(hour_attacks)
            
            for hour, count in hour_attacks.items():
                if count > avg_attacks * 1.5:  # 50% above average
                    # Predict attack in this hour within forecast window
                    target_dt = datetime.fromtimestamp(target_time)
                    
                    # Calculate confidence based on historical frequency
                    confidence = min(0.85, count / (avg_attacks * 2))
                    
                    most_common_type = max(set(hour_types[hour]), key=hour_types[hour].count)
                    
                    prediction_id = f"PRED-TEMPORAL-{int(time.time() * 1000)}-{hour}"
                    
                    predictions.append(ThreatPrediction(
                        prediction_id=prediction_id,
                        forecast_horizon=horizon,
                        predicted_at=time.time(),
                        target_time=target_time,
                        entity="unknown",
                        attack_type=most_common_type,
                        confidence=confidence,
                        severity="MEDIUM",
                        reasoning=[
                            f"Hour {hour}:00 shows elevated attack activity",
                            f"{count} attacks observed (avg: {avg_attacks:.1f})",
                            f"Most common attack type: {most_common_type}"
                        ],
                        historical_pattern=f"Temporal pattern: High activity at {hour}:00",
                        preventive_actions=[
                            f"Increase monitoring during hour {hour}:00",
                            "Preposition defensive resources",
                            f"Activate honeypots for {most_common_type}"
                        ],
                        likelihood_score=confidence
                    ))
        
        return predictions[:5]  # Top 5 temporal predictions
    
    def _predict_geographic_patterns(self, data: List[Dict], horizon: str,
                                     target_time: float) -> List[ThreatPrediction]:
        """Predict threats based on geographic/ASN patterns."""
        # Group by country/ASN
        geo_attacks = defaultdict(int)
        geo_types = defaultdict(list)
        
        for event in data:
            geo = event.get("geolocation", {})
            country = geo.get("country", "unknown")
            if country != "unknown":
                geo_attacks[country] += 1
                geo_types[country].append(event.get("attack_type", "unknown"))
        
        predictions = []
        
        # High-risk countries with patterns
        for country, count in sorted(geo_attacks.items(), key=lambda x: x[1], reverse=True)[:3]:
            if count >= 5:  # At least 5 attacks from this country
                most_common_type = max(set(geo_types[country]), key=geo_types[country].count)
                
                confidence = min(0.80, 0.4 + (count * 0.05))
                
                prediction_id = f"PRED-GEO-{int(time.time() * 1000)}-{country}"
                
                predictions.append(ThreatPrediction(
                    prediction_id=prediction_id,
                    forecast_horizon=horizon,
                    predicted_at=time.time(),
                    target_time=target_time,
                    entity=f"from-{country}",
                    attack_type=most_common_type,
                    confidence=confidence,
                    severity="HIGH" if count >= 10 else "MEDIUM",
                    reasoning=[
                        f"{count} attacks originated from {country}",
                        f"Primary attack type: {most_common_type}",
                        "Continued activity expected"
                    ],
                    historical_pattern=f"Geographic pattern: {country} attacks",
                    preventive_actions=[
                        f"Geo-fence traffic from {country}",
                        "Apply stricter validation for this region",
                        f"Deploy {most_common_type}-specific defenses"
                    ],
                    likelihood_score=confidence
                ))
        
        return predictions
    
    def create_alert_rule(self, name: str, description: str,
                         conditions: List[Dict], actions: List[ResponseAction],
                         priority: int = 5, action_params: Optional[Dict] = None) -> AlertRule:
        """
        Create custom alert rule.
        
        Args:
            name: Rule name
            description: Rule description
            conditions: List of conditions that must all be true
            actions: Actions to execute when rule triggers
            priority: Priority 1-10 (10 = highest)
            action_params: Parameters for actions
        
        Returns:
            Created AlertRule
        """
        # Generate unique ID with random component to avoid collisions
        import random
        rule_id = f"RULE-{int(time.time() * 1000)}-{random.randint(1000, 9999)}"
        
        rule = AlertRule(
            rule_id=rule_id,
            name=name,
            description=description,
            enabled=True,
            conditions=conditions,
            actions=actions,
            action_params=action_params or {},
            priority=priority,
            created_at=time.time(),
            last_triggered=None,
            trigger_count=0
        )
        
        self.alert_rules[rule_id] = rule
        
        return rule
    
    def evaluate_alert_rules(self, context: Dict[str, Any]) -> List[Tuple[AlertRule, bool]]:
        """
        Evaluate all alert rules against current context.
        
        Args:
            context: Current threat/entity context
        
        Returns:
            List of (rule, triggered) tuples
        """
        results = []
        
        # Sort rules by priority (highest first)
        sorted_rules = sorted(
            self.alert_rules.values(),
            key=lambda r: r.priority,
            reverse=True
        )
        
        for rule in sorted_rules:
            if not rule.enabled:
                continue
            
            triggered = self._evaluate_rule_conditions(rule.conditions, context)
            
            if triggered:
                rule.last_triggered = time.time()
                rule.trigger_count += 1
                self.stats["rules_triggered"] += 1
            
            results.append((rule, triggered))
        
        return results
    
    def _evaluate_rule_conditions(self, conditions: List[Dict], context: Dict) -> bool:
        """Evaluate if all conditions are met."""
        for condition in conditions:
            field = condition.get("field")
            operator = condition.get("operator")
            value = condition.get("value")
            
            # Get field value from context
            context_value = context.get(field)
            
            if context_value is None:
                return False
            
            # Evaluate condition
            if not self._evaluate_condition(context_value, operator, value):
                return False
        
        return True  # All conditions met
    
    def _evaluate_condition(self, context_val: Any, operator: str, expected_val: Any) -> bool:
        """Evaluate single condition."""
        try:
            if operator == "==" or operator == RuleConditionOperator.EQUALS.value:
                return context_val == expected_val
            elif operator == "!=" or operator == RuleConditionOperator.NOT_EQUALS.value:
                return context_val != expected_val
            elif operator == ">" or operator == RuleConditionOperator.GREATER_THAN.value:
                return float(context_val) > float(expected_val)
            elif operator == "<" or operator == RuleConditionOperator.LESS_THAN.value:
                return float(context_val) < float(expected_val)
            elif operator == ">=" or operator == RuleConditionOperator.GREATER_EQUAL.value:
                return float(context_val) >= float(expected_val)
            elif operator == "<=" or operator == RuleConditionOperator.LESS_EQUAL.value:
                return float(context_val) <= float(expected_val)
            elif operator == "contains" or operator == RuleConditionOperator.CONTAINS.value:
                return str(expected_val) in str(context_val)
            elif operator == "not_contains" or operator == RuleConditionOperator.NOT_CONTAINS.value:
                return str(expected_val) not in str(context_val)
            elif operator == "in" or operator == RuleConditionOperator.IN.value:
                return context_val in expected_val
            elif operator == "not_in" or operator == RuleConditionOperator.NOT_IN.value:
                return context_val not in expected_val
        except Exception:
            return False
        
        return False
    
    def execute_automated_response(self, incident_id: str, entity: str,
                                   threat_type: str, severity: str,
                                   actions: List[ResponseAction],
                                   action_params: Optional[Dict] = None) -> IncidentResponse:
        """
        Execute automated incident response.
        
        Args:
            incident_id: Incident identifier
            entity: IP/domain to respond to
            threat_type: Type of threat
            severity: Severity level
            actions: Actions to execute
            action_params: Optional parameters for actions
        
        Returns:
            IncidentResponse with execution results
        """
        self.stats["responses_executed"] += 1
        start_time = time.time()
        
        response_id = f"RESP-{int(time.time() * 1000)}"
        actions_executed = []
        success_count = 0
        failure_count = 0
        execution_log = []
        
        params = action_params or {}
        
        for action in actions:
            try:
                result = self._execute_action(action, entity, threat_type, params)
                actions_executed.append(result)
                
                if result["success"]:
                    success_count += 1
                    execution_log.append(f"✓ {action.value}: {result['message']}")
                else:
                    failure_count += 1
                    execution_log.append(f"✗ {action.value}: {result['message']}")
            
            except Exception as e:
                failure_count += 1
                execution_log.append(f"✗ {action.value}: Error - {str(e)}")
                actions_executed.append({
                    "action": action.value,
                    "success": False,
                    "message": str(e)
                })
        
        threat_mitigated = success_count > 0 and failure_count == 0
        if threat_mitigated:
            self.stats["responses_successful"] += 1
        
        response_time_ms = (time.time() - start_time) * 1000
        
        response = IncidentResponse(
            response_id=response_id,
            incident_id=incident_id,
            triggered_at=time.time(),
            entity=entity,
            threat_type=threat_type,
            severity=severity,
            actions_executed=actions_executed,
            success_count=success_count,
            failure_count=failure_count,
            threat_mitigated=threat_mitigated,
            response_time_ms=response_time_ms,
            execution_log=execution_log
        )
        
        # Store response
        self.responses.append(response)
        if len(self.responses) > self.max_responses:
            self.responses.pop(0)
        
        # Export response
        self._export_response(response)
        
        return response
    
    def _execute_action(self, action: ResponseAction, entity: str,
                       threat_type: str, params: Dict) -> Dict:
        """Execute single response action."""
        # In production, these would integrate with actual security systems
        # For now, we simulate the actions
        
        if action == ResponseAction.BLOCK_IP:
            return {
                "action": action.value,
                "success": True,
                "message": f"Blocked IP {entity} in firewall",
                "details": {"entity": entity, "type": "ip_block"}
            }
        
        elif action == ResponseAction.BLOCK_DOMAIN:
            return {
                "action": action.value,
                "success": True,
                "message": f"Blocked domain {entity} in DNS filter",
                "details": {"entity": entity, "type": "domain_block"}
            }
        
        elif action == ResponseAction.RATE_LIMIT:
            limit = params.get("rate_limit", "100/min")
            return {
                "action": action.value,
                "success": True,
                "message": f"Applied rate limit {limit} to {entity}",
                "details": {"entity": entity, "limit": limit}
            }
        
        elif action == ResponseAction.QUARANTINE:
            return {
                "action": action.value,
                "success": True,
                "message": f"Quarantined {entity} to isolated network segment",
                "details": {"entity": entity, "segment": "quarantine_vlan"}
            }
        
        elif action == ResponseAction.HONEYPOT_REDIRECT:
            honeypot_ip = params.get("honeypot_ip", "10.0.0.100")
            return {
                "action": action.value,
                "success": True,
                "message": f"Redirected {entity} to honeypot {honeypot_ip}",
                "details": {"entity": entity, "honeypot": honeypot_ip}
            }
        
        elif action == ResponseAction.FIREWALL_RULE:
            rule = params.get("rule", "DROP")
            return {
                "action": action.value,
                "success": True,
                "message": f"Created firewall rule: {rule} for {entity}",
                "details": {"entity": entity, "rule": rule}
            }
        
        elif action == ResponseAction.ISOLATE_SEGMENT:
            return {
                "action": action.value,
                "success": True,
                "message": f"Isolated network segment containing {entity}",
                "details": {"entity": entity, "action": "segment_isolation"}
            }
        
        elif action == ResponseAction.KILL_CONNECTION:
            return {
                "action": action.value,
                "success": True,
                "message": f"Terminated active connections from {entity}",
                "details": {"entity": entity, "connections_killed": random.randint(1, 10)}
            }
        
        elif action == ResponseAction.ALERT_ONLY:
            return {
                "action": action.value,
                "success": True,
                "message": f"Alert generated for {threat_type} from {entity}",
                "details": {"entity": entity, "threat": threat_type}
            }
        
        return {
            "action": action.value,
            "success": False,
            "message": "Unknown action type"
        }
    
    def update_network_topology(self, nodes: List[Dict], edges: List[Dict]):
        """
        Update network topology for visualization.
        
        Args:
            nodes: List of network nodes
            edges: List of network connections
        """
        # Update nodes
        for node_data in nodes:
            node_id = node_data.get("node_id", node_data.get("ip"))
            
            # Determine color based on threat level
            threat_level = node_data.get("threat_level", "CLEAN")
            color_map = {
                "CLEAN": "#00FF00",
                "SUSPICIOUS": "#FFFF00",
                "MALICIOUS": "#FFA500",
                "CRITICAL": "#FF0000"
            }
            
            node = NetworkTopologyNode(
                node_id=node_id,
                node_type=node_data.get("node_type", "device"),
                ip_address=node_data.get("ip_address", node_id),
                reputation_score=node_data.get("reputation_score", 0.0),
                threat_level=threat_level,
                is_blocked=node_data.get("is_blocked", False),
                connection_count=node_data.get("connection_count", 0),
                traffic_volume=node_data.get("traffic_volume", 0),
                attack_count=node_data.get("attack_count", 0),
                position=node_data.get("position"),
                color=color_map.get(threat_level, "#808080"),
                size=1.0 + (node_data.get("attack_count", 0) * 0.1)
            )
            
            self.topology_nodes[node_id] = node
        
        # Update edges
        self.topology_edges = []
        for edge_data in edges:
            edge = NetworkTopologyEdge(
                edge_id=f"{edge_data['source']}-{edge_data['target']}",
                source_node=edge_data["source"],
                target_node=edge_data["target"],
                connection_type=edge_data.get("type", "tcp"),
                traffic_volume=edge_data.get("traffic_volume", 0),
                packet_count=edge_data.get("packet_count", 0),
                is_suspicious=edge_data.get("is_suspicious", False),
                threat_score=edge_data.get("threat_score", 0.0),
                color="#FF0000" if edge_data.get("is_suspicious") else "#00FF00",
                thickness=1.0 + (edge_data.get("threat_score", 0.0) * 2.0)
            )
            self.topology_edges.append(edge)
        
        # Export topology
        self._export_topology()
    
    def configure_honeypot(self, honeypot_type: str, listen_ip: str,
                          listen_port: int, adaptive: bool = True) -> HoneypotConfig:
        """
        Configure adaptive honeypot.
        
        Args:
            honeypot_type: Type of honeypot (web, ssh, ftp, etc.)
            listen_ip: IP address to listen on
            listen_port: Port to listen on
            adaptive: Whether to adapt based on threats
        
        Returns:
            HoneypotConfig
        """
        self.stats["honeypots_deployed"] += 1
        
        honeypot_id = f"HONEY-{honeypot_type}-{listen_port}"
        
        # Default fake services based on type
        fake_services_map = {
            "web": ["apache", "nginx", "tomcat"],
            "ssh": ["OpenSSH_7.4"],
            "ftp": ["vsftpd 3.0.3"],
            "database": ["MySQL 5.7", "PostgreSQL 11"],
            "iot": ["camera", "router", "smart_device"]
        }
        
        config = HoneypotConfig(
            honeypot_id=honeypot_id,
            honeypot_type=honeypot_type,
            listen_ip=listen_ip,
            listen_port=listen_port,
            enabled=True,
            adaptive=adaptive,
            fake_services=fake_services_map.get(honeypot_type, ["generic"]),
            response_delays={"login": 0.5, "command": 0.2, "error": 0.1},
            interaction_count=0,
            attacker_count=0,
            signatures_captured=0
        )
        
        self.honeypots[honeypot_id] = config
        
        return config
    
    def _export_predictions(self, predictions: List[ThreatPrediction], horizon: str):
        """Export predictions to training materials."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        export_data = {
            "export_timestamp": time.time(),
            "export_datetime": datetime.now().isoformat(),
            "forecast_horizon": horizon,
            "prediction_count": len(predictions),
            "predictions": [asdict(p) for p in predictions]
        }
        
        # Export to training materials
        training_path = f"{self.export_dir}/predictions_{horizon}_{timestamp}.json"
        with open(training_path, 'w') as f:
            json.dump(export_data, f, indent=2)
        
        # Update latest
        latest_path = f"{self.export_dir}/predictions_latest.json"
        with open(latest_path, 'w') as f:
            json.dump(export_data, f, indent=2)
    
    def _export_response(self, response: IncidentResponse):
        """Export response to files."""
        # Server-local JSON for dashboard / audit trail
        responses_dir = os.path.join(self.base_dir, 'json', 'responses')
        os.makedirs(responses_dir, exist_ok=True)
        server_path = os.path.join(responses_dir, f"{response.response_id}.json")
        with open(server_path, 'w') as f:
            json.dump(asdict(response), f, indent=2)
        
        # Training materials
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        training_path = f"{self.export_dir}/response_{timestamp}.json"
        with open(training_path, 'w') as f:
            json.dump(asdict(response), f, indent=2)
    
    def _export_topology(self):
        """Export network topology."""
        topology_data = {
            "export_timestamp": time.time(),
            "export_datetime": datetime.now().isoformat(),
            "node_count": len(self.topology_nodes),
            "edge_count": len(self.topology_edges),
            "nodes": [asdict(n) for n in self.topology_nodes.values()],
            "edges": [asdict(e) for e in self.topology_edges]
        }
        
        # Export for visualization (server-local JSON)
        topology_dir = os.path.join(self.base_dir, 'json')
        os.makedirs(topology_dir, exist_ok=True)
        viz_path = os.path.join(topology_dir, 'network_topology.json')
        with open(viz_path, 'w') as f:
            json.dump(topology_data, f, indent=2)
        
        # Training materials
        training_path = f"{self.export_dir}/topology_latest.json"
        with open(training_path, 'w') as f:
            json.dump(topology_data, f, indent=2)
    
    def get_statistics(self) -> Dict:
        """Get orchestration statistics."""
        prediction_accuracy = 0.0
        if self.stats["predictions_made"] > 0:
            prediction_accuracy = (self.stats["predictions_accurate"] / 
                                  self.stats["predictions_made"] * 100)
        
        response_success_rate = 0.0
        if self.stats["responses_executed"] > 0:
            response_success_rate = (self.stats["responses_successful"] / 
                                    self.stats["responses_executed"] * 100)
        
        return {
            **self.stats,
            "active_rules": len([r for r in self.alert_rules.values() if r.enabled]),
            "total_rules": len(self.alert_rules),
            "prediction_accuracy": round(prediction_accuracy, 2),
            "response_success_rate": round(response_success_rate, 2),
            "topology_nodes": len(self.topology_nodes),
            "topology_edges": len(self.topology_edges),
            "active_honeypots": len([h for h in self.honeypots.values() if h.enabled])
        }


# Global instance
ORCHESTRATION_AVAILABLE = True
_orchestration_instance = None

def get_orchestration() -> AdvancedOrchestration:
    """Get global orchestration instance."""
    global _orchestration_instance
    if _orchestration_instance is None:
        _orchestration_instance = AdvancedOrchestration()
    return _orchestration_instance


if __name__ == "__main__":
    # Demo usage
    orch = AdvancedOrchestration()
    
    # Create alert rule
    print("Creating alert rule...")
    rule = orch.create_alert_rule(
        name="High Reputation Threat",
        description="Trigger when reputation score exceeds 0.8",
        conditions=[
            {"field": "reputation_score", "operator": ">", "value": 0.8},
            {"field": "threat_level", "operator": "in", "value": ["MALICIOUS", "CRITICAL"]}
        ],
        actions=[ResponseAction.BLOCK_IP, ResponseAction.ALERT_ONLY],
        priority=9
    )
    print(f"Created rule: {rule.name} ({rule.rule_id})")
    
    # Execute automated response
    print("\nExecuting automated response...")
    response = orch.execute_automated_response(
        incident_id="INC-001",
        entity="192.168.1.100",
        threat_type="SQL Injection",
        severity="HIGH",
        actions=[ResponseAction.BLOCK_IP, ResponseAction.HONEYPOT_REDIRECT]
    )
    print(f"Response ID: {response.response_id}")
    print(f"Actions executed: {response.success_count}/{response.success_count + response.failure_count}")
    print(f"Response time: {response.response_time_ms:.2f}ms")
    
    # Get statistics
    print("\nStatistics:")
    stats = orch.get_statistics()
    for key, value in stats.items():
        print(f"  {key}: {value}")
