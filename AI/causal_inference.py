#!/usr/bin/env python3
"""
Causal Inference Engine - Signal #19

Root cause analysis engine that distinguishes between legitimate operational changes
and disguised attacks. Uses causal graphs and counterfactual reasoning to determine
WHY events happen, not just that they happened.

Causal Analysis Capabilities:
- Config change correlation (deployments, patches, migrations)
- Identity event causality (login, privilege changes, service account activity)
- Temporal mismatch detection (attack vs. legitimate change timing)
- Counterfactual testing ("Would anomaly exist without this config change?")
- APT "living off the land" detection (legitimate tools used maliciously)

Causal Labels:
- LEGITIMATE_CAUSE: Normal operational change (deployment, patch, migration)
- MISCONFIGURATION: Human error, not malicious
- AUTOMATION_SIDE_EFFECT: CI/CD pipeline, orchestration tool
- EXTERNAL_ATTACK: Malicious actor
- INSIDER_MISUSE: Internal actor abusing access
- UNKNOWN_CAUSE: Insufficient context for classification

Privacy Protection:
- Never processes raw payloads or credentials
- Uses only metadata: timestamps, change types, entity IDs
- No PII retention

Author: Battle-Hardened AI Team
Version: 1.0.0
"""

import json
import os
import logging
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional, Tuple, Any
from datetime import datetime, timedelta, timezone
from enum import Enum
from collections import defaultdict

logger = logging.getLogger(__name__)


class CausalLabel(Enum):
    """Root cause classifications"""
    LEGITIMATE_CAUSE = "legitimate_cause"
    MISCONFIGURATION = "misconfiguration"
    AUTOMATION_SIDE_EFFECT = "automation_side_effect"
    EXTERNAL_ATTACK = "external_attack"
    INSIDER_MISUSE = "insider_misuse"
    UNKNOWN_CAUSE = "unknown_cause"


@dataclass
class CausalInferenceResult:
    """Result of causal analysis"""
    causal_label: CausalLabel
    confidence: float  # 0.0 to 1.0
    primary_causes: List[str]  # List of identified root causes
    non_causes: List[str]  # Factors ruled out via counterfactual testing
    temporal_correlation: float  # How well timing matches expected pattern
    reasoning: str  # Human-readable explanation
    timestamp: str
    
    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            "causal_label": self.causal_label.value,
            "confidence": self.confidence,
            "primary_causes": self.primary_causes,
            "non_causes": self.non_causes,
            "temporal_correlation": self.temporal_correlation,
            "reasoning": self.reasoning,
            "timestamp": self.timestamp
        }


class CausalInferenceEngine:
    """
    Causal Inference Engine - Layer 19
    
    Analyzes WHY events happen by building causal graphs and testing counterfactuals.
    Runs AFTER primary detection signals (1-18), BEFORE final ensemble decision.
    """
    
    def __init__(self, json_dir: Optional[str] = None):
        """
        Initialize causal inference engine.
        
        Args:
            json_dir: Directory for causal analysis logs
        """
        if json_dir is None:
            try:
                # Prefer shared JSON directory via path helper so logs
                # live alongside other server JSON state in both Docker
                # and native deployments.
                from AI.path_helper import get_json_dir  # type: ignore[import]
                self.json_dir = get_json_dir()
            except Exception:
                # Fallback to legacy behavior using a best-effort base_dir
                base_dir = '/app' if os.path.exists('/app') else os.path.join(os.path.dirname(__file__), '..', 'server')
                self.json_dir = os.path.join(base_dir, 'json')
        else:
            self.json_dir = json_dir
        self.causal_log_path = os.path.join(self.json_dir, "causal_analysis.json")
        
        # Time windows for correlation (in seconds)
        self.deployment_window = 3600  # 1 hour
        self.config_change_window = 1800  # 30 minutes
        self.identity_event_window = 900  # 15 minutes
        
        # Causal confidence thresholds
        self.high_confidence_threshold = 0.85
        self.medium_confidence_threshold = 0.70
        
        logger.info("[CAUSAL_INFERENCE] Engine initialized")
    
    def analyze_root_cause(
        self,
        signals: List[Any],  # List of DetectionSignal objects
        event: Dict[str, Any],
        config_changes: Optional[List[Dict]] = None,
        deployments: Optional[List[Dict]] = None,
        identity_events: Optional[List[Dict]] = None
    ) -> CausalInferenceResult:
        """
        Perform causal analysis to determine root cause of detected anomaly.
        
        Args:
            signals: List of DetectionSignal objects from primary detections (1-18)
            event: Normalized event object from Stage 1
            config_changes: Recent configuration changes (timestamps, change types)
            deployments: Recent deployments/CI events (timestamps, services)
            identity_events: Recent identity events (logins, privilege changes)
            
        Returns:
            CausalInferenceResult with root cause classification
        """
        event_time = self._parse_timestamp(event.get("timestamp", datetime.now(timezone.utc).isoformat()))
        
        # Check for legitimate operational causes
        deployment_match = self._check_deployment_correlation(event_time, deployments)
        config_match = self._check_config_correlation(event_time, config_changes)
        identity_match = self._check_identity_correlation(event_time, identity_events)
        
        # Calculate temporal correlation strength
        temporal_correlation = max(
            deployment_match.get("correlation", 0.0),
            config_match.get("correlation", 0.0),
            identity_match.get("correlation", 0.0)
        )
        
        # Counterfactual testing: Would anomaly exist without these changes?
        counterfactual_result = self._test_counterfactual(
            signals, event, deployment_match, config_match, identity_match
        )
        
        # Classify root cause
        causal_label, confidence, primary_causes, non_causes, reasoning = self._classify_cause(
            signals,
            event,
            deployment_match,
            config_match,
            identity_match,
            counterfactual_result,
            temporal_correlation
        )
        
        result = CausalInferenceResult(
            causal_label=causal_label,
            confidence=confidence,
            primary_causes=primary_causes,
            non_causes=non_causes,
            temporal_correlation=temporal_correlation,
            reasoning=reasoning,
            timestamp=datetime.now(timezone.utc).isoformat()
        )
        
        # Log causal analysis
        self._log_causal_analysis(event, result)
        
        return result
    
    def _check_deployment_correlation(
        self,
        event_time: datetime,
        deployments: Optional[List[Dict]]
    ) -> Dict[str, Any]:
        """Check if event correlates with recent deployment."""
        if not deployments:
            return {"correlation": 0.0, "matched_deployment": None}
        
        max_correlation = 0.0
        matched_deployment = None
        
        for deployment in deployments:
            deploy_time = self._parse_timestamp(deployment.get("timestamp"))
            time_diff = abs((event_time - deploy_time).total_seconds())
            
            if time_diff <= self.deployment_window:
                # Correlation strength decreases with time distance
                correlation = 1.0 - (time_diff / self.deployment_window)
                
                if correlation > max_correlation:
                    max_correlation = correlation
                    matched_deployment = deployment
        
        return {
            "correlation": max_correlation,
            "matched_deployment": matched_deployment
        }
    
    def _check_config_correlation(
        self,
        event_time: datetime,
        config_changes: Optional[List[Dict]]
    ) -> Dict[str, Any]:
        """Check if event correlates with configuration change."""
        if not config_changes:
            return {"correlation": 0.0, "matched_change": None}
        
        max_correlation = 0.0
        matched_change = None
        
        for change in config_changes:
            change_time = self._parse_timestamp(change.get("timestamp"))
            time_diff = abs((event_time - change_time).total_seconds())
            
            if time_diff <= self.config_change_window:
                correlation = 1.0 - (time_diff / self.config_change_window)
                
                if correlation > max_correlation:
                    max_correlation = correlation
                    matched_change = change
        
        return {
            "correlation": max_correlation,
            "matched_change": matched_change
        }
    
    def _check_identity_correlation(
        self,
        event_time: datetime,
        identity_events: Optional[List[Dict]]
    ) -> Dict[str, Any]:
        """Check if event correlates with identity event."""
        if not identity_events:
            return {"correlation": 0.0, "matched_event": None}
        
        max_correlation = 0.0
        matched_event = None
        
        for id_event in identity_events:
            id_time = self._parse_timestamp(id_event.get("timestamp"))
            time_diff = abs((event_time - id_time).total_seconds())
            
            if time_diff <= self.identity_event_window:
                correlation = 1.0 - (time_diff / self.identity_event_window)
                
                if correlation > max_correlation:
                    max_correlation = correlation
                    matched_event = id_event
        
        return {
            "correlation": max_correlation,
            "matched_event": matched_event
        }
    
    def _test_counterfactual(
        self,
        signals: List[Any],
        event: Dict[str, Any],
        deployment_match: Dict,
        config_match: Dict,
        identity_match: Dict
    ) -> Dict[str, Any]:
        """
        Test counterfactual: Would anomaly exist without identified causes?
        
        Simplified heuristic: If multiple primary signals detected threat AND
        there's a strong temporal match to legitimate change, it's likely
        the change caused the anomaly (not an attack).
        """
        threat_signal_count = sum(1 for s in signals if hasattr(s, 'is_threat') and s.is_threat)
        avg_confidence = sum(s.confidence for s in signals if hasattr(s, 'confidence')) / max(len(signals), 1)
        
        # If no legitimate causes found, anomaly would still exist (attack)
        max_legit_correlation = max(
            deployment_match.get("correlation", 0.0),
            config_match.get("correlation", 0.0),
            identity_match.get("correlation", 0.0)
        )
        
        if max_legit_correlation < 0.3:
            # Low correlation with legitimate changes → anomaly independent
            return {
                "would_exist_without_change": True,
                "confidence": 0.9
            }
        
        # High correlation → anomaly likely caused by change
        if max_legit_correlation > 0.7:
            return {
                "would_exist_without_change": False,
                "confidence": 0.8
            }
        
        # Moderate correlation → unclear
        return {
            "would_exist_without_change": None,
            "confidence": 0.5
        }
    
    def _classify_cause(
        self,
        signals: List[Any],
        event: Dict[str, Any],
        deployment_match: Dict,
        config_match: Dict,
        identity_match: Dict,
        counterfactual: Dict,
        temporal_correlation: float
    ) -> Tuple[CausalLabel, float, List[str], List[str], str]:
        """
        Classify root cause based on causal analysis.
        
        Returns:
            (causal_label, confidence, primary_causes, non_causes, reasoning)
        """
        primary_causes = []
        non_causes = []
        
        # Strong deployment correlation
        if deployment_match.get("correlation", 0.0) > 0.7:
            deployment = deployment_match.get("matched_deployment", {})
            service = deployment.get("service", "unknown")
            primary_causes.append(f"Deployment of {service}")
            
            if counterfactual.get("would_exist_without_change") == False:
                return (
                    CausalLabel.AUTOMATION_SIDE_EFFECT,
                    0.85,
                    primary_causes,
                    non_causes,
                    f"Anomaly caused by deployment side-effects ({service}). Not malicious."
                )
        
        # Strong config change correlation
        if config_match.get("correlation", 0.0) > 0.7:
            change = config_match.get("matched_change", {})
            change_type = change.get("change_type", "unknown")
            primary_causes.append(f"Configuration change: {change_type}")
            
            # Check if change was automated or manual
            is_automated = change.get("automated", False)
            
            if is_automated:
                return (
                    CausalLabel.AUTOMATION_SIDE_EFFECT,
                    0.80,
                    primary_causes,
                    non_causes,
                    f"Automated configuration change ({change_type}). Expected behavior."
                )
            else:
                # Manual change with anomaly → possible misconfiguration
                threat_count = sum(1 for s in signals if hasattr(s, 'is_threat') and s.is_threat)
                if threat_count < 5:  # Low threat consensus
                    return (
                        CausalLabel.MISCONFIGURATION,
                        0.75,
                        primary_causes,
                        non_causes,
                        f"Manual configuration change ({change_type}) likely caused anomaly. Review recommended."
                    )
        
        # Identity event correlation (login, privilege change)
        if identity_match.get("correlation", 0.0) > 0.7:
            id_event = identity_match.get("matched_event", {})
            event_type = id_event.get("event_type", "unknown")
            user = id_event.get("user", "unknown")
            primary_causes.append(f"Identity event: {event_type} by {user}")
            
            # Check if it's privileged access
            is_privileged = id_event.get("privileged", False)
            
            if is_privileged:
                # Privileged access with anomaly → possible insider misuse
                threat_count = sum(1 for s in signals if hasattr(s, 'is_threat') and s.is_threat)
                if threat_count >= 8:  # High threat consensus
                    return (
                        CausalLabel.INSIDER_MISUSE,
                        0.70,
                        primary_causes,
                        non_causes,
                        f"Privileged user {user} activity with suspicious patterns. Investigation required."
                    )
        
        # No legitimate cause found → likely external attack
        if temporal_correlation < 0.3:
            non_causes.extend([
                "No recent deployments",
                "No config changes",
                "No identity events"
            ])
            
            threat_count = sum(1 for s in signals if hasattr(s, 'is_threat') and s.is_threat)
            if threat_count >= 10:
                return (
                    CausalLabel.EXTERNAL_ATTACK,
                    0.90,
                    primary_causes or ["No legitimate operational cause identified"],
                    non_causes,
                    "High-confidence external attack. No correlation with legitimate operations."
                )
            else:
                return (
                    CausalLabel.UNKNOWN_CAUSE,
                    0.60,
                    primary_causes or ["Insufficient signal consensus"],
                    non_causes,
                    "Unclear root cause. Multiple signals disagree. Manual review recommended."
                )
        
        # Default: unknown cause
        return (
            CausalLabel.UNKNOWN_CAUSE,
            0.50,
            primary_causes or ["No clear causal pattern"],
            non_causes,
            "Unable to determine root cause with confidence. Further investigation needed."
        )
    
    def _parse_timestamp(self, timestamp: Any) -> datetime:
        """Parse timestamp to datetime object."""
        if isinstance(timestamp, datetime):
            return timestamp
        
        if isinstance(timestamp, str):
            try:
                return datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            except:
                pass
        
        return datetime.now(timezone.utc)
    
    def _log_causal_analysis(self, event: Dict, result: CausalInferenceResult):
        """Log causal analysis results to JSON."""
        try:
            os.makedirs(self.json_dir, exist_ok=True)
            
            log_entry = {
                "timestamp": result.timestamp,
                "event_summary": {
                    "src_ip": event.get("src_ip", "unknown"),
                    "dst_ip": event.get("dst_ip", "unknown"),
                    "protocol": event.get("protocol", "unknown")
                },
                "causal_analysis": result.to_dict()
            }
            
            # Append to log file
            existing_data = []
            if os.path.exists(self.causal_log_path):
                try:
                    with open(self.causal_log_path, 'r') as f:
                        existing_data = json.load(f)
                except:
                    existing_data = []
            
            existing_data.append(log_entry)
            
            # Keep only last 10,000 entries
            if len(existing_data) > 10000:
                existing_data = existing_data[-10000:]
            
            with open(self.causal_log_path, 'w') as f:
                json.dump(existing_data, f, indent=2)
            
            logger.debug(f"[CAUSAL_INFERENCE] Logged analysis: {result.causal_label.value}")
        
        except Exception as e:
            logger.error(f"[CAUSAL_INFERENCE] Failed to log analysis: {e}")
    
    def get_recent_analyses(self, limit: int = 100) -> List[Dict]:
        """Get recent causal analyses."""
        try:
            if os.path.exists(self.causal_log_path):
                with open(self.causal_log_path, 'r') as f:
                    data = json.load(f)
                    return data[-limit:] if data else []
        except Exception as e:
            logger.error(f"[CAUSAL_INFERENCE] Failed to read analyses: {e}")
        
        return []


# Singleton instance
_causal_engine = None


def get_causal_engine() -> CausalInferenceEngine:
    """Get singleton causal inference engine instance."""
    global _causal_engine
    if _causal_engine is None:
        _causal_engine = CausalInferenceEngine()
    return _causal_engine


def analyze_causality(entity_id: str, event_type: str, event_data: Dict) -> Optional[CausalInferenceResult]:
    """Convenience function to analyze causality.
    
    Args:
        entity_id: Entity identifier (e.g., IP address)
        event_type: Type of event ('request', 'login', 'connection', etc.)
        event_data: Event details including signals and context
    
    Returns:
        CausalInferenceResult if analysis successful, None otherwise
    """
    engine = get_causal_engine()
    
    # Extract signals from event data
    signals = event_data.get('existing_signals', [])
    
    # Build event object
    event = {
        'timestamp': event_data.get('timestamp', datetime.now(timezone.utc).isoformat()),
        'entity_id': entity_id,
        'event_type': event_type,
        **event_data
    }
    
    # Call analyze_root_cause with proper parameters
    return engine.analyze_root_cause(
        signals=signals,
        event=event,
        config_changes=event_data.get('config_changes'),
        deployments=event_data.get('deployments'),
        identity_events=event_data.get('identity_events')
    )
