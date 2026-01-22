#!/usr/bin/env python3
"""
Layered False-Positive Elimination Pipeline
No single signal confirms an attack - requires multiple independent signals to agree

5-Gate Architecture:
  Gate 1: Sanity & Context Filtering (cheap, fast)
  Gate 2: Behavior Consistency Check
  Gate 3: Temporal Correlation
  Gate 4: Cross-Signal Agreement
  Gate 5: Confidence Scoring

Only threats that pass all gates are confirmed as real attacks.
"""

import time
import logging
import os
import json
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional
from collections import defaultdict
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class SignalType(str, Enum):
    """Types of detection signals"""
    NETWORK_BEHAVIOR = "network_behavior"
    PROTOCOL_ANOMALY = "protocol_anomaly"
    AI_PREDICTION = "ai_prediction"
    RULE_BASED = "rule_based"
    HONEYPOT = "honeypot"
    REPUTATION = "reputation"


@dataclass
class ThreatSignal:
    """Single detection signal"""
    signal_type: SignalType
    ip_address: str
    timestamp: float
    confidence: float  # 0.0 to 1.0
    details: str
    raw_data: dict


@dataclass
class ConfidenceScore:
    """Final confidence assessment"""
    total_confidence: float  # 0.0 to 1.0
    gates_passed: List[str]
    gates_failed: List[str]
    contributing_signals: List[SignalType]
    behavior_strength: float
    temporal_strength: float
    cross_signal_agreement: float
    should_confirm: bool
    reason: str


class FalsePositiveFilter:
    """
    Multi-gate false positive elimination system
    Delays confirmation until multiple independent signals agree
    """
    
    def __init__(self):
        # Internal tracking
        self.ip_behavior_history = defaultdict(list)  # IP -> list of behaviors
        self.ip_signal_buffer = defaultdict(list)  # IP -> pending signals
        self.confirmed_attacks = defaultdict(list)  # IP -> confirmed attacks
        
        # Whitelisted IPs and internal networks
        self.whitelisted_ips = {'127.0.0.1', 'localhost', '::1'}
        self.internal_networks = ['192.168.', '10.', '172.16.', '172.17.', '172.18.']
        
        # Common legitimate services (reduce false positives)
        self.legitimate_services = {
            80: 'http', 443: 'https', 53: 'dns', 
            22: 'ssh', 21: 'ftp', 25: 'smtp',
            3306: 'mysql', 5432: 'postgres', 6379: 'redis'
        }
        
        # Gate thresholds
        self.min_signals_for_confirmation = 2  # Need at least 2 different signal types
        self.min_confidence_threshold = 0.75  # 75% confidence minimum
        self.temporal_window = 300  # 5 minutes window for correlation
        self.behavior_repeat_threshold = 3  # Need 3+ repetitions for consistency
        
        # Cleanup old data periodically
        self.last_cleanup = time.time()
        self.cleanup_interval = 3600  # 1 hour

        # Optional: load tuning parameters from JSON config
        self._load_config()

    def _load_config(self) -> None:
        """Load tuning parameters from fp_filter_config.json if present.

        Uses the shared JSON directory via AI.path_helper so the
        configuration file lives alongside the rest of the server JSON
        state in both Docker and native deployments. When not explicitly
        overridden, this resolves to fp_filter_config.json under the
        directory returned by AI.path_helper.get_json_dir().
        """
        try:
            # Allow explicit override via environment variable
            config_path = os.getenv("FP_FILTER_CONFIG")

            if not config_path:
                from AI.path_helper import get_json_file  # type: ignore[import]
                config_path = get_json_file('fp_filter_config.json')

            if not os.path.exists(config_path):
                return

            with open(config_path, 'r') as f:
                config = json.load(f)

            # Thresholds
            self.min_signals_for_confirmation = config.get(
                'min_signals_for_confirmation', self.min_signals_for_confirmation
            )
            self.min_confidence_threshold = config.get(
                'min_confidence_threshold', self.min_confidence_threshold
            )
            self.temporal_window = config.get('temporal_window', self.temporal_window)
            self.behavior_repeat_threshold = config.get(
                'behavior_repeat_threshold', self.behavior_repeat_threshold
            )

            logger.info(
                "[FP-FILTER] Loaded configuration from %s (min_signals=%s, min_conf=%.2f)",
                config_path,
                self.min_signals_for_confirmation,
                self.min_confidence_threshold,
            )
        except Exception as e:
            logger.warning(f"[FP-FILTER] Failed to load config: {e}")
    
    def assess_threat(self, signals: List[ThreatSignal]) -> ConfidenceScore:
        """
        Main entry point: assess multiple signals and determine if threat is real
        
        Returns confidence score with decision on whether to confirm attack
        """
        if not signals:
            return ConfidenceScore(
                total_confidence=0.0,
                gates_passed=[],
                gates_failed=["no_signals"],
                contributing_signals=[],
                behavior_strength=0.0,
                temporal_strength=0.0,
                cross_signal_agreement=0.0,
                should_confirm=False,
                reason="No signals provided"
            )
        
        ip_address = signals[0].ip_address
        gates_passed = []
        gates_failed = []
        
        # GATE 1: Sanity & Context Filtering
        gate1_pass, gate1_reason = self._gate1_sanity_context(signals)
        if gate1_pass:
            gates_passed.append("gate1_sanity_context")
        else:
            gates_failed.append("gate1_sanity_context")
            return ConfidenceScore(
                total_confidence=0.0,
                gates_passed=gates_passed,
                gates_failed=gates_failed,
                contributing_signals=[],
                behavior_strength=0.0,
                temporal_strength=0.0,
                cross_signal_agreement=0.0,
                should_confirm=False,
                reason=f"Gate 1 failed: {gate1_reason}"
            )
        
        # GATE 2: Behavior Consistency Check
        gate2_pass, behavior_strength = self._gate2_behavior_consistency(ip_address, signals)
        if gate2_pass:
            gates_passed.append("gate2_behavior_consistency")
        else:
            gates_failed.append("gate2_behavior_consistency")
            # Don't reject yet, continue evaluating
        
        # GATE 3: Temporal Correlation
        gate3_pass, temporal_strength = self._gate3_temporal_correlation(ip_address, signals)
        if gate3_pass:
            gates_passed.append("gate3_temporal_correlation")
        else:
            gates_failed.append("gate3_temporal_correlation")
        
        # GATE 4: Cross-Signal Agreement (CRITICAL)
        gate4_pass, cross_signal_agreement = self._gate4_cross_signal_agreement(signals)
        if gate4_pass:
            gates_passed.append("gate4_cross_signal_agreement")
        else:
            gates_failed.append("gate4_cross_signal_agreement")
            return ConfidenceScore(
                total_confidence=cross_signal_agreement,
                gates_passed=gates_passed,
                gates_failed=gates_failed,
                contributing_signals=[s.signal_type for s in signals],
                behavior_strength=behavior_strength,
                temporal_strength=temporal_strength,
                cross_signal_agreement=cross_signal_agreement,
                should_confirm=False,
                reason="Gate 4 failed: Insufficient cross-signal agreement"
            )
        
        # GATE 5: Confidence Scoring
        confidence_score = self._gate5_confidence_scoring(
            signals, behavior_strength, temporal_strength, cross_signal_agreement
        )
        
        if confidence_score.total_confidence >= self.min_confidence_threshold:
            gates_passed.append("gate5_confidence_scoring")
            should_confirm = True
            reason = f"All gates passed - Confidence: {confidence_score.total_confidence:.2%}"
        else:
            gates_failed.append("gate5_confidence_scoring")
            should_confirm = False
            reason = f"Confidence too low: {confidence_score.total_confidence:.2%} < {self.min_confidence_threshold:.2%}"
        
        return ConfidenceScore(
            total_confidence=confidence_score.total_confidence,
            gates_passed=gates_passed,
            gates_failed=gates_failed,
            contributing_signals=[s.signal_type for s in signals],
            behavior_strength=behavior_strength,
            temporal_strength=temporal_strength,
            cross_signal_agreement=cross_signal_agreement,
            should_confirm=should_confirm,
            reason=reason
        )
    
    def _gate1_sanity_context(self, signals: List[ThreatSignal]) -> Tuple[bool, str]:
        """
        Gate 1: Sanity & Context Filtering
        Remove obvious non-attacks based on context
        
        Fast checks:
        - Is source whitelisted?
        - Is source internal network?
        - Is behavior normal for the service?
        """
        ip_address = signals[0].ip_address

        # Check for honeypot signals first - these are always suspicious and
        # must NOT be bypassed by whitelisting. A whitelisted IP that hits a
        # honeypot is still considered malicious.
        honeypot_signals = [s for s in signals if s.signal_type == SignalType.HONEYPOT]
        if honeypot_signals:
            return True, "Honeypot interaction detected (always suspicious)"

        # Check whitelist (only for non-honeypot traffic)
        if ip_address in self.whitelisted_ips:
            return False, f"IP {ip_address} is whitelisted"

        # Check if internal network (configurable - may want to monitor internal too)
        # For now, we'll allow internal IPs but note them
        is_internal = any(ip_address.startswith(net) for net in self.internal_networks)
        
        # Check if all signals are very low confidence
        avg_confidence = sum(s.confidence for s in signals) / len(signals)
        if avg_confidence < 0.3:
            return False, f"All signals have low confidence (avg: {avg_confidence:.2%})"
        
        # Pass gate 1
        return True, "Context check passed"
    
    def _gate2_behavior_consistency(self, ip_address: str, signals: List[ThreatSignal]) -> Tuple[bool, float]:
        """
        Gate 2: Behavior Consistency Check
        
        Single packets are meaningless - attacks show intentional structure
        Check for:
        - Repetition of behavior
        - Progression/escalation
        - Directional patterns
        
        Returns: (pass/fail, behavior_strength 0.0-1.0)
        """
        # Add current signals to history
        current_time = time.time()
        for signal in signals:
            self.ip_behavior_history[ip_address].append({
                'signal_type': signal.signal_type,
                'timestamp': signal.timestamp,
                'details': signal.details
            })
        
        # Clean old history (keep last 1 hour)
        cutoff_time = current_time - 3600
        self.ip_behavior_history[ip_address] = [
            b for b in self.ip_behavior_history[ip_address]
            if b['timestamp'] > cutoff_time
        ]
        
        history = self.ip_behavior_history[ip_address]
        
        if len(history) < 2:
            return False, 0.2  # Not enough history
        
        # Check for repetition
        signal_types = [h['signal_type'] for h in history]
        type_counts = {}
        for st in signal_types:
            type_counts[st] = type_counts.get(st, 0) + 1
        
        max_repetitions = max(type_counts.values())
        
        # Check for progression (different signal types appearing)
        unique_signals = len(set(signal_types))
        
        # Behavior strength calculation
        repetition_score = min(max_repetitions / self.behavior_repeat_threshold, 1.0)
        diversity_score = min(unique_signals / 3.0, 1.0)  # 3+ different signals is strong
        
        behavior_strength = (repetition_score * 0.6) + (diversity_score * 0.4)
        
        passes = behavior_strength >= 0.4
        
        return passes, behavior_strength
    
    def _gate3_temporal_correlation(self, ip_address: str, signals: List[ThreatSignal]) -> Tuple[bool, float]:
        """
        Gate 3: Temporal Correlation
        
        Time separates accidents from intent
        Check for:
        - Pacing (not random)
        - Persistence over time
        - Escalation patterns
        
        Returns: (pass/fail, temporal_strength 0.0-1.0)
        """
        if len(signals) == 1:
            return False, 0.1  # Single event is weak
        
        # Get all signals in time window
        current_time = time.time()
        window_start = current_time - self.temporal_window
        
        history = self.ip_behavior_history.get(ip_address, [])
        recent_events = [h for h in history if h['timestamp'] > window_start]
        
        if len(recent_events) < 2:
            return False, 0.2
        
        # Calculate event spacing
        timestamps = sorted([e['timestamp'] for e in recent_events])
        intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
        
        # Attacks have intentional pacing (not random bursts)
        # Check variance in intervals
        if len(intervals) > 1:
            avg_interval = sum(intervals) / len(intervals)
            variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
            
            # Low variance = consistent pacing (good for attack detection)
            # High variance = random events (likely false positive)
            consistency_score = 1.0 / (1.0 + variance / 10.0)
        else:
            consistency_score = 0.5
        
        # Persistence score (more events over time = stronger)
        persistence_score = min(len(recent_events) / 10.0, 1.0)
        
        # Temporal strength
        temporal_strength = (consistency_score * 0.5) + (persistence_score * 0.5)
        
        passes = temporal_strength >= 0.4
        
        return passes, temporal_strength
    
    def _gate4_cross_signal_agreement(self, signals: List[ThreatSignal]) -> Tuple[bool, float]:
        """
        Gate 4: Cross-Signal Agreement (CRITICAL)
        
        Do not trust one detector - require agreement between multiple sources
        
        Example logic:
        - If AI confidence is high BUT protocol is valid → wait
        - If protocol anomaly + repeated behavior + AI confidence → escalate
        
        Returns: (pass/fail, agreement_score 0.0-1.0)
        """
        # Count unique signal types
        signal_types = set(s.signal_type for s in signals)

        # Check for strong combinations
        has_ai = SignalType.AI_PREDICTION in signal_types
        has_protocol = SignalType.PROTOCOL_ANOMALY in signal_types
        has_behavior = SignalType.NETWORK_BEHAVIOR in signal_types
        has_honeypot = SignalType.HONEYPOT in signal_types
        has_reputation = SignalType.REPUTATION in signal_types

        # Honeypot interactions are inherently high-signal, even if they are
        # the only signal type we have. Do NOT require a second signal type
        # for honeypot cases.
        if has_honeypot:
            return True, 0.95

        # For non-honeypot traffic, require at least 2 different signal types
        if len(signal_types) < self.min_signals_for_confirmation:
            return False, len(signal_types) / self.min_signals_for_confirmation
        
        # AI + Protocol anomaly = strong
        if has_ai and has_protocol:
            return True, 0.90
        
        # Behavior + Protocol + AI = very strong
        if has_behavior and has_protocol and has_ai:
            return True, 0.98
        
        # Reputation + any other signal = moderate
        if has_reputation and len(signal_types) >= 2:
            return True, 0.80
        
        # Calculate weighted agreement
        signal_weights = {
            SignalType.HONEYPOT: 1.0,
            SignalType.PROTOCOL_ANOMALY: 0.9,
            SignalType.AI_PREDICTION: 0.8,
            SignalType.NETWORK_BEHAVIOR: 0.7,
            SignalType.REPUTATION: 0.6,
            SignalType.RULE_BASED: 0.5
        }
        
        total_weight = sum(signal_weights.get(st, 0.5) for st in signal_types)
        agreement_score = min(total_weight / 2.0, 1.0)  # Normalize to 0-1
        
        passes = agreement_score >= 0.7
        
        return passes, agreement_score
    
    def _gate5_confidence_scoring(
        self, 
        signals: List[ThreatSignal],
        behavior_strength: float,
        temporal_strength: float,
        cross_signal_agreement: float
    ) -> ConfidenceScore:
        """
        Gate 5: Confidence Scoring
        
        Weighted sum of all factors:
        - Individual signal confidences
        - Behavior strength
        - Temporal correlation
        - Cross-signal agreement
        - Historical reputation
        
        Returns final confidence score
        """
        # Average individual signal confidences
        avg_signal_confidence = sum(s.confidence for s in signals) / len(signals)
        
        # Diversity bonus (more signal types = higher confidence)
        unique_signals = len(set(s.signal_type for s in signals))
        diversity_bonus = min(unique_signals / 4.0, 1.0)
        
        # Weighted confidence calculation
        weights = {
            'signals': 0.25,
            'behavior': 0.20,
            'temporal': 0.15,
            'cross_signal': 0.30,
            'diversity': 0.10
        }
        
        total_confidence = (
            avg_signal_confidence * weights['signals'] +
            behavior_strength * weights['behavior'] +
            temporal_strength * weights['temporal'] +
            cross_signal_agreement * weights['cross_signal'] +
            diversity_bonus * weights['diversity']
        )
        
        return ConfidenceScore(
            total_confidence=total_confidence,
            gates_passed=[],
            gates_failed=[],
            contributing_signals=[s.signal_type for s in signals],
            behavior_strength=behavior_strength,
            temporal_strength=temporal_strength,
            cross_signal_agreement=cross_signal_agreement,
            should_confirm=total_confidence >= self.min_confidence_threshold,
            reason=""
        )
    
    def add_to_whitelist(self, ip_address: str):
        """Add IP to whitelist (will always pass Gate 1)"""
        self.whitelisted_ips.add(ip_address)
        logger.info(f"Added {ip_address} to whitelist")
    
    def remove_from_whitelist(self, ip_address: str):
        """Remove IP from whitelist"""
        self.whitelisted_ips.discard(ip_address)
        logger.info(f"Removed {ip_address} from whitelist")
    
    def cleanup_old_data(self):
        """Periodic cleanup of old tracking data"""
        current_time = time.time()
        
        if current_time - self.last_cleanup < self.cleanup_interval:
            return
        
        cutoff_time = current_time - 3600  # 1 hour
        
        # Cleanup behavior history
        for ip in list(self.ip_behavior_history.keys()):
            self.ip_behavior_history[ip] = [
                b for b in self.ip_behavior_history[ip]
                if b['timestamp'] > cutoff_time
            ]
            if not self.ip_behavior_history[ip]:
                del self.ip_behavior_history[ip]
        
        self.last_cleanup = current_time
        logger.info("Cleaned up old false-positive filter data")


# Global instance
_fp_filter = None

def get_filter() -> FalsePositiveFilter:
    """Get or create global false-positive filter instance"""
    global _fp_filter
    if _fp_filter is None:
        _fp_filter = FalsePositiveFilter()
    return _fp_filter


# Convenience functions
def assess_threat(signals: List[ThreatSignal]) -> ConfidenceScore:
    """Assess threat signals and return confidence score"""
    return get_filter().assess_threat(signals)


def create_signal(
    signal_type: SignalType,
    ip_address: str,
    confidence: float,
    details: str,
    raw_data: Optional[dict] = None
) -> ThreatSignal:
    """Helper to create a threat signal"""
    return ThreatSignal(
        signal_type=signal_type,
        ip_address=ip_address,
        timestamp=time.time(),
        confidence=confidence,
        details=details,
        raw_data=raw_data or {}
    )
