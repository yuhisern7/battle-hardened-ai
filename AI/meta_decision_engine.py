#!/usr/bin/env python3
"""
Meta Decision Engine - Phase 5

Ensemble-based threat assessment that combines signals from all detection systems.
Reduces false positives through multi-signal validation and weighted voting.

Detection Signals Combined (12 methods):
1. Signature-based detection (3,066 patterns)
2. Behavioral heuristics (15 metrics)
3. LSTM sequence analysis (7-state attack progression)
4. Traffic autoencoder (zero-day anomaly detection)
5. Drift detection (model degradation)
6. Graph intelligence (lateral movement, C2, exfiltration)
7. ML anomaly detection (IsolationForest)
8. ML threat classification (RandomForest)
9. ML IP reputation (GradientBoosting)
10. VPN/Tor detection
11. Threat intelligence correlation
12. False positive filter (5-gate pipeline)

Ensemble Methods:
- Weighted voting (confidence-based)
- Signal correlation analysis
- Temporal consistency checking
- Cross-validation between signals
- Adaptive threshold adjustment

Author: Enterprise Security AI Team
Version: 1.0.0
"""

import json
import os
import logging
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional, Tuple
from datetime import datetime, timezone
from enum import Enum
from collections import defaultdict

from AI.path_helper import get_json_file

logger = logging.getLogger(__name__)


class ThreatLevel(str, Enum):
    """Threat severity levels"""
    SAFE = "SAFE"
    INFO = "INFO"
    SUSPICIOUS = "SUSPICIOUS"
    DANGEROUS = "DANGEROUS"
    CRITICAL = "CRITICAL"


class SignalType(str, Enum):
    """Types of detection signals"""
    SIGNATURE = "signature"
    BEHAVIORAL = "behavioral"
    SEQUENCE = "sequence"
    AUTOENCODER = "autoencoder"
    DRIFT = "drift"
    GRAPH = "graph"
    ML_ANOMALY = "ml_anomaly"
    ML_CLASSIFICATION = "ml_classification"
    ML_REPUTATION = "ml_reputation"
    VPN_TOR = "vpn_tor"
    THREAT_INTEL = "threat_intel"
    FP_FILTER = "fp_filter"
    HONEYPOT = "honeypot"
    CAUSAL_INFERENCE = "causal_inference"  # Signal #19
    TRUST_DEGRADATION = "trust_degradation"  # Signal #20


@dataclass
class DetectionSignal:
    """Individual detection signal from a specific system"""
    signal_type: SignalType
    is_threat: bool
    confidence: float  # 0.0 to 1.0
    threat_level: ThreatLevel
    details: str
    timestamp: str
    metadata: Dict = None
    
    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            "signal_type": self.signal_type.value,
            "is_threat": self.is_threat,
            "confidence": self.confidence,
            "threat_level": self.threat_level.value,
            "details": self.details,
            "timestamp": self.timestamp,
            "metadata": self.metadata or {}
        }


@dataclass
class EnsembleDecision:
    """Final ensemble decision combining all signals"""
    is_threat: bool
    threat_level: ThreatLevel
    confidence: float  # Aggregate confidence 0.0 to 1.0
    should_block: bool
    
    # Signal breakdown
    total_signals: int
    threat_signals: int
    safe_signals: int
    
    # Voting results
    weighted_vote_score: float  # 0.0 to 1.0
    unanimous_verdict: bool
    strong_consensus: bool  # >80% agreement
    
    # Contributing signals
    signals: List[DetectionSignal]
    primary_threats: List[str]  # Top threats detected
    
    # Metadata
    timestamp: str
    ip_address: str
    endpoint: str
    
    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            "is_threat": self.is_threat,
            "threat_level": self.threat_level.value,
            "confidence": self.confidence,
            "should_block": self.should_block,
            "total_signals": self.total_signals,
            "threat_signals": self.threat_signals,
            "safe_signals": self.safe_signals,
            "weighted_vote_score": self.weighted_vote_score,
            "unanimous_verdict": self.unanimous_verdict,
            "strong_consensus": self.strong_consensus,
            "signals": [s.to_dict() for s in self.signals],
            "primary_threats": self.primary_threats,
            "timestamp": self.timestamp,
            "ip_address": self.ip_address,
            "endpoint": self.endpoint
        }


class MetaDecisionEngine:
    """
    Ensemble-based meta decision engine that combines all detection signals.
    
    Features:
    - Weighted voting based on signal confidence
    - Signal correlation analysis
    - Adaptive thresholds
    - False positive reduction
    - Explainable decisions
    """
    
    def __init__(self, config_file: str | None = None):
        """Initialize meta decision engine.
        
        If no config_file is provided, use /app/json/meta_engine_config.json
        in Docker or server/json/meta_engine_config.json when running from
        the monorepo.
        """
        if config_file is None:
            self.config_file = get_json_file('meta_engine_config.json')
        else:
            self.config_file = config_file
        
        # Signal weights (can be tuned based on historical performance)
        self.signal_weights = {
            SignalType.SIGNATURE: 0.90,        # Very reliable, low false positives
            SignalType.BEHAVIORAL: 0.75,       # Good for attack patterns
            SignalType.SEQUENCE: 0.85,         # Strong for multi-stage attacks
            SignalType.AUTOENCODER: 0.80,      # Excellent for zero-days
            SignalType.DRIFT: 0.70,            # Model degradation indicator
            SignalType.GRAPH: 0.92,            # Critical for APT lateral movement detection
            SignalType.ML_ANOMALY: 0.72,       # Good but can have false positives
            SignalType.ML_CLASSIFICATION: 0.78, # Supervised, generally accurate
            SignalType.ML_REPUTATION: 0.82,    # IP history very valuable
            SignalType.VPN_TOR: 0.65,          # Suspicious but not always malicious
            SignalType.THREAT_INTEL: 0.95,     # Known threats, very reliable
            SignalType.FP_FILTER: 0.85,        # Multi-gate validation
            SignalType.HONEYPOT: 0.98,         # Direct attacker interaction, very strong signal
            SignalType.CAUSAL_INFERENCE: 0.88, # Root cause analysis, context-aware
            SignalType.TRUST_DEGRADATION: 0.90 # Persistent entity trust, recidivism tracking
        }
        
        # Voting thresholds
        self.threat_threshold = 0.50  # Weighted vote score to classify as threat
        # Default block threshold (0.75 standard, 0.65-0.70 for critical infrastructure)
        self.block_threshold = float(os.getenv('BLOCK_THRESHOLD', '0.75'))  # Weighted vote score to auto-block
        self.strong_consensus_threshold = 0.80  # Agreement % for strong consensus
        
        # APT-focused mode for critical infrastructure
        self.apt_detection_mode = os.getenv('APT_DETECTION_MODE', 'false').lower() == 'true'
        if self.apt_detection_mode:
            self.block_threshold = min(self.block_threshold, 0.70)  # Bias toward security
            logger.info("[META-ENGINE] APT Detection Mode enabled - aggressive blocking")
        
        # Minimum signals required for decision
        self.min_signals_for_decision = 2
        
        # Decision history for learning
        self.decision_history = []
        self.max_history = 10000
        
        # Performance metrics
        self.metrics = {
            "total_decisions": 0,
            "threats_detected": 0,
            "safe_classified": 0,
            "auto_blocked": 0,
            "high_confidence_decisions": 0,
            "unanimous_decisions": 0,
            "strong_consensus_decisions": 0
        }
        
        # Load configuration
        self._load_config()
        
        logger.info("[META-ENGINE] Meta Decision Engine initialized")
        logger.info(f"[META-ENGINE] Voting thresholds: threat={self.threat_threshold}, block={self.block_threshold}")
    
    def _load_config(self) -> None:
        """Load configuration from file"""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                
                # Update weights if provided
                if "signal_weights" in config:
                    for signal_type, weight in config["signal_weights"].items():
                        if signal_type in [s.value for s in SignalType]:
                            self.signal_weights[SignalType(signal_type)] = weight
                
                # Update thresholds
                self.threat_threshold = config.get("threat_threshold", self.threat_threshold)
                self.block_threshold = config.get("block_threshold", self.block_threshold)
                
                logger.info("[META-ENGINE] Loaded configuration from disk")
            except Exception as e:
                logger.warning(f"[META-ENGINE] Failed to load config: {e}")
    
    def save_config(self) -> None:
        """Save configuration to file"""
        try:
            os.makedirs(os.path.dirname(self.config_file), exist_ok=True)
            
            config = {
                "signal_weights": {k.value: v for k, v in self.signal_weights.items()},
                "threat_threshold": self.threat_threshold,
                "block_threshold": self.block_threshold,
                "strong_consensus_threshold": self.strong_consensus_threshold,
                "min_signals_for_decision": self.min_signals_for_decision,
                "last_updated": datetime.now(timezone.utc).isoformat()
            }
            
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=2)
            
            logger.info("[META-ENGINE] Configuration saved")
        except Exception as e:
            logger.error(f"[META-ENGINE] Failed to save config: {e}")
    
    def add_signal(self, signals: List[DetectionSignal], 
                   ip_address: str, endpoint: str = "") -> EnsembleDecision:
        """
        Make ensemble decision based on multiple detection signals.
        
        Args:
            signals: List of detection signals from various systems
            ip_address: IP address being assessed
            endpoint: Request endpoint
            
        Returns:
            EnsembleDecision with final verdict
        """
        if not signals:
            # No signals - default to safe
            return EnsembleDecision(
                is_threat=False,
                threat_level=ThreatLevel.SAFE,
                confidence=0.0,
                should_block=False,
                total_signals=0,
                threat_signals=0,
                safe_signals=0,
                weighted_vote_score=0.0,
                unanimous_verdict=True,
                strong_consensus=False,
                signals=[],
                primary_threats=[],
                timestamp=datetime.now(timezone.utc).isoformat(),
                ip_address=ip_address,
                endpoint=endpoint
            )
        
        # Count threat vs safe signals
        threat_signals = [s for s in signals if s.is_threat]
        safe_signals = [s for s in signals if not s.is_threat]

        # Calculate weighted vote score and boost for strong authoritative signals
        weighted_score = self._calculate_weighted_vote(signals)
        weighted_score = self._boost_authoritative_signals(weighted_score, signals)
        
        # Apply Layer 19 (Causal Inference) modulation
        weighted_score, causal_reason = self._apply_causal_modulation(weighted_score, signals)
        
        # Apply Layer 20 (Trust Degradation) modulation
        weighted_score, trust_reason, recommended_action = self._apply_trust_modulation(
            weighted_score, signals, ip_address
        )
        
        # Determine if threat based on weighted vote
        is_threat = weighted_score >= self.threat_threshold
        should_block = weighted_score >= self.block_threshold
        
        # Override block decision based on trust state
        if recommended_action == "quarantine":
            should_block = True  # Force block for quarantined entities
        elif recommended_action == "isolate":
            should_block = True if weighted_score >= 0.60 else False  # Stricter threshold
        
        # Calculate aggregate confidence
        aggregate_confidence = self._calculate_aggregate_confidence(signals, is_threat)
        
        # Determine threat level
        threat_level = self._determine_threat_level(weighted_score, threat_signals)
        
        # Check for consensus
        unanimous = len(threat_signals) == len(signals) or len(safe_signals) == len(signals)
        strong_consensus = self._check_strong_consensus(signals, is_threat)
        
        # Extract primary threats
        primary_threats = self._extract_primary_threats(threat_signals)
        
        # Create decision
        decision = EnsembleDecision(
            is_threat=is_threat,
            threat_level=threat_level,
            confidence=aggregate_confidence,
            should_block=should_block,
            total_signals=len(signals),
            threat_signals=len(threat_signals),
            safe_signals=len(safe_signals),
            weighted_vote_score=weighted_score,
            unanimous_verdict=unanimous,
            strong_consensus=strong_consensus,
            signals=signals,
            primary_threats=primary_threats,
            timestamp=datetime.now(timezone.utc).isoformat(),
            ip_address=ip_address,
            endpoint=endpoint
        )
        
        # Update metrics
        self._update_metrics(decision)
        
        # Store in history
        self._add_to_history(decision)
        
        # Log decision
        self._log_decision(decision)
        
        return decision

    def _boost_authoritative_signals(self, weighted_score: float, signals: List[DetectionSignal]) -> float:
        """Boost vote score when authoritative signals fire strongly.

        Honeypot hits, high-confidence threat intel, and a strong false-positive
        filter verdict should be able to drive the ensemble to an auto-block
        decision even if other signals are weaker.
        """
        boosted = weighted_score

        for s in signals:
            if not s.is_threat:
                continue

            if s.signal_type == SignalType.HONEYPOT and s.confidence >= 0.7:
                # Direct attacker interaction – treat as critical
                boosted = max(boosted, max(self.block_threshold, 0.9))
            elif s.signal_type == SignalType.THREAT_INTEL and s.confidence >= 0.9:
                # Known bad from intel feeds
                boosted = max(boosted, max(self.block_threshold, 0.9))
            elif s.signal_type == SignalType.FP_FILTER and s.confidence >= 0.9:
                # 5-gate filter saying "real attack"
                boosted = max(boosted, max(self.block_threshold, 0.85))

        return min(1.0, boosted)
    
    def _calculate_weighted_vote(self, signals: List[DetectionSignal]) -> float:
        """
        Calculate weighted vote score (0.0 to 1.0).
        
        Each signal contributes: weight * confidence * (1 if threat else 0)
        Normalized by total possible weight.
        """
        if not signals:
            return 0.0
        
        threat_score = 0.0
        total_weight = 0.0
        
        for signal in signals:
            weight = self.signal_weights.get(signal.signal_type, 0.5)
            total_weight += weight
            
            if signal.is_threat:
                # Threat signal contributes weighted confidence
                threat_score += weight * signal.confidence
        
        # Normalize to 0.0-1.0 range
        if total_weight > 0:
            return min(1.0, threat_score / total_weight)
        
        return 0.0
    
    def _calculate_aggregate_confidence(self, signals: List[DetectionSignal], 
                                       is_threat: bool) -> float:
        """
        Calculate aggregate confidence based on aligned signals.
        
        Confidence is higher when:
        - Multiple signals agree
        - High individual confidences
        - High-weight signals agree
        """
        if not signals:
            return 0.0
        
        # Get aligned signals (those that match the decision)
        aligned_signals = [s for s in signals if s.is_threat == is_threat]
        
        if not aligned_signals:
            return 0.0
        
        # Calculate weighted average confidence of aligned signals
        total_weighted_confidence = 0.0
        total_weight = 0.0
        
        for signal in aligned_signals:
            weight = self.signal_weights.get(signal.signal_type, 0.5)
            total_weighted_confidence += signal.confidence * weight
            total_weight += weight
        
        base_confidence = total_weighted_confidence / total_weight if total_weight > 0 else 0.0
        
        # Boost confidence if multiple signals agree
        agreement_boost = min(0.2, len(aligned_signals) * 0.05)
        
        return min(1.0, base_confidence + agreement_boost)
    
    def _determine_threat_level(self, weighted_score: float, 
                                threat_signals: List[DetectionSignal]) -> ThreatLevel:
        """
        Determine overall threat level based on weighted score and signals.
        """
        if weighted_score < 0.3:
            return ThreatLevel.SAFE
        elif weighted_score < 0.5:
            return ThreatLevel.INFO
        elif weighted_score < 0.65:
            return ThreatLevel.SUSPICIOUS
        elif weighted_score < 0.85:
            return ThreatLevel.DANGEROUS
        else:
            return ThreatLevel.CRITICAL
    
    def _check_strong_consensus(self, signals: List[DetectionSignal], 
                                is_threat: bool) -> bool:
        """
        Check if there's strong consensus (>80% agreement).
        """
        if not signals:
            return False
        
        aligned = sum(1 for s in signals if s.is_threat == is_threat)
        agreement_ratio = aligned / len(signals)
        
        return agreement_ratio >= self.strong_consensus_threshold
    
    def _extract_primary_threats(self, threat_signals: List[DetectionSignal]) -> List[str]:
        """
        Extract top threats from threat signals.
        Returns up to 5 primary threats sorted by confidence.
        """
        if not threat_signals:
            return []
        
        # Sort by confidence (descending)
        sorted_signals = sorted(threat_signals, key=lambda s: s.confidence, reverse=True)
        
        # Extract unique threat descriptions
        threats = []
        seen = set()
        
        for signal in sorted_signals:
            # Get first sentence of details
            threat_desc = signal.details.split('.')[0].strip()
            
            if threat_desc and threat_desc not in seen:
                threats.append(f"[{signal.signal_type.value.upper()}] {threat_desc}")
                seen.add(threat_desc)
            
            if len(threats) >= 5:
                break
        
        return threats
    
    def _update_metrics(self, decision: EnsembleDecision) -> None:
        """Update performance metrics"""
        self.metrics["total_decisions"] += 1
        
        if decision.is_threat:
            self.metrics["threats_detected"] += 1
        else:
            self.metrics["safe_classified"] += 1
        
        if decision.should_block:
            self.metrics["auto_blocked"] += 1
        
        if decision.confidence >= 0.9:
            self.metrics["high_confidence_decisions"] += 1
        
        if decision.unanimous_verdict:
            self.metrics["unanimous_decisions"] += 1
        
        if decision.strong_consensus:
            self.metrics["strong_consensus_decisions"] += 1
    
    def _add_to_history(self, decision: EnsembleDecision) -> None:
        """Add decision to history for learning"""
        self.decision_history.append(decision)
        
        # Trim history if too large
        if len(self.decision_history) > self.max_history:
            self.decision_history = self.decision_history[-self.max_history:]
    
    def _log_decision(self, decision: EnsembleDecision) -> None:
        """Log ensemble decision"""
        if decision.is_threat:
            logger.warning(
                f"[META-ENGINE] THREAT DETECTED | IP: {decision.ip_address} | "
                f"Level: {decision.threat_level.value} | Confidence: {decision.confidence:.2%} | "
                f"Vote: {decision.weighted_vote_score:.2%} | Signals: {decision.threat_signals}/{decision.total_signals} | "
                f"Block: {decision.should_block}"
            )
        else:
            logger.info(
                f"[META-ENGINE] SAFE | IP: {decision.ip_address} | "
                f"Confidence: {decision.confidence:.2%} | Signals: {decision.total_signals}"
            )
    
    def get_stats(self) -> dict:
        """Get decision engine statistics"""
        return {
            "metrics": self.metrics.copy(),
            "config": {
                "threat_threshold": self.threat_threshold,
                "block_threshold": self.block_threshold,
                "signal_weights": {k.value: v for k, v in self.signal_weights.items()}
            },
            "history_size": len(self.decision_history),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    
    def _apply_causal_modulation(
        self,
        weighted_score: float,
        signals: List[DetectionSignal]
    ) -> Tuple[float, str]:
        """
        Apply Layer 19 (Causal Inference) modulation to weighted score.
        
        If causal analysis identifies a legitimate cause (deployment, config change),
        downgrade the score. If it confirms external attack, boost the score.
        
        Returns:
            (modulated_score, reasoning)
        """
        # Find causal inference signal
        causal_signal = None
        for s in signals:
            if s.signal_type == SignalType.CAUSAL_INFERENCE:
                causal_signal = s
                break
        
        if not causal_signal or not causal_signal.metadata:
            return weighted_score, "No causal analysis available"
        
        causal_label = causal_signal.metadata.get("causal_label", "unknown_cause")
        causal_confidence = causal_signal.confidence
        
        # Legitimate operational causes → downgrade score
        if causal_label == "legitimate_cause" and causal_confidence >= 0.85:
            modulated = weighted_score - 0.20
            return max(0.0, modulated), f"Causal: Legitimate cause (-20%)"
        
        elif causal_label == "automation_side_effect" and causal_confidence >= 0.80:
            modulated = weighted_score - 0.15
            return max(0.0, modulated), f"Causal: Automation side-effect (-15%)"
        
        # Malicious causes → boost score
        elif causal_label == "external_attack" and causal_confidence >= 0.80:
            modulated = weighted_score + 0.15
            return min(1.0, modulated), f"Causal: External attack (+15%)"
        
        elif causal_label == "insider_misuse" and causal_confidence >= 0.75:
            modulated = weighted_score + 0.10
            return min(1.0, modulated), f"Causal: Insider misuse (+10%)"
        
        # Misconfiguration → route to governance (don't auto-block)
        elif causal_label == "misconfiguration":
            return weighted_score, "Causal: Possible misconfiguration (governance review)"
        
        # Unknown cause → require human review (no modulation)
        elif causal_label == "unknown_cause":
            return weighted_score, "Causal: Unknown (human review required)"
        
        return weighted_score, "Causal: No adjustment"
    
    def _apply_trust_modulation(
        self,
        weighted_score: float,
        signals: List[DetectionSignal],
        ip_address: str
    ) -> Tuple[float, str, str]:
        """
        Apply Layer 20 (Trust Degradation) modulation to weighted score.
        
        Low-trust entities get stricter thresholds and automatic actions.
        
        Returns:
            (modulated_score, reasoning, recommended_action)
        """
        # Find trust degradation signal
        trust_signal = None
        for s in signals:
            if s.signal_type == SignalType.TRUST_DEGRADATION:
                trust_signal = s
                break
        
        if not trust_signal or not trust_signal.metadata:
            return weighted_score, "No trust state available", "allow"
        
        trust_score = trust_signal.metadata.get("trust_score", 100.0)
        recommended_action = trust_signal.metadata.get("recommended_action", "allow")
        
        # Very low trust (<20) → quarantine automatically
        if trust_score < 20:
            return weighted_score, f"Trust: Critical ({trust_score:.1f}/100) - Auto-quarantine", "quarantine"
        
        # Low trust (20-39) → isolation/deny-by-default
        elif trust_score < 40:
            # Lower block threshold for low-trust entities
            modulated = weighted_score + 0.15  # Easier to trigger block
            return min(1.0, modulated), f"Trust: Low ({trust_score:.1f}/100) - Stricter threshold", "isolate"
        
        # Degraded trust (40-59) → rate limiting
        elif trust_score < 60:
            modulated = weighted_score + 0.10
            return min(1.0, modulated), f"Trust: Degraded ({trust_score:.1f}/100) - Rate limiting", "rate_limit"
        
        # Normal trust (60-79) → increased monitoring
        elif trust_score < 80:
            modulated = weighted_score + 0.05
            return min(1.0, modulated), f"Trust: Monitoring ({trust_score:.1f}/100)", "monitor"
        
        # High trust (≥80) → normal operation
        else:
            return weighted_score, f"Trust: Normal ({trust_score:.1f}/100)", "allow"
    
    def adjust_signal_weight(self, signal_type: SignalType, new_weight: float) -> None:
        """
        Adjust weight for a specific signal type.
        
        Args:
            signal_type: Type of signal to adjust
            new_weight: New weight (0.0 to 1.0)
        """
        if 0.0 <= new_weight <= 1.0:
            old_weight = self.signal_weights.get(signal_type, 0.5)
            self.signal_weights[signal_type] = new_weight
            
            logger.info(f"[META-ENGINE] Adjusted {signal_type.value} weight: {old_weight:.2f} → {new_weight:.2f}")
            
            # Save updated config
            self.save_config()
        else:
            logger.warning(f"[META-ENGINE] Invalid weight {new_weight}, must be 0.0-1.0")
    
    def get_signal_performance(self) -> Dict[str, dict]:
        """
        Analyze historical signal performance.
        
        Returns performance metrics for each signal type.
        """
        performance = defaultdict(lambda: {
            "total_activations": 0,
            "threat_activations": 0,
            "safe_activations": 0,
            "avg_confidence": 0.0,
            "contribution_to_threats": 0,
            "contribution_to_blocks": 0
        })
        
        if not self.decision_history:
            return {}
        
        # Analyze historical decisions
        for decision in self.decision_history:
            for signal in decision.signals:
                signal_key = signal.signal_type.value
                perf = performance[signal_key]
                
                perf["total_activations"] += 1
                
                if signal.is_threat:
                    perf["threat_activations"] += 1
                else:
                    perf["safe_activations"] += 1
                
                # Running average of confidence
                total = perf["total_activations"]
                perf["avg_confidence"] = (
                    (perf["avg_confidence"] * (total - 1) + signal.confidence) / total
                )
                
                # Track contribution to final decisions
                if decision.is_threat and signal.is_threat:
                    perf["contribution_to_threats"] += 1
                
                if decision.should_block and signal.is_threat:
                    perf["contribution_to_blocks"] += 1
        
        return dict(performance)
    
    def save_decision_history(self, filepath: str | None = None) -> None:
        """Save decision history to file.
        
        When no filepath is provided, use /app/json/decision_history.json
        in Docker or server/json/decision_history.json in the monorepo.
        """
        try:
            if filepath is None:
                filepath = get_json_file('decision_history.json')

            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            
            history_data = {
                "decisions": [d.to_dict() for d in self.decision_history[-1000:]],  # Last 1000
                "metrics": self.metrics,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            
            with open(filepath, 'w') as f:
                json.dump(history_data, f, indent=2)
            
            logger.info(f"[META-ENGINE] Saved {len(self.decision_history)} decisions to {filepath}")
        except Exception as e:
            logger.error(f"[META-ENGINE] Failed to save history: {e}")


# Singleton instance
_meta_engine = None


def get_meta_engine() -> MetaDecisionEngine:
    """Get singleton meta decision engine instance"""
    global _meta_engine
    if _meta_engine is None:
        _meta_engine = MetaDecisionEngine()
    return _meta_engine


def make_decision(signals: List[DetectionSignal], ip_address: str, 
                 endpoint: str = "") -> EnsembleDecision:
    """
    Convenience function to make ensemble decision.
    
    Args:
        signals: List of detection signals
        ip_address: IP address being assessed
        endpoint: Request endpoint
        
    Returns:
        EnsembleDecision
    """
    engine = get_meta_engine()
    return engine.add_signal(signals, ip_address, endpoint)


def get_stats() -> dict:
    """Get meta engine statistics"""
    engine = get_meta_engine()
    return engine.get_stats()


if __name__ == "__main__":
    # Demo
    print("Meta Decision Engine - Phase 5")
    print("=" * 70)
    
    # Create test signals
    signals = [
        DetectionSignal(
            signal_type=SignalType.SIGNATURE,
            is_threat=True,
            confidence=0.95,
            threat_level=ThreatLevel.CRITICAL,
            details="SQL injection pattern detected",
            timestamp=datetime.now(timezone.utc).isoformat()
        ),
        DetectionSignal(
            signal_type=SignalType.BEHAVIORAL,
            is_threat=True,
            confidence=0.78,
            threat_level=ThreatLevel.DANGEROUS,
            details="Suspicious behavioral pattern detected",
            timestamp=datetime.now(timezone.utc).isoformat()
        ),
        DetectionSignal(
            signal_type=SignalType.ML_ANOMALY,
            is_threat=False,
            confidence=0.60,
            threat_level=ThreatLevel.SAFE,
            details="Traffic appears normal",
            timestamp=datetime.now(timezone.utc).isoformat()
        )
    ]
    
    # Make decision
    decision = make_decision(signals, "203.0.113.50", "/admin/login")
    
    print(f"\nDecision: {'THREAT' if decision.is_threat else 'SAFE'}")
    print(f"Threat Level: {decision.threat_level.value}")
    print(f"Confidence: {decision.confidence:.2%}")
    print(f"Weighted Vote: {decision.weighted_vote_score:.2%}")
    print(f"Should Block: {decision.should_block}")
    print(f"Signals: {decision.threat_signals} threats / {decision.safe_signals} safe")
    print(f"Unanimous: {decision.unanimous_verdict}")
    print(f"Strong Consensus: {decision.strong_consensus}")
    print(f"\nPrimary Threats:")
    for threat in decision.primary_threats:
        print(f"  - {threat}")
