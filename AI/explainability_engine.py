"""
Phase 7: Explainability Engine
Complete decision transparency with forensic reporting and what-if analysis.

Features:
- Step-by-step decision breakdown
- Signal contribution analysis
- Attack timeline reconstruction
- What-if scenario simulator
- Forensic report generation (JSON/PDF)
- Counterfactual explanations
- Interactive threat investigation
"""

import json
import os
import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict, field
from collections import defaultdict
from enum import Enum

from AI.path_helper import get_json_dir


class ExplanationLevel(Enum):
    """Level of detail for explanations."""
    BRIEF = "brief"  # Summary only
    STANDARD = "standard"  # Normal detail
    DETAILED = "detailed"  # Full breakdown
    FORENSIC = "forensic"  # Complete evidence chain


@dataclass
class SignalContribution:
    """Individual signal's contribution to a decision."""
    signal_name: str
    weight: float
    confidence: float
    weighted_vote: float  # weight * confidence
    verdict: str  # "THREAT" or "SAFE"
    evidence: str  # Human-readable evidence
    certainty: str  # "LOW", "MEDIUM", "HIGH"


@dataclass
class DecisionBreakdown:
    """Complete breakdown of a threat decision."""
    decision_id: str
    timestamp: float
    entity: str  # IP/domain being assessed
    final_verdict: str  # "THREAT", "SAFE", "BLOCK"
    confidence: float  # 0.0 - 1.0
    threat_score: float  # Weighted vote percentage
    
    # Signal analysis
    total_signals: int
    threat_signals: int
    safe_signals: int
    signal_contributions: List[SignalContribution]
    
    # Decision factors
    primary_threat_type: Optional[str]
    attack_stage: Optional[str]
    severity_level: str  # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    
    # Context
    strong_consensus: bool
    consensus_percentage: float
    decision_reason: str  # Human-readable explanation
    
    # Recommendations
    recommended_action: str
    mitigation_steps: List[str]


@dataclass
class AttackTimeline:
    """Chronological reconstruction of an attack."""
    entity: str
    start_time: float
    end_time: float
    duration_seconds: float
    total_events: int
    
    stages: List[Dict[str, Any]]  # Chronological attack stages
    escalation_points: List[Dict]  # Key moments where threat level increased
    
    summary: str
    attack_pattern: str  # Identified pattern (brute force, multi-stage, etc.)


@dataclass
class WhatIfScenario:
    """Result of a what-if analysis."""
    scenario_name: str
    original_verdict: str
    modified_verdict: str
    original_confidence: float
    modified_confidence: float
    
    changes_made: List[str]  # Description of modifications
    verdict_changed: bool
    confidence_delta: float
    
    explanation: str


@dataclass
class ForensicReport:
    """Complete forensic report for incident investigation."""
    report_id: str
    generated_at: float
    entity: str
    incident_summary: str
    
    # Core analysis
    decision_breakdown: DecisionBreakdown
    attack_timeline: Optional[AttackTimeline]
    
    # Evidence
    signal_evidence: Dict[str, List[str]]
    threat_indicators: List[str]
    false_positive_indicators: List[str]
    
    # Context
    historical_context: Dict[str, Any]
    related_entities: List[str]
    
    # Recommendations
    immediate_actions: List[str]
    investigation_steps: List[str]
    preventive_measures: List[str]
    
    # Metadata
    analyst_notes: List[str]
    export_format: str  # "json" or "pdf"


class ExplainabilityEngine:
    """
    Explainability engine for transparent threat decisions.
    
    Architecture:
    - Decision breakdown with signal attribution
    - Attack timeline reconstruction from events
    - What-if scenario analysis
    - Forensic report generation
    - Training data export to ai_training_materials
    """
    
    def __init__(self, export_dir: str = "relay/ai_training_materials/explainability_data"):
        """
        Initialize explainability engine.
        
        Args:
            export_dir: Directory for training data export. When left at the
                default, this is resolved via AI.path_helper.get_relay_training_dir()
                so explainability data lives under the relay/ai_training_materials
                tree regardless of Docker vs native layout.
        """
        # Resolve default export directory through the relay path helper
        if export_dir == "relay/ai_training_materials/explainability_data":
            from AI.path_helper import get_relay_training_dir  # type: ignore[import]
            self.export_dir = os.path.join(get_relay_training_dir(), "explainability_data")
        else:
            self.export_dir = export_dir

        os.makedirs(self.export_dir, exist_ok=True)

        # Forensic reports: always derive from the unified JSON directory
        # helper so paths are stable regardless of environment.
        self.forensic_dir = os.path.join(get_json_dir(), 'forensic_reports')
        os.makedirs(self.forensic_dir, exist_ok=True)
        
        # Decision history (for pattern analysis)
        self.decision_history: List[DecisionBreakdown] = []
        self.max_history = 1000
        
        # Statistics
        self.stats = {
            "explanations_generated": 0,
            "forensic_reports_created": 0,
            "what_if_scenarios_run": 0,
            "timelines_reconstructed": 0
        }

    def reset_forensic_reports(self) -> Dict[str, Any]:
        """Delete all JSON forensic report files but keep the folder.

        This is used by the dashboard "reset forensic reports" control
        so operators can start a clean set of reports without touching
        the directory structure or any non-JSON artifacts.
        """
        removed = 0
        errors: List[str] = []

        try:
            for name in os.listdir(self.forensic_dir):
                path = os.path.join(self.forensic_dir, name)
                if os.path.isfile(path) and name.lower().endswith('.json'):
                    try:
                        os.remove(path)
                        removed += 1
                    except Exception as e:  # pragma: no cover - best effort cleanup
                        errors.append(f"{name}: {e}")
        except Exception as e:
            return {"success": False, "error": str(e), "removed": removed}

        result: Dict[str, Any] = {"success": True, "removed": removed}
        if errors:
            result["partial_errors"] = errors
        return result
    
    def explain_decision(self, ensemble_decision: Dict[str, Any],
                        signals: List[Dict[str, Any]],
                        level: ExplanationLevel = ExplanationLevel.STANDARD) -> DecisionBreakdown:
        """
        Generate complete explanation for a threat decision.
        
        Args:
            ensemble_decision: Decision from meta engine
            signals: List of detection signals that voted
            level: Level of detail for explanation
        
        Returns:
            DecisionBreakdown with full analysis
        """
        self.stats["explanations_generated"] += 1
        
        # Extract basic info
        decision_id = f"DEC-{int(time.time() * 1000)}"
        entity = ensemble_decision.get("entity", "unknown")
        final_verdict = ensemble_decision.get("verdict", "SAFE")
        confidence = ensemble_decision.get("confidence", 0.0)
        threat_score = ensemble_decision.get("threat_score", 0.0)
        
        # Analyze signal contributions
        signal_contributions = self._analyze_signal_contributions(signals)
        
        # Count verdicts
        threat_signals = sum(1 for s in signal_contributions if s.verdict == "THREAT")
        safe_signals = sum(1 for s in signal_contributions if s.verdict == "SAFE")
        
        # Determine primary threat
        primary_threat = self._identify_primary_threat(signal_contributions)
        
        # Determine attack stage
        attack_stage = self._determine_attack_stage(signal_contributions)
        
        # Calculate severity
        severity = self._calculate_severity(threat_score, threat_signals)
        
        # Check consensus
        strong_consensus, consensus_pct = self._check_consensus(signal_contributions)
        
        # Generate human-readable reason
        reason = self._generate_decision_reason(
            final_verdict, threat_score, primary_threat, 
            threat_signals, safe_signals, strong_consensus
        )
        
        # Generate recommendations
        recommended_action = self._recommend_action(final_verdict, threat_score, severity)
        mitigation_steps = self._generate_mitigation_steps(primary_threat, severity)
        
        breakdown = DecisionBreakdown(
            decision_id=decision_id,
            timestamp=time.time(),
            entity=entity,
            final_verdict=final_verdict,
            confidence=confidence,
            threat_score=threat_score,
            total_signals=len(signal_contributions),
            threat_signals=threat_signals,
            safe_signals=safe_signals,
            signal_contributions=signal_contributions,
            primary_threat_type=primary_threat,
            attack_stage=attack_stage,
            severity_level=severity,
            strong_consensus=strong_consensus,
            consensus_percentage=consensus_pct,
            decision_reason=reason,
            recommended_action=recommended_action,
            mitigation_steps=mitigation_steps
        )
        
        # Store in history
        self.decision_history.append(breakdown)
        if len(self.decision_history) > self.max_history:
            self.decision_history.pop(0)
        
        return breakdown
    
    def _analyze_signal_contributions(self, signals: List[Dict[str, Any]]) -> List[SignalContribution]:
        """Analyze how each signal contributed to the decision."""
        contributions = []
        
        for signal in signals:
            # Calculate weighted vote
            weight = signal.get("weight", 0.0)
            confidence = signal.get("confidence", 0.0)
            weighted_vote = weight * confidence
            
            # Determine verdict
            verdict = "THREAT" if signal.get("is_threat", False) else "SAFE"
            
            # Extract evidence
            evidence = signal.get("evidence", signal.get("signal_type", "No evidence"))
            
            # Determine certainty
            if confidence >= 0.8:
                certainty = "HIGH"
            elif confidence >= 0.5:
                certainty = "MEDIUM"
            else:
                certainty = "LOW"
            
            contributions.append(SignalContribution(
                signal_name=signal.get("signal_type", "unknown"),
                weight=weight,
                confidence=confidence,
                weighted_vote=weighted_vote,
                verdict=verdict,
                evidence=evidence,
                certainty=certainty
            ))
        
        # Sort by weighted vote (descending)
        contributions.sort(key=lambda x: x.weighted_vote, reverse=True)
        
        return contributions
    
    def _identify_primary_threat(self, contributions: List[SignalContribution]) -> Optional[str]:
        """Identify the primary threat type from signal contributions."""
        threat_contribs = [c for c in contributions if c.verdict == "THREAT"]
        
        if not threat_contribs:
            return None
        
        # Return the highest-weighted threat signal
        primary = threat_contribs[0]
        
        # Extract threat type from signal name
        threat_map = {
            "signature": "Known Attack Pattern",
            "behavioral": "Behavioral Anomaly",
            "sequence": "Multi-Stage Attack",
            "autoencoder": "Zero-Day Threat",
            "graph": "Network-Based Attack",
            "threat_intel": "Known Malicious Actor",
            "ml_classification": "ML-Detected Threat",
            "ml_anomaly": "Statistical Anomaly"
        }
        
        return threat_map.get(primary.signal_name, "Unclassified Threat")
    
    def _determine_attack_stage(self, contributions: List[SignalContribution]) -> Optional[str]:
        """Determine attack stage from signal patterns."""
        signal_names = [c.signal_name for c in contributions if c.verdict == "THREAT"]
        
        # Pattern matching for attack stages
        if "sequence" in signal_names:
            return "Multi-Stage Attack"
        elif "graph" in signal_names:
            return "Lateral Movement / C2"
        elif "behavioral" in signal_names and "signature" in signal_names:
            return "Active Exploitation"
        elif "autoencoder" in signal_names:
            return "Zero-Day Reconnaissance"
        elif "signature" in signal_names:
            return "Initial Compromise Attempt"
        
        return "Unknown Stage"
    
    def _calculate_severity(self, threat_score: float, threat_signals: int) -> str:
        """Calculate severity level."""
        if threat_score >= 0.9 or threat_signals >= 10:
            return "CRITICAL"
        elif threat_score >= 0.75 or threat_signals >= 7:
            return "HIGH"
        elif threat_score >= 0.5 or threat_signals >= 4:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _check_consensus(self, contributions: List[SignalContribution]) -> Tuple[bool, float]:
        """Check if there's strong consensus among signals."""
        if not contributions:
            return False, 0.0
        
        threat_votes = sum(c.weighted_vote for c in contributions if c.verdict == "THREAT")
        safe_votes = sum(c.weighted_vote for c in contributions if c.verdict == "SAFE")
        total_votes = threat_votes + safe_votes
        
        if total_votes == 0:
            return False, 0.0
        
        # Consensus is the percentage of the majority
        majority_votes = max(threat_votes, safe_votes)
        consensus_pct = (majority_votes / total_votes) * 100
        
        strong_consensus = consensus_pct >= 80.0
        
        return strong_consensus, round(consensus_pct, 2)
    
    def _generate_decision_reason(self, verdict: str, threat_score: float,
                                  primary_threat: Optional[str], threat_signals: int,
                                  safe_signals: int, strong_consensus: bool) -> str:
        """Generate human-readable decision reason."""
        if verdict == "THREAT" or verdict == "BLOCK":
            reason = f"Threat detected with {threat_score:.1f}% weighted vote. "
            
            if primary_threat:
                reason += f"Primary threat: {primary_threat}. "
            
            reason += f"{threat_signals} signals indicated threat, {safe_signals} indicated safe. "
            
            if strong_consensus:
                reason += "Strong consensus among detection systems. "
            
            if threat_score >= 0.9:
                reason += "Extremely high confidence - immediate action recommended."
            elif threat_score >= 0.75:
                reason += "High confidence - blocking recommended."
            else:
                reason += "Moderate confidence - investigation recommended."
        
        else:  # SAFE
            reason = f"No significant threat detected ({threat_score:.1f}% threat score). "
            
            if safe_signals > threat_signals * 2:
                reason += f"Strong safe consensus: {safe_signals} safe signals vs {threat_signals} threat signals. "
            
            if threat_signals > 0:
                reason += f"Note: {threat_signals} signals indicated potential threat, but not enough for blocking."
            else:
                reason += "All detection systems indicate normal activity."
        
        return reason
    
    def _recommend_action(self, verdict: str, threat_score: float, severity: str) -> str:
        """Recommend appropriate action."""
        if verdict == "BLOCK":
            return "BLOCK - Immediate blocking required"
        elif verdict == "THREAT":
            if severity == "CRITICAL":
                return "BLOCK - Critical threat detected"
            elif severity == "HIGH":
                return "BLOCK - High-severity threat"
            else:
                return "ALERT - Monitor and investigate"
        else:
            return "ALLOW - Continue monitoring"
    
    def _generate_mitigation_steps(self, primary_threat: Optional[str], severity: str) -> List[str]:
        """Generate mitigation steps based on threat type."""
        steps = []
        
        if severity in ["CRITICAL", "HIGH"]:
            steps.append("Block IP address immediately")
            steps.append("Review firewall rules for similar patterns")
        
        if primary_threat:
            threat_steps = {
                "Known Attack Pattern": [
                    "Update signature database",
                    "Check for similar attacks from other IPs",
                    "Review application logs for successful exploits"
                ],
                "Behavioral Anomaly": [
                    "Analyze behavioral patterns for other entities",
                    "Adjust behavioral thresholds if false positive",
                    "Monitor for repeated anomalous behavior"
                ],
                "Multi-Stage Attack": [
                    "Investigate complete attack chain",
                    "Check for lateral movement across network",
                    "Review logs for initial entry point"
                ],
                "Zero-Day Threat": [
                    "Isolate affected systems",
                    "Capture full packet data for analysis",
                    "Share indicators with security community"
                ],
                "Network-Based Attack": [
                    "Review network topology for compromised nodes",
                    "Check for command & control communications",
                    "Isolate potentially compromised segments"
                ],
                "Known Malicious Actor": [
                    "Cross-reference with threat intelligence feeds",
                    "Block at perimeter firewall",
                    "Check for data exfiltration"
                ]
            }
            
            steps.extend(threat_steps.get(primary_threat, ["Investigate further"]))
        
        steps.append("Document incident for future reference")
        
        return steps
    
    def reconstruct_attack_timeline(self, entity: str, 
                                    events: List[Dict[str, Any]]) -> AttackTimeline:
        """
        Reconstruct chronological attack timeline from events.
        
        Args:
            entity: IP/domain to analyze
            events: List of events (from reputation tracker, logs, etc.)
        
        Returns:
            AttackTimeline with staged reconstruction
        """
        self.stats["timelines_reconstructed"] += 1
        
        if not events:
            return AttackTimeline(
                entity=entity,
                start_time=time.time(),
                end_time=time.time(),
                duration_seconds=0,
                total_events=0,
                stages=[],
                escalation_points=[],
                summary="No events to reconstruct",
                attack_pattern="None"
            )
        
        # Sort events chronologically
        sorted_events = sorted(events, key=lambda e: e.get("timestamp", 0))
        
        start_time = sorted_events[0].get("timestamp", time.time())
        end_time = sorted_events[-1].get("timestamp", time.time())
        duration = end_time - start_time
        
        # Group events into stages
        stages = self._group_into_stages(sorted_events)
        
        # Identify escalation points
        escalation_points = self._identify_escalations(sorted_events)
        
        # Identify attack pattern
        attack_pattern = self._identify_attack_pattern(sorted_events, stages)
        
        # Generate summary
        summary = self._generate_timeline_summary(
            entity, len(sorted_events), duration, attack_pattern
        )
        
        return AttackTimeline(
            entity=entity,
            start_time=start_time,
            end_time=end_time,
            duration_seconds=duration,
            total_events=len(sorted_events),
            stages=stages,
            escalation_points=escalation_points,
            summary=summary,
            attack_pattern=attack_pattern
        )
    
    def _group_into_stages(self, events: List[Dict]) -> List[Dict[str, Any]]:
        """Group events into attack stages."""
        stages = []
        current_stage = None
        stage_events = []
        
        for event in events:
            attack_type = event.get("attack_type", "unknown")
            
            # Determine stage
            stage_name = self._classify_event_stage(attack_type)
            
            if stage_name != current_stage:
                # Save previous stage
                if current_stage and stage_events:
                    stages.append({
                        "stage": current_stage,
                        "events": len(stage_events),
                        "start_time": stage_events[0].get("timestamp"),
                        "end_time": stage_events[-1].get("timestamp"),
                        "description": self._describe_stage(current_stage, stage_events)
                    })
                
                # Start new stage
                current_stage = stage_name
                stage_events = [event]
            else:
                stage_events.append(event)
        
        # Save last stage
        if current_stage and stage_events:
            stages.append({
                "stage": current_stage,
                "events": len(stage_events),
                "start_time": stage_events[0].get("timestamp"),
                "end_time": stage_events[-1].get("timestamp"),
                "description": self._describe_stage(current_stage, stage_events)
            })
        
        return stages
    
    def _classify_event_stage(self, attack_type: str) -> str:
        """Classify event into attack stage."""
        reconnaissance = ["port_scan", "dns_query", "ping", "traceroute"]
        exploitation = ["sql_injection", "xss", "lfi", "rfi", "command_injection"]
        privilege_escalation = ["privilege_escalation", "sudo_exploit", "kernel_exploit"]
        lateral_movement = ["smb", "rdp", "ssh_bruteforce", "lateral_movement"]
        exfiltration = ["ftp", "http_post", "dns_exfil", "data_exfiltration"]
        
        if attack_type in reconnaissance:
            return "Reconnaissance"
        elif attack_type in exploitation:
            return "Exploitation"
        elif attack_type in privilege_escalation:
            return "Privilege Escalation"
        elif attack_type in lateral_movement:
            return "Lateral Movement"
        elif attack_type in exfiltration:
            return "Data Exfiltration"
        else:
            return "Unknown Activity"
    
    def _describe_stage(self, stage_name: str, events: List[Dict]) -> str:
        """Generate description for a stage."""
        event_count = len(events)
        attack_types = list(set(e.get("attack_type", "unknown") for e in events))
        
        desc = f"{event_count} events: {', '.join(attack_types[:3])}"
        if len(attack_types) > 3:
            desc += f" and {len(attack_types) - 3} more"
        
        return desc
    
    def _identify_escalations(self, events: List[Dict]) -> List[Dict]:
        """Identify key escalation points in attack."""
        escalations = []
        prev_severity = 0.0
        
        for i, event in enumerate(events):
            severity = event.get("severity", 0.0)
            
            # Escalation if severity jumps by 0.3 or more
            if severity - prev_severity >= 0.3:
                escalations.append({
                    "event_index": i,
                    "timestamp": event.get("timestamp"),
                    "severity_jump": round(severity - prev_severity, 2),
                    "attack_type": event.get("attack_type"),
                    "description": f"Severity escalated from {prev_severity:.2f} to {severity:.2f}"
                })
            
            prev_severity = severity
        
        return escalations
    
    def _identify_attack_pattern(self, events: List[Dict], stages: List[Dict]) -> str:
        """Identify overall attack pattern."""
        if len(events) == 1:
            return "Single Event"
        
        if len(events) >= 10 and all(e.get("attack_type") == events[0].get("attack_type") for e in events):
            return "Brute Force / Repeated Attempts"
        
        if len(stages) >= 3:
            return "Multi-Stage Attack (APT-like)"
        
        if len(stages) == 2:
            return "Two-Stage Attack"
        
        # Check for rapid succession
        if events:
            duration = events[-1].get("timestamp", 0) - events[0].get("timestamp", 0)
            if duration < 60:  # Less than 1 minute
                return "Rapid Attack Burst"
        
        return "Standard Attack Pattern"
    
    def _generate_timeline_summary(self, entity: str, event_count: int,
                                   duration: float, pattern: str) -> str:
        """Generate timeline summary."""
        duration_str = f"{duration:.0f} seconds" if duration < 3600 else f"{duration/3600:.1f} hours"
        
        summary = f"{entity} exhibited {pattern} with {event_count} events over {duration_str}."
        
        return summary
    
    def what_if_analysis(self, decision_breakdown: DecisionBreakdown,
                        scenario_name: str, modifications: Dict[str, Any]) -> WhatIfScenario:
        """
        Perform what-if analysis by modifying signals and recalculating.
        
        Args:
            decision_breakdown: Original decision
            scenario_name: Name of scenario (e.g., "Disable Behavioral")
            modifications: Dict of changes to apply
        
        Returns:
            WhatIfScenario with comparison
        """
        self.stats["what_if_scenarios_run"] += 1
        
        # Original values
        original_verdict = decision_breakdown.final_verdict
        original_confidence = decision_breakdown.confidence
        
        # Apply modifications
        modified_signals = self._apply_what_if_modifications(
            decision_breakdown.signal_contributions, modifications
        )
        
        # Recalculate decision
        modified_threat_score = self._recalculate_threat_score(modified_signals)
        modified_verdict = "THREAT" if modified_threat_score >= 50.0 else "SAFE"
        modified_confidence = modified_threat_score / 100.0
        
        # Generate explanation
        changes_made = self._describe_modifications(modifications)
        verdict_changed = (original_verdict != modified_verdict)
        confidence_delta = modified_confidence - original_confidence
        
        explanation = self._generate_what_if_explanation(
            scenario_name, original_verdict, modified_verdict,
            original_confidence, modified_confidence, changes_made
        )
        
        return WhatIfScenario(
            scenario_name=scenario_name,
            original_verdict=original_verdict,
            modified_verdict=modified_verdict,
            original_confidence=original_confidence,
            modified_confidence=modified_confidence,
            changes_made=changes_made,
            verdict_changed=verdict_changed,
            confidence_delta=round(confidence_delta, 4),
            explanation=explanation
        )
    
    def _apply_what_if_modifications(self, signals: List[SignalContribution],
                                    modifications: Dict[str, Any]) -> List[SignalContribution]:
        """Apply modifications to signals."""
        modified = []
        
        for signal in signals:
            new_signal = SignalContribution(**asdict(signal))
            
            # Check if this signal should be modified
            if "disable_signals" in modifications:
                if signal.signal_name in modifications["disable_signals"]:
                    new_signal.confidence = 0.0
                    new_signal.weighted_vote = 0.0
                    continue
            
            if "adjust_weights" in modifications:
                if signal.signal_name in modifications["adjust_weights"]:
                    new_weight = modifications["adjust_weights"][signal.signal_name]
                    new_signal.weight = new_weight
                    new_signal.weighted_vote = new_weight * new_signal.confidence
            
            if "adjust_confidence" in modifications:
                if signal.signal_name in modifications["adjust_confidence"]:
                    new_conf = modifications["adjust_confidence"][signal.signal_name]
                    new_signal.confidence = new_conf
                    new_signal.weighted_vote = new_signal.weight * new_conf
            
            modified.append(new_signal)
        
        return modified
    
    def _recalculate_threat_score(self, signals: List[SignalContribution]) -> float:
        """Recalculate threat score from modified signals."""
        threat_vote = sum(s.weighted_vote for s in signals if s.verdict == "THREAT")
        safe_vote = sum(s.weighted_vote for s in signals if s.verdict == "SAFE")
        total_vote = threat_vote + safe_vote
        
        if total_vote == 0:
            return 0.0
        
        return (threat_vote / total_vote) * 100.0
    
    def _describe_modifications(self, modifications: Dict[str, Any]) -> List[str]:
        """Describe modifications in human-readable form."""
        changes = []
        
        if "disable_signals" in modifications:
            for signal in modifications["disable_signals"]:
                changes.append(f"Disabled {signal} signal")
        
        if "adjust_weights" in modifications:
            for signal, weight in modifications["adjust_weights"].items():
                changes.append(f"Adjusted {signal} weight to {weight}")
        
        if "adjust_confidence" in modifications:
            for signal, conf in modifications["adjust_confidence"].items():
                changes.append(f"Adjusted {signal} confidence to {conf}")
        
        return changes
    
    def _generate_what_if_explanation(self, scenario_name: str, orig_verdict: str,
                                     mod_verdict: str, orig_conf: float, mod_conf: float,
                                     changes: List[str]) -> str:
        """Generate what-if explanation."""
        exp = f"Scenario '{scenario_name}': "
        
        if orig_verdict != mod_verdict:
            exp += f"Verdict changed from {orig_verdict} to {mod_verdict}. "
        else:
            exp += f"Verdict remained {orig_verdict}. "
        
        conf_change = (mod_conf - orig_conf) * 100
        if abs(conf_change) >= 5:
            direction = "increased" if conf_change > 0 else "decreased"
            exp += f"Confidence {direction} by {abs(conf_change):.1f}%. "
        
        exp += f"Changes: {', '.join(changes)}."
        
        return exp
    
    def generate_forensic_report(self, decision_breakdown: DecisionBreakdown,
                                attack_timeline: Optional[AttackTimeline] = None,
                                historical_context: Optional[Dict] = None,
                                export_format: str = "json") -> ForensicReport:
        """
        Generate complete forensic report for incident investigation.
        
        Args:
            decision_breakdown: Decision explanation
            attack_timeline: Optional timeline reconstruction
            historical_context: Optional historical data
            export_format: "json" or "pdf"
        
        Returns:
            ForensicReport with complete analysis
        """
        self.stats["forensic_reports_created"] += 1
        
        report_id = f"FORENSIC-{int(time.time() * 1000)}"
        
        # Generate incident summary
        summary = self._generate_incident_summary(decision_breakdown)
        
        # Collect signal evidence
        signal_evidence = self._collect_signal_evidence(decision_breakdown.signal_contributions)
        
        # Identify threat indicators
        threat_indicators = self._identify_threat_indicators(decision_breakdown)
        
        # Identify false positive indicators
        fp_indicators = self._identify_fp_indicators(decision_breakdown)
        
        # Find related entities (placeholder - would integrate with reputation tracker)
        related_entities = []
        
        # Generate action recommendations
        immediate_actions = self._generate_immediate_actions(decision_breakdown)
        investigation_steps = self._generate_investigation_steps(decision_breakdown)
        preventive_measures = self._generate_preventive_measures(decision_breakdown)
        
        report = ForensicReport(
            report_id=report_id,
            generated_at=time.time(),
            entity=decision_breakdown.entity,
            incident_summary=summary,
            decision_breakdown=decision_breakdown,
            attack_timeline=attack_timeline,
            signal_evidence=signal_evidence,
            threat_indicators=threat_indicators,
            false_positive_indicators=fp_indicators,
            historical_context=historical_context or {},
            related_entities=related_entities,
            immediate_actions=immediate_actions,
            investigation_steps=investigation_steps,
            preventive_measures=preventive_measures,
            analyst_notes=[],
            export_format=export_format
        )
        
        # Export report
        self._export_forensic_report(report)
        
        return report
    
    def _generate_incident_summary(self, breakdown: DecisionBreakdown) -> str:
        """Generate incident summary."""
        summary = f"Threat decision for {breakdown.entity} at {datetime.fromtimestamp(breakdown.timestamp).isoformat()}. "
        summary += f"Verdict: {breakdown.final_verdict} with {breakdown.confidence*100:.1f}% confidence. "
        summary += f"{breakdown.threat_signals} of {breakdown.total_signals} signals indicated threat. "
        
        if breakdown.primary_threat_type:
            summary += f"Primary threat: {breakdown.primary_threat_type}. "
        
        summary += f"Severity: {breakdown.severity_level}."
        
        return summary
    
    def _collect_signal_evidence(self, contributions: List[SignalContribution]) -> Dict[str, List[str]]:
        """Collect evidence by signal type."""
        evidence = defaultdict(list)
        
        for contrib in contributions:
            if contrib.verdict == "THREAT":
                evidence[contrib.signal_name].append(
                    f"{contrib.evidence} (confidence: {contrib.confidence:.2f}, weight: {contrib.weight})"
                )
        
        return dict(evidence)
    
    def _identify_threat_indicators(self, breakdown: DecisionBreakdown) -> List[str]:
        """Identify threat indicators."""
        indicators = []
        
        if breakdown.threat_score >= 90:
            indicators.append("Extremely high threat score (>90%)")
        
        if breakdown.strong_consensus:
            indicators.append(f"Strong consensus among signals ({breakdown.consensus_percentage}%)")
        
        if breakdown.threat_signals >= 10:
            indicators.append(f"Multiple independent signals detected threat ({breakdown.threat_signals})")
        
        if breakdown.primary_threat_type:
            indicators.append(f"Identified threat type: {breakdown.primary_threat_type}")
        
        if breakdown.severity_level in ["CRITICAL", "HIGH"]:
            indicators.append(f"{breakdown.severity_level} severity level")
        
        return indicators
    
    def _identify_fp_indicators(self, breakdown: DecisionBreakdown) -> List[str]:
        """Identify potential false positive indicators."""
        fp_indicators = []
        
        if breakdown.safe_signals > breakdown.threat_signals:
            fp_indicators.append(f"More safe signals than threat signals ({breakdown.safe_signals} vs {breakdown.threat_signals})")
        
        if breakdown.confidence < 0.6:
            fp_indicators.append(f"Low confidence score ({breakdown.confidence:.2f})")
        
        if not breakdown.strong_consensus:
            fp_indicators.append("Weak consensus among detection systems")
        
        # Check for low-certainty signals
        low_certainty = sum(1 for s in breakdown.signal_contributions 
                          if s.certainty == "LOW" and s.verdict == "THREAT")
        if low_certainty >= 3:
            fp_indicators.append(f"{low_certainty} low-certainty threat signals")
        
        return fp_indicators
    
    def _generate_immediate_actions(self, breakdown: DecisionBreakdown) -> List[str]:
        """Generate immediate action items."""
        return breakdown.mitigation_steps[:3]  # Top 3 priorities
    
    def _generate_investigation_steps(self, breakdown: DecisionBreakdown) -> List[str]:
        """Generate investigation steps."""
        steps = [
            "Review complete attack timeline",
            "Analyze signal evidence for each detection",
            "Check logs for related activity",
            "Verify threat indicators against known patterns",
            "Assess potential for false positive"
        ]
        
        if breakdown.primary_threat_type:
            steps.insert(1, f"Investigate {breakdown.primary_threat_type} specifics")
        
        return steps
    
    def _generate_preventive_measures(self, breakdown: DecisionBreakdown) -> List[str]:
        """Generate preventive measures."""
        measures = [
            "Update detection signatures",
            "Review and adjust signal weights if needed",
            "Implement additional monitoring for similar patterns",
            "Share indicators with threat intelligence platforms"
        ]
        
        if breakdown.severity_level == "CRITICAL":
            measures.insert(0, "Implement emergency firewall rules")
        
        return measures
    
    def _export_forensic_report(self, report: ForensicReport):
        """Export forensic report to files."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Export to local forensic reports directory
        server_path = os.path.join(self.forensic_dir, f"{report.report_id}.json")
        os.makedirs(os.path.dirname(server_path), exist_ok=True)
        
        with open(server_path, 'w') as f:
            json.dump(asdict(report), f, indent=2, default=str)
        
        # Export to training materials
        training_path = f"{self.export_dir}/forensic_{timestamp}.json"
        with open(training_path, 'w') as f:
            json.dump(asdict(report), f, indent=2, default=str)
        
        # Update latest
        latest_path = f"{self.export_dir}/forensic_latest.json"
        with open(latest_path, 'w') as f:
            json.dump(asdict(report), f, indent=2, default=str)
    
    def get_statistics(self) -> Dict:
        """Get explainability engine statistics."""
        return {
            **self.stats,
            "decision_history_size": len(self.decision_history),
            "avg_signals_per_decision": round(
                sum(d.total_signals for d in self.decision_history) / max(1, len(self.decision_history)), 2
            ) if self.decision_history else 0,
            "avg_threat_score": round(
                sum(d.threat_score for d in self.decision_history) / max(1, len(self.decision_history)), 2
            ) if self.decision_history else 0
        }


# Global instance
EXPLAINABILITY_ENGINE_AVAILABLE = True
_engine_instance = None


def get_explainability_engine() -> ExplainabilityEngine:
    """Get global explainability engine instance."""
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = ExplainabilityEngine()
    return _engine_instance


def create_explanation(ensemble_decision: Dict[str, Any],
                       signals: List[Dict[str, Any]],
                       level: ExplanationLevel = ExplanationLevel.STANDARD) -> DecisionBreakdown:
    """Convenience wrapper used by the core engine.

    This keeps the public API stable (`create_explanation`) while routing all
    work through the singleton ExplainabilityEngine instance.
    """
    engine = get_explainability_engine()
    return engine.explain_decision(ensemble_decision, signals, level=level)


def get_recent_explanations(limit: int = 15) -> List[Dict[str, Any]]:
    """Get recent decision explanations in dashboard-friendly format.

    This is a thin wrapper around the in-memory decision history that
    converts dataclass objects into plain JSON-serializable dicts and
    surfaces the key fields expected by the monitoring UI.
    """
    engine = get_explainability_engine()
    history = engine.decision_history[-limit:] if engine.decision_history else []

    decisions: List[Dict[str, Any]] = []

    for breakdown in reversed(history):  # Most recent first
        # Derive feature importance from signal contributions
        contributions = breakdown.signal_contributions or []
        # Already sorted by weighted_vote descending in _analyze_signal_contributions
        top_contribs = contributions[:5]
        total_weight = sum(c.weighted_vote for c in top_contribs if c.weighted_vote > 0)

        features_triggered: List[Dict[str, Any]] = []
        for c in top_contribs:
            importance = (c.weighted_vote / total_weight) if total_weight > 0 else 0.0
            features_triggered.append({
                "name": c.signal_name,
                "importance": round(importance, 3),
            })

        # Approximate per-model voting view from signal contributions
        model_votes: Dict[str, Dict[str, Any]] = {}
        for c in contributions:
            prediction = "threat" if c.verdict == "THREAT" else "safe"
            model_votes[c.signal_name] = {
                "prediction": prediction,
                "confidence": c.confidence,
            }

        decisions.append({
            "decision_id": breakdown.decision_id,
            "verdict": breakdown.final_verdict,
            "confidence": breakdown.confidence,
            "threat_type": breakdown.primary_threat_type,
            "ip_address": breakdown.entity,
            "explanation": breakdown.decision_reason,
            "features_triggered": features_triggered,
            "model_votes": model_votes,
            "timestamp": datetime.fromtimestamp(breakdown.timestamp).isoformat(),
            "models_voted": len(model_votes),
        })

    return decisions


def get_explanation_stats() -> Dict[str, Any]:
    """Aggregate statistics for decision explainability dashboard.

    Returns keys expected by the /api/explainability/decisions endpoint:
    - total_decisions
    - high_confidence_count
    - low_confidence_count
    - average_confidence
    """
    engine = get_explainability_engine()
    history = engine.decision_history or []

    total = len(history)
    if total == 0:
        return {
            "total_decisions": 0,
            "high_confidence_count": 0,
            "low_confidence_count": 0,
            "average_confidence": 0.0,
        }

    high_conf = sum(1 for d in history if d.confidence >= 0.8)
    low_conf = sum(1 for d in history if d.confidence < 0.5)
    avg_conf = sum(d.confidence for d in history) / float(total)

    return {
        "total_decisions": total,
        "high_confidence_count": high_conf,
        "low_confidence_count": low_conf,
        "average_confidence": round(avg_conf, 3),
    }


if __name__ == "__main__":
    # Demo usage
    engine = ExplainabilityEngine()
    
    # Mock ensemble decision
    ensemble_decision = {
        "entity": "192.168.1.100",
        "verdict": "THREAT",
        "confidence": 0.85,
        "threat_score": 85.0
    }
    
    # Mock signals
    signals = [
        {"signal_type": "signature", "weight": 0.90, "confidence": 0.95, "is_threat": True, "evidence": "SQL injection pattern"},
        {"signal_type": "behavioral", "weight": 0.75, "confidence": 0.80, "is_threat": True, "evidence": "Abnormal request frequency"},
        {"signal_type": "ml_classification", "weight": 0.78, "confidence": 0.70, "is_threat": False, "evidence": "ML classified as benign"},
    ]
    
    # Generate explanation
    print("Generating decision explanation...")
    breakdown = engine.explain_decision(ensemble_decision, signals)
    
    print(f"\nDecision: {breakdown.final_verdict}")
    print(f"Confidence: {breakdown.confidence:.2f}")
    print(f"Threat Score: {breakdown.threat_score:.1f}%")
    print(f"Reason: {breakdown.decision_reason}")
    print(f"\nSignal Contributions:")
    for contrib in breakdown.signal_contributions:
        print(f"  {contrib.signal_name}: {contrib.verdict} (confidence: {contrib.confidence:.2f}, weighted: {contrib.weighted_vote:.3f})")
    
    print(f"\nRecommended Action: {breakdown.recommended_action}")
    print(f"Mitigation Steps:")
    for step in breakdown.mitigation_steps:
        print(f"  - {step}")
    
    # Generate forensic report
    print("\n\nGenerating forensic report...")
    report = engine.generate_forensic_report(breakdown)
    print(f"Report ID: {report.report_id}")
    print(f"Incident Summary: {report.incident_summary}")
    
    print(f"\nStatistics:")
    stats = engine.get_statistics()
    for key, value in stats.items():
        print(f"  {key}: {value}")
