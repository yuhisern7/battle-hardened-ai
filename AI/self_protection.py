"""
MODULE G: Self-Protection & Monitor Integrity

Detects attempts to tamper with, disable, or blind the security monitoring system itself.
Monitors integrity of ML models, telemetry systems, and defensive components.

Conservative thresholds to avoid false positives and self-DOS.

Risk Level: MODERATE (Needs careful tuning)
"""

import hashlib
import json
import os
import time
import logging
from typing import Dict, List, Optional, Set
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum

from AI.path_helper import get_json_dir, get_json_file

logger = logging.getLogger(__name__)

# Feature flag to allow disabling self-protection checks in constrained environments
SELF_PROTECTION_ENABLED = os.getenv("SELF_PROTECTION_ENABLED", "true").lower() == "true"


class IntegrityThreat(str, Enum):
    """Types of integrity threats."""
    MODEL_TAMPERING = "model_tampering"
    TELEMETRY_SUPPRESSION = "telemetry_suppression"
    LOG_DELETION = "log_deletion"
    CONFIG_MODIFICATION = "config_modification"
    PROCESS_INJECTION = "process_injection"
    ROOTKIT_BEHAVIOR = "rootkit_behavior"
    MONITOR_BLINDING = "monitor_blinding"


@dataclass
class IntegrityViolation:
    """Detected integrity violation."""
    violation_id: str
    timestamp: str
    threat_type: IntegrityThreat
    component: str
    severity: float  # 0-1
    evidence: Dict
    recommended_action: str


class SelfProtection:
    """
    Self-protection and monitor integrity verification.
    
    Protects against:
    - Attackers trying to disable monitoring
    - Rootkits hiding malicious activity
    - ML model tampering
    - Telemetry suppression
    - Log deletion/manipulation
    - Configuration changes by unauthorized parties
    
    CONSERVATIVE MODE: High thresholds to avoid false positives.
    """
    
    def __init__(self, storage_dir: str = None):
        """Initialize self-protection monitor."""
        default_dir = get_json_dir()
        self.storage_dir = storage_dir or default_dir
        os.makedirs(self.storage_dir, exist_ok=True)
        
        self.integrity_file = get_json_file('integrity_violations.json')
        self.baseline_file = get_json_file('integrity_baseline.json')
        
        # Integrity state
        self.violations: List[IntegrityViolation] = []
        self.component_hashes: Dict[str, str] = {}
        self.telemetry_heartbeat: Dict[str, float] = {}
        self.last_log_count = 0
        
        # Conservative thresholds and escalation behaviour
        self.config = {
            "telemetry_silence_threshold": 60.0,  # 60 seconds (very conservative)
            "hash_mismatch_severity_threshold": 0.9,  # Only critical mismatches
            "min_violations_before_alert": 3,  # Need 3 violations to alert
            "log_deletion_threshold": 0.5,  # 50% log reduction
            "model_change_grace_period": 300,  # 5 min grace after training
            # New: when enabled, very severe integrity events will be mirrored
            # into the comprehensive audit log, and (optionally) nudge the
            # kill-switch into SAFE_MODE to prevent further automated actions.
            "auto_audit_on_violation": True,
            "auto_killswitch_on_critical": os.getenv("AUTO_KILLSWITCH_ON_INTEGRITY", "false").lower() == "true",
            "critical_severity_threshold": 0.9,
        }
        
        # Load state
        self._load_violations()
        self._load_or_create_baseline()

        logger.info(
            f"[SELF-PROTECT] Initialized with conservative thresholds (enabled={SELF_PROTECTION_ENABLED})"
        )
    
    def verify_model_integrity(self, model_path: str, expected_hash: Optional[str] = None) -> Dict:
        """
        Verify ML model file hasn't been tampered with.
        
        Args:
            model_path: Path to model file
            expected_hash: Expected SHA-256 hash (if known)
        
        Returns:
            Integrity check result
        """
        if not SELF_PROTECTION_ENABLED:
            return {
                "intact": True,
                "reason": "Self-protection disabled",
                "severity": 0.0,
            }

        if not os.path.exists(model_path):
            return {
                "intact": False,
                "reason": "Model file not found",
                "severity": 0.95,
                "threat_type": IntegrityThreat.MODEL_TAMPERING
            }
        
        # Compute current hash
        current_hash = self._hash_file(model_path)
        
        # Get baseline hash if we have one
        baseline_hash = self.component_hashes.get(model_path)
        
        if expected_hash:
            # Check against provided hash
            if current_hash != expected_hash:
                self._record_violation(
                    threat_type=IntegrityThreat.MODEL_TAMPERING,
                    component=model_path,
                    severity=0.95,
                    evidence={
                        "expected_hash": expected_hash,
                        "current_hash": current_hash,
                        "model_path": model_path
                    },
                    recommended_action="ROLLBACK model to last known good version"
                )
                return {
                    "intact": False,
                    "reason": "Hash mismatch with expected value",
                    "expected": expected_hash,
                    "current": current_hash,
                    "severity": 0.95,
                    "threat_type": IntegrityThreat.MODEL_TAMPERING
                }
        
        elif baseline_hash:
            # Check against baseline
            if current_hash != baseline_hash:
                # CONSERVATIVE: Only alert if file was recently modified
                # This avoids false positives during legitimate retraining
                mod_time = os.path.getmtime(model_path)
                time_since_mod = time.time() - mod_time
                
                if time_since_mod > self.config["model_change_grace_period"]:
                    self._record_violation(
                        threat_type=IntegrityThreat.MODEL_TAMPERING,
                        component=model_path,
                        severity=0.85,  # Lower severity for baseline mismatch
                        evidence={
                            "baseline_hash": baseline_hash,
                            "current_hash": current_hash,
                            "time_since_modification": time_since_mod,
                            "model_path": model_path
                        },
                        recommended_action="INVESTIGATE model change - may be legitimate retraining"
                    )
                    return {
                        "intact": False,
                        "reason": "Hash changed from baseline (outside grace period)",
                        "baseline": baseline_hash,
                        "current": current_hash,
                        "severity": 0.85,
                        "threat_type": IntegrityThreat.MODEL_TAMPERING
                    }
                else:
                    logger.info(f"[SELF-PROTECT] Model hash changed but within grace period ({time_since_mod:.0f}s)")
                    # Update baseline to new hash
                    self.component_hashes[model_path] = current_hash
                    self._save_baseline()
        else:
            # First time seeing this model - establish baseline
            self.component_hashes[model_path] = current_hash
            self._save_baseline()
            logger.info(f"[SELF-PROTECT] Established baseline for {model_path}")
        
        return {
            "intact": True,
            "hash": current_hash,
            "severity": 0.0
        }
    
    def detect_telemetry_suppression(self, telemetry_source: str) -> Dict:
        """
        Detect if telemetry data stream has been suppressed.
        
        Monitors for:
        - eBPF programs being unloaded
        - Packet capture stopped
        - Scapy observer killed
        - Kernel telemetry gaps
        
        CONSERVATIVE: Only alerts after 60 seconds of silence.
        """
        if not SELF_PROTECTION_ENABLED:
            return {
                "suppressed": False,
                "reason": "Self-protection disabled",
            }

        current_time = time.time()
        
        # Update heartbeat
        last_heartbeat = self.telemetry_heartbeat.get(telemetry_source, current_time)
        silence_duration = current_time - last_heartbeat
        
        # Check for suppression (CONSERVATIVE threshold)
        if silence_duration > self.config["telemetry_silence_threshold"]:
            self._record_violation(
                threat_type=IntegrityThreat.TELEMETRY_SUPPRESSION,
                component=telemetry_source,
                severity=0.80,  # High but not critical
                evidence={
                    "silence_duration_seconds": silence_duration,
                    "last_heartbeat": datetime.fromtimestamp(last_heartbeat).isoformat(),
                    "threshold": self.config["telemetry_silence_threshold"]
                },
                recommended_action="CHECK if telemetry service is running, restart if needed"
            )
            
            return {
                "suppressed": True,
                "silence_duration": silence_duration,
                "last_seen": datetime.fromtimestamp(last_heartbeat).isoformat(),
                "severity": 0.80,
                "threat_type": IntegrityThreat.TELEMETRY_SUPPRESSION
            }
        
        return {
            "suppressed": False,
            "last_heartbeat": datetime.fromtimestamp(last_heartbeat).isoformat(),
            "silence_duration": silence_duration
        }
    
    def heartbeat_telemetry(self, telemetry_source: str):
        """
        Record telemetry heartbeat.
        
        Call this regularly from telemetry sources to prove they're alive.
        """
        if not SELF_PROTECTION_ENABLED:
            return
        self.telemetry_heartbeat[telemetry_source] = time.time()
    
    def detect_log_tampering(self, current_log_count: int) -> Dict:
        """
        Detect if threat logs have been deleted or manipulated.
        
        CONSERVATIVE: Only alerts on significant reductions (>50%).
        """
        if not SELF_PROTECTION_ENABLED:
            return {
                "tampered": False,
                "reason": "Self-protection disabled",
            }

        if self.last_log_count == 0:
            # First run - establish baseline
            self.last_log_count = current_log_count
            return {"tampered": False, "reason": "Baseline established"}
        
        # Check for suspicious log reduction
        if current_log_count < self.last_log_count:
            reduction_ratio = (self.last_log_count - current_log_count) / self.last_log_count
            
            # CONSERVATIVE: Only alert on >50% reduction
            if reduction_ratio > self.config["log_deletion_threshold"]:
                self._record_violation(
                    threat_type=IntegrityThreat.LOG_DELETION,
                    component="threat_log",
                    severity=0.90,
                    evidence={
                        "previous_count": self.last_log_count,
                        "current_count": current_log_count,
                        "reduction_percent": reduction_ratio * 100,
                        "logs_deleted": self.last_log_count - current_log_count
                    },
                    recommended_action="INVESTIGATE log deletion - possible attacker cover-up"
                )
                
                return {
                    "tampered": True,
                    "reduction_percent": reduction_ratio * 100,
                    "logs_deleted": self.last_log_count - current_log_count,
                    "severity": 0.90,
                    "threat_type": IntegrityThreat.LOG_DELETION
                }
        
        # Update baseline
        self.last_log_count = current_log_count
        return {"tampered": False}
    
    def detect_config_tampering(self, config_file: str) -> Dict:
        """
        Detect unauthorized configuration changes.
        
        Monitors critical config files for unexpected modifications.
        """
        if not SELF_PROTECTION_ENABLED:
            return {
                "tampered": False,
                "reason": "Self-protection disabled",
            }

        if not os.path.exists(config_file):
            return {
                "tampered": False,
                "reason": "Config file does not exist"
            }
        
        current_hash = self._hash_file(config_file)
        baseline_hash = self.component_hashes.get(config_file)
        
        if baseline_hash and current_hash != baseline_hash:
            # Config changed - check if it's suspicious
            mod_time = os.path.getmtime(config_file)
            time_since_mod = time.time() - mod_time
            
            # CONSERVATIVE: Only alert if changed very recently (might be attack in progress)
            if time_since_mod < 300:  # 5 minutes
                self._record_violation(
                    threat_type=IntegrityThreat.CONFIG_MODIFICATION,
                    component=config_file,
                    severity=0.75,  # Medium severity - could be legitimate admin
                    evidence={
                        "baseline_hash": baseline_hash,
                        "current_hash": current_hash,
                        "modified_seconds_ago": time_since_mod,
                        "config_file": config_file
                    },
                    recommended_action="VERIFY config change was authorized"
                )
                
                return {
                    "tampered": True,
                    "baseline_hash": baseline_hash,
                    "current_hash": current_hash,
                    "time_since_modification": time_since_mod,
                    "severity": 0.75,
                    "threat_type": IntegrityThreat.CONFIG_MODIFICATION
                }
            else:
                # Update baseline - change is old enough to be legitimate
                self.component_hashes[config_file] = current_hash
                self._save_baseline()
        
        elif not baseline_hash:
            # Establish baseline
            self.component_hashes[config_file] = current_hash
            self._save_baseline()
        
        return {"tampered": False, "hash": current_hash}
    
    def detect_rootkit_behavior(self, observed_packets_kernel: int, observed_packets_userland: int) -> Dict:
        """
        Detect rootkit-like behavior by comparing kernel vs userland packet counts.
        
        If kernel sees many more packets than userland, something is intercepting/hiding traffic.
        
        CONSERVATIVE: Only alerts on >30% discrepancy.
        """
        if not SELF_PROTECTION_ENABLED:
            return {
                "rootkit_detected": False,
                "reason": "Self-protection disabled",
            }

        if observed_packets_kernel == 0 or observed_packets_userland == 0:
            return {"rootkit_detected": False, "reason": "Insufficient data"}
        
        # Calculate discrepancy
        discrepancy_ratio = abs(observed_packets_kernel - observed_packets_userland) / observed_packets_kernel
        
        # CONSERVATIVE: Need >30% discrepancy to alert
        if discrepancy_ratio > 0.30:
            self._record_violation(
                threat_type=IntegrityThreat.ROOTKIT_BEHAVIOR,
                component="packet_capture",
                severity=0.85,
                evidence={
                    "kernel_packets": observed_packets_kernel,
                    "userland_packets": observed_packets_userland,
                    "discrepancy_percent": discrepancy_ratio * 100,
                    "missing_packets": observed_packets_kernel - observed_packets_userland
                },
                recommended_action="INVESTIGATE potential rootkit - kernel/userland mismatch"
            )
            
            return {
                "rootkit_detected": True,
                "discrepancy_percent": discrepancy_ratio * 100,
                "kernel_count": observed_packets_kernel,
                "userland_count": observed_packets_userland,
                "severity": 0.85,
                "threat_type": IntegrityThreat.ROOTKIT_BEHAVIOR
            }
        
        return {
            "rootkit_detected": False,
            "discrepancy_percent": discrepancy_ratio * 100
        }
    
    def detect_monitor_blinding(self) -> Dict:
        """
        Detect attempts to blind the monitoring system.
        
        Checks:
        - Multiple telemetry sources silent
        - Log tampering + telemetry suppression (combined attack)
        - Critical components offline
        """
        if not SELF_PROTECTION_ENABLED:
            return {
                "blinding_detected": False,
                "reason": "Self-protection disabled",
            }

        silent_sources = []
        current_time = time.time()
        
        for source, last_heartbeat in self.telemetry_heartbeat.items():
            if current_time - last_heartbeat > self.config["telemetry_silence_threshold"]:
                silent_sources.append(source)
        
        # CONSERVATIVE: Only alert if multiple sources are silent
        if len(silent_sources) >= 2:
            self._record_violation(
                threat_type=IntegrityThreat.MONITOR_BLINDING,
                component="monitoring_system",
                severity=0.95,  # Critical - system is being blinded
                evidence={
                    "silent_sources": silent_sources,
                    "total_sources": len(self.telemetry_heartbeat),
                    "silence_threshold": self.config["telemetry_silence_threshold"]
                },
                recommended_action="CRITICAL - Multiple monitoring components offline, possible coordinated attack"
            )
            
            return {
                "blinding_detected": True,
                "silent_sources": silent_sources,
                "severity": 0.95,
                "threat_type": IntegrityThreat.MONITOR_BLINDING
            }
        
        return {
            "blinding_detected": False,
            "active_sources": len(self.telemetry_heartbeat) - len(silent_sources)
        }
    
    def get_violation_summary(self, time_window_hours: int = 24) -> Dict:
        """Get summary of integrity violations in time window."""
        cutoff = datetime.now() - timedelta(hours=time_window_hours)
        
        recent_violations = [
            v for v in self.violations
            if datetime.fromisoformat(v.timestamp) > cutoff
        ]
        
        if len(recent_violations) == 0:
            return {
                "total_violations": 0,
                "critical_violations": 0,
                "should_alert": False
            }
        
        # Count by severity
        critical = sum(1 for v in recent_violations if v.severity >= 0.9)
        high = sum(1 for v in recent_violations if 0.7 <= v.severity < 0.9)
        medium = sum(1 for v in recent_violations if v.severity < 0.7)
        
        # Count by type
        by_type = {}
        for v in recent_violations:
            by_type[v.threat_type.value] = by_type.get(v.threat_type.value, 0) + 1
        
        # CONSERVATIVE: Only alert if we have minimum violations
        should_alert = len(recent_violations) >= self.config["min_violations_before_alert"]
        
        return {
            "total_violations": len(recent_violations),
            "critical_violations": critical,
            "high_violations": high,
            "medium_violations": medium,
            "by_type": by_type,
            "should_alert": should_alert,
            "time_window_hours": time_window_hours
        }
    
    def _record_violation(
        self,
        threat_type: IntegrityThreat,
        component: str,
        severity: float,
        evidence: Dict,
        recommended_action: str
    ):
        """Record an integrity violation."""
        violation = IntegrityViolation(
            violation_id=f"integrity_{len(self.violations) + 1}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            timestamp=datetime.now().isoformat(),
            threat_type=threat_type,
            component=component,
            severity=severity,
            evidence=evidence,
            recommended_action=recommended_action
        )
        
        self.violations.append(violation)
        self._save_violations()
        
        logger.warning(f"[SELF-PROTECT] Integrity violation: {threat_type.value} on {component} (severity={severity:.2f})")

        # Optionally mirror integrity violations into the comprehensive audit log
        # so that Section 6 can see them in the compliance/audit views.
        if self.config.get("auto_audit_on_violation", True):
            try:
                from emergency_killswitch import get_audit_log, AuditEventType

                audit = get_audit_log()
                audit.log_event(
                    event_type=AuditEventType.INTEGRITY_VIOLATION,
                    actor="self_protection",
                    action=threat_type.value,
                    target=component,
                    outcome="detected",
                    details={
                        "violation_id": violation.violation_id,
                        "severity": severity,
                        "recommended_action": recommended_action,
                    },
                    risk_level="critical" if severity >= self.config.get("critical_severity_threshold", 0.9) else "high",
                    metadata={"module": "self_protection"},
                )
            except Exception as e:
                logger.debug(f"[SELF-PROTECT] Failed to write to audit log: {e}")

        # Optional: for truly critical integrity events, nudge the kill-switch
        # into SAFE_MODE to prevent further automated blocking until an
        # operator reviews the situation. Controlled via env flag
        # AUTO_KILLSWITCH_ON_INTEGRITY=true.
        if (
            self.config.get("auto_killswitch_on_critical")
            and severity >= self.config.get("critical_severity_threshold", 0.9)
        ):
            try:
                from emergency_killswitch import get_kill_switch, KillSwitchMode

                ks = get_kill_switch()
                ks.activate_kill_switch(
                    mode=KillSwitchMode.SAFE_MODE,
                    reason=f"Critical integrity violation: {threat_type.value} on {component}",
                    activated_by="self_protection",
                )
            except Exception as e:
                logger.debug(f"[SELF-PROTECT] Failed to activate kill-switch on critical integrity violation: {e}")
    
    def _hash_file(self, file_path: str) -> str:
        """Compute SHA-256 hash of file."""
        sha256 = hashlib.sha256()
        
        try:
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception as e:
            logger.error(f"[SELF-PROTECT] Failed to hash {file_path}: {e}")
            return "ERROR"
    
    def _save_violations(self):
        """Save violations to disk."""
        data = {
            "violations": [
                {
                    "violation_id": v.violation_id,
                    "timestamp": v.timestamp,
                    "threat_type": v.threat_type.value,
                    "component": v.component,
                    "severity": v.severity,
                    "evidence": v.evidence,
                    "recommended_action": v.recommended_action
                }
                for v in self.violations[-100:]  # Keep last 100
            ],
            "last_updated": datetime.now().isoformat()
        }
        
        try:
            with open(self.integrity_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"[SELF-PROTECT] Failed to save violations: {e}")
    
    def _load_violations(self):
        """Load violations from disk."""
        if not os.path.exists(self.integrity_file):
            return
        
        try:
            with open(self.integrity_file, 'r') as f:
                data = json.load(f)
            
            self.violations = [
                IntegrityViolation(
                    violation_id=v['violation_id'],
                    timestamp=v['timestamp'],
                    threat_type=IntegrityThreat(v['threat_type']),
                    component=v['component'],
                    severity=v['severity'],
                    evidence=v['evidence'],
                    recommended_action=v['recommended_action']
                )
                for v in data.get('violations', [])
            ]
            
            logger.info(f"[SELF-PROTECT] Loaded {len(self.violations)} violations")
        except Exception as e:
            logger.error(f"[SELF-PROTECT] Failed to load violations: {e}")
    
    def _save_baseline(self):
        """Save integrity baseline."""
        data = {
            "component_hashes": self.component_hashes,
            "last_updated": datetime.now().isoformat()
        }
        
        try:
            with open(self.baseline_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"[SELF-PROTECT] Failed to save baseline: {e}")
    
    def _load_or_create_baseline(self):
        """Load or create integrity baseline."""
        if os.path.exists(self.baseline_file):
            try:
                with open(self.baseline_file, 'r') as f:
                    data = json.load(f)
                self.component_hashes = data.get('component_hashes', {})
                logger.info(f"[SELF-PROTECT] Loaded baseline with {len(self.component_hashes)} components")
            except Exception as e:
                logger.error(f"[SELF-PROTECT] Failed to load baseline: {e}")
    
    def get_stats(self) -> Dict:
        """Get self-protection statistics."""
        summary = self.get_violation_summary(time_window_hours=24)
        
        return {
            "total_violations_all_time": len(self.violations),
            "violations_last_24h": summary["total_violations"],
            "critical_violations_24h": summary["critical_violations"],
            "should_alert": summary["should_alert"],
            "monitored_components": len(self.component_hashes),
            "telemetry_sources": len(self.telemetry_heartbeat),
            "configuration": self.config,
            "enabled": SELF_PROTECTION_ENABLED,
        }


# Singleton instance
_self_protection: Optional[SelfProtection] = None


def get_self_protection() -> SelfProtection:
    """Get singleton self-protection instance."""
    global _self_protection
    if _self_protection is None:
        _self_protection = SelfProtection()
    return _self_protection
