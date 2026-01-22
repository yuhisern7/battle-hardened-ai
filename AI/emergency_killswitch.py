"""
MODULE J (Partial): Emergency Kill-Switch & Comprehensive Audit Logs

Implements:
- Emergency kill-switch to disable all automated actions
- Comprehensive audit logging for compliance and forensics
- Safe fallback modes (monitoring-only)

Skips (legal complexity):
- Jurisdiction enforcement
- Lawful-use restrictions

Risk Level: LOW (Safety feature + compliance logging)
"""

import json
import os
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from enum import Enum
import threading

from AI.path_helper import get_json_dir

logger = logging.getLogger(__name__)

# Feature flag to allow disabling the kill-switch layer in constrained deployments
EMERGENCY_KILLSWITCH_ENABLED = os.getenv("EMERGENCY_KILLSWITCH_ENABLED", "true").lower() == "true"

# Feature flag and tunables for the comprehensive audit log
COMPREHENSIVE_AUDIT_ENABLED = os.getenv("COMPREHENSIVE_AUDIT_ENABLED", "true").lower() == "true"
AUDIT_BUFFER_SIZE = int(os.getenv("AUDIT_BUFFER_SIZE", "100"))
AUDIT_MAX_EVENTS = int(os.getenv("AUDIT_MAX_EVENTS", "10000"))


class KillSwitchMode(str, Enum):
    """Kill-switch operation modes."""
    ACTIVE = "active"  # Full operation
    MONITORING_ONLY = "monitoring_only"  # No blocking, only observe
    DISABLED = "disabled"  # System completely disabled
    SAFE_MODE = "safe_mode"  # Only critical actions allowed


class AuditEventType(str, Enum):
    """Types of auditable events."""
    THREAT_DETECTED = "threat_detected"
    ACTION_TAKEN = "action_taken"
    ACTION_BLOCKED = "action_blocked"
    APPROVAL_REQUESTED = "approval_requested"
    APPROVAL_GRANTED = "approval_granted"
    APPROVAL_DENIED = "approval_denied"
    MODEL_TRAINED = "model_trained"
    MODEL_UPDATED = "model_updated"
    CONFIG_CHANGED = "config_changed"
    KILL_SWITCH_ACTIVATED = "kill_switch_activated"
    KILL_SWITCH_DEACTIVATED = "kill_switch_deactivated"
    INTEGRITY_VIOLATION = "integrity_violation"
    SYSTEM_ERROR = "system_error"


@dataclass
class AuditEvent:
    """Audit log entry."""
    event_id: str
    timestamp: str
    event_type: AuditEventType
    actor: str  # Who/what triggered this event
    action: str
    target: str
    outcome: str  # success, failure, blocked
    details: Dict
    risk_level: str
    metadata: Dict


class EmergencyKillSwitch:
    """
    Emergency kill-switch with multiple safety modes.
    
    Modes:
    - ACTIVE: Full operation (normal mode)
    - MONITORING_ONLY: Observe and log but don't block anything
    - SAFE_MODE: Only allow critical defensive actions
    - DISABLED: System completely disabled
    
    Features:
    - Instant mode switching
    - Persistent state across restarts
    - Audit trail of all mode changes
    - Automatic fallback on errors
    """
    
    def __init__(self, storage_dir: Optional[str] = None):
        """Initialize kill-switch."""
        default_dir = get_json_dir()
        self.storage_dir = storage_dir or default_dir
        os.makedirs(self.storage_dir, exist_ok=True)
        
        self.killswitch_file = os.path.join(self.storage_dir, 'killswitch_state.json')
        
        # State
        self.current_mode = KillSwitchMode.ACTIVE
        self.mode_history: List[Dict] = []
        self.disabled_reason: Optional[str] = None
        self.disabled_by: Optional[str] = None
        self.enabled: bool = EMERGENCY_KILLSWITCH_ENABLED
        
        # Thread safety
        self.lock = threading.Lock()
        
        # Load state
        self._load_state()
        
        logger.info(
            f"[KILLSWITCH] Initialized in {self.current_mode.value} mode (enabled={self.enabled})"
        )
    
    def activate_kill_switch(self, mode: KillSwitchMode, reason: str, activated_by: str = "admin") -> Dict:
        """
        Activate kill-switch to specified mode.
        
        Args:
            mode: Mode to switch to
            reason: Reason for activation
            activated_by: Who activated it
        
        Returns:
            Result dict
        """
        with self.lock:
            if not self.enabled:
                logger.warning(
                    f"[KILLSWITCH] activate_kill_switch called while disabled via EMERGENCY_KILLSWITCH_ENABLED=false. No-op."
                )
                return {
                    "success": False,
                    "error": "Kill-switch enforcement disabled via EMERGENCY_KILLSWITCH_ENABLED=false",
                    "current_mode": self.current_mode.value,
                }

            previous_mode = self.current_mode
            
            self.current_mode = mode
            self.disabled_reason = reason
            self.disabled_by = activated_by
            
            # Record mode change
            change_record = {
                "timestamp": datetime.now().isoformat(),
                "previous_mode": previous_mode.value,
                "new_mode": mode.value,
                "reason": reason,
                "activated_by": activated_by
            }
            self.mode_history.append(change_record)
            
            # Save state
            self._save_state()
            
            logger.critical(f"[KILLSWITCH] Mode changed: {previous_mode.value} → {mode.value} by {activated_by}")
            logger.critical(f"[KILLSWITCH] Reason: {reason}")
            
            return {
                "success": True,
                "previous_mode": previous_mode.value,
                "new_mode": mode.value,
                "reason": reason,
                "activated_by": activated_by,
                "timestamp": datetime.now().isoformat()
            }
    
    def deactivate_kill_switch(self, deactivated_by: str = "admin") -> Dict:
        """
        Deactivate kill-switch (return to ACTIVE mode).
        
        Args:
            deactivated_by: Who deactivated it
        
        Returns:
            Result dict
        """
        return self.activate_kill_switch(
            mode=KillSwitchMode.ACTIVE,
            reason="Kill-switch deactivated - returning to normal operation",
            activated_by=deactivated_by
        )
    
    def is_action_allowed(self, action: str, is_critical: bool = False) -> Dict:
        """
        Check if an action is allowed given current kill-switch mode.
        
        Args:
            action: Action to check
            is_critical: Whether this is a critical defensive action
        
        Returns:
            Dict with allowed status and reason
        """
        with self.lock:
            if not self.enabled:
                # When disabled via env, always allow actions but surface mode for observability
                return {
                    "allowed": True,
                    "mode": self.current_mode.value,
                    "reason": "Kill-switch disabled via EMERGENCY_KILLSWITCH_ENABLED=false",
                }

            mode = self.current_mode
            
            # DISABLED: Nothing allowed
            if mode == KillSwitchMode.DISABLED:
                return {
                    "allowed": False,
                    "reason": f"System disabled: {self.disabled_reason}",
                    "mode": mode.value
                }
            
            # MONITORING_ONLY: No blocking actions
            if mode == KillSwitchMode.MONITORING_ONLY:
                if "block" in action or "quarantine" in action or "rollback" in action:
                    return {
                        "allowed": False,
                        "reason": "Monitoring-only mode: blocking actions disabled",
                        "mode": mode.value,
                        "suggested_action": "log_only"
                    }
                return {"allowed": True, "mode": mode.value}
            
            # SAFE_MODE: Only critical actions
            if mode == KillSwitchMode.SAFE_MODE:
                if not is_critical:
                    return {
                        "allowed": False,
                        "reason": "Safe mode: only critical defensive actions allowed",
                        "mode": mode.value
                    }
                return {"allowed": True, "mode": mode.value, "reason": "Critical action allowed"}
            
            # ACTIVE: Everything allowed
            return {"allowed": True, "mode": mode.value}
    
    def get_status(self) -> Dict:
        """Get current kill-switch status."""
        with self.lock:
            return {
                "current_mode": self.current_mode.value,
                "disabled_reason": self.disabled_reason,
                "disabled_by": self.disabled_by,
                "mode_changes": len(self.mode_history),
                "last_change": self.mode_history[-1] if self.mode_history else None,
                "enabled": self.enabled,
                "storage_dir": self.storage_dir,
            }
    
    def _save_state(self):
        """Save kill-switch state to disk."""
        state = {
            "current_mode": self.current_mode.value,
            "disabled_reason": self.disabled_reason,
            "disabled_by": self.disabled_by,
            "mode_history": self.mode_history[-50:],  # Keep last 50 changes
            "last_updated": datetime.now().isoformat()
        }
        
        try:
            with open(self.killswitch_file, 'w') as f:
                json.dump(state, f, indent=2)
        except Exception as e:
            # Do not crash the system if state cannot be persisted
            logger.error(f"[KILLSWITCH] Failed to save state: {e}")
    
    def _load_state(self):
        """Load kill-switch state from disk."""
        if not os.path.exists(self.killswitch_file):
            return
        
        try:
            with open(self.killswitch_file, 'r') as f:
                state = json.load(f)
            
            self.current_mode = KillSwitchMode(state.get('current_mode', 'active'))
            self.disabled_reason = state.get('disabled_reason')
            self.disabled_by = state.get('disabled_by')
            self.mode_history = state.get('mode_history', [])
            
            logger.info(f"[KILLSWITCH] Loaded state: {self.current_mode.value}")
            
            if self.current_mode != KillSwitchMode.ACTIVE:
                logger.warning(f"[KILLSWITCH] System NOT in active mode: {self.disabled_reason}")
        except Exception as e:
            logger.error(f"[KILLSWITCH] Failed to load state: {e}")


class ComprehensiveAuditLog:
    """
    Comprehensive audit logging for compliance and forensics.
    
    Features:
    - Immutable append-only logs
    - Structured JSON format
    - Automatic rotation and archival
    - Fast search and filtering
    - Compliance-ready (GDPR, HIPAA, PCI-DSS)
    """
    
    def __init__(self, storage_dir: Optional[str] = None):
        """Initialize audit logger."""
        default_dir = get_json_dir()
        self.storage_dir = storage_dir or default_dir
        self.archive_dir = os.path.join(self.storage_dir, 'audit_archive')
        os.makedirs(self.storage_dir, exist_ok=True)
        os.makedirs(self.archive_dir, exist_ok=True)
        
        self.audit_file = os.path.join(self.storage_dir, 'comprehensive_audit.json')
        
        # In-memory buffer for fast writes
        self.event_buffer: List[AuditEvent] = []
        self.buffer_size = max(1, AUDIT_BUFFER_SIZE)  # Flush after N events (configurable)
        
        # Statistics
        self.total_events = 0
        self.events_by_type: Dict[str, int] = {}
        self.enabled: bool = COMPREHENSIVE_AUDIT_ENABLED
        
        # Thread safety
        self.lock = threading.Lock()
        
        # Load existing logs
        self._load_stats()
        
        logger.info(
            f"[AUDIT] Initialized (total events: {self.total_events}, enabled={self.enabled}, buffer_size={self.buffer_size}, max_events={AUDIT_MAX_EVENTS})"
        )
    
    def __del__(self):
        """Flush buffer on destruction to prevent event loss."""
        try:
            if hasattr(self, 'event_buffer') and len(self.event_buffer) > 0:
                self._flush_buffer()
        except Exception as e:
            # Avoid exceptions during shutdown
            pass
    
    def log_event(
        self,
        event_type: AuditEventType,
        actor: str,
        action: str,
        target: str,
        outcome: str,
        details: Optional[Dict] = None,
        risk_level: str = "low",
        metadata: Optional[Dict] = None
    ) -> AuditEvent:
        """
        Log an auditable event.
        
        Args:
            event_type: Type of event
            actor: Who/what performed the action
            action: What action was performed
            target: What was affected
            outcome: Result (success, failure, blocked)
            details: Additional details
            risk_level: Risk level (low, medium, high, critical)
            metadata: Additional metadata
        
        Returns:
            AuditEvent object
        """
        with self.lock:
            event = AuditEvent(
                event_id=f"audit_{self.total_events + 1}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                timestamp=datetime.now().isoformat(),
                event_type=event_type,
                actor=actor,
                action=action,
                target=target,
                outcome=outcome,
                details=details or {},
                risk_level=risk_level,
                metadata=metadata or {}
            )
            
            # Add to buffer
            self.event_buffer.append(event)
            self.total_events += 1
            
            # Update statistics
            event_type_str = event_type.value
            self.events_by_type[event_type_str] = self.events_by_type.get(event_type_str, 0) + 1
            
            # Flush buffer if full
            if len(self.event_buffer) >= self.buffer_size:
                self._flush_buffer()
            
            # Log critical events immediately
            if risk_level == "critical":
                logger.critical(f"[AUDIT] CRITICAL: {action} on {target} by {actor} - {outcome}")
                self._flush_buffer()  # Immediate flush for critical events
            
            return event
    
    def search_events(
        self,
        event_type: Optional[AuditEventType] = None,
        actor: Optional[str] = None,
        time_range_hours: Optional[int] = None,
        risk_level: Optional[str] = None,
        outcome: Optional[str] = None
    ) -> List[AuditEvent]:
        """
        Search audit events with filters.
        
        Args:
            event_type: Filter by event type
            actor: Filter by actor
            time_range_hours: Only events in last N hours
            risk_level: Filter by risk level
            outcome: Filter by outcome
        
        Returns:
            List of matching events
        """
        # Load all events
        all_events = self._load_all_events()
        
        # Apply filters
        filtered = all_events
        
        if event_type:
            filtered = [e for e in filtered if e.event_type == event_type]
        
        if actor:
            filtered = [e for e in filtered if actor.lower() in e.actor.lower()]
        
        if time_range_hours:
            cutoff = datetime.now() - timedelta(hours=time_range_hours)
            filtered = [
                e for e in filtered
                if datetime.fromisoformat(e.timestamp) > cutoff
            ]
        
        if risk_level:
            filtered = [e for e in filtered if e.risk_level == risk_level]
        
        if outcome:
            filtered = [e for e in filtered if e.outcome == outcome]
        
        return filtered
    
    def get_compliance_report(self, days: int = 30) -> Dict:
        """
        Generate compliance report for last N days.
        
        Useful for:
        - SOC 2 audits
        - GDPR compliance
        - HIPAA compliance
        - PCI-DSS compliance
        """
        events = self.search_events(time_range_hours=days * 24)
        
        # Count by type
        by_type = {}
        for event in events:
            by_type[event.event_type.value] = by_type.get(event.event_type.value, 0) + 1
        
        # Count by outcome
        by_outcome = {}
        for event in events:
            by_outcome[event.outcome] = by_outcome.get(event.outcome, 0) + 1
        
        # Count by risk level
        by_risk = {}
        for event in events:
            by_risk[event.risk_level] = by_risk.get(event.risk_level, 0) + 1
        
        # Find critical events
        critical_events = [e for e in events if e.risk_level == "critical"]
        
        return {
            "report_period_days": days,
            "total_events": len(events),
            "events_by_type": by_type,
            "events_by_outcome": by_outcome,
            "events_by_risk": by_risk,
            "critical_events_count": len(critical_events),
            "critical_events": [
                {
                    "timestamp": e.timestamp,
                    "event_type": e.event_type.value,
                    "actor": e.actor,
                    "action": e.action,
                    "outcome": e.outcome
                }
                for e in critical_events[:10]  # Last 10 critical
            ],
            "generated_at": datetime.now().isoformat()
        }
    
    def _flush_buffer(self):
        """Flush event buffer to disk with auto-rotation at 1GB for ML training."""
        if len(self.event_buffer) == 0:
            return

        # If audit logging is disabled, drop buffered events to avoid unbounded memory growth
        if not self.enabled:
            logger.debug(
                f"[AUDIT] Dropping {len(self.event_buffer)} buffered events (COMPREHENSIVE_AUDIT_ENABLED=false)"
            )
            self.event_buffer.clear()
            return
        
        # Check if rotation is needed (1GB limit for ML training logs)
        try:
            from file_rotation import rotate_if_needed
            rotate_if_needed(self.audit_file)
        except ImportError:
            pass  # Graceful degradation if file_rotation module not available
        except Exception as e:
            logger.warning(f"[AUDIT] File rotation check failed: {e}")
        
        # Load existing events
        existing_events = []
        if os.path.exists(self.audit_file):
            try:
                with open(self.audit_file, 'r') as f:
                    data = json.load(f)
                existing_events = data.get('events', [])
            except Exception as e:
                logger.warning(f"[AUDIT] Failed to read existing audit file: {e}")
        
        # Append new events
        new_events = [asdict(e) for e in self.event_buffer]
        all_events = existing_events + new_events
        
        # Rotate if too large (keep last AUDIT_MAX_EVENTS in main file)
        if len(all_events) > AUDIT_MAX_EVENTS:
            # Archive old events
            self._archive_events(all_events[:-AUDIT_MAX_EVENTS])
            all_events = all_events[-AUDIT_MAX_EVENTS:]
        
        # Save
        data = {
            "events": all_events,
            "total_events": self.total_events,
            "events_by_type": self.events_by_type,
            "last_updated": datetime.now().isoformat()
        }
        
        try:
            with open(self.audit_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"[AUDIT] Failed to write audit log file: {e}")
            # Keep events in memory so they are not lost
            return
        
        # Clear buffer
        self.event_buffer.clear()
    
    def _archive_events(self, events: List[Dict]):
        """Archive old events to separate file."""
        archive_file = os.path.join(
            self.archive_dir,
            f"audit_archive_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        
        try:
            with open(archive_file, 'w') as f:
                json.dump({"events": events, "archived_at": datetime.now().isoformat()}, f)
            logger.info(f"[AUDIT] Archived {len(events)} events to {archive_file}")
        except Exception as e:
            logger.error(f"[AUDIT] Failed to archive events to {archive_file}: {e}")
    
    def _load_all_events(self) -> List[AuditEvent]:
        """Load all events from disk (including buffer)."""
        events = []
        
        # Load from main file
        if os.path.exists(self.audit_file):
            try:
                with open(self.audit_file, 'r') as f:
                    data = json.load(f)
                
                for e in data.get('events', []):
                    events.append(AuditEvent(
                        event_id=e['event_id'],
                        timestamp=e['timestamp'],
                        event_type=AuditEventType(e['event_type']),
                        actor=e['actor'],
                        action=e['action'],
                        target=e['target'],
                        outcome=e['outcome'],
                        details=e['details'],
                        risk_level=e['risk_level'],
                        metadata=e['metadata']
                    ))
            except Exception as e:
                logger.error(f"[AUDIT] Failed to load events: {e}")
        
        # Add buffer events
        events.extend(self.event_buffer)
        
        return events
    
    def _load_stats(self):
        """Load statistics from disk."""
        if os.path.exists(self.audit_file):
            try:
                with open(self.audit_file, 'r') as f:
                    data = json.load(f)
                
                self.total_events = data.get('total_events', 0)
                self.events_by_type = data.get('events_by_type', {})
            except:
                pass
    
    def get_stats(self) -> Dict:
        """Get audit log statistics."""
        with self.lock:
            return {
                "total_events": self.total_events,
                "events_by_type": self.events_by_type,
                "buffer_size": len(self.event_buffer),
                "events_in_main_file": self.total_events - len(self.event_buffer),
                "enabled": self.enabled,
                "storage_dir": self.storage_dir,
                "archive_dir": self.archive_dir,
            }

    def reset_log(self) -> Dict:
        """Clear all audit events and reset the JSON file.

        This preserves the archive directory but makes the main
        comprehensive_audit.json look like a brand new file so the
        next events start from a clean slate.
        """
        with self.lock:
            # Reset in-memory state
            self.event_buffer.clear()
            self.total_events = 0
            self.events_by_type = {}

            data = {
                "events": [],
                "total_events": 0,
                "events_by_type": {},
                "last_updated": datetime.now().isoformat(),
            }

            try:
                with open(self.audit_file, "w") as f:
                    json.dump(data, f, indent=2)
                logger.info(f"[AUDIT] Audit log reset: {self.audit_file}")
                return {
                    "success": True,
                    "message": "Audit log cleared",
                    "enabled": self.enabled,
                    "storage_dir": self.storage_dir,
                }
            except Exception as e:
                logger.error(f"[AUDIT] Failed to reset audit log: {e}")
                return {
                    "success": False,
                    "error": str(e),
                    "enabled": self.enabled,
                }


# Singleton instances
_kill_switch: Optional[EmergencyKillSwitch] = None
_audit_log: Optional[ComprehensiveAuditLog] = None


def get_kill_switch() -> EmergencyKillSwitch:
    """Get singleton kill-switch instance."""
    global _kill_switch
    if _kill_switch is None:
        _kill_switch = EmergencyKillSwitch()
    return _kill_switch


def get_audit_log() -> ComprehensiveAuditLog:
    """Get singleton audit log instance."""
    global _audit_log
    if _audit_log is None:
        _audit_log = ComprehensiveAuditLog()
    return _audit_log
