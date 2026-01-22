"""
MODULE H: Policy Governance & Approval Gates

Adds human-in-the-loop approval requirements for high-risk automated actions.
Reduces automation risk by requiring explicit approval for critical decisions.

Risk Level: LOW (Safety Improvement - adds safeguards)
"""

import json
import os
import logging
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from enum import Enum
import threading

from AI.path_helper import get_json_dir

logger = logging.getLogger(__name__)

# Feature flag to allow disabling governance layer in constrained deployments
POLICY_GOVERNANCE_ENABLED = os.getenv("POLICY_GOVERNANCE_ENABLED", "true").lower() == "true"


class ApprovalStatus(str, Enum):
    """Status of approval requests."""
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    AUTO_APPROVED = "auto_approved"


class RiskLevel(str, Enum):
    """Risk level of proposed actions."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ApprovalRequest:
    """Request for human approval of an automated action."""
    request_id: str
    timestamp: str
    proposed_action: str
    target: str  # What the action affects (IP, peer, model, etc.)
    risk_level: RiskLevel
    confidence: float
    evidence: Dict
    rationale: str
    expires_at: str
    status: ApprovalStatus
    approved_by: Optional[str] = None
    approved_at: Optional[str] = None
    rejection_reason: Optional[str] = None


@dataclass
class PolicyRule:
    """Governance policy rule."""
    rule_id: str
    action_pattern: str  # Regex pattern matching action names
    requires_approval: bool
    min_confidence_for_auto: float  # Below this, always need approval
    approval_timeout_seconds: int
    max_auto_approvals_per_hour: int
    description: str


class PolicyGovernance:
    """
    Policy governance system with human-in-the-loop approval.
    
    Features:
    - Approval gates for high-risk actions
    - Configurable policies per action type
    - Approval request queue management
    - Auto-approval with rate limits
    - Audit trail of all decisions
    
    Safety Features:
    - Default deny for unknown actions
    - Automatic expiration of pending requests
    - Rate limiting on auto-approvals
    - Complete audit logging
    """
    
    def __init__(self, storage_dir: Optional[str] = None):
        """Initialize policy governance."""
        # Use central JSON directory by default, while allowing override
        self.storage_dir = storage_dir or get_json_dir()
        os.makedirs(self.storage_dir, exist_ok=True)
        
        self.approvals_file = os.path.join(self.storage_dir, 'approval_requests.json')
        self.policies_file = os.path.join(self.storage_dir, 'governance_policies.json')
        self.audit_file = os.path.join(self.storage_dir, 'governance_audit.json')
        
        # State
        self.approval_requests: List[ApprovalRequest] = []
        self.policies: Dict[str, PolicyRule] = {}
        self.auto_approval_counts: Dict[str, List[float]] = {}  # action -> timestamps
        
        # Thread safety
        self.lock = threading.Lock()
        
        # Load state
        self._load_policies()
        self._load_approvals()

        logger.info(
            f"[GOVERNANCE] Initialized with {len(self.policies)} policies (enabled={POLICY_GOVERNANCE_ENABLED})"
        )
    
    def _load_policies(self):
        """Load or initialize default policies."""
        if os.path.exists(self.policies_file):
            try:
                with open(self.policies_file, 'r') as f:
                    data = json.load(f)
                
                for rule_id, rule_data in data.get('policies', {}).items():
                    self.policies[rule_id] = PolicyRule(**rule_data)
                
                logger.info(f"[GOVERNANCE] Loaded {len(self.policies)} policies")
                return
            except Exception as e:
                logger.error(f"[GOVERNANCE] Failed to load policies: {e}")
        
        # Initialize default policies
        self.policies = {
            "block_ip": PolicyRule(
                rule_id="block_ip",
                action_pattern="block_ip.*",
                requires_approval=False,  # Can auto-approve
                min_confidence_for_auto=0.85,  # High confidence required
                approval_timeout_seconds=300,  # 5 minutes
                max_auto_approvals_per_hour=50,
                description="IP blocking requires 85% confidence for auto-approval"
            ),
            "block_peer": PolicyRule(
                rule_id="block_peer",
                action_pattern="block_peer.*|isolate_peer.*",
                requires_approval=True,  # Always need human approval
                min_confidence_for_auto=1.0,  # Never auto-approve
                approval_timeout_seconds=600,  # 10 minutes
                max_auto_approvals_per_hour=0,
                description="Peer blocking always requires human approval (affects P2P network)"
            ),
            "model_rollback": PolicyRule(
                rule_id="model_rollback",
                action_pattern="rollback_model.*|restore_model.*",
                requires_approval=True,  # Always need approval
                min_confidence_for_auto=1.0,
                approval_timeout_seconds=900,  # 15 minutes
                max_auto_approvals_per_hour=0,
                description="Model rollback always requires human approval (major impact)"
            ),
            "rate_limit": PolicyRule(
                rule_id="rate_limit",
                action_pattern="rate_limit.*",
                requires_approval=False,
                min_confidence_for_auto=0.70,  # Moderate confidence OK
                approval_timeout_seconds=180,  # 3 minutes
                max_auto_approvals_per_hour=100,
                description="Rate limiting can auto-approve with 70% confidence"
            ),
            "quarantine": PolicyRule(
                rule_id="quarantine",
                action_pattern="quarantine.*",
                requires_approval=True,
                min_confidence_for_auto=0.95,  # Very high confidence for auto
                approval_timeout_seconds=600,
                max_auto_approvals_per_hour=10,
                description="Quarantine needs 95% confidence or human approval"
            ),
            "honeypot_redirect": PolicyRule(
                rule_id="honeypot_redirect",
                action_pattern="honeypot.*|redirect.*",
                requires_approval=False,
                min_confidence_for_auto=0.80,
                approval_timeout_seconds=300,
                max_auto_approvals_per_hour=30,
                description="Honeypot redirect can auto-approve with 80% confidence"
            ),
            "alert_only": PolicyRule(
                rule_id="alert_only",
                action_pattern="alert.*|log.*|notify.*",
                requires_approval=False,
                min_confidence_for_auto=0.50,  # Low bar for alerts
                approval_timeout_seconds=60,
                max_auto_approvals_per_hour=1000,
                description="Alerts and logging rarely need approval"
            )
        }
        
        self._save_policies()
    
    def request_approval(
        self,
        proposed_action: str,
        target: str,
        confidence: float,
        evidence: Dict,
        rationale: str
    ) -> ApprovalRequest:
        """
        Request approval for a proposed automated action.
        
        Args:
            proposed_action: Name of action to perform
            target: What the action affects
            confidence: Confidence level (0-1)
            evidence: Supporting evidence for the decision
            rationale: Human-readable explanation
        
        Returns:
            ApprovalRequest object
        """
        if not POLICY_GOVERNANCE_ENABLED:
            # Governance disabled: treat as auto-approved but still log
            logger.info(
                f"[GOVERNANCE] Governance disabled; treating {proposed_action} on {target} as auto-approved"
            )
            now = datetime.now().isoformat()
            return ApprovalRequest(
                request_id="governance_disabled",
                timestamp=now,
                proposed_action=proposed_action,
                target=target,
                risk_level=self._assess_risk(proposed_action, confidence),
                confidence=confidence,
                evidence=evidence,
                rationale=rationale,
                expires_at=now,
                status=ApprovalStatus.AUTO_APPROVED,
                approved_by="system",
                approved_at=now,
            )

        with self.lock:
            # Find applicable policy
            policy = self._find_policy(proposed_action)
            
            if not policy:
                # Default deny - unknown actions need approval
                policy = PolicyRule(
                    rule_id="default_deny",
                    action_pattern=".*",
                    requires_approval=True,
                    min_confidence_for_auto=1.0,
                    approval_timeout_seconds=600,
                    max_auto_approvals_per_hour=0,
                    description="Unknown actions require approval (default deny)"
                )
            
            # Determine risk level
            risk_level = self._assess_risk(proposed_action, confidence)
            
            # Check if can auto-approve
            can_auto_approve = self._can_auto_approve(policy, confidence, proposed_action)
            
            # Create approval request
            expires_at = datetime.now() + timedelta(seconds=policy.approval_timeout_seconds)
            
            request = ApprovalRequest(
                request_id=f"approval_{len(self.approval_requests) + 1}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                timestamp=datetime.now().isoformat(),
                proposed_action=proposed_action,
                target=target,
                risk_level=risk_level,
                confidence=confidence,
                evidence=evidence,
                rationale=rationale,
                expires_at=expires_at.isoformat(),
                status=ApprovalStatus.AUTO_APPROVED if can_auto_approve else ApprovalStatus.PENDING
            )
            
            if can_auto_approve:
                request.approved_by = "system"
                request.approved_at = datetime.now().isoformat()
                
                # Track auto-approval
                if proposed_action not in self.auto_approval_counts:
                    self.auto_approval_counts[proposed_action] = []
                self.auto_approval_counts[proposed_action].append(datetime.now().timestamp())
                
                logger.info(f"[GOVERNANCE] Auto-approved: {proposed_action} on {target} (confidence={confidence:.2f})")
            else:
                logger.warning(f"[GOVERNANCE] Approval required: {proposed_action} on {target} (confidence={confidence:.2f})")
            
            self.approval_requests.append(request)
            self._save_approvals()
            self._audit_log(request, "created")
            
            return request
    
    def approve_request(self, request_id: str, approved_by: str) -> Dict:
        """
        Approve a pending request.
        
        Args:
            request_id: ID of request to approve
            approved_by: Username/ID of approver
        
        Returns:
            Result dict
        """
        if not POLICY_GOVERNANCE_ENABLED:
            return {"success": False, "error": "Governance disabled"}

        with self.lock:
            request = self._find_request(request_id)
            
            if not request:
                return {"success": False, "error": "Request not found"}
            
            if request.status != ApprovalStatus.PENDING:
                return {"success": False, "error": f"Request is {request.status}, cannot approve"}
            
            # Check if expired
            if datetime.now() > datetime.fromisoformat(request.expires_at):
                request.status = ApprovalStatus.EXPIRED
                self._save_approvals()
                return {"success": False, "error": "Request has expired"}
            
            # Approve
            request.status = ApprovalStatus.APPROVED
            request.approved_by = approved_by
            request.approved_at = datetime.now().isoformat()
            
            self._save_approvals()
            self._audit_log(request, "approved", approved_by)
            
            logger.info(f"[GOVERNANCE] Request {request_id} approved by {approved_by}")
            
            return {
                "success": True,
                "request_id": request_id,
                "approved_by": approved_by,
                "action": request.proposed_action,
                "target": request.target
            }
    
    def reject_request(self, request_id: str, rejected_by: str, reason: str) -> Dict:
        """
        Reject a pending request.
        
        Args:
            request_id: ID of request to reject
            rejected_by: Username/ID of rejector
            reason: Reason for rejection
        
        Returns:
            Result dict
        """
        if not POLICY_GOVERNANCE_ENABLED:
            return {"success": False, "error": "Governance disabled"}

        with self.lock:
            request = self._find_request(request_id)
            
            if not request:
                return {"success": False, "error": "Request not found"}
            
            if request.status != ApprovalStatus.PENDING:
                return {"success": False, "error": f"Request is {request.status}, cannot reject"}
            
            # Reject
            request.status = ApprovalStatus.REJECTED
            request.approved_by = rejected_by
            request.approved_at = datetime.now().isoformat()
            request.rejection_reason = reason
            
            self._save_approvals()
            self._audit_log(request, "rejected", rejected_by, reason)
            
            logger.info(f"[GOVERNANCE] Request {request_id} rejected by {rejected_by}: {reason}")
            
            return {
                "success": True,
                "request_id": request_id,
                "rejected_by": rejected_by,
                "reason": reason
            }
    
    def get_pending_requests(self) -> List[ApprovalRequest]:
        """Get all pending approval requests (not expired)."""
        with self.lock:
            self._expire_old_requests()
            return [r for r in self.approval_requests if r.status == ApprovalStatus.PENDING]
    
    def _find_request(self, request_id: str) -> Optional[ApprovalRequest]:
        """Find request by ID."""
        for request in self.approval_requests:
            if request.request_id == request_id:
                return request
        return None
    
    def _find_policy(self, action: str) -> Optional[PolicyRule]:
        """Find applicable policy for an action."""
        import re
        
        for policy in self.policies.values():
            if re.match(policy.action_pattern, action):
                return policy
        return None
    
    def _can_auto_approve(self, policy: PolicyRule, confidence: float, action: str) -> bool:
        """Check if action can be auto-approved based on policy."""
        # Check if policy allows auto-approval
        if policy.requires_approval and confidence < 1.0:
            return False
        
        # Check confidence threshold
        if confidence < policy.min_confidence_for_auto:
            return False
        
        # Check rate limit
        if action in self.auto_approval_counts:
            # Clean old timestamps (older than 1 hour)
            cutoff = datetime.now().timestamp() - 3600
            self.auto_approval_counts[action] = [
                ts for ts in self.auto_approval_counts[action] if ts > cutoff
            ]
            
            # Check if exceeded rate limit
            if len(self.auto_approval_counts[action]) >= policy.max_auto_approvals_per_hour:
                logger.warning(f"[GOVERNANCE] Auto-approval rate limit exceeded for {action}")
                return False
        
        return True
    
    def _assess_risk(self, action: str, confidence: float) -> RiskLevel:
        """Assess risk level of an action."""
        # Risk based on action type and confidence
        if "rollback" in action or "block_peer" in action:
            return RiskLevel.CRITICAL
        elif "quarantine" in action or "block" in action:
            return RiskLevel.HIGH if confidence < 0.90 else RiskLevel.MEDIUM
        elif "rate_limit" in action or "honeypot" in action:
            return RiskLevel.MEDIUM if confidence < 0.80 else RiskLevel.LOW
        else:
            return RiskLevel.LOW
    
    def _expire_old_requests(self):
        """Mark expired pending requests."""
        now = datetime.now()
        
        for request in self.approval_requests:
            if request.status == ApprovalStatus.PENDING:
                if now > datetime.fromisoformat(request.expires_at):
                    request.status = ApprovalStatus.EXPIRED
                    logger.info(f"[GOVERNANCE] Request {request.request_id} expired")
        
        self._save_approvals()
    
    def _audit_log(self, request: ApprovalRequest, action: str, actor: str = "system", details: str = ""):
        """Log governance action to audit trail."""
        audit_entry = {
            "timestamp": datetime.now().isoformat(),
            "request_id": request.request_id,
            "action": action,
            "actor": actor,
            "proposed_action": request.proposed_action,
            "target": request.target,
            "risk_level": request.risk_level.value,
            "status": request.status.value,
            "details": details
        }
        
        # Append to audit log
        audit_log: List[dict] = []
        if os.path.exists(self.audit_file):
            try:
                with open(self.audit_file, 'r') as f:
                    loaded = json.load(f)
                    if isinstance(loaded, list):
                        audit_log = loaded
            except Exception as e:
                logger.warning(f"[GOVERNANCE] Failed to read audit log: {e}")

        audit_log.append(audit_entry)

        # Keep last 1000 entries
        audit_log = audit_log[-1000:]

        try:
            with open(self.audit_file, 'w') as f:
                json.dump(audit_log, f, indent=2)
        except Exception as e:
            logger.error(f"[GOVERNANCE] Failed to write audit log: {e}")
    
    def _save_approvals(self):
        """Save approval requests to disk."""
        data = {
            "approval_requests": [
                asdict(r) for r in self.approval_requests[-500:]  # Keep last 500
            ],
            "last_updated": datetime.now().isoformat()
        }

        try:
            with open(self.approvals_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"[GOVERNANCE] Failed to save approvals: {e}")
    
    def _load_approvals(self):
        """Load approval requests from disk."""
        if not os.path.exists(self.approvals_file):
            return
        
        try:
            with open(self.approvals_file, 'r') as f:
                data = json.load(f)
            
            self.approval_requests = [
                ApprovalRequest(
                    request_id=r['request_id'],
                    timestamp=r['timestamp'],
                    proposed_action=r['proposed_action'],
                    target=r['target'],
                    risk_level=RiskLevel(r['risk_level']),
                    confidence=r['confidence'],
                    evidence=r['evidence'],
                    rationale=r['rationale'],
                    expires_at=r['expires_at'],
                    status=ApprovalStatus(r['status']),
                    approved_by=r.get('approved_by'),
                    approved_at=r.get('approved_at'),
                    rejection_reason=r.get('rejection_reason')
                )
                for r in data.get('approval_requests', [])
            ]
            
            logger.info(f"[GOVERNANCE] Loaded {len(self.approval_requests)} approval requests")
        except Exception as e:
            logger.error(f"[GOVERNANCE] Failed to load approvals: {e}")
    
    def _save_policies(self):
        """Save policies to disk."""
        data = {
            "policies": {
                rule_id: asdict(rule) for rule_id, rule in self.policies.items()
            },
            "last_updated": datetime.now().isoformat()
        }

        try:
            with open(self.policies_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"[GOVERNANCE] Failed to save policies: {e}")
    
    def get_stats(self) -> Dict:
        """Get governance statistics."""
        with self.lock:
            self._expire_old_requests()
            
            total = len(self.approval_requests)
            pending = sum(1 for r in self.approval_requests if r.status == ApprovalStatus.PENDING)
            approved = sum(1 for r in self.approval_requests if r.status == ApprovalStatus.APPROVED)
            rejected = sum(1 for r in self.approval_requests if r.status == ApprovalStatus.REJECTED)
            auto_approved = sum(1 for r in self.approval_requests if r.status == ApprovalStatus.AUTO_APPROVED)
            expired = sum(1 for r in self.approval_requests if r.status == ApprovalStatus.EXPIRED)
            
            return {
                "total_requests": total,
                "pending_requests": pending,
                "approved_requests": approved,
                "rejected_requests": rejected,
                "auto_approved_requests": auto_approved,
                "expired_requests": expired,
                "total_policies": len(self.policies),
                "auto_approval_rate": auto_approved / max(1, total),
                "enabled": POLICY_GOVERNANCE_ENABLED,
            }


# Singleton instance
_policy_governance: Optional[PolicyGovernance] = None


def get_policy_governance() -> PolicyGovernance:
    """Get singleton policy governance instance."""
    global _policy_governance
    if _policy_governance is None:
        _policy_governance = PolicyGovernance()
    return _policy_governance
