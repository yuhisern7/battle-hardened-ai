"""
MODULE F: Formal Threat Model Enforcement

Defines formal security policies and threat models for ML system behavior.
Enforces rules around what ML models can and cannot do.

Pure documentation + policy configuration - no code execution changes.

Risk Level: NONE (Just defines rules, doesn't execute)
"""

import json
import os
import logging
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, asdict
from datetime import datetime
from enum import Enum

from AI.path_helper import get_json_dir

logger = logging.getLogger(__name__)

# Version identifier for the formal threat model/policy set
POLICY_VERSION = os.getenv("FORMAL_THREAT_MODEL_VERSION", "1.0.0")


class ThreatCategory(str, Enum):
    """Categories of threats the system defends against."""
    DATA_POISONING = "data_poisoning"
    MODEL_INVERSION = "model_inversion"
    MEMBERSHIP_INFERENCE = "membership_inference"
    BACKDOOR_ATTACK = "backdoor_attack"
    ADVERSARIAL_EXAMPLES = "adversarial_examples"
    MODEL_EXTRACTION = "model_extraction"
    BYZANTINE_PEER = "byzantine_peer"
    GRADIENT_LEAKAGE = "gradient_leakage"


class ActionType(str, Enum):
    """Actions the system can take."""
    BLOCK_IP = "block_ip"
    RATE_LIMIT = "rate_limit"
    QUARANTINE = "quarantine"
    ALERT = "alert"
    LOG_ONLY = "log_only"
    HONEYPOT_REDIRECT = "honeypot_redirect"
    MODEL_ROLLBACK = "model_rollback"
    ISOLATE_PEER = "isolate_peer"


@dataclass
class ThreatRule:
    """Formal rule defining how to handle a threat."""
    rule_id: str
    threat_category: ThreatCategory
    conditions: Dict  # Conditions that trigger this rule
    allowed_actions: List[ActionType]  # What system is allowed to do
    prohibited_actions: List[ActionType]  # What system must NOT do
    severity_threshold: float  # 0-1, minimum confidence to act
    requires_human_approval: bool
    description: str
    rationale: str  # Why this rule exists


@dataclass
class PolicyConstraint:
    """Constraint on system behavior."""
    constraint_id: str
    constraint_type: str  # 'must_have', 'must_not', 'should_have'
    description: str
    verification_method: str  # How to verify compliance
    applies_to: List[str]  # Which components this applies to


class FormalThreatModel:
    """
    Formal threat model and security policy enforcement.
    
    Defines:
    - What threats the system protects against
    - What actions are allowed vs prohibited
    - Confidence thresholds for automated actions
    - Human-in-the-loop requirements
    - Audit requirements
    
    This is a DECLARATIVE model - it defines rules but doesn't execute them.
    Other modules check these rules before taking action.
    """
    
    def __init__(self, storage_dir: Optional[str] = None):
        """Initialize threat model."""
        default_dir = get_json_dir()
        self.storage_dir = storage_dir or default_dir
        os.makedirs(self.storage_dir, exist_ok=True)
        
        self.threat_model_file = os.path.join(self.storage_dir, 'formal_threat_model.json')
        
        # Threat rules
        self.threat_rules: Dict[str, ThreatRule] = {}
        self.policy_constraints: List[PolicyConstraint] = []
        self.policy_version: str = POLICY_VERSION
        
        # Load or initialize default rules
        if os.path.exists(self.threat_model_file):
            self._load_threat_model()
        else:
            self._initialize_default_rules()
            self._save_threat_model()
        
        logger.info(f"[THREAT-MODEL] Loaded {len(self.threat_rules)} threat rules")
    
    def _initialize_default_rules(self):
        """Initialize default security rules."""
        
        # Rule 1: Data Poisoning Defense
        self.threat_rules["rule_data_poisoning"] = ThreatRule(
            rule_id="rule_data_poisoning",
            threat_category=ThreatCategory.DATA_POISONING,
            conditions={
                "byzantine_score": ">0.7",
                "update_deviation": ">3_sigma"
            },
            allowed_actions=[
                ActionType.QUARANTINE,
                ActionType.LOG_ONLY,
                ActionType.ALERT
            ],
            prohibited_actions=[
                ActionType.BLOCK_IP  # Don't auto-block peers - they might be legitimate
            ],
            severity_threshold=0.8,
            requires_human_approval=True,
            description="Detect and reject poisoned training data from peers",
            rationale="Data poisoning can corrupt ML models. Require human review before rejecting peer data."
        )
        
        # Rule 2: Adversarial Example Detection
        self.threat_rules["rule_adversarial"] = ThreatRule(
            rule_id="rule_adversarial",
            threat_category=ThreatCategory.ADVERSARIAL_EXAMPLES,
            conditions={
                "reconstruction_error": ">threshold",
                "confidence_variance": ">0.5"
            },
            allowed_actions=[
                ActionType.BLOCK_IP,
                ActionType.RATE_LIMIT,
                ActionType.HONEYPOT_REDIRECT,
                ActionType.ALERT
            ],
            prohibited_actions=[],
            severity_threshold=0.75,
            requires_human_approval=False,
            description="Detect and block adversarial examples designed to fool ML models",
            rationale="Adversarial attacks can bypass detection. Safe to auto-block as these are clearly malicious."
        )
        
        # Rule 3: Byzantine Peer Detection
        self.threat_rules["rule_byzantine_peer"] = ThreatRule(
            rule_id="rule_byzantine_peer",
            threat_category=ThreatCategory.BYZANTINE_PEER,
            conditions={
                "krum_score": ">threshold",
                "peer_reputation": "<0.3"
            },
            allowed_actions=[
                ActionType.ISOLATE_PEER,
                ActionType.LOG_ONLY,
                ActionType.ALERT
            ],
            prohibited_actions=[
                ActionType.BLOCK_IP,  # Peer might recover
                ActionType.MODEL_ROLLBACK  # Too drastic without human review
            ],
            severity_threshold=0.85,
            requires_human_approval=True,
            description="Detect malicious peers in federated learning network",
            rationale="False positives could break P2P network. Require human approval."
        )
        
        # Rule 4: Model Extraction Attack
        self.threat_rules["rule_model_extraction"] = ThreatRule(
            rule_id="rule_model_extraction",
            threat_category=ThreatCategory.MODEL_EXTRACTION,
            conditions={
                "query_rate": ">100/min",
                "query_diversity": "<0.2"
            },
            allowed_actions=[
                ActionType.RATE_LIMIT,
                ActionType.ALERT,
                ActionType.LOG_ONLY
            ],
            prohibited_actions=[
                ActionType.BLOCK_IP  # Might be legitimate researcher
            ],
            severity_threshold=0.7,
            requires_human_approval=False,
            description="Detect attempts to steal ML model via repeated queries",
            rationale="Rate limiting is safe defense. Full IP block needs investigation first."
        )
        
        # Rule 5: Backdoor Detection
        self.threat_rules["rule_backdoor"] = ThreatRule(
            rule_id="rule_backdoor",
            threat_category=ThreatCategory.BACKDOOR_ATTACK,
            conditions={
                "model_lineage_break": True,
                "unexpected_accuracy_on_trigger": ">0.9"
            },
            allowed_actions=[
                ActionType.MODEL_ROLLBACK,
                ActionType.QUARANTINE,
                ActionType.ALERT
            ],
            prohibited_actions=[],
            severity_threshold=0.95,  # Very high confidence needed
            requires_human_approval=True,
            description="Detect backdoored ML models with hidden triggers",
            rationale="Backdoors are severe but rare. Rollback needs human verification."
        )
        
        # Policy Constraints
        self.policy_constraints = [
            PolicyConstraint(
                constraint_id="constraint_no_payload_storage",
                constraint_type="must_not",
                description="System MUST NOT store full packet payloads or exploit code",
                verification_method="Code review + runtime monitoring",
                applies_to=["eBPF module", "packet capture", "signature extraction"]
            ),
            PolicyConstraint(
                constraint_id="constraint_audit_logging",
                constraint_type="must_have",
                description="All automated actions MUST be logged with full context",
                verification_method="Audit log completeness check",
                applies_to=["all modules"]
            ),
            PolicyConstraint(
                constraint_id="constraint_explainability",
                constraint_type="must_have",
                description="Every ML decision MUST have an explanation available",
                verification_method="Explainability engine coverage check",
                applies_to=["all ML models", "meta decision engine"]
            ),
            PolicyConstraint(
                constraint_id="constraint_graceful_degradation",
                constraint_type="must_have",
                description="System MUST degrade gracefully if ML models fail",
                verification_method="Fallback to rule-based detection verified",
                applies_to=["pcs_ai.py", "all ML modules"]
            ),
            PolicyConstraint(
                constraint_id="constraint_human_override",
                constraint_type="must_have",
                description="Humans MUST be able to override any automated decision",
                verification_method="Manual override UI exists and tested",
                applies_to=["all automated actions"]
            )
        ]
    
    def check_action_allowed(
        self,
        threat_category: ThreatCategory,
        proposed_action: ActionType,
        confidence: float
    ) -> Dict:
        """
        Check if a proposed action is allowed by the threat model.
        
        Args:
            threat_category: Type of threat detected
            proposed_action: Action system wants to take
            confidence: Confidence level (0-1)
        
        Returns:
            Dict with allowed status and reasoning
        """
        # Find applicable rule
        rule = None
        for r in self.threat_rules.values():
            if r.threat_category == threat_category:
                rule = r
                break
        
        if not rule:
            return {
                "allowed": False,
                "reason": f"No rule defined for {threat_category}",
                "requires_approval": True
            }
        
        # Check if action is prohibited
        if proposed_action in rule.prohibited_actions:
            return {
                "allowed": False,
                "reason": f"Action {proposed_action} is explicitly prohibited for {threat_category}",
                "rule_id": rule.rule_id,
                "requires_approval": True
            }
        
        # Check if action is allowed
        if proposed_action not in rule.allowed_actions:
            return {
                "allowed": False,
                "reason": f"Action {proposed_action} not in allowed list for {threat_category}",
                "rule_id": rule.rule_id,
                "requires_approval": True
            }
        
        # Check confidence threshold
        if confidence < rule.severity_threshold:
            return {
                "allowed": False,
                "reason": f"Confidence {confidence:.2f} below threshold {rule.severity_threshold}",
                "rule_id": rule.rule_id,
                "requires_approval": True
            }
        
        # Check human approval requirement
        if rule.requires_human_approval:
            return {
                "allowed": False,  # Not allowed without human review
                "reason": f"Rule requires human approval",
                "rule_id": rule.rule_id,
                "requires_approval": True
            }
        
        # All checks passed
        return {
            "allowed": True,
            "reason": f"Action permitted by rule {rule.rule_id}",
            "rule_id": rule.rule_id,
            "requires_approval": False,
            "rationale": rule.rationale
        }
    
    def verify_policy_compliance(self) -> Dict:
        """
        Verify system is compliant with all policy constraints.
        
        Returns compliance report.
        """
        compliance_results = []
        
        for constraint in self.policy_constraints:
            # This is a placeholder - real verification would check actual code/behavior
            result = {
                "constraint_id": constraint.constraint_id,
                "constraint_type": constraint.constraint_type,
                "description": constraint.description,
                "compliant": None,  # Would be True/False after verification
                "verification_method": constraint.verification_method,
                "last_checked": datetime.now().isoformat()
            }
            compliance_results.append(result)
        
        return {
            "total_constraints": len(self.policy_constraints),
            "constraints": compliance_results,
            "fully_compliant": None  # Would be computed from results
        }
    
    def get_threat_coverage(self) -> Dict:
        """Get coverage of threat categories."""
        covered = {rule.threat_category for rule in self.threat_rules.values()}
        all_threats = set(ThreatCategory)

        uncovered = all_threats - covered

        total = len(all_threats)
        coverage_percent = (len(covered) / total * 100.0) if total > 0 else 0.0

        return {
            "total_threat_categories": total,
            # Return string values for JSON friendliness
            "covered_categories": [c.value for c in covered],
            "uncovered_categories": [c.value for c in uncovered],
            "coverage_percent": coverage_percent,
        }
    
    def _save_threat_model(self):
        """Save threat model to disk."""
        data = {
            "policy_version": self.policy_version,
            "threat_rules": {
                rule_id: {
                    "rule_id": rule.rule_id,
                    "threat_category": rule.threat_category.value,
                    "conditions": rule.conditions,
                    "allowed_actions": [a.value for a in rule.allowed_actions],
                    "prohibited_actions": [a.value for a in rule.prohibited_actions],
                    "severity_threshold": rule.severity_threshold,
                    "requires_human_approval": rule.requires_human_approval,
                    "description": rule.description,
                    "rationale": rule.rationale,
                }
                for rule_id, rule in self.threat_rules.items()
            },
            "policy_constraints": [asdict(c) for c in self.policy_constraints],
            "last_updated": datetime.now().isoformat(),
        }

        try:
            with open(self.threat_model_file, 'w') as f:
                json.dump(data, f, indent=2)
            logger.info("[THREAT-MODEL] Saved threat model to disk")
        except Exception as e:
            logger.error(f"[THREAT-MODEL] Failed to save threat model: {e}")
    
    def _load_threat_model(self):
        """Load threat model from disk."""
        try:
            with open(self.threat_model_file, 'r') as f:
                data = json.load(f)
            
            # Load rules
            for rule_id, rule_data in data.get('threat_rules', {}).items():
                self.threat_rules[rule_id] = ThreatRule(
                    rule_id=rule_data['rule_id'],
                    threat_category=ThreatCategory(rule_data['threat_category']),
                    conditions=rule_data['conditions'],
                    allowed_actions=[ActionType(a) for a in rule_data['allowed_actions']],
                    prohibited_actions=[ActionType(a) for a in rule_data['prohibited_actions']],
                    severity_threshold=rule_data['severity_threshold'],
                    requires_human_approval=rule_data['requires_human_approval'],
                    description=rule_data['description'],
                    rationale=rule_data['rationale']
                )
            
            # Load constraints
            self.policy_constraints = [
                PolicyConstraint(**c) for c in data.get('policy_constraints', [])
            ]

            # Load policy version if present
            self.policy_version = data.get('policy_version', self.policy_version)
            
            logger.info("[THREAT-MODEL] Loaded threat model from disk")
        except Exception as e:
            logger.error(f"[THREAT-MODEL] Failed to load: {e}")
            self._initialize_default_rules()
    
    def get_stats(self) -> Dict:
        """Get threat model statistics."""
        return {
            "total_rules": len(self.threat_rules),
            "total_constraints": len(self.policy_constraints),
            "threat_coverage": self.get_threat_coverage(),
            "rules_requiring_approval": sum(
                1 for r in self.threat_rules.values() if r.requires_human_approval
            ),
            "policy_version": self.policy_version,
        }


# Singleton instance
_threat_model: Optional[FormalThreatModel] = None


def get_threat_model() -> FormalThreatModel:
    """Get singleton threat model instance."""
    global _threat_model
    if _threat_model is None:
        _threat_model = FormalThreatModel()
    return _threat_model
