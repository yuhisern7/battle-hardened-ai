"""Deterministic Step 21 semantic execution-denial gate (policy-driven).

This module is the final gate before actions/decisions leave the
21-layer ensemble. It is intentionally deterministic and static:

- Deny-by-default semantics.
- Read-only policy loaded from policies/step21/ via step21_policy.
- No network calls, randomness, or time-based heuristics.
- Every decision is logged to the comprehensive audit log.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict

from .step21_policy import load_step21_policy

logger = logging.getLogger(__name__)


def _safe_str(value: Any) -> str:
    try:
        return str(value)
    except Exception:
        return "<unprintable>"


def _evaluate_network_request(request: Dict[str, Any], policy: Dict[str, Any]) -> tuple[bool, str]:
    """Evaluate a network_request action using policy-defined rules."""

    payload = request.get("payload", {}) or {}
    action_defs = policy.get("actions", {}) or {}
    action_policy = action_defs.get("network_request", {}) or {}
    schema = action_policy.get("payload_schema", {}) or {}

    endpoint_rules = schema.get("endpoint", {})
    method_rules = schema.get("method", {})

    endpoint = payload.get("endpoint")
    method = payload.get("method")

    # Basic type and presence checks
    if not isinstance(endpoint, str) or not endpoint:
        return False, "struct_missing_or_invalid_endpoint"
    if not isinstance(method, str) or not method:
        return False, "struct_missing_or_invalid_method"

    # Enforce allowed HTTP verbs
    allowed_methods = set(method_rules.get("enum", []) or [])
    if allowed_methods:
        if method.upper() not in allowed_methods:
            return False, "method_not_allowed"

    # Enforce maximum endpoint length
    max_len = int(endpoint_rules.get("max_length", 0) or 0)
    if max_len and len(endpoint) > max_len:
        return False, "endpoint_too_long"

    # Enforce printable-only characters when requested
    if endpoint_rules.get("no_control_chars", False):
        for ch in endpoint:
            code = ord(ch)
            if code < 32 or code == 127:
                return False, "endpoint_contains_control_chars"

    # Trust threshold enforcement (if configured)
    trust_cfg = action_policy.get("trust", {}) or {}
    min_score = float(trust_cfg.get("min_score", 0.0) or 0.0)
    trust_score = request.get("trust_score")
    try:
        if trust_score is None:
            return False, "missing_trust_score"
        score_val = float(trust_score)
    except (TypeError, ValueError):
        return False, "invalid_trust_score_type"

    if score_val < min_score:
        return False, "trust_below_minimum"

    return True, "ok"


def evaluate_step21(request: Dict[str, Any]) -> Dict[str, Any]:
    """Evaluate a request against the externalized Step 21 policy.

    Returns a JSON-friendly dict:

        {
          "allow": bool,
          "reason_code": str,
          "policy_version": str | None,
          "policy_hash": str | None,
        }

    Any error loading or validating the policy results in allow=False
    with an appropriate reason_code. Callers must treat allow=False as
    a hard DENY for execution semantics.
    """

    # Default deny-by-default stance
    allow = False
    reason_code = "policy_error"
    policy_version: str | None = None
    policy_hash: str | None = None

    policy_obj, status = load_step21_policy(force_reload=False)
    if not policy_obj or not status.get("loaded") or not status.get("manifest_ok"):
        reason_code = _safe_str(status.get("error") or "policy_not_loaded")
        _log_step21_audit(request, allow=False, reason_code=reason_code, policy_version=None, policy_hash=None)
        return {
            "allow": False,
            "reason_code": reason_code,
            "policy_version": None,
            "policy_hash": None,
        }

    policy = policy_obj.raw
    policy_version = policy_obj.version
    policy_hash = policy_obj.policy_hash

    try:
        role = _safe_str(request.get("entity_role") or "")
        action = _safe_str(request.get("action") or "")

        # Role/action allow-list
        roles_def = policy.get("roles", {}) or {}
        role_def = roles_def.get(role, {}) or {}
        allowed_actions = set(role_def.get("allowed_actions", []) or [])
        if action not in allowed_actions:
            allow = False
            reason_code = "action_not_permitted_for_role"
        else:
            # For now we only implement the network_request structural
            # policy, which is the gateway Step 21 surface.
            if action == "network_request":
                allow, reason_code = _evaluate_network_request(request, policy)
            else:
                # Unknown action even if listed – fail closed until
                # explicitly modeled in policy module.
                allow = False
                reason_code = "unhandled_action_type"
    except Exception as exc:  # pragma: no cover - defensive
        allow = False
        reason_code = f"gate_evaluation_error:{type(exc).__name__}"

    _log_step21_audit(
        request,
        allow=allow,
        reason_code=reason_code,
        policy_version=policy_version,
        policy_hash=policy_hash,
    )

    return {
        "allow": bool(allow),
        "reason_code": reason_code,
        "policy_version": policy_version,
        "policy_hash": policy_hash,
    }


def _log_step21_audit(
    request: Dict[str, Any],
    allow: bool,
    reason_code: str,
    policy_version: str | None,
    policy_hash: str | None,
) -> None:
    """Emit a comprehensive audit log entry for the Step 21 decision.

    This is best-effort only and must never raise.
    """

    try:
        from .emergency_killswitch import get_audit_log, AuditEventType  # type: ignore[import]

        audit = get_audit_log()
        actor = _safe_str(request.get("entity_id") or "unknown_entity")
        # Build action label safely without nested conflicting quotes in f-string
        action_name = _safe_str(request.get("action") or "unknown_action")
        action = f"step21:{action_name}"
        target = _safe_str((request.get("payload") or {}).get("endpoint") or "step21")
        outcome = "allowed" if allow else "blocked"

        details = {
            "reason_code": reason_code,
            "policy_version": policy_version,
            "policy_hash": policy_hash,
            "trust_score": request.get("trust_score"),
            "entity_role": request.get("entity_role"),
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        }

        risk_level = "low" if allow else "high"
        event_type = AuditEventType.ACTION_TAKEN if allow else AuditEventType.ACTION_BLOCKED

        audit.log_event(
            event_type=event_type,
            actor=actor,
            action=action,
            target=target,
            outcome=outcome,
            details=details,
            risk_level=risk_level,
            metadata={"module": "step21_gate"},
        )
    except Exception:
        # Audit logging must never interfere with gating semantics.
        return


__all__ = ["evaluate_step21"]
