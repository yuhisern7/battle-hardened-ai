"""Step 21: Semantic Execution Denial Gate

This module implements the Step 21 semantic gate as a *stateless* validator
that runs AFTER Signals #1–20 and the ensemble/meta-decision engine.

It does NOT execute any actions itself. Instead, it evaluates whether a
proposed interaction is **semantically valid** in terms of:

- State legitimacy   (is the lifecycle / sequence valid?)
- Intent legitimacy  (is this action consistent with role/purpose?)
- Structural legitimacy (does the payload match expected schema/format?)
- Trust sufficiency  (is trust high enough for this operation?)

Usage (conceptual):

    from AI.step21_semantic_gate import evaluate_request

    # Build a request context from Signals #1–20 and your app state
    ctx = {
        "entity_id": "user123",
        "entity_role": "user",
        "action": "create_resource",
        "history": ["authenticated"],
        "payload": {"name": "file.txt", "size": 42},
        "trust_score": 0.9,
        "trust_threshold": 0.5,
    }

    decision = evaluate_request(ctx)
    if decision["verdict"] == "SEMANTICALLY_INVALID":
        # DENY EXECUTION MEANING HERE: no state change, no backend call
        ...

This module is deliberately generic and does not depend on other AI modules;
it can be adapted and wired into pcs_ai/server.py without breaking the
existing 20-signal architecture.
"""

from __future__ import annotations

import base64
import logging
from typing import Any, Dict, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Policy scaffolding (example defaults)
# ---------------------------------------------------------------------------

# Allowed actions per role/purpose for intent legitimacy checks.
# In a production system, this should be driven by real policy/config.
ALLOWED_ACTIONS: Dict[str, set[str]] = {
    "admin": {"create_resource", "delete_resource", "access_admin_panel", "upload_file"},
    "user":  {"create_resource", "delete_resource", "upload_file"},
    # Network-level entities (e.g., IPs) making requests through the NDR layer
    "network_entity": {"network_request"},
    # Additional roles and their allowed actions can be added here.
}

# Expected payload schemas for structural legitimacy.
# Keys are action names; values are dicts of field -> expected_type.
# Use Python types or special strings (e.g. "base64") to indicate encoding checks.
SCHEMA_DEFINITIONS: Dict[str, Dict[str, Any]] = {
    "create_resource":   {"name": str, "size": int},
    "delete_resource":   {"id": int},
    "access_admin_panel": {},  # no payload expected
    "upload_file":       {"filename": str, "data": "base64"},  # expects base64-encoded data
    # Network-level HTTP request as seen by the NDR / gateway layer.
    # This is fed from pcs_ai.assess_request_pattern and is intentionally
    # conservative: only well-formed, bounded requests are considered
    # structurally valid here.
    "network_request":   {"endpoint": str, "method": str},
}


# ---------------------------------------------------------------------------
# Individual semantic checks
# ---------------------------------------------------------------------------

def check_state_legitimacy(request: Dict[str, Any]) -> Tuple[bool, str | None]:
    """Check if the entity's current state allows this action.

    Example rules:
    - Non-initial actions require prior authentication in the history.
    - Destructive actions require an appropriate prior lifecycle step.
    """
    action = request.get("action")
    history = request.get("history", []) or []

    # Network-level requests are evaluated without application-session semantics
    if action == "network_request":
        return True, None

    # If action is not an initial step (like login), require that entity is authenticated
    if action not in ("login", "authenticate", "register"):
        if "authenticated" not in history:
            return False, "Entity is not authenticated or session not established."

    # Simple sequence rule: deleting a resource requires prior existence/creation
    if action == "delete_resource":
        if not any(
            isinstance(evt, str) and (
                evt.startswith("create_resource") or evt.startswith("created_resource")
            )
            for evt in history
        ):
            return False, (
                "Attempting to delete resource without prior creation or "
                "existence confirmation."
            )

    # Additional lifecycle/state rules can be added here.
    return True, None


def check_intent_legitimacy(request: Dict[str, Any]) -> Tuple[bool, str | None]:
    """Check if the action aligns with the entity's role/purpose.

    Prevents low-privilege entities from performing admin-level or
    out-of-profile actions.
    """
    action = request.get("action")
    role = request.get("entity_role")

    if role is None:
        return False, "Entity role unknown; cannot validate intent."

    allowed_actions = ALLOWED_ACTIONS.get(role, set())
    if action not in allowed_actions:
        return False, f"Action '{action}' is not permitted for role '{role}'."

    # Optional: plug in historical behavior/profile checks here.
    return True, None


def check_structural_legitimacy(request: Dict[str, Any]) -> Tuple[bool, str | None]:
    """Validate the structure and format of the request payload.

    - Ensures required fields are present.
    - Rejects unexpected fields.
    - Enforces simple type/format/length constraints.
    """
    raw_action = request.get("action")
    action = str(raw_action) if raw_action is not None else ""
    payload = request.get("payload", {}) or {}
    schema = SCHEMA_DEFINITIONS.get(action)

    # Specialized structural policy for network_request flowing from
    # pcs_ai.assess_request_pattern (Step 21 for gateway traffic).
    if action == "network_request":
        endpoint = payload.get("endpoint", "")
        method = payload.get("method", "")

        # Require basic fields
        if not isinstance(endpoint, str) or not endpoint:
            return False, "Network request missing a valid 'endpoint' string."
        if not isinstance(method, str) or not method:
            return False, "Network request missing a valid 'method' string."

        # Enforce sane HTTP verb set (case-insensitive)
        allowed_methods = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
        if method.upper() not in allowed_methods:
            return False, f"HTTP method '{method}' is not permitted for network_request."

        # Guard against absurdly long or structurally broken endpoints.
        if len(endpoint) > 2048:
            return False, "Endpoint length exceeds maximum of 2048 characters."

        # Reject non-printable control characters and hard newlines in endpoint.
        for ch in endpoint:
            code = ord(ch)
            if code < 32 or code == 127:
                return False, "Endpoint contains non-printable or control characters."

        # If all checks pass, treat as structurally valid.
        return True, None

    # If no schema is defined for this action, treat as structurally OK
    # but log it so policies can be tightened later.
    if schema is None:
        logger.debug("[STEP21] No schema defined for action '%s'", action)
        return True, None

    # Check that all required fields exist
    for field, expected in schema.items():
        if field not in payload:
            return False, f"Missing required field '{field}'."

    # Check for unexpected fields
    for field in payload:
        if field not in schema:
            return False, f"Unexpected field '{field}' in payload."

    # Validate each field's type and format
    for field, expected in schema.items():
        value = payload[field]

        # Special encoding types
        if expected == "base64":
            if not isinstance(value, str):
                return False, f"Field '{field}' must be a base64-encoded string."
            try:
                base64.b64decode(value, validate=True)
            except Exception:
                return False, f"Field '{field}' is not valid base64-encoded data."
            continue

        # Standard type checks
        if not isinstance(value, expected):
            return False, (
                f"Field '{field}' expected type {expected.__name__}, "
                f"got {type(value).__name__}."
            )

        # Simple length/range guards
        if isinstance(value, str) and len(value) > 256:
            return False, f"Field '{field}' exceeds maximum length."
        if isinstance(value, int) and value < 0:
            return False, f"Field '{field}' must be non-negative."

    return True, None


def check_trust_sufficiency(request: Dict[str, Any]) -> Tuple[bool, str | None]:
    """Verify the entity's trust score is high enough for this action.

    This expects trust_score and trust_threshold to be derived from the
    trust graph (Signal 20) and policy.
    """
    trust_score = request.get("trust_score")
    trust_threshold = request.get("trust_threshold")

    if trust_score is None or trust_threshold is None:
        return False, "Missing trust metrics (score or threshold)."

    try:
        score_val = float(trust_score)
        thresh_val = float(trust_threshold)
    except (TypeError, ValueError):
        return False, "Trust score/threshold is not a valid number."

    if score_val < thresh_val:
        return False, (
            f"Trust score {score_val} is below required threshold {thresh_val}."
        )

    return True, None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def evaluate_request(request: Dict[str, Any]) -> Dict[str, Any]:
    """Evaluate a request against Step 21 semantic criteria.

    Returns a JSON-friendly dict:

        {
          "verdict": "SEMANTICALLY_VALID" | "SEMANTICALLY_INVALID",
          "state_legitimacy":    {"status": bool, "reason": str | None},
          "intent_legitimacy":   {"status": bool, "reason": str | None},
          "structural_legitimacy": {"status": bool, "reason": str | None},
          "trust_sufficiency":   {"status": bool, "reason": str | None},
        }

    Callers are responsible for enforcing "execution meaning denied" when
    the verdict is SEMANTICALLY_INVALID (no state change, no backend call,
    neutral response), while still logging the event for learning.
    """
    state_ok, state_reason = check_state_legitimacy(request)
    intent_ok, intent_reason = check_intent_legitimacy(request)
    struct_ok, struct_reason = check_structural_legitimacy(request)
    trust_ok, trust_reason = check_trust_sufficiency(request)

    verdict = (
        "SEMANTICALLY_VALID"
        if (state_ok and intent_ok and struct_ok and trust_ok)
        else "SEMANTICALLY_INVALID"
    )

    action = request.get("action")
    logger.info("[STEP21] Semantic Gate Verdict: %s for action '%s'", verdict, action)
    if not state_ok:
        logger.info("[STEP21] StateLegitimacyFail: %s", state_reason)
    if not intent_ok:
        logger.info("[STEP21] IntentLegitimacyFail: %s", intent_reason)
    if not struct_ok:
        logger.info("[STEP21] StructuralLegitimacyFail: %s", struct_reason)
    if not trust_ok:
        logger.info("[STEP21] TrustSufficiencyFail: %s", trust_reason)

    return {
        "verdict": verdict,
        "state_legitimacy": {
            "status": state_ok,
            "reason": state_reason,
        },
        "intent_legitimacy": {
            "status": intent_ok,
            "reason": intent_reason,
        },
        "structural_legitimacy": {
            "status": struct_ok,
            "reason": struct_reason,
        },
        "trust_sufficiency": {
            "status": trust_ok,
            "reason": trust_reason,
        },
    }
