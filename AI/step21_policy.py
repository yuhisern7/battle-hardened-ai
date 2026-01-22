"""Step 21 policy loading and verification (externalized, read-only).

This module is responsible for loading the Step 21 semantic gate policy
from the versioned policy bundle on disk:

    policies/step21/policy.json
    policies/step21/schema.json
    policies/step21/manifest.json
    policies/step21/manifest.sig

Runtime behavior is strictly read-only:
- No writes to the policy directory.
- Any verification failure results in a fail-closed status that callers
  must interpret as "deny" at the Step 21 gate level.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Optional, Tuple


logger = logging.getLogger(__name__)


@dataclass
class Step21Policy:
    """In-memory representation of the Step 21 policy bundle."""

    version: str
    raw: Dict[str, Any]
    policy_hash: str
    manifest_hash: str
    manifest_ok: bool


_POLICY_CACHE: Optional[Step21Policy] = None
_STATUS_CACHE: Dict[str, Any] = {}


def _get_policy_dir() -> str:
    """Return absolute path to policies/step21 directory.

    Uses /app in containerized deployments and the repo root in
    monorepo/dev environments.
    """

    if os.path.exists("/app"):
        base_root = "/app"
    else:
        # AI/ lives at <root>/AI, so step up one level.
        base_root = os.path.dirname(os.path.dirname(__file__))

    return os.path.join(base_root, "policies", "step21")


def _read_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError(f"JSON document at {path!r} is not an object")
    return data


def _canonical_json_bytes(data: Dict[str, Any]) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _validate_against_schema(policy: Dict[str, Any], schema: Dict[str, Any]) -> Tuple[bool, str | None]:
    """Perform a minimal structural validation using the schema definition.

    This does not implement full JSON Schema; it enforces:
    - required top-level keys from schema["required"]
    - rejection of unknown top-level keys when additionalProperties is False
    """

    try:
        required = list(schema.get("required", []))
        props = schema.get("properties", {}) or {}
        additional_allowed = bool(schema.get("additionalProperties", True))

        for key in required:
            if key not in policy:
                return False, f"Missing required top-level property: {key}"

        if not additional_allowed:
            allowed_keys = set(props.keys())
            for key in policy.keys():
                if key not in allowed_keys:
                    return False, f"Unknown top-level property: {key}"

        return True, None
    except Exception as exc:  # pragma: no cover - defensive
        return False, f"Schema validation error: {exc}"


def _verify_manifest(policy_dir: str, policy: Dict[str, Any]) -> Tuple[bool, str | None, str, str]:
    """Verify manifest.json and manifest.sig against on-disk files.

    Returns (ok, error, policy_hash, manifest_hash).
    """

    manifest_path = os.path.join(policy_dir, "manifest.json")
    sig_path = os.path.join(policy_dir, "manifest.sig")

    if not (os.path.exists(manifest_path) and os.path.exists(sig_path)):
        return False, "manifest.json or manifest.sig missing", "", ""

    manifest = _read_json(manifest_path)
    files = manifest.get("files", {}) or {}

    # Compute per-file hashes and compare against manifest entries
    for name, info in files.items():
        expected = (info or {}).get("sha256")
        if not expected:
            return False, f"Missing sha256 for {name}", "", ""

        path = os.path.join(policy_dir, name)
        if not os.path.exists(path):
            return False, f"Manifest references missing file: {name}", "", ""

        with open(path, "rb") as f:
            actual = hashlib.sha256(f.read()).hexdigest()
        if actual != expected:
            return False, f"Hash mismatch for {name}", "", ""

    # Canonical manifest hash
    manifest_bytes = _canonical_json_bytes(manifest)
    manifest_hash = hashlib.sha256(manifest_bytes).hexdigest()

    # Verify manifest signature (simple digest match)
    sig = _read_json(sig_path)
    algo = sig.get("algorithm", "").upper()
    digest = sig.get("digest")
    if algo != "SHA256" or not isinstance(digest, str):
        return False, "Invalid manifest signature format", "", manifest_hash
    if digest != manifest_hash:
        return False, "Manifest signature digest mismatch", "", manifest_hash

    # Policy hash for callers (based on policy.json content)
    policy_bytes = _canonical_json_bytes(policy)
    policy_hash = hashlib.sha256(policy_bytes).hexdigest()

    return True, None, policy_hash, manifest_hash


def load_step21_policy(base_dir: str | None = None, force_reload: bool = False) -> Tuple[Optional[Step21Policy], Dict[str, Any]]:
    """Load and verify the Step 21 policy bundle.

    Returns (policy_or_none, status_dict).
    """

    global _POLICY_CACHE, _STATUS_CACHE

    if _POLICY_CACHE is not None and not force_reload:
        return _POLICY_CACHE, dict(_STATUS_CACHE)

    policy_dir = base_dir or _get_policy_dir()
    policy_path = os.path.join(policy_dir, "policy.json")
    schema_path = os.path.join(policy_dir, "schema.json")

    status: Dict[str, Any] = {
        "enabled": True,
        "loaded": False,
        "policy_dir": policy_dir,
        "version": None,
        "policy_hash": None,
        "manifest_hash": None,
        "manifest_ok": False,
        "last_checked": datetime.utcnow().isoformat() + "Z",
        "error": None,
    }

    try:
        if not (os.path.exists(policy_path) and os.path.exists(schema_path)):
            status["enabled"] = False
            status["error"] = "Step 21 policy bundle not found"
            _POLICY_CACHE = None
            _STATUS_CACHE = dict(status)
            return None, status

        policy = _read_json(policy_path)
        schema = _read_json(schema_path)

        ok, err = _validate_against_schema(policy, schema)
        if not ok:
            status["error"] = err
            _POLICY_CACHE = None
            _STATUS_CACHE = dict(status)
            return None, status

        manifest_ok, manifest_err, policy_hash, manifest_hash = _verify_manifest(policy_dir, policy)
        if not manifest_ok:
            status["error"] = manifest_err
            status["manifest_ok"] = False
            status["policy_hash"] = policy_hash or None
            status["manifest_hash"] = manifest_hash or None
            _POLICY_CACHE = None
            _STATUS_CACHE = dict(status)
            return None, status

        version = str(policy.get("version", "unknown"))
        status.update(
            {
                "loaded": True,
                "version": version,
                "policy_hash": policy_hash,
                "manifest_hash": manifest_hash,
                "manifest_ok": True,
            }
        )

        _POLICY_CACHE = Step21Policy(
            version=version,
            raw=policy,
            policy_hash=policy_hash,
            manifest_hash=manifest_hash,
            manifest_ok=True,
        )
        _STATUS_CACHE = dict(status)
        return _POLICY_CACHE, status
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning(f"[STEP21-POLICY] Failed to load policy: {exc}")
        status["error"] = str(exc)
        _POLICY_CACHE = None
        _STATUS_CACHE = dict(status)
        return None, status


def get_step21_policy_status() -> Dict[str, Any]:
    """Return last-known Step 21 policy status for system-status surfaces."""

    if not _STATUS_CACHE:
        _, status = load_step21_policy(force_reload=False)
        return status
    return dict(_STATUS_CACHE)


def verify_step21_policy(force_reload: bool = True) -> Dict[str, Any]:
    """Force a policy reload/verification and return status.

    Intended for governance endpoints (read-only).
    """

    _, status = load_step21_policy(force_reload=force_reload)
    status["success"] = bool(status.get("loaded") and status.get("manifest_ok"))
    return status


__all__ = [
    "Step21Policy",
    "load_step21_policy",
    "get_step21_policy_status",
    "verify_step21_policy",
]
