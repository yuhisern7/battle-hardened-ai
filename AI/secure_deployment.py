"""Secure deployment utilities for Phase 4 features.

This module centralizes configuration and runtime helpers for:

- Air-Gap Mode (no external dependencies)
- DIL (Disconnected / Intermittent / Limited) resilience for non-core exports
- MLS-style security domain labelling (metadata only)
- Optional key provider abstraction (software vs HSM skeleton)

Design constraints:
- Purely config-driven: no hard-coded environment assumptions.
- Fail-closed for non-core features only; never block or crash the
  21-layer + Step 21 enforcement pipeline.
- Minimal dependencies so it can be safely imported by both AI and
  server components.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import ipaddress
import hashlib
from datetime import datetime

from .path_helper import get_json_file, get_json_dir


logger = logging.getLogger(__name__)

_CONFIG_LOCK = threading.Lock()
_CONFIG: Dict[str, Any] = {}

_AIRGAP_ENABLED: bool = False
_DIL_ENABLED: bool = False

_ALLOWED_SUBNETS: List[ipaddress._BaseNetwork] = []  # type: ignore[attr-defined]

_EGRESS_BLOCKED_COUNT: int = 0

_SPOOL_PATH: Optional[str] = None
_SPOOL_MAX_BYTES: int = 0
_SPOOL_LOCK = threading.Lock()
_SPOOL_DROPPED_COUNT: int = 0

_SECURITY_DOMAIN_LABEL: str = "UNCLASSIFIED"
_SECURITY_DOMAIN_ALLOWED: List[str] = [
    "UNCLASSIFIED",
    "RESTRICTED",
    "SECRET",
    "TOP_SECRET",
]

_KEY_PROVIDER: str = "software"  # software | pkcs11

_ZEROIZE_PATHS: List[str] = []
_STEP21_POLICY_PATHS: List[str] = []
_TAMPER_MANIFEST_PATH: Optional[str] = None
_TAMPER_EVENTS_PATH: Optional[str] = None
_TAMPER_EVENT_COUNT: int = 0
_LAST_TAMPER_STATUS: Dict[str, Any] = {}


def _default_config() -> Dict[str, Any]:
    """Return default secure deployment configuration.

    Defaults are conservative and safe for non-air-gapped installs.
    """

    json_dir = get_json_dir()
    spool_path = os.path.join(os.path.dirname(json_dir), "logs", "egress_spool.jsonl")
    tamper_events_path = os.path.join(os.path.dirname(json_dir), "logs", "tamper_events.jsonl")
    tamper_manifest_path = os.path.join(json_dir, "tamper_manifest.json")

    return {
        "airgap_mode": False,
        # RFC1918 + loopback; operators can tighten as needed.
        "airgap_allowed_subnets": [
            "127.0.0.0/8",
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
        ],
        "dil_mode": False,
        "dil_spool_path": spool_path,
        # Max on-disk size for DIL spool (approximate, bytes).
        "dil_spool_max_bytes": 50 * 1024 * 1024,
        # MLS-style security domain label for this node.
        "security_domain_label": "UNCLASSIFIED",
        "allowed_security_domain_labels": list(_SECURITY_DOMAIN_ALLOWED),
        # Key provider abstraction (Phase 4 / optional HSM)
        "key_provider": "software",
        "pkcs11_module_path": None,
        "pkcs11_token_label": None,
        "pkcs11_key_label": None,
        # Name of ENV var containing the PIN/passphrase. The value itself is
        # never logged or persisted by this module.
        "pkcs11_pin_env_var": None,
        # Paths whose contents should be covered by the tamper manifest and
        # are candidates for zeroization. Relative paths are resolved against
        # the server/json directory. Defaults target specific key files and
        # the DIL egress spool rather than broad directories.
        "zeroize_paths": [
            "../crypto_keys/private_key.pem",
            "../crypto_keys/shared_secret.key",
            "../crypto_keys/ssl_key.pem",
            "../logs/egress_spool.jsonl",
        ],
        # Step 21 policy bundle paths to include in the tamper manifest
        # (integrity-only; these are NOT zeroize targets). Relative paths
        # are resolved against the server/json directory.
        "step21_policy_paths": [
            "../../policies/step21",
        ],
        # Locations for tamper manifest and event log.
        "tamper_manifest_path": tamper_manifest_path,
        "tamper_events_path": tamper_events_path,
    }


def _load_config_locked() -> None:
    """Load secure deployment configuration from server/json.

    This function must be called with _CONFIG_LOCK held.
    """

    global _CONFIG, _AIRGAP_ENABLED, _DIL_ENABLED
    global _ALLOWED_SUBNETS, _SPOOL_PATH, _SPOOL_MAX_BYTES
    global _SECURITY_DOMAIN_LABEL, _SECURITY_DOMAIN_ALLOWED, _KEY_PROVIDER
    global _ZEROIZE_PATHS, _STEP21_POLICY_PATHS, _TAMPER_MANIFEST_PATH, _TAMPER_EVENTS_PATH

    cfg_path = get_json_file("secure_deployment.json")
    cfg = _default_config()

    try:
        if os.path.exists(cfg_path):
            with open(cfg_path, "r", encoding="utf-8") as f:
                loaded = json.load(f)
            if isinstance(loaded, dict):
                cfg.update(loaded)
    except Exception as e:  # pragma: no cover - defensive
        logger.warning(f"[SECURE-DEPLOY] Failed to load secure_deployment.json, using defaults: {e}")

    _CONFIG = cfg

    _AIRGAP_ENABLED = bool(cfg.get("airgap_mode", False))
    _DIL_ENABLED = bool(cfg.get("dil_mode", False))

    # Allowed subnets for egress in air-gap mode (typically local-only).
    _ALLOWED_SUBNETS = []
    for cidr in cfg.get("airgap_allowed_subnets", []):
        try:
            _ALLOWED_SUBNETS.append(ipaddress.ip_network(cidr, strict=False))
        except Exception:
            logger.warning(f"[SECURE-DEPLOY] Invalid subnet in airgap_allowed_subnets: {cidr}")

    _SPOOL_PATH = cfg.get("dil_spool_path") or None
    _SPOOL_MAX_BYTES = int(cfg.get("dil_spool_max_bytes", 50 * 1024 * 1024))

    allowed_labels = cfg.get("allowed_security_domain_labels") or _SECURITY_DOMAIN_ALLOWED
    if isinstance(allowed_labels, list):
        _SECURITY_DOMAIN_ALLOWED = [str(v) for v in allowed_labels]
    _SECURITY_DOMAIN_LABEL = str(cfg.get("security_domain_label", "UNCLASSIFIED"))
    if _SECURITY_DOMAIN_LABEL not in _SECURITY_DOMAIN_ALLOWED:
        logger.warning(
            f"[SECURE-DEPLOY] security_domain_label '{_SECURITY_DOMAIN_LABEL}' not in allowed list; "
            f"falling back to 'UNCLASSIFIED'"
        )
        _SECURITY_DOMAIN_LABEL = "UNCLASSIFIED"

    _KEY_PROVIDER = str(cfg.get("key_provider", "software")).lower()
    if _KEY_PROVIDER not in {"software", "pkcs11"}:
        logger.warning(f"[SECURE-DEPLOY] Invalid key_provider '{_KEY_PROVIDER}', defaulting to 'software'")
        _KEY_PROVIDER = "software"

    # Resolve zeroize and tamper paths.
    json_dir = get_json_dir()

    zeroize_paths = cfg.get("zeroize_paths") or []
    resolved_zeroize: List[str] = []
    if isinstance(zeroize_paths, list):
        for p in zeroize_paths:
            try:
                p_str = str(p)
                if not p_str:
                    continue
                if os.path.isabs(p_str):
                    resolved_zeroize.append(os.path.normpath(p_str))
                else:
                    resolved_zeroize.append(os.path.normpath(os.path.join(json_dir, p_str)))
            except Exception:
                continue
    _ZEROIZE_PATHS = resolved_zeroize

    # Resolve Step 21 policy integrity paths (included in tamper manifest
    # but not used for zeroization).
    step21_policy_paths = cfg.get("step21_policy_paths") or []
    resolved_policy_paths: List[str] = []
    if isinstance(step21_policy_paths, list):
        for p in step21_policy_paths:
            try:
                p_str = str(p)
                if not p_str:
                    continue
                if os.path.isabs(p_str):
                    resolved_policy_paths.append(os.path.normpath(p_str))
                else:
                    resolved_policy_paths.append(os.path.normpath(os.path.join(json_dir, p_str)))
            except Exception:
                continue
    _STEP21_POLICY_PATHS = resolved_policy_paths

    tamper_manifest = cfg.get("tamper_manifest_path")
    if isinstance(tamper_manifest, str) and tamper_manifest:
        if os.path.isabs(tamper_manifest):
            _TAMPER_MANIFEST_PATH = os.path.normpath(tamper_manifest)
        else:
            _TAMPER_MANIFEST_PATH = os.path.normpath(os.path.join(json_dir, tamper_manifest))
    else:
        _TAMPER_MANIFEST_PATH = None

    tamper_events = cfg.get("tamper_events_path")
    if isinstance(tamper_events, str) and tamper_events:
        if os.path.isabs(tamper_events):
            _TAMPER_EVENTS_PATH = os.path.normpath(tamper_events)
        else:
            _TAMPER_EVENTS_PATH = os.path.normpath(os.path.join(json_dir, tamper_events))
    else:
        _TAMPER_EVENTS_PATH = None


def _ensure_loaded() -> None:
    if _CONFIG:
        return
    with _CONFIG_LOCK:
        if not _CONFIG:
            _load_config_locked()


def reload_config() -> None:
    """Reload secure deployment configuration from disk.

    Safe to call from admin endpoints when config is updated.
    """

    with _CONFIG_LOCK:
        _load_config_locked()


def is_airgap_enabled() -> bool:
    """Return whether Air-Gap Mode is currently enabled."""

    _ensure_loaded()
    return _AIRGAP_ENABLED


def is_dil_mode_enabled() -> bool:
    """Return whether DIL mode is currently enabled."""

    _ensure_loaded()
    return _DIL_ENABLED


def is_target_local(host: str) -> bool:
    """Return True if the given hostname/IP is considered local.

    Used for Air-Gap Mode egress checks. Only IP-based checks are
    performed here; hostname resolution policies are left to the
    deployment environment.
    """

    _ensure_loaded()

    host = (host or "").strip()
    if not host:
        return False

    if host in {"localhost", "127.0.0.1", "::1"}:
        return True

    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        # Hostname (not raw IP) – treat as external unless operators
        # explicitly map it via other controls (DNS, firewall).
        return False

    for net in _ALLOWED_SUBNETS:
        try:
            if ip in net:
                return True
        except Exception:
            continue
    return False


def record_egress_block(kind: str, target: str) -> None:
    """Record that an outbound egress attempt was blocked.

    This is intentionally light-weight and never raises.
    """

    global _EGRESS_BLOCKED_COUNT
    _EGRESS_BLOCKED_COUNT += 1
    logger.info(f"[SECURE-DEPLOY] Blocked outbound egress ({kind}) to {target!r} due to Air-Gap Mode")


def get_airgap_status() -> Dict[str, Any]:
    """Return current Air-Gap status for /api/system-status."""

    _ensure_loaded()
    return {
        "enabled": _AIRGAP_ENABLED,
        "egress_blocked_count": _EGRESS_BLOCKED_COUNT,
    }


def get_dil_status() -> Dict[str, Any]:
    """Return current DIL / spool status for /api/system-status."""

    _ensure_loaded()
    size = 0
    if _SPOOL_PATH and os.path.exists(_SPOOL_PATH):
        try:
            size = os.path.getsize(_SPOOL_PATH)
        except Exception:
            size = 0

    return {
        "enabled": _DIL_ENABLED,
        "spool_path": _SPOOL_PATH,
        "spool_bytes": size,
        "spool_dropped_events": _SPOOL_DROPPED_COUNT,
    }


def get_security_domain_label() -> str:
    """Return node-level security domain label.

    This is metadata only and is safe to attach to audit records,
    exports, and compliance reports. It must never be influenced by
    attacker-controlled inputs.
    """

    _ensure_loaded()
    return _SECURITY_DOMAIN_LABEL


def get_key_provider_status() -> Dict[str, Any]:
    """Return current key provider configuration (opaque to callers)."""

    _ensure_loaded()
    return {
        "provider": _KEY_PROVIDER,
        "pkcs11_configured": _KEY_PROVIDER == "pkcs11",
    }


def _hash_file(path: str) -> Optional[str]:
    """Compute SHA-256 hash of a file, best-effort."""

    try:
        sha256 = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception as e:  # pragma: no cover - defensive
        logger.warning(f"[SECURE-DEPLOY] Failed to hash {path}: {e}")
        return None


def _iter_zeroize_files() -> List[str]:
    """Return a list of files under configured zeroize paths."""

    _ensure_loaded()
    files: List[str] = []
    for base in _ZEROIZE_PATHS:
        try:
            if os.path.isdir(base):
                for root, _, filenames in os.walk(base):
                    for name in filenames:
                        full = os.path.join(root, name)
                        if os.path.isfile(full):
                            files.append(full)
            elif os.path.isfile(base):
                files.append(base)
        except Exception:
            continue
    return files


def _record_tamper_event(kind: str, details: Dict[str, Any]) -> None:
    """Append a tamper event to the JSONL log and audit log."""

    global _TAMPER_EVENT_COUNT, _LAST_TAMPER_STATUS

    _ensure_loaded()
    timestamp = datetime.utcnow().isoformat() + "Z"

    event = {
        "timestamp": timestamp,
        "kind": kind,
        "details": details,
    }

    if _TAMPER_EVENTS_PATH:
        try:
            os.makedirs(os.path.dirname(_TAMPER_EVENTS_PATH), exist_ok=True)
            with open(_TAMPER_EVENTS_PATH, "a", encoding="utf-8") as f:
                f.write(json.dumps(event) + "\n")
            _TAMPER_EVENT_COUNT += 1
        except Exception as e:  # pragma: no cover - defensive
            logger.warning(f"[SECURE-DEPLOY] Failed to write tamper event: {e}")

    _LAST_TAMPER_STATUS.setdefault("last_event", {})
    _LAST_TAMPER_STATUS["last_event"] = event

    try:
        from .emergency_killswitch import get_audit_log, AuditEventType  # type: ignore[import]

        audit = get_audit_log()
        audit.log_event(
            event_type=AuditEventType.INTEGRITY_VIOLATION,
            actor="secure_deployment",
            action=kind,
            target="zeroize/tamper",
            outcome="detected" if kind.startswith("tamper") else "executed",
            details=details,
            risk_level="critical",
            metadata={"module": "secure_deployment"},
        )
    except Exception:
        # Audit logging is best-effort and must not fail closed here.
        pass


def _iter_integrity_files() -> List[str]:
    """Return files that should be covered by the tamper manifest.

    This includes zeroize targets plus read-only integrity bundles such
    as the Step 21 policy directory.
    """

    _ensure_loaded()
    files: List[str] = []

    # Zeroize targets
    for base in _ZEROIZE_PATHS:
        try:
            if os.path.isdir(base):
                for root, _, filenames in os.walk(base):
                    for name in filenames:
                        full = os.path.join(root, name)
                        if os.path.isfile(full):
                            files.append(full)
            elif os.path.isfile(base):
                files.append(base)
        except Exception:
            continue

    # Step 21 policy bundle (integrity-only)
    for base in _STEP21_POLICY_PATHS:
        try:
            if os.path.isdir(base):
                for root, _, filenames in os.walk(base):
                    for name in filenames:
                        full = os.path.join(root, name)
                        if os.path.isfile(full):
                            files.append(full)
            elif os.path.isfile(base):
                files.append(base)
        except Exception:
            continue

    # Deduplicate
    return sorted(set(files))


def _build_manifest_entries() -> Dict[str, Any]:
    """Build manifest entries for all integrity-tracked files."""

    entries: Dict[str, Any] = {}
    for path in _iter_integrity_files():
        try:
            stat = os.stat(path)
            file_hash = _hash_file(path)
            entries[path] = {
                "sha256": file_hash,
                "size": stat.st_size,
                "mtime": stat.st_mtime,
            }
        except Exception:
            continue
    return entries


def update_tamper_manifest() -> Dict[str, Any]:
    """Rebuild the tamper manifest from current zeroize targets."""

    global _LAST_TAMPER_STATUS

    _ensure_loaded()
    if not _TAMPER_MANIFEST_PATH:
        status = {
            "enabled": False,
            "reason": "tamper_manifest_path not configured",
        }
        _LAST_TAMPER_STATUS = status
        return status

    entries = _build_manifest_entries()
    manifest_hash = hashlib.sha256(json.dumps(entries, sort_keys=True).encode("utf-8")).hexdigest()

    data = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "entries": entries,
        "manifest_hash": manifest_hash,
    }

    try:
        os.makedirs(os.path.dirname(_TAMPER_MANIFEST_PATH), exist_ok=True)
        with open(_TAMPER_MANIFEST_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception as e:  # pragma: no cover - defensive
        logger.warning(f"[SECURE-DEPLOY] Failed to write tamper manifest: {e}")
        status = {
            "enabled": True,
            "manifest_exists": False,
            "error": str(e),
        }
        _LAST_TAMPER_STATUS = status
        return status

    status = {
        "enabled": True,
        "manifest_exists": True,
        "entries": len(entries),
        "manifest_hash": manifest_hash,
        "generated_at": data["generated_at"],
        "last_verification_ok": True,
    }
    _LAST_TAMPER_STATUS = status
    return status


def verify_tamper_manifest() -> Dict[str, Any]:
    """Verify current files against the stored tamper manifest.

    If the manifest file does not exist yet, it will be created and no
    tamper event is raised. If a mismatch is detected, a tamper event
    is recorded.
    """

    global _LAST_TAMPER_STATUS

    _ensure_loaded()
    if not _TAMPER_MANIFEST_PATH:
        status = {
            "enabled": False,
            "reason": "tamper_manifest_path not configured",
        }
        _LAST_TAMPER_STATUS = status
        return status

    if not os.path.exists(_TAMPER_MANIFEST_PATH):
        status = update_tamper_manifest()
        status["manifest_created"] = True
        _LAST_TAMPER_STATUS = status
        return status

    try:
        with open(_TAMPER_MANIFEST_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:  # pragma: no cover - defensive
        logger.warning(f"[SECURE-DEPLOY] Failed to read tamper manifest: {e}")
        status = {
            "enabled": True,
            "manifest_exists": False,
            "error": str(e),
        }
        _LAST_TAMPER_STATUS = status
        return status

    stored_entries = data.get("entries", {}) or {}
    stored_hash = data.get("manifest_hash")

    current_entries = _build_manifest_entries()
    current_hash = hashlib.sha256(json.dumps(current_entries, sort_keys=True).encode("utf-8")).hexdigest()

    changed: List[Dict[str, Any]] = []
    all_paths = set(stored_entries.keys()) | set(current_entries.keys())
    for path in all_paths:
        before = stored_entries.get(path)
        after = current_entries.get(path)
        if before is None and after is not None:
            changed.append({"path": path, "change": "new"})
        elif before is not None and after is None:
            changed.append({"path": path, "change": "missing"})
        elif before and after and (
            before.get("sha256") != after.get("sha256")
            or before.get("size") != after.get("size")
        ):
            changed.append({"path": path, "change": "modified"})

    ok = stored_hash == current_hash and not changed

    status = {
        "enabled": True,
        "manifest_exists": True,
        "entries": len(current_entries),
        "manifest_hash": current_hash,
        "last_checked": datetime.utcnow().isoformat() + "Z",
        "last_verification_ok": ok,
        "changed_paths": changed,
    }

    if not ok:
        _record_tamper_event("tamper_manifest_mismatch", {"changed_paths": changed})

    _LAST_TAMPER_STATUS = status
    return status


def get_tamper_status() -> Dict[str, Any]:
    """Return cached tamper/zeroize status for system-status surfaces."""

    _ensure_loaded()

    status = dict(_LAST_TAMPER_STATUS) if _LAST_TAMPER_STATUS else {
        "enabled": bool(_TAMPER_MANIFEST_PATH),
        "manifest_exists": os.path.exists(_TAMPER_MANIFEST_PATH) if _TAMPER_MANIFEST_PATH else False,
        "entries": 0,
        "last_verification_ok": None,
    }

    status.update(
        {
            "events_count": _TAMPER_EVENT_COUNT,
            "manifest_path": _TAMPER_MANIFEST_PATH,
            "events_path": _TAMPER_EVENTS_PATH,
            "zeroize_paths": list(_ZEROIZE_PATHS),
            "step21_policy_paths": list(_STEP21_POLICY_PATHS),
        }
    )
    return status


def _zeroize_file(path: str, dry_run: bool, errors: List[str]) -> bool:
    """Best-effort zeroization of a single file.

    Returns True if the operation succeeded or the file no longer
    exists, False on error.
    """

    try:
        if not os.path.exists(path):
            return True

        if dry_run:
            return True

        size = os.path.getsize(path)
        try:
            with open(path, "r+b") as f:
                remaining = size
                chunk = b"\x00" * 4096
                while remaining > 0:
                    to_write = chunk if remaining >= len(chunk) else b"\x00" * remaining
                    f.write(to_write)
                    remaining -= len(to_write)
                f.flush()
        except Exception as e:
            errors.append(f"{path}: overwrite failed ({e})")

        try:
            with open(path, "wb") as f:
                f.truncate(0)
        except Exception as e:
            errors.append(f"{path}: truncate failed ({e})")

        try:
            os.remove(path)
        except Exception:
            pass

        return True
    except Exception as e:  # pragma: no cover - defensive
        errors.append(f"{path}: unexpected error ({e})")
        return False


def run_zeroize(dry_run: bool = False) -> Dict[str, Any]:
    """Run best-effort zeroization over configured sensitive paths.

    This never raises and is intended to be invoked from governance
    controls (admin actions, kill-switch flows, or shutdown hooks).
    """

    _ensure_loaded()

    files = _iter_zeroize_files()
    errors: List[str] = []
    processed = 0

    for path in files:
        if _zeroize_file(path, dry_run=dry_run, errors=errors):
            processed += 1

    if not dry_run:
        update_tamper_manifest()
        _record_tamper_event(
            "zeroize_run",
            {"files_processed": processed, "errors": errors, "zeroize_paths": list(_ZEROIZE_PATHS)},
        )

    return {
        "success": len(errors) == 0,
        "dry_run": dry_run,
        "total_targets": len(files),
        "files_processed": processed,
        "errors": errors,
    }


def spool_egress_event(kind: str, target: str, payload: Dict[str, Any]) -> None:
    """Best-effort store-and-forward spool for non-core exports.

    When DIL mode is enabled, failed exports (e.g., webhooks) may call
    this helper. It appends a JSON line to an append-only spool file,
    enforcing a soft max-size and dropping new events when the limit is
    exceeded. It never raises.
    """

    global _SPOOL_DROPPED_COUNT

    _ensure_loaded()
    if not (_DIL_ENABLED and _SPOOL_PATH and _SPOOL_MAX_BYTES > 0):
        return

    try:
        os.makedirs(os.path.dirname(_SPOOL_PATH), exist_ok=True)
    except Exception:
        # If we cannot ensure the directory, drop silently.
        _SPOOL_DROPPED_COUNT += 1
        return

    try:
        with _SPOOL_LOCK:
            # If file already beyond limit, drop this event
            if os.path.exists(_SPOOL_PATH) and os.path.getsize(_SPOOL_PATH) >= _SPOOL_MAX_BYTES:
                _SPOOL_DROPPED_COUNT += 1
                return

            record = {
                "timestamp": __import__("datetime").datetime.utcnow().isoformat() + "Z",
                "kind": kind,
                "target": target,
                "payload": payload,
            }
            with open(_SPOOL_PATH, "a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")
    except Exception as e:  # pragma: no cover - defensive
        _SPOOL_DROPPED_COUNT += 1
        logger.warning(f"[SECURE-DEPLOY] Failed to spool egress event: {e}")


def assert_airgap_compliance() -> None:
    """Assert Air-Gap compliance at runtime.

    This helper is intended to be called at startup and periodically
    (e.g., from /api/system-status). It never raises; enforcement is
    handled by the egress helpers (e.g., syslog/webhook gating and
    threat-intel short-circuiting).
    """

    _ensure_loaded()

    if not _AIRGAP_ENABLED:
        return

    # There is intentionally no deep inspection here; the authoritative
    # enforcement points are the outbound adapters (webhooks/syslog,
    # threat-intel HTTP queries, relay/P2P, etc.). This function exists
    # primarily to surface configuration into logs and to allow future
    # health checks.
    logger.info(
        "[SECURE-DEPLOY] Air-Gap Mode enabled: external egress will be "
        "blocked except for explicitly allowlisted local subnets."
    )


# ---------------------------------------------------------------------------
# Key provider abstraction (design-level skeleton)
# ---------------------------------------------------------------------------


@dataclass
class KeyProviderConfig:
    provider: str = "software"  # software | pkcs11
    pkcs11_module_path: Optional[str] = None
    pkcs11_token_label: Optional[str] = None
    pkcs11_key_label: Optional[str] = None
    pkcs11_pin_env_var: Optional[str] = None


def get_key_provider_config() -> KeyProviderConfig:
    """Return parsed key provider configuration.

    This is safe to use from crypto modules that need to decide where
    keys live. Actual PKCS#11 binding is deferred to those modules.
    """

    _ensure_loaded()
    cfg = _CONFIG
    return KeyProviderConfig(
        provider=_KEY_PROVIDER,
        pkcs11_module_path=cfg.get("pkcs11_module_path") or None,
        pkcs11_token_label=cfg.get("pkcs11_token_label") or None,
        pkcs11_key_label=cfg.get("pkcs11_key_label") or None,
        pkcs11_pin_env_var=cfg.get("pkcs11_pin_env_var") or None,
    )


__all__ = [
    "is_airgap_enabled",
    "is_dil_mode_enabled",
    "is_target_local",
    "record_egress_block",
    "get_airgap_status",
    "get_dil_status",
    "get_security_domain_label",
    "get_key_provider_status",
    "get_tamper_status",
    "spool_egress_event",
    "assert_airgap_compliance",
    "KeyProviderConfig",
    "get_key_provider_config",
    "update_tamper_manifest",
    "verify_tamper_manifest",
    "run_zeroize",
    "reload_config",
]
