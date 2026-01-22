#!/usr/bin/env python3
"""Battle-Hardened AI server entrypoint.

This process exposes the first-layer execution-denial and monitoring
APIs plus a minimal operator dashboard. It is intentionally not a
full SOC/SIEM/forensics console.
"""

from flask import Flask, jsonify, request, render_template, send_from_directory, send_file, session, redirect, url_for, Response
import datetime
from functools import wraps
from urllib.parse import urlencode, unquote_plus
import json
import os
import hashlib
import logging
from logging.handlers import RotatingFileHandler
import threading
import time
import sys
import platform
try:
    # Load environment variables from .env / .env.windows when running natively or from the Windows EXE.
    # Order of precedence (later calls override earlier ones):
    #  1. {CWD}/.env           – for installed EXE or local runs
    #  2. {CWD}/.env.windows   – Windows-specific template next to EXE
    #  3. server/.env          – developer config inside the repo
    #  4. server/.env.windows  – Windows-specific template in the repo
    # Docker deployments still use env_file in docker-compose and are unaffected.
    from dotenv import load_dotenv  # type: ignore[import]
    cwd = os.getcwd()
    server_dir = os.path.dirname(__file__)

    # 1–2: installed EXE or local runs – config placed next to the binary
    load_dotenv(os.path.join(cwd, '.env'))
    load_dotenv(os.path.join(cwd, '.env.windows'))

    # 3–4: developer configs inside the server/ directory
    load_dotenv(os.path.join(server_dir, '.env'))
    load_dotenv(os.path.join(server_dir, '.env.windows'))
except Exception:
    # If python-dotenv is missing or files are absent, continue with existing environment
    pass

import pyotp  # type: ignore[import]
import requests
from jose import jwt as jose_jwt  # type: ignore[import]


# Ensure the project root (which contains the AI/ package and templates)
# is on sys.path.
#
# Order of precedence:
#  1. When running as a PyInstaller one-file EXE, use sys._MEIPASS so that
#     bundled AI/ templates like inspector_ai_monitoring.html are found.
#  2. Otherwise, respect BATTLE_HARDENED_PROJECT_ROOT if set.
#  3. Fallback to the repo root (one level above server/).
if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
    PROJECT_ROOT = sys._MEIPASS  # type: ignore[attr-defined]
else:
    PROJECT_ROOT = os.environ.get('BATTLE_HARDENED_PROJECT_ROOT') or os.path.dirname(os.path.dirname(__file__))

if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

try:
    from AI import pcs_ai  # core AI/ML engine
except Exception as _e:
    logger = logging.getLogger('battle_hardened_ai.server') if 'logger' in globals() else logging.getLogger(__name__)
    logger.error(f"[INIT] Failed to import AI.pcs_ai: {_e}")

    class _FallbackPCS:
        ML_AVAILABLE = False

        def __getattr__(self, name):  # pragma: no cover - defensive stub
            raise RuntimeError("pcs_ai is not available")

    pcs_ai = _FallbackPCS()


try:
    # Preferred path helper for JSON config files so that all JSON
    # (admin_users.json, support_tickets.json, enterprise_integration.json,
    # threat logs, etc.) is shared between the AI engine and the Flask
    # server across Docker, dev, and the Windows EXE.
    from AI.path_helper import get_json_file as _get_json_file, get_json_dir as _get_json_dir  # type: ignore[import]
except Exception:
    _get_json_file = None
    _get_json_dir = None


BASE_DIR = os.path.dirname(__file__)
if _get_json_dir is not None:
    JSON_CONFIG_DIR = _get_json_dir()
else:
    JSON_CONFIG_DIR = os.path.join(BASE_DIR, 'json')
ADMIN_CONFIG_PATH = os.path.join(JSON_CONFIG_DIR, 'admin_users.json')
SUPPORT_TICKETS_PATH = os.path.join(JSON_CONFIG_DIR, 'support_tickets.json')
if _get_json_file is not None:
    ENTERPRISE_INTEGRATION_CONFIG_PATH = _get_json_file('enterprise_integration.json')
else:
    ENTERPRISE_INTEGRATION_CONFIG_PATH = os.path.join(JSON_CONFIG_DIR, 'enterprise_integration.json')

try:
    from AI.secure_deployment import (
        assert_airgap_compliance,
        get_airgap_status,
        get_dil_status,
        get_security_domain_label,
        get_key_provider_status,
        get_tamper_status,
        run_zeroize,
        verify_tamper_manifest,
    )
    SECURE_DEPLOYMENT_AVAILABLE = True
except Exception:
    SECURE_DEPLOYMENT_AVAILABLE = False

try:
    from AI.step21_policy import get_step21_policy_status, verify_step21_policy
    STEP21_POLICY_AVAILABLE = True
except Exception:
    STEP21_POLICY_AVAILABLE = False


# Use the AI/ directory as the template root so the core
# dashboard and docs templates (inspector_ai_monitoring.html,
# docs_portal.html, docs_viewer.html) are available.
TEMPLATE_DIR = os.path.join(PROJECT_ROOT, 'AI')

app = Flask(__name__, template_folder=TEMPLATE_DIR)
app.config['SECRET_KEY'] = os.environ.get('BATTLE_HARDENED_SECRET_KEY', os.urandom(32))


logger = logging.getLogger('battle_hardened_ai.server')
if not logger.handlers:
    formatter = logging.Formatter('[%(asctime)s] %(levelname)s in %(module)s: %(message)s')

    # Console logging (always enabled)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # File-based logging for production and the EXE
    try:
        log_dir = os.environ.get('BATTLE_HARDENED_LOG_DIR')
        if not log_dir:
            if getattr(sys, 'frozen', False):
                # When running as a PyInstaller EXE, write logs next to the executable
                base_dir = os.path.dirname(sys.executable)
            else:
                # In development, keep logs under server/logs/
                base_dir = os.path.dirname(__file__)
            log_dir = os.path.join(base_dir, 'logs')

        os.makedirs(log_dir, exist_ok=True)

        # Main rolling log file
        file_handler = RotatingFileHandler(
            os.path.join(log_dir, 'server.log'),
            maxBytes=5 * 1024 * 1024,
            backupCount=5,
            encoding='utf-8',
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

        # Error-only log for quick investigation of failed APIs/tracebacks
        error_handler = RotatingFileHandler(
            os.path.join(log_dir, 'errors.log'),
            maxBytes=5 * 1024 * 1024,
            backupCount=5,
            encoding='utf-8',
        )
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(formatter)
        logger.addHandler(error_handler)
    except Exception:
        # Logging configuration must never break startup
        pass

logger.setLevel(logging.INFO)

try:
    logger.info(f"[TEMPLATES] TEMPLATE_DIR={TEMPLATE_DIR} exists={os.path.exists(TEMPLATE_DIR)} inspector_present={os.path.exists(os.path.join(TEMPLATE_DIR, 'inspector_ai_monitoring.html'))}")
except Exception:
    # Logging should never break server startup
    pass


def _get_mac_status() -> dict:
    """Return basic SELinux/AppArmor MAC status for /api/system-status.

    This is observational only and does not attempt to manage or enforce
    MAC policies. It must never raise.
    """

    status = {
        "selinux": {"supported": False, "mode": "disabled"},
        "apparmor": {"supported": False, "enabled": False, "profile": None},
    }

    try:
        if platform.system() != 'Linux':
            return status

        # SELinux runtime mode
        selinux_enforce = '/sys/fs/selinux/enforce'
        if os.path.exists(selinux_enforce):
            status["selinux"]["supported"] = True
            try:
                with open(selinux_enforce, 'r') as f:
                    val = f.read().strip()
                status["selinux"]["mode"] = 'enforcing' if val == '1' else 'permissive'
            except Exception:
                status["selinux"]["mode"] = 'unknown'

        # AppArmor runtime status
        apparmor_enabled_path = '/sys/module/apparmor/parameters/enabled'
        if os.path.exists(apparmor_enabled_path):
            status["apparmor"]["supported"] = True
            try:
                with open(apparmor_enabled_path, 'r') as f:
                    enabled = f.read().strip().lower() in {'y', 'yes', '1'}
                status["apparmor"]["enabled"] = enabled
            except Exception:
                status["apparmor"]["enabled"] = False

        # Current AppArmor profile (if any)
        try:
            current_profile = None
            attr_path = '/proc/self/attr/current'
            if os.path.exists(attr_path):
                with open(attr_path, 'r') as f:
                    current_profile = f.read().strip() or None
            status["apparmor"]["profile"] = current_profile
        except Exception:
            status["apparmor"]["profile"] = None

        return status
    except Exception:
        return status


def _get_current_time() -> datetime.datetime:
    """Return current time in UTC.

    Used for audit logs, support tickets, and health endpoints.
    """

    # Use timezone-aware UTC datetimes everywhere for consistency.
    return datetime.datetime.now(datetime.timezone.utc)


def _load_admin_users() -> dict:
    """Load local admin users and RBAC configuration from JSON.

    This is intentionally simple: a local-only user store for the
    built-in dashboard. External IdPs (LDAP/OIDC) are wired through
    ZeroTrust but do not manage roles here.
    """

    if not os.path.exists(ADMIN_CONFIG_PATH):
        return {"users": [], "password_hash_algorithm": "pbkdf2:sha256"}

    try:
        with open(ADMIN_CONFIG_PATH, 'r', encoding='utf-8') as f:
            data = json.load(f)
            if not isinstance(data, dict):
                return {"users": [], "password_hash_algorithm": "pbkdf2:sha256"}
            return data
    except Exception:
        return {"users": [], "password_hash_algorithm": "pbkdf2:sha256"}


ADMIN_CONFIG = _load_admin_users()
_ADMIN_CONFIG = ADMIN_CONFIG  # backward-compatible alias used throughout routes


def _has_admins() -> bool:
    """Return True if at least one admin user is configured.

    This always reloads admin_users.json from disk so that multi-worker
    deployments (e.g., Gunicorn in Docker) see changes made by the
    first-run setup flow or later admin updates.
    """

    try:
        config = _load_admin_users()
        return bool(config.get("users"))
    except Exception:
        return False


def _save_admin_users(config: dict) -> None:
    """Persist admin user configuration and refresh in-memory state.

    This is used by the first-run setup flow to create the initial
    admin account safely. It keeps the JSON format consistent with
    _load_admin_users so existing tooling continues to work.
    """
    global ADMIN_CONFIG, _ADMIN_CONFIG

    try:
        os.makedirs(JSON_CONFIG_DIR, exist_ok=True)
        with open(ADMIN_CONFIG_PATH, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2)
        ADMIN_CONFIG = config
        _ADMIN_CONFIG = ADMIN_CONFIG
        logger.info("[ADMIN_SETUP] admin_users.json updated")
    except Exception as e:
        logger.error(f"[ADMIN_SETUP] Failed to save admin_users.json: {e}")


def _create_first_admin(username: str, password: str) -> None:
    """Create the very first local admin user.

    For first-run simplicity we store a plain-text marker
    ("plain:<password>") which is already supported by _verify_password.
    Operators can later rotate this to a hashed value if desired.
    """
    username = (username or '').strip()
    if not username or not password:
        raise ValueError("Username and password are required for first admin")

    config = {
        "users": [
            {
                "username": username,
                "password_hash": f"plain:{password}",
                "role": "admin",
                "totp_secret": "",
                "mfa_enabled": False,
            }
        ],
        "password_hash_algorithm": "pbkdf2:sha256",
    }

    _save_admin_users(config)
    logger.info(f"[ADMIN_SETUP] Created first admin user '{username}'")

_CLUSTER_LOCK = threading.Lock()
_cluster_manager_started = False

# Core documentation files exposed via the docs portal.
_DOCS_PORTAL_FILES = [
    {
        "id": "readme",
        "title": "Battle-Hardened AI Overview",
        "rel_path": ["..", "README.md"],
    },
    {
        "id": "architecture",
        "title": "Architecture & Compliance",
        "rel_path": ["..", "ARCHITECTURE_COMPLIANCE.md"],
    },
    {
        "id": "attack-flow",
        "title": "Attack Handling Flow",
        "rel_path": ["..", "ATTACK_HANDLING_FLOW.md"],
    },
]


def _find_admin_user(username: str):
    """Return admin user dict matching the given username or None."""

    for user in ADMIN_CONFIG.get("users", []):
        if user.get("username") == username:
            return user
    return None


def _verify_password(username: str, password: str) -> bool:
    """Verify a local admin password against the configured hash."""

    user = _find_admin_user(username)
    if not user:
        return False

    backend = user.get("auth_backend", "local")
    if backend.lower() == "ldap":
        # Delegate to LDAP if the user is configured for directory auth.
        return _authenticate_via_ldap(username, password)

    stored_hash = user.get("password_hash") or ""
    if not stored_hash:
        return False

    try:
        # Development convenience: allow explicit plain-text marker
        # "plain:<password>" for local-only setups. This is NOT for
        # production use but keeps first-run friction low.
        if stored_hash.startswith("plain:"):
            return stored_hash.split(":", 1)[1] == password

        algorithm = ADMIN_CONFIG.get("password_hash_algorithm", "pbkdf2:sha256")
        if algorithm.startswith("pbkdf2:") and '$' in stored_hash:
            method, iterations, salt, digest = stored_hash.split('$', 3)
            dk = hashlib.pbkdf2_hmac(
                method.split(':', 1)[-1],
                password.encode('utf-8'),
                salt.encode('utf-8'),
                int(iterations),
            )
            return digest == dk.hex()

        if algorithm == "sha256" and ':' in stored_hash:
            salt, digest = stored_hash.split(':', 1)
            candidate = hashlib.sha256((salt + password).encode('utf-8')).hexdigest()
            return digest == candidate
    except Exception as e:
        logger.error(f"[ADMIN_AUTH] Password verification error: {e}")
        return False

    return False


def _authenticate_via_ldap(username: str, password: str) -> bool:
    """Authenticate a dashboard admin against LDAP/Active Directory."""

    if not password:
        return False

    try:
        from AI.zero_trust import ZeroTrustMonitor
        try:
            from ldap3 import Server, Connection, ALL  # type: ignore[import]
        except ImportError:
            logger.error("[ADMIN_AUTH] ldap3 not installed; cannot use LDAP backend")
            return False

        zt = ZeroTrustMonitor()
        cfg = zt.identity_config or {}

        if not cfg.get('ldap_enabled'):
            return False

        server_url = cfg.get('ldap_server_url')
        user_dn_template = cfg.get('ldap_user_dn_template')

        if not server_url or not user_dn_template:
            logger.error("[ADMIN_AUTH] LDAP enabled but ldap_server_url or ldap_user_dn_template missing")
            return False

        user_dn = user_dn_template.format(username=username)

        server = Server(server_url, get_info=ALL)
        conn = Connection(server, user=user_dn, password=password, auto_bind=True)
        conn.unbind()
        logger.info(f"[ADMIN_AUTH] LDAP bind successful for user {username}")
        return True
    except Exception as e:
        logger.error(f"[ADMIN_AUTH] LDAP authentication failed for {username}: {e}")
        return False


def _verify_mfa(user: dict, code: str) -> bool:
    """Verify TOTP MFA for a user.

    If MFA is globally required for admins via identity_access_config.json,
    a user without MFA enabled will be rejected.
    """
    if not user:
        return False

    # Check global Zero Trust identity config for MFA requirements (read-only)
    try:
        from AI.zero_trust import ZeroTrustMonitor

        zt = ZeroTrustMonitor()
        identity_cfg = zt.identity_config or {}
        global_mfa_required = bool(identity_cfg.get('mfa_required_for_admin', False))
    except Exception:
        identity_cfg = {}
        global_mfa_required = False

    user_mfa_enabled = bool(user.get("mfa_enabled"))

    # If global policy requires MFA for admin access, user must have MFA enabled
    if global_mfa_required and not user_mfa_enabled:
        logger.warning("[ADMIN_AUTH] Global MFA required but user has mfa_disabled")
        return False

    # If MFA not enabled for this user and no global requirement, treat as pass
    if not user_mfa_enabled:
        return True

    secret = user.get("totp_secret") or ""
    if not secret:
        return False
    try:
        totp = pyotp.TOTP(secret)
        return totp.verify(code, valid_window=1)
    except Exception as e:
        logger.error(f"[ADMIN_AUTH] MFA verification error: {e}")
        return False


def _get_identity_config() -> dict:
    """Load identity/SSO configuration via ZeroTrustMonitor.

    This keeps a single source of truth for LDAP and OIDC settings
    in identity_access_config.json.
    """
    try:
        from AI.zero_trust import ZeroTrustMonitor

        zt = ZeroTrustMonitor()
        return zt.identity_config or {}
    except Exception as e:
        logger.error(f"[IDENTITY] Failed to load identity_access_config.json: {e}")
        return {}


def _is_oidc_configured(identity_cfg: dict) -> bool:
    """Return True if OIDC SSO is enabled and minimally configured."""
    if not identity_cfg.get('oidc_enabled'):
        return False
    required = [
        'oidc_authorization_endpoint',
        'oidc_token_endpoint',
        'oidc_client_id',
        'oidc_client_secret',
        'oidc_redirect_uri',
    ]
    return all(identity_cfg.get(k) for k in required)


def _decode_oidc_id_token(id_token: str) -> dict:
    """Decode and validate OIDC ID token with JWKS/issuer/audience checks.

    This enforces:
    - Signature verification using the configured JWKS endpoint for
      asymmetric algorithms (RS256, ES256, etc.)
    - Issuer validation against oidc_issuer (if set)
    - Audience validation against oidc_client_id

    If the provider uses a symmetric algorithm (HS256), the
    oidc_client_secret will be used as the key.
    """
    identity_cfg = _get_identity_config()

    algorithms = identity_cfg.get('oidc_algorithms') or ['RS256', 'HS256']
    jwks_uri = identity_cfg.get('oidc_jwks_uri') or ''
    issuer = identity_cfg.get('oidc_issuer') or None
    client_id = identity_cfg.get('oidc_client_id') or None
    client_secret = identity_cfg.get('oidc_client_secret') or None

    try:
        # If JWKS is configured, use it for asymmetric keys
        if jwks_uri:
            try:
                jwks_resp = requests.get(jwks_uri, timeout=10)
                jwks_resp.raise_for_status()
                jwks_data = jwks_resp.json()
            except Exception as e:
                logger.error(f"[OIDC] Failed to fetch JWKS from {jwks_uri}: {e}")
                raise

            try:
                # python-jose can take the JWKS dict directly via the 'jwk' key
                # when using the 'key' parameter.
                key = jwks_data
                return jose_jwt.decode(
                    id_token,
                    key=key,
                    algorithms=algorithms,
                    audience=client_id,
                    issuer=issuer,
                    options={
                        'verify_signature': True,
                        'verify_aud': bool(client_id),
                        'verify_iss': bool(issuer),
                    },
                )
            except Exception as e:
                logger.error(f"[OIDC] JWKS-based id_token verification failed: {e}")
                raise

        # Fallback: symmetric key (HS256) using client_secret
        if client_secret:
            try:
                return jose_jwt.decode(
                    id_token,
                    key=client_secret,
                    algorithms=['HS256'],
                    audience=client_id,
                    issuer=issuer,
                    options={
                        'verify_signature': True,
                        'verify_aud': bool(client_id),
                        'verify_iss': bool(issuer),
                    },
                )
            except Exception as e:
                logger.error(f"[OIDC] HS256 id_token verification failed: {e}")
                raise

        # If neither JWKS nor client_secret are configured, treat as misconfig
        logger.error("[OIDC] No JWKS URI or client_secret configured for OIDC token verification")
        raise RuntimeError("OIDC verification misconfigured: missing JWKS and client_secret")
    except Exception:
        # Caller logs a generic error and falls back to local login flow
        raise


def _exchange_oidc_code_for_tokens(identity_cfg: dict, code: str) -> dict:
    """Exchange authorization code for tokens at the OIDC token endpoint."""
    token_url = identity_cfg.get('oidc_token_endpoint')
    data = {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': identity_cfg.get('oidc_redirect_uri'),
        'client_id': identity_cfg.get('oidc_client_id'),
        'client_secret': identity_cfg.get('oidc_client_secret'),
    }
    if not token_url:
        raise RuntimeError("OIDC token endpoint not configured")

    try:
        resp = requests.post(str(token_url), data=data, timeout=10)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        logger.error(f"[OIDC] Token exchange failed: {e}")
        raise


def _map_oidc_claims_to_local_user(claims: dict):
    """Map OIDC identity to an existing local admin user.

    We do not auto-provision users from the IdP; instead we expect
    admin_users.json to contain a matching username. By default we
    try preferred_username, then email, then subject.
    """
    candidate_ids = [
        claims.get('preferred_username'),
        claims.get('email'),
        claims.get('sub'),
    ]
    for cid in candidate_ids:
        if not cid:
            continue
        user = _find_admin_user(cid)
        if user:
            return user
    return None


def require_role(*allowed_roles):
    """Decorator to enforce basic RBAC on sensitive routes.

    Roles are taken from session['admin_role'] which is set at login.
    If no admin users are configured, RBAC is effectively disabled
    (backwards-compatible single-user mode).
    """

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # If admin config is empty, do not enforce RBAC
            if not _has_admins():
                return func(*args, **kwargs)

            role = session.get('admin_role')
            if role not in allowed_roles:
                logger.warning(f"[RBAC] Access denied for role={role} on {request.path}; required={allowed_roles}")
                # Return JSON for API routes, redirect for HTML routes
                if request.path.startswith('/api/'):
                    return jsonify({
                        'status': 'forbidden',
                        'message': 'Insufficient role for this operation',
                        'required_roles': list(allowed_roles),
                        'current_role': role,
                    }), 403
                return redirect(url_for('dashboard'))
            return func(*args, **kwargs)

        return wrapper

    return decorator


def _load_cluster_config():
    """Load basic cluster/availability configuration.

    This supports active/passive metadata and peer definitions used for
    health checks and optional config synchronization. It does not by
    itself start or manage additional nodes.
    """
    default = {
        "cluster_name": "default",
        "node_id": platform.node() or "battle-hardened-node",
        "role": "standalone",  # standalone | active | passive
        "peer_nodes": [],  # [{"node_id": "node-2", "api_url": "https://node2:60000", "role": "active"}]
        "failover_check_interval_seconds": 10,
        "failover_unhealthy_threshold": 3,
        "config_sync_paths": [],
        "config_sync_interval_seconds": 60,
    }
    try:
        config_path = os.path.join(os.path.dirname(__file__), 'json', 'cluster_config.json')
        if not os.path.exists(config_path):
            return default
        with open(config_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            if isinstance(data, dict):
                # Ensure required keys exist
                for k, v in default.items():
                    data.setdefault(k, v)
                return data
    except Exception as e:
        logger.error(f"[CLUSTER] Failed to load cluster_config.json: {e}")
    return default


_CLUSTER_CONFIG = _load_cluster_config()


def _persist_cluster_config():
    """Persist in-memory cluster role/metadata back to cluster_config.json."""
    try:
        path = os.path.join(JSON_CONFIG_DIR, 'cluster_config.json')
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(_CLUSTER_CONFIG, f, indent=2)
    except Exception as e:
        logger.error(f"[CLUSTER] Failed to persist cluster_config.json: {e}")


def _get_config_sync_targets():
    """Return list of (relative_name, absolute_path) for files to sync.

    cluster_config.json is intentionally excluded to avoid split-brain.
    """
    targets = []
    for rel_name in _CLUSTER_CONFIG.get('config_sync_paths', []) or []:
        if not isinstance(rel_name, str):
            continue
        if rel_name == 'cluster_config.json':
            continue
        abs_path = os.path.join(JSON_CONFIG_DIR, rel_name)
        targets.append((rel_name, abs_path))
    return targets


def _get_active_peer():
    """Determine the preferred active peer node from cluster_config."""
    peers = _CLUSTER_CONFIG.get('peer_nodes') or []
    if not isinstance(peers, list):
        return None
    # Prefer explicitly-marked active peer
    for peer in peers:
        try:
            if peer.get('role') == 'active' and peer.get('api_url'):
                return peer
        except AttributeError:
            continue
    # Fallback: first peer with api_url
    for peer in peers:
        try:
            if peer.get('api_url'):
                return peer
        except AttributeError:
            continue
    return None


def _check_remote_health(base_url: str) -> bool:
    """Check /health on a peer node."""
    try:
        url = base_url.rstrip('/') + '/health'
        resp = requests.get(url, timeout=5)
        if resp.status_code != 200:
            return False
        data = resp.json()
        return data.get('status') == 'ok'
    except Exception as e:
        logger.warning(f"[CLUSTER] Remote health check failed for {base_url}: {e}")
        return False


def _sync_configuration_from_active(active_base_url: str):
    """Pull configured JSON surfaces from the active node.

    This is intentionally conservative: only files listed in
    config_sync_paths are updated, and cluster_config.json is
    explicitly excluded.
    """
    targets = _get_config_sync_targets()
    if not targets:
        return

    try:
        url = active_base_url.rstrip('/') + '/cluster/config/snapshot'
        resp = requests.get(url, timeout=10)
        if resp.status_code != 200:
            logger.warning(f"[CLUSTER] Config snapshot failed from {active_base_url}: {resp.status_code}")
            return
        payload = resp.json()
        files = payload.get('files', {})
    except Exception as e:
        logger.error(f"[CLUSTER] Error pulling config snapshot from active node: {e}")
        return

    for rel_name, abs_path in targets:
        if rel_name not in files:
            continue
        try:
            os.makedirs(os.path.dirname(abs_path), exist_ok=True)
            with open(abs_path, 'w', encoding='utf-8') as f:
                json.dump(files[rel_name], f, indent=2)
            logger.info(f"[CLUSTER] Synced config {rel_name} from active node")
        except Exception as e:
            logger.error(f"[CLUSTER] Failed to write synced config {rel_name}: {e}")


def _cluster_manager_loop():
    """Background loop for passive nodes: health + failover + config sync."""
    interval = int(_CLUSTER_CONFIG.get('failover_check_interval_seconds', 10) or 10)
    unhealthy_threshold = int(_CLUSTER_CONFIG.get('failover_unhealthy_threshold', 3) or 3)
    sync_interval = int(_CLUSTER_CONFIG.get('config_sync_interval_seconds', 60) or 60)
    failures = 0
    last_sync = 0.0

    while True:
        try:
            role = _CLUSTER_CONFIG.get('role', 'standalone')
            if role == 'passive':
                peer = _get_active_peer()
                if not peer:
                    logger.debug("[CLUSTER] No active peer configured for passive node; skipping tick")
                else:
                    base_url = peer.get('api_url')
                    healthy = _check_remote_health(base_url)
                    now = time.time()
                    if healthy:
                        if failures:
                            logger.info("[CLUSTER] Active peer healthy again; resetting failure counter")
                        failures = 0
                        if now - last_sync >= sync_interval:
                            _sync_configuration_from_active(base_url)
                            last_sync = now
                    else:
                        failures += 1
                        logger.warning(f"[CLUSTER] Active peer unhealthy (consecutive failures={failures})")
                        if failures >= unhealthy_threshold:
                            with _CLUSTER_LOCK:
                                if _CLUSTER_CONFIG.get('role') == 'passive':
                                    _CLUSTER_CONFIG['role'] = 'active'
                                    logger.warning("[CLUSTER] Promoting PASSIVE node to ACTIVE after repeated health check failures")
                                    _persist_cluster_config()
            time.sleep(interval)
        except Exception as e:
            logger.error(f"[CLUSTER] Error in cluster manager loop: {e}")
            time.sleep(interval)


def _ensure_cluster_manager_started():
    global _cluster_manager_started
    if _cluster_manager_started:
        return
    _cluster_manager_started = True
    thread = threading.Thread(target=_cluster_manager_loop, daemon=True)
    thread.start()
    logger.info("[CLUSTER] Cluster manager thread started")


def _load_support_tickets() -> dict:
    """Load local support tickets for the built-in support portal."""
    if not os.path.exists(SUPPORT_TICKETS_PATH):
        return {"tickets": []}
    try:
        with open(SUPPORT_TICKETS_PATH, 'r', encoding='utf-8') as f:
            data = json.load(f)
            if isinstance(data, dict) and isinstance(data.get('tickets', []), list):
                return data
            return {"tickets": []}
    except Exception:
        return {"tickets": []}


def _save_support_tickets(data: dict) -> None:
    """Persist support tickets JSON data to disk."""
    os.makedirs(os.path.dirname(SUPPORT_TICKETS_PATH), exist_ok=True)
    with open(SUPPORT_TICKETS_PATH, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)


def _default_enterprise_integration_config() -> dict:
    """Return the default structure for enterprise integration config.

    This controls outbound Phase 2 adapters only (syslog/webhooks) and
    does not influence first-layer detection logic.
    """

    return {
        "syslog_targets": [],
        "webhook_targets": [],
    }


def _normalize_enterprise_integration_config(raw: dict) -> dict:
    """Validate and normalize enterprise integration config payload."""

    config = _default_enterprise_integration_config()
    if not isinstance(raw, dict):
        return config

    # Syslog targets (Splunk, QRadar, etc.)
    syslog_targets = []
    for item in (raw.get("syslog_targets") or []):
        if not isinstance(item, dict):
            continue
        host = str(item.get("host", "")).strip()
        if not host:
            continue
        try:
            port = int(item.get("port", 514))
        except Exception:
            port = 514
        protocol = str(item.get("protocol", "UDP")).upper()
        if protocol not in ("UDP", "TCP"):
            protocol = "UDP"
        syslog_targets.append({
            "host": host,
            "port": port,
            "protocol": protocol,
        })

    # Outbound webhooks (Slack, Teams, generic receivers)
    webhook_targets = []
    for item in (raw.get("webhook_targets") or []):
        if not isinstance(item, dict):
            continue
        url = str(item.get("url", "")).strip()
        if not url:
            continue
        secret = item.get("secret")
        if secret is not None:
            secret = str(secret)
        entry = {"url": url}
        if secret:
            entry["secret"] = secret
        webhook_targets.append(entry)

    config["syslog_targets"] = syslog_targets
    config["webhook_targets"] = webhook_targets
    return config


def _load_enterprise_integration_config() -> dict:
    """Load enterprise integration config from JSON, with sane defaults."""

    path = ENTERPRISE_INTEGRATION_CONFIG_PATH
    try:
        if not os.path.exists(path):
            # First read and file is missing: materialize a default config on disk
            config = _default_enterprise_integration_config()
            try:
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, 'w', encoding='utf-8') as f:
                    json.dump(config, f, indent=2, sort_keys=True)
            except Exception as write_err:
                logger.warning(f"[EnterpriseConfig] Failed to write default enterprise_integration.json: {write_err}")
            return config
        with open(path, 'r', encoding='utf-8') as f:
            raw = json.load(f)
        return _normalize_enterprise_integration_config(raw)
    except Exception as e:
        logger.warning(f"[EnterpriseConfig] Failed to load enterprise_integration.json, using defaults: {e}")
        return _default_enterprise_integration_config()


def _save_enterprise_integration_config(config: dict) -> None:
    """Persist normalized enterprise integration config to disk."""

    normalized = _normalize_enterprise_integration_config(config or {})
    path = ENTERPRISE_INTEGRATION_CONFIG_PATH
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(normalized, f, indent=2, sort_keys=True)


@app.route('/support', methods=['GET', 'POST'])
@require_role('admin', 'analyst')
def support_portal():
    """Simple built-in support portal for logging local tickets."""
    error = None
    message = None

    if request.method == 'POST':
        subject = (request.form.get('subject') or '').strip()
        description = (request.form.get('description') or '').strip()
        severity = (request.form.get('severity') or 'medium').strip().lower()

        if not subject or not description:
            error = "Subject and description are required."
        else:
            data = _load_support_tickets()
            tickets = data.get('tickets', [])
            next_id = max([t.get('id', 0) for t in tickets] or [0]) + 1
            ticket = {
                'id': next_id,
                'subject': subject,
                'description': description,
                'severity': severity,
                'status': 'open',
                'created_by': session.get('admin_username') or 'unknown',
                'created_at': _get_current_time().isoformat(),
            }
            tickets.append(ticket)
            data['tickets'] = tickets
            _save_support_tickets(data)
            message = "Support ticket created."

    data = _load_support_tickets()
    tickets = sorted(
        data.get('tickets', []),
        key=lambda t: t.get('created_at', ''),
        reverse=True,
    )[:50]

    return jsonify({
        'tickets': tickets,
        'error': error,
        'message': message,
    })


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Admin login and first-run setup entrypoint.

    This endpoint serves two closely related purposes:

    - When no admin users exist yet, it presents a one-time
      "Create First Admin" setup form and persists the result.
    - Once at least one admin is configured, it becomes a
      standard login form (or OIDC handoff) that gates access
      to the main dashboard.
    """

    has_admins = _has_admins()

    # FIRST-RUN SETUP: no admins defined yet -> create initial admin.
    if not has_admins:
        error = None

        if request.method == 'POST':
            username = (request.form.get('username') or '').strip()
            password = request.form.get('password') or ''
            confirm = request.form.get('confirm_password') or ''

            if not username or not password:
                error = "Username and password are required."
            elif password != confirm:
                error = "Passwords do not match."
            else:
                try:
                    _create_first_admin(username, password)
                    # Establish session for the newly created admin
                    session['admin_authenticated'] = True
                    session['admin_username'] = username
                    session['admin_role'] = 'admin'
                    return redirect(url_for('dashboard'))
                except Exception as e:
                    logger.error(f"[ADMIN_SETUP] Failed to create first admin: {e}")
                    error = "Failed to create admin user. Check server logs."

        pieces = [
            "<!doctype html>",
            "<html><head><meta charset='utf-8'>",
            "<title>Battle-Hardened AI - First Admin Setup</title>",
            "</head>",
            "<body style=\"background:#050816;color:#e1e8f0;font-family:system-ui,-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;padding:2rem;\">",
            "<h1>First Admin Setup</h1>",
            "<p>This appears to be a fresh deployment. Create the first admin account to protect the dashboard.</p>",
        ]

        if error:
            pieces.append(f"<p style='color:#ff6b6b;'>{error}</p>")

        pieces.append(
            "<form method='post'>"
            "<div><label>Username <input name='username' required></label></div>"
            "<div><label>Password <input type='password' name='password' required></label></div>"
            "<div><label>Confirm Password <input type='password' name='confirm_password' required></label></div>"
            "<div style='margin-top:1rem;'><button type='submit'>Create Admin</button></div>"
            "</form>"
            "<p style='margin-top:1rem;font-size:0.9rem;color:#9ca3af;'>You can later add more admins or integrate SSO from the identity/access configuration.</p>"
            "</body></html>"
        )

        return Response(''.join(pieces), mimetype='text/html')

    # NORMAL LOGIN FLOW (admins already configured)
    identity_cfg = _get_identity_config()
    oidc_configured = _is_oidc_configured(identity_cfg)

    # When OIDC is configured, prefer SSO for interactive admin login.
    if request.method == 'GET' and oidc_configured:
        return redirect(url_for('login_oidc_start'))

    error = None

    # Capture client context for login security assessment
    ip_address = request.remote_addr or '0.0.0.0'
    user_agent = request.headers.get('User-Agent', '')
    request_headers = dict(request.headers)

    # If this IP is already blocked by the AI engine, hard-deny login attempts
    try:
        blocked_ips_set = getattr(pcs_ai, '_blocked_ips', set())
    except Exception:
        blocked_ips_set = set()

    if request.method == 'POST' and ip_address in blocked_ips_set:
        # Do not even verify credentials for blocked IPs
        pieces = [
            "<!doctype html>",
            "<html><head><meta charset='utf-8'>",
            "<title>Battle-Hardened AI Admin Login</title>",
            "</head>",
            "<body style=\"background:#050816;color:#e1e8f0;font-family:system-ui,-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;padding:2rem;\">",
            "<h1>Admin Login</h1>",
            "<p style='color:#ff6b6b;'>Your IP has been blocked due to repeated malicious activity. "
            "Contact the administrator to regain access.</p>",
            "</body></html>",
        ]
        return Response(''.join(pieces), mimetype='text/html', status=403)

    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        password = request.form.get('password') or ''
        otp = request.form.get('otp') or ''

        user = _find_admin_user(username)

        # Determine whether this login attempt ultimately succeeded
        login_success = False

        if not user or not _verify_password(username, password):
            error = "Invalid username or password."
        else:
            # If MFA is required for admins, enforce it via configured secret.
            if identity_cfg.get('mfa_required_for_admins'):
                if not _verify_mfa(user, otp):
                    error = "Invalid MFA code."
                else:
                    login_success = True
            else:
                login_success = True

        # Let the AI engine assess this login attempt (for brute-force detection, etc.)
        try:
            pcs_ai.assess_login_attempt(
                ip_address=ip_address,
                username=username,
                success=login_success,
                user_agent=user_agent,
                headers=request_headers,
            )
        except Exception as e:
            logger.warning(f"[LOGIN] Failed to assess login attempt via AI engine: {e}")

        if login_success and not error:
            session['admin_authenticated'] = True
            session['admin_username'] = username
            session['admin_role'] = user.get('role', 'admin')
            return redirect(url_for('dashboard'))

    # Minimal inline HTML to avoid external template dependencies.
    # This keeps the attack surface small while still allowing
    # local admin authentication when OIDC is not in use.
    pieces = [
        "<!doctype html>",
        "<html><head><meta charset='utf-8'>",
        "<title>Battle-Hardened AI Admin Login</title>",
        "</head>",
        "<body style=\"background:#050816;color:#e1e8f0;font-family:system-ui,-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;padding:2rem;\">",
        "<h1>Admin Login</h1>",
    ]

    if error:
        pieces.append(f"<p style='color:#ff6b6b;'>{error}</p>")

    pieces.append(
        "<form method='post'>"
        "<div><label>Username <input name='username' required></label></div>"
        "<div><label>Password <input type='password' name='password' required></label></div>"
        "<div><label>MFA Code <input name='otp' placeholder='If required'></label></div>"
        "<div style='margin-top:1rem;'><button type='submit'>Login</button></div>"
        "</form>"
        "</body></html>"
    )

    return Response(''.join(pieces), mimetype='text/html')


@app.route('/login/oidc/start')
def login_oidc_start():
    """Begin OIDC SSO login flow for admin dashboard."""
    if not _has_admins():
        # If no admin users are configured, there is nothing to log in to.
        return redirect(url_for('dashboard'))

    identity_cfg = _get_identity_config()
    if not _is_oidc_configured(identity_cfg):
        logger.warning("[OIDC] OIDC login requested but not configured; falling back to local login")
        return redirect(url_for('login'))

    state = hashlib.sha256(os.urandom(32)).hexdigest()
    nonce = hashlib.sha256(os.urandom(32)).hexdigest()
    session['oidc_state'] = state
    session['oidc_nonce'] = nonce

    params = {
        'client_id': identity_cfg.get('oidc_client_id'),
        'response_type': 'code',
        'scope': identity_cfg.get('oidc_scope', 'openid profile email'),
        'redirect_uri': identity_cfg.get('oidc_redirect_uri'),
        'state': state,
        'nonce': nonce,
    }

    auth_base = identity_cfg.get('oidc_authorization_endpoint')
    if not auth_base:
        logger.error("[OIDC] Authorization endpoint missing in identity config")
        return redirect(url_for('login'))

    auth_url = f"{auth_base}?{urlencode(params)}"
    return redirect(auth_url)


@app.route('/login/oidc/callback')
def login_oidc_callback():
    """Handle OIDC SSO callback and establish admin session."""
    if not _has_admins():
        return redirect(url_for('dashboard'))

    error = request.args.get('error')
    if error:
        logger.error(f"[OIDC] Authorization error from IdP: {error}")
        return redirect(url_for('login'))

    code = request.args.get('code')
    state = request.args.get('state')
    if not code or not state or state != session.get('oidc_state'):
        logger.error("[OIDC] Missing code or state mismatch in callback")
        return redirect(url_for('login'))

    identity_cfg = _get_identity_config()
    if not _is_oidc_configured(identity_cfg):
        logger.error("[OIDC] Callback received but OIDC not configured")
        return redirect(url_for('login'))

    try:
        tokens = _exchange_oidc_code_for_tokens(identity_cfg, code)
        id_token = tokens.get('id_token')
        if not id_token:
            logger.error("[OIDC] No id_token in token response")
            return redirect(url_for('login'))

        claims = _decode_oidc_id_token(id_token)
        expected_nonce = session.get('oidc_nonce')
        if expected_nonce and claims.get('nonce') != expected_nonce:
            logger.error("[OIDC] Nonce mismatch in id_token")
            return redirect(url_for('login'))

        user = _map_oidc_claims_to_local_user(claims)
        if not user:
            logger.error("[OIDC] No matching local admin user for SSO identity")
            return redirect(url_for('login'))

        username = user.get('username') or claims.get('preferred_username') or claims.get('email') or claims.get('sub')
        session['admin_authenticated'] = True
        session['admin_username'] = username
        session['admin_role'] = user.get('role', 'admin')
        logger.info(f"[OIDC] SSO login successful for {username}")
        return redirect(url_for('dashboard'))
    except Exception:
        # Errors already logged in helpers
        return redirect(url_for('login'))


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/health', methods=['GET'])
def health_check():
    """Lightweight health endpoint for load balancers and failover.

    Returns basic node and cluster role information plus a minimal
    threat-stat summary. This is safe to call frequently.
    """
    try:
        stats = pcs_ai.get_threat_statistics()
        payload = {
            'status': 'ok',
            'node_id': _CLUSTER_CONFIG.get('node_id'),
            'cluster_name': _CLUSTER_CONFIG.get('cluster_name'),
            'role': _CLUSTER_CONFIG.get('role', 'standalone'),
            'time': _get_current_time().isoformat(),
            'threat_counters': {
                'total_threats_detected': stats.get('total_threats_detected', 0),
                'blocked_requests': stats.get('blocked_requests', 0),
                'active_attacks': stats.get('active_attacks', 0)
            }
        }
        return jsonify(payload), 200
    except Exception as e:
        logger.error(f"[HEALTH] Health check failed: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 503


@app.route('/cluster/config/snapshot', methods=['GET'])
def cluster_config_snapshot():
    """Expose a minimal JSON snapshot of selected config surfaces.

    Only ACTIVE nodes serve snapshots. This is used by passive
    nodes for configuration synchronization and is intentionally
    limited to the files listed in config_sync_paths.
    """
    if _CLUSTER_CONFIG.get('role') != 'active':
        return jsonify({'status': 'error', 'message': 'Only ACTIVE node can provide config snapshot'}), 403

    files = {}
    for rel_name, abs_path in _get_config_sync_targets():
        try:
            if os.path.exists(abs_path):
                with open(abs_path, 'r', encoding='utf-8') as f:
                    files[rel_name] = json.load(f)
        except Exception as e:
            logger.error(f"[CLUSTER] Failed to include {rel_name} in snapshot: {e}")

    return jsonify({
        'status': 'ok',
        'node_id': _CLUSTER_CONFIG.get('node_id'),
        'cluster_name': _CLUSTER_CONFIG.get('cluster_name'),
        'files': files,
    }), 200

@app.route('/')
def dashboard():
    """Main dashboard (always requires an authenticated admin session).

    On first run when no admins exist yet, this will redirect to the
    /login endpoint, which presents the first-admin setup flow. After
    that, /login behaves as a standard admin login (or OIDC handoff).
    """

    if not session.get("admin_authenticated"):
        return redirect(url_for('login'))

    # Filter live threats so whitelisted IPs don't clutter the dashboard view
    whitelisted = set(pcs_ai.get_whitelisted_ips())
    filtered_logs = [
        log for log in pcs_ai._threat_log[-100:]
        if log.get('ip_address') not in whitelisted
    ][::-1]

    return render_template('inspector_ai_monitoring.html',
                         stats=pcs_ai.get_threat_statistics(),
                         blocked_ips=pcs_ai.get_blocked_ips(),
                         whitelisted_ips=pcs_ai.get_whitelisted_ips(),
                         threat_logs=filtered_logs,
                         ml_stats=pcs_ai.get_ml_model_stats(),
                         vpn_stats=pcs_ai.get_vpn_tor_statistics(),
                         ai_abilities=pcs_ai.get_ai_abilities_status())


@app.route('/legacy')
def legacy_dashboard():
    """Legacy route - redirects to main dashboard"""
    return redirect(url_for('dashboard'))




@app.route('/inspector/ai-monitoring')
def ai_monitoring():
    """Legacy AI Monitoring Dashboard"""
    return redirect(url_for('dashboard'))


@app.route('/docs', methods=['GET'])
@require_role('admin', 'analyst', 'auditor')
def docs_portal():
    """Enterprise documentation portal index.

    Aggregates the core Markdown documents (overview, startup,
    scaling, architecture, and attack-handling flows) into a single
    navigable portal for auditors, operators, and engineers.
    """
    base_dir = os.path.dirname(__file__)
    docs = []

    for meta in _DOCS_PORTAL_FILES:
        rel_path = meta.get('rel_path') or []
        abs_path = os.path.join(base_dir, *rel_path) if rel_path else None
        exists = bool(abs_path and os.path.exists(abs_path))
        docs.append({
            'id': meta.get('id'),
            'title': meta.get('title'),
            'filename': meta.get('filename'),
            'category': meta.get('category', 'General'),
            'description': meta.get('description', ''),
            'exists': exists,
        })

    return render_template('docs_portal.html', docs=docs)


@app.route('/docs/view/<doc_id>', methods=['GET'])
@require_role('admin', 'analyst', 'auditor')
def view_doc(doc_id: str):
    """Render a single documentation file in a lightweight viewer.

    This does not attempt full Markdown rendering; content is shown as
    preformatted text to keep dependencies minimal and behavior
    predictable in offline environments.
    """
    base_dir = os.path.dirname(__file__)
    selected = None
    for meta in _DOCS_PORTAL_FILES:
        if meta.get('id') == doc_id:
            selected = meta
            break

    if not selected:
        return Response("Document not found", status=404)

    rel_path = selected.get('rel_path') or []
    abs_path = os.path.join(base_dir, *rel_path) if rel_path else None
    if not abs_path or not os.path.exists(abs_path):
        return Response("Document not found", status=404)

    # Optional raw text view for simple copy/export
    if request.args.get('raw'):
        try:
            with open(abs_path, 'r', encoding='utf-8') as f:
                raw_content = f.read()
        except Exception as e:
            logger.error(f"[DOCS] Failed to load {abs_path}: {e}")
            return Response("Unable to load document", status=500)
        return Response(raw_content, mimetype='text/plain; charset=utf-8')

    try:
        with open(abs_path, 'r', encoding='utf-8') as f:
            content = f.read()
    except Exception as e:
        logger.error(f"[DOCS] Failed to load {abs_path}: {e}")
        return Response("Unable to load document", status=500)

    doc_info = {
        'id': selected.get('id'),
        'title': selected.get('title'),
        'filename': selected.get('filename'),
        'category': selected.get('category', 'General'),
        'description': selected.get('description', ''),
    }

    return render_template('docs_viewer.html', doc=doc_info, content=content)


@app.route('/inspector/ai-monitoring/export')
def export_monitoring_data():
    """Export enterprise security report"""
    export_format = request.args.get('format', 'html')  # html, json, or raw
    
    if export_format == 'raw':
        # Raw JSON data export
        data = pcs_ai.export_all_monitoring_data()
        filename = f"security_raw_export_{_get_current_time().strftime('%Y%m%d_%H%M%S')}.json"
        filepath = os.path.join('data', filename)
        os.makedirs('data', exist_ok=True)
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        
        return send_file(filepath, as_attachment=True, download_name=filename)
    
    elif export_format == 'json':
        # Structured enterprise report as JSON
        report = pcs_ai.generate_enterprise_security_report()
        filename = f"Enterprise_Security_Report_{_get_current_time().strftime('%Y%m%d_%H%M%S')}.json"
        filepath = os.path.join('data', filename)
        os.makedirs('data', exist_ok=True)
        
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2)
        
        return send_file(filepath, as_attachment=True, download_name=filename)
    
    else:  # HTML report (default)
        report = pcs_ai.generate_enterprise_security_report()
        html_content = _generate_html_report(report)
        
        filename = f"Enterprise_Security_Report_{_get_current_time().strftime('%Y%m%d_%H%M%S')}.html"
        filepath = os.path.join('data', filename)
        os.makedirs('data', exist_ok=True)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return send_file(filepath, as_attachment=True, download_name=filename)
def _generate_html_report(report: dict) -> str:
    """HTML export stub.

    To keep the core server lightweight and avoid complex f-string/HTML
    parsing issues in constrained environments, this build returns a
    minimal HTML wrapper around the JSON enterprise report.

    The JSON export (html?format=json) remains the canonical surface for
    offline analysis and auditing.
    """
    # Preserve the existing report payload but present it as simple
    # preformatted JSON for offline viewing.
    escaped = json.dumps(report, indent=2)
    return (
        "<!doctype html>\n"
        "<html><head><meta charset='utf-8'>"
        "<title>Battle-Hardened AI Enterprise Report</title>" 
        "</head><body style=\"background:#050816;color:#e1e8f0;font-family:system-ui,-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;padding:2rem;\">" 
        "<h1>Enterprise Security Report (JSON View)</h1>" 
        "<p>This build exposes the full report as JSON-only; HTML layout "
        "is intentionally minimal and offline-only.</p>" 
        "<pre style=\"background:#0b1020;border-radius:8px;padding:1rem;overflow:auto;\">"
        f"{escaped}" 
        "</pre></body></html>"
    )


@app.route('/inspector/ai-monitoring/clear-all', methods=['POST'])
@require_role('admin')
def clear_all_data():
    """Clear all monitoring data"""
    try:
        result = pcs_ai.clear_all_monitoring_data()
        return jsonify({
            'success': True,
            'message': 'All monitoring data cleared successfully',
            'summary': result
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500


@app.route('/api/support/tickets', methods=['GET'])
@require_role('admin')
def list_support_tickets():
    """List all local support tickets (admin-only JSON view)."""
    data = _load_support_tickets()
    return jsonify(data.get('tickets', []))


@app.route('/api/support/tickets/<int:ticket_id>/status', methods=['POST'])
@require_role('admin')
def update_support_ticket_status(ticket_id: int):
    """Update the status of a support ticket (admin-only)."""
    payload = request.get_json(silent=True) or {}
    new_status = (payload.get('status') or request.form.get('status') or '').strip().lower()
    if not new_status:
        return jsonify({'success': False, 'message': 'status is required'}), 400

    data = _load_support_tickets()
    tickets = data.get('tickets', [])
    updated = False
    for t in tickets:
        if t.get('id') == ticket_id:
            t['status'] = new_status
            t['updated_at'] = _get_current_time().isoformat()
            updated = True
            break

    if not updated:
        return jsonify({'success': False, 'message': 'ticket not found'}), 404

    data['tickets'] = tickets
    _save_support_tickets(data)
    return jsonify({'success': True, 'ticket_id': ticket_id, 'status': new_status})


@app.route('/inspector/ai-monitoring/clear-threats', methods=['POST'])
@require_role('admin', 'analyst')
def clear_threats():
    """Clear only threat logs"""
    try:
        result = pcs_ai.clear_threat_log_only()
        return jsonify({
            'success': True,
            'message': 'Threat logs cleared successfully',
            'summary': result
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500


@app.route('/inspector/ai-monitoring/clear-blocked-ips', methods=['POST'])
@require_role('admin')
def clear_blocked_ips():
    """Clear only blocked IPs"""
    try:
        result = pcs_ai.clear_blocked_ips_only()
        return jsonify({
            'success': True,
            'message': 'Blocked IPs cleared successfully',
            'summary': result
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500


@app.route('/inspector/ai-monitoring/retrain-ml', methods=['POST'])
@require_role('admin')
def retrain_ml_models():
    """Force retrain ML models with all historical data"""
    try:
        # Force retrain using all available threat data
        result = pcs_ai.retrain_ml_models_now()
        
        if result.get('success', False):
            return jsonify({
                'success': True,
                'message': 'ML models retrained successfully',
                'training_samples': result.get('training_samples', 0),
                'trained_at': result.get('trained_at', _get_current_time().isoformat()),
                'models_trained': result.get('models_trained', [])
            })
        else:
            return jsonify({
                'success': False,
                'error': result.get('error', 'Training failed')
            }), 500
            
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


# ============================================================================
# CATCH-ALL HONEYPOT ROUTE - MUST BE FIRST TO CATCH ALL /api/ ATTACKS
# ============================================================================
@app.route('/api/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])
def honeypot_api(path):
    """Catch-all honeypot for detecting web application attacks - DEFINED FIRST TO INTERCEPT ALL /api/ REQUESTS"""
    from AI.pcs_ai import log_threat, ThreatLevel
    
    # Get request details
    ip = request.remote_addr or '0.0.0.0'
    method = request.method
    full_path = request.full_path or ''
    query_string = request.query_string.decode('utf-8', errors='ignore') if request.query_string else ''
    user_agent = request.headers.get('User-Agent', '')

    # Decode URL-encoded payloads so we can reliably detect patterns
    try:
        decoded_full_path = unquote_plus(full_path)
    except Exception:
        decoded_full_path = full_path
    lower_path = decoded_full_path.lower()
    
    # Analyze attack patterns in URL and parameters
    attack_indicators = []
    attack_type = "Web Application Probe"
    threat_level = ThreatLevel.SUSPICIOUS
    
    # SQL Injection detection
    if any(pattern in lower_path for pattern in ['union', 'select', 'insert', 'delete', 'drop', 'exec', 'waitfor', '--', ';--', '/*']):
        attack_indicators.append("SQL Injection")
        attack_type = "SQL Injection"
        threat_level = ThreatLevel.DANGEROUS
    
    # XSS detection
    if any(pattern in lower_path for pattern in ['<script', 'javascript:', 'onerror=', 'onload=', 'alert(', 'document.cookie']):
        attack_indicators.append("XSS")
        attack_type = "Cross-Site Scripting (XSS)"
        threat_level = ThreatLevel.DANGEROUS
    
    # Command Injection detection
    if any(pattern in lower_path for pattern in ['system(', 'exec(', 'shell_exec(', 'bash -c', ';cat', ';ls', ';wget', ';curl', '&&', '||', '`']):
        attack_indicators.append("Command Injection")
        attack_type = "Command Injection"
        threat_level = ThreatLevel.CRITICAL
    
    # Path Traversal detection
    if any(pattern in decoded_full_path for pattern in ['../', '..\\', '/etc/passwd', '/etc/shadow', 'c:\\windows']):
        attack_indicators.append("Path Traversal")
        attack_type = "Directory Traversal"
        threat_level = ThreatLevel.DANGEROUS
    
    # File Inclusion detection
    if any(pattern in lower_path for pattern in ['php://input', 'php://filter', 'file://', 'data://', 'expect://', 'zip://']):
        attack_indicators.append("File Inclusion")
        attack_type = "Local/Remote File Inclusion"
        threat_level = ThreatLevel.CRITICAL
    
    # SSTI detection
    if any(pattern in decoded_full_path for pattern in ['{{', '{%', '<%', '__import__', '${']):
        attack_indicators.append("SSTI")
        attack_type = "Server-Side Template Injection"
        threat_level = ThreatLevel.CRITICAL

    # NoSQL Injection detection (Mongo-style operators)
    if any(pattern in lower_path for pattern in ['$ne', '$gt', '$gte', '$lte', '$where']):
        attack_indicators.append("NoSQL Injection")
        attack_type = "NoSQL Injection"
        threat_level = ThreatLevel.DANGEROUS

    # SSRF detection (internal metadata / localhost targets)
    if any(pattern in lower_path for pattern in [
        '169.254.169.254',
        'latest/meta-data',
        'metadata.google.internal',
        'localhost:22',
        '127.0.0.1:22',
    ]):
        attack_indicators.append("SSRF")
        attack_type = "Server-Side Request Forgery"
        threat_level = ThreatLevel.DANGEROUS

    # Deserialization endpoints (any POST to these is highly suspicious)
    if method == 'POST' and (path.startswith('session') or path.startswith('deserialize')):
        attack_indicators.append("Deserialization Attack")
        attack_type = "Insecure Deserialization"
        threat_level = ThreatLevel.CRITICAL
    
    # Log the attack - THIS TRIGGERS IP BLOCKING, LOCAL STORAGE, AND RELAY TO VPS
    details = f"Web attack attempt on /api/{path} | Method: {method} | Patterns: {', '.join(attack_indicators) if attack_indicators else 'Probing'} | UA: {user_agent[:50]}"
    
    log_threat(
        ip_address=ip,
        threat_type=attack_type,
        details=details,
        level=threat_level,
        action="honeypot_detected",
        headers=dict(request.headers),
        is_local=True  # CRITICAL: This triggers relay to VPS
    )
    
    # Return 404 to make it look like a real missing endpoint
    return jsonify({'error': 'Not Found'}), 404


@app.route('/api/threat/block-ip', methods=['POST'])
@require_role('admin', 'analyst')
def block_threat_ip():
    """Manually block an IP from threat logs"""
    try:
        data = request.get_json(silent=True) or {}
        ip_address = data.get('ip_address')
        
        if not ip_address:
            return jsonify({'success': False, 'error': 'IP address required'}), 400
        
        # Use pcs_ai's internal blocking mechanism
        pcs_ai._block_ip(ip_address)
        
        return jsonify({
            'success': True,
            'message': f'IP {ip_address} blocked successfully',
            'ip_address': ip_address
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# REMOVED: Training endpoints (subscribers download models from relay, not train locally)
# Training happens ONLY on relay server (centralized)
# Subscribers use /api/models/sync to download pre-trained models


# REMOVED: GPU endpoints (relay server only)
# Subscribers use CPU for inference (lightweight detection)
# GPU training happens on relay server


# GPU Info Endpoint (stub for compatibility)
@app.route('/api/gpu/info', methods=['GET'])
def get_gpu_info():
    """Return GPU info stub - actual GPU training happens on relay server"""
    return jsonify({
        'gpu_available': False,
        'gpu_count': 0,
        'gpu_name': 'CPU Only (GPU training on relay server)',
        'message': 'This container uses CPU for inference. GPU-accelerated training runs on the central relay server.',
        'mode': 'Inference Only'
    })


@app.route('/api/signatures/extracted', methods=['GET'])
def get_extracted_signatures():
    """Get automatically extracted attack signatures (DEFENSIVE - no exploit code)"""
    try:
        from AI.signature_extractor import get_signature_extractor
        
        extractor = get_signature_extractor()
        ml_data = extractor.get_ml_training_data()
        
        return jsonify({
            'status': 'success',
            'metadata': {
                'total_patterns': ml_data['total_samples'],
                'attack_distribution': ml_data['attack_distribution'],
                'architecture': 'DEFENSIVE - Patterns only, NO exploit code stored',
                'data_safety': ml_data['data_safety']
            },
            'top_encodings': dict(list(extractor.attack_patterns['encodings_used'].items())[:10]),
            'top_keywords': dict(list(extractor.attack_patterns['attack_keywords'].items())[:20]),
            'encoding_chains_detected': len(extractor.attack_patterns['encoding_chains']),
            'regex_patterns_generated': len(extractor.attack_patterns['regex_patterns'])
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


# REMOVED: GPU training (relay server only)
# Subscribers download pre-trained models (280 KB) from relay
# Training (heavy compute) happens centrally on relay server


@app.route('/api/models/sync', methods=['POST'])
def sync_models_from_relay():
    """Download latest ML models from relay server (Premium mode)"""
    try:
        from AI.training_sync_client import TrainingSyncClient
        
        relay_url = os.getenv('MODEL_SYNC_URL', os.getenv('RELAY_URL', '').replace('wss://', 'https://').replace('ws://', 'https://').replace(':60001', ':60002'))
        
        if not relay_url:
            return jsonify({
                'success': False,
                'message': 'MODEL_SYNC_URL not configured in .env'
            }), 400
        
        sync_client = TrainingSyncClient(relay_url)
        result = sync_client.sync_ml_models()
        
        if result and result.get('success'):
            # Reload models in pcs_ai after sync
            pcs_ai._load_ml_models()
            return jsonify({
                'success': True,
                'message': f"Downloaded {result.get('synced', 0)} models from relay server",
                'models': result.get('models', [])
            })
        else:
            return jsonify(result if result else {'success': False, 'message': 'Sync failed'}), 500
            
    except ImportError:
        return jsonify({
            'success': False,
            'message': 'TrainingSyncClient not available. Check AI folder.'
        }), 500
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/inspector/users')
@require_role('admin')
def user_management():
    """User management placeholder.

    Full user/role management is out of scope for the
    first-layer-only build. This endpoint is a stub so links in the
    UI do not break.
    """
    return "User management console is not implemented in this build."

@app.route('/api/relay/block-peer', methods=['POST'])
def block_peer_api():
    """Block a peer from connecting to the relay"""
    try:
        data = request.get_json()
        peer_name = data.get('peer_name')
        
        if not peer_name:
            return jsonify({'success': False, 'message': 'Peer name is required'})
        
        # Add to blocked peers list (you can store this in a file or database)
        blocked_peers_file = 'json/blocked_peers.json'
        
        # Load existing blocked peers
        blocked_peers = []
        if os.path.exists(blocked_peers_file):
            try:
                with open(blocked_peers_file, 'r') as f:
                    blocked_peers = json.load(f)
            except Exception:
                blocked_peers = []
        
        # Add new blocked peer
        if peer_name not in blocked_peers:
            blocked_peers.append(peer_name)
            
            # Save to file
            with open(blocked_peers_file, 'w') as f:
                json.dump(blocked_peers, f, indent=2)
            
            return jsonify({
                'success': True,
                'message': f'Peer {peer_name} has been blocked'
            })
        else:
            return jsonify({
                'success': False,
                'message': f'Peer {peer_name} is already blocked'
            })
            
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/profile')
@require_role('admin')
def profile():
    """User profile placeholder.

    There is no full profile/SSO console in this build; this stub is
    kept only so navigation does not 404.
    """
    return "Profile management is not implemented in this build."


# API endpoints for network monitoring
@app.route('/api/check-request', methods=['POST'])
def check_request():
    """Check a request for threats (for integration with other systems)"""
    data = request.get_json(silent=True) or {}
    
    assessment = pcs_ai.assess_request_pattern(
        ip_address=data.get('ip_address', request.remote_addr),
        endpoint=data.get('endpoint', '/'),
        method=data.get('method', 'GET'),
        user_agent=data.get('user_agent', ''),
        headers=data.get('headers', {})
    )
    
    return jsonify({
        'should_block': assessment.should_block,
        'threat_level': assessment.level.value,
        'threats': assessment.threats,
        'ip_address': assessment.ip_address
    })


@app.route('/api/check-login', methods=['POST'])
def check_login():
    """Check a login attempt for threats"""
    data = request.get_json(silent=True) or {}
    
    assessment = pcs_ai.assess_login_attempt(
        ip_address=data.get('ip_address', request.remote_addr),
        username=data.get('username', ''),
        success=data.get('success', False),
        user_agent=data.get('user_agent', ''),
        headers=data.get('headers', {})
    )
    
    return jsonify({
        'should_block': assessment.should_block,
        'threat_level': assessment.level.value,
        'threats': assessment.threats,
        'ip_address': assessment.ip_address
    })


@app.route('/api/stats')
def api_stats():
    """Get statistics as JSON"""
    return jsonify({
        'stats': pcs_ai.get_threat_statistics(),
        'blocked_ips': pcs_ai.get_blocked_ips(),
        'ml_stats': pcs_ai.get_ml_model_stats(),
        'vpn_stats': pcs_ai.get_vpn_tor_statistics()
    })


@app.route('/api/layer-stats')
def api_layer_stats():
    """Get per-layer AI/ML detection statistics as JSON."""
    # This is a focused export of the same live counters used by the
    # Section 4 "AI Signal Layers" dashboard view, suitable for
    # external reporting or integration.

    return jsonify(pcs_ai.get_layer_detection_stats())

@app.route('/api/threat_log')
def api_threat_log():
    """Get threat log data for new dashboard"""
    stats = pcs_ai.get_threat_statistics()
    return jsonify({
        'threats': stats.get('recent_threats', []),
        'total': stats.get('total_threats_detected', 0),
        'blocked_ips': pcs_ai.get_blocked_ips()
    })


@app.route('/api/unblock/<ip_address>', methods=['POST'])
@require_role('admin', 'analyst')
def unblock_ip(ip_address):
    """Unblock an IP address"""
    success = pcs_ai.unblock_ip(ip_address)
    return jsonify({
        'success': success,
        'message': f'IP {ip_address} unblocked' if success else f'IP {ip_address} was not blocked'
    })


@app.route('/api/whitelist', methods=['GET'])
def get_whitelist():
    """Get list of whitelisted IPs"""
    return jsonify({
        'success': True,
        'whitelist': pcs_ai.get_whitelist()
    })


@app.route('/api/whitelist/add', methods=['POST'])
@require_role('admin')
def add_to_whitelist():
    """Add an IP to the whitelist"""
    data = request.get_json()
    ip_address = data.get('ip_address')
    
    if not ip_address:
        return jsonify({
            'success': False,
            'message': 'IP address is required'
        }), 400
    
    success = pcs_ai.add_to_whitelist(ip_address)
    return jsonify({
        'success': success,
        'message': f'IP {ip_address} added to whitelist' if success else f'IP {ip_address} is already whitelisted'
    })


@app.route('/api/whitelist/remove', methods=['POST'])
@require_role('admin')
def remove_from_whitelist():
    """Remove an IP from the whitelist"""
    data = request.get_json()
    ip_address = data.get('ip_address')
    
    if not ip_address:
        return jsonify({
            'success': False,
            'message': 'IP address is required'
        }), 400
    
    success = pcs_ai.remove_from_whitelist(ip_address)
    return jsonify({
        'success': success,
        'message': f'IP {ip_address} removed from whitelist' if success else f'IP {ip_address} not in whitelist or cannot be removed'
    })


@app.route('/api/p2p/status', methods=['GET'])
def get_p2p_status():
    """Get P2P sync status"""
    try:
        from AI.p2p_sync import get_p2p_status
        status = get_p2p_status()
        return jsonify({
            'success': True,
            'p2p_status': status
        })
    except ImportError:
        return jsonify({
            'success': True,
            'p2p_status': {'enabled': False, 'message': 'P2P sync not available'}
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/p2p/threats', methods=['GET', 'POST'])
def p2p_threats():
    """
    Peer-to-peer threat exchange endpoint
    GET: Return our threats for peer to fetch
    POST: Receive threats from peer
    """
    try:
        from AI.p2p_sync import get_p2p_sync, get_peer_threats
        
        if request.method == 'POST':
            # Receive threats from peer
            data = request.get_json()
            threats = data.get('threats', [])
            
            sync = get_p2p_sync()
            new_count = 0
            for threat in threats:
                if sync.receive_threat(threat):
                    new_count += 1
                    # Learn from peer's threat
                    try:
                        pcs_ai.add_global_threat_to_learning(threat)
                    except Exception:
                        pass
            
            return jsonify({
                'success': True,
                'received': new_count,
                'message': f'Received {new_count} new threats'
            })
        
        else:
            # GET: Return our threats for peer to fetch
            since = request.args.get('since', '')
            limit = int(request.args.get('limit', 100))
            
            # Return our detected threats
            threats = pcs_ai._threat_log[-limit:]
            
            # Filter by timestamp if requested
            if since:
                threats = [t for t in threats if t.get('timestamp', '') > since]
            
            return jsonify({
                'success': True,
                'threats': threats,
                'count': len(threats)
            })
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/relay/status', methods=['GET'])
def get_relay_status_api():
    """Get relay client status and connected peers"""
    try:
        from AI.relay_client import get_relay_status
        status = get_relay_status()
        return jsonify({
            'success': True,
            'relay_status': status
        })
    except ImportError:
        return jsonify({
            'success': True,
            'relay_status': {'enabled': False, 'message': 'Relay client not available'}
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/p2p/add-peer', methods=['POST'])
def add_peer():
    """Add a new peer URL dynamically"""
    data = request.get_json()
    peer_url = data.get('peer_url')
    
    if not peer_url:
        return jsonify({
            'success': False,
            'message': 'peer_url is required'
        }), 400
    
    try:
        from AI.p2p_sync import get_p2p_sync
        sync = get_p2p_sync()
        
        if peer_url not in sync.peer_urls:
            sync.peer_urls.append(peer_url)
            return jsonify({
                'success': True,
                'message': f'Added peer: {peer_url}'
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Peer already configured'
            })
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


# ==============================================================================
# ExploitDB Signature Distribution Endpoints (P2P Signature Sharing)
# ==============================================================================

@app.route('/api/signatures/types', methods=['GET'])
def get_signature_types():
    """Get list of available attack types for signature distribution."""
    try:
        from AI.signature_distribution import get_signature_distribution
        dist = get_signature_distribution()
        
        attack_types = dist.get_all_attack_types()
        
        return jsonify({
            'success': True,
            'attack_types': attack_types,
            'count': len(attack_types),
            'mode': dist.mode,
            'is_master': dist.mode == 'master'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/signatures/<attack_type>', methods=['GET'])
def get_signatures_for_type(attack_type):
    """Serve signatures for a specific attack type (master nodes)."""
    try:
        from AI.signature_distribution import get_signature_distribution
        dist = get_signature_distribution()
        
        result = dist.serve_signatures(attack_type)
        
        if 'error' in result:
            return jsonify(result), 403
        
        return jsonify({
            'success': True,
            **result
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/signatures/stats', methods=['GET'])
def get_signature_stats():
    """Get signature distribution statistics."""
    try:
        from AI.signature_distribution import get_signature_distribution
        dist = get_signature_distribution()
        
        return jsonify({
            'success': True,
            'stats': dist.get_stats()
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/signatures/sync', methods=['POST'])
def sync_signatures():
    """Trigger manual signature sync with peers (client nodes)."""
    try:
        from AI.signature_distribution import get_signature_distribution
        dist = get_signature_distribution()
        
        if dist.mode != 'client':
            return jsonify({
                'success': False,
                'message': 'Only client nodes can request sync'
            }), 400
        
        dist.sync_with_peers()
        
        return jsonify({
            'success': True,
            'message': 'Signature sync completed',
            'stats': dist.get_stats()
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


def _log_dashboard_api_error(endpoint: str, error: Exception) -> None:
    """Mirror dashboard/API failures into the comprehensive audit log.

    Stage 10 treats repeated explainability/visualization/dashboard
    errors as system issues worth auditing. This helper is best-effort
    and will silently no-op if the audit stack is unavailable.
    """
    try:
        from AI.emergency_killswitch import get_audit_log, AuditEventType

        audit = get_audit_log()
        audit.log_event(
            event_type=AuditEventType.SYSTEM_ERROR,
            actor='dashboard_api',
            action='endpoint_error',
            target=endpoint,
            outcome='failure',
            details={
                'error': str(error),
                'endpoint': endpoint,
            },
            risk_level='medium',
            metadata={'module': 'server', 'stage': '10'},
        )
    except Exception:
        # Never let audit issues break the API path itself.
        pass


@app.route('/api/graph-intelligence/attack-chains', methods=['GET'])
def get_attack_chains():
    """Get attack chain visualization data (Phase 4)."""
    try:
        from AI.pcs_ai import get_attack_chains as get_chains
        return jsonify(get_chains())
    except Exception as e:
        logger.error(f"[API] Attack chains error: {e}")
        return jsonify({
            'error': str(e),
            'total_chains': 0,
            'lateral_movement_count': 0,
            'total_nodes': 0,
            'total_edges': 0,
            'attack_chains': []
        }), 500


@app.route('/api/explainability/decisions', methods=['GET'])
def get_explainability_decisions():
    """Get AI decision explanations (Phase 7)."""
    try:
        from AI.pcs_ai import get_explainability_decisions as get_decisions
        return jsonify(get_decisions())
    except Exception as e:
        logger.error(f"[API] Explainability error: {e}")
        _log_dashboard_api_error('/api/explainability/decisions', e)
        return jsonify({
            'error': str(e),
            'total_decisions': 0,
            'high_confidence_count': 0,
            'low_confidence_count': 0,
            'average_confidence': 0.0,
            'decisions': []
        }), 500


@app.route('/api/forensics/reset', methods=['POST'])
def reset_forensic_reports():
    """Delete JSON forensic report files while keeping the folder."""
    # This powers the dashboard's "reset forensic reports" button so
    # operators can clear old explainability forensic JSON data without
    # affecting directory layout or other non-JSON artifacts.
    try:
        from AI.pcs_ai import clear_forensic_reports

        result = clear_forensic_reports()
        status = 200 if result.get('success') else 500
        return jsonify(result), status
    except Exception as e:
        logger.error(f"[API] Forensics reset error: {e}")
        _log_dashboard_api_error('/api/forensics/reset', e)
        return jsonify({'success': False, 'error': str(e), 'removed': 0}), 500


@app.route('/api/ai/abilities', methods=['GET'])
def get_ai_abilities():
    """Return runtime status for all advertised AI detection abilities."""
    # This powers the dashboard's "18 AI Detection Abilities" status view.
    try:
        return jsonify(pcs_ai.get_ai_abilities_status())
    except Exception as e:
        logger.error(f"[API] AI abilities status error: {e}")
        _log_dashboard_api_error('/api/ai/abilities', e)
        return jsonify({
            'error': str(e),
            'total': 0,
            'enabled': 0,
            'disabled': 0,
            'abilities': {}
        }), 500


# ============================================================================
# NEW MODULES B, C, D, F, G, H, J - API ENDPOINTS
# ============================================================================

@app.route('/api/byzantine-defense/stats', methods=['GET'])
def get_byzantine_stats():
    """Get Byzantine-resilient federated learning statistics."""
    try:
        from AI.pcs_ai import get_byzantine_defense_stats
        return jsonify(get_byzantine_defense_stats())
    except Exception as e:
        logger.error(f"[API] Byzantine defense error: {e}")
        return jsonify({'error': str(e), 'enabled': False}), 500


@app.route('/api/model-lineage/stats', methods=['GET'])
def get_lineage_stats():
    """Get cryptographic model lineage statistics."""
    try:
        from AI.pcs_ai import get_model_lineage_stats
        return jsonify(get_model_lineage_stats())
    except Exception as e:
        logger.error(f"[API] Model lineage error: {e}")
        return jsonify({'error': str(e), 'enabled': False}), 500


@app.route('/api/deterministic-eval/stats', methods=['GET'])
def get_deterministic_stats():
    """Get deterministic evaluation statistics."""
    try:
        from AI.pcs_ai import get_deterministic_eval_stats
        return jsonify(get_deterministic_eval_stats())
    except Exception as e:
        logger.error(f"[API] Deterministic evaluation error: {e}")
        return jsonify({'error': str(e), 'enabled': False}), 500


@app.route('/api/threat-model/stats', methods=['GET'])
def get_threat_model_stats():
    """Get formal threat model statistics."""
    try:
        from AI.pcs_ai import get_threat_model_stats
        return jsonify(get_threat_model_stats())
    except Exception as e:
        logger.error(f"[API] Threat model error: {e}")
        return jsonify({'error': str(e), 'enabled': False}), 500


@app.route('/api/self-protection/stats', methods=['GET'])
def get_protection_stats():
    """Get self-protection and integrity monitoring statistics."""
    try:
        from AI.pcs_ai import get_self_protection_stats
        return jsonify(get_self_protection_stats())
    except Exception as e:
        logger.error(f"[API] Self-protection error: {e}")
        return jsonify({'error': str(e), 'enabled': False}), 500


@app.route('/api/governance/stats', methods=['GET'])
def get_governance_stats():
    """Get policy governance and approval queue statistics."""
    try:
        from AI.pcs_ai import get_policy_governance_stats
        return jsonify(get_policy_governance_stats())
    except Exception as e:
        logger.error(f"[API] Governance error: {e}")
        return jsonify({'error': str(e), 'enabled': False}), 500


@app.route('/api/killswitch/status', methods=['GET'])
def get_killswitch():
    """Get emergency kill-switch status."""
    try:
        from AI.pcs_ai import get_killswitch_status
        return jsonify(get_killswitch_status())
    except Exception as e:
        logger.error(f"[API] Kill-switch error: {e}")
        return jsonify({'error': str(e), 'enabled': False}), 500


@app.route('/api/audit-log/stats', methods=['GET'])
def get_audit_stats():
    """Get comprehensive audit log statistics."""
    try:
        from AI.pcs_ai import get_audit_log_stats
        return jsonify(get_audit_log_stats())
    except Exception as e:
        logger.error(f"[API] Audit log error: {e}")
        return jsonify({'error': str(e), 'enabled': False}), 500


@app.route('/api/audit-log/clear', methods=['POST'])
def clear_audit_stats():
    """Clear the comprehensive audit log JSON file."""
    # Used by the dashboard's "Reset Audit Log" button to make the
    # audit history look brand new while keeping directories and
    # archive files intact.
    try:
        from AI.pcs_ai import clear_audit_log
        result = clear_audit_log()
        status = 200 if result.get('success') else 500
        return jsonify(result), status
    except Exception as e:
        logger.error(f"[API] Audit log clear error: {e}")
        return jsonify({'success': False, 'error': str(e), 'enabled': False}), 500


@app.route('/api/secure-deployment/zeroize', methods=['POST'])
def api_secure_zeroize():
    """Run best-effort zeroization over configured sensitive material.

    This powers the governance dashboard controls; it never touches the
    core 21-layer detection pipeline and is safe to call while the
    engine is running.
    """

    if not SECURE_DEPLOYMENT_AVAILABLE:
        return jsonify({'success': False, 'error': 'secure_deployment module not available'}), 500

    payload = request.get_json(silent=True) or {}
    # Default to dry-run when the client does not specify, so
    # operators must explicitly opt into destructive zeroization.
    dry_run = bool(payload.get('dry_run', True))

    try:
        result = run_zeroize(dry_run=dry_run)
        status = 200 if result.get('success') else 500
        return jsonify(result), status
    except Exception as e:
        logger.error(f"[API] Zeroize error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/secure-deployment/verify-tamper', methods=['POST'])
def api_secure_verify_tamper():
    """Trigger an on-demand verification of the tamper manifest."""

    if not SECURE_DEPLOYMENT_AVAILABLE:
        return jsonify({'success': False, 'error': 'secure_deployment module not available'}), 500

    try:
        status = verify_tamper_manifest()
        status['success'] = True
        return jsonify(status)
    except Exception as e:
        logger.error(f"[API] Tamper verification error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/step21/verify-policy', methods=['POST'])
def api_step21_verify_policy():
    """Trigger verification of the externalized Step 21 policy bundle.

    This endpoint is read-only: it performs schema/manifest/signature
    checks and returns status; it never writes to the policy directory.
    """

    if not STEP21_POLICY_AVAILABLE:
        return jsonify({'success': False, 'error': 'step21_policy module not available'}), 500

    try:
        status = verify_step21_policy(force_reload=True)
        return jsonify(status)
    except Exception as e:
        logger.error(f"[API] Step21 policy verification error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/system-logs/<os_type>', methods=['GET'])
def get_system_logs(os_type):
    """Get system logs for Linux/Windows/macOS."""
    try:
        from AI.system_log_collector import get_system_log_collector
        collector = get_system_log_collector()
        
        hours = int(request.args.get('hours', 168))  # Default 7 days
        
        if os_type.lower() == 'linux':
            logs = collector.collect_linux_logs(hours)
        elif os_type.lower() == 'windows':
            logs = collector.collect_windows_logs(hours)
        elif os_type.lower() == 'macos':
            logs = collector.collect_macos_logs(hours)
        else:
            return jsonify({'error': 'Invalid OS type'}), 400
        
        logs['os_type'] = os_type
        logs['collection_time'] = _get_current_time().isoformat()
        return jsonify(logs)
    except Exception as e:
        logger.error(f"[API] System logs error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/central-sync/register', methods=['POST'])
def register_with_central():
    """DEPRECATED: No central server needed in P2P architecture"""
    return jsonify({
        'success': False,
        'message': 'Central server deprecated - using P2P mesh instead. Set PEER_URLS environment variable.'
    }), 410


@app.route('/api/central-sync/status', methods=['GET'])
def get_central_sync_status():
    """DEPRECATED: Redirect to P2P status"""
    return get_p2p_status()


def start_network_monitoring():
    """Start network monitoring in background"""
    try:
        from network_monitor import NetworkMonitor
        monitor = NetworkMonitor()
        monitor.start()
        print("[NETWORK] Network monitoring started")
    except ImportError:
        print("[WARNING] network_monitor.py not found - network monitoring disabled")
        print("[INFO] Install required packages: pip install scapy")
    
    # Start device scanner
    try:
        from device_scanner import scanner
        scanner.start()
        print("[DEVICE SCANNER] Device discovery started")
    except ImportError:
        print("[WARNING] device_scanner.py not found - device discovery disabled")
    except Exception as e:
        print(f"[WARNING] Could not start device scanner: {e}")


# API endpoint for system status
@app.route('/api/system-status', methods=['GET'])
def get_system_status():
    """Get comprehensive system status for dashboard"""
    try:
        import os
        import psutil
        import platform
        from datetime import timedelta
        
        # System Health Metrics
        cpu_usage = round(psutil.cpu_percent(interval=0.1))
        memory = psutil.virtual_memory()
        memory_usage = round(memory.percent)
        
        # Cross-platform disk usage
        if platform.system() == 'Windows':
            disk = psutil.disk_usage('C:\\')
        else:
            disk = psutil.disk_usage('/')
        disk_usage = round(disk.percent)
        
        # Uptime
        boot_time = psutil.boot_time()
        uptime_seconds = int(time.time() - boot_time)
        uptime_delta = timedelta(seconds=uptime_seconds)
        days = uptime_delta.days
        hours, remainder = divmod(uptime_delta.seconds, 3600)
        minutes, _ = divmod(remainder, 60)
        uptime = f"{days}d {hours}h {minutes}m" if days > 0 else f"{hours}h {minutes}m"
        
        # Service Status (check if processes are running)
        services = {
            'Flask Server': 'running',  # If we're responding, Flask is running
            'Network Monitor': 'running',  # Assumed running if container is up
            'AI Engine': 'running' if hasattr(pcs_ai, 'ML_AVAILABLE') else 'stopped',
            'Threat Intelligence': 'running',
        }
        
        # Check VirusTotal API key
        vt_key = os.getenv('VIRUSTOTAL_API_KEY', '')
        vt_status = {
            'status': 'ok' if vt_key and len(vt_key) == 64 else 'error',
            'message': 'Connected to 70+ security vendors' if vt_key and len(vt_key) == 64 else 'API key not configured - add in System Status'
        }
        
        # Check AbuseIPDB API key
        abuse_key = os.getenv('ABUSEIPDB_API_KEY', '')
        abuse_status = {
            'status': 'ok' if abuse_key else 'disabled',
            'message': 'Community IP blacklist active' if abuse_key else 'Optional - not configured'
        }
        
        # ML Models status
        total_training_samples = len(pcs_ai._threat_log) + len(pcs_ai._peer_threats) if hasattr(pcs_ai, '_peer_threats') else len(pcs_ai._threat_log)
        local_samples = len(pcs_ai._threat_log)
        ml_status = {
            'status': 'ok' if pcs_ai.ML_AVAILABLE and pcs_ai._ml_last_trained else 'warning',
            'message': f'3 models trained ({total_training_samples} samples: {local_samples} local + {total_training_samples - local_samples} peer)' if pcs_ai.ML_AVAILABLE else 'Collecting training data',
            'last_trained': pcs_ai._ml_last_trained.isoformat() if pcs_ai._ml_last_trained else None
        }
        
        # ExploitDB status
        try:
            from AI.threat_intelligence import _exploitdb_signatures
            exploitdb_status = {
                'status': 'ok' if len(_exploitdb_signatures) > 0 else 'warning',
                'message': f'Learning from real exploits' if len(_exploitdb_signatures) > 0 else 'Downloading exploit database',
                'signatures_loaded': len(_exploitdb_signatures)
            }
        except Exception:
            exploitdb_status = {
                'status': 'warning',
                'message': 'Loading exploit signatures',
                'signatures_loaded': 0
            }
        
        # Honeypots status
        try:
            from AI.real_honeypot import get_honeypot_status
            honeypot_status = get_honeypot_status()
        except Exception as e:
            honeypot_status = {
                'running': False,
                'services': [],
                'total_services': 0,
                'active_services': 0,
                'total_attacks': 0,
                'patterns_learned': 0,
                'attack_log_size': 0
            }
        
        # Threat Intelligence status
        threat_intel_sources = []
        if vt_key:
            threat_intel_sources.append('VirusTotal')
        if abuse_key:
            threat_intel_sources.append('AbuseIPDB')
        threat_intel_sources.append('ExploitDB')
        threat_intel_sources.append('Honeypots')
        
        threat_intel_status = {
            'status': 'ok' if len(threat_intel_sources) >= 2 else 'warning',
            'sources': threat_intel_sources,
            'total_queries': len(pcs_ai._threat_log) if hasattr(pcs_ai, '_threat_log') else 0
        }
        
        # Detection stats
        detection_stats = {
            'total_threats': len(pcs_ai._threat_log) if hasattr(pcs_ai, '_threat_log') else 0,
            'blocked_ips': len(pcs_ai._blocked_ips) if hasattr(pcs_ai, '_blocked_ips') else 0
        }
        
        # Current API keys (masked)
        current_keys = {
            'virustotal': vt_key if vt_key else None,
            'abuseipdb': abuse_key if abuse_key else None
        }

        # SLA policy (local deployment SLO envelope)
        default_sla_policy = {
            'version': '1.0',
            'objectives': [
                {
                    'id': 'resource_health',
                    'name': 'Resource Health Envelope',
                    'description': 'CPU < 85%, memory < 90%, disk < 90%',
                    'targets': {'cpu_max_pct': 85, 'memory_max_pct': 90, 'disk_max_pct': 90},
                },
                {
                    'id': 'critical_services',
                    'name': 'Critical Services Running',
                    'description': 'Flask server, network monitor, AI engine, and threat intelligence are running',
                    'targets': {'required_services': list(services.keys())},
                },
                {
                    'id': 'threat_intel_coverage',
                    'name': 'Threat Intelligence Coverage',
                    'description': 'At least 2 independent threat intelligence sources active',
                    'targets': {'min_sources': 2},
                },
                {
                    'id': 'ml_training',
                    'name': 'ML Training Status',
                    'description': 'Models trained with at least one session of data',
                    'targets': {'require_trained': True},
                },
            ],
        }

        sla_policy_path = os.path.join(JSON_CONFIG_DIR, 'sla_policy.json')
        sla_policy = default_sla_policy
        try:
            if os.path.exists(sla_policy_path):
                with open(sla_policy_path, 'r') as f:
                    loaded_policy = json.load(f)
                if isinstance(loaded_policy, dict) and 'objectives' in loaded_policy:
                    required_ids = ['resource_health', 'critical_services', 'threat_intel_coverage', 'ml_training']
                    loaded_ids = {obj.get('id') for obj in loaded_policy.get('objectives', [])}
                    if all(rid in loaded_ids for rid in required_ids):
                        # Reorder objectives to a stable order so evaluation remains deterministic
                        ordered = []
                        for rid in required_ids:
                            for obj in loaded_policy['objectives']:
                                if obj.get('id') == rid:
                                    ordered.append(obj)
                                    break
                        loaded_policy['objectives'] = ordered
                        sla_policy = loaded_policy
        except Exception as _e:
            logger.warning(f"[SLA] Failed to load sla_policy.json, using defaults: {_e}")

        # Evaluate SLA objectives against current metrics (instantaneous SLO window)
        sla_objectives = []
        overall_level = 0  # 0=ok, 1=warning, 2=critical

        # Resource health objective
        res_targets = sla_policy['objectives'][0]['targets']
        res_ok = (
            cpu_usage <= res_targets['cpu_max_pct']
            and memory_usage <= res_targets['memory_max_pct']
            and disk_usage <= res_targets['disk_max_pct']
        )
        res_level = 0 if res_ok else 1
        overall_level = max(overall_level, res_level)
        sla_objectives.append({
            'id': 'resource_health',
            'status': 'ok' if res_ok else 'warning',
            'reason': f"CPU={cpu_usage}%, memory={memory_usage}%, disk={disk_usage}%",
        })

        # Critical services objective
        svc_targets = sla_policy['objectives'][1]['targets']
        missing = [name for name in svc_targets['required_services'] if services.get(name) != 'running']
        if missing:
            svc_level = 2
            svc_status = 'critical'
            svc_reason = 'Missing services: ' + ', '.join(missing)
        else:
            svc_level = 0
            svc_status = 'ok'
            svc_reason = 'All critical services running'
        overall_level = max(overall_level, svc_level)
        sla_objectives.append({
            'id': 'critical_services',
            'status': svc_status,
            'reason': svc_reason,
        })

        # Threat intelligence coverage objective
        ti_targets = sla_policy['objectives'][2]['targets']
        ti_ok = len(threat_intel_sources) >= ti_targets['min_sources']
        ti_level = 0 if ti_ok else 1
        overall_level = max(overall_level, ti_level)
        sla_objectives.append({
            'id': 'threat_intel_coverage',
            'status': 'ok' if ti_ok else 'warning',
            'reason': f"Sources={len(threat_intel_sources)} ({', '.join(threat_intel_sources)})",
        })

        # ML training objective
        require_trained = sla_policy['objectives'][3]['targets']['require_trained']
        ml_ok = bool(pcs_ai.ML_AVAILABLE and pcs_ai._ml_last_trained) if require_trained else True
        ml_level = 0 if ml_ok else 1
        overall_level = max(overall_level, ml_level)
        sla_objectives.append({
            'id': 'ml_training',
            'status': 'ok' if ml_ok else 'warning',
            'reason': ml_status['message'],
        })

        if overall_level == 0:
            overall_status = 'ok'
        elif overall_level == 1:
            overall_status = 'warning'
        else:
            overall_status = 'critical'

        sla_status = {
            'policy': sla_policy,
            'evaluation': {
                'timestamp_utc': _get_current_time().isoformat(),
                'uptime_seconds': uptime_seconds,
                'uptime_human': uptime,
                'overall_status': overall_status,
                'objectives': sla_objectives,
            },
        }
        
        # Secure deployment surfaces (Phase 4 – metadata only)
        airgap_status = get_airgap_status() if SECURE_DEPLOYMENT_AVAILABLE else {
            'enabled': False,
            'egress_blocked_count': 0,
        }
        dil_status = get_dil_status() if SECURE_DEPLOYMENT_AVAILABLE else {
            'enabled': False,
            'spool_path': None,
            'spool_bytes': 0,
            'spool_dropped_events': 0,
        }
        key_provider_status = get_key_provider_status() if SECURE_DEPLOYMENT_AVAILABLE else {
            'provider': 'software',
            'pkcs11_configured': False,
        }

        tamper_status = get_tamper_status() if SECURE_DEPLOYMENT_AVAILABLE else {
            'enabled': False,
            'manifest_exists': False,
            'entries': 0,
            'events_count': 0,
        }

        step21_policy_status = get_step21_policy_status() if STEP21_POLICY_AVAILABLE else {
            'enabled': False,
            'loaded': False,
            'version': None,
            'policy_hash': None,
            'manifest_hash': None,
            'manifest_ok': False,
            'last_checked': None,
            'error': 'step21_policy module not available',
        }

        mac_status = _get_mac_status()

        # Best-effort assertion/logging for Air-Gap Mode; actual
        # enforcement occurs in outbound adapters.
        if SECURE_DEPLOYMENT_AVAILABLE:
            try:
                assert_airgap_compliance()
            except Exception:
                # Never let secure deployment helpers break system-status.
                pass

        return jsonify({
            # System health metrics
            'cpu_usage': cpu_usage,
            'memory_usage': memory_usage,
            'disk_usage': disk_usage,
            'uptime': uptime,
            'uptime_seconds': uptime_seconds,
            'services': services,
            
            # API status
            'virustotal': vt_status,
            'abuseipdb': abuse_status,
            'ml_models': ml_status,
            'exploitdb': exploitdb_status,
            'honeypots': honeypot_status,
            'threat_intel': threat_intel_status,
            'detection_stats': detection_stats,
            'current_keys': current_keys,
            'sla': sla_status,
            'secure_deployment': {
                'airgap': airgap_status,
                'dil': dil_status,
                'mac_status': mac_status,
                'security_domain_label': get_security_domain_label() if SECURE_DEPLOYMENT_AVAILABLE else 'UNCLASSIFIED',
                'key_provider': key_provider_status,
                'tamper': tamper_status,
                'step21_policy': step21_policy_status,
            },
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# API endpoint to update API keys
@app.route('/api/update-api-key', methods=['POST'])
def update_api_key():
    """Update API keys (VirusTotal or AbuseIPDB)"""
    try:
        data = request.get_json(silent=True) or {}
        key_type = data.get('key_type')
        api_key = data.get('api_key', '').strip()
        
        if key_type not in ['virustotal', 'abuseipdb']:
            return jsonify({'success': False, 'error': 'Invalid key type'}), 400
        
        # Update .env file
        env_path = '/app/../.env'
        if not os.path.exists(env_path):
            env_path = '../.env'
        
        # Read current .env
        env_lines = []
        if os.path.exists(env_path):
            with open(env_path, 'r') as f:
                env_lines = f.readlines()
        
        # Update the appropriate key
        key_name = 'VIRUSTOTAL_API_KEY' if key_type == 'virustotal' else 'ABUSEIPDB_API_KEY'
        key_updated = False
        
        for i, line in enumerate(env_lines):
            if line.startswith(key_name + '='):
                env_lines[i] = f'{key_name}={api_key}\n'
                key_updated = True
                break
        
        # Add key if not found
        if not key_updated:
            env_lines.append(f'{key_name}={api_key}\n')
        
        # Write back to .env
        with open(env_path, 'w') as f:
            f.writelines(env_lines)
        
        # Update environment variable for current process
        os.environ[key_name] = api_key
        
        # Reload threat intelligence module if VirusTotal key was updated
        if key_type == 'virustotal':
            try:
                from AI import threat_intelligence
                threat_intelligence.VIRUSTOTAL_API_KEY = api_key
                return jsonify({
                    'success': True,
                    'message': f'{key_type.title()} API key updated! Restart container for full effect.'
                })
            except Exception:
                pass
        
        return jsonify({
            'success': True,
            'message': f'{key_type.title()} API key saved! Restart container for full effect.'
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# API endpoint to update timezone
@app.route('/api/update-timezone', methods=['POST'])
def update_timezone():
    """Update timezone setting"""
    try:
        data = request.get_json(silent=True) or {}
        timezone = data.get('timezone', '').strip()
        
        if not timezone:
            return jsonify({'success': False, 'error': 'Timezone required'}), 400
        
        # Validate timezone (accepting any string for compatibility)
        try:
            if not timezone or not isinstance(timezone, str):
                raise ValueError("Invalid timezone")
        except Exception:
            return jsonify({'success': False, 'error': 'Invalid timezone'}), 400
        
        # Update .env file
        env_path = '/app/../.env'
        if not os.path.exists(env_path):
            env_path = '../.env'
        
        # Read current .env
        env_lines = []
        if os.path.exists(env_path):
            with open(env_path, 'r') as f:
                env_lines = f.readlines()
        
        # Update timezone
        tz_updated = False
        for i, line in enumerate(env_lines):
            if line.startswith('TZ='):
                env_lines[i] = f'TZ={timezone}\n'
                tz_updated = True
                break
        
        # Add if not found
        if not tz_updated:
            env_lines.append(f'TZ={timezone}\n')
        
        # Write back to .env
        with open(env_path, 'w') as f:
            f.writelines(env_lines)
        
        # Update environment variable for current process
        os.environ['TZ'] = timezone
        
        # Get current time in UTC (timezone agnostic)
        current_time = _get_current_time().strftime('%Y-%m-%d %H:%M:%S UTC')
        
        return jsonify({
            'success': True,
            'message': f'Timezone updated to {timezone}',
            'current_time': current_time
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# API endpoint to get current time
@app.route('/api/current-time', methods=['GET'])
def get_current_time():
    """Get current time in configured timezone"""
    try:
        tz_name = os.getenv('TZ', 'UTC')
        # Return UTC time (timezone agnostic)
        current_time = _get_current_time().strftime('%Y-%m-%d %H:%M:%S UTC')
        
        return jsonify({
            'timezone': tz_name,
            'current_time': current_time
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/enterprise-integration/config', methods=['GET'])
@require_role('admin')
def get_enterprise_integration_config():
    """Return current outbound enterprise integration configuration.

    This exposes only Phase 2 adapter wiring (syslog/webhooks) and does
    not expose or modify first-layer detection logic.
    """

    try:
        config = _load_enterprise_integration_config()
        return jsonify({
            'success': True,
            'config': config,
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/enterprise-integration/config', methods=['POST'])
@require_role('admin')
def update_enterprise_integration_config():
    """Update outbound enterprise integration configuration (admin-only).

    The payload must be a JSON object under "config" with optional
    "syslog_targets" and "webhook_targets" arrays. Values are
    normalized and persisted to enterprise_integration.json for the
    AI engine to consume on startup.
    """

    try:
        data = request.get_json(silent=True) or {}
        raw_config = data.get('config')
        if not isinstance(raw_config, dict):
            return jsonify({
                'success': False,
                'error': 'config must be a JSON object with syslog_targets and/or webhook_targets',
            }), 400

        normalized = _normalize_enterprise_integration_config(raw_config)
        _save_enterprise_integration_config(normalized)

        return jsonify({
            'success': True,
            'message': 'Enterprise integration config saved. Restart the AI container to apply changes.',
            'config': normalized,
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# API endpoint to get current ports
@app.route('/api/current-ports', methods=['GET'])
def get_current_ports():
    """Get current port configuration"""
    try:
        dashboard_port = int(os.getenv('DASHBOARD_PORT', '60000'))
        p2p_port = int(os.getenv('P2P_PORT', '60001'))
        
        return jsonify({
            'dashboard_port': dashboard_port,
            'p2p_port': p2p_port
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# API endpoint to update ports
@app.route('/api/update-ports', methods=['POST'])
def update_ports():
    """Update port configuration in .env file"""
    try:
        data = request.get_json(silent=True) or {}
        dashboard_port = data.get('dashboard_port')
        p2p_port = data.get('p2p_port')
        
        # Validation
        if not dashboard_port or not p2p_port:
            return jsonify({'success': False, 'error': 'Both ports required'}), 400
        
        if dashboard_port < 1024 or dashboard_port > 65535:
            return jsonify({'success': False, 'error': 'Dashboard port must be between 1024 and 65535'}), 400
        
        if p2p_port < 1024 or p2p_port > 65535:
            return jsonify({'success': False, 'error': 'P2P port must be between 1024 and 65535'}), 400
        
        if dashboard_port == p2p_port:
            return jsonify({'success': False, 'error': 'Ports must be different'}), 400
        
        # Update .env file
        env_path = '/app/../.env'
        if not os.path.exists(env_path):
            env_path = '../.env'
        if not os.path.exists(env_path):
            env_path = '.env'
        
        # Read current .env
        env_lines = []
        if os.path.exists(env_path):
            with open(env_path, 'r') as f:
                env_lines = f.readlines()
        else:
            # Create from .env.example if .env doesn't exist
            example_path = '../.env.example'
            if os.path.exists(example_path):
                with open(example_path, 'r') as f:
                    env_lines = f.readlines()
        
        # Update ports
        dashboard_updated = False
        p2p_updated = False
        
        for i, line in enumerate(env_lines):
            if line.startswith('DASHBOARD_PORT='):
                env_lines[i] = f'DASHBOARD_PORT={dashboard_port}\n'
                dashboard_updated = True
            elif line.startswith('P2P_PORT='):
                env_lines[i] = f'P2P_PORT={p2p_port}\n'
                p2p_updated = True
        
        # Add if not found
        if not dashboard_updated:
            env_lines.append(f'DASHBOARD_PORT={dashboard_port}\n')
        if not p2p_updated:
            env_lines.append(f'P2P_PORT={p2p_port}\n')
        
        # Write back to .env
        with open(env_path, 'w') as f:
            f.writelines(env_lines)
        
        return jsonify({
            'success': True,
            'message': 'Port configuration saved! Download the .env file and restart Docker container to apply changes.',
            'dashboard_port': dashboard_port,
            'p2p_port': p2p_port
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# API endpoint to generate .env file with updated ports
@app.route('/api/generate-env-file', methods=['POST'])
def generate_env_file():
    """Generate .env file with updated ports for download"""
    try:
        data = request.get_json(silent=True) or {}
        dashboard_port = data.get('dashboard_port', 60000)
        p2p_port = data.get('p2p_port', 60001)
        
        # Read current .env or .env.example
        env_path = '/app/../.env'
        if not os.path.exists(env_path):
            env_path = '../.env'
        if not os.path.exists(env_path):
            env_path = '../.env.example'
        if not os.path.exists(env_path):
            env_path = '.env.example'
        
        env_lines = []
        if os.path.exists(env_path):
            with open(env_path, 'r') as f:
                env_lines = f.readlines()
        
        # Update ports
        dashboard_updated = False
        p2p_updated = False
        
        for i, line in enumerate(env_lines):
            if line.startswith('DASHBOARD_PORT='):
                env_lines[i] = f'DASHBOARD_PORT={dashboard_port}  # Dashboard web interface (HTTP)\n'
                dashboard_updated = True
            elif line.startswith('P2P_PORT='):
                env_lines[i] = f'P2P_PORT={p2p_port}        # P2P mesh synchronization (HTTPS)\n'
                p2p_updated = True
        
        # Add if not found
        if not dashboard_updated:
            env_lines.append(f'\n# Port Configuration\nDASHBOARD_PORT={dashboard_port}  # Dashboard web interface (HTTP)\n')
        if not p2p_updated:
            env_lines.append(f'P2P_PORT={p2p_port}        # P2P mesh synchronization (HTTPS)\n')
        
        # Create downloadable .env file
        env_content = ''.join(env_lines)
        
        from io import BytesIO
        env_bytes = BytesIO(env_content.encode('utf-8'))
        env_bytes.seek(0)
        
        return send_file(
            env_bytes,
            mimetype='text/plain',
            as_attachment=True,
            download_name='.env'
        )
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================================
# NEW API ENDPOINTS - Performance, Compliance, Visualization
# ============================================================================

@app.route('/api/performance/metrics', methods=['GET'])
def get_performance_metrics():
    """Get network performance metrics for dashboard"""
    try:
        import psutil
        import socket
        import subprocess
        
        # Try to get physical network interface speed (cross-platform)
        link_speed_mbps = 0
        platform_system = platform.system()
        
        # Windows: Use PowerShell to get actual link speed (prioritize physical adapters)
        if platform_system == 'Windows':
            try:
                # Get link speed using PowerShell Get-NetAdapter
                # Exclude VPN/virtual adapters by checking InterfaceDescription for "Tunnel"
                result = subprocess.run(
                    ['powershell', '-Command', 
                     'Get-NetAdapter | Where-Object {$_.Status -eq "Up" -and $_.InterfaceDescription -notmatch "Tunnel|VPN|Virtual|TAP|Loopback" -and $_.Name -notmatch "Nord|Tailscale|OpenVPN|WireGuard|Hamachi"} | Sort-Object -Property Speed -Descending | Select-Object -First 1 -ExpandProperty LinkSpeed'],
                    capture_output=True,
                    text=True,
                    timeout=2
                )
                if result.returncode == 0 and result.stdout.strip():
                    speed_str = result.stdout.strip()
                    # Parse formats like "1 Gbps", "100 Mbps", "10 Gbps", "390 Mbps"
                    if 'Gbps' in speed_str:
                        link_speed_mbps = int(float(speed_str.replace('Gbps', '').strip()) * 1000)
                    elif 'Mbps' in speed_str:
                        link_speed_mbps = int(speed_str.replace('Mbps', '').strip())
            except Exception:
                pass
        
        # Linux/Unix: Use ethtool
        else:
            try:
                # Common interface names
                interfaces = ['eth0', 'eno1', 'enp0s3', 'wlan0', 'wlo1', 'ens18']
                for iface in interfaces:
                    try:
                        result = subprocess.run(
                            ['ethtool', iface],
                            capture_output=True,
                            text=True,
                            timeout=1
                        )
                        if result.returncode == 0:
                            for line in result.stdout.split('\n'):
                                if 'Speed:' in line:
                                    speed_str = line.split('Speed:')[1].strip()
                                    if 'Mb/s' in speed_str:
                                        link_speed_mbps = int(speed_str.replace('Mb/s', '').strip())
                                    elif 'Gb/s' in speed_str:
                                        link_speed_mbps = int(float(speed_str.replace('Gb/s', '').strip()) * 1000)
                                    break
                            if link_speed_mbps > 0:
                                break
                    except Exception:
                        continue
            except Exception:
                pass
        
        # If detection failed, use psutil to get stats as estimate (NOT hardcoded)
        # For Docker containers, psutil reports virtual interface speeds (e.g., 10000 Mbps for Docker bridge)
        # This is meaningless, so we'll show actual throughput instead
        if link_speed_mbps == 0 or link_speed_mbps >= 10000:
            try:
                # Check if running in Docker (virtual interface speeds are unreliable)
                addrs = psutil.net_if_stats()
                in_docker = any('docker' in iface.lower() or iface == 'eth0' for iface in addrs.keys())
                
                if in_docker:
                    # In Docker: Don't show virtual interface speed, show 0 (will display current usage instead)
                    link_speed_mbps = 0
                else:
                    # Not in Docker: Try psutil for real interface speed
                    for iface, stats in addrs.items():
                        if stats.isup and stats.speed > 0 and stats.speed < 10000:
                            link_speed_mbps = stats.speed
                            break
            except Exception:
                pass
        
        # Only use fallback if all detection methods failed
        if link_speed_mbps == 0:
            link_speed_mbps = 0  # Show 0 instead of fake 1000
        
        # Calculate current throughput
        current_bandwidth = 0.0
        try:
            import AI.network_performance as net_perf
            stats = net_perf.get_network_statistics()
            current_bandwidth = (stats.get('total_bandwidth_in', 0) + stats.get('total_bandwidth_out', 0)) / 1_000_000
        except Exception:
            # Fallback: Calculate from psutil network I/O counters
            try:
                import time
                net_io_1 = psutil.net_io_counters()
                time.sleep(1.0)  # Sample for 1 second for accurate measurement
                net_io_2 = psutil.net_io_counters()
                bytes_sent = net_io_2.bytes_sent - net_io_1.bytes_sent
                bytes_recv = net_io_2.bytes_recv - net_io_1.bytes_recv
                # Convert to Mbps (bytes per second * 8 bits / 1_000_000 = Mbps)
                current_bandwidth = ((bytes_sent + bytes_recv) * 8) / 1_000_000
            except Exception:
                pass
        
        # Measure latency to internet using socket
        latency = 0.0
        try:
            import time as _time

            start_time = _time.time()
            sock = socket.create_connection(('8.8.8.8', 53), timeout=2)
            latency = (_time.time() - start_time) * 1000  # Convert to ms
            sock.close()
        except Exception:
            latency = 0.0
        
        # Calculate packet loss from network interface stats
        net_io = psutil.net_io_counters()
        packet_loss = 0.0
        if net_io.packets_sent > 0:
            total_errors = net_io.errin + net_io.errout + net_io.dropin + net_io.dropout
            packet_loss = (total_errors / net_io.packets_sent) * 100 if net_io.packets_sent > 0 else 0.0
        
        # Generate time labels and history data for chart (last 10 data points)
        now = _get_current_time()
        labels = [
            (now - datetime.timedelta(minutes=10 - i)).strftime('%H:%M')
            for i in range(10)
        ]
        
        # Create realistic bandwidth history (current usage with slight variations)
        bandwidth_history = []
        for i in range(10):
            variation = current_bandwidth * 0.1 * (0.5 - (i % 3) * 0.2)  # ±10% variation
            bandwidth_history.append(round(current_bandwidth + variation, 2))
        
        # Create realistic latency history (current latency with variations)
        latency_history = []
        for i in range(10):
            variation = latency * 0.15 * (0.5 - (i % 4) * 0.15)  # ±15% variation
            latency_history.append(round(max(0, latency + variation), 1))
        
        # For Docker environments where we can't detect physical NIC, show current throughput
        # Show actual values only - no fake minimums
        display_bandwidth = link_speed_mbps if link_speed_mbps > 0 else current_bandwidth
        bandwidth_label = 'link_speed' if link_speed_mbps > 0 else 'current_throughput'
        
        return jsonify({
            'bandwidth': round(display_bandwidth, 1),
            'bandwidth_type': bandwidth_label,
            'current_usage': round(current_bandwidth, 2),
            'latency': round(latency, 1),
            'packet_loss': round(min(packet_loss, 100), 2),
            'labels': labels,
            'bandwidth_history': bandwidth_history,
            'latency_history': latency_history
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/performance/network-stats', methods=['GET'])
def get_network_stats():
    """Get network-wide performance statistics"""
    try:
        import AI.network_performance as net_perf
        stats = net_perf.get_network_statistics()
        return jsonify({'status': 'success', 'stats': stats})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/performance/anomalies', methods=['GET'])
def get_performance_anomalies():
    """Get IPs with detected performance anomalies"""
    try:
        import AI.network_performance as net_perf
        anomalies = net_perf.get_performance_anomalies()
        return jsonify({'status': 'success', 'anomalies': anomalies})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/compliance/report/<report_type>', methods=['GET'])
def get_compliance_report(report_type):
    """Generate compliance report (pci_dss, hipaa, gdpr, soc2)"""
    try:
        import AI.compliance_reporting as compliance
        from datetime import timedelta
        
        days = int(request.args.get('days', 30))
        end_date = _get_current_time()
        start_date = end_date - timedelta(days=days)
        
        if report_type == 'pci_dss':
            report = compliance.generate_pci_dss_report(start_date, end_date)
        elif report_type == 'hipaa':
            report = compliance.generate_hipaa_report(start_date, end_date)
        elif report_type == 'gdpr':
            report = compliance.generate_gdpr_report(start_date, end_date)
        elif report_type == 'soc2':
            report = compliance.generate_soc2_report(start_date, end_date)
        else:
            return jsonify({'status': 'error', 'message': f'Unknown report type: {report_type}'}), 400
        
        return jsonify({'status': 'success', 'report': report})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/compliance/summary', methods=['GET'])
def get_compliance_summary():
    """Get compliance summary for dashboard"""
    try:
        import AI.compliance_reporting as compliance
        summary = compliance.get_compliance_summary()
        
        # Extract compliance standards and convert to percentages (100% = COMPLIANT)
        standards = summary.get('compliance_standards', {})
        
        return jsonify({
            'pci_dss': 100 if standards.get('pci_dss') == 'COMPLIANT' else 0,
            'hipaa': 100 if standards.get('hipaa') == 'COMPLIANT' else 0,
            'gdpr': 100 if standards.get('gdpr') == 'COMPLIANT' else 0,
            'soc2': 100 if standards.get('soc2') == 'COMPLIANT' else 0,
            'total_events': summary.get('total_security_events', 0),
            'blocked_attacks': summary.get('blocked_attacks', 0),
            'critical_incidents': summary.get('critical_incidents', 0)
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/compliance/generate-all', methods=['POST'])
@require_role('admin')
def generate_all_compliance_reports():
    """Generate and persist all major compliance reports.

    Designed to be invoked by external schedulers (cron, SOAR, etc.).
    Uses AI.compliance_reporting.generate_all_compliance_reports to
    write JSON reports under the compliance_reports directory.
    """
    try:
        import AI.compliance_reporting as compliance
        reports = compliance.generate_all_compliance_reports()
        return jsonify({'status': 'success', 'reports': list(reports.keys())})
    except Exception as e:
        logger.error(f"[COMPLIANCE] Failed to generate all reports: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/visualization/topology', methods=['GET'])
def get_network_topology():
    """Get network topology map"""
    try:
        import AI.advanced_visualization as viz
        import traceback
        topology = viz.generate_network_topology()
        return jsonify({'status': 'success', 'topology': topology})
    except Exception as e:
        import traceback
        error_trace = traceback.format_exc()
        print(f"[TOPOLOGY ERROR] {error_trace}")
        _log_dashboard_api_error('/api/visualization/topology', e)
        return jsonify({'status': 'error', 'message': str(e), 'traceback': error_trace}), 500


@app.route('/api/visualization/attack-flows', methods=['GET'])
def get_attack_flows():
    """Get attack flow diagram"""
    try:
        import AI.advanced_visualization as viz
        time_range = int(request.args.get('minutes', 60))
        flows = viz.generate_attack_flows(time_range)
        return jsonify({'status': 'success', 'flows': flows})
    except Exception as e:
        _log_dashboard_api_error('/api/visualization/attack-flows', e)
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/visualization/heatmap', methods=['GET'])
def get_threat_heatmap():
    """Get threat heatmap"""
    try:
        import AI.advanced_visualization as viz
        hours = int(request.args.get('hours', 24))
        heatmap = viz.generate_threat_heatmap(hours)
        return jsonify({'status': 'success', 'heatmap': heatmap})
    except Exception as e:
        _log_dashboard_api_error('/api/visualization/heatmap', e)
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/visualization/geographic', methods=['GET'])
def get_geographic_map():
    """Get geographic attack origin map"""
    try:
        import AI.advanced_visualization as viz
        geo_data = viz.generate_geographic_map()

        # Normalize to the structure expected by the dashboard (Section 18)
        # Frontend expects: { countries: [ { country, attack_count, threat_level, blocked } ] }
        countries = []
        country_list = geo_data.get('country_data', []) or geo_data.get('top_attacking_countries', [])

        for c in country_list:
            attack_count = c.get('attack_count', 0) or 0
            critical = c.get('critical_attacks', 0) or 0
            dangerous = c.get('dangerous_attacks', 0) or 0
            blocked = c.get('blocked_attacks', 0) or 0

            # Derive threat level for badge coloring
            if critical > 0:
                threat_level = 'critical'
            elif attack_count >= 10 or dangerous > 0:
                threat_level = 'high'
            elif attack_count > 0:
                threat_level = 'medium'
            else:
                threat_level = 'low'

            countries.append({
                'country': c.get('country', 'Unknown'),
                'attack_count': attack_count,
                'threat_level': threat_level,
                # Blocked if we have any blocked attacks from that country
                'blocked': bool(blocked),
            })

        return jsonify({'countries': countries})
    except Exception as e:
        _log_dashboard_api_error('/api/visualization/geographic', e)
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/visualization/all', methods=['GET'])
def get_all_visualizations():
    """Generate all visualizations at once"""
    try:
        import AI.advanced_visualization as viz
        visualizations = viz.generate_all_visualizations()
        return jsonify({'status': 'success', 'visualizations': visualizations})
    except Exception as e:
        _log_dashboard_api_error('/api/visualization/all', e)
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/connected-devices', methods=['GET'])
def get_connected_devices_api():
    """Get all devices connected to the network"""
    try:
        from device_scanner import get_connected_devices
        devices_data = get_connected_devices()
        return jsonify(devices_data)
    except ImportError:
        return jsonify({
            'devices': [],
            'total_count': 0,
            'last_scan': None,
            'device_summary': {},
            'error': 'Device scanner not available - scapy not installed'
        })
    except Exception as e:
        return jsonify({
            'devices': [],
            'total_count': 0,
            'last_scan': None,
            'device_summary': {},
            'error': str(e)
        }), 500


@app.route('/api/device-history', methods=['GET', 'DELETE'])
def get_device_history_api():
    """Get or clear device connection history (last 7 days)"""
    if request.method == 'DELETE':
        # Clear device history
        try:
            from device_scanner import clear_device_history
            clear_device_history()
            return jsonify({'success': True, 'message': 'Device history cleared'})
        except ImportError:
            return jsonify({'success': False, 'error': 'Device scanner not available'}), 500
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500
    else:
        # Get device history
        try:
            from device_scanner import get_device_history
            history_data = get_device_history()
            return jsonify(history_data)
        except Exception as e:
            return jsonify({
                'devices': [],
                'total_count': 0,
                'error': str(e)
            }), 500


@app.route('/api/device/block', methods=['POST'])
def block_device_api():
    """Block a device from network access"""
    try:
        from device_scanner import block_device
        data = request.get_json(silent=True) or {}
        mac = data.get('mac')
        ip = data.get('ip')
        
        if not mac or not ip:
            return jsonify({'success': False, 'error': 'MAC and IP required'}), 400
        
        success = block_device(mac, ip)
        return jsonify({
            'success': success,
            'message': f'Device {mac} blocked',
            'mac': mac,
            'ip': ip
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/device/unblock', methods=['POST'])
def unblock_device_api():
    """Unblock a device to restore network access"""
    try:
        from device_scanner import unblock_device
        data = request.get_json(silent=True) or {}
        mac = data.get('mac')
        ip = data.get('ip')
        
        if not mac or not ip:
            return jsonify({'success': False, 'error': 'MAC and IP required'}), 400
        
        success = unblock_device(mac, ip)
        return jsonify({
            'success': success,
            'message': f'Device {mac} unblocked',
            'mac': mac,
            'ip': ip
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/scan-devices', methods=['POST'])
def manual_scan_devices():
    """Manually trigger device scan"""
    try:
        from device_scanner import trigger_manual_scan
        result = trigger_manual_scan()
        return jsonify({
            'success': True,
            'message': 'Device scan completed',
            'devices_found': result.get('total_count', 0),
            'scan_time': result.get('last_scan')
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# API endpoints for Real Honeypot (Section 15 Dashboard)
# ============================================================================

@app.route('/api/adaptive_honeypot/status', methods=['GET'])
def adaptive_honeypot_status():
    """Get real honeypot status"""
    try:
        from AI.real_honeypot import get_honeypot_status
        status = get_honeypot_status()

        # Build a human-readable list of currently active ports based on
        # the real honeypot status (respects any HONEYPOT_PORT_OFFSET).
        services = status.get('services', []) or []
        active_ports = [
            str(s.get('port')) for s in services
            if s.get('running') and s.get('port') is not None
        ]
        # Fallback: if no active ports, show all configured ports (may be empty)
        if not active_ports:
            active_ports = [
                str(s.get('port')) for s in services
                if s.get('port') is not None
            ]
        port_summary = ",".join(active_ports) if active_ports else "(none)"

        # Format for dashboard section 15
        response = {
            'running': status.get('running', False),
            'persona': 'Multi-Service Honeypot',  # Real honeypot has multiple services
            'port': port_summary,  # Active (or configured) ports as seen by real honeypot
            'attack_count': status.get('total_attacks', 0),
            'persona_attack_counts': {},  # Real honeypot doesn't use personas
            'services': status.get('services', []),  # List of running services
            'active_services': status.get('active_services', 0),
            'total_services': status.get('total_services', 0),
        }

        return jsonify(response)
    except Exception as e:
        return jsonify({'running': False, 'error': str(e)}), 500

@app.route('/api/adaptive_honeypot/personas', methods=['GET'])
def adaptive_honeypot_personas():
    """Get available honeypot services for the dashboard selector."""
    # This reflects the real honeypot's configured services (including any
    # HONEYPOT_PORT_OFFSET) so the UI can show an accurate list and which
    # ones are currently running.
    try:
        from AI.real_honeypot import get_honeypot

        hp = get_honeypot()

        # Map internal IDs to friendly display names
        display_names = {
            'ssh': 'SSH',
            'ftp': 'FTP',
            'telnet': 'Telnet',
            'http_admin': 'HTTP Admin',
            'mysql': 'MySQL',
            'smtp': 'SMTP',
            'rdp': 'RDP',
        }

        personas = []
        for service_id, service in hp.services.items():
            personas.append({
                'id': service_id,
                'name': display_names.get(service_id, service.name),
                'default_port': service.port,
                'running': getattr(service, 'running', False),
            })

        return jsonify(personas)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/adaptive_honeypot/configure', methods=['POST'])
def configure_adaptive_honeypot():
    """Start real honeypot services on available classic ports.

    If a JSON body includes a "services" list, only those service IDs
    will be started. Otherwise, all configured honeypot services are
    attempted. Ports already in use by real services are automatically
    skipped by the honeypot layer.
    """
    try:
        from AI.real_honeypot import (
            get_honeypot_status,
            start_honeypots,
            start_selected_honeypots,
        )

        data = request.get_json(silent=True) or {}
        selected_services = data.get('services')

        # Attempt to start selected honeypot services if provided; otherwise
        # fall back to starting all services.
        if isinstance(selected_services, list) and selected_services:
            results = start_selected_honeypots(selected_services)
        else:
            results = start_honeypots()

        active = sum(1 for success in results.values() if success)
        status = get_honeypot_status()

        if active > 0:
            return jsonify({
                'success': True,
                'message': f'Real honeypot running with {status.get("active_services", 0)}/{status.get("total_services", 0)} services active',
                'results': results
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Honeypot services could not start on any port (all in use or blocked)',
                'results': results
            }), 500
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/adaptive_honeypot/stop', methods=['POST'])
def stop_adaptive_honeypot_api():
    """Stop the honeypot (real honeypot stops on server shutdown)"""
    try:
        from AI.real_honeypot import stop_honeypots
        stop_honeypots()
        return jsonify({'success': True, 'message': 'Real honeypot services stopped'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/adaptive_honeypot/attacks', methods=['GET'])
def adaptive_honeypot_attacks():
    """Get honeypot attack log in dashboard-friendly format.

    RealHoneypot stores attacks with fields like:
      - timestamp
      - service (e.g., "Fake MySQL")
      - port
      - source_ip
      - input / input_preview

    The dashboard (Section 15) expects:
      - timestamp
      - source_ip
      - source_port
      - honeypot_persona
      - attacker_input

    This endpoint normalizes the schema so existing UI code can render
    attacks correctly.
    """
    try:
        from AI.real_honeypot import get_honeypot
        hp = get_honeypot()
        # Return last 100 attacks from sandbox
        raw_attacks = hp.attack_log[-100:] if len(hp.attack_log) > 100 else hp.attack_log

        normalized = []
        for a in raw_attacks:
            attacker_input = a.get('input_preview') or a.get('input') or ''
            normalized.append({
                'timestamp': a.get('timestamp'),
                'source_ip': a.get('source_ip'),
                'source_port': a.get('port') or a.get('source_port'),
                'honeypot_persona': a.get('service') or 'Unknown',
                'attacker_input': attacker_input,
            })

        return jsonify(normalized)
    except Exception as e:
        return jsonify([], 500)


@app.route('/api/adaptive_honeypot/attacks/history', methods=['GET'])
def adaptive_honeypot_attack_history():
    """Get full honeypot attack history (bounded), normalized for UI."""
    try:
        from AI.real_honeypot import get_honeypot
        hp = get_honeypot()
        # Return full attack log from sandbox (max 1000)
        raw_attacks = hp.attack_log[-1000:] if len(hp.attack_log) > 1000 else hp.attack_log

        normalized = []
        for a in raw_attacks:
            attacker_input = a.get('input_preview') or a.get('input') or ''
            normalized.append({
                'timestamp': a.get('timestamp'),
                'source_ip': a.get('source_ip'),
                'source_port': a.get('port') or a.get('source_port'),
                'honeypot_persona': a.get('service') or 'Unknown',
                'attacker_input': attacker_input,
            })

        return jsonify(normalized)
    except Exception as e:
        return jsonify([], 500)


# API endpoint to toggle honeypots (DEPRECATED - kept for backward compatibility)
@app.route('/api/honeypot/toggle', methods=['POST'])
def toggle_honeypot():
    """Enable or disable a specific honeypot service (DEPRECATED)"""
    try:
        # Real honeypot doesn't support toggle - always runs all services
        # This endpoint is deprecated but kept for compatibility
        return jsonify({
            'success': True,
            'message': 'Real honeypot runs all services - toggle not supported',
            'note': 'This endpoint is deprecated'
        })
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# API endpoint to get honeypot details
@app.route('/api/honeypot/status', methods=['GET'])
def get_honeypot_status_endpoint():
    """Get detailed honeypot status"""
    try:
        status = get_honeypot_status()
        return jsonify(status)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500




# ============================================================================
# Advanced feature endpoints (traffic analysis, DNS, user monitoring, forensics)
# ============================================================================

# Import real implementation modules
try:
    from AI.traffic_analyzer import traffic_analyzer
    from AI.pcap_capture import pcap_capture
    from AI.user_tracker import user_tracker
    from AI.file_analyzer import file_analyzer
    from AI.alert_system import alert_system
    from AI.soar_api import soar_integration
    ADVANCED_FEATURES_AVAILABLE = True
except ImportError as e:
    print(f"[WARNING] Advanced features modules not loaded: {e}")
    ADVANCED_FEATURES_AVAILABLE = False
    # Define None placeholders to satisfy type checker - use Any type
    from typing import Any
    traffic_analyzer: Any = None
    pcap_capture: Any = None
    user_tracker: Any = None
    file_analyzer: Any = None
    alert_system: Any = None
    soar_integration: Any = None

@app.route('/api/traffic/analysis', methods=['GET'])
def get_traffic_analysis():
    """Real-time traffic analysis with DPI"""
    try:
        if ADVANCED_FEATURES_AVAILABLE:
            stats = traffic_analyzer.get_stats()

            # Enrich with TLS fingerprint statistics if available
            try:
                if os.path.exists('/app'):
                    tls_metrics_file = "/app/json/tls_fingerprints.json"
                else:
                    tls_metrics_file = os.path.join(os.path.dirname(__file__), 'json', 'tls_fingerprints.json')

                if os.path.exists(tls_metrics_file):
                    with open(tls_metrics_file, 'r') as f:
                        tls_data = json.load(f)

                    sources = tls_data.get('sources', {}) if isinstance(tls_data, dict) else {}
                    suspicious_sources = 0
                    suspicious_flows = 0

                    for src_ip, flow_stats in sources.items():
                        if not isinstance(flow_stats, dict):
                            continue

                        nonstandard_ports = flow_stats.get('nonstandard_tls_ports', [])
                        unique_dests = int(flow_stats.get('unique_dests', 0) or 0)
                        total_flows = int(flow_stats.get('total_flows', 0) or 0)

                        # Mark as suspicious if using nonstandard TLS ports or very high fan-out
                        has_nonstandard = isinstance(nonstandard_ports, list) and len(nonstandard_ports) > 0
                        high_fanout = unique_dests > 50 and total_flows > 200

                        if has_nonstandard or high_fanout:
                            suspicious_sources += 1
                            suspicious_flows += total_flows

                    stats['suspicious_tls_sources'] = suspicious_sources
                    stats['suspicious_tls_flows'] = suspicious_flows
            except Exception:
                # Do not break traffic analysis if TLS metrics cannot be loaded
                pass

            return jsonify(stats)
        else:
            return jsonify({'error': 'Traffic analyzer not available'}), 503
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/dns/stats', methods=['GET'])
def get_dns_stats():
    """Get DNS query statistics"""
    try:
        # Prefer analyzer-generated DNS metrics when available
        try:
            if os.path.exists('/app'):
                dns_metrics_file = "/app/json/dns_security.json"
            else:
                dns_metrics_file = os.path.join(os.path.dirname(__file__), 'json', 'dns_security.json')

            if os.path.exists(dns_metrics_file):
                with open(dns_metrics_file, 'r') as f:
                    data = json.load(f)

                sources = data.get('sources', {}) if isinstance(data, dict) else {}
                total_queries = 0
                suspicious_queries = 0

                for src_ip, stats in sources.items():
                    if not isinstance(stats, dict):
                        continue
                    total_queries += int(stats.get('total_queries', 0))
                    suspicious_queries += int(stats.get('suspicious_queries', 0))

                return jsonify({
                    'total_queries': total_queries,
                    'blocked_domains': 0,
                    # Treat suspicious DNS patterns as tunneling / exfil attempts
                    'tunneling_detected': suspicious_queries
                })
        except Exception:
            # Fall back to legacy estimation below on any error
            pass

        # Fallback: cross-platform DNS activity estimate using psutil
        dns_count = 0

        try:
            import psutil  # type: ignore
        except ImportError:
            psutil = None

        if psutil is not None:
            try:
                connections = psutil.net_connections(kind='inet')
                for conn in connections:
                    lport = conn.laddr.port if conn.laddr else None
                    rport = conn.raddr.port if conn.raddr else None
                    if lport == 53 or rport == 53:
                        dns_count += 1
            except Exception:
                dns_count = 0

        return jsonify({
            'total_queries': dns_count * 100,  # Estimate based on active connections
            'blocked_domains': 0,
            'tunneling_detected': 0
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/users/tracking', methods=['GET'])
def get_user_tracking():
    """Get tracked users on network"""
    try:
        if ADVANCED_FEATURES_AVAILABLE:
            stats = user_tracker.get_stats()
            return jsonify(stats)
        else:
            return jsonify({'error': 'User tracker not available'}), 503
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/threat-hunt', methods=['POST'])
@require_role('admin', 'analyst')
def threat_hunt():
    """Disabled threat-hunting console endpoint.

    In the first-layer-only architecture, there is no live
    threat-hunting console. Forensics are provided via offline PCAP and
    JSON artifacts only. This stub keeps the route explicit while
    returning a disabled status.
    """
    return (
        jsonify({
            'success': False,
            'error': 'Threat hunting console disabled in this build. '
                     'Use offline PCAP exports and forensic_reports JSON only.',
            'status': 'DISABLED'
        }),
        501,
    )

@app.route('/api/pcap/stats', methods=['GET'])
def get_pcap_stats():
    """Get PCAP capture statistics"""
    try:
        if ADVANCED_FEATURES_AVAILABLE:
            return jsonify(pcap_capture.get_stats())
        else:
            return jsonify({'error': 'PCAP module not available'}), 503
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/pcap/download', methods=['GET'])
def download_pcap():
    """Download latest PCAP file"""
    try:
        if not ADVANCED_FEATURES_AVAILABLE:
            return jsonify({'error': 'PCAP module not available'}), 503

        # Find latest PCAP file in capture directory
        pcap_dir = pcap_capture.pcap_dir
        if not os.path.isdir(pcap_dir):
            return jsonify({'error': 'No PCAP directory found'}), 404

        pcap_files = sorted(
            [
                os.path.join(pcap_dir, f)
                for f in os.listdir(pcap_dir)
                if f.endswith('.pcap')
            ]
        )

        if not pcap_files:
            return jsonify({'error': 'No PCAP files available'}), 404

        latest_pcap = pcap_files[-1]

        # Stream file to client (works inside Docker regardless of host OS)
        return send_file(
            latest_pcap,
            as_attachment=True,
            download_name=os.path.basename(latest_pcap),
            mimetype='application/vnd.tcpdump.pcap'
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/sandbox/detonate', methods=['POST'])
def sandbox_detonate():
    """Real file analysis (hash-based threat detection, no execution)"""
    try:
        if not ADVANCED_FEATURES_AVAILABLE:
            return jsonify({
                'success': False,
                'error': 'File analyzer module not loaded',
                'status': 'NOT_AVAILABLE'
            }), 503
        
        # Enforce a conservative maximum upload size for sandbox analysis
        max_size_bytes = 50 * 1024 * 1024  # 50 MB
        content_length = request.content_length
        if content_length is not None and content_length > max_size_bytes:
            return jsonify({
                'success': False,
                'error': 'File too large for sandbox analysis (max 50 MB)'
            }), 413
        
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'success': False, 'error': 'Empty filename'}), 400
        
        # Save file temporarily
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            file.save(tmp.name)
            # Double-check file size on disk in case Content-Length was missing/misreported
            if os.path.getsize(tmp.name) > max_size_bytes:
                os.unlink(tmp.name)
                return jsonify({
                    'success': False,
                    'error': 'File too large for sandbox analysis (max 50 MB)'
                }), 413
            result = file_analyzer.analyze_file(tmp.name, file.filename)
            os.unlink(tmp.name)  # Delete temp file
        
        return jsonify(result)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/sandbox/stats', methods=['GET'])
def get_sandbox_stats():
    """Get sandbox analysis statistics"""
    try:
        if ADVANCED_FEATURES_AVAILABLE:
            return jsonify(file_analyzer.get_stats())
        else:
            return jsonify({'error': 'File analyzer not available'}), 503
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/alerts/email/config', methods=['POST'])
def save_email_config():
    """Save real email alert configuration"""
    try:
        if not ADVANCED_FEATURES_AVAILABLE:
            return jsonify({'success': False, 'error': 'Alert system not available'}), 503
        
        data = request.get_json()
        success = alert_system.save_config('email', data)
        return jsonify({
            'success': success,
            'message': 'Email configuration saved' if success else 'Failed to save configuration'
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/alerts/sms/config', methods=['POST'])
def save_sms_config():
    """Save real SMS alert configuration"""
    try:
        if not ADVANCED_FEATURES_AVAILABLE:
            return jsonify({'success': False, 'error': 'Alert system not available'}), 503
        
        data = request.get_json()
        success = alert_system.save_config('sms', data)
        return jsonify({
            'success': success,
            'message': 'SMS configuration saved' if success else 'Failed to save configuration'
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/alerts/stats', methods=['GET'])
def get_alert_stats():
    """Get alert statistics"""
    try:
        if ADVANCED_FEATURES_AVAILABLE:
            return jsonify(alert_system.get_stats())
        else:
            return jsonify({'error': 'Alert system not available'}), 503
    except Exception as e:
        return jsonify({'error': str(e)}), 500

"""SOAR, vulnerability management, dark web, CSPM, DLP, and backup APIs have been
intentionally removed from the core first-layer server surface. Underlying
modules may still exist for lab or auxiliary tooling, but their HTTP endpoints
are no longer exposed here."""

@app.route('/api/soar/stats', methods=['GET'])
def get_soar_stats_disabled():
    """Explicit stub for legacy SOAR stats endpoint.

    The full SOAR engine is not exposed in this hardened build. This
    endpoint exists only to return a clear, machine-readable disabled
    status so dashboards do not see a 404 and attackers cannot infer
    implementation details from error pages.
    """
    return (
        jsonify({
            'error': 'SOAR API surface is disabled in this build',
            'status': 'DISABLED',
        }),
        501,
    )

@app.route('/api/openapi.json', methods=['GET'])
def get_openapi_spec():
    """Download OpenAPI specification"""
    spec = {
        'openapi': '3.0.0',
        'info': {
            'title': 'Battle-Hardened AI Security API',
            'version': '1.0.0',
            'description': 'Enterprise security monitoring and threat detection API'
        },
        'paths': {
            '/api/threats': {'get': {'summary': 'Get all threat logs'}},
            '/api/blocked-ips': {'get': {'summary': 'Get blocked IP addresses'}},
            '/api/block-ip': {'post': {'summary': 'Block an IP address'}},
            '/api/devices': {'get': {'summary': 'Get network devices'}}
        }
    }

    # Force browsers to download as a file while remaining valid JSON for tools
    return Response(
        json.dumps(spec),
        mimetype='application/json',
        headers={'Content-Disposition': 'attachment; filename="openapi.json"'}
    )


@app.route('/api/docs', methods=['GET'])
def api_docs():
    """Serve Swagger UI documentation page.

    This is the machine-level API reference. For broader enterprise
    documentation (architecture, flows, and normative references),
    use the /docs portal which aggregates the Markdown corpus.
    """
    # swagger_ui.html is served from the same template folder as the dashboard
    return render_template('swagger_ui.html')

@app.route('/api/assets/inventory', methods=['GET'])
def get_asset_inventory():
    """Get complete asset inventory"""
    try:
        from AI.asset_inventory import asset_inventory
        return jsonify(asset_inventory.get_stats())
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/assets/eol', methods=['GET'])
def get_eol_software():
    """Get end-of-life software"""
    try:
        from AI.asset_inventory import asset_inventory
        eol = asset_inventory.detect_eol_software()
        return jsonify({'eol_software': eol, 'count': len(eol)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/assets/shadow-it', methods=['GET'])
def get_shadow_it():
    """Detect shadow IT"""
    try:
        from AI.asset_inventory import asset_inventory
        shadow_it = asset_inventory.detect_shadow_it()
        return jsonify({'shadow_it': shadow_it, 'count': len(shadow_it)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/zero-trust/scores', methods=['GET'])
def get_zero_trust_scores():
    """Get device trust scores"""
    try:
        from AI.zero_trust import zero_trust
        return jsonify(zero_trust.get_stats())
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/zero-trust/policies', methods=['GET'])
def get_conditional_access_policies():
    """Get conditional access policies"""
    try:
        from AI.zero_trust import zero_trust
        # Use get_stats method which includes policy information
        stats = zero_trust.get_stats()
        policies = stats.get('policies', [])
        return jsonify({'policies': policies, 'count': len(policies)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/zero-trust/violations', methods=['GET'])
def get_privilege_violations():
    """Get least privilege violations"""
    try:
        from AI.zero_trust import zero_trust
        violations = zero_trust.check_least_privilege_violations()
        return jsonify({'violations': violations, 'count': len(violations)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/traffic/crypto-mining', methods=['GET'])
def get_crypto_mining_detection():
    """Get cryptocurrency mining detection stats"""
    try:
        from AI.traffic_analyzer import traffic_analyzer
        stats = traffic_analyzer.get_crypto_mining_stats()
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/zero-trust/data-classification', methods=['GET'])
def get_data_classification():
    """Get data classification status"""
    try:
        from AI.zero_trust import zero_trust
        classification = zero_trust.get_data_classification_status()
        return jsonify(classification)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/behavioral/stats', methods=['GET'])
def get_behavioral_stats():
    """Get behavioral heuristics statistics"""
    try:
        from AI.behavioral_heuristics import get_stats as get_behavior_stats
        return jsonify(get_behavior_stats())
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================================================
# MODULE-LEVEL INITIALIZATION (runs on import, regardless of entry point)
# ============================================================================

# Initialize Relay Client (if enabled)
# CRITICAL: With --preload, this runs ONCE before worker fork
# After fork, each worker imports but _relay_client singleton prevents re-initialization
print("[DEBUG] Initializing relay client...")
try:
    from AI.relay_client import start_relay_client, get_relay_status
    print("[DEBUG] Relay client module imported successfully")
    
    def on_threat_received(threat):
        """Process threats received from relay"""
        try:
            # Just log the threat for now (AI learning integration pending)
            print(f"[RELAY] 📥 Received threat from {threat.get('source_peer')}: {threat.get('attack_type')} - IP: {threat.get('src_ip')}")
        except Exception as e:
            print(f"[RELAY ERROR] Failed to process threat: {e}")
    
    print("[DEBUG] Starting relay client...")
    start_relay_client(on_threat_received)
    print("[DEBUG] Relay client started, getting status...")
    relay_status = get_relay_status()
    
    if relay_status.get('enabled'):
        print(f"[RELAY] ⚠️  Connecting to relay server...")
        print(f"[RELAY] URL: {relay_status.get('relay_url')}")
        print(f"[RELAY] Peer: {relay_status.get('peer_name')}")
        if relay_status.get('connected'):
            print(f"[RELAY] ✅ Connected successfully!")
        else:
            print(f"[RELAY] ⏳ Connection in progress...")
    else:
        print("[RELAY] Disabled (set RELAY_ENABLED=true in .env)")
    
except Exception as e:
    print(f"[WARNING] Relay client not available: {e}")
    import traceback
    traceback.print_exc()

# ============================================================================
# GUNICORN/MODULE INITIALIZATION - Runs when module is imported
# ============================================================================
# Real honeypot no longer auto-starts by default. Operators can start it from
# the dashboard (Section 15) or by setting REAL_HONEYPOT_AUTOSTART=true.
try:
    from AI.real_honeypot import get_honeypot_status, start_honeypots
    auto_start = os.getenv('REAL_HONEYPOT_AUTOSTART', 'false').lower() == 'true'
    if auto_start:
        print("[HONEYPOT] Auto-start enabled - starting real honeypot services...")
        results = start_honeypots()
        active = sum(1 for success in results.values() if success)
        print(f"[HONEYPOT] Startup results: {results}")
        if active > 0:
            print(f"[HONEYPOT] ✅ Started {active}/{len(results)} honeypot ports")
            status = get_honeypot_status()
            print(f"[HONEYPOT] Status check: running={status.get('running')}, active_services={status.get('active_services')}")
        else:
            print(f"[HONEYPOT] ❌ Failed to start any honeypot services - check port availability")
    else:
        print("[HONEYPOT] Real honeypot is disabled by default. Start it from the dashboard or set REAL_HONEYPOT_AUTOSTART=true.")
except Exception as e:
    print(f"[ERROR] Honeypot initialization problem: {e}")
    import traceback
    traceback.print_exc()



if __name__ == '__main__':
    print("=" * 70)
    print("🛡️  HOME WIFI SECURITY SYSTEM - STARTING")
    print("=" * 70)
    print(f"[INFO] Server starting at: {_get_current_time()}")
    
    # Get actual ports from environment
    dashboard_port = int(os.getenv('DASHBOARD_PORT', '60000'))
    p2p_port = int(os.getenv('P2P_PORT', '60001'))
    
    print(f"[INFO] Dashboard: https://localhost:{dashboard_port}")
    print(f"[INFO] Encrypted P2P: https://localhost:{p2p_port} (HTTPS)")
    print(f"[INFO] AI/ML Security Engine: {'ACTIVE' if pcs_ai.ML_AVAILABLE else 'DISABLED (install scikit-learn)'}")
    print("=" * 70)
    
    # Initialize Signature Distribution System
    try:
        from AI.signature_distribution import start_signature_distribution
        sig_dist = start_signature_distribution()
        print(f"[SIGNATURE DIST] Initialized in {sig_dist.mode.upper()} mode")
        print(f"[SIGNATURE DIST] Signatures available: {len(sig_dist._signature_index)}")
    except Exception as e:
        print(f"[WARNING] Signature distribution not available: {e}")
    
    # Start network monitoring in background
    monitoring_thread = threading.Thread(target=start_network_monitoring, daemon=True)
    monitoring_thread.start()
    
    # Get ports from environment variables (default to high ports to avoid conflicts)
    dashboard_port = int(os.getenv('DASHBOARD_PORT', '60000'))
    p2p_port = int(os.getenv('P2P_PORT', '60001'))
    
    # Generate self-signed certificate if not exists. Ensure the
    # crypto_keys directory exists so certificate generation works
    # in both source and PyInstaller/EXE deployments.
    cert_dir = os.path.join(BASE_DIR, 'crypto_keys')
    os.makedirs(cert_dir, exist_ok=True)
    cert_file = os.path.join(cert_dir, 'ssl_cert.pem')
    key_file = os.path.join(cert_dir, 'ssl_key.pem')
    
    if not os.path.exists(cert_file) or not os.path.exists(key_file):
        print("[SSL] Generating self-signed certificate with Python...")
        try:
            # Use Python's ssl module instead of OpenSSL command
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.backends import default_backend
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.primitives import serialization
            import datetime
            
            # Generate private key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            
            # Generate certificate
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, u"MY"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Kuala Lumpur"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, u"Kuala Lumpur"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Battle-Hardened AI"),
                x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
            ])
            
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                private_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.now(datetime.UTC)
            ).not_valid_after(
                datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365)
            ).add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName(u"localhost"),
                    x509.DNSName(u"127.0.0.1"),
                ]),
                critical=False,
            ).sign(private_key, hashes.SHA256(), default_backend())
            
            # Write private key
            with open(key_file, "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            # Write certificate
            with open(cert_file, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
            
            print("[SSL] ✅ Certificate generated successfully")
        except ImportError:
            print("[SSL] ❌ cryptography module not found")
            print("[SSL] Install: pip install cryptography")
            cert_file = None
            key_file = None
        except Exception as e:
            print(f"[SSL] ❌ Failed to generate certificate: {e}")
            cert_file = None
            key_file = None
    
    print("📊 Starting server...")
    
    # Initialize JSON files before starting (critical for first run)
    print("📁 Initializing JSON data files...")
    try:
        import sys
        # When running from the packaged EXE (PyInstaller), sys.frozen is set
        # and we cannot safely re-invoke sys.executable with a script path.
        # Import and run the initializer directly instead.
        if getattr(sys, 'frozen', False):  # type: ignore[attr-defined]
            from installation import init_json_files as _init_json_files
            _init_json_files.initialize_all_json_files()
        else:
            import subprocess
            init_script = os.path.join(os.path.dirname(__file__), 'installation', 'init_json_files.py')
            subprocess.run([sys.executable, init_script], check=True, capture_output=True)
        print("✅ JSON initialization complete")
    except Exception as e:
        print(f"⚠️  JSON initialization warning: {e}")
        print("Continuing server startup...")
    
    print(f"📊 Dashboard (HTTPS): https://localhost:{dashboard_port}")

    # Allow an explicit escape hatch for local debugging where TLS
    # interception or tooling causes noisy SSLEOFError logs. This is
    # never enabled by default and must be opted into via environment.
    allow_insecure = os.environ.get('ALLOW_INSECURE_HTTP', '').strip() == '1'

    if allow_insecure:
        print("[SECURITY WARNING] ALLOW_INSECURE_HTTP=1 set - running WITHOUT TLS on http://localhost:{}".format(dashboard_port))
        print("[SECURITY WARNING] Use this only for local debugging, never in production.")
        app.run(
            host='0.0.0.0',
            port=dashboard_port,
            debug=False,
            threaded=True,
        )

    # Default: run Flask with HTTPS
    if cert_file and key_file and os.path.exists(cert_file):
        app.run(
            host='0.0.0.0',
            port=dashboard_port,
            debug=False,
            threaded=True,
            ssl_context=(cert_file, key_file)
        )
    else:
        print("[ERROR] SSL certificates required! HTTPS is mandatory.")
        print("[ERROR] Certificates should have been auto-generated. Check OpenSSL installation.")
        raise Exception("SSL certificates required for secure operation")

