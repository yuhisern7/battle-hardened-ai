# AI System Architecture & Implementation Guide

> **Purpose:** Comprehensive technical guide for developers. Explains the 7-stage attack detection pipeline implementation, testing procedures, and compliance architecture across AI modules, server components, and relay infrastructure.
>
> **Audience & distribution note:** This document assumes access to the **full source tree** (AI/, server/, relay/) as checked out from Git (for example in a development or CI environment). **Production customers who install via the Linux .deb/.rpm packages or the Windows EXE do not receive this source layout by default** – they operate the packaged services and refer primarily to README and INSTALLATION. Use this guide when you are **developing, auditing, or extending** the system from source.
>
> **Implementation note:** SIEM/SOAR, NGFW, XDR/EDR, VPN/ZTNA/NAC consume JSON outputs and do not participate in the primary enforcement path, which is executed on the local OS firewall using threat_log.json, blocked_ips.json, and related state.

**Related Documentation:**
- **[README.md](../../README.md)** - Main documentation with architecture overview and how Battle-Hardened AI enhances existing security controls while keeping enforcement on the local OS firewall
- **[Installation](../installation/Installation.md)** - Complete installation guide
- **Relay deployment (see relay/ directory in repo root)** - Relay server deployment
- **[Dashboard](../mapping/Dashboard.md)** - Core first-layer dashboard API reference
- **[Filepurpose](../mapping/Filepurpose.md)** - File organization by pipeline stage
- **[KALI_ATTACK_TESTS.md](../../KALI_ATTACK_TESTS.md)** - Attack testing commands

---

## Table of Contents

**PART I: ARCHITECTURE & IMPLEMENTATION**
- [0. Architecture Overview: 7-Stage Pipeline Visualization](#0-architecture-overview-7-stage-pipeline-visualization)
- [1. Pipeline Implementation Map: README Flow → Code Modules](#1-pipeline-implementation-map-readme-flow--code-modules)
  - [Stage 1: Data Ingestion & Normalization](#stage-1-data-ingestion--normalization)
    - [Stage 2: Parallel Multi-Signal Detection (20 Signals + Step 21 Semantic Gate)](#stage-2-parallel-multi-signal-detection-20-signals--step-21-semantic-gate)
  - [Stage 3: Ensemble Decision Engine (Weighted Voting)](#stage-3-ensemble-decision-engine-weighted-voting)
  - [Stage 4: Response Execution (Policy-Governed)](#stage-4-response-execution-policy-governed)
  - [Stage 5: Training Material Extraction (Privacy-Preserving)](#stage-5-training-material-extraction-privacy-preserving)
  - [Stage 6: Global Intelligence Sharing (Optional Relay)](#stage-6-global-intelligence-sharing-optional-relay)
  - [Stage 7: Continuous Learning Loop](#stage-7-continuous-learning-loop)
    - [Identity, Access, HA & Support Flows](#identity-access-ha--support-flows)
- [2. Dashboard Architecture: UI → API → AI Modules](#2-dashboard-architecture-ui--api--ai-modules)
- [3. File Structure & Path Conventions](#3-file-structure--path-conventions)
- [4. Privacy & Security Guarantees](#4-privacy--security-guarantees)
- [5. Developer Guidelines: Adding New Detections](#5-developer-guidelines-adding-new-detections)
- [6. Performance Considerations](#6-performance-considerations)
- [7. Common Pitfalls & Solutions](#7-common-pitfalls--solutions)
- [8. Quick Reference](#8-quick-reference)

**PART II: TESTING & VALIDATION**
- [9. Testing & Validation Guide (10-Stage Progressive Validation)](#9-testing--validation-guide-10-stage-progressive-validation)
    - [9.1 Testing Strategy Overview](#91-testing-strategy-overview)
    - [9.2 Quick Reference: 21 Detection Layers → Implementation Files](#92-quick-reference-21-detection-layers--implementation-files)
    - [9.3 Relay Output Files by Stage (Summary)](#93-relay-output-files-by-stage-summary)

---

## 0. Architecture Overview: 7-Stage Pipeline Visualization

**This system implements the README's 7-stage attack detection flow:**

```
┌───────────────────────────────────────────────────────────────────────────────┐
│                        BATTLE-HARDENED AI ARCHITECTURE                        │
│                        7-Stage Attack Detection Pipeline                      │
└───────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────┐
│  STAGE 1: INGESTION │  Network packet arrives
└──────────┬──────────┘
           │
           ▼
    ┌──────────────┐
    │ network_     │───→ Scapy/eBPF packet capture
    │ monitor.py   │───→ Metadata extraction (IPs, ports, protocols)
    └──────┬───────┘
           │
           ▼
┌───────────────────────────────────────────────────────────────────────────────┐
│  STAGE 2: PARALLEL DETECTION (Signals 1-20 = 18 Primary + 2 Strategic        │
│   + Step 21 Semantic Execution-Denial Gate)                                  │
├───────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│  PRIMARY SIGNALS (1-18): Direct threat detection                             │
│  ┌─────────────┬─────────────┬─────────────┬─────────────┐                 │
│  │ #1 Kernel   │ #2 Signature│ #3 Random   │ #4 Isolation│                 │
│  │ Telemetry   │ Matching    │ Forest      │ Forest      │                 │
│  └─────────────┴─────────────┴─────────────┴─────────────┘                 │
│  ┌─────────────┬─────────────┬─────────────┬─────────────┐                 │
│  │ #5 Gradient │ #6 Behavior │ #7 LSTM     │ #8 Auto-    │                 │
│  │ Boosting    │ Heuristics  │ Sequences   │ encoder     │                 │
│  └─────────────┴─────────────┴─────────────┴─────────────┘                 │
│  ┌─────────────┬─────────────┬─────────────┬─────────────┐                 │
│  │ #9 Drift    │ #10 Graph   │ #11 VPN/Tor │ #12 Threat  │                 │
│  │ Detection   │ Intel       │ Fingerprint │ Intel Feeds │                 │
│  └─────────────┴─────────────┴─────────────┴─────────────┘                 │
│  ┌─────────────┬─────────────┬─────────────┬─────────────┐                 │
│  │ #13 False   │ #14 Histor  │ #15 Explain │ #16 Predict │                 │
│  │ Pos Filter  │ Reputation  │ Engine      │ Modeling    │                 │
│  └─────────────┴─────────────┴─────────────┴─────────────┘                 │
│  ┌─────────────┬─────────────┐                                              │
│  │ #17 Byzant  │ #18 Integ   │                                              │
│  │ Defense     │ Monitor     │                                              │
│  └─────────────┴─────────────┘                                              │
│                                                                               │
│  STRATEGIC LAYERS (19-20): Dual-role signals (vote + modulate)               │
│  ┌──────────────────────────────┬──────────────────────────────┐            │
│  │ #19 Causal Inference Engine  │ #20 Trust Degradation Graph  │            │
│  │ WHY attacks happen            │ Persistent entity tracking   │            │
│  │ (legitimate vs malicious)     │ (permanent scarring)         │            │
│  └──────────────────────────────┴──────────────────────────────┘            │
│                                                                               │
│  All signals 1-20 produce: DetectionSignal(is_threat, confidence, details)   │
└──────────────────────────────────┬────────────────────────────────────────────┘
                                   │
                                   ▼
┌───────────────────────────────────────────────────────────────────────────────┐
│  STAGE 3: ENSEMBLE VOTING (meta_decision_engine.py)                          │
├───────────────────────────────────────────────────────────────────────────────┤
│  Step 1: Weighted Voting → Base score = Σ(weight × confidence × is_threat)  │
│  Step 2: Authoritative Boosting → Honeypot/ThreatIntel override             │
│  Step 3: Causal Modulation → Layer 19 adjusts score (-20% to +15%)          │
│  Step 4: Trust Modulation → Layer 20 boosts risk for low-trust entities     │
│  Step 5: Threshold Decision → Block if score ≥ threshold (default 75%)      │
└──────────────────────────────────┬────────────────────────────────────────────┘
                                   │
                                   ▼
┌───────────────────────────────────────────────────────────────────────────────┐
│  STAGE 4: RESPONSE EXECUTION                                                  │
├───────────────────────────────────────────────────────────────────────────────┤
│  • Firewall block (iptables/Windows Firewall)                                │
│  • Log to threat_log.json + blocked_ips.json                                 │
│  • Trust degradation (Layer 20 updates trust_graph.json)                     │
│  • Critical-event alerts (email/SMS; system failures, kill-switch, integrity)│
│  • Dashboard update                                                          │
└──────────────────────────────────┬────────────────────────────────────────────┘
                                   │
                                   ▼
┌───────────────────────────────────────────────────────────────────────────────┐
│  STAGE 5: TRAINING EXTRACTION (Privacy-Preserving)                           │
├───────────────────────────────────────────────────────────────────────────────┤
│  • Signature extraction (signature_extractor.py)                              │
│  • Behavioral statistics (behavioral_heuristics.py)                           │
│  • Graph patterns (graph_intelligence.py → anonymized topology)              │
│  • Reputation updates (reputation_tracker.py)                                 │
│  • NO payloads, NO PII, NO credentials                                        │
└──────────────────────────────────┬────────────────────────────────────────────┘
                                   │
                                   ▼ (Optional relay connection)
┌───────────────────────────────────────────────────────────────────────────────┐
│  STAGE 6: RELAY SHARING (Optional - Relay Server)                            │
├───────────────────────────────────────────────────────────────────────────────┤
│  Client Node                     Relay Server                                 │
│  ┌─────────────┐                ┌─────────────────────┐                     │
│  │ Local       │──Push threat──→│ global_attacks.json │                     │
│  │ findings    │   signatures    │ +43,971 ExploitDB   │                     │
│  │             │←──Pull models───│ trained_models/     │                     │
│  └─────────────┘   updates       └─────────────────────┘                     │
│                                                                               │
│  • WebSocket: wss://relay:60001 (threat push)                                │
│  • HTTPS API: https://relay:60002 (model pull)                               │
│  • Byzantine validation (reject poisoned updates)                             │
└──────────────────────────────────┬────────────────────────────────────────────┘
                                   │
                                   ▼
┌───────────────────────────────────────────────────────────────────────────────┐
│  STAGE 7: CONTINUOUS LEARNING                                                 │
├───────────────────────────────────────────────────────────────────────────────┤
│  • Weekly ML retraining (relay/ai_retraining.py)                              │
│  • Signature distribution (relay/signature_sync.py)                           │
│  • Drift baseline updates (AI/drift_detector.py)                              │
│  • Reputation decay (AI/reputation_tracker.py)                                │
│  • Model lineage tracking (AI/cryptographic_lineage.py)                       │
└───────────────────────────────────────────────────────────────────────────────┘
```

**Three deployment tiers (source/architecture view):**

1. **Customer Node runtime (packaged)** — What production customers run in the Linux package or Windows EXE; contains the compiled/packaged equivalents of `server/` and `AI/` but does **not** expose the raw source tree.
2. **AI Intelligence Layer (AI/ source tree)** — The source modules that implement all 20 detection signals, the Step 21 semantic gate, and ensemble logic (stages 2-3). Available to developers and auditors working from Git.
3. **Central Relay (relay/ + AI/ + server/)** — Operator-controlled training hub (stages 6-7). The relay deployment requires 3 folders: `relay/` (WebSocket server + model distribution API), `AI/` (crypto security, ML models, threat analysis), and `server/` (path utilities, JSON configs). Deployed separately on a VPS via Docker when used.

---

## 1. Pipeline Implementation Map: README Flow → Code Modules

### Stage 1: Data Ingestion & Normalization

**README:** "📥 PACKET ARRIVES → 📊 Pre-processing (metadata extraction, normalization)"

**Implementation:**
- **Packet Capture:** `server/network_monitor.py` (eBPF/XDP or scapy-based; bundled in Windows EXE builds)
- **Kernel Telemetry:** `AI/kernel_telemetry.py` (syscall correlation, Linux only)
- **System Logs:** `AI/system_log_collector.py` (auth logs, application logs)
- **Cloud APIs:** `AI/cloud_security.py` (AWS CloudTrail, Azure Activity, GCP Audit)
- **Device Discovery:** `server/device_scanner.py` (cross-platform network detection: Linux via ip route/addr, Windows via ipconfig parsing, fallback via socket trick)

**Data Flow:**
```
Raw packets → network_monitor.py → metadata extraction (IPs, ports, protocols, timestamps)
→ schema normalization → normalized event object
```

**JSON Persistence:** JSON is written under the directory returned by `AI/path_helper.get_json_dir()` (typically `server/json/` in native/Windows EXE runs, `/app/server/json/` in Docker relay containers)

**Stage 1 → Stage 2 Transition:**
1. Network monitor creates normalized event: `{"src_ip": "...", "dst_ip": "...", "src_port": ..., "protocol": "...", "timestamp": "...", ...}`
2. Event passed to `AI/pcs_ai.py` → `assess_threat(event)` method
3. `assess_threat()` orchestrates all 20 detection signals in parallel using the same event object, then the Step 21 semantic gate evaluates the combined result before any action
4. Each signal produces independent `DetectionSignal` object → fed into Stage 3 ensemble

---

### Stage 2: Parallel Multi-Signal Detection (20 Signals + Step 21 Semantic Gate)

**README:** "⚡ 20 PARALLEL DETECTIONS (18 primary + 2 strategic intelligence layers)" + Step 21 semantic execution-denial gate (21st detection layer)

**Implementation:** Each signal = independent AI module

**Primary Detection Signals (1-18):** Direct threat detection from network traffic and system events.

**Strategic Intelligence Layers (19-20):** Dual-role signals that participate in weighted voting AND provide strategic context. They analyze detection outputs from all signals (1-20), deployment logs, config changes, and entity history to modulate ensemble decisions.

| # | Signal | Module(s) | Model/Data | Output |
|---|--------|-----------|------------|--------|
| 1 | **Kernel Telemetry** | `AI/kernel_telemetry.py` | eBPF/XDP events | Syscall/network correlation |
| 2 | **Signatures** | `AI/threat_intelligence.py` | 3,066+ patterns | Pattern match confidence |
| 6 | **Behavioral** | `AI/behavioral_heuristics.py` | 15 metrics + APT | Heuristic risk score |
| 3 | **RandomForest** | `AI/pcs_ai.py` | `AI/ml_models/threat_classifier.pkl` | Classification score |
| 4 | **IsolationForest** | `AI/pcs_ai.py` | `AI/ml_models/anomaly_detector.pkl` | Anomaly score |
| 5 | **Gradient Boosting** | `AI/pcs_ai.py` | `AI/ml_models/ip_reputation.pkl` | Reputation score |
| 7 | **LSTM** | `AI/sequence_analyzer.py` | `AI/ml_models/sequence_lstm.keras` | Kill-chain state |
| 8 | **Autoencoder** | `AI/traffic_analyzer.py` | `AI/ml_models/traffic_autoencoder.keras` | Reconstruction error |
| 9 | **Drift Detection** | `AI/drift_detector.py` | `drift_baseline.json` | KS/PSI drift score |
| 10 | **Graph Intelligence** | `AI/graph_intelligence.py` | `network_graph.json` | Lateral movement |
| 11 | **VPN/Tor Fingerprinting** | `AI/pcs_ai.py` | VPN/Tor statistics (metadata-only) | Anonymization detection + optional deanonymization |
| 12 | **Threat Intel** | `AI/threat_intelligence.py` | VirusTotal, AbuseIPDB | OSINT correlation |
| 13 | **False Positive Filter** | `AI/false_positive_filter.py` | FP config | 5-gate validation |
| 14 | **Reputation** | `AI/reputation_tracker.py` | `reputation.db` (SQLite) | Recidivism score |
| 15 | **Explainability** | `AI/explainability_engine.py` | Decision history | Transparency |
| 16 | **Predictive Modeling** | `AI/advanced_orchestration.py` | Threat predictions | 24-48h forecast (advisory only) |
| 17 | **Byzantine Defense** | `AI/byzantine_federated_learning.py` | Peer trust scores | Update rejection |
| 18 | **Integrity** | `AI/self_protection.py`, `AI/cryptographic_lineage.py` | Lineage chain | Tampering detection |
| 19 | **Causal Inference** | `AI/causal_inference.py` (new) | Config change logs, deployment events | Root cause classification |
| 20 | **Trust Degradation** | `AI/trust_graph.py` (new) | `trust_graph.json` (persistent) | Entity trust scores 0-100 |

**Orchestration:** `AI/pcs_ai.py` → `assess_threat()` → constructs `DetectionSignal` objects

**APT Enhancements:**
- **Behavioral (Signal #6):** `detect_low_and_slow()`, `detect_off_hours_activity()`, `detect_credential_reuse()`
- **LSTM (Signal #7):** Campaign pattern matching (slow_burn, smash_and_grab, lateral_spread)
- **Graph (Signal #10):** Weight increased 0.88→0.92 for lateral movement detection
- **Causal Inference (Signal #19):** Distinguishes APT "living off the land" (legitimate tools/timing) from actual attacks
- **Trust Degradation (Signal #20):** Persistent attacker tracking across IP rotation, VPN changes, and session resets

**Strategic Intelligence Layer Architecture:**

**Layer 19 (Causal Inference Engine):**
- **Module:** `AI/causal_inference.py` (585 lines, production-ready)
- **Position:** Runs AFTER signals 1-18, BEFORE final ensemble decision
- **Inputs:** DetectionSignal objects (1-18), system config change logs, deployment/CI events, identity events (login, privilege change), time-series metadata
- **Core Logic:** Builds causal graphs (not correlations), tests counterfactuals, classifies root causes
- **Causal Labels:** LEGITIMATE_CAUSE, MISCONFIGURATION, AUTOMATION_SIDE_EFFECT, EXTERNAL_ATTACK, INSIDER_MISUSE, UNKNOWN_CAUSE
- **Temporal Correlation Windows:**
  - Deployment events: 3600 seconds (1 hour)
  - Config changes: 1800 seconds (30 minutes)
  - Identity events: 900 seconds (15 minutes)
- **Counterfactual Testing:** "Would this anomaly exist WITHOUT the deployment/config change?"
- **Score Modulation:**
  - Legitimate causes: -20% (legitimate_cause), -15% (automation_side_effect)
  - Malicious causes: +15% (external_attack), +10% (insider_misuse)
  - Misconfiguration: Route to governance queue (no auto-block)
  - Unknown: Require human review
- **Output:** CausalInferenceResult with causal_label, confidence (0.0-1.0), primary_causes[], non_causes[], reasoning
- **JSON Persistence:** `server/json/causal_analysis.json` (auto-rotates at 10,000 entries)
- **Privacy:** Never sees raw payloads, credentials, exploit code, or PII - operates only on detection outputs and metadata
- **Weight in Ensemble:** 0.88 (high reliability, context provides strong signal)

**Layer 20 (Trust Degradation Graph):**
- **Module:** `AI/trust_graph.py` (422 lines, production-ready)
- **Position:** Influences Stage 4 response severity, tracked by explainability engine (Signal #15)
- **Tracked Entities:** IPs, devices, user accounts, services, APIs, cloud roles, containers
- **Trust Score:** 0-100 per entity (internal baseline=100, external configurable baseline=60)
- **Degradation Model:** Non-linear decay with event-weighted penalties
  - minor_anomaly: -5
  - failed_auth: -10
  - suspicious_behavior: -15
  - confirmed_attack: -25
  - lateral_movement: -30
  - data_exfiltration: -35
  - integrity_breach: -40
  - repeated_attack: -50 (exponential for recidivists)
- **Recovery:** +1 trust per 24h without incident (slow recovery, capped at 80% of baseline - trust NEVER fully recovers)
- **Recidivism Detection:** 3+ attacks in 7 days = exponential penalty
- **Trust Thresholds & Actions (as implemented):**
    - ≥80: ALLOW (normal operation)
    - 60-79: MONITOR (increased monitoring, +5% score boost on ensemble vote)
    - 40-59: RATE_LIMIT (connection throttling, +10% score boost on ensemble vote)
    - 20-39: ISOLATE (deny-by-default firewall, +15% score boost; block once weighted vote ≥60%)
    - <20: QUARANTINE (automatic quarantine + SOC alert, force block regardless of ensemble score)
- **Output:** TrustStateUpdate with entity_id, previous_trust, current_trust, recommended_action, reasons[], timestamp
- **JSON Persistence:** `server/json/trust_graph.json` (persistent across restarts)
- **Privacy:** SHA-256 entity hashing, no PII retention, statistical scores only
- **Weight in Ensemble:** 0.90 (very high reliability, persistent memory prevents evasion)
- **Integration:** Feeds from Historical Reputation (Layer 14), influences response severity in Stage 4

**Stage 2 Output Format:**
Each signal produces:
```python
DetectionSignal(
    signal_type=SignalType.SIGNATURE,  # or GRAPH, LSTM, etc.
    is_threat=True,                    # Boolean: is this signal detecting a threat?
    confidence=0.92,                   # Float 0.0-1.0: how confident is the signal?
    details="...",                    # Human-readable description
    metadata={...},                    # Optional dict of signal-specific metadata
)
```

**Stage 2 → Stage 3 Transition:**
1. All applicable detection systems (1–20) complete analysis → `AI/pcs_ai.py` constructs a list of `DetectionSignal` objects for the ensemble.
2. **Layer 19 (Causal Inference)** analyzes existing signals + system metadata → produces a `CausalInferenceResult` that is injected as its own `DetectionSignal` (type `CAUSAL_INFERENCE`).
3. **Layer 20 (Trust Degradation)** updates the trust graph and emits a `DetectionSignal` (type `TRUST_DEGRADATION`) reflecting current trust state.
4. The full list of `DetectionSignal` objects (including causal and trust signals) is passed to `AI/meta_decision_engine.py` for weighted voting.
5. After the ensemble decision, `AI/pcs_ai.py` invokes the Step 21 semantic gate (`AI/step21_semantic_gate.py`) as a final semantic veto layer before any response is returned.

---

### Stage 3: Ensemble Decision Engine (Weighted Voting)

**README:** "🎯 ENSEMBLE VOTING → Calculate weighted score → Authoritative boosting → Consensus → Threshold decision"

**Implementation:**
- **Module:** `AI/meta_decision_engine.py`
- **Input:** List of `DetectionSignal` objects from Stage 2 (including causal and trust signals)
- **Algorithm (as implemented):**
  ```python
  # 1. Compute weighted vote score
  weighted_score = Σ (signal_weight × confidence × is_threat) / Σ signal_weight

  # 2. Apply configurable thresholds
  threat_threshold = 0.50   # classify as threat
  block_threshold  = 0.75   # auto-block (default)

  # 3. APT mode lowers the block threshold (env: APT_DETECTION_MODE=true)
  if apt_detection_mode:
      block_threshold = min(block_threshold, 0.70)

  # 4. Threshold decision
  if weighted_score >= block_threshold:
      decision = BLOCK
  elif weighted_score >= threat_threshold:
      decision = LOG_THREAT
  else:
      decision = ALLOW
  ```

  Signals for **causal inference (Layer 19)** and **trust degradation (Layer 20)** influence the decision through their own `signal_weight` and `confidence` values inside this voting process. The **Step 21 semantic gate** then runs in `AI/pcs_ai.py` after this ensemble decision and can veto execution entirely (deny execution meaning) if the semantic checks fail.

**Signal Weights (configurable):**
- Honeypot: 0.98 (highest - direct attacker interaction)
- Threat Intel: 0.95 (external validation)
- Graph Intelligence: 0.92 (APT lateral movement)
- Signature: 0.90 (known patterns)
- LSTM: 0.85 (kill-chain progression)
- Behavioral: 0.75 (statistical heuristics)
- Drift: 0.65 (model degradation warning)

**Configuration:** `server/json/meta_engine_config.json`
**Audit Trail:** `server/json/decision_history.json` (per-signal contributions)
**Output:** `EnsembleDecision(threat_level, should_block, weighted_score, reasons)`

**Stage 3 → Stage 4 Transition:**
1. Ensemble engine calculates `weighted_score` (0.0-1.0) from all filtered signals
2. Decision threshold applied:
   - `≥ 0.75` (or 0.70 in APT mode): `should_block=True` → Stage 4 firewall block
   - `≥ 0.50`: `should_block=False` but `threat_level=HIGH` → Stage 4 logs threat (no block)
   - `< 0.50`: `threat_level=LOW` → allow, minimal logging
3. `EnsembleDecision` object returned to `AI/pcs_ai.py` → triggers Stage 4 response actions

---

### Stage 4: Response Execution (Policy-Governed)

**README:** "🛡️ RESPONSE EXECUTION → Firewall block → Connection drop → Rate limiting → Logging → Alerts"

**Implementation:**

| Action | Module | Configuration |
|--------|--------|---------------|
| **Firewall Block** | `server/device_blocker.py` | iptables/nftables + TTL |
| **Connection Drop** | `server/network_monitor.py` | Active TCP session termination |
| **Rate Limiting** | `AI/pcs_ai.py` | 50-74% confidence attacks |
| **Logging** | Multiple modules | 10+ JSON audit surfaces |
| **Dashboard Update** | `server/server.py` | WebSocket real-time push |
| **Email/SMS Alerts** | `AI/alert_system.py` | SMTP/Twilio integration |

**Multi-Surface Logging:**
- `threat_log.json` — Primary threat log *(auto-rotates at 100MB, see `AI/file_rotation.py`)*
- `comprehensive_audit.json` — All THREAT_DETECTED/INTEGRITY_VIOLATION/SYSTEM_ERROR events *(auto-rotates at 100MB)*
- `attack_sequences.json` — LSTM kill-chain progressions
- `lateral_movement_alerts.json` — Graph intelligence hop chains
- `behavioral_metrics.json` — Per-IP heuristics
- `dns_security.json` — DNS analyzer findings
- `tls_fingerprints.json` — TLS fingerprinting data
- `integrity_violations.json` — Self-protection events
- `forensic_reports/*.json` — Explainability outputs
- `decision_history.json` — Ensemble voting records
- `causal_analysis.json` — **Layer 19: Root cause analysis results**
- `trust_graph.json` — **Layer 20: Entity trust state tracking (persistent across restarts)**

**Note:** Files marked with *(auto-rotates at 100MB)* use `AI/file_rotation.py` to prevent unbounded growth (optimized for resource-constrained relay servers). ML training reads all rotation files (`threat_log.json`, `threat_log_1.json`, `threat_log_2.json`, etc.) to preserve complete attack history.

**Policy Governance:**
- `AI/policy_governance.py` — Approval workflows
- `server/json/approval_requests.json` — Pending approvals
- `AI/emergency_killswitch.py` — SAFE_MODE override

**Stage 4 → Stage 5 Transition:**
1. Stage 4 writes attack details to `threat_log.json`, `comprehensive_audit.json`, and signal-specific logs
2. Background extraction jobs scan logs periodically (every hour):
    - `AI/signature_extractor.py` reads `threat_log.json` → extracts attack patterns → writes `honeypot_patterns.json`
   - `AI/reputation_tracker.py` reads `threat_log.json` → updates `reputation.db` with attacker IPs
   - `AI/graph_intelligence.py` reads `lateral_movement_alerts.json` → updates `network_graph.json`
3. Extracted materials staged locally in `server/json/` → ready for Stage 6 relay push

---

### Stage 5: Training Material Extraction (Privacy-Preserving)

**README:** "🧬 TRAINING MATERIAL EXTRACTION → Signatures → Statistics → Reputation → Graph patterns → Model weights"

**Implementation:**

**Customer-Side Extraction (Local Staging):**

| Material Type | Module | Local Staging | Privacy Protection |
|--------------|--------|---------------|-------------------|
| **Signatures** | `AI/signature_extractor.py` | `server/json/honeypot_patterns.json` | Patterns only, zero exploit code |
| **Behavioral Stats** | `AI/behavioral_heuristics.py` | `server/json/behavioral_metrics.json` | Connection rate, port entropy (anonymized) |
| **Reputation** | `AI/reputation_tracker.py` | `server/json/reputation.db` | SHA-256 hashed IPs (not raw) |
| **Graph Topology** | `AI/graph_intelligence.py` | `server/json/network_graph.json` | A→B→C labels (not real IPs) |

**Relay-Side Storage (After Stage 6 Push):**
- Signatures → `relay/ai_training_materials/ai_signatures/learned_signatures.json`
- Reputation → `relay/ai_training_materials/reputation_data/`
- Graph patterns → `relay/ai_training_materials/training_datasets/graph_topology.json`
- Attack records → `relay/ai_training_materials/global_attacks.json`

**Stage 5 → Stage 6 Flow:** Customer extracts materials locally → `AI/relay_client.py` pushes to relay (every hour) → relay aggregates into training datasets (see Section 4 for privacy guarantees)

---

### Stage 6: Global Intelligence Sharing (Optional Relay)

**README:** "🌍 RELAY SHARING → Push local findings → Pull global intel → Merge knowledge"

**Implementation:**

**Push to Relay (every hour):**
- **Module:** `AI/relay_client.py`, `AI/signature_uploader.py`
- **Authentication:** HMAC (`AI/crypto_security.py`, `server/crypto_keys/`)
- **Protocol:** WebSocket/HTTP POST to `relay/relay_server.py`
- **Payload:** Sanitized attack records (no payloads)

**Relay Server:**
- **Module:** `relay/relay_server.py`, `relay/signature_sync.py`
- **Storage:**
  - `relay/ai_training_materials/global_attacks.json` (central attack log)
  - `relay/ai_training_materials/ai_signatures/learned_signatures.json` (signature deduplication)
  - `relay/ai_training_materials/attack_statistics.json` (aggregated trends)

**Pull from Relay (every 6 hours):**
- **Module:** `AI/training_sync_client.py` (models), `AI/signature_distribution.py` (signatures/intel)
- **Downloads:**
    - Pre-trained ML model files (for example `*.pkl`) produced by the relay retraining pipeline (no raw training data)
    - Signature and threat-intel bundles via `AI/signature_distribution.py` (for example reputation feeds, emerging threat statistics)
- **Destination:**
    - Models → ML models directory resolved via `AI/path_helper.get_ml_models_dir()` (typically `AI/ml_models/` in the repo, `/app/ml_models/` in Docker)
    - Signatures/intel → Local signature store and JSON surfaces managed by `AI/signature_distribution.py` and `AI/reputation_tracker.py`

#### Privacy-Preserving Defensive Mesh (Stage 5–6 Summary)

- **One server protects an entire network segment (no endpoint agents required)** – the Gateway/Router deployment role enforces decisions for all devices behind a single node while keeping detection and enforcement local to that gateway (see [README.md](../../README.md#deployment-scope--three-roles-many-environments)).
- **Every attack makes the system smarter (automated signature extraction + ML retraining)** – Stage 5 extracts sanitized signatures, behavioral statistics, graph patterns, and reputation data into local JSON, which are then used by the relay-side retraining pipeline and Stage 7 continuous learning (see [Architecture_enhancements.md](Architecture_enhancements.md) and [relay/ai_retraining.py](../../relay/ai_retraining.py)).
- **Every node benefits from global learning (relay-shared intelligence from worldwide attacks)** – Stage 6 pushes only sanitized attack materials to the relay and pulls back signed models, signatures, and reputation feeds; customer nodes never exchange raw payloads or logs with each other directly.
- **Organizations retain full control (relay participation is optional, all data anonymized)** – the relay client (`AI/relay_client.py`, `AI/signature_uploader.py`) is optional and can be disabled entirely; when enabled, uploads are restricted to anonymized patterns and aggregated statistics guarded by HMAC authentication (see [Section 4: Privacy & Security Guarantees](#4-privacy--security-guarantees)).
- **Privacy is preserved (no raw payloads, no PII, only statistical features shared)** – Stage 5 explicitly forbids payloads, credentials, or PII in exported training materials, and the relay-side training datasets operate only on patterns, counts, hashes, and anonymized topologies (see [Stage 5: Training Material Extraction (Privacy-Preserving)](#stage-5-training-material-extraction-privacy-preserving)).

**Merge & Integration:**
- New signatures → Local signature database via `AI/signature_distribution.py`
- Reputation feed → `AI/reputation_tracker.py`
- Model updates → `AI/byzantine_federated_learning.py` validation → replace local models

**Relay Infrastructure (NOT shipped to customers):**
- `relay/docker-compose.yml` — Separate deployment
- `relay/training_sync_api.py` — Model distribution API
- `relay/exploitdb_scraper.py` — ExploitDB integration (3,066+ patterns)
- `relay/threat_crawler.py` — OSINT aggregation (VirusTotal, AbuseIPDB, URLhaus, MalwareBazaar)

**Relay Quick Reference (Developers/Auditors):**
- **Node → Relay (outbound)**
    - Threat patterns: `AI/relay_client.py` → `relay/relay_server.py` over `wss://<relay-host>:60001` (sanitized summaries only, HMAC via `AI/crypto_security.py`).
    - Optional honeypot patterns: `AI/training_sync_client.upload_honeypot_pattern()` → `relay/training_sync_api.py` (HTTPS, sanitized patterns only).
- **Relay → Node (inbound)**
    - Models: `AI/training_sync_client.py` → `relay/training_sync_api.py` over `https://<relay-host>:60002` (downloads **only** pre-trained models into `AI/path_helper.get_ml_models_dir()`).
    - Signatures/intel: `AI/signature_distribution.py` → `relay/training_sync_api.py` (downloads signatures, reputation feeds, and trend stats; merges into local JSON surfaces).
- **Training data boundaries:**
    - Raw training datasets and history stay under `relay/ai_training_materials/` (for example `global_attacks.json`, `training_datasets/`, `reputation_data/`) and are never pulled to customer nodes.
    - Customer nodes expose only their **sanitized** summaries and patterns to the relay; all enforcement decisions remain local.

**Stage 6 → Stage 7 Transition:**
1. Customer nodes push training materials to relay (every hour) → relay stores in `ai_training_materials/`
2. Relay aggregates data from all customer nodes worldwide:
   - Signatures merged into `learned_signatures.json` (deduplicated)
   - Attack records appended to `global_attacks.json` (grows continuously, rotates at 100MB)
   - Reputation data consolidated into `reputation_data/`
3. Aggregated dataset triggers Stage 7 retraining (weekly) → new models trained → distributed back to customers
4. **Critical:** `global_attacks.json` uses `AI/file_rotation.py` - ML training reads ALL rotation files (`global_attacks.json`, `global_attacks_1.json`, etc.) to preserve complete training history

---

### Stage 7: Continuous Learning Loop

**README:** "🔄 CONTINUOUS LEARNING → Signature updates → ML retraining → Reputation decay → Drift refresh"

**Implementation:**

**Hourly:** Signature auto-update
- **Module:** `AI/signature_distribution.py`
- **Action:** Pull new signatures from relay → merge into local database

**Weekly:** ML model retraining
- **Module:** `relay/ai_retraining.py`
- **Process:**
  1. Read `global_attacks.json` + `learned_signatures.json`
  2. Extract features → `training_datasets/attacks_features.csv`
  3. Train RandomForest/IsolationForest/GradientBoosting
  4. Store updated models → `ai_training_materials/ml_models/*.pkl`
  5. Push to relay API for global distribution
- **Optional:** `relay/gpu_trainer.py` for LSTM/autoencoder (GPU-accelerated)

**Daily:** Reputation decay
- **Module:** `AI/reputation_tracker.py`
- **Algorithm:** Half-life decay (30 days) → old attacks fade gradually

**Monthly:** Drift baseline refresh
- **Module:** `AI/drift_detector.py`
- **Trigger:** KS test p-value < 0.05 → schedule retraining
- **Action:** Update `drift_baseline.json` to current traffic distribution

**Continuous:** Byzantine validation
- **Module:** `AI/byzantine_federated_learning.py`
- **Accuracy:** 94% malicious update rejection
- **Logging:**
  - Local: `server/json/comprehensive_audit.json` (THREAT_DETECTED events)
  - Relay: `relay/ai_training_materials/global_attacks.json` (`attack_type="federated_update_rejected"`)

**Feedback Sources:**
- **Honeypot:** 100% confirmed attacks (highest quality training)
- **Human Validation:** SOC analyst confirms/rejects → ML improvement
- **False Positive Reports:** Whitelist updates → FP filter tuning

**Stage 7 → Stage 1 Feedback Loop (Completes the 7-Stage Cycle):**
1. Relay retrains models using aggregated data → new `*.pkl` and `*.keras` models created
2. Models pushed to relay API → `relay/training_sync_api.py` serves updated models
3. Customer nodes pull updates (every 6 hours) via `AI/training_sync_client.py` (models) and `AI/signature_distribution.py` (signatures/intel):
    - `AI/training_sync_client.py` downloads ONLY pre-trained ML models into the ML models directory returned by `AI/path_helper.get_ml_models_dir()`
    - `AI/signature_distribution.py` downloads new signatures and threat-intel bundles and merges them into the local signature and reputation stores
    - `AI/byzantine_federated_learning.py` validates model updates (94% malicious rejection rate)
4. Updated models loaded by Stage 2 detection signals → **improved accuracy for next packet analysis in Stage 1**
5. Cycle repeats: better detection → more accurate training data → better models → better detection...

**This continuous feedback loop enables the system to adapt to evolving threats without manual intervention.**

---

### Identity, Access, HA & Support Flows

> These flows implement the enterprise-ready capabilities around identity, access control, high availability, and basic operational support. They sit alongside the 7-stage detection pipeline and govern who can access the dashboard, how admin actions are authorized, and how nodes behave in clustered deployments.

#### Admin Identity & Access Control

**Local admin store (server/json/admin_users.json)**
- Single JSON file containing dashboard admin accounts.
- Each entry includes: `username`, salted password hash, `role` (for example `admin` or `analyst`), and optional `auth_backend` (for example `local` or `ldap`).
- Passwords are hashed; there are no plaintext passwords in the repo.

**Zero Trust identity config (server/json/identity_access_config.json)**
- Single source of truth for admin identity posture and Zero Trust toggles.
- Controls:
    - Whether TOTP MFA is required for admin login.
    - LDAP/AD backend settings (server URL, user DN template, bind options).
    - OIDC SSO settings (authorization/token endpoints, JWKS URI, issuer, client ID/secret, redirect URI, allowed algorithms).
- Used by helper functions in server/server.py to decide which authentication backends are active and how tokens are validated.

**Authentication backends (server/server.py)**
- **Local:** Default when `auth_backend` is missing or `local`; checks username + salted password hash from admin_users.json.
- **LDAP/AD:** Enabled when an admin has `auth_backend: "ldap"` and identity_access_config.json has `ldap_enabled` plus required LDAP settings. Password verification happens via LDAP bind (no LDAP groups/roles are pulled).
- **OIDC SSO:** Enabled when identity_access_config.json has `oidc_enabled=true` and minimal OIDC fields set. The server:
    - Performs an authorization-code flow against the configured IdP.
    - Fetches JWKS from the provider (when RS256 or similar is used).
    - Verifies ID token signature, issuer (`iss`), and audience (`aud`) against identity_access_config.json.
    - Optionally falls back to HS256 using `oidc_client_secret` if JWKS is not available and HS256 is explicitly configured.
    - Maps the resulting identity to an existing admin user based on configured claim (for example email/UPN).

**MFA & Zero Trust hooks**
- If MFA is required in identity_access_config.json, admin logins must present a valid TOTP code in addition to password/SSO.
- Zero Trust and UEBA signals from AI/user_tracker.py and AI/zero_trust.py are independent of admin auth but can be surfaced together in the dashboard's identity panel.

**RBAC enforcement**
- Sensitive routes in server/server.py (for example IP blocking/whitelisting, config export/import, compliance export, support portal) are protected with a `require_role('admin', 'analyst', ...)` decorator.
- The decorator reads the current admin session (username/role) and denies access if the role does not match.

#### High Availability & Cluster Behavior

**Cluster configuration (server/json/cluster_config.json)**
- Describes how a node participates in a cluster:
    - `cluster_name`, `node_id` – logical cluster and node identity.
    - `role` – `active`, `passive`, or `standalone`.
    - `peer_nodes` – list of peer base URLs used by the passive node to probe the active.
    - `failover_check_interval_seconds`, `failover_unhealthy_threshold` – how often to probe peers and how many failures trigger promotion.
    - `config_sync_paths`, `config_sync_interval_seconds` – which JSON surfaces are synchronized from the active node and how often.

**Health endpoint (/health)**
- Implemented in server/server.py and backed by pcs_ai.get_threat_statistics().
- Returns a minimal JSON payload with:
    - `status` (`ok` or `error`).
    - `node_id`, `cluster_name`, and current `role` from cluster_config.json.
    - A timestamp.
    - Compact `threat_counters` (for example total_threats_detected, blocked_requests, active_attacks).
- Designed to be safe for frequent polling by load balancers and passive nodes.

**Config snapshot endpoint (/cluster/config/snapshot)**
- Active-node-only route that returns a JSON snapshot of selected config surfaces to passive nodes.
- Only includes files listed in `config_sync_paths` in cluster_config.json; `cluster_config.json` itself is intentionally excluded to avoid split-brain.
- Files are returned as a `{ "files": { "relative_name": <loaded JSON>, ... } }` map.

**Passive-node background manager**
- A background task in server/server.py periodically:
    - Calls `/health` on the preferred active peer.
    - Tracks consecutive failures; when the unhealthy threshold is crossed, promotes the local node from `passive` to `active` by updating cluster_config.json.
    - On a healthy active response, calls `/cluster/config/snapshot` and writes any listed files into the local json/ directory to keep configs in sync.

These behaviors are intentionally conservative: they assume an external load balancer or operator will handle traffic routing to the new active node.

#### Compliance & Reporting Surfaces (Recap)

Identity and HA changes do not alter the core compliance or reporting modules, but they do affect who can trigger and download reports:
- AI/compliance_reporting.py generates PCI/HIPAA/GDPR/SOC2 JSON under server/json/compliance_reports/ and powers `/api/compliance/...` endpoints surfaced in Dashboard Section 12.
- server/report_generator.py and `/inspector/ai-monitoring/export` provide HTML/JSON exports for enterprise-style reports.
- Access to these export surfaces is governed by the same admin auth and RBAC stack described above.

#### Local Support Portal

**Portal UI (/support)**
- HTML support portal implemented in server/server.py and protected by `require_role('admin', 'analyst')`.
- Allows admins/analysts to create local support tickets with `subject`, `description`, `severity` and automatically records `created_by` (current admin) and `created_at` timestamp.

**Ticket storage (server/json/support_tickets.json)**
- JSON document with a `tickets` array of ticket objects.
- server/server.py helpers `_load_support_tickets()` and `_save_support_tickets()` manage this file; errors are logged but do not crash the server.

**Support APIs**
- `/api/support/tickets` (GET) – list of recent tickets for authenticated admins.
- `/api/support/tickets/<ticket_id>/status` (POST) – update a ticket's status (for example open → in_progress → closed).
- These APIs are local-only helpers; there is no external 24/7 support integration or contractual SLA system.

Together, these identity, HA, and support flows define how operators securely access and manage the system around the 7-stage detection pipeline without affecting the privacy guarantees of the attack data path.

---

## 2. Dashboard Architecture: UI → API → AI Modules

**Dashboard:** `AI/inspector_ai_monitoring.html` (core first-layer sections)
**Server:** `server/server.py` (Flask application with REST APIs)

### Section Mapping (Selected Examples)

| Section | Dashboard Area | API Endpoint | AI Modules |
|---------|----------------|--------------|------------|
| 1 | **AI Training Network** | `/api/p2p/status`, `/api/relay/status`, `/api/p2p/threats` | `AI/p2p_sync.py`, `AI/byzantine_federated_learning.py` |
| 2 | **Network Devices** | `/api/connected-devices`, `/api/device-history`, `/api/current-ports` | `server/device_scanner.py`, `AI/asset_inventory.py` |
| 3 | **VPN/Tor De-Anonymization** | *(internal: `pcs_ai.get_vpn_tor_statistics()`)* | `AI/pcs_ai.py` (VPN/Tor tracking) |
| 4 | **Real AI/ML Models** | `/api/stats`, `/api/layer-stats` | `AI/pcs_ai.py`, `AI/cryptographic_lineage.py` |
| 5 | **Security Overview** | `/api/stats` | `AI/pcs_ai.py`, `AI/meta_decision_engine.py` |
| 7 | **IP Management** | `/api/threat_log`, `/api/whitelist`, `/api/stats` | `AI/reputation_tracker.py`, `AI/threat_intelligence.py` |
| 14 | **Attack Chain (Graph)** | `/api/graph-intelligence/attack-chains` | `AI/graph_intelligence.py` |
| 15 | **Explainability** | `/api/explainability/decisions` | `AI/explainability_engine.py` |
| 16 | **Real Honeypot Services** | `/api/adaptive_honeypot/status`, `/api/adaptive_honeypot/attacks`, `/api/honeypot/status` | `AI/real_honeypot.py` |
| 17 | **Traffic Analysis** | `/api/traffic/analysis` | `AI/traffic_analyzer.py`, `AI/tls_fingerprint.py` |
| 18 | **DNS & Geo Security** | `/api/dns/stats`, `/api/visualization/geographic` | `AI/dns_analyzer.py` |
| 31 | **Governance & Emergency** | `/api/killswitch/status`, `/api/governance/audit` | `AI/emergency_killswitch.py`, `AI/policy_governance.py` |

**Data Flow:**
```
Dashboard JavaScript fetch('/api/...') 
  → server/server.py Flask route 
  → AI module function call 
  → JSON file read/write (server/json/) 
  → Response JSON 
  → Dashboard UI update
```

**Honeypot Deployment Note:**
- The real honeypot runs a fixed set of TCP services on ports `2222, 2121, 2323, 8080, 3306, 2525, 3389` for SSH/FTP/Telnet/HTTP Admin/MySQL/SMTP/RDP deception.
- On any node where one of these ports is already occupied by a legitimate service, the corresponding honeypot service **automatically skips startup** instead of attempting to rebind or move to a different port.
- This behavior is surfaced via `/api/adaptive_honeypot/status` and `/api/honeypot/status`: each service includes a `running` flag so operators can see exactly which honeypot ports are active on that host.

---

## 3. File Structure & Path Conventions

### Docker Paths (Production)
```
/app/                               # Container root
├── json/                          # Runtime JSON data (mounted from server/json/)
│   ├── threat_log.json
│   ├── comprehensive_audit.json
│   ├── decision_history.json
│   ├── reputation.db
│   └── ...
├── ml_models/                     # Runtime ML models directory (resolved by AI/path_helper.get_ml_models_dir)
│   ├── threat_classifier.pkl
│   ├── anomaly_detector.pkl
│   ├── ip_reputation.pkl
│   ├── feature_scaler.pkl
│   ├── sequence_lstm.keras
│   └── traffic_autoencoder.keras
├── crypto_keys/                   # HMAC keys for relay auth
└── relay/ai_training_materials/   # Relay-only (NOT in customer containers)
    ├── global_attacks.json
    ├── ai_signatures/
    ├── reputation_data/
    ├── ml_models/
    └── training_datasets/
```

### Native Development Paths
```
battle-hardened-ai/
├── server/
│   ├── json/                      # Runtime JSON (.gitignored)
│   └── crypto_keys/
├── AI/
│   ├── adaptive_honeypot.py
│   ├── pcs_ai.py
│   └── ...
└── relay/                         # Operator infrastructure only
    ├── ai_training_materials/
    └── ...
```

### Path Helper Quick Reference (AI/path_helper)

**Core paths for AI modules:**
- `get_json_dir()` → Base JSON directory (`server/json/` native, `/app/json/` Docker)
- `get_json_file(name)` → Absolute path to JSON file (e.g., `get_json_file("threat_log.json")`)
- `get_threat_log_file()` → Canonical threat log path
- `get_ml_models_dir()` → ML models directory (`AI/ml_models/` or `/app/ml_models/`)
- `get_relay_training_dir()` → Relay training export root (`relay/ai_training_materials/`)

**Key relay subdirectories:**
- `global_attacks.json` — Central attack log (relay writes, Stage 7 reads)
- `ai_signatures/learned_signatures.json` — Global signature database
- `reputation_data/` — Hashed reputation exports
- `training_datasets/` — Feature tables and anonymized graphs
- `ml_models/` — Trained models for distribution

---

## 4. Privacy & Security Guarantees

### Data Residency
✅ **Customer JSON stays local by default**
- All runtime JSON (`threat_log.json`, device lists, decision history, etc.) written to `server/json/`
- No silent uploads to third-party cloud services
- Relay is **your own infrastructure** (cloud VM, dedicated server, or on-premises), not a vendor service

✅ **Relay is operator-controlled infrastructure**
- `relay/` folder deployed only on infrastructure you operate
- Customers receive only `server/` + `AI/` (never `relay/`)
- Relay training materials inaccessible to customers

### Data Minimization
✅ **Privacy-preserving extraction (Stage 5)**
- IP addresses hashed (SHA-256) before relay transmission
- No raw exploit payloads or packet content
- PII/PHI never retained
- Only sanitized training summaries shared via `AI/relay_client.py`

### Auditability
✅ **Centralized external communication**
- Relay client/sync modules: `AI/relay_client.py`, `AI/training_sync_client.py`, `AI/central_sync.py`
- All outbound data flows documented and reviewable
- HMAC authentication: `AI/crypto_security.py`, `server/crypto_keys/`

### Compliance
✅ **GDPR/HIPAA/PCI-DSS ready**
- `AI/compliance_reporting.py` generates audit reports
- Configurable data retention policies
- Right-to-erasure support (IP reputation decay)
- Minimal data retention (no unnecessary logs)

---

## 5. Developer Guidelines: Adding New Detections

### Single Source of Truth Pattern
1. **New detection logic goes in `AI/pcs_ai.py`**
2. **Convert detection to `DetectionSignal` object**
3. **Route through `AI/false_positive_filter.py`** (multi-gate validation)
4. **Feed into `AI/meta_decision_engine.py`** (ensemble voting)

### Example: Adding Signal #19 (Causal Inference) & Signal #20 (Trust Degradation)

**Note:** Signals 19 and 20 are strategic intelligence layers with dual roles: they participate in weighted voting (like signals 1-18) AND provide strategic modulation by analyzing outputs from all signals (1-20). The following snippets are **conceptual examples**; the live implementation uses `DetectionSignal` objects (types `CAUSAL_INFERENCE` and `TRUST_DEGRADATION`) plus the meta engine API `make_decision(signals, ip_address, endpoint)` as described in Stage 2/3 above.

```python
# In AI/causal_inference.py (new module)

from enum import Enum
from typing import List, Dict, Any

class CausalLabel(Enum):
    LEGITIMATE_CAUSE = "legitimate_cause"
    MISCONFIGURATION = "misconfiguration"
    AUTOMATION_SIDE_EFFECT = "automation_side_effect"
    EXTERNAL_ATTACK = "external_attack"
    INSIDER_MISUSE = "insider_misuse"
    UNKNOWN_CAUSE = "unknown_cause"

class CausalInferenceEngine:
    def analyze_root_cause(self, signals: List[DetectionSignal], event: Dict[str, Any]) -> CausalInferenceResult:
        """Determine WHY an event happened using causal graphs."""
        # Build causal graph
        recent_config_changes = self._get_recent_config_changes()
        recent_deployments = self._get_recent_deployments()
        identity_events = self._get_recent_identity_events()
        
        # Test counterfactuals
        if self._temporal_correlation(event, recent_deployments, window=120):  # 2 minutes
            return CausalInferenceResult(
                causal_label=CausalLabel.LEGITIMATE_CAUSE,
                confidence=0.89,
                primary_causes=["CI/CD deployment 2 min before anomaly"],
                non_causes=["External IP", "Attack pattern"]
            )
        
        if not recent_config_changes and not recent_deployments:
            if any(s.signal_type == SignalType.THREAT_INTEL and s.is_threat for s in signals):
                return CausalInferenceResult(
                    causal_label=CausalLabel.EXTERNAL_ATTACK,
                    confidence=0.91,
                    primary_causes=["No config change", "External IP with prior reputation"],
                    non_causes=["Scheduled maintenance"]
                )
        
        return CausalInferenceResult(
            causal_label=CausalLabel.UNKNOWN_CAUSE,
            confidence=0.50,
            primary_causes=[],
            non_causes=[]
        )

# In AI/trust_graph.py (new module)

from enum import Enum

class EntityType(Enum):
    IP_ADDRESS = "ip"
    DEVICE = "device"
    ACCOUNT = "account"
    SERVICE = "service"

class TrustDegradationGraph:
    def __init__(self):
        self.trust_scores = {}  # {entity_id: trust_score}
        self.trust_history = {}  # {entity_id: [(timestamp, score, reason)]}
        
    def get_trust_score(self, entity_id: str, entity_type: EntityType) -> int:
        """Get current trust score (0-100) for entity."""
        if entity_id not in self.trust_scores:
            # Initial trust
            if entity_type == EntityType.IP_ADDRESS:
                # Internal vs external detection logic
                return 100 if self._is_internal_ip(entity_id) else 60
            return 100  # Devices, accounts start at 100
        return self.trust_scores[entity_id]
    
    def degrade_trust(self, entity_id: str, event_severity: str, reason: str) -> TrustStateUpdate:
        """Apply trust degradation based on event."""
        previous_trust = self.get_trust_score(entity_id, EntityType.IP_ADDRESS)
        
        # Event-weighted penalties
        penalties = {
            "minor_anomaly": 5,
            "confirmed_attack": 25,
            "lateral_movement": 30,
            "integrity_breach": 40
        }
        penalty = penalties.get(event_severity, 10)
        
        current_trust = max(0, previous_trust - penalty)
        self.trust_scores[entity_id] = current_trust
        
        # Determine recommended action
        if current_trust >= 80:
            action = "NORMAL"
        elif current_trust >= 60:
            action = "INCREASED_MONITORING"
        elif current_trust >= 40:
            action = "RATE_LIMIT"
        elif current_trust >= 20:
            action = "ISOLATE"
        else:
            action = "QUARANTINE"
        
        return TrustStateUpdate(
            entity_id=entity_id,
            entity_type=EntityType.IP_ADDRESS,
            previous_trust=previous_trust,
            current_trust=current_trust,
            reason=[reason],
            recommended_action=action
        )
    
    def recover_trust(self, hours_without_incident: int = 24):
        """Slow trust recovery (+1 per 24h)."""
        for entity_id in self.trust_scores:
            if hours_without_incident >= 24:
                # Cap recovery at initial baseline
                max_trust = 100 if self._is_internal(entity_id) else 60
                self.trust_scores[entity_id] = min(max_trust, self.trust_scores[entity_id] + 1)

# In AI/pcs_ai.py (update assess_threat method)

def assess_threat(self, event):
    """Main orchestration (existing method with Layer 19 & 20 integration)."""
    signals = []
    
    # Existing signals 1-18...
    
    # Route through FP filter
    filtered_signals = self.fp_filter.filter(signals, event)
    
    # NEW: Layer 19 - Causal Inference
    causal_result = self.causal_engine.analyze_root_cause(filtered_signals, event)
    
    # NEW: Layer 20 - Trust Degradation
    entity_trust = self.trust_graph.get_trust_score(event["src_ip"], EntityType.IP_ADDRESS)
    
    # Ensemble decision (with Layer 19 & 20 modulation)
    decision = self.meta_engine.make_decision(
        filtered_signals, 
        event, 
        causal_result=causal_result,
        entity_trust=entity_trust
    )
    
    # Update trust graph if threat detected
    if decision.should_block:
        trust_update = self.trust_graph.degrade_trust(
            event["src_ip"], 
            "confirmed_attack",
            f"Ensemble score: {decision.confidence}"
        )
        # Log trust update
        self._log_trust_update(trust_update)
    
    # Log causal analysis
    self._log_causal_analysis(causal_result)
    
    return decision
```
```python
# In AI/pcs_ai.py

def _get_new_signal_score(self, event):
    """New detection logic (e.g., protocol anomaly)."""
    score = ... # Your detection algorithm
    confidence = ... # How confident you are (0.0-1.0)
    return score, confidence

def assess_threat(self, event):
    """Main orchestration (existing method)."""
    signals = []
    
    # Existing signals 1-18...
    
    # NEW: Signal #19
    score, confidence = self._get_new_signal_score(event)
    signals.append(DetectionSignal(
        signal_type=SignalType.NEW_SIGNAL,
        is_threat=(score > threshold),
        confidence=confidence,
        details={"score": score, "reason": "protocol_anomaly"}
    ))
    
    # Route through FP filter
    filtered_signals = self.fp_filter.filter(signals, event)
    
    # Ensemble decision
    decision = self.meta_engine.make_decision(filtered_signals, event)
    
    return decision
```

### Updating Meta Decision Engine
```python
# In AI/meta_decision_engine.py

class SignalType(Enum):
    # Existing signals 1-18...
    NEW_SIGNAL = 19  # Add new enum value

def __init__(self):
    self.signal_weights = {
        # Existing weights...
        SignalType.NEW_SIGNAL: 0.80,  # Set weight (0.65-0.98 range)
    }
```

### Path Conventions
- **JSON output:** Use `server/json/new_signal_data.json` (auto-created at runtime)
- **Models:** All ML models (classical .pkl + deep learning .keras) → ML models directory from `AI/path_helper.get_ml_models_dir()`
- **Config:** Tunable parameters → `server/json/new_signal_config.json`

### Testing Checklist
- [ ] Signal fires independently in Stage 2
- [ ] FP filter gates work correctly
- [ ] Ensemble voting includes signal with correct weight
- [ ] Dashboard displays signal contribution (Section 4/15)
- [ ] Relay receives sanitized signal data (Stage 6)
- [ ] Documentation updated (README, Ai-instructions.md, Dashboard.md, Filepurpose.md)

---

## 6. Performance Considerations

### Real-Time Path (Latency-Critical)
**Goal:** Packet → Decision in <100ms

**Optimization Tips:**
- Batch ML inference where possible
- Use in-memory caching for reputation lookups
- Defer heavy analytics to background threads
- Keep `assess_threat()` pipeline synchronous and fast

### Background Analytics (Throughput-Optimized)
**Suitable for:**
- Graph topology computation
- LSTM sequence modeling (can lag by seconds)
- Forensic report generation
- Compliance report creation

### Model Loading
- **Lazy loading:** Load models on first use (not at startup)
- **Shared models:** Use singleton pattern for ML models
- **Model caching:** Keep loaded models in memory (don't reload per packet)

---

## 7. Common Pitfalls & Solutions

### Pitfall 1: Hardcoded Paths
❌ **Wrong:** `open("/home/user/server/json/threat_log.json")`
✅ **Correct:** Use environment-aware path resolution
```python
import os
json_dir = os.getenv('JSON_DIR', 'server/json')
threat_log_path = os.path.join(json_dir, 'threat_log.json')
```

### Pitfall 2: Whitelist Bypassing Honeypot
❌ **Wrong:** Whitelisted IPs bypass all detection (including honeypot)
✅ **Correct:** Honeypot hits are authoritative (never whitelisted)
```python
# In AI/false_positive_filter.py
if signal.signal_type == SignalType.HONEYPOT and signal.confidence >= 0.7:
    # NEVER suppress honeypot signals
    return True  # Always pass Gate 1
```

### Pitfall 3: Signal Weight Misconfiguration
❌ **Wrong:** All signals weighted equally
✅ **Correct:** Weight reflects signal reliability
```python
# Honeypot: 0.98 (direct attacker interaction)
# ML models: 0.75-0.85 (probabilistic)
# Drift: 0.65 (warning, not conclusive)
```

### Pitfall 4: Ignoring APT Mode
❌ **Wrong:** Always using 75% block threshold
✅ **Correct:** Check `APT_DETECTION_MODE` environment variable
```python
if os.getenv('APT_DETECTION_MODE') == 'true':
    block_threshold = 0.70
else:
    block_threshold = 0.75
```

### Pitfall 5: Dashboard API Shape Mismatch
❌ **Wrong:** Changing API response without updating dashboard JavaScript
✅ **Correct:** Maintain consistent API contracts or version endpoints
```python
# server/server.py
@app.route('/api/threats/summary')
def threats_summary():
    return {
        "total_threats": ...,
        "blocked": ...,
        "logged": ...,
        # NEVER remove fields without updating inspector_ai_monitoring.html
    }
```

---

## 8. Quick Reference

### Key Modules by Stage
- **Stage 1:** `server/network_monitor.py`, `AI/kernel_telemetry.py`, `AI/system_log_collector.py`
- **Stage 2:** `AI/pcs_ai.py` (orchestrator), all 20 detection modules plus the Step 21 semantic gate:
    - All signals 1-20 (see Section 1 table for complete list)
    - Includes strategic intelligence: `AI/causal_inference.py` (Layer 19), `AI/trust_graph.py` (Layer 20)
    - Step 21 semantic execution-denial gate: `AI/step21_semantic_gate.py` (post-ensemble, pre-action)
- **Stage 3:** `AI/meta_decision_engine.py`, `AI/false_positive_filter.py`, Layer 19 & 20 modulation
- **Stage 4:** `server/device_blocker.py`, `AI/alert_system.py`, `AI/file_rotation.py` (logging infrastructure)
- **Stage 5:** `AI/signature_extractor.py`, `AI/reputation_tracker.py`, `AI/graph_intelligence.py` (extraction)
- **Stage 6:** `AI/relay_client.py`, `AI/signature_uploader.py`, `relay/relay_server.py`, `relay/signature_sync.py`
- **Stage 7:** `relay/ai_retraining.py`, `relay/gpu_trainer.py`, `AI/drift_detector.py`, `AI/signature_distribution.py` (pulls updates)

### Critical JSON Files
- `threat_log.json` — Primary threat log (Stage 4 output) *(rotates at 100MB, ML reads all rotation files)*
- `comprehensive_audit.json` — All THREAT_DETECTED/INTEGRITY_VIOLATION events *(rotates at 100MB)*
- `decision_history.json` — Ensemble voting records (Stage 3)
- `reputation.db` — SQLite cross-session reputation (Stage 2 signal #14)
- `meta_engine_config.json` — Signal weights (Stage 3 configuration)
- `global_attacks.json` — Relay central attack log (Stage 6) *(rotates at 100MB on relay server, using the same file_rotation policy)*
- `honeypot_patterns.json` — Customer-side signature staging (Stage 5)
- `network_graph.json` — Graph topology (Stage 2 signal #10, Stage 5 extraction)
- `behavioral_metrics.json` — Per-IP heuristics (Stage 2 signal #6, Stage 5 extraction)
- `causal_analysis.json` — **Layer 19: Root cause analysis results (Stage 3 strategic intelligence)**
- `trust_graph.json` — **Layer 20: Entity trust state tracking (persistent, survives restarts)**

**File Rotation:** See `AI/file_rotation.py` and `ML_LOG_ROTATION.md` - rotation files (`*_1.json`, `*_2.json`, etc.) are never deleted, ensuring ML training has complete attack history.

### Environment Variables
- `APT_DETECTION_MODE=true` — Lower block threshold to 70%
- `BLOCK_THRESHOLD=0.65` — Custom threshold override
- `AUTO_KILLSWITCH_ON_INTEGRITY=true` — SAFE_MODE on integrity violations
- `JSON_DIR=/app/json` — Docker JSON path override
- `TZ=America/New_York` — Timezone for off-hours APT detection

---

## 9. Testing & Validation Guide (10-Stage Progressive Validation)

This section provides a comprehensive testing guide for all **21 detection layers** in the Battle-Hardened AI system (20 detection signals + 1 semantic gate), organized by the 7-stage attack detection pipeline + 3 extended validation stages.

**Testing validates end-to-end flow:**
- Each signal fires → local JSON + dashboard updates
- Relay server receives sanitized intelligence (when enabled)
- Ensemble decision engine produces correct verdicts (block/log/allow)

**Testing Status Legend:**
- [ ] Not tested yet
- [x] Tested and verified (local + relay logs confirmed)

> **Testing Rule:** Mark as tested ONLY after verifying: local JSON files, dashboard UI display, and relay server logs (if applicable).

### 9.1 Testing Strategy Overview

Tests follow the same **7-stage pipeline** from the README, plus 3 additional validation stages. Each stage builds on previously verified infrastructure:

**Stages 1-7 mirror the README's attack detection pipeline.** Each validates one major pipeline component:

**Core Pipeline Stages (README Flow)**

**Stage 1: Data Ingestion & Normalization**
- **Test:** HMAC/key setup, relay connectivity, packet capture
- **Goal:** Verify network_monitor captures traffic → normalizes metadata → feeds into detection signals
- **Validates README:** "Stage 1: Data Ingestion & Normalization" (packet capture, metadata extraction)

**Stage 2: Parallel Multi-Signal Detection (20 Signals + Step 21 Semantic Gate)**
- **Test:** Core detection pipeline (18 primary signals: signatures, ML models, behavioral, LSTM, autoencoder, drift, graph, VPN/Tor, threat intel, FP filter, reputation, explainability, predictive, Byzantine, integrity) + 2 strategic intelligence layers (causal inference, trust degradation) + Step 21 semantic execution-denial gate
- **Goal:** All 20 signals fire independently → produce threat assessments → visible in local JSON; Step 21 gate must consistently deny execution meaning for semantically invalid requests
- **Validates README:** "Stage 2: Parallel Multi-Signal Detection" (20 detection systems: 18 primary + 2 strategic) plus the Step 21 semantic gate (21st detection layer)

**Stage 3: Ensemble Decision Engine (Weighted Voting)**
- **Test:** Meta-decision engine combines signals → weighted consensus → threshold decisions (block/log/allow)
- **Goal:** Verify ensemble voting calculation → authoritative boosting → consensus checks → final verdict in threat_log.json
- **Validates README:** "Stage 3: Ensemble Decision Engine" (weighted voting, 75% block threshold, APT mode 70%)

**Stage 4: Response Execution (Policy-Governed)**
- **Test:** Automated responses (firewall blocks, connection drops, rate limiting, logging, alerts)
- **Goal:** Verify policy-governed actions execute → local logging → dashboard updates → alert delivery
- **Validates README:** "Stage 4: Response Execution" (immediate actions, logging, alerts)

**Stage 5: Training Material Extraction (Privacy-Preserving)**
- **Test:** Honeypot-to-signature pipeline, attack pattern extraction, behavioral statistics, reputation updates, graph topology anonymization
- **Goal:** Verify high-confidence attacks → sanitized training materials (no payloads/PII) → stored locally
- **Validates README:** "Stage 5: Training Material Extraction" (signatures, statistics, reputation, graph patterns, model weights)

**Stage 6: Global Intelligence Sharing (Optional Relay)**
- **Test:** Relay push/pull, signature distribution, model updates, Byzantine validation, global reputation feeds
- **Goal:** Verify local findings → relay server → global_attacks.json + learned_signatures.json → other nodes pull updates
- **Validates README:** "Stage 6: Relay Sharing" (push/pull protocol, global intelligence, privacy-preserving federation)

**Stage 7: Continuous Learning Loop**
- **Test:** Signature extraction, ML retraining, reputation decay, drift baseline updates, Byzantine validation, feedback integration
- **Goal:** Verify system improves over time → models retrain weekly → baselines adapt → false positives decrease
- **Validates README:** "Stage 7: Continuous Learning" (automated improvement, feedback mechanisms)

**Validation Stages (Extended Testing)**

**Stage 8: Explainability, Visualization & Dashboard**
- **Test:** Decision explanations, advanced visualizations (topology/heatmaps/geo), dashboard API endpoints, error handling
- **Goal:** Verify UI correctly reflects all pipeline stages → API failures logged as `SYSTEM_ERROR` events

**For every stage:** Validate complete flow → **trigger → local JSON → dashboard → relay JSON** (Logging & Central Capture Checklist).

### 9.2 Quick Reference: 21 Detection Layers → Implementation Files

This maps each of the **21 active detection layers** from the README-aligned architecture to the concrete files/modules that implement or feed them (20 detection signals + 1 semantic gate).

1. **eBPF Kernel Telemetry**  
   Files: AI/kernel_telemetry.py; server/network_monitor.py; server/docker-compose.yml (Linux capabilities and host networking); AI/pcs_ai.py (orchestration and signal wiring).

2. **Signature Matching**  
   Files: AI/threat_intelligence.py; AI/signature_extractor.py; AI/signature_distribution.py; AI/signature_uploader.py; AI/pcs_ai.py; relay/signature_sync.py; relay/exploitdb_scraper.py; relay/threat_crawler.py; relay/ai_training_materials/ai_signatures/; relay/ai_training_materials/exploitdb/.

3. **RandomForest (supervised classifier)**  
    Files: AI/pcs_ai.py (loads and uses RF pickles); AI/ml_models/ (seed RandomForest model pickles such as threat_classifier.pkl, anomaly_detector.pkl) and the runtime ML directory from AI/path_helper; relay/ai_retraining.py (trains and exports updated RF models to relay/ai_training_materials/ml_models/); relay/gpu_trainer.py (optional GPU training backend).

4. **IsolationForest (unsupervised anomaly)**  
    Files: AI/pcs_ai.py; AI/ml_models/anomaly_detector.pkl (or corresponding runtime ML directory); relay/ai_retraining.py; relay/gpu_trainer.py.

5. **Gradient Boosting (reputation modeling)**  
    Files: AI/pcs_ai.py; AI/ml_models/ip_reputation.pkl (or corresponding runtime ML directory); relay/ai_retraining.py; relay/gpu_trainer.py.

6. **Behavioral Heuristics**  
   Files: AI/behavioral_heuristics.py; AI/pcs_ai.py (uses heuristic scores as detection signals); server/network_monitor.py (feeds per-IP events into the heuristics engine); server/json/behavioral_metrics.json (persistence, when enabled).

7. **LSTM (sequential kill-chain analysis)**  
    Files: AI/sequence_analyzer.py; AI/ml_models/sequence_lstm.keras (or corresponding runtime ML directory); AI/pcs_ai.py (calls sequence analysis); server/json/attack_sequences.json (sequence export, when enabled); relay/ai_retraining.py (may incorporate sequence history into retraining).

8. **Autoencoder (zero-day anomaly detection)**  
    Files: AI/traffic_analyzer.py; AI/ml_models/traffic_autoencoder.keras (or corresponding runtime ML directory); AI/network_performance.py; AI/pcs_ai.py; server/json/network_performance.json; relay/ai_retraining.py; relay/gpu_trainer.py.

9. **Drift Detection**  
   Files: AI/drift_detector.py; AI/pcs_ai.py (invokes drift checks and flags); server/json/drift_baseline.json; server/json/drift_reports.json; relay/ai_retraining.py (uses history/drift context for when to retrain).

10. **Graph Intelligence (lateral movement / C2)**  
    Files: AI/graph_intelligence.py; AI/advanced_visualization.py (renders graph outputs); AI/advanced_orchestration.py (can export topology/training views); AI/pcs_ai.py; server/json/network_graph.json; server/json/lateral_movement_alerts.json; relay/ai_training_materials/training_datasets/graph_topology.json.

11. **VPN/Tor Fingerprinting**  
    Files: AI/pcs_ai.py (get_vpn_tor_statistics, composite metadata-only Layer 11 signal, optional deanonymization payload generators); server/server.py (vpn_stats and DNS/TLS stats wiring into dashboard sections); server/json/threat_log.json (stores VPN/Tor-related attacker_intel entries); server/json/dns_security.json and server/json/tls_fingerprints.json (DNS/tunneling and TLS fingerprint metrics consumed by Layer 11).

12. **Threat Intelligence Feeds (OSINT correlation)**  
    Files: relay/threat_crawler.py; relay/exploitdb_scraper.py; relay/ai_training_materials/threat_intelligence/; relay/ai_training_materials/reputation_data/; AI/threat_intelligence.py; AI/reputation_tracker.py; AI/pcs_ai.py.

13. **False Positive Filter (multi-gate)**  
    Files: AI/false_positive_filter.py; AI/meta_decision_engine.py (consumes FP-filtered signals); AI/pcs_ai.py; server/json/decision_history.json (records final ensemble decisions and FP-filter outcomes).

14. **Historical Reputation**  
    Files: AI/reputation_tracker.py; AI/pcs_ai.py; server/json/reputation.db (SQLite DB backing for long-term reputation); relay/ai_training_materials/reputation_data/ (aggregated global reputation, when exported).

15. **Explainability Engine (decision transparency)**  
    Files: AI/explainability_engine.py; AI/pcs_ai.py; server/report_generator.py (uses explainability data for reports); server/json/forensic_reports/; relay/ai_training_materials/explainability_data/ (when full repo is present for training).

16. **Predictive Modeling (short-term threat forecasting)**  
    Files: AI/advanced_orchestration.py (ThreatPrediction logic and export to orchestration_data); AI/pcs_ai.py (can integrate forecast results into decisions); relay/ai_training_materials/orchestration_data/.

17. **Byzantine Defense (poisoned update rejection)**  
    Files: AI/byzantine_federated_learning.py; AI/training_sync_client.py; relay/ai_retraining.py; relay/gpu_trainer.py; relay/ai_training_materials/ml_models/ (aggregated models after Byzantine-safe updates); server/json/comprehensive_audit.json; relay/ai_training_materials/global_attacks.json (when relay is present).

18. **Integrity Monitoring (model & telemetry tampering)**  
    Files: AI/self_protection.py; AI/emergency_killswitch.py; AI/cryptographic_lineage.py; AI/crypto_security.py; AI/policy_governance.py; server/json/integrity_violations.json; server/json/comprehensive_audit.json and audit_archive/ (governance/integrity + cryptographic lineage audit trail); AI/pcs_ai.py (routes integrity/self-protection and lineage/drift signals into the ensemble).

**STRATEGIC INTELLIGENCE LAYERS (19-20):** Dual-role signals that vote AND modulate (participate in weighted voting, then apply context-aware adjustments)

19. **Causal Inference Engine (root cause analysis)**  
    Files: AI/causal_inference.py (585 lines, production-ready); AI/meta_decision_engine.py (_apply_causal_modulation method); server/json/causal_analysis.json (auto-rotates at 10,000 entries); AI/pcs_ai.py (integration point).  
    **Purpose:** Distinguishes legitimate operational changes from disguised attacks via causal graphs (not correlations) and counterfactual testing.  
    **Inputs:** DetectionSignal objects (1-18), deployment logs, config change events, identity events (login/privilege change), time-series metadata.  
    **Output:** CausalInferenceResult with causal_label (LEGITIMATE_CAUSE/MISCONFIGURATION/AUTOMATION_SIDE_EFFECT/EXTERNAL_ATTACK/INSIDER_MISUSE/UNKNOWN_CAUSE), confidence (0.0-1.0), primary_causes[], non_causes[], reasoning.  
    **Score Modulation:** Downgrade by -20% (legitimate), boost by +15% (attack), route to governance (misconfiguration), require human review (unknown).  
    **Position:** Runs AFTER signals 1-18, BEFORE final ensemble decision.  
    **Weight:** 0.88 (high reliability, context provides strong signal).  
    **Privacy:** Metadata-only analysis, no payloads/credentials/PII.

20. **Trust Degradation Graph (zero-trust entity tracking)**  
    Files: AI/trust_graph.py (422 lines, production-ready); AI/meta_decision_engine.py (_apply_trust_modulation method); server/json/trust_graph.json (persistent across restarts); AI/pcs_ai.py (integration point).  
    **Purpose:** Persistent memory prevents "try again later" strategies via non-linear trust degradation with permanent scarring (recovery capped at 80% of baseline).  
    **Tracked Entities:** IPs, devices, user accounts, services, APIs, cloud roles, containers (SHA-256 hashed).  
    **Trust Score:** 0-100 per entity, event-weighted penalties (minor_anomaly=-5 to repeated_attack=-50), natural recovery (+1/day capped at 80% baseline).  
    **Trust Thresholds & Actions (as implemented):** ≥80 (ALLOW), 60-79 (MONITOR, +5% score boost on ensemble vote), 40-59 (RATE_LIMIT, +10% score boost on ensemble vote), 20-39 (ISOLATE, +15% score boost; block once weighted vote ≥60%), <20 (QUARANTINE, force block regardless of ensemble score).  
    **Recidivism:** 3+ attacks in 7 days = exponential penalty.  
    **Position:** Influences Stage 4 response severity and contributes to the ensemble via `TRUST_DEGRADATION` signals tracked by explainability engine (Signal #15).  
    **Weight:** 0.90 (very high reliability, persistent memory prevents evasion).  
    **Privacy:** SHA-256 entity hashing, no PII, statistical scores only.

### 9.3 Relay Output Files by Stage (Summary)

This summarizes which **relay JSON files** are expected to receive events when each stage is exercised and relay is enabled:

- **Stage 1 – Plumbing & Relay Channel**  
  - `relay/ai_training_materials/global_attacks.json` — central attack/event log when a real signed attack message is sent through the HMAC channel.

- **Stage 2 – Core Detection & Scoring**  
  - `relay/ai_training_materials/global_attacks.json` — all elevated attacks from the core pipeline (including ML, VPN/Tor, DNS tunneling, TLS C2 once promoted by pcs_ai).
  - `relay/ai_training_materials/attack_statistics.json` — aggregated counts and trends computed from global_attacks.json.

- **Stage 3 – Deception & Honeypots**  
  - `relay/ai_training_materials/global_attacks.json` — honeypot-sourced attacks promoted to the global view.  
  - `relay/ai_training_materials/ai_signatures/learned_signatures.json` — privacy-preserving signatures and patterns derived from honeypot hits and ExploitDB (no raw exploits).

- **Stage 4 – Network, Devices & Behavioral Analytics**  
  - `relay/ai_training_materials/global_attacks.json` — network/behavioral/graph/DNS/TLS/zero‑trust violations once pcs_ai elevates them to attacks.  
  - `relay/ai_training_materials/attack_statistics.json` — updated statistics including these NDR and UEBA events.

- **Stage 5 – Threat Intelligence & Signatures**  
  - `relay/ai_training_materials/ai_signatures/learned_signatures.json` — central store for all normalized signatures.  
  - `relay/ai_training_materials/threat_intelligence/` — OSINT / feed JSONs maintained by crawlers.  
  - `relay/ai_training_materials/reputation_data/` — aggregated global reputation exports.  
  - `relay/ai_training_materials/global_attacks.json` — attacks enriched with intel/reputation context.

- **Stage 6 – Policy, Governance & Self-Protection**  
  - `relay/ai_training_materials/global_attacks.json` — policy violations and self‑protection events that the ensemble promotes as attacks.

- **Stage 7 – Cryptography, Lineage & Federated / Relay**  
  - `relay/ai_training_materials/global_attacks.json` — training/federation-related security incidents recorded as attacks.  
  - `relay/ai_training_materials/ai_signatures/learned_signatures.json` + `relay/ai_training_materials/global_attacks.json` — input training materials for `relay/ai_retraining.py`.

- **Stage 8 – Explainability, Visualization & Dashboard**  
    - No new relay files; reuses:  
        - `relay/ai_training_materials/global_attacks.json` — attacks already logged in earlier stages.  
        - `relay/ai_training_materials/ai_signatures/learned_signatures.json` — signatures already logged.  
  - Additional logging surface for this stage:  
    - `server/json/comprehensive_audit.json` — SYSTEM_ERROR events from dashboard/explainability/visualization APIs when those paths fail.

Use this as a quick cross-check when validating that a given stage's detections are visible both **locally** (server/json) and at the **relay** (ai_training_materials).

---

**For architecture overview, see:** [README.md](../../README.md) (7-stage pipeline with diagrams)

---

## Governance, Change Control & Step 21 Policy Management

Step 21 semantic policies are governed configuration, not ad-hoc code. This section defines how to manage policy changes safely.

- **Roles & Responsibility:** Step 21 semantic policies (roles, actions, structural rules) are treated as governed configuration, not ad-hoc code. Only designated security owners should modify these policies via approved change-control processes.
- **Monitor-Only vs Enforce:** Environments can operate Step 21 in monitor-only mode (log semantic violations without blocking) during initial rollout or policy updates, then transition to full enforcement after validation.
- **Staged Rollouts:** Policy changes should be staged (test -> pre-production -> production) with audit trails in configuration management and clear rollback procedures to avoid accidental denial of legitimate traffic.
- **Auditability:** Each semantic decision is explainable and logged; this allows reviewers to see which policy dimension (state, intent, structure, trust) caused a block and adjust policies accordingly.

**Governed Step 21 Flow:**

```text
     +-------------------+
     | policies/step21/*.json     |
     | (roles, actions, schemas,  |
     |  trust thresholds)         |
     +---------+---------+
               |
               v
     +-------------------+
     | Step 21 Semantic Gate       |
     | (enforced in AI/step21_*.py)|
     +---------+---------+
               |
     +---------+---------+
     |                   |
     v                   v
  Monitor-only       Enforce mode
  (log semantic      (log + block invalid
   violations)       execution requests)
```

---

## Known System Limitations & Edge Cases

While Battle-Hardened AI provides robust defense-in-depth detection, certain attack scenarios remain challenging:

- **Ultra-Low-and-Slow Attacks:** Extremely slow campaigns (e.g., one request per day) may require longer observation windows for clear statistical separation; detection still improves over time through trust degradation and graph intelligence but can be delayed.
- **Insiders with Strong Privileges:** Fully trusted insiders with valid credentials who behave very similarly to normal workloads are inherently hard to distinguish; network behavior is still monitored, but intent may be ambiguous.
- **Partial Visibility / Encrypted Traffic:** When deployed without access to decrypted application traffic, certain payload-centric techniques rely more heavily on behavioral, graph, and reputation signals rather than deep content inspection.
- **Degraded Signal Set:** If some models or signals are disabled, missing, or misconfigured, ensemble robustness decreases; the system degrades gracefully but with reduced redundancy. Operators should treat missing signals as a misconfiguration to fix, not a normal state.
- **Misconfigured Mirroring / SPAN:** Incorrect SPAN/TAP or routing can create blind spots; Battle-Hardened AI assumes that the traffic it sees is representative of the environment it is defending.

