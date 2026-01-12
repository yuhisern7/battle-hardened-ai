# AI System Architecture & Implementation Guide

> **Purpose:** Comprehensive technical guide for developers. Explains the 7-stage attack detection pipeline implementation, testing procedures, and compliance architecture across AI modules, server components, and relay infrastructure.

**Related Documentation:**
- **[README.md](README.md)** - Main documentation with architecture overview
- **[INSTALLATION.md](INSTALLATION.md)** - Complete installation guide
- **[relay/RELAY_SETUP.md](relay/RELAY_SETUP.md)** - Relay server deployment
- **[dashboard.md](dashboard.md)** - Dashboard API reference (31 sections)
- **[filepurpose.md](filepurpose.md)** - File organization by pipeline stage
- **[KALI_ATTACK_TESTS.md](KALI_ATTACK_TESTS.md)** - Attack testing commands

---

## Table of Contents

**PART I: ARCHITECTURE & IMPLEMENTATION**
- [0. Architecture Overview: 7-Stage Pipeline Visualization](#0-architecture-overview-7-stage-pipeline-visualization)
- [1. Pipeline Implementation Map: README Flow → Code Modules](#1-pipeline-implementation-map-readme-flow--code-modules)
  - [Stage 1: Data Ingestion & Normalization](#stage-1-data-ingestion--normalization)
  - [Stage 2: Parallel Multi-Signal Detection (20 Signals)](#stage-2-parallel-multi-signal-detection-20-signals)
  - [Stage 3: Ensemble Decision Engine (Weighted Voting)](#stage-3-ensemble-decision-engine-weighted-voting)
  - [Stage 4: Response Execution (Policy-Governed)](#stage-4-response-execution-policy-governed)
  - [Stage 5: Training Material Extraction (Privacy-Preserving)](#stage-5-training-material-extraction-privacy-preserving)
  - [Stage 6: Global Intelligence Sharing (Optional Relay)](#stage-6-global-intelligence-sharing-optional-relay)
  - [Stage 7: Continuous Learning Loop](#stage-7-continuous-learning-loop)
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
  - [9.2 Quick Reference: 20 Detection Signals → Implementation Files](#92-quick-reference-20-detection-signals--implementation-files)
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
│  STAGE 2: PARALLEL DETECTION (20 Signals = 18 Primary + 2 Strategic)         │
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
│  All signals produce: DetectionSignal(is_threat, confidence, details)        │
└──────────────────────────────────┬────────────────────────────────────────────┘
                                   │
                                   ▼
┌───────────────────────────────────────────────────────────────────────────────┐
│  STAGE 3: ENSEMBLE VOTING (meta_decision_engine.py)                          │
├───────────────────────────────────────────────────────────────────────────────┤
│  Step 1: Weighted Voting → Base score = Σ(weight × confidence × is_threat)  │
│  Step 2: Authoritative Boosting → Honeypot/ThreatIntel override             │
│  Step 3: Causal Modulation → Layer 19 adjusts score (-20% to +15%)          │
│  Step 4: Trust Modulation → Layer 20 adjusts threshold (60%-75%)            │
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
│  • Alert delivery (email/SMS/SOAR)                                            │
│  • Dashboard update                                                           │
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
│  STAGE 6: RELAY SHARING (Optional - VPS relay server)                        │
├───────────────────────────────────────────────────────────────────────────────┤
│  Client Node                     Relay Server (VPS)                           │
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

**Three deployment tiers:**

1. **Customer Node (server/ + AI/)** — Runs stages 1-5 locally, optionally connects to relay for stages 6-7
2. **AI Intelligence Layer (AI/)** — Implements all 20 detection signals and ensemble logic (stages 2-3)
3. **Central Relay (relay/)** — Operator-controlled training hub (stages 6-7, **NOT shipped to customers**)

---

## 1. Pipeline Implementation Map: README Flow → Code Modules

### Stage 1: Data Ingestion & Normalization

**README:** "📥 PACKET ARRIVES → 📊 Pre-processing (metadata extraction, normalization)"

**Implementation:**
- **Packet Capture:** `server/network_monitor.py` (eBPF/XDP or scapy-based)
- **Kernel Telemetry:** `AI/kernel_telemetry.py` (syscall correlation, Linux only)
- **System Logs:** `AI/system_log_collector.py` (auth logs, application logs)
- **Cloud APIs:** `AI/cloud_security.py` (AWS CloudTrail, Azure Activity, GCP Audit)
- **Device Discovery:** `server/device_scanner.py` (asset inventory)

**Data Flow:**
```
Raw packets → network_monitor.py → metadata extraction (IPs, ports, protocols, timestamps)
→ schema normalization → normalized event object
```

**JSON Persistence:** `server/json/` (or `/app/json/` in Docker)

**Stage 1 → Stage 2 Transition:**
1. Network monitor creates normalized event: `{"src_ip": "...", "dst_ip": "...", "src_port": ..., "protocol": "...", "timestamp": "...", ...}`
2. Event passed to `AI/pcs_ai.py` → `assess_threat(event)` method
3. `assess_threat()` orchestrates all 20 detection signals in parallel using the same event object
4. Each signal produces independent `DetectionSignal` object → fed into Stage 3 ensemble

---

### Stage 2: Parallel Multi-Signal Detection (20 Signals)

**README:** "⚡ 20 PARALLEL DETECTIONS (18 primary + 2 strategic intelligence layers)"

**Implementation:** Each signal = independent AI module

**Primary Detection Signals (1-18):** Direct threat detection from network traffic and system events.

**Strategic Intelligence Layers (19-20):** Dual-role signals that participate in weighted voting AND provide strategic context. They analyze detection outputs from all signals (1-20), deployment logs, config changes, and entity history to modulate ensemble decisions.

| # | Signal | Module(s) | Model/Data | Output |
|---|--------|-----------|------------|--------|
| 1 | **Kernel Telemetry** | `AI/kernel_telemetry.py` | eBPF/XDP events | Syscall/network correlation |
| 2 | **Signatures** | `AI/threat_intelligence.py` | 3,066+ patterns | Pattern match confidence |
| 3 | **RandomForest** | `AI/pcs_ai.py` | `ml_models/threat_classifier.pkl` | Classification score |
| 4 | **IsolationForest** | `AI/pcs_ai.py` | `ml_models/anomaly_detector.pkl` | Anomaly score |
| 5 | **Gradient Boosting** | `AI/pcs_ai.py` | `ml_models/ip_reputation.pkl` | Reputation score |
| 6 | **Behavioral** | `AI/behavioral_heuristics.py` | 15 metrics + APT | Heuristic risk score |
| 7 | **LSTM** | `AI/sequence_analyzer.py` | `AI/ml_models/sequence_lstm.keras` | Kill-chain state |
| 8 | **Autoencoder** | `AI/traffic_analyzer.py` | `AI/ml_models/traffic_autoencoder.keras` | Reconstruction error |
| 9 | **Drift Detection** | `AI/drift_detector.py` | `drift_baseline.json` | KS/PSI drift score |
| 10 | **Graph Intelligence** | `AI/graph_intelligence.py` | `network_graph.json` | Lateral movement |
| 11 | **VPN/Tor Fingerprinting** | `AI/pcs_ai.py` | VPN/Tor statistics | De-anonymization |
| 12 | **Threat Intel** | `AI/threat_intelligence.py` | VirusTotal, AbuseIPDB | OSINT correlation |
| 13 | **False Positive Filter** | `AI/false_positive_filter.py` | FP config | 5-gate validation |
| 14 | **Reputation** | `AI/reputation_tracker.py` | `reputation.db` (SQLite) | Recidivism score |
| 15 | **Explainability** | `AI/explainability_engine.py` | Decision history | Transparency |
| 16 | **Predictive** | `AI/advanced_orchestration.py` | Threat predictions | 24-48h forecast |
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
- **Trust Thresholds & Actions:**
  - ≥80: ALLOW (normal operation)
  - 60-79: MONITOR (increased monitoring, +5% score boost)
  - 40-59: RATE_LIMIT (connection throttling, +10% score boost, stricter 65% block threshold)
  - 20-39: ISOLATE (deny-by-default firewall, +15% score boost, stricter 60% block threshold)
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
    signal_type=SignalType.SIGNATURE,  # or HONEYPOT, LSTM, etc.
    is_threat=True,  # Boolean: is this signal detecting a threat?
    confidence=0.92,  # Float 0.0-1.0: how confident is the signal?
    details={...}    # Dict: signal-specific metadata
)
```

**Stage 2 → Stage 3 Transition:**
1. All detection signals (1-20) complete analysis → produce list of `DetectionSignal` objects
2. Signals routed through `AI/false_positive_filter.py` (5-gate validation) → filters out low-confidence/whitelisted signals
3. **Layer 19 (Causal Inference)** analyzes filtered signals + system metadata → produces `CausalInferenceResult`:
   - Checks recent config changes, deployments, identity events
   - Builds causal graph to determine WHY event occurred
   - Classifies as legitimate, misconfiguration, automation side-effect, attack, insider misuse, or unknown
4. **Layer 20 (Trust Degradation)** retrieves entity trust state from persistent graph:
   - Looks up current trust score for source IP/device/account
   - Calculates trust degradation based on detected threats
   - Generates `TrustStateUpdate` with recommended action
5. Filtered signals + causal inference result + trust state → passed to `AI/meta_decision_engine.py` → weighted voting begins

---

### Stage 3: Ensemble Decision Engine (Weighted Voting)

**README:** "🎯 ENSEMBLE VOTING → Calculate weighted score → Authoritative boosting → Consensus → Threshold decision"

**Implementation:**
- **Module:** `AI/meta_decision_engine.py`
- **Input:** List of `DetectionSignal` objects from Stage 2
- **Algorithm:**
  ```python
  weighted_score = Σ (signal_weight × confidence × is_threat) / Σ signal_weight
  
  # Authoritative boosting
  if honeypot_confidence ≥ 0.7 or threat_intel_confidence ≥ 0.9:
      weighted_score = max(weighted_score, 0.90)
  
  # Causal inference adjustment (Layer 19)
  if causal_label == LEGITIMATE_CAUSE and causal_confidence ≥ 0.85:
      weighted_score -= 0.20  # Downgrade by 20%
  elif causal_label in [EXTERNAL_ATTACK, INSIDER_MISUSE] and causal_confidence ≥ 0.80:
      weighted_score += 0.15  # Boost by 15%
  elif causal_label == MISCONFIGURATION:
      route_to_governance_queue()  # Don't auto-block
  elif causal_label == UNKNOWN_CAUSE:
      require_human_review = True  # No auto-block even if score ≥ 75%
  
  # Trust state modulation (Layer 20)
  entity_trust = get_entity_trust_score(event.src_ip, event.user, event.device)
  if entity_trust < 40:
      block_threshold = 0.60  # Stricter threshold
  elif entity_trust < 20:
      return QUARANTINE  # Automatic quarantine regardless of score
  else:
      block_threshold = 0.75  # Normal threshold (or 0.70 in APT mode)
  
  # Threshold decision
  if weighted_score ≥ block_threshold:
      return BLOCK
  elif weighted_score ≥ 0.50:
      return LOG_THREAT
  else:
      return ALLOW
  ```

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
| **SOAR Integration** | `AI/soar_api.py` | REST API to external platforms |

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

**Note:** Files marked with *(auto-rotates at 100MB)* use `AI/file_rotation.py` to prevent unbounded growth (optimized for 1GB VPS servers). ML training reads all rotation files (`threat_log.json`, `threat_log_1.json`, `threat_log_2.json`, etc.) to preserve complete attack history.

**Policy Governance:**
- `AI/policy_governance.py` — Approval workflows
- `server/json/approval_requests.json` — Pending approvals
- `AI/emergency_killswitch.py` — SAFE_MODE override

**Stage 4 → Stage 5 Transition:**
1. Stage 4 writes attack details to `threat_log.json`, `comprehensive_audit.json`, and signal-specific logs
2. Background extraction jobs scan logs periodically (every hour):
   - `AI/signature_extractor.py` reads `threat_log.json` → extracts attack patterns → writes `extracted_signatures.json`
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
| **Signatures** | `AI/signature_extractor.py` | `server/json/extracted_signatures.json` | Patterns only, zero exploit code |
| **Behavioral Stats** | `AI/behavioral_heuristics.py` | `server/json/behavioral_metrics.json` | Connection rate, port entropy (anonymized) |
| **Reputation** | `AI/reputation_tracker.py` | `server/json/reputation.db` | SHA-256 hashed IPs (not raw) |
| **Graph Topology** | `AI/graph_intelligence.py` | `server/json/network_graph.json` | A→B→C labels (not real IPs) |

**Relay-Side Storage (After Stage 6 Push):**
- Signatures → `relay/ai_training_materials/ai_signatures/learned_signatures.json`
- Reputation → `relay/ai_training_materials/reputation_data/`
- Graph patterns → `relay/ai_training_materials/training_datasets/graph_topology.json`
- Attack records → `relay/ai_training_materials/global_attacks.json`

**Stage 5 → Stage 6 Flow:** Customer extracts materials locally → `AI/relay_client.py` pushes to relay (every hour) → relay aggregates into training datasets

**Privacy Guarantees:**
- ✅ No raw exploit payloads stored
- ✅ No PII/PHI retained
- ✅ IP addresses hashed (SHA-256)
- ✅ Packet content stripped (metadata only)
- ✅ Only statistical features shared

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
- **Module:** `AI/training_sync_client.py`, `AI/signature_distribution.py`
- **Downloads:**
  - 3,000+ new signatures from worldwide nodes
  - Known bad IP/ASN reputation feed
  - Model updates (Byzantine-validated)
  - Emerging threat statistics (CVEs, attack trends)
- **Destination:** `ml_models/` (aligned with `AI/pcs_ai.py`)

**Merge & Integration:**
- New signatures → signature database
- Reputation feed → `AI/reputation_tracker.py`
- Model updates → `AI/byzantine_federated_learning.py` validation → replace local models

**Relay Infrastructure (NOT shipped to customers):**
- `relay/docker-compose.yml` — Separate deployment
- `relay/training_sync_api.py` — Model distribution API
- `relay/exploitdb_scraper.py` — ExploitDB integration (3,066+ patterns)
- `relay/threat_crawler.py` — OSINT aggregation (VirusTotal, AbuseIPDB, URLhaus, MalwareBazaar)

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
- **SOAR Playbook Results:** Successful remediation → reinforcement learning

**Stage 7 → Stage 1 Feedback Loop (Completes the 7-Stage Cycle):**
1. Relay retrains models using aggregated data → new `*.pkl` and `*.keras` models created
2. Models pushed to relay API → `relay/training_sync_api.py` serves updated models
3. Customer nodes pull updates (every 6 hours) via `AI/training_sync_client.py`:
   - New signatures downloaded → merged into local signature database
   - New ML models downloaded → replace old models in `ml_models/` and `AI/ml_models/`
   - `AI/byzantine_federated_learning.py` validates updates (94% malicious rejection rate)
4. Updated models loaded by Stage 2 detection signals → **improved accuracy for next packet analysis in Stage 1**
5. Cycle repeats: better detection → more accurate training data → better models → better detection...

**This continuous feedback loop enables the system to adapt to evolving threats without manual intervention.**

---

## 2. Dashboard Architecture: UI → API → AI Modules

**Dashboard:** `AI/inspector_ai_monitoring.html` (31 sections)
**Server:** `server/server.py` (Flask application with REST APIs)

### Section Mapping (Selected Examples)

| Section | Dashboard Area | API Endpoint | AI Modules |
|---------|----------------|--------------|------------|
| 1 | **AI Training Network** | `/api/p2p/status`, `/api/p2p/peers` | `AI/p2p_sync.py`, `AI/byzantine_federated_learning.py` |
| 2 | **Network Devices** | `/api/devices/connected`, `/api/devices/history` | `server/device_scanner.py`, `AI/asset_inventory.py` |
| 3 | **VPN/Tor De-Anonymization** | `/api/vpn_tor/stats` | `AI/pcs_ai.py` (VPN/Tor tracking) |
| 4 | **Real AI/ML Models** | `/api/ml/models`, `/api/ml/lineage` | `AI/pcs_ai.py`, `AI/cryptographic_lineage.py` |
| 5 | **Security Overview** | `/api/security/overview` | `AI/pcs_ai.py`, `AI/meta_decision_engine.py` |
| 7 | **IP Management** | `/api/threats/by_ip` | `AI/reputation_tracker.py`, `AI/threat_intelligence.py` |
| 14 | **Attack Chain (Graph)** | `/api/graph/topology`, `/api/graph/lateral_movement` | `AI/graph_intelligence.py` |
| 15 | **Explainability** | `/api/explainability/decisions` | `AI/explainability_engine.py` |
| 16 | **Adaptive Honeypot** | `/api/adaptive_honeypot/status`, `/api/adaptive_honeypot/attacks` | `AI/adaptive_honeypot.py` |
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
├── ml_models/                     # Classical ML models (mounted)
│   ├── threat_classifier.pkl
│   ├── anomaly_detector.pkl
│   ├── ip_reputation.pkl
│   └── feature_scaler.pkl
├── AI/ml_models/                  # Deep learning models
│   ├── sequence_lstm.keras
│   └── traffic_autoencoder.keras
├── server/crypto_keys/            # HMAC keys for relay auth
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
│   ├── ml_models/                 # Deep learning
│   ├── adaptive_honeypot.py
│   ├── pcs_ai.py
│   └── ...
├── ml_models/                     # Classical ML (shared with relay sync)
└── relay/                         # Operator infrastructure only
    ├── ai_training_materials/
    └── ...
```

### Path Resolution Rules
- **JSON files:** Modules should use `server/json/` (native) or `/app/json/` (Docker)
- **ML models:** `AI/pcs_ai.py` uses `ml_models/` for classical ML, `AI/ml_models/` for deep learning
- **Relay sync:** `AI/training_sync_client.py` downloads to `ml_models/` (same as pcs_ai reads)
- **Relay training data:** Always under `relay/ai_training_materials/` (customer nodes never access this)

---

## 4. Privacy & Security Guarantees

### Data Residency
✅ **Customer JSON stays local by default**
- All runtime JSON (`threat_log.json`, device lists, decision history, etc.) written to `server/json/`
- No silent uploads to third-party cloud services
- Relay is **your own VPS/cloud**, not a vendor

✅ **Relay is operator-controlled infrastructure**
- `relay/` folder deployed only on infrastructure you operate
- Customers receive only `server/` + `AI/` (never `relay/`)
- Relay training materials inaccessible to customers

### Data Minimization
✅ **Training sync is explicit and limited**
- `AI/relay_client.py` sends only sanitized training summaries
- No raw JSON logs uploaded (only structured attack records)
- Replay server returns models/signatures (no customer data pulled)

✅ **Privacy-preserving extraction (Stage 5)**
- IP addresses hashed (SHA-256) before relay transmission
- No raw exploit payloads stored
- Packet content stripped (metadata only)
- PII/PHI never retained

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

**Note:** Signals 19 and 20 are strategic intelligence layers with dual roles: they participate in weighted voting (like signals 1-18) AND provide strategic modulation by analyzing outputs from all signals (1-20).

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
- **Models:** Classical ML → `ml_models/`, Deep learning → `AI/ml_models/`
- **Config:** Tunable parameters → `server/json/new_signal_config.json`

### Testing Checklist
- [ ] Signal fires independently in Stage 2
- [ ] FP filter gates work correctly
- [ ] Ensemble voting includes signal with correct weight
- [ ] Dashboard displays signal contribution (Section 4/15)
- [ ] Relay receives sanitized signal data (Stage 6)
- [ ] Documentation updated (README, ai-abilities.md)

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
- **Stage 2:** `AI/pcs_ai.py` (orchestrator), all 20 detection modules:
  - All signals 1-20 (see Section 1 table for complete list)
  - Includes strategic intelligence: `AI/causal_inference.py` (Layer 19), `AI/trust_graph.py` (Layer 20)
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
- `global_attacks.json` — Relay central attack log (Stage 6) *(rotates at 1GB on relay server)*
- `extracted_signatures.json` — Customer-side signature staging (Stage 5)
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

This section provides a comprehensive testing guide for all **20 detection signals** in the Battle-Hardened AI system, organized by the 7-stage attack detection pipeline + 3 extended validation stages.

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

**Stage 2: Parallel Multi-Signal Detection (20 Signals)**
- **Test:** Core detection pipeline (18 primary signals: signatures, ML models, behavioral, LSTM, autoencoder, drift, graph, VPN/Tor, threat intel, FP filter, reputation, explainability, predictive, Byzantine, integrity) + 2 strategic intelligence layers (causal inference, trust degradation)
- **Goal:** All 20 signals fire independently → produce threat assessments → visible in local JSON
- **Validates README:** "Stage 2: Parallel Multi-Signal Detection" (20 detection systems: 18 primary + 2 strategic)

**Stage 3: Ensemble Decision Engine (Weighted Voting)**
- **Test:** Meta-decision engine combines signals → weighted consensus → threshold decisions (block/log/allow)
- **Goal:** Verify ensemble voting calculation → authoritative boosting → consensus checks → final verdict in threat_log.json
- **Validates README:** "Stage 3: Ensemble Decision Engine" (weighted voting, 75% block threshold, APT mode 70%)

**Stage 4: Response Execution (Policy-Governed)**
- **Test:** Automated responses (firewall blocks, connection drops, rate limiting, logging, alerts, SOAR integration)
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

**Stage 8: Enterprise Integration & Cloud Posture**
- **Test:** SOAR workflows, enterprise integrations, cloud security posture (CSPM), IAM risk detection
- **Goal:** Verify enterprise features integrate with core pipeline → incidents flow to relay as `soar_incident` / `cloud_misconfiguration`

**Stage 9: Resilience, Backup & Compliance**
- **Test:** Backup status monitoring, ransomware resilience, compliance reporting (PCI/HIPAA/GDPR), breach notifications
- **Goal:** Verify backup/compliance issues → comprehensive_audit.json → relay as `backup_issue` / `compliance_issue`

**Stage 10: Explainability, Visualization & Dashboard**
- **Test:** Decision explanations, advanced visualizations (topology/heatmaps/geo), dashboard API endpoints, error handling
- **Goal:** Verify UI correctly reflects all pipeline stages → API failures logged as `SYSTEM_ERROR` events

**For every stage:** Validate complete flow → **trigger → local JSON → dashboard → relay JSON** (Logging & Central Capture Checklist).

### 9.2 Quick Reference: 20 Detection Signals → Implementation Files

This maps each of the **20 active detection signals** from the README to the concrete files/modules that implement or feed that signal.

1. **eBPF Kernel Telemetry**  
   Files: AI/kernel_telemetry.py; server/network_monitor.py; server/docker-compose.yml (Linux capabilities and host networking); AI/pcs_ai.py (orchestration and signal wiring).

2. **Signature Matching**  
   Files: AI/threat_intelligence.py; AI/signature_extractor.py; AI/signature_distribution.py; AI/signature_uploader.py; AI/pcs_ai.py; relay/signature_sync.py; relay/exploitdb_scraper.py; relay/threat_crawler.py; relay/ai_training_materials/ai_signatures/; relay/ai_training_materials/exploitdb/.

3. **RandomForest (supervised classifier)**  
   Files: AI/pcs_ai.py (loads and uses RF pickles); ml_models/ (RandomForest model pickles such as anomaly_detector/threat_classifier); relay/ai_retraining.py (trains and exports updated RF models to ai_training_materials/ml_models/); relay/gpu_trainer.py (optional GPU training backend).

4. **IsolationForest (unsupervised anomaly)**  
   Files: AI/pcs_ai.py; ml_models/ (IsolationForest pickle); relay/ai_retraining.py; relay/gpu_trainer.py.

5. **Gradient Boosting (reputation modeling)**  
   Files: AI/pcs_ai.py; ml_models/ (gradient boosting/reputation model); relay/ai_retraining.py; relay/gpu_trainer.py.

6. **Behavioral Heuristics**  
   Files: AI/behavioral_heuristics.py; AI/pcs_ai.py (uses heuristic scores as detection signals); server/network_monitor.py (feeds per-IP events into the heuristics engine); server/json/behavioral_metrics.json (persistence, when enabled).

7. **LSTM (sequential kill-chain analysis)**  
   Files: AI/sequence_analyzer.py; AI/ml_models/sequence_lstm.keras; AI/pcs_ai.py (calls sequence analysis); server/json/attack_sequences.json (sequence export, when enabled); relay/ai_retraining.py (may incorporate sequence history into retraining).

8. **Autoencoder (zero-day anomaly detection)**  
   Files: AI/traffic_analyzer.py; AI/ml_models/traffic_autoencoder.keras; AI/network_performance.py; AI/pcs_ai.py; server/json/network_performance.json; relay/ai_retraining.py; relay/gpu_trainer.py.

9. **Drift Detection**  
   Files: AI/drift_detector.py; AI/pcs_ai.py (invokes drift checks and flags); server/json/drift_baseline.json; server/json/drift_reports.json; relay/ai_retraining.py (uses history/drift context for when to retrain).

10. **Graph Intelligence (lateral movement / C2)**  
    Files: AI/graph_intelligence.py; AI/advanced_visualization.py (renders graph outputs); AI/advanced_orchestration.py (can export topology/training views); AI/pcs_ai.py; server/json/network_graph.json; server/json/lateral_movement_alerts.json; relay/ai_training_materials/training_datasets/graph_topology.json.

11. **VPN/Tor Fingerprinting**  
    Files: AI/pcs_ai.py (get_vpn_tor_statistics and related tracking); server/server.py (vpn_stats wiring into dashboard sections); server/json/threat_log.json (stores VPN/Tor-related attacker_intel entries).

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
    **Trust Thresholds & Actions:** ≥80 (ALLOW), 60-79 (MONITOR, +5% score boost), 40-59 (RATE_LIMIT, +10% boost, 65% block threshold), 20-39 (ISOLATE, +15% boost, 60% block threshold), <20 (QUARANTINE, force block regardless of ensemble score).  
    **Recidivism:** 3+ attacks in 7 days = exponential penalty.  
    **Position:** Influences Stage 4 response severity, tracked by explainability engine (Signal #15).  
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

- **Stage 8 – Enterprise, Cloud & SOAR**  
  - `relay/ai_training_materials/global_attacks.json` — incidents raised from SOAR or cloud posture checks that are shared globally.

- **Stage 9 – Resilience, Backup & Compliance**  
  - `relay/ai_training_materials/global_attacks.json` — any ransomware/backup/compliance‑related incidents escalated as attacks.

- **Stage 10 – Explainability, Visualization & Dashboard**  
  - No new relay files; reuses:  
    - `relay/ai_training_materials/global_attacks.json` — attacks already logged in earlier stages.  
    - `relay/ai_training_materials/ai_signatures/learned_signatures.json` — signatures already logged.  
  - Additional logging surface for this stage:  
    - `server/json/comprehensive_audit.json` — SYSTEM_ERROR events from dashboard/explainability/visualization APIs when those paths fail.

Use this as a quick cross-check when validating that a given stage's detections are visible both **locally** (server/json) and at the **relay** (ai_training_materials).

---

**For architecture overview, see:** `README.md` (7-stage pipeline with diagrams)
