# File Purpose Overview: 7-Stage Pipeline Implementation

This document maps each file in `AI/`, `server/`, and `relay/` folders to the **7-stage attack detection pipeline** documented in the README.

> **Audience & distribution note:** This is a **developer/auditor reference** tied to the Git repository layout. It assumes you have the full source tree checked out (AI/, server/, relay/) so you can inspect modules and JSON surfaces directly. **Production customers who install via the Linux .deb/.rpm packages or the Windows EXE normally do not see this folder structure**; they operate the packaged services using README and INSTALLATION. Use this file when you need to understand or verify how the runtime behavior maps back to individual source files.

---

## 🎯 Deployment Context for File Architecture

**Pipeline implementation varies by deployment role:**

| Deployment Role | What Pipelines Protect | File Locations |
|----------------|------------------------|----------------|
| **Gateway/Router** | Entire network segment (all devices) | Same AI/ server/ modules, different scope of traffic |
| **Host-only** | Local machine + terminated services | Same AI/ server/ modules, host traffic only |
| **Observer** | SPAN/mirror traffic (analysis only) | Same AI/ modules, no direct enforcement |

**Installation reference:** For deployment setup, see:
- [Installation.md § Deployment Role](installation/Installation.md#🎯-deployment-role-read-first)
- [Installation.md § Gateway Pre-Flight Checklist](installation/Installation.md#✅-gateway-pre-flight-checklist)
- [Installation.md § Linux Gateway Setup](installation/Installation.md#scenario-1-linux-gatewayrouter-network-wide-protection---recommended)

**Cloud deployment:** All file architectures and pipelines work identically on cloud VMs (AWS/Azure/GCP) with virtual NICs. Physical hardware not required.

---
- **[Installation](installation/Installation.md)** — Complete installation guide for Linux (Docker/packaged appliance), Windows EXE, macOS (dev/testing), plus optional relay setup
- **[README.md](README.md)** — Project overview, features, MITRE ATT&CK coverage, architecture
- **[KALI_ATTACK_TESTS.md](KALI_ATTACK_TESTS.md)** — Attack simulation test procedures
- **[Dashboard](Dashboard.md)** — Core first-layer dashboard API reference
- **[AI instructions](Ai-instructions.md)** — Developer guide and implementation details
- **[Architecture Enhancements](Architecture_Enhancements.md)** — 5 implemented features (Model Signing, Pattern Filtering, Performance Monitoring, Adversarial Training, ONNX) plus compliance verification
- **[ONNX Integration](ONNX_Integration.md)** — ONNX model format implementation (2-5x faster CPU inference)
- **[Attack handling flow](Attack_handling_flow.md)** — Attack handling flow diagrams
- **[test-hmac.md](test-hmac.md)** — HMAC authentication testing guide

**Workspace Files:**
- `.gitignore` — Git exclusion patterns (excludes `*.json`, `*.pkl`, `*.keras`, `__pycache__`, `.venv`, etc.)
- `battle-hardened-ai.code-workspace` — VS Code workspace configuration
- `build/` — Build artifacts directory (used for generic builds and logs).
- `assets/` — Static assets and UI resources bundled into the server/EXE builds.

**Pipeline Stages:**
1. **Data Ingestion & Normalization**  Packet capture, metadata extraction
2. **Parallel Detections (20 Signals + Step 21 Semantic Gate)**  Independent threat assessments (18 primary + 2 strategic intelligence layers) plus a semantic execution-denial gate for a total of **21 detection layers**
3. **Ensemble Voting**  Weighted consensus decision
4. **Response Execution** → Firewall blocks, logging, alerts
5. **Training Extraction** → Privacy-preserving signatures
6. **Relay Sharing** → Global intelligence exchange
7. **Continuous Learning** → ML retraining, adaptation

---
## Dashboard Section Mapping (inspector_ai_monitoring.html)

**Core First-Layer Dashboard (24 Sections):**

| Section | Title | Purpose | Key Files |
|---------|-------|---------|----------|
| **1** | 🤖 AI Training Network - Shared Machine Learning | Global P2P mesh for distributed AI training & real-time threat sharing | `AI/relay_client.py`, `AI/p2p_sync.py`, `AI/training_sync_client.py`, `relay/relay_server.py` |
| **2** | 🌐 Network Devices - Live Monitor, Ports & History | Live device discovery, asset inventory, network topology | `server/device_scanner.py`, `server/json/connected_devices.json`, `server/json/device_history.json` |
| **3** | 🔓 Attackers VPN/Tor De-Anonymization Statistics | VPN/Tor fingerprinting, anonymization tracking | `AI/pcs_ai.py` (Signal #11), dashboard metrics |
| **4** | 🤖 Real AI/ML Models - Machine Learning Intelligence | Core ML models: RandomForest, IsolationForest, GradientBoosting, LSTM | `AI/ml_models/*.pkl`, `AI/ml_models/sequence_lstm.keras`, `AI/pcs_ai.py` (Signals #3-5, #7) |
| **5** | 📊 Security Overview - Live Statistics | Real-time threat counters, attack summaries, blocked IPs | `server/json/threat_log.json`, `server/json/blocked_ips.json`, `AI/pcs_ai.py` |
| **6** | 🎯 Threat Analysis by Type | Attack type breakdown, threat categories | `server/json/threat_log.json`, `AI/behavioral_heuristics.py` |
| **7** | 🛡️ IP Management & Threat Monitoring | IP blocking, whitelisting, threat filtering, Linux Firewall Commander (Tab 4: dual-layer kernel firewall enforcement across 5 distributions) | `server/json/blocked_ips.json`, `server/json/whitelist.json`, `server/device_blocker.py`, `AI/firewall_backend.py`, `server/installation/bh_firewall_sync.py` |
| **8** | 🔐 Failed Login Attempts (Battle-Hardened AI Server) | Dashboard login failures, brute-force attempts | `server/server.py`, `server/json/admin_users.json` |
| **9** | 📈 Attack Type Breakdown (View) | Visual attack type distribution, trend analysis | `server/json/threat_log.json`, `AI/advanced_visualization.py` |
| **10** | 📦 Automated Signature Extraction - Attack Pattern Analysis | Attack pattern learning, signature generation | `AI/signature_extractor.py`, `relay/ai_training_materials/ai_signatures/learned_signatures.json` |
| **11** | 💻 System Health & Network Performance | CPU/RAM/network metrics, performance monitoring | `AI/network_performance.py`, `server/json/network_performance.json` |
| **12** | 📑 Audit Evidence & Compliance Mapping | Comprehensive audit log, compliance frameworks | `server/json/comprehensive_audit.json`, `AI/compliance_reporting.py`, `AI/emergency_killswitch.py` |
| **13** | 🔗 Attack Chain Visualization (Phase 4 - Graph Intelligence) | Network graph, lateral movement, C2 detection | `AI/graph_intelligence.py`, `server/json/network_graph.json`, `server/json/lateral_movement_alerts.json` |
| **14** | 🧠 Decision Explainability Engine (Phase 7 - Transparency) | AI decision transparency, forensic reports | `AI/explainability_engine.py`, `server/json/forensic_reports/`, `relay/ai_training_materials/explainability_data/` |
| **15** | 🍯 Adaptive Honeypot - AI Training Sandbox | Real honeypot services (7 ports), attack capture | `AI/real_honeypot.py`, `AI/adaptive_honeypot.py`, `server/json/honeypot_attacks.json`, `server/json/honeypot_patterns.json` |
| **16** | 🤖 AI Security Crawlers & Threat Intelligence Sources | OSINT feeds, CVE/MalwareBazaar/URLhaus/OTX | `AI/threat_intelligence.py`, `relay/threat_crawler.py`, `relay/exploitdb_scraper.py`, `server/json/local_threat_intel.json` |
| **17** | 🔍 Traffic Analysis & Inspection | Protocol analysis, crypto mining detection, traffic anomalies | `AI/traffic_analyzer.py`, `AI/network_performance.py`, `server/json/crypto_mining.json` |
| **18** | 🌍 DNS & Geo Security | DNS tunneling/DGA detection, TLS fingerprinting, geographic analysis | `AI/dns_analyzer.py`, `AI/tls_fingerprint.py`, `server/json/dns_security.json`, `server/json/tls_fingerprints.json` |
| **19** | 👤 User & Identity Trust Signals | User behavior tracking, trust scoring, UEBA | `AI/user_tracker.py`, `AI/trust_graph.py`, `server/json/tracked_users.json`, `server/json/trust_graph.json` |
| **20** | 💣 Sandbox Detonation | Static file analysis, sandbox integration (external) | `AI/file_analyzer.py` |
| **21** | 📧 Email/SMS Alerts (Critical Only) | Critical SYSTEM event notifications (kill-switch, integrity, failures) | `AI/alert_system.py` |
| **22** | 🪙 Cryptocurrency Mining Detection | Traffic analysis enhanced with crypto mining patterns | `AI/traffic_analyzer.py`, `server/json/crypto_mining.json` (Signal #8) |
| **23** | 🚨 Governance & Emergency Controls | Kill-switch, approval workflows, policy governance, self-protection | `AI/emergency_killswitch.py`, `AI/policy_governance.py`, `AI/self_protection.py`, `AI/secure_deployment.py`, `server/json/approval_requests.json`, `server/json/integrity_violations.json` |
| **24** | 🏢 Enterprise Security Integrations | SOAR API, enterprise adapters (SIEM/ticketing/ITSM outbound only) | `AI/soar_api.py`, `AI/soar_workflows.py`, `AI/enterprise_integration.py`, `server/json/soar_incidents.json` |

**Additional Non-Core Sections (Experimental/Auxiliary):**
- **Vulnerability & Supply Chain Management** (non-numbered) — CVE tracking, patch management, SBOM | `AI/vulnerability_manager.py`, `server/json/sbom.json`
- **Dark Web Monitoring** (non-numbered) — Dark web intelligence (experimental) | Auxiliary feature
- **Attack Simulation / Purple Team** (non-numbered) — Red team/BAS testing (experimental) | Auxiliary feature
- **Cloud Security Posture Management** (non-numbered) — Multi-cloud monitoring (AWS/Azure/GCP) | `AI/cloud_security.py`, `server/json/cloud_findings.json`
- **Data Loss Prevention / DLP** (non-numbered) — Data classification, DLP events (experimental) | `AI/zero_trust.py` (partial)
- **Backup & Recovery Status** (non-numbered) — Backup monitoring, ransomware resilience | `AI/backup_recovery.py`, `server/json/backup_status.json`, `server/json/recovery_tests.json`

**Note:** Sections marked as "experimental" or "non-core" represent auxiliary enterprise capabilities whose HTTP APIs are disabled by default. They should be treated as lab/development tooling unless explicitly enabled and configured by operators.

---
## Critical JSON Surfaces by Pipeline Stage

| Pipeline Stage | Local JSON (JSON directory via AI/path_helper) | Relay JSON (relay/ai_training_materials/) | Purpose |
|----------------|---------------------------|-------------------------------------------|---------|
| **Stage 1: Data Ingestion** | `connected_devices.json`, `device_history.json`, `network_monitor_state.json` | N/A | Device discovery, packet capture state |
| **Stage 2: Parallel Detections (Signals 1-20)** | `threat_log.json`, `dns_security.json`, `tls_fingerprints.json`, `network_graph.json`, `lateral_movement_alerts.json`, `attack_sequences.json`, `behavioral_metrics.json`, `drift_baseline.json`, `drift_reports.json`, `model_lineage.json`, `reputation.db`, `causal_analysis.json`, `trust_graph.json` | N/A | Individual signal outputs (18 primary + 2 strategic); Step 21 semantic gate evaluates the combined result |
| **Stage 3: Ensemble Voting** | `decision_history.json`, `meta_engine_config.json`, `fp_filter_config.json` | N/A | Weighted voting, thresholds |
| **Stage 4: Response Execution** | `threat_log.json`, `blocked_ips.json`, `comprehensive_audit.json`, `integrity_violations.json`, `forensic_reports/`, `causal_analysis.json`, `trust_graph.json` | N/A | Actions, logging, alerts, causal & trust state |
| **Stage 5: Training Extraction** | `local_threat_intel.json`, `reputation_export.json` | `ai_signatures/learned_signatures.json`, `reputation_data/`, `training_datasets/`, `explainability_data/` | Privacy-preserving materials |
| **Stage 6: Relay Sharing** | `crypto_keys/` (HMAC auth) | `global_attacks.json`, `attack_statistics.json`, `ai_signatures/learned_signatures.json`, `threat_intelligence/`, `ml_models/` | Global intelligence |
| **Stage 7: Continuous Learning** | `drift_baseline.json`, `comprehensive_audit.json` (Byzantine events) | `trained_models/`, `ml_models/` (updated), `training_datasets/` | Retraining, adaptation |
| **Enterprise Extensions (Auxiliary / Non-Core)** | `soar_incidents.json`, `cloud_findings.json`, `backup_status.json`, `recovery_tests.json`, `compliance_reports/`, `sbom.json`, `admin_users.json`, `identity_access_config.json`, `cluster_config.json`, `whitelist.json`, `support_tickets.json` | Optional: `global_attacks.json` (when enterprise modules are enabled) | Optional enterprise integrations (identity/SSO/RBAC, HA/cluster metadata, local support portal, and experimental SOAR/cloud/backup/compliance modules that are not part of the core first-layer surface and whose HTTP APIs are disabled by default) |

---

## File Map by Pipeline Stage

### Stage 1: Data Ingestion & Normalization

**Purpose:** Capture packets, extract metadata, normalize events

**Server Files:**
- `server/network_monitor.py` — Live packet capture (Scapy/eBPF), feeds all detection signals; bundled in Windows EXE builds
- `server/device_scanner.py` — Network device discovery and asset enumeration; cross-platform network detection (Linux: ip route/addr, Windows: ipconfig parsing, fallback: socket trick)
- `server/json/connected_devices.json` — Active device inventory
- `server/json/device_history.json` — 7-day device connection history
- `server/json/network_monitor_state.json` — Packet capture state and counters

**AI Files:**
- `AI/kernel_telemetry.py` — eBPF/XDP kernel telemetry (Linux only)
- `AI/system_log_collector.py` — System log ingestion and normalization
- `AI/pcap_capture.py` — PCAP saving for offline analysis and training (no in-product forensics console)
- `AI/asset_inventory.py` — Asset inventory management
- `AI/cloud_security.py` — Cloud API integration (AWS CloudTrail, Azure Activity, GCP Audit)

---

### Stage 2: Parallel Multi-Signal Detection (20 Signals + Step 21 Semantic Gate)

**Purpose:** 20 independent detection systems produce threat assessments (18 primary + 2 strategic intelligence layers), then a Step 21 semantic execution-denial gate evaluates the request before any action for a total of **21 detection layers**.

#### 21 Detection Layers – Quick Reference

- **Layer 1 – eBPF Kernel Telemetry:** Correlates low-level syscalls and network activity to surface kernel-level anomalies and suspicious host behavior.
- **Layer 2 – Signature Matching:** Matches traffic, logs, and honeypot activity against curated signatures (local rules, ExploitDB-derived patterns, and learned_signatures) to spot known attacks.
- **Layer 3 – RandomForest Threat Classifier:** Supervised ML model that scores flows/hosts based on engineered features to classify them as benign, suspicious, or malicious.
- **Layer 4 – IsolationForest Anomaly Detector:** Unsupervised outlier detector that flags statistically rare behavior and novel attack patterns not yet covered by signatures.
- **Layer 5 – Gradient Boosting Reputation Model:** Learns a reputation score from historical behavior, intel hits, and recidivism to up- or down-rank entities over time.
- **Layer 6 – Behavioral Heuristics Engine:** Rule/heuristic layer that watches connection/auth patterns (low-and-slow scans, off-hours access, credential reuse) and assigns risk scores.
- **Layer 7 – LSTM Sequence Model:** Sequence model that tracks multi-step kill chains and APT-style campaigns across time, detecting coordinated sequences that may look benign in isolation.
- **Layer 8 – Traffic Analysis & Crypto-Mining Detector:** Examines protocol mix, destinations, and volume to detect anomalies, abuse patterns, and crypto-mining behavior.
- **Layer 9 – Drift Detection:** Monitors feature and model output distributions for drift, flagging when the environment has changed enough that models may be unreliable and retraining is required.
- **Layer 10 – Graph Intelligence Engine:** Builds and queries graphs of entities and connections to detect lateral movement, command-and-control structures, and high-risk choke points.
- **Layer 11 – VPN/Tor Fingerprinting:** Tracks VPN, Tor, and anonymization infrastructure usage so that otherwise borderline behavior from anonymized sources is treated with more caution.
- **Layer 12 – Threat Intelligence Feeds:** Correlates local activity with external IoCs and threat feeds (CVE, MalwareBazaar, URLhaus, OTX, etc.) to quickly flag known bad infrastructure.
- **Layer 13 – False Positive Filter:** Applies a multi-gate consensus and context check to downgrade noisy detections and reduce false positives before they reach operators.
- **Layer 14 – Historical Reputation Tracker:** Maintains long-term per-entity reputation and recidivism statistics, increasing scores for repeat offenders and decaying older incidents.
- **Layer 15 – Explainability Consistency Checks:** Generates explanations for decisions and can surface inconsistencies (e.g., high risk with weak supporting evidence) as an additional signal.
- **Layer 16 – Predictive Modeling & Forecasting:** Uses historical telemetry to forecast 24–48 hour risk windows and predict where attacks are likely to move next.
- **Layer 17 – Byzantine/Federated Defense:** Evaluates federated learning updates for poisoning attempts, rejecting suspicious updates and logging them as security events.
- **Layer 18 – Integrity & Lineage Monitoring:** Watches binaries, models, configs, and cryptographic lineage for tampering or unexpected changes and raises integrity violations.
- **Layer 19 – Causal Inference Engine (Strategic):** Distinguishes legitimate change, automation, and misconfiguration from real attacks, then modulates scores based on root cause.
- **Layer 20 – Trust Degradation Graph (Strategic):** Maintains a persistent 0–100 trust score per entity and applies non-linear penalties for repeated or severe abuse, influencing isolation/quarantine.
- **Layer 21 – Semantic Execution-Denial Gate:** Final semantic safety layer in pcs_ai/step21_semantic_gate that inspects the meaning of requested actions/operations and vetoes dangerous or out-of-policy intents even if numeric risk is borderline.

**PRIMARY DETECTION SIGNALS (1-18): Direct threat identification**

**Signal #1: eBPF Kernel Telemetry**
- `AI/kernel_telemetry.py` — Syscall/network correlation

**Signal #2: Signature Matching**
- `AI/threat_intelligence.py` — Signature matching (3,066+ patterns)
- `AI/signature_extractor.py` — Extract new signatures from attacks
- `AI/real_honeypot.py` — Real honeypot services (7 ports: SSH 2222, FTP 2121, Telnet 2323, MySQL 3306, HTTP 8080, SMTP 2525, RDP 3389)
- `server/json/honeypot_attacks.json` — Honeypot attack logs
- `server/json/honeypot_patterns.json` — Extracted honeypot patterns
- `relay/exploitdb_scraper.py` — ExploitDB pattern generation (43,971+ exploits)
- `relay/ai_training_materials/exploitdb/` — ExploitDB mirror
- `relay/ai_training_materials/ai_signatures/learned_signatures.json` — Global signature database

**Signal #3: RandomForest**
- `AI/pcs_ai.py` — Loads `AI/ml_models/threat_classifier.pkl`
- `AI/ml_models/threat_classifier.pkl` — RandomForest classifier

**Signal #4: IsolationForest**
- `AI/pcs_ai.py` — Loads `AI/ml_models/anomaly_detector.pkl`
- `AI/ml_models/anomaly_detector.pkl` — IsolationForest anomaly detector

**Signal #5: Gradient Boosting**
- `AI/pcs_ai.py` — Loads `AI/ml_models/ip_reputation.pkl`
- `AI/ml_models/ip_reputation.pkl` — Gradient boosting reputation model

**Signal #6: Behavioral Heuristics**
- `AI/behavioral_heuristics.py` — 15 metrics + APT patterns (low-and-slow, off-hours, credential reuse)
- `server/json/behavioral_metrics.json` — Per-IP heuristic scores

**Signal #7: LSTM Sequences**
- `AI/sequence_analyzer.py` — Kill-chain state progression + APT campaign patterns
- `AI/ml_models/sequence_lstm.keras` — LSTM model
- `server/json/attack_sequences.json` — Sequence history

**Signal #8: Traffic Analysis**
- `AI/traffic_analyzer.py` — Protocol/app breakdown, crypto mining detection, network anomalies
- `AI/network_performance.py` — Network performance metrics
- `server/json/crypto_mining.json` — Crypto mining detection log

**Signal #9: Drift Detection**
- `AI/drift_detector.py` — KS/PSI model degradation monitoring
- `server/json/drift_baseline.json` — Baseline distribution
- `server/json/drift_reports.json` — Drift analysis results

**Signal #10: Graph Intelligence**
- `AI/graph_intelligence.py` — Lateral movement, C2 detection, hop chains
- `server/json/network_graph.json` — Network topology
- `server/json/lateral_movement_alerts.json` — Hop chain alerts
- `AI/advanced_visualization.py` — Graph rendering

**Signal #11: VPN/Tor Fingerprinting**
- `AI/pcs_ai.py` — VPN/Tor de-anonymization statistics

**Signal #12: Threat Intel Feeds**
- `AI/threat_intelligence.py` — OSINT correlation (VirusTotal, AbuseIPDB)
- `relay/threat_crawler.py` — CVE, MalwareBazaar, URLhaus, AlienVault OTX
- `relay/ai_training_materials/threat_intelligence/` — Crawled intel data
- `server/json/local_threat_intel.json` — Local threat indicators

**Signal #13: False Positive Filter**
- `AI/false_positive_filter.py` — 5-gate consensus validation
- `server/json/fp_filter_config.json` — FP filter tuning

**Signal #14: Historical Reputation**
- `AI/reputation_tracker.py` — Cross-session recidivism tracking
- `server/json/reputation.db` — SQLite reputation database
- `server/json/reputation_export.json` — Training export
- `relay/ai_training_materials/reputation_data/` — Global reputation

**Signal #15: Explainability Engine**
- `AI/explainability_engine.py` — Decision transparency
- `server/json/forensic_reports/` — Per-incident explanations
- `relay/ai_training_materials/explainability_data/` — Training export

**Signal #16: Predictive Modeling**
- `AI/advanced_orchestration.py` — 24–48h threat forecasting and scoring (advisory outputs only)
- `relay/ai_training_materials/orchestration_data/` — Prediction exports

**Signal #17: Byzantine Defense**
- `AI/byzantine_federated_learning.py` — Poisoned update rejection (Krum, trimmed mean)
- `server/json/comprehensive_audit.json` — Rejected update events

**Signal #18: Integrity Monitoring**
- `AI/self_protection.py` — Tampering detection
- `AI/cryptographic_lineage.py` — Model provenance tracking
- `server/json/integrity_violations.json` — Integrity violations
- `server/json/model_lineage.json` — Cryptographic lineage chain
- `server/json/comprehensive_audit.json` — Lineage/integrity events

**STRATEGIC INTELLIGENCE LAYERS (19-20): Dual-role signals that vote AND modulate**

**Note:** Layers 19 and 20 serve a dual purpose:
1. **As detection signals** (participate in Step 1 weighted voting with all other signals)
2. **As strategic modulators** (apply additional context-aware adjustments in Steps 3-4)

**Signal #19: Causal Inference Engine**
- `AI/causal_inference.py` — Root cause analysis (WHY attacks happen, not just THAT they happened)
- `server/json/causal_analysis.json` — Causal inference logs (auto-rotates at 10,000 entries)
- **Purpose:** Distinguishes legitimate operational changes from disguised attacks
- **Inputs:** All detection outputs (1-20), deployment events, config changes, identity events (login/privilege changes)
- **Output:** Causal labels (LEGITIMATE_CAUSE, AUTOMATION_SIDE_EFFECT, EXTERNAL_ATTACK, INSIDER_MISUSE, MISCONFIGURATION, UNKNOWN_CAUSE)
- **Dual Role:** Participates in weighted voting (Step 1) AND applies causal modulation (Step 3)
- **Score Modulation:** Downgrade by -20% (legitimate), boost by +15% (attack), route to governance (misconfiguration)
- **Privacy:** Metadata-only analysis, no payloads/credentials/PII

**Signal #20: Trust Degradation Graph**
- `AI/trust_graph.py` — Zero-trust enforcement with persistent entity trust tracking
- `server/json/trust_graph.json` — Entity trust state (persistent across restarts)
- **Purpose:** Persistent memory prevents "try again later" strategies via non-linear trust degradation
- **Tracked Entities:** IPs, devices, user accounts, services, APIs, cloud roles, containers (SHA-256 hashed)
- **Trust Model:** 0-100 scale, event-weighted penalties (minor_anomaly=-5 to repeated_attack=-50), natural recovery (+1/day capped at 80% baseline)
- **Actions:** ALLOW (≥80), MONITOR (60-79), RATE_LIMIT (40-59), ISOLATE (20-39), QUARANTINE (<20)
- **Recidivism:** 3+ attacks in 7 days = exponential penalty
- **Dual Role:** Participates in weighted voting (Step 1) AND applies trust modulation (Step 4)
- **Position:** Influences final decision thresholds and can force quarantine regardless of score
- **Privacy:** SHA-256 entity hashing, no PII, statistical scores only

**Additional Detection Support:**
- `AI/dns_analyzer.py` — DNS tunneling/DGA detection (feeds Signal #2)
- `server/json/dns_security.json` — DNS analyzer metrics
- `AI/tls_fingerprint.py` — Encrypted C2 detection (feeds Signal #8)
- `server/json/tls_fingerprints.json` — TLS fingerprinting data

**Developer Path Guidelines (Stage 2 and Beyond):**
- When adding or modifying detection layers, always resolve local JSON paths via the helpers in `AI/path_helper` (for example `get_json_file("threat_log.json")`, `get_threat_log_file()`), rather than hardcoding `server/json` or `/app/json`.
- ML models for new signals must load from the directory returned by `get_ml_models_dir()` so that training sync and relay-distributed updates remain consistent.
- Any new training exports intended for the relay (for example new `training_datasets/` or `reputation_data/` variants) should build their paths from `get_relay_training_dir()` and append a subdirectory, instead of embedding `relay/ai_training_materials` literals in AI modules.
- Documentation examples should describe JSON and relay locations in terms of these helpers ("JSON directory", "relay training directory") rather than fixed filesystem paths so that Docker/native deployments stay aligned.- **Container path differences:** Customer node containers use `/app/json/` for JSON storage, while relay server containers use `/app/server/json/` because the relay Dockerfile copies the server/ folder to provide path_helper.py and config access.
---

### Stage 3: Ensemble Decision Engine (Sequential Intelligence Modulation)

**Purpose:** Combine 20 signals → weighted voting + causal/trust modulation → final decision (with a separate Step 21 semantic veto layer in `AI/pcs_ai.py`).

**AI Files:**
- `AI/meta_decision_engine.py` — Weighted voting, causal modulation, trust modulation, override logic
- `AI/causal_inference.py` — Root cause analysis (Layer 19)
- `AI/trust_graph.py` — Entity trust scoring (Layer 20)
- `server/json/meta_engine_config.json` — Signal weights (0.65-0.98)
- `server/json/decision_history.json` — Per-signal contributions audit
- `server/json/causal_analysis.json` — Causal inference results
- `server/json/trust_graph.json` — Entity trust state

**5-Step Modulation Flow (as implemented):**

**Note:** All 20 signals (including Layers 19 and 20) participate in Step 1 weighted voting. Layers 19 and 20 then apply **additional modulation** in Steps 3-4 to refine the decision based on causal context and trust state. After the ensemble decision, `AI/pcs_ai.py` invokes the Step 21 semantic gate (`AI/step21_semantic_gate.py`) as a final veto layer before any response is returned.

**Step 1: Weighted Voting (All Signals 1–20)**
- Calculate base score: Σ(weight × confidence × is_threat) / Σ(weight)
- Signal weights: Honeypot 0.98, Threat Intel 0.95, Graph 0.92, Integrity 0.90, Signature 0.90, Trust 0.90, Causal 0.88, LSTM 0.85, Reputation 0.85, FP Filter 0.82, Autoencoder 0.80, RandomForest 0.80, Gradient Boost 0.78, Explainability 0.78, Behavioral 0.75, IsolationForest 0.75, VPN/Tor 0.70, Drift 0.65

**Step 2: Authoritative Signal Boosting**
- Honeypot (confidence ≥0.7) → force score to 90%+
- Threat Intel (confidence ≥0.9) → force score to 90%+
- False Positive Filter (5/5 gates) → boost +10%

**Step 3: Causal Inference Modulation (Layer 19)**
- LEGITIMATE_CAUSE (≥0.85 confidence) → score -20%
- AUTOMATION_SIDE_EFFECT (≥0.80 confidence) → score -15%
- EXTERNAL_ATTACK (≥0.80 confidence) → score +15%
- INSIDER_MISUSE (≥0.75 confidence) → score +10%
- MISCONFIGURATION → route to governance (no auto-block)
- UNKNOWN_CAUSE → human review required

**Step 4: Trust Degradation Modulation (Layer 20)**
- Trust ≥80 → normal operation (no extra boost)
- Trust 60-79 → monitoring (+5% score boost on ensemble vote)
- Trust 40-59 → rate limiting (+10% score boost on ensemble vote)
- Trust 20-39 → isolation (+15% score boost; block once weighted vote ≥60%)
- Trust <20 → auto-quarantine (force block regardless of ensemble score)

**Step 5: Final Decision with Override Logic**
- Global block threshold: 0.75 by default (overridable via `BLOCK_THRESHOLD` env); if `APT_DETECTION_MODE=true`, the engine lowers this to at most 0.70.
- Trust action "quarantine" → force block regardless of weighted score.
- Trust action "isolate" → block if weighted score ≥0.60 (even if global block threshold is higher).
- Otherwise: block if weighted score ≥block_threshold; log-only if weighted score ≥0.50; allow below 0.50.

---

### Stage 4: Response Execution (Policy-Governed)

**Purpose:** Execute actions, log events, send alerts

**Server Files:**
- `server/device_blocker.py` — Firewall blocking (iptables/nftables)
- `server/installation/bh_firewall_sync.py` — Linux kernel firewall sync daemon (5-second sync loop with safety checks, multi-distro support)
- `server/json/blocked_ips.json` — Current blocklist
- `server/json/threat_log.json` — Primary threat log

**AI Files:**
- `AI/firewall_backend.py` — Multi-distribution firewall backend abstraction (iptables-nft/firewalld/VyOS/OpenWRT/Alpine auto-detection, dual-layer enforcement: Priority 1 ACCEPT whitelist + Priority 2 DROP blocklist)
- `AI/alert_system.py` — Email/SMS alerting (SMTP/Twilio) for critical system events (system failure, kill-switch changes, integrity breaches; not general threat alerts)
- `AI/policy_governance.py` — Approval workflows
- `AI/emergency_killswitch.py` — SAFE_MODE override
- `AI/file_rotation.py` — ML training log rotation utility (auto-rotates at 100MB for memory safety)
- `server/json/approval_requests.json` — Pending approvals
- `server/json/comprehensive_audit.json` — Central audit log (all THREAT_DETECTED/INTEGRITY_VIOLATION/SYSTEM_ERROR events)
- `server/json/integrity_violations.json` — Self-protection violations

**Logging Surfaces (Multi-Surface Logging):**
- `server/json/threat_log.json` — Primary threat log (auto-rotates at 100MB → threat_log_1.json, threat_log_2.json, etc.)
- `server/json/comprehensive_audit.json` — Comprehensive audit trail (auto-rotates at 100MB → comprehensive_audit_1.json, etc.)
- `server/json/attack_sequences.json` — LSTM progressions
- `server/json/lateral_movement_alerts.json` — Graph hop chains
- `server/json/behavioral_metrics.json` — Heuristic scores
- `server/json/dns_security.json` — DNS findings
- `server/json/tls_fingerprints.json` — TLS findings
- `server/json/forensic_reports/` — Explainability outputs

**ML Training Log Rotation:** Files used for ML training (`threat_log.json`, `comprehensive_audit.json`, `global_attacks.json`, `learned_signatures.json`) automatically rotate when reaching 100MB (optimized for resource-constrained environments). When rotation occurs, the current file is renamed with a numeric suffix (e.g., `threat_log.json` → `threat_log_1.json`), and a new file is created. This ensures continuous logging without unbounded file growth while preserving all historical attack data for ML training.

---

### Stage 5: Training Material Extraction (Privacy-Preserving)

**Purpose:** Convert attacks → sanitized training materials (no payloads/PII)

**AI Files:**
- `AI/signature_extractor.py` — Extract attack patterns (no exploit code)
- `AI/signature_uploader.py` — Upload signatures to relay
- `AI/reputation_tracker.py` — Export hashed IP reputation
- `AI/graph_intelligence.py` — Anonymize graph topology (A→B→C labels)

**Training Outputs:**
- `relay/ai_training_materials/ai_signatures/learned_signatures.json` — Signature database
- `relay/ai_training_materials/reputation_data/` — Hashed reputation
- `relay/ai_training_materials/training_datasets/` — Feature tables
- `relay/ai_training_materials/explainability_data/` — Decision context

**Privacy Guarantees:**
- ✅ No raw payloads
- ✅ No PII/PHI
- ✅ IP hashing (SHA-256)
- ✅ Metadata only

---

### Stage 6: Global Intelligence Sharing (Optional Relay)

**Purpose:** Push local findings → relay → pull global intel → merge

**Push to Relay:**
- `AI/relay_client.py` — WebSocket client for sanitized threat summaries
- `AI/signature_uploader.py` — Signature sharing
- `AI/training_sync_client.py` — Optional upload of sanitized honeypot patterns (no raw training data)
- `AI/central_sync.py` — Central server sync
- `AI/crypto_security.py` — HMAC authentication
- `server/crypto_keys/` — Shared HMAC keys

**Relay Server:**
- `relay/relay_server.py` — WebSocket relay, HMAC validation (requires AI/crypto_security.py, server/path_helper.py)
- `relay/signature_sync.py` — Signature deduplication
- `relay/ai_training_materials/global_attacks.json` — Central attack log from all customer nodes (auto-rotates at 100MB → global_attacks_1.json, etc.)
- `relay/ai_training_materials/ai_signatures/learned_signatures.json` — Attack pattern signatures for ML training (auto-rotates at 100MB → learned_signatures_1.json, etc.)
- `relay/ai_training_materials/attack_statistics.json` — Aggregated trends
- `relay/ai_training_materials/ai_signatures/learned_signatures.json` — Global signatures

**Pull from Relay:**
- `AI/signature_distribution.py` — Download signatures
- `AI/training_sync_client.py` — Download ONLY pre-trained ML models (no raw training data)
- `relay/training_sync_api.py` — HTTPS model distribution and training stats API (port 60002)

**Relay Infrastructure (NOT shipped to customers):**
- `relay/docker-compose.yml` — Relay deployment (requires AI/, relay/, server/ folders)
- `relay/Dockerfile` — Relay container image (built with context: .. to access all 3 folders)
- `relay/ai_training_materials/` — Training data lake (stored at /app/relay/ai_training_materials/ in container)
- `relay/crypto_keys/` — Relay HMAC keys (mounted to /app/relay/crypto_keys/ in container)

**Required Container Folder Structure:**
- `/app/AI/` — Crypto security (HMAC signing via crypto_security.py), ML models, threat analysis modules
- `/app/relay/` — WebSocket relay server (relay_server.py), model distribution API (training_sync_api.py)
- `/app/server/` — Path utilities (path_helper.py), JSON config access
- `/app/server/json/` — Server JSON directory (used by AI modules via path_helper for relay-side configs)

---

### Stage 7: Continuous Learning Loop

**Purpose:** Automated improvement → signature updates → ML retraining → baseline adaptation

**Hourly: Signature Auto-Update**
- `AI/signature_distribution.py` — Pull new signatures from relay

**Weekly: ML Retraining**
- `relay/ai_retraining.py` — Feature extraction → model training
- `relay/gpu_trainer.py` — GPU-accelerated deep learning
- `relay/ai_training_materials/training_datasets/` — Feature tables
- `relay/ai_training_materials/ml_models/` — Updated models
- `relay/ai_training_materials/trained_models/` — Model archive

**Daily: Reputation Decay**
- `AI/reputation_tracker.py` — Half-life decay (30 days)

**Monthly: Drift Baseline Refresh**
- `AI/drift_detector.py` — Baseline update, retraining triggers
- `server/json/drift_baseline.json` — Updated baseline

**Continuous: Byzantine Validation**
- `AI/byzantine_federated_learning.py` — Reject poisoned updates (94% accuracy)
- `server/json/comprehensive_audit.json` — Rejected update events
- `relay/ai_training_materials/global_attacks.json` — `attack_type="federated_update_rejected"`

**Feedback Sources:**
- `AI/real_honeypot.py` — 100% confirmed attacks (highest quality)
- Human validation → ML improvement
- False positive reports → FP filter tuning

---

### Enterprise Extensions (Auxiliary / Non-Core, Optional)

These modules provide optional enterprise-style capabilities (identity/SSO/RBAC, cloud posture, backup/compliance reporting, vulnerability management, etc.) that sit **outside** the core first-layer execution-denial surface. Their HTTP APIs are disabled by default in the core server and they should be treated as lab/auxiliary tooling unless explicitly enabled and wired by an operator.

**User & Identity Monitoring:**
- `AI/user_tracker.py` — UEBA, session tracking
- `server/json/tracked_users.json` — User behavior data

**Zero Trust:**
- `AI/zero_trust.py` — Zero trust posture scoring (DLP-related features are experimental and non-core)

**Cloud / Backup / Compliance / Vulnerability (Auxiliary):**
- `AI/cloud_security.py` — Experimental cloud security posture checks for AWS/Azure/GCP (CSPM-style), persisting snapshots to `server/json/cloud_findings.json`.
- `AI/backup_recovery.py` — Experimental backup monitoring and ransomware resilience analysis, writing `server/json/backup_status.json` and `server/json/recovery_tests.json` when used.
- `AI/compliance_reporting.py` — Generates PCI/HIPAA/GDPR/SOC2-style compliance summaries in `server/json/compliance_reports/`.
- `AI/vulnerability_manager.py` — CVE/SBOM-based vulnerability aggregation using `server/json/sbom.json`.

**Analysis & Evaluation Helpers:**
- `AI/file_analyzer.py` — File hashing, metadata extraction.
- `AI/formal_threat_model.py` — Structured attack scenarios.
- `AI/deterministic_evaluation.py` — Model validation harnesses.

---

## Server Infrastructure Files

**Dashboard & API:**
- `server/server.py` — Flask application (REST APIs, dashboard serving)
- `AI/inspector_ai_monitoring.html` — Core first-layer dashboard UI
- `AI/swagger_ui.html` — API documentation UI
- Dashboard/API failures → `comprehensive_audit.json` as `SYSTEM_ERROR` events

**Deployment:**
- `server/Dockerfile` — Server container image
- `server/docker-compose.yml` — Linux deployment
- `server/entrypoint.sh` — Container entrypoint
- `server/.env` — Primary server environment file for Linux/Docker deployments.
- `packaging/windows/dist/.env.windows` — Windows EXE environment file that ships alongside `BattleHardenedAI.exe` in the Windows packaging dist folder.
- `server/requirements.txt` — Python dependencies

**Installation & Startup (server/installation/):**
- `server/installation/bh_firewall_sync.py` — Linux kernel firewall sync daemon (5-second sync loop with safety checks, multi-distro support)
- `server/installation/init_json_files.py` — Creates all 35+ required JSON files at startup
- `server/installation/watchdog.py` — Production auto-restart monitor (crash protection)
- `server/installation/gunicorn_config.py` — Production Gunicorn config (sync workers)
- `server/installation/gunicorn_config_extreme.py` — Extreme-scale config (async workers, 640k+ connections)
- `server/installation/start_extreme_scale.sh` — Extreme-scale startup script with requirement checks

**Packaging & OS Integration (packaging/):**
- `packaging/debian/` — Debian/Ubuntu package metadata and build scripts for .deb packaging.
- `packaging/systemd/` — Systemd unit/service definitions for Linux deployments.
- `packaging/windows/BattleHardenedAI.iss` — Inno Setup script for building the Windows installer from the local `packaging/windows/dist/` output.
- `packaging/windows/BattleHardenedAI.spec` — PyInstaller spec used to build the Windows EXE from the repository root into `packaging/windows/dist/`; bundles all AI/*.py modules and critical server modules (device_scanner.py, network_monitor.py).
- `packaging/windows/build_windows_exe.ps1` — PowerShell script that builds `BattleHardenedAI.exe` via PyInstaller into `packaging/windows/dist/`.
- `packaging/windows/build_windows_installer.ps1` — PowerShell script that invokes `build_windows_exe.ps1` (if needed) and `BattleHardenedAI.iss` to produce the Windows installer.

**Reporting:**
- `server/report_generator.py` — Enterprise security reports (HTML/JSON)

**Testing:**
- `server/test_system.py` — System validation harness

**Audit Archives:**
- `server/json/audit_archive/` — Rotated audit logs

**Device Management:**
- `server/json/blocked_devices.json` — ARP-blocked devices (via `device_blocker.py`)

**Git Tracking:**
- `server/.dockerignore` — Docker build exclusions
- `server/json/.gitkeep` — Ensures JSON directory exists in Git

---

## Relay Infrastructure Files (Operator-Only)

**Relay Server:**
- `relay/relay_server.py` — WebSocket relay + HMAC validation
- `relay/signature_sync.py` — Signature/attack storage
- `relay/training_sync_api.py` — Model distribution API
- `relay/start_services.py` — Multi-service orchestration

**Training & Retraining:**
- `relay/ai_retraining.py` — ML retraining pipeline
- `relay/gpu_trainer.py` — GPU-accelerated training

**Threat Intelligence:**
- `relay/exploitdb_scraper.py` — ExploitDB pattern generation
- `relay/threat_crawler.py` — OSINT crawler (CVE, MalwareBazaar, URLhaus, AlienVault OTX)

**Deployment:**
- `relay/Dockerfile` — Relay container image
- `relay/docker-compose.yml` — Relay deployment
- `relay/.env.relay` — Relay environment config
- `relay/requirements.txt` — Python dependencies
- `relay/setup.sh` — Relay server installer
- `relay/setup_exploitdb.sh` — ExploitDB setup

**Training Materials:**
- `relay/ai_training_materials/README.md` — Training data documentation
- `relay/ai_training_materials/global_attacks.json` — Central attack log (all customer nodes, all stages)
- `relay/ai_training_materials/attack_statistics.json` — Aggregated statistics
- `relay/ai_training_materials/ai_signatures/` — Global signature database
- `relay/ai_training_materials/exploitdb/` — ExploitDB mirror
- `relay/ai_training_materials/threat_intelligence/` — Crawled threat intel
- `relay/ai_training_materials/reputation_data/` — Global reputation
- `relay/ai_training_materials/trained_models/` — Model archive
- `relay/ai_training_materials/ml_models/` — Active models for distribution
- `relay/ai_training_materials/training_datasets/` — Feature tables
- `relay/crypto_keys/` — Relay HMAC keys (shared_secret.key and related material used by relay_server.py)

**Documentation:**
- `relay/README.md` — Relay architecture and deployment guide

---

## File Naming Conventions

**Customer node components in the source tree (server/ + AI/):**
- `server/json/*.json` — Runtime state (`.gitignored`, created at runtime). In packaged Linux/Windows builds these live under the internal JSON directory resolved by AI/path_helper, even though you may not see the raw `server/json` folder on disk.
- `AI/*.py` — Detection modules, orchestration, honeypot, governance (bundled into the Linux package/Windows EXE for customers; visible only when working from the Git source tree).
- `AI/ml_models/` — Canonical ML models directory (RandomForest, IsolationForest, GradientBoosting, scaler, sequence LSTM, node fingerprint, signature cache) used by both source-based and packaged deployments.

**Relay (relay/):**
- `relay/ai_training_materials/` — Training data lake (NOT accessible to customers)
- `relay/*.py` — Relay services, training, crawlers

**Configuration:**
- `.env`, `.env.*` — Environment variables (ports, features, relay URLs)
- `*_config.json` — Runtime configuration (meta engine, FP filter)

**Logs & Audit:**
- `*_log.json` — Event logs (threat, comprehensive audit)
- `*_status.json` — State snapshots (backup, cloud)
- `*_history.json` — Historical data (device, attack sequences)

---

**For testing procedures, see:** [AI instructions Section 9](Ai-instructions.md#9-testing--validation-guide-10-stage-progressive-validation) (10-stage validation mapped to pipeline)
**For API reference, see:** [Dashboard](Dashboard.md) (dashboard sections mapped to pipeline stages)
**For implementation guide, see:** [AI instructions](Ai-instructions.md) (developer guide with pipeline implementation details)

---

## Detailed File Descriptions

### AI Folder

- AI/adaptive_honeypot.py — Adaptive honeypot configuration and management (complements real_honeypot.py with dynamic port/service adaptation).
- AI/advanced_orchestration.py — Advanced orchestration engine for predictive threat modeling, automated responses, custom alert rules, topology export, and training/orchestration data export.
- AI/advanced_visualization.py — Generates network topology, attack flows, heatmaps, geo maps, and timelines from JSON logs for use in dashboards.
- AI/alert_system.py — Email/SMS alerting (SMTP/Twilio) for critical SYSTEM events only (system failure, kill-switch changes, integrity breaches); does NOT send general threat alerts. See Dashboard.md Section 23 for current dashboard mapping.
- AI/asset_inventory.py — Builds a hardware/software asset inventory from local scans and connected_devices.json, tracking EOL and shadow IT risks.
- AI/backup_recovery.py — Monitors backup locations, estimates ransomware resilience, tracks recovery tests, writes backup_status.json/recovery_tests.json, and logs backup_issue/ransomware_resilience_low posture issues into the comprehensive audit log and (when present) relay global_attacks.json.
- AI/behavioral_heuristics.py — Behavioral engine that tracks per-entity connection/auth patterns and computes heuristic risk scores.
- AI/byzantine_federated_learning.py — Byzantine-resilient federated learning aggregator (Krum, Multi-Krum, trimmed mean, median) with peer reputation and audit/relay logging for rejected/poisoned updates.
- AI/central_sync.py — Optional central server sync client that uploads sanitized threat summaries and ingests global threat patterns.
- AI/cloud_security.py — Cloud security posture checks for AWS/Azure/GCP using CLIs, with misconfig, IAM, encryption, and exposure summaries, persisting snapshots to cloud_findings.json and escalating high/critical issues into the comprehensive audit log and relay global_attacks.json.
- AI/compliance_reporting.py — Generates PCI/HIPAA/GDPR/SOC2 compliance reports and control-mapping views from local telemetry and SBOM/asset data, writing JSON reports under server/json/compliance_reports and logging compliance_issue events into the comprehensive audit log and relay global_attacks.json.
- AI/cryptographic_lineage.py — Tracks cryptographic provenance, key usage, and signature lineage for auditability, and surfaces lineage integrity/drift issues into the comprehensive audit log (and, when configured, relay global_attacks.json).
- AI/crypto_security.py — Central cryptography helper (HMAC, signing, verification, key handling) used by server and relay for secure messaging.
- AI/deterministic_evaluation.py — Provides deterministic evaluation harnesses and scoring for AI models using fixed datasets.
- AI/drift_detector.py — Monitors model input/output statistics over time to detect data/model drift and trigger retraining.
- AI/emergency_killswitch.py — Implements emergency kill switches to safely disable or downgrade AI actions under operator control and hosts the central comprehensive_audit.json log used by other modules for THREAT_DETECTED/ACTION_TAKEN/INTEGRITY_VIOLATION/SYSTEM_ERROR events.
- AI/enterprise_integration.py — Optional adapter that exports decisions and evidence to enterprise tools (SIEM, ticketing, ITSM) and external APIs; disabled by default and does not orchestrate response flows inside Battle-Hardened AI.
- AI/explainability_engine.py — Builds human-readable explanations and feature attributions for AI decisions and threat scores, maintains decision history, and emits forensic_reports JSON plus optional explainability_data for training.
- AI/exploitdb — Placeholder directory for future local ExploitDB cache (currently, ExploitDB data is only stored on relay server at `relay/ai_training_materials/exploitdb/`).
- AI/false_positive_filter.py — Filters noisy detections using heuristics and metadata to reduce false positives before reaching the dashboard.
- AI/firewall_backend.py — Multi-distribution firewall backend abstraction layer supporting iptables-nft (Debian/Ubuntu), firewalld (RHEL/Rocky/Alma/SUSE), VyOS, OpenWRT, and Alpine Linux; implements dual-layer enforcement with Priority 1 ACCEPT whitelist rules and Priority 2 DROP blocklist rules, auto-detects backend on startup, and provides unified API for firewall operations across distributions.
- AI/file_analyzer.py — Analyzes files and artifacts (hashing, type, basic features) for use in malware/intel workflows.
- AI/file_rotation.py — ML training log rotation utility that auto-rotates large log files (threat_log.json, comprehensive_audit.json, global_attacks.json) at 100MB to prevent unbounded growth on memory-constrained servers.
- AI/formal_threat_model.py — Encodes a higher-level formal threat model, mapping signals and components into structured attack scenarios.
- AI/graph_intelligence.py — Builds and queries graph-based views of entities, connections, and attacks for graph-driven reasoning.
- AI/inspector_ai_monitoring.html — Main HTML dashboard template rendered by server.py to show AI monitoring and visualizations.
- AI/kernel_telemetry.py — Handles kernel/eBPF/XDP telemetry ingestion and feature extraction on supported hosts.
- AI/meta_decision_engine.py — Core meta-decision engine that fuses multiple signals/detections into final threat decisions and actions.
- AI/ml_models/sequence_lstm.keras — Saved Keras LSTM model for attack sequence prediction and kill-chain progression detection (Signal #7).
- AI/network_performance.py — Tracks per-IP bandwidth, performance metrics, and network health, writing into network_performance.json.
- AI/node_fingerprint.py — Creates device/node fingerprints from observed behavior and attributes for long-term identification.
- AI/p2p_sync.py — Handles peer-to-peer sync logic for nodes in the mesh (metadata/state exchange between peers).
- AI/path_helper.py — Universal path resolution helper that works across Docker containers (/app/) and native installations, ensuring correct paths for json/, ml_models/, and crypto_keys/ directories.
- AI/pcap_capture.py — Packet capture helper for saving traffic (pcap) samples for offline analysis or training.
- AI/pcs_ai.py — Central AI orchestrator and source of truth: wires together models, detection modules (including DNS/TLS analyzers), logs, and the dashboard API, tags relay-bound threats with a stable sensor_id, and routes integrity/lineage/federated/cloud/backup/compliance signals into the audit/relay paths.
- AI/policy_governance.py — Models security policies, approvals, and governance workflows around automated actions.
- AI/relay_client.py — Client-side relay connector used by customer nodes to talk to the relay WebSocket mesh (threat sharing, stats, no model downloads).
- AI/reputation_tracker.py — Maintains local IP/domain reputation, aggregating stats from threat logs and external intel.
- AI/self_protection.py — Implements self-protection checks so the AI/agent can detect tampering or local compromise, writing violations into integrity_violations.json and comprehensive_audit.json and optionally triggering the kill switch.
- AI/sequence_analyzer.py — Sequence analysis utilities for logs/traffic, feeding sequence models like the LSTM.
- AI/signature_distribution.py — Manages downloading and applying signatures/models distributed from the relay or central sources.
- AI/signature_extractor.py — Extracts signatures and patterns from attacks/honeypot hits for later training and sharing.
- AI/signature_uploader.py — Prepares and uploads privacy-preserving signatures to the relay/signature_sync service.
- AI/soar_api.py — Experimental API surface for SOAR-style lab workflows; disabled by default and not part of the core first-layer control (no orchestration in the default deployment).
- AI/soar_workflows.py — Experimental library of SOAR-style workflows/runbooks used only in lab environments; persists cases into soar_incidents.json when explicitly enabled but is disabled in the default first-layer deployment and does not drive autonomous response.
- AI/swagger_ui.html — Embedded Swagger UI HTML used to expose and document the local API when enabled.
- AI/system_log_collector.py — Collects system logs and events into structured JSON for analysis by other AI modules.
- AI/threat_intelligence.py — Local threat intelligence aggregator that merges external feeds and local observations.
- AI/dns_analyzer.py — DNS security analyzer that uses metadata-only heuristics (tunneling/DGA/exfil) to score DNS activity and write aggregated metrics into dns_security.json.
- AI/tls_fingerprint.py — TLS/encrypted-flow fingerprinting engine that tracks non-standard TLS ports and suspicious encrypted C2 patterns, writing per-IP metrics into tls_fingerprints.json.
- AI/traffic_analyzer.py — Higher-level traffic analysis module that combines metrics and detections from network monitors.
- AI/training_sync_client.py — Customer-side client for downloading pre-trained ML models from the relay’s HTTPS training API and optionally uploading sanitized honeypot patterns (never raw training data).
- AI/user_tracker.py — Tracks user accounts and behavior patterns (logins, anomalies) on the protected environment.
- AI/vulnerability_manager.py — Manages vulnerability findings and risk views, tying CVEs/scan data into the dashboard.
- AI/zero_trust.py — Implements zero-trust style checks and posture scoring for devices/users/services.

---

## Server Folder

- server/.dockerignore — Excludes unneeded files from the server Docker build context.
- server/.env — Main environment file for the server container (ports, relay URLs, feature flags, API keys, etc.).
- server/.env.linux — Example/server env template tuned for Linux/host-network deployments.
- `packaging/windows/.env.windows` — Canonical Windows environment template used by the EXE build and installer; copied into packaging/windows/dist/.env.windows and ultimately installed as .env.windows next to BattleHardenedAI.exe.
- `server/crypto_keys/` — Holds all cryptographic materials: HMAC keys (shared_secret.key, private_key.pem, public_key.pem) for relay authentication and SSL certificates (ssl_cert.pem, ssl_key.pem) for HTTPS dashboard.
- `server/debug_server.py` — Development server for testing without Gunicorn (single-threaded Flask dev mode).
- `server/device_blocker.py` — Implements ARP-based device blocking and unblocking, persisting blocked_devices.json.
- `server/device_scanner.py` — Scans the local network for devices using ARP discovery via Scapy, with cross-platform network detection (Linux: ip route/addr, Windows: ipconfig parsing, fallback: socket.connect() to detect local IP), classifies them by vendor/type, and populates connected_devices.json and device_history.json.
- `server/docker-compose.yml` — Docker Compose definition for the Linux/host-network server deployment with required capabilities.
	- Windows runs natively via `server/installation/watchdog.py` during development; production Windows deployments typically use the packaged `BattleHardenedAI.exe` installer. Docker deployment is Linux-only via `server/docker-compose.yml`.
- server/Dockerfile — Builds the server container image, installing dependencies, copying AI code, and wiring HTTPS/gunicorn.
- server/entrypoint.sh — Container entrypoint that launches server.py and gunicorn with TLS certificates from crypto_keys/ directory.
- server/installation/bh_firewall_sync.py — Linux kernel firewall synchronization daemon that runs as a systemd service (battle-hardened-ai-firewall-sync.service); syncs blocked_ips.json and whitelist.json to native Linux firewall every 5 seconds with safety checks to prevent whitelisted IPs from being blocked, supports multiple firewall backends via AI/firewall_backend.py, and logs sync operations to journalctl.
- server/installation/init_json_files.py — Python script that creates all 35+ required JSON files at server startup with proper initialization.
- server/installation/watchdog.py — Production auto-restart monitor that wraps Gunicorn with crash detection and recovery (recommended for production deployments).
- server/installation/gunicorn_config.py — Production Gunicorn configuration with sync workers optimized for 4k-8k concurrent connections.
- server/installation/gunicorn_config_extreme.py — Extreme-scale Gunicorn configuration using gevent async workers for 640k+ concurrent connections.
- server/installation/start_extreme_scale.sh — Extreme-scale startup script that validates gevent installation and starts with gunicorn_config_extreme.py.
- server/error.log — Flask/Gunicorn error log file (auto-created at runtime).
- server/pcap/ — Directory for stored packet capture files (.pcap format) for offline analysis and training.
- server/relay/ — Symlink or directory for relay-related client files (alternative organization structure).
- server/json/.gitkeep — Placeholder file ensuring the json directory exists in version control.
- server/json/approval_requests.json — Persists operator approval/exception requests for governance and change control.
- server/json/audit_archive/ — Storage for archived audit reports and historical compliance outputs.
- server/json/blocked_ips.json — Current list of blocked IPs chosen by AI/operator actions.
- server/json/connected_devices.json — Snapshot of currently known network devices and their attributes.
- server/json/crypto_mining.json — Crypto-mining detection activity from Signal #8 (Traffic Analysis layer), displayed in Dashboard Section 17. Not related to the deprecated "Cryptocurrency Mining" label that briefly appeared in Section 22 docs (see Dashboard.md for current section mapping).
- server/json/device_history.json — Historical device inventory with ports/types over time for forensics and trend analysis.
- server/json/forensic_reports/ — Folder for structured incident explainability reports generated by AI or operators for offline analysis (no separate hunting console).
- server/json/network_monitor_state.json — Persistent state for the live network monitor (counters, trackers, thresholds).
- server/json/network_performance.json — Historical bandwidth and performance metrics per IP recorded by network_performance.py.
- server/json/dns_security.json — Aggregated DNS behavior metrics and suspicious query counts written by AI/dns_analyzer.py from live DNS traffic.
- server/json/tls_fingerprints.json — Aggregated TLS/encrypted-flow fingerprints per source IP written by AI/tls_fingerprint.py.
- server/json/comprehensive_audit.json — Central append-only audit log for security, governance, integrity, lineage, federated, and dashboard/API events, maintained by EmergencyKillSwitch and consumed across the pipeline.
- server/json/integrity_violations.json — Records integrity and self-protection violations detected by AI/self_protection.py.
- server/json/cloud_findings.json — (Auxiliary) Stores recent cloud security posture snapshots and misconfiguration findings from AI/cloud_security.py when that module is used.
- server/json/backup_status.json — (Auxiliary) Summaries of backup jobs, freshness, and status from AI/backup_recovery.py when that module is used.
- server/json/recovery_tests.json — (Auxiliary) Results of recovery/restore tests used to estimate ransomware resilience in AI/backup_recovery.py.
- server/json/compliance_reports/ — (Auxiliary) Directory for JSON compliance reports (PCI, HIPAA, GDPR, SOC2) written by AI/compliance_reporting.py.
- server/json/sbom.json — (Auxiliary) Software bill of materials (SBOM) for the deployment, listing packages and versions.
 - server/json/admin_users.json — Local dashboard admin accounts (username, salted password hash, role, optional auth_backend such as local or ldap).
 - server/json/identity_access_config.json — Zero Trust identity and access configuration for admin login (MFA requirement, LDAP/AD settings, OIDC SSO endpoints, issuer, client ID/secret, redirect URI).
 - server/json/cluster_config.json — Cluster identity and failover configuration (cluster_name, node_id, role, peer_nodes, health-check and config-sync intervals, config_sync_paths).
 - server/json/whitelist.json — Operator-managed IP whitelist for infrastructure and SOC workstations that must never be blocked at HTTP; still fully logged and analyzed by the detection pipeline.
 - server/json/support_tickets.json — Local support portal ticket store backing the /support UI and `/api/support/tickets` JSON APIs.
- server/json/threat_log.json — Main threat log of detections and actions generated by AI and network monitor.
- server/json/tracked_users.json — Storage for tracked user accounts and related behavioral data.
- `server/network_monitor.py` — Scapy-based live network sniffer that detects scans, floods, ARP spoofing, and feeds behavioral heuristics, graph intelligence, DNS analyzer, TLS fingerprinting, and pcs_ai; includes relay client integration via `_share_threat_to_relay()` for automatic threat sharing to global relay server; bundled in Windows EXE builds via BattleHardenedAI.spec.
- `server/report_generator.py` — Standalone HTML/JSON report generator for enterprise-style security reports that stitches together threat statistics, explainability data, and compliance summaries.
- `server/requirements.txt` — Python dependency list for building the server image (includes Flask-CORS==4.0.0 for cross-origin API requests).
- server/server.py — Flask dashboard/API server that renders inspector_ai_monitoring.html and exposes REST/JSON endpoints (traffic, DNS/TLS, explainability, audit, visualization, compliance), including logging dashboard/API failures as SYSTEM_ERROR events into comprehensive_audit.json.
- server/test_system.py — System-level test harness for validating that core services and integrations are functioning.
 - server/logs/ — Runtime log directory (includes startup.log, error.log, and other rotating server logs).
 - packaging/windows/windows-firewall/ — Windows Firewall helper scripts (source location) that are installed as `{app}/windows-firewall` to apply the AI-managed block lists on Windows nodes.

---

## Relay Folder

**Note:** The relay server Docker deployment requires 3 folders from the workspace:
- `AI/` → `/app/AI/` (crypto security, ML models)
- `relay/` → `/app/relay/` (WebSocket server, training API)
- `server/` → `/app/server/` (path_helper.py, JSON configs)

This is configured in `relay/Dockerfile` with `context: ..` so Docker can access the parent directory.

- relay/.env — Active relay server environment configuration (used by Docker Compose).
- relay/documents/Ai_training_commands.md — Relay AI training command reference and usage examples.
- relay/documents/Automation_fix.md — Notes and fixes for automating relay deployment and training flows.
- relay/documents/Docker_deployment.md — Relay Docker deployment guide and container lifecycle notes.
- relay/documents/Model_distribution_proof.md — Documentation proving relay model distribution is working correctly.
- relay/documents/Quick_commands.md — Common one‑liner commands for operating the relay.
- relay/documents/Relay_readme.md — Relay-specific architecture and operational overview.
- relay/documents/Relay_setup.md — Complete relay server deployment guide (supersedes earlier root‑level setup scripts).
- relay/ai_retraining.py — Relay-side retraining manager that consumes ai_training_materials and exports updated models.
- relay/ai_training_materials/ — On-disk training corpus for the relay (global_attacks, signatures, ExploitDB, models, datasets).
- relay/ai_training_materials/ai_signatures/ — Stores learned_signatures.json created by ExploitDB scraper and signature_sync.
- relay/crypto_keys/ — Holds the relay's HMAC authentication keys (shared_secret.key, public_key.pem) for client validation and encrypted communication.
- relay/ai_training_materials/exploitdb/ — Local checkout of ExploitDB (CSV and exploits) used by exploitdb_scraper.py.
- relay/ai_training_materials/README.md — Explains the layout/usage of the relay training materials directory.
- relay/ai_training_materials/reputation_data/ — Stores aggregate reputation/intel data derived from crawlers and attacks.
- relay/ai_training_materials/threat_intelligence/ — Stores raw/int-derived threat intel from crawlers for training.
- relay/ai_training_materials/trained_models/ — Archive of trained model artifacts produced by relay training runs.
- relay/ai_training_materials/training_datasets/ — Prepared feature/label datasets ready for model training or GPU training.
 - relay/ai_training_materials/global_attacks.json — Central sanitized global attack/event log aggregated from customer nodes across all stages (core, honeypot, federated, and any optional auxiliary modules).
 - relay/ai_training_materials/attack_statistics.json — Aggregated statistics and trends derived from global_attacks.json, used for dashboards and analytics.
- relay/docker-compose.yml — Compose file to run the relay server with host networking and mounted training data.
- relay/Dockerfile — Builds the relay container image with WebSocket relay, training API, and training tools.
- relay/exploitdb_scraper.py — Scrapes a local/remote ExploitDB CSV to derive attack patterns and export learned_signatures.json.
- relay/gpu_trainer.py — Optional GPU-accelerated training pipeline using TensorFlow/PyTorch on ai_training_materials datasets.
- relay/relay_server.py — WebSocket relay for the security mesh; verifies HMAC, relays messages, and logs global attacks/stats.
- relay/requirements.txt — Python dependency list for the relay image (websockets, Flask, ML stack).
- relay/installation/entrypoint.sh — Container/host entrypoint wrapper for starting the relay services.
- relay/installation/quick_deploy.sh — One‑shot installer that hardens the relay host (Docker, firewall) and launches the relay stack; replaces the older setup.sh flow.
- relay/installation/relay-server.service — Systemd unit file for running the relay as a managed Linux service.
- relay/signature_sync.py — File-based signature and global attack synchronization service used by relay_server for storage.
- relay/start_services.py — Orchestration script that launches relay_server.py and training_sync_api.py as parallel services.
- relay/threat_crawler.py — Threat intel crawler suite for CVEs, MalwareBazaar, AlienVault OTX, URLhaus, and sample AttackerKB data.
- relay/training_sync_api.py — Flask-based model distribution API that serves only pre-trained models and training stats to subscribers.
