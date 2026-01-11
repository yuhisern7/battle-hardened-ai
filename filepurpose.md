# File Purpose Overview: 7-Stage Pipeline Implementation

This document maps each file in `AI/`, `server/`, and `relay/` folders to the **7-stage attack detection pipeline** documented in the README.

**For installation instructions, see [INSTALLATION.md](INSTALLATION.md)**  
**For relay server setup, see [relay/RELAY_SETUP.md](relay/RELAY_SETUP.md)**  
**For attack testing, see [KALI_ATTACK_TESTS.md](KALI_ATTACK_TESTS.md)**

**Pipeline Stages:**
1. **Data Ingestion & Normalization** → Packet capture, metadata extraction
2. **20 Parallel Detections** → Independent threat assessments (18 primary + 2 strategic intelligence layers)
3. **Ensemble Voting** → Weighted consensus decision
4. **Response Execution** → Firewall blocks, logging, alerts
5. **Training Extraction** → Privacy-preserving signatures
6. **Relay Sharing** → Global intelligence exchange
7. **Continuous Learning** → ML retraining, adaptation

---

## Critical JSON Surfaces by Pipeline Stage

| Pipeline Stage | Local JSON (server/json/) | Relay JSON (relay/ai_training_materials/) | Purpose |
|----------------|---------------------------|-------------------------------------------|---------|
| **Stage 1: Data Ingestion** | `connected_devices.json`, `device_history.json`, `network_monitor_state.json` | N/A | Device discovery, packet capture state |
| **Stage 2: 20 Parallel Detections** | `threat_log.json`, `dns_security.json`, `tls_fingerprints.json`, `network_graph.json`, `lateral_movement_alerts.json`, `attack_sequences.json`, `behavioral_metrics.json`, `drift_baseline.json`, `drift_reports.json`, `model_lineage.json`, `reputation.db`, `causal_analysis.json`, `trust_graph.json` | N/A | Individual signal outputs (18 primary + 2 strategic) |
| **Stage 3: Ensemble Voting** | `decision_history.json`, `meta_engine_config.json`, `fp_filter_config.json` | N/A | Weighted voting, thresholds |
| **Stage 4: Response Execution** | `threat_log.json`, `blocked_ips.json`, `comprehensive_audit.json`, `integrity_violations.json`, `forensic_reports/`, `causal_analysis.json`, `trust_graph.json` | N/A | Actions, logging, alerts, causal & trust state |
| **Stage 5: Training Extraction** | `local_threat_intel.json`, `reputation_export.json` | `ai_signatures/learned_signatures.json`, `reputation_data/`, `training_datasets/`, `explainability_data/` | Privacy-preserving materials |
| **Stage 6: Relay Sharing** | `crypto_keys/` (HMAC auth) | `global_attacks.json`, `attack_statistics.json`, `ai_signatures/learned_signatures.json`, `threat_intelligence/`, `ml_models/` | Global intelligence |
| **Stage 7: Continuous Learning** | `drift_baseline.json`, `comprehensive_audit.json` (Byzantine events) | `trained_models/`, `ml_models/` (updated), `training_datasets/` | Retraining, adaptation |
| **Enterprise Extensions** | `soar_incidents.json`, `cloud_findings.json`, `backup_status.json`, `recovery_tests.json`, `compliance_reports/`, `sbom.json` | `global_attacks.json` (enterprise incidents) | SOAR, cloud, backup, compliance |

---

## File Map by Pipeline Stage

### Stage 1: Data Ingestion & Normalization

**Purpose:** Capture packets, extract metadata, normalize events

**Server Files:**
- `server/network_monitor.py` — Live packet capture (Scapy/eBPF), feeds all detection signals
- `server/device_scanner.py` — Network device discovery and asset enumeration
- `server/json/connected_devices.json` — Active device inventory
- `server/json/device_history.json` — 7-day device connection history
- `server/json/network_monitor_state.json` — Packet capture state and counters

**AI Files:**
- `AI/kernel_telemetry.py` — eBPF/XDP kernel telemetry (Linux only)
- `AI/system_log_collector.py` — System log ingestion and normalization
- `AI/pcap_capture.py` — PCAP saving for forensics
- `AI/asset_inventory.py` — Asset inventory management

---

### Stage 2: Parallel Multi-Signal Detection (20 Signals)

**Purpose:** 20 independent detection systems produce threat assessments (18 primary + 2 strategic intelligence layers)

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
- `AI/pcs_ai.py` — Loads `ml_models/threat_classifier.pkl`
- `ml_models/threat_classifier.pkl` — RandomForest classifier

**Signal #4: IsolationForest**
- `AI/pcs_ai.py` — Loads `ml_models/anomaly_detector.pkl`
- `ml_models/anomaly_detector.pkl` — IsolationForest anomaly detector

**Signal #5: Gradient Boosting**
- `AI/pcs_ai.py` — Loads `ml_models/ip_reputation.pkl`
- `ml_models/ip_reputation.pkl` — Gradient boosting reputation model

**Signal #6: Behavioral Heuristics**
- `AI/behavioral_heuristics.py` — 15 metrics + APT patterns (low-and-slow, off-hours, credential reuse)
- `server/json/behavioral_metrics.json` — Per-IP heuristic scores

**Signal #7: LSTM Sequences**
- `AI/sequence_analyzer.py` — Kill-chain state progression + APT campaign patterns
- `AI/ml_models/sequence_lstm.keras` — LSTM model
- `server/json/attack_sequences.json` — Sequence history

**Signal #8: Autoencoder**
- `AI/traffic_analyzer.py` — Zero-day anomaly detection via reconstruction error
- `AI/ml_models/traffic_autoencoder.keras` — Autoencoder model
- `AI/network_performance.py` — Network performance metrics

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
- `AI/advanced_orchestration.py` — 24-48h threat forecasting
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

**STRATEGIC INTELLIGENCE LAYERS (19-20): Context-aware analysis consuming signals 1-18**

**Signal #19: Causal Inference Engine**
- `AI/causal_inference.py` — Root cause analysis (WHY attacks happen, not just THAT they happened)
- `server/json/causal_analysis.json` — Causal inference logs (auto-rotates at 10,000 entries)
- **Purpose:** Distinguishes legitimate operational changes from disguised attacks
- **Inputs:** Primary signals (1-18), deployment events, config changes, identity events (login/privilege changes)
- **Output:** Causal labels (LEGITIMATE_CAUSE, AUTOMATION_SIDE_EFFECT, EXTERNAL_ATTACK, INSIDER_MISUSE, MISCONFIGURATION, UNKNOWN_CAUSE)
- **Score Modulation:** Downgrade by -20% (legitimate), boost by +15% (attack), route to governance (misconfiguration)
- **Position:** Runs AFTER primary signals, BEFORE ensemble decision
- **Privacy:** Metadata-only analysis, no payloads/credentials/PII

**Signal #20: Trust Degradation Graph**
- `AI/trust_graph.py` — Zero-trust enforcement with persistent entity trust tracking
- `server/json/trust_graph.json` — Entity trust state (persistent across restarts)
- **Purpose:** Persistent memory prevents "try again later" strategies via non-linear trust degradation
- **Tracked Entities:** IPs, devices, user accounts, services, APIs, cloud roles, containers (SHA-256 hashed)
- **Trust Model:** 0-100 scale, event-weighted penalties (minor_anomaly=-5 to repeated_attack=-50), natural recovery (+1/day capped at 80% baseline)
- **Actions:** ALLOW (≥80), MONITOR (60-79), RATE_LIMIT (40-59), ISOLATE (20-39), QUARANTINE (<20)
- **Recidivism:** 3+ attacks in 7 days = exponential penalty
- **Position:** Influences Stage 4 response severity, tracked by explainability engine (Signal #15)
- **Privacy:** SHA-256 entity hashing, no PII, statistical scores only

**Additional Detection Support:**
- `AI/dns_analyzer.py` — DNS tunneling/DGA detection (feeds Signal #2)
- `server/json/dns_security.json` — DNS analyzer metrics
- `AI/tls_fingerprint.py` — Encrypted C2 detection (feeds Signal #8)
- `server/json/tls_fingerprints.json` — TLS fingerprinting data
- `AI/adaptive_honeypot.py` — Multi-persona honeypot (training source for Signal #2)

---

### Stage 3: Ensemble Decision Engine (Sequential Intelligence Modulation)

**Purpose:** Combine 20 signals → 5-step sequential modulation → final decision

**AI Files:**
- `AI/meta_decision_engine.py` — Weighted voting, causal modulation, trust modulation, override logic
- `AI/causal_inference.py` — Root cause analysis (Layer 19)
- `AI/trust_graph.py` — Entity trust scoring (Layer 20)
- `server/json/meta_engine_config.json` — Signal weights (0.65-0.98)
- `server/json/decision_history.json` — Per-signal contributions audit
- `server/json/causal_analysis.json` — Causal inference results
- `server/json/trust_graph.json` — Entity trust state

**5-Step Sequential Modulation Flow:**

**Step 1: Weighted Voting (Primary Signals 1-18)**
- Calculate base score: Σ(weight × confidence × is_threat) / Σ(weight)
- Signal weights: Honeypot 0.98, Threat Intel 0.95, Graph 0.92, Signature 0.90, Causal 0.88, LSTM 0.85, Behavioral 0.75, Drift 0.65

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
- Trust ≥80 → normal threshold (75%)
- Trust 60-79 → monitoring (+5% score boost)
- Trust 40-59 → stricter threshold (65%, +10% boost)
- Trust 20-39 → very strict (60%, +15% boost)
- Trust <20 → auto-quarantine (force block)

**Step 5: Final Decision with Override Logic**
- Trust action "quarantine" → force block regardless of score
- Trust action "isolate" → block if score ≥60%
- Otherwise: block if score ≥75% (or ≥70% in APT mode)

**Thresholds:**
- ≥75% (0.75) → Auto-block (normal mode)
- ≥70% (0.70) → Auto-block (APT mode)
- ≥60% (0.60) → Auto-block (low-trust entities, trust <40)
- ≥50% (0.50) → Log as threat (no block)
- <50% → Allow
- Trust <20 → Auto-quarantine + SOC alert (ignores all thresholds)

---

### Stage 4: Response Execution (Policy-Governed)

**Purpose:** Execute actions, log events, send alerts

**Server Files:**
- `server/device_blocker.py` — Firewall blocking (iptables/nftables)
- `server/json/blocked_ips.json` — Current blocklist
- `server/json/threat_log.json` — Primary threat log

**AI Files:**
- `AI/alert_system.py` — Email/SMS alerting (SMTP/Twilio)
- `AI/soar_api.py`, `AI/soar_workflows.py` — SOAR integration
- `AI/policy_governance.py` — Approval workflows
- `AI/emergency_killswitch.py` — SAFE_MODE override
- `AI/file_rotation.py` — ML training log rotation utility (auto-rotates at 1GB)
- `server/json/approval_requests.json` — Pending approvals
- `server/json/comprehensive_audit.json` — Central audit log (all THREAT_DETECTED/INTEGRITY_VIOLATION/SYSTEM_ERROR events)
- `server/json/integrity_violations.json` — Self-protection violations

**Logging Surfaces (Multi-Surface Logging):**
- `server/json/threat_log.json` — Primary threat log (auto-rotates at 1GB → threat_log_1.json, threat_log_2.json, etc.)
- `server/json/comprehensive_audit.json` — Comprehensive audit trail (auto-rotates at 1GB → comprehensive_audit_1.json, etc.)
- `server/json/attack_sequences.json` — LSTM progressions
- `server/json/lateral_movement_alerts.json` — Graph hop chains
- `server/json/behavioral_metrics.json` — Heuristic scores
- `server/json/dns_security.json` — DNS findings
- `server/json/tls_fingerprints.json` — TLS findings
- `server/json/forensic_reports/` — Explainability outputs

**ML Training Log Rotation:** Files used for ML training (`threat_log.json`, `comprehensive_audit.json`, `global_attacks.json`) automatically rotate when reaching 1GB. When rotation occurs, the current file is renamed with a numeric suffix (e.g., `threat_log.json` → `threat_log_1.json`), and a new file is created. This ensures continuous logging without unbounded file growth while preserving all historical attack data for ML training.

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
- `AI/relay_client.py` — WebSocket/HTTP client
- `AI/signature_uploader.py` — Signature sharing
- `AI/training_sync_client.py` — Training data sync
- `AI/central_sync.py` — Central server sync
- `AI/crypto_security.py` — HMAC authentication
- `server/crypto_keys/` — Shared HMAC keys

**Relay Server:**
- `relay/relay_server.py` — WebSocket relay, HMAC validation
- `relay/signature_sync.py` — Signature deduplication
- `relay/ai_training_materials/global_attacks.json` — Central attack log from all customer nodes (auto-rotates at 1GB → global_attacks_1.json, etc.)
- `relay/ai_training_materials/attack_statistics.json` — Aggregated trends
- `relay/ai_training_materials/ai_signatures/learned_signatures.json` — Global signatures

**Pull from Relay:**
- `AI/signature_distribution.py` — Download signatures
- `AI/training_sync_client.py` — Download models
- `relay/training_sync_api.py` — Model distribution API

**Relay Infrastructure (NOT shipped to customers):**
- `relay/docker-compose.yml` — Relay deployment
- `relay/Dockerfile` — Relay container image
- `relay/ai_training_materials/` — Training data lake
- `relay/ai_training_materials/crypto_keys/` — Relay HMAC keys

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
- `AI/adaptive_honeypot.py` — 100% confirmed attacks (highest quality)
- Human validation → ML improvement
- False positive reports → FP filter tuning
- SOAR playbook results → reinforcement learning

---

### Enterprise Extensions (Beyond Core Pipeline)

**User & Identity Monitoring:**
- `AI/user_tracker.py` — UEBA, session tracking
- `server/json/tracked_users.json` — User behavior data

**Zero Trust:**
- `AI/zero_trust.py` — Zero trust posture scoring, DLP

**SOAR Integration:**
- `AI/soar_api.py`, `AI/soar_workflows.py` — Incident workflows
- `server/json/soar_incidents.json` — SOAR cases
- Logged to `comprehensive_audit.json` and `relay/ai_training_materials/global_attacks.json` as `soar_incident`

**Cloud Security:**
- `AI/cloud_security.py` — CSPM for AWS/Azure/GCP
- `server/json/cloud_findings.json` — Cloud misconfigurations
- High/critical findings → `comprehensive_audit.json` and `relay/ai_training_materials/global_attacks.json` as `cloud_misconfiguration`

**Backup & Recovery:**
- `AI/backup_recovery.py` — Backup monitoring, ransomware resilience
- `server/json/backup_status.json` — Backup health
- `server/json/recovery_tests.json` — Recovery test results
- Issues → `comprehensive_audit.json` and `relay/ai_training_materials/global_attacks.json` as `backup_issue`/`ransomware_resilience_low`

**Compliance:**
- `AI/compliance_reporting.py` — PCI/HIPAA/GDPR/SOC2 reports
- `server/json/compliance_reports/` — Compliance snapshots
- Issues → `comprehensive_audit.json` and `relay/ai_training_materials/global_attacks.json` as `compliance_issue`

**Vulnerability Management:**
- `AI/vulnerability_manager.py` — CVE tracking, SBOM
- `server/json/sbom.json` — Software bill of materials

**File Analysis & Sandbox:**
- `AI/file_analyzer.py` — File hashing, metadata extraction

**Formal Threat Modeling:**
- `AI/formal_threat_model.py` — Structured attack scenarios

**Deterministic Evaluation:**
- `AI/deterministic_evaluation.py` — Model validation harnesses

---

## Server Infrastructure Files

**Dashboard & API:**
- `server/server.py` — Flask application (REST APIs, dashboard serving)
- `AI/inspector_ai_monitoring.html` — Dashboard UI (31 sections)
- `AI/swagger_ui.html` — API documentation UI
- Dashboard/API failures → `comprehensive_audit.json` as `SYSTEM_ERROR` events

**Deployment:**
- `server/Dockerfile` — Server container image
- `server/docker-compose.yml` — Linux deployment
- `server/docker-compose.windows.yml` — Windows deployment
- `server/entrypoint.sh` — Container entrypoint
- `server/.env`, `server/.env.linux`, `server/.env.windows` — Environment configs
- `server/requirements.txt` — Python dependencies

**Installation:**
- `server/installation/install.sh` — Linux/Unix installer
- `server/installation/QUICKSTART_WINDOWS.bat` — Windows quickstart
- `server/installation/cloud-deploy.sh` — VPS cloud deployment

**Reporting:**
- `server/report_generator.py` — Enterprise security reports (HTML/JSON)

**Testing:**
- `server/test_system.py` — System validation harness

**Audit Archives:**
- `server/json/audit_archive/` — Rotated audit logs

**Device Management:**
- `server/json/blocked_devices.json` — ARP-blocked devices (via `device_blocker.py`)

**Crypto Mining Detection:**
- `server/json/crypto_mining.json` — Crypto mining activity

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
- `relay/setup.sh` — VPS installer
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
- `relay/ai_training_materials/crypto_keys/` — Relay HMAC keys

**Documentation:**
- `relay/README.md` — Relay architecture and deployment guide

---

## File Naming Conventions

**Customer Node (server/ + AI/):**
- `server/json/*.json` — Runtime state (`.gitignored`, created at runtime)
- `AI/*.py` — Detection modules, orchestration, honeypot, governance
- `AI/ml_models/*.keras` — Deep learning models (LSTM, autoencoder)
- `ml_models/*.pkl` — Classical ML models (RandomForest, IsolationForest, GradientBoosting, scaler)

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

**For testing procedures, see:** `ai-abilities.md` (10-stage validation mapped to pipeline)
**For API reference, see:** `dashboard.md` (31 dashboard sections mapped to pipeline stages)
**For implementation guide, see:** `ai-instructions.md` (developer guide with pipeline implementation details)

- AI/adaptive_honeypot.py — Adaptive multi-persona honeypot that mimics various services (HTTP admin, FTP, SSH, DB, etc.) and feeds honeypot hits into the AI threat log.
- AI/advanced_orchestration.py — Advanced orchestration engine for predictive threat modeling, automated responses, custom alert rules, topology export, and training/orchestration data export.
- AI/advanced_visualization.py — Generates network topology, attack flows, heatmaps, geo maps, and timelines from JSON logs for use in dashboards.
- AI/alert_system.py — Configurable email/SMS alerting system with SMTP/Twilio-style integration and severity-based threat notifications.
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
- AI/enterprise_integration.py — Bridges to enterprise tools (SIEM, ticketing, ITSM) and external APIs for incident/alert integration.
- AI/explainability_engine.py — Builds human-readable explanations and feature attributions for AI decisions and threat scores, maintains decision history, and emits forensic_reports JSON plus optional explainability_data for training.
- AI/exploitdb — Placeholder/path used for local ExploitDB-related resources on the customer side (complements relay ExploitDB usage).
- AI/false_positive_filter.py — Filters noisy detections using heuristics and metadata to reduce false positives before reaching the dashboard.
- AI/file_analyzer.py — Analyzes files and artifacts (hashing, type, basic features) for use in malware/intel workflows.
- AI/formal_threat_model.py — Encodes a higher-level formal threat model, mapping signals and components into structured attack scenarios.
- AI/graph_intelligence.py — Builds and queries graph-based views of entities, connections, and attacks for graph-driven reasoning.
- AI/inspector_ai_monitoring.html — Main HTML dashboard template rendered by server.py to show AI monitoring and visualizations.
- AI/kernel_telemetry.py — Handles kernel/eBPF/XDP telemetry ingestion and feature extraction on supported hosts.
- AI/meta_decision_engine.py — Core meta-decision engine that fuses multiple signals/detections into final threat decisions and actions.
- AI/ml_models/sequence_lstm.keras — Saved Keras sequence LSTM model used for time-series or sequence-based anomaly detection.
- AI/ml_models/traffic_autoencoder.keras — Saved Keras autoencoder model used for network traffic anomaly detection.
- AI/network_performance.py — Tracks per-IP bandwidth, performance metrics, and network health, writing into network_performance.json.
- AI/node_fingerprint.py — Creates device/node fingerprints from observed behavior and attributes for long-term identification.
- AI/p2p_sync.py — Handles peer-to-peer sync logic for nodes in the mesh (metadata/state exchange between peers).
- AI/pcap_capture.py — Packet capture helper for saving traffic (pcap) samples for offline analysis or training.
- AI/pcs_ai.py — Central AI orchestrator and source of truth: wires together models, detection modules (including DNS/TLS analyzers), logs, and the dashboard API, tags relay-bound threats with a stable sensor_id, and routes integrity/lineage/federated/cloud/backup/compliance signals into the audit/relay paths.
- AI/policy_governance.py — Models security policies, approvals, and governance workflows around automated actions.
- AI/relay_client.py — Client-side relay connector used by customer nodes to talk to the relay WebSocket and model API.
- AI/reputation_tracker.py — Maintains local IP/domain reputation, aggregating stats from threat logs and external intel.
- AI/self_protection.py — Implements self-protection checks so the AI/agent can detect tampering or local compromise, writing violations into integrity_violations.json and comprehensive_audit.json and optionally triggering the kill switch.
- AI/sequence_analyzer.py — Sequence analysis utilities for logs/traffic, feeding sequence models like the LSTM.
- AI/signature_distribution.py — Manages downloading and applying signatures/models distributed from the relay or central sources.
- AI/signature_extractor.py — Extracts signatures and patterns from attacks/honeypot hits for later training and sharing.
- AI/signature_uploader.py — Prepares and uploads privacy-preserving signatures to the relay/signature_sync service.
- AI/soar_api.py — API interface for SOAR-like workflows, exposing actions and playbooks to orchestration.
- AI/soar_workflows.py — Library of automated SOAR workflows/runbooks for incidents and playbook steps that persists cases into soar_incidents.json, logs incident/playbook activity into the comprehensive audit log, and mirrors high/critical incidents into relay global_attacks.json as soar_incident entries.
- AI/swagger_ui.html — Embedded Swagger UI HTML used to expose and document the local API when enabled.
- AI/system_log_collector.py — Collects system logs and events into structured JSON for analysis by other AI modules.
- AI/threat_intelligence.py — Local threat intelligence aggregator that merges external feeds and local observations.
- AI/dns_analyzer.py — DNS security analyzer that uses metadata-only heuristics (tunneling/DGA/exfil) to score DNS activity and write aggregated metrics into dns_security.json.
- AI/tls_fingerprint.py — TLS/encrypted-flow fingerprinting engine that tracks non-standard TLS ports and suspicious encrypted C2 patterns, writing per-IP metrics into tls_fingerprints.json.
- AI/traffic_analyzer.py — Higher-level traffic analysis module that combines metrics and detections from network monitors.
- AI/training_sync_client.py — Customer-side client for syncing models/training artifacts with the relay’s training API.
- AI/user_tracker.py — Tracks user accounts and behavior patterns (logins, anomalies) on the protected environment.
- AI/vulnerability_manager.py — Manages vulnerability findings and risk views, tying CVEs/scan data into the dashboard.
- AI/zero_trust.py — Implements zero-trust style checks and posture scoring for devices/users/services.

---

## Server Folder

- server/.dockerignore — Excludes unneeded files from the server Docker build context.
- server/.env — Main environment file for the server container (ports, relay URLs, feature flags, API keys, etc.).
- server/.env.linux — Example/server env template tuned for Linux/host-network deployments.
- server/.env.windows — Example/server env template tuned for Windows Docker deployments.
- server/crypto_keys/ — Holds cryptographic material (e.g., shared_secret.key) used for HMAC between customer and relay.
- server/device_blocker.py — Implements ARP-based device blocking and unblocking, persisting blocked_devices.json.
- server/device_scanner.py — Scans the local network for devices, classifies them by vendor/type, and populates connected_devices.json and device_history.json.
- server/docker-compose.yml — Docker Compose definition for the Linux/host-network server deployment with required capabilities.
- server/docker-compose.windows.yml — Docker Compose definition for Windows deployments using bridged networking and port mappings.
- server/Dockerfile — Builds the server container image, installing dependencies, copying AI code, and wiring HTTPS/gunicorn.
- server/entrypoint.sh — Container entrypoint that launches server.py and gunicorn with TLS certificates.
- server/installation/cloud-deploy.sh — One-shot script to install Docker on a VPS, clone the repo, and deploy the server stack in the cloud.
- server/installation/install.sh — Local/Unix installer that prepares JSON directories and launches the server container via docker compose.
- server/installation/QUICKSTART_WINDOWS.bat — Windows quickstart to set up env/json directories and start the Windows Docker stack.
- server/json/.gitkeep — Placeholder file ensuring the json directory exists in version control.
- server/json/approval_requests.json — Persists operator approval/exception requests for governance and change control.
- server/json/audit_archive/ — Storage for archived audit reports and historical compliance outputs.
- server/json/blocked_ips.json — Current list of blocked IPs chosen by AI/operator actions.
- server/json/connected_devices.json — Snapshot of currently known network devices and their attributes.
- server/json/crypto_mining.json — Time series and summary of crypto-mining detection activity and risk levels.
- server/json/device_history.json — Historical device inventory with ports/types over time for forensics and trend analysis.
- server/json/forensic_reports/ — Folder for structured forensic reports generated by AI or operators.
- server/json/network_monitor_state.json — Persistent state for the live network monitor (counters, trackers, thresholds).
- server/json/network_performance.json — Historical bandwidth and performance metrics per IP recorded by network_performance.py.
- server/json/dns_security.json — Aggregated DNS behavior metrics and suspicious query counts written by AI/dns_analyzer.py from live DNS traffic.
- server/json/tls_fingerprints.json — Aggregated TLS/encrypted-flow fingerprints per source IP written by AI/tls_fingerprint.py.
- server/json/comprehensive_audit.json — Central append-only audit log for security, governance, integrity, lineage, federated, backup, cloud, compliance, and dashboard/API events, maintained by EmergencyKillSwitch and consumed across Stages 6–10.
- server/json/integrity_violations.json — Records integrity and self-protection violations detected by AI/self_protection.py.
- server/json/soar_incidents.json — Persists SOAR/incidents and case metadata created by AI/soar_workflows.py.
- server/json/cloud_findings.json — Stores recent cloud security posture snapshots and misconfiguration findings from AI/cloud_security.py.
- server/json/backup_status.json — Summaries of backup jobs, freshness, and status from AI/backup_recovery.py.
- server/json/recovery_tests.json — Results of recovery/restore tests used to estimate ransomware resilience in AI/backup_recovery.py.
- server/json/compliance_reports/ — Directory for JSON compliance reports (PCI, HIPAA, GDPR, SOC2) written by AI/compliance_reporting.py.
- server/json/sbom.json — Software bill of materials (SBOM) for the deployment, listing packages and versions.
- server/json/threat_log.json — Main threat log of detections and actions generated by AI and network monitor.
- server/json/tracked_users.json — Storage for tracked user accounts and related behavioral data.
- server/network_monitor.py — Scapy-based live network sniffer that detects scans, floods, ARP spoofing, and now feeds behavioral heuristics, graph intelligence, DNS analyzer, TLS fingerprinting, and pcs_ai.
- server/report_generator.py — Standalone HTML/JSON report generator for enterprise-style security reports that stitches together threat statistics, explainability data, and compliance summaries.
- server/requirements.txt — Python dependency list for building the server image.
- server/server.py — Flask dashboard/API server that renders inspector_ai_monitoring.html and exposes REST/JSON endpoints (traffic, DNS/TLS, explainability, audit, visualization, compliance), including logging dashboard/API failures as SYSTEM_ERROR events into comprehensive_audit.json.
- server/test_system.py — System-level test harness for validating that core services and integrations are functioning.

---

## Relay Folder

- relay/.env.relay — Env configuration for the relay server (ports, training flags, paths, logging, crypto enable).
- relay/ai_retraining.py — Relay-side retraining manager that consumes ai_training_materials and exports updated models.
- relay/ai_training_materials/ — On-disk training corpus for the relay (global_attacks, signatures, ExploitDB, models, datasets).
- relay/ai_training_materials/ai_signatures/ — Stores learned_signatures.json created by ExploitDB scraper and signature_sync.
- relay/ai_training_materials/crypto_keys/ — Holds the relay’s copy of shared_secret.key used for HMAC validation.
- relay/ai_training_materials/exploitdb/ — Local checkout of ExploitDB (CSV and exploits) used by exploitdb_scraper.py.
- relay/ai_training_materials/README.md — Explains the layout/usage of the relay training materials directory.
- relay/ai_training_materials/reputation_data/ — Stores aggregate reputation/intel data derived from crawlers and attacks.
- relay/ai_training_materials/threat_intelligence/ — Stores raw/int-derived threat intel from crawlers for training.
- relay/ai_training_materials/trained_models/ — Archive of trained model artifacts produced by relay training runs.
- relay/ai_training_materials/training_datasets/ — Prepared feature/label datasets ready for model training or GPU training.
 - relay/ai_training_materials/global_attacks.json — Central sanitized global attack/event log aggregated from customer nodes across all stages (core, honeypot, federated, SOAR, cloud, backup, compliance, etc.).
 - relay/ai_training_materials/attack_statistics.json — Aggregated statistics and trends derived from global_attacks.json, used for dashboards and analytics.
- relay/docker-compose.yml — Compose file to run the relay server on a VPS with host networking and mounted training data.
- relay/Dockerfile — Builds the relay container image with WebSocket relay, training API, and training tools.
- relay/exploitdb_scraper.py — Scrapes a local/remote ExploitDB CSV to derive attack patterns and export learned_signatures.json.
- relay/gpu_trainer.py — Optional GPU-accelerated training pipeline using TensorFlow/PyTorch on ai_training_materials datasets.
- relay/README.md — Relay-specific documentation describing roles, architecture, and deployment examples.
- relay/relay_server.py — WebSocket relay for the security mesh; verifies HMAC, relays messages, and logs global attacks/stats.
- relay/requirements.txt — Python dependency list for the relay image (websockets, Flask, ML stack).
- relay/setup.sh — Convenience script to install Docker/firewall rules and launch the relay stack on a VPS.
- relay/setup_exploitdb.sh — Helper script that clones the full ExploitDB repo locally for use by exploitdb_scraper.py.
- relay/signature_sync.py — File-based signature and global attack synchronization service used by relay_server for storage.
- relay/start_services.py — Orchestration script that launches relay_server.py and training_sync_api.py as parallel services.
- relay/threat_crawler.py — Threat intel crawler suite for CVEs, MalwareBazaar, AlienVault OTX, URLhaus, and sample AttackerKB data.
- relay/training_sync_api.py — Flask-based model distribution API that serves only pre-trained models and training stats to subscribers.
