# EXE Build Checklist - Battle Hardened AI

## ✅ BUILD STATUS (2026-02-04)

**Last Build:** Completed 2026-02-04 (TensorFlow 2.18.1 + Python 3.12 distutils compatibility)  
**PyInstaller Spec:** `packaging/windows/BattleHardenedAI.spec` ✅ Updated  
**Icon:** `assets/BATTLE-HARDENED-AI.ico` (multi-size ICO: 16–256px) ✅ Included  
**Environment Files:** `server/.env` (Linux/Docker) and `packaging/windows/.env.windows` (Windows template copied to `packaging/windows/dist/.env.windows` for the EXE) ✅ Synchronized  

### Recent Fixes Applied (2026-02-04)
- ✅ **Python 3.12 Distutils Compatibility** - Created `distutils_compat.py` shim module that redirects `import distutils` to `setuptools._distutils`
- ✅ **TensorFlow 2.18.1** - Downgraded from 2.20.0 (missing tensorflow.python.trackable) to 2.18.1 (stable Keras integration)
- ✅ **ONNX 1.16.2** - Locked to compatible version (was 1.15.0, tested 1.20.1/1.19.1 had conflicts)
- ✅ **setuptools ≥65.0.0** - Required for Python 3.12+ distutils compatibility
- ✅ **Runtime Hook** - `runtime_hook_ml.py` loads distutils_compat.py before TensorFlow imports
- ✅ **PyInstaller collect_all** - Use `collect_all('setuptools')` to bundle entire setuptools package
- ✅ **ML Models Working** - TensorFlow, ONNX Runtime, and all 21 AI layers load successfully in EXE

### Recent Fixes Applied (2026-02-05)
- ✅ **Protobuf 5.29.5** - Pinned `protobuf>=5.28.0,<6.0.0` to fix TensorFlow 2.18.1 MessageFactory compatibility (protobuf 6.x removed deprecated API)
- ✅ **Tensorboard 2.18.0** - Fixed dependency conflict (was 2.20.0, TensorFlow 2.18.1 requires 2.18.x)
- ✅ **Corrupted JSON Cleanup** - Deleted corrupted threat_log.json from user data directory
- ✅ **Production Ready** - Zero critical warnings, all ML models load and train successfully

### Expected Harmless Warnings (Cosmetic Only - Can Be Ignored)
- ⚠️ `[RUNTIME HOOK] Failed to load skl2onnx: could not get source code` - PyInstaller build-time inspection limitation, skl2onnx works perfectly at runtime
- ⚠️ `[AI WARNING] Failed to load ML models: could not get source code` - Same PyInstaller inspection issue, ML models initialize and train successfully immediately after

### Previous Fixes Applied (2026-01-24)
- ✅ Added `websockets` module (was missing - caused relay_client.py error)
- ✅ Added `websockets.client` and `asyncio` for async support
- ✅ Added `Flask-CORS==4.0.0` to server/requirements.txt (was missing - caused API CORS errors)
- ✅ Added server/network_monitor.py to .spec datas section (was missing - caused Section 17/22 failures)
- ✅ Added cross-platform network detection to device_scanner.py (Windows: ipconfig, Linux: ip route, fallback: socket trick)
- ✅ Updated `.env.windows` to match `.env` relay server values
- ✅ Fixed Documentation file capitalization for GitHub
- ✅ Included all 52 JSON files, ML models, crypto keys, policies
- ✅ All 55 AI Python modules included
- ✅ Windows firewall scripts, installation utilities, packaging files included

## ✅ CORE PYTHON MODULES

### AI Detection Modules (55 files)
- [ ] All 55 .py files from AI/ directory as Python source
- [ ] AI/__init__.py for package imports
- [ ] **5 Architecture Enhancement Modules**:
  - [ ] AI/model_signing.py - Ed25519 cryptographic model verification (MITRE T1574.012)
  - [ ] AI/pattern_filter.py - Bloom filter deduplication (70-80% bandwidth savings)
  - [ ] AI/model_performance_monitor.py - Production ML accuracy tracking (MITRE T1565.001)
  - [ ] AI/onnx_model_converter.py - ONNX model conversion (relay-side)
  - [ ] ONNX runtime integration in AI/pcs_ai.py (2-5x faster inference)

### Server Modules (Critical - Bundled via .spec)
- [ ] server/device_scanner.py (cross-platform network detection: Linux via ip route/addr, Windows via ipconfig parsing, fallback via socket trick)
- [ ] server/network_monitor.py (live traffic analysis, feeds all detection signals)

### 21-Layer Detection System
1. [ ] step21_gate.py
2. [ ] step21_policy.py  
3. [ ] step21_semantic_gate.py
4. [ ] behavioral_heuristics.py
5. [ ] traffic_analyzer.py
6. [ ] dns_analyzer.py
7. [ ] tls_fingerprint.py
8. [ ] file_analyzer.py
9. [ ] sequence_analyzer.py
10. [ ] causal_inference.py
11. [ ] graph_intelligence.py
12. [ ] kernel_telemetry.py
13. [ ] network_performance.py
14. [ ] pcap_capture.py
15. [ ] adaptive_honeypot.py
16. [ ] real_honeypot.py
17. [ ] threat_intelligence.py
18. [ ] reputation_tracker.py
19. [ ] trust_graph.py
20. [ ] false_positive_filter.py
21. [ ] drift_detector.py

## ✅ DATA FILES

### JSON Files (52 files from server/json/)
- [ ] admin_users.json
- [ ] alert_config.json (Section 21)
- [ ] approval_requests.json
- [ ] attack_sequences.json
- [ ] backup_status.json
- [ ] behavioral_metrics.json
- [ ] blocked_devices.json (Section 2)
- [ ] blocked_ips.json
- [ ] blocked_peers.json (Section 1)
- [ ] causal_analysis.json
- [ ] cloud_findings.json
- [ ] cluster_config.json (Section 11)
- [ ] comprehensive_audit.json
- [ ] connected_devices.json (Section 2)
- [ ] crypto_mining.json
- [ ] decision_history.json
- [ ] device_history.json (Section 2)
- [ ] dns_security.json
- [ ] drift_baseline.json
- [ ] drift_reports.json
- [ ] enterprise_integration.json
- [ ] file_analysis.json (Section 20)
- [ ] formal_threat_model.json
- [ ] fp_filter_config.json
- [ ] governance_policies.json
- [ ] honeypot_attacks.json
- [ ] honeypot_patterns.json
- [ ] identity_access_config.json
- [ ] integrity_violations.json
- [ ] killswitch_state.json (Section 23)
- [ ] lateral_movement_alerts.json (Section 13)
- [ ] local_threat_intel.json
- [ ] meta_engine_config.json
- [ ] ml_performance_metrics.json
- [ ] ml_training_data.json
- [ ] model_lineage.json
- [ ] network_graph.json
- [ ] network_performance.json
- [ ] peer_threats.json (Section 1)
- [ ] recovery_tests.json
- [ ] relay_status.json (Section 1, runtime)
- [ ] reputation_export.json
- [ ] sample_threats.json
- [ ] sandbox_results.json (Section 20)
- [ ] sbom.json
- [ ] secure_deployment.json
- [ ] sla_policy.json
- [ ] soar_incidents.json
- [ ] support_tickets.json
- [ ] system_health.json (Section 11, runtime)
- [ ] threat_log.json
- [ ] tls_fingerprints.json
- [ ] tracked_users.json
- [ ] tracking_data.json
- [ ] trust_graph.json
- [ ] whitelist.json
- [ ] pattern_filter_state.json (Architecture Enhancement #2)
- [ ] ml_performance.json (Architecture Enhancement #3)
- [ ] **Directories:**
  - [ ] compliance_reports/ (Section 12)
  - [ ] forensic_reports/ (Section 14)

### ML Models (AI/ml_models/)
- [ ] anomaly_detector.pkl
- [ ] feature_scaler.pkl
- [ ] ip_reputation.pkl
- [ ] node_fingerprint.json
- [ ] signature_cache/ directory
- [ ] **ONNX Models (Architecture Enhancement #5 - optional but recommended)**:
  - [ ] anomaly_detector.onnx
  - [ ] feature_scaler.onnx
  - [ ] threat_classifier.onnx
  - [ ] Note: If ONNX models absent, system falls back to .pkl models

### Crypto Keys
- [ ] Build-time source keys present in `server/crypto_keys/` (for Linux/Docker and initial TLS)
- [ ] `server/crypto_keys/private_key.pem`
- [ ] `server/crypto_keys/public_key.pem`
- [ ] `server/crypto_keys/shared_secret.key`
- [ ] `server/crypto_keys/ssl_cert.pem`
- [ ] `server/crypto_keys/ssl_key.pem`
- [ ] Windows EXE runtime keys stored in `%LOCALAPPDATA%\Battle-Hardened AI\server\crypto_keys` (auto-created on first run)
- [ ] **Model Signing Keys (Architecture Enhancement #1)**:
  - [ ] `relay_public_key.pem` (customer verification key for relay-signed models)
  - [ ] `relay_signing_key.pem` (relay-side only, not shipped to customers)

### Step21 Policies (policies/step21/)
- [ ] manifest.json
- [ ] manifest.sig
- [ ] policy.json
- [ ] schema.json

## ✅ UI/DASHBOARD FILES

### HTML Templates
- [ ] inspector_ai_monitoring.html
- [ ] docs_portal.html
- [ ] docs_viewer.html
- [ ] swagger_ui.html

### Flask Templates (if any in server/templates/)
- [ ] Check server/templates/ directory
- [ ] Include all .html files

### Static Assets (if any in server/static/)
- [ ] CSS files
- [ ] JavaScript files
- [ ] Images/icons

## ✅ CONFIGURATION

### Environment Files
- [ ] server/.env (Linux/Docker runtime configuration)
- [ ] packaging/windows/dist/.env.windows (Windows EXE runtime configuration copied from `packaging/windows/.env.windows` by the EXE build script)

### Runtime Directories (auto-create on startup; for Windows EXE these live under `%LOCALAPPDATA%/Battle-Hardened AI/server/`)
- [ ] logs/
- [ ] pcap/
- [ ] json/ (if not exists)

## ✅ WINDOWS-SPECIFIC

### Firewall Scripts
— [ ] packaging/windows/windows-firewall/ directory contents

### Installation Scripts
- [ ] server/installation/ directory contents

### Packaging
- [ ] packaging/windows/ directory contents (build scripts, .iss, local dist/)
- [ ] packaging/windows/distutils_compat.py (Python 3.12 distutils compatibility shim)
- [ ] packaging/windows/runtime_hook_ml.py (PyInstaller runtime hook for ML package initialization)

### Required Source Folders for EXE Build
- [ ] AI/ (all detection modules and AI/ml_models/)
- [ ] server/device_scanner.py and server/network_monitor.py (bundled via BattleHardenedAI.spec datas section)
- [ ] server/json/ (all JSON configuration and state files)
- [ ] server/crypto_keys/ (TLS and HMAC keys; build-time source, Windows EXE runtime uses per-user data dir)
- [ ] server/installation/ (watchdog, Gunicorn configs, init_json_files.py)
- [ ] packaging/windows/windows-firewall/ (Windows firewall integration scripts)
- [ ] policies/step21/ (semantic gate policies)
- [ ] packaging/windows/ (BattleHardenedAI.iss, build scripts, local dist/)

## ✅ ICON & BRANDING

- [ ] assets/BATTLE-HARDENED-AI.ico (single multi-size ICO for EXE icon)

## ✅ EXCLUSIONS (DO NOT INCLUDE)

- [ ] ❌ relay/ folder (NOT for customers)
- [ ] ❌ __pycache__/ directories
- [ ] ❌ .git/ directory
- [ ] ❌ .venv/ directory
- [ ] ❌ build/ directory
- [ ] ❌ dist/ directory

## ✅ DASHBOARD SECTIONS (24 SECTIONS - VERIFY ALL)

### Section 1: 🤖 AI Training Network - Shared Machine Learning
**API Endpoints:**
- [ ] `/api/p2p/status` - P2P sync status
- [ ] `/api/relay/status` - Relay client status and connected peers
- [ ] `/api/p2p/add-peer` - Add new peer dynamically

**JSON Files:**
- [ ] `peer_threats.json` - Shared threat intelligence
- [ ] `ml_training_data.json` - Collaborative ML data

**Playcards/Metrics:**
- [ ] Total Servers Active
- [ ] Last Sync timestamp
- [ ] Threats Shared (local counter)
- [ ] Threats Learned (from peers)
- [ ] Global Threats Shared (relay total)
- [ ] Connected peers list with badges
- [ ] **Pattern Filter Bandwidth Saved** (Architecture Enhancement #2 - 70-80% deduplication)

**Python Modules:**
- [ ] `AI/p2p_sync.py`
- [ ] `AI/relay_client.py`
- [ ] `AI/pattern_filter.py` (Architecture Enhancement #2)

---

### Section 2: 🌐 Network Devices - Live Monitor, Ports & History
**API Endpoints:**
- [ ] `/api/connected-devices` - Get all network devices
- [ ] `/api/device-history` - 7-day device connection history
- [ ] `/api/scan-devices` - Trigger network scan
- [ ] `/api/device/block` - Block device by MAC
- [ ] `/api/device/unblock` - Unblock device

**JSON Files:**
- [ ] `connected_devices.json` - Current device inventory
- [ ] `device_history.json` - 7-day device connection log
- [ ] `blocked_devices.json` - Blocked device list

**Playcards/Metrics:**
- [ ] Total Devices count
- [ ] Active Now count
- [ ] New Devices (24h)
- [ ] Blocked Devices count
- [ ] Live device table (MAC, IP, hostname, OS, first/last seen)
- [ ] Device history timeline (7 days)

**Python Modules:**
- [ ] `server/device_scanner.py` ⚠️ **CRITICAL - Must be in hiddenimports**
- [ ] `server/device_blocker.py`

---

### Section 3: 🔓 VPN/Tor De-Anonymization Statistics
**API Endpoints:**
- [ ] `/api/traffic/analysis` - Traffic analysis with VPN/Tor detection

**JSON Files:**
- [ ] `threat_log.json` - Contains VPN/Tor detection events
- [ ] `tls_fingerprints.json` - TLS fingerprint database

**Playcards/Metrics:**
- [ ] VPN Exit Nodes Detected
- [ ] Tor Exit Nodes Detected
- [ ] Proxy Chains Identified
- [ ] Anonymization Attempts Blocked

**Python Modules:**
- [ ] `AI/traffic_analyzer.py`
- [ ] `AI/tls_fingerprint.py`

---

### Section 4: 🤖 Real AI/ML Models - Machine Learning Intelligence
**API Endpoints:**
- [ ] `/api/stats` - ML model statistics and training metrics
- [ ] `/api/architecture-enhancements/status` - All 5 enhancement statuses (NEW)
- [ ] `/api/model-signing/verification-status` - Signature verification details (Enhancement #1)
- [ ] `/api/onnx/performance` - ONNX vs pickle inference times (Enhancement #5)
- [ ] `/api/pattern-filter/stats` - Pattern deduplication statistics (Enhancement #2)
- [ ] `/api/ml-performance` - ML performance monitoring (Enhancement #3)

**JSON Files:**
- [ ] `ml_training_data.json` - Training dataset
- [ ] `ml_performance_metrics.json` - Model accuracy/precision
- [ ] `drift_baseline.json` - Baseline for drift detection
- [ ] `drift_reports.json` - Detected model drift
- [ ] `ml_performance.json` - **Architecture Enhancement #3** - Performance monitoring data
- [ ] `pattern_filter_state.json` - **Architecture Enhancement #2** - Bloom filter state

**ML Models:**
- [ ] `AI/ml_models/anomaly_detector.pkl`
- [ ] `AI/ml_models/feature_scaler.pkl`
- [ ] `AI/ml_models/ip_reputation.pkl`
- [ ] `AI/ml_models/anomaly_detector.onnx` - **Architecture Enhancement #5** (optional, 2-5x faster)
- [ ] `AI/ml_models/feature_scaler.onnx` - **Architecture Enhancement #5** (optional)
- [ ] `AI/ml_models/threat_classifier.onnx` - **Architecture Enhancement #5** (optional)

**Playcards/Metrics:**
- [ ] Model Accuracy
- [ ] False Positive Rate
- [ ] Training Samples count
- [ ] Last Retrained timestamp
- [ ] Active Models list
- [ ] **Model Signatures** - ✅ Verified (Ed25519) or ⚠️ Unverified (Enhancement #1)
- [ ] **ONNX Inference Time** - X.Xms (4.0x faster) vs pickle baseline (Enhancement #5)
- [ ] **Pattern Filter Efficiency** - XX% bandwidth saved (Enhancement #2)
- [ ] **Performance Monitor Status** - Accuracy XX.X% (healthy/warning/critical) (Enhancement #3)
- [ ] **Adversarial Training** - ✅ Enabled or ❌ Disabled (Enhancement #4)

**Python Modules:**
- [ ] `AI/pcs_ai.py`
- [ ] `AI/drift_detector.py`
- [ ] `AI/meta_decision_engine.py`
- [ ] `AI/model_signing.py` - **Architecture Enhancement #1** (MITRE T1574.012 defense)
- [ ] `AI/pattern_filter.py` - **Architecture Enhancement #2** (70-80% bandwidth savings)
- [ ] `AI/model_performance_monitor.py` - **Architecture Enhancement #3** (MITRE T1565.001 defense)
- [ ] `AI/onnx_model_converter.py` - **Architecture Enhancement #5** (relay-side conversion)
- [ ] ONNX runtime integration in `AI/pcs_ai.py` - **Architecture Enhancement #5** (2-5x faster inference)

---

### Section 5: 📊 Security Overview - Live Statistics
**API Endpoints:**
- [ ] `/api/stats` - Overall security statistics
- [ ] `/api/threat_log` - Real-time threat log

**JSON Files:**
- [ ] `threat_log.json` - All detected threats
- [ ] `whitelist.json` - Whitelisted IPs
- [ ] `blocked_ips.json` - Blocked IP addresses

**Playcards/Metrics:**
- [ ] Total Threats Detected
- [ ] Threats Blocked (24h)
- [ ] Whitelisted IPs count
- [ ] Attack Types breakdown
- [ ] Recent threats table

**Python Modules:**
- [ ] `AI/pcs_ai.py`

---

### Section 6: 🎯 Threat Analysis by Type
**API Endpoints:**
- [ ] `/api/stats` - Threat breakdown by MITRE ATT&CK technique

**JSON Files:**
- [ ] `threat_log.json` - Categorized threat data

**Playcards/Metrics:**
- [ ] SQL Injection attempts
- [ ] XSS attempts
- [ ] Brute Force attempts
- [ ] Port Scans
- [ ] Malware Downloads
- [ ] Command Injection
- [ ] Path Traversal
- [ ] DDoS attempts

**Python Modules:**
- [ ] `AI/pcs_ai.py`
- [ ] `AI/sequence_analyzer.py`

---

### Section 7: 🛡️ IP Management & Threat Monitoring
**API Endpoints:**
- [ ] `/api/threat_log` - Threat log with IP filtering
- [ ] `/api/threat/block-ip` - Block IP address
- [ ] `/api/whitelist/add` - Add IP to whitelist
- [ ] `/api/whitelist/remove` - Remove IP from whitelist

**JSON Files:**
- [ ] `threat_log.json` - Threats with source IPs
- [ ] `whitelist.json` - Whitelisted IPs
- [ ] `blocked_ips.json` - Blocked IPs

**Playcards/Metrics:**
- [ ] Threat log table (IP, type, severity, timestamp, action)
- [ ] Block/Whitelist action buttons
- [ ] IP reputation scores

**Python Modules:**
- [ ] `AI/pcs_ai.py`
- [ ] `AI/reputation_tracker.py`

---

### Section 8: 🔐 Failed Login Attempts (Battle-Hardened AI Server)
**API Endpoints:**
- [ ] `/api/failed-logins` - Admin dashboard failed login attempts

**JSON Files:**
- [ ] `admin_users.json` - Admin user database (includes failed login tracking)

**Playcards/Metrics:**
- [ ] Failed Login Attempts (24h)
- [ ] Suspicious Login IPs
- [ ] Login attempt timeline

**Python Modules:**
- [ ] `server/server.py` (login tracking logic)

---

### Section 9: 📈 Attack Type Breakdown (View)
**API Endpoints:**
- [ ] `/api/stats` - Attack type distribution

**JSON Files:**
- [ ] `threat_log.json` - Attack categorization data

**Playcards/Metrics:**
- [ ] Attack type pie chart
- [ ] Attack type trend graph
- [ ] Top 10 attack types

**Python Modules:**
- [ ] `AI/pcs_ai.py`

---

### Section 10: 📦 Automated Signature Extraction
**API Endpoints:**
- [ ] `/api/signature-extraction/stats` - Signature extraction statistics
- [ ] `/api/signatures/extracted` - Extracted attack signatures

**JSON Files:**
- [ ] `attack_sequences.json` - Attack patterns
- [ ] `threat_log.json` - Source data for extraction

**ML Models:**
- [ ] `AI/ml_models/signature_cache/` - Cached signatures

**Playcards/Metrics:**
- [ ] Signatures Extracted (total)
- [ ] New Signatures (24h)
- [ ] Shared to Network
- [ ] Extraction Accuracy

**Python Modules:**
- [ ] `AI/signature_extractor.py`
- [ ] `AI/sequence_analyzer.py`

---

### Section 11: 💻 System Health & Network Performance
**API Endpoints:**
- [ ] `/api/system-health/stats` - System health metrics
- [ ] `/api/system-status` - Server status and uptime
- [ ] `/api/performance/metrics` - Network performance data

**JSON Files:**
- [ ] `cluster_config.json` - HA/failover configuration
- [ ] `network_performance.json` - Performance metrics
- [ ] `sla_policy.json` - SLA thresholds

**Playcards/Metrics:**
- [ ] CPU Usage %
- [ ] Memory Usage %
- [ ] Disk Usage %
- [ ] Network Throughput
- [ ] Uptime
- [ ] Health Status (healthy/degraded/critical)

**Python Modules:**
- [ ] `AI/network_performance.py`
- [ ] `AI/kernel_telemetry.py`

---

### Section 12: 📑 Audit Evidence & Compliance Mapping
**API Endpoints:**
- [ ] `/api/compliance/summary` - Compliance framework coverage

**JSON Files:**
- [ ] `comprehensive_audit.json` - Audit trail
- [ ] `sbom.json` - Software Bill of Materials
- [ ] `model_lineage.json` - ML model provenance

**Playcards/Metrics:**
- [ ] Compliance Frameworks (NIST, ISO 27001, PCI-DSS, HIPAA, SOC 2)
- [ ] Controls Implemented
- [ ] Audit Events (24h)
- [ ] Compliance Score %

**Python Modules:**
- [ ] `AI/compliance_reporting.py`
- [ ] `AI/cryptographic_lineage.py`

---

### Section 13: 🔗 Attack Chain Visualization (Graph Intelligence)
**API Endpoints:**
- [ ] `/api/graph-intelligence/stats` - Graph intelligence metrics
- [ ] `/api/visualization/topology` - Network topology graph

**JSON Files:**
- [ ] `network_graph.json` - Attack graph data
- [ ] `lateral_movement_alerts.json` - Lateral movement detection
- [ ] `trust_graph.json` - Trust relationships

**Playcards/Metrics:**
- [ ] Attack Chains Detected
- [ ] Lateral Movement Attempts
- [ ] Graph Nodes count
- [ ] Graph Edges count
- [ ] Attack path visualization

**Python Modules:**
- [ ] `AI/graph_intelligence.py`
- [ ] `AI/trust_graph.py`
- [ ] `AI/causal_inference.py`

---

### Section 14: 💡 Decision Explainability Engine
**API Endpoints:**
- [ ] `/api/explainability/stats` - Explainability metrics

**JSON Files:**
- [ ] `decision_history.json` - Decision audit trail
- [ ] `fp_filter_config.json` - False positive filtering rules

**Playcards/Metrics:**
- [ ] Decisions Made (total)
- [ ] Decisions Explained (%)
- [ ] Confidence Scores avg
- [ ] Explainability Coverage %

**Python Modules:**
- [ ] `AI/explainability_engine.py`
- [ ] `AI/false_positive_filter.py`

---

### Section 15: 🍯 Adaptive Honeypot (8 Service Personas)
**API Endpoints:**
- [ ] `/api/adaptive_honeypot/status` - Honeypot runtime status
- [ ] `/api/adaptive_honeypot/personas` - Available service personas
- [ ] `/api/adaptive_honeypot/configure` - Configure/start honeypot
- [ ] `/api/adaptive_honeypot/stop` - Stop honeypot
- [ ] `/api/adaptive_honeypot/attacks` - Real-time attacks
- [ ] `/api/adaptive_honeypot/attacks/history` - Attack history

**JSON Files:**
- [ ] `honeypot_attacks.json` - Captured honeypot attacks
- [ ] `honeypot_patterns.json` - Attack patterns learned

**Playcards/Metrics:**
- [ ] Active Personas (8: SSH, FTP, HTTP, HTTPS, Telnet, MySQL, RDP, SMB)
- [ ] Attacks Captured (total)
- [ ] Attacker IPs seen
- [ ] Attack timeline
- [ ] Real-time attack feed

**Python Modules:**
- [ ] `AI/adaptive_honeypot.py`
- [ ] `AI/real_honeypot.py`

---

### Section 16: 🕷️ AI Security Crawlers (10 Threat Intel Sources)
**API Endpoints:**
- [ ] `/api/threat-crawlers/stats` - Crawler statistics

**JSON Files:**
- [ ] `local_threat_intel.json` - Crawled threat intelligence

**Playcards/Metrics:**
- [ ] Active Crawlers (10 sources)
- [ ] Threats Discovered (24h)
- [ ] Last Crawl timestamp
- [ ] IOCs Collected

**Python Modules:**
- [ ] `AI/threat_intelligence.py`
- [ ] `AI/signature_distribution.py`

---

### Section 17: 🔍 Traffic Analysis & Inspection
**API Endpoints:**
- [ ] `/api/traffic/analysis` - Deep packet inspection results

**JSON Files:**
- [ ] `threat_log.json` - Traffic-based threats
- [ ] `tls_fingerprints.json` - TLS fingerprint database

**Playcards/Metrics:**
- [ ] Packets Analyzed
- [ ] Encrypted Traffic (%)
- [ ] Suspicious Flows detected
- [ ] Protocol Breakdown

**Python Modules:**
- [ ] `AI/traffic_analyzer.py`
- [ ] `AI/pcap_capture.py`
- [ ] `server/network_monitor.py` ⚠️ **CRITICAL - Must be in hiddenimports**

---

### Section 18: 🌍 DNS & Geo Security (Tunneling Detection)
**API Endpoints:**
- [ ] `/api/dns/stats` - DNS security statistics

**JSON Files:**
- [ ] `dns_security.json` - DNS threat data

**Playcards/Metrics:**
- [ ] DNS Tunneling Attempts
- [ ] DGA Domains Detected
- [ ] Geo-Blocked Requests
- [ ] DNS Queries (total)

**Python Modules:**
- [ ] `AI/dns_analyzer.py`

---

### Section 19: 👤 User & Identity Trust Signals
**API Endpoints:**
- [ ] `/api/users/tracking` - User/device tracking data
- [ ] `/api/zero-trust/scores` - Zero trust scores

**JSON Files:**
- [ ] `tracked_users.json` - User behavior tracking
- [ ] `tracking_data.json` - Identity tracking data
- [ ] `identity_access_config.json` - Access policies
- [ ] `admin_users.json` - Admin user database

**Playcards/Metrics:**
- [ ] Users Tracked
- [ ] High-Risk Users
- [ ] Trust Scores avg
- [ ] Identity Anomalies

**Python Modules:**
- [ ] `AI/user_tracker.py`
- [ ] `AI/zero_trust.py`

---

### Section 20: 💣 Sandbox Detonation
**API Endpoints:**
- [ ] `/api/sandbox/stats` - Sandbox analysis statistics
- [ ] `/api/sandbox/detonate` - Upload file for analysis

**JSON Files:**
- [ ] `file_analysis.json` - Sandbox analysis results

**Playcards/Metrics:**
- [ ] Files Analyzed (total)
- [ ] Malware Detected
- [ ] Clean Files
- [ ] Analysis Queue

**Python Modules:**
- [ ] `AI/file_analyzer.py`

---

### Section 21: 📧 Email/SMS Alerts (Critical Only)
**API Endpoints:**
- [ ] `/api/alerts/stats` - Alert system statistics
- [ ] `/api/alerts/email/config` - Email alert configuration
- [ ] `/api/alerts/sms/config` - SMS alert configuration

**JSON Files:**
- [ ] (Alerts are sent, not stored in JSON)

**Playcards/Metrics:**
- [ ] Email Alerts Sent
- [ ] SMS Alerts Sent
- [ ] Subscribers count
- [ ] Email/SMS config forms

**Python Modules:**
- [ ] `AI/alert_system.py`

---

### Section 22: 🪙 Cryptocurrency Mining Detection
**API Endpoints:**
- [ ] `/api/traffic/crypto-mining` - Crypto mining detection stats

**JSON Files:**
- [ ] `crypto_mining.json` - Mining detection events

**Playcards/Metrics:**
- [ ] Miner Processes Detected
- [ ] CPU Spikes (mining-related)
- [ ] Mining Connections
- [ ] Risk Level
- [ ] Detected Miners list
- [ ] High CPU Processes list

**Python Modules:**
- [ ] `AI/traffic_analyzer.py`
- [ ] `AI/crypto_security.py`

---

### Section 23: 🚨 Governance & Emergency Controls
**API Endpoints:**
- [ ] `/api/governance/pending-approvals` - Policy approval queue
- [ ] `/api/governance/stats` - Governance statistics
- [ ] `/api/killswitch/status` - Emergency killswitch status
- [ ] `/api/audit-log/clear` - Clear audit log
- [ ] `/api/self-protection/stats` - Self-protection metrics

**JSON Files:**
- [ ] `approval_requests.json` - Policy approval queue
- [ ] `governance_policies.json` - Governance rules
- [ ] `comprehensive_audit.json` - Audit trail
- [ ] `integrity_violations.json` - Tamper detection
- [ ] `secure_deployment.json` - Deployment security status

**Playcards/Metrics:**
- [ ] Pending Approvals
- [ ] Governance Policies Active
- [ ] Emergency Killswitch status
- [ ] Integrity Violations (24h)
- [ ] Self-Protection Status

**Python Modules:**
- [ ] `AI/policy_governance.py`
- [ ] `AI/emergency_killswitch.py`
- [ ] `AI/self_protection.py`
- [ ] `AI/secure_deployment.py`

---

### Section 24: 🏢 Enterprise Security Integrations
**API Endpoints:**
- [ ] `/api/enterprise-integration/config` - Syslog/webhook configuration
- [ ] `/api/vulnerabilities/scan` - Vulnerability scan results
- [ ] `/api/backup/status` - Backup status
- [ ] `/api/backup/resilience` - Backup resilience tests
- [ ] `/api/zero-trust/violations` - Zero trust violations
- [ ] `/api/behavioral/stats` - Behavioral heuristics
- [ ] `/api/sandbox/stats` - File sandbox stats
- [ ] `/api/cloud/posture` - Cloud security posture (CSPM)
- [ ] `/api/vulnerabilities/darkweb` - Dark web monitoring
- [ ] `/api/soar/attack-simulation` - SOAR/BAS integration
- [ ] `/api/zero-trust/dlp` - Data Loss Prevention

**JSON Files:**
- [ ] `enterprise_integration.json` - Syslog/webhook targets
- [ ] `backup_status.json` - Backup/recovery data
- [ ] `recovery_tests.json` - Recovery test results
- [ ] `cloud_findings.json` - Cloud security findings
- [ ] `behavioral_metrics.json` - Behavioral analysis
- [ ] `soar_incidents.json` - SOAR incidents

**Playcards/Metrics:**
- [ ] SIEM Integrations (syslog targets)
- [ ] Backup Status (last backup, resilience score)
- [ ] Vulnerability Count
- [ ] Cloud Misconfigurations
- [ ] Zero Trust Violations
- [ ] DLP Incidents
- [ ] Dark Web Leaks

**Python Modules:**
- [ ] `AI/enterprise_integration.py`
- [ ] `AI/backup_recovery.py`
- [ ] `AI/vulnerability_manager.py`
- [ ] `AI/cloud_security.py`
- [ ] `AI/behavioral_heuristics.py`
- [ ] `AI/zero_trust.py`
- [ ] `AI/soar_api.py`

## ✅ CRITICAL HIDDENIMPORTS (Must be in BattleHardenedAI.spec)

### Core Server Modules (in server/ folder)
- [ ] `device_scanner` ⚠️ **CRITICAL for Section 2**
- [ ] `device_blocker` ⚠️ **CRITICAL for Section 2**
- [ ] `network_monitor` ⚠️ **CRITICAL for Section 17/22**
- [ ] `report_generator`
- [ ] `debug_server`

### All AI Modules (in AI/ folder)
All 55 .py files must be importable:
- [ ] `adaptive_honeypot` (Section 15)
- [ ] `advanced_orchestration`
- [ ] `advanced_visualization`
- [ ] `alert_system` (Section 21)
- [ ] `asset_inventory`
- [ ] `backup_recovery` (Section 24)
- [ ] `behavioral_heuristics` (Section 24)
- [ ] `byzantine_federated_learning`
- [ ] `causal_inference` (Section 13)
- [ ] `central_sync`
- [ ] `cloud_security` (Section 24)
- [ ] `compliance_reporting` (Section 12)
- [ ] `crypto_security` (Section 22)
- [ ] `cryptographic_lineage` (Section 12)
- [ ] `deterministic_evaluation`
- [ ] `dns_analyzer` (Section 18)
- [ ] `drift_detector` (Section 4)
- [ ] `emergency_killswitch` (Section 23)
- [ ] `enterprise_integration` (Section 24)
- [ ] `explainability_engine` (Section 14)
- [ ] `false_positive_filter` (Section 14)
- [ ] `file_analyzer` (Section 20)
- [ ] `file_rotation`
- [ ] `formal_threat_model`
- [ ] `graph_intelligence` (Section 13)
- [ ] `kernel_telemetry` (Section 11)
- [ ] `meta_decision_engine` (Section 4)
- [ ] `model_signing` ⚠️ **CRITICAL for Architecture Enhancement #1**
- [ ] `model_performance_monitor` ⚠️ **CRITICAL for Architecture Enhancement #3**
- [ ] `network_performance` (Section 11)
- [ ] `node_fingerprint`
- [ ] `onnx_model_converter` (Relay-side for Architecture Enhancement #5)
- [ ] `p2p_sync` ⚠️ **CRITICAL for Section 1**
- [ ] `path_helper` (used by many modules)
- [ ] `pattern_filter` ⚠️ **CRITICAL for Architecture Enhancement #2**
- [ ] `pcap_capture` (Section 17)
- [ ] `pcs_ai` ⚠️ **CRITICAL for Sections 4-9**
- [ ] `policy_governance` (Section 23)
- [ ] `real_honeypot` (Section 15)
- [ ] `relay_client` ⚠️ **CRITICAL for Section 1**
- [ ] `reputation_tracker` (Section 7)
- [ ] `secure_deployment` (Section 23)
- [ ] `self_protection` (Section 23)
- [ ] `sequence_analyzer` (Sections 6, 10)
- [ ] `signature_distribution` (Section 16)
- [ ] `signature_extractor` (Section 10)
- [ ] `signature_uploader`
- [ ] `soar_api` (Section 24)
- [ ] `soar_workflows`
- [ ] `step21_gate` (Section 4)
- [ ] `step21_policy` (Section 4)
- [ ] `step21_semantic_gate` (Section 4)
- [ ] `system_log_collector`
- [ ] `threat_intelligence` (Section 16)
- [ ] `tls_fingerprint` (Sections 3, 17)
- [ ] `traffic_analyzer` ⚠️ **CRITICAL for Sections 3, 17, 22**
- [ ] `training_sync_client`
- [ ] `trust_graph` (Section 13)
- [ ] `user_tracker` (Section 19)
- [ ] `vulnerability_manager` (Section 24)
- [ ] `zero_trust` (Sections 19, 24)

### Third-Party Dependencies
- [ ] `flask`
- [ ] `flask_cors` ⚠️ **CRITICAL - API CORS**
- [ ] `dotenv`
- [ ] `cryptography` and all submodules
- [ ] `scapy` and `scapy.all`
- [ ] `websockets` and `websockets.client` ⚠️ **CRITICAL for Section 1**
- [ ] `psutil`
- [ ] `sklearn` and all submodules
- [ ] `joblib`
- [ ] `numpy`
- [ ] `pandas`
- [ ] `sqlite3`
- [ ] `werkzeug`
- [ ] `jinja2`
- [ ] `click`
- [ ] `itsdangerous`
- [ ] `datetime`
- [ ] `pytz`
- [ ] `requests`
- [ ] `asyncio` ⚠️ **CRITICAL for async operations**
- [ ] `email.mime` modules
- [ ] `onnxruntime` ⚠️ **CRITICAL for Architecture Enhancement #5 (2-5x faster inference)**
- [ ] `skl2onnx` (Relay-side for Architecture Enhancement #5 conversion)
- [ ] `onnx` (Model format support)

---

## ✅ API ENDPOINTS TO VERIFY (Organized by Section)

## ✅ API ENDPOINTS TO VERIFY (Organized by Section)

### Section 1 - AI Training Network
- [ ] `/api/p2p/status`
- [ ] `/api/relay/status`
- [ ] `/api/p2p/add-peer`

### Section 2 - Network Devices
- [ ] `/api/connected-devices`
- [ ] `/api/device-history`
- [ ] `/api/scan-devices`
- [ ] `/api/device/block`
- [ ] `/api/device/unblock`

### Section 3 - VPN/Tor De-Anonymization
- [ ] `/api/traffic/analysis`

### Section 4 - AI/ML Models
- [ ] `/api/stats` (ML metrics)

### Section 5 - Security Overview
- [ ] `/api/stats` (overall stats)
- [ ] `/api/threat_log`

### Section 6 - Threat Analysis by Type
- [ ] `/api/stats` (threat breakdown)

### Section 7 - IP Management
- [ ] `/api/threat_log`
- [ ] `/api/threat/block-ip`
- [ ] `/api/whitelist/add`
- [ ] `/api/whitelist/remove`

### Section 8 - Failed Logins
- [ ] `/api/failed-logins`

### Section 9 - Attack Type Breakdown
- [ ] `/api/stats` (attack distribution)

### Section 10 - Signature Extraction
- [ ] `/api/signature-extraction/stats`
- [ ] `/api/signatures/extracted`

### Section 11 - System Health
- [ ] `/api/system-health/stats`
- [ ] `/api/system-status`
- [ ] `/api/performance/metrics`

### Section 12 - Audit & Compliance
- [ ] `/api/compliance/summary`

### Section 13 - Attack Chain Visualization
- [ ] `/api/graph-intelligence/stats`
- [ ] `/api/visualization/topology`

### Section 14 - Decision Explainability
- [ ] `/api/explainability/stats`

### Section 15 - Adaptive Honeypot
- [ ] `/api/adaptive_honeypot/status`
- [ ] `/api/adaptive_honeypot/personas`
- [ ] `/api/adaptive_honeypot/configure`
- [ ] `/api/adaptive_honeypot/stop`
- [ ] `/api/adaptive_honeypot/attacks`
- [ ] `/api/adaptive_honeypot/attacks/history`

### Section 16 - Threat Crawlers
- [ ] `/api/threat-crawlers/stats`

### Section 17 - Traffic Analysis
- [ ] `/api/traffic/analysis`

### Section 18 - DNS & Geo Security
- [ ] `/api/dns/stats`

### Section 19 - User & Identity
- [ ] `/api/users/tracking`
- [ ] `/api/zero-trust/scores`

### Section 20 - Sandbox Detonation
- [ ] `/api/sandbox/stats`
- [ ] `/api/sandbox/detonate`

### Section 21 - Email/SMS Alerts
- [ ] `/api/alerts/stats`
- [ ] `/api/alerts/email/config`
- [ ] `/api/alerts/sms/config`

### Section 22 - Crypto Mining Detection
- [ ] `/api/traffic/crypto-mining`

### Section 23 - Governance & Emergency
- [ ] `/api/governance/pending-approvals`
- [ ] `/api/governance/stats`
- [ ] `/api/killswitch/status`
- [ ] `/api/audit-log/clear`
- [ ] `/api/self-protection/stats`

### Section 24 - Enterprise Integrations
- [ ] `/api/enterprise-integration/config`
- [ ] `/api/vulnerabilities/scan`
- [ ] `/api/backup/status`
- [ ] `/api/backup/resilience`
- [ ] `/api/zero-trust/violations`
- [ ] `/api/behavioral/stats`
- [ ] `/api/cloud/posture`
- [ ] `/api/vulnerabilities/darkweb`
- [ ] `/api/soar/attack-simulation`
- [ ] `/api/zero-trust/dlp`

### System/Utility Endpoints
- [ ] `/api/system-status`
- [ ] `/api/openapi.json`
- [ ] `/api/docs`
- [ ] `/api/current-time`
- [ ] `/api/current-ports`
- [ ] `/api/update-timezone`
- [ ] `/api/update-ports`
- [ ] `/api/update-api-key`
- [ ] `/api/generate-env-file`

---

## POST-BUILD VERIFICATION (Updated with Section-Specific Checks)

### 1. Basic EXE Checks
- [ ] EXE has BATTLE-HARDENED-AI.ico icon
- [ ] EXE size is reasonable (~200-300 MB)
- [ ] Run EXE and verify NO import errors (especially `websockets`, `flask_cors`)
- [ ] Check all 21 AI layers load without errors
- [ ] Verify server/device_scanner.py and server/network_monitor.py are bundled and accessible
- [ ] Verify dashboard loads at https://localhost:60000
- [ ] Check .env.windows is present next to BattleHardenedAI.exe

### 2. Section-by-Section Verification (ALL 24 SECTIONS)

#### Section 1 - AI Training Network
- [ ] Page loads without "Loading..." stuck state
- [ ] P2P status displays (enabled/disabled)
- [ ] Relay status displays (connected/disconnected)
- [ ] Total Servers Active shows count
- [ ] Last Sync timestamp appears
- [ ] Threats Shared/Learned counters work

#### Section 2 - Network Devices
- [ ] Device table populates (or shows empty state)
- [ ] Device scan button works
- [ ] Block/Unblock buttons functional
- [ ] Device history timeline displays
- [ ] Device count metrics update

#### Section 3 - VPN/Tor De-Anonymization
- [ ] VPN/Tor detection stats load
- [ ] Anonymization metrics display
- [ ] Traffic analysis data shows

#### Section 4 - AI/ML Models
- [ ] ML model stats load
- [ ] Model accuracy displays
- [ ] Training metrics show
- [ ] ML models (.pkl files) are accessible

#### Section 5 - Security Overview
- [ ] Total threats counter works
- [ ] Blocked threats (24h) updates
- [ ] Threat log table populates
- [ ] Recent threats display

#### Section 6 - Threat Analysis by Type
- [ ] Attack type breakdown loads
- [ ] All attack categories show counts
- [ ] Charts/graphs render

#### Section 7 - IP Management
- [ ] Threat log with IPs loads
- [ ] Block IP button works
- [ ] Whitelist add/remove works
- [ ] IP reputation shows

#### Section 8 - Failed Logins
- [ ] Failed login attempts display
- [ ] Login attempt timeline shows
- [ ] Suspicious IP tracking works

#### Section 9 - Attack Type Breakdown
- [ ] Attack distribution chart renders
- [ ] Pie chart/bar graph displays
- [ ] Attack trend data shows

#### Section 10 - Signature Extraction
- [ ] Signatures extracted count shows
- [ ] New signatures (24h) updates
- [ ] Signature cache accessible
- [ ] Extraction accuracy displays

#### Section 11 - System Health
- [ ] CPU/Memory/Disk usage displays
- [ ] Network throughput shows
- [ ] Uptime displays
- [ ] Health status indicator works

#### Section 12 - Audit & Compliance
- [ ] Compliance frameworks list
- [ ] Controls implemented count
- [ ] Audit events display
- [ ] Compliance score shows

#### Section 13 - Attack Chain Visualization
- [ ] Network graph renders
- [ ] Attack chains display
- [ ] Lateral movement alerts show
- [ ] Graph nodes/edges count

#### Section 14 - Decision Explainability
- [ ] Decisions made count
- [ ] Explainability % displays
- [ ] Confidence scores show
- [ ] Decision history accessible

#### Section 15 - Adaptive Honeypot
- [ ] Honeypot status displays
- [ ] 8 service personas show
- [ ] Configure honeypot works
- [ ] Attack capture feed updates
- [ ] Attack history displays

#### Section 16 - Threat Crawlers
- [ ] Active crawlers count (10)
- [ ] Threats discovered shows
- [ ] Last crawl timestamp
- [ ] IOCs collected displays

#### Section 17 - Traffic Analysis
- [ ] Packets analyzed count
- [ ] Encrypted traffic % shows
- [ ] Suspicious flows display
- [ ] Protocol breakdown renders

#### Section 18 - DNS & Geo Security
- [ ] DNS tunneling attempts show
- [ ] DGA domains detected
- [ ] Geo-blocked requests count
- [ ] DNS queries total displays

#### Section 19 - User & Identity
- [ ] Users tracked count
- [ ] High-risk users display
- [ ] Trust scores show
- [ ] Identity anomalies count

#### Section 20 - Sandbox Detonation
- [ ] Files analyzed count
- [ ] Malware detected shows
- [ ] Upload file form works
- [ ] Analysis results display

#### Section 21 - Email/SMS Alerts
- [ ] Email alerts sent count
- [ ] SMS alerts sent count
- [ ] Subscribers count
- [ ] Config forms work

#### Section 22 - Crypto Mining Detection
- [ ] Miner processes count
- [ ] CPU spikes display
- [ ] Mining connections show
- [ ] Risk level indicator works
- [ ] Detected miners list

#### Section 23 - Governance & Emergency
- [ ] Pending approvals count
- [ ] Governance policies display
- [ ] Killswitch status shows
- [ ] Audit log clear works
- [ ] Integrity violations count

#### Section 24 - Enterprise Integrations
- [ ] SIEM integrations display
- [ ] Backup status shows
- [ ] Vulnerability count
- [ ] Cloud findings display
- [ ] Zero trust violations
- [ ] DLP incidents count
- [ ] Enterprise config form works

### 3. JSON Files Verification
- [ ] All 52 JSON files are bundled
- [ ] JSON files are readable at runtime
- [ ] JSON files initialize with defaults if missing
- [ ] File paths resolve correctly (Windows %LOCALAPPDATA% or bundled)

### 4. ML Models Verification
- [ ] anomaly_detector.pkl loads
- [ ] feature_scaler.pkl loads
- [ ] ip_reputation.pkl loads
- [ ] signature_cache/ directory accessible

### 5. Crypto & Security
- [ ] SSL certificates auto-generate
- [ ] HTTPS works (self-signed cert warning is normal)
- [ ] Crypto keys accessible
- [ ] HMAC verification works

### 6. Network & Integration
- [ ] Relay connection works (if enabled)
- [ ] P2P sync works (if configured)
- [ ] Firewall integration available
- [ ] Device scanning works
- [ ] Network monitoring active

### 7. Module Import Check (Critical)
Run and check for NO errors:
- [ ] `import device_scanner` (server module)
- [ ] `import device_blocker` (server module)
- [ ] `import network_monitor` (server module)
- [ ] `import AI.p2p_sync`
- [ ] `import AI.relay_client`
- [ ] `import AI.pcs_ai`
- [ ] `import AI.traffic_analyzer`
- [ ] `import AI.adaptive_honeypot`
- [ ] `import websockets`
- [ ] `import flask_cors`

### 8. API Response Check (Sample Test)
Use browser console or curl to test:
```javascript
// Section 1
fetch('/api/p2p/status').then(r => r.json()).then(console.log)
fetch('/api/relay/status').then(r => r.json()).then(console.log)

// Section 2
fetch('/api/connected-devices').then(r => r.json()).then(console.log)

// Section 15
fetch('/api/adaptive_honeypot/status').then(r => r.json()).then(console.log)

// Section 22
fetch('/api/traffic/crypto-mining').then(r => r.json()).then(console.log)
```

All should return JSON (not 404 or 500 errors)

## KNOWN ISSUES FIXED

- ❌ **RESOLVED:** `ModuleNotFoundError: No module named 'websockets'` - Added to spec
- ❌ **RESOLVED:** `.env.windows` had placeholder URLs - Updated to match `.env`
- ❌ **RESOLVED:** Documentation files had inconsistent capitalization on GitHub - Fixed with git mv

## CURRENT BUILD COMMAND

```powershell
Set-Location packaging/windows
.\build_windows_exe.ps1 -Clean
```

## CLEAN REBUILD (if needed)

```powershell
Set-Location packaging/windows
.\build_windows_exe.ps1 -Clean
```

## EXPECTED OUTPUT

- **Location:** `packaging/windows/dist/BattleHardenedAI.exe`
- **Size:** ~200-300 MB (includes numpy, scipy, sklearn)
- **Startup Time:** ~5-10 seconds (first run slower)
- **Dependencies Bundled:** All (no external installs needed)
