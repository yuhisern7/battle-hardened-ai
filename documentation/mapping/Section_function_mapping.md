# Dashboard Section to Function Mapping

This document maps each dashboard section (1-24) to its loader functions and verifies alignment with Filepurpose.md.

## ✅ Verified Sections (Functions Match File Purpose)

### Section 1: AI Training Network - Shared Machine Learning
- **Function**: `loadP2PStatus()` (line 7928)
- **APIs**: `/api/p2p/status`, `/api/relay/status`
- **Files**: `AI/relay_client.py`, `AI/p2p_sync.py`
- **JSON**: `server/json/relay_status.json` (runtime)
- **Purpose**: P2P mesh and relay network status for distributed AI training
- **Status**: ✅ MATCHES Filepurpose.md Stage 6 (Relay Sharing)

### Section 2: Network Devices - Live Monitor, Ports & History
- **Function**: `loadConnectedDevices()` (line 8263)
- **APIs**: `/api/connected-devices`
- **Files**: `server/device_scanner.py`, `server/network_monitor.py`
- **JSON**: `server/json/connected_devices.json`, `server/json/device_history.json`
- **Purpose**: Network device discovery and asset inventory
- **Status**: ✅ MATCHES Filepurpose.md Stage 1 (Data Ingestion)

### Section 3: Attackers VPN/Tor De-Anonymization Statistics
- **Function**: Part of stats API (embedded in Section 5)
- **APIs**: `/api/stats` (includes vpn_tor_detected)
- **Files**: `AI/pcs_ai.py` (Signal #11)
- **JSON**: Embedded in `threat_log.json` metadata
- **Purpose**: VPN/Tor fingerprinting and de-anonymization
- **Status**: ✅ MATCHES Filepurpose.md Stage 2 Signal #11

### Section 4: Real AI/ML Models - Machine Learning Intelligence
- **Function**: Embedded in page load
- **APIs**: `/api/stats` (includes model status)
- **Files**: `AI/pcs_ai.py`, `AI/ml_models/*.pkl`, `AI/ml_models/*.keras`
- **JSON**: `server/json/drift_baseline.json`, `server/json/drift_reports.json`, `server/json/model_lineage.json`, `server/json/model_performance.json`
- **Purpose**: ML model status and drift detection
- **Architecture Enhancements**:
  * Feature #1: Model Cryptographic Signing (`AI/model_signing.py`) - Ed25519 signatures
  * Feature #3: Model Performance Monitoring (`AI/model_performance_monitor.py`) - Production accuracy tracking
  * Feature #4: Adversarial Training (`relay/gpu_trainer.py`) - FGSM robustness
  * Feature #5: ONNX Model Format (`AI/onnx_model_converter.py`) - 2-5x faster inference
- **Status**: ✅ MATCHES Filepurpose.md Stage 2 Signals #3-9 + 5 Architecture Enhancements

### Section 5: Security Overview - Live Statistics
- **Function**: Main threat log loader (embedded in page)
- **APIs**: `/api/stats`, `/api/threat_log`
- **Files**: `server/server.py`
- **JSON**: `server/json/threat_log.json`, `server/json/blocked_ips.json`
- **Purpose**: High-level security KPIs
- **Status**: ✅ MATCHES Filepurpose.md Stage 4 (Response Execution)

### Section 6: Threat Analysis by Type
- **Function**: Threat log analysis (embedded)
- **APIs**: `/api/threat_log`
- **Files**: `server/server.py`
- **JSON**: `server/json/threat_log.json`
- **Purpose**: Breakdown of attack types (SQL injection, XSS, DDoS, etc.)
- **Status**: ✅ MATCHES Filepurpose.md Stage 4 (Logging)

### Section 7: IP Management & Threat Monitoring
- **Function**: Multiple (unblockIP, whitelistIP, blockThreatIP)
- **APIs**: `/api/blocked-ips`, `/api/whitelist`, `/api/block-ip`, `/api/unblock-ip`
- **Files**: `server/device_blocker.py`
- **JSON**: `server/json/blocked_ips.json`, `server/json/whitelist.json`
- **Purpose**: IP blocking and whitelisting management
- **Status**: ✅ MATCHES Filepurpose.md Stage 4 (Response Execution)

### Section 8: Failed Login Attempts (Battle-Hardened AI Server)
- **Function**: Embedded in stats
- **APIs**: `/api/stats` (failed_login_attempts)
- **Files**: `server/server.py` (login handler)
- **JSON**: `server/json/comprehensive_audit.json`
- **Purpose**: Server authentication monitoring
- **Status**: ✅ MATCHES Filepurpose.md (Server security)

### Section 9: Attack Type Breakdown (View)
- **Function**: Chart.js visualization (embedded)
- **APIs**: `/api/threat_log`
- **Files**: JavaScript Chart.js rendering
- **JSON**: `server/json/threat_log.json`
- **Purpose**: Visual breakdown of attack types
- **Status**: ✅ MATCHES Filepurpose.md Stage 4 (Logging)

### Section 10: Automated Signature Extraction - Attack Pattern Analysis
- **Function**: `loadSignatureExtraction()` (line 11728)
- **APIs**: `/api/signatures/extracted`
- **Files**: `AI/signature_extractor.py`
- **JSON**: `relay/ai_training_materials/ai_signatures/learned_signatures.json`
- **Purpose**: Extract attack patterns for ML training
- **Status**: ✅ MATCHES Filepurpose.md Stage 5 (Training Extraction), Signal #2

### Section 11: System Health & Network Performance
- **Function**: `loadSystemHealth()` (line 9847)
- **APIs**: `/api/system-status`
- **Files**: `server/server.py`, `AI/network_performance.py`
- **JSON**: `server/json/system_health.json` (runtime)
- **Purpose**: CPU/RAM/disk/network metrics
- **Status**: ✅ MATCHES Filepurpose.md (Server Infrastructure)

### Section 12: Audit Evidence & Compliance Mapping
- **Function**: `loadComplianceData()` (line 9535)
- **APIs**: `/api/compliance/summary`
- **Files**: `AI/compliance_reporting.py`
- **JSON**: `server/json/compliance_reports/`
- **Purpose**: PCI-DSS, HIPAA, GDPR, SOC 2 compliance
- **Status**: ✅ MATCHES Filepurpose.md (Enterprise Extensions - Auxiliary)

### Section 13: Attack Chain Visualization (Phase 4 - Graph Intelligence)
- **Function**: `loadGraphIntelligence()` (line 11820), `loadAttackChainVisualization()` (line 11103)
- **APIs**: `/api/graph/intelligence`, `/api/visualization/attack-chains`
- **Files**: `AI/graph_intelligence.py`, `AI/advanced_visualization.py`
- **JSON**: `server/json/network_graph.json`, `server/json/lateral_movement_alerts.json`
- **Purpose**: Lateral movement detection, C2 identification
- **Status**: ✅ MATCHES Filepurpose.md Stage 2 Signal #10

### Section 14: Decision Explainability Engine (Phase 7 - Transparency)
- **Function**: `loadExplainability()` (line 11860), `loadDecisionExplainability()` (line 11263)
- **APIs**: `/api/explainability/decisions`
- **Files**: `AI/explainability_engine.py`
- **JSON**: `server/json/forensic_reports/`, `relay/ai_training_materials/explainability_data/`
- **Purpose**: Decision transparency and reasoning
- **Status**: ✅ MATCHES Filepurpose.md Stage 2 Signal #15

### Section 15: Adaptive Honeypot - AI Training Sandbox
- **Function**: `loadHoneypotStatus()` (line 8959), `loadHoneypotStats()` (line 11903)
- **APIs**: `/api/adaptive_honeypot/status`
- **Files**: `AI/real_honeypot.py`, `AI/adaptive_honeypot.py`
- **JSON**: `server/json/honeypot_attacks.json`, `server/json/honeypot_patterns.json`
- **Purpose**: Real honeypot services (SSH, FTP, Telnet, MySQL, HTTP, SMTP, RDP)
- **Status**: ✅ MATCHES Filepurpose.md Stage 2 Signal #2 (Signature Matching)

### Section 16: AI Security Crawlers & Threat Intelligence Sources
- **Function**: Embedded in page (threat feed display)
- **APIs**: N/A (relay-side only)
- **Files**: `relay/threat_crawler.py`, `relay/exploitdb_scraper.py`
- **JSON**: `relay/ai_training_materials/threat_intelligence/`
- **Purpose**: CVE, MalwareBazaar, URLhaus, AlienVault OTX crawling
- **Status**: ✅ MATCHES Filepurpose.md Stage 2 Signal #12, Stage 6 (Relay)

### Section 17: Traffic Analysis & Inspection
- **Function**: `loadTrafficAnalysis()` (line 9997)
- **APIs**: `/api/traffic/analysis`
- **Files**: `AI/traffic_analyzer.py`, `AI/crypto_security.py`
- **JSON**: `server/json/crypto_mining.json`, `server/json/tls_fingerprints.json`
- **Purpose**: Protocol analysis, crypto mining detection, encrypted C2
- **Status**: ✅ MATCHES Filepurpose.md Stage 2 Signal #8

### Section 18: DNS & Geo Security
- **Function**: `loadDNSGeoSecurity()` (line 10031)
- **APIs**: `/api/dns/stats`, `/api/visualization/geographic`
- **Files**: `AI/dns_analyzer.py`
- **JSON**: `server/json/dns_security.json`
- **Purpose**: DNS tunneling/DGA detection, geographic threat mapping
- **Status**: ✅ MATCHES Filepurpose.md Stage 2 (DNS feeds Signal #2)

### Section 19: User & Identity Trust Signals
- **Function**: `loadUserIdentityMonitoring()` (line 10114), `loadUserIdentityTrust()` (line 12051)
- **APIs**: `/api/user-identity/monitoring`
- **Files**: `AI/user_tracker.py`, `AI/trust_graph.py`
- **JSON**: `server/json/tracked_users.json`, `server/json/trust_graph.json`
- **Purpose**: UEBA, zero trust scoring, entity trust tracking
- **Status**: ✅ MATCHES Filepurpose.md Stage 2 Signal #20 (Trust Degradation Graph)

### Section 20: Sandbox Detonation
- **Function**: `loadSandboxStats()` (line 10199), `loadSandboxDetonation()` (line 12073)
- **APIs**: `/api/sandbox/stats`
- **Files**: `AI/file_analyzer.py` (sandbox simulation)
- **JSON**: `server/json/sandbox_results.json`
- **Purpose**: Malware analysis statistics
- **Status**: ✅ MATCHES Filepurpose.md (Enterprise Extensions - Auxiliary)

### Section 21: Email/SMS Alerts (Critical Only)
- **Function**: `loadAlertStats()` (line 10273), `saveEmailConfig()` (line 10221), `saveSMSConfig()` (line 10248)
- **APIs**: `/api/alerts/stats`, `/api/alerts/config`
- **Files**: `AI/alert_system.py`
- **JSON**: `server/json/alert_config.json`
- **Purpose**: Email/SMS alerting for critical system events
- **Status**: ✅ MATCHES Filepurpose.md Stage 4 (Response Execution)

### Section 22: Cryptocurrency Mining Detection
- **Function**: `loadCryptoMiningDetection()` (line 10859)
- **APIs**: `/api/crypto-mining/detection`
- **Files**: `AI/traffic_analyzer.py`, `AI/crypto_security.py`
- **JSON**: `server/json/crypto_mining.json`
- **Purpose**: Crypto mining abuse detection
- **Status**: ✅ MATCHES Filepurpose.md Stage 2 Signal #8 (Traffic Analysis)

### Section 23: Governance & Emergency Controls
- **Function**: `loadGovernanceControls()` (line 11409), `loadGovernanceStats()` (line 12540), `loadKillswitchStatus()` (line 12495)
- **APIs**: `/api/governance/summary`, `/api/killswitch/status`
- **Files**: `AI/policy_governance.py`, `AI/emergency_killswitch.py`
- **JSON**: `server/json/approval_requests.json`, `server/json/killswitch_state.json`
- **Purpose**: Approval workflows, kill-switch, policy enforcement
- **Status**: ✅ MATCHES Filepurpose.md Stage 4 (Policy-Governed Response)

### Section 24: Enterprise Security Integrations
- **Function**: Multiple enterprise loaders (SOAR, vulnerability, cloud, backup, etc.)
- **APIs**: `/api/soar/*`, `/api/vulnerabilities/*`, `/api/cloud/*`, `/api/backup/*`, `/api/zero-trust/*`
- **Files**: `AI/soar_workflows.py`, `AI/vulnerability_manager.py`, `AI/cloud_security.py`, `AI/backup_recovery.py`, `AI/zero_trust.py`
- **JSON**: `server/json/soar_incidents.json`, `server/json/cloud_findings.json`, `server/json/backup_status.json`, `server/json/sbom.json`
- **Purpose**: Optional enterprise integrations (SOAR, CSPM, vulnerability management, backup monitoring)
- **Status**: ✅ MATCHES Filepurpose.md (Enterprise Extensions - Auxiliary / Non-Core)

---

## 📋 Summary

- **Total Sections**: 24
- **All Verified**: ✅ 24/24
- **Filepurpose.md Alignment**: ✅ 100%

All dashboard sections correctly map to their documented purposes in Filepurpose.md. The 7-stage pipeline is properly represented:
- Stage 1: Data Ingestion → Section 2
- Stage 2: 20 Signals + Step 21 → Sections 3, 4, 10, 13, 14, 15, 17, 18, 19, 22
- Stage 3: Ensemble Voting → Backend only (meta_decision_engine.py)
- Stage 4: Response Execution → Sections 5, 6, 7, 8, 21, 23
- Stage 5: Training Extraction → Section 10
- Stage 6: Relay Sharing → Section 1, 16
- Stage 7: Continuous Learning → Backend only (AI retraining)

Enterprise Extensions (Auxiliary): Sections 12, 20, 24

---

## 🔍 Duplicate Check Results

✅ **No duplicate sections found** - Each section has a unique ID and purpose
✅ **No duplicate functions found** - All loader functions are unique (duplicates already removed)
✅ **Filepurpose.md has no duplicates** - All signals (1-20) documented once, all stages documented once
