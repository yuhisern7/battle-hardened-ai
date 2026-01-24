# EXE Build Checklist - Battle Hardened AI

## ✅ BUILD STATUS (2026-01-24)

**Last Build:** Completed 2026-01-24 (websockets included)  
**PyInstaller Spec:** `server/BattleHardenedAI.spec` ✅ Updated  
**Icon:** `assets/BATTLE-HARDENED-AI.ico` (multi-size ICO: 16–256px) ✅ Included  
**Environment Files:** `server/.env` (Linux/Docker) and `server/.env.windows` (Windows template copied to `packaging/windows/dist/.env.windows` for the EXE) ✅ Synchronized  

### Recent Fixes Applied
- ✅ Added `websockets` module (was missing - caused relay_client.py error)
- ✅ Added `websockets.client` and `asyncio` for async support
- ✅ Updated `.env.windows` to match `.env` relay server values
- ✅ Fixed Documentation file capitalization for GitHub
- ✅ Included all 52 JSON files, ML models, crypto keys, policies
- ✅ All 55 AI Python modules included
- ✅ Windows firewall scripts, installation utilities, packaging files included

## ✅ CORE PYTHON MODULES

### AI Detection Modules (55 files)
- [ ] All 55 .py files from AI/ directory as Python source
- [ ] AI/__init__.py for package imports

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
- [ ] approval_requests.json
- [ ] attack_sequences.json
- [ ] backup_status.json
- [ ] behavioral_metrics.json
- [ ] blocked_devices.json
- [ ] blocked_ips.json
- [ ] blocked_peers.json
- [ ] causal_analysis.json
- [ ] cloud_findings.json
- [ ] cluster_config.json
- [ ] comprehensive_audit.json
- [ ] connected_devices.json
- [ ] crypto_mining.json
- [ ] decision_history.json
- [ ] device_history.json
- [ ] dns_security.json
- [ ] drift_baseline.json
- [ ] drift_reports.json
- [ ] enterprise_integration.json
- [ ] file_analysis.json
- [ ] formal_threat_model.json
- [ ] fp_filter_config.json
- [ ] governance_policies.json
- [ ] honeypot_attacks.json
- [ ] honeypot_patterns.json
- [ ] identity_access_config.json
- [ ] integrity_violations.json
- [ ] lateral_movement_alerts.json
- [ ] local_threat_intel.json
- [ ] meta_engine_config.json
- [ ] ml_performance_metrics.json
- [ ] ml_training_data.json
- [ ] model_lineage.json
- [ ] network_graph.json
- [ ] network_performance.json
- [ ] peer_threats.json
- [ ] recovery_tests.json
- [ ] reputation_export.json
- [ ] sample_threats.json
- [ ] sbom.json
- [ ] secure_deployment.json
- [ ] sla_policy.json
- [ ] soar_incidents.json
- [ ] support_tickets.json
- [ ] threat_log.json
- [ ] tls_fingerprints.json
- [ ] tracked_users.json
- [ ] tracking_data.json
- [ ] trust_graph.json
- [ ] whitelist.json

### ML Models (AI/ml_models/)
- [ ] anomaly_detector.pkl
- [ ] feature_scaler.pkl
- [ ] ip_reputation.pkl
- [ ] node_fingerprint.json
- [ ] signature_cache/ directory

### Crypto Keys
- [ ] Build-time source keys present in `server/crypto_keys/` (for Linux/Docker and initial TLS)
- [ ] `server/crypto_keys/private_key.pem`
- [ ] `server/crypto_keys/public_key.pem`
- [ ] `server/crypto_keys/shared_secret.key`
- [ ] `server/crypto_keys/ssl_cert.pem`
- [ ] `server/crypto_keys/ssl_key.pem`
- [ ] Windows EXE runtime keys stored in `%LOCALAPPDATA%\Battle-Hardened AI\server\crypto_keys` (auto-created on first run)

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
- [ ] packaging/windows/dist/.env.windows (Windows EXE runtime configuration copied from `server/.env.windows` by the EXE build script)

### Runtime Directories (auto-create on startup; for Windows EXE these live under `%LOCALAPPDATA%/Battle-Hardened AI/server/`)
- [ ] logs/
- [ ] pcap/
- [ ] json/ (if not exists)

## ✅ WINDOWS-SPECIFIC

### Firewall Scripts
- [ ] windows-firewall/ directory contents

### Installation Scripts
- [ ] server/installation/ directory contents

### Packaging
- [ ] packaging/windows/ directory contents (build scripts, .iss, local dist/)

### Required Source Folders for EXE Build
- [ ] AI/ (all detection modules and AI/ml_models/)
- [ ] server/json/ (all JSON configuration and state files)
- [ ] server/crypto_keys/ (TLS and HMAC keys; build-time source, Windows EXE runtime uses per-user data dir)
- [ ] server/installation/ (watchdog, Gunicorn configs, init_json_files.py)
- [ ] server/windows-firewall/ (Windows firewall integration scripts)
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

## ✅ DASHBOARD FEATURES TO VERIFY

1. [ ] Real-time threat monitoring
2. [ ] Device management (block/unblock)
3. [ ] IP blocking interface
4. [ ] Attack visualization
5. [ ] Honeypot analytics
6. [ ] DNS security monitoring
7. [ ] TLS fingerprinting display
8. [ ] Network graph visualization
9. [ ] Compliance reporting
10. [ ] SOAR integration status
11. [ ] File analysis results
12. [ ] Behavioral metrics
13. [ ] Trust graph viewer
14. [ ] Admin user management
15. [ ] Alert system
16. [ ] Backup/recovery status
17. [ ] Cloud security findings
18. [ ] Drift detection reports
19. [ ] Audit logs
20. [ ] ML performance metrics

## ✅ API ENDPOINTS TO VERIFY

- [ ] /api/stats
- [ ] /api/threat_log
- [ ] /api/connected-devices
- [ ] /api/traffic/analysis
- [ ] /api/dns/stats
- [ ] /api/adaptive_honeypot/status
- [ ] /api/signatures/extracted
- [ ] /api/system-status
- [ ] /api/compliance/summary
- [ ] /api/governance/stats
- [ ] /api/killswitch/status
- [ ] /api/alerts/stats
- [ ] /api/sandbox/stats
- [ ] /api/traffic/crypto-mining
- [ ] /api/enterprise-integration/config
- [ ] Representative SOAR/documentation endpoints: /api/soar/stats, /api/openapi.json, /api/docs
- [ ] All other REST endpoints documented in documentation/Dashboard.md respond with 2xx or appropriate auth errors

## POST-BUILD VERIFICATION

1. [ ] EXE has BATTLE-HARDENED-AI.ico icon
2. [ ] EXE size is reasonable (check for bloat)
3. [ ] Run EXE and verify NO import errors (especially `websockets`)
4. [ ] Check all 21 AI layers load without errors
5. [ ] Verify dashboard loads at https://localhost:60000 (self-signed by default; or http://localhost:60000 if TLS is terminated by an external proxy)
6. [ ] Test relay connection works (if RELAY_ENABLED=true in .env.windows)
7. [ ] Verify JSON files are accessible and readable
8. [ ] Confirm ML models load (anomaly_detector.pkl, etc.)
9. [ ] Test crypto operations work (private/public keys)
10. [ ] Verify NO relay/ folder references or files included
11. [ ] Check .env.windows is present next to BattleHardenedAI.exe (`packaging/windows/dist/.env.windows`)
12. [ ] Verify runtime crypto_keys directory is accessible at `%LOCALAPPDATA%/Battle-Hardened AI/server/crypto_keys`
13. [ ] Test Step21 semantic gate loads
14. [ ] Confirm honeypot functionality works
15. [ ] Verify all APIs respond correctly

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
