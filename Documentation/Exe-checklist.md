# EXE Build Checklist - Battle Hardened AI

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

### Crypto Keys (server/crypto_keys/)
- [ ] private_key.pem
- [ ] public_key.pem
- [ ] shared_secret.key
- [ ] ssl_cert.pem
- [ ] ssl_key.pem

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
- [ ] .env
- [ ] .env.windows

### Runtime Directories (auto-create on startup)
- [ ] logs/
- [ ] pcap/
- [ ] json/ (if not exists)

## ✅ WINDOWS-SPECIFIC

### Firewall Scripts
- [ ] windows-firewall/ directory contents

### Installation Scripts
- [ ] server/installation/ directory contents

### Packaging
- [ ] server/packaging/ directory contents

## ✅ ICON & BRANDING

- [ ] assets/desktop.ico (for EXE icon)

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

- [ ] /api/threats
- [ ] /api/devices
- [ ] /api/block_ip
- [ ] /api/honeypot
- [ ] /api/dns
- [ ] /api/tls
- [ ] /api/graph
- [ ] /api/compliance
- [ ] /api/soar
- [ ] /api/alerts
- [ ] /api/backup
- [ ] /api/admin
- [ ] All other REST endpoints functional

## BUILD COMMAND

```powershell
.venv/Scripts/pyinstaller.exe server/BattleHardenedAI.spec
```

## POST-BUILD VERIFICATION

1. [ ] EXE has desktop.ico icon
2. [ ] EXE size is reasonable (check for bloat)
3. [ ] Run EXE and verify no import errors
4. [ ] Check all 21 AI layers load
5. [ ] Verify dashboard loads
6. [ ] Test each API endpoint
7. [ ] Verify JSON files are accessible
8. [ ] Confirm ML models load
9. [ ] Test crypto operations
10. [ ] Verify no relay/ folder references
