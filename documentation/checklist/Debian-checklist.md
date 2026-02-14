# Debian Package Checklist - Battle-Hardened AI

> Goal: Ship a reproducible `.deb` package for Debian/Ubuntu gateways and hosts that matches the architecture and behavior documented in README.md and Installation.md, with clean systemd integration and no surprises for operators.

## ✅ EXPECTED WARNINGS (HARMLESS - CAN BE IGNORED)

### PyInstaller Build-Time Inspection Warnings (Windows EXE Only)
These warnings appear during Windows EXE execution due to PyInstaller's frozen environment limitations. They do NOT affect functionality:

- ⚠️ `[RUNTIME HOOK] Failed to load skl2onnx: could not get source code` - skl2onnx imports and works correctly, PyInstaller just can't inspect source at build time
- ⚠️ `[AI WARNING] Failed to load ML models: could not get source code` - ML models initialize, train, and predict successfully (check logs: "✅ ML models initialized successfully")

**Why these occur:** PyInstaller uses `inspect.getsource()` during module analysis, but frozen executables don't have source code files. The actual imports succeed immediately after the warning.

**Impact:** None - purely cosmetic. All ML functionality works perfectly (TensorFlow, ONNX, scikit-learn, model training/inference).

**Linux/Debian:** These warnings do NOT appear in native Python or Debian package installations.

### Geolocation API Rate Limits (All Platforms - 2026-02-06 Fix Applied)
- ⚠️ `[GEO] Rate limit exceeded for ip-api.com (45 requests/min). Using fallback for X.X.X.X` - System has 24-hour geolocation cache to prevent this. Only appears during high-volume attack testing.
- ✅ **Fix Applied:** IP geolocation data cached for 24 hours per IP to prevent rate limit errors. Failed lookups also cached to prevent retry storms.

---

## ✅ RECENT UPDATES (2026-02-09)

**Health Check Implementation:**
- ✅ Created `packaging/health-check.sh` (265 lines) - Comprehensive 7-step diagnostics
- ✅ Enhanced `packaging/debian-startup.sh` (267 lines) - Windows installer-style 8-step progress output
- ✅ Added dashboard banner in `AI/inspector_ai_monitoring.html` - Auto-detects installation issues
- ✅ Integrated health check into `packaging/debian/battle-hardened-ai.postinst` - Calls debian-startup.sh after setup
- ✅ Added API endpoints: `/api/health/status` (quick status), `/api/health/check` (full diagnostics)
- ✅ All 3 systemd services verified: battle-hardened-ai, firewall-sync, device-scanner
- ✅ Fixed `.env` template path in debian/rules (../../server/.env → ../server/.env)
- ✅ Created comprehensive verification checklist: `documentation/Debian-packaging-verification.md`

## ✅ PYTHON 3.12 COMPATIBILITY (2026-02-04)

**Distutils Compatibility:**
- ✅ Python 3.12 removed `distutils` from standard library
- ✅ TensorFlow 2.18.1 requires distutils during initialization
- ✅ `setuptools>=65.0.0` in requirements.txt provides `setuptools._distutils`
- ✅ Python automatically finds distutils via setuptools (no manual shim needed for venv)
- ✅ All ML packages (TensorFlow, ONNX, scikit-learn) work correctly with Python 3.12+

**Tested Working Versions (server/requirements.txt):**
- `tensorflow-cpu>=2.18.0,<2.19.0` - TensorFlow 2.18.x has stable Keras integration (2.20.0 missing tensorflow.python.trackable)
- `onnx==1.16.2` - Compatible with TensorFlow 2.18.x (1.20.1 has ml_dtypes conflicts, 1.19.1 breaks skl2onnx)
- `setuptools>=65.0.0` - Provides distutils compatibility for Python 3.12+
- `onnxruntime==1.16.3` - Fast inference runtime
- `skl2onnx==1.16.0` - sklearn to ONNX conversion

## ✅ SCOPE & TARGETS

- [x] Target distros and versions defined (Debian 12, Ubuntu 22.04 LTS as documented in Installation.md).
- [x] Architecture targets defined (`amd64` first; arm64 can be added later).
- [x] Package name/version decided (`battle-hardened-ai` with Debian versioning as in `packaging/debian/control`).
- [x] Single-node gateway profile is the primary supported mode (documented in README and the Debian .deb section of Installation.md).

## ✅ FILESYSTEM LAYOUT (LINUX STANDARD)

Decide and **keep consistent** between `.deb` and `.rpm`:

- [x] Application code under `/opt/battle-hardened-ai` (or `/usr/lib/battle-hardened-ai`) – chosen and documented (installed via `packaging/debian/rules`).
- [x] Configuration / JSON state under `/var/lib/battle-hardened-ai/server/json` (via `AI/path_helper` and `BATTLE_HARDENED_DATA_DIR`).
- [x] Logs under `/var/log/battle-hardened-ai`.
- [x] PCAP capture directory under `/var/lib/battle-hardened-ai/pcap` (created in `battle-hardened-ai.postinst`).
- [x] Crypto keys under `/var/lib/battle-hardened-ai/server/crypto_keys`, matching `AI.path_helper.get_crypto_keys_dir()` and `server/crypto_keys/`.
- [x] Systemd unit(s) installed to `/lib/systemd/system/`.
- [x] Ownership and permissions defined (e.g. `bhai:bhai` service user, no root-only JSON unless required).

## ✅ CORE PYTHON MODULES (MATCH WINDOWS EXE CONTENT)

Ensure the same logical code is present for Linux packages as for the EXE build (no hidden omissions):

- [x] All 55+ Python modules from `AI/` installed as source on the target (entire `AI/` tree copied under `/opt/battle-hardened-ai/AI/` by `packaging/debian/rules`).
- [x] `AI/__init__.py` present so package imports work.
- [x] **5 Architecture Enhancement Modules** present:
  - [x] `AI/model_signing.py` - Ed25519 cryptographic model verification (MITRE T1574.012 defense)
  - [x] `AI/pattern_filter.py` - Bloom filter deduplication (70-80% bandwidth savings)
  - [x] `AI/model_performance_monitor.py` - Production ML accuracy tracking (MITRE T1565.001 defense)
  - [x] `AI/onnx_model_converter.py` - Model conversion to ONNX format (relay-side, may be present but not used on gateway)
  - [x] ONNX runtime integration in `AI/pcs_ai.py` - 2-5x faster CPU inference
- [x] 21-layer detection modules present:
  - [x] `AI/step21_gate.py`
  - [x] `AI/step21_policy.py`
  - [x] `AI/step21_semantic_gate.py`
  - [x] Behavioral, traffic, DNS, TLS, file, sequence, causal, graph, kernel, network performance, PCAP, honeypot, threat intel, reputation, trust graph, FP filter, drift detector modules (same list as in Exe-checklist.md) included via the full `AI/` copy.

- [x] Server-side modules present:
  - [x] `server/server.py` (main Flask/API server).
  - [x] `server/network_monitor.py` (live traffic analysis, feeds all detection signals).
  - [x] `server/device_scanner.py` (cross-platform network detection: Linux via ip route/addr, Windows via ipconfig parsing, fallback via socket trick).
  - [x] `server/device_blocker.py` (firewall enforcement).
  - [x] `server/installation/*` (Gunicorn configs, init_json_files.py, firewall sync helper) as needed for Linux.
  - [x] Any helper scripts referenced by docs are either included (under `/opt/battle-hardened-ai/server/`) or clearly documented as dev-only.

## ✅ DATA & STATE FILES (JSON, ML, POLICIES)

### JSON Files (from `server/json/`)

- [x] All JSON surfaces required by the dashboard and APIs are installed **or** auto-created on first run by init scripts (`postinst` copies templates to `/var/lib/battle-hardened-ai/server/json/` on first install, and `init_json_files.py` remains available).
- [x] For files that must exist at install time (to avoid 500s), ensure they are shipped in the package or created by `postinst` or an init script (templates under `/opt/battle-hardened-ai/server/json/` plus `postinst` seeding cover this).
- [x] Key JSON files are present/handled (either as templates under `server/json/` copied by `postinst`, or created on demand by `installation/init_json_files.py`):
  - [x] `admin_users.json`
  - [x] `alert_config.json` (Section 21 - Email/SMS alerting)
  - [x] `approval_requests.json` (Section 23 - Governance)
  - [x] `attack_sequences.json`
  - [x] `backup_status.json` (Section 24 - Backup monitoring)
  - [x] `behavioral_metrics.json`
  - [x] `blocked_devices.json` (Section 2)
  - [x] `blocked_ips.json`
  - [x] `blocked_peers.json` (Section 1 - P2P mesh)
  - [x] `causal_analysis.json`
  - [x] `cloud_findings.json` (Section 24 - Cloud security)
  - [x] `cluster_config.json` (Section 11 - HA configuration)
  - [x] `comprehensive_audit.json`
  - [x] `connected_devices.json` (Section 2 - Device inventory)
  - [x] `crypto_mining.json`
  - [x] `decision_history.json` (Explainability)
  - [x] `device_history.json` (Section 2 - 7-day history)
  - [x] `dns_security.json`
  - [x] `drift_baseline.json`
  - [x] `drift_reports.json` (Section 4 - Drift detection)
  - [ ] `enterprise_integration.json` ⚠️ **PLANNED** - Structure documented but not implemented
  - [x] `file_analysis.json` (Section 20 - Sandbox)
  - [x] `formal_threat_model.json`
  - [x] `fp_filter_config.json` (False positive filter)
  - [x] `governance_policies.json`
  - [x] `honeypot_attacks.json`
  - [x] `honeypot_patterns.json`
  - [x] `identity_access_config.json`
  - [x] `integrity_violations.json` (Section 23 - Self-protection)
  - [x] `killswitch_state.json` (Section 23 - Emergency killswitch)
  - [x] `lateral_movement_alerts.json` (Section 13 - Graph intelligence)
  - [x] `local_threat_intel.json`
  - [x] `meta_engine_config.json`
  - [x] `ml_performance_metrics.json`
  - [x] `model_lineage.json`
  - [x] `network_graph.json` (Section 13 - Attack chains)
  - [x] `network_performance.json`
  - [x] `peer_threats.json` (Section 1 - P2P threats)
  - [x] `recovery_tests.json` (Section 24 - Backup recovery)
  - [x] `relay_status.json` (Section 1 - Relay connection, runtime)
  - [x] `reputation_export.json`
  - [x] `sample_threats.json`
  - [x] `sandbox_results.json` (Section 20 - Sandbox detonation)
  - [x] `sbom.json`
  - [x] `secure_deployment.json`
  - [x] `sla_policy.json`
  - [x] `soar_incidents.json`
  - [x] `support_tickets.json`
  - [x] `system_health.json` (Section 11 - System metrics, runtime)
  - [x] `threat_log.json`
  - [x] `tls_fingerprints.json`
  - [x] `tracked_users.json` (Section 19 - UEBA)
  - [x] `tracking_data.json`
  - [x] `trust_graph.json`
  - [x] `whitelist.json`
  - [x] `pattern_filter_state.json` (Architecture Enhancement #2 - Bloom filter state)
  - [x] `ml_performance.json` (Architecture Enhancement #3 - ML performance monitoring data)
  - [x] **Directories:**
    - [x] `compliance_reports/` (Section 12 - PCI-DSS/HIPAA/GDPR/SOC2)
    - [x] `forensic_reports/` (Section 14 - Decision explainability)

(Exact list has been reconciled with `server/json/` and Filepurpose.md; any new JSON surfaces added later must follow the same pattern.)

### ML Models (`AI/ml_models/`)

- [x] `anomaly_detector.pkl`
- [x] `feature_scaler.pkl`
- [x] `ip_reputation.pkl`
- [x] `node_fingerprint.json`
- [x] `signature_cache/` directory (if used in Linux deployments)
- [x] **ONNX Models (Architecture Enhancement #5 - 2-5x faster inference)**:
  - [x] `anomaly_detector.onnx` (if relay distributes ONNX models)
  - [x] `feature_scaler.onnx` (if available)
  - [x] `threat_classifier.onnx` (if available)
  - [x] Note: ONNX models are optional; system falls back to pickle models if unavailable

### Crypto Keys (`server/crypto_keys/` → runtime location)

- [x] Ensure build-time keys from `server/crypto_keys/` are either:
  - [x] Shipped into a secure location (for lab/demo) under `/opt/battle-hardened-ai/server/crypto_keys`, **and**
  - [x] Generated/overridden on first run in `/var/lib/battle-hardened-ai/server/crypto_keys` by `packaging/debian/battle-hardened-ai.postinst`.
- [x] TLS cert/key paths in Linux match the defaults in `.env` / README (Gunicorn and server use `BASE_DIR/crypto_keys/ssl_{cert,key}.pem`, while Debian runtime keys live under `/var/lib/battle-hardened-ai/server/crypto_keys` for message security and relay HMAC).
- [x] **Model Signing Keys (Architecture Enhancement #1)**:
  - [x] Customer verification public key: `/var/lib/battle-hardened-ai/server/crypto_keys/relay_public_key.pem` (for verifying relay-signed models)
  - [x] Relay signing private key: Only on relay server, not shipped with customer gateway package

### Step 21 Policies (`policies/step21/`)

- [x] `manifest.json`
- [x] `manifest.sig`
- [x] `policy.json`
- [x] `schema.json`
- [x] Installed to a stable path (`/opt/battle-hardened-ai/policies/step21`) via `packaging/debian/rules`, resolved by `AI/step21_policy._get_policy_dir()`.

## ✅ UI / DASHBOARD FILES (LINUX)

- [x] HTML dashboard files copied to the path the server expects:
  - [x] `AI/inspector_ai_monitoring.html` (or server templates if moved)
  - [x] `AI/docs_portal.html`
  - [x] `AI/docs_viewer.html`
  - [x] `AI/swagger_ui.html`
- [x] If `server/templates/` or `server/static/` exist, include all `.html`, `.css`, `.js`, and assets needed for the dashboard.

## ✅ CONFIGURATION & ENVIRONMENT

- [x] Linux `.env` file (`server/.env`) is **not** blindly overwritten on upgrade; default values are copied to `/etc/battle-hardened-ai/.env` on first install only (logic implemented in `battle-hardened-ai.postinst`).
- [x] Package:
  - Ships a default `/etc/battle-hardened-ai/.env` on first install, and
  - Documents editing it in Installation.md, with the systemd unit referencing it via `EnvironmentFile=`.
- [x] JSON directory and ML model directory resolution in `AI/path_helper.py` are compatible with the chosen filesystem layout via `BATTLE_HARDENED_DATA_DIR=/var/lib/battle-hardened-ai`.

### Python Runtime Strategy (PLAN BEFORE BUILD)

- [x] Decide Python runtime model for Debian:
  - [x] Use system `python3` with a dedicated virtualenv under `/opt/battle-hardened-ai/venv` (implemented in `packaging/debian/battle-hardened-ai.postinst`).
  - [ ] Depend solely on system `python3` + `pip` packages (no venv).
- [x] For the chosen model, document clearly in Installation.md:
  - [x] Minimum supported Python version (3.10+ on Debian/Ubuntu as per the Debian .deb section).
  - [x] Which dependencies are installed via `apt` vs `pip` (base `python3`, `python3-venv`, `systemd`, `iptables`, `ipset`, `curl` via `apt`; Python packages from `server/requirements.txt` including Flask-CORS==4.0.0, onnxruntime (Architecture Enhancement #5), skl2onnx (relay-side for Enhancement #5) via `pip` in the venv).
- [x] Ensure `gunicorn` (Linux-only) is available where systemd `ExecStart` expects it: either in the venv or system-wide (systemd `ExecStart` uses `/opt/battle-hardened-ai/venv/bin/gunicorn`, and postinst now creates the venv and installs requirements).
- [x] Confirm that sequence/deep-learning features gracefully degrade if TensorFlow is not installed (as documented in `server/requirements.txt` and guarded in `AI/sequence_analyzer.py` by optional TensorFlow imports).
- [x] **Architecture Enhancements - Graceful Degradation**:
  - [x] ONNX runtime is optional: System falls back to pickle models if `onnxruntime` unavailable (check `AI/pcs_ai.py` for fallback logic)
  - [x] Model signing warnings logged if public keys missing (system still functions with reduced security)
  - [x] Pattern filter can be disabled without breaking relay uploads (just loses bandwidth savings)

### Service User & Permissions (PLAN BEFORE BUILD)

- [x] Choose a dedicated service account (e.g. `bhai`) with:
  - [x] No interactive login shell and no home directory (system account) or a minimal home (created in `battle-hardened-ai.postinst`).
  - [x] Group ownership aligned with log and data directories (`bhai:bhai` on `/var/lib` and `/var/log`).
- [x] Define ownership model:
  - [x] `/opt/battle-hardened-ai/**` owned by `root:root`, mode `755` (read-only code) – provided by default Debian package install semantics.
  - [x] `/var/lib/battle-hardened-ai/**` owned by `bhai:bhai`, mode `750` (JSON, models, keys) – created in `battle-hardened-ai.postinst`.
  - [x] `/var/log/battle-hardened-ai/**` owned by `bhai:bhai`, mode `750` – created in `battle-hardened-ai.postinst`.
  - [x] `/etc/battle-hardened-ai/**` owned by `root:bhai`, mode `640`/`750` (config readable by service, writable by root) – `.env` and directory ownership set in `battle-hardened-ai.postinst`.
- [x] Decide on `umask` for the service (e.g. 007 as in gunicorn_config) to prevent world-readable files (set `UMask=007` in systemd units).

## ✅ SYSTEMD INTEGRATION

- [x] `packaging/systemd/battle-hardened-ai.service` created with:
  - [x] `ExecStart` finalized using Gunicorn as per `server/installation/gunicorn_config.py` for Linux:
    - [x] `ExecStart=/opt/battle-hardened-ai/venv/bin/gunicorn --config /opt/battle-hardened-ai/server/installation/gunicorn_config.py server:app`
  - [x] `WorkingDirectory` set to `/opt/battle-hardened-ai/server` (so relative paths in `server.py` and gunicorn_config work).
  - [x] `User`/`Group` set to the dedicated service account (`bhai`).
  - [x] `Restart=on-failure` (systemd unit configured).
  - [x] `EnvironmentFile=/etc/battle-hardened-ai/.env` referenced explicitly.
  - [x] `Environment=BATTLE_HARDENED_DATA_DIR=/var/lib/battle-hardened-ai BATTLE_HARDENED_PROJECT_ROOT=/opt/battle-hardened-ai` so `AI/path_helper` and gunicorn_config resolve correctly.
  - [x] Resource and security options planned:
    - [x] `LimitNOFILE=65535`.
    - [x] `CapabilityBoundingSet`/`AmbientCapabilities` set for the firewall sync unit to grant only `CAP_NET_ADMIN` (see `battle-hardened-ai-firewall-sync.service`).
- [x] `packaging/systemd/battle-hardened-ai-firewall-sync.service` created (5-second sync daemon for ipset/iptables).
- [x] `packaging/systemd/battle-hardened-ai-device-scanner.service` created (separate daemon for ARP/raw socket device scanning with CAP_NET_ADMIN and CAP_NET_RAW capabilities).
- [x] Debian package installs all 3 systemd units to `/lib/systemd/system/`.
- [x] `postinst` (or debhelper) calls:
  - [x] `systemctl daemon-reload`
  - [x] `systemctl enable`/`restart` all 3 services: `battle-hardened-ai`, `battle-hardened-ai-firewall-sync`, `battle-hardened-ai-device-scanner`.
- [x] `prerm`/`postrm` handle stop/disable cleanly for all 3 services.

## ✅ DEBIAN PACKAGING FILES (`packaging/debian/`)

- [x] `control`
  - [x] Package metadata (name, version, maintainer, description) filled in.
  - [x] Dependencies listed: `python3`, `python3-venv` or equivalent, `systemd`, `iptables`, `ipset`, `curl` (extend as needed from `server/requirements.txt`).
- [x] `rules`
  - [x] Uses `dh` (debhelper) for a simple build.
  - [x] Installs files to the chosen filesystem layout.
- [ ] `.install` file(s) (e.g. `battle-hardened-ai.install`)
  - [ ] Canonical layout decision documented and used consistently:
    - [ ] Runtime **data root** for non-frozen deployments set via `BATTLE_HARDENED_DATA_DIR=/var/lib/battle-hardened-ai` in the systemd unit so that `AI/path_helper.get_data_root()` points to `/var/lib/battle-hardened-ai` instead of the project root.
    - [ ] Application code installed under `/opt/battle-hardened-ai` (read-only, owned by root):
      - [ ] `AI/` → `/opt/battle-hardened-ai/AI/`
      - [ ] `server/` (minus Windows-only artifacts like `debug_server.py` and any dev-only helpers) → `/opt/battle-hardened-ai/server/`
      - [ ] `policies/` → `/opt/battle-hardened-ai/policies/`
      - [ ] `assets/` → `/opt/battle-hardened-ai/assets/`
    - [ ] Runtime **data directories** created under `/var/lib/battle-hardened-ai` (writable by service user):
      - [ ] JSON: `/var/lib/battle-hardened-ai/server/json/` (target for `get_json_dir()`)
      - [ ] ML models: `/var/lib/battle-hardened-ai/AI/ml_models/` (target for `get_ml_models_dir()`)
      - [ ] Crypto keys: `/var/lib/battle-hardened-ai/server/crypto_keys/` (target for `get_crypto_keys_dir()`)
      - [ ] Relay training directory (optional, if relay ever runs on same host): `/var/lib/battle-hardened-ai/relay/ai_training_materials/` (target for `get_relay_training_dir()`, but **not** shipped with the gateway `.deb`).
    - [ ] Logs directory: `/var/log/battle-hardened-ai/` (referenced by server logging config and systemd `StandardOutput`/`StandardError`).
    - [ ] Config directory: `/etc/battle-hardened-ai/` (contains `.env` or config templates referenced by the systemd unit’s `EnvironmentFile=`).
  - [ ] `battle-hardened-ai.install` contains explicit mappings (plan, to be implemented):
    - [ ] `AI/* opt/battle-hardened-ai/AI/`
    - [ ] `server/*.py opt/battle-hardened-ai/server/`
    - [ ] `server/installation/* opt/battle-hardened-ai/server/installation/`
    - [ ] `server/json/* opt/battle-hardened-ai/server/json/` (initial templates; runtime JSON will live under `/var/lib/battle-hardened-ai/server/json/` and may be copied/initialized by `postinst`)
    - [ ] `server/pcap/* opt/battle-hardened-ai/server/pcap/` (if any baseline/example files are shipped)
    - [ ] `server/crypto_keys/* opt/battle-hardened-ai/server/crypto_keys/` (lab/demo keys only; production keys generated/overridden at first run)
    - [ ] `policies/* opt/battle-hardened-ai/policies/`
    - [ ] `assets/* opt/battle-hardened-ai/assets/`
    - [ ] `packaging/systemd/battle-hardened-ai.service lib/systemd/system/`
    - [ ] (No entries for `relay/`, `packaging/windows/` (including `windows-firewall` helpers), `.git`, `.venv`, `build/`, or other Windows-only files as per the EXCLUSIONS section.)
- [x] Optional maintainer scripts:
  - [x] `postinst` for first-time JSON/dir initialization, venv setup, and service enable/start.
  - [x] `prerm`/`postrm` for cleanup and service stop/disable.

### Postinst / Upgrade / Removal Behavior (PLAN BEFORE BUILD)

- [x] `postinst` responsibilities clearly defined and implemented:
  - [x] Create `/var/lib/battle-hardened-ai/**` and `/var/log/battle-hardened-ai/**` with correct ownership and modes.
  - [x] Copy initial JSON templates from `/opt/battle-hardened-ai/server/json/` into `/var/lib/battle-hardened-ai/server/json/` **only on first install** (if target is empty).
  - [x] Generate crypto keys in `/var/lib/battle-hardened-ai/server/crypto_keys/` if none exist (lab/demo keys may still exist under `/opt/...` for reference only), implemented via an embedded Python helper in `battle-hardened-ai.postinst`.
  - [ ] Seed SBOM or integrity baselines if required by self_protection.
  - [x] Reload systemd and enable/start the services.
- [ ] Upgrade behavior:
  - [x] Preserve existing JSON and logs; never overwrite `/var/lib/battle-hardened-ai/**` by default (`postinst` only seeds when targets are empty).
  - [ ] Handle JSON schema changes via migration scripts if keys/structures change.
- [x] Removal behavior:
  - [x] `apt remove` stops/ disables the service but leaves `/var/lib` and `/var/log` intact (implemented in `prerm`/`postrm` and documented here).
  - [x] `apt purge` also leaves data directories intact by design; operators remove them manually if desired (behavior documented in `postrm`).

## ✅ FIREWALL INTEGRATION (LINUX)

- [x] Package either:
  - [x] Ships helper scripts to sync `blocked_ips.json` into ipset/iptables (Linux equivalent of Windows firewall script), **and/or**
  - [x] Documents how to wire existing firewall automation to `blocked_ips.json` (see `Documentation/Firewall_enforcement.md` for Linux/Docker and Debian/.deb guidance).
- [x] Ensure any Linux-only firewall scripts or config are included under a stable path (`/opt/battle-hardened-ai/server/installation/bh_firewall_sync.py`).

### Firewall Sync Helper (PLAN BEFORE BUILD)

- [x] Align `server/installation/bh_firewall_sync.py` with Debian layout:
  - [x] Modify or parameterize JSON path so it reads from `AI.path_helper.get_blocked_ips_file()` (e.g. `/var/lib/battle-hardened-ai/server/json/blocked_ips.json` under `.deb`, `/app/json/blocked_ips.json` under Docker) instead of a hard-coded `/app/json` path.
  - [x] Install script to a stable location (e.g. `/opt/battle-hardened-ai/server/installation/bh_firewall_sync.py`) via `packaging/debian/rules`.
- [x] Decide how the helper is started:
  - [x] Via a separate systemd unit (and optional BH_FIREWALL_SYNC_ENABLED env guard) using `battle-hardened-ai-firewall-sync.service`.
  - [ ] Via the main service using `BH_FIREWALL_SYNC_ENABLED` env var (Docker-style) if that model is preserved.
- [x] Document required capabilities (NET_ADMIN, ipset/iptables availability) for Linux hosts (see Firewall_enforcement.md and Docker/host networking notes).

## ✅ RUNTIME DIRECTORIES & PERMISSIONS

On install (or first start), ensure the following exist with correct ownership and permissions:

- [x] `/var/lib/battle-hardened-ai/server/json/` (state + JSON surfaces; created and seeded by `battle-hardened-ai.postinst`).
- [x] `/var/lib/battle-hardened-ai/pcap/` (created by `battle-hardened-ai.postinst`).
- [x] `/var/lib/battle-hardened-ai/server/crypto_keys/` (created and populated by `battle-hardened-ai.postinst`).
- [x] `/var/log/battle-hardened-ai/` (created by `battle-hardened-ai.postinst`).
- [x] Permissions allow the service user to read/write, but are not world-readable for sensitive content (`bhai:bhai`, `750` on data/log directories, `UMask=007` in systemd units).

### Logging & Rotation (PLAN BEFORE BUILD)

- [x] Decide logging strategy:
  - [x] Rely primarily on systemd-journald (Gunicorn logs to stdout/stderr as configured in `gunicorn_config.py`).
  - [x] Reserve `/var/log/battle-hardened-ai/` for optional structured/app logs managed by the Python code (directory created in `postinst`).
- [x] If file logs are used beyond the journal and transient debug output, create a `logrotate` config snippet so logs do not grow without bounds (`packaging/debian/battle-hardened-ai.logrotate`).
- [x] Ensure log files never contain sensitive secrets or full payloads beyond what README promises (logging remains focused on metadata, summaries, and threat context).

## ✅ DASHBOARD SECTIONS (24 SECTIONS - VERIFY ALL ON DEBIAN/UBUNTU)

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

**Python Modules:**
- [ ] `AI/p2p_sync.py`
- [ ] `AI/relay_client.py`
- [ ] `AI/pattern_filter.py` - Architecture Enhancement #2 (70-80% bandwidth savings)

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
- [ ] `server/device_scanner.py` ⚠️ **CRITICAL**
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
- [ ] `/api/architecture-enhancements/status` - All 5 enhancement statuses
- [ ] `/api/model-signing/verification-status` - Signature verification details (Enhancement #1)
- [ ] `/api/onnx/performance` - ONNX vs pickle inference times (Enhancement #5)
- [ ] `/api/pattern-filter/stats` - Pattern deduplication statistics (Enhancement #2)
- [ ] `/api/ml-performance` - ML performance monitoring (Enhancement #3)

**JSON Files:**
- [ ] `ml_training_data.json` - Training dataset
- [ ] `ml_performance_metrics.json` - Model accuracy/precision
- [ ] `drift_baseline.json` - Baseline for drift detection
- [ ] `drift_reports.json` - Detected model drift
- [ ] `ml_performance.json` - Architecture Enhancement #3 - Performance monitoring data
- [ ] `pattern_filter_state.json` - Architecture Enhancement #2 - Bloom filter state

**ML Models:**
- [ ] `AI/ml_models/anomaly_detector.pkl`
- [ ] `AI/ml_models/feature_scaler.pkl`
- [ ] `AI/ml_models/ip_reputation.pkl`
- [ ] `AI/ml_models/anomaly_detector.onnx` - Architecture Enhancement #5 (2-5x faster)
- [ ] `AI/ml_models/feature_scaler.onnx` - Architecture Enhancement #5
- [ ] `AI/ml_models/threat_classifier.onnx` - Architecture Enhancement #5

**Playcards/Metrics:**
- [ ] Model Accuracy
- [ ] False Positive Rate
- [ ] Training Samples count
- [ ] Last Retrained timestamp
- [ ] Active Models list
- [ ] Model Signatures - ✅ Verified (Ed25519) or ⚠️ Unverified (Enhancement #1)
- [ ] ONNX Inference Time - X.Xms (2-5x faster) vs pickle baseline (Enhancement #5)
- [ ] Pattern Filter Efficiency - XX% bandwidth saved (Enhancement #2)
- [ ] Performance Monitor Status - Accuracy XX.X% (healthy/warning/critical) (Enhancement #3)
- [ ] Adversarial Training - ✅ Enabled or ❌ Disabled (Enhancement #4)

**Python Modules:**
- [ ] `AI/pcs_ai.py`
- [ ] `AI/drift_detector.py`
- [ ] `AI/meta_decision_engine.py`
- [ ] `AI/model_signing.py` - Architecture Enhancement #1 (MITRE T1574.012)
- [ ] `AI/pattern_filter.py` - Architecture Enhancement #2 (70-80% bandwidth savings)
- [ ] `AI/model_performance_monitor.py` - Architecture Enhancement #3 (MITRE T1565.001)
- [ ] `AI/onnx_model_converter.py` - Architecture Enhancement #5 (relay-side)
- [ ] ONNX runtime integration in `AI/pcs_ai.py` - Architecture Enhancement #5

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
- [ ] `/api/firewall/detect` - Firewall backend detection (NEW)
- [ ] `/api/firewall/status` - Firewall sync status + IP counts (NEW)
- [ ] `/api/firewall/sync` - Force immediate firewall sync (NEW)
- [ ] `/api/firewall/test` - 3-step integration test (NEW)
- [ ] `/api/firewall/rules` - View our rules vs customer rules (NEW)
- [ ] `/api/firewall/backend` - Manual backend override (NEW)

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
- [ ] `AI/firewall_backend.py` (NEW - multi-distro backend abstraction)
- [ ] `server/installation/bh_firewall_sync.py` (NEW - 5-second sync daemon)

**Linux Firewall Commander Subsection (Tab 4 - NEW):**
- [ ] **Backend Detection Panel:**
  - [ ] Auto-detect firewall backend (iptables/firewalld/VyOS/OpenWRT/Alpine)
  - [ ] Display detected backend with full name
  - [ ] Show sync daemon status (Active/Inactive)
  - [ ] Show last sync timestamp
- [ ] **Sync Health Indicators:**
  - [ ] Whitelist IP count (synced vs pending)
  - [ ] Blocklist IP count (synced vs pending)
  - [ ] Sync warning banner (hidden when synced)
  - [ ] Visual sync status badges (✅ Synced / ⚠️ Pending)
- [ ] **Action Buttons:**
  - [ ] ⚡ Force Sync Now (immediate sync, bypasses 5s delay)
  - [ ] 🧪 Test Integration (3-step non-destructive test)
  - [ ] 📋 View Native Rules (customer's existing firewall rules)
  - [ ] 🔄 Refresh Status (manual refresh)
- [ ] **Our Firewall Rules Table:**
  - [ ] Whitelist layer (Priority 1 ACCEPT)
  - [ ] Blocklist layer (Priority 2 DROP)
  - [ ] IP counts per layer
  - [ ] Kernel sync status per layer
  - [ ] Color-coded action badges (ACCEPT=green, DROP=red)
- [ ] **Customer Rules Display:**
  - [ ] Collapsible section
  - [ ] Read-only native firewall rules
  - [ ] Excludes Battle-Hardened AI rules
  - [ ] Shows iptables/firewalld raw output
- [ ] **Test Results Modal:**
  - [ ] Step 1: Add test IP (show success/failure)
  - [ ] Step 2: Verify in kernel firewall (show success/failure)
  - [ ] Step 3: Remove test IP (show success/failure)
  - [ ] Overall pass/fail indicator
  - [ ] Detailed error messages for failures
- [ ] **Auto-Refresh:**
  - [ ] 30-second interval when tab is active
  - [ ] Only refreshes if tab is visible (prevents unnecessary API calls)

**Firewall Backend Support:**
- [ ] **iptables-nft (Debian/Ubuntu):**
  - [ ] ipset creation (bh_whitelist, bh_blocked)
  - [ ] iptables rule insertion (Priority 1/2)
  - [ ] netfilter-persistent save
  - [ ] Stats collection (Number of entries parsing)
- [ ] **firewalld (RHEL/Rocky/Alma/SUSE):**
  - [ ] ipset creation via firewall-cmd
  - [ ] rich-rule creation (ipset-based ACCEPT/DROP)
  - [ ] Permanent rule save
  - [ ] Stats collection via firewall-cmd --info-ipset
- [ ] **VyOS (Partial Support):**
  - [ ] address-group creation
  - [ ] firewall rule creation
  - [ ] Basic sync (no advanced stats)
- [ ] **OpenWRT (Partial Support):**
  - [ ] UCI ipset configuration
  - [ ] /etc/config/firewall rule creation
  - [ ] uci commit + firewall reload
- [ ] **Alpine Linux (Partial Support):**
  - [ ] awall JSON config generation
  - [ ] awall rule application
  - [ ] Basic sync (no advanced stats)

**Safety Guarantees:**
- [ ] Whitelist wins conflicts (IP in both lists = ACCEPTED)
- [ ] Safety check in sync daemon (removes whitelisted IPs from blocklist before syncing)
- [ ] Non-destructive testing (preserves production blocklist)
- [ ] Startup script creates dual-layer ipsets + rules
- [ ] Uninstall script removes both layers cleanly

**Systemd Service:**
- [ ] `battle-hardened-ai-firewall-sync.service` created
- [ ] Runs `server/installation/bh_firewall_sync.py`
- [ ] 5-second sync loop
- [ ] Auto-restart on failure
- [ ] Logs to journalctl

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
- [ ] `server/network_monitor.py` ⚠️ **CRITICAL**

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
- [ ] `killswitch_state.json` - Emergency killswitch status
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
- [ ] `enterprise_integration.json` - Syslog/webhook targets ⚠️ **PLANNED** - Use threat_log.json/blocked_ips.json manually until implemented
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

---

## ✅ DASHBOARD FEATURES TO VERIFY (LINUX DEPLOYMENT)

**All 24 sections above must load and function correctly on Debian/Ubuntu installations.**

## ✅ CRITICAL HIDDENIMPORTS (FOR .DEB PYTHON VENV)

When setting up the Python venv in `postinst`, ensure all required modules are installed via `requirements.txt`:

### Server-Level Modules (5 modules)
- [ ] `device_scanner` ⚠️ **CRITICAL** for Section 2
- [ ] `device_blocker` for Section 2
- [ ] `network_monitor` ⚠️ **CRITICAL** for Sections 17, 22
- [ ] `report_generator`
- [ ] `debug_server` (may be excluded on Linux as it's Windows-focused)

### AI-Level Modules (55 modules - all under `AI/` directory)
- [ ] `AI.adaptive_honeypot` (Section 15)
- [ ] `AI.advanced_orchestration`
- [ ] `AI.advanced_visualization`
- [ ] `AI.alert_system` (Section 21)
- [ ] `AI.asset_inventory`
- [ ] `AI.backup_recovery` (Section 24)
- [ ] `AI.behavioral_heuristics` (Section 24)
- [ ] `AI.byzantine_federated_learning`
- [ ] `AI.causal_inference` (Section 13)
- [ ] `AI.central_sync`
- [ ] `AI.cloud_security` (Section 24)
- [ ] `AI.compliance_reporting` (Section 12)
- [ ] `AI.crypto_security` (Section 22)
- [ ] `AI.cryptographic_lineage` (Section 12)
- [ ] `AI.deterministic_evaluation`
- [ ] `AI.dns_analyzer` (Section 18)
- [ ] `AI.drift_detector` (Section 4)
- [ ] `AI.emergency_killswitch` (Section 23)
- [ ] `AI.enterprise_integration` (Section 24)
- [ ] `AI.explainability_engine` (Section 14)
- [ ] `AI.false_positive_filter` (Section 14)
- [ ] `AI.file_analyzer` (Section 20)
- [ ] `AI.file_rotation`
- [ ] `AI.formal_threat_model`
- [ ] `AI.graph_intelligence` (Section 13)
- [ ] `AI.kernel_telemetry` (Section 11)
- [ ] `AI.meta_decision_engine` (Section 4)
- [ ] `AI.model_signing` ⚠️ **CRITICAL** for Architecture Enhancement #1 (MITRE T1574.012)
- [ ] `AI.model_performance_monitor` ⚠️ **CRITICAL** for Architecture Enhancement #3 (MITRE T1565.001)
- [ ] `AI.network_performance` (Section 11)
- [ ] `AI.node_fingerprint`
- [ ] `AI.onnx_model_converter` - Architecture Enhancement #5 (relay-side conversion)
- [ ] `AI.p2p_sync` ⚠️ **CRITICAL** for Section 1
- [ ] `AI.path_helper`
- [ ] `AI.pattern_filter` ⚠️ **CRITICAL** for Architecture Enhancement #2 (70-80% bandwidth savings)
- [ ] `AI.pcap_capture` (Section 17)
- [ ] `AI.pcs_ai` ⚠️ **CRITICAL** for Sections 4-9
- [ ] `AI.policy_governance` (Section 23)
- [ ] `AI.real_honeypot` (Section 15)
- [ ] `AI.relay_client` ⚠️ **CRITICAL** for Section 1
- [ ] `AI.reputation_tracker` (Section 7)
- [ ] `AI.secure_deployment` (Section 23)
- [ ] `AI.self_protection` (Section 23)
- [ ] `AI.sequence_analyzer` (Sections 6, 10)
- [ ] `AI.signature_distribution` (Section 16)
- [ ] `AI.signature_extractor` (Section 10)
- [ ] `AI.signature_uploader`
- [ ] `AI.soar_api` (Section 24)
- [ ] `AI.soar_workflows`
- [ ] `AI.step21_gate` (Section 4)
- [ ] `AI.step21_policy` (Section 4)
- [ ] `AI.step21_semantic_gate` (Section 4)
- [ ] `AI.system_log_collector`
- [ ] `AI.threat_intelligence` (Section 16)
- [ ] `AI.tls_fingerprint` (Sections 3, 17)
- [ ] `AI.traffic_analyzer` ⚠️ **CRITICAL** for Sections 3, 17, 22
- [ ] `AI.training_sync_client`
- [ ] `AI.trust_graph` (Section 13)
- [ ] `AI.user_tracker` (Section 19)
- [ ] `AI.vulnerability_manager` (Section 24)
- [ ] `AI.zero_trust` (Sections 19, 24)

### Third-Party Dependencies (from `server/requirements.txt`)
- [ ] `flask` - Web framework
- [ ] `flask-cors==4.0.0` ⚠️ **CRITICAL** for API CORS
- [ ] `websockets` ⚠️ **CRITICAL** for Section 1 (P2P/Relay)
- [ ] `scapy` - Packet capture
- [ ] `cryptography` - Encryption and SSL
- [ ] `scikit-learn` - ML models
- [ ] `numpy`, `pandas` - Data processing
- [ ] `joblib` - Model serialization
- [ ] `psutil` - System monitoring
- [ ] `requests` - HTTP client
- [ ] `gunicorn` - Production WSGI server (Linux only)
- [ ] `onnxruntime` ⚠️ **CRITICAL** for Architecture Enhancement #5 (2-5x faster CPU inference)
- [ ] `skl2onnx` - Architecture Enhancement #5 (relay-side ONNX conversion)
- [ ] `onnx` - ONNX model format support

---

## ✅ API ENDPOINTS TO VERIFY (ORGANIZED BY SECTION)

### Section 1: AI Training Network
- [ ] `/api/p2p/status`
- [ ] `/api/relay/status`
- [ ] `/api/p2p/add-peer`

### Section 2: Network Devices
- [ ] `/api/connected-devices`
- [ ] `/api/device-history`
- [ ] `/api/scan-devices`
- [ ] `/api/device/block`
- [ ] `/api/device/unblock`

### Section 3: VPN/Tor De-Anonymization
- [ ] `/api/traffic/analysis`

### Sections 4-9: AI/ML & Security Overview
- [ ] `/api/stats`
- [ ] `/api/threat_log`
- [ ] `/api/threat/block-ip`
- [ ] `/api/whitelist/add`
- [ ] `/api/whitelist/remove`
- [ ] `/api/failed-logins`

### Section 10: Signature Extraction
- [ ] `/api/signature-extraction/stats`
- [ ] `/api/signatures/extracted`

### Section 11: System Health
- [ ] `/api/system-health/stats`
- [ ] `/api/system-status`
- [ ] `/api/performance/metrics`

### Section 12: Audit & Compliance
- [ ] `/api/compliance/summary`

### Section 13: Attack Chain Visualization
- [ ] `/api/graph-intelligence/stats`
- [ ] `/api/visualization/topology`

### Section 14: Decision Explainability
- [ ] `/api/explainability/stats`

### Section 15: Adaptive Honeypot
- [ ] `/api/adaptive_honeypot/status`
- [ ] `/api/adaptive_honeypot/personas`
- [ ] `/api/adaptive_honeypot/configure`
- [ ] `/api/adaptive_honeypot/stop`
- [ ] `/api/adaptive_honeypot/attacks`
- [ ] `/api/adaptive_honeypot/attacks/history`

### Section 16: Threat Crawlers
- [ ] `/api/threat-crawlers/stats`

### Section 17: Traffic Analysis
- [ ] `/api/traffic/analysis`

### Section 18: DNS & Geo Security
- [ ] `/api/dns/stats`

### Section 19: User & Identity
- [ ] `/api/users/tracking`
- [ ] `/api/zero-trust/scores`

### Section 20: Sandbox Detonation
- [ ] `/api/sandbox/stats`
- [ ] `/api/sandbox/detonate`

### Section 21: Email/SMS Alerts
- [ ] `/api/alerts/stats`
- [ ] `/api/alerts/email/config`
- [ ] `/api/alerts/sms/config`

### Section 22: Crypto Mining Detection
- [ ] `/api/traffic/crypto-mining`

### Section 23: Governance & Emergency
- [ ] `/api/governance/pending-approvals`
- [ ] `/api/governance/stats`
- [ ] `/api/killswitch/status`
- [ ] `/api/audit-log/clear`
- [ ] `/api/self-protection/stats`

### Section 24: Enterprise Integrations
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

### System & Utility APIs
- [ ] `/api/openapi.json` - OpenAPI specification
- [ ] `/api/docs` - API documentation
- [ ] `/api/soar/stats` - SOAR orchestration
- [ ] All endpoints return JSON or appropriate auth errors (not 404/500).

## ✅ POST-BUILD VERIFICATION (DEBIAN/UBUNTU VIA DOCKER)

Canonical dev test environment is a clean Debian/Ubuntu Docker container:

### Basic Installation & Service Test
1. [ ] Start a container (example): `docker run --rm -it -v "$PWD":/src -w /src debian:12-slim bash`.
2. [ ] Inside the container, install build/runtime deps (`apt-get update && apt-get install -y systemd systemd-sysv iptables ipset curl python3 python3-venv` as needed).
3. [ ] Install package with `dpkg -i battle-hardened-ai_*.deb` (from `/src`).
4. [ ] Run `systemctl status battle-hardened-ai` – service is active (or clearly fails with useful logs). Note: running full systemd in Docker may require `--privileged` or a tuned base image; adjust per your Docker baseline.
5. [ ] Confirm logs are written under `/var/log/battle-hardened-ai/` inside the container.
6. [ ] Confirm JSON state and ML models are in the expected `/var/lib/battle-hardened-ai/` locations.
7. [ ] Verify dashboard loads from the container at `https://<container-ip>:60000` (or `http://` if TLS terminated externally) as per Installation.md.

### Section-by-Section Verification (24 Sections)

**Section 1 - AI Training Network:**
- [ ] `/api/p2p/status` returns JSON (not 500)
- [ ] `/api/relay/status` returns JSON (not 500)
- [ ] Section displays P2P/Relay status without "Loading..." stuck

**Section 2 - Network Devices:**
- [ ] `/api/connected-devices` returns JSON array
- [ ] `/api/scan-devices` triggers device scan
- [ ] Device table populates or shows empty state
- [ ] `device_scanner.py` module loads without ImportError

**Section 3 - VPN/Tor De-Anonymization:**
- [ ] `/api/traffic/analysis` returns traffic data with VPN/Tor detection

**Section 4 - AI/ML Models:**
- [ ] `/api/stats` returns ML model metrics
- [ ] ML models load from `/var/lib/battle-hardened-ai/AI/ml_models/`
- [ ] Model accuracy, FPR, training samples display

**Section 5 - Security Overview:**
- [ ] `/api/stats` returns security statistics
- [ ] `/api/threat_log` returns threat array
- [ ] Total threats, blocked IPs, whitelisted IPs display

**Section 6 - Threat Analysis by Type:**
- [ ] Attack type breakdown displays (SQL, XSS, brute force, etc.)
- [ ] Attack counts update correctly

**Section 7 - IP Management:**
- [ ] `/api/threat/block-ip` blocks IP correctly
- [ ] `/api/whitelist/add` adds IP to whitelist
- [ ] Threat log table populates

**Section 8 - Failed Logins:**
- [ ] `/api/failed-logins` returns failed login attempts
- [ ] Failed login count displays

**Section 9 - Attack Type Breakdown (View):**
- [ ] Attack pie chart/graph displays
- [ ] Attack type distribution correct

**Section 10 - Signature Extraction:**
- [ ] `/api/signature-extraction/stats` returns extraction metrics
- [ ] Signatures extracted count displays

**Section 11 - System Health:**
- [ ] `/api/system-health/stats` returns CPU/memory/disk metrics
- [ ] `/api/system-status` returns uptime
- [ ] Health status displays (healthy/degraded/critical)

**Section 12 - Audit & Compliance:**
- [ ] `/api/compliance/summary` returns compliance framework coverage
- [ ] SBOM file exists at `/var/lib/battle-hardened-ai/server/json/sbom.json`
- [ ] Compliance score displays

**Section 13 - Attack Chain Visualization:**
- [ ] `/api/graph-intelligence/stats` returns graph metrics
- [ ] Attack chains display
- [ ] Lateral movement alerts display

**Section 14 - Decision Explainability:**
- [ ] `/api/explainability/stats` returns decision metrics
- [ ] Decisions made/explained counts display

**Section 15 - Adaptive Honeypot:**
- [ ] `/api/adaptive_honeypot/status` returns honeypot status
- [ ] `/api/adaptive_honeypot/attacks` returns attack feed
- [ ] 8 service personas display (SSH, FTP, HTTP, HTTPS, Telnet, MySQL, RDP, SMB)
- [ ] Attacks captured count displays

**Section 16 - Threat Crawlers:**
- [ ] `/api/threat-crawlers/stats` returns crawler metrics
- [ ] 10 threat intel sources show status
- [ ] Threats discovered count displays

**Section 17 - Traffic Analysis:**
- [ ] `/api/traffic/analysis` returns DPI results
- [ ] Packets analyzed count displays
- [ ] Encrypted traffic % displays

**Section 18 - DNS & Geo Security:**
- [ ] `/api/dns/stats` returns DNS threat metrics
- [ ] DNS tunneling attempts display
- [ ] DGA domains detected count displays

**Section 19 - User & Identity:**
- [ ] `/api/users/tracking` returns user tracking data
- [ ] `/api/zero-trust/scores` returns trust scores
- [ ] Users tracked count displays

**Section 20 - Sandbox Detonation:**
- [ ] `/api/sandbox/stats` returns sandbox metrics
- [ ] File upload form works
- [ ] Files analyzed count displays

**Section 21 - Email/SMS Alerts:**
- [ ] `/api/alerts/stats` returns alert metrics
- [ ] Email/SMS config forms display
- [ ] Alerts sent counts display

**Section 22 - Crypto Mining Detection:**
- [ ] `/api/traffic/crypto-mining` returns mining detection data
- [ ] Miner processes detected count displays
- [ ] High CPU processes list displays

**Section 23 - Governance & Emergency:**
- [ ] `/api/governance/stats` returns governance metrics
- [ ] `/api/killswitch/status` returns killswitch status
- [ ] Pending approvals display
- [ ] Emergency killswitch control displays

**Section 24 - Enterprise Integrations:**
- [ ] `/api/enterprise-integration/config` returns integration config
- [ ] `/api/backup/status` returns backup status
- [ ] `/api/cloud/posture` returns cloud security findings
- [ ] All enterprise integration playcards display

### Attack Tests & Detection Validation
8. [ ] Run at least one test from `KALI_ATTACK_TESTS.md` (adapted for container networking) to ensure detection, blocking, and logging work end-to-end.
9. [ ] Confirm Step 21 semantic gate loads and blocks a policy-violating HTTP request (as described in README.md).
10. [ ] Verify relay connectivity (if enabled in `.env`) does not block core operation when disabled.

### Cleanup & Removal Test
11. [ ] Check that removing the package with `apt remove battle-hardened-ai` stops the service and leaves operator data (JSON/logs) in a sensible state (documented behavior).

### Browser Console Tests (Optional JavaScript API Validation)
```javascript
// Test Section 1
fetch('/api/p2p/status').then(r => r.json()).then(console.log)
fetch('/api/relay/status').then(r => r.json()).then(console.log)

// Test Section 2
fetch('/api/connected-devices').then(r => r.json()).then(console.log)

// Test Section 15
fetch('/api/adaptive_honeypot/status').then(r => r.json()).then(console.log)

// Test Section 22
fetch('/api/traffic/crypto-mining').then(r => r.json()).then(console.log)
```
All should return JSON objects, not 404/500 errors.

## ✅ MODES / PROFILES (GATEWAY VS HOST)

- [x] Decide whether the `.deb` supports multiple modes or only gateway mode:
  - [x] **Gateway mode (default):** Primary and only officially supported profile for the `.deb`, with full network monitoring, firewall sync, and honeypot ports (documented in README/Installation.md).
  - [x] **Host-only mode (optional):** Not provided as a separate profile in the initial `.deb`; operators who want a single-host deployment can still install the package on a host and tune `.env` (for example, disabling firewall sync), but this is treated as an advanced configuration.
- [x] Ensure mode selection does not silently disable critical JSON surfaces or Step 21 gate behavior; since there is a single gateway-focused profile, all JSON surfaces and Step 21 behavior remain enabled by default.

## ✅ EXCLUSIONS / NON-GOALS FOR .DEB

- [x] ❌ Do not ship the `relay/` folder at all (relay remains a separate component, not part of the gateway `.deb`) – `packaging/debian/rules` only installs `AI/`, `server/`, `policies/`, and `assets/`.
- [x] ❌ Do not include `__pycache__/`, `.git/`, `.venv/`, `build/`, or `dist` directories.
- [x] ❌ Do not include Windows-only artifacts from `server/`:
  - [x] `server/debug_server.py` (no such file is present; Windows helpers live under `packaging/windows/` and are not installed).
- [x] ❌ Do not include Windows packaging or tooling:
  - [x] `packaging/windows/` (not referenced in `rules`).
  - [x] Any `.ps1` / `.bat` scripts that are only for Windows EXE or Windows firewall setup (all outside the installed directories).
- [x] ❌ Do not include Docker-only dev artifacts in the `.deb` payload (they may remain in the source repo but are not installed on target systems):
  - [x] Root-level `docker-compose.yml`, any `Dockerfile`/`docker-compose.yml` under `server` or `relay`, and `.dockerignore` (none of these are under the copied install paths, or they are intentionally omitted).
- [x] ❌ Do not hard-code environment-specific secrets; expect operators to configure via `.env` or environment variables (no secrets baked into the Debian layout).

## ✅ BUILD COMMAND (DEVELOPMENT)

Document the canonical developer build flow for `.deb` (for use on a Debian/Ubuntu build host with `debhelper`, `devscripts`, and `dpkg-dev` installed):

- [x] Ensure Debian maintainer scripts are executable (e.g. `chmod +x packaging/debian/battle-hardened-ai.*`).
- [x] From repo root: `cd packaging/debian`.
- [x] Run `dpkg-buildpackage -us -uc` (or `debuild`) with the correct environment.
- [x] Confirm the output `battle-hardened-ai_*.deb` lands in the parent directory.

## ✅ KNOWN ISSUES / OPEN QUESTIONS

Track early Debian/RPM mistakes here to avoid repeating the "100 tries" EXE experience:

- [ ] Paths where Linux layout diverges from Windows EXE (especially crypto keys and JSON directory).
- [ ] Any missing runtime dependency discovered only after deployment (add to `Depends:` in `control`).
- [ ] Any systemd behavior differences across Debian/Ubuntu releases (e.g. `systemctl` vs `service` fallbacks).
- [x] Decision on whether the package is **gateway-only** or also supports host-only mode on Linux, and how that is exposed in docs and defaults (resolved as a gateway-focused `.deb`, with host-only behavior treated as advanced tuning via `.env`).
