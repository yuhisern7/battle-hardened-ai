# Debian Package Checklist - Battle-Hardened AI

> Goal: Ship a reproducible `.deb` package for Debian/Ubuntu gateways and hosts that matches the architecture and behavior documented in README.md and Installation.md, with clean systemd integration and no surprises for operators.

## ✅ SCOPE & TARGETS

- [ ] Target distros and versions defined (e.g. Debian 12, Ubuntu 22.04).
- [ ] Architecture targets defined (e.g. `amd64` first, arm64 later).
- [ ] Package name/version decided (e.g. `battle-hardened-ai` 1.x.y matching git tag).
- [ ] Single-node gateway profile is the primary supported mode (matches README and Installation.md).

## ✅ FILESYSTEM LAYOUT (LINUX STANDARD)

Decide and **keep consistent** between `.deb` and `.rpm`:

- [ ] Application code under `/opt/battle-hardened-ai` (or `/usr/lib/battle-hardened-ai`) – chosen and documented.
- [ ] Configuration / JSON state under `/var/lib/battle-hardened-ai/json` (symlink or path used consistently in `AI/path_helper.py`).
- [ ] Logs under `/var/log/battle-hardened-ai`.
- [ ] PCAP capture directory under `/var/lib/battle-hardened-ai/pcap` (or similar), aligned with `server/pcap/` expectations.
- [ ] Crypto keys under `/var/lib/battle-hardened-ai/crypto_keys` (or `/etc/battle-hardened-ai/crypto_keys`), matching what `server/crypto_keys/` does today.
- [ ] Systemd unit(s) installed to `/lib/systemd/system/`.
- [ ] Ownership and permissions defined (e.g. `bhai:bhai` service user, no root-only JSON unless required).

## ✅ CORE PYTHON MODULES (MATCH WINDOWS EXE CONTENT)

Ensure the same logical code is present for Linux packages as for the EXE build (no hidden omissions):

- [ ] All 55+ Python modules from `AI/` installed as source (or part of the Python environment) on the target.
- [ ] `AI/__init__.py` present so package imports work.
- [ ] 21-layer detection modules present:
  - [ ] `AI/step21_gate.py`
  - [ ] `AI/step21_policy.py`
  - [ ] `AI/step21_semantic_gate.py`
  - [ ] Behavioral, traffic, DNS, TLS, file, sequence, causal, graph, kernel, network performance, PCAP, honeypot, threat intel, reputation, trust graph, FP filter, drift detector modules (same list as in Exe-checklist.md).

- [ ] Server-side modules present:
  - [ ] `server/server.py` (main Flask/API server)
  - [ ] `server/network_monitor.py` / `server/device_scanner.py` / `server/device_blocker.py` as applicable
  - [ ] `server/installation/*` (gunicorn configs, init_json_files.py) as needed for Linux
  - [ ] Any helper scripts referenced by docs (e.g. JSON init, report generator) are included or explicitly documented as dev-only.

## ✅ DATA & STATE FILES (JSON, ML, POLICIES)

### JSON Files (from `server/json/`)

- [ ] All JSON surfaces required by the dashboard and APIs are installed **or** auto-created on first run by init scripts.
- [ ] For files that must exist at install time (to avoid 500s), ensure they are shipped in the package or created by `postinst` or an init script.
- [ ] Key JSON files are present/handled:
  - [ ] `admin_users.json`
  - [ ] `attack_sequences.json`
  - [ ] `behavioral_metrics.json`
  - [ ] `blocked_devices.json`
  - [ ] `blocked_ips.json`
  - [ ] `causal_analysis.json`
  - [ ] `comprehensive_audit.json`
  - [ ] `crypto_mining.json`
  - [ ] `dns_security.json`
  - [ ] `drift_baseline.json`
  - [ ] `enterprise_integration.json`
  - [ ] `governance_policies.json`
  - [ ] `honeypot_attacks.json`
  - [ ] `honeypot_patterns.json`
  - [ ] `local_threat_intel.json`
  - [ ] `meta_engine_config.json`
  - [ ] `ml_performance_metrics.json`
  - [ ] `model_lineage.json`
  - [ ] `network_graph.json`
  - [ ] `network_performance.json`
  - [ ] `reputation_export.json`
  - [ ] `sample_threats.json`
  - [ ] `sbom.json`
  - [ ] `secure_deployment.json`
  - [ ] `sla_policy.json`
  - [ ] `soar_incidents.json`
  - [ ] `support_tickets.json`
  - [ ] `threat_log.json`
  - [ ] `tls_fingerprints.json`
  - [ ] `trust_graph.json`
  - [ ] `whitelist.json`

(Exact list should be reconciled with `server/json/` and Filepurpose.md.)

### ML Models (`AI/ml_models/`)

- [ ] `anomaly_detector.pkl`
- [ ] `feature_scaler.pkl`
- [ ] `ip_reputation.pkl`
- [ ] `node_fingerprint.json`
- [ ] `signature_cache/` directory (if used in Linux deployments)

### Crypto Keys (`server/crypto_keys/` → runtime location)

- [ ] Ensure build-time keys from `server/crypto_keys/` are either:
  - Shipped into a secure location (for lab/demo), **or**
  - Generated/overridden on first run by an init script on real deployments.
- [ ] TLS cert/key paths in Linux match the defaults in `.env` / README.

### Step 21 Policies (`policies/step21/`)

- [ ] `manifest.json`
- [ ] `manifest.sig`
- [ ] `policy.json`
- [ ] `schema.json`
- [ ] Installed to a stable path (e.g. `/opt/battle-hardened-ai/policies/step21`) referenced correctly by `AI/step21_policy.py`.

## ✅ UI / DASHBOARD FILES (LINUX)

- [ ] HTML dashboard files copied to the path the server expects:
  - [ ] `AI/inspector_ai_monitoring.html` (or server templates if moved)
  - [ ] `AI/docs_portal.html`
  - [ ] `AI/docs_viewer.html`
  - [ ] `AI/swagger_ui.html`
- [ ] If `server/templates/` or `server/static/` exist, include all `.html`, `.css`, `.js`, and assets needed for the dashboard.

## ✅ CONFIGURATION & ENVIRONMENT

- [ ] Linux `.env` file (`server/.env`) is **not** blindly overwritten on upgrade; default values go to `/etc/battle-hardened-ai/.env` or similar template.
- [ ] Package either:
  - Ships a default `/etc/battle-hardened-ai/.env` and documents editing it, **or**
  - Expects environment variables to be provided by systemd unit `EnvironmentFile=` directive.
- [ ] JSON directory and ML model directory resolution in `AI/path_helper.py` are compatible with the chosen filesystem layout.

### Python Runtime Strategy (PLAN BEFORE BUILD)

- [ ] Decide Python runtime model for Debian:
  - [ ] Use system `python3` with a dedicated virtualenv under `/opt/battle-hardened-ai/venv` (recommended), **or**
  - [ ] Depend solely on system `python3` + `pip` packages (no venv).
- [ ] For the chosen model, document clearly in Installation.md:
  - [ ] Minimum supported Python version (e.g. 3.10/3.11, TensorFlow optional as in `server/requirements.txt`).
  - [ ] Which dependencies are installed via `apt` vs `pip` (e.g. `python3-scapy` vs `scapy` from pip).
- [ ] Ensure `gunicorn` (Linux-only) is available where systemd `ExecStart` expects it: either in the venv or system-wide.
- [ ] Confirm that sequence/deep-learning features gracefully degrade if TensorFlow is not installed (as documented in requirements).

### Service User & Permissions (PLAN BEFORE BUILD)

- [ ] Choose a dedicated service account (e.g. `bhai`) with:
  - [ ] No interactive login shell and no home directory (system account) or a minimal home.
  - [ ] Group ownership aligned with log and data directories.
- [ ] Define ownership model:
  - [ ] `/opt/battle-hardened-ai/**` owned by `root:root`, mode `755` (read-only code).
  - [ ] `/var/lib/battle-hardened-ai/**` owned by `bhai:bhai`, mode `750` (JSON, models, keys).
  - [ ] `/var/log/battle-hardened-ai/**` owned by `bhai:bhai`, mode `750`.
  - [ ] `/etc/battle-hardened-ai/**` owned by `root:bhai`, mode `640` (config readable by service, writable by root).
- [ ] Decide on `umask` for the service (e.g. 007 as in gunicorn_config) to prevent world-readable files.

## ✅ SYSTEMD INTEGRATION

- [ ] `packaging/systemd/battle-hardened-ai.service` created with:
  - [ ] `ExecStart` finalized (PLAN):
    - [ ] Prefer Gunicorn as per `server/installation/watchdog.py` for Linux:
      - [ ] Example: `ExecStart=/opt/battle-hardened-ai/venv/bin/gunicorn --config /opt/battle-hardened-ai/server/installation/gunicorn_config.py server:app`
    - [ ] Alternatively, use watchdog if we decide to keep the Python-managed restart loop under systemd:
      - [ ] Example: `ExecStart=/opt/battle-hardened-ai/venv/bin/python /opt/battle-hardened-ai/server/installation/watchdog.py`.
  - [ ] `WorkingDirectory` set to `/opt/battle-hardened-ai/server` (so relative paths in `server.py` and gunicorn_config work).
  - [ ] `User`/`Group` set to the dedicated service account (e.g. `bhai`).
  - [ ] `Restart=on-failure` (or `always` if we rely solely on systemd for restarts instead of watchdog).
  - [ ] `EnvironmentFile=/etc/battle-hardened-ai/.env` (or equivalent) referenced explicitly.
  - [ ] `Environment=BATTLE_HARDENED_DATA_DIR=/var/lib/battle-hardened-ai BATTLE_HARDENED_PROJECT_ROOT=/opt/battle-hardened-ai` so `AI/path_helper` and gunicorn_config resolve correctly.
  - [ ] Resource and security options planned:
    - [ ] `LimitNOFILE` (e.g. 65535) and `MemoryMax` in line with KALI tests.
    - [ ] `CapabilityBoundingSet`/`AmbientCapabilities` set if kernel telemetry or firewall sync requires NET_ADMIN, etc.
- [ ] Debian package installs this unit to `/lib/systemd/system/battle-hardened-ai.service`.
- [ ] `postinst` (or debhelper) calls:
  - [ ] `systemctl daemon-reload`
  - [ ] `systemctl enable --now battle-hardened-ai`
- [ ] `prerm`/`postrm` handle stop/disable cleanly.

## ✅ DEBIAN PACKAGING FILES (`packaging/debian/`)

- [ ] `control`
  - [ ] Package metadata (name, version, maintainer, description) filled in.
  - [ ] Dependencies listed: `python3`, `python3-venv` or equivalent, `systemd`, `iptables`, `ipset`, `curl`/`wget` if required, any others from `server/requirements.txt` that must be OS packages.
- [ ] `rules`
  - [ ] Uses `dh` (debhelper) for a simple build.
  - [ ] Installs files to the chosen filesystem layout.
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
- [ ] Optional maintainer scripts:
  - [ ] `postinst` for first-time JSON/dir initialization (or call into existing `server/installation/init_json_files.py`).
  - [ ] `prerm`/`postrm` for cleanup.

### Postinst / Upgrade / Removal Behavior (PLAN BEFORE BUILD)

- [ ] `postinst` responsibilities clearly defined and implemented:
  - [ ] Create `/var/lib/battle-hardened-ai/**` and `/var/log/battle-hardened-ai/**` with correct ownership and modes.
  - [ ] Copy or generate initial JSON templates from `/opt/battle-hardened-ai/server/json/` into `/var/lib/battle-hardened-ai/server/json/` **only on first install**, not on upgrade.
  - [ ] Generate crypto keys in `/var/lib/battle-hardened-ai/server/crypto_keys/` if none exist (lab/demo keys may still exist under `/opt/...` for reference only).
  - [ ] Seed SBOM or integrity baselines if required by self_protection.
  - [ ] Reload systemd and enable/start the service.
- [ ] Upgrade behavior:
  - [ ] Preserve existing JSON and logs; never overwrite `/var/lib/battle-hardened-ai/**` by default.
  - [ ] Handle JSON schema changes via migration scripts if keys/structures change.
- [ ] Removal behavior:
  - [ ] `apt remove` stops/ disables the service but leaves `/var/lib` and `/var/log` intact (documented).
  - [ ] `apt purge` optionally removes data directories (confirm and document behavior).

## ✅ FIREWALL INTEGRATION (LINUX)

- [ ] Package either:
  - [ ] Ships helper scripts to sync `blocked_ips.json` into ipset/iptables (Linux equivalent of Windows firewall script), **and/or**
  - [ ] Documents how to wire existing firewall automation to `blocked_ips.json`.
- [ ] Ensure any Linux-only firewall scripts or config are included under a stable path (`/opt/battle-hardened-ai/tools/` or similar).

### Firewall Sync Helper (PLAN BEFORE BUILD)

- [ ] Align `server/installation/bh_firewall_sync.py` (currently using `JSON_PATH="/app/json/blocked_ips.json"`) with Debian layout:
  - [ ] Modify or parameterize JSON path so it reads from `get_blocked_ips_file()` / `/var/lib/battle-hardened-ai/server/json/blocked_ips.json` instead of `/app/json`.
  - [ ] Install script to a stable location (e.g. `/opt/battle-hardened-ai/server/installation/bh_firewall_sync.py`).
- [ ] Decide how the helper is started:
  - [ ] Via a separate systemd unit/timer (e.g. `battle-hardened-ai-firewall-sync.service`), **or**
  - [ ] Via the main service using `BH_FIREWALL_SYNC_ENABLED` env var (Docker-style) if that model is preserved.
- [ ] Document required capabilities (NET_ADMIN, ipset/iptables availability) for Linux hosts.

## ✅ RUNTIME DIRECTORIES & PERMISSIONS

On install (or first start), ensure the following exist with correct ownership and permissions:

- [ ] `/var/lib/battle-hardened-ai/json/` (state + JSON surfaces)
- [ ] `/var/lib/battle-hardened-ai/pcap/`
- [ ] `/var/lib/battle-hardened-ai/crypto_keys/`
- [ ] `/var/log/battle-hardened-ai/`
- [ ] Permissions allow the service user to read/write, but are not world-readable for sensitive content.

### Logging & Rotation (PLAN BEFORE BUILD)

- [ ] Decide logging strategy:
  - [ ] Rely primarily on systemd-journald (Gunicorn logs to stdout/stderr as configured in `gunicorn_config.py`), **and**
  - [ ] Optionally have the app write structured logs under `/var/log/battle-hardened-ai/`.
- [ ] If file logs are used, create a `logrotate` config snippet so logs do not grow without bounds.
- [ ] Ensure log files never contain sensitive secrets or full payloads beyond what README promises.

## ✅ DASHBOARD FEATURES TO VERIFY (LINUX DEPLOYMENT)

Verify the same UX expectations as the EXE, but from a Debian/Ubuntu install:

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
17. [ ] Cloud security findings (as implemented today)
18. [ ] Drift detection reports
19. [ ] Audit logs
20. [ ] ML performance metrics

## ✅ API ENDPOINTS TO VERIFY (FROM .DEB INSTALL)

- [ ] `/api/stats`
- [ ] `/api/threat_log`
- [ ] `/api/connected-devices`
- [ ] `/api/traffic/analysis`
- [ ] `/api/dns/stats`
- [ ] `/api/adaptive_honeypot/status`
- [ ] `/api/signatures/extracted`
- [ ] `/api/system-status`
- [ ] `/api/compliance/summary`
- [ ] `/api/governance/stats`
- [ ] `/api/killswitch/status`
- [ ] `/api/alerts/stats`
- [ ] `/api/sandbox/stats`
- [ ] `/api/traffic/crypto-mining`
- [ ] `/api/enterprise-integration/config`
- [ ] Representative SOAR/documentation endpoints: `/api/soar/stats`, `/api/openapi.json`, `/api/docs`
- [ ] All other REST endpoints documented in `documentation/Dashboard.md` respond with 2xx or appropriate auth errors.

## ✅ POST-BUILD VERIFICATION (DEBIAN/UBUNTU)

On a clean Debian/Ubuntu VM or container:

1. [ ] Install package with `sudo dpkg -i battle-hardened-ai_*.deb`.
2. [ ] Run `sudo systemctl status battle-hardened-ai` – service is active (or clearly fails with useful logs).
3. [ ] Confirm logs are written under `/var/log/battle-hardened-ai/`.
4. [ ] Confirm JSON state and ML models are in the expected `/var/lib/battle-hardened-ai/` locations.
5. [ ] Verify dashboard loads at `https://<host>:60000` (or `http://` if TLS terminated externally) as per Installation.md.
6. [ ] Run at least one test from `KALI_ATTACK_TESTS.md` to ensure detection, blocking, and logging work end-to-end.
7. [ ] Confirm Step 21 semantic gate loads and blocks a policy-violating HTTP request (as described in README.md).
8. [ ] Verify relay connectivity (if enabled in `.env`) does not block core operation when disabled.
9. [ ] Check that removing the package with `sudo apt remove battle-hardened-ai` stops the service and leaves operator data (JSON/logs) in a sensible state (documented behavior).

## ✅ MODES / PROFILES (GATEWAY VS HOST)

- [ ] Decide whether the `.deb` supports multiple modes or only gateway mode:
  - [ ] **Gateway mode (default):** Full network monitoring, eBPF/XDP, firewall sync, honeypot ports (as described in README/Installation.md).
  - [ ] **Host-only mode (optional):** Reduced feature set for single-host deployments (no firewall sync, limited packet capture); if implemented, clearly document how to enable it (e.g. via `.env` flag or separate systemd unit template).
- [ ] Ensure mode selection does not silently disable critical JSON surfaces or Step 21 gate behavior; differences must be explicit in docs and UI.

## ✅ EXCLUSIONS / NON-GOALS FOR .DEB

- [ ] ❌ Do not ship the `relay/` folder at all (relay remains a separate component, not part of the gateway `.deb`).
- [ ] ❌ Do not include `__pycache__/`, `.git/`, `.venv/`, `build/`, or `dist/` directories.
- [ ] ❌ Do not include Windows-only artifacts from `server/`:
  - [ ] `server/debug_server.py` (dev helper only, not for production packages)
- [ ] ❌ Do not include Windows packaging or tooling:
  - [ ] `packaging/windows/`
  - [ ] Any `.ps1` / `.bat` scripts that are only for Windows EXE or Windows firewall setup.
- [ ] ❌ Do not include Docker-only dev artifacts in the `.deb` payload (they may remain in the source repo but are not installed on target systems):
  - [ ] Root-level `docker-compose.yml`, any `Dockerfile`/`docker-compose.yml` under `server/` or `relay/`, and `.dockerignore`.
- [ ] ❌ Do not hard-code environment-specific secrets; expect operators to configure via `.env` or environment variables.

## ✅ BUILD COMMAND (DEVELOPMENT)

Document the canonical developer build flow for `.deb`:

- [ ] From repo root: `cd packaging/debian` or appropriate root.
- [ ] Run `dpkg-buildpackage -us -uc` (or `debuild`) with the correct environment.
- [ ] Output `.deb` lands in parent directory; version and architecture are correct.

(Exact commands will be updated once the Debian packaging files are implemented and tested.)

## ✅ KNOWN ISSUES / OPEN QUESTIONS

Track early Debian/RPM mistakes here to avoid repeating the "100 tries" EXE experience:

- [ ] Paths where Linux layout diverges from Windows EXE (especially crypto keys and JSON directory).
- [ ] Any missing runtime dependency discovered only after deployment (add to `Depends:` in `control`).
- [ ] Any systemd behavior differences across Debian/Ubuntu releases (e.g. `systemctl` vs `service` fallbacks).
- [ ] Decision on whether the package is **gateway-only** or also supports host-only mode on Linux, and how that is exposed in docs and defaults.
