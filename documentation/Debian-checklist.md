# Debian Package Checklist - Battle-Hardened AI

> Goal: Ship a reproducible `.deb` package for Debian/Ubuntu gateways and hosts that matches the architecture and behavior documented in README.md and Installation.md, with clean systemd integration and no surprises for operators.

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
- [x] 21-layer detection modules present:
  - [x] `AI/step21_gate.py`
  - [x] `AI/step21_policy.py`
  - [x] `AI/step21_semantic_gate.py`
  - [x] Behavioral, traffic, DNS, TLS, file, sequence, causal, graph, kernel, network performance, PCAP, honeypot, threat intel, reputation, trust graph, FP filter, drift detector modules (same list as in Exe-checklist.md) included via the full `AI/` copy.

- [x] Server-side modules present:
  - [x] `server/server.py` (main Flask/API server).
  - [x] `server/network_monitor.py` / `server/device_scanner.py` / `server/device_blocker.py` as applicable.
  - [x] `server/installation/*` (Gunicorn configs, init_json_files.py, firewall sync helper) as needed for Linux.
  - [x] Any helper scripts referenced by docs are either included (under `/opt/battle-hardened-ai/server/`) or clearly documented as dev-only.

## ✅ DATA & STATE FILES (JSON, ML, POLICIES)

### JSON Files (from `server/json/`)

- [x] All JSON surfaces required by the dashboard and APIs are installed **or** auto-created on first run by init scripts (`postinst` copies templates to `/var/lib/battle-hardened-ai/server/json/` on first install, and `init_json_files.py` remains available).
- [x] For files that must exist at install time (to avoid 500s), ensure they are shipped in the package or created by `postinst` or an init script (templates under `/opt/battle-hardened-ai/server/json/` plus `postinst` seeding cover this).
- [x] Key JSON files are present/handled (either as templates under `server/json/` copied by `postinst`, or created on demand by `installation/init_json_files.py`):
  - [x] `admin_users.json`
  - [x] `attack_sequences.json`
  - [x] `behavioral_metrics.json`
  - [x] `blocked_devices.json`
  - [x] `blocked_ips.json`
  - [x] `causal_analysis.json`
  - [x] `comprehensive_audit.json`
  - [x] `crypto_mining.json`
  - [x] `dns_security.json`
  - [x] `drift_baseline.json`
  - [x] `enterprise_integration.json`
  - [x] `governance_policies.json`
  - [x] `honeypot_attacks.json`
  - [x] `honeypot_patterns.json`
  - [x] `local_threat_intel.json`
  - [x] `meta_engine_config.json`
  - [x] `ml_performance_metrics.json`
  - [x] `model_lineage.json`
  - [x] `network_graph.json`
  - [x] `network_performance.json`
  - [x] `reputation_export.json`
  - [x] `sample_threats.json`
  - [x] `sbom.json`
  - [x] `secure_deployment.json`
  - [x] `sla_policy.json`
  - [x] `soar_incidents.json`
  - [x] `support_tickets.json`
  - [x] `threat_log.json`
  - [x] `tls_fingerprints.json`
  - [x] `trust_graph.json`
  - [x] `whitelist.json`

(Exact list has been reconciled with `server/json/` and Filepurpose.md; any new JSON surfaces added later must follow the same pattern.)

### ML Models (`AI/ml_models/`)

- [x] `anomaly_detector.pkl`
- [x] `feature_scaler.pkl`
- [x] `ip_reputation.pkl`
- [x] `node_fingerprint.json`
- [x] `signature_cache/` directory (if used in Linux deployments)

### Crypto Keys (`server/crypto_keys/` → runtime location)

- [x] Ensure build-time keys from `server/crypto_keys/` are either:
  - [x] Shipped into a secure location (for lab/demo) under `/opt/battle-hardened-ai/server/crypto_keys`, **and**
  - [x] Generated/overridden on first run in `/var/lib/battle-hardened-ai/server/crypto_keys` by `packaging/debian/battle-hardened-ai.postinst`.
- [x] TLS cert/key paths in Linux match the defaults in `.env` / README (Gunicorn and server use `BASE_DIR/crypto_keys/ssl_{cert,key}.pem`, while Debian runtime keys live under `/var/lib/battle-hardened-ai/server/crypto_keys` for message security and relay HMAC).

### Step 21 Policies (`policies/step21/`)

- [x] `manifest.json`
- [x] `manifest.sig`
- [x] `policy.json`
- [x] `schema.json`
- [x] Installed to a stable path (`/opt/battle-hardened-ai/policies/step21`) via `packaging/debian/rules`, resolved by `AI/step21_policy._get_policy_dir()`.

## ✅ UI / DASHBOARD FILES (LINUX)

- [ ] HTML dashboard files copied to the path the server expects:
  - [ ] `AI/inspector_ai_monitoring.html` (or server templates if moved)
  - [ ] `AI/docs_portal.html`
  - [ ] `AI/docs_viewer.html`
  - [ ] `AI/swagger_ui.html`
- [ ] If `server/templates/` or `server/static/` exist, include all `.html`, `.css`, `.js`, and assets needed for the dashboard.

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
  - [x] Which dependencies are installed via `apt` vs `pip` (base `python3`, `python3-venv`, `systemd`, `iptables`, `ipset`, `curl` via `apt`; Python packages from `server/requirements.txt` via `pip` in the venv).
- [x] Ensure `gunicorn` (Linux-only) is available where systemd `ExecStart` expects it: either in the venv or system-wide (systemd `ExecStart` uses `/opt/battle-hardened-ai/venv/bin/gunicorn`, and postinst now creates the venv and installs requirements).
- [x] Confirm that sequence/deep-learning features gracefully degrade if TensorFlow is not installed (as documented in `server/requirements.txt` and guarded in `AI/sequence_analyzer.py` by optional TensorFlow imports).

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
- [x] Debian package installs this unit to `/lib/systemd/system/battle-hardened-ai.service`.
- [x] `postinst` (or debhelper) calls:
  - [x] `systemctl daemon-reload`
  - [x] `systemctl enable`/`restart` `battle-hardened-ai` and `battle-hardened-ai-firewall-sync`.
- [x] `prerm`/`postrm` handle stop/disable cleanly.

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

## ✅ POST-BUILD VERIFICATION (DEBIAN/UBUNTU VIA DOCKER)

Canonical dev test environment is a clean Debian/Ubuntu Docker container:

1. [ ] Start a container (example): `docker run --rm -it -v "$PWD":/src -w /src debian:12-slim bash`.
2. [ ] Inside the container, install build/runtime deps (`apt-get update && apt-get install -y systemd systemd-sysv iptables ipset curl python3 python3-venv` as needed).
3. [ ] Install package with `dpkg -i battle-hardened-ai_*.deb` (from `/src`).
4. [ ] Run `systemctl status battle-hardened-ai` – service is active (or clearly fails with useful logs). Note: running full systemd in Docker may require `--privileged` or a tuned base image; adjust per your Docker baseline.
5. [ ] Confirm logs are written under `/var/log/battle-hardened-ai/` inside the container.
6. [ ] Confirm JSON state and ML models are in the expected `/var/lib/battle-hardened-ai/` locations.
7. [ ] Verify dashboard loads from the container at `https://<container-ip>:60000` (or `http://` if TLS terminated externally) as per Installation.md.
8. [ ] Run at least one test from `KALI_ATTACK_TESTS.md` (adapted for container networking) to ensure detection, blocking, and logging work end-to-end.
9. [ ] Confirm Step 21 semantic gate loads and blocks a policy-violating HTTP request (as described in README.md).
10. [ ] Verify relay connectivity (if enabled in `.env`) does not block core operation when disabled.
11. [ ] Check that removing the package with `apt remove battle-hardened-ai` stops the service and leaves operator data (JSON/logs) in a sensible state (documented behavior).

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
