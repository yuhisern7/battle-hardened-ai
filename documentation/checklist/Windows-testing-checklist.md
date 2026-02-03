# Windows testing checklist

This checklist validates the Battle-Hardened AI Windows EXE and installer on a clean Windows environment before moving on to .deb and .rpm packaging.

---

## Shipped Windows payload

- **BattleHardenedAI.exe** (PyInstaller one-file EXE)
  - Entrypoint: `server/server.py`.
  - Bundles: all Python dependencies reachable from `server.py` (Flask, Flask-CORS, scikit-learn, numpy, cryptography, requests, websockets, ldap3, python-jose, pyotp, python-dotenv, scapy, onnxruntime, skl2onnx, etc., as listed in `server/requirements.txt`).
  - Bundles core AI code under `AI/` plus critical server modules (`server/device_scanner.py` with cross-platform network detection, `server/network_monitor.py` for traffic analysis) as specified in `BattleHardenedAI.spec` datas section.
  - Bundles 5 architecture enhancement modules:
    - `AI/model_signing.py` - Ed25519 cryptographic model verification
    - `AI/pattern_filter.py` - Bloom filter deduplication (70-80% bandwidth savings)
    - `AI/model_performance_monitor.py` - Production ML accuracy tracking
    - `AI/onnx_model_converter.py` - Model conversion (relay-side)
    - ONNX runtime integration in `AI/pcs_ai.py` - 2-5x faster inference
  - Bundles these templates (explicit in the PyInstaller spec):
    - `AI/inspector_ai_monitoring.html`
    - `AI/docs_portal.html`
    - `AI/docs_viewer.html`
    - `AI/swagger_ui.html`
- **Inno Setup installer payload** (per `packaging/windows/BattleHardenedAI.iss`):
  - `BattleHardenedAI.exe` into `{pf}/Battle-Hardened AI`.
  - `README.md`, `LICENSE`.
  - Full `documentation/*` and `policies/*` trees.
  - `packaging/windows/.env.windows` → installed as `{app}/.env.windows` (primary configuration template).
  - `packaging/windows/windows-firewall/configure_bh_windows_firewall.ps1` → installed as `{app}/windows-firewall/configure_bh_windows_firewall.ps1`.

---

## A. Build and payload sanity

- [ ] On the build machine, ensure the virtual environment has all of `server/requirements.txt` installed (including Flask-CORS==4.0.0).
- [ ] Run `packaging/windows/build_windows_installer.ps1` and confirm:
  - [ ] `packaging/windows/dist/BattleHardenedAI.exe` is (re)built from `packaging/windows/BattleHardenedAI.spec` with no errors.
  - [ ] PyInstaller output confirms bundling of `server/device_scanner.py` and `server/network_monitor.py` from datas section.
  - [ ] `packaging/windows/BattleHardenedAI-Setup.exe` is produced successfully.
- [ ] Verify the installer contents (via Inno Setup log or 7‑Zip) include:
  - [ ] `BattleHardenedAI.exe`.
  - [ ] `README.md`, `LICENSE`.
  - [ ] `documentation/*` and `policies/*`.
  - [ ] `.env.windows` at the application root.
  - [ ] `windows-firewall/configure_bh_windows_firewall.ps1`.

---

## B. Clean Windows test environment

- [ ] Test VM: Windows 10/11 or Server x64, fully patched.
- [ ] Local Administrator rights (required for install, logging directories, and firewall sync).
- [ ] PowerShell execution policy allows running `configure_bh_windows_firewall.ps1` (for example, `RemoteSigned` or appropriate override for the test).
- [ ] If testing network monitoring or device scanning:
  - [ ] Install Npcap (recommended for Scapy on Windows).
  - [ ] Run `BattleHardenedAI.exe` from an elevated console so Scapy can open raw sockets.

---

## C. Post-install filesystem and configuration

After installing `BattleHardenedAI-Setup.exe`:

- [ ] Confirm the install path exists and matches expectations, for example:
  - [ ] `C:/Program Files/Battle-Hardened AI/BattleHardenedAI.exe`.
- [ ] Confirm the following are present under `{app}`:
  - [ ] `.env.windows`.
  - [ ] `documentation/...` and `policies/...`.
  - [ ] `windows-firewall/configure_bh_windows_firewall.ps1`.
- [ ] Edit `.env.windows` in-place to point to your test relay (or disable relay for free mode):
  - [ ] `RELAY_ENABLED=true/false` set to the desired mode.
  - [ ] `RELAY_URL` and `RELAY_API_URL` point at your test VPS (if Premium/relay is tested).
    - [ ] `MESSAGE_SECURITY_KEY_DIR` path is valid (or unset to use the default from `AI/path_helper.get_crypto_keys_dir()`:
      `%LOCALAPPDATA%/Battle-Hardened AI/server/crypto_keys` on Windows EXE).
  - [ ] `DASHBOARD_PORT` and `P2P_PORT` set to intended test ports (default 60000/60001).
  - [ ] Start `BattleHardenedAI.exe` once and verify:
  - [ ] Logs directory created next to the EXE (for example, `{app}/logs/server.log`, `{app}/logs/errors.log`).
  - [ ] JSON storage directory exists via the path helper under your user profile: `%LOCALAPPDATA%/Battle-Hardened AI/server/json/` (for `threat_log.json`, `blocked_ips.json`, and related files).

---

## D. Runtime and feature checks

With `BattleHardenedAI.exe` running:

- [ ] **Dashboard**
  - [ ] Browse to `https://localhost:60000` (or configured port) from the same machine (self-signed by default; use `http://localhost:60000` only if TLS is terminated by an external proxy).
  - [ ] Basic login and system-status pages load without errors.
- [ ] **Template loading**
  - [ ] Navigate to the inspector/monitoring view and docs portal to confirm the bundled templates render correctly.
- [ ] **Architecture Enhancements Validation**
  - [ ] Check logs for "Model signature verified" messages (cryptographic signing active).
  - [ ] Confirm ONNX models loaded: Look for "Loading ONNX model" or "Using ONNX Runtime" in logs (2-5x faster inference).
  - [ ] If relay enabled, verify pattern filter statistics show bandwidth savings (70-80% deduplication).
  - [ ] Access `/api/ml-performance` endpoint to confirm performance monitoring is tracking accuracy metrics.
  - [ ] Verify crypto keys directory exists: `%LOCALAPPDATA%/Battle-Hardened AI/server/crypto_keys/` (for model signing public keys).
- [ ] **Threat logging and blocked IPs**
  - [ ] Trigger at least one test "attack" path (for example, using the KALI/port-scan lab scenario or an internal test route).
  - [ ] Confirm `threat_log.json` and `blocked_ips.json` are written under `%LOCALAPPDATA%/Battle-Hardened AI/server/json/` (paths resolved via `AI.path_helper.get_json_dir`).
- [ ] **Windows firewall sync**
  - [ ] From an elevated PowerShell in `{app}/windows-firewall`, run:
    - [ ] `./configure_bh_windows_firewall.ps1 -SkipBaselineRules -ExcludeAddresses YOUR_RELAY_IP` (or just `./configure_bh_windows_firewall.ps1` for one-time baseline + sync).
  - [ ] Confirm that a rule named "Battle-Hardened AI Blocked IPs" (or your custom `-BlockRuleName`) appears in Windows Defender Firewall:
    - Direction: Inbound.
    - Action: Block.
    - RemoteAddress: includes the IPs from `blocked_ips.json`.
- [ ] **Optional: Network monitoring and device scanning**
  - [ ] Enable and start the relevant features from the dashboard (or API).
  - [ ] Confirm no "Scapy not installed" errors in logs (the EXE bundles Scapy; issues here indicate driver/permission problems, not packaging).
  - [ ] Validate that port-scan or ARP spoofing events are detected and reflected in the dashboard and logs.

---

## E. Graceful degradation and security hooks

- [ ] If `AI.secure_deployment` or `AI.step21_policy` are not fully configured, confirm:
  - [ ] The server still starts and `/api/system-status` surfaces their status without crashing.
- [ ] Disable the relay (`RELAY_ENABLED=false`) and confirm:
  - [ ] The EXE still runs; local threat logging and blocking still function.
  - [ ] No hard failures on missing relay connectivity (only warnings or informational messages).
- [ ] **Architecture Enhancements - Graceful Fallback**
  - [ ] If ONNX runtime unavailable, confirm system falls back to pickle models (check logs for "ONNX not available, using pickle" message).
  - [ ] If model signatures missing, verify appropriate warnings logged (system should still function with reduced security).
  - [ ] If pattern filter disabled, confirm relay uploads still work (just without deduplication).
  - [ ] If performance monitoring disabled, confirm ML inference still operates normally.

---

## F. Architecture Enhancements - Final Validation

Before declaring Windows packaging complete, verify the **5 production-ready architecture enhancements** are fully operational:

- [ ] **Enhancement #1: Model Cryptographic Signing**
  - [ ] Relay signing keys exist in `%LOCALAPPDATA%/Battle-Hardened AI/server/crypto_keys/relay_signing_key.pem`.
  - [ ] Customer verification public keys exist in `%LOCALAPPDATA%/Battle-Hardened AI/server/crypto_keys/relay_public_key.pem`.
  - [ ] Logs show "Model signature verified successfully" when loading models.
  - [ ] Test: Tamper with a `.pkl` model file → verify system rejects it with "Signature verification failed" error.

- [ ] **Enhancement #2: Smart Pattern Filtering**
  - [ ] Bloom filter state persists in `%LOCALAPPDATA%/Battle-Hardened AI/server/json/pattern_filter_state.json`.
  - [ ] API endpoint `/api/pattern-filter/stats` returns deduplication statistics (70-80% bandwidth saved).
  - [ ] Test: Upload duplicate attack patterns → verify only first upload reaches relay.

- [ ] **Enhancement #3: Model Performance Monitoring**
  - [ ] API endpoint `/api/ml-performance` returns accuracy metrics for active models.
  - [ ] Performance data persists in `%LOCALAPPDATA%/Battle-Hardened AI/server/json/ml_performance.json`.
  - [ ] Dashboard shows ML performance metrics (accuracy, precision, F1 score).
  - [ ] Test: Simulate degraded accuracy → verify WARNING alert at <92%, CRITICAL at <85%.

- [ ] **Enhancement #4: Adversarial Training**
  - [ ] (Relay-side only) If testing relay: Logs show "Generated adversarial examples" during training.
  - [ ] Customer side: Models loaded from relay include adversarial robustness (verify in model metadata if available).

- [ ] **Enhancement #5: ONNX Model Format**
  - [ ] ONNX models exist alongside pickle models in `%LOCALAPPDATA%/Battle-Hardened AI/server/ml_models/` (`.onnx` files).
  - [ ] Logs show "Loading ONNX model: <model_name>.onnx" on startup.
  - [ ] Logs show "ONNX inference time: X.Xms" (should be 2-5x faster than pickle baseline).
  - [ ] Test: Delete `.onnx` file → verify automatic fallback to `.pkl` with "ONNX model not found, using pickle" message.

**Final Checklist:**
- [ ] All 5 enhancements operational without errors.
- [ ] Performance improvements verified (2-5x faster inference, 70-80% bandwidth savings).
- [ ] Security guarantees active (model signing, adversarial robustness, performance monitoring).
- [ ] Graceful fallbacks work (ONNX → pickle, missing signatures → warnings).
- [ ] Documentation references updated: [Architecture_Enhancements.md](../architecture/Architecture_Enhancements.md) and [ONNX_Integration.md](../architecture/ONNX_Integration.md)

---

When all items above are checked on a clean Windows VM, including the **5 architecture enhancements validation**, the Windows EXE and installer are considered ready, and you can proceed to validating the `.deb` and `.rpm` packages for Linux.
