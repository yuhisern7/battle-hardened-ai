# Windows testing checklist

This checklist validates the Battle-Hardened AI Windows EXE and installer on a clean Windows environment before moving on to .deb and .rpm packaging.

---

## Shipped Windows payload

- **BattleHardenedAI.exe** (PyInstaller one-file EXE)
  - Entrypoint: `server/server.py`.
  - Bundles: all Python dependencies reachable from `server.py` (Flask, scikit-learn, numpy, cryptography, requests, websockets, ldap3, python-jose, pyotp, python-dotenv, scapy, etc., as listed in `server/requirements.txt`).
  - Bundles core AI code under `AI/` plus these templates (explicit in the PyInstaller spec):
    - `AI/inspector_ai_monitoring.html`
    - `AI/docs_portal.html`
    - `AI/docs_viewer.html`
    - `AI/swagger_ui.html`
- **Inno Setup installer payload** (per `packaging/windows/BattleHardenedAI.iss`):
  - `BattleHardenedAI.exe` into `{pf}/Battle-Hardened AI`.
  - `README.md`, `LICENSE`.
  - Full `documentation/*` and `policies/*` trees.
  - `server/.env.windows` → installed as `{app}/.env.windows` (primary configuration template).
  - `server/windows-firewall/configure_bh_windows_firewall.ps1` → installed as `{app}/windows-firewall/configure_bh_windows_firewall.ps1`.

---

## A. Build and payload sanity

- [ ] On the build machine, ensure the virtual environment has all of `server/requirements.txt` installed.
- [ ] Run `packaging/windows/build_windows_installer.ps1` and confirm:
  - [ ] `packaging/windows/dist/BattleHardenedAI.exe` is (re)built from `server/BattleHardenedAI.spec` with no errors.
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

When all items above are checked on a clean Windows VM, the Windows EXE and installer are considered ready, and you can proceed to validating the `.deb` and `.rpm` packages for Linux.
