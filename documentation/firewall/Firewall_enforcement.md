# Battle-Hardened AI Firewall Enforcement

Battle-Hardened AI makes **first-layer decisions** about which IPs are malicious or trusted and writes them into structured JSON files:
- `blocked_ips.json` - IPs to block at firewall level
- `whitelist.json` - IPs with firewall-level immunity (never blocked)

This guide shows how to **enforce these decisions at OS firewall level** on:

- **Linux** (Debian/Ubuntu, RHEL/Rocky, VyOS, OpenWRT, Alpine, SUSE)
- **Windows** (native host firewall)

**Enterprise environments:** Use this as a reference implementation. Integrate with existing GPO/MDM/EDR firewall policies as appropriate.

**Architecture:** Battle-Hardened AI provides **detection and decision logic**. Firewall enforcement translates those decisions into kernel-level network filtering.

---

## 🐧 Linux Firewall Backend Support

Battle-Hardened AI **auto-detects** your Linux firewall backend and uses the appropriate commands:

| Distribution | Default Firewall | Detection Method | Support Status |
|--------------|------------------|------------------|----------------|
| **Debian/Ubuntu** | iptables-nft (nftables backend) | `update-alternatives --query iptables` | ✅ Full (Primary platform) |
| **RHEL/Rocky/Alma** | firewalld | `systemctl is-active firewalld` | ✅ Full (ipset via firewalld) |
| **SUSE** | firewalld | `systemctl is-active firewalld` | ✅ Full (same as RHEL) |
| **VyOS** | VyOS CLI | `which vbash`, `/opt/vyatta` | ⚠️ Partial (requires manual setup) |
| **OpenWRT** | UCI firewall | `which uci`, `/etc/config/firewall` | ⚠️ Partial (config reload required) |
| **Alpine Linux** | awall | `which awall`, `/etc/awall` | ⚠️ Partial (file-based config) |

**Auto-detection:** The firewall sync daemon (`bh_firewall_sync.py`) detects your backend at startup and uses the correct commands automatically.

**Manual override:** Set `BH_FIREWALL_BACKEND` in `.env` to force a specific backend (e.g., `BH_FIREWALL_BACKEND=firewalld`).

---

## 📦 Implementation File Manifest

This section lists all files involved in the Linux Firewall Commander subsection implementation (Section 7, Phase 1-6).

### ✅ New Files Created

| File Path | Purpose | Phase | Lines | Status |
|-----------|---------|-------|-------|--------|
| `AI/firewall_backend.py` | Multi-distro firewall backend abstraction layer | Phase 1 | 654 | ✅ Created |
| `server/api/firewall_routes.py` | API endpoints for firewall management | Phase 3 | ~300 | ❌ Not needed (routes added directly to server.py) |
| `AI/inspector_ai_monitoring.html` | Section 7 Linux Firewall Commander UI (Tab 4) | Phase 4 | ~200 | ✅ Complete |
| `documentation/firewall/Multi_distro_support.md` | Per-backend configuration examples | Phase 5 | ~200 | ⚠️ Optional (examples in this file) |

**Total new files:** 2 created, 1 not needed, 1 optional

### 🔧 Existing Files Modified

| File Path | Changes Made | Phase | Status |
|-----------|--------------|-------|--------|
| `server/installation/bh_firewall_sync.py` | Added dual-layer sync (whitelist + blocklist), backend detection, logging | Phase 1 | ✅ Complete |
| `packaging/debian-startup.sh` | Create both ipsets (bh_whitelist + bh_blocked), dual-layer iptables rules | Phase 2 | ✅ Complete |
| `packaging/debian-uninstall.sh` | Destroy both ipsets, remove dual-layer rules | Phase 2 | ✅ Complete |
| `packaging/systemd/battle-hardened-ai-firewall-sync.service` | Service definition for firewall sync daemon (no changes needed) | Phase 2 | ✅ Verified |
| `server/server.py` | Added 6 firewall API routes (detect, status, sync, test, rules, backend) | Phase 3 | ✅ Complete |
| `server/json/blocked_ips.json` | Schema unchanged (existing) | N/A | ✅ Existing |
| `server/json/whitelist.json` | Schema unchanged (existing) | N/A | ✅ Existing |
| `AI/inspector_ai_monitoring.html` | Added Section 7 Tab 4 (Firewall Commander UI with status, actions, tables) | Phase 4 | ✅ Complete |
| `documentation/installation/Installation.md` | Added Step 8b (firewall verification with backend testing) | Phase 5 | ✅ Complete |
| `documentation/checklist/Debian-checklist.md` | Added Linux Firewall subsection verification (Tab 4 components) | Phase 5 | ✅ Complete |
| `documentation/architecture/Attack_handling_flow.md` | Updated IP blocking to document dual-layer enforcement | Phase 5 | ✅ Complete |
| `documentation/architecture/Architecture_enhancements.md` | Added Feature #6 (Linux Firewall Commander) | Phase 5 | ✅ Complete |
| `README.md` | Updated firewall documentation paths | Phase 1 | ✅ Complete |
| `documentation/firewall/Firewall_enforcement.md` | This file (comprehensive rewrite with dual-layer architecture) | Phase 1 | ✅ Complete |

**Total modified files:** 14 (all complete)

### 🎯 Implementation Phases Summary

**Phase 1: Backend Abstraction Layer** ✅ COMPLETE
- Created: `AI/firewall_backend.py` (654 lines, multi-distro detection & sync)
- Modified: `server/installation/bh_firewall_sync.py` (dual-layer enforcement)
- Modified: `README.md` (documentation path updates)
- Modified: `documentation/firewall/Firewall_enforcement.md` (this file)

**Phase 2: Startup Script Updates** ✅ COMPLETE
- Modified: `packaging/debian-startup.sh` (create both ipsets with dual-layer rules)
- Modified: `packaging/debian-uninstall.sh` (cleanup both ipsets)
- Verified: `packaging/systemd/battle-hardened-ai-firewall-sync.service` (systemd service - no changes needed)

**Phase 3: API Endpoints** ✅ COMPLETE
- Modified: `server/server.py` (added 6 firewall API routes directly)
- Routes implemented:
  * `GET /api/firewall/detect` - Returns detected backend + capabilities
  * `GET /api/firewall/status` - Returns sync status, IP counts, firewall stats
  * `POST /api/firewall/sync` - Force immediate sync (bypasses 5s delay)
  * `POST /api/firewall/test` - Test integration (add/verify/remove test IP)
  * `GET /api/firewall/rules` - Returns our rules vs customer rules
  * `POST /api/firewall/backend` - Override backend detection

**Phase 4: Frontend UI** ✅ COMPLETE
- Modified: `AI/inspector_ai_monitoring.html` (added Section 7, Tab 4 "Linux Firewall Commander")
- Components: 
  * Status panel (backend detection, sync daemon health)
  * Sync health indicators (whitelist/blocklist IP counts)
  * Our rules table (dual-layer priority display)
  * Customer rules table (collapsible, read-only)
  * Action buttons (Force Sync, Test Integration, View Native Rules, Refresh)
  * Test results modal (3-step validation display)
  * Auto-refresh (30s interval when tab active)
- JavaScript functions:
  * `fetchFirewallStatus()` - Load status from API
  * `forceFirewallSync()` - Immediate sync via API
  * `testFirewallIntegration()` - Run 3-step test
  * `viewNativeRules()` - Display customer firewall rules
  * `toggleCustomerRules()` - Show/hide customer rules
  * `closeTestResults()` - Close test modal
  * Auto-refresh interval

**Phase 5: Documentation** ✅ COMPLETE
- Modified: `documentation/installation/Installation.md` (Step 8b verification with backend testing)
- Modified: `documentation/checklist/Debian-checklist.md` (Linux Firewall subsection verification)
- Modified: `documentation/architecture/Attack_handling_flow.md` (dual-layer enforcement documentation)
- Modified: `documentation/architecture/Architecture_enhancements.md` (added Feature #6)
- Optional: `documentation/firewall/Multi_distro_support.md` (examples included in this file instead)

**Phase 6: Testing** ⏳ PENDING
- Test on Debian 12 (iptables-nft), Rocky Linux 9 (firewalld)
- Verify dual-layer enforcement, automatic sync, Force Sync, Test Integration

---

## 🎯 Deployment Role Determines Firewall Enforcement Scope

**What firewall enforcement protects depends on deployment mode:**

| Deployment Role | Firewall Enforcement Scope | What Gets Blocked |
|----------------|---------------------------|-------------------|
| **Gateway/Router (Linux)** | Entire network segment (all devices behind gateway) | All traffic through gateway via iptables/nftables |
| **Host-only (Linux/Windows)** | Local machine + services it terminates | Traffic to/from this host only |
| **Observer** | Detection-only (no firewall enforcement) | Nothing (analysis mode - external firewall required) |

**Installation reference:** For deployment setup, see:
- [Installation.md § Deployment Role](../installation/Installation.md#🎯-deployment-role-read-first)
- [Installation.md § Gateway Pre-Flight Checklist](../installation/Installation.md#✅-gateway-pre-flight-checklist)
- [Installation.md § Linux Gateway Setup](../installation/Installation.md#scenario-1-linux-gatewayrouter-network-wide-protection---recommended)
- [Installation.md § Cloud Gateway Setup](../installation/Installation.md#scenario-2-cloud-gateway-with-virtual-nics-awsazuregcp)

**Note:** Cloud VMs (AWS/Azure/GCP) fully supported with virtual NICs. Observer mode provides detection only (no firewall enforcement).

---

## 📋 Quick Reference: Firewall Components

**Two enforcement layers:**

1. **Whitelist (Priority 1 - ACCEPT)** - Trusted IPs bypass all blocking
2. **Blocklist (Priority 2 - DROP)** - Malicious IPs dropped at kernel

**Why two layers?** If an IP is in BOTH lists, whitelist wins. This protects critical infrastructure from accidental blocking.

**Linux implementation:**
- `ipset` named `bh_whitelist` (ACCEPT rules, priority 1)
- `ipset` named `bh_blocked` (DROP rules, priority 2)
- Firewall rules reference these ipsets

**Windows implementation:**
- Windows Firewall rule "Battle-Hardened AI Whitelist" (ACCEPT, priority higher)
- Windows Firewall rule "Battle-Hardened AI Blocked IPs" (DROP, priority lower)

---

### Firewall Ports Summary (Enterprise View)

Use this table as the **authoritative reference** when creating firewall rules via GPO/Intune, on-prem firewalls, or EDR policy consoles.

| Component / Role | Direction | Port(s) / Protocol | Purpose |
|------------------|-----------|--------------------|---------|
| Linux gateway / edge node | Inbound | 60000/TCP | HTTPS dashboard (SOC/administrator access) |
| Linux gateway / edge node | Inbound | 2121, 2222, 2323, 3306, 8080, 2525, 3389/TCP | Honeypot services for attacker interaction and training |
| Linux gateway / edge node | Outbound (optional) | 60001–60002/TCP | Client → relay (WebSocket + HTTPS model API) |
| Windows host / appliance | Inbound | 60000/TCP | HTTPS dashboard on Windows deployments |
| Windows host / appliance | Inbound | 2121, 2222, 2323, 3306, 8080, 2525, 3389/TCP | Windows honeypot services (optional, security lab / decoy) |
| Windows host / appliance | Outbound (optional) | 60001–60002/TCP | Client → relay (WebSocket + HTTPS model API) |
| Relay server (VPS) | Inbound | 60001/TCP | WebSocket relay endpoint (wss://) |
| Relay server (VPS) | Inbound | 60002/TCP | HTTPS model distribution API |

In tightly controlled environments, these ports are normally opened on **security appliances and relay servers only**, not on general-purpose endpoints.

---

## 1. Linux Firewall Enforcement — Dual-Layer Protection

### 1.1. Overview

Battle-Hardened AI syncs **two types** of firewall rules to Linux:

1. **Whitelist (Priority 1)** - ACCEPT rules for trusted IPs from `whitelist.json`
2. **Blocklist (Priority 2)** - DROP rules for malicious IPs from `blocked_ips.json`

**Rule processing order ensures whitelist wins:**
```bash
# Processed FIRST (highest priority)
iptables -I INPUT 1 -m set --match-set bh_whitelist src -j ACCEPT
iptables -I FORWARD 1 -m set --match-set bh_whitelist src -j ACCEPT

# Processed SECOND (lower priority)
iptables -I INPUT 2 -m set --match-set bh_blocked src -j DROP
iptables -I FORWARD 2 -m set --match-set bh_blocked src -j DROP
```

**Result:** If IP is in both lists, it will be ACCEPTED (whitelisted).

### 1.2. Enable Automatic Firewall Sync

**Step 1: Enable in environment configuration**

- **Debian/Ubuntu (.deb package):**
  ```bash
  # Edit environment file
  sudo vim /etc/battle-hardened-ai/.env
  
  # Add or verify:
  BH_FIREWALL_SYNC_ENABLED=true
  ```

- **RHEL/Rocky (.rpm package):**
  ```bash
  # Edit environment file
  sudo vim /etc/battle-hardened-ai/.env
  
  # Add or verify:
  BH_FIREWALL_SYNC_ENABLED=true
  # Optional: Force firewalld backend
  BH_FIREWALL_BACKEND=firewalld
  ```

**Step 2: Run startup script (Debian/Ubuntu)**

The `debian-startup.sh` script creates both ipsets and firewall rules:

```bash
sudo bash /opt/battle-hardened-ai/packaging/debian-startup.sh
```

**Expected output:**
```
✅ Creating Battle-Hardened AI ipsets...
Created ipset: bh_whitelist
Created ipset: bh_blocked

✅ Installing firewall rules...
Whitelist ACCEPT rules: Added (INPUT + FORWARD)
Blocklist DROP rules: Added (INPUT + FORWARD)

✅ Saving firewall rules...
Rules saved to /etc/iptables/rules.v4

✅ Restarting services...
battle-hardened-ai.service: active
battle-hardened-ai-firewall-sync.service: active

Firewall Status:
├─ Whitelist IPs: 8 (from whitelist.json)
├─ Blocked IPs: 24 (from blocked_ips.json)
├─ iptables ACCEPT rules: Active (priority 1)
└─ iptables DROP rules: Active (priority 2)
```

**Step 3: Verify firewall sync service**

```bash
# Check sync service status
sudo systemctl status battle-hardened-ai-firewall-sync

# Should show:
#   Active: active (running)
#   Main PID: XXXX (bh_firewall_sync.py)
```

### 1.3. Verify Firewall Rules

**Check ipsets exist and have correct IPs:**

```bash
# Whitelist ipset
sudo ipset list bh_whitelist
# Output shows: Number of entries: 8

# Blocklist ipset  
sudo ipset list bh_blocked
# Output shows: Number of entries: 24
```

**Check iptables rules reference both ipsets:**

```bash
sudo iptables -L INPUT -n -v | head -20

# Expected output (first 2 rules):
# Chain INPUT (policy ACCEPT 123K packets, 45M bytes)
#  pkts bytes target  prot opt in  out  source     destination
#  1234 567K ACCEPT  all  --  *   *   0.0.0.0/0  0.0.0.0/0  match-set bh_whitelist src
#  5678 89K  DROP    all  --  *   *   0.0.0.0/0  0.0.0.0/0  match-set bh_blocked src
```

**Check rule references (should be 2 per ipset):**

```bash
sudo ipset list bh_whitelist | grep References
# References: 2

sudo ipset list bh_blocked | grep References  
# References: 2
```

**Meaning:** Each ipset is referenced by 2 iptables rules (INPUT chain + FORWARD chain).

### 1.4. Multi-Backend Verification

**Debian/Ubuntu (iptables-nft):**
```bash
# Verify backend
sudo update-alternatives --query iptables | grep Value
# Should show: /usr/sbin/iptables-nft

# View rules
sudo iptables -L -n -v | grep bh_
```

**RHEL/Rocky/Alma (firewalld):**
```bash
# Verify firewalld active
sudo systemctl is-active firewalld
# Should show: active

# Check ipsets via firewalld
sudo firewall-cmd --get-ipsets
# Should include: bh_whitelist, bh_blocked

# View rich rules
sudo firewall-cmd --list-rich-rules
# Should show:
#   rule source ipset=bh_whitelist accept priority=-1
#   rule source ipset=bh_blocked drop priority=0
```

**VyOS:**
```bash
# View address groups
show firewall group
# Should show: BH_WHITELIST, BH_BLOCKED

# View rules
show firewall name WAN_IN
# Should show whitelist ACCEPT (rule 1) and blocklist DROP (rule 2)
```

### 1.5. Automatic Sync Behavior

The firewall sync daemon runs every **5 seconds** and:

1. Reads `whitelist.json` → Syncs to `bh_whitelist` ipset/firewall
2. Reads `blocked_ips.json` → Syncs to `bh_blocked` ipset/firewall
3. Removes IPs from blocklist if they appear in whitelist (safety check)
4. Cleans up orphaned firewall entries not in JSON files

**Dashboard actions automatically sync:**
- Click "Unblock" → IP removed from `blocked_ips.json` → Next sync (≤5s) removes from firewall
- Click "Whitelist" → IP added to `whitelist.json` → Next sync (≤5s) adds to firewall whitelist
- If IP in both files → Whitelist wins (ACCEPT rule processed first)

---

## 2. Windows (EXE or Native Python) — Firewall Integration

On Windows, Battle-Hardened AI runs either as a native Python service or as the packaged Windows EXE and writes to the same logical JSON file (`blocked_ips.json` in the JSON directory resolved via `AI/path_helper`; in a source checkout this is `server/json/blocked_ips.json`).

There are **two layers** of integration with Windows Defender Firewall:

- **Baseline allow rules (ports opened):** Ensure the dashboard and honeypot/relay ports are reachable on the host.
- **Dynamic block rules (malicious IPs):** Sync the `blocked_ips.json` list into a firewall rule so malicious IPs are dropped.

### 2.1. Concept

- Read `server/json/blocked_ips.json` periodically.
- Extract the list of blocked IPs.
- Maintain a **single firewall rule** whose `RemoteAddress` list is updated from that file.

This keeps your firewall configuration simple and centralized.

### 2.2. Example PowerShell Script Locations

The project includes a single ready-to-use script in both **source** and **installed** layouts that configures baseline allow rules **and** syncs blocked IPs into a Windows Defender block rule:

- From a source clone: [packaging/windows/windows-firewall/configure_bh_windows_firewall.ps1](packaging/windows/windows-firewall/configure_bh_windows_firewall.ps1)
- From the Windows installer: `{app}\windows-firewall\configure_bh_windows_firewall.ps1` (for example `C:\Program Files\Battle-Hardened AI\windows-firewall\configure_bh_windows_firewall.ps1`)

In **enterprise environments**, baseline rules are usually created centrally via GPO/Intune or your EDR/endpoint firewall console. This script is provided as a **reference** and is suitable for labs, pilots, or controlled security appliances where local rule changes are permitted.

### 2.3. Run Manually (Baseline vs. Sync)

From an elevated PowerShell prompt (Run as Administrator), after starting Battle-Hardened AI (for example `python server\server.py` from a clone, or `BattleHardenedAI.exe` from the install directory):

**Source checkout (baseline + initial sync):**

```powershell
cd C:\Users\YOURUSER\workspace\battle-hardened-ai\server

powershell.exe -ExecutionPolicy Bypass -File .\windows-firewall\configure_bh_windows_firewall.ps1
```

**Installed EXE (baseline + initial sync, excluding the relay VPS IP):**

```powershell
cd "C:\Program Files\Battle-Hardened AI\windows-firewall"

.\u005cconfigure_bh_windows_firewall.ps1 -ExcludeAddresses YOUR_RELAY_IP
```

This one-shot script is **idempotent** and is meant to be:

- Run once (or rarely) to create/update inbound **allow** rules for the dashboard and honeypot ports (unless `-SkipBaselineRules` is used).
- Optionally create/update an outbound **allow** rule for the relay ports 60001–60002 (unless `-SkipRelayOutbound` is used).
- Read the current `blocked_ips.json` and create or update a **single inbound firewall rule** (by default named `Battle-Hardened AI Blocked IPs`) whose `RemoteAddress` list is populated with the blocked IPs (unless `-SkipBlockSync` is used).

You do **not** run this manually after every block event. Instead, you either call it periodically (see Task Scheduler below) or integrate it into your automation.

### 2.4. Schedule Automatic Sync (Task Scheduler)

To keep the firewall in sync automatically:

1. Open **Task Scheduler** → **Create Task**.
2. On **General**:
   - Run whether user is logged on or not.
   - Run with highest privileges.
3. On **Triggers**:
   - New → Begin the task: *On a schedule*.
   - Set to run **every 1 minute** (or your preferred interval).
4. On **Actions** (example for an installed EXE under `C:\Program Files\Battle-Hardened AI`):
   - Action: *Start a program*.
   - Program/script:

     ```text
     powershell.exe
     ```

     - Add arguments (pointing to the **runtime** JSON path under `%LOCALAPPDATA%`):

       ```text
       -ExecutionPolicy Bypass -File "C:\Program Files\Battle-Hardened AI\windows-firewall\configure_bh_windows_firewall.ps1" -SkipBaselineRules -JsonPath "$env:LOCALAPPDATA\Battle-Hardened AI\server\json\blocked_ips.json"
       ```

5. Save the task.

Now Windows Defender Firewall will be updated periodically from Battle-Hardened AI's `blocked_ips.json`, and malicious IPs will be blocked at the OS firewall level.

---

## 📋 Firewall Integration Checklist

Use this checklist to verify complete firewall enforcement is working correctly.

### ✅ Linux Firewall Checklist (Debian/Ubuntu)

**Pre-Installation:**
- [ ] System is Debian 10+ or Ubuntu 18.04+ (iptables-nft backend)
- [ ] `iptables-persistent` package will be installed (handled by debian-startup.sh)
- [ ] System has ipset support (`apt install ipset`)
- [ ] Firewall sync enabled: `BH_FIREWALL_SYNC_ENABLED=true` in `/etc/battle-hardened-ai/.env`

**Post-Installation (After running debian-startup.sh):**
- [ ] Both ipsets created:
  ```bash
  sudo ipset list bh_whitelist -name  # Should succeed
  sudo ipset list bh_blocked -name    # Should succeed
  ```
- [ ] Whitelist has ACCEPT rules at priority 1:
  ```bash
  sudo iptables -L INPUT -n -v | head -5
  # First rule should be: ACCEPT match-set bh_whitelist src
  ```
- [ ] Blocklist has DROP rules at priority 2:
  ```bash
  sudo iptables -L INPUT -n -v | head -5
  # Second rule should be: DROP match-set bh_blocked src
  ```
- [ ] Both ipsets referenced by 2 chains each:
  ```bash
  sudo ipset list bh_whitelist | grep References  # Should show: 2
  sudo ipset list bh_blocked | grep References    # Should show: 2
  ```
- [ ] Firewall sync service running:
  ```bash
  sudo systemctl is-active battle-hardened-ai-firewall-sync  # Should show: active
  ```
- [ ] Rules saved permanently:
  ```bash
  sudo iptables-save | grep bh_  # Should show 4 rules (2 whitelist + 2 blocked)
  ```

**Functional Testing:**
- [ ] Add IP to dashboard whitelist → verify in `bh_whitelist` ipset within 5 seconds
- [ ] Add IP to dashboard blocklist → verify in `bh_blocked` ipset within 5 seconds
- [ ] Add IP to BOTH lists → verify it appears in whitelist only (blocklist removes it)
- [ ] Remove IP from whitelist → verify removed from `bh_whitelist` ipset
- [ ] Packet counters incrementing correctly:
  ```bash
  sudo iptables -L INPUT -n -v | grep bh_
  # pkts column should increment when traffic matches
  ```

### ✅ Linux Firewall Checklist (RHEL/Rocky/Alma)

**Pre-Installation:**
- [ ] System is RHEL 8+, Rocky 8+, or AlmaLinux 8+
- [ ] firewalld service active: `systemctl is-active firewalld` returns `active`
- [ ] Firewall sync enabled: `BH_FIREWALL_SYNC_ENABLED=true` in `/etc/battle-hardened-ai/.env`
- [ ] Optional: Backend override set: `BH_FIREWALL_BACKEND=firewalld`

**Post-Installation:**
- [ ] Both ipsets created via firewalld:
  ```bash
  sudo firewall-cmd --get-ipsets
  # Should include: bh_whitelist, bh_blocked
  ```
- [ ] Rich rules added with correct priority:
  ```bash
  sudo firewall-cmd --list-rich-rules
  # Should show:
  #   rule source ipset=bh_whitelist accept priority=-1  (processed first)
  #   rule source ipset=bh_blocked drop priority=0       (processed second)
  ```
- [ ] Firewall sync service running:
  ```bash
  sudo systemctl is-active battle-hardened-ai-firewall-sync  # Should show: active
  ```
- [ ] Configuration persistent:
  ```bash
  sudo firewall-cmd --permanent --get-ipsets
  # Should include: bh_whitelist, bh_blocked
  ```

**Functional Testing:**
- [ ] Add IP to whitelist → verify in firewalld ipset: `firewall-cmd --ipset=bh_whitelist --get-entries`
- [ ] Add IP to blocklist → verify in firewalld ipset: `firewall-cmd --ipset=bh_blocked --get-entries`
- [ ] Reload firewalld → verify rules persist: `firewall-cmd --reload`

### ✅ Linux Firewall Checklist (VyOS)

**Pre-Installation:**
- [ ] VyOS 1.3+ or 1.4+
- [ ] `vbash` accessible
- [ ] Firewall sync enabled: `BH_FIREWALL_SYNC_ENABLED=true`
- [ ] Backend override: `BH_FIREWALL_BACKEND=vyos`

**Post-Installation:**
- [ ] Address groups created:
  ```bash
  show firewall group
  # Should show: BH_WHITELIST (address-group), BH_BLOCKED (address-group)
  ```
- [ ] Firewall rules created with correct order:
  ```bash
  show firewall name WAN_IN
  # Rule 1: source BH_WHITELIST action accept  (processed first)
  # Rule 2: source BH_BLOCKED action drop      (processed second)
  ```
- [ ] Configuration saved:
  ```bash
  show configuration commands | grep BH_
  ```

**Functional Testing:**
- [ ] Add IP via dashboard → verify in address group
- [ ] Commit and save → verify persistence after reboot

### ✅ Windows Firewall Checklist

**Pre-Installation:**
- [ ] Windows 10/11 or Windows Server 2016+
- [ ] Windows Defender Firewall enabled
- [ ] PowerShell execution policy allows scripts
- [ ] Battle-Hardened AI EXE or Python installation running

**Post-Installation:**
- [ ] Baseline inbound rules created:
  ```powershell
  Get-NetFirewallRule -DisplayName "Battle-Hardened AI*" | Select DisplayName, Direction, Action
  # Should show:
  #   - Battle-Hardened AI Dashboard (Inbound, Allow)
  #   - Battle-Hardened AI Honeypot Services (Inbound, Allow)
  ```
- [ ] Blocklist rule created:
  ```powershell
  Get-NetFirewallRule -DisplayName "Battle-Hardened AI Blocked IPs" | Select DisplayName, Action
  # Should show: Battle-Hardened AI Blocked IPs (Block)
  ```
- [ ] Blocklist rule has IPs:
  ```powershell
  (Get-NetFirewallRule -DisplayName "Battle-Hardened AI Blocked IPs" | Get-NetFirewallAddressFilter).RemoteAddress
  # Should show array of blocked IPs from blocked_ips.json
  ```
- [ ] Task Scheduler job configured:
  ```powershell
  Get-ScheduledTask -TaskName "Battle-Hardened AI Firewall Sync"
  # Should show: Ready state
  ```

**Functional Testing:**
- [ ] Add IP to blocklist → run sync script → verify in firewall rule
- [ ] Task Scheduler triggers automatically every minute
- [ ] Check Task Scheduler history for successful runs
- [ ] Verify blocked_ips.json path is correct in Task

### ✅ Dashboard Section 7 Verification

**Blocked IPs Tab:**
- [ ] Firewall Status column shows one of:
  - `✅ BLOCKED` - IP in firewall blocklist
  - `✅ WHITELISTED (Override)` - IP in firewall whitelist
  - `⏳ Pending Sync` - Waiting for next sync cycle
- [ ] Unblock button removes IP from firewall (verify within 5s on Linux)
- [ ] Whitelist button adds IP to whitelist and removes from blocklist

**Whitelist Tab:**
- [ ] Shows all whitelisted IPs
- [ ] Firewall enforcement status visible
- [ ] Remove from whitelist works correctly

**Linux Firewall Subsection (if implemented):**
- [ ] Backend detected correctly (e.g., "iptables-nft (Debian 12)")
- [ ] Sync status shows "Active (last: Xs ago)"
- [ ] Whitelist sync health: "X/X IPs synchronized ✅"
- [ ] Blocklist sync health: "X/X IPs synchronized ✅"
- [ ] "Force Sync Now" button triggers immediate sync
- [ ] "Test Integration" button passes all tests
- [ ] Customer firewall rules displayed (read-only)
- [ ] Conflict warnings shown if detected

### 🚨 Troubleshooting Checklist

**Linux - Firewall sync service not starting:**
- [ ] Check environment: `grep BH_FIREWALL_SYNC_ENABLED /etc/battle-hardened-ai/.env`
- [ ] Check service logs: `sudo journalctl -u battle-hardened-ai-firewall-sync -n 50`
- [ ] Verify permissions: `ls -l /var/lib/battle-hardened-ai/server/json/*.json`
- [ ] Check ipset exists: `which ipset` and `sudo ipset list`

**Linux - IPs not syncing to firewall:**
- [ ] Verify JSON files updating: `tail -f /var/lib/battle-hardened-ai/server/json/blocked_ips.json`
- [ ] Check sync daemon running: `ps aux | grep bh_firewall_sync`
- [ ] Check for iptables errors: `sudo journalctl -u battle-hardened-ai-firewall-sync | grep -i error`
- [ ] Verify ipset not full: `sudo ipset list bh_blocked | grep "Number of entries"`

**Linux - Whitelist not taking priority:**
- [ ] Verify rule order: `sudo iptables -L INPUT -n --line-numbers | head -10`
  - Whitelist ACCEPT should be line 1
  - Blocklist DROP should be line 2
- [ ] Check ipset contents: `sudo ipset list bh_whitelist`
- [ ] Test manually: `sudo ipset test bh_whitelist 1.2.3.4`

**Windows - PowerShell script fails:**
- [ ] Check execution policy: `Get-ExecutionPolicy` (should be RemoteSigned or Bypass)
- [ ] Verify JSON path exists: `Test-Path "$env:LOCALAPPDATA\Battle-Hardened AI\server\json\blocked_ips.json"`
- [ ] Run script manually with `-Verbose` flag
- [ ] Check Windows Firewall service: `Get-Service -Name mpssvc`

**Windows - Task Scheduler not running:**
- [ ] Check task enabled: Open Task Scheduler → Find task → Check "Enabled"
- [ ] View task history: Right-click task → History
- [ ] Verify trigger configured correctly
- [ ] Test run manually: Right-click → Run

---

## 3. Notes and Limitations

### Architecture

- **Dual-layer enforcement:** Whitelist (ACCEPT, priority 1) processed before blocklist (DROP, priority 2)
- **Automatic sync:** Dashboard changes reflect in firewall within 5 seconds (Linux) or 1 minute (Windows Task Scheduler)
- **Safety guarantee:** IP in both whitelist and blocklist = ACCEPTED (whitelist wins)
- **No manual intervention:** Firewall rules managed automatically by sync daemon

### Platform-Specific Notes

**Linux gateway deployment:**
- ipset/iptables rules affect all traffic passing through the gateway (INPUT + FORWARD chains)
- Protects entire network segment behind the gateway
- Requires 2 NICs and IP forwarding enabled (see Installation.md)

**Linux host-only deployment:**
- Firewall rules protect only the local machine
- INPUT chain only (no FORWARD chain protection)
- For network-wide protection, use gateway deployment

**Windows deployment:**
- Windows Firewall protects only the local machine
- Does NOT protect other LAN devices (Windows rarely acts as router)
- For network-wide protection, use Linux gateway instead
- Enterprise: integrate with GPO/Intune for centralized firewall management

**Distribution compatibility:** See "Linux Firewall Backend Support" table above for detailed compatibility matrix.

### Security Best Practices

- **Test before production:** Always test firewall rules in lab environment first
- **Whitelist critical infrastructure:** Add management IPs, SOC workstations, SIEM collectors to whitelist before enabling
- **Monitor sync health:** Check Section 7 Linux Firewall subsection regularly
- **Avoid lockouts:** Never block your own admin IP without whitelisting it first
- **Backup rules:** Export firewall configuration before enabling Battle-Hardened AI sync
- **Emergency access:** Always have out-of-band management (IPMI, console) available

### Performance Considerations

- **ipset efficiency:** Uses O(1) hash lookups, handles 100,000+ IPs efficiently
- **Sync interval:** 5-second sync provides near real-time enforcement without CPU overhead
- **Memory usage:** ~40 bytes per IP in ipset (10,000 IPs = ~400KB RAM)
- **Rule processing:** Kernel-level filtering (near-zero latency)

### Troubleshooting

For systematic troubleshooting, see the **🚨 Troubleshooting Checklist** above. Common quick fixes:

- **Firewall sync not working:** `sudo journalctl -u battle-hardened-ai-firewall-sync -f`
- **Permission errors:** Verify bhai user can read JSON files
- **Rules disappearing:** Check for conflicting tools (UFW/firewalld auto-management)
- **Locked out:** Boot single-user mode, run `ipset destroy bh_blocked && ipset destroy bh_whitelist`

### Related Documentation

- [Installation.md](../installation/Installation.md) - Initial setup and deployment modes
- [Dashboard.md](../mapping/Dashboard.md) - Section 7 IP Management interface
- [Debian-checklist.md](../checklist/Debian-checklist.md) - Post-installation verification
- [Attack_handling_flow.md](../architecture/Attack_handling_flow.md) - Complete threat response pipeline

---

**Last Updated:** February 2026  
**Applies to:** Battle-Hardened AI v1.0.0+
