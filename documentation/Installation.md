# Battle-Hardened AI - Complete Installation Guide

**Complete installation instructions for Linux, Windows, macOS, and optional Relay Server setup.**

---

## ⚙️ Network Configuration - IP Whitelisting

**If your network uses a different IP segment than the defaults**, you need to whitelist your gateway/router IP to prevent accidental blocking.

### Default Whitelisted IPs (Never Blocked):
- `127.0.0.1`, `localhost`, `::1` - Localhost
- `172.17.0.1`, `172.18.0.1`, `172.19.0.1`, `172.16.0.1` - Docker bridges
- `10.0.0.1` - Common gateway
- `192.168.0.1` - Common home router

### Add Custom IPs (For Different Network Segments):

**Method 1: Edit JSON file directly**
```bash
# Create/edit server/json/whitelist.json
nano server/json/whitelist.json
```

Add your IPs as a JSON array:
```json
[
  "10.0.5.1",
  "172.16.10.1",
  "192.168.1.1",
  "192.168.50.100"
]
```

**Method 2: Use Python API (after installation)**
```python
from AI.pcs_ai import add_to_whitelist

# Add your gateway/trusted IPs
add_to_whitelist("10.0.5.1")
add_to_whitelist("192.168.1.1")
```

**Important:** Only specific IPs are whitelisted, NOT entire ranges. Example: `192.168.0.119` (Kali attacker) WILL be blocked, only `192.168.0.1` (router) is exempt.

---

## 🔐 HMAC Shared Secret Key Required

**To enable encrypted relay communication, obtain the HMAC shared secret key from:**

**Elite Cybersecurity Specialist – 202403184091 (MA0319303)**

**Contact:** Yuhisern Navaratnam  
**WhatsApp:** +60172791717  
**Email:** yuhisern@protonmail.com

Place the `shared_secret.key` file in:
- **Client:** `server/crypto_keys/shared_secret.key`
- **Relay VPS:** `relay/crypto_keys/shared_secret.key`

---

## 🚀 Quick Start - Choose Your Deployment

> **Primary architecture:** Battle-Hardened AI is designed first and foremost for **Linux gateway/edge deployments** (physical or virtual appliances in front of a segment). Windows and macOS installs are supported as **host/appliance** tiers for specific servers or branches, but the canonical 7-stage, 21-layer architecture and firewall enforcement story assume a Linux node at the network boundary.

> **Distribution model:** Production customers normally receive **pre-packaged binaries**, not the GitHub source tree:
> - **Linux gateway/edge nodes:** Installed via a signed **.deb/.rpm package** provided by the vendor.
> - **Windows hosts/appliances:** Installed via the signed **BattleHardenedAI-Setup.exe** installer.
> - **Documentation and helper scripts:** Shipped alongside the packages.
>
> The **`git clone` and source-based commands** in this guide are intended for **development, lab environments, or contributors**. If you have received an official package/installer, follow the **package/installer subsections** for your platform and you can safely ignore any steps that mention cloning from GitHub.

**Who should read what (customers vs developers):**

| Role / Scenario                         | Use these docs primarily                                                                                         |
|-----------------------------------------|-------------------------------------------------------------------------------------------------------------------|
| **Customer operator (Linux appliance)** | This INSTALLATION guide (Linux .deb/.rpm sections), README (high level), FIREWALL_ENFORCEMENT, dashboard docs    |
| **Customer operator (Windows EXE)**     | This INSTALLATION guide (Windows installer/EXE sections), README, FIREWALL_ENFORCEMENT, Windows firewall scripts |
| **Developers / auditors (source)**      | ai-instructions (architecture & pipeline), ARCHITECTURE_COMPLIANCE, dashboard (API details), filepurpose, etc.  |

If you are running the **packaged Linux or Windows builds**, you normally do **not** interact with the full Git source tree; treat the developer/auditor docs as optional deep-dive references rather than required install steps.

### 🖥️ Client Installation (Choose One)

#### Linux (Recommended - Full Features)
- ✅ **Docker**: Network-wide monitoring + full eBPF support
- ✅ **21/21 Detection Layers** at maximum capability (20 detection signals + Step 21 semantic gate)
- ✅ **Easiest Setup**: Single command `docker compose up -d`
- ✅ **Production Ready**: Host mode networking for entire network protection

#### Windows (Native Python Required)
- ⚠️ **Docker Limitation**: Cannot monitor network-wide traffic
- ✅ **Native Python**: Required for network-wide protection
- ✅ **21/21 Detection Layers** (~99% capability - Signal #1 uses Scapy instead of eBPF; Step 21 semantic gate still active)
- ✅ **Requirements**: Python 3.10+, Npcap driver, Administrator privileges
- ✅ **Real Honeypot**: 7 services (SSH, FTP, Telnet, MySQL, HTTP, SMTP, RDP)

#### macOS (Native Python Required)
- ⚠️ **Docker Limitation**: Same as Windows
- ✅ **Native Python**: Required for network-wide protection
- ⚠️ **Not Recommended**: Best for testing/development only

### 🌐 Optional: Relay Server (VPS)
- ✅ **Centralized AI Training** - All customers share same threat intelligence
- ✅ **ExploitDB Integration** - 43,971 exploits automatically loaded
- ✅ **Global Threat Sharing** - P2P encrypted threat distribution
- ✅ **One-Time Setup** - Deploy once, all customers benefit
- 📖 **Setup Guide:** See [relay/RELAY_SETUP.md](relay/RELAY_SETUP.md)

**Platform Decision Guide:**
- **Linux users** → Use Docker (easiest, full features)
- **Windows/macOS users** → Use native Python for network-wide protection
- **Testing only** → Docker works on any platform (limited to container traffic)
- **Multiple customers** → Deploy relay server on VPS (optional)

---

## 📋 Table of Contents

### Client Installation
- [Linux Installation (Docker)](#linux-installation-docker)
- [Windows Installation (Native Python)](#windows-installation-native-python)
- [macOS Installation (Native Python)](#macos-installation-native-python)
- [Detection Capability Comparison](#detection-capability-comparison)

### Relay Server (Optional)
- [Relay Server Setup](#relay-server-setup-optional)
- [Client-Relay Configuration](#client-relay-configuration)

### Post-Installation
- [Verification & Testing](#post-installation)
- [Training & Synchronization](#training--synchronization)
- [Troubleshooting](#troubleshooting)
- [Updating](#updating)
- [Uninstallation](#uninstallation)

---

## Linux Installation (Docker)

### ✅ What You Get
- **21/21 detection layers** at full capability (20 signals + Step 21 semantic gate)
- **7 honeypot services** (SSH, FTP, Telnet, MySQL, HTTP, SMTP, RDP) for network-wide attack detection
- **Kernel-level eBPF** monitoring (Signal #1)
- **Network-wide protection** via Docker host mode
- **Auto-updating ML models** with synthetic training data
- **HTTPS dashboard** on port 60000
- **Optional VPS relay** for global threat sharing

### System Requirements
- Ubuntu 20.04+, Debian 11+, RHEL/CentOS 8+, Fedora 36+, or Kali Linux
- 2 GB RAM (4 GB recommended)
- 2 GB free disk space
- Ports 60000 (Dashboard), 60001 (Relay/P2P - optional)

**Linux Firewall Checklist (Host OS):**
- If you run a host firewall (ufw, firewalld, iptables, cloud security groups), ensure:
   - **Inbound allowed:**
      - TCP 60000 from your admins/SOC (dashboard/API)
      - TCP 2121, 2222, 2323, 3306, 8080, 2525, 3389 from the segments you want the real honeypot to see
   - **Outbound allowed:**
      - TCP 60001 and 60002 from the Battle-Hardened AI node to your relay VPS (WebSocket + HTTPS API), if you use the optional relay.

Example with `ufw` on the Linux gateway/host:

```bash
sudo ufw allow 60000/tcp comment 'Battle-Hardened AI Dashboard'
sudo ufw allow 2121,2222,2323,3306,8080,2525,3389/tcp comment 'Battle-Hardened AI Honeypot'
sudo ufw allow out 60001,60002/tcp comment 'Battle-Hardened AI Relay'
```

### Linux Package Installation (.deb/.rpm – Recommended for customers)

If you received a signed **Battle-Hardened AI Linux package** from the vendor (for example `battle-hardened-ai_*.deb` or `battle-hardened-ai-*.rpm`), use this high-level flow:

1. **Install Docker and Docker Compose** on the gateway/host if they are not already present (follow the commands in **Step 1: Install Docker** below).
2. **Install the package** for your distribution:

   **Debian/Ubuntu/Kali (.deb):**

   ```bash
   sudo dpkg -i battle-hardened-ai_*.deb
   sudo apt-get install -f   # pulls any missing dependencies
   ```

   **RHEL/CentOS/Fedora (.rpm):**

   ```bash
   sudo rpm -ivh battle-hardened-ai-*.rpm
   # or (recommended on newer distros):
   sudo dnf install ./battle-hardened-ai-*.rpm
   ```

3. **Enable and start the service** (the package sets up a systemd unit named `battle-hardened-ai`):

   ```bash
   sudo systemctl enable battle-hardened-ai
   sudo systemctl start battle-hardened-ai
   sudo systemctl status battle-hardened-ai
   ```

4. Once the service reports **active (running)** and the firewall checklist above is satisfied, access the dashboard from an admin/SOC workstation:

   ```text
   https://YOUR_GATEWAY_IP:60000
   ```

The remaining Docker and `git clone` instructions in this section describe a **developer/source installation** from GitHub and are mainly intended for lab setups or contributors.

#### Debian/Ubuntu .deb – Gateway/Host Deployment Details

If you are deploying the **.deb package** on a physical or virtual gateway/host (instead of running from source), the service behaves as a standard Linux appliance with a fixed, documented layout.

The `.deb` is designed primarily for **gateway/edge deployments** (single-node appliance in front of a segment). You can also install it on a single Linux host, but there is no separate "host-only" profile – behavior is the same binary and same services, with advanced operators free to tune `.env` (for example, disabling firewall sync) if they intentionally want a passive, non-enforcing host setup.

**Supported distributions and architecture**
- Debian 12 (bookworm), Ubuntu Server 22.04 LTS
- Architecture: `amd64` (x86_64). Other derivatives may work but are not officially validated yet.

**Python runtime model**
- Uses the system `python3` with an isolated virtual environment under `/opt/battle-hardened-ai/venv`.
- The Debian `postinst` script automatically:
   - Creates the venv at `/opt/battle-hardened-ai/venv`.
   - Installs all Python dependencies from `/opt/battle-hardened-ai/server/requirements.txt` using `pip`.
- Base OS dependencies (managed by `apt` and pulled in automatically when you run `apt-get install -f`):
   - `python3`, `python3-venv`, `systemd`, `iptables`, `ipset`, `curl` (plus standard libraries these depend on).
- Minimum Python version: **3.10+** (tested with the default Python on Debian 12/Ubuntu 22.04).

**Filesystem layout on packaged installs**
- Application code (read-only, owned by root):
   - `/opt/battle-hardened-ai/AI/`
   - `/opt/battle-hardened-ai/server/`
   - `/opt/battle-hardened-ai/policies/`
   - `/opt/battle-hardened-ai/assets/`
- Configuration:
   - `/etc/battle-hardened-ai/.env` – primary configuration file read by the systemd unit via `EnvironmentFile=`.
   - On **first install**, a default `.env` is copied from `/opt/battle-hardened-ai/server/.env` **only if** `/etc/battle-hardened-ai/.env` does not already exist.
   - On **upgrades**, the existing `/etc/battle-hardened-ai/.env` is preserved and not overwritten.
- Runtime data (writable by the `bhai` service user):
   - JSON state: `/var/lib/battle-hardened-ai/server/json/` (all dashboard/API JSON surfaces).
   - ML models: `/var/lib/battle-hardened-ai/AI/ml_models/` (seeded from `/opt/battle-hardened-ai/AI/ml_models/` on first install).
   - Crypto keys: `/var/lib/battle-hardened-ai/server/crypto_keys/` (runtime RSA keys, shared secret, TLS cert/key generated on first install).
   - PCAP captures: `/var/lib/battle-hardened-ai/pcap/`.
- Logs:
   - `/var/log/battle-hardened-ai/` (owned by `bhai:bhai`).
   - Systemd journal (`journalctl -u battle-hardened-ai`) for stdout/stderr from Gunicorn and the app.

**Systemd services installed by the .deb**
- `battle-hardened-ai.service` – main API and dashboard service:
   - Runs Gunicorn from `/opt/battle-hardened-ai/venv/bin/gunicorn`.
   - Uses `BATTLE_HARDENED_PROJECT_ROOT=/opt/battle-hardened-ai` and `BATTLE_HARDENED_DATA_DIR=/var/lib/battle-hardened-ai` so `AI.path_helper` resolves paths correctly.
- `battle-hardened-ai-firewall-sync.service` – optional Linux firewall sync helper:
   - Reads `blocked_ips.json` via `AI.path_helper` and keeps an `ipset` + `iptables` DROP rule set in sync.
   - Requires `ipset` and `iptables` on the host (installed via `apt` dependencies).

Useful commands on a Debian/Ubuntu gateway:

```bash
sudo systemctl status battle-hardened-ai
sudo systemctl status battle-hardened-ai-firewall-sync

sudo journalctl -u battle-hardened-ai -n 50 --no-pager
sudo journalctl -u battle-hardened-ai-firewall-sync -n 50 --no-pager
```

**Editing configuration on packaged installs**

To change network interface, relay URL, or other settings used by the packaged service, edit the managed `.env` file under `/etc` (do **not** edit the copy under `/opt`):

```bash
sudo nano /etc/battle-hardened-ai/.env
```

Common settings to review:
- `NETWORK_INTERFACE=eth0` (or your primary gateway NIC)
- `RELAY_ENABLED=false` / `true`
- `RELAY_URL=wss://YOUR_VPS_IP:60001` (if using the optional relay)
- `BH_FIREWALL_SYNC_ENABLED=true` (should normally be `true` on Linux gateways so the firewall sync service enforces blocks)

After making changes, reload the service:

```bash
sudo systemctl restart battle-hardened-ai
sudo systemctl restart battle-hardened-ai-firewall-sync
```

#### Building the .deb from source (developers only)

If you are a developer or auditor working from the Git repository and want to build the Debian package yourself, use a clean Debian 12 or Ubuntu 22.04 build environment:

```bash
sudo apt-get update
sudo apt-get install -y build-essential debhelper devscripts dpkg-dev python3 python3-venv

cd /path/to/battle-hardened-ai/packaging/debian
dpkg-buildpackage -us -uc
```

This produces a file like `battle-hardened-ai_*.deb` one level up (in the repository root). You can also run the same commands inside a Debian Docker container mounted over the repo if you are building from Windows.

To install the locally built package on a Debian/Ubuntu gateway or host:

```bash
sudo dpkg -i battle-hardened-ai_*.deb
sudo apt-get install -f   # pulls any missing dependencies

sudo systemctl enable battle-hardened-ai battle-hardened-ai-firewall-sync
sudo systemctl start battle-hardened-ai battle-hardened-ai-firewall-sync
sudo systemctl status battle-hardened-ai
```

### Step 1: Install Docker

**Ubuntu / Debian / Kali Linux:**

```bash
# Update system
sudo apt-get update

# Install prerequisites
sudo apt-get install -y ca-certificates curl gnupg

# Add Docker's official GPG key
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

# Add Docker repository
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Install Docker
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Start Docker service
sudo systemctl start docker
sudo systemctl enable docker

# Add your user to docker group (avoid needing sudo)
sudo usermod -aG docker $USER

# Apply group changes (logout/login or run this)
newgrp docker

# Verify Docker works
docker --version
docker compose version
docker ps
```

**RHEL / CentOS / Fedora:**

```bash
# Install Docker
sudo dnf -y install dnf-plugins-core
sudo dnf config-manager --add-repo https://download.docker.com/linux/fedora/docker-ce.repo
sudo dnf install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Start Docker
sudo systemctl start docker
sudo systemctl enable docker

# Add user to docker group
sudo usermod -aG docker $USER
newgrp docker

# Verify
docker --version
docker compose version
docker ps
```

### Step 2: Install Battle-Hardened AI (Developer / from GitHub source)

```bash
# Clone repository
git clone https://github.com/YOUR_USERNAME/battle-hardened-ai.git
cd battle-hardened-ai/server

# Create configuration (optional - for VPS relay)
cat > .env << 'EOF'
TZ=Asia/Kuala_Lumpur
NETWORK_INTERFACE=eth0
RELAY_ENABLED=false
# RELAY_URL=wss://YOUR_VPS_IP:60001
RELAY_CRYPTO_ENABLED=true
EOF

# Build and start (takes 3-5 minutes first time)
docker compose up -d --build

# Wait for startup
sleep 15

# Check status
docker ps
# Expected: battle-hardened-ai Up (healthy) 0.0.0.0:60000-60001

# Verify training completed
docker logs battle-hardened-ai --tail 30
# Look for:
# [AI] ✅ Anomaly Detector trained on synthetic data
# [AI] ✅ Threat Classifier trained: 10 classes
# [RELAY] WebSocket relay client loaded
```

### Step 3: Access Dashboard

Open browser: **https://localhost:60000**

Accept SSL certificate warning (self-signed certificate).

**✅ Installation Complete!** Dashboard should show 0 threats and 20 green detection signals.

---

## Windows Installation (Native Python)

> **Important:** Production customers normally use the **signed Windows installer** (`BattleHardenedAI-Setup.exe`) distributed by the vendor and **do not need to install Python or clone from GitHub**. The `Native Python` steps below are primarily for **development, labs, and advanced operators**. For packaged installs, skip to **Windows .exe Installer – Post-Install Configuration** and follow those instructions instead.

### ✅ What You Get
- **20/20 detection signals** (Signal #1 uses Scapy = ~99% vs Linux 100%)
- **Network-wide protection** via promiscuous mode
- **Real honeypot** with 7 services (SSH, FTP, Telnet, MySQL, HTTP, SMTP, RDP)
- **HTTPS dashboard** with auto-generated SSL certificates
- **Local attack logging** + optional relay server integration

### System Requirements

**Minimum (Testing/Home Network):**
- **CPU**: 4 cores (auto-creates 9 workers = ~250-500 connections)
- **RAM**: 8 GB
- **Storage**: 20 GB free
- **Network**: 100 Mbps
- **OS**: Windows 10 (build 19041+) or Windows 11
- **Python**: 3.10 or higher
- **Privileges**: Administrator (required for network monitoring + firewall)

**Recommended (Small Business/Production):**
- **CPU**: 8 cores (auto-creates 17 workers = ~500-1,000 connections)
- **RAM**: 16 GB
- **Storage**: 50 GB free
- **Network**: 1 Gbps
- **OS**: Windows Server 2019+ or Windows 11 Pro
- **Python**: 3.11+
- **Privileges**: Administrator

**Enterprise (Large Networks):**
- **CPU**: 16+ cores (auto-creates 33+ workers = ~1,000-2,000 connections)
- **RAM**: 32+ GB
- **Storage**: 100+ GB SSD
- **Network**: 10 Gbps
- **OS**: Windows Server 2022
- **Python**: 3.11+
- **Privileges**: Administrator

**🔧 How Auto-Scaling Works:**

The system **automatically detects your CPU cores** and calculates optimal workers:

**Formula**: `(CPU cores × 2 + 1) workers × 4 threads × ~250 connections/thread`

**Real Examples - What "Concurrent Connections" Means:**

**Concurrent Connections = Number of attackers hitting you AT THE SAME TIME**

| Your CPU | Auto Workers | Threads | **Max SIMULTANEOUS Attacks** | Real-World Example |
|----------|-------------|---------|------------------------------|-------------------|
| 4 cores | 9 workers | 36 threads | **~250-500** | 500 Nmap scans at once, or 250 honeypot connections simultaneously |
| 8 cores | 17 workers | 68 threads | **~500-1,000** | Small DDoS (1,000 bots), or 500 different IPs attacking at exact same moment |
| 16 cores | 33 workers | 132 threads | **~1,000-2,000** | Medium DDoS, or entire corporate network (1,000+ devices) under attack |
| 32 cores | 65 workers | 260 threads | **~2,000-4,000** | Large DDoS, or national-scale attack (thousands of bots) |

**Windows OS Limit**: ~10,000 max connections (TCP/IP stack limitation)

**Real Attack Scenarios:**

1. **Single Attacker (Low Load)**
   - 1 Kali machine running Nmap = ~10-50 concurrent connections
   - ✅ Any CPU can handle this easily

2. **Multiple Attackers (Medium Load)**
   - 10 attackers each running 50 scans = 500 concurrent connections
   - ✅ 8-core CPU handles this comfortably

3. **Small DDoS Attack (High Load)**
   - 1,000 botnet IPs each making 1 connection = 1,000 concurrent connections
   - ✅ 8-16 core CPU required

4. **Large DDoS Attack (Extreme Load)**
   - 10,000 botnet IPs flooding = 10,000 concurrent connections
   - ⚠️ Windows limit reached (need Linux + extreme config for this scale)

**Important:** "Concurrent" means **at the exact same moment** - not total attacks per day/hour.

Example: Your 8-core system can handle:
- ✅ **1,000 concurrent connections** = 1,000 attackers RIGHT NOW
- ✅ **1,000,000 total attacks per day** = logged over 24 hours (no problem)

**You don't configure anything** - the Windows production launcher (either the native `installation/watchdog.py` script during development, or the packaged `BattleHardenedAI.exe` in production installs) automatically:
1. Detects your CPU cores using Python's `multiprocessing.cpu_count()` logic baked into the server
2. Calculates optimal worker count
3. Spawns workers with crash protection
4. Auto-restarts failed workers
5. Prevents memory leaks (workers recycle after 1,000 requests)

### Step 1: Install Python

1. Download Python 3.10+ from: https://www.python.org/downloads/
2. Run installer:
   - ✅ Check **"Add Python to PATH"**
   - Click **"Install Now"**
3. Verify in PowerShell:
```powershell
python --version
# Should show: Python 3.10.x or higher
```

### Step 2: Install Npcap Driver

**Required for network packet capture (enables Scapy)**

1. Download: https://npcap.com/#download (~5 MB)
2. Run installer (Administrator required):
   - ✅ Check **"Install Npcap in WinPcap API-compatible Mode"**
   - ✅ Check **"Support loopback traffic"** (recommended)
   - Click **Install**
3. **Restart computer** after installation

**What Npcap provides:**
- Raw socket access for packet capture
- Promiscuous mode (network-wide monitoring)
- 802.11 wireless monitoring support

### Step 3: Clone Repository and Install Dependencies

Open **PowerShell** (regular user):

```powershell
# Clone repository
git clone https://github.com/YOUR_USERNAME/battle-hardened-ai.git
cd battle-hardened-ai

# Create virtual environment (recommended)
python -m venv .venv
.venv\Scripts\Activate.ps1

# Install Python dependencies
cd server
pip install -r requirements.txt

# Initialize JSON data files (CRITICAL - creates all required files)
python installation\init_json_files.py

# Verify Scapy works with Npcap
python -c "from scapy.all import sniff; print('✅ Scapy working')"
```

#### Understanding JSON Initialization

**What `init_json_files.py` does:**
- Creates `server/json/` directory with **35+ required JSON files**
- Initializes honeypot_attacks.json, threat_log.json, blocked_ips.json, and more
- Works on any installation location (Windows/Linux/macOS) using absolute paths
- Safe to run multiple times (won't overwrite existing files)
- **Auto-runs on Docker startup** (via entrypoint.sh)
- **Auto-runs on server startup** (via server.py)

**Files Created (Organized by Pipeline Stage):**

1. **Stage 1 - Network Discovery** (3 files)
   - connected_devices.json, device_history.json, network_monitor_state.json

2. **Stage 2 - Threat Detection** (15 files)
   - threat_log.json, honeypot_attacks.json, dns_security.json
   - behavioral_metrics.json, file_analysis.json, tls_fingerprints.json
   - crypto_mining.json, tracked_users.json, network_performance.json
   - network_graph.json, trust_graph.json, tracking_data.json
   - lateral_movement_alerts.json, attack_sequences.json, integrity_violations.json

3. **Stage 3 - AI Decision Making** (4 files)
   - decision_history.json, meta_engine_config.json
   - fp_filter_config.json, causal_analysis.json

4. **Stage 4 - Response & Audit** (6 files)
   - blocked_ips.json, blocked_devices.json, blocked_peers.json
   - whitelist.json, comprehensive_audit.json, approval_requests.json

5. **Stage 5 - Learning & Refinement** (3 files)
   - honeypot_patterns.json, local_threat_intel.json, reputation_export.json

6. **Stage 6 - P2P Sharing** (1 file)
   - peer_threats.json

7. **Stage 7 - Continuous Learning** (5 files)
   - ml_training_data.json, ml_performance_metrics.json
   - model_lineage.json, drift_baseline.json, drift_reports.json

8. **Enterprise Extensions (Auxiliary / Optional)** (4 files)
   - backup_status.json, soar_incidents.json, cloud_findings.json, sbom.json

9. **Subdirectories**
   - forensic_reports/, compliance_reports/, audit_archive/

**GitHub Clone Behavior:**
- GitHub excludes `*.json` files via `.gitignore` (prevents runtime data in repo)
- On fresh clone, `server/json/` is empty
- **Without initialization**, honeypot/threat logging will fail
- `init_json_files.py` solves this by auto-creating all files

**Integration Points:**
- **Docker:** Automatically runs via `entrypoint.sh`
- **Native:** Automatically runs on `server.py` startup
- **Manual:** Run `python installation/init_json_files.py` anytime

### Step 4: Configure Windows Firewall

**⚠️ CRITICAL - Run PowerShell as Administrator (Required)**

**Understanding Windows Network Profiles:**
- Windows has 3 network profiles: **Public**, **Private**, **Domain**
- **Public networks** (most Wi-Fi) block ALL inbound connections by default for security
- Firewall rules MUST include `-Profile Any` to work on Public networks
- This is NOT a bug - it's Windows security by design

**Add Firewall Rules (Administrator PowerShell):**

```powershell
# Delete old rules if they exist (in case you created them without -Profile Any)
Remove-NetFirewallRule -DisplayName "Battle-Hardened AI Honeypot" -ErrorAction SilentlyContinue
Remove-NetFirewallRule -DisplayName "Battle-Hardened AI Dashboard" -ErrorAction SilentlyContinue

# Create NEW rules with -Profile Any (works on ALL network types including Public)
New-NetFirewallRule -DisplayName "Battle-Hardened AI Honeypot" `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort 2121,2222,2323,3306,8080,2525,3389 `
    -Action Allow `
    -Profile Any `
    -Enabled True

New-NetFirewallRule -DisplayName "Battle-Hardened AI Dashboard" `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort 60000 `
    -Action Allow `
    -Profile Any `
    -Enabled True

# Verify rules are created with correct profile
Get-NetFirewallRule -DisplayName "*Battle-Hardened*" | Select-Object DisplayName, Profile, Enabled
```

**Expected output:**
```
DisplayName                      Profile Enabled
-----------                      ------- -------
Battle-Hardened AI Dashboard     Any        True
Battle-Hardened AI Honeypot      Any        True
```

**⚠️ If you already created the rules earlier (without -Profile Any):**

```powershell
# Update existing rules to work on ALL profiles including Public
Set-NetFirewallRule -DisplayName "Battle-Hardened AI Honeypot" -Profile Any -Enabled True
Set-NetFirewallRule -DisplayName "Battle-Hardened AI Dashboard" -Profile Any -Enabled True

# Verify the fix
Get-NetFirewallRule -DisplayName "*Battle-Hardened*" | Select-Object DisplayName, Profile, Enabled
# Profile should now show "Any"
```

**Why `-Profile Any` is Required:**

Without `-Profile Any`, the firewall rule defaults to Domain + Private profiles only.

| Scenario | Without `-Profile Any` | With `-Profile Any` |
|----------|----------------------|---------------------|
| **Public Wi-Fi** (coffee shop, home) | ❌ BLOCKED | ✅ ALLOWED |
| **Private network** | ✅ ALLOWED | ✅ ALLOWED |
| **Domain network** (enterprise) | ✅ ALLOWED | ✅ ALLOWED |

**For ENTERPRISE/ORGANIZATIONAL environments:**

Organizations typically use Domain or Private network profiles, so `-Profile Any` rules work without issues. However:

1. **Security Review Required** - IT/Security must approve inbound ports:
   - Honeypot ports (2121, 2222, 2323, etc.) accept external connections
   - Document purpose: Network intrusion detection system (NIDS)
   - Show this is a security monitoring tool, not a production service

2. **Best Practice - Deploy on Dedicated Security Appliance:**
   - Windows Server VM or physical security device
   - Connected to network SPAN/mirror port (passive monitoring)
   - Isolated from production network
   - Managed by Security Operations Center (SOC)

3. **Alternative - Use Linux Instead:**
   - No Public/Private network profile restrictions
   - Full Docker support with host networking
   - Better eBPF support (100% capability vs Windows 98%)
   - Industry standard for network security appliances

**Why Honeypot Ports Must Accept Inbound:**
- Honeypot services **intentionally** accept connections from attackers
- This is how the system detects and logs attack attempts
- Without inbound access, honeypot cannot function (no attacks logged)
- Similar to how Intrusion Detection Systems (IDS) work

**Why firewall rules are required:**
- Honeypot services must accept **incoming connections from external attackers**
- Windows Firewall **blocks inbound connections by default**
- Without these rules, external telnet/nmap attempts will hang on "Trying..."

**Honeypot Ports (must accept inbound traffic):**
- **2121** (FTP), **2222** (SSH), **2323** (Telnet)
- **3306** (MySQL), **8080** (HTTP), **2525** (SMTP), **3389** (RDP)

### Handling Antivirus / EDR False Positives (Windows)

Battle-Hardened AI for Windows is designed to run **with** enterprise security controls enabled. You should **not** disable antivirus or EDR during installation or runtime.

If a particular AV/EDR product flags `BattleHardenedAI-Setup.exe` (installer) or the installed `BattleHardenedAI.exe` as a false positive:

1. **Keep protection enabled** – Do not turn off AV/EDR for the entire host.
2. Add narrow allowlist/exception rules for the signed binaries and paths only.

#### 2) In an enterprise EDR/AV console (generic steps)

In your EDR/AV management portal (Defender for Endpoint, CrowdStrike, SentinelOne, Cortex XDR, etc.):

- Go to the **policy** or **exclusions/allowlist** section.
- Add an exception by:
   - **File hash** (recommended for production builds), and/or
   - **Path**: `C:\Program Files\Battle-Hardened AI\BattleHardenedAI.exe` and the installer filename you distribute (for example, `BattleHardenedAI-Setup.exe`).
- Apply the policy to the relevant device group(s).
- Keep protection enabled; only this signed binary and path are allowed.

This pattern keeps AV/EDR fully active for the rest of the system, while explicitly authorizing the Battle-Hardened AI binaries used as a first-layer defense node.

### Windows .exe Installer – Post-Install Configuration

If you install Battle-Hardened AI using the **Windows GUI installer** (`BattleHardenedAI-Setup.exe`), complete these steps **after** the setup finishes:

1. **Locate the install directory**  
   Default path: `C:\Program Files\Battle-Hardened AI\`

2. **Edit the installed `.env.windows` file** in that directory and set at minimum:
   - `RELAY_URL` – your relay WebSocket endpoint, e.g. `wss://YOUR_VPS_OR_DOMAIN:60001`  
   - `RELAY_API_URL` – your relay HTTPS API endpoint, e.g. `https://YOUR_VPS_OR_DOMAIN:60002`  
   - `CUSTOMER_ID` – the unique customer identifier provided to you  
   - `PEER_NAME` – a friendly node name (e.g. `branch-office-1`, `dc-core-01`)  
   - `BATTLE_HARDENED_SECRET_KEY` – replace `CHANGE_ME_TO_A_LONG_RANDOM_VALUE` with a long, random string; keep it secret and consistent across restarts (and across nodes, if you cluster).

   Optionally, adjust:
   - `TZ` – your timezone (e.g. `Asia/Kuala_Lumpur`)  
   - `DASHBOARD_PORT` / `P2P_PORT` – only if your environment requires different ports.

3. **Obtain the HMAC shared secret key (relay authentication)**  
   Follow the instructions in **“HMAC Shared Secret Key Required”** at the top of this document and request the key from the Cybersecurity Specialist. You will receive a file named `shared_secret.key` **out-of-band** (it is **not** included in the installer).

4. **Place `shared_secret.key` in the crypto directory**  
   - Create the directory `server\crypto_keys\` under the install path if it does not exist.  
   - Copy the key file to:  
     `C:\Program Files\Battle-Hardened AI\server\crypto_keys\shared_secret.key`

   This path matches the default `MESSAGE_SECURITY_KEY_DIR=server/crypto_keys` used by the Windows build.

Once `.env.windows` is configured and `shared_secret.key` is in place, you can start Battle-Hardened AI either via the Start Menu shortcut created by the installer or by launching `BattleHardenedAI.exe` directly from the install directory.

### Step 5: Run Battle-Hardened AI

**⚠️ Must run PowerShell as Administrator**

#### 🧪 Development Mode (Testing Only - Single Process)

**Use for:** Quick testing with 1-10 concurrent connections

**⚠️ WARNING**: Will crash under load - DO NOT use in production

```powershell
cd C:\Users\YOUR_USERNAME\workspace\battle-hardened-ai\server
python server.py
```

**Limitations:**
- Single-threaded (no multi-worker)
- Crashes with 50+ concurrent connections
- No auto-restart on crash
- No memory leak protection
- Use ONLY for development/debugging

---

#### 🛡️ Production Mode (Recommended - Multi-Worker with Crash Protection)

**Use for:** Real production environments, handling hundreds of concurrent connections

**✅ Features:**
- **Multi-worker processes** - Auto-scaled based on your CPU cores
- **Auto-restart on crash** - Workers respawn automatically
- **Memory leak protection** - Workers recycle after 1,000 requests
- **Timeout protection** - Kills slow attacks (Slowloris defense)
- **Connection queue** - 2,048 pending connections before dropping
- **Graceful shutdown** - 30-second grace period for existing requests

**Run Production Server (from a clone, development-style):**
```powershell
cd C:\Users\YOUR_USERNAME\workspace\battle-hardened-ai\server
python installation\watchdog.py
```

**Run Production Server (from the Windows installer, recommended for production):**
- Use the Start Menu shortcut created by the installer, or
- Launch `BattleHardenedAI.exe` directly from `C:\Program Files\Battle-Hardened AI` (or your chosen install path).

**What Happens Automatically:**

1. **CPU Detection**: System detects your CPU cores (e.g., 8 cores)
2. **Worker Calculation**: Formula: `(8 × 2) + 1 = 17 workers`
3. **Thread Allocation**: 17 workers × 4 threads = 68 concurrent threads
4. **Capacity**: ~500-1,000 concurrent connections
5. **Crash Protection**: If worker crashes, watchdog respawns it automatically
6. **Memory Recycling**: Each worker restarts after 1,000 requests

**Your Actual Capacity (Based on Your CPU):**

Your system will show something like this on startup:

```
[WATCHDOG] 👁️  Server watchdog started
[WATCHDOG] 📊 Detected 8 CPU cores
[WATCHDOG] 🚀 Starting 17 workers (formula: 8 × 2 + 1)
[WATCHDOG] 💪 Capacity: ~500-1,000 concurrent connections
[WATCHDOG] 🔄 Max restarts per hour: 10
```

**Expected output:**
```
[SSL] ✅ SSL certificates generated (auto-created: ssl_cert.pem, ssl_key.pem)
[CRYPTO] ✅ Lineage signing key generated (auto-created: json/lineage_signing_key.pem)
[HONEYPOT] Starting 7 honeypot services...
[HONEYPOT] ✅ SSH honeypot listening on port 2222
[HONEYPOT] ✅ FTP honeypot listening on port 2121
[HONEYPOT] ✅ Telnet honeypot listening on port 2323
[NETWORK] Starting promiscuous mode monitoring (NETWORK-WIDE PROTECTION)
[AI] ✅ All 20 detection signals initialized
[DASHBOARD] HTTPS server running on https://0.0.0.0:60000
```

**🔐 Auto-Generated Security Files (DO NOT SHARE):**

On first run (whether via `installation\watchdog.py` or the packaged `BattleHardenedAI.exe`), the server automatically creates:
- `server/crypto_keys/ssl_cert.pem` - SSL certificate for HTTPS dashboard (self-signed)
- `server/crypto_keys/ssl_key.pem` - SSL private key (KEEP SECRET)
- `server/json/lineage_signing_key.pem` - Cryptographic lineage signing key (KEEP SECRET)

**These files are auto-generated and already in .gitignore - never commit them to Git.**

**Note:** The relay server encryption keys (for VPS communication) must be manually shared between your client and VPS relay server. See [relay/RELAY_SETUP.md](relay/RELAY_SETUP.md) for details.

### Step 6: Access Dashboard

Open browser: **https://localhost:60000**

Accept self-signed SSL certificate warning.

### Step 7: Test Honeypot

**From another device on your network (e.g., Kali Linux):**

```bash
# Get Windows IP address first
# From Windows PowerShell: ipconfig | Select-String "IPv4"
# Example: 192.168.1.100 (YOUR_WINDOWS_IP)

# Test FTP honeypot (should show "220 FTP Server Ready" banner)
telnet YOUR_WINDOWS_IP 2121

# Test SSH honeypot (should show "SSH-2.0-OpenSSH" banner)
telnet YOUR_WINDOWS_IP 2222

# Full TCP connection scan (use -sT for full connect, not SYN scan)
nmap -sT -p 2121,2222,2323 YOUR_WINDOWS_IP
```

**Check attack logs on Windows:**
- `server\json\honeypot_attacks.json` - Full attack details
- `server\json\honeypot_patterns.json` - Attack patterns
- Dashboard → Section 15: Honeypot Attacks

**⚠️ Troubleshooting "Trying..." Connection Hangs:**

**MOST COMMON ISSUE: Firewall Rules Missing `-Profile Any`**

Windows "Public" networks block ALL inbound connections by default - UNLESS the firewall rule has `-Profile Any`.

**Step 1: Check Your Network Profile**
```powershell
Get-NetConnectionProfile | Select-Object Name, NetworkCategory
```

**Step 2: Check Firewall Rule Profile (Administrator PowerShell)**
```powershell
Get-NetFirewallRule -DisplayName "Battle-Hardened AI Honeypot" | Select-Object DisplayName, Profile, Enabled
```

**If Profile shows "Domain, Private" (NOT "Any") - THIS IS THE PROBLEM:**

```powershell
# FIX: Update existing rules to work on ALL profiles including Public
Set-NetFirewallRule -DisplayName "Battle-Hardened AI Honeypot" -Profile Any -Enabled True
Set-NetFirewallRule -DisplayName "Battle-Hardened AI Dashboard" -Profile Any -Enabled True

# Verify fix
Get-NetFirewallRule -DisplayName "*Battle-Hardened*" | Select-Object DisplayName, Profile, Enabled
# Profile should now show "Any"
```

**After Fixing Firewall, Test Connection:**
```powershell
# Test locally from Windows
Test-NetConnection -ComputerName 127.0.0.1 -Port 2222
# TcpTestSucceeded should be True

# Test from your Windows IP
Test-NetConnection -ComputerName 192.168.68.111 -Port 2222
# TcpTestSucceeded should be True
```

**From Kali Linux:**
```bash
telnet 192.168.68.111 2222
# Should connect immediately and show SSH banner
```

**Other Checks If Still Not Working:**

1. **Check ports are listening:**
   ```powershell
   netstat -an | Select-String "2121|2222|2323"
   # Should show: 0.0.0.0:2121 LISTENING
   ```

2. **Check server is running:**
   ```powershell
   Get-Process python
   # Should show python.exe process
   ```

3. **Check Wi-Fi Router AP Isolation:**
   - Some routers have "AP Isolation" or "Client Isolation" enabled
   - This blocks device-to-device communication on same network
   - Log into router admin panel → Wireless → Advanced → Disable AP Isolation

**✅ Installation Complete!**

---

## macOS Installation (Native Python)

> **Note:** macOS support is primarily for **development and testing** and assumes access to the GitHub source repository. It is **not part of the standard packaged customer distribution** (Linux packages + Windows installer). Treat this section as a developer-only path.

### ✅ What You Get
- Same as Windows (20/20 signals, ~99% capability)
- Network-wide protection via promiscuous mode
- Real honeypot + HTTPS dashboard

### System Requirements
- macOS 11 (Big Sur) or higher
- Python 3.10+
- 2 GB RAM, 2 GB disk
- Administrator access

### Step 1: Install Homebrew

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

### Step 2: Install Python

```bash
brew install python@3.11
python3 --version  # Should show 3.10+
```

### Step 3: Clone Repository and Install Dependencies

```bash
git clone https://github.com/YOUR_USERNAME/battle-hardened-ai.git
cd battle-hardened-ai

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
cd server
pip install -r requirements.txt

# Initialize JSON files
python installation/init_json_files.py
```

### Step 4: Run Battle-Hardened AI

**⚠️ Requires sudo for promiscuous mode:**

```bash
sudo python3 server.py
```

**Expected output:**
```
[SSL] ✅ SSL certificates generated
[CRYPTO] ✅ Lineage signing key generated
[HONEYPOT] Starting 7 honeypot services...
[HONEYPOT] ✅ SSH honeypot listening on port 2222
[NETWORK] Starting promiscuous mode monitoring
[AI] ✅ All 20 detection signals initialized
[DASHBOARD] HTTPS server running on https://0.0.0.0:60000
```

### Step 5: Access Dashboard

Browser: **https://localhost:60000**

**⚠️ Firewall Note:** macOS requires manual firewall configuration:
- System Preferences → Security & Privacy → Firewall → Firewall Options
- Allow incoming connections for Python

**✅ Installation Complete!**

---

## Relay Server Setup (Optional)

### Why Use a Relay Server?

**Problem: Local-Only Training**
- Each customer trains AI on their own attacks only
- Customer A: 100 attacks → AI knows 100 patterns
- Customer B: 200 attacks → AI knows 200 patterns
- **Result:** INCONSISTENT protection ❌

**Solution: Centralized Relay Training**
- Deploy relay server on VPS with ExploitDB (43,971 exploits)
- ALL customers download same centrally-trained models
- Customer A (Day 1): Downloads 43,971 patterns ✅
- Customer B (Month 3): Downloads 43,971 + real-world attacks ✅
- **Result:** EVERYONE protected equally (or better) ✅

### Architecture

```
Customer A (Japan)  ─┐
Customer B (USA)    ─┼─→  Relay Server (VPS)  ←─ ExploitDB (43,971 exploits)
Customer C (Europe) ─┘         │
                               ↓
                     Centralized AI Models
                     (Everyone downloads same models)
```

### Relay Server Deployment

**For detailed relay server setup, see: [relay/RELAY_SETUP.md](relay/RELAY_SETUP.md)**

**Quick Setup:**

```bash
# SSH into your VPS
ssh root@YOUR_VPS_IP

# Clone repository
git clone https://github.com/YOUR_USERNAME/battle-hardened-ai.git
cd battle-hardened-ai/relay

# Start relay server (downloads 43,971 ExploitDB exploits)
docker compose up -d

# Monitor ExploitDB download (takes 5-10 minutes)
docker compose logs -f | grep "ExploitDB"

# Verify relay is ready
curl -k https://YOUR_VPS_IP:60002/health
# Should return: {"status": "healthy", "exploits": 43971}
```

**VPS Requirements:**
- Ubuntu/Debian recommended
- Public IP address
- Ports 60001 (WebSocket), 60002 (API) open
- 4 GB RAM, 2 CPU cores
- 5 GB disk space (for ExploitDB)

---

## Client-Relay Configuration

### Connect Clients to Relay Server

**Option A: Environment Variables (Recommended)**

Create `.env` file in `server/` directory:

```bash
# server/.env
RELAY_ENABLED=true
RELAY_URL=wss://YOUR_VPS_IP:60001
RELAY_API_URL=https://YOUR_VPS_IP:60002
CUSTOMER_ID=customer-unique-id-here
PEER_NAME=customer-location-name
```

**Option B: Docker Compose (Linux)**

Edit `server/docker-compose.yml`:

```yaml
environment:
  - RELAY_ENABLED=true
  - RELAY_URL=wss://YOUR_VPS_IP:60001
  - RELAY_API_URL=https://YOUR_VPS_IP:60002
  - CUSTOMER_ID=customer-123
  - PEER_NAME=japan-office
```

**Restart Client:**

```bash
# Docker
docker compose down && docker compose up -d

# Native Python
# Restart server.py (Ctrl+C then rerun)
```

### Verify Relay Connection

**Check Client Logs:**

```bash
# Docker
docker compose logs --tail=100 | grep "AI\|RELAY"

# Native
# Check terminal output where server.py is running
```

**SUCCESS indicators:**
```
[AI] 🌐 Requesting training from relay server (43,971 ExploitDB exploits)...
[AI] ✅ Relay trained models using 43971 exploits
[AI] 📥 Downloading trained models from relay...
[AI] ✅ Downloaded anomaly detector (280 KB)
[AI] ✅ Downloaded threat classifier (280 KB)
[AI] ✅ Downloaded IP reputation model (280 KB)
[RELAY] ✅ Connected to relay server wss://YOUR_VPS_IP:60001
```

**FAILURE indicators (relay not configured):**
```
[AI] ⚠️  Relay training failed, falling back to local training
[AI] 🎓 AUTO-TRAINING locally with 100 historical threat events...
```

### Dashboard Verification

Open: **https://localhost:60000**

**Section 1 - AI Training Network – Shared Machine Learning:**
- Connection: ✅ Connected
- Last Sync: < 1 second ago
- Shared Attacks: 43,971+ patterns
- Model Version: v1.x.x

**Section 4 - Real AI/ML Models – Machine Learning Intelligence:**
- Training Data Size: Should show **43,971+** (not 100-1000)
- Last Trained: Recent timestamp
- Models Status: All showing "TRAINED ✅"

### Training & Synchronization

#### How Training Works

**Without Relay (Default):**
```
1. Client starts → No models exist
2. Loads threat_log.json (100-1000 local attacks)
3. Trains models locally (30 seconds)
4. Result: AI knows 100-1000 patterns
```

**With Relay (Configured):**
```
1. Client starts → No models exist
2. Calls RELAY_API_URL/train
3. Relay trains using 43,971 ExploitDB exploits (3-5 min)
4. Client downloads 3 model files (280 KB each)
5. Result: AI knows 43,971+ patterns ✅
```

#### Model Update Frequency

**Automatic Updates:**
- Client checks relay every **24 hours**
- Downloads new models if relay version is newer
- No downtime during update

**Manual Retrain:**
```bash
# Force immediate retrain from relay
curl -k -X POST https://localhost:60000/inspector/ai-monitoring/retrain-ml
```

#### Training Data Growth

**Month 1:**
- Relay: 43,971 ExploitDB + 0 real attacks = 43,971 patterns
- New customer downloads 43,971 patterns

**Month 6:**
- Customer A experienced 5,000 attacks
- Customer B experienced 3,000 attacks
- Relay: 43,971 + 8,000 = 51,971 patterns
- New customer downloads 51,971 patterns ✅

**Year 1:**
- 100 customers, avg 1,000 attacks each
- Relay: 43,971 + 100,000 = 143,971 patterns
- New customer downloads 143,971 patterns ✅ (INSTANT EXPERT!)

#### Troubleshooting Relay Training

**Issue: "Relay training failed, falling back to local"**

**Cause:** Can't connect to RELAY_API_URL

**Fix:**
```bash
# Test connection from client machine
curl -k https://YOUR_VPS_IP:60002/health

# If fails, check:
# 1. VPS firewall allows port 60002
# 2. Docker container running on VPS: docker compose ps
# 3. RELAY_API_URL correct in .env file
```

**Issue: Training Data Shows 100-1000 (not 43,971)**

**Cause:** Using local training, relay not connected

**Fix:**
```bash
# Check environment variables (Docker)
docker compose exec battle-hardened-ai env | grep RELAY

# Should show:
# RELAY_ENABLED=true
# RELAY_API_URL=https://YOUR_VPS_IP:60002

# If empty, update .env and restart
docker compose down && docker compose up -d
```

**Issue: Fresh Installation Has 0 Threat Data**

**Cause:** No attacks detected yet, threat_log.json empty

**Solution:**
- **With Relay:** Training uses ExploitDB (43,971 patterns) - no local data needed ✅
- **Without Relay:** Generate attacks to populate threat_log.json:
  ```bash
  # From another machine (e.g., Kali Linux)
  curl -k "https://CLIENT_IP:60000/test?id=1'%20OR%20'1'='1"
  curl -k "https://CLIENT_IP:60000/test?name=<script>alert(1)</script>"
  nmap -sS CLIENT_IP
  # Repeat 10-20 times to build training data
  ```

---

## Post-Installation

### ✅ What You Get
- Same as Windows (20/20 signals, ~99% capability)
- Network-wide protection via promiscuous mode
- Real honeypot + HTTPS dashboard

### System Requirements
- macOS 11 (Big Sur) or higher
- Python 3.10+
- 2 GB RAM, 2 GB disk
- Administrator access

### Step 1: Install Homebrew

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

### Step 2: Install Python

```bash
brew install python@3.11
python3 --version  # Should show 3.10+
```

### Step 3: Clone Repository and Install Dependencies

```bash
git clone https://github.com/YOUR_USERNAME/battle-hardened-ai.git
cd battle-hardened-ai

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
cd server
pip install -r requirements.txt
```

### Step 4: Run Battle-Hardened AI

**⚠️ Requires sudo for promiscuous mode:**

```bash
sudo python3 server.py
```

### Step 5: Access Dashboard

Browser: **https://localhost:60000**

**⚠️ Firewall Note:** macOS requires manual firewall configuration:
- System Preferences → Security & Privacy → Firewall → Firewall Options
- Allow incoming connections for Python

**✅ Installation Complete!**

---

## Detection Capability Comparison

### Platform Capabilities Summary

| Platform | Signal #1 (Kernel) | Signals #2-20 | Total Capability | Network-Wide | Deployment Method |
|----------|-------------------|---------------|------------------|--------------|-------------------|
| **Linux** | ✅ eBPF (100%) | ✅ Full (100%) | **100%** | ✅ Yes | Docker (recommended) |
| **Windows** | ⚠️ Scapy (98%) | ✅ Full (100%) | **~99%** | ✅ Yes | Native Python |
| **macOS** | ⚠️ Scapy (98%) | ✅ Full (100%) | **~99%** | ✅ Yes | Native Python |

### Signal #1 Differences: Linux eBPF vs Windows/macOS Scapy

| Capability | Linux (eBPF) | Windows/macOS (Scapy) |
|------------|-------------|----------------------|
| **Packet capture** | ✅ Kernel-level | ✅ Userland (Npcap/libpcap) |
| **Syscall correlation** | ✅ Process→network mapping | ❌ Limited |
| **Process integrity** | ✅ Kernel verification | ⚠️ Userland only |
| **Attack detection** | 100% | ~98% |

**Practical Impact:**
- **99%+ of attacks are still detected** (Signals #2-20 handle most threats)
- Lost capabilities mainly affect:
  - Advanced rootkit detection (rare)
  - Kernel-level tampering (Signal #18 still works at userland level)
  - Process injection mapping (Signal #4 Privilege Escalation still works)
- **For network-based attacks** (vast majority): No difference in detection

**Bottom Line:** Windows/macOS users get 98-99% detection capability vs Linux 100%.

---

## Post-Installation

### Verify Everything Works

**Linux (Docker):**
```bash
# Check container status
docker ps
# Expected: battle-hardened-ai Up (healthy)

# Check logs
docker logs battle-hardened-ai --tail 50

# Access dashboard
curl -k https://localhost:60000
```

**Windows/macOS (Native):**
```powershell
# Check server is running
Get-Process python  # Windows
ps aux | grep python  # macOS

# Check logs in terminal where server is running

# Access dashboard
curl -k https://localhost:60000  # macOS
curl.exe -k https://localhost:60000  # Windows
```

### Dashboard Sections

Navigate to **https://localhost:60000** and verify all sections:

1. **Threat Overview** - Should show 0 threats initially
2. **20 Detection Signals** - All should be green/active
3. **ML Model Status** - All 5 models trained
4. **Network Statistics** - Live packet capture stats
5. **Top Threats** - Initially empty
6. **Recent Alerts** - Initially empty
7. **Geographic Threat Map** - World map visualization
8. **Attack Timeline** - Initially empty
9. **Blocked IPs** - Initially empty
10. **MITRE ATT&CK Coverage** - 98 techniques covered
11. **Compliance Status** - Regulatory framework compliance
12. **System Resources** - CPU, RAM, disk usage
13. **Relay Status** - Connected (if relay enabled) or Disabled
14. **Explainability Log** - AI decision explanations
15. **Honeypot Attacks** - Attack logs (Windows/macOS only)

### Test Attack Detection

**Simulate attacks from another machine:**

```bash
# Port scan (should trigger Signal #10 Graph Intelligence)
nmap -sS 192.168.X.X

# SQL injection attempt (should trigger multiple signals)
curl "http://192.168.X.X/login?user=admin'--"

# SSH brute force simulation (should trigger Signal #7 LSTM Sequences)
# (requires SSH service running on target)
```

Check dashboard for detected threats.

---

## Troubleshooting

### Common Issues

#### 1. Docker: "Cannot connect to Docker daemon"

**Linux:**
```bash
# Start Docker service
sudo systemctl start docker

# Enable on boot
sudo systemctl enable docker

# Add user to docker group
sudo usermod -aG docker $USER
newgrp docker
```

**Windows/macOS:**
- Start Docker Desktop application
- Wait for "Docker is running" notification

#### 2. Windows: "Npcap not found" or Scapy errors

```powershell
# Reinstall Npcap from: https://npcap.com/#download
# Ensure "WinPcap API-compatible mode" is checked

# Verify installation
python -c "from scapy.all import sniff; print('OK')"
```

#### 3. Windows: Telnet shows "Trying..." forever

**Cause:** Windows Firewall blocking inbound connections

**Solution:**
```powershell
# Run as Administrator
Get-NetFirewallRule -DisplayName "*Battle-Hardened*"

# If not found, add rules:
New-NetFirewallRule -DisplayName "Battle-Hardened AI Honeypot" `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort 2121,2222,2323,3306,8080,2525,3389 `
    -Action Allow
```

**Also check:**
- Router AP Isolation (blocks device-to-device communication)
- Windows network profile (Public networks are more restrictive)

#### 4. Port already in use

```bash
# Linux: Find process using port 60000
sudo lsof -i :60000
sudo kill -9 <PID>

# Windows: Find and kill process
netstat -ano | Select-String "60000"
Stop-Process -Id <PID> -Force
```

#### 5. ML Models not training

```bash
# Check logs for training errors
docker logs battle-hardened-ai | grep -E "ML|TRAINED|synthetic"

# Rebuild container (fix should be in latest code)
cd battle-hardened-ai/server
git pull
docker compose down
docker compose up -d --build
```

#### 6. SSL Certificate errors

**Expected:** Self-signed certificates show browser warnings

**Solution:** Click "Advanced" → "Proceed to localhost (unsafe)"

**For production:** Replace with real certificates:
```bash
# Place certificates in server/crypto_keys/
server/crypto_keys/ssl_cert.pem
server/crypto_keys/ssl_key.pem
```

---

## Updating

> **Package-based installs:** If you installed Battle-Hardened AI using a vendor-provided **.deb/.rpm package** on Linux or the **Windows installer (.exe)**, prefer updating via your **OS package manager** or the latest installer from the vendor. The commands below assume a **source-based deployment** where you cloned the GitHub repository directly.

### Update Process

**Linux (Docker):**
```bash
cd battle-hardened-ai/server

# Pull latest code
git pull

# Rebuild and restart
docker compose down
docker compose up -d --build

# Verify
docker logs battle-hardened-ai --tail 50
```

**Windows/macOS (Native Python):**
```powershell
cd battle-hardened-ai

# Pull latest code
git pull

# Update dependencies
cd server
pip install -r requirements.txt --upgrade

# Restart server (Production Mode)
# (Stop current process with Ctrl+C, then restart)
python installation\watchdog.py
```

### Backup Before Update

**Linux (Docker):**
```bash
# Backup threat logs and ML models
docker cp battle-hardened-ai:/app/ml_models ./backup_ml_models
docker cp battle-hardened-ai:/app/json ./backup_json

# After update, restore if needed
docker cp ./backup_ml_models/. battle-hardened-ai:/app/ml_models/
docker cp ./backup_json/. battle-hardened-ai:/app/json/
```

**Windows/macOS:**
```powershell
# Backup directories
Copy-Item -Recurse server/ml_models ./backup_ml_models
Copy-Item -Recurse server/json ./backup_json

# After update, restore if needed
Copy-Item -Recurse ./backup_ml_models/* server/ml_models/
Copy-Item -Recurse ./backup_json/* server/json/
```

---

## Uninstallation

> **Package-based installs:** For Linux deployments installed via **.deb/.rpm**, remove Battle-Hardened AI using your distribution's package manager (for example `sudo apt-get remove battle-hardened-ai` or `sudo dnf remove battle-hardened-ai`) and stop/disable the `battle-hardened-ai` systemd service. The commands in this section focus on cleaning up **source-based installs** created from a GitHub clone.

### Complete Removal

**Linux (Docker):**
```bash
# Stop and remove container
cd battle-hardened-ai/server
docker compose down

# Remove images
docker rmi battle-hardened-ai:latest

# Remove repository
cd ../..
rm -rf battle-hardened-ai

# Clean Docker system (optional - removes unused images)
docker system prune -a
```

**Windows (Native Python):**
```powershell
# Remove firewall rules
Remove-NetFirewallRule -DisplayName "Battle-Hardened AI Honeypot"
Remove-NetFirewallRule -DisplayName "Battle-Hardened AI Dashboard"

# Remove repository
Remove-Item -Recurse -Force battle-hardened-ai

# Uninstall Npcap (optional)
# Control Panel → Programs → Uninstall Npcap
```

**macOS:**
```bash
# Remove repository
rm -rf battle-hardened-ai

# Uninstall Python packages (if using system Python)
pip uninstall -y -r server/requirements.txt
```

---

## Support & Resources

### Documentation
- **[README.md](README.md)** - Features, architecture, MITRE ATT&CK coverage
- **[relay/RELAY_SETUP.md](relay/RELAY_SETUP.md)** - VPS relay server setup (detailed guide)
- **[testconnection.md](testconnection.md)** - Client relay troubleshooting
- **[Dashboard](Dashboard.md)** - Dashboard features and usage
- **[ai-abilities.md](ai-abilities.md)** - AI capabilities and detection logic

### Quick Commands Reference

**Linux (Docker):**
```bash
# Start
docker compose up -d

# Stop
docker compose down

# Restart
docker compose restart

# Logs
docker logs -f battle-hardened-ai

# Update
git pull && docker compose up -d --build

# Enter container
docker exec -it battle-hardened-ai bash
```

**Windows/macOS (Native):**
```powershell
# Start (Administrator PowerShell - Production Mode)
python installation\watchdog.py

# Start (Development Mode - Testing Only)
python server.py

# Stop
Ctrl+C

# Update
git pull
pip install -r server/requirements.txt --upgrade

# Check status
Get-Process python  # Windows
ps aux | grep python  # macOS
```

### Getting Help

**Before asking for help, collect this information:**

1. **Platform:** Linux/Windows/macOS
2. **Deployment:** Docker or Native Python
3. **Logs:**
   ```bash
   # Linux Docker
   docker logs battle-hardened-ai --tail 100 > logs.txt
   
   # Windows/macOS Native
   # Copy terminal output where server is running
   ```
4. **Versions:**
   ```bash
   # Linux
   docker --version
   docker compose version
   
   # Windows/macOS
   python --version
   pip list | grep -E "scapy|tensorflow|scikit-learn"
   ```

**Submit Issues:**
- GitHub Repository: https://github.com/yuhisern7/battle-hardened-ai
- Include logs, platform info, and steps to reproduce

---

**Last Updated:** January 11, 2026  
**Version:** 3.0  
**Compatibility:**
- Docker 20.10+, Docker Compose v2.0+
- Python 3.10+, Npcap 1.70+ (Windows), libpcap (macOS)
