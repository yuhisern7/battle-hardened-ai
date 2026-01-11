# Battle-Hardened AI - Installation Guide

Complete installation instructions for Linux, Windows, and macOS.

---

## 🚀 Quick Start - Choose Your Platform

### Linux (Recommended - Full Features)
- ✅ **Docker**: Network-wide monitoring + full eBPF support
- ✅ **20/20 Detection Signals** at maximum capability (100%)
- ✅ **Easiest Setup**: Single command `docker compose up -d`
- ✅ **Production Ready**: Host mode networking for entire network protection

### Windows (Native Python Required)
- ⚠️ **Docker Limitation**: Cannot monitor network-wide traffic
- ✅ **Native Python**: Required for network-wide protection
- ✅ **20/20 Detection Signals** (~99% capability - Signal #1 uses Scapy instead of eBPF)
- ✅ **Requirements**: Python 3.10+, Npcap driver, Administrator privileges
- ✅ **Real Honeypot**: 7 services (SSH, FTP, Telnet, MySQL, HTTP, SMTP, RDP)

### macOS (Native Python Required)
- ⚠️ **Docker Limitation**: Same as Windows
- ✅ **Native Python**: Required for network-wide protection
- ⚠️ **Not Recommended**: Best for testing/development only

**Platform Decision Guide:**
- **Linux users** → Use Docker (easiest, full features)
- **Windows/macOS users** → Use native Python for network-wide protection
- **Testing only** → Docker works on any platform (limited to container traffic)

---

## 📋 Table of Contents

- [Linux Installation (Docker)](#linux-installation-docker)
- [Windows Installation (Native Python)](#windows-installation-native-python)
- [macOS Installation (Native Python)](#macos-installation-native-python)
- [Detection Capability Comparison](#detection-capability-comparison)
- [Post-Installation](#post-installation)
- [Troubleshooting](#troubleshooting)
- [Updating](#updating)
- [Uninstallation](#uninstallation)

---

## Linux Installation (Docker)

### ✅ What You Get
- **20/20 detection signals** at full capability
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
- Ports 60000 (Dashboard), 60001 (Relay - optional)

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

### Step 2: Install Battle-Hardened AI

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

### ✅ What You Get
- **20/20 detection signals** (Signal #1 uses Scapy = ~99% vs Linux 100%)
- **Network-wide protection** via promiscuous mode
- **Real honeypot** with 7 services (SSH, FTP, Telnet, MySQL, HTTP, SMTP, RDP)
- **HTTPS dashboard** with auto-generated SSL certificates
- **Local attack logging** + optional VPS relay

### System Requirements
- Windows 10 (build 19041+) or Windows 11
- Python 3.10 or higher
- 2 GB RAM (4 GB recommended)
- 2 GB free disk space
- **Administrator privileges** (required for network monitoring + firewall)

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

# Verify Scapy works with Npcap
python -c "from scapy.all import sniff; print('✅ Scapy working')"
```

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

### Step 5: Run Battle-Hardened AI

**⚠️ Must run PowerShell as Administrator:**

```powershell
cd C:\Users\YOUR_USERNAME\workspace\battle-hardened-ai\server
python server.py
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

On first run, the server automatically creates:
- `server/ssl_cert.pem` - SSL certificate for HTTPS dashboard (self-signed)
- `server/ssl_key.pem` - SSL private key (KEEP SECRET)
- `server/json/lineage_signing_key.pem` - Cryptographic lineage signing key (KEEP SECRET)

**These files are auto-generated and already in .gitignore - never commit them to Git.**

**Note:** The relay server encryption keys (for VPS communication) must be manually shared between your client and VPS relay server. See [RELAY_SETUP.md](RELAY_SETUP.md) for details.

### Step 6: Access Dashboard

Open browser: **https://localhost:60000**

Accept self-signed SSL certificate warning.

### Step 7: Test Honeypot

**From another device on your network (e.g., Kali Linux):**

```bash
# Get Windows IP address first
# From Windows PowerShell: ipconfig | Select-String "IPv4"
# Example: 192.168.68.111

# Test FTP honeypot (should show "220 FTP Server Ready" banner)
telnet 192.168.68.111 2121

# Test SSH honeypot (should show "SSH-2.0-OpenSSH" banner)
telnet 192.168.68.111 2222

# Full TCP connection scan (use -sT for full connect, not SYN scan)
nmap -sT -p 2121,2222,2323 192.168.68.111
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
# Place certificates in server/
server/ssl_cert.pem
server/ssl_key.pem
```

---

## Updating

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

# Restart server
# (Stop current process with Ctrl+C, then restart)
python server.py
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
- **[testconnection.md](testconnection.md)** - Client relay troubleshooting
- **[RELAY_SETUP.md](RELAY_SETUP.md)** - VPS relay server setup
- **[dashboard.md](dashboard.md)** - Dashboard features and usage
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
# Start (Administrator PowerShell)
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
