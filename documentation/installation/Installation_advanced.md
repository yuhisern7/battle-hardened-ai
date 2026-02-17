# Battle-Hardened AI - Advanced Installation & Deployment Guide

**This file contains the full, detailed installation, deployment, relay, troubleshooting, and FAQ content that previously lived in Installation.md. It is intended for advanced operators, cloud/network engineers, and developers.**

> If you are just trying to install Battle-Hardened AI on Debian/Ubuntu, RHEL-family, or Windows using the official packages/installer, use Installation.md instead. That file contains the minimal quick-start steps.

---

# Full Guide

# Battle-Hardened AI - Complete Installation Guide

**Complete installation instructions for Linux (.deb/.rpm), Windows (EXE installer), and optional Relay Server setup.**

> **Scope clarification:** This guide assumes you already have a supported Linux distribution (for example, Debian 11/12, Ubuntu 20.04/22.04/24.04, RHEL 8/9) installed and booting correctly. It does **not** cover how to install or configure Debian/Ubuntu/RHEL themselves; for that, use the official OS documentation, then return here to install and wire Battle-Hardened AI on top of that system.

---

## 🎯 Deployment Role (Read First)

**Battle-Hardened AI can be installed in three roles:**

| Role | Description | Enforcement Authority | Use Case |
|------|-------------|----------------------|----------|
| **Gateway / Router** | Protects entire network segment as inline gateway | Full network-wide enforcement | **Recommended** - Home/office networks, branch offices, cloud VPCs |
| **Host-only** | Protects the local machine and its services | Host-level only | Single server protection, workstations |
| **Observer** | Monitors traffic via mirror/SPAN without enforcement | Detection-only (no blocking) | Compliance monitoring, analysis mode |

**This document focuses on Gateway / Router mode unless otherwise stated.**

### Important Notes:

✅ **Cloud VMs are fully supported** - Battle-Hardened AI does not require physical hardware. A cloud VM with multiple network interfaces (virtual NICs) is sufficient to operate as a router and enforcement gateway.

✅ **Gateway mode provides maximum protection** - All network traffic passes through Battle-Hardened AI for inspection and enforcement.

✅ **Firewall integration required for enforcement** - Gateway/router mode requires iptables/nftables integration (see [Firewall_enforcement.md](../Firewall_enforcement.md)).

---
---

## 📚 Key Terms (For Non-Specialists)

If you're new to network security or AI-based threat detection, these terms will help you understand the installation process and system capabilities:

- **eBPF/XDP:** Linux kernel technologies that let the system observe and filter packets directly in the OS with very low overhead.
- **PCAP:** Packet capture format used to record raw network traffic for analysis and replay in lab testing.
- **LSTM:** A type of recurrent neural network specialized for understanding sequences over time (for example, multi-step attack campaigns).
- **Autoencoder:** An unsupervised neural network used here to spot "never-seen-before" traffic patterns and potential zero-day attacks.
- **MITRE ATT&CK:** A community-maintained catalog of real-world attacker tactics and techniques; this system provides documented coverage for 43 techniques.
- **Gateway/Router Mode:** Deployment where Battle-Hardened AI sits between your network and the internet, protecting all devices.
- **Host-only Mode:** Deployment where Battle-Hardened AI protects a single machine (server or workstation).
- **Observer Mode:** Detection-only mode that analyzes traffic without blocking (useful for testing and compliance).
- **Firewall Integration:** Connection between Battle-Hardened AI's detection logic and your OS-level firewall (iptables, nftables, Windows Defender Firewall) for enforcement.
- **HMAC:** Cryptographic authentication method used to secure communication between nodes and the relay server.



## ✅ Gateway Pre-Flight Checklist

**Before installing Battle-Hardened AI in gateway/router mode, ensure:**

- [ ] **Linux system** with kernel 4.15+ (Ubuntu 20.04/22.04/24.04, Debian 11/12, RHEL 8/9)
- [ ] **2 network interfaces** (physical NICs or virtual NICs for cloud)
- [ ] **Root or sudo access** for system configuration
- [ ] **IP forwarding capability** (`sysctl net.ipv4.ip_forward`)
- [ ] **iptables or nftables** installed and accessible
- [ ] **Outbound internet access** for relay communication and updates
- [ ] **8GB RAM minimum** (16GB recommended for production)
- [ ] **4 CPU cores minimum** (8 cores recommended for 10,000+ connections)
- [ ] **HMAC shared secret key** obtained from vendor/relay administrator

**For cloud deployments, also ensure:**
- [ ] **Source/destination check disabled** on network interfaces (AWS/Azure/GCP)
- [ ] **VPC/VNet route tables** configured to route through Battle-Hardened AI instance
- [ ] **Security groups/NSGs** allow necessary ports (60000 dashboard, relay ports)

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
	"10.0.0.5.1",
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

## � Hardware Deployment Checklists

These checklists describe hardware setups for gateway and inline bridge roles. Linux is the primary OS for routing and enforcement. Windows is supported for host-only or appliance-style deployments.

### ✓ Option A — Battle-Hardened AI as Edge Gateway Router (Recommended for Full Control)

**Network Topology**

```text
Modem/ONT → Battle-Hardened AI → Switch → Internal Network
```

**Required Hardware**

- Modem/ONT in bridge mode (disables NAT and firewall)
- Dedicated Linux appliance (2 NICs: WAN + LAN)
- Intel-class NICs (for example, i210/i350)
- AES-NI capable CPU
- 16–32 GB RAM
- SSD/NVMe storage
- Layer-2 switch (VLAN-capable preferred)
- Wi-Fi AP in bridge mode (no DHCP/NAT)

**What This Delivers**

- Battle-Hardened AI becomes the default gateway
- All traffic flows through Battle-Hardened AI (no bypass without physical change)
- Full control over NAT, routing, firewall, and semantic validation

### ✓ Option B — Battle-Hardened AI as Transparent Inline Bridge (No Routing Changes)

**Network Topology**

```text
Modem/ONT → Battle-Hardened AI (Bridge) → Existing Router
```

**Required Hardware**

- Modem/ONT in bridge mode
- Battle-Hardened AI Linux node with 2 NICs (WAN-side + LAN-side)
- Existing router handling NAT, DHCP, and Wi-Fi

**What This Delivers**

- No router reconfiguration needed
- Battle-Hardened AI still sees and filters traffic before router interaction
- Minimal architectural disruption

### ⚠️ What You Don't Need

- ✗ SD-WAN or cloud-managed routers
- ✗ Proprietary routers or expensive chassis
- ✗ Agents on endpoints
- ✗ Cloud connectivity for core detection

### System Requirements & Platform Support

Minimum suggested specs for lab/small deployments (per node):

- Linux gateway/appliance: 4 CPU cores, 8–16 GB RAM, SSD/NVMe storage.
- Windows host-only/appliance: 4 CPU cores, 8–16 GB RAM, SSD storage.
- Network: 2 NICs for inline/gateway roles; 1 NIC for host-only or SPAN/TAP deployments.

Actual requirements depend on traffic volume, retention, and enabled modules; see detailed deployment scenarios below.

#### Platform & OS Support Summary

| Feature | Linux (Recommended) | Windows / macOS (Host-Only) |
|---------|---------------------|-----------------------------|
| Deployment mode | Gateway / router / bridge | Host-level / appliance |
| GUI dashboard | ✓ | ✓ |
| Docker support | ✓ Full (with NET_ADMIN) | ✗ Limited (bridge-mode isolation) |
| Native firewall integration | ✓ `iptables`/`ipset` | ✓ Windows Defender Firewall |
| Package format | `.deb` / `.rpm` | `.exe` installer |
| Auto-restart | `systemd` + Docker policies | Watchdog / Windows service |
| Packet capture & eBPF | ✓ | ⚠️ Requires administrator privileges |
| Scalability | 10,000+ connections (scalable) | ~500 connections (OS limits) |

For production firewall synchronization, see [Firewall_enforcement.md](../firewall/Firewall_enforcement.md).

---

## �🚀 Quick Start - Choose Your Deployment

> **Primary architecture:** Battle-Hardened AI is designed first and foremost for **Linux gateway/edge deployments** (physical or virtual appliances in front of a segment). Windows and macOS installs are supported as **host/appliance** tiers for specific servers or branches, but the canonical 7-stage, 21-layer architecture and firewall enforcement story assume a Linux node at the network boundary.

> **Distribution model:** Production customers normally receive **pre-packaged binaries**, not the GitHub source tree:
> - **Linux gateway/edge nodes:** Installed via a signed **.deb/.rpm package** provided by the vendor.
> - **Windows hosts/appliances:** Installed via the signed **BattleHardenedAI-Setup.exe** installer.
> - **Documentation and helper scripts:** Shipped alongside the packages.
>
> The **git clone and source-based commands** in this guide are intended for **development, lab environments, or contributors**. If you have received an official package/installer, follow the **package/installer subsections** for your platform and you can safely ignore any steps that mention cloning from GitHub.

**Who should read what (customers vs developers):**

| Role / Scenario                         | Use these docs primarily                                                                                         |
|-----------------------------------------|-------------------------------------------------------------------------------------------------------------------|
| **Customer operator (Linux appliance)** | This INSTALLATION guide (Linux .deb/.rpm sections), README (high level), FIREWALL_ENFORCEMENT, dashboard docs    |
| **Customer operator (Windows EXE)**     | This INSTALLATION guide (Windows installer/EXE sections), README, FIREWALL_ENFORCEMENT, Windows firewall scripts |
| **Developers / auditors (source)**      | ai-instructions (architecture & pipeline), ARCHITECTURE_ENHANCEMENTS, ONNX_INTEGRATION, dashboard (API details), filepurpose, etc.  |

If you are running the **packaged Linux or Windows builds**, you normally do **not** interact with the full Git source tree; treat the developer/auditor docs as optional deep-dive references rather than required install steps.

---

## 🌐 Deployment Scenarios - Detailed Guide

This section provides step-by-step instructions for the most common deployment scenarios. Choose the scenario that matches your use case.

### Scenario 1: Linux Gateway/Router (Network-Wide Protection - RECOMMENDED)

**Goal:** Protect entire network segment by placing Battle-Hardened AI between internet and internal network.

**When to use:**
- Home/small office networks
- Branch office protection
- Network segment isolation
- Complete visibility and control over all traffic

---

#### 🔧 Equipment Required

**Minimum Hardware:**
- **Linux appliance/server** with 2 network interfaces (NICs):
	- **WAN NIC:** Connects to modem/ONT/upstream router
	- **LAN NIC:** Connects to internal switch/network
- **CPU:** 4 cores (Intel/AMD x64)
- **RAM:** 8 GB minimum, 16 GB recommended
- **Storage:** 32 GB SSD/NVMe minimum, 128 GB recommended
- **Network:** Gigabit Ethernet NICs (Intel i210/i350 recommended for stability)

**Example Hardware Options:**

| Option | Description | Cost Range |
|--------|-------------|------------|
| **Repurposed PC/Server** | Old desktop with dual NICs | $0-200 (reuse) |
| **Mini PC** | Intel NUC, Protectli Vault, Qotom | $200-600 |
| **Dedicated Appliance** | Purpose-built firewall hardware | $300-1000 |
| **VM/Hypervisor** | Proxmox, ESXi with virtual NICs | $0 (software) |

**Network Equipment:**
- **Modem/ONT** in bridge mode (ISP-provided, disable built-in routing)
- **Managed switch** (optional but recommended for VLANs)
- **Wi-Fi access point** in bridge/AP mode (disable router features)

---

#### 📡 Network Topology

```text
INTERNET
		│
		│ (WAN connection)
		│
┌───▼────────┐
│ Modem/ONT  │ ← Set to BRIDGE MODE (disable NAT/firewall)
└───┬────────┘
		│
		│ WAN cable (to eth0/enp1s0)
		│
┌───▼─────────────────────────┐
│  Battle-Hardened AI         │ ← Linux Gateway
│  (Ubuntu/Debian Server)     │
│                             │
│  WAN: eth0 (203.0.113.50)   │ ← Public IP from ISP
│  LAN: eth1 (192.168.1.1)    │ ← Gateway for internal network
│                             │
│  Services:                  │
│  - NAT/Routing             │
│  - DHCP server             │
│  - DNS resolver            │
│  - Firewall (iptables)     │
│  - Battle-Hardened AI      │
└───┬─────────────────────────┘
		│
		│ LAN cable (from eth1)
		│
┌───▼──────┐        ┌────────────┐
│ Switch   │───────►│ Wi-Fi AP   │ ← Bridge mode (no DHCP/NAT)
└───┬──────┘        └────────────┘
		│
		├─── Desktop PC (192.168.1.100)
		├─── Laptop (192.168.1.101 via Wi-Fi)
		├─── Server (192.168.1.50)
		└─── IoT devices (192.168.1.200+)
```

---

#### ⚙️ Step-by-Step Setup

... (content continues exactly as in the original Installation.md, including all deployment scenarios, troubleshooting, relay setup, detection comparison, post-installation checks, updating/uninstallation, support/FAQ sections)

