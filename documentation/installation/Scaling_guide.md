# Battle-Hardened AI - Scaling to 100,000+ Concurrent Connections

> **Audience & distribution:** This guide is aimed at **advanced Linux operators and developers** tuning capacity. Customer deployments normally use the Linux `.deb`/`.rpm` packages or Windows EXE installer; they run the **same Gunicorn/Docker stack under the hood**, but you typically manage it via the packaged service (systemd/Docker) rather than calling `gunicorn` or `docker compose` directly. Treat explicit `pip`/`gunicorn`/`docker` commands here as **reference or source-based examples**.

---

**Related overview:** For high-level deployment roles, threat model, and capabilities, see **[README.md](../../README.md)**.

---

## 🎯 Deployment Role & Capacity Context

**Before scaling, understand what you're protecting:**

| Role | What Capacity Numbers Mean | Example |
|------|---------------------------|----------|
| **Gateway / Router** | Total inbound/outbound sessions for protected network segment | 8,250 connections = entire office network traffic |
| **Host-only** | Connections to local server and terminated services | 8,250 connections = single web/API server load |
| **Observer** | Volume of mirrored/SPAN traffic analyzed | 8,250 connections = analyzed flows (enforcement via external firewall) |

**See [Installation.md](Installation.md) for deployment role details and Pre-Flight Checklist.**

### Important Notes:

✅ **Cloud VMs fully supported** - These capacity numbers apply equally to cloud VMs (AWS/Azure/GCP) with virtual NICs. Physical hardware not required.

✅ **Linux is primary tier** - All extreme-scale configurations (100,000+ connections) require Linux gateway deployment.

✅ **Windows is host-tier** - Windows deployments are limited to ~10,000 connections maximum due to OS constraints.

---

## 📊 Current Capacity vs Extreme Scale (Linux as Primary Tier)

| Configuration | CPU Cores | Workers | Connections/Worker | Max Connections | Deployment Mode | Use Case |
|--------------|-----------|---------|-------------------|-----------------|-----------------|----------|
| **Default (Linux gateway)** | 8 | 17 | ~250 (sync) | ~4,250 | Gateway/Router | Home/SMB network segments |
| **Production (Linux gateway)** | 16 | 33 | ~250 (sync) | ~8,250 | Gateway/Router/Host | Enterprise networks, high-traffic servers |
| **Extreme Scale (Linux only)** | 32+ | 128 | 10,000 (async) | **1,280,000** | Gateway (national-scale) | DDoS defense, carrier-grade edge |

> **Deployment context:** When deployed as a **gateway**, these connections represent total network segment traffic. When deployed as a **host**, they represent load on that specific server. See [Installation.md § Deployment Role](Installation.md#-deployment-role-read-first) for details.

> **Cloud deployment:** All configurations work on cloud VMs (AWS EC2, Azure VMs, GCP Compute) with virtual NICs. No physical hardware required. See [Installation.md § Cloud Gateway Deployment](Installation.md#scenario-2-cloud-gateway-with-virtual-nics-awsazuregcp).

---

## 🚀 How to Scale to 100,000+ Connections

Battle-Hardened AI always scales the **first-layer decision point** you deploy:

- When used as a **gateway**, these connection counts represent total inbound/outbound sessions for the protected segment.
- When deployed on a **single server or reverse proxy**, they represent the load for that host and its terminated services.
- When used as an **observer** behind a WAF or load balancer, capacity numbers describe how much mirrored or forwarded traffic the node can analyze; enforcement still depends on how you feed its decisions back into upstream firewalls or routing.

### Option 1: Extreme-Scale Config (Single Server)

**Requirements:**
- ✅ Linux OS (mandatory - Windows cannot handle this scale)
- ✅ 32+ CPU cores
- ✅ 64+ GB RAM
- ✅ 10Gbps+ network interface

**1. Install async worker support:**
```bash
pip install gevent
```

**2. Increase system limits:**
```bash
# Increase connection backlog
sudo sysctl -w net.core.somaxconn=65535
sudo sysctl -w net.ipv4.tcp_max_syn_backlog=65535

# Increase file descriptor limit
ulimit -n 1000000

# Make permanent
echo "net.core.somaxconn=65535" | sudo tee -a /etc/sysctl.conf
echo "net.ipv4.tcp_max_syn_backlog=65535" | sudo tee -a /etc/sysctl.conf
echo "* soft nofile 1000000" | sudo tee -a /etc/security/limits.conf
echo "* hard nofile 1000000" | sudo tee -a /etc/security/limits.conf
```

**3. Run with extreme-scale config:**
```bash
cd server
gunicorn --config installation/gunicorn_config_extreme.py server:app
```

**Capacity:**
- **Formula**: CPU cores × 4 workers/CPU × 10,000 connections/worker
- **32 CPUs**: 32 × 4 = 128 workers × 10,000 = **1,280,000 max connections**
- **16 CPUs**: 16 × 4 = 64 workers × 10,000 = **640,000 max connections**

---

### Option 2: Reverse Proxy (Load Balancing)

**Architecture:**
```
Internet → Nginx/HAProxy → [Battle-Hardened AI 1]
                        → [Battle-Hardened AI 2]
                        → [Battle-Hardened AI 3]
```

**Nginx Load Balancer Config:**
```nginx
upstream battle_hardened_ai {
    least_conn;  # Route to least busy server
    server 192.168.1.10:60000 max_fails=3 fail_timeout=30s;
    server 192.168.1.11:60000 max_fails=3 fail_timeout=30s;
    server 192.168.1.12:60000 max_fails=3 fail_timeout=30s;
}

server {
    listen 443 ssl http2;
    server_name security.yourcompany.com;
    
    ssl_certificate /etc/ssl/certs/cert.pem;
    ssl_private_key /etc/ssl/private/key.pem;
    
    # Connection limits
    limit_conn_zone $binary_remote_addr zone=addr:10m;
    limit_conn addr 100;  # Max 100 connections per IP
    
    location / {
        proxy_pass https://battle_hardened_ai;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
        
        # Preserve real IP for threat detection
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

**Capacity:**
- **Per server**: ~8,250 connections (16-core CPU with sync workers)
- **3 servers**: 3 × 8,250 = **~25,000 connections**
- **12 servers**: 12 × 8,250 = **~100,000 connections**

---

## 🛡️ Deployment Modes Clarified

### Linux

**Option A: Docker (Recommended for Most Users)**
```bash
# Packaged appliance (customers): the Linux package starts and manages this Docker stack for you.
# Use systemctl as documented in INSTALLATION, for example:
#   sudo systemctl status battle-hardened-ai

# From source / custom Docker management (developers/labs):
cd server
docker compose up -d
```
- ✅ Auto-restart built-in (Docker restart policy)
- ✅ No watchdog.py needed
- ✅ Isolated environment with all dependencies (Flask-CORS, Scapy, ML libraries, etc.)
- ✅ **Capacity**: ~4,250 connections (8-core), ~8,250 connections (16-core)
- ✅ Dynamic worker scaling based on CPU cores

**Deployment context:** These connection numbers represent:
- **Gateway role**: Total network segment traffic (all devices)
- **Host role**: Load on this server only
- **Observer role**: Volume of mirrored traffic analyzed

For gateway deployment, see [Installation.md § Linux Gateway Setup](Installation.md#scenario-1-linux-gatewayrouter-network-wide-protection---recommended).

**Option B: Extreme Scale (National-Level Defense)**
```bash
cd server
pip install gevent
./installation/start_extreme_scale.sh
```
- ✅ Scales to 640,000+ connections (16-core) or 1,280,000+ (32-core)
- ✅ Async workers (gevent)
- ✅ Purpose-built for DDoS-grade attack loads
- ❌ Requires system tuning (ulimit, sysctl)

---

### Windows

**Production Mode (Recommended):**
- **From installer (preferred):** Use the Start Menu shortcut created by the Battle-Hardened AI installer, or run `BattleHardenedAI.exe` from `C:\Program Files\Battle-Hardened AI`.
- **From source (advanced/dev):**
    ```powershell
    cd server
    python installation/watchdog.py
    ```
- ✅ Auto-restart on crash
- ✅ Handles 100s of concurrent connections
- ⚠️ Windows max: ~10,000 connections (OS limitation)

**Development Mode (Testing Only):**
```powershell
cd server
python server.py
```
- ❌ Single-threaded (crashes under load)
- ❌ Use only for testing/debugging

---

## 📊 Capacity Comparison

| Deployment | Platform | Max Connections | Auto-Restart | Use Case |
|------------|----------|----------------|--------------|----------|
| `python server.py` | Any | ~10 | ❌ | Testing only |
| `python installation/watchdog.py` | Windows/Mac | ~500-1,000 | ✅ | Production-style from source (advanced/dev) |
| `docker compose up -d` | Linux (8-core) | ~4,250 | ✅ | Production (Docker) |
| `docker compose up -d` | Linux (16-core) | ~8,250 | ✅ | Production (Docker) |
| `installation/gunicorn_config.py` | Linux (16-core) | ~8,250 | ❌ | Production (native Linux) |
| `installation/gunicorn_config_extreme.py` | Linux (16-core) | **640,000** | ❌ | National-scale DDoS defense |
| `installation/gunicorn_config_extreme.py` | Linux (32-core) | **1,280,000** | ❌ | National-scale DDoS defense |
| **Nginx + 12 servers** | Linux (16-core each) | **~100,000** | ✅ | Enterprise load balancing |

---

## 🔧 System Tuning for Extreme Scale

### Linux Kernel Tuning

**Edit `/etc/sysctl.conf`:**
```bash
# Connection backlog
net.core.somaxconn=65535
net.ipv4.tcp_max_syn_backlog=65535

# File descriptors
fs.file-max=2097152

# Connection tracking
net.netfilter.nf_conntrack_max=1000000

# TCP optimization
net.ipv4.tcp_fin_timeout=15
net.ipv4.tcp_tw_reuse=1
net.ipv4.tcp_max_tw_buckets=2000000

# Buffer sizes
net.core.rmem_max=134217728
net.core.wmem_max=134217728
net.ipv4.tcp_rmem=4096 87380 67108864
net.ipv4.tcp_wmem=4096 65536 67108864
```

**Apply:**
```bash
sudo sysctl -p
```

---

## 🎯 Recommended Configurations

**Home Network (1-10 devices):**
```bash
# Windows (Host-only role - protects local machine)
python installation/watchdog.py

# Linux Gateway (protects entire home network - requires 2 NICs)
docker compose up -d
# + Complete Installation.md § Linux Gateway Setup first
```
**Capacity:** 100-500 connections  
**Deployment role:**
- **Windows**: Host-only (local machine protection)
- **Linux (single NIC)**: Host-only (protects VPS/server)
- **Linux (dual NIC)**: Gateway/Router (protects entire home network)

For Linux gateway deployment, follow [Installation.md § Gateway Pre-Flight Checklist](Installation.md#-gateway-pre-flight-checklist).

---

**SMB Network (10-100 devices):**
```bash
# Linux Gateway (recommended - requires 2 NICs + firewall integration)
docker compose up -d
# + Complete Installation.md § Linux Gateway Setup
```
**Capacity:** ~4,250-8,250 connections (depends on CPU cores)  
**Deployment role:** Gateway/Router  
**What's protected:** Entire SMB network segment behind this appliance

**Prerequisites:**
- Linux VM/appliance with 2 NICs (WAN + LAN)
- IP forwarding enabled, iptables/nftables configured
- DHCP/DNS configured, clients routing through gateway
- See [Installation.md § Linux Gateway Setup](Installation.md#scenario-1-linux-gatewayrouter-network-wide-protection---recommended)

---

**Enterprise Network (100-1,000 devices):**
```bash
# Multiple Gateway nodes OR Load-balanced cluster
docker compose up -d  # On 3-12 servers
# + nginx/HAProxy load balancer
```
**Capacity:** 25,000-100,000 connections (12 × 16-core servers)  
**Deployment roles:**
- **Gateway cluster**: Each node protects a network segment
- **Reverse proxy tier**: Behind load balancer, protects application tier
- **Observer nodes**: Analyze mirrored traffic, enforce via external firewall

---

**National-Scale DDoS Defense (1,000+ devices or targeted attacks):**
```bash
# Linux Native + Extreme Config
pip install gevent
gunicorn --config gunicorn_config_extreme.py server:app

# + nginx load balancer across 20+ servers
```
**Capacity:** 100,000-1,000,000 connections

These configurations are designed for **national or carrier-scale edge gateways**, large DDoS shield tiers, or very high-volume observer deployments where Battle-Hardened AI processes massive traffic volumes at the first layer.

---

## ✅ Verification Commands

**Check current capacity:**
```bash
# Count active workers
ps aux | grep gunicorn | wc -l

# Check open connections
netstat -an | grep :60000 | wc -l

# Monitor in real-time
watch -n 1 'netstat -an | grep :60000 | wc -l'
```

**Stress test:**
```bash
# Install apache bench
sudo apt install apache2-utils

# Test 10,000 concurrent connections
ab -n 100000 -c 10000 https://localhost:60000/

# Test 100,000 concurrent connections (requires extreme config)
ab -n 1000000 -c 100000 https://localhost:60000/
```

---

## 🚨 When to Use Each Mode

| Connections | Configuration | Command |
|------------|---------------|---------|
| < 500 | Windows watchdog | `python installation/watchdog.py` |
| < 5,000 | Linux Docker (8-core) | `docker compose up -d` |
| < 10,000 | Linux Docker (16-core) | `docker compose up -d` |
| < 100,000 | Multi-server cluster | 12+ servers (16-core) + nginx |
| < 640,000 | Extreme single server | `gunicorn --config installation/gunicorn_config_extreme.py server:app` (16-core) |
| > 640,000 | Extreme multi-server | Multiple extreme servers + nginx |


---

## 💡 Deployment Pattern Recommendations

### Operational Guidance & Reference Deployment Patterns

- **Home / Lab:** Single-node deployment at the home router or gateway mirror port; modest CPU (4 cores), 8–16 GB RAM, and SSD storage are typically sufficient for thousands of concurrent flows.
- **SMB / Branch Office:** Inline or tap-based deployment at the site gateway, with 8–16 cores, 32 GB RAM, and NVMe storage to sustain higher connection rates and full audit logging.
- **Enterprise / Data Center:** One Battle-Hardened AI node per major segment (e.g., DC edge, user access, cloud egress), potentially clustered behind a load balancer or distribution layer for scale-out; sizing depends on peak connections and desired retention period.
- **ISP / High-Throughput:** Requires careful capacity planning, hardware acceleration (where available), and potentially multiple nodes sharded by customer or prefix; in these environments, aggressive log rotation and selective telemetry are critical.
- **Overload Behavior:** When resource pressure increases, operators should prioritize maintaining detection and logging fidelity by scaling vertically/horizontally rather than accepting packet loss; standard OS and network QoS controls apply.

---

See [Startup guide](Startup_guide.md) for detailed startup instructions.
