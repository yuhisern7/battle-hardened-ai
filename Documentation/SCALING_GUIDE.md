# Battle-Hardened AI - Scaling to 100,000+ Concurrent Connections

## 📊 Current Capacity vs Extreme Scale (Linux as Primary Tier)

| Configuration | CPU Cores | Workers | Connections/Worker | Max Connections | Use Case |
|--------------|-----------|---------|-------------------|-----------------|----------|
| **Default (Linux gateway)** | 8 | 17 | ~250 (sync) | ~4,250 | Home/SMB segments (Linux edge box) |
| **Production (Linux gateway)** | 16 | 33 | ~250 (sync) | ~8,250 | Enterprise segments (Linux gateway / reverse proxy) |
| **Extreme Scale (Linux only)** | 32+ | 128 | 10,000 (async) | **1,280,000** | National-scale / DDoS defense on Linux edge |

> **Primary deployment:** All capacity numbers in this guide assume Battle-Hardened AI is running on **Linux** as a gateway / edge appliance or reverse proxy in front of the protected segment. Windows and macOS deployments are treated as host/appliance tiers and do not participate in the extreme-scale/Linux gateway architecture.

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
cd server
docker compose up -d
```
- ✅ Auto-restart built-in (Docker restart policy)
- ✅ No watchdog.py needed
- ✅ Isolated environment
- ✅ **Capacity**: ~4,250 connections (8-core), ~8,250 connections (16-core)
- ✅ Dynamic worker scaling based on CPU cores

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
# Windows (recommended): use the Battle-Hardened AI Windows installer and start via Start Menu shortcut or BattleHardenedAI.exe

# Windows (from source/dev):
cd battle-hardened-ai/server
python installation/watchdog.py

# Linux
docker compose up -d
```
**Capacity:** 100-500 connections

- On **Windows**, this protects the **local host** and any services it terminates, unless you route other devices through it.
- On **Linux**, if the node is placed as a **gateway or front-line reverse proxy**, it can protect the **entire home network segment** behind it.

---

**SMB Network (10-100 devices):**
```bash
# Linux (Docker - Recommended)
docker compose up -d
```
**Capacity:** ~4,250-8,250 connections (depends on CPU cores)

When deployed as a **gateway or dedicated security appliance** in front of the SMB network, Battle-Hardened AI provides first-layer protection for that segment. When deployed on a single server, it protects that host and the services it terminates.

---

**Enterprise Network (100-1,000 devices):**
```bash
# Multiple Docker servers + Reverse Proxy
docker compose up -d  # On 3-12 servers
# + nginx load balancer
```
**Capacity:** 25,000-100,000 connections (12 × 16-core servers)

In this mode, Battle-Hardened AI nodes typically sit **behind an external load balancer or WAF** and act as a **first-layer execution gate for application tiers**. They can also run as **observer nodes** analyzing mirrored traffic, with enforcement wired back into firewalls or orchestration.

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

See [STARTUP_GUIDE.md](STARTUP_GUIDE.md) for detailed startup instructions.
