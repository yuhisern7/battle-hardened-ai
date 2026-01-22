# Battle-Hardened AI - Complete Startup Guide

## 🚀 Quick Start (TL;DR)

**Windows (Production) - Recommended:**
- Install via the Battle-Hardened AI Windows installer, then start via the Start Menu shortcut or by running `BattleHardenedAI.exe` from the install directory (for example `C:\Program Files\Battle-Hardened AI`).
   - Access: https://localhost:60000 (HTTPS)

**Windows (Native from Source) - Advanced/Dev:**
```powershell
cd battle-hardened-ai
python -m venv .venv
.venv\Scripts\Activate.ps1
cd server
pip install -r requirements.txt
python installation/watchdog.py
```
Access: https://localhost:60000 (HTTPS)

**Linux Docker - Server:**
```bash
cd server
docker-compose up -d
```
Access: https://YOUR_IP:60000

**Linux Docker - VPS Relay:**
```bash
cd relay
docker-compose up -d
```
Ports: 60001 (WebSocket), 60002 (API)

---

## ✅ Production Features

Battle-Hardened AI includes enterprise-grade stability and crash protection:

- ✅ **Multi-worker** - Handles 1000s of attacks simultaneously
- ✅ **Auto-restart on crash** - Watchdog/Docker respawn workers automatically
- ✅ **Memory leak protection** - Workers recycle after 1000 requests
- ✅ **Request timeout** - Kills slow attacks (Slowloris protection)
- ✅ **Connection queue** - 2048 pending connections before dropping
- ✅ **Graceful shutdown** - 30-second grace period for existing requests

---

## 🎯 Overview
This guide shows you how to run the server in **development mode** (simple testing) vs **production mode** (handles thousands of concurrent attacks).

Battle-Hardened AI always protects **whatever traffic reaches its first-layer decision point**. What you can realistically defend depends on **where you place it and which port(s) it listens on**:

- **Gateway placement** – Battle-Hardened AI runs on a Linux box, router, or dedicated security appliance that sits in front of your network or segment. All inbound/outbound traffic for that boundary passes through port 60000 (or your chosen port) on this node.
- **Server/host placement** – Battle-Hardened AI runs directly on an application or security server (Windows or Linux) and protects the **local host and any services it terminates** (web, API, SSH, RDP, custom services) on its bound port.
- **Observer/monitoring placement** – Battle-Hardened AI runs on a node that receives mirrored/SPAN traffic or cloud flow logs. It still performs full first-layer analysis, but **enforcement depends on how you wire its block/allow decisions into firewalls, routers, or orchestration.**

For **network-wide protection**, you must deploy Battle-Hardened AI at a **gateway or routing/control point** where traffic either **naturally passes through** or is **explicitly mirrored**.

---

## 🪟 WINDOWS (Native)

### ⚡ Development Mode (Simple Testing)
**Use for:** Testing with 1-10 concurrent connections  
**Warning:** Will crash under heavy load

```powershell
cd server
python server.py
```

**Access:** https://localhost:60000

---

### 🛡️ Production Mode (Crash-Resistant)
**Use for:** Real attacks, stress testing, multiple simultaneous connections  
**Features (EXE or watchdog-based launcher):** 
- Multi-worker processes (handles 1000s of connections)
- Auto-restart on crash
- Memory leak protection
- Timeout protection

**Production Server with Auto-Restart (from source):**
```powershell
cd server
python installation/watchdog.py
```

**Production Server with Auto-Restart (from installer, recommended):**
- Start Battle-Hardened AI via the Start Menu shortcut or by running `BattleHardenedAI.exe` from the install directory.

**Access:** https://localhost:60000

**Capacity:**
- **Formula**: (CPU cores × 2 + 1) workers × 4 threads
- **8-core CPU**: 17 workers × 4 threads = 68 concurrent connections
- **16-core CPU**: 33 workers × 4 threads = 132 concurrent connections
- **Connection queue**: 2,048 pending connections before dropping

---

## 🐧 LINUX (Docker)

### 🐳 Server Container (Production)

**Build and run:**
```bash
cd server
docker-compose up -d --build
```

**View logs:**
```bash
docker-compose logs -f
```

**Stop server:**
```bash
docker-compose down
```

**Access:** https://YOUR_SERVER_IP:60000

**Configuration:**
- Already uses Gunicorn production server
- **Dynamic workers**: (CPU cores × 2 + 1) workers × 4 threads per worker
- **8-core CPU**: 17 workers × 4 threads = 68 concurrent connections
- **16-core CPU**: 33 workers × 4 threads = 132 concurrent connections
- Auto-restart via Docker restart policy
- Health checks every 30 seconds

---

## ☁️ VPS RELAY SERVER (Linux)

### 🌐 Relay Container (Production)

**Build and run:**
```bash
cd relay
docker-compose up -d --build
```

**View logs:**
```bash
docker-compose logs -f relay-server
```

**Stop relay:**
```bash
docker-compose down
```

**Ports:**
- 60001: WebSocket relay (clients connect here)
- 60002: Model distribution API

**Features:**
- Handles 1000s of client connections
- Automatically distributes threat signatures
- GPU-accelerated ML training (if GPU available)
- Persistent storage via volume mounts

---

## 📊 Comparing Modes

| Feature | Development | Production | Docker |
|---------|------------|------------|--------|
| **Max Connections** | ~10 | ~1000s | ~1000s |
| **Auto-Restart** | ❌ | ✅ | ✅ |
| **Crash Protection** | ❌ | ✅ | ✅ |
| **Memory Limits** | ❌ | ✅ | ✅ |
| **Timeout Protection** | ❌ | ✅ | ✅ |
| **Suitable For** | Testing | Production | Cloud |

---

## 🔍 Monitoring

### Check Server Health
**Windows:**
```powershell
curl -k https://localhost:60000/health
```

**Linux:**
```bash
curl -k https://localhost:60000/health
```

### View Logs
**Windows Production:**
```powershell
cat logs/gunicorn_access.log
cat logs/gunicorn_error.log
```

**Docker:**
```bash
docker-compose logs -f
```

---

## 🚨 Troubleshooting

### Server Won't Start
1. Check port 60000 is not in use:
   ```powershell
   netstat -ano | findstr :60000
   ```

2. Check SSL certificates exist:
   ```powershell
   ls crypto_keys/ssl_cert.pem crypto_keys/ssl_key.pem
   ```

3. Check Python version (requires 3.11+):
   ```powershell
   python --version
   ```

### Port & WAF Conflicts (Coexistence)

Battle-Hardened AI is designed to live **alongside** existing reverse proxies, WAFs, and application servers. To avoid conflicts and double-binding problems:

- **Do not bind Battle-Hardened AI to the same IP:port as your WAF or web server.** If your WAF listens on `443`, keep Battle-Hardened AI on `60000` (default) or another dedicated port.
- **Decide who is truly first layer:**
   - If **Battle-Hardened AI is first layer**, direct external traffic to port 60000 on the Battle-Hardened AI node, and have it forward or proxy to your internal WAF/app stack.
   - If a **WAF is first layer**, let the WAF terminate `443` and forward a copy of traffic (or selected routes) to Battle-Hardened AI on 60000 for analysis and enforcement decisions.
- **Avoid double TLS termination on the same port.** If a reverse proxy (Nginx/HAProxy/Apache) terminates TLS on `443`, keep Battle-Hardened AI’s TLS listener on `60000` (or another free port) and let the proxy handle external certificates.
- **For home/SMB labs**, the simplest model is:
   - Router/NAT forwards `443` from the internet to `60000` on the Battle-Hardened AI box
   - Battle-Hardened AI enforces first-layer decisions and optionally forwards allowed traffic to an internal web server on a different port

Always verify bindings with `netstat` (Windows) or `ss -tulpen` (Linux) before starting Battle-Hardened AI in production. If port 60000 is in use, change either the conflicting service or Battle-Hardened AI’s bind port in the configuration.

### Server Crashes Under Load
**Problem:** Using development mode  
**Solution:** Switch to production mode with `python installation/watchdog.py`

### Out of Memory
**Problem:** Too many workers for available RAM  
**Solution:** Edit `server/installation/gunicorn_config.py`, reduce `workers` value

### Too Many Restarts
**Problem:** Watchdog shows "10 restarts in 1 hour"  
**Solution:** Check error logs, likely a code bug or database corruption

---

## ⚙️ Configuration Files

### server/installation/gunicorn_config.py
Production server configuration:
- Workers: Auto-scaled based on CPU cores
- Threads: 4 per worker
- Timeout: 30 seconds
- Memory recycling: After 1000 requests

### server/installation/watchdog.py
Auto-restart monitor:
- Max restarts: 10 per hour
- Restart delay: 5 seconds
- Logs all crashes

### .env
Environment configuration:
- RELAY_ENABLED: Enable/disable VPS relay
- RELAY_URL: WebSocket relay server address
- DEBUG: Enable debug logging

---

## 🎯 Quick Start Recommendations

These examples show **how to run** Battle-Hardened AI; what you actually protect depends on placement and routing:

- On **Windows/macOS**, running natively protects the **local host and any services it terminates**, plus any traffic you explicitly route or proxy through it.
- On **Linux VPS or bare metal**, running as a front-line service can protect an entire **home/SMB/enterprise segment** when the node sits at a **gateway or reverse-proxy position**.
- A **relay server** is an intelligence node only; it does **not** protect traffic directly.

**Home Testing (Windows):** (host-only by default)
```powershell
cd server
python installation/watchdog.py
```

This protects the Windows machine (and any services it terminates) unless you deliberately route other devices' traffic through it.

**Production Server (Linux VPS):** (gateway or reverse-proxy)
```bash
cd server
docker-compose up -d
```

Use this when the VPS is positioned as a **gateway or reverse proxy** in front of other servers or networks so that inbound traffic passes through Battle-Hardened AI first.

**Relay Server (Linux VPS):**
```bash
cd relay
docker-compose up -d
```

Relay nodes exchange **sanitized, privacy-preserving training material** only; they do **not** inspect or block live traffic.

**Access Dashboard:**
- Local: https://localhost:60000
- VPS: https://YOUR_VPS_IP:60000

---

## 📈 Scaling Limits

### Single Server (Production Mode)
- **Workers**: Auto-scaled: (CPU cores × 2 + 1)
- **Connections per worker**: ~250 (sync mode)
- **Total capacity**: 
  - 8-core CPU: 17 workers × 250 = ~4,250 connections
  - 16-core CPU: 33 workers × 250 = ~8,250 connections
- **Memory**: ~200MB per worker
- **Extreme scale**: See [SCALING_GUIDE.md](SCALING_GUIDE.md) for 640,000+ connections

### Recommended Hardware
- **Development**: 2 CPU, 4GB RAM (~1,250 connections) — Ideal for **single-host protection** or small lab environments.
- **Small Business**: 4 CPU, 8GB RAM (~2,250 connections) — Suitable for a **gateway or front-line security appliance** in front of a home/SMB network or a handful of public-facing services.
- **Enterprise**: 16 CPU, 32GB RAM (~8,250 connections) — Appropriate for **enterprise edge or reverse-proxy roles**, or as part of a small cluster behind a load balancer.
- **National-Scale**: 32+ CPU, 64GB+ RAM (1,280,000+ connections with gevent) — Designed for **national-scale gateways, large DDoS shield tiers, or high-volume observer nodes**.

### Stress Test Results
- **1 attacker, 100 requests/sec**: ✅ No issues
- **10 attackers, 50 requests/sec each**: ✅ No issues
- **100 attackers, 10 requests/sec each**: ✅ Slight latency
- **1000 attackers, 1 request/sec each**: ⚠️ Queue backlog

---

## ✅ Verification Checklist

Before going live:

- [ ] Production mode enabled (not `python server.py`)
- [ ] Watchdog running (auto-restart)
- [ ] Firewall allows port 60000
- [ ] SSL certificates generated
- [ ] Logs directory created
- [ ] Relay server connected (check dashboard)
- [ ] Health check returns 200 OK
- [ ] Stress test passed (100+ concurrent connections)

---

## 🆘 Support

If server crashes repeatedly:
1. Check `logs/gunicorn_error.log`
2. Look for Python exceptions
3. Check disk space
4. Verify database files aren't corrupted
5. Restart with `python installation/watchdog.py`

**Emergency Reset:**
```powershell
cd server
rm -rf logs/*.log
rm -rf json/*.json
python installation/init_json_files.py
python installation/watchdog.py
```
