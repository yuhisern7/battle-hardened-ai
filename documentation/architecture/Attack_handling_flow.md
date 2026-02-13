# COMPLETE ATTACK HANDLING FLOW

> **Audience & distribution:** This document is written for **security engineers, architects, and auditors** who want to verify that the implemented attack path matches the documented design. It describes the **intended and currently implemented behavior** of the system, not a legal or formal security guarantee. Operational behavior still depends on configuration (for example whitelist entries, deployment mode, and firewall wiring).

---

**Related overview:** For the end-to-end 7-stage pipeline description and positioning, see **[README.md](../../README.md)**. For how these decisions drive firewalls, IDS/IPS, NDR/XDR, cloud controls, and other tools, see the **Enterprise Integration Topologies** and **Ecosystem View — BH-AI as the Autonomous Gate** sections in README.md.

---

## 🎯 Deployment Mode Determines Protection Scope

**What gets protected depends on deployment role:**

| Deployment Role | Traffic Scope | Enforcement Authority |
|----------------|---------------|----------------------|
| **Gateway/Router** | Entire network segment (all devices behind gateway) | Full network-wide blocking via iptables/nftables |
| **Host-only** | Local machine + services it terminates | Host-level blocking only |
| **Observer** | SPAN/mirror traffic (analysis only) | Detection-only (no direct blocking) |

**Installation reference:** For deployment setup, see:
- [Installation.md § Deployment Role](../installation/Installation.md#-deployment-role-read-first)
- [Installation.md § Gateway Pre-Flight Checklist](../installation/Installation.md#-gateway-pre-flight-checklist)
- [Installation.md § Linux Gateway Setup](../installation/Installation.md#scenario-1-linux-gatewayrouter-network-wide-protection---recommended)

**Cloud deployment:** All attack handling flows work identically on cloud VMs (AWS/Azure/GCP) with virtual NICs. Physical hardware not required.

**PoC testing:** For formal acceptance testing, see [Battle-Hardened-AI_PoC_Acceptance_Criteria.md](../checklist/Battle-Hardened-AI_PoC_Acceptance_Criteria.md) and [Linux-Gateway-Testing.md](../checklist/Linux-Gateway-Testing.md).

---

When a request matches any configured or learned attack pattern in scope of the current deployment, the IP is blocked and logged as described below, subject to the documented whitelist and configuration rules.

---

## 📊 ATTACK FLOW (Milliseconds)

### 1️⃣ ATTACK DETECTION (Instant)
**Location:** `server/server.py` catch-all honeypot route
- **Endpoint:** `/api/<any_path>` 
- **Methods:** GET, POST, PUT, DELETE, PATCH, OPTIONS
- **Detects:**
  - SQL Injection (`union`, `select`, `drop`, `--`, etc.)
  - XSS (`<script>`, `javascript:`, `alert(`)
  - Command Injection (`system(`, `exec(`, `bash -c`, `&&`, etc.)
  - Path Traversal (`../`, `..\\`, `/etc/passwd`)
  - File Inclusion (`php://input`, `file://`, `data://`)
  - SSTI (`{{`, `{%`, `<%`)

### 2️⃣ IP BLOCKING (< 1 second)
**Location:** `AI/pcs_ai.py` threat handling pipeline
```python
_block_ip(ip_address)
print(f"[IP BLOCKING] 🚫 Blocked {ip_address} for {threat_type}")
```

**Dual-Layer Enforcement Architecture:**

1. **Application Layer (Immediate - <1ms):**
   - Added to `_blocked_ips` set (in-memory)
   - Returns HTTP 403 Forbidden for all subsequent requests
   - Persisted to `server/json/blocked_ips.json`

2. **Kernel Firewall Layer (5-second sync):**
   - **Firewall Sync Daemon:** `server/installation/bh_firewall_sync.py` (5-second loop)
   - **Backend Auto-Detection:** `AI/firewall_backend.py` detects Linux distro firewall:
     - **Debian/Ubuntu:** iptables-nft (Full Support ✅)
     - **RHEL/Rocky/Alma/SUSE:** firewalld (Full Support ✅)
     - **VyOS:** CLI address groups (Partial Support ⚠️)
     - **OpenWRT:** UCI firewall (Partial Support ⚠️)
     - **Alpine:** awall (Partial Support ⚠️)
   - **Dual-Layer Rules:**
     - **Whitelist (Priority 1):** `iptables -I INPUT 1 -m set --match-set bh_whitelist src -j ACCEPT`
     - **Blocklist (Priority 2):** `iptables -I INPUT 2 -m set --match-set bh_blocked src -j DROP`
   - **Safety Check:** Sync daemon removes whitelisted IPs from blocklist before syncing (whitelist wins conflicts)
   - **Dashboard Management:** Section 7, 4th tab "🔥 Linux Firewall Commander" (Force Sync, Test Integration, View Native Rules)

**Whitelist Protection:**
- **Localhost Defaults:** `127.0.0.1`, `localhost`, `::1` (built-in)
- **Custom Whitelist:** `server/json/whitelist.json` (manually added IPs)
- **GitHub Protection:** Dynamically unblocks GitHub's published IP ranges (fetched from `https://api.github.com/meta`) for automated security updates
- **Kernel Priority:** Whitelist = Priority 1 ACCEPT (wins all conflicts)

**Result:** 
- **Application-Level:** Attacker gets HTTP 403 Forbidden (immediate)
- **Kernel-Level:** Packets dropped by firewall within 5 seconds (network-wide protection if deployed as gateway)

### 3️⃣ LOCAL STORAGE (< 1 second)
**Location:** `AI/pcs_ai.py` threat logging functions
- **Threat Log:** Appended to `_threat_log` array (in memory)
- **Disk Persistence:** Saved to `server/json/threat_log.json`
- **Details Stored:**
  - Timestamp (ISO 8601 UTC)
  - IP Address
  - Threat Type (SQL Injection, XSS, etc.)
  - Attack Details (sanitized payload)
  - Geolocation (city, region, country, coordinates)
  - User Agent
  - HTTP Method
  - Request Headers

**Files Updated:**
- `server/json/threat_log.json` - All threats (last 1000)
- `server/json/blocked_ips.json` - Blocked IPs with reason & timestamp

### 4️⃣ PATTERN EXTRACTION (< 1 second)
**Location:** `AI/pcs_ai.py` + `AI/signature_extractor.py`
**Module:** `AI/signature_extractor.py`
- **Extracts:**
  - Keywords (`SELECT`, `UNION`, `<script>`, `../`, etc.)
  - Encodings (URL encoding, base64, hex)
  - Regex patterns (SQL patterns, command patterns)
- **SANITIZED:** No attacker IPs, no raw exploit code
- **Added to Event:** `event['extracted_signatures']`

**What Gets Extracted:**
```json
{
  "keywords_found": ["union", "select", "from"],
  "encodings_detected": ["url_encoded"],
  "regex_patterns": ["sql_injection_union_select"]
}
```

### 5️⃣ RELAY TO RELAY SERVER (< 2 seconds)
**Location:** Multiple detection modules with relay integration
**Condition:** `RELAY_ENABLED=true` (✅ Enabled in `.env`)
**Modules:** 
- `AI/pcs_ai.py` - Web application attack relay sharing
- `server/network_monitor.py` - Network-level attack relay sharing (port scans, floods, ARP spoofing)
- `AI/relay_client.py` - WebSocket client for threat broadcast

**Network Monitor Integration:**
- Helper function: `_share_threat_to_relay(ip, type, details, level)`
- Called after EVERY network threat detection
- Shares: SYN scans, FIN scans, NULL scans, XMAS scans, port scans, SYN floods, UDP floods, ARP spoofing, DNS attacks
- Universal: Works for ANY customer network (no hardcoded IPs)

**Sends to Relay Server:**
- WebSocket URL: `wss://<RELAY_SERVER_IP>:60001`
- **HMAC Signed:** 32-byte shared secret (`server/crypto_keys/shared_secret.key`)
- **Payload:**
```json
{
  "ip_address": "<ANONYMIZED>",
  "threat_type": "SQL Injection",
  "attack_type": "SQL Injection",
  "sensor_id": "windows-node",
  "details": "<SANITIZED PATTERN>",
  "level": "DANGEROUS",
  "timestamp": "2026-01-12T12:20:00Z",
  "extracted_signatures": {
    "keywords_found": ["union", "select"],
    "encodings_detected": ["url_encoded"]
  }
}
```

**Security:**
- ✅ HMAC authentication (prevents spoofing)
- ✅ WebSocket Secure (SSL/TLS)
- ✅ Anonymized (no real IPs sent to relay)
- ✅ Sanitized (no exploit code, only patterns)

### 6️⃣ RELAY SERVER STORAGE (< 3 seconds)
**Location:** Relay Server `relay/relay_server.py` → `relay/signature_sync.py`
**Container:** `security-relay-server` (Docker - built with AI/, relay/, server/ folders)
**File:** `/app/relay/ai_training_materials/global_attacks.json`
**Required Folders:**
- `/app/AI/` - Crypto security (HMAC), ML models, threat analysis
- `/app/relay/` - WebSocket relay + model distribution API
- `/app/server/` - Path utilities (path_helper.py), JSON config access

**Relay Server Receives:****
- Verifies HMAC signature
- Broadcasts to all connected peers (0 currently)
- Calls `sync_service.store_global_attack()`

**Relay Server Stores:**
```json
{
  "attack_type": "SQL Injection",
  "timestamp": "2026-01-12T12:20:00Z",
  "pattern": {
    "keywords": ["union", "select"],
    "encodings": ["url_encoded"]
  },
  "region": "North America",
  "source": "windows-node"
}
```

**Current Status:** ✅ **WORKING** (Total: 225 attacks stored)
**Log Output:** `📝 Saved SANITIZED attack to global_attacks.json (Total: 225)`

---

## 🔍 VERIFICATION COMMANDS

### Check Local Blocking
```powershell
# See last 10 blocked IPs
Get-Content server\json\blocked_ips.json | ConvertFrom-Json | Select-Object -ExpandProperty blocked_ips | Select-Object -Last 10

# See last 10 threats
Get-Content server\json\threat_log.json | ConvertFrom-Json | Select-Object -Last 10
```

### Check Relay Server Pattern Storage
```bash
# SSH to relay server
ssh root@<RELAY_SERVER_IP>

# View last 50 attacks stored (inside Docker container)
docker exec security-relay-server tail -50 /app/relay/ai_training_materials/global_attacks.json

# Count total attacks
docker exec security-relay-server jq '. | length' /app/relay/ai_training_materials/global_attacks.json

# Watch attacks live
docker exec security-relay-server tail -f /app/relay/ai_training_materials/global_attacks.json

# Or access mounted volume on host (if using volume mounts)
tail -50 /root/battle-hardened-ai/relay/ai_training_materials/global_attacks.json
```

### Check Relay Server Logs
```bash
# On relay server
docker logs security-relay-server --tail 100 | grep "Saved SANITIZED attack"
```

---

## 🛡️ ENTERPRISE WHITELIST CONFIGURATION

**File:** `server/json/whitelist.json`

**Example Enterprise Configuration (explicit, operator-managed):**
```json
[
  "10.0.0.1",          // Enterprise gateway
  "192.168.0.116",     // Security appliance (self)
  "172.18.0.1",        // Docker bridge (Windows) - only if this host truly must never be blocked
  "172.17.0.1",        // Docker bridge (Linux) - only if this host truly must never be blocked
  "10.0.1.10",         // SOC workstation
  "10.0.1.11",         // SIEM collector
  "10.0.2.5",          // Active Directory DC
  "10.0.3.20"          // Patch management server
]
```

**⚠️ IMPORTANT - Enterprise Deployment:**
- **DO NOT whitelist entire subnets** (e.g., `10.0.0.0/8`, `192.168.0.0/16`)
- **Only whitelist specific IPs** that must never be blocked:
  - Network infrastructure (gateways, DNS, NTP)
  - Security operations (SOC, SIEM, monitoring)
  - Management systems (AD DCs, patch servers)
  - CI/CD automation (deployment servers)
- **Pentesting workstations:** Remove from whitelist during security assessments
- **Default gateway exemption:** Only `.1` addresses (not entire VLAN)

**Testing/Development Note:**
- Pentesting IP `192.168.0.119` is **not** in the whitelist by default and will be blocked on attack attempts unless you explicitly add it for a specific lab scenario.

---

## 🚀 ATTACK TESTING FROM KALI

**All commands in:** `KALI_ATTACK_TESTS.md`

**Example SQL Injection:**
```bash
curl -k "https://192.168.0.116:60000/api/threats?id=1%27%20OR%20%271%27%3D%271"
```

**Expected Result:**
1. ✅ Returns 404 (honeypot catches non-existent endpoint)
2. ✅ IP `192.168.0.119` **BLOCKED** within 1 second
3. ✅ Logged to `threat_log.json` with "SQL Injection" type
4. ✅ Pattern extracted (keywords: `OR`, `=`)
5. ✅ Sent to relay server via WSS
6. ✅ Stored in relay server `global_attacks.json` (sanitized, no IP)
7. ✅ Next request from Kali: **403 Forbidden**

---

## 🔗 HOW THIS MAPS TO THE 7-STAGE PIPELINE & 21 DETECTION LAYERS

This 4-step attack handling flow is a concrete, minimal slice through the full 7-stage, 21-layer architecture described in README, Filepurpose.md, Dashboard.md, and Ai-instructions.md:

- **Stage 1 – Data Ingestion & Normalization:**
  - Packets from Kali are captured by server/network_monitor.py and normalized before entering the AI pipeline.
- **Stage 2 – Parallel Multi-Signal Detection (20 Signals + Step 21 Semantic Gate):**
  - AI/pcs_ai.py and AI/real_honeypot.py run the 20 detection signals (18 primary + 2 strategic) and then the Step 21 semantic execution-denial gate over the normalized event.
- **Stage 3 – Ensemble Decision Engine:**
  - AI/meta_decision_engine.py consumes the DetectionSignal list and produces a weighted decision (block/log/allow).
- **Stage 4 – Response Execution:**
  - `_block_ip()` in AI/pcs_ai.py calls server/device_blocker.py and writes blocked_ips.json, while `_log_threat()` and the honeypot logging functions update threat_log.json and honeypot_attacks.json.
- **Stage 5 – Training Extraction:**
  - AI/signature_extractor.py turns the logged attack into sanitized signatures (keywords, encodings, patterns) with no exploit code or raw payloads.
- **Stage 6 – Relay Sharing (Optional):**
  - AI/relay_client.py sends the sanitized pattern to relay/relay_server.py (running in Docker with AI/, relay/, server/ folders), which persists into relay/ai_training_materials/global_attacks.json and, over time, learned_signatures.json.
  - Relay server uses AI/crypto_security.py for HMAC verification and server/path_helper.py for path resolution.
- **Stage 7 – Continuous Learning:**
  - Relay/ai_retraining.py and related tooling use global_attacks.json and learned_signatures.json to retrain models and write updated signatures and models into relay/ai_training_materials (for example ml_models/).
  - Customer nodes later pull **only** pre-trained models via AI/training_sync_client.py (HTTPS to relay/training_sync_api.py on port 60002) and updated signatures/threat-intel bundles via AI/signature_distribution.py; no raw training data ever leaves relay.

The guarantees in this document are therefore a strict, end-to-end instantiation of the broader 7-stage, 21-layer design: any attack that triggers the detection stack will follow exactly this log → block → extract → relay path.

---

## Enforcement vs Enterprise Integration (Critical Distinction)

Battle-Hardened AI operates across two separate planes that serve different purposes and must not be confused.

### 1. Enforcement Plane (Execution Authority)

Battle-Hardened AI enforces decisions locally and directly at the first layer.

**Deployment role determines enforcement scope:**

| Deployment Role | Enforcement Authority | What Gets Blocked |
|----------------|----------------------|-------------------|
| **Gateway/Router** | Network-wide (entire segment) | All traffic through gateway (iptables/nftables) |
| **Host-only** | Host-level only | Traffic to/from this machine only |
| **Observer** | Detection-only (no enforcement) | Nothing (analysis mode) |

When deployed as a **gateway**, inline bridge, or privileged host appliance, Battle-Hardened AI runs with appropriate system authority and applies enforcement actions immediately using the underlying operating system's firewall and networking controls.

This includes:

- Dropping or rejecting connections
- Temporarily or permanently blocking sources
- Applying rate limits or isolation rules

These actions are executed without reliance on external systems, cloud services, or third-party APIs. This is what allows Battle-Hardened AI to deny execution before any downstream system is engaged.

In short: Battle-Hardened AI does not ask another system to block traffic – it enforces the decision itself at the boundary.

**For gateway deployment setup:**
- See [Installation.md § Linux Gateway Setup](../installation/Installation.md#scenario-1-linux-gatewayrouter-network-wide-protection---recommended)
- See [Installation.md § Cloud Gateway Setup](../installation/Installation.md#scenario-2-cloud-gateway-with-virtual-nics-awsazuregcp)
- See [Installation.md § Gateway Pre-Flight Checklist](../installation/Installation.md#-gateway-pre-flight-checklist)

### 2. Enterprise Integration Plane (Visibility & Coordination)

Separately, Battle-Hardened AI emits structured decision events (JSON / syslog) to enterprise platforms such as SIEMs, SOAR tools, and security dashboards.

These integrations exist to:

- Provide visibility into decisions
- Support auditing and compliance
- Enable correlation with other security telemetry
- Drive optional secondary workflows

Enterprise platforms do not perform first-layer blocking. They observe, record, and coordinate around decisions that have already been enforced.

This separation ensures:

- Deterministic, low-latency protection
- No dependency on vendor APIs for enforcement
- No requirement for per-vendor firewall integrations

---

## 📈 CURRENT STATUS

| Component | Status | Details |
|-----------|--------|---------|
| **Attack Detection** | ✅ WORKING | Catch-all honeypot active |
| **IP Blocking (Application)** | ✅ WORKING | `_block_ip()` called for ALL attacks |
| **IP Blocking (Kernel Firewall)** | ✅ WORKING | Dual-layer enforcement (5s sync) |
| **Firewall Backend Detection** | ✅ WORKING | iptables/firewalld/VyOS/OpenWRT/Alpine |
| **Firewall Sync Daemon** | ✅ WORKING | 5-second loop syncing to kernel |
| **Dashboard Management** | ✅ WORKING | Section 7, Tab 4 "Linux Firewall Commander" |
| **Local Storage** | ✅ WORKING | `threat_log.json`, `blocked_ips.json` |
| **Pattern Extraction** | ✅ WORKING | Keywords, encodings extracted |
| **Relay Connection** | ✅ WORKING | `wss://<RELAY_SERVER_IP>:60001` connected |
| **Relay Storage** | ✅ WORKING | 225 attacks stored in `global_attacks.json` |
| **Kali Whitelist** | ✅ REMOVED | Will be blocked on attack |

---

## ⚠️ CRITICAL: NO EXCEPTIONS

**EVERY attack pattern triggers:**
1. **Immediate IP block** (< 1 second - Application layer HTTP 403)
2. **Kernel firewall block** (< 5 seconds - Network layer DROP)
3. **Local storage** (threat_log.json + blocked_ips.json)
4. **Pattern extraction** (sanitized signatures)
5. **Relay to relay server** (global sharing)
6. **Relay server storage** (global_attacks.json)

**NO HIDDEN WHITELISTING** for attack sources (beyond localhost defaults, dynamic GitHub ranges, and any explicit entries you put into `whitelist.json`)
**NO DELAYS** in application-layer blocking (instant on detection)
**5-SECOND SYNC** for kernel firewall enforcement (acceptable latency)
**NO EXCEPTIONS** for any attack type

---

**Last Verified:** February 6, 2026  
**Status:** ✅ ARCHITECTURE COMPLIANT  
**Architecture Enhancements:** 6 features implemented (Model Signing, Pattern Filtering, Performance Monitoring, Adversarial Training, ONNX, Linux Firewall Commander)
