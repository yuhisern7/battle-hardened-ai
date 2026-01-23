# COMPLETE ATTACK HANDLING FLOW

> **Audience & distribution:** This document is written for **security engineers, architects, and auditors** who want to verify that the implemented attack path matches the documented design. It describes the **intended and currently implemented behavior** of the system, not a legal or formal security guarantee. Operational behavior still depends on configuration (for example whitelist entries, deployment mode, and firewall wiring).

## ✅ INTENDED BEHAVIOR: DETECTED ATTACKS ARE IMMEDIATELY BLOCKED

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
- **Whitelist Check:** Skips whitelisting for hardcoded infrastructure and managed whitelist entries
- **GitHub IP Check:** Skips GitHub IPs (for automated security updates)
- **Docker Bridge Check:** Skips Docker bridge interfaces
- **BLOCKS EVERYONE ELSE** - Added to `_blocked_ips` set
- **Persisted:** Saved to `server/json/blocked_ips.json` (Line 3104)

**Result:** Attacker CANNOT make any more requests (403 Forbidden)

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
**Location:** `AI/pcs_ai.py` (relay client integration)
**Condition:** `RELAY_ENABLED=true` (✅ Enabled in `.env`)
**Module:** `AI/relay_client.py`

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
**Container:** `security-relay-server` (Docker)
**File:** `/app/relay/ai_training_materials/global_attacks.json`

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

# View last 50 attacks stored
tail -50 /root/battle-hardened-ai/relay/ai_training_materials/global_attacks.json

# Count total attacks
jq '. | length' /root/battle-hardened-ai/relay/ai_training_materials/global_attacks.json

# Watch attacks live
tail -f /root/battle-hardened-ai/relay/ai_training_materials/global_attacks.json
```

### Check Relay Server Logs
```bash
# On relay server
docker logs security-relay-server --tail 100 | grep "Saved SANITIZED attack"
```

---

## 🛡️ ENTERPRISE WHITELIST CONFIGURATION

**File:** `server/json/whitelist.json`

**Example Enterprise Configuration:**
```json
[
  "10.0.0.1",          // Enterprise gateway
  "192.168.0.116",     // Security appliance (self)
  "172.18.0.1",        // Docker bridge (Windows)
  "172.17.0.1",        // Docker bridge (Linux)
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
- Pentesting IP `192.168.0.119` was **REMOVED** from whitelist ✅
- Will now be blocked on attack attempts (as designed)

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
  - AI/relay_client.py sends the sanitized pattern to relay/relay_server.py, which persists into relay/ai_training_materials/global_attacks.json and, over time, learned_signatures.json.
- **Stage 7 – Continuous Learning:**
  - Relay/ai_retraining.py and related tooling use global_attacks.json and learned_signatures.json to retrain models and distribute updated signatures and models back to nodes.

The guarantees in this document are therefore a strict, end-to-end instantiation of the broader 7-stage, 21-layer design: any attack that triggers the detection stack will follow exactly this log → block → extract → relay path.

---

## 📈 CURRENT STATUS

| Component | Status | Details |
|-----------|--------|---------|
| **Attack Detection** | ✅ WORKING | Catch-all honeypot active |
| **IP Blocking** | ✅ WORKING | `_block_ip()` called for ALL attacks |
| **Local Storage** | ✅ WORKING | `threat_log.json`, `blocked_ips.json` |
| **Pattern Extraction** | ✅ WORKING | Keywords, encodings extracted |
| **Relay Connection** | ✅ WORKING | `wss://<RELAY_SERVER_IP>:60001` connected |
| **Relay Storage** | ✅ WORKING | 225 attacks stored in `global_attacks.json` |
| **Kali Whitelist** | ✅ REMOVED | Will be blocked on attack |

---

## ⚠️ CRITICAL: NO EXCEPTIONS

**EVERY attack pattern triggers:**
1. **Immediate IP block** (< 1 second)
2. **Local storage** (threat_log.json + blocked_ips.json)
3. **Pattern extraction** (sanitized signatures)
4. **Relay to relay server** (global sharing)
5. **Relay server storage** (global_attacks.json)

**NO WHITELISTING** for attack sources (except localhost/Docker/GitHub)
**NO DELAYS** in blocking (instant on detection)
**NO EXCEPTIONS** for any attack type
