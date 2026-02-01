# Dashboard Sections: Complete API Reference

This document provides a comprehensive guide to the core dashboard sections, mapping them to the **7-stage attack detection pipeline** and their corresponding APIs and AI modules.

> **Distribution note:** In production, customers typically access the dashboard via a **Linux appliance installed from a .deb/.rpm package** or a **Windows host/appliance installed from the signed EXE**, and do **not** work with the Git source tree. The API examples and helper scripts in this file assume a **development or lab environment** where you have the repository checked out and can run Python scripts from the project root. For packaged deployments, you can still hit the same HTTPS endpoints (for example from Postman or your own tools); just ignore any instructions that mention the repo layout.

**Installation & Setup:**
- For installation instructions, see [Installation](installation/Installation.md)
- For relay server setup, see [relay/RELAY_SETUP.md](relay/RELAY_SETUP.md)
- For attack testing, see [KALI_ATTACK_TESTS.md](KALI_ATTACK_TESTS.md)

**Pipeline Stages:**
1. **Data Ingestion**  Packet capture, metadata extraction
2. **Parallel Detections (20 Signals + Step 21 Semantic Gate)**  Independent threat assessments with a final semantic execution-denial gate (21 total detection layers)
3. **Ensemble Voting**  Weighted consensus decision
4. **Response Execution** → Firewall blocks, logging, alerts
5. **Training Extraction** → Privacy-preserving signatures
6. **Relay Sharing** → Global intelligence exchange
7. **Continuous Learning** → ML retraining, adaptation

---

## Quick Start: Testing Dashboard APIs

**Prerequisites (developer/lab usage):**
- Dashboard running at `https://localhost:60000` (packaged node or dev instance)
- Git checkout of the repo if you want to use the Python helper scripts (run them from the `battle-hardened-ai/` root)
- Install `requests`: `pip install requests`

**Common Helper:**
```python
import requests

BASE_URL = "https://localhost:60000"

def show_json(path: str):
    """Fetch and display any dashboard API endpoint."""
    url = f"{BASE_URL}{path}"
    resp = requests.get(url, timeout=10, verify=False)  # Note: verify=False for self-signed cert
    resp.raise_for_status()
    print(f"GET {url} -> status {resp.status_code}")
    print(resp.json())
```

---

## Pipeline Stage Map: Sections by Detection Stage

### Stage 1: Data Ingestion & Normalization

**Dashboard Sections:**
- **Section 2:** Network Devices – Live Monitor, Ports & History
- **Section 17:** Traffic Analysis & Inspection
- **Section 18:** DNS & Geo Security

---

### Stage 2: Parallel Multi-Signal Detection (20 Signals + Step 21 Semantic Gate)

**Dashboard Sections:**
- **Section 3:** VPN/Tor De-Anonymization (Signal #11)
- **Section 4:** Real AI/ML Models (Signals #3-9, #16-20)
- **Section 6:** Threat Analysis by Type (All signals aggregated)
- **Section 8:** Failed Login Attempts (Behavioral Signal #6)
- **Section 10:** Automated Signature Extraction (Signal #2)
- **Section 13:** Attack Chain Visualization (Graph Signal #10)
- **Section 15:** Adaptive Honeypot (Signal #2 training source)
- **Section 16:** AI Security Crawlers & Threat Intelligence (Signal #12)
- **Section 22:** Cryptocurrency Mining Detection (Traffic Signal #8)

---

### Stage 3: Ensemble Decision Engine

**Dashboard Sections:**
- **Section 5:** Security Overview – Live Statistics (Final voting results)
- **Section 7:** IP Management & Threat Monitoring (Block/log/allow decisions)
- **Section 9:** Attack Type Breakdown (View only; drill‑down fed by Section 6 ensemble statistics)
- **Section 14:** Decision Explainability Engine (Weighted voting transparency)

---

### Stage 4: Response Execution

**Dashboard Sections:**
- **Section 11:** System Health & Network Performance (Self-protection monitoring)
- **Section 21:** Email/SMS Alerts (Critical-event alert delivery)

---

### Stage 5: Training Material Extraction

**Dashboard Sections:**
- **Section 10:** Automated Signature Extraction (Privacy-preserving patterns)
- **Section 15:** Adaptive Honeypot (High-quality training source)

---

### Stage 6: Global Intelligence Sharing

**Dashboard Sections:**
- **Section 1:** AI Training Network – Shared Machine Learning (P2P/relay status)
- **Section 23:** Governance & Emergency Controls (Central sync status)

---

### Stage 7: Continuous Learning Loop

**Dashboard Sections:**
- **Section 4:** Real AI/ML Models (Drift detection, lineage, retraining metrics)
- **Section 12:** Audit Evidence & Compliance Mapping (Evidence extraction, formal threat‑model summaries mapped to external frameworks)

---

### Enterprise & Validation Features (Beyond Core Pipeline)

**Dashboard Sections:**
- **Section 19:** User & Identity Trust Signals
- **Section 20:** Sandbox Detonation
  

---

## Section Reference: APIs & Modules by Dashboard Section

## Section 1 – AI Training Network (Stage 6: Relay Sharing)

**Pipeline Stage:** Global Intelligence Sharing
**Purpose:** Shows P2P mesh status, relay connectivity, and federated learning metrics

**APIs:**
- `/api/p2p/status` — P2P mesh health and peer count
- `/api/relay/status` — Relay server connectivity
- `/api/p2p/threats` — Threats shared/received via relay

**Backend Modules:**
- `AI/p2p_sync.py` — P2P synchronization
- `AI/relay_client.py` — Relay communication
- `AI/byzantine_federated_learning.py` — Federated aggregation

**Test Script:**
```python
from helper import show_json

show_json("/api/p2p/status")    # P2P mesh status
show_json("/api/relay/status")  # Relay connectivity
show_json("/api/p2p/threats")   # Shared threat intelligence
```

---

## Section 2 – Network Devices (Stage 1: Data Ingestion)

**Pipeline Stage:** Data Ingestion & Normalization
**Purpose:** Live device discovery, asset inventory, and network topology

**APIs:**
- `/api/connected-devices` — Active devices on network
- `/api/scan-devices` — Trigger new device scan
- `/api/current-ports` — Port scan configuration
- `/api/device-history` — 7-day device connection history
- `/api/assets/inventory` — Complete asset inventory
- `/api/visualization/topology` — Network topology graph

**Backend Modules:**
- `server/device_scanner.py` — Device discovery with cross-platform network detection (Linux: ip route/addr, Windows: ipconfig parsing, fallback: socket trick)
- `AI/asset_inventory.py` — Asset management
- `AI/advanced_visualization.py` — Topology visualization

**Test Script:**
```python
from helper import show_json

show_json("/api/connected-devices")       # Live devices
show_json("/api/current-ports")           # Port scan config
show_json("/api/device-history")          # Historical connections
show_json("/api/assets/inventory")        # Asset inventory
show_json("/api/visualization/topology")  # Network graph
```

---

## Section 3 – VPN/Tor De-Anonymization (Stage 2: Signal #11)

**Pipeline Stage:** Parallel Multi-Signal Detection
**Detection Signal:** #11 VPN/Tor Fingerprinting
**Purpose:** Multi-vector de-anonymization statistics

**APIs:**
- Internal: `pcs_ai.get_vpn_tor_statistics()` (no direct HTTP endpoint)

**Backend Modules:**
- `AI/pcs_ai.py` — VPN/Tor tracking (Signal #11)
- Integrated into threat enrichment pipeline

**Test Script:**
```python
import os, sys
sys.path.insert(0, os.path.dirname(__file__))
import AI.pcs_ai as pcs_ai

stats = pcs_ai.get_vpn_tor_statistics()
print(stats)
```

---

## Section 4 – Real AI/ML Models (Stage 2: Signals #3-9, #16-20)

**Pipeline Stage:** Parallel Multi-Signal Detection + Continuous Learning
**Detection Signals:**
- #3 RandomForest
- #4 IsolationForest
- #5 Gradient Boosting
- #7 LSTM
- #8 Autoencoder
- #9 Drift Detection
- #16 Predictive Modeling
- #17 Byzantine Defense
- #18 Integrity Monitoring (Cryptographic Lineage)
- #19 Causal Inference Engine
- #20 Trust Degradation Graph

**APIs:**
- `/api/stats` — includes `ml_stats` with per-model metrics and layer detection stats
- `/api/layer-stats` — focused JSON export of per-layer AI/ML detection counters
- Internal: `pcs_ai.get_ml_model_stats()` (aggregated from multiple modules)

**Backend Modules:**
- `AI/pcs_ai.py` — Model orchestration
- `AI/drift_detector.py` — Signal #9
- `AI/meta_decision_engine.py` — Ensemble stats
- `AI/reputation_tracker.py` — Signal #14
- `AI/byzantine_federated_learning.py` — Signal #17
- `AI/cryptographic_lineage.py` — Signal #18
- `AI/deterministic_evaluation.py` — Model validation

**Test Script:**
```python
import os, sys
sys.path.insert(0, os.path.dirname(__file__))
import AI.pcs_ai as pcs_ai
from pprint import pprint

ml_stats = pcs_ai.get_ml_model_stats()
pprint(ml_stats)
```

---

## Section 5  Security Overview (Stage 3: Ensemble Results)

**Pipeline Stage:** Ensemble Decision Engine + Step 21 Semantic Gate
**Purpose:** High-level KPIs from ensemble voting across all 20 detection signals, gated by the Step 21 semantic execution-denial layer (21 total detection layers)

**APIs:**
- Internal: `pcs_ai.get_threat_statistics()`

**Backend Modules:**
- `AI/pcs_ai.py` — Aggregated threat stats
- `AI/meta_decision_engine.py` — Ensemble decisions

**Test Script:**
```python
import os, sys
sys.path.insert(0, os.path.dirname(__file__))
import AI.pcs_ai as pcs_ai
from pprint import pprint

stats = pcs_ai.get_threat_statistics()
pprint(stats)
```

---

## Section 6  Threat Analysis by Type (Stage 2: All Signals Aggregated)

**Pipeline Stage:** Parallel Multi-Signal Detection (aggregated across all 20 detection signals, prior to Step 21 semantic gating)
**Purpose:** Per-attack-type breakdown from ensemble classifications

**APIs:**
- Internal: `pcs_ai.get_threat_statistics()` → `threats_by_type`

**Backend Modules:**
- `AI/pcs_ai.py` — Threat type aggregation from all signals

**Test Script:**
```python
import os, sys
sys.path.insert(0, os.path.dirname(__file__))
import AI.pcs_ai as pcs_ai

stats = pcs_ai.get_threat_statistics()
print(stats.get("threats_by_type", {}))
```

---

## Section 7 – IP Management & Threat Monitoring (Stage 3: Decision Outcomes)

**Pipeline Stage:** Ensemble Decision Engine (block/log/allow outcomes)
**Purpose:** Per-IP threat history, block/whitelist management

**APIs:**
- `/api/threat_log` — Complete threat log with ensemble decisions
- `/api/unblock/<ip>` — Remove IP from blocklist
- `/api/whitelist` — Current whitelist
- `/api/whitelist/add`, `/api/whitelist/remove` — Whitelist management
- `/api/threat/block-ip` — Manual block trigger
- `/api/stats` — Includes `blocked_ips_count`

**Backend Modules:**
- `AI/pcs_ai.py` — `_threat_log`, `get_blocked_ips()`, `get_whitelisted_ips()`
- `AI/meta_decision_engine.py` — Final block/log/allow decisions
- `AI/reputation_tracker.py` — Signal #14 (cross-session reputation)

**Test Script:**
```python
from helper import show_json

show_json("/api/threat_log")   # Threat log with decisions
show_json("/api/whitelist")    # Whitelist entries
show_json("/api/stats")        # Blocked IPs count
```

---

## Section 8 – Failed Login Attempts (Stage 2: Signal #6 Behavioral)

**Pipeline Stage:** Parallel Multi-Signal Detection
**Detection Signal:** #6 Behavioral Heuristics
**Purpose:** Tracks failed authentication attempts as part of behavioral threat scoring

Backed by: `stats.failed_login_attempts` inside `pcs_ai.get_threat_statistics()`.

```python
# Show failed login attempts tracked for this server
import os, sys
sys.path.insert(0, os.path.dirname(__file__))
import AI.pcs_ai as pcs_ai

stats = pcs_ai.get_threat_statistics()
print(stats.get("failed_login_attempts", {}))
```

## Section 9 – Attack Type Breakdown (View)

Backed by: `stats.attack_summary` from `pcs_ai.get_threat_statistics()` and the same ensemble statistics that power Section 6. This section is a visual drill‑down only and does not introduce new detection logic.

```python
# Show aggregate attack‑type counts for the chart
import os, sys
sys.path.insert(0, os.path.dirname(__file__))
import AI.pcs_ai as pcs_ai

stats = pcs_ai.get_threat_statistics()
print(stats.get("attack_summary", {}))
```

## Section 10 – Automated Signature Extraction – Attack Pattern Analysis

Backed by: `/api/signatures/extracted`, `/api/signatures/types`, `/api/signatures/stats` and `AI/signature_extractor.py`, `AI/signature_distribution.py`.

```python
# Inspect extracted defensive signatures and stats
from helper import show_json

show_json("/api/signatures/extracted")  # extracted patterns
show_json("/api/signatures/types")      # attack types with signatures
show_json("/api/signatures/stats")      # high‑level signature stats
```

## Section 11 – System Health & Network Performance

Backed by: `/api/system-status`, `/api/performance/metrics`, `/api/performance/network-stats`, `/api/performance/anomalies`, `/api/self-protection/stats` and modules like `AI/network_performance.py`, `AI/system_log_collector.py`, `AI/self_protection.py`.

For high-availability and clustering, a separate lightweight `/health` endpoint is exposed for load balancers and passive nodes. It returns node_id, cluster_name, current role (active/passive/standalone), a timestamp, and minimal threat counters so failover logic can make decisions without hitting heavier APIs.

```python
# Show host health and network performance metrics
from helper import show_json

show_json("/api/system-status")             # CPU, RAM, disk, uptime, services
show_json("/api/performance/metrics")       # time‑series perf metrics
show_json("/api/performance/network-stats") # bandwidth/latency
show_json("/api/performance/anomalies")     # detected anomalies
show_json("/api/self-protection/stats")     # integrity/self‑protection stats
show_json("/health")                        # node + cluster health for HA
```

## Section 12 – Audit Evidence & Compliance Mapping

Backed by: `/api/compliance/summary`, `/api/compliance/report/<type>`, `/api/threat-model/stats`, `/api/audit-log/stats` and `AI/compliance_reporting.py`, `AI/policy_governance.py`, `AI/formal_threat_model.py`.

```python
# Reveal audit evidence and threat‑model/audit summaries suitable for external compliance mapping
from helper import show_json

show_json("/api/compliance/summary")       # evidence summaries aligned to PCI/HIPAA/GDPR/SOC2 controls
show_json("/api/threat-model/stats")       # formal threat‑model metrics
show_json("/api/audit-log/stats")          # audit log statistics
# For full reports: /api/compliance/report/gdpr (or pci, hipaa, soc2, etc.)
show_json("/api/compliance/report/gdpr")
```

## Section 13 – Attack Chain Visualization (Stage 2: Signal #10 Graph Intelligence)

**Pipeline Stage:** Parallel Multi-Signal Detection
**Detection Signal:** #10 Graph Intelligence (lateral movement, C2 detection)
**Purpose:** Kill-chain visualization, hop chains, pivot detection

**APIs:**
- `/api/graph-intelligence/attack-chains` — Attack chain topology

**Backend Modules:**
- `AI/graph_intelligence.py` — Signal #10 implementation
- `AI/advanced_visualization.py` — Graph rendering

**JSON Output:**
- `network_graph.json` — Topology data (stored under the JSON directory resolved by AI/path_helper, typically server/json/ in native/Windows EXE runs or /app/json/ in Docker)
- `lateral_movement_alerts.json` — Hop chain alerts (same JSON directory resolution)

**Test Script:**
```python
from helper import show_json

show_json("/api/graph-intelligence/attack-chains")
```

---

## Section 14 – Decision Explainability Engine (Stage 3: Transparency)

**Pipeline Stage:** Ensemble Decision Engine (decision transparency)
**Detection Signal:** #15 Explainability Engine
**Purpose:** Human-readable explanations for block/log/allow decisions

**APIs:**
- `/api/explainability/decisions` — Recent decisions with per-signal contributions

**Backend Modules:**
- `AI/explainability_engine.py` — Signal #15 implementation
- `AI/meta_decision_engine.py` — Weighted voting breakdown
- `AI/false_positive_filter.py` — Gate-level reasoning

**JSON Output:**
- `forensic_reports/*.json` — Incident explainability reports stored under the JSON directory resolved by AI/path_helper (typically server/json/ in native/Windows EXE runs or /app/json/ in Docker). These are used for offline analysis (no separate hunting console).

**Test Script:**
```python
from helper import show_json

show_json("/api/explainability/decisions")
```

---

## Section 15 – Real Honeypot Services (Stage 5: Training Source)

**Pipeline Stage:** Training Material Extraction (100% confirmed attacks)
**Detection Signal:** Feeds Signal #2 (Signature Matching) with high-quality training data
**Purpose:** Multi-service deception, attacker profiling, signature extraction

**Real Honeypot Services:**
- **SSH** (port 2222) - Fake SSH server with banners
- **FTP** (port 2121) - FTP with directory listings
- **Telnet** (port 2323) - Legacy telnet service
- **MySQL** (port 3306) - Database honeypot
- **HTTP Admin** (port 8080) - Web admin interface
- **SMTP** (port 2525) - Mail server honeypot
- **RDP** (port 3389) - Remote desktop honeypot

**Port Conflicts & Coverage Note:**
- These ports are fixed by design so operators can reason about coverage.
- If a port is already used by a real service on a given node, the honeypot for that port **automatically skips startup** instead of competing for the port.
- The `/api/adaptive_honeypot/status` and `/api/honeypot/status` responses reflect this: services where the port was in use will appear with `running: false`, while remaining honeypot services continue to run.

**APIs:**
- `/api/adaptive_honeypot/status` — Service status, attack counts
- `/api/adaptive_honeypot/attacks` — Recent honeypot hits (last 100)
- `/api/adaptive_honeypot/attacks/history` — Full attack history (max 1000)
- `/api/honeypot/status` — Detailed service status

**Backend Modules:**
- `AI/real_honeypot.py` — Multi-service honeypot implementation
- `AI/signature_extractor.py` — Extract patterns from honeypot attacks
- `AI/false_positive_filter.py` — Honeypot hits bypass whitelists (Gate 1)
- `AI/meta_decision_engine.py` — Honeypot signals weighted 0.98 (highest)

**JSON Output:**
- `honeypot_attacks.json` — All honeypot attack logs (under the JSON directory resolved by AI/path_helper; usually server/json/ or /app/json/)
- `honeypot_patterns.json` — Extracted attack patterns (same JSON directory resolution)

**Delayed IP Blocking:**
- First attack logged → 60-second delay before IP block
- Allows multiple attack attempts for better pattern analysis
- Countdown messages: "⏳ Attack from IP - 45s until block"

**Test Script:**
```python
from helper import show_json

show_json("/api/adaptive_honeypot/status")       # Status & services
show_json("/api/adaptive_honeypot/attacks")      # Recent hits
show_json("/api/adaptive_honeypot/attacks/history")  # Full history
show_json("/api/honeypot/status")                # Detailed status
```

**Testing from Kali Linux:**
```bash
# Test SSH honeypot
telnet WINDOWS_IP 2222

# Test FTP honeypot  
telnet WINDOWS_IP 2121

# Brute force attack (triggers delayed blocking)
hydra -l admin -P rockyou.txt ftp://WINDOWS_IP:2121 -t 4
```

---

## Section 16 – AI Security & Threat Intelligence Sources

**Pipeline Stage:** Parallel Multi-Signal Detection
**Detection Signal:** #12 Threat Intelligence Integration
**Purpose:** External threat feeds, ExploitDB signatures, reputation databases

**Threat Intelligence Sources:**
- **ExploitDB** - 43,971+ exploit signatures (auto-downloaded on relay server)
- **VirusTotal** - 70+ security vendor analysis (optional API key)
- **AbuseIPDB** - Community IP blacklist (optional API key)
- **Honeypot Intelligence** - Real-world attack data from honeypot services
- **P2P Threat Sharing** - Global threat exchange via relay/P2P mesh

**APIs:**
- `/api/system-status` — Shows VirusTotal/AbuseIPDB status
- `/api/update-api-key` — Configure VirusTotal/AbuseIPDB keys
- `/api/signatures/extracted` — Extracted defensive signatures
- `/api/signatures/types` — Attack types with signatures
- `/api/signatures/stats` — Signature statistics

**Backend Modules:**
- `AI/threat_intelligence.py` — Core threat intel integration (Signal #12)
- `relay/exploitdb_scraper.py` — ExploitDB download and parsing
- `relay/threat_crawler.py` — Dark web monitoring
- `AI/signature_extractor.py` — Pattern extraction from attacks
- `AI/signature_distribution.py` — P2P signature sharing

**Configuration:**
Set API keys in `.env` file or via dashboard System Status section:
```bash
VIRUSTOTAL_API_KEY=your_64_char_key_here
ABUSEIPDB_API_KEY=your_key_here
```

**Test Script:**
```python
from helper import show_json

show_json("/api/system-status")            # Shows threat intel status
show_json("/api/signatures/extracted")     # Extracted patterns
show_json("/api/signatures/types")         # Attack types
show_json("/api/signatures/stats")         # Signature statistics
```

## Section 17 – Traffic Analysis & Inspection

Backed by: `/api/traffic/analysis`, `/api/pcap/stats` plus `AI/traffic_analyzer.py`, `AI/kernel_telemetry.py`, `AI/pcap_capture.py`.

**Dashboard Metrics:**
- **Deep Packet Inspection (DPI)** — Total packets analyzed from active network interfaces
- **Application Blocks** — Count of blocked applications (Tor, BitTorrent) detected via traffic analysis
- **Encrypted Traffic %** — Percentage of connections using TLS/SSL (port 443)

```python
# Reveal live traffic analysis (DPI, app blocking, encrypted traffic)
from helper import show_json

show_json("/api/traffic/analysis")  # Returns {total_packets, protocols, encrypted_percent, blocked_apps, total_connections}
show_json("/api/pcap/stats")        # PCAP capture statistics
```

**Why Section 17 might show zeros:**
- `total_packets = 0` → No network interface traffic captured yet (normal for new installs)
- `blocked_apps = {}` → No Tor/BitTorrent detected (good security posture)
- `encrypted_percent = 0%` → No active connections on port 443 (normal if no HTTPS traffic)

## Section 18 – DNS & Geo Security

Backed by: `/api/dns/stats`, `/api/visualization/geographic` and `AI/dns_analyzer.py`, `AI/advanced_visualization.py`.

**Dashboard Metrics:**
- **DNS Queries Analyzed** — Total DNS queries observed and scored (from dns_security.json per-source metrics)
- **Geographic Attack Table** — Countries attacking the network with attack counts, threat levels, and block status

**What this section does:**
Two-panel observability surface combining **DNS behavior analytics** (tunneling/DGA detection) with **geographic attack mapping**. This is a **telemetry and decision-support surface**, not an inline DNS firewall or geo-blocking engine.

**Left Panel: DNS Security (dns_analyzer.py)**
- DNS tunneling / exfiltration heuristics (entropy analysis, label length, base64-like patterns)
- DGA-like domain detection (high-entropy, algorithmically-generated C&C domains)
- Large TXT/NULL payload anomalies (uncommon for normal DNS)
- Per-source IP query tracking and suspicious query counter
- **No built-in blocklist or DNSSEC validator** — those capabilities live in external DNS resolvers

**Right Panel: Geo-IP View (advanced_visualization.py)**
- Table showing countries, attack counts, threat levels (Low/Medium/High/Critical), and block status
- Data sourced from threat_log.json geolocation enrichment (7-day window)
- **Enforcement is external** — use this data to drive rules in perimeter firewalls/WAF/VPN, not inline blocking

```python
# Show DNS statistics, tunneling/DGA detections, and geo‑risk hints
from helper import show_json

show_json("/api/dns/stats")                    # DNS query counts, suspicious query counter
show_json("/api/visualization/geographic")     # Country-level attack statistics
```

**Detection Methods (DNS):**
1. **Subdomain Length Analysis** — Very long labels flag tunneling candidates
2. **Shannon Entropy** — High-entropy labels (random-looking) indicate DGA or exfil encoding
3. **Deep Subdomain Chains** — Many labels in single name (6+) common for tunneling frameworks
4. **Base64-Like Patterns** — Labels matching base64 character distribution suggest data encoding
5. **Large TXT/NULL Payloads** — Uncommon record types with large payloads (>400 bytes) flag exfil attempts

**Why Section 18 might show zeros:**
- `dns-queries = 0` → No DNS queries captured yet in dns_security.json (normal for new installs)
- `geo-data-tbody empty` → No attacks logged in threat_log.json with geolocation data (good security posture)

## Section 19 – User & Identity Trust Signals

Backed by: `/api/users/tracking`, `/api/zero-trust/scores`, `/api/zero-trust/data-classification` and `AI/user_tracker.py`, `AI/zero_trust.py`.

```python
# UEBA‑style trust signals and behavioral scoring (not IAM or policy admin)
from helper import show_json

show_json("/api/users/tracking")                 # user behavior & sessions
show_json("/api/zero-trust/scores")             # trust scores for entities
show_json("/api/zero-trust/data-classification")# data‑classification views used as trust signals

Admin identity for the dashboard itself (local admins with salted password hashes, optional TOTP MFA, optional LDAP-backed login, and optional OIDC SSO) is configured via `admin_users.json` and `identity_access_config.json` in the JSON directory resolved by AI/path_helper (typically server/json/ or /app/json/). This configuration is enforced around all sensitive APIs, but it does not have a separate public JSON API surface and is deliberately scoped as access control, not workforce IAM or lifecycle management.
```

## Section 20 – Sandbox Detonation

Backed by: `/api/sandbox/detonate`, `/api/sandbox/stats` and `AI/file_analyzer.py`.

```python
# Sandbox detonation statistics
from helper import show_json

show_json("/api/sandbox/stats")
# To detonate a sample:
# import requests; requests.post(BASE_URL+"/api/sandbox/detonate", files={"file": open("sample.bin","rb")})
```

## Section 21 – Email/SMS Alerts (Critical System Events)

Backed by: `/api/alerts/stats` and `AI/alert_system.py`.

**Dashboard Metrics:**
- **Alerts Sent (24h)** — Total notifications sent in last 24 hours (email + SMS combined)
- **Active Subscribers** — Number of configured recipients (email addresses + phone numbers)

**What this section does:**
Email/SMS alerting for **critical SYSTEM events only**: system failure, kill-switch changes, integrity breaches. Does NOT send general threat alerts (those go to SIEM). Uses SMTP for email and Twilio/AWS SNS/Nexmo for SMS.

**Dashboard Loaders:**
- `loadAlertStats()` — Updates alerts sent count and active subscribers count

```python
# Show alert system statistics
from helper import show_json

show_json("/api/alerts/stats")  # Returns {email_sent, sms_sent, subscribers}
```

**Configuration:**
- **Email:** Requires SMTP server, port (587/TLS recommended), encryption, recipients list
- **SMS:** Requires provider (Twilio/AWS SNS/Nexmo), phone numbers in international format (+1, +44, etc.)
- **Triggers:** Critical threats, new device detected, malware, insider threat (configurable checkboxes)

## Section 22 – Cryptocurrency Mining Detection

Backed by: `/api/traffic/crypto-mining` and `AI/crypto_security.py`.

**Dashboard Metrics:**
- **Miners Detected** — Total confirmed cryptocurrency mining processes/connections
- **High CPU Processes** — Processes using >80% CPU sustained (potential mining)
- **Mining Connections** — Active connections to known mining pools (Stratum protocol)
- **Risk Level** — Overall mining threat assessment (Low/Medium/High/Critical)

**What this section does:**
Detects unauthorized cryptomining malware (cryptojacking) through multiple signals: network traffic to mining pools, high CPU patterns, known mining software signatures, and Stratum protocol detection. Identifies Bitcoin/Monero/Ethereum mining activity.

**Dashboard Loaders:**
- `loadCryptoMiningDetection()` — Updates all 4 crypto mining metrics and detected mining activity list

```python
# Show cryptocurrency mining detection metrics
from helper import show_json

show_json("/api/traffic/crypto-mining")  # Returns {miner_processes, cpu_spikes, mining_connections, risk_level, detected_miners[], high_cpu_processes[], mining_traffic[]}
```

**Detection Methods:**
1. Mining pool connection detection (500+ known pools)
2. Stratum protocol analysis (JSON-RPC mining protocol)
3. CPU usage pattern analysis (>80% sustained on all cores)
4. Process name/hash signatures (XMRig, CGMiner, BFGMiner, etc.)
5. DNS queries for mining domains
6. GPU usage anomalies
7. Memory access patterns typical of mining algorithms
from helper import show_json

show_json("/api/zero-trust/dlp")  # Returns DISABLED with zero counts
```

### 22.5 – Backup & Recovery Status

**APIs:**
- `/api/backup/status` — Backup monitoring and ransomware resilience metrics

**Dashboard Loaders:**
- `loadBackupRecoveryStatus()` — Updates backup locations, success rates, resilience scores, RTO

```python
from helper import show_json

show_json("/api/backup/status")  # Returns DISABLED with zero counts
```

## Section 23 – Governance & Emergency Controls

**Purpose:** Command surface for high-assurance governance with kill-switch, approval workflows, audit logging, and secure deployment controls.

**APIs:**
- `/api/killswitch/status` — Emergency kill-switch mode and state changes
- `/api/governance/stats` — Approval queue metrics and pending requests
- `/api/system-logs/{os}` — System logs for Linux/Windows/macOS
- `/api/self-protection/stats` — Integrity monitoring and self-protection status
- `/api/secure-deployment/stats` — Secure deployment and tamper control metrics
- `/api/audit-log/stats` — Audit log health and statistics
- `/api/ai/abilities` — 18 AI abilities on/off flags
- `/api/central-sync/status` — Central sync controller status
- `/api/system-status` — Underlying node health

**Backend Modules:**
- `AI/emergency_killswitch.py` — Kill-switch mode control (ACTIVE/MONITORING_ONLY/SAFE_MODE/DISABLED)
- `AI/policy_governance.py` — Approval workflows and policy enforcement
- `AI/system_log_collector.py` — Multi-OS system log collection
- `AI/self_protection.py` — Integrity monitoring and tampering detection
- `AI/secure_deployment.py` — Secure deployment controls (air-gap, DIL, MAC, zeroize)
- `AI/central_sync.py` — Central sync coordination

**Dashboard Loaders:**
- `loadGovernanceControls()` — Single unified loader that updates:
  - Kill-switch mode, changes count, last changed by
  - Approval queue metrics (pending, approved, rejected, auto-approved, auto-approval rate)
  - Pending approval requests list
  - Audit log statistics and critical events
  - Self-protection integrity status and violation counts
  - Secure deployment metrics (air-gap, DIL, MAC, tamper manifest)
- `loadSystemLogs(osType)` — Updates Linux/Windows/macOS system log metrics (called separately with tab switching)
- Individual helper loaders also available: `loadKillswitchStatus()`, `loadGovernanceStats()`, `loadSelfProtectionStats()`, `loadSecureDeployment()`

**Metrics Displayed:**

**Kill-Switch:**
- Current mode (ACTIVE/MONITORING_ONLY/SAFE_MODE/DISABLED)
- Total mode changes count
- Last changed by user/timestamp

**Approval Queue:**
- Pending approvals awaiting human review
- Total approved/rejected requests
- Auto-approved requests and auto-approval rate
- Pending approval requests list

**System Logs (3 OS tabs):**
- Crashes, auth failures, service errors, total events per OS
- Recent event logs for Linux/Windows/macOS

**Self-Protection:**
- Integrity status (INTACT/COMPROMISED)
- Violations count (24 hours)
- Monitored components count
- Active telemetry sources

**Secure Deployment:**
- Air-gap mode status
- DIL/store-and-forward mode
- MAC policies (SELinux/AppArmor)
- Security domain label
- Key provider (software/HSM)
- Tamper manifest status

```python
# Governance, kill‑switch, approval‑queue, system logs, and secure deployment
from helper import show_json

show_json("/api/killswitch/status")        # Returns {current_mode, mode_changes, disabled_by, timestamp}
show_json("/api/governance/stats")         # Returns {pending_requests, approved_requests, rejected_requests, auto_approved_requests, auto_approval_rate, pending_requests[]}
show_json("/api/audit-log/stats")          # Returns {compliance_report_7d: {total_events, critical_events_count, events_by_type, critical_events[]}}
show_json("/api/self-protection/stats")    # Returns {violations_24h, monitored_components, telemetry_sources}
show_json("/api/secure-deployment/stats")  # Returns secure deployment metrics
show_json("/api/ai/abilities")             # 18 AI abilities on/off flags
show_json("/api/central-sync/status")      # central sync controller status
show_json("/api/system-status")            # underlying node health

# Clustered deployments also rely on two non-dashboard endpoints for governance and failover:
# - /health – lightweight node/cluster health used by external load balancers and passive nodes
# - /cluster/config/snapshot – active-node-only snapshot for config synchronization
```

## Section 24 – Enterprise Security Integrations (Outbound)

**Plane:** Enterprise Integration (visibility & coordination only)

**Purpose:** Configure and inspect outbound adapters that export first‑layer execution‑denial decisions into enterprise tooling such as SIEM, SOAR, and IT‑operations platforms, without introducing any new primary enforcement path.

**APIs:**
- `/api/enterprise-integration/config` (GET) — Returns current enterprise integration configuration
- `/api/enterprise-integration/config` (POST) — Updates configuration (admin‑only)

**Backend Modules & Surfaces:**
- `server/server.py` — Helper functions `_load_enterprise_integration_config()`, `_save_enterprise_integration_config()` and secured HTTP handlers
- `enterprise_integration.json` — JSON configuration file (syslog_targets, webhook_targets, etc.)
- `AI/enterprise_integration.py` — Integration logic for outbound adapters

**Dashboard Loaders:**
- `loadEnterpriseIntegrationStatus()` — Displays current syslog/webhook target counts
- Live JSON editor for `enterprise_integration.json` configuration

**Metrics Displayed:**
- Number of configured syslog targets
- Number of configured webhook targets
- Live configuration editor with save/reload functionality

```python
# Enterprise integration configuration
from helper import show_json

show_json("/api/enterprise-integration/config")  # Current integration config
```

**Notes:**
- These integrations are **export‑only**: they send events and summaries out but do not control the first‑layer firewall enforcement path.
- For safety and audit clarity, the integration plane is deliberately separated from the enforcement plane described in the firewall enforcement and attack‑handling documentation.
