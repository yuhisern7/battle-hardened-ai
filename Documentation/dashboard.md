# Dashboard Sections: Complete API Reference

This document provides a comprehensive guide to the 23 core dashboard sections, mapping them to the **7-stage attack detection pipeline** and their corresponding APIs and AI modules.

**Installation & Setup:**
- For installation instructions, see [INSTALLATION.md](INSTALLATION.md)
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

**Prerequisites:**
- Dashboard running at `https://localhost:60000`
- Run scripts from repo root: `battle-hardened-ai/`
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
- `server/device_scanner.py` — Device discovery (Stage 1)
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

Backed by: `/api/traffic/analysis`, `/api/traffic/crypto-mining`, `/api/pcap/stats` plus `AI/traffic_analyzer.py`, `AI/kernel_telemetry.py`, `AI/pcap_capture.py`.

```python
# Reveal live traffic analysis and crypto‑mining detection
from helper import show_json

show_json("/api/traffic/analysis")       # protocol/app breakdown, anomalies
show_json("/api/traffic/crypto-mining")  # crypto‑mining indicators
show_json("/api/pcap/stats")             # PCAP capture statistics
```

## Section 18 – DNS & Geo Security

Backed by: `/api/dns/stats`, `/api/traffic/crypto-mining` (for DNS‑based C2), and geolocation enrichment in the core threat pipeline.

```python
# Show DNS statistics, tunneling/DGA detections, and geo‑risk hints
from helper import show_json

show_json("/api/dns/stats")  # same JSON used for DNS/TLD charts
```

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

## Section 21 – Email/SMS Alerts (Critical Only)

Backed by: `/api/alerts/stats` and `AI/alert_system.py`.

```python
# Critical alert metrics (system failure, kill‑switch, integrity breach)
from helper import show_json

show_json("/api/alerts/stats")  # counts/routes of critical alerts sent
```

## Section 22 – Cryptocurrency Mining Detection

Backed by: `/api/traffic/crypto-mining` and `AI/crypto_security.py`, `AI/traffic_analyzer.py`.

```python
# Crypto‑mining detection statistics
from helper import show_json

show_json("/api/traffic/crypto-mining")
```

## Section 23 – Governance & Emergency Controls

Backed by: `/api/governance/stats`, `/api/killswitch/status`, `/api/audit-log/stats`, `/api/ai/abilities`, `/api/central-sync/status`, `/api/system-status` and modules like `AI/policy_governance.py`, `AI/emergency_killswitch.py`, `AI/central_sync.py`.

```python
# Governance, kill‑switch, approval‑queue, and global sync surfaces
from helper import show_json

show_json("/api/governance/stats")      # governance/approval metrics
show_json("/api/killswitch/status")     # emergency kill‑switch state
show_json("/api/audit-log/stats")       # audit‑log health
show_json("/api/ai/abilities")          # 18 AI abilities on/off flags
show_json("/api/central-sync/status")   # central sync controller status
show_json("/api/system-status")         # underlying node health

Clustered deployments also rely on two non-dashboard endpoints for governance and failover:
- `/health` – lightweight node/cluster health used by external load balancers and passive nodes (driven by `cluster_config.json` in the JSON directory resolved by AI/path_helper).
- `/cluster/config/snapshot` – active-node-only snapshot of selected JSON config surfaces listed in `config_sync_paths` inside the same `cluster_config.json`, used by passive nodes for safe config synchronization.
```
