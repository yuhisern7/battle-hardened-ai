# Battle-Hardened AI – Diagrams for PowerPoint

> This file collects the key diagrams from README.md so they can be reused when building slide decks. The content below is a direct copy of the diagrams only; the source of truth for narrative and context remains README.md.

---

## High-Level Architecture

![Battle Hardened AI](assets/BATTLE-HARDENED-AI.png)

---

## Visual Attack Detection & Response Flow

*Copied from "What Does Battle-Hardened AI Do?" in README.md*

```
📥 PACKET ARRIVES
    ↓
📊 Pre-processing (metadata extraction, normalization)
    ↓
⚡ 20 PARALLEL DETECTIONS (Primary Signals 1-18 + Strategic Intelligence 19-20)
    ├─ Kernel Telemetry (eBPF/XDP syscall correlation)
    ├─ Signatures (3,066+ attack patterns)
    ├─ RandomForest ML (supervised classification)
    ├─ IsolationForest ML (unsupervised anomaly detection)
    ├─ GradientBoosting ML (reputation modeling)
    ├─ Behavioral (15 metrics + APT: low-and-slow, off-hours, credential reuse)
    ├─ LSTM Sequences (6 attack states + APT campaign patterns)
    ├─ Autoencoder (zero-day via reconstruction error)
    ├─ Drift Detection (model degradation monitoring)
    ├─ Graph Intelligence (lateral movement, C2, hop chains)
    ├─ VPN/Tor Fingerprint (de-anonymization)
    ├─ Threat Intel (VirusTotal, AbuseIPDB, ExploitDB, etc.)
    ├─ False Positive Filter (5-gate consensus validation)
   ├─ Historical Reputation (cross-session recidivism ~94%, internal lab evaluation; see "Validation & Testing" below)
    ├─ Explainability Engine (human-readable decisions)
    ├─ Predictive Modeling (24-48h threat forecasting)
    ├─ Byzantine Defense (poisoned update rejection)
    ├─ Integrity Monitoring (tampering detection)
    ├─ 🧠 Causal Inference Engine (root cause: why did this happen?)
    └─ 🔐 Trust Degradation Graph (zero-trust: entity trust scoring 0-100)
   ↓
🎯 ENSEMBLE VOTING (weighted consensus + causal adjustment + trust modulation)
    ├─ Calculate weighted score (0.65-0.98 per signal)
    ├─ Apply authoritative boosting (honeypot, threat intel override)
    ├─ Causal inference adjustment (downgrade if legitimate, boost if malicious)
    ├─ Trust state modulation (stricter thresholds if trust <40, quarantine if <20)
    ├─ Check consensus strength (unanimous / strong / divided)
   └─ Decision: Block (≥75%) / Log (≥50%) / Allow (<50%)
   │   └─ APT Mode: Block threshold lowered to ≥70%
   │   └─ Low Trust (<40): Block threshold lowered to ≥60%
   ↓
🧩 STEP 21: SEMANTIC EXECUTION-DENIAL GATE
   ├─ Evaluate state legitimacy (lifecycle, sequence, authentication)
   ├─ Evaluate intent legitimacy (role vs requested action)
   ├─ Validate structural legitimacy (payload/schema/encoding safety)
   ├─ Check trust sufficiency (trust_graph thresholds per entity; thresholds are customizable per organization policy)
   ├─ If SEMANTICALLY_INVALID → deny execution meaning (no state change, no backend call)
   └─ If SEMANTICALLY_VALID → proceed to response execution
   ↓
🛡️ RESPONSE EXECUTION (policy-governed)
    ├─ Firewall block (iptables/nftables + TTL)
    ├─ Connection drop (active session termination)
    ├─ Rate limiting (if 50-74% confidence)
    ├─ Local logging → threat_log.json (rotates at 100MB) + 10+ audit surfaces
    ├─ Dashboard update (real-time WebSocket push)
   └─ Alerts (SIEM integration; email/SMS only for critical SYSTEM events like kill-switch/integrity violations)
    ↓
🧬 TRAINING MATERIAL EXTRACTION (privacy-preserving, customer-side)
   ├─ Extract to local staging: honeypot_patterns.json under the JSON directory returned by AI.path_helper.get_json_dir()
    ├─ Signatures (patterns only, zero exploit code)
    ├─ Statistics (anonymized: connection rate, port entropy, fan-out)
   ├─ Reputation (SHA-256 hashed IPs → reputation.db, not raw addresses)
    ├─ Graph patterns (topology labels A→B→C → network_graph.json)
    └─ Model weight deltas (RandomForest/LSTM/Autoencoder adjustments)
    ↓
🌍 RELAY SHARING (optional, authenticated)
    ├─ Push: Local findings → Relay Server (every hour)
    ├─ Pull: Global intel ← Relay Server (every 6 hours)
   │   ├─ 3,000+ new signatures from worldwide nodes *(lab-measured, relay training corpus)*
    │   ├─ Known bad IP/ASN reputation feed
    │   ├─ Model updates (Byzantine-validated)
    │   └─ Emerging threat statistics (CVEs, attack trends)
    └─ Merge: Integrate global knowledge into local detection
    ↓
🔄 CONTINUOUS LEARNING (feedback-driven improvement)
    ├─ Signature database auto-updated (hourly)
    ├─ ML models retrained (weekly with labeled data)
   ├─ Reputation tracker updated (with decay, half-life 30 days)
    ├─ Drift baseline refreshed (monthly adaptation)
   └─ Byzantine validation (94% malicious update rejection, measured on adversarial lab simulations; see "Validation & Testing" below)
    ↓
🔁 LOOP: Next packet processed with improved defenses
```

---

## Execution Timing Comparison

*Copied from "Comparison: Execution Timing" in README.md*

```text
Traditional security flow:

Attack → Execute → Detect → Investigate → Respond
          ↑
     (Other tools operate here)
```

```text
Battle-Hardened AI flow:

Attack → Validate → ❌ DENY (no execution)
      or
      → ✅ ALLOW → Execute → [Traditional stack]
           ↑
   (BH-AI operates exclusively at this pre-execution decision point)
```

---

## Stack Enforcement by Layer

```text
┌─────────────────────────────────────────────────────────┐
│                 FIRST-LAYER POSITIONING                 │
├─────────────────────────────────────────────────────────┤
│  App Layer (L7)   → Step 21 Semantic Execution-Denial Gate │
│  Transport (L4)   → Flow validation                     │
│  Network (L3)     → IP & route context                  │
│  Link Layer (L2)  → Frame/MAC insights                  │
│  Kernel Telemetry → Syscall/socket correlation          │
└─────────────────────────────────────────────────────────┘
```

---

## First-Layer Decision Flow

```text
ATTACKER REQUEST
   ↓
[ Battle-Hardened AI ]
   ├─ Step 1: Semantic Validity
   ├─ Step 2: Trust Graph
   ├─ Step 3: Causal Reasoning
   └─ Step 4: Consensus (21 layers)
   ↓
✅ ALLOW  or  ❌ DENY
```

---

## Decision Engine → Firewall → Integrations

*Copied from "Integration with Enterprise Security" in README.md*

```text
      ┌────────────────────────────┐
      │   Battle-Hardened AI       │
      │   (Decision Engine)        │
      └────────────┬───────────────┘
         │
         │ JSON decisions
         ▼
      ┌────────────────────────────┐
      │   OS Firewall / Gateway    │
      │ (iptables/ipset or WDFW)   │
      └────────────┬───────────────┘
         │
      Enforced traffic
         │
   ┌───────────────┴────────────────┐
   │                                │
   ▼                                ▼
  SIEM / SOAR / NGFW                Optional Relay
 (JSON feeds, syslog, APIs)   (patterns & model updates only)
```

---

## End-to-End Block Flow (Attack → Decision → Firewall)

*Copied from "Example: End-to-End Block Flow" in README.md*

```text
    ┌─────────────────────────────┐
    │  Battle-Hardened AI Engine │
    │  (AI/ + server/)           │
    └────────────┬────────────────┘
         │
         │ JSON decisions
         ▼
    ┌─────────────────────────────┐
    │  blocked_ips.json,         │
    │  threat_log.json, etc.    │
    └────────────┬────────────────┘
         │
     ┌───────────────┴─────────────────────────────┐
     │                                             │
     ▼                                             ▼
┌───────────────┐                        ┌────────────────────────────┐
│ Linux Gateway │                        │ Windows EXE Installation   │
│  (Docker/bare │                        │  {app}\BattleHardenedAI.exe│
│   metal)      │                        │  {app}\.env.windows        │
└──────┬────────┘                        └──────────────┬─────────────┘
   │ iptables/ipset updates                        │ Task Scheduler
   ▼                                               ▼ (JSON path → script)
┌───────────────┐                        ┌────────────────────────────┐
│ OS Firewall   │                        │ {app}\windows-firewall\    │
│ (iptables/    │                        │ configure_bh_windows_      │
│  nftables)    │                        │ firewall.ps1               │
└──────┬────────┘                        └──────────────┬─────────────┘
   │                                                   │
   ▼                                                   ▼
   Enforced traffic (blocks, TTL)                 Windows Defender Firewall
```

---

## Representative Deployment Topologies

*Copied from "Representative deployment topologies" in README.md*

```text
 (A) Linux Gateway / Router (recommended)

    Internet / WAN
      │
   ┌────▼────┐
   │ Modem / │ (bridge mode)
   │   ONT   │
   └────┬────┘
      │
   ┌────▼─────────────────────┐
   │  Battle-Hardened AI      │  (Linux gateway / container)
   │  (NAT, routing, firewall │
   │   + 21-layer AI engine)  │
   └────┬─────────────────────┘
      │
    ┌───▼───┐      ┌────────────┐
    │Switch │ ...  │ Wi‑Fi AP   │
    └───────┘      └────────────┘


 (B) Windows Host-Only / Appliance

    Internet / LAN
      │
    ┌───▼────────────┐
    │ Windows Server │  BattleHardenedAI.exe
    │  or Workstation│  + .env.windows
    └───┬────────────┘
      │ (host services: RDP/SSH/HTTP)
      ▼
    Protected apps / data


 (C) Optional Relay / Training Hub

    Multiple Sites                        VPS / Data Center

  ┌─────────────────┐                 ┌────────────────────┐
  │  BH-AI Node A   │  WS 60001/     │  Relay + Training   │
  └─────────────────┘  HTTPS 60002   │  (Docker/systemd)   │
  ┌─────────────────┐  ────────────► │  ai_training_...    │
  │  BH-AI Node B   │  ◄──────────── │  model dist. API    │
  └─────────────────┘                 └────────────────────┘
```

---

## Operational Loop: Continuous Defense Improvement

*Copied from "Operational Loop: Continuous Defense Improvement" in README.md*

```
┌───────────────────────────────┐
│  1. DETECT                                                  │
│  └─→ 21 layers analyze traffic (signatures, ML, behavioral) │
└──────────┬────────────────────┘
                     ↓
┌───────────────────────────────┐
│  2. DECIDE (Deny/Allow)                                     │
│  └─→ Ensemble voting + semantic gate + trust modulation     │
│     Block ≥75% | Log ≥50% | Allow <50%                     │
└──────────┬────────────────────┘
                     ↓
┌───────────────────────────────┐
│  3. ENFORCE                                                 │
│  └─→ Command OS firewall (iptables/nftables/Windows FW)     │
│     Drop packets, terminate connections, apply TTL          │
└──────────┬────────────────────┘
                     ↓
┌───────────────────────────────┐
│  4. LOG & EXPORT                                            │
│  └→ Local: threat_log.json, comprehensive_audit.json       │
│  └→ Dashboard: Real-time WebSocket updates                 │
│  └─→ SIEM/SOAR: Outbound JSON export (optional)             │
└──────────┬────────────────────┘
                     ↓
┌───────────────────────────────┐
│  5. LEARN & MEASURE                                         │
│  └→ Extract attack signatures (sanitized patterns only)    │
│  └→ Update reputation tracker (IP trust scores)            │
│  └→ Monitor ML performance (accuracy, drift detection)     │
│  └→ Collect behavioral metrics (anonymized statistics)     │
│  └─→ Validate model integrity (Byzantine defense)           │
└──────────┬────────────────────┘
                     ↓
┌───────────────────────────────┐
│  6. UPDATE (Continuous Improvement)                         │
│  └→ Hourly: New signatures merged into detection database  │
│  └→ Every 6 hours: Pull updated models from relay          │
│  └→ Weekly: Retrain ML models with labeled attack data     │
│  └→ Monthly: Refresh drift baseline (adapt to environment) │
│  └─→ On degradation: Auto-retrain if accuracy <92%          │
└──────────┬────────────────────┘
                     │
                     └─→ Loop back to DETECT with improved defenses
```

---

## Network Deployment Topologies

*Copied from "Topologies" section in README.md*

### Router Mode (Production Default)

Battle-Hardened AI VM acts as the **default gateway** for protected systems:

```
Internet ──→ BH-AI Gateway ──→ Protected Systems
              (Decision +         (receive only
              Enforcement)         pre-approved traffic)
```
![Edge Gateway Mode — BH-AI as Perimeter Decision Authority](../../assets/topologies/1.png)

- Protected systems route all traffic through BH-AI
- BH-AI inspects traffic and commands firewall
- Attackers blocked before reaching protected services

---

### Transparent Bridge Mode (Planned)

BH-AI operates inline **without becoming the default gateway**:

```
Internet ──→ BH-AI Bridge ──→ Router ──→ Protected Systems
              (transparent        (existing gateway)
               inspection)
```
![Transparent Inline Bridge Mode — BH-AI as an Inline Decision Authority](../../assets/topologies/2.png)

- No routing changes required
- BH-AI inspects traffic via bridge interface
- Commands firewall on bridge to drop malicious packets

---

### Tap/Mirror Mode (Observer Only)

BH-AI receives copy of traffic via **SPAN port or network TAP**:

```
Internet ──→ Router ──→ Protected Systems
               │
               └──→ SPAN/TAP ──→ BH-AI Observer
                                  (monitor-only)
```
![Tap/Mirror Mode — BH-AI as Monitoring Decision Authority](../../assets/topologies/3.png)

- No enforcement (logging and alerting only)
- Useful for PoC validation and compliance monitoring
- Cannot block attacks (read-only deployment)

---

## Enterprise Integration Topologies (Examples)

*Copied from "Enterprise Integration Topologies (Examples)" section in README.md*

These examples show how Battle-Hardened AI, when placed at the gateway, **amplifies the entire security stack** instead of competing with it.

### 1. Edge Gateway in Front of NGFW / IPS

```
Internet ──→ BH-AI Gateway ──→ NGFW / IPS ──→ Core Switch / VLANs ──→ Servers & Users
              (Semantic           (Deep packet /               
              execution gate)      compliance inspection)
```
![Edge Gateway in Front of NGFW/IPS — BH-AI as First-Layer Decision Authority](../../assets/topologies/4.png)

- BH-AI makes first-layer, semantic allow/deny decisions and blocks clearly malicious flows before they ever hit the NGFW/IPS.
- The NGFW/IPS sees **fewer, higher-quality events**, focusing on deep content/compliance rather than obvious brute-force, scanning, or reputation-abuse traffic.
- BH-AI JSON feeds (threat_log.json, blocked_ips.json) can drive NGFW address groups and IPS policies via SIEM/SOAR, turning traditional firewalls into a high-speed enforcement plane for BH-AI decisions.

---

### 2. Data Center / East–West Segmentation with NDR/XDR

```
User / Internet ──→ BH-AI DC Gateway ──→ App / DB Tiers
                          │                    │
                          │                    └──→ NDR sensors / taps
                          └──→ SIEM / SOAR / XDR (BH-AI JSON + NDR events)
```
![Data Center / East–West Segmentation with NDR/XDR — BH-AI Gateway with NDR Sensors](../../assets/topologies/5.png)

- BH-AI at the data center edge enforces semantic execution validity for north–south traffic, while NDR sensors observe east–west flows inside the DC.
- NDR/XDR platforms ingest BH-AI's decision JSON alongside their own telemetry, using BH-AI's **explicit block/allow verdicts and explanations** to prioritize investigations and automate responses.
- When BH-AI blocks an entity, that decision can be mirrored into NDR/XDR and EDR policy (for example, quarantine host, tighten identity policy, or escalate playbooks).

---

### 3. Cloud VPC / Hybrid Edge with Cloud Firewalls

```
Internet / WAN ──→ BH-AI Cloud Gateway (VM) ──→ Cloud NVA / SGs ──→ Workloads
                         │                         (NGFW, WAF, SGs)
                         └──→ SIEM/SOAR / Cloud APIs
```
![Cloud VPC / Hybrid Edge with Cloud Firewalls — BH-AI as Cloud Gateway VM](../../assets/topologies/6.png)

- BH-AI runs as a cloud VM gateway (AWS/Azure/GCP), enforcing first-layer decisions on VPC/VNet ingress/egress.
- Its JSON outputs are consumed by cloud-native firewalls, WAFs, and security groups through automation (Lambda/Functions, SOAR, or custom controllers), so **cloud firewalls inherit BH-AI's 21-layer reasoning and trust decisions**.

---

### 4. Branch / Remote Site with XDR and EDR

```
Branch Internet ──→ BH-AI Branch Gateway ──→ Local LAN ──→ Endpoints (with EDR/XDR agents)
                                  │
                                  └──→ Central SIEM / SOAR / XDR ingest (JSON)
```
![Branch / Remote Site with XDR and EDR — BH-AI Branch Gateway with Central XDR Integration](../../assets/topologies/7.png)

- BH-AI blocks malicious flows at the branch edge and exports decisions to the central XDR/SIEM stack.
- Endpoint EDR/XDR agents continue to watch host behavior, but benefit from **reduced attack surface and rich BH-AI context** (why traffic was blocked, which layers fired, trust deltas).
- SOAR playbooks can treat BH-AI as an upstream authority: when BH-AI quarantines an IP or entity, playbooks update EDR policies, NGFW rules, and ticketing systems in lockstep.

---

### Ecosystem View — BH-AI as the Autonomous Gate

At a high level, BH-AI sits at the execution gate and exports **vendor-neutral JSON decisions** that other systems consume:

```text
          Internet / WAN / Users
                   │
                   ▼
        ┌────────────────────────────┐
        │      Battle-Hardened AI    │
        │   (Gateway / Host / TAP)   │
        │  21-layer + Step 21 gate   │
        └───────────┬────────────────┘
            OS firewall enforcement
 (iptables/ipset/nftables, Windows Firewall)
                    │
        JSON decisions & events (export)
   ┌─────────────┼─────────────┬──────────────┬───────────────┐
   ▼             ▼             ▼              ▼
NGFW/WAF &   SIEM / SOAR   XDR / EDR     VPN / ZTNA / NAC
cloud firewalls (dynamic  (correlation,  (policy & access   
address groups, rules)    playbooks)      adjustments)
   ┌─────────────┴─────────────┬──────────────┬───────────────┐
   ▼                           ▼              ▼
API gateways & LB        GRC / audit &   ITSM / ticketing /
tiers (route, throttle,  compliance tools  runbooks (cases,
or send to honeypot)     (evidence,        approvals, change
                          control mapping)  tracking)
```
![Ecosystem View — BH-AI as the Autonomous Gate Controlling All Security Tools](../../assets/topologies/8.png)

In enterprise deployments this means:

- **Firewalls / NGFW / WAF / cloud controls** enforce BH-AI block/allow decisions via dynamic address groups, tags, and policies.
- **NDR / IDS / XDR / EDR** gain an upstream semantic verdict and trust score for each entity, improving triage, correlation, and automated containment.
- **SIEM / SOAR** orchestrate changes across all these planes using BH-AI's explainable JSON events as the trigger and ground truth.
- **VPN, Zero-Trust access, and NAC** can tighten or relax access based on BH-AI trust deltas and recent semantic violations.
- **API gateways, load balancers, and reverse proxies** can route, throttle, or divert suspicious flows (for example to honeypots) based on BH-AI output.
- **GRC, audit, and ticketing systems** consume BH-AI's audit trails and decisions as evidence and as automatic case-open/close signals.

Taken together, these patterns highlight the intended positioning: **Battle-Hardened AI is an autonomous defensive gate that drives firewalls, IDS/IPS, NDR, XDR, cloud controls, identity and access systems, and operational tooling via a single, explainable decision plane.**

---

## Federated Relay Architecture (Optional)

*Copied from "Federated Relay Architecture" in README.md*

Privacy-preserving global intelligence sharing through relay server:

- **Privacy-Preserving:** Only abstract patterns shared; full data sovereignty maintained
- **Model Cryptographic Signing:** Ed25519 signatures prevent malicious model injection
- **Byzantine Validation:** 94% malicious update rejection rate
- **Smart Pattern Filtering:** Bloom filter deduplication (70-80% bandwidth savings)

| Data Type | Shared with Relay? | Why Safe? |
|-----------|-------------------|-----------|
| Attack patterns | ✓ Yes (sanitized) | Abstract signatures only, no payloads |
| Behavioral metrics | ✓ Yes (anonymized) | Statistical aggregates, no identifiable data |
| ML models | ⬇️ Downloaded only | Relay trains and distributes |
| Customer traffic | ❌ Never | Stays local; only pattern hashes leave site |
| User credentials | ❌ Never | Local analysis only |
| Raw logs/PII | ❌ Never | Full data sovereignty |

---

## Hardware Network Topologies

*Copied from "Hardware Deployment Checklists" in README.md*

```text
Option A — Battle-Hardened AI as Edge Gateway Router (Recommended for Full Control)

Network Topology

Modem/ONT → Battle-Hardened AI → Switch → Internal Network
```

```text
Option B — Battle-Hardened AI as Transparent Inline Bridge (No Routing Changes)

Network Topology

Modem/ONT → Battle-Hardened AI (Bridge) → Existing Router
```
