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
   └─ Alerts (critical-event email/SMS + SIEM integration)
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
