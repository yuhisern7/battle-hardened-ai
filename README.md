# Battle-Hardened AI
### The Details Here Are ANTI-MARKETING 

This document is written for people who understand first-layer enforcement, gateways, and control planes. It assumes familiarity with firewalls, routing, kernel telemetry, and pre-execution decision systems.

Nothing in Battle-Hardened AI is designed as a marketing gimmick: every term (21 layers, semantic execution-denial, trust graph, causal inference) corresponds to concrete modules, code paths, and enforcement points that can be inspected in this repository and its documentation. For a formal mapping from claims to code and runtime behavior, see [documentation/mapping/Filepurpose.md](documentation/mapping/Filepurpose.md) and [documentation/architecture/Architecture_Enhancements.md](documentation/architecture/Architecture_Enhancements.md).

---

### 🔑 Summary Highlights

- Blocks malicious actions **before execution** using a 21-layer AI ensemble and a final semantic execution-denial gate.
- Acts as a **first-layer firewall commander** for gateways and routers, deciding what should be blocked while delegating actual enforcement to the local firewall control plane.
- Works **without agents**, exporting neutral JSON that plugs into existing SIEM, SOAR, firewall, and XDR stacks.
- Provides documented coverage for **43 MITRE ATT&CK techniques** via pre-execution denial and trust degradation.
- Built for **enterprise, government, and national-security** defense use cases where autonomy, auditability, and privacy are mandatory.
- Optionally connects to a **central relay/VPS** where many Battle-Hardened AI nodes share only sanitized attack patterns and receive model/signature updates,
  so global learning improves over time without any customer content or PII leaving local infrastructure.
- Implements **5 production-ready architecture enhancements** for ML pipeline security:
  - Model cryptographic signing (Ed25519) prevents model injection attacks
  - Smart pattern filtering (70-80% bandwidth savings)
  - Production ML performance monitoring with auto-retrain triggers
  - Adversarial training (FGSM) for ML evasion resistance
  - ONNX model format (2-5x faster CPU inference)

### Executive Summary (Non-Technical)

- **Stop breaches before they start:** Battle-Hardened AI sits at the gateway and decides what is allowed to execute, blocking malicious activity before it reaches servers, endpoints, or data.
- **Reduce analyst load, not add to it:** It runs autonomously with explainable decisions and conservative defaults, cutting noise instead of generating more alerts.
- **Integrate with what you already have:** Decisions are exported as simple JSON and enforced through existing firewalls, SIEM, SOAR, and EDR/XDR tools—no rip-and-replace.
- **Protect privacy and sovereignty:** Detection happens on your infrastructure, and when the optional relay to the central VPS is enabled, only anonymized
   patterns and statistics are shared—no raw payloads, credentials, or customer data.


Battle-Hardened AI introduces a new category of security: a **first-layer autonomous execution-control system** that operates at the router and gateway boundary, making **pre-execution decisions with full context**—semantic, behavioral, and causal—before any downstream tool is engaged.

We are not aware of any publicly documented enterprise-grade system that:

- Operates as a first-layer gateway authority
- Performs semantic execution validation
- Maintains persistent trust memory
- Uses causal inference to command routers and firewalls prior to execution

![Battle Hardened AI](assets/BATTLE-HARDENED-AI.png)

---

## Architecture Understanding

### Core Premise: First-Layer Execution-Control Authority

Battle-Hardened AI operates at the **gateway boundary** as the **decision authority**, making pre-execution determinations about what should be blocked or allowed. It does not handle packets directly—instead, it **commands the local firewall** (iptables, nftables, Windows Defender Firewall) to enforce its decisions.

This architecture creates a clear separation of concerns:
- **Battle-Hardened AI:** Intelligence, analysis, and decision-making
- **OS Firewall:** Enforcement and packet filtering

### Control-Plane Split: Decision vs Enforcement

```
┌──────────────────────────────────────────────────────────┐
│                    DECISION PLANE                        │
│  Battle-Hardened AI (21 detection layers + semantic gate)│
│  - Analyzes traffic via mirror/tap/inline observation    │
│  - Evaluates trust, causality, semantics                 │
│  - Makes block/allow decisions                           │
│  - Emits JSON decisions to enforcement plane             │
└────────────────────┬─────────────────────────────────────┘
                     │ Commands (JSON + firewall API)
                     ↓
┌──────────────────────────────────────────────────────────┐
│                   ENFORCEMENT PLANE                      │
│  OS Firewall (iptables/nftables/Windows Defender)       │
│  - Receives IP block/unblock commands                    │
│  - Applies rules at kernel level                         │
│  - Drops packets, terminates connections                 │
│  - No analysis—purely enforcement                        │
└──────────────────────────────────────────────────────────┘
```

**This ensures:**
- Battle-Hardened AI cannot be bypassed by routing changes (firewall enforces at kernel)
- Firewall remains auditable and controllable by operators
- Integration with SIEM/SOAR happens via JSON export, not enforcement path

### Deployment Roles

Battle-Hardened AI supports three primary deployment roles (Gateway/Router, Host-only, Observer) that define protection scope and enforcement method.

For the canonical table, environment mapping, and installation links, see [Deployment Scope — Three Roles, Many Environments](#deployment-scope--three-roles-many-environments) below.

### Topologies

#### Router Mode (Production Default)

Battle-Hardened AI VM acts as the **default gateway** for protected systems:

```
Internet ──→ BH-AI Gateway ──→ Protected Systems
              (Decision +         (receive only
              Enforcement)         pre-approved traffic)
```

- Protected systems route all traffic through BH-AI
- BH-AI inspects traffic and commands firewall
- Attackers blocked before reaching protected services

**Setup:** See [Installation.md](documentation/installation/Installation.md) Gateway/Router Mode section.

#### Transparent Bridge Mode (Planned)

BH-AI operates inline **without becoming the default gateway**:

```
Internet ──→ BH-AI Bridge ──→ Router ──→ Protected Systems
              (transparent        (existing gateway)
               inspection)
```

- No routing changes required
- BH-AI inspects traffic via bridge interface
- Commands firewall on bridge to drop malicious packets

**Status:** Coming soon. See [Installation.md](documentation/installation/Installation.md) for updates.

#### Tap/Mirror Mode (Observer Only)

BH-AI receives copy of traffic via **SPAN port or network TAP**:

```
Internet ──→ Router ──→ Protected Systems
               │
               └──→ SPAN/TAP ──→ BH-AI Observer
                                  (monitor-only)
```

- No enforcement (logging and alerting only)
- Useful for PoC validation and compliance monitoring
- Cannot block attacks (read-only deployment)

**Use case:** Pre-production testing, regulatory compliance validation.

### Federated Relay Architecture

When the **optional relay** is enabled, Battle-Hardened AI nodes share intelligence globally while preserving privacy:

- Customer nodes upload **sanitized patterns and statistics only** (no payloads, credentials, or PII).
- Relay distributes **models, signatures, and reputation feeds only** (no raw training data from customers).
- Model signing, Byzantine validation, and ONNX optimization harden distribution against tampering and performance regressions.

For the full Stage 5–7 technical flow and privacy guarantees, see [Stage 5: Training Material Extraction (Privacy-Preserving)](#stage-5-training-material-extraction-privacy-preserving), [Stage 6: Global Intelligence Sharing (Optional Relay)](#stage-6-global-intelligence-sharing-optional-relay), and [Stage 7: Continuous Learning Loop](#stage-7-continuous-learning-loop).

### Architecture Enhancements: ML Pipeline Hardening Layer

Beyond the 21 detection layers, Battle-Hardened AI implements **5 production security features** that harden the ML training pipeline against supply chain attacks, performance degradation, and adversarial manipulation:

| Enhancement | Security Benefit | Performance Benefit | MITRE Defense |
|-------------|------------------|---------------------|---------------|
| **#1: Model Cryptographic Signing** | Prevents model injection | <1ms overhead | T1574.012 (Supply Chain) |
| **#2: Smart Pattern Filtering** | Reduces attack surface | 70-80% bandwidth savings | N/A (Operational) |
| **#3: Model Performance Monitoring** | Detects model poisoning | ~5% overhead | T1565.001 (Data Manipulation) |
| **#4: Adversarial Training** | ML evasion resistance | Training +30% (relay-side only) | T1562.004 (Impair Defenses) |
| **#5: ONNX Model Format** | Faster threat response | **2-5x faster inference** | N/A (Performance) |

**Key capabilities:**
- Ed25519 cryptographic signatures verify every model before loading
- Bloom filters deduplicate attack patterns (76% bandwidth reduction in production)
- Production accuracy tracking triggers auto-retraining if model degrades
- FGSM adversarial training makes models robust against ML evasion attacks
- ONNX Runtime provides 2-5x faster CPU inference (no GPU required)

**For detailed technical documentation:**
- [Architecture_Enhancements.md](documentation/architecture/Architecture_Enhancements.md) - Complete implementation guide
- [ONNX_Integration.md](documentation/architecture/ONNX_Integration.md) - ONNX deployment and benchmarks

### Operational Loop: Continuous Defense Improvement

Battle-Hardened AI operates in a **continuous improvement cycle** that ensures defenses adapt to evolving threats:

```
┌─────────────────────────────────────────────────────────────┐
│  1. DETECT                                                  │
│  └─ 21 layers analyze traffic (signatures, ML, behavioral) │
└────────────────────┬────────────────────────────────────────┘
                     ↓
┌─────────────────────────────────────────────────────────────┐
│  2. DECIDE (Deny/Allow)                                     │
│  └─ Ensemble voting + semantic gate + trust modulation     │
│     Block ≥75% | Log ≥50% | Allow <50%                     │
└────────────────────┬────────────────────────────────────────┘
                     ↓
┌─────────────────────────────────────────────────────────────┐
│  3. ENFORCE                                                 │
│  └─ Command OS firewall (iptables/nftables/Windows FW)     │
│     Drop packets, terminate connections, apply TTL          │
└────────────────────┬────────────────────────────────────────┘
                     ↓
┌─────────────────────────────────────────────────────────────┐
│  4. LOG & EXPORT                                            │
│  ├─ Local: threat_log.json, comprehensive_audit.json       │
│  ├─ Dashboard: Real-time WebSocket updates                 │
│  └─ SIEM/SOAR: Outbound JSON export (optional)             │
└────────────────────┬────────────────────────────────────────┘
                     ↓
┌─────────────────────────────────────────────────────────────┐
│  5. LEARN & MEASURE                                         │
│  ├─ Extract attack signatures (sanitized patterns only)    │
│  ├─ Update reputation tracker (IP trust scores)            │
│  ├─ Monitor ML performance (accuracy, drift detection)     │
│  ├─ Collect behavioral metrics (anonymized statistics)     │
│  └─ Validate model integrity (Byzantine defense)           │
└────────────────────┬────────────────────────────────────────┘
                     ↓
┌─────────────────────────────────────────────────────────────┐
│  6. UPDATE (Continuous Improvement)                         │
│  ├─ Hourly: New signatures merged into detection database  │
│  ├─ Every 6 hours: Pull updated models from relay          │
│  ├─ Weekly: Retrain ML models with labeled attack data     │
│  ├─ Monthly: Refresh drift baseline (adapt to environment) │
│  └─ On degradation: Auto-retrain if accuracy <92%          │
└────────────────────┬────────────────────────────────────────┘
                     │
                     └──→ Loop back to DETECT with improved defenses
```

**Key feedback mechanisms:**

- **Immediate (real-time):** Reputation updates, trust degradation, firewall rules
- **Hourly:** Signature extraction and merging
- **Every 6 hours:** Model and intelligence updates from relay (if enabled)
- **Weekly:** ML model retraining with new labeled attack data
- **Monthly:** Baseline drift refresh (adapts to legitimate network changes)
- **On-demand:** Emergency retraining if performance monitoring detects accuracy <85%

**Privacy-preserving learning:**
- Only **patterns** uploaded to relay (sanitized signatures, no payloads)
- Only **models** downloaded from relay (no raw training data exposed)
- All raw logs, credentials, and customer data remain on-premises
- Full data sovereignty maintained

This **closed-loop architecture** ensures defenses improve automatically without manual intervention, while maintaining strict privacy and auditability requirements.

See [Stage 7: Continuous Learning Loop](#stage-7-continuous-learning-loop) below for technical implementation details.

---

## What Does Battle-Hardened AI Do?

*Visual Attack Detection & Response Flow*

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

🔒 ARCHITECTURE ENHANCEMENTS (5 Production Security Features)
   ├─ Model Cryptographic Signing (Ed25519) - Prevents model injection attacks
   ├─ Smart Pattern Filtering (Bloom filter) - 70-80% bandwidth savings
   ├─ Model Performance Monitoring - Production accuracy tracking, auto-retrain triggers
   ├─ Adversarial Training (FGSM) - ML evasion resistance
   └─ ONNX Model Format - 2-5x faster CPU inference (no GPU needed)
   See: Architecture Enhancements section for full details
```

Implementation-wise, customer nodes:
- Push sanitized threat summaries and extracted patterns to a centrally-operated relay/VPS over WebSocket (typically `wss://<relay-host>:60001`) using a dedicated relay client; **no raw payloads, logs, or customer data are ever sent**.
- Pull **only pre-trained models** and curated signature/reputation/intel bundles from an HTTPS training API (typically `https://<relay-host>:60002`); raw training datasets and history remain on the relay and never transit customer networks.
- Load downloaded models from their local ML models directory (resolved by `AI.path_helper.get_ml_models_dir()`); nodes never read `relay/ai_training_materials/` directly.

**This architecture creates a federated, privacy-preserving defense mesh where:**

- **One server protects an entire network segment** (no endpoint agents required)
- **Every attack makes the system smarter** (automated signature extraction + ML retraining)
- **Every node benefits from global learning** (relay-shared intelligence from worldwide attacks)
- **Organizations retain full control** (relay participation is optional, all data anonymized)
- **Privacy is preserved** (no raw payloads, no PII, only statistical features shared)

---

In the standard shipping profiles:

- The **Linux gateway container** and the **Windows EXE** both include the persistent reputation tracker by default (backed by `reputation.db` under the JSON directory), so repeat offenders and long-lived bad actors are remembered across sessions.
- Core OSINT threat crawlers (hash/URL/score–only feeds such as MalwareBazaar, URLhaus, and CVE scores) are enabled by default and feed the threat intelligence and DNS/geo sections, while heavier text-based feeds remain optional and operator-controlled.
- Advanced TensorFlow-based autoencoder and sequence models are available as an optional, environment-specific profile for customers that explicitly want the full ML stack and are prepared for the larger footprint.

### Canonical Deployment

In its standard form, Battle-Hardened AI runs on a **Linux gateway or edge appliance** (physical or virtual), directly in front of the protected segment. Optional Windows/macOS nodes act as **host-level defenders** for specific assets or branches. It is designed to integrate without disrupting existing stacks—SIEM, SOAR, IAM, EDR/XDR, NGFW—acting solely as the execution-control authority and gateway commander.

#### Deployment Context: Gateway vs Host vs Observer

For a complete role comparison, installation links, and environment mapping, see [Deployment Scope — Three Roles, Many Environments](#deployment-scope--three-roles-many-environments).

### Semantic Enforcement Model

*How Battle-Hardened AI decides which requests are allowed to execute or blocked before they reach downstream systems.*

Unlike traditional tools that detect attacks **after** execution, Battle-Hardened AI enforces **semantic execution validity** using 21 independent detection and reasoning layers. These layers incorporate:

- Kernel-level telemetry
- Behavioral and statistical intelligence
- Graph analysis
- Causal inference
- Persistent trust memory

This ensemble determines when trust, structure, or semantics are invalid, and can autonomously instruct routers and firewalls to block execution **before harm occurs**.

- **Semantic execution validity:** Verifies that a request both makes sense and is safe *before* it is allowed to run.
- **Causal inference:** Determines the root reason an action occurred, helping identify intent and trustworthiness.

> Attacks are observed, understood, and remembered—yet denied at origin.

### Not an Incremental Add-On

Battle-Hardened AI is a **stateful, pre-execution control class**—a first-layer decision system that:

- Resists probing and iterative evasion
- Degrades adversary trust over time
- Prevents coercion by malicious inputs
- Covers 43 MITRE ATT&CK techniques
- Operates independently of alert volume or SIEM bloat

For a detailed comparison with NDR/XDR platforms and traditional tools, including scoring examples and vendor landscape, see [Competitive Positioning vs NDR/XDR Platforms](#competitive-positioning-vs-ndrxdr-platforms).

### What Makes Us Different

This section illustrates **execution timing and stack placement** only; market and vendor comparisons are centralized under the competitive positioning section below.

#### Comparison: Execution Timing

Traditional security flow:

```text
Attack → Execute → Detect → Investigate → Respond
          ↑
     (Other tools operate here)
```

Battle-Hardened AI flow:

```text
Attack → Validate → ❌ DENY (no execution)
      or
      → ✅ ALLOW → Execute → [Traditional stack]
           ↑
   (BH-AI operates exclusively at this pre-execution decision point)
```

#### Stack Enforcement by Layer

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

#### What Battle-Hardened AI Is Not

To remain strictly focused as a first-layer decision system, Battle-Hardened AI does **not**:

- Act as a SIEM (log aggregator)
- Act as a SOAR (workflow orchestrator)
- Act as an EDR (host process monitor)
- Act as an IAM (identity manager)
- Act as a threat intel aggregator

It makes **execution decisions only**.

#### First-Layer Decision Flow

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

### 🧪 Example: SSH Credential Stuffing

- **Traditional flow:** Attackers perform high-volume or distributed SSH login attempts. Sessions are established, and only then do downstream tools detect anomalies and raise alerts.
- **With Battle-Hardened AI:** Behavioral, sequence, and trust signals flag abnormal SSH login patterns. Trust for the source degrades, and the semantic execution-denial gate determines that the login attempts are not legitimate for the entity.
- **Outcome:** Connections are blocked **before** successful session establishment, and the attacker cannot meaningfully interact with protected systems.

#### Data Handling & Privacy Principles

Battle-Hardened AI follows strict data-handling principles at the first layer:

- Observes all traffic, retains only patterns
- Validates structure and semantics, not full payloads
- Makes allow/deny decisions, but does not investigate
- Maintains trust models without exposing raw content externally

### Integration with Enterprise Security

Battle-Hardened AI emits **vendor-neutral JSON decision feeds**. Example:

```json
{
  "blocked_ips": [
    {
      "ip": "203.0.113.10",
      "timestamp": "2026-01-20T17:51:38.361466+00:00",
      "reason": "Threat detection by AI engine"
    }
  ]
}
```

The JSON format is **identical across Linux (Docker) and Windows**. Enforcement is handled externally via:

- `ipset`/`iptables` (Linux)
- PowerShell + Windows Defender Firewall (Windows)
- JSON feeds consumed by SIEM/SOAR/NGFW/EDR integrations

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

This makes it explicit that Battle-Hardened AI is the decision authority, the OS firewall/gateway is the enforcement plane, and enterprise tools and the optional relay consume decisions rather than drive them.

No vendor-specific code is baked into the core. Adapters or SOAR playbooks watch the JSON and translate it into:

- SIEM/SOAR: trigger rules and playbooks
- NGFW/WAF: update dynamic address groups and blocklists
- EDR/XDR: isolate hosts or adjust policy

#### Where to Configure BH Outputs

- **SIEM/SOAR**: Create a data source to ingest Battle-Hardened AI JSON; trigger enforcement via playbooks or rules.
- **NGFW/WAF**: Use your automation layer (SOAR, scripts, or connectors) to call vendor APIs when Battle-Hardened AI outputs change.
- **EDR/XDR**: Integrate with vendor APIs through SOAR or connector scripts to apply block/allow decisions to endpoints.

You never modify Battle-Hardened AI code—you wire your tools to the Battle-Hardened AI feed.

### Quick Start: From Install to Enforcement

**Home / Lab**

- Download the latest Linux package (`.deb`/`.rpm`) or Windows `.exe` installer from the distribution channel provided by the project.
- Install following [documentation/installation/Installation.md](documentation/installation/Installation.md).
- Open the dashboard documented in [Dashboard](documentation/mapping/Dashboard.md) to verify live telemetry and decision traces.
- Wire your local firewall using [documentation/firewall/Firewall_enforcement.md](documentation/firewall/Firewall_enforcement.md) and confirm that blocked IPs appear both in the dashboard and in JSON outputs.

**Enterprise / SOC**

- Select one gateway or choke point per protected segment, and install Battle-Hardened AI there using [documentation/installation/Installation.md](documentation/installation/Installation.md).
- Follow [Installation guide](documentation/installation/Installation.md) to start services, then integrate with SIEM/SOAR as described in [Dashboard](documentation/mapping/Dashboard.md) and [Attack handling flow](documentation/architecture/Attack_handling_flow.md).
- Enable firewall synchronization using [documentation/firewall/Firewall_enforcement.md](documentation/firewall/Firewall_enforcement.md) so auto-block decisions propagate to `iptables`/`ipset` (Linux) or Windows Defender Firewall.
- Run a controlled test from [KALI_ATTACK_TESTS.md](KALI_ATTACK_TESTS.md) to validate end-to-end detection, blocking, and logging before broad rollout.

### What Battle-Hardened AI Offers (Capabilities & Roadmap)

These capabilities span **current, implemented features** and **roadmap items**. Use this checklist together with the implementation-status table below to understand what works today versus what is planned.

#### Current Capabilities (v1.0)

- 21-layer detection and reasoning pipeline (20 signals + Step 21 semantic gate) wired into the main gateway request path.
- Linux and Windows deployments with local firewall enforcement via iptables/ipset (Linux) and Windows Defender Firewall (Windows).
- Real-time dashboard with 24 core sections, governance/killswitch controls, and decision explainability for autonomous blocks/allows.
- Optional relay/VPS for federated, pattern-only threat sharing and model/signature distribution (no raw payloads or customer data).
- JSON-based integration surfaces for SIEM/SOAR/firewalls (threat_log.json, blocked_ips.json, enterprise integration JSON, and relay feeds).

#### Roadmap (Future Enhancements)

- Additional cloud provider coverage and deeper cloud posture management.
- Expanded enterprise integration presets and sample configurations for common SIEM/firewall platforms.
- More formal external validation (third-party tests, red-team exercises, and production case studies).
- Progressive UI and documentation improvements for operators (troubleshooting, runbooks, and deployment blueprints).

#### Current Dashboard Sections (24 core sections)

These 24 sections correspond to the main dashboard surfaces shipped in the current build. Some contain early-access or partially implemented capabilities; see "Implementation Status at a Glance" for subsystem details.

| # | Section | Description |
|---|---------|-------------|
| 1 | AI Training Network – Shared Machine Learning | Full view of the optional P2P/federated training mesh: which nodes are participating, what sanitized attack signatures and statistical patterns have been shared, current model versions and lineage, training job status, and whether the relay is operating in fully offline/air‑gapped, local‑only, or collaborative mode (no raw payloads or customer data ever leave the deployment). |
| 2 | Network Devices – Live Monitor, Ports & History | Live asset and device inventory across observed subnets: active hosts, open ports and services, role classification, per‑device trust/risk posture, and 7‑day historical view of appearance, disappearance, and behavior changes so operators can see how the protected environment is evolving over time. |
| 3 | Attackers VPN/Tor De-Anonymization Statistics | Aggregated view of anonymization infrastructure hitting the system: VPN/Tor/proxy detection, upstream ASN/region breakdowns, recurrence and campaign statistics, de‑anonymization heuristics, and how these signals feed into reputation/trust degradation so you can see which remote infrastructures are persistently hostile. |
| 4 | Real AI/ML Models – Machine Learning Intelligence | Inventory and operational status of the ML stack that powers the 21 detection layers: which models are deployed, their roles in the ensemble, training datasets and provenance, Byzantine/federated defenses, deterministic evaluation results, cryptographic lineage, and drift/integrity health so you can see exactly what AI is running and how trustworthy it is. |
| 5 | Security Overview – Live Statistics | One-page, live security posture summary: total connections, blocked vs allowed decisions, active attacks and campaigns, kill‑switch state, SLA envelope status, and high‑level KPIs so leadership and operators can understand overall risk without drilling into individual signals or flows. |
| 6 | Threat Analysis by Type | Aggregated view of observed threats over time, grouped by category, tactic, severity, and confidence; highlights top attack types, trending behaviors, and MITRE‑aligned coverage, and feeds Section 9’s visual breakdown for rapid exploration of where the system is spending defensive effort. |
| 7 | IP Management & Threat Monitoring | Per‑IP and per‑entity risk console: live reputation/trust scores, historical incidents, recidivism flags, geographic/ASN context, and management actions (temporary quarantine, escalation, documentation) so defenders can quickly see which sources are persistently hostile and how the system is responding. |
| 8 | Failed Login Attempts (Battle-Hardened AI Server) | Focused analytics on authentication abuse against the platform itself: failed logins by source, account, method, and time; brute‑force and password‑spray patterns; off‑hours abuse; and correlations back to trust and reputation layers to ensure the control plane is not being quietly attacked. |
| 9 | Attack Type Breakdown (View) | Visual drill‑down of the ensemble’s threat classifications from Section 6: charts and timelines of attack families, severities, and confidence bands, designed purely for understanding and reporting (it introduces no new detection logic beyond what the 21 layers already decided). |
| 10 | Automated Signature Extraction – Attack Pattern Analysis | Workspace for deterministic, privacy‑respecting signature generation: shows which patterns have been extracted from malicious traffic, how they map to protocol/field locations and attack families, their promotion status into local rules, and what will be exported to the relay as pattern‑only intelligence (no payloads, no customer data). |
| 11 | System Health & Network Performance | Deep operational health view for the Battle‑Hardened AI node(s): CPU, memory, disk, NIC utilization, queue depths, latency budgets, network performance, watchdog/failover status, and integrity/self‑protection signals so operators know when to scale out, investigate hardware issues, or respond to attempted tampering. |
| 12 | Audit Evidence & Compliance Mapping | Curated audit evidence extracted from detections, decisions, and runbooks, mapped to external frameworks (PCI‑DSS, HIPAA, GDPR, SOC 2, MITRE, etc.); provides exportable JSON/CSV bundles and narrative summaries for auditors while deliberately avoiding becoming a policy or GRC engine itself. |
| 13 | Attack Chain Visualization (Phase 4 - Graph Intelligence) | Interactive graph view of multi‑step attacks and campaigns: nodes for hosts, users, and services; edges for reconnaissance, exploitation, lateral movement, and exfiltration; and overlays for tactics/severity so defenders can see how an intrusion is unfolding across the environment in real time. |
| 14 | Decision Explainability Engine (Phase 7 - Transparency) | Per‑decision forensic surface that exposes which of the 21 layers fired, their confidence scores, trust changes, causal reasoning, and final Step 21 semantic gate outcome, along with human‑readable narratives so SOC and IR teams can understand and defend every autonomous block or allow. |
| 15 | Adaptive Honeypot - AI Training Sandbox | Live view of the integrated honeypot environment: which services are exposed, which ports are active or auto‑skipped due to conflicts, attack traffic and payload patterns hitting decoy services, and how those interactions are being converted into new training material and signatures without risking production assets. |
| 16 | AI Security Crawlers & Threat Intelligence Sources | Status board for security crawlers and external intelligence: crawl schedules and last‑run times, coverage of external sources (exploit databases, OSINT, dark‑web indicators), error conditions, and how many indicators have been promoted into local reputation/threat‑intel layers. In the standard builds (Linux container and Windows EXE), hash/URL/score‑only OSINT crawlers are enabled by default, while heavier text‑based feeds remain optional and operator‑controlled. |
| 17 | Traffic Analysis & Inspection | Deep packet and flow analysis for live traffic: protocol and application breakdowns, encrypted vs cleartext ratios, unusual ports and methods, inspection verdicts from relevant detection layers, and enforcement summaries so operators can verify that network controls match policy and understand what is being blocked. |
| 18 | DNS & Geo Security | Dedicated surface for DNS and geographic‑risk analytics: DGA and tunneling heuristics, suspicious query patterns, NXDOMAIN and entropy metrics, geo‑IP risk zoning, and how those signals feed blocking, reputation, and trust so defenders can spot command‑and‑control, staging, and reconnaissance activity. This view is enriched by the OSINT crawlers and the local reputation tracker, so repeated bad infrastructure is treated more aggressively over time. |
| 19 | User & Identity Trust Signals | Identity‑centric view of entities the system observes: behavioral risk scores, unusual login and session patterns, device/location changes, Zero‑Trust trust deltas, and how identity signals are influencing execution decisions—explicitly without acting as IAM, lifecycle, or policy administration tooling. |
| 20 | Sandbox Detonation | Overview of file detonation and sandboxing results: how many artifacts have been detonated, verdict classifications, extracted indicators (domains, hashes, behaviors), and how those outcomes inform signatures, reputation, and causal reasoning, all while keeping payload inspection local to the protected environment. |
| 21 | Email/SMS Alerts (Critical Only) | Configuration and runtime status for critical system event alerts: which destinations are configured, which SYSTEM events (system failure, kill‑switch changes, integrity breaches) will trigger email/SMS notifications, recent send history, and failure diagnostics—positioned as a narrow safety‑of‑operation channel for system health only, not general threat alerting. |
| 22 | Cryptocurrency Mining Detection | Specialized analytics for crypto‑mining behavior: detection of mining pools and protocols (Stratum), anomalous resource usage (sustained 80%+ CPU), long‑lived connections to known mining pool IPs, associated entities and campaigns, and enforcement outcomes so operators can quickly confirm that cryptojacking/mining malware is being identified and blocked. Mining detections are strengthened by network traffic analysis, process monitoring, and the persistent reputation tracker. |
| 23 | Governance & Emergency Controls | Command surface for high‑assurance governance: current kill‑switch mode and approval workflow, pending and historical decisions in the approval queue, policy governance and Step 21 policy bundle status, secure‑deployment/tamper health, and audit/log integrity so operators can safely move between observe, approval, and fully autonomous deny modes. |
| 24 | Enterprise Security Integrations | Configuration and status view for outbound adapters that export first‑layer decisions into SIEM, SOAR, and IT‑operations platforms using the enterprise_integration.json surface, keeping this integration plane strictly export‑only and separate from the local firewall enforcement path. |

The **Enterprise Security Integrations** section (24) provides configuration and status for outbound adapters that stream first‑layer decisions into SIEM, SOAR, and IT‑operations platforms. This integrations surface focuses on visibility and coordination only; primary blocking remains on the local firewall enforcement plane. Note: The section title in technical documentation may include "(Outbound)" for clarity, but the dashboard displays it as "Enterprise Security Integrations".

##### Example: Minimal `enterprise_integration.json`

Battle-Hardened AI resolves an `enterprise_integration.json` file from its JSON configuration directory (see `AI/path_helper.py` and `documentation/mapping/Dashboard.md` for directory details). A minimal, realistic example looks like this:

```json
{
   "syslog_targets": [
      {
         "name": "primary-siem",
         "host": "10.0.10.5",
         "port": 514,
         "protocol": "udp",
         "format": "cef",
         "enabled": true
      }
   ],
   "webhook_targets": [
      {
         "name": "soar-playbook-ingest",
         "url": "https://soar.example.com/hooks/bh-ai-events",
         "method": "POST",
         "verify_tls": true,
         "enabled": true
      }
   ]
}
```

In this configuration, first-layer decisions (blocks/allows plus reasons) are streamed as summarized events to the SIEM and SOAR endpoints. Raw packet payloads and full PCAPs remain local to the Battle-Hardened AI node; only structured metadata and verdicts are exported.

#### Implementation Status at a Glance

This table summarizes major capability areas, where they live in the repository, and whether they are fully implemented or still evolving.

| Capability Area | Representative Modules / Paths | Status | Notes |
|-----------------|--------------------------------|--------|-------|
| Kernel telemetry & packet capture | `AI/kernel_telemetry.py`, `AI/pcap_capture.py` | Implemented | eBPF/syscall visibility and packet capture used in core detection layers. |
| Ensemble scoring & meta-decision engine | `AI/meta_decision_engine.py`, `AI/pcs_ai.py` | Implemented | Weighted voting, boosting, and decision export to JSON/firewall. |
| Causal inference & trust graph | `AI/causal_inference.py`, `AI/trust_graph.py` | Implemented (initial) | Produces root-cause and long-term trust signals (Layers 19 & 20). |
| Federated relay & training sync | `relay/relay_server.py`, `relay/training_sync_api.py`, `AI/training_sync_client.py`, `AI/byzantine_federated_learning.py` | Implemented (early access) | Optional; supports sanitized sharing and **models-only** updates with Byzantine validation (no raw training data leaves the relay). |
| Cloud security & API ingestion | `AI/cloud_security.py` | Partial / roadmap | Initial support present; broader provider coverage and runbooks will expand over time. |
| Step 21 semantic gate & policy governance | `AI/step21_semantic_gate.py`, `AI/policy_governance.py` | Implemented; refinement planned | Core semantic gate is active; additional policy bundles and hardening are listed under "Future Enhancements". |
| Compliance reporting & governance | `AI/compliance_reporting.py`, `AI/policy_governance.py` | Partial / roadmap | Baseline evidence surfaces exist; deeper framework mappings will grow with customer usage. |

#### Example: End-to-End Block Flow (Attack → Decision → Firewall)

The typical flow for a network attack looks like this:

1. **Packet observed** – Traffic hits the protected interface; kernel telemetry and packet capture modules record the flow.
2. **21-layer evaluation** – `AI/pcs_ai.py` orchestrates the detection pipeline (20 signals + Step 21 semantic gate) and produces a `SecurityAssessment` with `should_block`, `threat_level`, and `threats`.
3. **Decision export** – The assessment is written to JSON surfaces such as `threat_log.json` and `blocked_ips.json` in the configured JSON directory.
4. **Firewall sync** – On Windows, the `packaging/windows/windows-firewall/configure_bh_windows_firewall.ps1` script (installed as `{app}/windows-firewall/configure_bh_windows_firewall.ps1` and typically invoked by Task Scheduler with `-SkipBaselineRules` and an explicit `-JsonPath`) reads `blocked_ips.json` and updates the "Battle-Hardened AI Blocked IPs" rule. On Linux, iptables/ipset are updated via the server’s enforcement layer.
5. **Operator view** – The dashboard surfaces the same decision and context in Sections 5 (Security Overview), 7 (IP Management), 14 (Decision Explainability), and 23 (Governance & Emergency Controls).

This model keeps enforcement local to the OS firewalls, with the AI engine responsible for making high-quality, explainable allow/block decisions and exporting them in a machine-consumable form.

Firewall enforcement paths (Linux vs Windows EXE):

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

#### Troubleshooting & Operational Scenarios (Quick Reference)

- **Step 21 seems too aggressive (false positives):** Use the Governance & Emergency Controls section (23) to move from fully autonomous deny into observe or approval modes, then adjust the Step 21 policy bundle under `policies/step21` (for example, HTTP method and trust-threshold settings) and reload. For detailed guidance, see `documentation/architecture/Architecture_Enhancements.md` and `documentation/architecture/Attack_handling_flow.md`.
- **Relay/central training status is unhealthy:** Check Section 1 on the dashboard and the `/api/relay/status` endpoint for detailed error messages (DNS, TLS, authentication). Verify relay settings in the environment or in the installed `.env.windows` file next to `BattleHardenedAI.exe` (for EXE deployments), and ensure outbound firewall rules permit the configured relay URL/port.
- **Blocked IPs are not reflected in Windows Firewall:** Confirm that `blocked_ips.json` is being updated in the runtime JSON directory (for EXE builds this is under `%LOCALAPPDATA%/Battle-Hardened AI/server/json`), and that Task Scheduler is invoking `{app}/windows-firewall/configure_bh_windows_firewall.ps1` with `-SkipBaselineRules` and the correct `-JsonPath`. See `documentation/firewall/Firewall_enforcement.md` for examples.
- **Dashboard shows data but enforcement appears inactive:** On Linux, verify iptables/ipset rules were created and are still present; on Windows, inspect the "Battle-Hardened AI Blocked IPs" rule and ensure no third-party software has overridden it. In both cases, check the watchdog/service status and the Security Overview (Section 5) for recent block events.
- **General startup and health issues:** Follow the `documentation/installation/Installation.md` checklist, paying special attention to permissions, NIC binding, and JSON directory configuration. The System Health & Network Performance section (11) is the primary runtime surface for spotting resource and integrity problems.

### What Does Not Exist (Breakthrough)

To the best of our knowledge from publicly available vendor and research materials, no documented unified implementation—commercial or open—covers all of the following as a single architecture:

- Observe attacks end-to-end, across network, application, and behavioral layers
- Learn continuously from real adversary behavior
- Preserve raw attack intelligence in structured, privacy-respecting form
- Maintain long-lived trust memory that cannot be trivially reset
- Enforce protocol and execution semantic validity
- Deny execution meaning before attacker impact
- Apply these controls uniformly across environments
- Treat semantic invalidity as a first-class defensive signal

This is not a feature gap — **it is a paradigm gap**.

While isolated forms of semantic validation exist in narrow domains, to our knowledge no NDR or XDR platform implements system-wide semantic execution denial integrated with learning, trust memory, and causal reasoning. Battle-Hardened AI closes that gap by design.

### Normative References (Source-of-Truth Documents)

For auditors, engineers, and operators, the following documents serve as the authoritative technical references for this system:

- [Filepurpose](documentation/mapping/Filepurpose.md) — Maps every core file and JSON surface to the 7-stage pipeline and 21 detection layers
- [AI instructions](documentation/architecture/Ai-instructions.md) — Developer implementation guide, validation flow, and dashboard/endpoint mapping
- [Dashboard](documentation/mapping/Dashboard.md) — Dashboard and API reference tied directly to pipeline stages and JSON surfaces
- [Architecture Enhancements & Compliance](documentation/architecture/Architecture_Enhancements.md) — 5 implemented features plus compliance verification of runtime code paths
- [AI/ML pipeline proof](documentation/mapping/AI_ml_file_proof.md) — Complete technical proof of AI/ML training pipeline with exact file paths, line numbers, and 758K+ training examples
- [Attack handling flow](documentation/architecture/Attack_handling_flow.md) — End-to-end attack handling, from honeypot and network monitoring through pcs_ai, firewall, and relay
- [JSON File Rotation](documentation/JSON_file_rotation.md) — Automatic rotation system for JSON files to prevent bloat (threat logs, performance metrics, network state)

These documents collectively define the system’s intended behavior, guarantees, and constraints.

If you're starting from source as a developer or auditor, begin with [Filepurpose](documentation/mapping/Filepurpose.md); it is the canonical map for the AI/, server/, and relay/ components.

### Key Terms (For Non-Specialists)

- **eBPF/XDP:** Linux kernel technologies that let the system observe and filter packets directly in the OS with very low overhead.
- **PCAP:** Packet capture format used to record raw network traffic for analysis and replay in lab testing.
- **LSTM:** A type of recurrent neural network specialized for understanding sequences over time (for example, multi-step attack campaigns).
- **Autoencoder:** An unsupervised neural network used here to spot "never-seen-before" traffic patterns and potential zero-day attacks.
- **MITRE ATT&CK:** A community-maintained catalog of real-world attacker tactics and techniques; this README maps coverage against those techniques.

### Deployment Scope — Three Roles, Many Environments

**Battle-Hardened AI operates in 3 deployment roles:**

| Deployment Role | Protection Scope | Enforcement Method |
|----------------|------------------|-------------------|
| **Gateway/Router** | Entire network segment (all devices behind gateway) | Direct firewall commands (iptables/nftables on Linux) |
| **Host-only** | Single machine + services it terminates | Local firewall (iptables on Linux, Windows Defender Firewall) |
| **Observer** | Detection-only (no direct enforcement) | Exports decisions to external firewall via JSON feeds |

**Installation reference:** For setup by deployment role, see:
- [Installation.md § Deployment Role](documentation/installation/Installation.md#🎯-deployment-role-read-first)
- [Installation.md § Gateway Pre-Flight Checklist](documentation/installation/Installation.md#✅-gateway-pre-flight-checklist)
- [Installation.md § Linux Gateway Setup](documentation/installation/Installation.md#scenario-1-linux-gatewayrouter-network-wide-protection---recommended)
- [Installation.md § Cloud Gateway Setup](documentation/installation/Installation.md#scenario-2-cloud-gateway-with-virtual-nics-awsazuregcp)

**Cloud deployment:** Works identically on cloud VMs (AWS/Azure/GCP) with virtual NICs. Physical hardware not required.

**These 3 roles adapt to different environments:**

- **🏠 Home & Small Office:** Gateway protects entire LAN; host-only protects individual Windows/macOS machines
- **🏢 Enterprise Networks:** Gateway at LAN/VLAN/VPN edge; observer via SPAN/mirror for SOC visibility without routing changes
- **🖥 Servers & Data Centers:** Gateway on reverse proxies/appliance nodes; host-only on critical servers
- **🌐 Websites & APIs:** Gateway in front of web servers/API gateways (works alongside WAFs, not replacing them)
- **☁️ Cloud (IaaS/PaaS):** Gateway with virtual NICs (AWS ENIs, Azure vNICs, GCP interfaces); observer via VPC/VNet flow logs
- **🏭 OT & Critical Infrastructure:** Observer mode for non-intrusive ICS/SCADA/lab monitoring (no agents on sensitive equipment)
- **⚖️ Government & Defense:** Gateway for classified networks with strict data sovereignty (air-gapped relay option available)

#### Enforcement Requires Firewall Integration

To make deny decisions real, Battle-Hardened AI must be connected to the underlying firewall. **Before any production rollout, review [documentation/firewall/Firewall_enforcement.md](documentation/firewall/Firewall_enforcement.md) end-to-end.** On Linux, this typically involves `ipset`/`iptables`; on Windows, it wires into Windows Defender Firewall via PowerShell.

### Hardware Deployment Checklists

These checklists describe hardware setups for gateway and inline bridge roles. Linux is the primary OS for routing and enforcement. Windows is supported for host-only or appliance-style deployments.

#### ✅ Option A — Battle-Hardened AI as Edge Gateway Router (Recommended for Full Control)

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
- Wi‑Fi AP in bridge mode (no DHCP/NAT)

**What This Delivers**

- Battle-Hardened AI becomes the default gateway
- All traffic flows through Battle-Hardened AI (no bypass without physical change)
- Full control over NAT, routing, firewall, and semantic validation

#### ✅ Option B — Battle-Hardened AI as Transparent Inline Bridge (No Routing Changes)

**Network Topology**

```text
Modem/ONT → Battle-Hardened AI (Bridge) → Existing Router
```

**Required Hardware**

- Modem/ONT in bridge mode
- Battle-Hardened AI Linux node with 2 NICs (WAN-side + LAN-side)
- Existing router handling NAT, DHCP, and Wi‑Fi

**What This Delivers**

- No router reconfiguration needed
- Battle-Hardened AI still sees and filters traffic before router interaction
- Minimal architectural disruption

#### ⚠️ What You Don’t Need

- ❌ SD-WAN or cloud-managed routers
- ❌ Proprietary routers or expensive chassis
- ❌ Agents on endpoints
- ❌ Cloud connectivity for core detection

### System Requirements & Platform Support

Minimum suggested specs for lab/small deployments (per node):

- Linux gateway/appliance: 4 CPU cores, 8–16 GB RAM, SSD/NVMe storage.
- Windows host-only/appliance: 4 CPU cores, 8–16 GB RAM, SSD storage.
- Network: 2 NICs for inline/gateway roles; 1 NIC for host-only or SPAN/TAP deployments.

Actual requirements depend on traffic volume, retention, and enabled modules; see Installation and Windows checklists for details.

#### Platform & OS Support Summary

| Feature | Linux (Recommended) | Windows / macOS (Host-Only) |
|---------|---------------------|-----------------------------|
| Deployment mode | Gateway / router / bridge | Host-level / appliance |
| GUI dashboard | ✅ | ✅ |
| Docker support | ✅ Full (with NET_ADMIN) | ❌ Limited (bridge-mode isolation) |
| Native firewall integration | ✅ `iptables`/`ipset` | ✅ Windows Defender Firewall |
| Package format | `.deb` / `.rpm` | `.exe` installer |
| Auto-restart | `systemd` + Docker policies | Watchdog / Windows service |
| Packet capture & eBPF | ✅ | ⚠️ Requires administrator privileges |
| Scalability | 10,000+ connections (scalable) | ~500 connections (OS limits) |

See [documentation/installation/Installation.md](documentation/installation/Installation.md) and [Windows-testing-checklist.md](documentation/checklist/Windows-testing-checklist.md) for detailed setup instructions. For production firewall synchronization, see [documentation/firewall/Firewall_enforcement.md](documentation/firewall/Firewall_enforcement.md).

---

## Competitive Positioning vs NDR/XDR Platforms

**Battle-Hardened AI is not positioned as "better detection" or "higher accuracy."**  
**It is a first-layer autonomous execution-denial system — a fundamentally different defensive control class.**

Most commercial NDR/XDR platforms are **event-driven correlation engines** that observe activity, correlate events, and surface alerts. Battle-Hardened AI is a **stateful autonomous defense system** that reasons about cause, remembers adversaries across time, degrades trust persistently, and determines whether interactions are allowed to execute at all—**before** any state changes occur.

### Key Architectural Differentiators

**21 Independent Detection Layers:** Battle-Hardened AI explicitly documents 20 independent signal classes plus a Step 21 semantic execution-denial gate. Each layer has defined purpose, known failure modes, and participates in consensus voting. Most vendors don't disclose signal counts or boundaries.

**Causal Inference (Layer 19):** Determines **why** anomalies occur (attack vs. legitimate deployment), resolving contradictory signals and preventing false positives. Competitors perform correlation (what happened together), not causation (why it happened).

**Persistent Trust Memory (Layer 20):** Trust degrades based on behavior and persists across sessions, reboots, and time gaps—never fully recovering. Competitors use time-decayed scores that reset. **Attackers exploit forgetting; Battle-Hardened AI doesn't forget.**

**Semantic Execution Gate (Layer 21):** Final enforcement validates state validity, intent, structural integrity, and trust thresholds before allowing execution—even if earlier layers approved.

**First-Layer vs Downstream:** Battle-Hardened AI operates at the execution gate ("Should this be allowed?") **before** state changes. NDR/XDR platforms act **after** ("What happened and how do we respond?").

### Platform Comparison

| Platform | Signals/Layers | Decision Method | Causal Reasoning | Trust Memory | Explainability | Analyst Dependency |
|----------|----------------|-----------------|------------------|--------------|----------------|-------------------|
| **Battle-Hardened AI** | **21 documented** | Transparent weighted voting |  Layer 19 |  Persistent (Layer 20) |  Full trace | Optional (autonomous) |
| CrowdStrike Falcon | 3-4 (undisclosed) | ML black box |  |  | Limited alerts | Required |
| SentinelOne Singularity | 4-5 (undisclosed) | Storyline correlation |  |  | Limited storyline | Required |
| Darktrace | 5-6 (undisclosed) | Neural network |  | Partial (decaying) | Limited scores | Required |
| Cortex XDR | 3-4 (undisclosed) | Behavioral analytics |  |  | Partial event chain | Required |
| Traditional IDS | 1 | Signature matching |  |  | Binary | Required |

*Competitor capabilities inferred from public materials.*

### Conservative Scoring Prevents False Positives

**Example: SQL Injection Detection**
- **12 of 20 signals** fire → Base weighted score: **57.2%**
- **Authoritative signals** (Threat Intel 98% + FP Filter 5/5) → Boosted to **100%** → **BLOCK**

**Why this matters:**

| Event | Battle-Hardened AI | CrowdStrike/Darktrace |
|-------|-------------------|----------------------|
| **SQL Injection** | Base 57% → Boosted 100% → ✅ **BLOCK** | ~85% → ✅ **BLOCK** |
| **Legitimate CI/CD Deployment** | Base 45% → No boost → ✅ **ALLOW** | ~75% → ❌ **FALSE POSITIVE** |
| **APT Low-and-Slow** | Base 35% → Trust degradation → 65% → ✅ **BLOCK** | ~40% → ❌ **MISS** |

**Conservative base scoring (57.2%) prevents false positives on ambiguous events, while authoritative signals ensure real threats are blocked.** Competitors' aggressive scoring (80-90%) creates false positives on legitimate operations.

### Summary

✅ **21 documented layers** vs 3-6 undisclosed  
✅ **Transparent decision traces** vs black-box ML  
✅ **Causal inference** (unique—no competitor has this)  
✅ **Persistent trust memory** (never resets)  
✅ **Semantic execution gate** (pre-impact denial)  
✅ **Conservative scoring** (fewer false positives)  
✅ **Autonomous operation** (SOC-optional)

*For detailed insights, see [Why Evasion Is Extremely Hard in Practice](#why-evasion-is-extremely-hard-in-practice).*

### Integration with Existing Security Stack

Battle-Hardened AI is designed to sit in front of, and alongside, existing controls rather than replace them.

- **Versus firewalls (NGFW/WAF):** Traditional firewalls enforce static or signature-based rules on packets and sessions. Battle-Hardened AI acts as a semantic commander in front of them, deciding *whether* an interaction should be allowed at all and then driving firewall rules accordingly.
- **Versus NDR/XDR:** NDR/XDR platforms aggregate telemetry and raise alerts *after* execution. Battle-Hardened AI operates at the execution gate, using 21 documented layers plus the semantic execution-denial gate to reject malicious actions before they reach those systems.
- **Versus SD-WAN and routing gear:** SD-WAN optimizes paths and connectivity between sites. Battle-Hardened AI focuses purely on security semantics and trust, determining which flows should exist at all and leaving path selection to the network layer.
- **Versus EDR (agent-based):** EDR agents live on individual endpoints and watch local processes. Battle-Hardened AI typically runs as a gateway node with no agents, protecting many devices at once and exporting decisions that EDR/XDR tools can still consume.

---

#### Stage 4: Response Execution (Policy-Governed)

Based on ensemble decision, the system executes controlled responses:

**Immediate Actions (if `should_block = true`):**
1. **Firewall Block:** Add IP to `iptables` or `nftables` with TTL (e.g., 24 hours), or invoke Fortinet, Cisco ASA, and other programmable firewalls via their APIs
2. **Connection Drop:** Terminate active TCP connections from attacker
3. **Rate Limiting:** If partial threat (50-74%), apply aggressive rate limiting instead of full block

**Logging Actions (always executed):**
1. **Local Threat Log:** Write to `threat_log.json` under the JSON directory returned by `AI.path_helper.get_json_dir()`
    ```json
    {
       "timestamp": "2026-01-07T10:32:15Z",
       "ip_address": "203.0.113.42",
       "threat_type": "SQL Injection",
       "details": "Port 443 login form SQL injection string detected",
       "level": "CRITICAL",
       "action": "blocked",
       "geolocation": {
          "country": "United States",
          "region": "New York",
          "city": "New York",
          "asn": "AS15169"
       },
       "anonymization_detection": {
          "is_anonymized": false,
          "anonymization_type": "direct",
          "confidence": 0
       },
       "behavioral_metrics": null,
       "attack_sequence": null,
       "source": "local"
    }
    ```

2. **JSON Audit Surfaces:** Update multiple files:
   - `threat_log.json` (primary threat log, auto-rotates at 100MB)
   - `comprehensive_audit.json` (all THREAT_DETECTED events, auto-rotates at 100MB)
   - `dns_security.json` (DNS tunneling metrics)
   - `tls_fingerprints.json` (encrypted traffic patterns)
   - `network_graph.json` (topology updates)
   - `behavioral_metrics.json` (per-IP statistics)
   - `attack_sequences.json` (LSTM state sequences)
   - `lateral_movement_alerts.json` (graph intelligence findings)
   - `causal_analysis.json` *(Layer 19: root cause analysis results)*
   - `trust_graph.json` *(Layer 20: entity trust state tracking)*
   
   **Note:** Files marked "auto-rotates at 100MB" use file rotation (`AI/file_rotation.py`) to prevent unbounded growth (optimized for resource-constrained relay servers). ML training reads ALL rotation files (`threat_log.json`, `threat_log_1.json`, `threat_log_2.json`, etc.) to preserve complete attack history.

3. **Dashboard Update:** Real-time WebSocket push to `inspector_ai_monitoring.html`

**Alert Actions (configurable):**
1. **Email/SMS:** Send only for critical system events (system failure, kill-switch changes, and integrity breaches; not general threat alerts)
2. **Syslog/SIEM:** Forward to enterprise logging systems

**Stage 4 → Stage 5 Transition:**

Stage 4 writes attack details to `threat_log.json`, `comprehensive_audit.json`, and signal-specific logs → background extraction jobs scan logs periodically (every hour):
- `AI/signature_extractor.py` is invoked from `AI/pcs_ai.py` when threats are logged → extracts attack patterns from each new event → appends them to `honeypot_patterns.json` under the JSON directory returned by `AI.path_helper.get_json_dir()`
- `AI/reputation_tracker.py` reads `threat_log.json` → updates `reputation.db` with attacker IPs (SHA-256 hashed)
- `AI/graph_intelligence.py` reads `lateral_movement_alerts.json` → updates `network_graph.json`

Extracted materials staged locally in the JSON directory returned by `AI.path_helper.get_json_dir()` → ready for Stage 6 relay push.

---

#### Stage 5: Training Material Extraction (Privacy-Preserving)

High-confidence attacks are converted into **sanitized training materials** (no payloads, no PII).

**What Gets Extracted:**

1. **Attack Signatures** (patterns only, zero exploit code):
   ```json
   {
     "signature_id": "sig_20260107_001",
     "attack_type": "SQL Injection",
     "pattern": "' OR 1=1--",
     "encoding": "url_encoded",
     "http_method": "POST",
     "confidence": 0.95
   }
   ```

2. **Behavioral Statistics**:
   ```json
   {
     "avg_connection_rate": 50,
     "port_entropy": 3.8,
     "fan_out": 20,
       "geographic_region": "AS15169"
   }
   ```

3. **Reputation Updates**:
   ```json
   {
   "ip_hash": "sha256(203.0.113.42)",
     "attack_count": 3,
     "severity_avg": 0.87,
     "last_seen": "2026-01-07"
   }
   ```

4. **Graph Topology** (anonymized):
   ```json
   {
   "pattern": "A→B→C",
     "hop_count": 3,
     "time_window": 300,
     "attack_type": "lateral_movement"
   }
   ```

5. **Model Weights** (ML/LSTM updates):
   - Updated RandomForest trees
   - LSTM weight adjustments
   - Autoencoder parameter updates

**Customer-Side Local Staging:**

Extracted materials are initially stored locally on the customer node under the JSON directory returned by `AI.path_helper.get_json_dir()` (typically `server/json/` on bare-metal or `/app/json/` in Docker deployments):
- `honeypot_patterns.json` (attack patterns)
- `behavioral_metrics.json` (connection statistics)
- `reputation.db` (SQLite - IP reputation hashes)
- `network_graph.json` (topology patterns)

**Note:** Customer nodes extract locally first. Relay receives these materials via Stage 6 push (not direct writes). This maintains the customer/relay separation - relay paths (`relay/ai_training_materials/`) are only on the relay server, never accessible to customer nodes.

**Bandwidth Optimization:** Bloom filter-based pattern deduplication (`AI/pattern_filter.py`) achieves 70-80% bandwidth reduction by filtering duplicate signatures before relay upload while maintaining 99.9% accuracy.

---

#### Stage 6: Global Intelligence Sharing (Optional Relay)

If relay is enabled, sanitized materials are shared worldwide.

**Push to Relay** (authenticated WebSocket):
```
Client → Relay Server
{
   "node_id": "sha256(unique_id)",
   "signatures": [],
   "statistics": {},
   "reputation_updates": [],
   "model_diffs": {}
}
```

**Pull from Relay** (every 6 hours):
```
Client ← Relay Server
{
   "global_signatures": [],
   "reputation_feed": [],
   "model_updates": {},
  "threat_statistics": {
    "top_attack_types": ["SQL Injection", "Brute Force"],
    "emerging_threats": ["CVE-2026-1234"]
  }
}
```

**Integration:**
- New signatures → added to signature database
- Reputation feed → merged with local reputation tracker
- Model updates → validated by Byzantine defense → merged if safe
- Statistics → displayed in dashboard "AI Training Network" section

**Result:** Every node learns from attacks observed **anywhere in the global network**.

**Model Distribution Security:** All models distributed via relay are cryptographically signed with Ed25519 signatures (`AI/model_signing.py`) and verified before loading, preventing model injection attacks even if the relay is compromised (defends against MITRE T1574.012).

**Stage 6 → Stage 7 Transition:**

Customer nodes push training materials to relay (every hour) → relay stores in `relay/ai_training_materials/` directory → relay aggregates data from all customer nodes worldwide:
- Signatures merged into `learned_signatures.json` (deduplicated)
- Attack records appended to `global_attacks.json` (grows continuously, rotates at 100MB using `AI/file_rotation.py`)
- Reputation data consolidated into `reputation_data/`

Aggregated dataset triggers Stage 7 retraining (weekly) → new models trained → distributed back to customers via Stage 6 pull.

**Critical:** `relay/ai_training_materials/global_attacks.json` uses file rotation - ML training reads ALL rotation files (`global_attacks.json`, `global_attacks_1.json`, `global_attacks_2.json`, etc.) to preserve complete training history.

---

#### Stage 7: Continuous Learning Loop

The system continuously improves through feedback:

1. **Signature Extraction:** New attack patterns added every hour
2. **ML Retraining:** Models retrained weekly with new labeled data (relay uses ONNX format for 2-5x faster inference on customer nodes)
3. **Adversarial Training:** Relay generates adversarial examples via FGSM to harden models against ML evasion attacks (defends against MITRE T1562.004)
4. **Model Performance Monitoring:** Production accuracy tracked continuously (`AI/model_performance_monitor.py`); auto-retraining triggered if accuracy drops below 85% (defends against MITRE T1565.001)
5. **Drift Detection:** Baseline updated monthly to adapt to network changes
6. **Reputation Decay:** Old attacks gradually fade (half-life: 30 days)
7. **Byzantine Validation:** Malicious updates rejected (94% accuracy in internal lab testing)

**Feedback Sources:**
- **Honeypot Interactions:** 100% confirmed attacks (highest quality training data)
- **Human Validation:** SOC analyst confirms/rejects alerts → improves ML
- **False Positive Reports:** Whitelisted events → update FP filter

**Performance Enhancements:** Customer nodes use ONNX Runtime for optimized ML inference (2-5x faster than pickle, 40% lower CPU usage). See [documentation/architecture/Architecture_Enhancements.md](documentation/architecture/Architecture_Enhancements.md) for complete technical details on model signing, adversarial training, performance monitoring, and ONNX integration.

**Stage 7 → Stage 1 Feedback Loop (Completes the 7-Stage Cycle):**

1. Relay retrains models using aggregated global attack data → new `*.pkl` and `*.keras` models created
2. Models pushed to relay API → `relay/training_sync_api.py` serves updated models
3. Customer nodes pull updates (every 6 hours) via `AI/training_sync_client.py`:
   - New signatures downloaded → merged into local signature database
   - New ML models downloaded → replace old models in the ML models directory returned by `AI/path_helper.get_ml_models_dir()` (AI/ml_models in development, /app/ml_models in Docker)
   - `AI/byzantine_federated_learning.py` validates updates (94% malicious rejection rate in internal evaluations)
4. Updated models loaded by Stage 2 detection signals → **improved accuracy for next packet analysis in Stage 1**
5. Cycle repeats: better detection → more accurate training data → better models → better detection...

**This continuous feedback loop enables the system to adapt to evolving threats without manual intervention.**

---

## High-Level Capabilities

Battle-Hardened AI is designed to be operator-friendly: the dashboard focuses on clear, explainable decisions, conservative defaults, and monitor-only modes so that it reduces analyst workload instead of creating another noisy alert stream.

### Threat Model & Assumptions

- **Scope:** Network-level detection and response for IP-based entities (devices, users, services, cloud roles) using packet, flow, and log telemetry. Endpoint EDR/host-level controls remain separate and complementary.
- **In-Scope Adversaries:** External attackers, APT campaigns, misconfigured automation, and insider threats operating over the network (including authenticated but anomalous behavior visible in traffic and logs).
- **Out-of-Scope Adversaries:** Physical attacks, pre-boot firmware compromise, supply-chain backdoors present before first packet, and offline data theft not observable in network or system logs.
- **Deployment Assumptions:** Battle-Hardened AI is placed where it has full visibility to relevant traffic (inline proxy, gateway, or SPAN/TAP). For encrypted traffic, visibility is limited to metadata (SNI, certificate, timing, sizes) unless deployed behind a TLS termination point.
- **Trust Model:** The AI server itself is treated as a hardened, monitored asset; OS, Docker (when used), and surrounding infrastructure must follow standard security best practices.

### Validation & Testing (Where the Numbers Come From)

- **Signature Count (3,066+):** Derived from the active signature set used by the Signature Matching layer, built from curated public attack pattern sources and sanitized honeypot extractions. The count reflects unique, deduplicated patterns, not rule-line inflation.
- **Accuracy Figures (~94% Recidivism / Byzantine Rejection):** Measured on held-out evaluation sets constructed from historical threat logs and simulated relay updates. Metrics are computed as standard classification accuracy on labeled events (attack vs benign or valid vs poisoned updates), with time windows and dataset sizes documented in internal test harness notebooks.
- **Evasion Probability (modeled extremely low):** An order-of-magnitude illustration assuming independence across multiple high-confidence signals and conservative success probabilities per evasion dimension. It is not a formal cryptographic guarantee.
- **Thresholds & Weights:** Defense thresholds (50% log, 75% block) and signal weights (0.65–0.98) were tuned via cross-validation on mixed benign/attack corpora to minimize false positives while preserving high recall on known and synthetic attack traces.

#### Current Validation Status

At present, these figures are derived from internal lab evaluations, adversarial simulations, and scripted attack scenarios (see [AI instructions](documentation/architecture/Ai-instructions.md) and [KALI_ATTACK_TESTS.md](KALI_ATTACK_TESTS.md)). There is no independent third-party validation or production case study published yet; as pilots and reviews complete, this section will be updated with external metrics and deployment evidence.

### Known Limitations & Edge Cases

- **Ultra-Low-and-Slow Attacks:** Extremely slow campaigns (e.g., one request per day) may require longer observation windows for clear statistical separation; detection still improves over time through trust degradation and graph intelligence but can be delayed.
- **Insiders with Strong Privileges:** Fully trusted insiders with valid credentials who behave very similarly to normal workloads are inherently hard to distinguish; network behavior is still monitored, but intent may be ambiguous.
- **Partial Visibility / Encrypted Traffic:** When deployed without access to decrypted application traffic, certain payload-centric techniques rely more heavily on behavioral, graph, and reputation signals rather than deep content inspection.
- **Degraded Signal Set:** If some models or signals are disabled, missing, or misconfigured, ensemble robustness decreases; the system degrades gracefully but with reduced redundancy. Operators should treat missing signals as a misconfiguration to fix, not a normal state.
- **Misconfigured Mirroring / SPAN:** Incorrect SPAN/TAP or routing can create blind spots; Battle-Hardened AI assumes that the traffic it sees is representative of the environment it is defending.

### Operational Guidance & Reference Deployment Patterns

- **Home / Lab:** Single-node deployment at the home router or gateway mirror port; modest CPU (4 cores), 8–16 GB RAM, and SSD storage are typically sufficient for thousands of concurrent flows.
- **SMB / Branch Office:** Inline or tap-based deployment at the site gateway, with 8–16 cores, 32 GB RAM, and NVMe storage to sustain higher connection rates and full audit logging.
- **Enterprise / Data Center:** One Battle-Hardened AI node per major segment (e.g., DC edge, user access, cloud egress), potentially clustered behind a load balancer or distribution layer for scale-out; sizing depends on peak connections and desired retention period.
- **ISP / High-Throughput:** Requires careful capacity planning, hardware acceleration (where available), and potentially multiple nodes sharded by customer or prefix; in these environments, aggressive log rotation and selective telemetry are critical.
- **Overload Behavior:** When resource pressure increases, operators should prioritize maintaining detection and logging fidelity by scaling vertically/horizontally rather than accepting packet loss; standard OS and network QoS controls apply.

### Security of the System Itself (Self-Protection)

- **Model & Telemetry Integrity:** Integrity Monitoring (Signal 18) detects attempts to tamper with logs, telemetry sources, or model artifacts and escalates severity when such tampering coincides with threats.
- **Poisoning Resistance:** Byzantine Federated Learning (Signal 17) evaluates incoming model updates and relay contributions, rejecting suspected poisoned updates with high accuracy before they influence production models.
- **Minimal Attack Surface:** The core server exposes a tightly scoped HTTP interface and can be placed behind reverse proxies or firewalls; operators are expected to restrict SSH, management ports, and relay access to trusted administrative paths.
- **OS & Container Hardening:** Standard OS baselines (patching, CIS-style hardening, least-privilege service accounts) and hardened Docker configurations (if used) are assumed; Battle-Hardened AI does not override host security posture.
 - **Emergency Controls:** Kill-switch modes and the Governance & Emergency Controls dashboard section (core section 23 and related APIs) allow operators to rapidly shift from autonomous enforcement to monitor-only or fully disabled enforcement in case of suspected compromise.

### Governance, Change Control & Step 21 Policy Management

- **Roles & Responsibility:** Step 21 semantic policies (roles, actions, structural rules) are treated as governed configuration, not ad-hoc code. Only designated security owners should modify these policies via approved change-control processes.
- **Monitor-Only vs Enforce:** Environments can operate Step 21 in monitor-only mode (log semantic violations without blocking) during initial rollout or policy updates, then transition to full enforcement after validation.
- **Staged Rollouts:** Policy changes should be staged (test → pre-production → production) with audit trails in configuration management and clear rollback procedures to avoid accidental denial of legitimate traffic.
- **Auditability:** Each semantic decision is explainable and logged; this allows reviewers to see which policy dimension (state, intent, structure, trust) caused a block and adjust policies accordingly.

Governed Step 21 flow (monitor-only vs enforce):

```text
     ┌──────────────────────────────┐
     │  policies/step21/*.json     │
     │  (roles, actions, schemas,  │
     │   trust thresholds)         │
     └─────────────┬────────────────┘
             │
             ▼
     ┌──────────────────────────────┐
     │  Step 21 Semantic Gate       │
     │  (enforced in AI/step21_*.py)│
     └─────────────┬────────────────┘
             │
     ┌─────────────┴───────────────────────────────┐
     │                                             │
     ▼                                             ▼
  Monitor-only mode                             Enforce mode
  (log semantic violations                      (log + block invalid
   to threat_log.json,                          execution requests
   causal_analysis.json,                         before state change)
   trust_graph.json)                            
```

### How to Trust This (Auditors & CISOs)

- **What It Guarantees:** Best-effort, defense-in-depth detection and blocking across 21 documented layers with full decision transparency, persistent memory, and continuous learning; explicit documentation of 43 mapped MITRE ATT&CK techniques.
- **What It Does Not Guarantee:** It is not a formal proof of security, not a replacement for endpoint controls, traditional firewalls, or rigorous patch management, and cannot prevent attacks that are fundamentally invisible to its telemetry.
- **Independent Verification:** Auditors can inspect code, configuration, and logs (threat_log.json, comprehensive_audit.json, causal_analysis.json, trust_graph.json) to verify that the documented layers and policies are active and behaving as described.
- **Architecture Compliance:** The documented behavior in this README is backed by the architecture and validation materials in Architecture_Enhancements.md and related runbooks, allowing formal review against organizational security standards.
- **Control Interaction:** Battle-Hardened AI is designed to complement, not replace, existing NDR, IDS/IPS, firewalls, and EDR controls, adding semantic gating, persistent trust, and federated learning as additional defensive layers.

### FAQ & Common Objections

- **“What if the models are wrong?”** The ensemble is intentionally conservative, supported by causal inference and trust modulation. All actions are logged with explainable traces so operators can tune thresholds and override decisions when needed.
- **“How do I roll back a bad update?”** Model and policy updates can be versioned and rolled back via configuration management and deployment tooling; emergency kill-switch and monitor-only modes provide additional safety nets during incident response.
- **“What if the relay is compromised?”** Relay participation is optional and uses anonymized, pattern-level data. Byzantine defenses and integrity checks reduce the risk of poisoned updates; in high-assurance environments, relay can be fully disabled.
- **“How does this coexist with my existing NDR/EDR/Firewall?”** Battle-Hardened AI is typically deployed as a complementary layer (gateway, sensor, or proxy), feeding additional intelligence into existing controls and automation/orchestration pipelines rather than replacing them.
- **“What happens if Step 21 blocks a critical request by mistake?”** Semantic decisions are fully logged and explainable; operators can switch to monitor-only mode, adjust the offending policy, and replay or safely reissue the legitimate request through normal change processes.

### Advanced Defense Modules

- Byzantine-resilient learning
- Cryptographic lineage & provenance
- Deterministic evaluation
- Formal threat modeling
- Self-protection & integrity monitoring
- Policy-driven governance
- Emergency kill-switch modes

### Autonomous & Governed Response

- Adaptive honeypots
- Self-healing actions (firewall, services, rollback)
- Predictive threat modeling
- Deception and attacker profiling

### Persistent Intelligence

- Cross-session reputation memory
- Geolocation-aware risk scoring
- Reputation decay
- OSINT correlation
- No payload storage

## Defensive-Only Assurance

Battle-Hardened AI:

- Does not store exploit payloads
- Does not perform offensive actions
- Does not exfiltrate customer traffic
- Operates under observer-first principles
- Supports human-in-the-loop enforcement

## Closing Statement

Battle-Hardened AI is an open, battle-hardened cyber defense platform.

It is engineered for **real-world defensive use** by:

- Military and defense organizations
- Law enforcement and national security agencies
- Government ministries and critical infrastructure operators
- Enterprises and SOC teams
- Advanced home labs and small environments that want first-layer protection

The platform is released as open source, with no commercial appliance SKU, and is
intended for expert operators who understand security engineering, governance,
and operational risk. It continues to evolve rapidly, but every shipped feature is
designed around a single goal: safely enforcing first-layer, pre-execution denial
in high-assurance environments.

Battle-Hardened AI demonstrates how:

- Multi-signal detection
- Governed AI automation
- Federated intelligence
- Kernel-level telemetry

can be safely applied to modern network defense at **home, organizational, and
national scale**.

### Deployment & Access

**Home / Lab usage:** USD 10 / month  
**Organizations / SOCs:** USD 50 / month

These subscription tiers cover managed builds, signed packages, and support; the source code remains available for self-hosted deployments without a subscription.

### Founder & Core Development

Founded and led by **Yuhisern Navaratnam** (core development and support coordination).

**Contact:** Yuhisern Navaratnam  
**WhatsApp:** +60172791717  
**Email:** yuhisern@protonmail.com

![Elite Cybersecurity Specialist](assets/ELITE-CYBERSECURITY-SPECIALIST.png)
