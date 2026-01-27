## Battle-Hardened AI

---

### 🔑 Summary Highlights

- Blocks malicious actions **before execution** using a 21-layer AI ensemble and a final semantic execution-denial gate.
- Acts as a **first-layer firewall commander** for gateways and routers, deciding what should be blocked while delegating actual enforcement to the local firewall control plane.
- Works **without agents**, exporting neutral JSON that plugs into existing SIEM, SOAR, firewall, and XDR stacks.
- Provides documented coverage for **43 MITRE ATT&CK techniques** via pre-execution denial and trust degradation.
- Built for **enterprise, government, and national-security** defense use cases where autonomy, auditability, and privacy are mandatory.
- Optionally connects to a **central relay/VPS** where many Battle-Hardened AI nodes share only sanitized attack patterns and receive model/signature updates,
  so global learning improves over time without any customer content or PII leaving local infrastructure.

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

In the standard shipping profiles:

- The **Linux gateway container** and the **Windows EXE** both include the persistent reputation tracker by default (backed by `reputation.db` under the JSON directory), so repeat offenders and long-lived bad actors are remembered across sessions.
- Core OSINT threat crawlers (hash/URL/score–only feeds such as MalwareBazaar, URLhaus, and CVE scores) are enabled by default and feed the threat intelligence and DNS/geo sections, while heavier text-based feeds remain optional and operator-controlled.
- Advanced TensorFlow-based autoencoder and sequence models are available as an optional, environment-specific profile for customers that explicitly want the full ML stack and are prepared for the larger footprint.

### Canonical Deployment

In its standard form, Battle-Hardened AI runs on a **Linux gateway or edge appliance** (physical or virtual), directly in front of the protected segment. Optional Windows/macOS nodes act as **host-level defenders** for specific assets or branches. It is designed to integrate without disrupting existing stacks—SIEM, SOAR, IAM, EDR/XDR, NGFW—acting solely as the execution-control authority and gateway commander.

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

This is not an incremental NDR/XDR feature enhancement. Battle-Hardened AI is a **stateful, pre-execution control class**—a new layer that:

- Resists probing and iterative evasion
- Degrades adversary trust over time
- Prevents coercion by malicious inputs
- Covers 43 MITRE ATT&CK techniques
- Operates independently of alert volume or SIEM bloat

### What Makes Us Different

Most platforms react **after** execution. Battle-Hardened AI intervenes **before**.

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

## Competitive Landscape

Battle-Hardened AI is designed to sit in front of, and alongside, existing controls rather than replace them.

- **Versus firewalls (NGFW/WAF):** Traditional firewalls enforce static or signature-based rules on packets and sessions. Battle-Hardened AI acts as a semantic commander in front of them, deciding *whether* an interaction should be allowed at all and then driving firewall rules accordingly.
- **Versus NDR/XDR:** NDR/XDR platforms aggregate telemetry and raise alerts *after* execution. Battle-Hardened AI operates at the execution gate, using 21 documented layers plus the semantic execution-denial gate to reject malicious actions before they reach those systems.
- **Versus SD-WAN and routing gear:** SD-WAN optimizes paths and connectivity between sites. Battle-Hardened AI focuses purely on security semantics and trust, determining which flows should exist at all and leaving path selection to the network layer.
- **Versus EDR (agent-based):** EDR agents live on individual endpoints and watch local processes. Battle-Hardened AI typically runs as a gateway node with no agents, protecting many devices at once and exporting decisions that EDR/XDR tools can still consume.

---

## Visual Attack Detection & Response Flow

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
- Install following [documentation/Installation.md](documentation/Installation.md), then bring services up as described in [Startup guide](documentation/Startup_guide.md).
- Open the dashboard documented in [Dashboard](documentation/Dashboard.md) to verify live telemetry and decision traces.
- Wire your local firewall using [documentation/Firewall_enforcement.md](documentation/Firewall_enforcement.md) and confirm that blocked IPs appear both in the dashboard and in JSON outputs.

**Enterprise / SOC**

- Select one gateway or choke point per protected segment, and install Battle-Hardened AI there using [documentation/Installation.md](documentation/Installation.md).
- Follow [Startup guide](documentation/Startup_guide.md) to start services, then integrate with SIEM/SOAR as described in [Dashboard](documentation/Dashboard.md) and [Attack handling flow](documentation/Attack_handling_flow.md).
- Enable firewall synchronization using [documentation/Firewall_enforcement.md](documentation/Firewall_enforcement.md) so auto-block decisions propagate to `iptables`/`ipset` (Linux) or Windows Defender Firewall.
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
| 13 | Attack Chain Visualization (Graph Intelligence) | Interactive graph view of multi‑step attacks and campaigns: nodes for hosts, users, and services; edges for reconnaissance, exploitation, lateral movement, and exfiltration; and overlays for tactics/severity so defenders can see how an intrusion is unfolding across the environment in real time. |
| 14 | Decision Explainability Engine | Per‑decision forensic surface that exposes which of the 21 layers fired, their confidence scores, trust changes, causal reasoning, and final Step 21 semantic gate outcome, along with human‑readable narratives so SOC and IR teams can understand and defend every autonomous block or allow. |
| 15 | Real Honeypot – AI Training Sandbox | Live view of the integrated honeypot environment: which services are exposed, which ports are active or auto‑skipped due to conflicts, attack traffic and payload patterns hitting decoy services, and how those interactions are being converted into new training material and signatures without risking production assets. |
| 16 | AI Security Crawlers & Threat Intelligence Sources | Status board for security crawlers and external intelligence: crawl schedules and last‑run times, coverage of external sources (exploit databases, OSINT, dark‑web indicators), error conditions, and how many indicators have been promoted into local reputation/threat‑intel layers. In the standard builds (Linux container and Windows EXE), hash/URL/score‑only OSINT crawlers are enabled by default, while heavier text‑based feeds remain optional and operator‑controlled. |
| 17 | Traffic Analysis & Inspection | Deep packet and flow analysis for live traffic: protocol and application breakdowns, encrypted vs cleartext ratios, unusual ports and methods, inspection verdicts from relevant detection layers, and enforcement summaries so operators can verify that network controls match policy and understand what is being blocked. |
| 18 | DNS & Geo Security | Dedicated surface for DNS and geographic‑risk analytics: DGA and tunneling heuristics, suspicious query patterns, NXDOMAIN and entropy metrics, geo‑IP risk zoning, and how those signals feed blocking, reputation, and trust so defenders can spot command‑and‑control, staging, and reconnaissance activity. This view is enriched by the OSINT crawlers and the local reputation tracker, so repeated bad infrastructure is treated more aggressively over time. |
| 19 | User & Identity Trust Signals | Identity‑centric view of entities the system observes: behavioral risk scores, unusual login and session patterns, device/location changes, Zero‑Trust trust deltas, and how identity signals are influencing execution decisions—explicitly without acting as IAM, lifecycle, or policy administration tooling. |
| 20 | Sandbox Detonation | Overview of file detonation and sandboxing results: how many artifacts have been detonated, verdict classifications, extracted indicators (domains, hashes, behaviors), and how those outcomes inform signatures, reputation, and causal reasoning, all while keeping payload inspection local to the protected environment. |
| 21 | Email/SMS Alerts (Critical Only) | Configuration and runtime status for critical out‑of‑band alerts: which destinations are configured, which events (system failure, kill‑switch changes, integrity breaches) will trigger notifications, recent send history, and failure diagnostics—positioned as a narrow safety‑of‑operation channel rather than a full alerting platform. |
| 22 | Cryptocurrency Mining Detection | Specialized analytics for crypto‑mining behavior: detection of mining pools and protocols, anomalous resource usage and long‑lived connections, associated entities and campaigns, and enforcement outcomes so operators can quickly confirm that mining activity is being identified and constrained. Mining detections are strengthened by OSINT feeds and the persistent reputation tracker, which remember and escalate repeat abuse from the same entities. |
| 23 | Governance & Emergency Controls | Command surface for high‑assurance governance: current kill‑switch mode and approval workflow, pending and historical decisions in the approval queue, policy governance and Step 21 policy bundle status, secure‑deployment/tamper health, and audit/log integrity so operators can safely move between observe, approval, and fully autonomous deny modes. |
| 24 | Forensics Export for Offline Hunting | Read‑only export surface for JSON/HTML enterprise reports and curated PCAP‑based hunting material generated by the first‑layer engine, supporting offline analysis and compliance reporting without introducing new detection logic or network‑facing attack surface. |

An additional **Enterprise Security Integrations** view provides configuration and status for outbound adapters that stream first‑layer decisions into SIEM, SOAR, and IT‑operations platforms. This integrations surface focuses on visibility and coordination only; primary blocking remains on the local firewall enforcement plane.

##### Example: Minimal `enterprise_integration.json`

Battle-Hardened AI resolves an `enterprise_integration.json` file from its JSON configuration directory (see `AI/path_helper.py` and `documentation/Dashboard.md` for directory details). A minimal, realistic example looks like this:

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
4. **Firewall sync** – On Windows, the `server/windows-firewall/configure_bh_windows_firewall.ps1` script (typically invoked by Task Scheduler with `-SkipBaselineRules` and an explicit `-JsonPath`) reads `blocked_ips.json` and updates the "Battle-Hardened AI Blocked IPs" rule. On Linux, iptables/ipset are updated via the server’s enforcement layer.
5. **Operator view** – The dashboard surfaces the same decision and context in Sections 5 (Security Overview), 7 (IP Management), 14 (Decision Explainability), and 23 (Governance & Emergency Controls).

This model keeps enforcement local to the OS firewalls, with the AI engine responsible for making high-quality, explainable allow/block decisions and exporting them in a machine-consumable form.

#### Troubleshooting & Operational Scenarios (Quick Reference)

- **Step 21 seems too aggressive (false positives):** Use the Governance & Emergency Controls section (23) to move from fully autonomous deny into observe or approval modes, then adjust the Step 21 policy bundle under `policies/step21` (for example, HTTP method and trust-threshold settings) and reload. For detailed guidance, see `documentation/Architecture_compliance.md` and `documentation/Attack_handling_flow.md`.
- **Relay/central training status is unhealthy:** Check Section 1 on the dashboard and the `/api/relay/status` endpoint for detailed error messages (DNS, TLS, authentication). Verify relay settings in the environment or `.env.windows` (for EXE deployments), and ensure outbound firewall rules permit the configured relay URL/port.
- **Blocked IPs are not reflected in Windows Firewall:** Confirm that `blocked_ips.json` is being updated in the runtime JSON directory (for EXE builds this is under `%LOCALAPPDATA%/Battle-Hardened AI/server/json`), and that Task Scheduler is invoking `server/windows-firewall/configure_bh_windows_firewall.ps1` with `-SkipBaselineRules` and the correct `-JsonPath`. See `documentation/Firewall_enforcement.md` for examples.
- **Dashboard shows data but enforcement appears inactive:** On Linux, verify iptables/ipset rules were created and are still present; on Windows, inspect the "Battle-Hardened AI Blocked IPs" rule and ensure no third-party software has overridden it. In both cases, check the watchdog/service status and the Security Overview (Section 5) for recent block events.
- **General startup and health issues:** Follow the `documentation/Startup_guide.md` and `documentation/Installation.md` checklists, paying special attention to permissions, NIC binding, and JSON directory configuration. The System Health & Network Performance section (11) is the primary runtime surface for spotting resource and integrity problems.

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

- [Filepurpose](documentation/Filepurpose.md) — Maps every core file and JSON surface to the 7-stage pipeline and 21 detection layers
- [AI instructions](documentation/Ai-instructions.md) — Developer implementation guide, validation flow, and dashboard/endpoint mapping
- [Dashboard](documentation/Dashboard.md) — Dashboard and API reference tied directly to pipeline stages and JSON surfaces
- [Architecture compliance verification](documentation/Architecture_compliance.md) — Formal proof that runtime code paths implement the documented log → block → relay architecture
- [Attack handling flow](documentation/Attack_handling_flow.md) — End-to-end attack handling, from honeypot and network monitoring through pcs_ai, firewall, and relay

These documents collectively define the system’s intended behavior, guarantees, and constraints.

If you're starting from source as a developer or auditor, begin with [Filepurpose](documentation/Filepurpose.md); it is the canonical map for the AI/, server/, and relay/ components.

### Key Terms (For Non-Specialists)

- **eBPF/XDP:** Linux kernel technologies that let the system observe and filter packets directly in the OS with very low overhead.
- **PCAP:** Packet capture format used to record raw network traffic for analysis and replay in lab testing.
- **LSTM:** A type of recurrent neural network specialized for understanding sequences over time (for example, multi-step attack campaigns).
- **Autoencoder:** An unsupervised neural network used here to spot "never-seen-before" traffic patterns and potential zero-day attacks.
- **MITRE ATT&CK:** A community-maintained catalog of real-world attacker tactics and techniques; this README maps coverage against those techniques.

### Deployment Scope — What Can Be Protected

Battle-Hardened AI is built as a **first-layer decision authority** designed to operate in a **gateway or router role**—strategically positioned to decide which interactions are permitted to produce operational effects before downstream systems are even touched. It may also be deployed in **host-only** or **observer** mode when direct inline placement isn’t possible.

#### Deployment Modes and Coverage

##### 🏠 Home & Small Office Networks

- As a gateway node (for example, a Linux box or dedicated appliance between modem and LAN), Battle-Hardened AI protects the **entire network** behind it.
- In host-only mode on Windows or macOS, Battle-Hardened AI secures that individual host and any mirrored traffic explicitly routed through it.

##### 🏢 Enterprise Networks

- Positioned at the LAN/VLAN/VPN edge or attached to a SPAN/mirror port, Battle-Hardened AI provides execution control at the boundary (north–south) and can observe lateral (east–west) traffic when mirrored.
- Deployed as a SOC sensor, it delivers deep threat visibility without requiring routing changes.

##### 🖥 Servers, Data Centers & Application Stacks

- Installed directly on reverse proxies or appliance nodes, Battle-Hardened AI governs first-layer execution control for inbound connections to mission-critical workloads and services.

##### 🌐 Websites & APIs

- Deployed in front of web servers or API gateways, Battle-Hardened AI filters inbound HTTP(S) traffic semantically before application stacks process it, working alongside WAFs—not as a replacement.

##### ☁️ Cloud Infrastructure (IaaS / PaaS)

- Operates as a sidecar or inline observer within cloud deployments, with access to VPC/VNet flows, load balancers, or telemetry, allowing pre-execution enforcement for exposed cloud services.

##### 🏭 OT, Critical Infrastructure & R&D Environments

- Deployed as a non-intrusive observer or segment gateway, Battle-Hardened AI enforces semantic denial without inserting agents into sensitive ICS/SCADA/lab equipment.

##### ⚖️ Government, Defense & Regulated SOCs

- As a semantic command node in front of classified or sovereign environments, Battle-Hardened AI enforces execution control while maintaining strict data privacy and sovereignty.

#### Placement Determines Authority

| Placement Type | Visibility & Authority |
|----------------|------------------------|
| Gateway (primary) | Full control of inbound/outbound traffic; pre-execution enforcement |
| Host-level | Protection scoped to local host services (for example, SSH, RDP, HTTP) |
| Observer | High-fidelity telemetry; enforcement via connected firewall/router |

For true control, Battle-Hardened AI must sit at a routing, NAT, or firewall decision point—either as a bridge, gateway, or authoritative observer wired into enforcement APIs.

#### Enforcement Requires Firewall Integration

To make deny decisions real, Battle-Hardened AI must be connected to the underlying firewall. **Before any production rollout, review [documentation/Firewall_enforcement.md](documentation/Firewall_enforcement.md) end-to-end.** On Linux, this typically involves `ipset`/`iptables`; on Windows, it wires into Windows Defender Firewall via PowerShell.

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

See [documentation/Installation.md](documentation/Installation.md), [Windows-testing-checklist.md](documentation/Windows-testing-checklist.md), and [Startup guide](documentation/Startup_guide.md) for detailed setup instructions. For production firewall synchronization, see [documentation/Firewall_enforcement.md](documentation/Firewall_enforcement.md).

---

## Competitive Positioning vs NDR/XDR Platforms

This section brings together two complementary views:
- An **architecture-level comparison** of Battle-Hardened AI vs commercial NDR/XDR platforms (how the systems are built).
- An **operational and scoring comparison** based on the ensemble example and competitive tables (how decisions behave in practice).

## Battle-Hardened AI vs Commercial NDR/XDR Platforms (Architecture-Level Comparison)

#### Positioning Statement (Critical)

**Battle-Hardened AI is not positioned as “better detection” or “higher accuracy.”**  
**It is positioned as a first-layer autonomous execution-denial system — a fundamentally different defensive control class.**

Most commercial NDR/XDR platforms are **event-driven correlation engines**. They observe activity, correlate events, and surface alerts for downstream investigation.

Battle-Hardened AI is a **stateful autonomous defense system** that reasons about cause, remembers adversaries across time, degrades trust persistently, and determines whether interactions are allowed to have any operational meaning at all.

**This distinction is architectural, not incremental.**

**Battle-Hardened AI emits decisions and evidence; it does not orchestrate response.** External systems (ticketing, SIEM, SOAR, or custom automation) may consume its JSON outputs, but orchestration is deliberately kept outside this first-layer control.

---

#### 1. Detection Architecture: Reasoning vs Correlation

Commercial NDR/XDR platforms are built around **telemetry aggregation and correlation pipelines**. Events are ingested, normalized, scored, and surfaced as alerts. Detection logic is primarily reactive, and decision state is largely session-bound or time-decayed.

Battle-Hardened AI uses a **multi-engine, stateful consensus architecture**. Detection is not driven by isolated alerts, but by independent signal engines voting over time, with each decision updating persistent system state.

**This means:**
- Detection state does not reset between sessions
- Signals can contradict each other and still be resolved coherently
- The system accumulates understanding, not just alerts

**This is why Battle-Hardened AI does not use “alert volume” as a success metric.**

---

#### 2. Independent Detection Layers (Why 21 Matters)

Battle-Hardened AI explicitly documents **21 detection layers**: **20 independent detection signal classes plus a Step 21 semantic execution-denial gate**.

Each detection class has:
- A defined purpose
- Known failure modes
- Explicit confidence behavior
- Participation in consensus rather than unilateral triggering

This is rare not because other vendors cannot build more signals, but because:
- Most vendors do not disclose how many detection classes exist
- Signal boundaries are intentionally opaque
- Multiple detections are often re-labelings of the same underlying logic

The claim is not **“more signals = better.”**  
The claim is **signal independence, transparency, and a final semantic safety gate governing execution authority**.

If a system cannot enumerate its detection classes publicly, it cannot be independently validated.

For a true **first-layer** defensive system, these 21 layers matter because:
- **Redundancy** – even if several signal classes misclassify or are bypassed, many others (plus the Step 21 semantic gate) still protect the system
- **No single point of failure** – there is no “one magic algorithm” to evade; attackers must simultaneously defeat diverse, independent detectors and the final semantic gate
- **Semantic validation** – Layer 21 does not care only about syntax or signatures; it asks whether the requested operation makes sense at all in context
- **Zero‑trust enforcement** – Layer 20 ensures that past behavior and trust degradation directly modulate current execution thresholds

---

#### 3. Kernel Telemetry as a First-Class Input

Battle-Hardened AI treats **kernel-level telemetry (eBPF) as a first-class signal source**.

Kernel telemetry is:
- Consumed directly by reasoning layers
- Retained as part of persistent entity memory
- Used to validate or falsify higher-level signals

In most commercial platforms, kernel telemetry (if present) is:
- Abstracted
- Heavily filtered
- Reduced to events before reasoning occurs

**The difference is not access — it is architectural importance.**

---

#### 4. Causal Inference (Layer 19): Understanding Why

Battle-Hardened AI includes an **explicit causal reasoning layer** that evaluates **why** anomalies occur.

This layer:
- Distinguishes attacks from legitimate deployments
- Resolves contradictory signals
- Prevents benign operational changes from triggering destructive responses

Most commercial NDR/XDR systems perform **correlation, not causation**.  
They can identify **what happened together**, but not **why it happened**.

This is why false positives in commercial systems often require analyst interpretation, while Battle-Hardened AI can self-correct.

---

#### 5. Persistent Trust Memory (Layer 20)

Battle-Hardened AI models **trust as a persistent, first-class security variable**.

Trust:
- Degrades based on observed behavior
- Persists across sessions, reboots, and time gaps
- Modulates all future decisions

This differs fundamentally from:
- Reputation feeds
- Time-decayed anomaly scores
- Session-bound confidence levels

**Attackers exploit forgetting.**  
**Battle-Hardened AI is explicitly designed not to forget.**

---

#### 6. Explainability at the Decision Level

Battle-Hardened AI produces **full decision traces**, including:
- Which signals fired
- How confidence evolved
- How trust changed
- Why an action was taken or withheld

Most platforms expose:
- Alerts
- Scores
- Storylines

Those are **summaries**, not explanations.

Explainability in Battle-Hardened AI exists at the **reasoning layer**, not as a UI afterthought.

---

#### 7. Explicit Failure Awareness

Battle-Hardened AI treats **failure as a modeled system state**.

False positives, uncertainty, and ambiguity:
- Are explicitly represented
- Influence trust over time
- Feed back into learning and future decisions

Commercial systems generally suppress or hide failure because their architectures do not expose internal reasoning states.

Here, **transparency increases credibility rather than risk**.

---

#### 8. Learning, Adaptation, and Deception Feedback

Battle-Hardened AI supports:
- Local learning
- Optional federated learning
- Persistent post-compromise adaptation
- Deception outcomes as first-class signals

Most commercial NDR/XDR platforms:
- Learn primarily in the cloud
- Reset locally after incidents
- Treat deception as an external or optional module

This makes Battle-Hardened AI resistant to iterative probing and slow APT-style campaigns.

---

#### 9. SOC Dependency vs First-Layer Autonomy

Battle-Hardened AI is designed to:
- Operate autonomously
- Take defensive action without constant analyst approval
- Function in constrained or offline environments

Commercial NDR/XDR platforms are architecturally dependent on:
- SOC workflows
- Human validation
- Continuous cloud interaction

As a **first-layer system**, Battle-Hardened AI reduces downstream alert volume and analyst workload rather than replacing SOC tooling.

Autonomy here is not optional — it is foundational.

---

#### First-Layer vs Everything Else: Architectural Clarity

At a high level, Battle-Hardened AI operates at the **execution gate**, deciding whether interactions should be allowed at all, while most other platforms act **after** state has already changed. The table below summarizes that contrast.

| Category | First-layer systems | Downstream systems |
|----------|---------------------|--------------------|
| Primary question | "Should this be allowed to execute?" | "What just happened, and how do we respond?" |
| Decision timing | Before any state change | After state has already changed |
| Failure concern | False negatives (allowing malicious execution) | False positives (alert fatigue) |
| Data use | Patterns, signals, semantic structure | Payloads, logs, full forensic visibility |
| Integration point | Stack entry point (execution gate) | Aggregation, logging, or correlation layer |
| Core benefit | Block impact before it starts | Understand and recover after the fact |

Battle-Hardened AI is not another alerting layer—it is a **stateful, autonomous, semantic gatekeeper** where concepts like persistent trust memory, causal reasoning, and execution semantics are foundational design elements, not add-on features.

#### Interpretation Legend

- **ND** = Not publicly documented in vendor materials consulted
- **Partial** = Present but undocumented or non-explainable
- **Documented** = Explicit, transparent, and architecturally core

This comparison emphasizes **architectural transparency**, not definitive absence of capabilities in third-party products. "ND" indicates that a property was not clearly described in public documentation at the time of writing, not that the feature is definitively missing.

### Core Detection & Reasoning Capabilities

| Platform | Detection Architecture | Signal Types | Kernel Telemetry | Causal Reasoning | Trust Memory |
|----------|------------------------|-------------|------------------|------------------|-------------|
| **Battle-Hardened AI** | Multi-engine, semantic-first | 21-layer consensus | Documented eBPF | Layer 19 (documented) | Layer 20 (persistent) |
| CrowdStrike Falcon | Correlation pipelines | ND | Partial | ND | ND |
| SentinelOne Singularity | Behavior + rules | ND | Partial | ND | ND |
| Cortex XDR | Data lake correlation | ND | ND | ND | ND |
| Microsoft Defender ATP | Telemetry correlation | ND | Partial | ND | ND |
| Darktrace | Statistical anomaly detection | ND | ND | ND | Partial (decaying) |
| Vectra AI | Behavior + ML scoring | ND | ND | ND | ND |
| ExtraHop | Protocol analytics | ND | ND | ND | ND |
| Cisco Secure NDR | Signature + analytics | ND | ND | ND | ND |
| Trend Micro XDR | Multi-product correlation | ND | Partial | ND | ND |
| Carbon Black | Endpoint behavior monitoring | ND | Partial | ND | ND |
| Fortinet FortiNDR | Heuristics + signatures | ND | ND | ND | ND |
| Stellar Cyber | Open XDR correlation | ND | ND | ND | ND |
| Corelight | Zeek-based analytics | ND | ND | ND | ND |
| Fidelis Network | Session analysis | ND | ND | ND | ND |
| Suricata + ML | Rules + partial ML | Partial | ND | ND | ND |

### Transparency & Analyst Burden

| Platform | Explainability | Decision Trace | Failure Awareness | Analyst Dependency |
|----------|----------------|----------------|-------------------|-------------------|
| **Battle-Hardened AI** | Full and documented | Layer-by-layer trace | Explicit failure states | Optional (autonomous) |
| CrowdStrike Falcon | Limited | Alert-level only | ND | Required |
| SentinelOne | Limited | Storyline abstraction | ND | Required |
| Cortex XDR | Partial | Event chain trace | ND | Required |
| Microsoft Defender | Limited | Alert-level | ND | Required |
| Darktrace | Limited | Anomaly scores | ND | Required |
| Vectra AI | Partial | Score explanations | ND | Required |
| ExtraHop | Partial | Protocol summaries | ND | Required |
| Others | Limited | ND | ND | Required |

### Adaptation & Adversary Resistance

| Platform | Learning Architecture | Attack Feedback Loop | Deception Handling | Self-Defense |
|----------|-----------------------|----------------------|--------------------|-------------|
| **Battle-Hardened AI** | Local + federated optional | Persistent adaptation | Deception as first-class | Trust degradation model |
| NDR/XDR (general) | Primarily cloud-based | ND or session-bound | ND or limited | ND |

*Competitor capabilities are inferred from publicly available documentation and marketing materials. "ND" indicates aspects that are not clearly or explicitly documented and therefore cannot be independently verified.*

See [Positioning Statement](#positioning-statement-critical) and [Why Evasion Is Extremely Hard in Practice](#why-evasion-is-extremely-hard-in-practice) for further architectural insights.

---

## Applicability to Military & Law-Enforcement Environments

After understanding how Battle-Hardened AI operates and how it compares to other platforms, this section focuses on where it can be safely deployed in high-assurance environments.

Battle-Hardened AI is suitable for use in defensive cyber security roles within military and law-enforcement organizations, including:

- Cyber defense research and development (R&D) programs

- Security Operations Centers (SOC) and CERT environments

- National or organizational early-warning and threat-sensing deployments

- Controlled, observer-first monitoring systems with human-in-the-loop governance

The platform is not an offensive system and is not intended for autonomous or weaponized cyber operations.

#### Privacy, Data Sovereignty & Classified Network Safety

**Why Battle-Hardened AI is Safe for Government, Military, Police, Companies, and Home Networks:**

Battle-Hardened AI is explicitly designed for deployment in high-security and classified environments where data privacy, operational security, and regulatory compliance are paramount. The architecture ensures that sensitive organizational data never leaves your network perimeter.

**Zero Access to Customer Data:**

- **No Customer Payload Storage:** The system never retains raw network payloads of legitimate traffic, file contents, email bodies, database records, or application data
- **Attack Forensics Stored Locally:** Full attack details (malicious payloads, URLs, headers) are logged LOCALLY in `threat_log.json` under the JSON directory managed by `AI.path_helper.get_json_dir()` (typically `server/json/` on bare-metal or `/app/json/` in Docker deployments) for forensic analysis—YOU control this data, it never leaves your server
- **Only Patterns Shared to Relay Server:** Attack signatures (keywords, encodings, pattern hashes) are extracted and sent to relay server for global ML training—NO full payloads, NO customer data
- **Metadata Only:** Only statistical traffic features are analyzed (packet sizes, timing, connection patterns, protocol flags)
- **Local Processing:** All detection and analysis occurs entirely on your server infrastructure—nothing is processed externally

**What Gets Shared (Optional Relay Participation):**

If you choose to enable the optional global intelligence relay, only the following **anonymized, sanitized materials** are exchanged:

1. **Attack Signatures** (pattern strings like `' OR 1=1--`, never actual exploit code or victim data)
2. **Behavioral Statistics** (anonymized metrics: average connection rates, port entropy scores, ASN regions—not geolocation)
3. **Reputation Hashes** (SHA-256 hashed attacker IPs, not raw addresses or victim IPs)
4. **Graph Topologies** (anonymized patterns like "A→B→C", not real server names or IP addresses)
5. **ML Model Weight Deltas** (neural network parameter updates, not training data)

**What is NEVER Shared:**
In implementation, raw training datasets and history under the relay's `ai_training_materials/` directory (for example `global_attacks.json`, `learned_signatures.json`, `training_datasets/`) are used **only** by the relay for retraining. Customer nodes talk to the relay's HTTPS training API to download **pre-trained model files and curated signature/reputation/intel bundles**, not the underlying training data.

**What is NEVER Shared:**

- ❌ Customer network traffic or packet payloads
- ❌ Authentication credentials or session tokens
- ❌ File contents, database records, or application data
- ❌ Internal IP addresses, hostnames, or network topology
- ❌ User identities, employee information, or PII
- ❌ Business communications (emails, documents, messages)
- ❌ Proprietary code, trade secrets, or classified information
- ❌ Exploit payloads or weaponized code samples

**Data Sovereignty Guarantees:**

- **Air-Gap Compatible:** Can operate entirely disconnected from the internet—relay participation is completely optional
- **On-Premises Deployment:** All data remains on your infrastructure; no cloud dependencies for core detection functionality
- **Local-First Architecture:** Detection, blocking, logging, and AI training occur entirely within your security perimeter
- **No Third-Party Services Required:** Operates independently; external threat intelligence feeds (VirusTotal, AbuseIPDB) are optional enhancements
- **Full Data Control:** You own all logs, threat data, and ML models—nothing is held by external parties

**Compliance & Auditability:**

- **Regulatory Compliance:** Designed to support PCI-DSS, HIPAA, GDPR, SOC 2, and government security frameworks
- **Full Transparency:** All AI decisions include human-readable explanations (Explainability Engine)
- **Audit Trails:** Complete forensic logging of all detections, blocks, and system actions
- **Reversible Actions:** All automated responses are logged and can be reversed or overridden
- **Cryptographic Lineage:** Model provenance tracking ensures AI training integrity and prevents poisoning attacks

**Perfect for Classified & Sensitive Networks:**

Battle-Hardened AI's privacy-preserving design makes it suitable for:

- **Military networks** (SIPRNET-equivalent security posture)
- **Law enforcement** (criminal investigation data protection)
- **Intelligence agencies** (signals intelligence / SIGINT protection)
- **Critical infrastructure** (SCADA/ICS operational security)
- **Healthcare systems** (HIPAA-protected patient data)
- **Financial institutions** (PCI-DSS cardholder data environments)
- **Government agencies** (classified network defense)
- **Enterprise R&D** (trade secret and IP protection)

The operator (relay server administrator) has **zero visibility** into your network traffic, internal operations, or business activities. The relay only aggregates anonymized threat intelligence—similar to how antivirus vendors share malware signatures without seeing what files you scan.

---

## MITRE ATT&CK Coverage Matrix

Building on the execution-control and competitive sections above, this matrix shows where Battle-Hardened AI’s detection layers and semantic execution-denial gate align with the MITRE ATT&CK framework.

**Total MITRE ATT&CK Techniques Covered: 43 distinct techniques** (credibly mapped, no inflation)

### Coverage Summary by Tactic

| MITRE Tactic | Technique Count | Techniques Covered | Primary Detection Signals |
|--------------|----------------|-------------------|---------------------------|
| **TA0043 - Reconnaissance** | 4 | T1595 (Active Scanning), T1590 (Gather Victim Network Info), T1046 (Network Service Discovery), T1018 (Remote System Discovery) | #6 Behavioral, #10 Graph, #1 Kernel, #7 LSTM |
| **TA0001 - Initial Access** | 5 | T1190 (Exploit Public-Facing Application), T1133 (External Remote Services), T1078 (Valid Accounts), T1566 (Phishing), T1204 (User Execution) | #2 Signatures, #8 Autoencoder, #12 Threat Intel, #16 Predictive |
| **TA0006 - Credential Access** | 3 | T1110 (Brute Force), T1110.003 (Password Spraying), T1078 (Valid Accounts) | #6 Behavioral, #7 LSTM, #14 Reputation |
| **TA0008 - Lateral Movement** | 6 | T1021 (Remote Services), T1021.002 (SMB/Windows Admin Shares), T1021.004 (SSH), T1080 (Taint Shared Content), T1210 (Exploitation of Remote Services), T1570 (Lateral Tool Transfer) | #10 Graph, #1 Kernel, #7 LSTM, #20 Trust |
| **TA0007 - Discovery** | 1 | T1018 (Remote System Discovery) | #6 Behavioral, #19 Causal, #20 Trust |
| **TA0011 - Command & Control** | 9 | T1071 (Application Layer Protocol), T1095 (Non-Application Layer Protocol), T1041 (Exfiltration Over C2), T1568 (Dynamic Resolution), T1090 (Proxy), T1090.003 (Multi-hop Proxy), T1079 (Multilayer Encryption), T1108 (Redundant Access), T1102 (Web Service) | #10 Graph, #8 Autoencoder, #12 Threat Intel, #11 VPN/Tor |
| **TA0009 - Collection** | 1 | T1213 (Data from Information Repositories) | #6 Behavioral, #19 Causal |
| **TA0010 - Exfiltration** | 2 | T1041 (Exfiltration Over C2 Channel), T1048 (Exfiltration Over Alternative Protocol) | #10 Graph, #6 Behavioral, #8 Autoencoder |
| **TA0040 - Impact** | 3 | T1485 (Data Destruction), T1486 (Data Encrypted for Impact), T1491 (Defacement) | #8 Autoencoder, #19 Causal, #18 Integrity |
| **TA0003 - Persistence** | 1 | T1505 (Server Software Component) | #1 Kernel, #2 Signatures, #18 Integrity |
| **TA0004 - Privilege Escalation** | 2 | T1055 (Process Injection), T1068 (Exploitation for Privilege Escalation) | #1 Kernel, #8 Autoencoder |
| **TA0005 - Defense Evasion** | 2 | T1070 (Indicator Removal), T1562 (Impair Defenses) | #9 Drift, #18 Integrity, #1 Kernel |
| **TA0002 - Execution** | 1 | T1059 (Command and Scripting Interpreter) | #2 Signatures, #7 LSTM, #8 Autoencoder |
| **TA0042 - Resource Development** | 3 | T1583 (Acquire Infrastructure), T1584 (Compromise Infrastructure), T1608 (Stage Capabilities) | #5 Gradient Boost, #12 Threat Intel, #14 Reputation |
| **TA0015 - Supply Chain Compromise** | 3 | T1195 (Supply Chain Compromise), T1199 (Trusted Relationship), T1565 (Data Manipulation) | #17 Byzantine, #18 Integrity |
| **Cross-Cutting Semantic Gating** | N/A | Execution / Privilege Escalation / Impact techniques blocked pre-execution by semantic gate | Step 21 Semantic Execution-Denial Gate |
| **TOTAL** | **43** | **43 distinct MITRE ATT&CK techniques** | **21 detection layers (20 signals + Step 21 semantic gate)** |

### Why 43 Techniques is a Strong, Credible Number

Each of the **43 techniques** in the matrix is:
- Mapped to at least one concrete detection layer
- Counted once (no sub-technique inflation)
- Backed by an auditable detection method

In other words, this is a **technical coverage statement**, not a marketing number.

**Battle-Hardened AI defensibly covers 43 MITRE ATT&CK techniques using its documented detection layers and semantic gate.**

### Per-Technique MITRE ATT&CK Breakdown (43 Techniques)

Below is an auditor-style mapping from each MITRE technique to the **primary Battle-Hardened AI layers** that detect or constrain it.

#### TA0043 – Reconnaissance

- **T1595 – Active Scanning** – Layers: #6 Behavioral, #10 Graph, #1 Kernel, #7 LSTM.
- **T1590 – Gather Victim Network Info** – Layers: #6 Behavioral, #19 Causal, #20 Trust.
- **T1046 – Network Service Discovery** – Layers: #1 Kernel, #6 Behavioral, #3 RandomForest, #4 IsolationForest.
- **T1018 – Remote System Discovery** – Layers: #10 Graph, #7 LSTM, #19 Causal.

#### TA0001 – Initial Access

- **T1190 – Exploit Public-Facing Application** – Layers: #2 Signatures, #8 Autoencoder, #4 IsolationForest, #1 Kernel, Step 21.
- **T1133 – External Remote Services** – Layers: #6 Behavioral, #10 Graph, #11 VPN/Tor, #12 Threat Intel, #14 Reputation, #20 Trust.
- **T1078 – Valid Accounts** – Layers: #6 Behavioral, #7 LSTM, #14 Reputation, #20 Trust, Step 21.
- **T1566 – Phishing** – Layers: #2 Signatures, #8 Autoencoder, #16 Predictive, #12 Threat Intel, #14 Reputation.
- **T1204 – User Execution** – Layers: #8 Autoencoder, #4 IsolationForest, #19 Causal, Step 21.

#### TA0006 – Credential Access

- **T1110 – Brute Force** – Layers: #6 Behavioral, #7 LSTM, #14 Reputation, #13 FP Filter.
- **T1110.003 – Password Spraying** – Layers: #10 Graph, #6 Behavioral, #7 LSTM, #19 Causal, #20 Trust.
- **T1078 – Valid Accounts (Reuse)** – Layers: #6 Behavioral, #7 LSTM, #14 Reputation, #20 Trust, Step 21.

#### TA0008 – Lateral Movement

- **T1021 – Remote Services** – Layers: #1 Kernel, #10 Graph, #7 LSTM, #20 Trust.
- **T1021.002 – SMB/Windows Admin Shares** – Layers: #1 Kernel, #10 Graph, #18 Integrity, #6 Behavioral.
- **T1021.004 – SSH** – Layers: #10 Graph, #11 VPN/Tor, #6 Behavioral, #14 Reputation, #20 Trust.
- **T1080 – Taint Shared Content** – Layers: #18 Integrity, #10 Graph, #6 Behavioral.
- **T1210 – Exploitation of Remote Services** – Layers: #2 Signatures, #1 Kernel, #8 Autoencoder, #19 Causal, Step 21.
- **T1570 – Lateral Tool Transfer** – Layers: #1 Kernel, #10 Graph, #8 Autoencoder, #20 Trust.

#### TA0007 – Discovery

- **T1018 – Remote System Discovery** – Layers: #6 Behavioral, #19 Causal, #20 Trust.

#### TA0011 – Command & Control

- **T1071 – Application Layer Protocol** – Layers: #10 Graph, #8 Autoencoder, #3 RandomForest/#4 IsolationForest, #11 VPN/Tor, #12 Threat Intel.
- **T1095 – Non-Application Layer Protocol** – Layers: #1 Kernel, #10 Graph, #8 Autoencoder.
- **T1041 – Exfiltration Over C2** – Layers: #10 Graph, #6 Behavioral, #8 Autoencoder.
- **T1568 – Dynamic Resolution** – Layers: #10 Graph, #12 Threat Intel, #19 Causal.
- **T1090 – Proxy** – Layers: #11 VPN/Tor, #6 Behavioral, #14 Reputation, #10 Graph.
- **T1090.003 – Multi-hop Proxy** – Layers: #10 Graph, #20 Trust.
- **T1079 – Multilayer Encryption** – Layers: #8 Autoencoder, #1 Kernel.
- **T1108 – Redundant Access** – Layers: #10 Graph, #20 Trust, #19 Causal.
- **T1102 – Web Service** – Layers: #2 Signatures, #10 Graph, #12 Threat Intel, #14 Reputation.

#### TA0009 – Collection

- **T1213 – Data from Information Repositories** – Layers: #6 Behavioral, #19 Causal, #10 Graph, #20 Trust.

#### TA0010 – Exfiltration

- **T1048 – Exfiltration Over Alternative Protocol** – Layers: #10 Graph, #8 Autoencoder, #6 Behavioral.
- **T1041 – Exfiltration Over C2 Channel** – Layers: #10 Graph, #6 Behavioral, #8 Autoencoder (same C2 path, higher data volume).

#### TA0040 – Impact

- **T1485 – Data Destruction** – Layers: #1 Kernel, #18 Integrity, #9 Drift, #19 Causal.
- **T1486 – Data Encrypted for Impact** – Layers: #1 Kernel, #18 Integrity, #8 Autoencoder.
- **T1491 – Defacement** – Layers: #18 Integrity, #1 Kernel, #10 Graph, #6 Behavioral.

#### TA0003 – Persistence

- **T1505 – Server Software Component** – Layers: #18 Integrity, #2 Signatures, #17 Byzantine, Cryptographic Lineage.

#### TA0004 – Privilege Escalation

- **T1055 – Process Injection** – Layers: #1 Kernel, #8 Autoencoder, #19 Causal.
- **T1068 – Exploitation for Privilege Escalation** – Layers: #2/#3/#4/#8 traffic detection, #1 Kernel, #20 Trust.

#### TA0005 – Defense Evasion

- **T1070 – Indicator Removal** – Layers: #18 Integrity, #9 Drift, #1 Kernel, Cryptographic Lineage.
- **T1562 – Impair Defenses** – Layers: #18 Integrity, #9 Drift, #19 Causal.

#### TA0002 – Execution

- **T1059 – Command and Scripting Interpreter** – Layers: #2 Signatures, #8 Autoencoder, #1 Kernel, #7 LSTM, #19 Causal, Step 21.

#### TA0042 – Resource Development

- **T1583 – Acquire Infrastructure** – Layers: #5/#14 Reputation, #12 Threat Intel.
- **T1584 – Compromise Infrastructure** – Layers: #12 Threat Intel, #14 Reputation, #10 Graph.
- **T1608 – Stage Capabilities** – Layers: #8 Autoencoder, #2 Signatures, #14 Reputation.

#### TA0015 – Supply Chain Compromise

- **T1195 – Supply Chain Compromise** – Layers: #17 Byzantine, #18 Integrity, Cryptographic Lineage.
- **T1199 – Trusted Relationship** – Layers: #10 Graph, #20 Trust, #6 Behavioral.
- **T1565 – Data Manipulation** – Layers: #18 Integrity, Cryptographic Lineage, #9 Drift, #19 Causal.

---

## Deployment Model

Battle-Hardened AI adopts a **single-node-per-network architecture**. Each protected network segment typically requires only one Battle-Hardened AI server, eliminating the need for endpoint agents while still providing comprehensive, network-wide visibility and control.

An optional private relay allows these nodes to share anonymized AI training insights—such as signatures, behavioral patterns, and reputation updates—without exposing sensitive data. This federated learning approach supports global intelligence gains while maintaining strong data sovereignty.

## 🛡️ Security & Compliance

Battle-Hardened AI is designed for high-assurance environments and aligns with modern security and governance expectations:

- **Zero Trust Architecture principles (NIST 800-207):** Treats every entity as untrusted by default, using persistent trust scores and semantic checks before allowing execution.
- **Federated learning privacy isolation:** Shares only anonymized patterns and model updates; no PII or raw payloads are transmitted, even when the relay is enabled.
- **Edge-enforceable policies without central dependency:** Enforcement decisions run locally at the gateway or host, so execution control does not rely on cloud services or centralized orchestrators.
- **Optional relay for multi-organization intelligence fusion:** The relay augments local detection with global intelligence without compromising data sovereignty or regulatory boundaries.
- **Compliance-ready posture:** Designed to support HIPAA, FedRAMP, ISO 27001, PCI-DSS, and similar frameworks by providing explainable decisions, audit trails, and clear separation of duties between detection, enforcement, and orchestration.

## 21 Detection Layers: Core AI Capabilities

Battle-Hardened AI employs **21 layered detection engines**—20 independent signals and a final semantic execution-denial gate. They operate in parallel and are fused via weighted ensemble logic to maximize accuracy and resilience.

- **Layers 1–18:** Primary detection signals derived from traffic, system telemetry, and threat intelligence.
- **Layers 19–20:** Strategic intelligence layers that handle intent, causality, and long-term trust memory.
- **Layer 21:** A semantic execution gate that finalizes enforcement decisions based on structural, contextual, and trust criteria.

| # | Signal | Description |
|---|--------|-------------|
| 1 | eBPF Kernel Telemetry | Low-level syscall and network visibility with userland correlation |
| 2 | Signature Matching | Deterministic detection using known exploit patterns |
| 3 | RandomForest | Supervised classifier for threat categorization |
| 4 | IsolationForest | Unsupervised anomaly detection for high-dimensional outliers |
| 5 | Gradient Boosting | Long-term reputation modeling |
| 6 | Behavioral Heuristics | Statistical and behavioral risk scoring |
| 7 | LSTM | Sequential modeling of kill-chain progression |
| 8 | Autoencoder | Zero-day detection via unsupervised reconstruction error |
| 9 | Drift Detection | ML model health monitoring and retraining triggers |
| 10 | Graph Intelligence | Lateral movement, pivot detection, and communication mapping |
| 11 | VPN/Tor Fingerprinting | Obfuscation and anonymization detection |
| 12 | Threat Intelligence Feeds | OSINT and enterprise threat feed correlation |
| 13 | False Positive Filter | Multi-layer pre-confirmation before alerts influence actions |
| 14 | Historical Reputation | Long-lived actor profiling based on cumulative behaviors |
| 15 | Explainability Engine | Transparent confidence-weighted ensemble summaries |
| 16 | Predictive Modeling | Short-horizon behavioral forecasting |
| 17 | Byzantine Defense | Distributed consensus and model poisoning protection |
| 18 | Integrity Monitoring | Detection-stack and telemetry-path tamper alerts |
| 19 | Causal Inference Engine | Root-cause derivation across signals and state transitions |
| 20 | Trust Degradation Graph | Persistent entity trust memory for long-term enforcement |
| 21 | Step 21 Semantic Gate | Final gate enforcing policy, intent, trust, and structural validity |

Each layer produces a distinct signal. These are combined in the ensemble and then finalized by Step 21 to avoid single-point model failure and provide diverse detection redundancy.

### Future Enhancements: Step 21 Policy Hardening

Planned updates include:

- Configurable, path-based endpoint rules for `network_request` semantics
- Externalized policy configuration files for structured semantic enforcement

These improvements will strengthen Step 21’s enforcement precision without introducing fragile allow-lists.

## Why Evasion Is Extremely Hard in Practice

Battle-Hardened AI implements true **defense-in-depth** by combining:

- 20 parallel detection layers
- A semantic execution gate
- Persistent trust memory
- Causal inference and anomaly modeling

Evasion requires an attacker to consistently avoid, mislead, or neutralize these mechanisms **in combination**, across time and campaigns. This dramatically raises the cost of reliable evasion beyond what most real-world adversaries will invest against a single target, even though no system can claim absolute impossibility.

### Detection Redundancy Examples

- **Port scans:** Detected by heuristic rates, kernel telemetry, and graph topology
- **Exploit attempts:** Caught by signature matching, anomaly detection, and sequential analysis
- **Lateral movement:** Identified via graph transitions, connection patterns, and reputation scoring
- **Anonymous attacks:** Defeated by VPN/Tor detection and cross-session behavioral fingerprinting

### Persistent Detection via Cross-Session Memory

- Long-term actor profiling
- Recidivism detection and escalating risk
- Detection memory cannot be reset by IP rotation or simple stealth tactics

### Protection Against Zero-Days

- Autoencoder flags structural outliers
- No dependency on signatures
- Works out of the box for novel exploits

### LSTM-Driven Attack Progression Analysis

- Models multi-stage campaigns (recon → exploit → lateral → exfiltration)
- Detects even slow or evasive campaigns

### Final Defense: Trust and Causality

- **Layer 19:** Causal graphs detect misaligned timing and synthetic deployment noise
- **Layer 20:** Trust scores degrade irreversibly; multiple attempts compound risk

Attackers must avoid all of the following simultaneously:

- Signature matches (3,000+ known payloads from curated public/relay-derived signatures)
- Behavioral anomalies (15 tracked metrics)
- Autoencoder outliers
- Temporal drift
- Graph transitions
- Detection memory

This architecture makes Battle-Hardened AI extremely difficult to circumvent while remaining resilient and adaptable across environments.

---

## 🧠 Federated AI Training & Relay Architecture

### End-to-End Threat Detection and Response Pipeline

Battle-Hardened AI continuously monitors the network by processing every packet and event through a high-fidelity, multi-layered threat detection and response pipeline. This section outlines each stage of the data flow—from raw packet capture to federated learning and global signature propagation.

#### Stage 1: Ingestion & Preprocessing

**Sources:**

- **Network traffic:** Captured via eBPF/XDP, supporting TCP/UDP/ICMP, HTTP, DNS, and TLS.
- **System logs:** Authentication logs, system events, application logs.
- **Cloud APIs:** AWS, Azure, GCP logs tracking IAM, security, and configuration drift.
- **Active scans:** Device discovery, port scans, and service fingerprinting.

**Processing:**

- Parse headers and extract metadata (IP, ports, timestamps, protocols).
- Normalize across protocols into a unified schema.
- Remove payloads; retain only structural and statistical features.

**Normalized output sample:**

```json
{
  "src_ip": "203.0.113.42",
  "dst_ip": "198.51.100.10",
  "src_port": 54321,
  "dst_port": 443,
  "protocol": "TCP",
  "timestamp": "2026-01-07T10:32:15Z",
  "http_method": "POST",
  "http_path": "/login.php",
  "packet_size": 1420
}
```

#### Stage 2: Multi-Signal Parallel Analysis

All normalized events are sent to `assess_threat(event)`, which triggers all 20 detection systems simultaneously. Each signal emits a structured output object with threat confidence, context, and supporting evidence. Highlighted examples:

- **Layer 1:** eBPF syscall/network correlation
- **Layer 2:** Pattern matching for 3,000+ exploits *(current lab signature set; grows via relay)*
- **Layers 3–5:** RandomForest, IsolationForest, Gradient Boosting ML models
- **Layer 6:** Behavioral heuristics (rate, fan-out, entropy)
- **Layer 7:** LSTM modeling multi-stage attacks
- **Layer 8:** Autoencoder-based zero-day anomaly detection
- **Layer 10:** Graph analysis for lateral movement
- **Layer 12:** OSINT and threat feed correlation
- **Layer 14:** Persistent reputation tracking
- **Layer 19:** Causal inference engine for intent analysis
- **Layer 20:** Trust degradation model for long-term risk memory

Each layer produces independent `DetectionSignal` objects with fields such as:

```json
{
  "is_threat": true,
  "confidence": 0.94,
  "signal": "lateral_movement",
  "details": "3-hop pivot chain within 5 minutes"
}
```

These are passed through a 5-gate false-positive validator and then forwarded to the ensemble engine.

#### Step 21: Semantic Execution Denial Gate

The final semantic gate prevents unauthorized or unsafe execution even after ensemble approval.

**Enforcement dimensions:**

- **State validity:** Blocks illogical actions (for example, delete before create).
- **Intent validation:** Prevents role-based misuse (for example, non-admin writing to admin fields).
- **Structural integrity:** Validates payloads against schema and encoding expectations.
- **Trust score check:** Entity must meet trust thresholds for the intended action.

If any dimension fails, execution is silently denied—no state changes occur, but full logs are retained for learning and audit.

**Concrete example – HTTP request gate** (simplified, aligned with `policies/step21/policy.json`):

- **Role:** `network_entity`
- **Action:** `network_request`
- **Allowed methods:** `GET`, `POST`
- **Endpoint constraints:** Normalized path, length ≤ 200 characters, no control characters
- **Minimum trust score:** 40.0

Example outcomes:

- `GET /api/status` from a client with trust score 72.5 → **Allowed** (well-formed, permitted method, high trust).
- `DELETE /admin/users/42` from a client with trust score 35.0 → **Denied** (disallowed method and below trust threshold; Step 21 blocks execution even if earlier layers were undecided).

#### Stage 3: Meta Decision Ensemble Engine

All validated signals enter `meta_decision_engine.py` for weighted voting.

**Scoring formula:**

```text
Weighted Score = Σ (signal_weight × confidence × is_threat) / Σ (signal_weights)
```

**Example:**

- 12 of 20 signals mark a threat.
- Signals include: signature match, LSTM kill-chain detection, threat intel feed, autoencoder anomaly, behavioral surge.
- Base weighted sum ≈ 0.572 (57.2%) before boosting.

**Boosting mechanisms:**

- Threat intel with ≥0.9 confidence forces score ≥0.90.
- False Positive Filter passing 5/5 gates adds +0.10.

**Final score example:**

```json
{
  "weighted_vote_score": 0.572,
  "boosted_score": 1.0,
  "decision": "BLOCK"
}
```

#### Relay Architecture and Federated Intelligence

Optionally, Battle-Hardened AI nodes can enable encrypted relays for:

- Federated model training across deployments
- Sanitized pattern and reputation exchange
- Zero sharing of PII, payloads, or raw traffic

This enables rapid learning across global deployments while preserving strict data locality, regulatory compliance, and operator control.

This completes the full cycle—from ingestion to semantic enforcement—with global learning capabilities ensuring resilience and continuous improvement.

---

## Competitive Advantage vs NDR/XDR Platforms (Operational & Scoring View)

The architecture-level comparison above focuses on **how** Battle-Hardened AI is constructed relative to commercial NDR/XDR platforms. This section uses the concrete ensemble example to show **how those architectural choices change real-world scoring, false positives, and evasion resistance** when compared to leading products.

### 🏆 Competitive Advantage: Why This Approach Outperforms Industry Leaders

**Direct Conceptual Comparison vs. Named Competitors:**

| Aspect                       | Battle-Hardened AI (21 Signals/Layers) | SentinelOne Singularity | Darktrace Cyber AI | Bitdefender GravityZone | Vectra AI Cognito | CrowdStrike Falcon |
|------------------------------|---------------------------------------|-------------------------|---------------------|--------------------------|-------------------|--------------------|
| **Number of Signals/Layers** | 21 documented: 18 primary (e.g., kernel telemetry, signatures, RandomForest, LSTM, autoencoders, graph intel); 2 strategic (causal inference, trust degradation); +1 semantic gate for denial. True independence + voting. | Not quantified (dual AI engines: behavioral + cloud ML); focuses on "multi-layered" correlation via Storyline. | "Multi-layered" self-learning (unsupervised ML, Bayesian); no specific count (e.g., anomaly + behavioral DNA models). | "Multi-layered" ML (e.g., HyperDetect with supervised/unsupervised; 60,000+ data points); layers like heuristics + anomaly, but not enumerated as 21. | 3-6 signals (behavioral IOAs, velocity/prioritization); "AI Detections" for surfaces (network/identity/cloud). | Not quantified; AI-powered IOAs + Threat Graph; "layers" across endpoint/identity/cloud, but behavioral focus. |
| **Detection Diversity**      | High: Covers signatures, ML (supervised/unsupervised/deep), behavioral heuristics, sequences, drift, graph, VPN/Tor, intel feeds, FP filters, predictive, Byzantine/integrity. | Medium-High: Behavioral AI for anomalies/zero-days; endpoint-to-cloud signals. | High: Anomaly-based (novel threats); encrypted traffic + predictive modeling. | High: Heuristics + ML for behavior; supply chain + process monitoring. | Medium: Attacker behaviors (C2/lateral); encrypted analysis + signals. | Medium-High: Big data ML for patterns; endpoint events + predictive hunting. |
| **Fusion/Ensemble**          | Weighted voting; conservative base (57.2%) + authoritative boosts; causal downgrade + trust modulation. | Storyline correlation; AI stitches events into narratives. | Bayesian fusion; self-adapting without labels. | Tunable ML layers; continuous anomaly fusion. | Velocity/breadth prioritization; AI triage. | Integrated IOAs; cloud-native correlation. |
| **Unique Tech Edge**         | Semantic denial pre-impact; non-resetting trust; causal root-cause (legit vs. attack). | Agentic multistep autonomy; ransomware rollback. | Self-learning unsupervised; agentic simulation. | Behavioral hardening pre-exploit; quantum roadmap. | Evasion-resistant encrypted signals. | Scalable AI for simpler attacks. |
| **Overall Conceptual Rating**| ★★★★½ (Exceptional diversity/transparency; superior for semantic purity/privacy). | ★★★★ (Strong agentic integration; excels in rollback/autonomy). | ★★★★½ (Adaptive anomaly hunting; high for novel threats). | ★★★★ (Layered prevention; strong quantum readiness). | ★★★★ (Behavioral prioritization; evasion focus). | ★★★★ (Endpoint pattern mastery; scalable). |

**Industry Standard vs. Battle-Hardened AI (Summary Table):**

| Solution | Signals / Layers | Decision Method | Base Score Transparency | Unique Capabilities |
|----------|------------------|-----------------|------------------------|---------------------|
| **Battle-Hardened AI** | **21 (20 signals + Step 21 gate)** | Transparent weighted voting + 4-layer modulation | ✅ Full breakdown (57.2% → 100%) | Causal inference, trust degradation, authoritative boosting, semantic execution gate |
| CrowdStrike Falcon | 3-4 | ML black box | ❌ Proprietary "threat score" | Behavioral, threat intel, cloud reputation |
| Darktrace Enterprise | 5-6 | Neural network | ❌ Opaque self-learning AI | Entity modeling, anomaly detection |
| Palo Alto Cortex XDR | 3-4 | Behavioral analytics | ❌ Hidden scoring | WildFire detonation, threat intel |
| SentinelOne Singularity | 4-5 | Static/dynamic analysis | ❌ Black-box ML | Behavioral, threat intel |
| Microsoft Defender ATP | 3-4 | Cloud signals + ML | ❌ Hidden confidence | Detonation, behavioral |
| Traditional IDS (Snort) | 1 | Signature matching | ✅ Binary (match/no match) | Rule-based only |

**Why Conservative Base Scoring (57.2%) is Superior:**

The base score of **57.2%** is **intentionally conservative**—a key differentiator from competitors:

**Competitors' Aggressive Scoring Problem:**
- CrowdStrike/Darktrace: Often score 80-90% on ambiguous events → **high false positive rates**
- Example: Legitimate CI/CD deployment triggers behavioral alerts → 85% score → **incorrectly blocked**

**Battle-Hardened AI's Conservative Approach:**
- Base score 57.2% (below 75% threshold) → **would NOT block** on ambiguous signals alone
- **BUT:** Authoritative signals (Threat Intel 98% confidence + FP Filter 5/5 gates) boost to 100% → **correct block**
- Result: **Same threat detection, fewer false positives**

**Real-World Scenario Comparison:**

| Event | Battle-Hardened AI | CrowdStrike | Darktrace |
|-------|-------------------|-------------|-----------|
| **SQL Injection** (this example) | Base 57.2% → Threat Intel boost → 100% → ✅ **BLOCK** | ~80% → ✅ **BLOCK** | ~85% → ✅ **BLOCK** |
| **Legitimate Deployment** (triggers 8-10 signals) | Base 45% → No authoritative signal → ✅ **ALLOW** | ~75% → ❌ **FALSE POSITIVE (blocked)** | ~70% → ❌ **FALSE POSITIVE (blocked)** |
| **APT Low-and-Slow** (3 signals over 24h) | Base 35% → Trust degradation → 65% final score (low-trust block threshold 60%) → ✅ **BLOCK** | ~40% → ❌ **MISS** | ~50% → ❌ **MISS** |

**Unique Strategic Intelligence (No Competitor Has This):**

**1. Causal Inference (Layer 19):**
- **What it does:** Determines WHY anomaly occurred (deployment vs. attack)
- **Competitor gap:** CrowdStrike/Darktrace have NO root cause analysis
- **Impact:** Prevents false positives on legitimate operational changes

**2. Trust Degradation (Layer 20):**
- **What it does:** Persistent entity trust scoring with permanent scarring (trust never fully recovers)
- **Competitor gap:** Only Darktrace has partial entity modeling (but trust CAN reset)
- **Impact:** Prevents "try again later" strategies used by APT groups

**3. Authoritative Signal Boosting:**
- **What it does:** High-confidence signals override ensemble score
- **Competitor gap:** Most use simple weighted averages (no override mechanism)
- **Impact:** Ensures known threats are blocked even if other signals disagree

**Evasion Resistance Comparison:**

| Solution | Evasion Probability | Attack Vectors Attacker Must Bypass |
|----------|---------------------|-------------------------------------|
| **Battle-Hardened AI** | Modeled extremely low (see note) | Multiple independent signals, semantic gate, causal inference, trust degradation, and authoritative overrides |
| CrowdStrike Falcon | ~5-10% | 3-4 signals (behavioral, threat intel, static analysis) |
| Darktrace Enterprise | ~15-20% | 5-6 signals (anomaly detection, entity modeling) |
| Traditional IDS | ~30-40% | 1 signal (signature matching) |

These probabilities are illustrative, model-based estimates meant to compare architectural robustness, not empirically measured failure rates in production.

Taken together, the layered ensemble, semantic gate, causal reasoning, and trust model make practical evasion **extremely difficult** for real attacks while maintaining operational effectiveness.

**Transparency Advantage:**

**Battle-Hardened AI:**
```
SOC Analyst sees: "Base 57.2% (12/20 signals), Threat Intel match 
(98% confidence) + FP Filter (5/5 gates) → Final 100% → BLOCKED"
```
✅ **Fully auditable**, explainable, debuggable

**Competitors (CrowdStrike/Darktrace):**
```
SOC Analyst sees: "Threat Score: 85 → BLOCKED"
```
❌ **Black box**, difficult to audit, unclear why 85% was assigned

**Summary: Battle-Hardened AI Wins On:**

✅ **Signal/Layer Diversity:** 21 vs 3-6 (competitors)  
✅ **Transparency:** Full weighted breakdown vs black-box ML  
✅ **False Positive Reduction:** Conservative base (57.2%) + authoritative boost vs aggressive scoring (80-90%)  
✅ **Strategic Intelligence:** Causal inference + trust degradation (UNIQUE—no competitor has this)  
✅ **Evasion Resistance:** Modeled extremely low (see note) vs 5-40% (competitors)  
✅ **Explainability:** Human-readable decisions vs opaque neural networks  
✅ **APT Detection:** Trust degradation defeats "try again later" strategies (competitors miss low-and-slow attacks)

---
For the exact decision thresholds, boosting rules, and Stage 3→4 wiring, see the earlier **Federated AI Training & Relay Architecture** section (Stages 3–4). In short, events are logged from ~50% confidence upward, auto-blocked from ~75% (lower in APT/low‑trust modes), and further modulated by authoritative signals, causal labels, and long‑term trust state.

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
2. **ML Retraining:** Models retrained weekly with new labeled data
3. **Drift Detection:** Baseline updated monthly to adapt to network changes
4. **Reputation Decay:** Old attacks gradually fade (half-life: 30 days)
5. **Byzantine Validation:** Malicious updates rejected (94% accuracy in internal lab testing)

**Feedback Sources:**
- **Honeypot Interactions:** 100% confirmed attacks (highest quality training data)
- **Human Validation:** SOC analyst confirms/rejects alerts → improves ML
- **False Positive Reports:** Whitelisted events → update FP filter

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

At present, these figures are derived from internal lab evaluations, adversarial simulations, and scripted attack scenarios (see [AI instructions](documentation/Ai-instructions.md) and [KALI_ATTACK_TESTS.md](KALI_ATTACK_TESTS.md)). There is no independent third-party validation or production case study published yet; as pilots and reviews complete, this section will be updated with external metrics and deployment evidence.

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

### How to Trust This (Auditors & CISOs)

- **What It Guarantees:** Best-effort, defense-in-depth detection and blocking across 21 documented layers with full decision transparency, persistent memory, and continuous learning; explicit documentation of 43 mapped MITRE ATT&CK techniques.
- **What It Does Not Guarantee:** It is not a formal proof of security, not a replacement for endpoint controls, traditional firewalls, or rigorous patch management, and cannot prevent attacks that are fundamentally invisible to its telemetry.
- **Independent Verification:** Auditors can inspect code, configuration, and logs (threat_log.json, comprehensive_audit.json, causal_analysis.json, trust_graph.json) to verify that the documented layers and policies are active and behaving as described.
- **Architecture Compliance:** The documented behavior in this README is backed by the architecture and validation materials in Architecture_compliance.md and related runbooks, allowing formal review against organizational security standards.
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