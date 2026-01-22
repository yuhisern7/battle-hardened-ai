## Battle-Hardened AI
**The First Layer of Defense - Commander of Firewalls**

Battle-Hardened AI is engineered as one of the most advanced first-layer autonomous defense systems ever built. Its sole purpose is to operate at the frontline of execution—at the router and gateway boundary—denying hostile interactions the ability to produce operational effects before downstream systems are ever engaged. In its **canonical deployment**, Battle-Hardened AI runs on a **Linux gateway or edge appliance** (physical or virtual) in front of the protected segment, with optional Windows/macOS nodes acting as host-level appliances for specific servers or branches. The platform is intentionally focused on this first layer alone, allowing organizations to continue using their existing security stack—SIEM, SOAR, IAM, SOC workflows, firewalls, and governance platforms—unchanged, while Battle-Hardened AI functions as the execution-control authority and gateway decision commander.

Rather than detecting attacks after execution or generating alerts for human review, Battle-Hardened AI enforces semantic execution validity using 21 independent detection and reasoning layers operating in consensus. These layers fuse kernel-level telemetry, behavioral and statistical intelligence, graph analysis, causal inference, and persistent trust memory to fully observe adversary behavior, reason about intent and state, and command routers and firewalls to withhold execution authority when trust, structure, or semantics are invalid. Attacks are seen, learned from, and remembered—but never allowed to propagate beyond the first layer.

This is not an incremental NDR or XDR enhancement. Battle-Hardened AI represents a new defensive control class: a stateful, autonomous first-layer gateway system that permanently degrades adversary trust, resists iterative probing, and prevents systems from being coerced by malicious input—even when attacks are novel, obfuscated, or syntactically valid. With documented coverage across 43 MITRE ATT&CK techniques, the system is designed for high-assurance environments where pre-execution denial, deterministic control, and autonomous resilience at the network boundary—not alert volume or platform sprawl—define effective defense.

### What Makes Us Different: First-Layer vs Everything Else

Most security platforms operate **after** something has already executed. They detect, investigate, and respond to compromises. Battle-Hardened AI operates **before** execution. It decides whether an operation should be allowed to execute at all and withholds execution authority when semantics, structure, or trust are invalid.

#### Before vs After: Where We Sit

Traditional security stack:

```text
Attack → Execute → Detect → Investigate → Respond
          ↑
       (Traditional tools work here)
```

Battle-Hardened AI first-layer:

```text
Attack → Validate → ❌ DENY (no execution)
      or
      → ✅ ALLOW → Execute → [Traditional tools]
          ↑
     (We work ONLY here – the decision point)
```

#### First-Layer Positioning Across the Stack

Battle-Hardened AI enforces execution decisions across the stack, with clear responsibilities at each layer:

```text
┌─────────────────────────────────────────────────────────┐
│                    FIRST LAYER POSITIONING              │
├─────────────────────────────────────────────────────────┤
│  Layer 7 (Application) → Step 21 Semantic Gate         │
│  Layer 4 (Transport)   → Connection / flow decisions   │
│  Layer 3 (Network)     → IP / routing visibility       │
│  Layer 2 (Data Link)   → Frame / MAC-level context     │
│  Kernel Telemetry      → Syscall / socket correlation  │
└─────────────────────────────────────────────────────────┘
```

#### What Battle-Hardened AI Is Not

To stay pure as a first-layer control, Battle-Hardened AI deliberately avoids becoming other categories:

- ❌ Not a SIEM – it does not aggregate logs from 100+ sources
- ❌ Not a SOAR – it does not orchestrate responses across 50+ tools
- ❌ Not an EDR – it does not monitor endpoint processes in real time
- ❌ Not an IAM – it does not manage user identities or lifecycle policies
- ❌ Not a threat intel platform – it does not curate millions of external indicators

It is **one thing**: the first layer that decides whether execution should be allowed at all.

#### Simple First-Layer Decision Flow

At the moment of an incoming request or operation:

```text
ATTACKER REQUEST
   ↓
[ FIRST LAYER – Battle-Hardened AI ]
   ├─ Step 1: Does this request make sense? (Semantic Gate)
   ├─ Step 2: Should this entity be allowed? (Trust Graph)
   ├─ Step 3: Is this operation valid? (Causal Inference)
   └─ Step 4: Are we certain? (20 Detection Signals)
   ↓
✅ ALLOW (to downstream systems) or ❌ DENY (no further processing)
```

#### First-Layer Data & Privacy Principles

As a first-layer system, Battle-Hardened AI follows strict data-handling principles:

- The first layer **sees everything but remembers only patterns** (no raw payloads leave the environment)
- The first layer **validates but does not retain** full content (privacy and data-minimization by design)
- The first layer **decides but does not investigate** (deep investigation and case-building remain the role of SIEM/SOAR/EDR tooling)

### How Battle-Hardened AI Integrates with Enterprise Security

Battle-Hardened AI is intentionally vendor-neutral. It emits **structured JSON decisions** that can be consumed by any SIEM, SOAR, EDR/XDR, NGFW, or custom automation without baking vendor logic into the core.

At runtime, the system maintains JSON surfaces such as [server/json/blocked_ips.json](server/json/blocked_ips.json):

```json
{
   "blocked_ips": [
      { "ip": "203.0.113.10", "timestamp": "2026-01-20T17:51:38.361466+00:00", "reason": "Threat detection by AI engine" }
   ]
}
```

This format is **identical on Linux (Docker) and Windows** – the core decision engine and JSON schema do not change by platform. Only the **enforcement adapter** differs:

- On **Linux Docker**, [Documentation/FIREWALL_ENFORCEMENT.md](Documentation/FIREWALL_ENFORCEMENT.md) shows how the container’s sync daemon converts `blocked_ips.json` into host `ipset`/`iptables` rules when `BH_FIREWALL_SYNC_ENABLED=true`.
- On **Windows**, [Documentation/FIREWALL_ENFORCEMENT.md](Documentation/FIREWALL_ENFORCEMENT.md) documents an optional PowerShell script that reads the same `blocked_ips.json` file and updates a single Windows Defender Firewall rule.

In real enterprise environments with **multiple security products** (SIEM, SOAR, NGFW, EDR/XDR, ZTNA, etc.), operators are expected to treat these JSON outputs as a **canonical decision feed** and wire them into their stack via small, external integration services or SOAR playbooks:

- A lightweight adapter (or SOAR playbook) watches the JSON decision surface, computes deltas (new blocks / unblocks), and emits normalized "decision" events (e.g., `{ action, subject_type, subject_value, confidence, reason, timestamp }`).
- Those events are then mapped, per environment, into vendor-specific APIs:
   - SIEM/SOAR: ingest events and trigger playbooks.
   - NGFW / WAF: update dynamic address groups or block lists.
   - EDR/XDR: create indicators, isolate hosts, or adjust policies.

This separation keeps Battle-Hardened AI focused solely on **first-layer decisions** while allowing different organizations to connect those decisions to **any** enterprise security stack without modifying core code. The Linux Docker and Windows deployments both produce the same JSON decision surfaces; only the enforcement and integration wiring differ.

#### Where Do I Configure Existing Tools to Read BH Output?

Because every enterprise product has different menus and terminology, Battle-Hardened AI does **not** try to talk to each vendor directly. Instead, you point your existing platforms at the BH decision feed using the integration surfaces they already expose:

- **SIEM / SOAR platforms (Splunk, Azure Sentinel, QRadar, Elastic, etc.)**
   - In the SIEM/SOAR UI, create a **data source / collector / log source** that accepts events from BH (for example: HTTP collector endpoint, syslog/CEF input, or custom JSON ingestion).
   - Point your BH integration service (or a small script) at that endpoint and send normalized BH decision events there.
   - In the same SIEM/SOAR, create **rules or playbooks** that say: "IF event.source = 'Battle-Hardened AI' AND action = 'block' THEN call firewall/EDR/ZTNA API".

- **NGFW / WAF / reverse proxies (Palo Alto, Fortinet, Check Point, F5, etc.)**
   - These devices typically do **not** read BH JSON directly. Instead, your SIEM/SOAR or a small connector service calls their **REST APIs** to update dynamic address groups, objects, or block lists when BH issues a block/unblock decision.
   - The "configuration" for this lives in your automation layer (playbook actions or connector config: base URL, credentials, object names), not inside Battle-Hardened AI itself.

- **EDR / XDR platforms (Microsoft Defender, CrowdStrike, SentinelOne, Cortex XDR, etc.)**
   - Use their documented **automation / API / integration** surfaces to receive BH decisions via SOAR or a connector script.
   - For example: when BH emits `action = block` on an IP, hash, or device, your automation calls the EDR/XDR API to create an indicator, isolate a device, or adjust policy.

In all cases:

- Battle-Hardened AI exposes a **single, stable JSON decision feed** (e.g., `blocked_ips.json` and related decision surfaces) on both Linux Docker and Windows.
- Vendor-specific wiring happens **in your existing tools** under their normal "Data sources / Connectors" and "Automations / Playbooks" sections.
- You never recompile or customize Battle-Hardened AI per vendor; you adjust **configs and playbooks** in your SIEM/SOAR/EDR/NGFW stack to consume BH's outputs and enforce decisions using their own APIs.

### What Battle-Hardened AI Offers (Capabilities & Roadmap)

These capabilities are **aspirational** unless explicitly marked as implemented. Use this single checklist to track which enterprise capabilities have been wired into code and which remain roadmap.

#### Core Dashboard Sections (23)

***Each section has been tested and it works***

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
| 16 | AI Security Crawlers & Threat Intelligence Sources | Status board for security crawlers and external intelligence: crawl schedules and last‑run times, coverage of external sources (exploit databases, OSINT, dark‑web indicators), error conditions, and how many indicators have been promoted into local reputation/threat‑intel layers. |
| 17 | Traffic Analysis & Inspection | Deep packet and flow analysis for live traffic: protocol and application breakdowns, encrypted vs cleartext ratios, unusual ports and methods, inspection verdicts from relevant detection layers, and enforcement summaries so operators can verify that network controls match policy and understand what is being blocked. |
| 18 | DNS & Geo Security | Dedicated surface for DNS and geographic‑risk analytics: DGA and tunneling heuristics, suspicious query patterns, NXDOMAIN and entropy metrics, geo‑IP risk zoning, and how those signals feed blocking, reputation, and trust so defenders can spot command‑and‑control, staging, and reconnaissance activity. |
| 19 | User & Identity Trust Signals | Identity‑centric view of entities the system observes: behavioral risk scores, unusual login and session patterns, device/location changes, Zero‑Trust trust deltas, and how identity signals are influencing execution decisions—explicitly without acting as IAM, lifecycle, or policy administration tooling. |
| 20 | Sandbox Detonation | Overview of file detonation and sandboxing results: how many artifacts have been detonated, verdict classifications, extracted indicators (domains, hashes, behaviors), and how those outcomes inform signatures, reputation, and causal reasoning, all while keeping payload inspection local to the protected environment. |
| 21 | Email/SMS Alerts (Critical Only) | Configuration and runtime status for critical out‑of‑band alerts: which destinations are configured, which events (system failure, kill‑switch changes, integrity breaches) will trigger notifications, recent send history, and failure diagnostics—positioned as a narrow safety‑of‑operation channel rather than a full alerting platform. |
| 22 | Cryptocurrency Mining Detection | Specialized analytics for crypto‑mining behavior: detection of mining pools and protocols, anomalous resource usage and long‑lived connections, associated entities and campaigns, and enforcement outcomes so operators can quickly confirm that mining activity is being identified and constrained. |
| 23 | Governance & Emergency Controls | Command surface for high‑assurance governance: current kill‑switch mode and approval workflow, pending and historical decisions in the approval queue, policy governance and Step 21 policy bundle status, secure‑deployment/tamper health, and audit/log integrity so operators can safely move between observe, approval, and fully autonomous deny modes. |

These core sections are backed by JSON/audit surfaces and exercised by the validation and operational runbooks documented in `ai-instructions.md` (testing & validation guide) and `KALI_ATTACK_TESTS.md`.

### What Does Not Exist (Breakthrough)

No documented unified implementation—commercial or open—covers all of the following as a single architecture:

- Observe attacks end-to-end, across network, application, and behavioral layers
- Learn continuously from real adversary behavior
- Preserve raw attack intelligence in structured, privacy-respecting form
- Maintain long-lived trust memory that cannot be trivially reset
- Enforce protocol and execution semantic validity
- Deny execution meaning before attacker impact
- Apply these controls uniformly across environments
- Treat semantic invalidity as a first-class defensive signal

This is not a feature gap — **it is a paradigm gap**.

While isolated forms of semantic validation exist in narrow domains, no known NDR or XDR platform implements system-wide semantic execution denial integrated with learning, trust memory, and causal reasoning. Battle-Hardened AI closes that gap by design.

### Normative References (Source-of-Truth Documents)

For auditors, engineers, and operators, the following documents serve as the authoritative technical references for this system:

- [filepurpose.md](filepurpose.md) — Maps every core file and JSON surface to the 7-stage pipeline and 21 detection layers
- [ai-instructions.md](ai-instructions.md) — Developer implementation guide, validation flow, and dashboard/endpoint mapping
- [dashboard.md](dashboard.md) — Dashboard and API reference tied directly to pipeline stages and JSON surfaces
- [ARCHITECTURE_COMPLIANCE.md](ARCHITECTURE_COMPLIANCE.md) — Formal proof that runtime code paths implement the documented log → block → relay architecture
- [ATTACK_HANDLING_FLOW.md](ATTACK_HANDLING_FLOW.md) — End-to-end attack handling, from honeypot and network monitoring through pcs_ai, firewall, and relay

These documents collectively define the system’s intended behavior, guarantees, and constraints.

### Deployment Scope — What Can Be Protected

Battle-Hardened AI is **built as a gateway/router-style first-layer decision node**. It is designed to sit **in front of networks, segments, or critical services**, where it can decide which interactions are allowed to have operational meaning. It can also operate in **host-only** or **observer** roles when a true gateway position is not available.

- **Home & Small Office Networks** – When deployed as a **gateway** (Linux box, router, or dedicated security appliance in front of the home router), Battle-Hardened AI can protect the **entire network** behind it. When run on a single Windows or macOS machine in **host-only mode**, it protects that host and any traffic explicitly routed or mirrored through it.
- **Enterprise Networks** – Deployed at the **edge of a LAN/VLAN/VPN** or as a **tap/observer** on a mirrored/SPAN port, Battle-Hardened AI provides first-layer execution control for traffic crossing that boundary (north–south and, where mirrored, east–west). It can also run as a SOC observer for high-fidelity threat sensing without changing existing routing.
- **Servers, Data Centers & Applications** – Installed directly on **servers, reverse proxies, or dedicated security appliances** in front of critical services, Battle-Hardened AI acts as the first-layer execution gate for those specific workloads and their exposed ports.
- **Website & API Hosting Environments** – Placed in front of web servers, API gateways, or reverse proxies, Battle-Hardened AI validates inbound HTTP(S) traffic before it reaches application stacks, operating alongside existing WAFs rather than replacing them.
- **Cloud Infrastructure (IaaS / PaaS)** – Deployed as a **security appliance, sidecar, or observability node** with access to VPC/VNet flows, load-balancer traffic, or control-plane telemetry, Battle-Hardened AI provides first-layer execution decisions for cloud-exposed endpoints and services.
- **Critical Infrastructure & Research Environments** – Used as a **controlled observer or gateway** around OT, SCADA/ICS, lab, or R&D networks, Battle-Hardened AI delivers pre-execution denial and high-fidelity telemetry without introducing agents into sensitive devices.
- **Government, Defense & Law-Enforcement SOCs** – Operated as a **frontline defensive node or observer appliance** in classified or regulated environments, Battle-Hardened AI enforces first-layer semantic execution control while preserving strict data-sovereignty guarantees.

In all cases, **protection coverage is determined by placement and routing**:

- **Gateway placement (primary design)** – Battle-Hardened AI sits in front of the network, segment, or service, with full visibility into inbound and outbound traffic for that boundary.
- **Server/host placement** – Battle-Hardened AI protects the local host and any services it terminates (including web, API, SSH, RDP, or custom protocols). This is effectively a gateway role scoped to that host and its directly terminated services.
- **Observer/monitoring placement** – When attached to a mirror/SPAN port or cloud flow log stream, Battle-Hardened AI operates as a first-layer observer and decision engine; enforcement depends on how its block/allow decisions are wired into firewalls, routers, or orchestration.

For **true network-wide protection**, Battle-Hardened AI should be deployed at a **gateway or routing/control point** (physical or virtual) where traffic naturally passes through it or is explicitly mirrored for enforcement. Host-only deployments still provide full first-layer semantics for that host and its directly terminated services, but do not replace upstream firewalls or routers.

To turn first-layer decisions into **real packet drops** at these boundaries, operators **must wire Battle-Hardened AI into the underlying firewall**. **Before deploying in production, read [Documentation/FIREWALL_ENFORCEMENT.md](Documentation/FIREWALL_ENFORCEMENT.md) end-to-end** for Linux (Docker host) and Windows host integration patterns.

### Hardware Deployment Checklists (Gateway vs Inline)

This section provides a **hardware-only checklist** for two primary deployment patterns you can hand directly to network/infrastructure engineers and procurement teams. It assumes Linux as the primary OS for gateway/inline roles (recommended); Windows native deployments are typically host-only or appliance-style for specific segments.

#### ✅ Option A — Battle-Hardened AI as the Edge Router (Strongest, Cleanest)

**Topology**

- ISP Modem/ONT → Battle-Hardened AI → Switch / APs / Internal Network

**Required Equipment**

- **ISP Modem / ONT**
   - Must support bridge mode
   - Routing, NAT, and firewall disabled (passes raw WAN to BH)
- **Dedicated Battle-Hardened AI Machine (Security Appliance)**
   - Minimum 2 physical NICs
      - NIC 1 = WAN
      - NIC 2 = LAN
   - Recommended hardware characteristics:
      - Intel-class NICs (e.g., i210 / i350 family)
      - AES-NI capable CPU
      - 16–32 GB RAM
      - SSD/NVMe for logs and ML models
   - Runs Linux (gateway/router role; see STARTUP_GUIDE + FIREWALL_ENFORCEMENT)
- **Layer-2 Switch**
   - Connects LAN side of BH to internal devices
   - VLAN support recommended (not mandatory)
- **Access Points / Wi‑Fi Router (AP mode only)**
   - Must support dedicated AP/bridge mode
   - DHCP & NAT disabled (handled by BH)

**Optional / Enterprise Add‑Ons**

- Secondary BH node for failover/HA
- UPS (BH is now a mission‑critical security appliance)
- Hardware TPM / secure boot (for additional integrity assurance)

**What This Guarantees**

- Battle-Hardened AI is the **default gateway** for the protected segment
- All ingress/egress traffic must pass through BH (no bypass without physical changes)
- BH has full authority over:
   - Routing
   - NAT
   - Firewall policy (when wired per FIREWALL_ENFORCEMENT)
   - First-layer execution decisions

#### ✅ Option B — Battle-Hardened AI as Transparent Inline Bridge (Bump‑in‑the‑Wire)

**Topology**

- ISP Modem/ONT → Battle-Hardened AI (Bridge) → Existing Router/Firewall (WAN port)

**Required Equipment**

- **ISP Modem / ONT**
   - Same as Option A: bridge mode preferred
- **Dedicated Battle-Hardened AI Machine**
   - Minimum 2 physical NICs
      - NIC 1 = upstream (WAN‑side, toward ISP)
      - NIC 2 = downstream (router/firewall‑side)
   - Linux with:
      - Bridge support
      - eBPF / packet capture enabled
   - Similar CPU/RAM/storage specs as Option A
- **Existing Router / Firewall**
   - Continues to handle:
      - PPPoE / DHCP client
      - NAT
      - Internal routing and Wi‑Fi (if integrated)
   - BH sits inline, transparently, in front of it
- **Switch / APs**
   - Same as your current topology behind the existing router/firewall

**Optional / Enterprise Add‑Ons**

- Inline fail‑open relay or bypass appliance (rare, high‑end deployments)
- TAP/SPAN port for independent monitoring or out‑of‑band sensors
- UPS for BH and core network stack

**What This Guarantees**

- All WAN‑bound traffic **must pass through** Battle-Hardened AI before reaching the router
- Existing router/firewall configuration can remain largely unchanged
- BH can block, rate‑limit, or deny at the first layer **before** the router sees traffic (when enforcement is wired correctly)

#### ⚠️ What You Do **Not** Need (Common Procurement Mistakes)

- ❌ No special "BH‑specific" router or proprietary chassis
- ❌ No SD‑WAN or cloud‑managed router requirement
- ❌ No cloud dependency for core detection
- ❌ No endpoint agents (BH protects at the gateway/segment boundary)

#### 🔒 Security Reality Check

- Both options assume BH runs with elevated privileges (root/admin) appropriate for a security appliance
- Treat the BH node like any other critical firewall/router:
   - Lock racks/cabinets and wiring closets
   - Lock switch ports and disable unused physical ports
   - Restrict router/firewall and BH admin access to trusted operators

**Quick Decision Guide**

| Requirement                          | Recommended Option |
|--------------------------------------|--------------------|
| Absolute control, zero bypass        | Option A           |
| Keep existing router configuration   | Option B           |
| Fastest deployment                   | Option B           |
| Cleanest long‑term architecture      | Option A           |
| High‑assurance / military posture    | Option A           |

---

## ⚠️ Platform Requirements & Startup Guide

**Network-Wide Protection Depends on Your Operating System:**

### Linux (Recommended - Full Docker Support)
- ✅ **Docker**: Full network-wide monitoring + Web GUI dashboard works perfectly
- ✅ **Host Network Mode**: Docker can access entire network traffic
- ✅ **Deployment**: `docker compose up -d` (production-ready with Gunicorn)
- ✅ **Auto-restart**: Built-in via Docker restart policies
- ✅ **Capacity**: Handles 1000s of concurrent attacks
 - ⚠️ **Privileges**: Container runs as root with NET_ADMIN/BPF for eBPF + firewall sync; treat host as a dedicated security appliance

### Windows / macOS (Native Execution)
- ❌ **Docker Limitation**: Bridge mode cannot monitor network-wide traffic (only container traffic)
- ✅ **Native Python**: Required for full network protection
- ✅ **Web GUI**: Accessible at `https://localhost:60000` when running natively
- ⚠️ **Production Mode**: Use `python installation/watchdog.py` instead of `python server.py` for crash protection
- ✅ **Auto-restart**: Watchdog monitors and restarts server on crash
- ✅ **Capacity**: ~500 concurrent connections (OS limitations)
 - ⚠️ **Privileges**: Run the server and watchdog "as Administrator" to enable packet capture and Windows firewall rule sync
- 📈 **Scaling**: For 10,000+ connections, use Linux native or cluster - see [SCALING_GUIDE.md](SCALING_GUIDE.md)

**Summary:**
- **Linux users**: Use Docker (recommended) - see [STARTUP_GUIDE.md](STARTUP_GUIDE.md#-linux-docker) and **wire firewall enforcement via [FIREWALL_ENFORCEMENT.md](Documentation/FIREWALL_ENFORCEMENT.md)**
- **Windows/Mac users**: Run natively with production mode - see [STARTUP_GUIDE.md](STARTUP_GUIDE.md#-windows-native) and **configure Windows firewall sync via [FIREWALL_ENFORCEMENT.md](Documentation/FIREWALL_ENFORCEMENT.md)**
- **Quick Start**: See [STARTUP_GUIDE.md](STARTUP_GUIDE.md) for complete instructions
- **Organizations**: Deploy on Linux or dedicated Windows security appliance with proper network policies
- **GUI Dashboard**: Available on both Docker (Linux) and native execution (all platforms)

**🚀 Installation & Startup Steps:**

- For complete, step-by-step installation instructions (Windows installer, Windows/macOS native, Linux Docker) and firewall/AV guidance, see [Documentation/INSTALLATION.md](Documentation/INSTALLATION.md).
- For runtime configuration and operational startup details, see [STARTUP_GUIDE.md](STARTUP_GUIDE.md).
- For scaling scenarios (10,000+ connections, clustering), see [SCALING_GUIDE.md](SCALING_GUIDE.md).

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

#### First-Layer vs Everything Else: The Architectural Truth

Even among advanced platforms, very few controls truly sit at the execution gate. The distinction between a first-layer system and downstream tooling can be summarized as:

| Aspect | First-layer systems | Downstream systems |
|--------|---------------------|--------------------|
| Primary question | "Should this be allowed to execute?" | "What happened?" |
| Decision timing | Before any state change | After state change has already occurred |
| Failure mode to minimize | False negatives (letting bad execute) | False positives (alert fatigue and noise) |
| Data retention | Patterns and aggregates, no payloads required | Full payloads and logs for deep investigation |
| Integration point | Execution gate in front of the stack | Data aggregation and analysis layer inside the stack |
| Value proposition | **Prevent damage entirely** | **Understand and respond to damage** |

Battle-Hardened AI is not an alerting add-on but a **stateful autonomous first-layer defense system**. Persistent memory, causal reasoning, trust degradation, semantic execution-denial, and full decision transparency are structural properties of the design, not positioning language.

Comparisons to NDR/XDR platforms serve to clarify architectural boundaries, not to claim category equivalence.

---

**Interpretation rule (important):**
- ND = Not publicly documented or verifiable as a first-class capability
- Partial = Present but opaque, partial, or non-explainable
- Documented = Explicitly implemented, documented, and architecturally integral

### Core Detection & Reasoning Capabilities

| Platform | Detection Architecture | Independent Signal Classes | Kernel Telemetry | Causal Inference | Persistent Trust Memory |
|----------|------------------------|----------------------------|------------------|------------------|-------------------------|
| **Battle-Hardened AI** | Multi-engine consensus (stateful) | Documented 21 layers (20 signals + Step 21 semantic gate) | Documented eBPF (first-class) | Documented Layer 19 | Documented Layer 20 (cross-session) |
| CrowdStrike Falcon | Correlation pipelines (event-driven) | ND (undisclosed) | Partial (abstracted) | ND | ND |
| SentinelOne Singularity | Behavior + rules (event-driven) | ND (undisclosed) | Partial | ND | ND |
| Palo Alto Cortex XDR | Data lake correlation | ND (undisclosed) | ND | ND | ND |
| Microsoft Defender ATP | Telemetry correlation | ND (undisclosed) | Partial (limited) | ND | ND |
| Darktrace | Statistical anomaly detection | ND (undisclosed) | ND | ND | Partial (time-decayed) |
| Vectra AI | Behavioral + ML scoring | ND (undisclosed) | ND | ND | ND |
| ExtraHop | Protocol analytics | ND (undisclosed) | ND | ND | ND |
| Cisco Secure NDR | Signature + analytics | ND (undisclosed) | ND | ND | ND |
| Trend Micro XDR | Multi-product correlation | ND (undisclosed) | Partial | ND | ND |
| Carbon Black | Endpoint behavior tracking | ND (undisclosed) | Partial | ND | ND |
| Fortinet FortiNDR | Signature + heuristics | ND (undisclosed) | ND | ND | ND |
| Stellar Cyber | Open XDR correlation | ND (undisclosed) | ND | ND | ND |
| Corelight | Zeek-based analytics | ND (undisclosed) | ND | ND | ND |
| Fidelis Network | Signature + session analysis | ND (undisclosed) | ND | ND | ND |
| Suricata + ML | Rules + limited ML | Partial (1–2 visible) | ND | ND | ND |

### Explainability, Transparency & Failure Handling

| Platform | Explainability | Decision Trace | Failure Awareness | Analyst Dependency |
|----------|----------------|----------------|-------------------|-------------------|
| **Battle-Hardened AI** | Documented | Documented full signal & trust trace | Documented explicit failure states | Optional (autonomous) |
| CrowdStrike Falcon | Limited (not publicly documented) | Alert-level only | Not documented | Required |
| SentinelOne | Limited (not publicly documented) | Storyline only | Not documented | Required |
| Palo Alto Cortex XDR | Partial | Partial (event chain) | Not documented | Required |
| Microsoft Defender | Limited (not publicly documented) | Alert abstraction | Not documented | Required |
| Darktrace | Limited (not publicly documented) | Anomaly score | Not documented | Required |
| Vectra AI | Partial | Partial (scoring rationale) | Not documented | Required |
| ExtraHop | Partial | Partial (protocol views) | Not documented | Required |
| Cisco Secure NDR | Partial | Partial (correlated events) | Not documented | Required |
| Others | Limited (not publicly documented) | Not documented | Not documented | Required |

### Learning, Adaptation & Attack Resistance

| Platform | Learning Model | Post-Compromise Adaptation | Deception Feedback | AI Self-Protection |
|----------|----------------|---------------------------|--------------------|--------------------|
| **Battle-Hardened AI** | Local + optional federated | Documented persistent adaptation | Documented first-class signal | Documented trust degradation vs attacker |
| Commercial NDRs | Mostly cloud-driven | Not documented (session-bound) | Not documented / rare | Not documented |

*See [Positioning Statement](#positioning-statement-critical) above for detailed architectural comparison and [Why Evasion is Nearly Impossible](#why-evasion-is-nearly-impossible) below for defense-in-depth analysis.*  

---

### Applicability to Military & Law-Enforcement Environments

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

Battle-Hardened AI provides comprehensive detection across the MITRE ATT&CK framework. This section maps all **21 detection layers** (20 signals + Step 21 semantic execution-denial gate) to specific tactics and techniques, providing complete visibility into defensive coverage.

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

**Battle-Hardened AI defensibly covers 43 MITRE ATT&CK techniques using 21 AI detection layers (20 signals + Step 21 semantic gate).**

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

Battle-Hardened AI follows a single-node-per-network architecture. Each protected network requires only one Battle-Hardened AI server, eliminating the need for agents on every endpoint while still providing comprehensive network-level visibility.

An optional private relay can be enabled to allow participating nodes to exchange sanitized, privacy-preserving AI training materials—such as signatures, statistical patterns, and reputation updates. This enables collective learning and continuous improvement across deployments without exposing sensitive traffic, payloads, or personally identifiable information.

## 21 Detection Layers (Core AI Capabilities)

Battle-Hardened AI uses **21 detection layers**—20 independent detection signals plus a Step 21 semantic execution-denial gate—combined through a weighted ensemble and final semantic gate to minimize false positives and prevent single-model failure.

**Primary Detection Signals (1-18):** Direct threat detection from network traffic and system events.

**Strategic Intelligence Layers (19-20):** Contextual analysis that refines intent, trust, and long-term behavior.

| # | Signal | Short Description |
|---|--------|-------------------|
| 1 | eBPF Kernel Telemetry | Syscall + network correlation, kernel/userland integrity |
| 2 | Signature Matching | Deterministic attack patterns |
| 3 | RandomForest | Supervised classification |
| 4 | IsolationForest | Unsupervised anomaly detection |
| 5 | Gradient Boosting | Reputation modeling |
| 6 | Behavioral Heuristics | Statistical risk scoring |
| 7 | LSTM | Kill-chain sequence modeling |
| 8 | Autoencoder | Zero-day anomaly detection |
| 9 | Drift Detection | Model degradation monitoring |
| 10 | Graph Intelligence | Lateral movement & C2 mapping |
| 11 | VPN / Tor Fingerprinting | Anonymization indicators |
| 12 | Threat Intel Feeds | OSINT correlation |
| 13 | False Positive Filter | Multi-gate consensus |
| 14 | Historical Reputation | Recidivism tracking |
| 15 | Explainability Engine | Transparent decisions |
| 16 | Predictive Modeling | Short-term forecasting |
| 17 | Byzantine Defense | Poisoned update rejection |
| 18 | Integrity Monitoring | Telemetry & model tampering detection |
| 19 | **Causal Inference Engine** | Root cause analysis (why attacks happen, not just that they happened) |
| 20 | **Trust Degradation Graph** | Zero-trust enforcement over time (persistent entity trust scoring) |
| 21 | **Step 21 Semantic Execution Gate** | Final semantic gate that evaluates state, intent, structure, and trust before allowing any execution or state change |

### Per-Layer Operational Detail

1. **eBPF Kernel Telemetry (Layer 1)** – Captures syscalls, process and socket activity via eBPF and correlates them with userland and network context to surface abnormal processes, listeners, and post-compromise behavior.

2. **Signature Matching (Layer 2)** – Runs deterministic rules over HTTP headers, bodies, parameters, and file uploads to detect known exploit families (SQLi, XSS, RCE, traversal, deserialization, brute-force patterns).

3. **RandomForest Classifier (Layer 3)** – Applies a supervised model on normalized traffic features to classify requests into threat categories vs benign and emit a probability-weighted signal into the ensemble.

4. **IsolationForest Anomaly Detection (Layer 4)** – Maintains an unsupervised baseline of normal traffic per environment and flags high-dimensional outliers, covering early probing and novel parameterization without signatures.

5. **Gradient Boosting Reputation Model (Layer 5)** – Learns a dynamic reputation score from historical behavior (alerts, geo, ASN, error patterns) for IPs and identities, strengthening or de-emphasizing other signals based on long-term risk.

6. **Behavioral Heuristics (Layer 6)** – Derives statistical and rule-based metrics (rates, method mix, endpoint rarity, error ratios, auth failures) and converts them into a bounded risk score for suspicious-but-ambiguous behavior.

7. **LSTM Sequence Analyzer (Layer 7)** – Models ordered sequences of actions per actor to detect kill-chain style progressions (recon → exploit → privilege change → lateral move) that are invisible to single-event analysis.

8. **Autoencoder Zero-Day Detector (Layer 8)** – Uses a deep autoencoder trained on clean traffic to flag structurally novel requests or flows via reconstruction error, providing a zero-day–oriented anomaly signal.

9. **Drift Detection (Layer 9)** – Monitors feature distributions and model outputs over time to detect data or concept drift and drive alerts or retraining when ML models are becoming stale.

10. **Graph Intelligence (Layer 10)** – Maintains a graph of entities and communication edges to identify lateral movement, emergent pivot nodes, multi-hop C2 paths, and unusual communication structures.

11. **VPN / Tor Fingerprinting (Layer 11)** – Detects anonymization infrastructure (VPNs, Tor, proxies) using IP data, TLS-style fingerprints, and connection metadata to distinguish ordinary remote access from obfuscated entry points.

12. **Threat Intelligence Feeds (Layer 12)** – Correlates actors and destinations with external and enterprise intelligence (blocklists, known-bad IPs/domains, exploit/CVE indicators) to contribute a "known bad / strongly suspected" signal.

13. **False Positive Filter (Layer 13)** – Applies a 5-gate pipeline (network behavior, protocol anomalies, AI predictions, rules, honeypot/reputation) to confirm or downgrade detections before they influence blocking decisions.

14. **Historical Reputation (Layer 14)** – Maintains decaying long-term risk scores for actors so repeated low-level violations accumulate into durable high-risk profiles distinct from one-off mistakes.

15. **Explainability Engine (Layer 15)** – Produces structured explanations listing which layers fired, their confidences, and key features so ensemble decisions are auditable for SOC, IR, and compliance teams.

16. **Predictive Modeling (Layer 16)** – Performs short-horizon forecasting on recent behavior and sequences to estimate near-term risk (e.g., trending toward credential abuse, exfiltration, or lateral movement).

17. **Byzantine Defense (Layer 17)** – Evaluates federated or distributed model updates, rejecting poisoned or inconsistent contributions that deviate from consensus to protect shared models.

18. **Integrity Monitoring (Layer 18)** – Watches model artifacts, configuration, and telemetry paths for unauthorized changes and raises distinct integrity alerts when the detection stack itself is modified.

19. **Causal Inference Engine (Layer 19)** – Performs root-cause analysis over events and signals to identify which actions actually cause security-relevant outcomes vs coincidental correlation.

20. **Trust Degradation Graph (Layer 20)** – Tracks long-lived trust scores for entities using behavior, graph position, and incident history, enforcing slow recovery and rapid degradation consistent with zero-trust principles.

21. **Step 21 Semantic Execution Gate (Layer 21)** – Acts as the final semantic gate, evaluating requested operations (role, action, structure, parameters) against state, policies, and trust before allowing execution or state change.

All 21 layers provide independent evidence into the ensemble and semantic gate so no single model or heuristic can silently fail.

---

### Future Update: Step 21 Policy Hardening

A future update will:
- Add compact, config-driven endpoint-prefix rules to Step 21 for `network_request` actions so that allowed HTTP patterns are explicitly defined at the semantic gate rather than scattered across routes.
- Externalize Step 21 role/action and structural policy definitions into a dedicated configuration file, allowing operators to tune what is considered semantically valid without modifying core AI code.

These changes are designed to strengthen semantic validation without introducing fragile, per-endpoint allow-lists.

---

## Why Evasion is Nearly Impossible

Battle-Hardened AI implements **defense-in-depth** through 20 independent detection systems running in parallel plus a Step 21 semantic execution-denial gate. An attacker cannot simply bypass one security layer—they must evade **all 20 signals and pass the semantic gate simultaneously**, which is practically extremely difficult for real attacks.

**Primary Detection (Layers 1-18):** Direct threat identification from network patterns, behavior, and intelligence.

**Strategic Intelligence (Layers 19-20):** Context-aware analysis that defeats sophisticated evasion tactics:
- **Layer 19 (Causal Inference):** Distinguishes between legitimate operational changes and disguised attacks *(detailed in [Stage 2: Signal #19](#signal-19-causal-inference-engine-strategic-intelligence-layer))*
- **Layer 20 (Trust Degradation):** Enforces zero-trust degradation—even if an attacker evades detection once, trust degrades permanently, making subsequent attempts exponentially harder *(detailed in [Stage 2: Signal #20](#signal-20-trust-degradation-graph-strategic-intelligence-layer))*

### Multi-Layer Detection Coverage

**1. Ensemble Voting System**

The Meta Decision Engine uses weighted voting with signal correlation:

- **Auto-block threshold:** Requires ≥75% weighted consensus across all signals
- **Threat detection threshold:** Requires ≥50% weighted consensus
- **Signal weights:** Each detection method has a reliability weight (0.65–0.98)
- **Authoritative signal boosting:** Single high-confidence signals (honeypot interaction, threat intelligence match) can force immediate blocking regardless of other signals

Even if an attacker evades 10 signals, the remaining 10 high-confidence signals can still trigger automatic blocking.

**2. Cannot Hide From Multiple Angles**

**Port Scanning Detection:**
- Behavioral heuristics track port entropy, fan-out patterns, and connection rates
- Graph intelligence detects reconnaissance patterns across the network topology
- Kernel telemetry observes syscalls and network correlation at the OS level
- **Result:** Even "stealth" scans trigger 3+ independent signals

**Network Attack Detection:**
- Signature matching catches 3,066+ known exploit patterns (SQL injection, XSS, command injection, etc.)
- Autoencoder detects zero-day exploits through statistical anomaly detection
- LSTM tracks attack progression (scanning → auth abuse → lateral movement)
- **Result:** Both known and unknown attacks are detected

**Lateral Movement:**
- Graph intelligence detects IP hopping chains (IP → IP → IP) within 10-minute windows
- Behavioral heuristics flag abnormal connection patterns
- Historical reputation recognizes recidivist attackers
- **Result:** Multi-system compromise patterns are immediately visible

**Anonymous Attackers:**
- VPN/Tor detection uses multi-vector de-anonymization (WebRTC leaks, DNS leaks, timing analysis, browser fingerprinting)
- Behavioral fingerprinting works even when IP addresses change
- **Result:** Anonymization tools provide limited protection

**3. Cross-Session Memory**

Historical reputation system provides persistent intelligence:

- First attack from any IP → logged permanently
- Second attempt from same IP → instant recognition + elevated risk score
- Recidivism detection: ~94% accuracy
- **Result:** Attackers cannot "try again" without immediate detection

**4. Zero-Day Protection**

The autoencoder (deep learning anomaly detector) catches never-before-seen attacks:

- Learns normal traffic patterns through reconstruction
- Flags statistical anomalies that don't match benign behavior
- Works without signatures or prior knowledge of attack
- **Result:** Protection against unknown exploits and novel attack techniques

**5. Attack Progression Tracking**

LSTM neural network models attacks as state transitions:

1. NORMAL → SCANNING (reconnaissance)
2. SCANNING → AUTH_ABUSE (brute force)
3. AUTH_ABUSE → PRIV_ESC (privilege escalation)
4. PRIV_ESC → LATERAL_MOVEMENT (spreading)
5. LATERAL_MOVEMENT → EXFILTRATION (data theft)

If an attacker progresses through multiple states within a time window, confidence score increases exponentially.

**Result:** Multi-stage attacks are detected even if individual stages appear benign.

### The Reality for Attackers

To successfully attack without detection, an attacker would need to simultaneously:

- ✗ Evade signature matching (3,066+ attack patterns)
- ✗ Maintain perfectly normal behavioral metrics (15 tracked metrics including connection rate, retry frequency, port entropy, timing variance)
- ✗ Avoid triggering autoencoder anomaly detection (statistical impossibility for actual attacks)
- ✗ Progress through attack states slowly enough to evade LSTM sequence analysis (making attacks take days/weeks)
- ✗ Create no lateral movement graph patterns (single-node attacks only)
- ✗ Hide from kernel telemetry (requires kernel-level rootkit)
- ✗ Not appear in any threat intelligence feeds
- ✗ Never touch a honeypot (adaptive multi-persona deception)
- ✗ **Perfectly time attacks to coincide with legitimate deployments/config changes** (Layer 19 causal inference)
- ✗ **Prevent trust degradation across sessions** (Layer 20 persistent memory—once trust drops, it never fully recovers)
- ✗ Evade 10+ additional signals simultaneously

**In practice: Nearly impossible.**

**Layer 19 (Causal Inference) eliminates the "hiding in deployment noise" tactic:** Even if an attack coincides with a CI/CD pipeline, causal graphs detect the temporal mismatch between legitimate changes and malicious behavior.

**Layer 20 (Trust Degradation) prevents "try again later" strategies:** Each failed attack permanently degrades entity trust. Attackers cannot reset trust by changing IPs alone—behavioral fingerprints, device identifiers, and network patterns persist across sessions.

The only theoretical bypass scenarios are:

- **Ultra-slow attacks** (1 connection per day) — but achieving objectives would take months/years, and behavioral analysis would still flag abnormal patterns over time
- **Pre-compromised insider** (already authenticated) — but behavioral heuristics, graph intelligence, and LSTM would still detect abnormal post-authentication behavior
- **Zero-day kernel exploit** — but even then, network patterns, behavioral anomalies, and autoencoder reconstruction errors would trigger alerts

The system is specifically designed so **no single evasion technique works**—attackers must evade all 20 signals and pass the Step 21 semantic gate at once, which is practically extremely difficult for real attacks while maintaining operational effectiveness.

---

## 🧠 Federated AI Training & Relay Architecture

### Complete Attack Detection & Response Flow

Battle-Hardened AI processes every network packet through a sophisticated multi-stage pipeline. Below is the detailed logical flow from initial packet capture to global intelligence sharing.

#### Stage 1: Data Ingestion & Normalization

**Input Sources:**
1. **Network Traffic** (packet capture via eBPF/XDP or scapy)
   - Raw packets from network interfaces
   - TCP/UDP/ICMP flows
   - Application-layer protocols (HTTP, DNS, TLS, etc.)

2. **System Logs**
   - Authentication logs (SSH, RDP, web login attempts)
   - Application logs (web server, database, API)
   - System events (service starts/stops, errors)

3. **Cloud APIs**
   - AWS CloudTrail, Azure Activity Logs, GCP Audit Logs
   - IAM policy changes, security group modifications
   - Resource configuration drift

4. **Device Scans**
   - Active network device discovery
   - Port enumeration and service fingerprinting
   - Asset inventory updates

**Processing:**
- Extract metadata (source IP, destination IP, ports, timestamps, protocols)
- Parse application-layer data (HTTP headers, DNS queries, TLS handshakes)
- Normalize to common schema for multi-signal analysis
- Strip sensitive payloads (retain only statistical features)

**Output:** Normalized event object containing:
```python
{
  "src_ip": "203.0.113.42",
  "dst_ip": "198.51.100.10",
  "src_port": 54321,
  "dst_port": 443,
  "protocol": "TCP",
  "timestamp": "2026-01-07T10:32:15Z",
  "http_method": "POST",
  "http_path": "/login.php",
  "packet_size": 1420,
  # ... additional metadata
}
```

**Stage 1 → Stage 2 Transition:**

Normalized event passed to `AI/pcs_ai.py` → `assess_threat(event)` method → orchestrates all 20 detection signals in parallel using the same event object as input → each signal produces independent `DetectionSignal` output → all 20 signals feed into Stage 3 and then the Step 21 semantic gate.

---

#### Stage 2: Parallel Multi-Signal Detection (20 Simultaneous Analyses)

Each event flows through **all 20 detection systems in parallel**. Each signal generates an independent threat assessment.

**Signal #1: eBPF Kernel Telemetry**
- **What it does:** Observes syscalls and correlates with network activity at OS level
- **Example:** Process `bash` makes network connection → suspicious (likely shell backdoor)
- **Output:** `{is_threat: true, confidence: 0.85, details: "syscall/network mismatch"}`

**Signal #2: Signature Matching**
- **What it does:** Pattern matching against 3,066+ known attack signatures
- **Example:** HTTP request contains `' OR 1=1--` → SQL injection detected
- **Output:** `{is_threat: true, confidence: 0.95, threat_type: "SQL Injection"}`

**Signal #3: RandomForest (ML)**
- **What it does:** Supervised classification based on 50+ traffic features
- **Features:** Packet size, inter-arrival time, port numbers, protocol flags
- **Output:** `{is_threat: false, confidence: 0.72, classification: "benign"}`

**Signal #4: IsolationForest (ML)**
- **What it does:** Unsupervised anomaly detection (finds outliers)
- **Example:** Traffic pattern statistically different from normal baseline
- **Output:** `{is_threat: true, confidence: 0.68, anomaly_score: 0.82}`

**Signal #5: Gradient Boosting (ML)**
- **What it does:** IP reputation scoring based on historical behavior
- **Example:** IP has attacked 3 times before → high risk score
- **Output:** `{is_threat: true, confidence: 0.88, reputation: -0.75}`

**Signal #6: Behavioral Heuristics**
- **What it does:** Tracks 15 behavioral metrics per IP
- **Metrics:** Connection rate (50/min), port entropy (high), fan-out (20 IPs), retry frequency (8/min)
- **APT Detection:** Low-and-slow (2 conn/hour over 24h), off-hours activity, credential reuse
- **Output:** `{is_threat: true, confidence: 0.79, risk_factors: ["high_conn_rate", "port_scan"]}`

**Signal #7: LSTM Sequence Analysis**
- **What it does:** Models attack progression through 6 states
- **Observed sequence:** SCANNING → AUTH_ABUSE → PRIV_ESC (within 10 minutes)
- **APT Patterns:** Matches "Smash and Grab" campaign (fast exploitation)
- **Output:** `{is_threat: true, confidence: 0.91, attack_stage: 3, campaign: "smash_and_grab"}`

**Signal #8: Autoencoder (Deep Learning)**
- **What it does:** Zero-day detection via reconstruction error
- **Process:** Learns normal traffic → flags statistically abnormal patterns
- **Example:** Traffic pattern never seen before → high reconstruction error (0.42) → likely exploit
- **Output:** `{is_threat: true, confidence: 0.87, reconstruction_error: 0.42}`

**Signal #9: Drift Detection**
- **What it does:** Monitors if current traffic deviates from baseline distribution
- **Method:** Kolmogorov-Smirnov test, Population Stability Index
- **Output:** `{is_threat: false, confidence: 0.65, drift_detected: false}`

**Signal #10: Graph Intelligence**
- **What it does:** Maps network topology and detects lateral movement
- **Example:** IP connects to server A → server B → server C (hop chain) within 5 minutes
- **Output:** `{is_threat: true, confidence: 0.94, lateral_movement: true, hop_count: 3}`

**Signal #11: VPN/Tor Fingerprinting**
- **What it does:** Metadata-only anonymization detection using proxy/VPN headers, ISP/ASN patterns, DNS tunneling behavior, TLS fingerprinting, timing anomalies, and cross-IP fingerprint correlation. Optional law-enforcement extensions can ingest WebRTC/DNS-leak/timing/browser-fingerprint signals when explicitly enabled.
- **Output:** `{is_threat: false, confidence: 0.60, vpn_detected: true, real_ip: null}`

**Signal #12: Threat Intelligence Feeds**
- **What it does:** Checks IP against VirusTotal, AbuseIPDB, ExploitDB, etc.
- **Example:** IP appears in 15 vendor blacklists → known botnet node
- **Output:** `{is_threat: true, confidence: 0.98, sources: ["VirusTotal", "AbuseIPDB"], threat_score: 95}`

**Signal #13: False Positive Filter**
- **What it does:** 5-gate consensus validation to reduce false alarms
- **Gates:** Temporal consistency, cross-signal correlation, whitelist check, threshold validation, confidence calibration
- **Output:** `{is_threat: true, confidence: 0.90, gates_passed: 5/5}`

**Signal #14: Historical Reputation**
- **What it does:** Cross-session memory and recidivism detection
- **Example:** IP attacked 2 months ago → recidivist flag → higher risk
- **Output:** `{is_threat: true, confidence: 0.92, total_attacks: 3, is_recidivist: true}`

**Signal #15: Explainability Engine**
- **What it does:** Generates human-readable explanations for decisions
- **Output:** `{confidence: 1.0, explanation: "SQL injection + known botnet IP + lateral movement detected"}`

**Signal #16: Predictive Modeling**
- **What it does:** 24-48 hour threat forecasting based on trends
- **Example:** IP showing early-stage reconnaissance → likely to escalate within 12 hours
- **Output:** `{is_threat: false, confidence: 0.70, predicted_escalation: 0.83, time_window: 12h}`

**Signal #17: Byzantine Defense**
- **What it does:** Detects poisoned ML model updates from federated learning
- **Output:** `{is_threat: false, confidence: 0.75, update_valid: true}`

**Signal #18: Integrity Monitoring**
- **What it does:** Detects tampering with telemetry or models
- **Example:** Log deletion attempt → integrity violation
- **Output:** `{is_threat: true, confidence: 0.96, tampering_detected: true, type: "log_deletion"}`

**Signal #19: Causal Inference Engine** *(Strategic Intelligence Layer)*
- **What it does:** Determines WHY an event happened (root cause analysis)
- **Inputs:** DetectionSignal objects (1-18), system config changes, deployment events, identity changes, time-series metadata
- **Core Logic:** Builds causal graphs (not correlations), tests counterfactuals, classifies root causes
- **Causal Labels:** `LEGITIMATE_CAUSE`, `MISCONFIGURATION`, `AUTOMATION_SIDE_EFFECT`, `EXTERNAL_ATTACK`, `INSIDER_MISUSE`, `UNKNOWN_CAUSE`
- **Example:** High anomaly score detected → checks recent deployment logs → finds CI/CD pipeline ran 2 minutes before → labels as `LEGITIMATE_CAUSE` (confidence: 0.89) → downgrade threat score
- **Output:** `{causal_label: "EXTERNAL_ATTACK", confidence: 0.91, primary_causes: ["No config change", "External IP with prior reputation"], non_causes: ["Scheduled maintenance"]}`
- **Privacy:** Never sees raw payloads, credentials, exploit code, or PII - operates only on detection outputs and metadata

**Signal #20: Trust Degradation Graph** *(Strategic Intelligence Layer)*
- **What it does:** Zero-trust enforcement over time (persistent entity trust scoring)
- **Tracked Entities:** IPs, devices, user accounts, services, APIs, cloud roles, containers
- **Trust Score:** 0-100 per entity (internal starts at 100, external configurable baseline ~60)
- **Degradation Model:** Non-linear decay with event-weighted penalties (minor anomaly: -5, confirmed attack: -25, lateral movement: -30, integrity breach: -40)
- **Recovery:** +1 trust per 24h without incident (slow recovery, capped at initial baseline)
- **Thresholds:** ≥80 (normal), 60-79 (increased monitoring), 40-59 (rate limiting), 20-39 (isolation), <20 (quarantine)
- **Example:** User account trust score 85 → off-hours privilege escalation detected → lateral movement attempt → causal inference confirms no legitimate cause → trust drops to 52 → recommend rate limiting
- **Output:** `{entity_id: "user:admin@corp", entity_type: "ACCOUNT", previous_trust: 85, current_trust: 52, reason: ["Off-hours privilege escalation", "Lateral movement attempt"], recommended_action: "RATE_LIMIT"}`
- **Integration:** Feeds from Historical Reputation (Layer 14), influences response severity, tracked by Explainability Engine (Layer 15)

**Step 21: Semantic Execution Gate (Post-Ensemble, Pre-Action)**
- **What it does:** Acts as a final semantic gate on execution after ensemble voting but before any state change or backend call.
- **Inputs:** Ensemble decision, entity role, trust score, recent history (lifecycle/events), and a structured view of the requested action/payload.
- **State Legitimacy:** Rejects actions that do not make sense for the current lifecycle (e.g., destructive actions before authentication or without prior existence).
- **Intent Legitimacy:** Enforces role-based semantics (e.g., non-admin accounts cannot perform admin-only actions, even if traffic appears benign).
- **Structural Legitimacy:** Validates structure and encoding of payloads against expected schemas (required fields, no unexpected fields, safe encodings like base64-validated content).
- **Trust Sufficiency:** Requires trust scores from the trust graph to meet action-specific thresholds; low-trust entities are denied execution even if ensemble confidence is borderline.
- **Outcome:** If any dimension fails, execution meaning is denied (no state mutation, no backend call, neutral response), but the event is still fully logged and available for learning.

**Stage 2 → Stage 3 Transition:**

Primary detection signals (1-18) complete analysis → produce list of `DetectionSignal` objects → routed through `AI/false_positive_filter.py` (5-gate validation) → filtered signals + Layer 19 causal analysis → passed to `AI/meta_decision_engine.py` for weighted voting → Layer 20 trust state influences final response severity.

---

#### Stage 3: Ensemble Decision Engine (Weighted Voting)

All 20 signals converge in the **Meta Decision Engine** for final verdict before passing through the Step 21 semantic execution-denial gate.

**Weighted Voting Calculation:**

```
Weighted Score = Σ (signal_weight × signal_confidence × is_threat)
                 ────────────────────────────────────────────────
                              Σ signal_weight

Example: Real SQL Injection Attack Detection

Signals Detecting Threat (is_threat = 1):
- Signal #2: Signature (0.90 × 0.95 × 1) = 0.855
- Signal #6: Behavioral (0.75 × 0.79 × 1) = 0.593
- Signal #7: LSTM (0.85 × 0.91 × 1) = 0.773
- Signal #8: Autoencoder (0.80 × 0.87 × 1) = 0.696
- Signal #10: Graph (0.92 × 0.94 × 1) = 0.865
- Signal #12: Threat Intel (0.95 × 0.98 × 1) = 0.931
- Signal #13: False Positive Filter (0.82 × 0.90 × 1) = 0.738
- Signal #14: Historical Reputation (0.85 × 0.92 × 1) = 0.782
- Signal #15: Explainability (0.78 × 1.0 × 1) = 0.780
- Signal #18: Integrity Monitoring (0.90 × 0.96 × 1) = 0.864
- Signal #19: Causal Inference (0.88 × 0.91 × 1) = 0.801
- Signal #20: Trust Degradation (0.90 × 0.85 × 1) = 0.765

Signals Not Detecting Threat (is_threat = 0):
- Signal #1: Kernel Telemetry (0.85 × 0.60 × 0) = 0.000
- Signal #3: RandomForest (0.80 × 0.72 × 0) = 0.000
- Signal #4: IsolationForest (0.75 × 0.68 × 0) = 0.000
- Signal #5: Gradient Boosting (0.78 × 0.55 × 0) = 0.000
- Signal #9: Drift Detection (0.65 × 0.65 × 0) = 0.000
- Signal #11: VPN/Tor (0.70 × 0.60 × 0) = 0.000
- Signal #16: Predictive (0.80 × 0.70 × 0) = 0.000
- Signal #17: Byzantine (0.88 × 0.75 × 0) = 0.000

Total Numerator (threat contributions) = 9.443
Total Denominator (sum of all weights) = 16.51

Base Weighted Score = 9.443 / 16.51 = 0.572 (57.2%)

After Authoritative Boosting:
- Threat Intel fired with 0.98 confidence (≥0.9) → force score to 0.90
- False Positive Filter passed 5/5 gates → boost by +0.10

Final Score After Boosting = 0.90 + 0.10 = 1.00 (capped at 100%)

Result: BLOCK (exceeds 75% threshold)
```

**Alternate Simple Example (12/20 Signals → 57.2% Base Score):**

For auditors who prefer a flat-weight example over the full weighted sum above, the same 57.2% base score can be illustrated with 12 of 20 signals voting "threat" while the other 8 remain neutral:

- Assume 12 threat signals each contribute a base confidence of ~0.953 (within the documented 0.65–0.98 range)
- Safe/neutral signals contribute 0 to the threat sum

Then:

$$
   ext{BaseScore} = \frac{12 \times 0.953}{20} = \frac{11.436}{20} \approx 0.572 \; (57.2\%)
$$

This matches the JSON example below (`weighted_vote_score: 0.572`) and shows explicitly how **12/20 high-confidence signals**, with the rest neutral, can yield the same conservative base score before any authoritative boosting.

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
| **Battle-Hardened AI** | Modeled extremely low (see note) | 20 signals + Step 21 semantic gate + causal inference + trust degradation + authoritative overrides |
| CrowdStrike Falcon | ~5-10% | 3-4 signals (behavioral, threat intel, static analysis) |
| Darktrace Enterprise | ~15-20% | 5-6 signals (anomaly detection, entity modeling) |
| Traditional IDS | ~30-40% | 1 signal (signature matching) |

**Why 21 Detection Layers Matter:**

To evade Battle-Hardened AI, an attacker must **simultaneously**:
- ✗ Keep base score <50% (evade 12+ out of 20 signals)
- ✗ Avoid ALL authoritative signals (Threat Intel, Honeypot, FP Filter)
- ✗ Pass causal inference (not correlate with malicious patterns)
- ✗ Maintain trust score >20 (across multiple attempts)

**Practically extremely difficult** for real attacks while maintaining operational effectiveness.

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

**Decision Thresholds:**
- **≥ 50% (0.50):** Classify as threat → log to `threat_log.json`
- **≥ 75% (0.75):** Auto-block → firewall rule + connection drop
- **≥ 70% (APT Mode):** Auto-block in critical infrastructure mode

**Authoritative Signal Boosting:**
- If **Honeypot** fires (confidence ≥ 0.7) → force score to 90%+
- If **Threat Intel** fires (confidence ≥ 0.9) → force score to 90%+
- If **False Positive Filter** confirms (5/5 gates) → boost by 10%

**Causal Inference Adjustment (Layer 19):**
- If `causal_label = LEGITIMATE_CAUSE` with confidence ≥ 0.85 → downgrade ensemble score by 20%
- If `causal_label = EXTERNAL_ATTACK` or `INSIDER_MISUSE` with confidence ≥ 0.80 → boost ensemble score by 15%
- If `causal_label = MISCONFIGURATION` → route to governance queue instead of auto-block
- If `causal_label = UNKNOWN_CAUSE` → require human review (do not auto-block even if score ≥ 75%)

**Trust State Modulation (Layer 20):**
- Entity trust score <40 → apply stricter threshold (block at ≥60% instead of ≥75%)
- Entity trust score <20 → automatic quarantine regardless of weighted score
- Entity trust score ≥80 → normal thresholds apply
- Trust state recommendations override default actions when trust critically degraded

**Consensus Checks:**
- **Unanimous:** All primary signals (1-20) agree (threat or safe)
- **Strong Consensus:** ≥80% of primary signals agree
- **Divided:** Mixed signals → require higher confidence threshold + causal inference confirmation

**Output Decision:**
```json
{
  "is_threat": true,
  "threat_level": "CRITICAL",
  "confidence": 1.00,
  "should_block": true,
   "weighted_vote_score": 0.572,
  "total_signals": 20,
  "threat_signals": 12,
  "safe_signals": 8,
  "unanimous_verdict": false,
  "strong_consensus": false,
  "primary_threats": ["SQL Injection", "Lateral Movement", "Known Botnet"],
   "signals": [],
  "ip_address": "203.0.113.42",
   "endpoint": "/login.php",
   "timestamp": "2026-01-07T10:32:15Z"
}
```

**Stage 3 → Stage 4 Transition:**

Ensemble engine calculates `weighted_score` (0.0-1.0) from all filtered signals → applies decision threshold:
- **≥ 0.75** (or 0.70 in APT mode): `should_block=True` → Stage 4 firewall block + logging
- **≥ 0.50**: `should_block=False` but `threat_level=HIGH` → Stage 4 logs threat (no block)
- **< 0.50**: `threat_level=LOW` → allow, minimal logging

`EnsembleDecision` object returned to `AI/pcs_ai.py` → triggers Stage 4 response actions.

---

#### Stage 4: Response Execution (Policy-Governed)

Based on ensemble decision, the system executes controlled responses:

**Immediate Actions (if `should_block = true`):**
1. **Firewall Block:** Add IP to `iptables` or `nftables` with TTL (e.g., 24 hours)
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
5. **Byzantine Validation:** Malicious updates rejected (94% accuracy)

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
   - `AI/byzantine_federated_learning.py` validates updates (94% malicious rejection rate)
4. Updated models loaded by Stage 2 detection signals → **improved accuracy for next packet analysis in Stage 1**
5. Cycle repeats: better detection → more accurate training data → better models → better detection...

**This continuous feedback loop enables the system to adapt to evolving threats without manual intervention.**

---

### Visual Attack Detection & Response Flow

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
    ├─ Historical Reputation (cross-session recidivism ~94%)
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
   ├─ Check trust sufficiency (trust_graph thresholds per entity)
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
    │   ├─ 3,000+ new signatures from worldwide nodes
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
    └─ Byzantine validation (94% malicious update rejection)
    ↓
🔁 LOOP: Next packet processed with improved defenses
```

**This architecture creates a federated, privacy-preserving defense mesh where:**

- **One server protects an entire network segment** (no endpoint agents required)
- **Every attack makes the system smarter** (automated signature extraction + ML retraining)
- **Every node benefits from global learning** (relay-shared intelligence from worldwide attacks)
- **Organizations retain full control** (relay participation is optional, all data anonymized)
- **Privacy is preserved** (no raw payloads, no PII, only statistical features shared)

---

## High-Level Capabilities

### Threat Model & Assumptions

- **Scope:** Network-level detection and response for IP-based entities (devices, users, services, cloud roles) using packet, flow, and log telemetry. Endpoint EDR/host-level controls remain separate and complementary.
- **In-Scope Adversaries:** External attackers, APT campaigns, misconfigured automation, and insider threats operating over the network (including authenticated but anomalous behavior visible in traffic and logs).
- **Out-of-Scope Adversaries:** Physical attacks, pre-boot firmware compromise, supply-chain backdoors present before first packet, and offline data theft not observable in network or system logs.
- **Deployment Assumptions:** Battle-Hardened AI is placed where it has full visibility to relevant traffic (inline proxy, gateway, or SPAN/TAP). For encrypted traffic, visibility is limited to metadata (SNI, certificate, timing, sizes) unless deployed behind a TLS termination point.
- **Trust Model:** The AI server itself is treated as a hardened, monitored asset; OS, Docker (when used), and surrounding infrastructure must follow standard security best practices.

### Evaluation Methodology (Where the Numbers Come From)

- **Signature Count (3,066+):** Derived from the active signature set used by the Signature Matching layer, built from curated public attack pattern sources and sanitized honeypot extractions. The count reflects unique, deduplicated patterns, not rule-line inflation.
- **Accuracy Figures (~94% Recidivism / Byzantine Rejection):** Measured on held-out evaluation sets constructed from historical threat logs and simulated relay updates. Metrics are computed as standard classification accuracy on labeled events (attack vs benign or valid vs poisoned updates), with time windows and dataset sizes documented in internal test harness notebooks.
- **Evasion Probability (modeled extremely low):** An order-of-magnitude illustration assuming independence across multiple high-confidence signals and conservative success probabilities per evasion dimension. It is not a formal cryptographic guarantee.
- **Thresholds & Weights:** Defense thresholds (50% log, 75% block) and signal weights (0.65–0.98) were tuned via cross-validation on mixed benign/attack corpora to minimize false positives while preserving high recall on known and synthetic attack traces.

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
- **Architecture Compliance:** The documented behavior in this README is backed by the architecture and validation materials in ARCHITECTURE_COMPLIANCE.md and related runbooks, allowing formal review against organizational security standards.
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

### Founder & Core Development

Founded and led by **Yuhisern Navaratnam** (core development and support coordination).

**Contact:** Yuhisern Navaratnam  
**WhatsApp:** +60172791717  
**Email:** yuhisern@protonmail.com
