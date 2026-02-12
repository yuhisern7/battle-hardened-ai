# Battle-Hardened AI
## Proof-of-Concept (PoC) Acceptance Criteria

**Linux Gateway / First-Layer Enforcement Deployment**

---

## 1. Purpose of This Document

This document defines the formal acceptance criteria for evaluating Battle-Hardened AI during a customer Proof-of-Concept (PoC).

The purpose of the PoC is to verify that Battle-Hardened AI:

- Operates as a first-layer gateway
- Observes and attributes hostile activity in real time
- Autonomously commands the local firewall
- Blocks malicious sources before protected systems are affected
- Functions independently of SIEM/SOAR platforms
- Implements 5 production-ready ML pipeline security enhancements (cryptographic signing, smart filtering, performance monitoring, adversarial training, ONNX optimization)

This document is designed for:

- Security architects
- SOC leadership
- Network engineering teams
- Risk and compliance stakeholders

### 1.5 Architecture Enhancements Integration

Battle-Hardened AI includes **5 architecture enhancements** that secure and optimize the ML training pipeline:

1. **Model Cryptographic Signing** - Ed25519 signatures prevent model injection (MITRE T1574.012 defense)
2. **Smart Pattern Filtering** - Bloom filter deduplication saves 70-80% relay bandwidth
3. **Model Performance Monitoring** - Production accuracy tracking detects poisoning (MITRE T1565.001 defense)
4. **Adversarial Training** - FGSM algorithm resists ML evasion attacks (MITRE T1562.004 defense)
5. **ONNX Model Format** - 2-5x faster CPU inference without GPU requirements

These enhancements are **ML pipeline features**, not detection layers. The PoC validates that:
- Models are cryptographically verified before loading
- ML performance remains high in production
- The system operates efficiently (2-5x faster inference)

For technical details: [Architecture_Enhancements.md](../architecture/Architecture_Enhancements.md) and [ONNX_Integration.md](../architecture/ONNX_Integration.md)

---

## 2. PoC Deployment Scope

### Deployment Model

- **Linux Gateway / Router Mode**
- Cloud-based or on-premises virtual machine
- Battle-Hardened AI positioned in front of protected systems

### Out of Scope

- Endpoint agents
- Replacement of existing firewalls
- SIEM/SOAR correlation logic
- Incident response workflows

---

## 3. Pre-PoC Environment Requirements

### Infrastructure

- Linux VM (Ubuntu 22.04 LTS recommended)
- Two network interfaces:
  - WAN (upstream / internet)
  - LAN (protected network)
- Root or sudo access

### Networking

- IP forwarding enabled
- iptables or nftables available
- Protected systems configured to route traffic through Battle-Hardened AI

### Software

- Battle-Hardened AI installed via provided package
- Docker running (Linux gateway deployment)
- Firewall enforcement enabled per documentation

---

## 4. PoC Validation Phases

Each phase below contains objective criteria that must be met for acceptance.

### Phase 1 — Gateway Functionality Validation

**Objective:** Confirm Battle-Hardened AI is operating as the network gateway.

**Acceptance Criteria:**

- Protected systems route traffic through Battle-Hardened AI
- Internet access functions normally
- No packet loss or routing failure during normal operations

**Pass Condition:**  
Battle-Hardened AI successfully routes traffic without disrupting legitimate connectivity.

---

### Phase 2 — Traffic Visibility & Attribution

**Objective:** Confirm Battle-Hardened AI observes and attributes inbound traffic.

**Test Actions:**

- External connection attempts
- Port scanning
- Repeated authentication failures

**Acceptance Criteria:**

- Source IP addresses are correctly identified
- Events are visible in the Battle-Hardened AI dashboard
- Activity is logged with timestamps and metadata

**Pass Condition:**  
All hostile and benign traffic is visible and attributable.

---

### Phase 3 — Attack Detection

**Objective:** Confirm real attacks are correctly detected.

**Test Actions:**

- SQL injection attempt
- Command injection attempt
- Brute-force login attempt

**Acceptance Criteria:**

- Attacks are classified as malicious
- Detection confidence is recorded
- Threat events are logged

**Pass Condition:**  
Attacks are detected without false negatives.

---

### Phase 4 — Autonomous Firewall Enforcement

**Objective:** Confirm Battle-Hardened AI directly commands the firewall.

**Acceptance Criteria:**

- Attacker IP is recorded in the block list
- Firewall rules are created automatically
- No manual firewall interaction is required

**Pass Condition:**  
Firewall rules are applied immediately by Battle-Hardened AI.

---

### Phase 5 — Enforcement Effectiveness

**Objective:** Confirm attackers are actually blocked.

**Acceptance Criteria:**

- Blocked attackers cannot reconnect
- Connections time out or are dropped
- Legitimate users remain unaffected

**Pass Condition:**  
Selective enforcement is confirmed.

---

### Phase 6 — Independence from External Tools

**Objective:** Confirm enforcement does not rely on SIEM/SOAR.

**Acceptance Criteria:**

- Blocking functions even if:
  - SIEM is unavailable
  - Webhooks or syslog targets are disabled
- Firewall rules still apply locally

**Pass Condition:**  
Battle-Hardened AI enforces decisions autonomously.

---

### Phase 7 — Persistence & Resilience

**Objective:** Confirm state persists across restarts.

**Acceptance Criteria:**

- Firewall rules persist after restart
- Attacker remains blocked
- Trust state is retained

**Pass Condition:**  
Defense is stateful and resilient.

---

### Phase 8 — False Positive Validation

**Objective:** Ensure legitimate traffic is not disrupted.

**Acceptance Criteria:**

- Normal web traffic functions
- APIs and services remain accessible
- No unexplained blocking of trusted sources

**Pass Condition:**  
Operational traffic remains unaffected.

---

### Phase 9 — Architecture Enhancements Validation

**Objective:** Confirm the 5 ML pipeline security enhancements are operational.

**Test Actions:**

- Check model signature verification in logs
- Monitor pattern filter bandwidth savings
- Review ML performance metrics in dashboard
- Validate ONNX models are loaded (2-5x faster inference)

**Acceptance Criteria:**

- Model signatures are verified before loading (cryptographic signing active)
- Pattern filter statistics show deduplication (70-80% bandwidth reduction)
- ML performance metrics are tracked and reported
- ONNX runtime is used for inference (check logs for "Loading ONNX model" messages)
- System operates at 2-5x faster inference speed vs baseline pickle models

**Pass Condition:**  
All 5 architecture enhancements are operational and provide documented benefits.

---

## 5. PoC Acceptance Decision

### PoC is Accepted if ALL are true:

- ✅ Battle-Hardened AI functions as a gateway
- ✅ Attacks are detected and attributed
- ✅ Firewall rules are enforced automatically
- ✅ Enforcement is persistent
- ✅ SIEM/SOAR is not required for blocking
- ✅ Legitimate traffic is unaffected
- ✅ 5 architecture enhancements are operational (model signing, pattern filtering, performance monitoring, ONNX optimization)

### PoC is Rejected if ANY are false:

- ❌ Attacks pass through unblocked
- ❌ Firewall enforcement fails
- ❌ System depends on external tools to block
- ❌ Blocks do not persist
- ❌ Legitimate traffic is disrupted

---

## 6. What This PoC Demonstrates

Successful completion proves that Battle-Hardened AI is operating as:

- A **first-layer execution-control system**
- An **autonomous firewall commander**
- A **pre-execution security authority**
- A **stateful, learning defensive control**
- A **production-hardened ML security platform** with 5 architecture enhancements providing cryptographic integrity, bandwidth optimization, performance monitoring, adversarial robustness, and 2-5x faster inference

This PoC does not evaluate alerting quality or SOC workflows; it validates **preventive authority** and **ML pipeline security**.

---

## 7. Post-PoC Next Steps (Optional)

Upon acceptance, customers may proceed to:

- Extended soak testing
- Integration with SIEM/SOAR for visibility
- High-availability deployment
- Policy tuning and governance controls

---

## 8. Validation Methodology & Testing Framework

This section documents how Battle-Hardened AI's quantitative claims are derived and validated.

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


---

## Final Note

This PoC acceptance framework focuses on **measurable security outcomes**, not feature claims.

If Battle-Hardened AI passes these criteria, it is operating as a **new defensive control class**, not merely another detection tool.
