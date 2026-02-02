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

This document is designed for:

- Security architects
- SOC leadership
- Network engineering teams
- Risk and compliance stakeholders

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

## 5. PoC Acceptance Decision

### PoC is Accepted if ALL are true:

- ✅ Battle-Hardened AI functions as a gateway
- ✅ Attacks are detected and attributed
- ✅ Firewall rules are enforced automatically
- ✅ Enforcement is persistent
- ✅ SIEM/SOAR is not required for blocking
- ✅ Legitimate traffic is unaffected

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

This PoC does not evaluate alerting quality or SOC workflows; it validates **preventive authority**.

---

## 7. Post-PoC Next Steps (Optional)

Upon acceptance, customers may proceed to:

- Extended soak testing
- Integration with SIEM/SOAR for visibility
- High-availability deployment
- Policy tuning and governance controls

---

## Final Note

This PoC acceptance framework focuses on **measurable security outcomes**, not feature claims.

If Battle-Hardened AI passes these criteria, it is operating as a **new defensive control class**, not merely another detection tool.
