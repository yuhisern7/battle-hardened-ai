# Linux Gateway Testing Checklist

**Battle-Hardened AI – First-Layer Gateway Validation**

---

This document defines the mandatory testing steps to validate Battle-Hardened AI when deployed as a Linux gateway / router in front of protected systems.

The goal of this testing is to prove that Battle-Hardened AI:

- Operates as a functional network gateway
- Observes and attributes hostile activity
- Commands the local firewall autonomously
- Blocks attackers before protected services are reached
- Does not depend on SIEM/SOAR for enforcement

---

## Steps After Purchasing a Cloud VM (Before Testing)

Once a cloud VM is provisioned, complete the following steps before running any attack tests.

### 1. Provision the Correct VM Topology

Ensure the VM has:

- **Linux OS** (Ubuntu 22.04 LTS recommended)
- **Two network interfaces:**
  - **NIC 1 (WAN)** – Internet-facing / upstream
  - **NIC 2 (LAN)** – Protected subnet
- **Root or sudo access**

The VM will act as a router and firewall enforcement point, not just an application host.

---

### 2. Prepare the Operating System

On the Battle-Hardened AI VM:

- Update system packages
- Confirm kernel supports:
  - netfilter (iptables or nftables)
  - eBPF
- Enable IP forwarding:

```bash
sysctl net.ipv4.ip_forward=1
```

Verify:

```bash
cat /proc/sys/net/ipv4/ip_forward
# Expected output: 1
```

---

### 3. Install Battle-Hardened AI

- Install the provided `.deb` or `.rpm` package
- Confirm:
  - Docker is installed and running
  - Battle-Hardened AI container is running
  - Container uses host networking

Verify:

```bash
docker ps
```

---

### 4. Configure Firewall Enforcement

Follow `FIREWALL_ENFORCEMENT.md` to ensure:

- Firewall sync is enabled
- BH-AI is allowed to create, update, and remove rules
- iptables or nftables rules are applied on the host (not inside Docker only)

---

### 5. Route Protected Systems Through BH-AI

For every protected VM or subnet:

- Set default gateway = BH-AI LAN IP
- Confirm outbound connectivity works

From a protected system:

```bash
ping 8.8.8.8
curl https://example.com
```

If traffic flows, BH-AI is now acting as the gateway.

---

## Required Testing Checklist

All items below must pass for a successful gateway validation.

### A. Gateway & Routing Validation

**Objective:** Prove BH-AI is functioning as the network gateway.

- [ ] Protected system routes traffic through BH-AI
- [ ] Internet access works normally
- [ ] No packet loss under normal load

**Failure here means BH-AI is not yet a router.**

---

### B. Traffic Visibility & Attribution

**Objective:** Prove BH-AI can see and attribute traffic.

From an external attacker system (e.g., Kali):

- [ ] Perform port scan:
  ```bash
  nmap -p 1-1000 <target>
  ```

- [ ] Attempt repeated login failures
- [ ] Send malformed HTTP requests

**Expected results:**

- [ ] Attacker IP visible in dashboard
- [ ] Events logged with timestamps
- [ ] Detection layers triggered

**If attacker IP is missing, visibility is broken.**

---

### C. Attack Detection Validation

**Objective:** Prove attacks are correctly identified.

Trigger at least one real attack:

- SQL injection attempt
- Command injection attempt
- Brute-force login attempt

**Expected results:**

- [ ] Threat classification applied
- [ ] Detection confidence recorded
- [ ] Event written to threat logs

**This validates the detection pipeline.**

---

### D. Firewall Command & Rule Creation

**Objective:** Prove BH-AI commands the firewall directly.

After an attack is detected:

- [ ] Attacker IP appears in `blocked_ips.json`
- [ ] Reason and timestamp recorded

Verify on the BH-AI host:

```bash
iptables -L -n | grep <attacker_ip>
# or
nft list ruleset | grep <attacker_ip>
```

**If no rule exists, enforcement is not active.**

---

### E. Enforcement Validation (Critical)

**Objective:** Prove attackers are actually blocked.

From attacker system:

- [ ] Attempt to reconnect
- [ ] Attempt ping / curl / scan

**Expected:**

- ❌ Connection fails
- ❌ Requests timeout or drop

From a legitimate client:

- [ ] Access still works normally

**This proves selective blocking, not blanket denial.**

---

### F. Independence from SIEM / SOAR

**Objective:** Prove enforcement works without integrations.

- [ ] Disable outbound syslog/webhooks (optional)
- [ ] Trigger another attack

**Expected:**

- [ ] Attack still blocked locally
- [ ] Firewall rules still applied

**This confirms BH-AI is self-enforcing.**

---

### G. Persistence & Recovery Test

**Objective:** Prove state survives restarts.

- [ ] Restart BH-AI container
- [ ] Restart the VM

After restart:

- [ ] Firewall rules still present
- [ ] Attacker still blocked
- [ ] Trust state preserved

**Failure here indicates stateless defense (not acceptable).**

---

### H. False Positive Sanity Check

**Objective:** Ensure legitimate traffic is not blocked.

- [ ] Normal browsing works
- [ ] API requests succeed
- [ ] No unexplained blocks

**This validates semantic + causal filtering.**

---

## Acceptance Criteria (Pass / Fail)

The deployment **passes** if all are true:

- ✅ BH-AI routes traffic
- ✅ BH-AI detects real attacks
- ✅ BH-AI identifies attacker IPs
- ✅ BH-AI blocks attackers via firewall
- ✅ Blocking persists across restarts
- ✅ No dependency on SIEM/SOAR for enforcement

If any of the above fail, the deployment is **not production-ready**.

---

## What This Testing Proves

Passing this checklist proves that Battle-Hardened AI is operating as:

- A **first-layer gateway**
- An **autonomous firewall commander**
- A **pre-execution enforcement system**
- A **stateful, learning defense control**

This is the minimum bar for enterprise and regulated environments.
