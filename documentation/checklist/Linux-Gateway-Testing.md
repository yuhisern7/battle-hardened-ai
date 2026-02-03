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
- Implements 5 production-ready ML pipeline security enhancements (cryptographic signing, smart filtering, performance monitoring, adversarial training, ONNX optimization)

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

### I. Architecture Enhancements Validation

**Objective:** Verify the 5 ML pipeline security enhancements are operational.

#### Enhancement #1: Model Cryptographic Signing

- [ ] Check logs for model signature verification:
  ```bash
  docker logs battle-hardened-ai 2>&1 | grep "Model signature verified"
  ```

- [ ] Verify public key exists:
  ```bash
  ls -la /var/lib/battle-hardened-ai/server/crypto_keys/relay_public_key.pem
  ```

- [ ] Test tamper detection (optional):
  - Modify a `.pkl` model file
  - Restart BH-AI
  - Expected: "Signature verification failed" error in logs

**Expected:** Models load with cryptographic verification (MITRE T1574.012 defense).

#### Enhancement #2: Smart Pattern Filtering

- [ ] Check pattern filter statistics via API:
  ```bash
  curl -k https://localhost:60000/api/pattern-filter/stats
  ```

- [ ] Verify Bloom filter state file exists:
  ```bash
  ls -la /var/lib/battle-hardened-ai/server/json/pattern_filter_state.json
  ```

- [ ] If relay enabled, confirm bandwidth savings (70-80% deduplication)

**Expected:** Pattern deduplication active, reducing relay bandwidth consumption.

#### Enhancement #3: Model Performance Monitoring

- [ ] Check ML performance metrics via API:
  ```bash
  curl -k https://localhost:60000/api/ml-performance
  ```

- [ ] Verify performance data persists:
  ```bash
  cat /var/lib/battle-hardened-ai/server/json/ml_performance.json
  ```

- [ ] Check dashboard displays accuracy metrics (accuracy, precision, F1 score)

**Expected:** ML performance tracking active (MITRE T1565.001 defense - detects model poisoning).

#### Enhancement #4: Adversarial Training

- [ ] (Relay-side feature) If testing relay server:
  - Check logs for "Generated adversarial examples" during training
  - Verify FGSM algorithm executed

- [ ] Customer gateway: Models received from relay include adversarial robustness

**Expected:** Models resistant to ML evasion attacks (MITRE T1562.004 defense).

#### Enhancement #5: ONNX Model Format (Performance)

- [ ] Check logs for ONNX model loading:
  ```bash
  docker logs battle-hardened-ai 2>&1 | grep "Loading ONNX model"
  docker logs battle-hardened-ai 2>&1 | grep "Using ONNX Runtime"
  ```

- [ ] Verify ONNX models exist:
  ```bash
  ls -la /var/lib/battle-hardened-ai/AI/ml_models/*.onnx
  ```

- [ ] Check inference performance (should be 2-5x faster than pickle):
  ```bash
  docker logs battle-hardened-ai 2>&1 | grep "ONNX inference time"
  ```

- [ ] Test fallback: Delete `.onnx` file, verify system falls back to `.pkl` models

**Expected:** 2-5x faster CPU inference, 40% lower CPU usage, no GPU required.

#### Architecture Enhancements Summary

- [ ] All 5 enhancements operational without errors
- [ ] Performance improvements verified (2-5x faster inference)
- [ ] Security guarantees active (model signing, adversarial robustness, performance monitoring)
- [ ] Graceful fallbacks work (ONNX → pickle, missing signatures → warnings)
- [ ] Bandwidth savings confirmed (70-80% pattern deduplication if relay enabled)

**For detailed technical documentation:**
- [Architecture_Enhancements.md](../architecture/Architecture_Enhancements.md)
- [ONNX_Integration.md](../architecture/ONNX_Integration.md)

---

## Acceptance Criteria (Pass / Fail)

The deployment **passes** if all are true:

- ✅ BH-AI routes traffic
- ✅ BH-AI detects real attacks
- ✅ BH-AI identifies attacker IPs
- ✅ BH-AI blocks attackers via firewall
- ✅ Blocking persists across restarts
- ✅ No dependency on SIEM/SOAR for enforcement
- ✅ 5 architecture enhancements operational (model signing, pattern filtering, performance monitoring, ONNX optimization)

If any of the above fail, the deployment is **not production-ready**.

---

## What This Testing Proves

Passing this checklist proves that Battle-Hardened AI is operating as:

- A **first-layer gateway**
- An **autonomous firewall commander**
- A **pre-execution enforcement system**
- A **stateful, learning defense control**
- A **production-hardened ML security platform** with cryptographic integrity, bandwidth optimization, performance monitoring, adversarial robustness, and 2-5x faster inference

This is the minimum bar for enterprise and regulated environments.
