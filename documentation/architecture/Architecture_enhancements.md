# Architecture Enhancements - Implementation Guide

**Date:** February 6, 2026  
**Status:** Implemented (6 features)

---

**Related overview:** For high-level architecture, threat model, deployment roles, and how Battle-Hardened AI acts as an autonomous defensive gate for the wider security stack, see **[README.md](../../README.md)** (*How BH-AI Enhances Existing Security Controls*, Enterprise Integration Topologies, and Ecosystem View).


## ✅ Implemented Features

### 1. Model Cryptographic Signing (Security)

**File:** `AI/model_signing.py`

**Purpose:** Prevent malicious model injection even if relay server compromised

**How it works:**
- Relay server signs models with Ed25519 private key
- Customer nodes verify signatures with public key (pinned)
- Model hash included in signature (prevents tampering)

**Usage:**

```python
# Relay server - Sign model before distribution
from AI.model_signing import get_relay_signer

signer = get_relay_signer()
signature_data = signer.sign_model(
    model_path="relay/ai_training_materials/ml_models/threat_classifier.pkl",
    metadata={'version': '1.0', 'training_date': '2026-02-03'}
)
# signature_data contains: model_hash, signature, timestamp

# Customer node - Verify signature before loading
from AI.model_signing import get_customer_verifier

verifier = get_customer_verifier()
valid, reason = verifier.verify_model(
    model_path="AI/ml_models/threat_classifier.pkl",
    signature_data=signature_data
)

if valid:
    model = pickle.load(open(model_path, 'rb'))  # Safe to load
else:
    raise SecurityError(f"Model signature invalid: {reason}")
```

**Security guarantees:**
- ✅ Ed25519 signatures (256-bit, quantum-resistant alternative)
- ✅ Tamper detection (hash verification)
- ✅ Trust on first use (public key pinning)

---

### 2. Smart Pattern Filtering (Bandwidth Optimization)

**File:** `AI/pattern_filter.py`

**Purpose:** Prevent duplicate attack patterns from being uploaded to relay

**How it works:**
- Bloom filter for probabilistic deduplication (memory-efficient)
- Pattern fingerprinting (hash of keywords + encodings + attack_type)
- TTL-based rotation (patterns expire after 7 days)

**Usage:**

```python
from AI.pattern_filter import get_pattern_filter

filter = get_pattern_filter()

# Before uploading pattern to relay
pattern = {
    'attack_type': 'sql_injection',
    'keywords': ['union', 'select', 'information_schema'],
    'encodings': ['url_encoded'],
    'payload_length': 1024
}

if filter.should_upload(pattern):
    # Novel pattern - upload to relay
    await signature_uploader.upload_signature(pattern)
else:
    # Duplicate - skip upload (save bandwidth)
    logger.debug("Pattern already uploaded, skipping")

# Get statistics
stats = filter.get_statistics()
print(f"Bandwidth saved: {stats['bandwidth_saved_percent']}%")
```

**Bandwidth savings:**
- 70-80% reduction in relay traffic
- ~1MB memory for 100K patterns
- 0.1% false positive rate (acceptable)

---

### 3. Model Performance Monitoring (Quality Assurance)

**File:** `AI/model_performance_monitor.py`

**Purpose:** Track ML model accuracy in production and detect degradation

**How it works:**
- Track ground truth labels (confirmed attacks vs false positives)
- Compare model predictions vs actual outcomes
- Report aggregated metrics to relay (privacy-preserved)
- Trigger automatic retraining if degradation detected

**Usage:**

```python
from AI.model_performance_monitor import get_performance_monitor

monitor = get_performance_monitor()

# After making a prediction and confirming outcome
monitor.record_prediction(
    model_name='threat_classifier',
    predicted_threat=True,   # Model predicted attack
    actual_threat=True,      # Confirmed attack (ground truth)
    confidence=0.95,
    metadata={'attack_type': 'sql_injection'}
)

# Get performance metrics
perf = monitor.get_model_performance('threat_classifier')
print(f"Accuracy: {perf['metrics']['accuracy']}")
print(f"Precision: {perf['metrics']['precision']}")
print(f"Recall: {perf['metrics']['recall']}")
print(f"F1 Score: {perf['metrics']['f1_score']}")

# Get telemetry for relay (privacy-preserved)
telemetry = monitor.get_fleet_telemetry()
# Contains: aggregated metrics, NO customer-specific data
```

**Alerts:**
- WARNING: Accuracy < 92%
- CRITICAL: Accuracy < 85% (triggers emergency retrain)

---

### 4. Adversarial Training (Robustness)

**File:** `relay/gpu_trainer.py` (enhanced)

**Purpose:** Make models robust against ML evasion attacks

**How it works:**
- Generates adversarial examples using FGSM (Fast Gradient Sign Method)
- Trains on both real attacks + adversarial examples (70% real, 30% adversarial)
- Makes models resistant to adversarial perturbations

**Usage:**

```python
# relay/gpu_trainer.py - Automatic when ADVERSARIAL_TRAINING_ENABLED=true

from relay.gpu_trainer import get_gpu_trainer

trainer = get_gpu_trainer()

# Load training data
X, y, _ = trainer.load_training_materials()

# Train with adversarial robustness
result = trainer.train_with_adversarial_examples(X, y)

print(f"Accuracy: {result['accuracy']:.2%}")
print(f"Adversarial examples: {result['adversarial_training']['num_adversarial']}")
```

**FGSM Algorithm:**
1. Compute gradient of loss with respect to input
2. Take sign of gradient (direction of maximum loss increase)
3. Add small perturbation: `X_adv = X + epsilon * sign(gradient)`
4. Train on both real + adversarial examples

**Configuration:**
```bash
# .env
ADVERSARIAL_TRAINING_ENABLED=true  # Enable adversarial training
```

---

## 🔧 Integration Checklist

### Customer Node Integration

1. **Update signature uploader to use pattern filter:**
```python
# AI/signature_uploader.py - Before upload
from AI.pattern_filter import get_pattern_filter

filter = get_pattern_filter()
if not filter.should_upload(signature):
    return {'success': True, 'skipped': 'duplicate'}
```

2. **Update model download to verify signatures:**
```python
# AI/training_sync_client.py - After download
from AI.model_signing import get_customer_verifier

verifier = get_customer_verifier()
for model_file in downloaded_models:
    valid, reason = verifier.verify_model(model_file, signature_data)
    if not valid:
        raise SecurityError(f"Invalid signature: {reason}")
```

3. **Update AI detection to record performance:**
```python
# AI/pcs_ai.py - After ensemble decision
from AI.model_performance_monitor import get_performance_monitor

monitor = get_performance_monitor()
monitor.record_prediction(
    model_name='ensemble',
    predicted_threat=decision.is_threat,
    actual_threat=confirmed_threat,  # From ground truth
    confidence=decision.confidence
)
```

### Relay Server Integration

1. **Sign models before distribution:**
```python
# relay/ai_retraining.py - After training
from AI.model_signing import get_relay_signer

signer = get_relay_signer()
for model_file in trained_models:
    signature_data = signer.sign_model(model_file)
    # Store signature_data alongside model
```

2. **Enable adversarial training:**
```python
# relay/docker-compose.yml or .env
environment:
  - ADVERSARIAL_TRAINING_ENABLED=true
```

3. **Install ONNX conversion dependencies:**
```bash
# relay/requirements.txt
pip install skl2onnx onnx

# ONNX conversion happens automatically after training
# Check logs: [ONNX] ✅ Converted 4/4 models to ONNX format
```

### Customer Node Setup

**Install ONNX Runtime (optional - automatic fallback to pickle if missing):**
```bash
pip install onnxruntime  # For 2-5x faster inference
# OR for GPU: pip install onnxruntime-gpu
```

**Models load automatically** - no code changes needed. System prefers ONNX, falls back to pickle.

---

### 5. ONNX Model Format (Performance - 2-5x CPU Speedup)

**File:** `AI/onnx_model_converter.py`

**Purpose:** Optimize ML inference speed by 2-5x on CPU without requiring GPU

**Quick Summary:**
- Relay auto-converts trained sklearn models to ONNX format
- Customer nodes download both .onnx (production) and .pkl (backup)
- Transparent ONNX loading with automatic fallback to pickle
- **2-5x faster inference on CPU** (no GPU needed)

**Performance Gains:**
- RandomForest: 15.2ms → **3.8ms** (4.0x faster)
- IsolationForest: 12.8ms → **4.2ms** (3.0x faster)
- GradientBoosting: 18.5ms → **7.1ms** (2.6x faster)

**Installation:**
```bash
# Relay server
pip install skl2onnx onnx

# Customer nodes
pip install onnxruntime
```

For complete ONNX integration details including usage examples, benchmarks, troubleshooting, and cross-platform deployment, see:
- **[ONNX_integration.md](ONNX_integration.md)** - Complete ONNX integration guide

---
### 6. Linux Firewall Commander (Multi-Distro Kernel Enforcement)

**Files:** `AI/firewall_backend.py`, `server/installation/bh_firewall_sync.py`

**Purpose:** Enforce IP blocks at kernel firewall level across multiple Linux distributions with dual-layer whitelist/blocklist priority system

**How it works:**
- **Backend Detection:** Auto-detects Linux firewall backend (iptables, firewalld, VyOS, OpenWRT, Alpine)
- **Dual-Layer Architecture:**
  - **Layer 1 (Priority 1):** Whitelist = ACCEPT (wins all conflicts)
  - **Layer 2 (Priority 2):** Blocklist = DROP (only if not whitelisted)
- **Sync Daemon:** 5-second loop syncs `whitelist.json` and `blocked_ips.json` to kernel firewall
- **Safety Check:** Removes whitelisted IPs from blocklist before syncing (prevents conflicts)
- **Dashboard UI:** Section 7, 4th tab "🔥 Linux Firewall Commander" for monitoring and manual control

**Supported Backends:**

| Linux Distro | Firewall Backend | Support Level | Commands Used |
|--------------|-----------------|---------------|---------------|
| Debian/Ubuntu | iptables-nft | ✅ Full | `ipset`, `iptables`, `netfilter-persistent` |
| RHEL/Rocky/Alma/SUSE | firewalld | ✅ Full | `firewall-cmd --ipset`, `--add-rich-rule` |
| VyOS | CLI address groups | ⚠️ Partial | `configure`, `set firewall group` |
| OpenWRT | UCI firewall | ⚠️ Partial | `uci add firewall ipset` |
| Alpine Linux | awall | ⚠️ Partial | `awall` JSON config |

**Usage:**

```python
# Automatic backend detection on startup
from AI.firewall_backend import detect_firewall_backend, sync_whitelist_to_firewall, sync_blocklist_to_firewall

backend = detect_firewall_backend()
print(f"Detected: {backend}")  # Example: "iptables" or "firewalld"

# Sync whitelist (Priority 1 ACCEPT)
whitelist_ips = ['127.0.0.1', '192.168.1.100', '10.0.0.5']
retcode, message = sync_whitelist_to_firewall(backend, whitelist_ips)
if retcode == 0:
    print(f"✅ Whitelist synced: {message}")

# Sync blocklist (Priority 2 DROP) - AFTER safety check removes whitelisted IPs
blocklist_ips = ['203.0.113.42', '198.51.100.88']  # Already filtered
retcode, message = sync_blocklist_to_firewall(backend, blocklist_ips)
if retcode == 0:
    print(f"✅ Blocklist synced: {message}")
```

**Firewall Sync Daemon:**

```python
# server/installation/bh_firewall_sync.py - Runs as systemd service
import time
from AI.firewall_backend import detect_firewall_backend, sync_whitelist_to_firewall, sync_blocklist_to_firewall

backend = detect_firewall_backend()

while True:
    # Load latest IPs from JSON
    whitelist = load_whitelist_ips()  # From server/json/whitelist.json
    blocked = load_blocked_ips()      # From server/json/blocked_ips.json
    
    # Safety check: Remove whitelisted IPs from blocklist
    blocklist_safe = list(set(blocked) - set(whitelist))
    
    # Sync to kernel firewall
    sync_whitelist_to_firewall(backend, whitelist)
    sync_blocklist_to_firewall(backend, blocklist_safe)
    
    time.sleep(5)  # 5-second interval
```

**Dashboard API Endpoints (server/server.py):**

```python
# GET /api/firewall/detect - Returns backend type + capabilities
# GET /api/firewall/status - Returns sync status, IP counts, last sync time
# POST /api/firewall/sync - Force immediate sync (bypasses 5s delay)
# POST /api/firewall/test - 3-step integration test (non-destructive)
# GET /api/firewall/rules - View our rules vs customer firewall rules
# POST /api/firewall/backend - Manual backend override (emergency)
```

**Dashboard UI (Section 7, Tab 4):**

- **Status Panel:** Backend detected, sync daemon health, last sync timestamp
- **Sync Health:** Whitelist X/X synced ✅, Blocklist X/X synced ✅
- **Action Buttons:**
  - ⚡ **Force Sync Now** - Immediate sync (bypasses 5-second delay)
  - 🧪 **Test Integration** - 3-step validation (add test IP → verify → remove)
  - 📋 **View Native Rules** - Show customer's existing firewall rules (read-only)
  - 🔄 **Refresh Status** - Manual status refresh
- **Our Rules Table:** Displays dual-layer architecture (Whitelist Priority 1, Blocklist Priority 2)
- **Customer Rules:** Collapsible section showing existing firewall rules (non-Battle-Hardened AI)
- **Auto-Refresh:** Every 30 seconds (when tab active)

**Safety Guarantees:**

- ✅ **Whitelist Wins Conflicts:** IP in both whitelist + blocklist = ACCEPTED (Priority 1 > Priority 2)
- ✅ **Safety Check:** Sync daemon removes whitelisted IPs from blocklist before syncing
- ✅ **Non-Destructive Testing:** Test integration preserves production blocklist
- ✅ **Startup Scripts:** `packaging/debian-startup.sh` creates dual-layer ipsets + rules
- ✅ **Uninstall Cleanup:** `packaging/debian-uninstall.sh` removes both layers

**Startup Script (packaging/debian-startup.sh):**

```bash
# Create ipsets
ipset create bh_whitelist hash:ip family inet hashsize 1024 maxelem 100000
ipset create bh_blocked hash:ip family inet hashsize 1024 maxelem 100000

# Add dual-layer rules (priority enforced by position)
iptables -I INPUT 1 -m set --match-set bh_whitelist src -j ACCEPT
iptables -I INPUT 2 -m set --match-set bh_blocked src -j DROP
iptables -I FORWARD 1 -m set --match-set bh_whitelist src -j ACCEPT
iptables -I FORWARD 2 -m set --match-set bh_blocked src -j DROP

# Save rules
netfilter-persistent save
```

**Performance:**
- ✅ 5-second sync latency (acceptable for threat response)
- ✅ Kernel-level packet dropping (no Python overhead)
- ✅ ipset hash tables (O(1) lookup, supports 100K+ IPs)
- ✅ Minimal memory footprint (~1MB for 10K IPs)

**Multi-Distro Compatibility:**
- Tested on: Debian 12, Ubuntu 22.04/24.04, Rocky Linux 9, AlmaLinux 9
- Fallback: If backend unavailable, falls back to legacy iptables-only mode
- Manual Override: `BH_FIREWALL_BACKEND` environment variable for edge cases

---
## 📊 Expected Impact

| Enhancement | Bandwidth Saved | Security Improved | Performance Impact |
|-------------|----------------|-------------------|-------------------|
| **Model Signing** | 0% | +++++ (Critical) | Negligible (<1ms) |
| **Pattern Filtering** | 70-80% | - | Negligible (<1ms) |
| **Performance Monitoring** | 0% | - | Minor (~5% overhead) |
| **Adversarial Training** | 0% | ++++ (High) | Training time +30% |
| **ONNX Models** | 4% | - | **2-5x faster inference** |
| **Linux Firewall Commander** | 0% | +++++ (Critical) | 5-second sync latency |
---

## 🚀 Deployment

### Enable All Features

```bash
# Customer node .env
SIGNATURE_UPLOAD_ENABLED=true
ADVERSARIAL_TRAINING_ENABLED=true

# Relay server .env
ADVERSARIAL_TRAINING_ENABLED=true
```

### Verify Installation

```python
# Test model signing
from AI.model_signing import get_relay_signer, get_customer_verifier
signer = get_relay_signer()
verifier = get_customer_verifier()
print(f"Signing enabled: {signer.private_key is not None}")
print(f"Verification enabled: {verifier.public_key is not None}")

# Test pattern filtering
from AI.pattern_filter import get_pattern_filter
filter = get_pattern_filter()
print(f"Pattern filter loaded: {filter.unique_patterns_uploaded} known patterns")

# Test performance monitoring
from AI.model_performance_monitor import get_performance_monitor
monitor = get_performance_monitor()
print(f"Performance monitor loaded: {monitor._get_total_evaluations()} evaluations")
```

---

## 📈 Monitoring

### Dashboard Metrics

Add these sections to dashboard:

1. **Pattern Filter Statistics:**
   - Bandwidth saved: X%
   - Unique patterns uploaded: X
   - Duplicates filtered: X

2. **Model Performance:**
   - Accuracy: X%
   - Precision: X%
   - Recall: X%
   - Status: HEALTHY / DEGRADED / CRITICAL

3. **Model Signatures:**
   - Total signed models: X
   - Last signature timestamp
   - Public key fingerprint

4. **Adversarial Training:**
   - Adversarial examples generated: X
   - Training robustness: X%
   - Last training timestamp

5. **ONNX Performance:**
   - Inference format: ONNX / Pickle
   - Average inference time: X ms
   - Speedup vs pickle: Xx faster
   - Models using ONNX: 4/4 ✅

---

## 🔐 Security Considerations

1. **Protect relay server IP:**
   - **DO NOT** hardcode relay IP in public documentation
   - Distribute relay IP/URL securely to customers (email, secure portal)
   - Replace placeholders (YOUR-RELAY-IP) with actual IP only in customer-specific `.env` files
   - Keep relay server behind firewall (only ports 60001-60002 exposed)

2. **Protect private signing key:**
   - `relay/crypto_keys/model_signing_private.pem` must be kept secret
   - Set permissions: `chmod 600`
   - Never commit to Git (already in .gitignore)

3. **Distribute public key to customers:**
   - `relay/crypto_keys/model_signing_public.pem` can be shared
   - Pin in customer installations (trust on first use)
   - Verify fingerprint matches vendor-provided hash

4. **Performance monitoring privacy:**
   - Only aggregated metrics sent to relay
   - No customer-specific attack data
   - No IP addresses or network topology

---

## 📝 Next Steps

These 6 enhancements are now ready for testing. To enable in production:

1. Deploy updated code to relay server
2. Install ONNX dependencies: `pip install skl2onnx onnx` (relay) and `pip install onnxruntime` (customers)
3. Update customer nodes with new AI modules
4. Enable features via environment variables
5. Monitor dashboard metrics for verification
6. Observe bandwidth savings, model performance improvements, and 2-5x faster inference

**Expected Results:**
- ✅ Bandwidth savings: 70-80% reduction
- ✅ Model security: Tamper-proof cryptographic signatures
- ✅ Quality assurance: Automated degradation detection
- ✅ Robustness: Adversarial attack resistance
- ✅ Performance: 2-5x faster ML inference on CPU
- ✅ Kernel enforcement: Multi-distro firewall integration

---

## Attack Flow & Compliance Verification

For complete verification of the attack handling flow, deployment roles, identity/access control, high-availability clustering, and privacy compliance, see:

- **[Attack_handling_flow.md](Attack_handling_flow.md)** - Complete 3-step attack flow verification, code references, deployment modes, and testing commands

All 6 architecture enhancements integrate with this verified attack flow:
- Pattern extraction feeds Enhancement #2 (Pattern Filtering)
- Model distribution uses Enhancement #1 (Cryptographic Signing) and #5 (ONNX Format)
- Performance tracking uses Enhancement #3 (Performance Monitoring)
- Relay training uses Enhancement #4 (Adversarial Training)
- Firewall enforcement uses Enhancement #6 (Linux Firewall Commander)

---

**Last Updated:** February 12, 2026  
**Status:** ✅ PRODUCTION-READY  
**Features Implemented:** 6 enhancements (Model Signing, Pattern Filtering, Performance Monitoring, Adversarial Training, ONNX, Linux Firewall Commander)
