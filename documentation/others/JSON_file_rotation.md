# JSON File Rotation System

## Overview
Automatic file rotation prevents JSON files from growing to massive sizes (40k+ lines) which cause:
- JSON validation errors
- Performance degradation
- Memory issues on low-spec VPS servers
- Slow dashboard loading

## How It Works

When a JSON file reaches **100MB**, the system automatically:
1. Renames current file with numeric suffix: `file.json` → `file_1.json`
2. Creates fresh empty file: `file.json`
3. Continues writing to new file
4. Preserves all historical data in rotation files

**Example rotation sequence:**
```
file.json (100MB) → file_1.json
file.json (100MB) → file_2.json
file.json (100MB) → file_3.json
... (infinite rotations supported)
```

## Files with Automatic Rotation

### Local Customer Files (Windows EXE / Linux Gateway)

These files rotate at **100MB** on YOUR local system (not the relay server):

#### 1. **threat_log.json** ✅
- **Location:** `server/json/threat_log.json` (local)
- **Purpose:** ML training data (attack detection logs from YOUR network)
- **Rotation:** Every 100MB
- **Writer:** `AI/pcs_ai.py` via `_log_threat()`
- **Status:** **ENABLED** (since v1.0)

#### 2. **network_performance.json** ✅
- **Location:** `server/json/network_performance.json` (local)
- **Purpose:** Network performance metrics (bandwidth, latency, packet loss from YOUR network)
- **Rotation:** Every 100MB
- **Writer:** `AI/network_performance.py` via `save_performance_metrics()` (every 60 seconds)
- **Status:** **ENABLED** (as of this update)
- **Previous Issue:** File grew to 42,969 lines (10+ MB) with no rotation

#### 3. **network_monitor_state.json** ✅
- **Location:** `server/json/network_monitor_state.json` (local)
- **Purpose:** Network monitor state (port scan tracking, ARP spoofing detection on YOUR network)
- **Rotation:** Every 100MB
- **Writer:** `server/network_monitor.py` via `_save_monitor_state()` (every 5 minutes)
- **Status:** **ENABLED** (as of this update)
- **Previous Issue:** File became corrupted at 180 lines (JSON truncation)
- **Note:** Has built-in cleanup every 5 minutes, so rarely reaches rotation size

#### 4. **comprehensive_audit.json** ✅
- **Location:** `server/json/comprehensive_audit.json` (local)
- **Purpose:** System audit logs (YOUR local system events)
- **Rotation:** Every 100MB
- **Writer:** Various system components
- **Status:** **ENABLED** (since v1.0)

### Relay Server Files (Relay VPS - wss://YOUR_RELAY_IP:60001)

These files rotate at **100MB** on the RELAY SERVER (not your local system):

#### 5. **global_attacks.json** ✅
- **Location:** `relay/global_attacks.json` (relay server VPS)
- **Purpose:** Sanitized global attack patterns aggregated from ALL Battle-Hardened AI nodes
- **Rotation:** Every 100MB
- **Writer:** `relay/relay_server.py`
- **Status:** **ENABLED** (relay-only)

#### 6. **ai_training_materials/** (Relay ML Training Data) ✅
- **Location:** `relay/ai_training_materials/` (relay server VPS)
- **Purpose:** Global ML training materials shared across all nodes
- **Rotation:** Separate rotation system (not covered in this document)
- **Writer:** `relay/ai_retraining.py`, `relay/gpu_trainer.py`
- **Status:** **ENABLED** (relay has its own rotation mechanism)

## Files WITHOUT Rotation (Intentionally)

### 1. **drift_baseline.json** ❌
- **Location:** `server/json/drift_baseline.json`
- **Size:** 31,269 lines (normal)
- **Purpose:** ML model drift detection baseline (Layer 9)
- **Why No Rotation:** This file MUST contain complete feature distributions for comparing traffic patterns. Refreshed monthly by ML retraining. Large size is **expected and essential** for AI accuracy.

## Implementation

All rotation is handled by `AI/file_rotation.py`:

```python
from AI.file_rotation import rotate_if_needed

# Before writing data
rotate_if_needed('/path/to/file.json')

# Then write fresh data
with open('/path/to/file.json', 'w') as f:
    json.dump(data, f, indent=2)
```

## Rotation Files Are Preserved
**CRITICAL:** Rotation files are **NEVER automatically deleted**. They contain:
- Historical attack data for ML training
- Compliance audit trails
- Performance trend analysis

If storage becomes a concern:
- Archive rotation files to cold storage
- Do NOT delete (AI will "forget" learned attacks)
- Consider external backup systems

## Storage Impact

Typical growth rates:
- **threat_log.json**: ~1-5 MB/day (active network)
- **network_performance.json**: ~500 KB/day (normal traffic)
- **network_monitor_state.json**: ~100 KB/day (has built-in cleanup)

With 100MB rotation threshold:
- **threat_log.json** rotates every ~20-100 days
- **network_performance.json** rotates every ~200 days
- **network_monitor_state.json** rarely rotates (cleanup prevents bloat)

## Testing Rotation

To test rotation manually:
```powershell
# PowerShell
python -c "from AI.file_rotation import get_rotation_status; import json; print(json.dumps(get_rotation_status('server/json/threat_log.json'), indent=2))"
```

Output shows:
- Current file size
- Percentage full (0-100%)
- Rotation status (needs rotation: true/false)
- List of existing rotation files

## Troubleshooting

### File growing too large before rotation?
- **Cause:** Rotation triggered at 100MB threshold
- **Solution:** Lower `MAX_FILE_SIZE` in `AI/file_rotation.py` (e.g., 50MB for 512MB VPS)

### JSON validation errors?
- **Cause:** File corrupted during write
- **Solution:** Rotation system detects and auto-heals corrupted files (backs up to `.corrupt` and resets)

### Rotation files taking too much space?
- **Solution:** Archive to external storage, compress with `gzip`, or move to S3/cold storage

## Recent Fixes

**2024 Update:**
- ✅ Added rotation to `network_performance.json` (prevented 40k+ line bloat)
- ✅ Added rotation to `network_monitor_state.json` (prevents corruption)
- ✅ Updated documentation to explain rotation behavior
- ✅ Verified `drift_baseline.json` large size is intentional (ML baseline, not bloat)

## Dashboard Impact

With rotation enabled:
- Section 1 (Relay Metrics): No impact
- Section 8 (Network Performance): Loads only current `network_performance.json` (not rotations)
- Section 12 (Threat Intelligence): Uses current `threat_log.json` only
- ML Training: Loads ALL rotations via `load_all_rotations()` for complete attack history

## See Also
- [AI/file_rotation.py](../AI/file_rotation.py) - Rotation implementation
- [AI/network_performance.py](../AI/network_performance.py) - Performance tracking with rotation
- [server/network_monitor.py](../server/network_monitor.py) - Network monitoring with rotation
- [Filepurpose.md](mapping/Filepurpose.md) - Complete file-to-pipeline mapping
