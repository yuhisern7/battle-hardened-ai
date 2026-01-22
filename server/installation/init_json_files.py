#!/usr/bin/env python3
"""
Initialize all required JSON files for Battle-Hardened AI
Run this before starting the server for the first time
Works on Windows/Linux/macOS - creates files relative to installation directory
"""

import os
import json
from datetime import datetime, timezone

def get_json_dir():
    """Get absolute path to json directory"""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    # Go up one level from installation/ to server/, then into json/
    json_dir = os.path.join(script_dir, '..', 'json')
    return json_dir

def ensure_dir(directory):
    """Create directory if it doesn't exist"""
    os.makedirs(directory, exist_ok=True)
    print(f"[OK] Directory: {directory}")

def create_json_file(filepath, default_content):
    """Create JSON file if it doesn't exist"""
    if os.path.exists(filepath):
        print(f"[SKIP] Exists: {os.path.basename(filepath)}")
        return
    
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    
    with open(filepath, 'w') as f:
        json.dump(default_content, f, indent=2)
    
    print(f"[OK] Created: {os.path.basename(filepath)}")

def initialize_all_json_files():
    """Initialize all required JSON files"""
    
    print("=" * 80)
    print("Battle-Hardened AI - JSON File Initialization")
    print("=" * 80)
    print()
    
    json_dir = get_json_dir()
    ensure_dir(json_dir)
    print()
    
    # Stage 1: Data Ingestion
    print("Stage 1: Data Ingestion")
    create_json_file(os.path.join(json_dir, 'connected_devices.json'), [])
    create_json_file(os.path.join(json_dir, 'device_history.json'), [])
    create_json_file(os.path.join(json_dir, 'network_monitor_state.json'), {
        "running": False,
        "packets_captured": 0,
        "last_updated": datetime.now(timezone.utc).isoformat()
    })
    print()
    
    # Stage 2: Threat Detection
    print("Stage 2: Threat Detection")
    create_json_file(os.path.join(json_dir, 'threat_log.json'), [])
    create_json_file(os.path.join(json_dir, 'honeypot_attacks.json'), [])
    create_json_file(os.path.join(json_dir, 'dns_security.json'), {})
    create_json_file(os.path.join(json_dir, 'tls_fingerprints.json'), {})
    create_json_file(os.path.join(json_dir, 'behavioral_metrics.json'), {})
    create_json_file(os.path.join(json_dir, 'attack_sequences.json'), {})
    create_json_file(os.path.join(json_dir, 'network_graph.json'), {"nodes": [], "edges": []})
    create_json_file(os.path.join(json_dir, 'lateral_movement_alerts.json'), [])
    create_json_file(os.path.join(json_dir, 'drift_baseline.json'), {})
    create_json_file(os.path.join(json_dir, 'drift_reports.json'), [])
    create_json_file(os.path.join(json_dir, 'causal_analysis.json'), [])
    create_json_file(os.path.join(json_dir, 'trust_graph.json'), {"nodes": {}, "edges": []})
    create_json_file(os.path.join(json_dir, 'tracked_users.json'), {})
    create_json_file(os.path.join(json_dir, 'file_analysis.json'), [])
    create_json_file(os.path.join(json_dir, 'crypto_mining.json'), [])
    create_json_file(os.path.join(json_dir, 'network_performance.json'), {})
    print()
    
    # Stage 3: Ensemble Voting
    print("Stage 3: Ensemble Voting")
    create_json_file(os.path.join(json_dir, 'decision_history.json'), [])
    create_json_file(os.path.join(json_dir, 'meta_engine_config.json'), {
        "weights": {},
        "thresholds": {"CRITICAL": 0.9, "DANGEROUS": 0.7, "SUSPICIOUS": 0.5}
    })
    create_json_file(os.path.join(json_dir, 'fp_filter_config.json'), {
        "enabled": True,
        "min_confidence": 0.7
    })
    print()
    
    # Stage 4: Response Execution
    print("Stage 4: Response Execution")
    create_json_file(os.path.join(json_dir, 'blocked_ips.json'), {"blocked_ips": []})
    create_json_file(os.path.join(json_dir, 'blocked_devices.json'), [])
    create_json_file(os.path.join(json_dir, 'blocked_peers.json'), [])
    create_json_file(os.path.join(json_dir, 'whitelist.json'), [])
    create_json_file(os.path.join(json_dir, 'comprehensive_audit.json'), [])
    create_json_file(os.path.join(json_dir, 'integrity_violations.json'), [])
    print()
    
    # Stage 5: Training Extraction
    print("Stage 5: Training Extraction")
    create_json_file(os.path.join(json_dir, 'honeypot_patterns.json'), [])
    create_json_file(os.path.join(json_dir, 'local_threat_intel.json'), [])
    create_json_file(os.path.join(json_dir, 'reputation_export.json'), {})
    print()
    
    # Stage 6: Relay Sharing
    print("Stage 6: Relay Sharing")
    create_json_file(os.path.join(json_dir, 'peer_threats.json'), [])
    print()
    
    # Stage 7: Continuous Learning
    print("Stage 7: Continuous Learning")
    create_json_file(os.path.join(json_dir, 'ml_training_data.json'), [])
    create_json_file(os.path.join(json_dir, 'ml_performance_metrics.json'), {})
    create_json_file(os.path.join(json_dir, 'model_lineage.json'), {})
    create_json_file(os.path.join(json_dir, 'tracking_data.json'), {})
    print()
    
    # Enterprise Extensions
    print("Enterprise Extensions")
    create_json_file(os.path.join(json_dir, 'soar_incidents.json'), [])
    create_json_file(os.path.join(json_dir, 'cloud_findings.json'), [])
    create_json_file(os.path.join(json_dir, 'backup_status.json'), {})
    create_json_file(os.path.join(json_dir, 'recovery_tests.json'), [])
    create_json_file(os.path.join(json_dir, 'sbom.json'), {"components": []})
    create_json_file(os.path.join(json_dir, 'governance_policies.json'), [])
    create_json_file(os.path.join(json_dir, 'approval_requests.json'), [])
    create_json_file(os.path.join(json_dir, 'formal_threat_model.json'), {})
    print()
    
    # Create subdirectories
    print("Subdirectories")
    ensure_dir(os.path.join(json_dir, 'forensic_reports'))
    ensure_dir(os.path.join(json_dir, 'compliance_reports'))
    print()
    
    print("=" * 80)
    print("All JSON files initialized!")
    print(f"Location: {json_dir}")
    print("=" * 80)
    print()
    print("Next steps:")
    print("1. Windows: python server.py")
    print("2. Linux/Docker: docker compose up")
    print()

if __name__ == '__main__':
    initialize_all_json_files()
