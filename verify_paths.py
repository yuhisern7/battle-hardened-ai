#!/usr/bin/env python3
"""Verify all AI files use path_helper correctly"""

import os
import re

AI_DIR = 'AI'
CRITICAL_FILES = [
    'pcs_ai.py',
    'real_honeypot.py', 
    'compliance_reporting.py',
    'user_tracker.py',
    'traffic_analyzer.py',
    'pcap_capture.py',
    'advanced_visualization.py',
    'network_performance.py',
    'reputation_tracker.py',
    'zero_trust.py',
    'vulnerability_manager.py',
    'soar_workflows.py',
    'soar_api.py',
    'tls_fingerprint.py',
    'behavioral_heuristics.py',
    'causal_inference.py',
    'trust_graph.py',
    'file_analyzer.py',
    'cloud_security.py',
    'backup_recovery.py',
    'alert_system.py',
    'asset_inventory.py',
    'adaptive_honeypot.py'
]

def check_file(filepath):
    """Check if file uses path_helper or has hardcoded paths"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        has_path_helper = 'path_helper' in content
        has_hardcoded = bool(re.search(r'(\.\./server/json|/app/json)', content))
        
        return {
            'uses_path_helper': has_path_helper,
            'has_hardcoded': has_hardcoded
        }
    except Exception as e:
        return {'error': str(e)}

def main():
    print("=" * 80)
    print("PATH VERIFICATION REPORT")
    print("=" * 80)
    
    updated = []
    needs_fix = []
    missing = []
    
    for filename in CRITICAL_FILES:
        filepath = os.path.join(AI_DIR, filename)
        
        if not os.path.exists(filepath):
            missing.append(filename)
            continue
        
        result = check_file(filepath)
        
        if 'error' in result:
            print(f"❌ ERROR: {filename} - {result['error']}")
            continue
        
        if result['uses_path_helper']:
            updated.append(filename)
        elif result['has_hardcoded']:
            needs_fix.append(filename)
    
    print(f"\n✅ UPDATED WITH path_helper ({len(updated)}):")
    for f in updated:
        print(f"   ✓ {f}")
    
    print(f"\n❌ STILL HAS HARDCODED PATHS ({len(needs_fix)}):")
    for f in needs_fix:
        print(f"   ✗ {f}")
    
    if missing:
        print(f"\n⚠️  MISSING FILES ({len(missing)}):")
        for f in missing:
            print(f"   ? {f}")
    
    print(f"\n" + "=" * 80)
    print(f"SUMMARY: {len(updated)}/{len(CRITICAL_FILES)} files updated")
    print(f"STATUS: {'✅ ALL DONE!' if len(needs_fix) == 0 else '⚠️  NEEDS FIXING'}")
    print("=" * 80)
    
    return len(needs_fix) == 0

if __name__ == '__main__':
    success = main()
    exit(0 if success else 1)
