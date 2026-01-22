#!/usr/bin/env python3
"""Debug script to check if server can start and handle requests"""

import sys
import os

print("="*60)
print("BATTLE-HARDENED AI - SERVER DIAGNOSTIC")
print("="*60)

# Test 1: Check Python version
print(f"\n[1] Python Version: {sys.version}")

# Test 2: Check working directory
print(f"\n[2] Current Directory: {os.getcwd()}")
print(f"    Files in directory: {os.listdir('.')}")

# Test 3: Check if /app exists (Docker detection)
is_docker = os.path.exists('/app')
print(f"\n[3] Running in Docker: {is_docker}")
if is_docker:
    print(f"    /app directory contents: {os.listdir('/app')}")

# Test 4: Try to import AI module
print("\n[4] Attempting to import AI.pcs_ai...")
try:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    import AI.pcs_ai as pcs_ai
    print("    [OK] AI.pcs_ai imported successfully")
    print(f"    [OK] Threat log size: {len(pcs_ai._threat_log)} events")
    print(f"    [OK] Blocked IPs: {len(pcs_ai._blocked_ips)} IPs")
except Exception as e:
    print(f"    [FAIL] FAILED to import AI.pcs_ai: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

# Test 5: Try to import Flask
print("\n[5] Attempting to import Flask...")
try:
    from flask import Flask
    print("    [OK] Flask imported successfully")
except Exception as e:
    print(f"    [FAIL] FAILED to import Flask: {e}")
    sys.exit(1)

# Test 6: Try to create Flask app
print("\n[6] Attempting to create Flask app...")
try:
    app = Flask(__name__)
    print("    [OK] Flask app created successfully")
except Exception as e:
    print(f"    [FAIL] FAILED to create Flask app: {e}")
    sys.exit(1)

# Test 7: Try to add a test route
print("\n[7] Testing Flask route registration...")
try:
    @app.route('/test')
    def test_route():
        return "OK"
    print("    [OK] Test route registered successfully")
except Exception as e:
    print(f"    [FAIL] FAILED to register route: {e}")
    sys.exit(1)

# Test 8: Try to call pcs_ai functions
print("\n[8] Testing AI functions...")
try:
    stats = pcs_ai.get_threat_statistics()
    print(f"    [OK] get_threat_statistics() returned: {stats}")
    
    abilities = pcs_ai.get_ai_abilities_status()
    print(f"    [OK] get_ai_abilities_status() returned {len(abilities)} abilities")
except Exception as e:
    print(f"    [FAIL] FAILED to call AI functions: {e}")
    import traceback
    traceback.print_exc()

print("\n" + "="*60)
print("DIAGNOSTIC COMPLETE")
print("="*60)
print("\nIf all tests passed, the issue is likely in server.py request handling.")
print("Run the server with: python server.py")
print("Then test with: curl -k https://localhost:60000/test")
