#!/usr/bin/env python3
"""Quick test of path_helper from any directory"""

import sys
import os

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from AI.path_helper import *

print("=== Path Helper Test ===")
print(f"Current Working Dir: {os.getcwd()}")
print(f"Project Root: {get_project_root()}")
print(f"JSON Directory: {get_json_dir()}")
print(f"ML Models Directory: {get_ml_models_dir()}")
print(f"Relay Training Directory: {get_relay_training_dir()}")
print(f"\nSample Files:")
print(f"  Threat Log: {get_threat_log_file()}")
print(f"  Blocked IPs: {get_blocked_ips_file()}")
print("\n✅ All paths resolved successfully!")
