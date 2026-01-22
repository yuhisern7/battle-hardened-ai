"""
Universal Path Helper - Works from ANY directory
Dynamically resolves paths whether running from:
- Docker container (/app/)
- AI/ directory (python pcs_ai.py)
- server/ directory (python server.py)
- Root directory (python -m AI.pcs_ai)
- Any subdirectory
"""

import os
import sys

def get_project_root():
    """
    Find project root by looking for .git directory or README.md
    Works from any subdirectory in the project
    """
    # When running as a frozen one-file EXE (PyInstaller), use the
    # directory containing the executable as the project root so that
    # JSON/config files live next to the installed binary instead of
    # inside the temporary extraction directory.
    try:
        if getattr(sys, 'frozen', False):  # type: ignore[attr-defined]
            exe_dir = os.path.dirname(getattr(sys, 'executable', sys.argv[0]))
            return exe_dir
    except Exception:
        # If anything goes wrong, fall back to the normal discovery logic
        pass

    # Start from the directory containing this file (AI/)
    current_dir = os.path.abspath(os.path.dirname(__file__))
    
    # Check if we're in Docker (priority check)
    if os.path.exists('/app'):
        return '/app'
    
    # Walk up directory tree to find project root
    search_dir = current_dir
    while search_dir != os.path.dirname(search_dir):  # Not at filesystem root
        # Look for project markers
        if (os.path.exists(os.path.join(search_dir, '.git')) or
            os.path.exists(os.path.join(search_dir, 'README.md')) or
            os.path.exists(os.path.join(search_dir, 'battle-hardened-ai.code-workspace')) or
            (os.path.exists(os.path.join(search_dir, 'AI')) and 
             os.path.exists(os.path.join(search_dir, 'server')))):
            return search_dir
        
        search_dir = os.path.dirname(search_dir)
    
    # Fallback: If this file is in AI/, project root is parent directory
    if os.path.basename(current_dir) == 'AI':
        return os.path.dirname(current_dir)
    
    # Last resort: use current working directory
    return os.getcwd()


def get_json_dir():
    """Get absolute path to server/json/ directory from anywhere"""
    if os.path.exists('/app/json'):  # Docker
        return '/app/json'
    
    root = get_project_root()
    json_dir = os.path.join(root, 'server', 'json')
    
    # Create if doesn't exist
    os.makedirs(json_dir, exist_ok=True)
    
    return json_dir


def get_ml_models_dir():
    """Get absolute path to AI/ml_models/ directory from anywhere"""
    if os.path.exists('/app/ml_models'):  # Docker
        return '/app/ml_models'
    
    root = get_project_root()
    ml_dir = os.path.join(root, 'AI', 'ml_models')
    
    # Create if doesn't exist
    os.makedirs(ml_dir, exist_ok=True)
    
    return ml_dir


def get_relay_training_dir():
    """Get absolute path to relay/ai_training_materials/ directory from anywhere"""
    root = get_project_root()
    
    if os.path.exists('/app/relay/ai_training_materials'):  # Docker relay
        return '/app/relay/ai_training_materials'
    
    relay_dir = os.path.join(root, 'relay', 'ai_training_materials')
    
    # Create if doesn't exist
    os.makedirs(relay_dir, exist_ok=True)
    
    return relay_dir


def get_crypto_keys_dir():
    """Get absolute path to crypto_keys directory from anywhere"""
    if os.path.exists('/app/ml_models/crypto_keys'):  # Docker
        return '/app/ml_models/crypto_keys'
    
    root = get_project_root()
    crypto_dir = os.path.join(root, 'server', 'crypto_keys')
    
    # Create if doesn't exist
    os.makedirs(crypto_dir, exist_ok=True)
    
    return crypto_dir


def get_json_file(filename):
    """Get absolute path to a specific JSON file in server/json/"""
    return os.path.join(get_json_dir(), filename)


def get_ml_model_file(filename):
    """Get absolute path to a specific ML model file"""
    return os.path.join(get_ml_models_dir(), filename)


def get_relay_file(filename):
    """Get absolute path to a file in relay/ai_training_materials/"""
    return os.path.join(get_relay_training_dir(), filename)


# Convenience functions for common paths
def get_threat_log_file():
    return get_json_file('threat_log.json')

def get_blocked_ips_file():
    return get_json_file('blocked_ips.json')

def get_whitelist_file():
    return get_json_file('whitelist.json')

def get_tracking_data_file():
    return get_json_file('tracking_data.json')

def get_peer_threats_file():
    return get_json_file('peer_threats.json')

def get_ml_training_file():
    return get_json_file('ml_training_data.json')

def get_ml_metrics_file():
    return get_json_file('ml_performance_metrics.json')


# Test function
if __name__ == '__main__':
    print("=== Path Helper Test ===")
    print(f"Project Root: {get_project_root()}")
    print(f"JSON Directory: {get_json_dir()}")
    print(f"ML Models Directory: {get_ml_models_dir()}")
    print(f"Relay Training Directory: {get_relay_training_dir()}")
    print(f"Crypto Keys Directory: {get_crypto_keys_dir()}")
    print(f"\nThreat Log: {get_threat_log_file()}")
    print(f"Blocked IPs: {get_blocked_ips_file()}")
