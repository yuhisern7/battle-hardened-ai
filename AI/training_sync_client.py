#!/usr/bin/env python3
"""
ML Model Sync Client
Downloads ONLY pre-trained ML models from relay server (280 KB total)

Subscribers get:
- Pre-trained ML models (anomaly_detector.pkl, threat_classifier.pkl, etc.)
- NO raw exploit data (security risk)
- NO ExploitDB database (stays on relay server)
- Models are trained centrally on relay with 825 MB+ training data
- Subscribers just use models for inference (detect attacks)
"""

import os
import json
import logging
import requests
import pickle
from datetime import datetime
from typing import Dict, List, Optional

from AI.path_helper import get_ml_models_dir

logger = logging.getLogger(__name__)

TRAINING_SYNC_ENABLED = os.getenv("TRAINING_SYNC_ENABLED", "true").lower() == "true"
TRAINING_SYNC_VERIFY_TLS = os.getenv("TRAINING_SYNC_VERIFY_TLS", "true").lower() == "true"


class TrainingSyncClient:
    """Downloads ONLY pre-trained ML models from relay server (not raw training data)"""
    
    def __init__(self, relay_url: str = None):
        """
        Args:
            relay_url: Relay server URL (e.g., https://vps-ip:60002)
        """
        self.relay_url = relay_url or os.getenv('RELAY_URL', 'https://localhost:60002')
        # Store downloaded models where the AI engine expects them
        # In Docker this resolves to /app/ml_models, matching pcs_ai._ML_MODELS_DIR.
        self.local_ml_dir = get_ml_models_dir()

        # Create local directory for models only
        os.makedirs(self.local_ml_dir, exist_ok=True)
    
    
    def sync_ml_models(self):
        """Download ONLY pre-trained ML models (280 KB total) - NOT raw training data"""
        if not TRAINING_SYNC_ENABLED:
            logger.info("TrainingSyncClient disabled via TRAINING_SYNC_ENABLED=false")
            return

        logger.info(f"🔄 Syncing ML models from {self.relay_url}")
        
        # Download ONLY the trained models
        self.download_ml_models()
        
        logger.info("✅ ML model sync complete (no raw exploit data downloaded)")
    
    
    def download_ml_models(self):
        """Download pre-trained ML models from relay server"""
        models = ["anomaly_detector", "threat_classifier", "ip_reputation", "feature_scaler"]
        
        for model_name in models:
            try:
                response = requests.get(
                    f"{self.relay_url}/models/{model_name}",
                    timeout=30,
                    verify=TRAINING_SYNC_VERIFY_TLS,
                )
                response.raise_for_status()
                
                filepath = os.path.join(self.local_ml_dir, f"{model_name}.pkl")
                
                with open(filepath, 'wb') as f:
                    f.write(response.content)
                
                logger.info(f"✅ Downloaded {model_name}.pkl ({len(response.content)} bytes)")
            except Exception as e:
                logger.warning(f"⚠️ Failed to download {model_name}: {e}")
    
    
    def get_training_stats(self) -> Optional[Dict]:
        """Get statistics about training data on relay server (for info only)"""
        try:
            response = requests.get(
                f"{self.relay_url}/stats",
                timeout=10,
                verify=TRAINING_SYNC_VERIFY_TLS,
            )
            response.raise_for_status()
            
            stats = response.json()
            training_data = stats.get('relay_training_data', {})
            logger.info(f"📊 Relay server training data:")
            logger.info(f"   • {training_data.get('exploitdb_signatures', 0):,} ExploitDB signatures (relay-side)")
            logger.info(f"   • {training_data.get('global_attacks_logged', 0):,} worldwide attacks (relay-side)")
            logger.info(f"   • {stats.get('models_available', 0)} ML models (downloading...)")
            
            return stats
        except Exception as e:
            logger.error(f"❌ Failed to get training stats: {e}")
            return None


def upload_honeypot_pattern(pattern_entry: Dict):
    """
    Upload honeypot attack pattern to relay server for global distribution
    
    Args:
        pattern_entry: Dict with keys: timestamp, service, pattern, keywords, source
    """
    if not TRAINING_SYNC_ENABLED:
        logger.debug("[HONEYPOT] Training sync disabled - pattern not uploaded")
        return False
    
    try:
        relay_url = os.getenv('RELAY_URL', 'https://165.22.108.8:60002')
        
        # Send pattern to relay /api/honeypot/pattern endpoint
        response = requests.post(
            f"{relay_url}/api/honeypot/pattern",
            json=pattern_entry,
            timeout=10,
            verify=TRAINING_SYNC_VERIFY_TLS
        )
        
        if response.status_code == 200:
            logger.info(f"[HONEYPOT] Pattern uploaded to relay: {pattern_entry['service']}")
            return True
        else:
            logger.warning(f"[HONEYPOT] Relay rejected pattern: {response.status_code}")
            return False
            
    except requests.exceptions.ConnectionError:
        logger.debug(f"[HONEYPOT] Relay server offline - pattern saved locally only")
        return False
    except Exception as e:
        logger.debug(f"[HONEYPOT] Pattern upload failed: {e}")
        return False


def main():
    """Test ML model sync (NOT raw training data)"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Sync ML models from relay server')
    parser.add_argument('--relay-url', help='Relay server URL (e.g., https://vps-ip:60002)')
    parser.add_argument('--stats-only', action='store_true', help='Only show statistics')
    
    args = parser.parse_args()
    
    client = TrainingSyncClient(relay_url=args.relay_url)
    
    if args.stats_only:
        client.get_training_stats()
    else:
        # Sync ONLY ML models (not raw data)
        client.get_training_stats()
        client.sync_ml_models()
        logger.info(f"\n✅ ML models synced (280 KB total)")
        logger.info(f"📍 Models saved to: ml_models/")
        logger.info(f"🔒 No exploit data downloaded (stays on relay server)")


if __name__ == '__main__':
    main()
