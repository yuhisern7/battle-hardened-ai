#!/usr/bin/env python3
"""
Central Server Sync Client
Sends **sanitized local threat summaries** to an operator-controlled
central server (for example, your own VPS/relay in the cloud) and
receives a global threat feed for enrichment.

This client is intentionally limited: it does not stream full raw JSON
log files or packet payloads, only the minimal fields defined in
``add_threat`` (IP, attack type, severity, tool label, coarse geo/ASN,
timestamp), preserving the "JSON stays on the customer node" model.
"""

import os
import json
import time
import logging
import requests
import threading
from datetime import datetime, timedelta
from typing import List, Dict, Any
import urllib3

# Suppress SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

class CentralServerSync:
    """Synchronizes threats with central server"""
    
    def __init__(self):
        self.server_url = os.getenv('CENTRAL_SERVER_URL', '').rstrip('/')
        self.api_key = os.getenv('CENTRAL_SERVER_API_KEY', '')
        self.sync_enabled = os.getenv('SYNC_ENABLED', 'false').lower() == 'true'
        self.sync_interval = int(os.getenv('SYNC_INTERVAL', '300'))  # 5 minutes default
        # Allow operators to enable strict TLS verification for production
        self.verify_tls = os.getenv('CENTRAL_VERIFY_TLS', 'false').lower() == 'true'
        
        self.local_threats_queue = []
        self.last_sync_time = None
        self.global_threats_cache = []
        self._lock = threading.Lock()
        
        self.sync_thread = None
        self.running = False
        
        if self.sync_enabled:
            if not self.server_url or not self.api_key:
                logger.warning("Central server sync enabled but URL or API key not configured")
                self.sync_enabled = False
            else:
                logger.info(f"Central server sync enabled: {self.server_url}")
    
    def start(self):
        """Start background sync thread"""
        if not self.sync_enabled:
            logger.info("Central server sync disabled")
            return
        
        self.running = True
        self.sync_thread = threading.Thread(target=self._sync_loop, daemon=True)
        self.sync_thread.start()
        logger.info("Central server sync started")
    
    def stop(self):
        """Stop sync thread"""
        self.running = False
        if self.sync_thread:
            self.sync_thread.join(timeout=5)
        logger.info("Central server sync stopped")
    
    def add_threat(self, threat: Dict[str, Any]):
        """Add a threat to the upload queue"""
        if not self.sync_enabled:
            return
        
        # Sanitize threat data (remove sensitive info)
        safe_threat = {
            'ip': threat.get('ip'),
            'attack_type': threat.get('attack_type'),
            'severity': threat.get('severity'),
            'tool_detected': threat.get('tool_detected'),
            'timestamp': threat.get('timestamp', datetime.now().isoformat()),
            'country': threat.get('country'),
            'asn': threat.get('asn')
        }
        
        with self._lock:
            self.local_threats_queue.append(safe_threat)
            # Limit queue size
            if len(self.local_threats_queue) > 1000:
                self.local_threats_queue = self.local_threats_queue[-1000:]
    
    def _sync_loop(self):
        """Background sync loop"""
        while self.running:
            try:
                # Upload local threats
                if self.local_threats_queue:
                    self._upload_threats()
                
                # Download global threats
                self._download_threats()
                
                self.last_sync_time = datetime.now()
                
            except Exception as e:
                logger.error(f"Sync error: {e}")
            
            # Wait for next sync
            time.sleep(self.sync_interval)
    
    def _upload_threats(self):
        """Upload local threats to central server"""
        with self._lock:
            if not self.local_threats_queue:
                return
            # Prepare batch
            batch = self.local_threats_queue[:100]  # Upload max 100 at a time
        
        try:
            response = requests.post(
                f"{self.server_url}/api/v1/submit-threats",
                headers={
                    'X-API-Key': self.api_key,
                    'Content-Type': 'application/json'
                },
                json={'threats': batch},
                # Accept self-signed certs by default; can be hardened via CENTRAL_VERIFY_TLS=true
                verify=self.verify_tls,
                timeout=30
            )
            
            if response.status_code == 200:
                # Remove uploaded threats
                with self._lock:
                    self.local_threats_queue = self.local_threats_queue[100:]
                logger.info(f"Uploaded {len(batch)} threats to central server")
            else:
                logger.error(f"Failed to upload threats: {response.status_code} - {response.text}")
        
        except Exception as e:
            logger.error(f"Error uploading threats: {e}")
    
    def _download_threats(self):
        """Download global threats from central server"""
        try:
            # Get threats since last sync
            params = {}
            if self.last_sync_time:
                # Get threats since last sync (with small buffer for clock skew)
                since = (self.last_sync_time - timedelta(seconds=60)).isoformat()
                params['since'] = since
                params['limit'] = 500
            else:
                # First sync - get last 1000 threats
                params['limit'] = 1000
            
            response = requests.get(
                f"{self.server_url}/api/v1/get-threats",
                headers={'X-API-Key': self.api_key},
                params=params,
                verify=self.verify_tls,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                new_threats = data.get('threats', [])
                
                if new_threats:
                    self.global_threats_cache = new_threats
                    logger.info(f"Downloaded {len(new_threats)} threats from central server")
                    
                    # Process global threats (add to local ML training)
                    self._process_global_threats(new_threats)
            else:
                logger.error(f"Failed to download threats: {response.status_code}")
        
        except Exception as e:
            logger.error(f"Error downloading threats: {e}")
    
    def _process_global_threats(self, threats: List[Dict[str, Any]]):
        """Process global threats for local learning"""
        # Import here to avoid circular dependency
        try:
            from pcs_ai import add_global_threat_to_learning
            
            for threat in threats:
                add_global_threat_to_learning(threat)
        
        except ImportError:
            logger.warning("Could not import pcs_ai for global threat learning")
        except Exception as e:
            logger.error(f"Error processing global threats: {e}")
    
    def get_threat_patterns(self) -> Dict[str, int]:
        """Get aggregated threat patterns from central server"""
        if not self.sync_enabled:
            return {}
        
        try:
            response = requests.get(
                f"{self.server_url}/api/v1/threat-patterns",
                headers={'X-API-Key': self.api_key},
                verify=self.verify_tls,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                return data.get('patterns', {})
            
        except Exception as e:
            logger.error(f"Error getting threat patterns: {e}")
        
        return {}
    
    def get_stats(self) -> Dict[str, Any]:
        """Get central server statistics"""
        if not self.sync_enabled:
            return {'sync_enabled': False}
        
        try:
            response = requests.get(
                f"{self.server_url}/api/v1/stats",
                headers={'X-API-Key': self.api_key},
                verify=self.verify_tls,
                timeout=10
            )
            
            if response.status_code == 200:
                return response.json()
            return {
                'sync_enabled': True,
                'error': f"HTTP {response.status_code} while getting stats"
            }
        except Exception as e:
            logger.error(f"Error getting stats: {e}")
            return {'sync_enabled': True, 'error': str(e)}
    
    def health_check(self) -> bool:
        """Check if central server is reachable"""
        if not self.sync_enabled:
            return False
        
        try:
            response = requests.get(
                f"{self.server_url}/health",
                verify=self.verify_tls,
                timeout=5
            )
            return response.status_code == 200
        
        except Exception:
            return False
    
    def get_sync_status(self) -> Dict[str, Any]:
        """Get current sync status"""
        return {
            'enabled': self.sync_enabled,
            'server_url': self.server_url if self.sync_enabled else None,
            'last_sync': self.last_sync_time.isoformat() if self.last_sync_time else None,
            'queued_threats': len(self.local_threats_queue),
            'cached_global_threats': len(self.global_threats_cache),
            'server_reachable': self.health_check() if self.sync_enabled else False
        }


# Global singleton instance
_sync_client = None

def get_sync_client() -> CentralServerSync:
    """Get global sync client instance"""
    global _sync_client
    if _sync_client is None:
        _sync_client = CentralServerSync()
    return _sync_client


def start_sync():
    """Start central server sync"""
    client = get_sync_client()
    client.start()


def stop_sync():
    """Stop central server sync"""
    client = get_sync_client()
    client.stop()


def sync_threat(threat: Dict[str, Any]):
    """Add threat to sync queue"""
    client = get_sync_client()
    client.add_threat(threat)


def get_sync_status() -> Dict[str, Any]:
    """Get sync status"""
    client = get_sync_client()
    return client.get_sync_status()
