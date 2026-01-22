#!/usr/bin/env python3
"""
Peer-to-Peer Threat Intelligence Synchronization with Encrypted Communication

Every container is equal - all share threats with each other automatically.
No central server needed. Simple, efficient, brilliant.

When A gets attacked, B and C learn immediately.
The network gets smarter every hour, automatically.

🔐 All connections are HTTPS encrypted - hackers cannot sniff the data.
"""

import os
import json
import time
import threading
import logging
import requests
from datetime import datetime
from typing import List, Dict, Any, Optional
import ssl

# Disable SSL warnings for self-signed certificates only when explicitly allowed
import urllib3

logger = logging.getLogger(__name__)

P2P_SYNC_ENABLED = os.getenv("P2P_SYNC_ENABLED", "false").lower() == "true"
P2P_SYNC_DISABLE_SSL_VERIFY = os.getenv("P2P_SYNC_DISABLE_SSL_VERIFY", "false").lower() == "true"
P2P_SYNC_MAX_QUEUE = int(os.getenv("P2P_SYNC_MAX_QUEUE", "10000"))

if P2P_SYNC_DISABLE_SSL_VERIFY:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class P2PSync:
    """Peer-to-peer threat intelligence synchronization with encrypted connections"""
    
    def __init__(self):
        # Load peer URLs from environment - automatically use HTTPS
        peer_urls_str = os.getenv('PEER_URLS', '')
        raw_urls = [url.strip() for url in peer_urls_str.split(',') if url.strip()]
        
        # Auto-upgrade HTTP to HTTPS for encryption
        self.peer_urls = []
        for url in raw_urls:
            if url.startswith('http://'):
                # Upgrade to HTTPS for encrypted communication
                https_url = url.replace('http://', 'https://')
                self.peer_urls.append(https_url)
                logger.info(f"🔐 Auto-upgraded to HTTPS: {https_url}")
            else:
                self.peer_urls.append(url)
        
        # Configuration
        self.enabled = P2P_SYNC_ENABLED
        self.sync_interval = int(os.getenv('P2P_SYNC_INTERVAL', '180'))  # 3 minutes
        self.my_peer_name = os.getenv('PEER_NAME', f'peer-{os.getpid()}')
        
        # State
        self.threat_queue = []  # Threats to broadcast to peers
        self.received_threats = {}  # Threats received from peers (threat_id -> threat)
        self.peer_status = {}  # Track which peers are online
        self.last_sync = {}  # Last sync time per peer
        self.lock = threading.Lock()
        self.running = False
        self.sync_thread = None
        
        # Stats
        self.threats_sent = 0
        self.threats_received = 0
        self.sync_errors = 0
        
        logger.info(
            f"P2P Sync initialized: {len(self.peer_urls)} peers configured (enabled={self.enabled})"
        )
        if self.peer_urls:
            logger.info(f"Peers: {', '.join(self.peer_urls)}")
    
    def start(self):
        """Start background synchronization with all peers"""
        if not self.enabled:
            logger.info("P2P sync disabled (set P2P_SYNC_ENABLED=true to enable)")
            return
        
        if not self.peer_urls:
            logger.warning("P2P sync enabled but no peers configured (set PEER_URLS)")
            return
        
        if self.running:
            logger.warning("P2P sync already running")
            return
        
        self.running = True
        self.sync_thread = threading.Thread(target=self._sync_loop, daemon=True)
        self.sync_thread.start()
        logger.info(f"P2P sync started: broadcasting to {len(self.peer_urls)} peers every {self.sync_interval}s")
    
    def stop(self):
        """Stop background synchronization"""
        self.running = False
        if self.sync_thread:
            self.sync_thread.join(timeout=5)
        logger.info("P2P sync stopped")
    
    def add_threat(self, threat: Dict[str, Any]):
        """
        Add a threat to broadcast to all peers
        
        Args:
            threat: Threat event dictionary with keys like:
                    - attack_type
                    - severity  
                    - src_ip
                    - timestamp
                    - details
        """
        # Sanitize threat data - only share what helps learning
        safe_threat = {
            'threat_id': f"{self.my_peer_name}-{int(time.time() * 1000)}",
            'source_peer': self.my_peer_name,
            'attack_type': threat.get('attack_type', 'unknown'),
            'severity': threat.get('severity', 'medium'),
            'src_ip': threat.get('src_ip', ''),
            'geolocation': threat.get('geolocation', {}),
            'timestamp': threat.get('timestamp', datetime.now().isoformat()),
            'ml_confidence': threat.get('ml_confidence', 0.0),
            'exploit_match': threat.get('exploit_match', ''),
            'cve_match': threat.get('cve_match', []),
        }
        
        with self.lock:
            self.threat_queue.append(safe_threat)
            # Bound queue size to avoid unbounded memory growth
            if len(self.threat_queue) > P2P_SYNC_MAX_QUEUE:
                overflow = len(self.threat_queue) - P2P_SYNC_MAX_QUEUE
                del self.threat_queue[0:overflow]
                logger.debug(
                    f"P2P threat_queue truncated by {overflow} entries (max={P2P_SYNC_MAX_QUEUE})"
                )
        
        logger.debug(f"Queued threat for P2P broadcast: {safe_threat['attack_type']} from {safe_threat['src_ip']}")
    
    def receive_threat(self, threat: Dict[str, Any]) -> bool:
        """
        Receive a threat from a peer
        
        Args:
            threat: Threat data from peer
            
        Returns:
            True if threat is new, False if already seen
        """
        threat_id = threat.get('threat_id')
        if not threat_id:
            logger.warning("Received threat without ID, ignoring")
            return False
        
        with self.lock:
            if threat_id in self.received_threats:
                return False  # Already seen
            
            self.received_threats[threat_id] = threat
            self.threats_received += 1
        
        logger.info(f"Received new threat from peer {threat.get('source_peer', 'unknown')}: {threat.get('attack_type')}")
        return True
    
    def get_received_threats(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recently received threats from peers"""
        with self.lock:
            threats = list(self.received_threats.values())
        
        # Sort by timestamp, newest first
        threats.sort(key=lambda t: t.get('timestamp', ''), reverse=True)
        return threats[:limit]
    
    def get_sync_status(self) -> Dict[str, Any]:
        """Get current P2P sync status"""
        with self.lock:
            status = {
                'enabled': self.enabled,
                'peers_configured': len(self.peer_urls),
                'peers_online': sum(1 for s in self.peer_status.values() if s),
                'peer_urls': self.peer_urls,
                'peer_status': self.peer_status.copy(),
                'threats_queued': len(self.threat_queue),
                'threats_sent': self.threats_sent,
                'threats_received': self.threats_received,
                'sync_errors': self.sync_errors,
                'last_sync': self.last_sync.copy(),
            }
        return status
    
    def _sync_loop(self):
        """Background thread that syncs with all peers"""
        logger.info("P2P sync loop started")
        
        while self.running:
            try:
                # Broadcast our threats to all peers
                self._broadcast_threats()
                
                # Fetch threats from all peers
                self._fetch_from_peers()
                
            except Exception as e:
                logger.error(f"P2P sync error: {e}")
                with self.lock:
                    self.sync_errors += 1
            
            # Wait for next sync interval
            time.sleep(self.sync_interval)
        
        logger.info("P2P sync loop ended")
    
    def _broadcast_threats(self):
        """Broadcast queued threats to all peers"""
        with self.lock:
            threats_to_send = self.threat_queue[:100]  # Send in batches
            self.threat_queue = self.threat_queue[100:]
        
        if not threats_to_send:
            return
        
        logger.info(f"Broadcasting {len(threats_to_send)} threats to {len(self.peer_urls)} peers")
        
        for peer_url in self.peer_urls:
            try:
                response = requests.post(
                    f"{peer_url}/api/p2p/threats",
                    json={'threats': threats_to_send},
                    timeout=10,
                    # Allow opt-out of TLS verification only when explicitly configured
                    verify=not P2P_SYNC_DISABLE_SSL_VERIFY,
                )
                
                if response.status_code == 200:
                    with self.lock:
                        self.peer_status[peer_url] = True
                        self.last_sync[peer_url] = datetime.now().isoformat()
                        self.threats_sent += len(threats_to_send)
                    logger.debug(f"Sent {len(threats_to_send)} threats to {peer_url}")
                else:
                    logger.warning(f"Peer {peer_url} returned {response.status_code}")
                    with self.lock:
                        self.peer_status[peer_url] = False
                
            except requests.exceptions.RequestException as e:
                logger.warning(f"Failed to reach peer {peer_url}: {e}")
                with self.lock:
                    self.peer_status[peer_url] = False
    
    def _fetch_from_peers(self):
        """Fetch new threats from all peers"""
        for peer_url in self.peer_urls:
            try:
                # Get threats newer than our last sync
                since = self.last_sync.get(peer_url, '')
                params = {'since': since, 'limit': 100}
                
                response = requests.get(
                    f"{peer_url}/api/p2p/threats",
                    params=params,
                    timeout=10,
                    verify=not P2P_SYNC_DISABLE_SSL_VERIFY,
                )
                
                if response.status_code == 200:
                    data = response.json()
                    threats = data.get('threats', [])
                    
                    new_count = 0
                    for threat in threats:
                        if self.receive_threat(threat):
                            new_count += 1
                    
                    if new_count > 0:
                        logger.info(f"Fetched {new_count} new threats from {peer_url}")
                    
                    with self.lock:
                        self.peer_status[peer_url] = True
                        self.last_sync[peer_url] = datetime.now().isoformat()
                
            except requests.exceptions.RequestException as e:
                logger.debug(f"Could not fetch from peer {peer_url}: {e}")
                with self.lock:
                    self.peer_status[peer_url] = False


# Global singleton instance
_p2p_sync = None
_p2p_lock = threading.Lock()


def get_p2p_sync() -> P2PSync:
    """Get global P2P sync instance (singleton)"""
    global _p2p_sync
    
    if _p2p_sync is None:
        with _p2p_lock:
            if _p2p_sync is None:
                _p2p_sync = P2PSync()
    
    return _p2p_sync


def sync_threat(threat: Dict[str, Any]):
    """
    Broadcast a threat to all peers
    
    Usage:
        from AI.p2p_sync import sync_threat
        sync_threat(threat_event)
    """
    sync = get_p2p_sync()
    if sync.enabled:
        sync.add_threat(threat)


def start_p2p_sync():
    """
    Start P2P synchronization
    
    Usage:
        from AI.p2p_sync import start_p2p_sync
        start_p2p_sync()
    """
    sync = get_p2p_sync()
    sync.start()


def get_p2p_status() -> Dict[str, Any]:
    """
    Get P2P sync status
    
    Returns:
        Dict with sync statistics and peer status
    """
    sync = get_p2p_sync()
    return sync.get_sync_status()


def get_peer_threats(limit: int = 100) -> List[Dict[str, Any]]:
    """
    Get threats received from peers
    
    Returns:
        List of threat dictionaries
    """
    sync = get_p2p_sync()
    return sync.get_received_threats(limit)


if __name__ == '__main__':
    # Test P2P sync
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Set test environment
    os.environ['P2P_SYNC_ENABLED'] = 'true'
    os.environ['PEER_URLS'] = 'https://localhost:5001,https://localhost:5002'
    os.environ['PEER_NAME'] = 'test-peer'
    
    sync = get_p2p_sync()
    start_p2p_sync()
    
    # Add test threat
    test_threat = {
        'attack_type': 'port_scan',
        'severity': 'high',
        'src_ip': '192.168.1.100',
        'timestamp': datetime.now().isoformat(),
    }
    sync_threat(test_threat)
    
    print("P2P Sync Status:")
    print(json.dumps(get_p2p_status(), indent=2))
    
    # Keep running
    try:
        while True:
            time.sleep(10)
            print(f"\nThreats sent: {sync.threats_sent}, received: {sync.threats_received}")
    except KeyboardInterrupt:
        sync.stop()
