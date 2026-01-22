"""ExploitDB Signature Distribution System for P2P Mesh.

This module enables containers to share ExploitDB signatures via P2P mesh,
eliminating the need for every container to download the full 500MB+ database.

Architecture:
- Master nodes: Have full ExploitDB, serve signatures to clients
- Client nodes: Request signatures on-demand, cache locally
- Hybrid mode: Download only frequently-used signatures

Features:
- Distributed signature serving
- On-demand signature loading
- Local caching for performance
- Automatic signature updates via P2P
- Fallback to local ExploitDB if available
"""

import json
import os
import hashlib
import time
from typing import Dict, List, Optional, Set
from pathlib import Path
from collections import defaultdict
from datetime import datetime, timedelta
import threading
import logging
import urllib3

from AI.path_helper import get_ml_models_dir

logger = logging.getLogger(__name__)

# Optional imports with graceful fallback
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    logger.warning("[SIGNATURE DIST] requests library not available - P2P features disabled")

try:
    from server.server import get_peer_urls  # type: ignore[attr-defined]
    PEER_DISCOVERY_AVAILABLE = True
except ImportError:
    PEER_DISCOVERY_AVAILABLE = False
    logger.warning("[SIGNATURE DIST] Peer discovery not available - P2P features limited")

SIGNATURE_DIST_DISABLE_SSL_VERIFY = os.getenv("SIGNATURE_DIST_DISABLE_SSL_VERIFY", "false").lower() == "true"

if SIGNATURE_DIST_DISABLE_SSL_VERIFY:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class SignatureDistributionSystem:
    """Manages ExploitDB signature distribution across P2P mesh."""
    
    def __init__(self, mode: str = "auto", cache_dir: str = None):
        """Initialize signature distribution system.
        
        Args:
            mode: "master" (has ExploitDB), "client" (receives from P2P), "auto" (detect)
            cache_dir: Directory to cache received signatures. If None, defaults to
                a "signature_cache" subdirectory under the unified ML models dir.
        """
        self.mode = mode
        if cache_dir is None:
            cache_dir = os.path.join(get_ml_models_dir(), "signature_cache")
        self.cache_dir = Path(cache_dir)
        
        # Signature storage
        self._local_signatures = {}  # Signatures from local ExploitDB
        self._cached_signatures = {}  # Signatures from P2P
        self._signature_index = {}  # Fast lookup index
        self._signature_stats = defaultdict(int)
        
        # P2P sync
        self._peer_signature_sources = []  # List of peers serving signatures
        self._last_sync_time = None
        self._sync_lock = threading.Lock()
        
        # Auto-detect mode
        if self.mode == "auto":
            self.mode = self._detect_mode()
        
        logger.info(f"[SIGNATURE DIST] Mode: {self.mode.upper()}")
        
        # Load signatures based on mode
        if self.mode == "master":
            self._load_local_exploitdb()
        else:
            self._load_cached_signatures()
    
    def _detect_mode(self) -> str:
        """Auto-detect if this container should be master or client."""
        exploitdb_paths = [
            "AI/exploitdb",
            "exploitdb",
            "/app/AI/exploitdb"
        ]
        
        for path in exploitdb_paths:
            if os.path.exists(path) and os.path.isdir(path):
                csv_path = os.path.join(path, "files_exploits.csv")
                if os.path.exists(csv_path):
                    logger.info(f"[SIGNATURE DIST] Found ExploitDB at {path} - Running as MASTER")
                    return "master"
        
        logger.info("[SIGNATURE DIST] No ExploitDB found - Running as CLIENT")
        return "client"
    
    def _load_local_exploitdb(self):
        """Load signatures from local ExploitDB (master mode only)."""
        try:
            from AI.exploitdb_scraper import get_scraper  # type: ignore[import]
            scraper = get_scraper()
            
            # Get all learned signatures
            self._local_signatures = scraper.attack_patterns.copy()
            
            # Build index for fast lookups
            for attack_type, signatures in self._local_signatures.items():
                for sig in signatures:
                    sig_id = self._generate_signature_id(sig)
                    self._signature_index[sig_id] = {
                        'attack_type': attack_type,
                        'signature': sig
                    }
            
            logger.info(f"[SIGNATURE DIST] Loaded {len(self._signature_index)} signatures from local ExploitDB")
            
        except Exception as e:
            logger.warning(f"[SIGNATURE DIST] Warning: Could not load ExploitDB: {e}")
            self.mode = "client"  # Fallback to client if ExploitDB missing
    
    def _load_cached_signatures(self):
        """Load previously cached signatures from disk."""
        cache_file = self.cache_dir / "signatures.json"
        
        if cache_file.exists():
            try:
                with open(cache_file, 'r') as f:
                    self._cached_signatures = json.load(f)
                
                # Build index
                for attack_type, signatures in self._cached_signatures.items():
                    for sig in signatures:
                        sig_id = self._generate_signature_id(sig)
                        self._signature_index[sig_id] = {
                            'attack_type': attack_type,
                            'signature': sig
                        }
                
                logger.info(f"[SIGNATURE DIST] Loaded {len(self._signature_index)} cached signatures")
            except Exception as e:
                logger.warning(f"[SIGNATURE DIST] Warning: Could not load cache: {e}")
        else:
            logger.info("[SIGNATURE DIST] No cached signatures found")
    
    def _save_cached_signatures(self):
        """Save cached signatures to disk."""
        cache_file = self.cache_dir / "signatures.json"
        
        try:
            with open(cache_file, 'w') as f:
                json.dump(self._cached_signatures, f, indent=2)
            logger.info(f"[SIGNATURE DIST] Saved {len(self._signature_index)} signatures to cache")
        except Exception as e:
            logger.warning(f"[SIGNATURE DIST] Warning: Could not save cache: {e}")
    
    def _generate_signature_id(self, signature: Dict) -> str:
        """Generate unique ID for a signature."""
        sig_str = json.dumps(signature, sort_keys=True)
        return hashlib.md5(sig_str.encode()).hexdigest()[:16]
    
    def get_signatures_for_attack_type(self, attack_type: str) -> List[Dict]:
        """
        Get all signatures for a specific attack type.
        
        Args:
            attack_type: Type of attack (e.g., "sql_injection", "xss")
        
        Returns:
            List of signature dictionaries
        """
        # Check local signatures first (master mode)
        if self.mode == "master" and attack_type in self._local_signatures:
            return self._local_signatures[attack_type]
        
        # Check cached signatures (client mode)
        if attack_type in self._cached_signatures:
            self._signature_stats[attack_type] += 1
            return self._cached_signatures[attack_type]
        
        # Request from P2P peers
        if self.mode == "client":
            signatures = self._request_signatures_from_peers(attack_type)
            if signatures:
                self._cached_signatures[attack_type] = signatures
                self._save_cached_signatures()
                return signatures
        
        return []
    
    def _request_signatures_from_peers(self, attack_type: str) -> Optional[List[Dict]]:
        """Request signatures from P2P peers."""
        if not REQUESTS_AVAILABLE or not PEER_DISCOVERY_AVAILABLE:
            return None
        
        try:
            assert 'get_peer_urls' in globals(), "get_peer_urls not available"
            assert 'requests' in globals(), "requests not available"
            peer_urls = get_peer_urls()  # type: ignore[possibly-unbound]

            for peer_url in peer_urls:
                try:
                    response = requests.get(  # type: ignore[possibly-unbound]
                        f"{peer_url}/api/signatures/{attack_type}",
                        timeout=5,
                        verify=not SIGNATURE_DIST_DISABLE_SSL_VERIFY,
                    )
                    
                    if response.status_code == 200:
                        data = response.json()
                        signatures = data.get('signatures', [])
                        logger.info(
                            f"[SIGNATURE DIST] Received {len(signatures)} signatures from peer {peer_url} (count={len(signatures)})"
                        )
                        return signatures
                
                except Exception:
                    continue
        
        except Exception as e:
            logger.error(f"[SIGNATURE DIST] Error requesting from peers: {e}")
        
        return None
    
    def serve_signatures(self, attack_type: str) -> Dict:
        """
        Serve signatures to requesting peers (master mode).
        
        Args:
            attack_type: Type of attack signatures requested
        
        Returns:
            Dictionary with signatures and metadata
        """
        if self.mode != "master":
            return {
                'error': 'Not a master node',
                'mode': self.mode
            }
        
        signatures = self._local_signatures.get(attack_type, [])
        
        return {
            'attack_type': attack_type,
            'signatures': signatures,
            'count': len(signatures),
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'source': 'local_exploitdb'
        }
    
    def get_all_attack_types(self) -> List[str]:
        """Get list of all available attack types."""
        if self.mode == "master":
            return list(self._local_signatures.keys())
        else:
            return list(self._cached_signatures.keys())
    
    def sync_with_peers(self):
        """Synchronize signature list with P2P peers (client mode)."""
        if self.mode != "client":
            return
        
        if not REQUESTS_AVAILABLE or not PEER_DISCOVERY_AVAILABLE:
            return
        
        with self._sync_lock:
            try:
                assert 'get_peer_urls' in globals(), "get_peer_urls not available"
                assert 'requests' in globals(), "requests not available"
                peer_urls = get_peer_urls()  # type: ignore[possibly-unbound]

                for peer_url in peer_urls:
                    try:
                        # Get list of available attack types
                        response = requests.get(  # type: ignore[possibly-unbound]
                            f"{peer_url}/api/signatures/types",
                            timeout=5,
                            verify=not SIGNATURE_DIST_DISABLE_SSL_VERIFY,
                        )
                        
                        if response.status_code == 200:
                            data = response.json()
                            attack_types = data.get('attack_types', [])
                            
                            # Request signatures for types we don't have
                            for attack_type in attack_types:
                                if attack_type not in self._cached_signatures:
                                    sigs = self._request_signatures_from_peers(attack_type)
                                    if sigs:
                                        self._cached_signatures[attack_type] = sigs
                            
                            self._save_cached_signatures()
                            self._last_sync_time = datetime.now(timezone.utc)
                            break

                    except Exception:
                        continue

            except Exception as e:
                logger.error(f"[SIGNATURE DIST] Sync error: {e}")
    
    def get_stats(self) -> Dict:
        """Get statistics about signature distribution."""
        return {
            'mode': self.mode,
            'total_signatures': len(self._signature_index),
            'attack_types_count': len(self._local_signatures if self.mode == "master" else self._cached_signatures),
            'cache_hits': dict(self._signature_stats),
            'last_sync': self._last_sync_time.isoformat() if self._last_sync_time else None,
            'is_master': self.mode == "master"
        }


# Global instance
_signature_dist = None


def get_signature_distribution() -> SignatureDistributionSystem:
    """Get global signature distribution instance."""
    global _signature_dist
    if _signature_dist is None:
        mode = os.environ.get('SIGNATURE_MODE', 'auto')
        _signature_dist = SignatureDistributionSystem(mode=mode)
    return _signature_dist


def start_signature_distribution():
    """Initialize and start signature distribution system."""
    dist = get_signature_distribution()
    
    if dist.mode == "client":
        # Start periodic sync with peers
        def sync_loop():
            while True:
                time.sleep(600)  # Sync every 10 minutes
                dist.sync_with_peers()
        
        sync_thread = threading.Thread(target=sync_loop, daemon=True)
        sync_thread.start()
        logger.info("[SIGNATURE DIST] Started periodic sync thread")
    
    return dist
