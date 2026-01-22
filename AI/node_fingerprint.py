#!/usr/bin/env python3
"""
Node Fingerprinting & Feature Normalization
Solves Problem 2: Feature Consistency Across Nodes

Ensures ML models trained on different node types (Linux/Windows, server/desktop)
remain compatible by normalizing feature distributions and detecting drift.
"""

import os
import json
import hashlib
import platform
import psutil
from datetime import datetime, timezone
from typing import Dict, Any, List, Tuple, Optional
from pathlib import Path
import numpy as np
import logging

from AI.path_helper import get_ml_model_file

logger = logging.getLogger(__name__)


class NodeFingerprint:
    """Captures node characteristics for peer compatibility scoring"""
    
    def __init__(self):
        self.fingerprint_file = get_ml_model_file("node_fingerprint.json")
        self.fingerprint = self._generate_fingerprint()
        self._save_fingerprint()
        
        logger.info(f"[NODE-FP] Node type: {self.fingerprint['node_type']}")
        logger.info(f"[NODE-FP] Fingerprint: {self.fingerprint['fingerprint_hash'][:16]}...")
    
    def _generate_fingerprint(self) -> Dict[str, Any]:
        """Generate unique fingerprint for this node"""
        
        # Operating system
        os_info = {
            'system': platform.system(),  # Linux, Windows, Darwin
            'release': platform.release(),
            'version': platform.version(),
            'machine': platform.machine(),  # x86_64, ARM, etc.
        }
        
        # Node classification
        node_type = self._classify_node_type()
        
        # Network characteristics
        network_info = self._get_network_characteristics()
        
        # Traffic profile
        traffic_profile = self._estimate_traffic_profile()
        
        # Feature statistics (will be updated as data arrives)
        feature_stats = {
            'feature_means': [],
            'feature_stds': [],
            'feature_mins': [],
            'feature_maxs': [],
            'sample_count': 0,
            'last_updated': datetime.now(timezone.utc).isoformat()
        }
        
        fingerprint = {
            'fingerprint_hash': '',  # Set below
            'node_type': node_type,
            'os_info': os_info,
            'network_info': network_info,
            'traffic_profile': traffic_profile,
            'feature_stats': feature_stats,
            'created_at': datetime.now(timezone.utc).isoformat(),
        }
        
        # Generate hash
        fp_string = json.dumps({
            'node_type': node_type,
            'os': os_info['system'],
            'network': network_info['type'],
            'traffic': traffic_profile
        }, sort_keys=True)
        fingerprint['fingerprint_hash'] = hashlib.sha256(fp_string.encode()).hexdigest()
        
        return fingerprint
    
    def _classify_node_type(self) -> str:
        """Classify node as server, desktop, embedded, etc."""
        
        # Check CPU cores and memory
        cpu_count = psutil.cpu_count() or 1  # Default to 1 if None
        memory_gb = psutil.virtual_memory().total / (1024**3)
        
        # Check if running in Docker
        in_docker = os.path.exists('/.dockerenv')
        
        # Check for GUI (desktop indicator)
        has_display = bool(os.environ.get('DISPLAY') or os.environ.get('WAYLAND_DISPLAY'))
        
        # Classify
        if in_docker:
            return 'docker-container'
        elif platform.system() == 'Linux' and not has_display and cpu_count >= 4:
            return 'linux-server'
        elif platform.system() == 'Windows':
            return 'windows-desktop' if has_display else 'windows-server'
        elif platform.system() == 'Darwin':
            return 'macos-desktop'
        elif cpu_count <= 2 and memory_gb < 2:
            return 'embedded'  # Raspberry Pi, etc.
        else:
            return 'generic-desktop'
    
    def _get_network_characteristics(self) -> Dict[str, Any]:
        """Detect network environment (NAT, public IP, etc.)"""
        
        network_range = os.getenv('NETWORK_RANGE', '192.168.0.0/24')
        
        # Determine if behind NAT
        is_nat = network_range.startswith(('192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.', 
                                            '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', 
                                            '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', 
                                            '172.30.', '172.31.'))
        
        return {
            'type': 'NAT' if is_nat else 'PUBLIC',
            'range': network_range,
            'interfaces': len(psutil.net_if_addrs())
        }
    
    def _estimate_traffic_profile(self) -> str:
        """Estimate expected traffic profile"""
        
        node_type = self._classify_node_type()
        
        # Server nodes expect different traffic than desktops
        if 'server' in node_type:
            return 'server'  # Expect: SSH, HTTP, database traffic
        elif 'desktop' in node_type:
            return 'desktop'  # Expect: browsing, RDP, file sharing
        elif 'embedded' in node_type:
            return 'iot'  # Expect: lightweight, specific protocols
        else:
            return 'mixed'
    
    def _save_fingerprint(self):
        """Save fingerprint to disk"""
        os.makedirs(os.path.dirname(self.fingerprint_file), exist_ok=True)
        with open(self.fingerprint_file, 'w') as f:
            json.dump(self.fingerprint, f, indent=2)
    
    def update_feature_statistics(self, features: np.ndarray):
        """Update running statistics for feature normalization"""
        
        if len(features) == 0:
            return
        
        stats = self.fingerprint['feature_stats']
        
        if stats['sample_count'] == 0:
            # First sample
            stats['feature_means'] = features.tolist()
            stats['feature_stds'] = [0.0] * len(features)
            stats['feature_mins'] = features.tolist()
            stats['feature_maxs'] = features.tolist()
            stats['sample_count'] = 1
        else:
            # Incremental update (Welford's online algorithm)
            n = stats['sample_count']
            n_new = n + 1
            
            means = np.array(stats['feature_means'])
            stds = np.array(stats['feature_stds'])
            mins = np.array(stats['feature_mins'])
            maxs = np.array(stats['feature_maxs'])
            
            # Update mean
            delta = features - means
            new_means = means + delta / n_new
            
            # Update variance (for std calculation)
            if n > 1:
                m2 = (stds ** 2) * (n - 1)
                m2_new = m2 + delta * (features - new_means)
                new_stds = np.sqrt(m2_new / n)
            else:
                new_stds = np.abs(features - means)
            
            # Update min/max
            new_mins = np.minimum(mins, features)
            new_maxs = np.maximum(maxs, features)
            
            stats['feature_means'] = new_means.tolist()
            stats['feature_stds'] = new_stds.tolist()
            stats['feature_mins'] = new_mins.tolist()
            stats['feature_maxs'] = new_maxs.tolist()
            stats['sample_count'] = n_new
        
        stats['last_updated'] = datetime.now(timezone.utc).isoformat()
        self._save_fingerprint()
    
    def get_compatibility_score(self, peer_fingerprint: Dict[str, Any]) -> float:
        """
        Calculate compatibility score with another peer (0.0 = incompatible, 1.0 = identical)
        
        Nodes with similar characteristics should share ML data.
        Nodes with different profiles should use separate models.
        """
        
        score = 0.0
        weight_sum = 0.0
        
        # OS compatibility (weight: 0.3)
        if peer_fingerprint.get('os_info', {}).get('system') == self.fingerprint['os_info']['system']:
            score += 0.3
        weight_sum += 0.3
        
        # Node type compatibility (weight: 0.4)
        if peer_fingerprint.get('node_type') == self.fingerprint['node_type']:
            score += 0.4
        elif self._similar_node_types(peer_fingerprint.get('node_type', ''), self.fingerprint['node_type']):
            score += 0.2  # Partial credit for similar types
        weight_sum += 0.4
        
        # Traffic profile compatibility (weight: 0.2)
        if peer_fingerprint.get('traffic_profile') == self.fingerprint['traffic_profile']:
            score += 0.2
        weight_sum += 0.2
        
        # Network type compatibility (weight: 0.1)
        if peer_fingerprint.get('network_info', {}).get('type') == self.fingerprint['network_info']['type']:
            score += 0.1
        weight_sum += 0.1
        
        return score / weight_sum if weight_sum > 0 else 0.0
    
    def _similar_node_types(self, type1: str, type2: str) -> bool:
        """Check if two node types are similar enough"""
        
        server_types = {'linux-server', 'windows-server', 'docker-container'}
        desktop_types = {'windows-desktop', 'macos-desktop', 'generic-desktop'}
        
        if type1 in server_types and type2 in server_types:
            return True
        if type1 in desktop_types and type2 in desktop_types:
            return True
        
        return False
    
    def normalize_features(self, features: np.ndarray) -> np.ndarray:
        """
        Normalize features using node-specific statistics (federated normalization)
        
        This ensures features from different node types are on comparable scales.
        """
        
        stats = self.fingerprint['feature_stats']
        
        if stats['sample_count'] < 10:
            # Not enough data for normalization
            return features
        
        means = np.array(stats['feature_means'])
        stds = np.array(stats['feature_stds'])
        
        # Avoid division by zero
        stds = np.where(stds == 0, 1.0, stds)
        
        # Z-score normalization
        normalized = (features - means) / stds
        
        return normalized
    
    def detect_distribution_drift(self, features: np.ndarray, threshold: float = 3.0) -> Tuple[bool, List[int]]:
        """
        Detect if incoming features are significantly different from node's distribution
        
        Returns:
            (has_drift, drifted_feature_indices)
        """
        
        stats = self.fingerprint['feature_stats']
        
        if stats['sample_count'] < 50:
            return False, []  # Not enough data
        
        means = np.array(stats['feature_means'])
        stds = np.array(stats['feature_stds'])
        
        # Calculate z-scores
        stds = np.where(stds == 0, 1.0, stds)
        z_scores = np.abs((features - means) / stds)
        
        # Features with z-score > threshold are drifting
        drifted_indices = np.where(z_scores > threshold)[0].tolist()
        
        has_drift = len(drifted_indices) > 0
        
        return has_drift, drifted_indices
    
    def get_fingerprint(self) -> Dict[str, Any]:
        """Get current fingerprint"""
        return self.fingerprint.copy()
    
    def get_summary(self) -> str:
        """Get human-readable summary"""
        return (f"Node Type: {self.fingerprint['node_type']} | "
                f"OS: {self.fingerprint['os_info']['system']} | "
                f"Network: {self.fingerprint['network_info']['type']} | "
                f"Traffic: {self.fingerprint['traffic_profile']} | "
                f"Samples: {self.fingerprint['feature_stats']['sample_count']}")


# Global instance
_node_fingerprint: Optional[NodeFingerprint] = None

def get_node_fingerprint() -> NodeFingerprint:
    """Get or create global node fingerprint instance"""
    global _node_fingerprint
    if _node_fingerprint is None:
        _node_fingerprint = NodeFingerprint()
    return _node_fingerprint
