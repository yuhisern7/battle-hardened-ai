"""SOAR API Integration Module
Real API key management and OpenAPI spec generation.
For military/government/police integrations with SOAR platforms.
"""

import os
import json
import secrets
from datetime import datetime
from typing import Dict, List

from AI.path_helper import get_json_file, get_json_dir

class SOARIntegration:
    """Manage API keys for SOAR integrations"""
    
    def __init__(self):
        # Use centralized JSON directory helper for cross-platform consistency
        json_dir = get_json_dir()
        # Ensure the JSON directory exists across platforms before writing
        os.makedirs(json_dir, exist_ok=True)
        self.keys_file = get_json_file('api_keys.json')
        self.stats_file = get_json_file('api_stats.json')
        self.keys = self.load_keys()
        self.stats = {'total_requests': 0, 'last_request': None, 'request_timings': []}
        self.load_stats()
        
    def load_keys(self) -> List[Dict]:
        """Load existing API keys"""
        try:
            if os.path.exists(self.keys_file):
                with open(self.keys_file, 'r') as f:
                    return json.load(f)
        except:
            pass
        return []
    
    def save_keys(self):
        """Save API keys to file"""
        try:
            with open(self.keys_file, 'w') as f:
                json.dump(self.keys, f, indent=2)
        except Exception as e:
            print(f"[SOAR] Keys save error: {e}")
    
    def load_stats(self):
        """Load API usage statistics"""
        try:
            if os.path.exists(self.stats_file):
                with open(self.stats_file, 'r') as f:
                    self.stats = json.load(f)
        except:
            pass
    
    def save_stats(self):
        """Save API usage statistics"""
        try:
            with open(self.stats_file, 'w') as f:
                json.dump(self.stats, f)
        except:
            pass
    
    def generate_key(self, name: str = "SOAR Integration") -> Dict:
        """Generate new API key"""
        api_key = f"sk_{secrets.token_urlsafe(32)}"
        key_data = {
            'id': len(self.keys) + 1,
            'name': name,
            'key': api_key,
            'key_preview': f"{api_key[:12]}...{api_key[-4:]}",
            'created_at': datetime.now().isoformat(),
            'last_used': None,
            'requests': 0
        }
        
        self.keys.append(key_data)
        self.save_keys()
        
        return {
            'success': True,
            'api_key': api_key,
            'created_at': key_data['created_at']
        }
    
    def get_all_keys(self) -> List[Dict]:
        """Get all API keys (without full key value)"""
        return [{
            'id': k['id'],
            'name': k.get('name', 'Unknown'),
            'key_preview': k['key_preview'],
            'created_at': k['created_at'],
            'last_used': k.get('last_used'),
            'requests': k.get('requests', 0)
        } for k in self.keys]
    
    def revoke_key(self, key_id: int) -> bool:
        """Revoke an API key"""
        try:
            self.keys = [k for k in self.keys if k['id'] != key_id]
            self.save_keys()
            return True
        except:
            return False
    
    def validate_key(self, api_key: str) -> bool:
        """Validate an API key"""
        start_time = datetime.now()
        for key in self.keys:
            if key['key'] == api_key:
                # Update usage stats
                key['last_used'] = datetime.now().isoformat()
                key['requests'] = key.get('requests', 0) + 1
                self.save_keys()
                
                # Track request latency (in milliseconds)
                elapsed = (datetime.now() - start_time).total_seconds() * 1000
                self.stats['total_requests'] += 1
                self.stats['last_request'] = datetime.now().isoformat()
                
                # Keep last 1000 request timings for accurate average
                if 'request_timings' not in self.stats:
                    self.stats['request_timings'] = []
                self.stats['request_timings'].append(elapsed)
                if len(self.stats['request_timings']) > 1000:
                    self.stats['request_timings'] = self.stats['request_timings'][-1000:]
                
                self.save_stats()
                return True
        return False
    
    def get_stats(self) -> Dict:
        """Get API usage statistics"""
        # Calculate real average latency from actual request timings
        total_reqs = self.stats.get('total_requests', 0)
        request_timings = self.stats.get('request_timings', [])
        avg_latency = sum(request_timings) / len(request_timings) if request_timings else 0.0
        
        return {
            'total_keys': len(self.keys),
            'active_keys': len([k for k in self.keys if k.get('last_used')]),
            'total_requests': total_reqs,
            'last_request': self.stats.get('last_request'),
            'avg_latency_ms': round(avg_latency, 2)
        }

# Global instance
soar_integration = SOARIntegration()
