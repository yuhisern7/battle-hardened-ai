"""User and Identity Monitoring Module
Track network users via ARP, DHCP, and DNS - real data only.
For military/government/police use.
"""

import os
import json
import subprocess
import platform
import shutil
import logging
from datetime import datetime
from collections import defaultdict
from typing import Dict, List

from AI.path_helper import get_threat_log_file

from AI.path_helper import get_json_file

try:
    import psutil  # type: ignore
except ImportError:
    psutil = None

logger = logging.getLogger(__name__)

# Feature flag so operators can disable user tracking when not desired
USER_TRACKING_ENABLED = os.getenv("USER_TRACKING_ENABLED", "true").lower() == "true"

class UserTracker:
    """Track users on the network using real system data"""
    
    def __init__(self):
        # Universal path resolution via centralized helper
        self.users_file = get_json_file('tracked_users.json')
        self.suspicious_activities = []
        self.enabled = USER_TRACKING_ENABLED
        
    def get_arp_table(self) -> List[Dict]:
        """Get ARP table to identify connected users (cross-platform)"""
        if not self.enabled:
            return []
        users = []
        try:
            # Run arp command (works on Linux, macOS, Windows)
            result = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=2)
            if result.returncode == 0:
                system = platform.system()
                
                for line in result.stdout.split('\n'):
                    if not line.strip():
                        continue
                    
                    try:
                        # Windows format: Interface: 192.168.1.1 --- 0xb
                        #                  Internet Address      Physical Address      Type
                        #                  192.168.1.100        aa-bb-cc-dd-ee-ff     dynamic
                        if system == 'Windows':
                            if 'Interface:' in line or 'Internet Address' in line:
                                continue
                            parts = line.split()
                            if len(parts) >= 2:
                                ip = parts[0]
                                mac = parts[1].replace('-', ':')
                                if '.' in ip and ':' in mac:
                                    users.append({
                                        'hostname': 'Unknown',
                                        'ip': ip,
                                        'mac': mac,
                                        'last_seen': datetime.now().isoformat()
                                    })
                        
                        # macOS/Linux format: ? (192.168.1.100) at aa:bb:cc:dd:ee:ff [ether] on en0
                        #                or: hostname (192.168.1.100) at aa:bb:cc:dd:ee:ff [ether] on eth0
                        elif '(' in line and ')' in line:
                            parts = line.split()
                            if len(parts) >= 4:
                                hostname = parts[0] if parts[0] != '?' else 'Unknown'
                                ip = parts[1].strip('()')
                                mac = parts[3] if len(parts) > 3 else 'Unknown'
                                
                                if '.' in ip:  # Valid IP
                                    users.append({
                                        'hostname': hostname,
                                        'ip': ip,
                                        'mac': mac,
                                        'last_seen': datetime.now().isoformat()
                                    })
                    except:
                        continue  # Skip malformed lines
        except subprocess.TimeoutExpired:
            logger.warning("[USER_TRACKER] arp command timed out")
        except Exception as e:
            logger.error(f"[USER_TRACKER] ARP error: {e}")
        
        return users
    
    def detect_suspicious_activity(self, users: List[Dict]) -> int:
        """Detect suspicious user behavior"""
        if not self.enabled:
            return 0
        suspicious_count = 0

        # Load threat log to check if any user IPs are in blocklist
        try:
            threat_log = get_threat_log_file()
            if os.path.exists(threat_log):
                with open(threat_log, 'r') as f:
                    data = json.load(f)

                # threat_log.json is expected to be a list of threat events
                threats = data if isinstance(data, list) else []

                blocked_ips = set()
                for t in threats:
                    if not isinstance(t, dict):
                        continue
                    ip = t.get('ip_address') or t.get('src_ip')
                    action = (t.get('action') or '').lower()
                    level = (t.get('level') or '').upper()
                    # Treat events as "blocked" if their action indicates blocking or level is CRITICAL
                    is_blocked = ('block' in action) or level == 'CRITICAL'
                    if ip and is_blocked:
                        blocked_ips.add(ip)

                for user in users:
                    if user.get('ip') in blocked_ips:
                        suspicious_count += 1
                        self.suspicious_activities.append({
                            'user': user.get('hostname', 'Unknown'),
                            'ip': user.get('ip'),
                            'reason': 'IP matches blocked threat',
                            'timestamp': datetime.now().isoformat()
                        })
                        # Bound memory: keep only the most recent 1000 suspicious activity entries
                        if len(self.suspicious_activities) > 1000:
                            self.suspicious_activities = self.suspicious_activities[-1000:]
        except Exception as e:
            logger.error(f"[USER_TRACKER] Suspicious activity detection error: {e}")

        return suspicious_count
    
    def get_stats(self) -> Dict:
        """Get user tracking statistics"""
        if not self.enabled:
            return {
                'tracked_users': 0,
                'suspicious_activities': 0,
                'insider_threats': 0,
                'active_sessions': 0,
                'users': [],
                'enabled': False,
            }

        users = self.get_arp_table()
        suspicious = self.detect_suspicious_activity(users)
        
        # Count active sessions using psutil (cross-platform)
        active_sessions = 0
        if psutil is not None:
            try:
                connections = psutil.net_connections(kind='inet')
                active_sessions = len([c for c in connections if c.status == 'ESTABLISHED'])
            except:
                pass
        
        # Insider threats are critical suspicious activities
        insider_threats = len([a for a in self.suspicious_activities if 'blocked threat' in a.get('reason', '')])
        
        # Save users to file
        try:
            os.makedirs(os.path.dirname(self.users_file), exist_ok=True)
            with open(self.users_file, 'w') as f:
                json.dump(users, f, indent=2)
        except Exception as e:
            logger.debug(f"[USER_TRACKER] Failed to write tracked_users.json: {e}")
        
        return {
            'tracked_users': len(users),
            'suspicious_activities': suspicious,
            'insider_threats': insider_threats,
            'active_sessions': active_sessions,
            'users': users,
            'enabled': True,
        }

# Global instance
user_tracker = UserTracker()
