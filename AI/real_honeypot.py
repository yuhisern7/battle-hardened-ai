#!/usr/bin/env python3
"""
Real Multi-Port Honeypot System - Sandbox Attack Collection
Runs multiple honeypot services simultaneously on different ports
Stores attacks locally + sends patterns to relay for global learning
"""

import socket
import threading
import logging
import time
import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from collections import defaultdict

logger = logging.getLogger(__name__)

# Track first attack time per IP for delayed blocking
_honeypot_attack_tracker = defaultdict(lambda: None)  # IP -> first_attack_timestamp
_HONEYPOT_BLOCK_DELAY_SECONDS = 60  # Block after 60 seconds of continuous attacks

# Local storage paths
if os.path.exists('/app'):
    HONEYPOT_ATTACKS_FILE = "/app/json/honeypot_attacks.json"
    HONEYPOT_PATTERNS_FILE = "/app/json/honeypot_patterns.json"
else:
    # Use absolute path from AI/ directory to server/json/
    _current_dir = os.path.dirname(os.path.abspath(__file__))
    HONEYPOT_ATTACKS_FILE = os.path.join(_current_dir, '..', 'server', 'json', 'honeypot_attacks.json')
    HONEYPOT_PATTERNS_FILE = os.path.join(_current_dir, '..', 'server', 'json', 'honeypot_patterns.json')


class HoneypotService:
    """Single honeypot service running on one port"""
    
    def __init__(self, name: str, port: int, banner: str, keywords: List[str]):
        self.name = name
        self.port = port
        self.banner = banner if isinstance(banner, bytes) else banner.encode()
        self.keywords = keywords
        self.running = False
        self.socket = None
        self.thread = None
        self.attack_count = 0
        
    def start(self):
        """Start this honeypot service"""
        if self.running:
            return False
            
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind(('0.0.0.0', self.port))
            self.socket.listen(5)
            self.running = True
            
            self.thread = threading.Thread(target=self._accept_connections, daemon=True)
            self.thread.start()
            
            logger.info(f"[HONEYPOT] {self.name} started on port {self.port}")
            return True
        except Exception as e:
            logger.error(f"[HONEYPOT] Failed to start {self.name}: {e}")
            return False
    
    def stop(self):
        """Stop this honeypot service"""
        self.running = False
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
        logger.info(f"[HONEYPOT] {self.name} stopped")
    
    def _accept_connections(self):
        """Accept and handle connections"""
        while self.running:
            try:
                if not self.socket:
                    break
                    
                self.socket.settimeout(1.0)
                client, addr = self.socket.accept()
                self.attack_count += 1
                
                # Handle in background
                handler = threading.Thread(
                    target=self._handle_client,
                    args=(client, addr),
                    daemon=True
                )
                handler.start()
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    logger.error(f"[HONEYPOT] Accept error on {self.name}: {e}")
                break
    
    def _handle_client(self, client: socket.socket, addr: tuple):
        """Handle individual attacker connection"""
        ip = addr[0]
        try:
            # Send banner
            client.send(self.banner)
            
            # Receive attacker input (optional - log connection even if no data sent)
            client.settimeout(5.0)
            data = client.recv(4096)
            
            # Log attack - even if no data received (connection attempt itself is suspicious)
            attack_data = {
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'service': self.name,
                'port': self.port,
                'source_ip': ip,
                'input': data.decode('utf-8', errors='ignore') if data else '',
                'input_hex': data.hex() if data else '',
                'keywords_matched': [k for k in self.keywords if k.lower() in data.decode('utf-8', errors='ignore').lower()] if data else []
            }
            
            # Log attack globally
            RealHoneypot.log_attack(attack_data)
            print(f"[HONEYPOT] 🎯 Attack logged: {self.name} from {ip} ({len(data) if data else 0} bytes)")
            logger.info(f"[HONEYPOT] Attack logged: {self.name} from {ip} ({len(data) if data else 0} bytes)")
                
        except Exception as e:
            print(f"[HONEYPOT] ⚠️ Client error on {self.name} from {ip}: {e}")
            logger.debug(f"[HONEYPOT] Client error on {self.name} from {ip}: {e}")
        finally:
            try:
                client.close()
            except:
                pass


class RealHoneypot:
    """
    Real multi-port honeypot system
    Runs all services simultaneously, logs to sandbox, sends patterns to relay
    """
    
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        if hasattr(self, '_initialized'):
            return
        self._initialized = True
        
        self.services: Dict[str, HoneypotService] = {}
        self.attack_log: List[Dict] = []
        self.patterns_learned: List[str] = []
        self.running = False
        
        # Define honeypot services
        self._define_services()
    
    def _define_services(self):
        """Define all available honeypot services"""
        services_config = {
            'ssh': {
                'name': 'Fake SSH',
                'port': 2222,
                'banner': 'SSH-2.0-OpenSSH_7.4\r\n',
                'keywords': ['root', 'admin', 'password', 'login']
            },
            'ftp': {
                'name': 'Fake FTP',
                'port': 2121,
                'banner': '220 ProFTPD 1.3.5 Server\r\n',
                'keywords': ['USER', 'PASS', 'RETR', 'LIST']
            },
            'telnet': {
                'name': 'Fake Telnet',
                'port': 2323,
                'banner': 'Welcome to Telnet Server\r\nLogin: ',
                'keywords': ['login', 'password', 'admin', 'root']
            },
            'http_admin': {
                'name': 'Fake Admin Panel',
                'port': 8080,
                'banner': 'HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\n\r\n<html><title>Admin Login</title></html>',
                'keywords': ['admin', 'login', 'password', 'username']
            },
            'mysql': {
                'name': 'Fake MySQL',
                'port': 3306,
                'banner': b'\x4a\x00\x00\x00\x0a\x35\x2e\x37\x2e\x32\x39\x00',
                'keywords': ['mysql', 'database', 'select', 'root']
            },
            'smtp': {
                'name': 'Fake SMTP',
                'port': 2525,
                'banner': '220 mail.example.com ESMTP\r\n',
                'keywords': ['MAIL', 'RCPT', 'DATA', 'HELO']
            },
            'rdp': {
                'name': 'Fake RDP',
                'port': 3389,
                'banner': b'\x03\x00\x00\x13\x0e\xd0\x00\x00\x124\x00\x02',
                'keywords': ['rdp', 'windows', 'remote']
            }
        }
        
        for service_id, config in services_config.items():
            self.services[service_id] = HoneypotService(
                name=config['name'],
                port=config['port'],
                banner=config['banner'],
                keywords=config['keywords']
            )
    
    def start_all(self) -> Dict[str, bool]:
        """Start all honeypot services"""
        results = {}
        for service_id, service in self.services.items():
            results[service_id] = service.start()
        
        # Set running to True if at least one service started
        active_count = sum(1 for success in results.values() if success)
        self.running = active_count > 0
        
        if self.running:
            logger.info(f"[HONEYPOT] ✅ Started {active_count}/{len(self.services)} real honeypot services")
        else:
            logger.error(f"[HONEYPOT] ❌ Failed to start any honeypot services!")
        
        return results
    
    def stop_all(self):
        """Stop all honeypot services"""
        for service in self.services.values():
            service.stop()
        self.running = False
        logger.info("[HONEYPOT] All honeypot services stopped")
    
    @classmethod
    def log_attack(cls, attack_data: Dict):
        """
        Log attack to local sandbox + extract patterns for relay
        Called from honeypot service threads
        """
        instance = cls()
        instance.attack_log.append(attack_data)
        
        # Save to local file (sandbox storage)
        try:
            os.makedirs(os.path.dirname(HONEYPOT_ATTACKS_FILE), exist_ok=True)
            
            # Debug: Print actual file path
            print(f"[HONEYPOT] Saving attack to: {HONEYPOT_ATTACKS_FILE}")
            
            # Load existing attacks
            attacks = []
            if os.path.exists(HONEYPOT_ATTACKS_FILE):
                try:
                    with open(HONEYPOT_ATTACKS_FILE, 'r') as f:
                        attacks = json.load(f)
                except:
                    pass
            
            # Append new attack
            attacks.append(attack_data)
            
            # Save back
            with open(HONEYPOT_ATTACKS_FILE, 'w') as f:
                json.dump(attacks, f, indent=2)
            
            print(f"[HONEYPOT] ✅ Attack saved! Total attacks: {len(attacks)}")
            logger.info(f"[HONEYPOT] Attack from {attack_data['source_ip']} on {attack_data['service']} logged to sandbox")
            
        except Exception as e:
            logger.error(f"[HONEYPOT] Failed to log attack: {e}")
        
        # Extract attack pattern for relay distribution
        instance._extract_pattern(attack_data)
        
        # Block the attacker's IP
        instance._block_attacker_ip(attack_data['source_ip'])
    
    def _block_attacker_ip(self, ip: str):
        """Block attacker IP after 60 seconds of attacks (delayed blocking to collect data)"""
        try:
            # Track first attack time
            if _honeypot_attack_tracker[ip] is None:
                _honeypot_attack_tracker[ip] = datetime.now(timezone.utc)
                print(f"[HONEYPOT] 🕒 First attack from {ip} - will block after {_HONEYPOT_BLOCK_DELAY_SECONDS}s of attacks")
                logger.info(f"[HONEYPOT] First attack from {ip} - delayed blocking enabled")
                return  # Don't block on first attack
            
            # Check if enough time has passed
            first_attack_time = _honeypot_attack_tracker[ip]
            time_elapsed = (datetime.now(timezone.utc) - first_attack_time).total_seconds()
            
            if time_elapsed < _HONEYPOT_BLOCK_DELAY_SECONDS:
                print(f"[HONEYPOT] ⏳ Attack from {ip} - {int(_HONEYPOT_BLOCK_DELAY_SECONDS - time_elapsed)}s until block")
                return  # Not enough time passed, allow more attacks
            
            # Time to block!
            blocked_ips_file = os.path.join(os.path.dirname(__file__), '..', 'server', 'json', 'blocked_ips.json')
            
            # Load existing blocked IPs
            blocked_data = {'blocked_ips': []}
            if os.path.exists(blocked_ips_file):
                try:
                    with open(blocked_ips_file, 'r') as f:
                        blocked_data = json.load(f)
                except:
                    pass
            
            # Check if already blocked
            existing_ips = [entry.get('ip') for entry in blocked_data.get('blocked_ips', [])]
            if ip in existing_ips:
                return
            
            # Add new blocked IP
            blocked_entry = {
                'ip': ip,
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'reason': f'Honeypot attack attempts over {_HONEYPOT_BLOCK_DELAY_SECONDS} seconds',
                'source': 'honeypot',
                'first_attack': first_attack_time.isoformat(),
                'attacks_duration': f'{int(time_elapsed)}s',
                'permanent': True
            }
            
            blocked_data['blocked_ips'].append(blocked_entry)
            
            # Save back
            with open(blocked_ips_file, 'w') as f:
                json.dump(blocked_dLOCKED {ip} after {int(time_elapsed)}s of attacks!")
            logger.info(f"[HONEYPOT] Blocked attacker IP {ip} after {int(time_elapsed)}s of continuous attacks
            print(f"[HONEYPOT] 🚫 Blocked attacker IP: {ip}")
            logger.info(f"[HONEYPOT] Blocked attacker IP: {ip}")
            
        except Exception as e:
            logger.error(f"[HONEYPOT] Failed to block IP {ip}: {e}")
    
    def _extract_pattern(self, attack_data: Dict):
        """Extract attack pattern and prepare for relay distribution"""
        try:
            attack_input = attack_data.get('input', '')
            
            # Extract pattern (first 200 chars, sanitized)
            pattern = attack_input[:200].strip()
            
            if not pattern or pattern in self.patterns_learned:
                return
            
            self.patterns_learned.append(pattern)
            
            # Save pattern locally
            patterns = []
            if os.path.exists(HONEYPOT_PATTERNS_FILE):
                try:
                    with open(HONEYPOT_PATTERNS_FILE, 'r') as f:
                        patterns = json.load(f)
                except:
                    pass
            
            pattern_entry = {
                'timestamp': attack_data['timestamp'],
                'service': attack_data['service'],
                'pattern': pattern,
                'keywords': attack_data.get('keywords_matched', []),
                'source': 'honeypot'
            }
            
            patterns.append(pattern_entry)
            
            with open(HONEYPOT_PATTERNS_FILE, 'w') as f:
                json.dump(patterns, f, indent=2)
            
            logger.info(f"[HONEYPOT] Learned new attack pattern: {pattern[:50]}...")
            
            # Send to relay (if enabled)
            self._send_pattern_to_relay(pattern_entry)
            
        except Exception as e:
            logger.error(f"[HONEYPOT] Pattern extraction failed: {e}")
    
    def _send_pattern_to_relay(self, pattern_entry: Dict):
        """Send attack pattern to relay server for global learning"""
        try:
            # Check if relay is enabled
            import os
            if os.getenv('RELAY_ENABLED', 'true').lower() != 'true':
                return
            
            # Import relay client
            try:
                from AI.training_sync_client import upload_honeypot_pattern
                upload_honeypot_pattern(pattern_entry)
                logger.info(f"[HONEYPOT] Pattern sent to relay for global distribution")
            except ImportError:
                logger.debug("[HONEYPOT] Relay client not available")
        except Exception as e:
            logger.debug(f"[HONEYPOT] Relay upload failed: {e}")
    
    def get_status(self) -> Dict:
        """Get honeypot system status"""
        active_services = [
            {
                'name': s.name,
                'port': s.port,
                'running': s.running,
                'attacks': s.attack_count
            }
            for s in self.services.values()
        ]
        
        return {
            'running': self.running,
            'services': active_services,
            'total_services': len(self.services),
            'active_services': sum(1 for s in self.services.values() if s.running),
            'total_attacks': sum(s.attack_count for s in self.services.values()),
            'patterns_learned': len(self.patterns_learned),
            'attack_log_size': len(self.attack_log)
        }


# Global instance and convenience functions
_honeypot = None

def get_honeypot() -> RealHoneypot:
    """Get or create global honeypot instance"""
    global _honeypot
    if _honeypot is None:
        _honeypot = RealHoneypot()
    return _honeypot

def start_honeypots():
    """Start all honeypot services"""
    hp = get_honeypot()
    return hp.start_all()

def stop_honeypots():
    """Stop all honeypot services"""
    hp = get_honeypot()
    hp.stop_all()

def get_honeypot_status() -> Dict:
    """Get honeypot status"""
    hp = get_honeypot()
    return hp.get_status()
