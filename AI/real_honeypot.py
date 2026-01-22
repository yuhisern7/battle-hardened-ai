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
import os
import json
import random
import string
from datetime import datetime, timezone
from typing import Dict, List, Optional
from collections import defaultdict


logger = logging.getLogger(__name__)

from AI.path_helper import get_blocked_ips_file
_honeypot_attack_tracker = defaultdict(lambda: None)  # IP -> first_attack_timestamp
_HONEYPOT_BLOCK_DELAY_SECONDS = 10  # Block after 10 seconds of attacks (reduced from 60 for faster response)

# Local storage paths - Universal path resolution
from AI.path_helper import get_json_file
HONEYPOT_ATTACKS_FILE = get_json_file('honeypot_attacks.json')
HONEYPOT_PATTERNS_FILE = get_json_file('honeypot_patterns.json')


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
            print(f"[HONEYPOT] ✅ {self.name} started on port {self.port}")
            return True
        except OSError as e:
            # Common case: port already in use by a real service on the customer's host.
            # In that case, we *intentionally* skip this honeypot service and keep the others.
            err_no = getattr(e, 'errno', None)
            if err_no is not None:
                msg = (
                    f"[HONEYPOT] ⚠️ Failed to bind {self.name} on port {self.port} "
                    f"(errno={err_no}): {e}. Treating as 'port in use' and skipping this service."
                )
                logger.warning(msg)
                print(msg)
            else:
                msg = f"[HONEYPOT] ⚠️ Failed to start {self.name} on port {self.port}: {e}"
                logger.error(msg)
                print(msg)
            return False
        except Exception as e:
            msg = f"[HONEYPOT] ❌ Unexpected error starting {self.name} on port {self.port}: {e}"
            logger.error(msg)
            print(msg)
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
        data = b""
        attack_logged = False
        try:
            # Send banner (best effort; failures are still considered an attack attempt)
            try:
                client.send(self.banner)
            except Exception as banner_err:
                logger.debug(f"[HONEYPOT] Banner send error on {self.name} to {ip}: {banner_err}")

            # Receive attacker input (optional - log connection even if no data sent)
            try:
                client.settimeout(5.0)
                data = client.recv(4096)
            except Exception as recv_err:
                logger.debug(f"[HONEYPOT] Recv error on {self.name} from {ip}: {recv_err}")

            # Log attack - even if no data received (connection attempt itself is suspicious)
            text = data.decode('utf-8', errors='ignore') if data else ''
            attack_data = {
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'service': self.name,
                'port': self.port,
                'source_ip': ip,
                'input': text,
                'input_hex': data.hex() if data else '',
                'keywords_matched': [k for k in self.keywords if k.lower() in text.lower()] if text else []
            }

            RealHoneypot.log_attack(attack_data)
            attack_logged = True
            print(f"[HONEYPOT] 🎯 Attack logged: {self.name} from {ip} ({len(data) if data else 0} bytes)")
            logger.info(f"[HONEYPOT] Attack logged: {self.name} from {ip} ({len(data) if data else 0} bytes)")

        except Exception as e:
            # Even if something went wrong above, we still want to record
            # that this IP touched a honeypot port.
            print(f"[HONEYPOT] ⚠️ Client error on {self.name} from {ip}: {e}")
            logger.debug(f"[HONEYPOT] Client error on {self.name} from {ip}: {e}")

            if not attack_logged:
                try:
                    fallback_attack = {
                        'timestamp': datetime.now(timezone.utc).isoformat(),
                        'service': self.name,
                        'port': self.port,
                        'source_ip': ip,
                        'input': '',
                        'input_hex': '',
                        'keywords_matched': []
                    }
                    RealHoneypot.log_attack(fallback_attack)
                    print(f"[HONEYPOT] 🎯 Attack (fallback) logged: {self.name} from {ip} (0 bytes)")
                except Exception as log_err:
                    logger.debug(f"[HONEYPOT] Failed to log fallback attack for {ip}: {log_err}")
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
        """Define all available honeypot services with REALISTIC banners for recon/enumeration"""
        # Optional global port offset so advanced operators can shift honeypots
        # away from the default ports. By default this is 0, so we use the
        # classic ports (2121, 2222, 2323, 8080, 3306, 2525, 3389).
        port_offset = 0
        offset_env = os.getenv('HONEYPOT_PORT_OFFSET')
        if offset_env is not None and offset_env != "":
            try:
                port_offset = int(offset_env)
                logger.info(f"[HONEYPOT] Using configured port offset from HONEYPOT_PORT_OFFSET={port_offset}")
            except Exception as e:
                logger.warning(f"[HONEYPOT] Invalid HONEYPOT_PORT_OFFSET value '{offset_env}', defaulting to 0: {e}")
                port_offset = 0

        services_config = {
            'ssh': {
                'name': 'Fake SSH',
                'port': 2222,
                'banner': 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n',  # Realistic Ubuntu SSH banner
                'keywords': ['root', 'admin', 'password', 'login']
            },
            'ftp': {
                'name': 'Fake FTP',
                'port': 2121,
                'banner': '220 (vsFTPd 3.0.5)\r\n',  # Realistic vsFTPd banner (most common FTP server)
                'keywords': ['USER', 'PASS', 'RETR', 'LIST']
            },
            'telnet': {
                'name': 'Fake Telnet',
                'port': 2323,
                'banner': 'Ubuntu 22.04.3 LTS\r\nwifi-router login: ',  # Realistic Linux telnet banner
                'keywords': ['login', 'password', 'admin', 'root']
            },
            'http_admin': {
                'name': 'Fake Admin Panel',
                'port': 8080,
                'banner': 'HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Type: text/html\r\nX-Powered-By: PHP/8.2.12\r\n\r\n<!DOCTYPE html><html><head><title>Router Admin Panel</title></head><body><h2>Login</h2><form><input name="username" placeholder="Username"><input type="password" name="password" placeholder="Password"><button>Login</button></form></body></html>',  # Realistic router admin panel
                'keywords': ['admin', 'login', 'password', 'username']
            },
            'mysql': {
                'name': 'Fake MySQL',
                'port': 3306,
                'banner': b'\x5a\x00\x00\x00\x0a\x38\x2e\x30\x2e\x33\x35\x00\x2d\x00\x00\x00\x12\x34\x56\x78\x00\xff\xf7\x21\x02\x00\xff\x81\x15\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x7e\x4b\x3d\x50\x6f\x63\x79\x64\x71\x77\x6b\x00\x6d\x79\x73\x71\x6c\x5f\x6e\x61\x74\x69\x76\x65\x5f\x70\x61\x73\x73\x77\x6f\x72\x64\x00',  # Realistic MySQL 8.0.35 handshake packet
                'keywords': ['mysql', 'database', 'select', 'root']
            },
            'smtp': {
                'name': 'Fake SMTP',
                'port': 2525,
                'banner': '220 mail.homeserver.local ESMTP Postfix (Ubuntu)\r\n',  # Realistic Postfix banner
                'keywords': ['MAIL', 'RCPT', 'DATA', 'HELO']
            },
            'rdp': {
                'name': 'Fake RDP',
                'port': 3389,
                'banner': b'\x03\x00\x00\x13\x0e\xd0\x00\x00\x124\x00\x02\x1f\x08\x00\x02\x00\x00\x00',  # Realistic Windows Server 2019 RDP response
                'keywords': ['rdp', 'windows', 'remote']
            }
        }
        
        for service_id, config in services_config.items():
            self.services[service_id] = HoneypotService(
                name=config['name'],
                port=config['port'] + port_offset,
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

    def start_selected(self, service_ids: List[str]) -> Dict[str, bool]:
        """Start only the selected honeypot services.

        Used by the dashboard when an operator bulk-selects specific
        services to run instead of enabling the full set.
        """
        results: Dict[str, bool] = {}

        # Start only the requested services; unknown IDs are recorded as False
        for service_id in service_ids:
            service = self.services.get(service_id)
            if not service:
                results[service_id] = False
                continue
            results[service_id] = service.start()

        # Recalculate global running flag based on any active service
        active_count = sum(1 for s in self.services.values() if s.running)
        self.running = active_count > 0

        if self.running:
            logger.info(f"[HONEYPOT] ✅ Selected services started; {active_count}/{len(self.services)} total services running")
        else:
            logger.error("[HONEYPOT] ❌ Failed to start any of the selected honeypot services!")

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

        # Sanitize payload/input before any persistence to avoid storing full exploit content
        sanitized_attack = dict(attack_data)  # shallow copy
        raw_input = sanitized_attack.get('input', '')
        if isinstance(raw_input, str) and raw_input:
            # Keep only a short preview and length; drop full payload
            sanitized_attack['input_preview'] = raw_input[:200]
            sanitized_attack['input_length'] = len(raw_input)
            sanitized_attack.pop('input', None)
        # input_hex is already a hex representation; keep as-is for forensics

        instance.attack_log.append(sanitized_attack)
        
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
            attacks.append(sanitized_attack)
            
            # Save back
            with open(HONEYPOT_ATTACKS_FILE, 'w') as f:
                json.dump(attacks, f, indent=2)
            
            print(f"[HONEYPOT] ✅ Attack saved! Total attacks: {len(attacks)}")
            logger.info(f"[HONEYPOT] Attack from {attack_data['source_ip']} on {attack_data['service']} logged to sandbox")
            
        except Exception as e:
            logger.error(f"[HONEYPOT] Failed to log attack: {e}")

        # Feed this honeypot interaction into the main AI threat log so it
        # appears in Section 7 "Live Threats" and downstream analytics.
        try:
            try:
                from AI.pcs_ai import log_honeypot_attack
            except ImportError:
                log_honeypot_attack = None

            if log_honeypot_attack is not None:
                ip = attack_data.get('source_ip', '0.0.0.0')
                service_name = attack_data.get('service', 'Unknown service')
                port = attack_data.get('port') or attack_data.get('source_port')
                preview = sanitized_attack.get('input_preview', '') or ''
                input_length = sanitized_attack.get('input_length', 0)

                # Build a compact, privacy-safe description
                base_detail = f"{service_name} honeypot hit on port {port} from {ip}"
                detail_parts = [base_detail]
                if preview:
                    detail_parts.append(f"payload='{preview[:100]}'")
                if input_length:
                    detail_parts.append(f"len={input_length}")
                details = " | ".join(detail_parts)

                persona_safe = str(service_name).lower().replace(' ', '_') if service_name else 'unknown'

                threat_data = {
                    'ip_address': ip,
                    'threat_type': f"honeypot_{persona_safe}",
                    'level': 'CRITICAL',  # All real honeypot hits are treated as high severity
                    'details': details,
                    'timestamp': attack_data.get('timestamp') or datetime.now(timezone.utc).isoformat(),
                    'honeypot_persona': service_name,
                    'honeypot_port': port,
                    'analysis': {
                        'attack_category': 'honeypot_probe',
                        'suspicion_score': 0.95,
                    },
                }

                log_honeypot_attack(threat_data)
        except Exception as ai_err:
            logger.debug(f"[HONEYPOT] Failed to feed honeypot attack into AI threat log: {ai_err}")
        
        # Extract attack pattern for relay distribution
        instance._extract_pattern(attack_data)
        
        # Block the attacker's IP
        instance._block_attacker_ip(attack_data['source_ip'])
    
    def _block_attacker_ip(self, ip: str):
        """Immediately block any IP that touches a real honeypot service.

        This is intentionally more aggressive than other detectors: *any* interaction
        with the real honeypot ports results in an immediate, permanent block.
        """
        try:
            # Time to block immediately on first honeypot interaction
            first_attack_time = _honeypot_attack_tracker[ip] or datetime.now(timezone.utc)
            _honeypot_attack_tracker[ip] = first_attack_time

            blocked_ips_file = get_blocked_ips_file()
            
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
                'reason': 'Immediate block: direct interaction with real honeypot service',
                'source': 'honeypot',
                'first_attack': first_attack_time.isoformat(),
                'attacks_duration': '0s',
                'permanent': True
            }
            
            blocked_data['blocked_ips'].append(blocked_entry)
            
            # Save back
            with open(blocked_ips_file, 'w') as f:
                json.dump(blocked_data, f, indent=2)
            
            logger.info(f"[HONEYPOT] Immediately blocked attacker IP {ip} for honeypot interaction")
            print(f"[HONEYPOT] 🚫 Blocked attacker IP: {ip}")
            logger.info(f"[HONEYPOT] Blocked attacker IP: {ip}")

            # Keep AI engine's in-memory blocklist in sync so the dashboard
            # and request interceptor see this IP as blocked immediately.
            try:
                import AI.pcs_ai as pcs_ai
                pcs_ai._block_ip(ip)
            except Exception as sync_error:
                logger.debug(f"[HONEYPOT] Failed to sync blocked IP {ip} to AI engine: {sync_error}")
            
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

def start_selected_honeypots(service_ids: List[str]) -> Dict[str, bool]:
    """Start only a selected subset of honeypot services.

    This is used by the dashboard list-selector so operators can
    enable specific services in bulk instead of all-at-once.
    """
    hp = get_honeypot()
    return hp.start_selected(service_ids)

def get_honeypot_status() -> Dict:
    """Get honeypot status"""
    hp = get_honeypot()
    return hp.get_status()
