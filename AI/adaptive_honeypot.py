#!/usr/bin/env python3
"""
Adaptive Honeypot - Single honeypot that morphs into different services
Can impersonate FTP, SSH, HTTP, Telnet, MySQL, etc. by changing port and signature
"""

import socket
import threading
import logging
import time
import json
import re
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from AI.path_helper import get_json_file

logger = logging.getLogger(__name__)


_HONEYPOT_LOG_FILE = get_json_file('honeypot_attacks.json')


def _get_local_time() -> datetime:
    """Get current datetime in configured timezone (TZ env), fallback to UTC."""
    try:
        # Use timezone-aware datetime with UTC
        return datetime.now(timezone.utc)
    except Exception:
        return datetime.now(timezone.utc)


class AdaptiveHoneypot:
    """
    Single honeypot that can impersonate multiple services
    Changes behavior based on configured persona
    """
    
    def __init__(self):
        self.running = False
        self.server_thread = None
        self.server_socket = None
        self.attack_log = []
        self.ip_stats: Dict[str, Dict[str, Any]] = {}
        
        # Current configuration
        self.enabled = False
        self.current_persona = "http_admin"
        self.current_port = 8080
        self.custom_banner = None
        
        # Service personas with templates
        self.personas = {
            "http_admin": {
                "name": "HTTP Admin Panel",
                "default_port": 8080,
                "protocol": "TCP",
                "banner": "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\nContent-Type: text/html\r\n\r\n<html><title>Admin Login</title><body><h1>Admin Panel Login</h1></body></html>",
                "keywords": ["admin", "login", "password"]
            },
            "ftp": {
                "name": "FTP Server",
                "default_port": 2121,
                "protocol": "TCP",
                "banner": "220 ProFTPD 1.3.5 Server (Welcome) [::ffff:0.0.0.0]\r\n",
                "keywords": ["USER", "PASS", "LIST", "RETR"]
            },
            "ssh": {
                "name": "SSH Server",
                "default_port": 2222,
                "protocol": "TCP",
                "banner": "SSH-2.0-OpenSSH_7.4\r\n",
                "keywords": ["ssh", "publickey", "password"]
            },
            "telnet": {
                "name": "Telnet Server",
                "default_port": 2323,
                "protocol": "TCP",
                "banner": "Welcome to Telnet Server\r\nLogin: ",
                "keywords": ["login", "password", "admin"]
            },
            "mysql": {
                "name": "MySQL Server",
                "default_port": 3306,
                "protocol": "TCP",
                "banner": b"\x4a\x00\x00\x00\x0a\x35\x2e\x37\x2e\x32\x39\x00",  # MySQL handshake
                "keywords": ["mysql", "database", "root"]
            },
            "rdp": {
                "name": "Windows RDP",
                "default_port": 3389,
                "protocol": "TCP",
                "banner": b"\x03\x00\x00\x13\x0e\xd0\x00\x00\x124\x00\x02",  # RDP connection response
                "keywords": ["rdp", "windows", "remote"]
            },
            "smtp": {
                "name": "SMTP Mail Server",
                "default_port": 2525,
                "protocol": "TCP",
                "banner": "220 mail.example.com ESMTP Postfix\r\n",
                "keywords": ["MAIL", "RCPT", "DATA", "HELO"]
            },
            "http_wordpress": {
                "name": "WordPress Site",
                "default_port": 8081,
                "protocol": "TCP",
                "banner": "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nX-Powered-By: PHP/7.4\r\n\r\n<html><title>WordPress</title></html>",
                "keywords": ["wp-admin", "wp-login", "xmlrpc"]
            },
            "http_phpmyadmin": {
                "name": "phpMyAdmin",
                "default_port": 8082,
                "protocol": "TCP",
                "banner": "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\n\r\n<html><title>phpMyAdmin</title></html>",
                "keywords": ["phpmyadmin", "database", "sql"]
            },
            "smb": {
                "name": "Windows SMB",
                "default_port": 445,
                "protocol": "TCP",
                "banner": b"\x00\x00\x00\x90FFSMB",  # Minimal SMB signature
                "keywords": ["smb", "cifs", "share"]
            },
            "vnc": {
                "name": "VNC Remote Desktop",
                "default_port": 5900,
                "protocol": "TCP",
                "banner": "RFB 003.008\n",
                "keywords": ["vnc", "remote", "desktop"]
            },
            "docker_api": {
                "name": "Docker API",
                "default_port": 2375,
                "protocol": "TCP",
                "banner": "HTTP/1.1 200 OK\r\nApi-Version: 1.41\r\nDocker-Experimental: false\r\n\r\n",
                "keywords": ["docker", "container", "api"]
            },
            "redis": {
                "name": "Redis Database",
                "default_port": 6379,
                "protocol": "TCP",
                "banner": "+PONG\r\n",
                "keywords": ["redis", "set", "get", "ping"]
            },
            "ldap": {
                "name": "LDAP Directory",
                "default_port": 389,
                "protocol": "TCP",
                "banner": "LDAPv3 ready\r\n",
                "keywords": ["ldap", "bind", "cn=", "dc="]
            },
            "kubernetes_api": {
                "name": "Kubernetes API Server",
                "default_port": 6443,
                "protocol": "TCP",
                "banner": "HTTP/2 200\r\nServer: kube-apiserver\r\n\r\n",
                "keywords": ["kubernetes", "kube-system", "api/v1"]
            },
            "elasticsearch": {
                "name": "Elasticsearch Cluster",
                "default_port": 9200,
                "protocol": "TCP",
                "banner": "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"cluster_name\":\"es-cluster\"}",
                "keywords": ["elasticsearch", "_search", "index"]
            }
        }

        # Load any previously persisted honeypot attacks
        self._load_persistent_log()
    
    def get_available_personas(self) -> Dict:
        """Get list of available service personas"""
        return {
            key: {
                "name": persona["name"],
                "default_port": persona["default_port"],
                "protocol": persona["protocol"]
            }
            for key, persona in self.personas.items()
        }
    
    def configure(self, persona: str, port: int, custom_banner: Optional[str] = None) -> bool:
        """
        Configure honeypot to impersonate a specific service
        
        Args:
            persona: Service type to impersonate (e.g., 'ftp', 'ssh', 'http_admin')
            port: Port number to listen on
            custom_banner: Optional custom banner/signature
        """
        if persona not in self.personas:
            logger.error(f"Unknown persona: {persona}")
            return False
        
        # Stop if running
        if self.running:
            self.stop()
        
        self.current_persona = persona
        self.current_port = port
        self.custom_banner = custom_banner
        
        logger.info(f"Honeypot configured: {self.personas[persona]['name']} on port {port}")
        return True
    
    def start(self) -> bool:
        """Start the adaptive honeypot"""
        if self.running:
            logger.warning("Honeypot already running")
            return False
        
        try:
            self.running = True
            self.enabled = True
            self.server_thread = threading.Thread(target=self._run_server, daemon=True)
            self.server_thread.start()
            
            persona_name = self.personas[self.current_persona]["name"]
            logger.info(f"[HONEYPOT] Started: {persona_name} on port {self.current_port}")
            return True
        except Exception as e:
            logger.error(f"Failed to start honeypot: {e}")
            self.running = False
            self.enabled = False
            return False
    
    def stop(self):
        """Stop the honeypot"""
        self.running = False
        self.enabled = False
        
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception:
                pass

        logger.info("[HONEYPOT] Stopped")
    
    def _run_server(self):
        """Main server loop"""
        try:
            # Create socket
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('0.0.0.0', self.current_port))
            self.server_socket.listen(5)
            self.server_socket.settimeout(1.0)  # Timeout for clean shutdown
            
            logger.info(f"Listening on port {self.current_port}")
            
            while self.running:
                try:
                    client_socket, address = self.server_socket.accept()
                    # Handle connection in separate thread
                    threading.Thread(
                        target=self._handle_connection,
                        args=(client_socket, address),
                        daemon=True
                    ).start()
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        logger.error(f"Accept error: {e}")
        
        except Exception as e:
            logger.error(f"Server error: {e}")
        finally:
            if self.server_socket:
                self.server_socket.close()
    
    def _handle_connection(self, client_socket: socket.socket, address: tuple):
        """Handle incoming connection"""
        try:
            ip_address = address[0]
            port = address[1]
            
            # Get persona configuration
            persona = self.personas[self.current_persona]
            
            # Send banner
            banner = self.custom_banner if self.custom_banner else persona["banner"]
            if isinstance(banner, str):
                banner = banner.encode('utf-8')
            client_socket.send(banner)
            
            # Receive attacker's input
            try:
                client_socket.settimeout(5.0)
                data = client_socket.recv(4096)
                attacker_input = data.decode('utf-8', errors='ignore')
            except Exception:
                attacker_input = "<no input>"

            ip_stats = self._update_ip_stats(ip_address)
            analysis = self._analyze_attacker_input(attacker_input, self.current_persona, ip_stats)
            
            # Log attack
            attack_entry = {
                'timestamp': _get_local_time().isoformat(),
                'source_ip': ip_address,
                'source_port': port,
                'honeypot_persona': self.current_persona,
                'honeypot_port': self.current_port,
                'service_name': persona['name'],
                'attacker_input': attacker_input[:500],  # Limit size
                'banner_sent': banner.decode('utf-8', errors='ignore')[:200],
                'analysis': analysis
            }
            
            self.attack_log.append(attack_entry)
            
            # Log to console
            category = analysis.get('attack_category', 'unknown') if isinstance(analysis, dict) else 'unknown'
            score = analysis.get('suspicion_score') if isinstance(analysis, dict) else None
            logger.warning(f"🎣 HONEYPOT HIT: {ip_address}:{port} → {persona['name']} (port {self.current_port}) [category={category}]")
            if attacker_input:
                logger.info(f"Attacker sent: {attacker_input[:100]}")
            if score is not None:
                logger.info(f"Honeypot analysis suspicion score: {score:.2f}")
            
            # Persist log and feed attack to AI training (sandbox)
            self._save_persistent_log()

            self._feed_to_ai_training(attack_entry)
            
            # Keep log size manageable
            if len(self.attack_log) > 1000:
                self.attack_log = self.attack_log[-500:]
                self._save_persistent_log()
        
        except Exception as e:
            logger.error(f"Connection handler error: {e}")
        finally:
            try:
                client_socket.close()
            except Exception:
                pass
    
    def get_status(self) -> Dict:
        """Get current honeypot status"""
        # Aggregate metrics
        persona_counts: Dict[str, int] = {}
        category_counts: Dict[str, int] = {}
        attacker_counts: Dict[str, int] = {}
        suspicion_scores: List[float] = []

        for entry in self.attack_log:
            persona = entry.get('honeypot_persona', self.current_persona)
            persona_counts[persona] = persona_counts.get(persona, 0) + 1

            analysis = entry.get('analysis') or {}
            category = analysis.get('attack_category', 'unknown')
            category_counts[category] = category_counts.get(category, 0) + 1

            score = analysis.get('suspicion_score')
            if isinstance(score, (int, float)):
                suspicion_scores.append(float(score))

            ip = entry.get('source_ip')
            if ip:
                attacker_counts[ip] = attacker_counts.get(ip, 0) + 1

        avg_suspicion = sum(suspicion_scores) / len(suspicion_scores) if suspicion_scores else 0.0

        # Top attackers by honeypot hits (up to 5)
        top_attackers = []
        if attacker_counts:
            sorted_attackers = sorted(attacker_counts.items(), key=lambda kv: kv[1], reverse=True)[:5]
            top_attackers = [
                {'ip': ip, 'hits': count}
                for ip, count in sorted_attackers
            ]

        return {
            'enabled': self.enabled,
            'running': self.running,
            'current_persona': self.current_persona,
            'persona_name': self.personas[self.current_persona]['name'],
            'port': self.current_port,
            'total_attacks': len(self.attack_log),
            'recent_attacks': self.attack_log[-10:] if self.attack_log else [],
            'persona_attack_counts': persona_counts,
            'attack_categories': category_counts,
            'average_suspicion_score': avg_suspicion,
            'top_attackers': top_attackers
        }
    
    def get_attack_log(self, limit: int = 100) -> List[Dict]:
        """Get recent attack log"""
        return self.attack_log[-limit:] if self.attack_log else []

    def get_full_attack_log(self) -> List[Dict]:
        """Get full persisted attack log (bounded to last 1000 entries)."""
        return list(self.attack_log) if self.attack_log else []
    
    def clear_log(self):
        """Clear attack log"""
        self.attack_log = []
        logger.info("Honeypot attack log cleared")
        self._save_persistent_log()

    def _load_persistent_log(self) -> None:
        """Load honeypot attacks from persistent storage if available."""
        try:
            if os.path.exists(_HONEYPOT_LOG_FILE):
                with open(_HONEYPOT_LOG_FILE, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        # Keep at most 1000 entries to avoid unbounded growth
                        self.attack_log = data[-1000:]
                        logger.info(f"Loaded {len(self.attack_log)} honeypot attacks from disk")
        except Exception as e:
            logger.warning(f"Failed to load honeypot log from disk: {e}")

    def _save_persistent_log(self) -> None:
        """Persist honeypot attacks to disk for durability across restarts."""
        try:
            os.makedirs(os.path.dirname(_HONEYPOT_LOG_FILE), exist_ok=True)
            # Save a bounded window of attacks
            to_save = self.attack_log[-1000:]
            with open(_HONEYPOT_LOG_FILE, 'w', encoding='utf-8') as f:
                json.dump(to_save, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.error(f"Failed to save honeypot log to disk: {e}")

    def _update_ip_stats(self, ip_address: str) -> Dict[str, Any]:
        """Update per-IP statistics for honeypot interactions."""
        now = time.time()
        stats = self.ip_stats.get(ip_address)
        if not stats:
            stats = {
                'total_hits': 0,
                'first_seen': now,
                'last_seen': now
            }
        stats['total_hits'] += 1
        stats['last_seen'] = now
        self.ip_stats[ip_address] = stats
        return stats

    def _analyze_attacker_input(self, attacker_input: str, persona_key: str, ip_stats: Dict[str, Any]) -> Dict[str, Any]:
        """Lightweight heuristic analysis of honeypot input to enrich AI signals."""
        text = attacker_input or ""
        lowercase = text.lower()
        input_length = len(text)

        persona = self.personas.get(persona_key, {})
        persona_keywords = persona.get('keywords', [])
        matched_keywords = [k for k in persona_keywords if k.lower() in lowercase]

        has_binary_data = any(ord(ch) < 9 or ord(ch) > 126 for ch in text[:64]) if text else False

        suspicious_tags: List[str] = []

        if any(token in lowercase for token in ["union select", "select ", " or 1=1", "information_schema", "sqlmap"]):
            suspicious_tags.append("sql_injection")
        if any(token in lowercase for token in ["<script", "javascript:", "onerror=", "onload=", "document.cookie"]):
            suspicious_tags.append("xss")
        if any(token in lowercase for token in [";rm ", ";cat ", ";wget ", ";curl ", "bash -c", "sh -c", "&&", "||"]):
            suspicious_tags.append("command_injection")
        if any(token in lowercase for token in ["user ", "pass ", "login", "password"]):
            suspicious_tags.append("credential_guess")
        if any(token in lowercase for token in ["wp-admin", "wp-login", "xmlrpc.php"]):
            suspicious_tags.append("wordpress_probe")
        if any(token in lowercase for token in ["phpmyadmin", "select * from", "drop table"]):
            suspicious_tags.append("db_admin_probe")
        if persona_key in ["redis", "docker_api", "mysql"]:
            suspicious_tags.append("service_exploitation_probe")

        if not text or text == "<no input>":
            attack_category = "empty_probe"
        elif "sql_injection" in suspicious_tags:
            attack_category = "sql_injection"
        elif "command_injection" in suspicious_tags:
            attack_category = "command_injection"
        elif "xss" in suspicious_tags:
            attack_category = "xss"
        elif "credential_guess" in suspicious_tags:
            attack_category = "credential_guess"
        elif "wordpress_probe" in suspicious_tags or "db_admin_probe" in suspicious_tags:
            attack_category = "app_enumeration"
        elif has_binary_data:
            attack_category = "binary_probe"
        else:
            attack_category = "generic_probe"

        base_score = 0.6
        base_score += 0.1 * min(len(suspicious_tags), 3)
        base_score += 0.05 * min(len(matched_keywords), 3)
        if ip_stats.get('total_hits', 0) > 5:
            base_score += 0.15
        if has_binary_data:
            base_score += 0.05
        suspicion_score = max(0.0, min(base_score, 1.0))

        return {
            'attack_category': attack_category,
            'input_length': input_length,
            'matched_keywords': matched_keywords,
            'suspicious_tags': suspicious_tags,
            'has_binary_data': has_binary_data,
            'suspicion_score': suspicion_score,
            'ip_total_hits': ip_stats.get('total_hits', 1)
        }
    
    def _feed_to_ai_training(self, attack_entry: Dict):
        """
        Feed honeypot attack to AI training system
        This is the sandbox - all attacks are safely logged and used to train ML models
        """
        try:
            # Import AI module (lazy import to avoid circular dependency)
            from AI.pcs_ai import log_honeypot_attack
            
            # Convert attack to threat log format
            analysis = attack_entry.get('analysis') or {}
            analysis_summary_parts = []
            category = analysis.get('attack_category')
            if category:
                analysis_summary_parts.append(f"category={category}")
            score = analysis.get('suspicion_score')
            if isinstance(score, (int, float)):
                analysis_summary_parts.append(f"score={score:.2f}")
            ip_hits = analysis.get('ip_total_hits')
            if isinstance(ip_hits, int) and ip_hits > 1:
                analysis_summary_parts.append(f"ip_total_hits={ip_hits}")
            analysis_summary = ", ".join(analysis_summary_parts)

            base_detail = f"{attack_entry['service_name']} attack: {attack_entry['attacker_input'][:100]}"
            if analysis_summary:
                details = f"{base_detail} ({analysis_summary})"
            else:
                details = base_detail

            threat_data = {
                'ip_address': attack_entry['source_ip'],
                'threat_type': f"honeypot_{attack_entry['honeypot_persona']}",
                'level': 'DANGEROUS',  # All honeypot hits are suspicious
                'details': details,
                'timestamp': attack_entry['timestamp'],
                'source': 'honeypot',
                'honeypot_persona': attack_entry['honeypot_persona'],
                'honeypot_port': attack_entry['honeypot_port'],
                'analysis': analysis
            }
            
            # Feed to AI
            log_honeypot_attack(threat_data)
            logger.info(f"🤖 Fed attack to AI training: {attack_entry['source_ip']}")
            
        except ImportError:
            # AI module not available, skip
            pass
        except Exception as e:
            logger.error(f"Failed to feed attack to AI: {e}")


# Global instance
_honeypot = None

def get_honeypot() -> AdaptiveHoneypot:
    """Get or create global honeypot instance"""
    global _honeypot
    if _honeypot is None:
        _honeypot = AdaptiveHoneypot()
    return _honeypot


# Convenience functions
def start_honeypot(persona: str, port: int, custom_banner: Optional[str] = None) -> bool:
    """Start honeypot with specified configuration"""
    hp = get_honeypot()
    hp.configure(persona, port, custom_banner)
    return hp.start()

def stop_honeypot():
    """Stop the honeypot"""
    hp = get_honeypot()
    hp.stop()

def get_honeypot_status() -> Dict:
    """Get honeypot status"""
    hp = get_honeypot()
    return hp.get_status()

def get_available_personas() -> Dict:
    """Get available service personas"""
    hp = get_honeypot()
    return hp.get_available_personas()
