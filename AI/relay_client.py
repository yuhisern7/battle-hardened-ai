#!/usr/bin/env python3
"""
WebSocket Relay Client for Enterprise Security Mesh
Connects to an operator-controlled relay server (your VPS/cloud) and
shares **sanitized threat summaries only** with unlimited peers worldwide
(no raw JSON logs, packet payloads, or user PII are sent by this client).
"""

import os
import json
import time
import asyncio
import threading
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Callable
import websockets
from websockets.client import WebSocketClientProtocol

logger = logging.getLogger(__name__)

# Cryptographic security (optional, fallback gracefully)
try:
    from AI.crypto_security import get_message_security
    CRYPTO_ENABLED = os.getenv('RELAY_CRYPTO_ENABLED', 'true').lower() == 'true'
    if CRYPTO_ENABLED:
        logger.info("[RELAY] Cryptographic message signing enabled")
except ImportError:
    CRYPTO_ENABLED = False
    logger.warning("[RELAY] Cryptographic security not available (install cryptography package)")

# Node fingerprinting for peer compatibility
try:
    from AI.node_fingerprint import get_node_fingerprint
    NODE_FP_ENABLED = True
    logger.info("[RELAY] Node fingerprinting enabled - will filter incompatible peers")
except ImportError:
    NODE_FP_ENABLED = False
    logger.info("[RELAY] Node fingerprinting not available")


class RelayClient:
    """WebSocket client for relay-based P2P mesh"""
    
    def __init__(self):
        # Configuration
        self.relay_url = os.getenv('RELAY_URL', '')  # e.g., wss://relay.yourdomain.com:60001
        self.enabled = os.getenv('RELAY_ENABLED', 'false').lower() == 'true'
        self.peer_name = os.getenv('PEER_NAME', f'peer-{os.getpid()}')
        self.customer_id = os.getenv('CUSTOMER_ID', '')  # Unique customer identifier
        self.reconnect_delay = int(os.getenv('RELAY_RECONNECT_DELAY', '5'))
        
        # State
        self.websocket: Optional[WebSocketClientProtocol] = None
        self.running = False
        self.connected = False
        self.threat_queue = []
        self.received_threats = {}
        self.lock = threading.Lock()
        
        # Callback for when threats are received
        self.on_threat_received: Optional[Callable] = None
        
        # Statistics
        self.threats_sent = 0
        self.threats_received = 0
        # Global statistics reported by relay server (authoritative mesh-wide view)
        self.global_threats_shared = 0
        self.connection_errors = 0
        self.last_heartbeat = None
        self.active_peers = 0
        self.seen_peers = set()  # Track unique peer names we've seen
        # Internal counter so we occasionally request fresh stats from relay
        self._heartbeat_count = 0
        
        # Background thread
        self.relay_thread = None
        self.loop = None
        
        if self.enabled and self.relay_url:
            logger.info(f"🌐 Relay client initialized: {self.relay_url}")
            logger.info(f"📡 Peer name: {self.peer_name}")
            if self.customer_id:
                logger.info(f"🔑 Customer ID: {self.customer_id}")
            else:
                logger.warning("⚠️  No CUSTOMER_ID configured - crypto verification will fail")
        elif self.enabled:
            logger.warning("⚠️  Relay enabled but RELAY_URL not configured")
    
    def start(self, on_threat_received: Optional[Callable] = None):
        """Start relay client in background thread"""
        if not self.enabled:
            logger.info("Relay client disabled (set RELAY_ENABLED=true)")
            return
        
        if not self.relay_url:
            logger.warning("Relay client enabled but no RELAY_URL configured")
            return
        
        if self.running:
            logger.warning("Relay client already running")
            return
        
        self.on_threat_received = on_threat_received
        self.running = True
        
        # Start background thread with its own event loop
        self.relay_thread = threading.Thread(target=self._run_loop, daemon=True)
        self.relay_thread.start()
        
        logger.info(f"✅ Relay client started: {self.relay_url}")
    
    def stop(self):
        """Stop relay client"""
        self.running = False
        if self.relay_thread:
            self.relay_thread.join(timeout=5)
        logger.info("🛑 Relay client stopped")
    
    def add_threat(self, threat: Dict[str, Any]):
        """Queue a threat to broadcast via relay"""
        # Sanitize and prepare threat
        safe_threat = {
            'type': 'threat',
            'threat_id': f"{self.peer_name}-{int(time.time() * 1000)}",
            'source_peer': self.peer_name,
            'customer_id': self.customer_id,  # Include customer ID for per-customer crypto
            'attack_type': threat.get('attack_type', 'unknown'),
            'severity': threat.get('severity', 'medium'),
            'src_ip': threat.get('src_ip', ''),
            'geolocation': threat.get('geolocation', {}),
            'timestamp': threat.get('timestamp', datetime.now(timezone.utc).isoformat()),
            'ml_confidence': threat.get('ml_confidence', 0.0),
            'exploit_match': threat.get('exploit_match', ''),
            'cve_match': threat.get('cve_match', []),
            'extracted_signatures': threat.get('extracted_signatures', {}),  # PATTERNS ONLY - no payloads
        }
        
        # Add node fingerprint for peer compatibility filtering
        if NODE_FP_ENABLED:
            assert 'get_node_fingerprint' in globals(), "get_node_fingerprint not available"
            node_fp = get_node_fingerprint()  # type: ignore[possibly-unbound]
            safe_threat['node_fingerprint'] = {
                'node_type': node_fp.fingerprint['node_type'],
                'os': node_fp.fingerprint['os_info']['system'],
                'traffic_profile': node_fp.fingerprint['traffic_profile'],
                'fingerprint_hash': node_fp.fingerprint['fingerprint_hash'][:32]
            }
        
        with self.lock:
            self.threat_queue.append(safe_threat)
        
        logger.debug(f"📤 Queued threat: {safe_threat['attack_type']} from {safe_threat['src_ip']}")
    
    def get_status(self) -> Dict[str, Any]:
        """Get relay client status"""
        with self.lock:
            # ALWAYS use the relay server's active_peers count - it's authoritative!
            # Don't calculate or second-guess it
            return {
                'enabled': self.enabled,
                'connected': self.connected,
                'relay_url': self.relay_url,
                'peer_name': self.peer_name,
                'active_peers': self.active_peers,  # Trust the relay server
                'seen_peers': len(self.seen_peers),  # How many unique peers sent us threats
                'threats_queued': len(self.threat_queue),
                'threats_sent': self.threats_sent,
                'threats_received': self.threats_received,
                # Mesh-wide total threats shared across all connected servers
                'global_threats_shared': self.global_threats_shared,
                'connection_errors': self.connection_errors,
                'last_heartbeat': self.last_heartbeat,
            }
    
    def _run_loop(self):
        """Run event loop in background thread"""
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        
        try:
            self.loop.run_until_complete(self._relay_loop())
        except Exception as e:
            logger.error(f"Relay loop error: {e}")
        finally:
            self.loop.close()
    
    async def _relay_loop(self):
        """Main relay connection loop with auto-reconnect"""
        while self.running:
            try:
                logger.info(f"🔌 Connecting to relay: {self.relay_url}")
                
                # SSL context for WSS (WebSocket Secure)
                ssl_context = None
                if self.relay_url.startswith('wss://'):
                    import ssl as ssl_module
                    ssl_context = ssl_module.create_default_context()
                    
                    # Allow self-signed certificates (for development/testing)
                    # In production, use proper CA-signed certificates
                    ssl_context.check_hostname = False
                    ssl_context.verify_mode = ssl_module.CERT_NONE
                    logger.info(f"🔐 Using WSS (WebSocket Secure) with SSL verification disabled")
                
                async with websockets.connect(
                    self.relay_url,
                    ping_interval=20,
                    ping_timeout=30,
                    close_timeout=10,
                    ssl=ssl_context  # Enable SSL for WSS
                ) as websocket:
                    self.websocket = websocket
                    
                    with self.lock:
                        self.connected = True
                        self.connection_errors = 0
                    
                    logger.info(f"✅ Connected to relay server")
                    
                    # Handle messages
                    await self._handle_connection(websocket)
                    
            except websockets.exceptions.WebSocketException as e:
                logger.error(f"WebSocket error: {e}")
                with self.lock:
                    self.connected = False
                    self.connection_errors += 1
            except Exception as e:
                logger.error(f"Relay connection error: {e}")
                with self.lock:
                    self.connected = False
                    self.connection_errors += 1
            
            # Reconnect delay
            if self.running:
                logger.info(f"⏳ Reconnecting in {self.reconnect_delay}s...")
                await asyncio.sleep(self.reconnect_delay)
    
    async def _handle_connection(self, websocket: WebSocketClientProtocol):
        """Handle active WebSocket connection"""
        # Create tasks for sending and receiving
        send_task = asyncio.create_task(self._send_threats(websocket))
        recv_task = asyncio.create_task(self._receive_messages(websocket))
        heartbeat_task = asyncio.create_task(self._send_heartbeats(websocket))
        
        # Wait for any task to complete (usually means disconnection)
        done, pending = await asyncio.wait(
            [send_task, recv_task, heartbeat_task],
            return_when=asyncio.FIRST_COMPLETED
        )
        
        # Log which task completed
        for task in done:
            task_name = "unknown"
            if task == send_task:
                task_name = "send_threats"
            elif task == recv_task:
                task_name = "receive_messages"
            elif task == heartbeat_task:
                task_name = "heartbeats"
            logger.error(f"[RELAY] Task '{task_name}' completed unexpectedly: {task.exception() if task.exception() else 'no error'}")
        
        # Cancel remaining tasks
        for task in pending:
            task.cancel()
    
    async def _send_threats(self, websocket: WebSocketClientProtocol):
        """Send queued threats to relay with cryptographic signing"""
        while True:
            try:
                # Get threats from queue
                with self.lock:
                    threats = self.threat_queue[:10]  # Send in batches
                    self.threat_queue = self.threat_queue[10:]
                
                # Send each threat
                for threat in threats:
                    # Sign message if crypto enabled
                    if CRYPTO_ENABLED:
                        try:
                            assert 'get_message_security' in globals(), "get_message_security not available"
                            security = get_message_security()  # type: ignore[possibly-unbound]
                            threat = security.sign_message(threat)
                            logger.debug(f"🔐 Signed threat message with HMAC+RSA")
                        except Exception as e:
                            logger.warning(f"Failed to sign message: {e}, sending unsigned")
                    
                    await websocket.send(json.dumps(threat))
                    with self.lock:
                        self.threats_sent += 1
                    logger.debug(f"📤 Sent threat: {threat['attack_type']}")
                
                # Wait before next batch
                await asyncio.sleep(1)
                
            except Exception as e:
                logger.error(f"Error sending threats: {e}")
                # Don't crash the connection - just wait and retry
                await asyncio.sleep(5)
    
    async def _receive_messages(self, websocket: WebSocketClientProtocol):
        """Receive messages from relay with cryptographic verification"""
        logger.debug("[RELAY] _receive_messages task started, waiting for messages...")
        async for message in websocket:
            try:
                data = json.loads(message)
                msg_type = data.get('type')
                logger.debug(f"[RELAY] Received message type: {msg_type}")
                
                # Verify signed messages (threats only, control messages are from trusted relay)
                if msg_type == 'threat' and CRYPTO_ENABLED:
                    try:
                        assert 'get_message_security' in globals(), "get_message_security not available"
                        security = get_message_security()  # type: ignore[possibly-unbound]
                        is_valid, reason = security.verify_message(data)
                        
                        if not is_valid:
                            logger.warning(f"🚫 Rejected threat message: {reason}")
                            continue  # Drop invalid message
                        
                        logger.debug(f"✅ Verified threat message (HMAC+timestamp+nonce)")
                    except Exception as e:
                        logger.warning(f"Message verification failed: {e}, dropping message")
                        continue
                
                if msg_type == 'welcome':
                    # Welcome message from relay
                    with self.lock:
                        self.active_peers = data.get('active_peers', 0)
                        # Relay includes its global total threats shared so far
                        total_shared = data.get('total_threats_shared')
                        if isinstance(total_shared, int):
                            self.global_threats_shared = total_shared
                    logger.info(f"🎉 Welcome! Active peers: {self.active_peers}")
                
                elif msg_type == 'heartbeat_ack':
                    # Heartbeat acknowledgment - relay may include updated peer count
                    with self.lock:
                        self.last_heartbeat = datetime.now(timezone.utc).isoformat()
                        # Update active_peers if relay sends it
                        if 'active_peers' in data:
                            self.active_peers = data.get('active_peers', 0)
                            logger.debug(f"Heartbeat: {self.active_peers} active peers")
                
                elif msg_type == 'peer_joined':
                    # Notification that a new peer joined
                    with self.lock:
                        self.active_peers = data.get('active_peers', self.active_peers)
                    logger.info(f"👋 Peer joined! Now {self.active_peers} active peers")
                
                elif msg_type == 'peer_left':
                    # Notification that a peer left
                    with self.lock:
                        self.active_peers = data.get('active_peers', self.active_peers)
                    logger.info(f"👋 Peer left. Now {self.active_peers} active peers")
                
                elif msg_type == 'threat':
                    # Threat from another peer
                    threat_id = data.get('threat_id')
                    source_peer = data.get('source_peer')
                    
                    # Check peer compatibility (filter incompatible nodes)
                    if NODE_FP_ENABLED and 'node_fingerprint' in data:
                        assert 'get_node_fingerprint' in globals(), "get_node_fingerprint not available"
                        node_fp = get_node_fingerprint()  # type: ignore[possibly-unbound]
                        peer_fp = data['node_fingerprint']
                        
                        compatibility = node_fp.get_compatibility_score(peer_fp)
                        
                        # Only accept threats from compatible peers (score > 0.5)
                        if compatibility < 0.5:
                            logger.debug(f"🚫 Rejected threat from incompatible peer {source_peer} "
                                       f"(compatibility: {compatibility:.2f}, node_type: {peer_fp.get('node_type')})")
                            continue
                        
                        logger.debug(f"✅ Accepted threat from compatible peer {source_peer} "
                                   f"(compatibility: {compatibility:.2f})")
                    
                    with self.lock:
                        # Track unique peers we've seen
                        if source_peer and source_peer != self.peer_name:
                            self.seen_peers.add(source_peer)
                        
                        # Avoid duplicates
                        if threat_id and threat_id not in self.received_threats:
                            self.received_threats[threat_id] = data
                            self.threats_received += 1
                            
                            logger.info(f"📥 Received threat from {data.get('source_peer')}: "
                                      f"{data.get('attack_type')}")
                            
                            # Callback to process threat
                            if self.on_threat_received:
                                try:
                                    self.on_threat_received(data)
                                except Exception as e:
                                    logger.error(f"Error in threat callback: {e}")
                
                elif msg_type == 'stats_response':
                    # Server statistics
                    stats = data.get('stats', {})
                    logger.info(f"📊 Relay stats: {stats}")
                    # Update mesh-wide global threats counter if present
                    with self.lock:
                        threats_shared = stats.get('threats_shared')
                        if isinstance(threats_shared, int):
                            self.global_threats_shared = threats_shared
                
            except json.JSONDecodeError:
                logger.error(f"Invalid JSON from relay: {message}")
            except Exception as e:
                logger.error(f"Error processing message: {e}")
    
    async def _send_heartbeats(self, websocket: WebSocketClientProtocol):
        """Send periodic heartbeats"""
        while True:
            try:
                await asyncio.sleep(30)
                await websocket.send(json.dumps({'type': 'heartbeat'}))
                # Periodically request full stats so we refresh global counters
                self._heartbeat_count += 1
                if self._heartbeat_count % 10 == 0:
                    try:
                        await websocket.send(json.dumps({'type': 'stats'}))
                    except Exception as e:
                        logger.error(f"Stats request error: {e}")
            except Exception as e:
                logger.error(f"Heartbeat error: {e}")
                # Don't crash - just retry
                await asyncio.sleep(5)


# Global singleton
_relay_client = None
_relay_lock = threading.Lock()


def get_relay_client() -> RelayClient:
    """Get global relay client instance"""
    global _relay_client
    
    if _relay_client is None:
        with _relay_lock:
            if _relay_client is None:
                _relay_client = RelayClient()
    
    return _relay_client


def start_relay_client(on_threat_received: Optional[Callable] = None):
    """Start relay client"""
    client = get_relay_client()
    client.start(on_threat_received)


def relay_threat(threat: Dict[str, Any]):
    """Broadcast threat via relay"""
    client = get_relay_client()
    if client.enabled:
        client.add_threat(threat)


def get_relay_status() -> Dict[str, Any]:
    """Get relay status"""
    client = get_relay_client()
    return client.get_status()


if __name__ == '__main__':
    # Test relay client
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    os.environ['RELAY_ENABLED'] = 'true'
    os.environ['RELAY_URL'] = 'ws://localhost:60001'
    os.environ['PEER_NAME'] = 'test-peer'
    
    def on_threat(threat):
        print(f"Received: {threat}")
    
    start_relay_client(on_threat)
    
    # Send test threat
    time.sleep(2)
    relay_threat({
        'attack_type': 'port_scan',
        'severity': 'high',
        'src_ip': '1.2.3.4'
    })
    
    try:
        while True:
            time.sleep(10)
            status = get_relay_status()
            print(f"\nStatus: {status}")
    except KeyboardInterrupt:
        client = get_relay_client()
        client.stop()
