#!/usr/bin/env python3
"""
Node-to-Relay Signature Uploader
Sends extracted attack signatures from security node to relay server database

Data Flow:
1. pcs_ai.py extracts signature from detected attack
2. Payload is DELETED immediately
3. upload_signature() sends ONLY pattern to relay
4. Relay stores signatures in file-based JSON (no SQL database)
5. Node receives confirmation

Privacy Guarantee:
- NO device lists sent
- NO network topology sent
- NO customer data sent
- ONLY attack pattern (keywords, encodings, hashes)
"""

import asyncio
import json
import logging
import os
import websockets
from typing import Dict, Any, Optional
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

SIGNATURE_UPLOAD_ENABLED = os.getenv("SIGNATURE_UPLOAD_ENABLED", "true").lower() == "true"


class SignatureUploader:
    """
    Uploads attack signatures to relay server
    Maintains connection to relay and handles signature transmission
    """
    
    def __init__(self, relay_url: str = "ws://localhost:60001"):
        self.relay_url = relay_url
        self.websocket = None
        self.connected = False
        self.signatures_sent = 0
        self.send_failures = 0
        self.enabled = SIGNATURE_UPLOAD_ENABLED
    
    async def connect(self):
        """Connect to relay server"""
        if not self.enabled:
            logger.info("SignatureUploader disabled via SIGNATURE_UPLOAD_ENABLED=false")
            return False

        try:
            self.websocket = await websockets.connect(self.relay_url)
            self.connected = True
            logger.info(f"✅ Connected to relay server: {self.relay_url}")
            
            # Receive welcome message
            welcome = await self.websocket.recv()
            welcome_data = json.loads(welcome)
            logger.info(f"Relay server: {welcome_data.get('relay_server', 'unknown')}")
            logger.info(f"Active peers: {welcome_data.get('active_peers', 0)}")
            
            return True
        except Exception as e:
            logger.error(f"Failed to connect to relay: {e}")
            self.connected = False
            return False
    
    async def disconnect(self):
        """Disconnect from relay server"""
        if self.websocket:
            await self.websocket.close()
            self.connected = False
            logger.info("Disconnected from relay server")
    
    async def upload_signature(self, signature: Dict[str, Any]) -> Dict[str, Any]:
        """
        Upload attack signature to relay server
        
        Args:
            signature: Dict containing:
                - attack_type: Type of attack
                - keywords: List of detected keywords
                - encodings: List of encoding types
                - payload_length: Original attack size
                - ml_features: Feature vector
        
        Returns:
            Dict with status and signature_id
        """
        
        if not self.enabled:
            logger.info("Signature upload skipped (SIGNATURE_UPLOAD_ENABLED=false)")
            return {'success': False, 'error': 'Signature uploading disabled'}

        if not self.connected:
            logger.warning("Not connected to relay, attempting reconnect...")
            if not await self.connect():
                return {'success': False, 'error': 'Not connected to relay'}
        
        try:
            # Validate signature (ensure NO prohibited data)
            if not self._validate_signature(signature):
                return {'success': False, 'error': 'Signature contains prohibited data'}
            
            # Prepare message
            message = {
                'type': 'signature_upload',
                'signature': signature,
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'node_version': '1.0.0'
            }
            
            # Send to relay
            await self.websocket.send(json.dumps(message))
            self.signatures_sent += 1
            
            logger.info(f"📤 Uploaded signature: {signature['attack_type']}")
            
            # Wait for confirmation (optional)
            try:
                response = await asyncio.wait_for(self.websocket.recv(), timeout=5.0)
                response_data = json.loads(response)
                return response_data
            except asyncio.TimeoutError:
                # Relay might not send immediate confirmation
                return {'success': True, 'note': 'Sent without confirmation'}
        
        except Exception as e:
            logger.error(f"Failed to upload signature: {e}")
            self.send_failures += 1
            self.connected = False
            return {'success': False, 'error': str(e)}
    
    def _validate_signature(self, signature: Dict[str, Any]) -> bool:
        """
        Validate signature before upload
        Ensure NO customer data included
        """
        
        # Prohibited fields that violate privacy
        prohibited_fields = [
            'device_list', 'ip_addresses', 'network_topology',
            'customer_id', 'organization_name', 'device_history',
            'blocked_ips', 'whitelist', 'connected_devices',
            'exploit_code', 'payload', 'attack_payload', 'malware_binary',
            'full_packet', 'pcap_data'
        ]
        
        for field in prohibited_fields:
            if field in signature:
                logger.error(f"❌ PRIVACY VIOLATION: Attempted to send '{field}'")
                return False
        
        # Required fields
        required_fields = ['attack_type', 'keywords', 'encodings']
        if not all(field in signature for field in required_fields):
            logger.error("Missing required fields in signature")
            return False
        
        return True
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get uploader statistics"""
        return {
            'connected': self.connected,
            'signatures_sent': self.signatures_sent,
            'send_failures': self.send_failures,
            'relay_url': self.relay_url
        }


# Global uploader instance
_uploader = None


def get_uploader(relay_url: str = "ws://localhost:60001") -> SignatureUploader:
    """Get or create global uploader instance"""
    global _uploader
    if _uploader is None:
        _uploader = SignatureUploader(relay_url)
    return _uploader


async def upload_signature_async(signature: Dict[str, Any], relay_url: str = "ws://localhost:60001") -> Dict[str, Any]:
    """
    Async wrapper for signature upload
    
    Usage in pcs_ai.py:
        import asyncio
        from signature_uploader import upload_signature_async
        
        # After extracting signature:
        asyncio.create_task(upload_signature_async(signature))
    """
    uploader = get_uploader(relay_url)
    
    if not uploader.connected:
        await uploader.connect()
    
    return await uploader.upload_signature(signature)


def upload_signature_sync(signature: Dict[str, Any], relay_url: str = "ws://localhost:60001") -> Dict[str, Any]:
    """
    Synchronous wrapper for signature upload (for non-async code)
    
    Usage in pcs_ai.py:
        from signature_uploader import upload_signature_sync
        
        # After extracting signature:
        result = upload_signature_sync(signature)
    """
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    
    return loop.run_until_complete(upload_signature_async(signature, relay_url))


if __name__ == "__main__":
    # Test signature upload
    logger.info("Testing signature uploader...")
    
    test_signature = {
        'attack_type': 'SQL Injection',
        'keywords': ['SELECT', 'UNION', 'FROM', 'WHERE'],
        'encodings': ['url_encoded'],
        'payload_length': 156,
        'encoding_chain_depth': 1,
        'ml_features': {
            'keyword_count': 4,
            'encoding_count': 1,
            'has_base64': False,
            'has_url_encoding': True,
            'pattern_complexity': 6
        }
    }
    
    async def test():
        uploader = SignatureUploader("ws://localhost:60001")
        
        if await uploader.connect():
            result = await uploader.upload_signature(test_signature)
            logger.info(f"Upload result: {result}")
            
            stats = uploader.get_statistics()
            logger.info(f"Uploader stats: {json.dumps(stats, indent=2)}")
            
            await uploader.disconnect()
    
    asyncio.run(test())
