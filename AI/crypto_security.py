#!/usr/bin/env python3
"""
Cryptographic Security for Threat Messages
Implements message signing, HMAC validation, and replay attack protection
"""

import os
import json
import hmac
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional, Tuple
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import logging

from AI.path_helper import get_crypto_keys_dir, get_project_root

logger = logging.getLogger(__name__)

# Feature flags and tunables for message security
MESSAGE_SECURITY_ENABLED = os.getenv("MESSAGE_SECURITY_ENABLED", "true").lower() == "true"
MESSAGE_SECURITY_MAX_NONCES = int(os.getenv("MESSAGE_SECURITY_MAX_NONCES", "10000"))
MESSAGE_SECURITY_KEY_DIR = os.getenv("MESSAGE_SECURITY_KEY_DIR")  # Optional override


class MessageSecurity:
    """Handles cryptographic operations for secure mesh communication"""
    
    def __init__(self, key_dir: str = "ml_models/crypto_keys"):
        """
        Initialize message security system.
        
        Args:
            key_dir: Directory to store cryptographic keys
        """
        # Allow environment override for key directory, but keep existing default.
        # If the override is a relative path (e.g. "server/crypto_keys"), resolve it
        # from the project root so it works regardless of current working directory
        # (watchdog, Docker, direct server.py, etc.).
        if MESSAGE_SECURITY_KEY_DIR:
            key_dir_candidate = MESSAGE_SECURITY_KEY_DIR
            if not os.path.isabs(key_dir_candidate) and not key_dir_candidate.startswith('/app'):
                root = get_project_root()
                key_dir_candidate = os.path.join(root, key_dir_candidate)
            self.key_dir = key_dir_candidate
        else:
            # Use unified crypto-keys location (server/crypto_keys or /app/ml_models/crypto_keys in Docker)
            self.key_dir = get_crypto_keys_dir()

        # Ensure key directory exists for whichever path is active (cross-platform)
        os.makedirs(self.key_dir, exist_ok=True)
        
        self.private_key_file = os.path.join(self.key_dir, "private_key.pem")
        self.public_key_file = os.path.join(self.key_dir, "public_key.pem")
        self.shared_secret_file = os.path.join(self.key_dir, "shared_secret.key")
        
        # Get customer ID from environment (unique per installation)
        self.customer_id = os.getenv('CUSTOMER_ID', 'demo-customer-0000')
        
        # Load or generate keys
        self.private_key, self.public_key = self._load_or_generate_keypair()
        self.shared_secret = self._load_or_generate_secret()
        
        # Replay attack protection
        self.nonce_cache = set()  # Track used nonces
        self.nonce_expiry = {}  # Nonce -> expiry timestamp
        self.message_window_seconds = 300  # Accept messages within 5 minutes
        self.enabled = MESSAGE_SECURITY_ENABLED
        self.max_nonces = max(1000, MESSAGE_SECURITY_MAX_NONCES)

        logger.info(
            f"[CRYPTO] Message security initialized (enabled={self.enabled}, key_dir={self.key_dir})"
        )
        logger.info(f"[CRYPTO] Public key fingerprint: {self._get_public_key_fingerprint()[:16]}...")
    
    def _load_or_generate_keypair(self) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        """Load existing RSA keypair or generate new one"""
        if os.path.exists(self.private_key_file) and os.path.exists(self.public_key_file):
            try:
                # Load existing keys
                with open(self.private_key_file, 'rb') as f:
                    private_key = serialization.load_pem_private_key(
                        f.read(),
                        password=None,
                        backend=default_backend()
                    )

                with open(self.public_key_file, 'rb') as f:
                    public_key = serialization.load_pem_public_key(
                        f.read(),
                        backend=default_backend()
                    )

                logger.info("[CRYPTO] Loaded existing RSA keypair")
                return private_key, public_key

            except Exception as e:
                logger.warning(f"[CRYPTO] Failed to load keys: {e}, generating new keypair")
        
        # Generate new keypair
        logger.info("[CRYPTO] Generating new 2048-bit RSA keypair...")
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        
        # Save keys
        try:
            with open(self.private_key_file, 'wb') as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            # Restrict private key permissions
            try:
                os.chmod(self.private_key_file, 0o600)
            except Exception:
                pass

            with open(self.public_key_file, 'wb') as f:
                f.write(public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))
        except Exception as e:
            logger.error(f"[CRYPTO] Failed to save RSA keypair: {e}")

        logger.info("[CRYPTO] RSA keypair generated and saved")
        return private_key, public_key
    
    def _load_or_generate_secret(self) -> bytes:
        """Load existing shared secret or generate new one"""
        if os.path.exists(self.shared_secret_file):
            try:
                with open(self.shared_secret_file, 'rb') as f:
                    secret = f.read()
                logger.info("[CRYPTO] Loaded existing shared secret for HMAC")
                return secret
            except Exception as e:
                logger.warning(f"[CRYPTO] Failed to load secret: {e}, generating new one")
        
        # Generate new 256-bit secret
        logger.info("[CRYPTO] Generating new 256-bit shared secret...")
        secret = secrets.token_bytes(32)

        try:
            with open(self.shared_secret_file, 'wb') as f:
                f.write(secret)
            try:
                os.chmod(self.shared_secret_file, 0o600)
            except Exception:
                pass
        except Exception as e:
            logger.error(f"[CRYPTO] Failed to save shared secret: {e}")

        logger.info("[CRYPTO] Shared secret generated and saved")
        return secret
    
    def _get_public_key_fingerprint(self) -> str:
        """Get SHA256 fingerprint of public key"""
        public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return hashlib.sha256(public_pem).hexdigest()
    
    def sign_message(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sign a threat message with RSA signature and HMAC.
        
        Args:
            message: Original message dict
            
        Returns:
            Message with signature, HMAC, timestamp, and nonce
        """
        # Add metadata
        message = message.copy()
        message['timestamp'] = datetime.now(timezone.utc).isoformat() + 'Z'
        message['nonce'] = secrets.token_hex(16)  # 128-bit nonce
        message['peer_id'] = self._get_public_key_fingerprint()[:32]
        message['customer_id'] = self.customer_id  # Per-customer identification
        
        # Convert to canonical JSON (deterministic)
        canonical_json = json.dumps(message, sort_keys=True, separators=(',', ':'))
        message_bytes = canonical_json.encode('utf-8')
        
        # RSA signature (for authenticity)
        signature = self.private_key.sign(
            message_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        message['signature'] = signature.hex()
        
        # HMAC (for integrity)
        hmac_digest = hmac.new(
            self.shared_secret,
            message_bytes,
            hashlib.sha256
        ).hexdigest()
        message['hmac'] = hmac_digest
        
        return message
    
    def verify_message(self, message: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Verify message signature, HMAC, and replay protection.
        
        Args:
            message: Signed message to verify
            
        Returns:
            (is_valid, reason)
        """
        try:
            # Check required fields
            required = ['timestamp', 'nonce', 'peer_id', 'signature', 'hmac']
            if not all(field in message for field in required):
                return False, "Missing security fields"
            
            # Check timestamp (replay attack protection)
            try:
                msg_time = datetime.fromisoformat(message['timestamp'].replace('Z', '+00:00'))
                if msg_time.tzinfo:
                    msg_time = msg_time.replace(tzinfo=None)
                
                age_seconds = (datetime.now(timezone.utc) - msg_time).total_seconds()
                
                if abs(age_seconds) > self.message_window_seconds:
                    return False, f"Message timestamp outside window ({age_seconds:.0f}s old)"
            
            except Exception as e:
                return False, f"Invalid timestamp: {e}"
            
            # Check nonce (replay attack protection)
            nonce = message['nonce']
            if nonce in self.nonce_cache:
                return False, "Duplicate nonce (replay attack detected)"
            
            # Verify HMAC (integrity check)
            msg_copy = message.copy()
            expected_hmac = msg_copy.pop('hmac')
            signature = msg_copy.pop('signature')
            
            canonical_json = json.dumps(msg_copy, sort_keys=True, separators=(',', ':'))
            message_bytes = canonical_json.encode('utf-8')
            
            calculated_hmac = hmac.new(
                self.shared_secret,
                message_bytes,
                hashlib.sha256
            ).hexdigest()
            
            if not hmac.compare_digest(calculated_hmac, expected_hmac):
                return False, "HMAC validation failed (message tampered)"
            
            # TODO: Verify RSA signature (requires peer public key distribution)
            # For now, we rely on HMAC for integrity
            
            # Accept message - add nonce to cache
            self.nonce_cache.add(nonce)
            self.nonce_expiry[nonce] = datetime.now(timezone.utc) + timedelta(seconds=self.message_window_seconds * 2)

            # Clean up expired/non-needed nonces
            self._cleanup_nonces()

            return True, "OK"
        
        except Exception as e:
            logger.error(f"[CRYPTO] Verification error: {e}")
            return False, f"Verification failed: {e}"
    
    def _cleanup_nonces(self):
        """Remove expired nonces from cache"""
        now = datetime.now(timezone.utc)
        expired = [n for n, exp in self.nonce_expiry.items() if exp < now]
        
        for nonce in expired:
            self.nonce_cache.discard(nonce)
            del self.nonce_expiry[nonce]
        
        if expired:
            logger.debug(f"[CRYPTO] Cleaned up {len(expired)} expired nonces")

        # Bound nonce cache size to avoid unbounded memory growth
        if len(self.nonce_cache) > self.max_nonces:
            overflow = len(self.nonce_cache) - self.max_nonces
            # Drop oldest by expiry time
            ordered = sorted(self.nonce_expiry.items(), key=lambda x: x[1])
            to_drop = [n for n, _ in ordered[:overflow]]
            for n in to_drop:
                self.nonce_cache.discard(n)
                self.nonce_expiry.pop(n, None)
            logger.warning(
                f"[CRYPTO] Nonce cache truncated by {overflow} entries (max={self.max_nonces})"
            )
    
    def get_public_key_pem(self) -> str:
        """Get public key in PEM format for distribution"""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
    
    def get_stats(self) -> Dict[str, Any]:
        """Get security statistics"""
        return {
            "enabled": self.enabled,
            "key_fingerprint": self._get_public_key_fingerprint()[:32],
            "nonce_cache_size": len(self.nonce_cache),
            "message_window_seconds": self.message_window_seconds,
            "hmac_algorithm": "HMAC-SHA256",
            "signature_algorithm": "RSA-PSS-SHA256",
            "key_size": 2048,
            "key_dir": self.key_dir,
            "max_nonces": self.max_nonces,
        }


# Global instance
_message_security: Optional[MessageSecurity] = None

def get_message_security() -> MessageSecurity:
    """Get or create global message security instance"""
    global _message_security
    if _message_security is None:
        _message_security = MessageSecurity()
    return _message_security
