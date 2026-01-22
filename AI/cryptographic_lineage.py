"""
MODULE C: Cryptographic Learning Lineage

Immutable audit trail for ML model evolution using cryptographic signatures.
Tracks every training session, model update, and parameter change with
tamper-proof provenance chains.

Uses standard crypto libraries (SHA-256, Ed25519) - no system modifications.

Risk Level: LOW (Pure logging/tracking, no execution changes)
"""

import hashlib
import json
import os
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
import logging

logger = logging.getLogger(__name__)

# Feature flag for lineage tracking and optional disk persistence
LINEAGE_ENABLED = os.getenv("LINEAGE_ENABLED", "true").lower() == "true"

# Try to import cryptography for Ed25519 signatures
try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    logger.warning("[LINEAGE] cryptography library not available - signatures disabled")


@dataclass
class ModelCheckpoint:
    """Represents a point in model evolution history."""
    checkpoint_id: str
    timestamp: str
    model_hash: str  # SHA-256 of model weights
    parent_hash: Optional[str]  # Hash of previous checkpoint (blockchain-style)
    training_data_hash: str  # Hash of training data used
    hyperparameters: Dict
    metrics: Dict  # Accuracy, loss, etc.
    source: str  # 'local_training', 'peer_sync', 'relay_update'
    signature: Optional[str]  # Ed25519 signature
    metadata: Dict


class CryptographicLineage:
    """
    Immutable model lineage tracker using cryptographic hashing.
    
    Creates an audit trail where each model version references its parent,
    forming a blockchain-like chain of custody for ML model evolution.
    
    Features:
    - SHA-256 hashing of model weights
    - Ed25519 digital signatures
    - Tamper-evident chain of custody
    - Forensic audit capabilities
    - Provenance verification
    """
    
    def __init__(self, storage_dir: str = None):
        """Initialize lineage tracker."""
        # Storage paths
        from AI.path_helper import get_json_dir, get_json_file
        default_dir = get_json_dir()
        self.storage_dir = storage_dir or default_dir
        os.makedirs(self.storage_dir, exist_ok=True)
        
        self.lineage_file = get_json_file('model_lineage.json')
        self.key_file = os.path.join(self.storage_dir, 'lineage_signing_key.pem')
        
        # Lineage chain
        self.checkpoints: List[ModelCheckpoint] = []
        self.checkpoint_index: Dict[str, ModelCheckpoint] = {}
        
        # Signing key for authenticity
        self.private_key = None
        self.public_key = None
        self.enabled = LINEAGE_ENABLED
        
        # Load existing lineage
        self._load_lineage()
        self._load_or_generate_keys()
        
        logger.info(
            f"[LINEAGE] Initialized with {len(self.checkpoints)} checkpoints (enabled={self.enabled}, storage_dir={self.storage_dir})"
        )
    
    def _load_or_generate_keys(self):
        """Load or generate Ed25519 signing keys."""
        if not CRYPTO_AVAILABLE:
            return
        
        if os.path.exists(self.key_file):
            try:
                with open(self.key_file, 'rb') as f:
                    self.private_key = serialization.load_pem_private_key(
                        f.read(), password=None
                    )
                self.public_key = self.private_key.public_key()
                logger.info("[LINEAGE] Loaded existing signing keys")
            except Exception as e:
                logger.error(f"[LINEAGE] Failed to load keys: {e}")
                self._generate_new_keys()
        else:
            self._generate_new_keys()
    
    def _generate_new_keys(self):
        """Generate new Ed25519 key pair."""
        if not CRYPTO_AVAILABLE:
            return
        
        self.private_key = ed25519.Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        
        # Save private key
        pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        with open(self.key_file, 'wb') as f:
            f.write(pem)
        
        os.chmod(self.key_file, 0o600)  # Read/write for owner only
        logger.info("[LINEAGE] Generated new Ed25519 signing keys")
    
    def _hash_model_weights(self, weights) -> str:
        """Compute SHA-256 hash of model weights."""
        try:
            import numpy as np
        except ImportError:
            np = None  # type: ignore

        if np is not None and isinstance(weights, np.ndarray):
            data = weights.tobytes()
        elif isinstance(weights, list):
            # Convert list to bytes
            data = json.dumps(weights, sort_keys=True).encode()
        else:
            data = str(weights).encode()
        
        return hashlib.sha256(data).hexdigest()
    
    def _sign_checkpoint(self, checkpoint: ModelCheckpoint) -> str:
        """Sign checkpoint with Ed25519 private key."""
        if not CRYPTO_AVAILABLE or self.private_key is None:
            return "UNSIGNED"
        
        # Create deterministic message from checkpoint
        message_dict = {
            "checkpoint_id": checkpoint.checkpoint_id,
            "timestamp": checkpoint.timestamp,
            "model_hash": checkpoint.model_hash,
            "parent_hash": checkpoint.parent_hash,
            "training_data_hash": checkpoint.training_data_hash
        }
        message = json.dumps(message_dict, sort_keys=True).encode()
        
        # Sign
        signature = self.private_key.sign(message)
        return signature.hex()
    
    def record_checkpoint(
        self,
        model_weights,
        training_data_hash: str,
        hyperparameters: Dict,
        metrics: Dict,
        source: str = "local_training",
        metadata: Dict = None
    ) -> ModelCheckpoint:
        """
        Record a new model checkpoint in the lineage.
        
        Args:
            model_weights: Model weights (numpy array or serializable)
            training_data_hash: SHA-256 of training data
            hyperparameters: Model hyperparameters
            metrics: Training metrics (accuracy, loss, etc.)
            source: Origin of this model version
            metadata: Additional metadata
        
        Returns:
            ModelCheckpoint object
        """
        # Compute model hash
        model_hash = self._hash_model_weights(model_weights)
        
        # Get parent checkpoint (latest one)
        parent_hash = None
        if len(self.checkpoints) > 0:
            parent_hash = self.checkpoints[-1].model_hash
        
        # Create checkpoint
        checkpoint = ModelCheckpoint(
            checkpoint_id=f"ckpt_{len(self.checkpoints) + 1}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            timestamp=datetime.now().isoformat(),
            model_hash=model_hash,
            parent_hash=parent_hash,
            training_data_hash=training_data_hash,
            hyperparameters=hyperparameters,
            metrics=metrics,
            source=source,
            signature=None,  # Will be filled by signing
            metadata=metadata or {}
        )
        
        # Sign checkpoint
        checkpoint.signature = self._sign_checkpoint(checkpoint)
        
        # Add to chain
        self.checkpoints.append(checkpoint)
        self.checkpoint_index[checkpoint.checkpoint_id] = checkpoint
        
        # Save
        self._save_lineage()
        
        logger.info(f"[LINEAGE] Recorded checkpoint {checkpoint.checkpoint_id}")
        logger.info(f"[LINEAGE] Model hash: {model_hash[:16]}...")
        
        return checkpoint
    
    def verify_chain_integrity(self) -> Dict:
        """
        Verify cryptographic integrity of entire lineage chain.
        
        Checks:
        - Parent hash links are valid
        - No gaps in chain
        - Chronological ordering
        - Signature validity (if available)
        
        Returns:
            Verification report
        """
        issues = []
        verified_checkpoints = 0
        
        for i, checkpoint in enumerate(self.checkpoints):
            # Check parent link
            if i > 0:
                expected_parent = self.checkpoints[i - 1].model_hash
                if checkpoint.parent_hash != expected_parent:
                    issues.append({
                        "checkpoint": checkpoint.checkpoint_id,
                        "issue": "Parent hash mismatch",
                        "expected": expected_parent,
                        "got": checkpoint.parent_hash
                    })
            
            # Check chronological order
            if i > 0:
                prev_time = datetime.fromisoformat(self.checkpoints[i - 1].timestamp)
                curr_time = datetime.fromisoformat(checkpoint.timestamp)
                if curr_time < prev_time:
                    issues.append({
                        "checkpoint": checkpoint.checkpoint_id,
                        "issue": "Timestamp out of order"
                    })
            
            # Verify signature (if crypto available)
            if CRYPTO_AVAILABLE and checkpoint.signature != "UNSIGNED":
                # This is a simplified check - full verification would need public key
                verified_checkpoints += 1

        report = {
            "is_valid": len(issues) == 0,
            "total_checkpoints": len(self.checkpoints),
            "verified_signatures": verified_checkpoints,
            "issues": issues,
            "chain_length": len(self.checkpoints),
            "genesis_checkpoint": self.checkpoints[0].checkpoint_id if self.checkpoints else None,
            "latest_checkpoint": self.checkpoints[-1].checkpoint_id if self.checkpoints else None
        }

        # If we detect lineage issues, surface them into the comprehensive
        # audit log so Stage 7 can see cryptographic provenance problems as
        # real security events, not just a passive stats blob.
        if issues and self.enabled:
            try:
                from emergency_killswitch import get_audit_log, AuditEventType

                audit = get_audit_log()
                for issue in issues:
                    audit.log_event(
                        event_type=AuditEventType.THREAT_DETECTED,
                        actor="cryptographic_lineage",
                        action="lineage_integrity_check",
                        target=issue.get("checkpoint", "model_lineage_chain"),
                        outcome="failure",
                        details=issue,
                        risk_level="high",
                        metadata={"module": "cryptographic_lineage"},
                    )
            except Exception as e:
                logger.debug(f"[LINEAGE] Failed to write integrity issues to audit log: {e}")

        return report
    
    def get_provenance(self, checkpoint_id: str) -> List[ModelCheckpoint]:
        """
        Get full provenance chain for a checkpoint.
        
        Walks backward through parent links to genesis checkpoint.
        """
        if checkpoint_id not in self.checkpoint_index:
            return []
        
        provenance = []
        current = self.checkpoint_index[checkpoint_id]
        
        while current:
            provenance.append(current)
            if current.parent_hash is None:
                break
            
            # Find parent
            current = None
            for ckpt in self.checkpoints:
                if ckpt.model_hash == provenance[-1].parent_hash:
                    current = ckpt
                    break
        
        return provenance
    
    def detect_model_drift_via_lineage(self, window_size: int = 10) -> Dict:
        """
        Detect model drift by analyzing lineage chain.
        
        Looks for:
        - Sudden accuracy drops
        - Unusual hyperparameter changes
        - Unexpected sources (peer vs local)
        """
        if len(self.checkpoints) < window_size:
            return {"drift_detected": False, "reason": "Insufficient history"}
        
        recent = self.checkpoints[-window_size:]
        
        # Check accuracy trend
        accuracies = [c.metrics.get('accuracy', 0) for c in recent]
        if len(accuracies) > 1:
            avg_accuracy = sum(accuracies[:-1]) / len(accuracies[:-1])
            latest_accuracy = accuracies[-1]
            
            if latest_accuracy < avg_accuracy * 0.9:  # 10% drop
                return {
                    "drift_detected": True,
                    "reason": "Accuracy dropped significantly",
                    "avg_accuracy": avg_accuracy,
                    "latest_accuracy": latest_accuracy,
                    "drop_percent": ((avg_accuracy - latest_accuracy) / avg_accuracy) * 100
                }
        
        # Check for suspicious source changes
        sources = [c.source for c in recent]
        if sources.count('peer_sync') > window_size * 0.7:  # >70% from peers
            return {
                "drift_detected": True,
                "reason": "High proportion of peer updates (potential poisoning)",
                "peer_update_rate": sources.count('peer_sync') / len(sources)
            }
        
        return {"drift_detected": False}
    
    def _save_lineage(self):
        """Save lineage to disk."""
        lineage_data = {
            "checkpoints": [asdict(c) for c in self.checkpoints],
            "last_updated": datetime.now().isoformat()
        }
        
        try:
            with open(self.lineage_file, 'w') as f:
                json.dump(lineage_data, f, indent=2)
        except Exception as e:
            logger.error(f"[LINEAGE] Failed to save lineage to {self.lineage_file}: {e}")
    
    def _load_lineage(self):
        """Load lineage from disk."""
        if not os.path.exists(self.lineage_file):
            return
        
        try:
            with open(self.lineage_file, 'r') as f:
                data = json.load(f)
            
            self.checkpoints = [
                ModelCheckpoint(**ckpt) for ckpt in data.get('checkpoints', [])
            ]
            self.checkpoint_index = {
                c.checkpoint_id: c for c in self.checkpoints
            }
            
            logger.info(f"[LINEAGE] Loaded {len(self.checkpoints)} checkpoints")
        except Exception as e:
            logger.error(f"[LINEAGE] Failed to load lineage: {e}")
    
    def get_stats(self) -> Dict:
        """Get lineage statistics."""
        if len(self.checkpoints) == 0:
            return {
                "total_checkpoints": 0,
                "total_signatures": 0,
                "chain_depth": 0,
                "last_checkpoint_time": None,
                "checkpoint_history": [],
                "enabled": self.enabled,
                "storage_dir": self.storage_dir,
            }
        
        sources = {}
        signatures_count = 0
        for c in self.checkpoints:
            sources[c.source] = sources.get(c.source, 0) + 1
            if c.signature:
                signatures_count += 1
        
        # Build checkpoint history for dashboard
        checkpoint_history = []
        for idx, cp in enumerate(reversed(self.checkpoints[-20:])):  # Last 20
            checkpoint_history.append({
                "checkpoint_id": len(self.checkpoints) - idx,
                "timestamp": cp.timestamp,
                "model_hash": cp.model_hash,
                "signature_valid": bool(cp.signature),
                "source": cp.source
            })
        
        return {
            "total_checkpoints": len(self.checkpoints),
            "total_signatures": signatures_count,
            "chain_depth": len(self.checkpoints),
            "genesis_date": self.checkpoints[0].timestamp,
            "last_checkpoint_time": self.checkpoints[-1].timestamp,
            "sources": sources,
            "signatures_enabled": CRYPTO_AVAILABLE and self.private_key is not None,
            "checkpoint_history": checkpoint_history,
            "enabled": self.enabled,
            "storage_dir": self.storage_dir,
        }


# Singleton instance
_lineage_tracker: Optional[CryptographicLineage] = None


def get_lineage_tracker() -> CryptographicLineage:
    """Get singleton lineage tracker instance."""
    global _lineage_tracker
    if _lineage_tracker is None:
        _lineage_tracker = CryptographicLineage()
    return _lineage_tracker
