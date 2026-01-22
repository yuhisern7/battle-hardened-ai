#!/usr/bin/env python3
"""
Sequence Analyzer - LSTM-based Attack State Transition Model

Models attack behavior as ordered state transitions using LSTM neural network.
Detects multi-stage attacks by learning progression patterns.

States:
- NORMAL: Benign traffic
- SCANNING: Port/network reconnaissance
- AUTH_ABUSE: Brute force or credential stuffing
- PRIV_ESC: Privilege escalation attempts
- LATERAL_MOVEMENT: Moving between systems
- EXFILTRATION: Data theft attempts

PRIVACY: State sequences stay LOCAL - never shared with relay.
Only abstract LSTM weights shared (if opted in).
"""

import os
import json
import time
import numpy as np
import logging
from datetime import datetime
from collections import deque
from typing import Dict, List, Tuple, Optional, Any
from AI.path_helper import get_json_dir, get_ml_models_dir, get_json_file
from dataclasses import dataclass, asdict
from enum import Enum

logger = logging.getLogger(__name__)

# TensorFlow imports with fallback
try:
    import tensorflow as tf
    from tensorflow import keras  # type: ignore[attr-defined]
    from tensorflow.keras import layers  # type: ignore[import]
    from tensorflow.keras.models import Sequential, load_model  # type: ignore[import]
    from tensorflow.keras.layers import LSTM, Dense, Dropout  # type: ignore[import]
    from tensorflow.keras.optimizers import Adam  # type: ignore[import]
    TF_AVAILABLE = True
except ImportError:
    TF_AVAILABLE = False
    logger.warning("[SEQUENCE] TensorFlow not available - sequence analysis disabled")


class AttackState(str, Enum):
    """Attack progression states"""
    NORMAL = "normal"
    SCANNING = "scanning"
    AUTH_ABUSE = "auth_abuse"
    PRIV_ESC = "priv_esc"
    LATERAL_MOVEMENT = "lateral_movement"
    EXFILTRATION = "exfiltration"


@dataclass
class StateEvent:
    """Single state observation"""
    timestamp: float
    entity_id: str
    state: AttackState
    confidence: float  # 0.0 to 1.0
    
    # Supporting signals
    signature_score: float = 0.0
    heuristic_score: float = 0.0
    behavioral_features: Optional[Dict] = None

    # Derived attack progression stage (0-5), kept in sync with state
    attack_stage: int = 0
    
    def __post_init__(self):
        if self.behavioral_features is None:
            self.behavioral_features = {}


@dataclass
class SequencePrediction:
    """Sequence analysis prediction"""
    entity_id: str
    current_state: AttackState
    current_state_probability: float
    predicted_next_state: AttackState
    next_state_probability: float
    sequence_risk_score: float  # 0.0 to 1.0
    confidence: float
    attack_stage: int  # 0 (benign) to 5 (exfiltration)
    sequence_length: int
    timestamp: float


class SequenceAnalyzer:
    """
    LSTM-based sequence analyzer for attack state transitions.
    Learns multi-stage attack patterns from ordered events.
    """
    
    def __init__(self, storage_dir: Optional[str] = None):
        if not TF_AVAILABLE:
            raise ImportError("TensorFlow required for sequence analysis. Install: pip install tensorflow")
        
        default_json_dir = get_json_dir()
        self.storage_dir = storage_dir or default_json_dir
        self.model_dir = get_ml_models_dir()
        os.makedirs(self.model_dir, exist_ok=True)
        os.makedirs(self.storage_dir, exist_ok=True)
        
        self.model_path = os.path.join(self.model_dir, 'sequence_lstm.keras')
        self.sequences_file = get_json_file('attack_sequences.json')
        
        # State tracking
        self.entity_sequences: Dict[str, deque] = {}  # entity_id -> sequence of events
        self.sequence_length = 10  # Look back 10 events
        
        # State encoding
        self.state_to_idx = {state: idx for idx, state in enumerate(AttackState)}
        self.idx_to_state = {idx: state for state, idx in self.state_to_idx.items()}
        self.num_states = len(AttackState)
        
        # Feature dimensions
        self.feature_dim = 5  # state_idx, signature_score, heuristic_score, time_delta, sequence_position
        
        # LSTM model
        self.model = None
        self.is_trained = False
        
        # Training data buffer
        self.training_sequences = []
        self.training_labels = []
        self.min_training_samples = 50
        
        # Load or create model
        self._initialize_model()
        
        # State transition probabilities (for rule-based fallback)
        self.transition_probs = self._initialize_transition_matrix()
        
        # APT campaign patterns (known attack progressions)
        self.apt_patterns = {
            'slow_burn': {  # Low-and-slow APT
                'min_dwell_time': 3600,  # 1 hour between stages
                'max_dwell_time': 86400 * 7,  # Up to 7 days
                'typical_sequence': [
                    AttackState.SCANNING,
                    AttackState.AUTH_ABUSE,
                    AttackState.NORMAL,  # Go quiet
                    AttackState.PRIV_ESC,
                    AttackState.LATERAL_MOVEMENT,
                    AttackState.EXFILTRATION
                ]
            },
            'smash_and_grab': {  # Fast exploitation
                'min_dwell_time': 60,  # 1 minute between stages
                'max_dwell_time': 3600,  # < 1 hour total
                'typical_sequence': [
                    AttackState.SCANNING,
                    AttackState.PRIV_ESC,
                    AttackState.EXFILTRATION
                ]
            },
            'lateral_spread': {  # Worm-like behavior
                'min_dwell_time': 300,  # 5 minutes
                'max_dwell_time': 7200,  # 2 hours
                'typical_sequence': [
                    AttackState.AUTH_ABUSE,
                    AttackState.LATERAL_MOVEMENT,
                    AttackState.LATERAL_MOVEMENT,
                    AttackState.LATERAL_MOVEMENT
                ]
            }
        }
        
        # Load existing sequences
        self.load_sequences()
    
    def detect_apt_campaign_pattern(self, entity_id: str) -> Optional[Dict[str, Any]]:
        """Detect if entity's sequence matches known APT campaign patterns.
        
        Args:
            entity_id: Entity to analyze
        
        Returns:
            Dictionary with matched campaign type and confidence, or None
        """
        if entity_id not in self.entity_sequences:
            return None
        
        sequence = list(self.entity_sequences[entity_id])
        if len(sequence) < 3:
            return None
        
        # Extract state sequence and timing
        states = [event.state for event in sequence[-10:]]  # Last 10 states
        timestamps = [event.timestamp for event in sequence[-10:]]
        
        # Check each APT pattern
        best_match = None
        best_confidence = 0.0
        
        for pattern_name, pattern in self.apt_patterns.items():
            confidence = self._match_sequence_pattern(
                states, timestamps, pattern['typical_sequence'],
                pattern['min_dwell_time'], pattern['max_dwell_time']
            )
            
            if confidence > best_confidence:
                best_confidence = confidence
                best_match = pattern_name
        
        if best_confidence > 0.6:  # 60% match threshold
            return {
                'campaign_type': best_match,
                'confidence': best_confidence,
                'states_observed': [s.value for s in states],
                'timestamp': time.time()
            }
        
        return None
    
    def _match_sequence_pattern(self, observed_states: List[AttackState],
                                timestamps: List[float],
                                pattern_sequence: List[AttackState],
                                min_dwell: float, max_dwell: float) -> float:
        """Calculate how well observed sequence matches an APT pattern.
        
        Returns:
            Confidence score 0.0-1.0
        """
        if len(observed_states) < 2:
            return 0.0
        
        # Check if pattern states appear in observed sequence (order matters)
        pattern_matches = 0
        last_match_idx = -1
        
        for pattern_state in pattern_sequence:
            for i in range(last_match_idx + 1, len(observed_states)):
                if observed_states[i] == pattern_state:
                    pattern_matches += 1
                    last_match_idx = i
                    break
        
        sequence_similarity = pattern_matches / len(pattern_sequence)
        
        # Check timing (dwell time between states)
        timing_score = 0.0
        if len(timestamps) >= 2:
            dwells = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
            valid_dwells = sum(1 for d in dwells if min_dwell <= d <= max_dwell)
            timing_score = valid_dwells / len(dwells) if dwells else 0.0
        
        # Combined confidence (70% sequence, 30% timing)
        return (sequence_similarity * 0.7) + (timing_score * 0.3)
    
    def _initialize_model(self):
        """Initialize or load LSTM model"""
        if os.path.exists(self.model_path):
            try:
                assert TF_AVAILABLE, "TensorFlow not available"
                self.model = load_model(self.model_path)  # type: ignore[possibly-unbound]
                self.is_trained = True
                logger.info(f"[SEQUENCE] Loaded trained LSTM model from {self.model_path}")
            except Exception as e:
                logger.warning(f"[SEQUENCE] Failed to load model: {e}, creating new one")
                self._build_model()
        else:
            self._build_model()
    
    def _build_model(self):
        """Build LSTM neural network architecture"""
        assert TF_AVAILABLE, "TensorFlow not available"
        self.model = Sequential([  # type: ignore[possibly-unbound]
            # LSTM layers
            LSTM(64, return_sequences=True, input_shape=(self.sequence_length, self.feature_dim)),  # type: ignore[possibly-unbound]
            Dropout(0.2),  # type: ignore[possibly-unbound]
            LSTM(32, return_sequences=False),  # type: ignore[possibly-unbound]
            Dropout(0.2),  # type: ignore[possibly-unbound]
            
            # Dense layers for state classification
            Dense(32, activation='relu'),  # type: ignore[possibly-unbound]
            Dropout(0.2),  # type: ignore[possibly-unbound]
            Dense(self.num_states, activation='softmax')  # type: ignore[possibly-unbound]  # Output: probability per state
        ])
        
        self.model.compile(
            optimizer=Adam(learning_rate=0.001),  # type: ignore[possibly-unbound]
            loss='categorical_crossentropy',
            metrics=['accuracy']
        )
        
        logger.info("[SEQUENCE] Built new LSTM model architecture")
    
    def _initialize_transition_matrix(self) -> np.ndarray:
        """
        Initialize state transition probability matrix (rule-based fallback).
        Rows = current state, Cols = next state
        """
        # Attack progression logic:
        # NORMAL -> SCANNING (reconnaissance starts)
        # SCANNING -> AUTH_ABUSE (try to authenticate)
        # AUTH_ABUSE -> PRIV_ESC (escalate after auth)
        # PRIV_ESC -> LATERAL_MOVEMENT (move to other systems)
        # LATERAL_MOVEMENT -> EXFILTRATION (steal data)
        
        transitions = np.zeros((self.num_states, self.num_states))
        
        # Normal state - mostly stays normal, can transition to scanning
        transitions[self.state_to_idx[AttackState.NORMAL]] = [0.95, 0.04, 0.005, 0.003, 0.001, 0.001]
        
        # Scanning - can go to auth abuse or back to normal (failed recon)
        transitions[self.state_to_idx[AttackState.SCANNING]] = [0.3, 0.4, 0.25, 0.03, 0.01, 0.01]
        
        # Auth abuse - escalate or fail back to normal
        transitions[self.state_to_idx[AttackState.AUTH_ABUSE]] = [0.4, 0.1, 0.3, 0.15, 0.03, 0.02]
        
        # Priv escalation - move laterally or exfiltrate
        transitions[self.state_to_idx[AttackState.PRIV_ESC]] = [0.2, 0.05, 0.1, 0.3, 0.25, 0.1]
        
        # Lateral movement - continue moving or exfiltrate
        transitions[self.state_to_idx[AttackState.LATERAL_MOVEMENT]] = [0.1, 0.1, 0.05, 0.1, 0.4, 0.25]
        
        # Exfiltration - final stage, often stays or goes back to normal (cleanup)
        transitions[self.state_to_idx[AttackState.EXFILTRATION]] = [0.3, 0.05, 0.05, 0.05, 0.15, 0.4]
        
        return transitions
    
    def observe_event(self, entity_id: str, signature_score: float = 0.0,
                     heuristic_score: float = 0.0, behavioral_features: Optional[Dict] = None) -> StateEvent:
        """
        Observe a security event and classify its state.
        
        Args:
            entity_id: IP or device identifier
            signature_score: Attack signature confidence (0-1)
            heuristic_score: Behavioral heuristic score (0-1)
            behavioral_features: Dict with port_entropy, fan_out, retry_freq, etc.
        
        Returns:
            StateEvent with classified state
        """
        now = time.time()
        behavioral_features = behavioral_features or {}
        
        # Classify current state based on signals
        state, confidence = self._classify_state(signature_score, heuristic_score, behavioral_features)
        # Derive coarse attack stage from state for downstream consumers
        stage = self._get_attack_stage(state)

        event = StateEvent(
            timestamp=now,
            entity_id=entity_id,
            state=state,
            confidence=confidence,
            signature_score=signature_score,
            heuristic_score=heuristic_score,
            behavioral_features=behavioral_features,
            attack_stage=stage,
        )
        
        # Add to entity's sequence
        if entity_id not in self.entity_sequences:
            self.entity_sequences[entity_id] = deque(maxlen=self.sequence_length * 2)
        
        self.entity_sequences[entity_id].append(event)
        
        return event
    
    def _classify_state(self, signature_score: float, heuristic_score: float,
                       behavioral_features: Dict) -> Tuple[AttackState, float]:
        """
        Classify current state based on multiple signals.
        Uses rule-based logic when model is not trained.
        """
        # Extract behavioral metrics
        port_entropy = behavioral_features.get('port_entropy', 0.0)
        fan_out = behavioral_features.get('fan_out', 0)
        retry_freq = behavioral_features.get('retry_frequency', 0.0)
        auth_failure_ratio = behavioral_features.get('auth_failure_ratio', 0.0)
        connection_rate = behavioral_features.get('connection_count_1min', 0)
        
        # Rule-based state classification
        confidence = 0.5  # Base confidence
        
        # Scanning indicators
        if port_entropy > 4.0 or connection_rate > 100:
            return AttackState.SCANNING, min(0.7 + (port_entropy - 4.0) * 0.05, 0.95)
        
        # Auth abuse indicators
        if auth_failure_ratio > 0.5 or retry_freq > 10:
            return AttackState.AUTH_ABUSE, min(0.6 + auth_failure_ratio * 0.3, 0.95)
        
        # Lateral movement indicators
        if fan_out > 50:
            return AttackState.LATERAL_MOVEMENT, min(0.65 + (fan_out - 50) * 0.005, 0.95)
        
        # Privilege escalation (high signature + moderate heuristics)
        if signature_score > 0.7 and heuristic_score > 0.4:
            return AttackState.PRIV_ESC, min((signature_score + heuristic_score) / 2, 0.95)
        
        # Exfiltration (consistent high traffic + suspicious behavior)
        if heuristic_score > 0.7 and signature_score > 0.5:
            return AttackState.EXFILTRATION, min((signature_score + heuristic_score) / 2, 0.95)
        
        # Default to normal
        base_score = max(signature_score, heuristic_score)
        if base_score < 0.3:
            return AttackState.NORMAL, 1.0 - base_score
        
        return AttackState.NORMAL, 0.6
    
    def predict_sequence(self, entity_id: str) -> Optional[SequencePrediction]:
        """
        Predict next state in attack sequence using LSTM.
        
        Args:
            entity_id: Entity to analyze
        
        Returns:
            SequencePrediction with current state, predicted next state, and risk score
        """
        if entity_id not in self.entity_sequences:
            return None
        
        sequence = list(self.entity_sequences[entity_id])
        if len(sequence) < 2:
            return None  # Need at least 2 events
        
        # Get current state
        current_event = sequence[-1]
        current_state = current_event.state
        
        # Prepare sequence for LSTM
        if self.is_trained and len(sequence) >= self.sequence_length:
            # Use LSTM model
            assert self.model is not None, "Model not initialized"
            features = self._prepare_sequence_features(sequence[-self.sequence_length:])
            predictions = self.model.predict(np.expand_dims(features, axis=0), verbose=0)[0]
            
            # Get predicted next state
            next_state_idx = int(np.argmax(predictions))
            next_state = self.idx_to_state[next_state_idx]
            next_state_prob = float(predictions[next_state_idx])
            current_state_prob = float(predictions[self.state_to_idx[current_state]])
        else:
            # Use rule-based transition matrix
            current_idx = self.state_to_idx[current_state]
            predictions = self.transition_probs[current_idx]
            next_state_idx = int(np.argmax(predictions))
            next_state = self.idx_to_state[next_state_idx]
            next_state_prob = float(predictions[next_state_idx])
            current_state_prob = 0.7  # Default confidence for rule-based
        
        # Calculate sequence risk score
        risk_score = self._calculate_sequence_risk(sequence, current_state, next_state)
        
        # Determine attack stage
        stage = self._get_attack_stage(current_state)
        
        return SequencePrediction(
            entity_id=entity_id,
            current_state=current_state,
            current_state_probability=current_state_prob,
            predicted_next_state=next_state,
            next_state_probability=next_state_prob,
            sequence_risk_score=risk_score,
            confidence=current_event.confidence,
            attack_stage=stage,
            sequence_length=len(sequence),
            timestamp=time.time()
        )
    
    def _prepare_sequence_features(self, events: List[StateEvent]) -> np.ndarray:
        """Convert sequence of events to LSTM input features"""
        features = np.zeros((self.sequence_length, self.feature_dim))
        
        # Pad if sequence is shorter than required
        start_idx = max(0, self.sequence_length - len(events))
        
        for i, event in enumerate(events):
            idx = start_idx + i
            if idx >= self.sequence_length:
                break
            
            # Time delta from previous event
            time_delta = 0.0
            if i > 0:
                time_delta = min((event.timestamp - events[i-1].timestamp) / 60.0, 10.0)  # Minutes, cap at 10
            
            features[idx] = [
                self.state_to_idx[event.state],  # State encoding
                event.signature_score,
                event.heuristic_score,
                time_delta,
                i / len(events)  # Sequence position (0 to 1)
            ]
        
        return features
    
    def _calculate_sequence_risk(self, sequence: List[StateEvent], 
                                 current_state: AttackState, 
                                 predicted_next_state: AttackState) -> float:
        """Calculate risk score based on sequence progression"""
        risk = 0.0
        
        # Base risk from current state
        state_risk = {
            AttackState.NORMAL: 0.0,
            AttackState.SCANNING: 0.2,
            AttackState.AUTH_ABUSE: 0.4,
            AttackState.PRIV_ESC: 0.7,
            AttackState.LATERAL_MOVEMENT: 0.8,
            AttackState.EXFILTRATION: 0.95
        }
        risk += state_risk[current_state] * 0.4
        
        # Risk from predicted progression
        if predicted_next_state != AttackState.NORMAL:
            risk += state_risk[predicted_next_state] * 0.3
        
        # Risk from sequence velocity (how fast progressing through states)
        if len(sequence) >= 3:
            recent = sequence[-3:]
            unique_states = len(set(e.state for e in recent))
            if unique_states > 2:  # Rapidly changing states = active attack
                risk += 0.15
        
        # Risk from sustained non-normal behavior
        non_normal_count = sum(1 for e in sequence[-5:] if e.state != AttackState.NORMAL)
        risk += (non_normal_count / 5) * 0.15
        
        return min(risk, 1.0)
    
    def _get_attack_stage(self, state: AttackState) -> int:
        """Map state to attack stage number (0-5)"""
        stage_map = {
            AttackState.NORMAL: 0,
            AttackState.SCANNING: 1,
            AttackState.AUTH_ABUSE: 2,
            AttackState.PRIV_ESC: 3,
            AttackState.LATERAL_MOVEMENT: 4,
            AttackState.EXFILTRATION: 5
        }
        return stage_map[state]
    
    def add_training_sample(self, sequence: List[StateEvent], next_state: AttackState):
        """Add a confirmed sequence for training"""
        if len(sequence) < self.sequence_length:
            return  # Too short
        
        features = self._prepare_sequence_features(sequence[-self.sequence_length:])
        label = np.zeros(self.num_states)
        label[self.state_to_idx[next_state]] = 1.0  # One-hot encoding
        
        self.training_sequences.append(features)
        self.training_labels.append(label)
    
    def train_model(self, epochs: int = 10, batch_size: int = 16) -> Dict:
        """
        Train LSTM model on collected sequences.
        
        Returns:
            Training metrics
        """
        if len(self.training_sequences) < self.min_training_samples:
            logger.warning(f"[SEQUENCE] Not enough training samples ({len(self.training_sequences)} < {self.min_training_samples})")
            return {'status': 'insufficient_data', 'samples': len(self.training_sequences)}
        
        X = np.array(self.training_sequences)
        y = np.array(self.training_labels)
        
        logger.info(f"[SEQUENCE] Training LSTM on {len(X)} sequences...")
        
        assert self.model is not None, "Model not initialized"
        history = self.model.fit(
            X, y,
            epochs=epochs,
            batch_size=batch_size,
            validation_split=0.2,
            verbose=0
        )
        
        self.is_trained = True
        
        # Save model
        assert self.model is not None, "Model not initialized"
        self.model.save(self.model_path)
        logger.info(f"[SEQUENCE] Model saved to {self.model_path}")
        
        return {
            'status': 'success',
            'samples': len(X),
            'epochs': epochs,
            'final_loss': float(history.history['loss'][-1]),
            'final_accuracy': float(history.history['accuracy'][-1])
        }
    
    def get_stats(self) -> Dict:
        """Get sequence analysis statistics"""
        total_sequences = len(self.entity_sequences)
        
        # Count entities in each state
        state_counts = {state: 0 for state in AttackState}
        for sequence in self.entity_sequences.values():
            if sequence:
                last_event = sequence[-1]
                state_counts[last_event.state] += 1
        
        return {
            'total_entities_tracked': total_sequences,
            'model_trained': self.is_trained,
            'training_samples': len(self.training_sequences),
            'current_state_distribution': {str(k): v for k, v in state_counts.items()},
            'model_path': self.model_path if self.is_trained else None
        }
    
    def save_sequences(self):
        """Save tracked sequences to disk"""
        try:
            def serialize_event(event):
                """Convert StateEvent to JSON-serializable dict"""
                d = asdict(event)
                # Convert enum to string name
                if isinstance(event.state, AttackState):
                    d['state'] = event.state.name
                return d
            
            data = {
                'sequences': {
                    entity_id: [serialize_event(event) for event in sequence]
                    for entity_id, sequence in self.entity_sequences.items()
                },
                'last_updated': datetime.now().isoformat()
            }
            
            with open(self.sequences_file, 'w') as f:
                json.dump(data, f, indent=2)
            
            return True
        except Exception as e:
            logger.error(f"[SEQUENCE] Failed to save sequences: {e}")
            return False
    
    def load_sequences(self):
        """Load tracked sequences from disk"""
        try:
            if not os.path.exists(self.sequences_file):
                return False
            
            with open(self.sequences_file, 'r') as f:
                data = json.load(f)
            
            for entity_id, events in data.get('sequences', {}).items():
                self.entity_sequences[entity_id] = deque(maxlen=self.sequence_length * 2)
                for event_data in events:
                    # Convert state name back to enum
                    if 'state' in event_data and isinstance(event_data['state'], str):
                        try:
                            event_data['state'] = AttackState[event_data['state']]
                        except (KeyError, AttributeError):
                            # Fallback for old format like "AttackState.NORM"
                            state_name = event_data['state'].split('.')[-1]
                            event_data['state'] = AttackState[state_name]
                    
                    event = StateEvent(**event_data)
                    self.entity_sequences[entity_id].append(event)
            
            logger.info(f"[SEQUENCE] Loaded {len(self.entity_sequences)} entity sequences")
            return True
        except Exception as e:
            logger.error(f"[SEQUENCE] Failed to load sequences: {e}")
            return False


# Global instance
_sequence_analyzer = None


def get_sequence_analyzer() -> Optional[SequenceAnalyzer]:
    """Get or create global sequence analyzer instance"""
    global _sequence_analyzer
    if _sequence_analyzer is None:
        if TF_AVAILABLE:
            _sequence_analyzer = SequenceAnalyzer()
        else:
            logger.warning("[SEQUENCE] TensorFlow not available - sequence analysis disabled")
            return None
    return _sequence_analyzer


# Convenience functions
def observe_event(entity_id: str, signature_score: float = 0.0,
                 heuristic_score: float = 0.0, behavioral_features: Optional[Dict] = None) -> Optional[StateEvent]:
    """Observe and classify a security event"""
    analyzer = get_sequence_analyzer()
    if analyzer:
        return analyzer.observe_event(entity_id, signature_score, heuristic_score, behavioral_features)
    return None


def predict_next_state(entity_id: str) -> Optional[SequencePrediction]:
    """Predict next state in attack sequence"""
    analyzer = get_sequence_analyzer()
    if analyzer:
        return analyzer.predict_sequence(entity_id)
    return None


def get_stats() -> Dict:
    """Get sequence analysis statistics"""
    analyzer = get_sequence_analyzer()
    if analyzer:
        return analyzer.get_stats()
    return {'status': 'disabled', 'reason': 'TensorFlow not available'}
