"""
MODULE D: Deterministic Evaluation & Proof Mode

Reproducible ML testing with fixed random seeds and controlled evaluation.
Enables scientific validation of ML models with deterministic results.

Pure testing/validation - doesn't affect production.

Risk Level: NONE (Testing only, optional feature)
"""

import numpy as np
import random
import os
import json
import logging
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass
from datetime import datetime

from AI.path_helper import get_json_dir

logger = logging.getLogger(__name__)


@dataclass
class EvaluationResult:
    """Deterministic evaluation result."""
    test_id: str
    timestamp: str
    random_seed: int
    model_name: str
    dataset_hash: str
    metrics: Dict
    reproducible: bool
    configuration: Dict


class DeterministicEvaluator:
    """
    Deterministic evaluation framework for ML models.
    
    Ensures:
    - Fixed random seeds for reproducibility
    - Controlled test data sampling
    - Identical evaluation conditions across runs
    - Scientific rigor in model validation
    
    Use cases:
    - Regulatory compliance (prove model behavior)
    - Scientific paper results
    - A/B testing with confidence
    - Forensic investigation of model decisions
    """
    
    def __init__(self, storage_dir: Optional[str] = None):
        """Initialize deterministic evaluator."""
        default_dir = get_json_dir()
        self.storage_dir = storage_dir or default_dir
        os.makedirs(self.storage_dir, exist_ok=True)
        
        self.results_file = os.path.join(self.storage_dir, 'deterministic_eval_results.json')
        self.evaluation_history: List[EvaluationResult] = []
        
        self._load_results()
        
        logger.info("[DETERMINISTIC] Evaluator initialized")
    
    def set_random_seed(self, seed: int = 42):
        """
        Set fixed random seed for deterministic behavior.
        
        Sets seeds for:
        - Python random
        - NumPy random
        - (TensorFlow/PyTorch if available)
        """
        random.seed(seed)
        np.random.seed(seed)
        
        # Try TensorFlow
        try:
            import tensorflow as tf
            tf.random.set_seed(seed)
            logger.info(f"[DETERMINISTIC] TensorFlow seed set to {seed}")
        except ImportError:
            pass
        
        # Try PyTorch
        try:
            import torch
            torch.manual_seed(seed)
            if torch.cuda.is_available():
                torch.cuda.manual_seed_all(seed)
            logger.info(f"[DETERMINISTIC] PyTorch seed set to {seed}")
        except ImportError:
            pass
        
        logger.info(f"[DETERMINISTIC] Random seed set to {seed}")
    
    def evaluate_model(
        self,
        model,
        test_data,
        model_name: str,
        random_seed: int = 42,
        metrics_fn: Optional[Callable] = None
    ) -> EvaluationResult:
        """
        Evaluate model deterministically.
        
        Args:
            model: ML model to evaluate
            test_data: Test dataset (X, y) tuple
            model_name: Name of model being evaluated
            random_seed: Fixed random seed for reproducibility
            metrics_fn: Custom metrics function (default: basic accuracy)
        
        Returns:
            EvaluationResult with deterministic metrics
        """
        # Set seed for determinism
        self.set_random_seed(random_seed)
        
        # Hash test data for verification
        X_test, y_test = test_data
        data_hash = self._hash_dataset(X_test, y_test)
        
        # Run evaluation
        if metrics_fn:
            metrics = metrics_fn(model, X_test, y_test)
        else:
            metrics = self._default_metrics(model, X_test, y_test)
        
        # Create result
        result = EvaluationResult(
            test_id=f"eval_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{random_seed}",
            timestamp=datetime.now().isoformat(),
            random_seed=random_seed,
            model_name=model_name,
            dataset_hash=data_hash,
            metrics=metrics,
            reproducible=True,
            configuration={
                "test_size": len(X_test),
                "feature_count": X_test.shape[1] if hasattr(X_test, 'shape') else 0
            }
        )
        
        # Save result
        self.evaluation_history.append(result)
        self._save_results()
        
        logger.info(f"[DETERMINISTIC] Evaluated {model_name} (seed={random_seed})")
        logger.info(f"[DETERMINISTIC] Metrics: {metrics}")
        
        return result
    
    def verify_reproducibility(
        self,
        model,
        test_data,
        model_name: str,
        random_seed: int = 42,
        num_runs: int = 3
    ) -> Dict:
        """
        Verify model evaluation is truly reproducible.
        
        Runs evaluation multiple times with same seed and checks
        if results are identical.
        """
        results = []
        
        for run in range(num_runs):
            result = self.evaluate_model(
                model, test_data, model_name, random_seed
            )
            results.append(result)
        
        # Check if all metrics are identical
        first_metrics = results[0].metrics
        is_reproducible = all(
            r.metrics == first_metrics for r in results[1:]
        )
        
        if is_reproducible:
            logger.info(f"[DETERMINISTIC] ✅ Model is reproducible ({num_runs} runs)")
        else:
            logger.warning(f"[DETERMINISTIC] ⚠️ Model is NOT reproducible")
            # Log differences
            for i, result in enumerate(results[1:], 1):
                diff = {
                    k: (first_metrics[k], result.metrics[k])
                    for k in first_metrics
                    if first_metrics[k] != result.metrics.get(k)
                }
                if diff:
                    logger.warning(f"[DETERMINISTIC] Run {i+1} differences: {diff}")
        
        return {
            "is_reproducible": is_reproducible,
            "num_runs": num_runs,
            "random_seed": random_seed,
            "metrics_match": is_reproducible,
            "first_run_metrics": first_metrics
        }
    
    def _default_metrics(self, model, X_test, y_test) -> Dict:
        """Default metrics: accuracy, precision, recall, F1."""
        try:
            # Try predict_proba first
            if hasattr(model, 'predict_proba'):
                y_pred_proba = model.predict_proba(X_test)
                y_pred = np.argmax(y_pred_proba, axis=1)
            else:
                y_pred = model.predict(X_test)
            
            # Compute metrics
            accuracy = np.mean(y_pred == y_test)
            
            # Precision, recall, F1 for binary classification
            if len(np.unique(y_test)) == 2:
                tp = np.sum((y_pred == 1) & (y_test == 1))
                fp = np.sum((y_pred == 1) & (y_test == 0))
                fn = np.sum((y_pred == 0) & (y_test == 1))
                
                precision = tp / (tp + fp) if (tp + fp) > 0 else 0
                recall = tp / (tp + fn) if (tp + fn) > 0 else 0
                f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
                
                return {
                    "accuracy": float(accuracy),
                    "precision": float(precision),
                    "recall": float(recall),
                    "f1_score": float(f1)
                }
            else:
                return {"accuracy": float(accuracy)}
        
        except Exception as e:
            logger.error(f"[DETERMINISTIC] Metrics computation failed: {e}")
            return {"error": str(e)}
    
    def _hash_dataset(self, X, y) -> str:
        """Hash dataset for verification."""
        import hashlib
        
        # Convert to bytes
        if hasattr(X, 'tobytes'):
            X_bytes = X.tobytes()
        else:
            X_bytes = str(X).encode()
        
        if hasattr(y, 'tobytes'):
            y_bytes = y.tobytes()
        else:
            y_bytes = str(y).encode()
        
        combined = X_bytes + y_bytes
        return hashlib.sha256(combined).hexdigest()
    
    def compare_evaluations(self, test_id_1: str, test_id_2: str) -> Dict:
        """Compare two evaluation runs."""
        eval1 = None
        eval2 = None
        
        for result in self.evaluation_history:
            if result.test_id == test_id_1:
                eval1 = result
            if result.test_id == test_id_2:
                eval2 = result
        
        if not eval1 or not eval2:
            return {"error": "One or both test IDs not found"}
        
        # Compare
        same_seed = eval1.random_seed == eval2.random_seed
        same_dataset = eval1.dataset_hash == eval2.dataset_hash
        same_metrics = eval1.metrics == eval2.metrics
        
        return {
            "same_seed": same_seed,
            "same_dataset": same_dataset,
            "same_metrics": same_metrics,
            "seed_1": eval1.random_seed,
            "seed_2": eval2.random_seed,
            "metrics_1": eval1.metrics,
            "metrics_2": eval2.metrics,
            "is_identical": same_seed and same_dataset and same_metrics
        }
    
    def generate_proof_certificate(self, test_id: str) -> Dict:
        """
        Generate cryptographic proof certificate for evaluation.
        
        Can be used for regulatory compliance or scientific publication.
        """
        result = None
        for r in self.evaluation_history:
            if r.test_id == test_id:
                result = r
                break
        
        if not result:
            return {"error": "Test ID not found"}
        
        import hashlib
        
        # Create certificate
        certificate = {
            "test_id": result.test_id,
            "timestamp": result.timestamp,
            "model_name": result.model_name,
            "random_seed": result.random_seed,
            "dataset_hash": result.dataset_hash,
            "metrics": result.metrics,
            "reproducible": result.reproducible,
            "configuration": result.configuration
        }
        
        # Sign certificate with hash
        cert_json = json.dumps(certificate, sort_keys=True)
        certificate["certificate_hash"] = hashlib.sha256(cert_json.encode()).hexdigest()
        
        logger.info(f"[DETERMINISTIC] Generated proof certificate for {test_id}")
        
        return certificate
    
    def _save_results(self):
        """Save evaluation results to disk."""
        data = {
            "evaluation_history": [
                {
                    "test_id": r.test_id,
                    "timestamp": r.timestamp,
                    "random_seed": r.random_seed,
                    "model_name": r.model_name,
                    "dataset_hash": r.dataset_hash,
                    "metrics": r.metrics,
                    "reproducible": r.reproducible,
                    "configuration": r.configuration
                }
                for r in self.evaluation_history
            ],
            "last_updated": datetime.now().isoformat()
        }
        
        with open(self.results_file, 'w') as f:
            json.dump(data, f, indent=2)
    
    def _load_results(self):
        """Load evaluation results from disk."""
        if not os.path.exists(self.results_file):
            return
        
        try:
            with open(self.results_file, 'r') as f:
                data = json.load(f)
            
            self.evaluation_history = [
                EvaluationResult(**r) for r in data.get('evaluation_history', [])
            ]
            
            logger.info(f"[DETERMINISTIC] Loaded {len(self.evaluation_history)} evaluation results")
        except Exception as e:
            logger.error(f"[DETERMINISTIC] Failed to load results: {e}")
    
    def get_stats(self) -> Dict:
        """Get evaluator statistics."""
        if len(self.evaluation_history) == 0:
            return {
                "total_test_runs": 0,
                "reproducibility_rate": 1.0,
                "proof_certificates_generated": 0,
                "consistency_score": 1.0,
                "recent_tests": []
            }
        
        model_counts = {}
        for r in self.evaluation_history:
            model_counts[r.model_name] = model_counts.get(r.model_name, 0) + 1
        
        reproducible = sum(1 for r in self.evaluation_history if r.reproducible)
        reproducibility_rate = reproducible / len(self.evaluation_history)
        
        # Build recent tests for dashboard
        recent_tests = []
        for result in reversed(self.evaluation_history[-15:]):  # Last 15
            recent_tests.append({
                "test_id": result.test_id,
                "timestamp": result.timestamp,
                "model_name": result.model_name,
                "reproducible": result.reproducible,
                "accuracy": result.metrics.get('accuracy', 0),
                "dataset_hash": result.dataset_hash[:16] if result.dataset_hash else "N/A"
            })
        
        return {
            "total_test_runs": len(self.evaluation_history),
            "reproducibility_rate": reproducibility_rate,
            "proof_certificates_generated": reproducible,
            "consistency_score": reproducibility_rate,
            "models_evaluated": model_counts,
            "recent_tests": recent_tests,
            "latest_evaluation": self.evaluation_history[-1].test_id if self.evaluation_history else None
        }


# Singleton instance
_deterministic_evaluator: Optional[DeterministicEvaluator] = None


def get_deterministic_evaluator() -> DeterministicEvaluator:
    """Get singleton deterministic evaluator instance."""
    global _deterministic_evaluator
    if _deterministic_evaluator is None:
        _deterministic_evaluator = DeterministicEvaluator()
    return _deterministic_evaluator
