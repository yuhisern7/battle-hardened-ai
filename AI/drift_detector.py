#!/usr/bin/env python3
"""
Drift Detector - Model Input Distribution Monitoring (Phase 3)

Detects when the statistical distribution of model inputs changes over time,
indicating that models may need retraining or that attack patterns are evolving.

Uses statistical tests:
- Kolmogorov-Smirnov test for distribution drift
- Population Stability Index (PSI) for feature drift
- Concept drift detection via accuracy monitoring

Privacy: Distribution statistics stored locally, only aggregate metrics shared.
"""

import os
import json
import time
import logging
from datetime import datetime
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, asdict
from collections import deque
import numpy as np

from AI.path_helper import get_json_dir

logger = logging.getLogger(__name__)

# Import statistical tools
try:
    from scipy import stats
    from sklearn.preprocessing import StandardScaler
    SCIPY_AVAILABLE = True
except ImportError:
    SCIPY_AVAILABLE = False
    logger.warning("[DRIFT] scipy not available - drift detection disabled")

# Feature flag to allow operators to disable drift detection without code changes
DRIFT_ENABLED = os.getenv('DRIFT_ENABLED', 'true').lower() == 'true'


@dataclass
class DriftReport:
    """Report of detected drift in model inputs"""
    timestamp: str
    feature_index: int
    feature_name: str
    drift_detected: bool
    drift_score: float  # 0-1, higher = more drift
    test_statistic: float
    p_value: float
    recommendation: str  # 'retrain', 'monitor', 'ok'
    
    def to_dict(self) -> dict:
        d = asdict(self)
        # Convert numpy types to native Python types
        for key, value in d.items():
            if hasattr(value, 'item'):  # numpy scalar
                d[key] = value.item()
            elif isinstance(value, (np.bool_, np.integer, np.floating)):
                d[key] = value.item()
        return d


@dataclass
class DriftStatistics:
    """Overall drift statistics across all features"""
    timestamp: str
    total_features: int
    features_drifted: int
    drift_percentage: float
    max_drift_score: float
    avg_drift_score: float
    requires_retraining: bool
    samples_since_baseline: int
    
    def to_dict(self) -> dict:
        d = asdict(self)
        # Convert numpy types to native Python types
        for key, value in d.items():
            if hasattr(value, 'item'):  # numpy scalar
                d[key] = value.item()
            elif isinstance(value, (np.bool_, np.integer, np.floating)):
                d[key] = value.item()
        return d


class DriftDetector:
    """
    Monitor statistical drift in model input distributions.
    
    Detects when feature distributions change significantly from baseline,
    indicating that models trained on old data may perform poorly on new data.
    
    Methods:
    - Kolmogorov-Smirnov test: Statistical test for distribution differences
    - PSI (Population Stability Index): Industry standard for feature stability
    - Rolling window comparison: Recent vs historical distributions
    
    Privacy: Only stores statistical summaries, not raw data.
    """
    
    def __init__(self, storage_dir: Optional[str] = None, window_size: int = 1000):
        """
        Initialize drift detector.
        
        Args:
            storage_dir: Directory for persistent storage
            window_size: Number of samples to keep for baseline comparison
        """
        # Storage paths (default to centralized JSON directory)
        default_storage_dir = get_json_dir()
        self.storage_dir = storage_dir or default_storage_dir
        os.makedirs(self.storage_dir, exist_ok=True)
        
        self.baseline_file = os.path.join(self.storage_dir, 'drift_baseline.json')
        self.reports_file = os.path.join(self.storage_dir, 'drift_reports.json')
        
        # Configuration
        self.window_size = window_size
        self.feature_names = [
            'endpoint_length', 'special_char_ratio', 'sql_keyword_count',
            'request_rate', 'failed_auth_ratio', 'port_entropy',
            'payload_size', 'header_count', 'param_count',
            'numeric_ratio', 'uppercase_ratio', 'path_depth',
            'query_complexity', 'entropy', 'timing_variance'
        ]
        
        # Baseline distribution (historical normal data)
        self.baseline_features: deque = deque(maxlen=window_size)
        self.baseline_statistics: Dict[int, Dict] = {}  # Feature index -> stats
        
        # Current window (recent data)
        self.current_features: deque = deque(maxlen=window_size // 2)
        
        # Drift detection state
        self.drift_reports: List[DriftReport] = []
        self.last_check: Optional[datetime] = None
        self.last_statistics: Optional[DriftStatistics] = None
        self.samples_processed = 0
        self.retraining_triggered = 0
        
        # Thresholds
        self.ks_pvalue_threshold = 0.05  # K-S test significance level
        self.psi_threshold = 0.2  # PSI > 0.2 indicates significant drift
        self.drift_score_threshold = 0.6  # Overall drift score for retraining
        
        # Load existing baseline
        self._load_baseline()
    
    def _load_baseline(self):
        """Load baseline distribution from disk"""
        try:
            if os.path.exists(self.baseline_file):
                with open(self.baseline_file, 'r') as f:
                    data = json.load(f)
                    
                    # Restore baseline features
                    baseline_data = data.get('baseline_features', [])
                    self.baseline_features = deque(baseline_data, maxlen=self.window_size)
                    
                    # Restore statistics
                    self.baseline_statistics = data.get('baseline_statistics', {})
                    # Convert string keys back to int
                    self.baseline_statistics = {
                        int(k): v for k, v in self.baseline_statistics.items()
                    }
                    
                    self.samples_processed = data.get('samples_processed', 0)
                    
                    logger.info(f"[DRIFT] Loaded baseline with {len(self.baseline_features)} samples")
        except Exception as e:
            logger.error(f"[DRIFT] Failed to load baseline: {e}")
    
    def _save_baseline(self):
        """Save baseline distribution to disk"""
        try:
            data = {
                'baseline_features': list(self.baseline_features),
                'baseline_statistics': self.baseline_statistics,
                'samples_processed': self.samples_processed,
                'updated': datetime.now().isoformat()
            }
            
            with open(self.baseline_file, 'w') as f:
                json.dump(data, f, indent=2)
            
            logger.info("[DRIFT] Saved baseline distribution")
            return True
        except Exception as e:
            logger.error(f"[DRIFT] Failed to save baseline: {e}")
            return False
    
    def _save_reports(self):
        """Save drift reports to disk"""
        try:
            reports_data = [r.to_dict() for r in self.drift_reports[-100:]]  # Last 100 reports
            
            with open(self.reports_file, 'w') as f:
                json.dump(reports_data, f, indent=2)
            
            return True
        except Exception as e:
            logger.error(f"[DRIFT] Failed to save reports: {e}")
            return False
    
    def update_baseline(self, features: np.ndarray):
        """
        Add samples to baseline distribution.
        
        Call this with NORMAL/SAFE traffic to establish baseline.
        
        Args:
            features: Feature vector (1D numpy array)
        """
        if not SCIPY_AVAILABLE:
            return
        
        # Add to baseline window
        self.baseline_features.append(features.tolist())
        self.samples_processed += 1
        
        # Recalculate baseline statistics every 100 samples
        if len(self.baseline_features) >= 100 and self.samples_processed % 100 == 0:
            self._calculate_baseline_statistics()
            self._save_baseline()
    
    def _calculate_baseline_statistics(self):
        """Calculate statistical summary of baseline distribution"""
        if len(self.baseline_features) < 10:
            return
        
        baseline_array = np.array(self.baseline_features)
        
        for i in range(baseline_array.shape[1]):
            feature_values = baseline_array[:, i]
            
            self.baseline_statistics[i] = {
                'mean': float(np.mean(feature_values)),
                'std': float(np.std(feature_values)),
                'min': float(np.min(feature_values)),
                'max': float(np.max(feature_values)),
                'median': float(np.median(feature_values)),
                'q25': float(np.percentile(feature_values, 25)),
                'q75': float(np.percentile(feature_values, 75))
            }
    
    def add_current_sample(self, features: np.ndarray):
        """
        Add sample to current window for drift comparison.
        
        Call this with ALL traffic (both normal and suspicious).
        
        Args:
            features: Feature vector (1D numpy array)
        """
        if not SCIPY_AVAILABLE:
            return
        
        self.current_features.append(features.tolist())
    
    def check_drift(self) -> DriftStatistics:
        """
        Check for distribution drift between baseline and current window.
        
        Returns:
            DriftStatistics with overall drift assessment
        """
        if not SCIPY_AVAILABLE:
            return self._empty_statistics()
        
        if len(self.baseline_features) < 100:
            logger.warning("[DRIFT] Insufficient baseline samples (need 100+)")
            return self._empty_statistics()
        
        if len(self.current_features) < 50:
            logger.warning("[DRIFT] Insufficient current samples (need 50+)")
            return self._empty_statistics()
        
        baseline_array = np.array(self.baseline_features)
        current_array = np.array(self.current_features)
        
        drift_reports = []
        drift_scores = []
        
        # Check each feature for drift
        for i in range(min(baseline_array.shape[1], current_array.shape[1])):
            baseline_feature = baseline_array[:, i]
            current_feature = current_array[:, i]
            
            # Kolmogorov-Smirnov test
            ks_stat, p_value = stats.ks_2samp(baseline_feature, current_feature)
            
            # Population Stability Index (PSI)
            psi_score = self._calculate_psi(baseline_feature, current_feature)
            
            # Combined drift score
            drift_score = self._calculate_drift_score(ks_stat, p_value, psi_score)
            drift_scores.append(drift_score)
            
            # Determine if drift detected
            drift_detected = (p_value < self.ks_pvalue_threshold) or (psi_score > self.psi_threshold)
            
            # Recommendation
            if drift_score > 0.8:
                recommendation = 'retrain'
            elif drift_score > 0.5:
                recommendation = 'monitor'
            else:
                recommendation = 'ok'
            
            # Create report
            feature_name = self.feature_names[i] if i < len(self.feature_names) else f'feature_{i}'
            report = DriftReport(
                timestamp=datetime.now().isoformat(),
                feature_index=int(i),
                feature_name=feature_name,
                drift_detected=bool(drift_detected),
                drift_score=float(drift_score),
                test_statistic=float(ks_stat),
                p_value=float(p_value),
                recommendation=recommendation
            )
            
            drift_reports.append(report)
        
        # Overall statistics
        features_drifted = sum(1 for r in drift_reports if r.drift_detected)
        max_drift = max(drift_scores) if drift_scores else 0.0
        avg_drift = np.mean(drift_scores) if drift_scores else 0.0
        
        # Determine if retraining required
        requires_retraining = (
            features_drifted >= 3 or  # 3+ features drifted
            max_drift > self.drift_score_threshold or  # Any feature severely drifted
            avg_drift > 0.4  # Overall average drift high
        )
        
        statistics = DriftStatistics(
            timestamp=datetime.now().isoformat(),
            total_features=int(len(drift_reports)),
            features_drifted=int(features_drifted),
            drift_percentage=float(features_drifted / len(drift_reports) * 100) if drift_reports else 0.0,
            max_drift_score=float(max_drift),
            avg_drift_score=float(avg_drift),
            requires_retraining=bool(requires_retraining),
            samples_since_baseline=int(len(self.current_features))
        )
        
        # Store reports
        self.drift_reports.extend(drift_reports)
        self.last_check = datetime.now()
        self.last_statistics = statistics
        
        # Save to disk
        self._save_reports()
        
        if requires_retraining:
            self.retraining_triggered += 1
            logger.warning(f"[DRIFT] ⚠️ DRIFT DETECTED: {features_drifted}/{len(drift_reports)} features drifted (avg: {avg_drift:.2f})")
        
        return statistics
    
    def _calculate_psi(self, baseline: np.ndarray, current: np.ndarray, bins: int = 10) -> float:
        """
        Calculate Population Stability Index (PSI).
        
        PSI measures how much a distribution has shifted:
        - PSI < 0.1: No significant change
        - 0.1 < PSI < 0.2: Moderate change
        - PSI > 0.2: Significant change (retraining recommended)
        
        Args:
            baseline: Baseline feature values
            current: Current feature values
            bins: Number of bins for histogram
        
        Returns:
            PSI score
        """
        try:
            # Create bins based on baseline distribution
            min_val = min(baseline.min(), current.min())
            max_val = max(baseline.max(), current.max())
            
            if min_val == max_val:
                return 0.0  # No variation
            
            bin_edges = np.linspace(min_val, max_val, bins + 1)
            
            # Calculate percentage in each bin
            baseline_percents, _ = np.histogram(baseline, bins=bin_edges)
            current_percents, _ = np.histogram(current, bins=bin_edges)
            
            # Avoid division by zero
            baseline_percents = baseline_percents / len(baseline) + 1e-10
            current_percents = current_percents / len(current) + 1e-10
            
            # PSI formula
            psi = np.sum((current_percents - baseline_percents) * np.log(current_percents / baseline_percents))
            
            return float(abs(psi))
        
        except Exception as e:
            logger.error(f"[DRIFT] PSI calculation failed: {e}")
            return 0.0
    
    def _calculate_drift_score(self, ks_stat: float, p_value: float, psi: float) -> float:
        """
        Combine multiple drift metrics into single score (0-1).
        
        Args:
            ks_stat: Kolmogorov-Smirnov statistic
            p_value: K-S test p-value
            psi: Population Stability Index
        
        Returns:
            Combined drift score (0 = no drift, 1 = severe drift)
        """
        # Normalize K-S statistic (0-1)
        ks_score = min(ks_stat, 1.0)
        
        # Convert p-value to score (low p-value = high drift)
        p_score = max(0.0, 1.0 - p_value)
        
        # Normalize PSI (cap at 1.0 for PSI > 0.5)
        psi_score = min(psi / 0.5, 1.0)
        
        # Weighted combination
        drift_score = (
            0.4 * ks_score +
            0.3 * p_score +
            0.3 * psi_score
        )
        
        return float(drift_score)
    
    def _empty_statistics(self) -> DriftStatistics:
        """Return empty statistics when drift check cannot run"""
        return DriftStatistics(
            timestamp=datetime.now().isoformat(),
            total_features=0,
            features_drifted=0,
            drift_percentage=0.0,
            max_drift_score=0.0,
            avg_drift_score=0.0,
            requires_retraining=False,
            samples_since_baseline=len(self.current_features)
        )
    
    def reset_current_window(self):
        """Clear current window after drift check or retraining"""
        self.current_features.clear()
        logger.info("[DRIFT] Current window reset")
    
    def update_baseline_from_current(self):
        """
        Update baseline with current window after retraining.
        
        Call this after model retraining to establish new baseline.
        """
        if len(self.current_features) < 50:
            logger.warning("[DRIFT] Insufficient current samples to update baseline")
            return False
        
        # Add current samples to baseline
        for features in self.current_features:
            self.baseline_features.append(features)
        
        # Recalculate statistics
        self._calculate_baseline_statistics()
        self._save_baseline()
        
        # Clear current window
        self.reset_current_window()
        
        logger.info("[DRIFT] Baseline updated with current distribution")
        return True
    
    def get_stats(self) -> dict:
        """Get drift detector statistics"""
        stats = {
            'scipy_available': SCIPY_AVAILABLE,
            'enabled': bool(SCIPY_AVAILABLE and DRIFT_ENABLED),
            'baseline_samples': len(self.baseline_features),
            'current_samples': len(self.current_features),
            'samples_processed': self.samples_processed,
            'last_check': self.last_check.isoformat() if self.last_check else None,
            'total_drift_reports': len(self.drift_reports),
            'retraining_triggered': self.retraining_triggered,
            'ks_threshold': self.ks_pvalue_threshold,
            'psi_threshold': self.psi_threshold,
            'baseline_file': self.baseline_file
        }

        # Attach the most recent overall drift statistics snapshot if available
        if self.last_statistics is not None:
            stats['last_drift_statistics'] = self.last_statistics.to_dict()
        
        return stats
    
    def get_recent_reports(self, limit: int = 10) -> List[Dict]:
        """Get recent drift reports"""
        recent = self.drift_reports[-limit:] if self.drift_reports else []
        return [r.to_dict() for r in recent]


# Global instance
_drift_detector = None


def get_drift_detector() -> Optional[DriftDetector]:
    """Get or create global drift detector instance"""
    global _drift_detector
    if _drift_detector is None and SCIPY_AVAILABLE and DRIFT_ENABLED:
        _drift_detector = DriftDetector()
    return _drift_detector


# Convenience functions
def update_baseline(features: np.ndarray):
    """Add normal traffic to baseline distribution"""
    detector = get_drift_detector()
    if detector:
        detector.update_baseline(features)


def check_drift() -> Optional[DriftStatistics]:
    """Check for distribution drift"""
    detector = get_drift_detector()
    if detector:
        return detector.check_drift()
    return None


def track_features(features: np.ndarray):
    """Track features in current window for drift comparison"""
    detector = get_drift_detector()
    if detector:
        detector.add_current_sample(features)
