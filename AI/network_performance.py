"""Network Performance Metrics with AI Anomaly Detection

Monitors network performance and detects anomalies:
- Bandwidth monitoring (bytes/sec per IP)
- Latency tracking (RTT measurements)
- Packet loss detection
- Connection quality scoring
- AI-powered anomaly detection

Integrates with ML models to detect DDoS, network saturation, and quality issues.
"""

import time
import json
import os
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, DefaultDict, Dict, List, Tuple, Optional
import threading
import pytz
import logging

logger = logging.getLogger(__name__)

# Configuration flags
NETWORK_PERF_ENABLED = os.getenv("NETWORK_PERF_ENABLED", "true").lower() == "true"
MAX_IP_METRICS = int(os.getenv("NETWORK_PERF_MAX_IPS", "10000"))

# Try importing ML libraries and initialize anomaly detector
try:
    import numpy as np
    from sklearn.ensemble import IsolationForest
    ML_AVAILABLE = True

    # AI anomaly detector for network performance
    _performance_anomaly_detector = IsolationForest(
        contamination=0.1,  # 10% of data expected to be anomalies
        random_state=42,
        n_estimators=100,
    )
except ImportError:
    ML_AVAILABLE = False
    np = None  # type: ignore[assignment]
    IsolationForest = None  # type: ignore[assignment]
    _performance_anomaly_detector = None

# Performance metrics storage
_performance_metrics: DefaultDict[str, Dict[str, Any]] = defaultdict(lambda: {
    'bandwidth': {
        'bytes_sent': 0,
        'bytes_received': 0,
        'last_measurement': None,
        'rate_history': []  # [(timestamp, bytes/sec)]
    },
    'latency': {
        'rtt_samples': [],  # [(timestamp, rtt_ms)]
        'avg_rtt': 0.0,
        'min_rtt': float('inf'),
        'max_rtt': 0.0,
        'jitter': 0.0  # RTT variance
    },
    'packet_loss': {
        'packets_sent': 0,
        'packets_received': 0,
        'loss_rate': 0.0,
        'loss_history': []
    },
    'quality_score': 100.0,  # 0-100, higher is better
    'anomaly_score': 0.0,  # 0-1, higher means more anomalous
    'first_seen': None,
    'last_seen': None
})

# Network-wide performance stats
_network_stats = {
    'total_bandwidth_in': 0,
    'total_bandwidth_out': 0,
    'average_latency': 0.0,
    'network_quality': 100.0,
    'congestion_level': 0.0,  # 0-1
    'active_connections': 0
}

# Persistent storage
from AI.path_helper import get_json_file
_PERFORMANCE_METRICS_FILE = get_json_file('network_performance.json')

# Configuration
MAX_HISTORY_SAMPLES = 100  # Keep last 100 measurements per IP
PERFORMANCE_SAVE_INTERVAL = 60  # Save every 60 seconds
ANOMALY_THRESHOLD = 0.7  # Anomaly score above this triggers alert


def _get_current_time():
    """Get current datetime in configured timezone"""
    try:
        tz_name = os.getenv('TZ', 'Asia/Kuala_Lumpur')
        tz = pytz.timezone(tz_name)
        return datetime.now(tz)
    except:
        return datetime.now(pytz.UTC)


def update_bandwidth(ip_address: str, bytes_sent: int, bytes_received: int) -> None:
    """Update bandwidth metrics for an IP address.
    
    Args:
        ip_address: Source IP
        bytes_sent: Bytes sent by this IP
        bytes_received: Bytes received by this IP
    """
    if not NETWORK_PERF_ENABLED:
        return

    # Bound number of tracked IPs to avoid unbounded memory growth
    if ip_address not in _performance_metrics and len(_performance_metrics) >= MAX_IP_METRICS:
        logger.debug(
            f"[NET-PERF] Max IP metrics reached ({MAX_IP_METRICS}); dropping new IP {ip_address}"
        )
        return

    metrics = _performance_metrics[ip_address]
    now = _get_current_time()
    
    if metrics['bandwidth']['last_measurement']:
        # Calculate time delta
        time_delta = (now - metrics['bandwidth']['last_measurement']).total_seconds()
        
        if time_delta > 0:
            # Calculate bytes/sec rates
            sent_rate = bytes_sent / time_delta
            recv_rate = bytes_received / time_delta
            
            # Store in history
            metrics['bandwidth']['rate_history'].append({
                'timestamp': now.isoformat(),
                'sent_rate': sent_rate,
                'recv_rate': recv_rate,
                'total_rate': sent_rate + recv_rate
            })
            
            # Limit history size
            if len(metrics['bandwidth']['rate_history']) > MAX_HISTORY_SAMPLES:
                metrics['bandwidth']['rate_history'].pop(0)
    
    # Update totals
    metrics['bandwidth']['bytes_sent'] += bytes_sent
    metrics['bandwidth']['bytes_received'] += bytes_received
    metrics['bandwidth']['last_measurement'] = now
    
    if not metrics['first_seen']:
        metrics['first_seen'] = now.isoformat()
    metrics['last_seen'] = now.isoformat()
    
    # Update network-wide stats
    _network_stats['total_bandwidth_in'] += bytes_received
    _network_stats['total_bandwidth_out'] += bytes_sent


def update_latency(ip_address: str, rtt_ms: float) -> None:
    """Update latency metrics for an IP address.
    
    Args:
        ip_address: Source IP
        rtt_ms: Round-trip time in milliseconds
    """
    if not NETWORK_PERF_ENABLED:
        return

    if ip_address not in _performance_metrics and len(_performance_metrics) >= MAX_IP_METRICS:
        logger.debug(
            f"[NET-PERF] Max IP metrics reached ({MAX_IP_METRICS}); dropping latency for {ip_address}"
        )
        return

    metrics = _performance_metrics[ip_address]
    now = _get_current_time()
    
    # Store RTT sample
    metrics['latency']['rtt_samples'].append({
        'timestamp': now.isoformat(),
        'rtt': rtt_ms
    })
    
    # Limit history
    if len(metrics['latency']['rtt_samples']) > MAX_HISTORY_SAMPLES:
        metrics['latency']['rtt_samples'].pop(0)
    
    # Calculate statistics
    rtts = [s['rtt'] for s in metrics['latency']['rtt_samples']]
    if ML_AVAILABLE and np is not None:
        metrics['latency']['avg_rtt'] = float(np.mean(rtts))
    else:
        metrics['latency']['avg_rtt'] = sum(rtts) / len(rtts)
    metrics['latency']['min_rtt'] = min(rtts)
    metrics['latency']['max_rtt'] = max(rtts)
    
    # Calculate jitter (variance in RTT)
    if ML_AVAILABLE and np is not None and len(rtts) > 1:
        metrics['latency']['jitter'] = float(np.std(rtts))
    elif len(rtts) > 1:
        mean = sum(rtts) / len(rtts)
        variance = sum((x - mean) ** 2 for x in rtts) / len(rtts)
        metrics['latency']['jitter'] = variance ** 0.5
    
    if not metrics['first_seen']:
        metrics['first_seen'] = now.isoformat()
    metrics['last_seen'] = now.isoformat()


def update_packet_loss(ip_address: str, packets_sent: int, packets_received: int) -> None:
    """Update packet loss metrics for an IP address.
    
    Args:
        ip_address: Source IP
        packets_sent: Total packets sent
        packets_received: Total packets received (ACKs)
    """
    if not NETWORK_PERF_ENABLED:
        return

    if ip_address not in _performance_metrics and len(_performance_metrics) >= MAX_IP_METRICS:
        logger.debug(
            f"[NET-PERF] Max IP metrics reached ({MAX_IP_METRICS}); dropping packet loss for {ip_address}"
        )
        return

    metrics = _performance_metrics[ip_address]
    now = _get_current_time()
    
    metrics['packet_loss']['packets_sent'] = packets_sent
    metrics['packet_loss']['packets_received'] = packets_received
    
    # Calculate loss rate
    if packets_sent > 0:
        loss_rate = (packets_sent - packets_received) / packets_sent
        metrics['packet_loss']['loss_rate'] = max(0.0, min(1.0, loss_rate))
        
        metrics['packet_loss']['loss_history'].append({
            'timestamp': now.isoformat(),
            'loss_rate': metrics['packet_loss']['loss_rate']
        })
        
        if len(metrics['packet_loss']['loss_history']) > MAX_HISTORY_SAMPLES:
            metrics['packet_loss']['loss_history'].pop(0)
    
    if not metrics['first_seen']:
        metrics['first_seen'] = now.isoformat()
    metrics['last_seen'] = now.isoformat()


def calculate_quality_score(ip_address: str) -> float:
    """Calculate connection quality score (0-100) based on multiple factors.
    
    Score factors:
    - Latency (lower is better)
    - Jitter (lower is better)
    - Packet loss (lower is better)
    - Bandwidth stability (less variance is better)
    
    Returns:
        Quality score 0-100 (100 = perfect)
    """
    metrics = _performance_metrics[ip_address]
    score = 100.0
    
    # Factor 1: Latency penalty
    avg_rtt = metrics['latency']['avg_rtt']
    if avg_rtt > 0:
        if avg_rtt < 50:
            latency_penalty = 0
        elif avg_rtt < 100:
            latency_penalty = 10
        elif avg_rtt < 200:
            latency_penalty = 20
        elif avg_rtt < 500:
            latency_penalty = 35
        else:
            latency_penalty = 50
        score -= latency_penalty
    
    # Factor 2: Jitter penalty
    jitter = metrics['latency']['jitter']
    if jitter > 50:
        score -= 20
    elif jitter > 30:
        score -= 10
    elif jitter > 10:
        score -= 5
    
    # Factor 3: Packet loss penalty
    loss_rate = metrics['packet_loss']['loss_rate']
    if loss_rate > 0.1:  # >10% loss
        score -= 30
    elif loss_rate > 0.05:  # >5% loss
        score -= 20
    elif loss_rate > 0.01:  # >1% loss
        score -= 10
    elif loss_rate > 0:
        score -= 5
    
    # Ensure score is in valid range
    score = max(0.0, min(100.0, score))
    metrics['quality_score'] = score
    
    return score


def detect_performance_anomaly(ip_address: str) -> Tuple[bool, float, str]:
    """Use AI to detect performance anomalies.
    
    Returns:
        (is_anomaly, anomaly_score, reason)
    """
    if not ML_AVAILABLE or np is None or _performance_anomaly_detector is None:
        return False, 0.0, "ML not available"

    metrics = _performance_metrics[ip_address]
    
    # Extract features for ML model
    features = []
    
    # Bandwidth features
    if metrics['bandwidth']['rate_history']:
        recent_rates = [r['total_rate'] for r in metrics['bandwidth']['rate_history'][-10:]]
        features.append(np.mean(recent_rates) if recent_rates else 0)
        features.append(np.std(recent_rates) if len(recent_rates) > 1 else 0)
        features.append(np.max(recent_rates) if recent_rates else 0)
    else:
        features.extend([0, 0, 0])
    
    # Latency features
    features.append(metrics['latency']['avg_rtt'])
    features.append(metrics['latency']['jitter'])
    
    # RTT range (handle uninitialized min/max)
    min_rtt = metrics['latency']['min_rtt']
    max_rtt = metrics['latency']['max_rtt']
    rtt_range = (max_rtt - min_rtt) if min_rtt != float('inf') and max_rtt > 0 else 0.0
    features.append(rtt_range)
    
    # Packet loss features
    features.append(metrics['packet_loss']['loss_rate'])
    
    # Quality score
    features.append(metrics['quality_score'])
    
    if len(features) < 8:
        return False, 0.0, "Insufficient data"
    
    try:
        # Reshape for prediction
        features_array = np.array(features).reshape(1, -1)
        
        # Train detector if needed (with all IPs' data)
        if not hasattr(_performance_anomaly_detector, 'offset_'):
            all_features = []
            for ip, m in _performance_metrics.items():
                if m['bandwidth']['rate_history']:
                    ip_features = []
                    recent_rates = [r['total_rate'] for r in m['bandwidth']['rate_history'][-10:]]
                    ip_features.append(np.mean(recent_rates) if recent_rates else 0)
                    ip_features.append(np.std(recent_rates) if len(recent_rates) > 1 else 0)
                    ip_features.append(np.max(recent_rates) if recent_rates else 0)
                    ip_features.append(m['latency']['avg_rtt'])
                    ip_features.append(m['latency']['jitter'])
                    
                    # RTT range (handle uninitialized min/max)
                    min_rtt = m['latency']['min_rtt']
                    max_rtt = m['latency']['max_rtt']
                    rtt_range = (max_rtt - min_rtt) if min_rtt != float('inf') and max_rtt > 0 else 0.0
                    ip_features.append(rtt_range)
                    
                    ip_features.append(m['packet_loss']['loss_rate'])
                    ip_features.append(m['quality_score'])
                    all_features.append(ip_features)
            
            if len(all_features) >= 5:
                _performance_anomaly_detector.fit(np.array(all_features))
        
        # Predict anomaly
        if hasattr(_performance_anomaly_detector, 'offset_'):
            prediction = _performance_anomaly_detector.predict(features_array)[0]
            anomaly_score = -_performance_anomaly_detector.score_samples(features_array)[0]
            
            is_anomaly = prediction == -1
            
            # Determine reason
            reason = ""
            if is_anomaly:
                if metrics['latency']['avg_rtt'] > 500:
                    reason = "Extremely high latency"
                elif metrics['packet_loss']['loss_rate'] > 0.1:
                    reason = "High packet loss"
                elif metrics['latency']['jitter'] > 100:
                    reason = "Severe jitter"
                elif metrics['quality_score'] < 50:
                    reason = "Poor connection quality"
                else:
                    reason = "Abnormal network pattern"
            
            metrics['anomaly_score'] = float(anomaly_score)
            
            return is_anomaly, float(anomaly_score), reason
        else:
            return False, 0.0, "Detector not trained yet"
    
    except Exception as e:
        return False, 0.0, f"Error: {str(e)}"


def get_performance_metrics(ip_address: str) -> Optional[Dict[str, Any]]:
    """Get performance metrics for an IP address."""
    if ip_address not in _performance_metrics:
        return None
    
    metrics = dict(_performance_metrics[ip_address])
    
    # Calculate quality score
    calculate_quality_score(ip_address)
    
    # Detect anomalies
    is_anomaly, anomaly_score, reason = detect_performance_anomaly(ip_address)
    metrics['is_anomaly'] = is_anomaly
    metrics['anomaly_reason'] = reason
    
    return metrics


def get_all_performance_metrics() -> dict:
    """Get performance metrics for all IPs."""
    result = {}
    for ip in _performance_metrics.keys():
        result[ip] = get_performance_metrics(ip)
    return result


def get_network_statistics() -> dict:
    """Get network-wide performance statistics."""
    # Calculate average metrics across all IPs
    if _performance_metrics:
        all_latencies = [m['latency']['avg_rtt'] for m in _performance_metrics.values() if m['latency']['avg_rtt'] > 0]
        all_quality = [m['quality_score'] for m in _performance_metrics.values()]
        
        if all_latencies:
            _network_stats['average_latency'] = sum(all_latencies) / len(all_latencies)
        
        if all_quality:
            _network_stats['network_quality'] = sum(all_quality) / len(all_quality)
        
        _network_stats['active_connections'] = len(_performance_metrics)
        
        # Calculate congestion level (0-1)
        avg_loss = sum(m['packet_loss']['loss_rate'] for m in _performance_metrics.values()) / len(_performance_metrics)
        avg_latency_normalized = min(1.0, _network_stats['average_latency'] / 1000)  # Normalize to 0-1
        _network_stats['congestion_level'] = (avg_loss + avg_latency_normalized) / 2
    
    return dict(_network_stats)


def get_top_bandwidth_users(limit: int = 10) -> List[dict]:
    """Get top bandwidth consumers."""
    bandwidth_users = []
    
    for ip, metrics in _performance_metrics.items():
        total_bandwidth = metrics['bandwidth']['bytes_sent'] + metrics['bandwidth']['bytes_received']
        
        # Calculate current rate (last measurement)
        current_rate = 0
        if metrics['bandwidth']['rate_history']:
            current_rate = metrics['bandwidth']['rate_history'][-1]['total_rate']
        
        bandwidth_users.append({
            'ip': ip,
            'total_bytes': total_bandwidth,
            'current_rate': current_rate,
            'quality_score': metrics['quality_score']
        })
    
    # Sort by total bandwidth
    bandwidth_users.sort(key=lambda x: x['total_bytes'], reverse=True)
    
    return bandwidth_users[:limit]


def get_performance_anomalies() -> List[dict]:
    """Get all IPs with detected performance anomalies."""
    anomalies = []
    
    for ip, metrics in _performance_metrics.items():
        is_anomaly, score, reason = detect_performance_anomaly(ip)
        
        if is_anomaly and score > ANOMALY_THRESHOLD:
            anomalies.append({
                'ip': ip,
                'anomaly_score': score,
                'reason': reason,
                'quality_score': metrics['quality_score'],
                'avg_latency': metrics['latency']['avg_rtt'],
                'packet_loss': metrics['packet_loss']['loss_rate'],
                'last_seen': metrics['last_seen']
            })
    
    # Sort by anomaly score
    anomalies.sort(key=lambda x: x['anomaly_score'], reverse=True)
    
    return anomalies


def save_performance_metrics() -> None:
    """Save performance metrics to disk."""
    if not NETWORK_PERF_ENABLED:
        logger.debug("[NET-PERF] save_performance_metrics skipped (NETWORK_PERF_ENABLED=false)")
        return

    try:
        os.makedirs(os.path.dirname(_PERFORMANCE_METRICS_FILE), exist_ok=True)
        
        # Convert to serializable format
        def serialize_metrics(obj):
            """Convert datetime objects to ISO format strings."""
            if isinstance(obj, datetime):
                return obj.isoformat()
            elif isinstance(obj, dict):
                return {k: serialize_metrics(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [serialize_metrics(item) for item in obj]
            elif isinstance(obj, tuple):
                return tuple(serialize_metrics(item) for item in obj)
            return obj
        
        data = {
            'metrics': serialize_metrics(dict(_performance_metrics)),
            'network_stats': serialize_metrics(_network_stats),
            'last_updated': _get_current_time().isoformat()
        }
        
        with open(_PERFORMANCE_METRICS_FILE, 'w') as f:
            json.dump(data, f, indent=2)

    except Exception as e:
        logger.warning(f"[NET-PERF] Failed to save performance metrics: {e}")


def load_performance_metrics() -> None:
    """Load performance metrics from disk."""
    global _performance_metrics, _network_stats
    
    try:
        if os.path.exists(_PERFORMANCE_METRICS_FILE):
            with open(_PERFORMANCE_METRICS_FILE, 'r') as f:
                data = json.load(f)

            # Restore metrics
            for ip, metrics in data.get('metrics', {}).items():
                _performance_metrics[ip] = metrics

            _network_stats.update(data.get('network_stats', {}))

            logger.info(f"[NET-PERF] Loaded metrics for {len(_performance_metrics)} IPs")

    except Exception as e:
        logger.warning(f"[NET-PERF] Failed to load performance metrics: {e}")


def start_auto_save():
    """Start background thread to auto-save metrics."""
    def auto_save_loop():
        while True:
            time.sleep(PERFORMANCE_SAVE_INTERVAL)
            save_performance_metrics()
    
    thread = threading.Thread(target=auto_save_loop, daemon=True)
    thread.start()


# Initialize on import
load_performance_metrics()
start_auto_save()
