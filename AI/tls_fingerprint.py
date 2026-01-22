#!/usr/bin/env python3
"""TLS / Encrypted Flow Fingerprinting (Metadata-Only)

Provides lightweight, metadata-only heuristics for TLS-like flows:
- Track per-source IP destinations and ports used for encrypted traffic.
- Flag unusual TLS ports and excessive fan-out as potential C2 / evasion.
"""

import os
import json
import time
from dataclasses import dataclass, asdict
from typing import Dict, Any, List
import logging

from AI.path_helper import get_json_file


logger = logging.getLogger(__name__)

_TLS_METRICS_FILE = get_json_file("tls_fingerprints.json")


STANDARD_TLS_PORTS = {443, 8443, 9443}


@dataclass
class TlsFlowStats:
    src_ip: str
    total_flows: int = 0
    unique_dests: int = 0
    unique_ports: int = 0
    nonstandard_tls_ports: List[int] = None
    first_seen: float = 0.0
    last_seen: float = 0.0

    def __post_init__(self):
        if self.nonstandard_tls_ports is None:
            self.nonstandard_tls_ports = []


_flows: Dict[str, TlsFlowStats] = {}
_last_save: float = 0.0
_SAVE_INTERVAL = 60.0

_dest_sets: Dict[str, set] = {}
_port_sets: Dict[str, set] = {}


def _save_metrics() -> None:
    try:
        os.makedirs(os.path.dirname(_TLS_METRICS_FILE), exist_ok=True)
        data = {
            "last_updated": time.time(),
            "sources": {ip: asdict(stats) for ip, stats in _flows.items()},
        }
        with open(_TLS_METRICS_FILE, "w") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        logger.warning(f"[TLS] Failed to save TLS metrics: {e}")


def observe_tls_flow(
    src_ip: str,
    dst_ip: str,
    dst_port: int,
    src_port: int,
    packet_size: int,
) -> Dict[str, Any]:
    """Observe an encrypted (TLS-like) TCP flow and return heuristic verdict.

    Returns dict with keys:
        suspicious (bool), threat_type (str), confidence (float), reasons (List[str])
    """

    global _last_save
    now = time.time()

    if src_ip not in _flows:
        _flows[src_ip] = TlsFlowStats(src_ip=src_ip, first_seen=now, last_seen=now)
        _dest_sets[src_ip] = set()
        _port_sets[src_ip] = set()

    stats = _flows[src_ip]
    dests = _dest_sets[src_ip]
    ports = _port_sets[src_ip]

    stats.total_flows += 1
    stats.last_seen = now

    dests.add((dst_ip, dst_port))
    ports.add(dst_port)
    stats.unique_dests = len(dests)
    stats.unique_ports = len(ports)

    suspicious = False
    confidence = 0.0
    reasons: List[str] = []

    # Non-standard TLS ports used heavily
    if dst_port not in STANDARD_TLS_PORTS and dst_port >= 1024:
        if dst_port not in stats.nonstandard_tls_ports:
            stats.nonstandard_tls_ports.append(dst_port)
        suspicious = True
        confidence += 0.3
        reasons.append(f"Encrypted-looking traffic on nonstandard port {dst_port}")

    # Excessive fan-out over TLS ports may indicate C2 beacons
    if stats.unique_dests > 50 and stats.total_flows > 200:
        suspicious = True
        confidence += 0.3
        reasons.append(
            f"High TLS fan-out: {stats.unique_dests} destinations / {stats.total_flows} flows"
        )

    # Very frequent small packets over TLS port can indicate beaconing
    if packet_size < 200 and stats.total_flows > 500:
        suspicious = True
        confidence += 0.2
        reasons.append("Frequent small TLS packets (possible beaconing)")

    confidence = min(confidence, 0.95)

    if now - _last_save > _SAVE_INTERVAL:
        _save_metrics()
        _last_save = now

    result: Dict[str, Any] = {
        "suspicious": suspicious,
        "confidence": confidence,
        "reasons": reasons,
        "threat_type": "Encrypted C2 Suspected" if suspicious else "BENIGN_TLS",
    }

    if suspicious:
        logger.warning(
            f"[TLS] Suspicious encrypted flow from {src_ip} to {dst_ip}:{dst_port} | "
            f"reasons={'; '.join(reasons)}"
        )

    return result


__all__ = ["observe_tls_flow"]
