#!/usr/bin/env python3
"""DNS Security & DGA / Tunneling Heuristics

Lightweight DNS analyzer for NDR pipeline.

Goals (NDR-safe, metadata only):
- Track per-IP DNS query behavior (no payload content inspection).
- Detect obvious DNS tunneling / exfil (very long, high-entropy labels).
- Detect DGA-like domains (high entropy, many unique characters).
- Persist summary metrics to JSON for dashboard & training.
"""

import json
import os
import math
import time
from collections import defaultdict
from dataclasses import dataclass, asdict
from typing import Dict, Any, List
import logging

from AI.path_helper import get_json_file


logger = logging.getLogger(__name__)

_DNS_METRICS_FILE = get_json_file("dns_security.json")


@dataclass
class DnsStats:
    """Aggregate DNS behavior metrics per source IP."""

    ip: str
    total_queries: int = 0
    suspicious_queries: int = 0
    last_query_ts: float = 0.0
    last_domains: List[str] = None

    def __post_init__(self):
        if self.last_domains is None:
            self.last_domains = []


_dns_stats: Dict[str, DnsStats] = {}
_last_save: float = 0.0
_SAVE_INTERVAL = 60.0  # seconds


def _shannon_entropy(s: str) -> float:
    """Approximate Shannon entropy for a domain string."""
    if not s:
        return 0.0
    freq = defaultdict(int)
    for ch in s:
        freq[ch] += 1
    length = len(s)
    ent = 0.0
    for count in freq.values():
        p = count / length
        ent -= p * math.log2(p)
    return ent


def _is_base64_like(label: str) -> bool:
    """Cheap check for base64-ish labels used in tunneling/exfil."""
    if len(label) < 16:
        return False
    allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
    hits = sum(1 for c in label if c in allowed)
    return hits / max(len(label), 1) > 0.9


def _update_stats(src_ip: str, domain: str, suspicious: bool) -> None:
    global _last_save
    now = time.time()

    if src_ip not in _dns_stats:
        _dns_stats[src_ip] = DnsStats(ip=src_ip)

    stats = _dns_stats[src_ip]
    stats.total_queries += 1
    if suspicious:
        stats.suspicious_queries += 1
    stats.last_query_ts = now
    stats.last_domains.append(domain)
    if len(stats.last_domains) > 20:
        stats.last_domains.pop(0)

    # Periodic persistence
    if now - _last_save > _SAVE_INTERVAL:
        _save_metrics()
        _last_save = now


def _save_metrics() -> None:
    """Persist DNS behavior metrics to JSON."""
    try:
        os.makedirs(os.path.dirname(_DNS_METRICS_FILE), exist_ok=True)
        data = {
            "last_updated": time.time(),
            "sources": {ip: asdict(stats) for ip, stats in _dns_stats.items()},
        }
        with open(_DNS_METRICS_FILE, "w") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        logger.warning(f"[DNS] Failed to save DNS metrics: {e}")


def analyze_dns_query(
    src_ip: str,
    query_name: str,
    qtype: str,
    payload_len: int,
) -> Dict[str, Any]:
    """Analyze a single DNS query and return heuristic verdict.

    Returns dict with keys:
        suspicious (bool), threat_type (str), confidence (float), reasons (List[str])
    """

    reasons: List[str] = []
    suspicious = False
    confidence = 0.0

    domain = (query_name or "").strip(".")
    domain_lower = domain.lower()

    # Basic length checks
    if len(domain) > 80:
        suspicious = True
        confidence += 0.3
        reasons.append(f"Very long domain: {len(domain)} chars")

    labels = domain_lower.split(".") if domain_lower else []
    deepest_label = max(labels, key=len) if labels else ""

    # Deep subdomain chains are common for tunneling
    if len(labels) >= 6:
        suspicious = True
        confidence += 0.2
        reasons.append(f"Deep subdomain chain: {len(labels)} labels")

    # High-entropy labels often indicate DGA/tunneling
    ent = _shannon_entropy(deepest_label)
    if ent >= 3.5 and len(deepest_label) >= 20:
        suspicious = True
        confidence += 0.3
        reasons.append(f"High-entropy label '{deepest_label[:16]}...' (H={ent:.2f})")

    # Base64-like labels used for DNS exfil/tunneling
    if _is_base64_like(deepest_label):
        suspicious = True
        confidence += 0.3
        reasons.append("Label appears base64-like (possible DNS exfil)")

    # Large TXT/NULL payloads via DNS are uncommon
    qtype_upper = qtype.upper() if isinstance(qtype, str) else str(qtype)
    if qtype_upper in {"TXT", "NULL"} and payload_len > 400:
        suspicious = True
        confidence += 0.3
        reasons.append(f"Large {qtype_upper} DNS payload: {payload_len} bytes")

    # Cap confidence
    confidence = min(confidence, 0.95)

    # Update metrics even for benign queries
    _update_stats(src_ip, domain_lower or "<empty>", suspicious)

    result: Dict[str, Any] = {
        "suspicious": suspicious,
        "confidence": confidence,
        "reasons": reasons,
        "threat_type": "DNS Exfiltration Suspected" if suspicious else "BENIGN_DNS",
    }

    if suspicious:
        logger.warning(
            f"[DNS] Suspicious DNS query from {src_ip}: {domain_lower} | "
            f"qtype={qtype_upper} | reasons={'; '.join(reasons)}"
        )

    return result


__all__ = ["analyze_dns_query"]
