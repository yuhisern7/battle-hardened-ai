#!/usr/bin/env python3
"""
Graph Intelligence Module - Network Topology Analysis
Pure Python implementation (no NetworkX dependency)

Capabilities:
- Network topology mapping (IP→IP communication graph)
- Lateral movement detection (hop chain analysis)
- Command & Control (C2) pattern detection
- Data exfiltration path tracing
- Network segmentation violation detection
- Centrality metrics (betweenness, degree)

Author: Enterprise Security AI Team
Version: 1.0.0 (Phase 4)
"""

import json
import os
import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Set, Tuple, Optional, Any
from collections import defaultdict, deque
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)

# Feature flag to allow operators to disable graph intelligence without code changes
GRAPH_INTELLIGENCE_ENABLED = os.getenv('GRAPH_INTELLIGENCE_ENABLED', 'true').lower() == 'true'


@dataclass
class Connection:
    """Represents a network connection between two nodes"""
    source: str
    destination: str
    port: int
    protocol: str
    timestamp: str
    packet_count: int = 1
    byte_count: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return asdict(self)


@dataclass
class LateralMovementAlert:
    """Alert for detected lateral movement"""
    alert_id: str
    source_ip: str
    hop_chain: List[str]
    hop_count: int
    time_window: float  # seconds
    ports_used: List[int]
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    timestamp: str
    confidence: float  # 0.0-1.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return asdict(self)


class NetworkGraph:
    """
    Pure Python network graph implementation
    Uses adjacency list for efficient storage and traversal
    """
    
    def __init__(self, graph_file: Optional[str] = None, alerts_file: Optional[str] = None):
        """
        Initialize network graph
        
        Args:
            graph_file: Path to save/load graph data
            alerts_file: Path to save lateral movement alerts
        """
        # Graph structure: adjacency list
        self.adjacency: Dict[str, Dict[str, List[Connection]]] = defaultdict(lambda: defaultdict(list))
        
        # Node metadata
        self.nodes: Set[str] = set()
        self.node_metadata: Dict[str, Dict[str, Any]] = {}
        
        # Network zones (for segmentation violation detection)
        self.zones: Dict[str, str] = {}  # IP → zone name
        self.zone_rules: Dict[Tuple[str, str], bool] = {}  # (zone1, zone2) → allowed
        
        # Tracking
        self.connection_count = 0
        self.last_cleanup = datetime.now(timezone.utc)
        self.alerts: List[LateralMovementAlert] = []
        
        # File paths for persistent JSON
        from AI.path_helper import get_json_dir, get_relay_training_dir  # type: ignore[import]

        json_base = get_json_dir()
        self.graph_file = graph_file or os.path.join(json_base, "network_graph.json")
        self.alerts_file = alerts_file or os.path.join(json_base, "lateral_movement_alerts.json")

        # Training materials path (resolved via relay/ai_training_materials helper)
        training_base = os.path.join(get_relay_training_dir(), "training_datasets")
        self.training_file = os.path.join(training_base, "graph_topology.json")
        
        # Create directories if they don't exist
        os.makedirs(os.path.dirname(self.graph_file), exist_ok=True)
        os.makedirs(os.path.dirname(self.alerts_file), exist_ok=True)
        os.makedirs(os.path.dirname(self.training_file), exist_ok=True)
        
        # Load existing data
        self._load_graph()
        self._load_alerts()
        
        logger.info("[GRAPH] Network graph intelligence initialized")
    
    def add_connection(self, source: str, destination: str, port: int, 
                      protocol: str = "TCP", byte_count: int = 0) -> None:
        """
        Add a connection to the graph
        
        Args:
            source: Source IP address
            destination: Destination IP address
            port: Destination port
            protocol: Protocol (TCP, UDP, etc.)
            byte_count: Number of bytes transferred
        """
        # Add nodes
        self.nodes.add(source)
        self.nodes.add(destination)
        
        # Create connection
        conn = Connection(
            source=source,
            destination=destination,
            port=port,
            protocol=protocol,
            timestamp=datetime.now(timezone.utc).isoformat(),
            byte_count=byte_count
        )
        
        # Add to adjacency list
        self.adjacency[source][destination].append(conn)
        
        # Initialize node metadata if needed
        if source not in self.node_metadata:
            self.node_metadata[source] = {
                "first_seen": datetime.now(timezone.utc).isoformat(),
                "connection_count": 0,
                "unique_destinations": set(),
                "unique_ports": set()
            }
        
        # Update metadata
        self.node_metadata[source]["connection_count"] += 1
        self.node_metadata[source]["unique_destinations"].add(destination)
        self.node_metadata[source]["unique_ports"].add(port)
        
        self.connection_count += 1
        
        # Periodic cleanup (remove old connections)
        if self.connection_count % 1000 == 0:
            self._cleanup_old_connections()
    
    def get_neighbors(self, node: str) -> Set[str]:
        """Get all neighbors (destinations) of a node"""
        if node not in self.adjacency:
            return set()
        return set(self.adjacency[node].keys())
    
    def get_degree(self, node: str) -> int:
        """Get degree (number of unique neighbors) of a node"""
        return len(self.get_neighbors(node))
    
    def get_in_degree(self, node: str) -> int:
        """Get in-degree (number of nodes pointing to this node)"""
        in_degree = 0
        for source in self.adjacency:
            if node in self.adjacency[source]:
                in_degree += 1
        return in_degree
    
    def detect_lateral_movement(self, time_window_minutes: int = 10, 
                                min_hops: int = 3) -> List[LateralMovementAlert]:
        """
        Detect lateral movement patterns (IP hopping)
        
        Args:
            time_window_minutes: Time window to analyze
            min_hops: Minimum number of hops to trigger alert
            
        Returns:
            List of lateral movement alerts
        """
        alerts = []
        cutoff_time = datetime.now(timezone.utc) - timedelta(minutes=time_window_minutes)
        
        # For each source node, find hop chains
        for source in self.nodes:
            hop_chains = self._find_hop_chains(source, cutoff_time, max_depth=10)
            
            for chain in hop_chains:
                if len(chain) >= min_hops:
                    # Calculate time window for this chain
                    chain_times = self._get_chain_timestamps(chain)
                    if chain_times:
                        time_span = (max(chain_times) - min(chain_times)).total_seconds()
                        
                        # Fast lateral movement = suspicious
                        if time_span < 600:  # 10 minutes
                            # Get ports used
                            ports_used = self._get_chain_ports(chain)
                            
                            # Calculate severity
                            severity = self._calculate_lateral_severity(len(chain), time_span, ports_used)
                            confidence = min(0.5 + (len(chain) - min_hops) * 0.1, 0.95)
                            
                            alert = LateralMovementAlert(
                                alert_id=f"LM-{source}-{datetime.now(timezone.utc).timestamp()}",
                                source_ip=source,
                                hop_chain=chain,
                                hop_count=len(chain),
                                time_window=time_span,
                                ports_used=ports_used,
                                severity=severity,
                                timestamp=datetime.now(timezone.utc).isoformat(),
                                confidence=confidence
                            )
                            
                            alerts.append(alert)
                            self.alerts.append(alert)
                            
                            logger.warning(f"[GRAPH] Lateral movement detected: {source} → {' → '.join(chain)} "
                                         f"({len(chain)} hops in {time_span:.1f}s)")
        
        return alerts
    
    def detect_c2_patterns(self, min_controlled_nodes: int = 5) -> List[Dict[str, Any]]:
        """
        Detect Command & Control (C2) patterns
        
        A node is suspicious if it controls many other nodes:
        - High out-degree (talks to many nodes)
        - Low in-degree (few talk to it)
        - Periodic beaconing patterns
        
        Args:
            min_controlled_nodes: Minimum nodes controlled to trigger alert
            
        Returns:
            List of C2 pattern alerts
        """
        c2_alerts = []
        
        for node in self.nodes:
            out_degree = self.get_degree(node)
            in_degree = self.get_in_degree(node)
            
            # C2 pattern: high out-degree, low in-degree
            if out_degree >= min_controlled_nodes and in_degree < 3:
                ratio = out_degree / max(in_degree, 1)
                
                # Check for beaconing (periodic connections)
                beaconing_score = self._detect_beaconing(node)
                
                confidence = min(0.5 + (ratio * 0.05) + (beaconing_score * 0.3), 0.95)
                
                c2_alert = {
                    "alert_type": "C2_PATTERN",
                    "node": node,
                    "controlled_nodes": out_degree,
                    "in_degree": in_degree,
                    "ratio": ratio,
                    "beaconing_score": beaconing_score,
                    "confidence": confidence,
                    "severity": "HIGH" if confidence > 0.7 else "MEDIUM",
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
                
                c2_alerts.append(c2_alert)
                
                logger.warning(f"[GRAPH] C2 pattern detected: {node} controls {out_degree} nodes "
                             f"(beaconing: {beaconing_score:.2f}, confidence: {confidence:.2f})")
        
        return c2_alerts
    
    def detect_exfiltration_paths(self, internal_subnets: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """
        Detect data exfiltration paths
        
        Looks for:
        - Internal → DMZ → External flows
        - Unusual routes (bypassing expected gateways)
        - High-volume transfers to external IPs
        
        Args:
            internal_subnets: List of internal subnet prefixes (e.g., ["192.168.", "10."])
            
        Returns:
            List of exfiltration path alerts
        """
        if internal_subnets is None:
            internal_subnets = ["192.168.", "10.", "172.16."]
        
        exfil_alerts = []
        
        # Classify nodes as internal/external
        internal_nodes = {n for n in self.nodes if any(n.startswith(subnet) for subnet in internal_subnets)}
        external_nodes = self.nodes - internal_nodes
        
        # Find paths from internal to external
        for internal in internal_nodes:
            for external in external_nodes:
                paths = self._find_paths(internal, external, max_length=5)
                
                for path in paths:
                    # Calculate data volume
                    volume = self._calculate_path_volume(path)
                    
                    # Suspicious if high volume or unusual route
                    if volume > 10_000_000 or len(path) > 2:  # >10MB or multi-hop
                        severity = "HIGH" if volume > 100_000_000 else "MEDIUM"  # >100MB
                        confidence = min(0.6 + (len(path) - 2) * 0.1, 0.9)
                        
                        exfil_alert = {
                            "alert_type": "EXFILTRATION_PATH",
                            "path": path,
                            "volume_bytes": volume,
                            "hops": len(path),
                            "severity": severity,
                            "confidence": confidence,
                            "timestamp": datetime.now(timezone.utc).isoformat()
                        }
                        
                        exfil_alerts.append(exfil_alert)
                        
                        logger.warning(f"[GRAPH] Exfiltration path: {' → '.join(path)} "
                                     f"({volume / 1_000_000:.1f} MB)")
        
        return exfil_alerts
    
    def calculate_betweenness_centrality(self, sample_size: int = 100) -> Dict[str, float]:
        """
        Calculate betweenness centrality (approximate for large graphs)
        
        Nodes with high betweenness are critical communication paths
        
        Args:
            sample_size: Number of node pairs to sample (for performance)
            
        Returns:
            Dictionary mapping node → centrality score
        """
        centrality = {node: 0.0 for node in self.nodes}
        
        if len(self.nodes) < 2:
            return centrality
        
        # Sample node pairs
        import random
        node_list = list(self.nodes)
        pairs = min(sample_size, len(node_list) * (len(node_list) - 1) // 2)
        
        for _ in range(pairs):
            source = random.choice(node_list)
            target = random.choice([n for n in node_list if n != source])
            
            # Find shortest paths
            paths = self._find_shortest_paths(source, target)
            
            if paths:
                # Each intermediate node gets credit
                for path in paths:
                    for node in path[1:-1]:  # Exclude source and target
                        centrality[node] += 1.0 / len(paths)
        
        # Normalize
        if pairs > 0:
            for node in centrality:
                centrality[node] /= pairs
        
        return centrality
    
    def detect_segmentation_violations(self) -> List[Dict[str, Any]]:
        """
        Detect network segmentation violations
        
        Example zones:
        - DMZ: Should not talk directly to internal DB
        - Guest: Should not access corporate network
        - IoT: Should be isolated
        
        Returns:
            List of segmentation violation alerts
        """
        violations = []
        
        for source in self.adjacency:
            source_zone = self.zones.get(source, "unknown")
            
            for dest in self.adjacency[source]:
                dest_zone = self.zones.get(dest, "unknown")
                
                # Check if communication is allowed
                if (source_zone, dest_zone) in self.zone_rules:
                    if not self.zone_rules[(source_zone, dest_zone)]:
                        violation = {
                            "alert_type": "SEGMENTATION_VIOLATION",
                            "source": source,
                            "destination": dest,
                            "source_zone": source_zone,
                            "dest_zone": dest_zone,
                            "severity": "HIGH",
                            "timestamp": datetime.now(timezone.utc).isoformat()
                        }
                        
                        violations.append(violation)
                        
                        logger.error(f"[GRAPH] Segmentation violation: {source_zone} → {dest_zone} "
                                   f"({source} → {dest})")
        
        return violations
    
    def set_zone(self, ip: str, zone: str) -> None:
        """Assign an IP to a network zone"""
        self.zones[ip] = zone
    
    def set_zone_rule(self, source_zone: str, dest_zone: str, allowed: bool) -> None:
        """Define if communication between zones is allowed"""
        self.zone_rules[(source_zone, dest_zone)] = allowed
    
    def get_graph_stats(self) -> Dict[str, Any]:
        """Get graph statistics"""
        node_count = len(self.nodes)
        connection_count = self.connection_count
        stats = {
            "node_count": node_count,
            "connection_count": connection_count,
            "average_degree": sum(self.get_degree(n) for n in self.nodes) / max(node_count, 1),
            "max_degree": max((self.get_degree(n) for n in self.nodes), default=0),
            "alert_count": len(self.alerts),
            "zones_configured": len(set(self.zones.values())),
            "last_update": datetime.now(timezone.utc).isoformat(),
            # Backwards-compatible aliases used by get_attack_chains
            "total_nodes": node_count,
            "total_edges": connection_count,
        }
        return stats
    
    def save_graph(self) -> None:
        """Save graph to disk"""
        try:
            # Convert to serializable format
            graph_data = {
                "metadata": {
                    "node_count": len(self.nodes),
                    "connection_count": self.connection_count,
                    "timestamp": datetime.now(timezone.utc).isoformat()
                },
                "nodes": list(self.nodes),
                "adjacency": {
                    source: {
                        dest: [conn.to_dict() for conn in conns[-10:]]  # Keep last 10 connections
                        for dest, conns in dests.items()
                    }
                    for source, dests in self.adjacency.items()
                },
                "zones": self.zones
            }
            
            # Save to the JSON directory managed by AI.path_helper
            with open(self.graph_file, 'w') as f:
                json.dump(graph_data, f, indent=2)
            
            # Save training data to ai_training_materials/
            training_data = {
                "graph_stats": self.get_graph_stats(),
                "centrality_scores": self.calculate_betweenness_centrality(sample_size=50),
                "lateral_movement_patterns": [alert.to_dict() for alert in self.alerts[-100:]],
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            
            with open(self.training_file, 'w') as f:
                json.dump(training_data, f, indent=2)
            
            logger.info(f"[GRAPH] Saved graph: {len(self.nodes)} nodes, {self.connection_count} connections")
            
        except Exception as e:
            logger.error(f"[GRAPH] Failed to save graph: {e}")
    
    def save_alerts(self) -> None:
        """Save lateral movement alerts"""
        try:
            alerts_data = {
                "alerts": [alert.to_dict() for alert in self.alerts[-1000:]],  # Last 1000 alerts
                "total_count": len(self.alerts),
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            
            with open(self.alerts_file, 'w') as f:
                json.dump(alerts_data, f, indent=2)
            
        except Exception as e:
            logger.error(f"[GRAPH] Failed to save alerts: {e}")
    
    def _load_graph(self) -> None:
        """Load graph from disk"""
        try:
            if os.path.exists(self.graph_file):
                with open(self.graph_file, 'r') as f:
                    data = json.load(f)
                
                self.nodes = set(data.get("nodes", []))
                self.zones = data.get("zones", {})
                
                logger.info(f"[GRAPH] Loaded graph: {len(self.nodes)} nodes")
        except Exception as e:
            logger.warning(f"[GRAPH] Could not load graph: {e}")
    
    def _load_alerts(self) -> None:
        """Load alerts from disk"""
        try:
            if os.path.exists(self.alerts_file):
                with open(self.alerts_file, 'r') as f:
                    data = json.load(f)
                
                # Support both legacy list format and newer dict format
                if isinstance(data, list):
                    alert_list = data
                elif isinstance(data, dict):
                    alert_list = data.get("alerts", [])
                else:
                    alert_list = []

                # Convert to LateralMovementAlert objects
                for alert_dict in alert_list:
                    alert = LateralMovementAlert(**alert_dict)
                    self.alerts.append(alert)
                
                logger.info(f"[GRAPH] Loaded {len(self.alerts)} alerts")
        except Exception as e:
            logger.warning(f"[GRAPH] Could not load alerts: {e}")
    
    def _cleanup_old_connections(self, max_age_hours: int = 24) -> None:
        """Remove connections older than max_age_hours"""
        cutoff = datetime.now(timezone.utc) - timedelta(hours=max_age_hours)
        removed = 0
        
        for source in list(self.adjacency.keys()):
            for dest in list(self.adjacency[source].keys()):
                # Filter old connections
                self.adjacency[source][dest] = [
                    conn for conn in self.adjacency[source][dest]
                    if datetime.fromisoformat(conn.timestamp) > cutoff
                ]
                
                # Remove empty entries
                if not self.adjacency[source][dest]:
                    del self.adjacency[source][dest]
                    removed += 1
            
            if not self.adjacency[source]:
                del self.adjacency[source]
        
        self.last_cleanup = datetime.now(timezone.utc)
        
        if removed > 0:
            logger.info(f"[GRAPH] Cleaned up {removed} old connections")
    
    def _find_hop_chains(self, source: str, cutoff_time: datetime, max_depth: int = 10) -> List[List[str]]:
        """Find all hop chains starting from source (DFS)"""
        chains = []
        
        def dfs(node: str, path: List[str], depth: int):
            if depth >= max_depth:
                return
            
            if node in self.adjacency:
                for dest in self.adjacency[node]:
                    # Check if connection is recent
                    recent_conns = [
                        conn for conn in self.adjacency[node][dest]
                        if datetime.fromisoformat(conn.timestamp) > cutoff_time
                    ]
                    
                    if recent_conns and dest not in path:  # Avoid cycles
                        new_path = path + [dest]
                        chains.append(new_path)
                        dfs(dest, new_path, depth + 1)
        
        dfs(source, [source], 0)
        return chains
    
    def _find_paths(self, source: str, target: str, max_length: int = 5) -> List[List[str]]:
        """Find all paths from source to target (BFS)"""
        if source == target:
            return [[source]]
        
        paths = []
        queue = deque([([source], set([source]))])
        
        while queue:
            path, visited = queue.popleft()
            
            if len(path) > max_length:
                continue
            
            current = path[-1]
            
            if current in self.adjacency:
                for neighbor in self.adjacency[current]:
                    if neighbor == target:
                        paths.append(path + [neighbor])
                    elif neighbor not in visited:
                        queue.append((path + [neighbor], visited | {neighbor}))
        
        return paths
    
    def _find_shortest_paths(self, source: str, target: str) -> List[List[str]]:
        """Find all shortest paths from source to target (BFS)"""
        if source == target:
            return [[source]]
        
        # BFS to find shortest distance
        queue = deque([(source, [source])])
        visited = {source}
        shortest_len = None
        paths = []
        
        while queue:
            node, path = queue.popleft()
            
            # If we've found paths and current is longer, stop
            if shortest_len and len(path) > shortest_len:
                break
            
            if node in self.adjacency:
                for neighbor in self.adjacency[node]:
                    if neighbor == target:
                        new_path = path + [neighbor]
                        if shortest_len is None:
                            shortest_len = len(new_path)
                        if len(new_path) == shortest_len:
                            paths.append(new_path)
                    elif neighbor not in visited:
                        visited.add(neighbor)
                        queue.append((neighbor, path + [neighbor]))
        
        return paths
    
    def _get_chain_timestamps(self, chain: List[str]) -> List[datetime]:
        """Get timestamps for connections in a chain"""
        timestamps = []
        
        for i in range(len(chain) - 1):
            source = chain[i]
            dest = chain[i + 1]
            
            if source in self.adjacency and dest in self.adjacency[source]:
                for conn in self.adjacency[source][dest]:
                    timestamps.append(datetime.fromisoformat(conn.timestamp))
        
        return timestamps
    
    def _get_chain_ports(self, chain: List[str]) -> List[int]:
        """Get ports used in a chain"""
        ports = set()
        
        for i in range(len(chain) - 1):
            source = chain[i]
            dest = chain[i + 1]
            
            if source in self.adjacency and dest in self.adjacency[source]:
                for conn in self.adjacency[source][dest]:
                    ports.add(conn.port)
        
        return sorted(list(ports))
    
    def _calculate_lateral_severity(self, hop_count: int, time_window: float, ports: List[int]) -> str:
        """Calculate severity of lateral movement"""
        score = 0
        
        # More hops = more severe
        if hop_count >= 7:
            score += 3
        elif hop_count >= 5:
            score += 2
        elif hop_count >= 3:
            score += 1
        
        # Faster movement = more severe
        if time_window < 120:  # 2 minutes
            score += 3
        elif time_window < 300:  # 5 minutes
            score += 2
        elif time_window < 600:  # 10 minutes
            score += 1
        
        # Multiple ports = reconnaissance
        if len(ports) >= 10:
            score += 2
        elif len(ports) >= 5:
            score += 1
        
        if score >= 6:
            return "CRITICAL"
        elif score >= 4:
            return "HIGH"
        elif score >= 2:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _detect_beaconing(self, node: str) -> float:
        """
        Detect periodic beaconing patterns
        
        Returns:
            Score 0.0-1.0 indicating beaconing confidence
        """
        if node not in self.adjacency:
            return 0.0
        
        # Collect all connection timestamps
        all_timestamps = []
        for dest in self.adjacency[node]:
            for conn in self.adjacency[node][dest]:
                all_timestamps.append(datetime.fromisoformat(conn.timestamp))
        
        if len(all_timestamps) < 5:
            return 0.0
        
        # Sort timestamps
        all_timestamps.sort()
        
        # Calculate time deltas
        deltas = [(all_timestamps[i+1] - all_timestamps[i]).total_seconds() 
                 for i in range(len(all_timestamps) - 1)]
        
        if not deltas:
            return 0.0
        
        # Check for periodicity (low variance = beaconing)
        mean_delta = sum(deltas) / len(deltas)
        variance = sum((d - mean_delta) ** 2 for d in deltas) / len(deltas)
        std_dev = variance ** 0.5
        
        # Coefficient of variation
        if mean_delta > 0:
            cv = std_dev / mean_delta
            # Low CV = periodic, high CV = random
            beaconing_score = max(0.0, 1.0 - cv)
            return min(beaconing_score, 1.0)
        
        return 0.0
    
    def _calculate_path_volume(self, path: List[str]) -> int:
        """Calculate total bytes transferred along a path"""
        total_bytes = 0
        
        for i in range(len(path) - 1):
            source = path[i]
            dest = path[i + 1]
            
            if source in self.adjacency and dest in self.adjacency[source]:
                for conn in self.adjacency[source][dest]:
                    total_bytes += conn.byte_count
        
        return total_bytes


class _DisabledGraph:
    """No-op graph implementation used when graph intelligence is disabled"""

    def __init__(self):
        self.alerts: List[LateralMovementAlert] = []

    # Interface-compatible no-op methods
    def add_connection(self, *_, **__):
        return None

    def detect_lateral_movement(self, *_, **__):
        return []

    def detect_c2_patterns(self, *_, **__):
        return []

    def save_graph(self, *_, **__):
        return None

    def save_alerts(self, *_, **__):
        return None

    def get_graph_stats(self) -> Dict[str, Any]:
        return {
            "node_count": 0,
            "connection_count": 0,
            "average_degree": 0.0,
            "max_degree": 0,
            "alert_count": 0,
            "zones_configured": 0,
            "last_update": datetime.now(timezone.utc).isoformat(),
            "total_nodes": 0,
            "total_edges": 0,
        }


# Singleton instance
_graph_instance: Optional[NetworkGraph] = None
_disabled_graph_instance: Optional[_DisabledGraph] = None


def get_graph_intelligence() -> NetworkGraph:
    """Get singleton graph intelligence instance (or no-op when disabled)"""
    global _graph_instance, _disabled_graph_instance
    if not GRAPH_INTELLIGENCE_ENABLED:
        if _disabled_graph_instance is None:
            _disabled_graph_instance = _DisabledGraph()
        return _disabled_graph_instance  # type: ignore[return-value]
    if _graph_instance is None:
        _graph_instance = NetworkGraph()
    return _graph_instance


# Convenience functions
def track_connection(source: str, dest: str, port: int, protocol: str = "TCP", bytes: int = 0) -> None:
    """Track a network connection"""
    graph = get_graph_intelligence()
    graph.add_connection(source, dest, port, protocol, bytes)


def analyze_lateral_movement() -> List[LateralMovementAlert]:
    """Analyze network for lateral movement"""
    graph = get_graph_intelligence()
    return graph.detect_lateral_movement()


def analyze_c2_patterns() -> List[Dict[str, Any]]:
    """Analyze network for C2 patterns"""
    graph = get_graph_intelligence()
    return graph.detect_c2_patterns()


def save_graph_data() -> None:
    """Save graph and alerts to disk"""
    graph = get_graph_intelligence()
    graph.save_graph()
    graph.save_alerts()


def get_attack_chains() -> Dict[str, Any]:
    """
    Get attack chains for dashboard visualization.
    
    Returns:
        Dict containing attack chain data with nodes, edges, and statistics
    """
    graph = get_graph_intelligence()
    
    # Get lateral movement alerts (these are our attack chains)
    alerts = graph.alerts
    
    # Build attack chain data
    attack_chains = []
    for alert in alerts[-10:]:  # Last 10 chains
        chain = {
            "chain_id": alert.alert_id,
            "attack_path": alert.hop_chain,
            "stages": alert.hop_count,
            "severity": alert.severity,
            "first_seen": alert.timestamp,
            "last_seen": alert.timestamp,
            "compromised_hosts": alert.hop_count,
            "lateral_movement": True if alert.hop_count > 2 else False,
            "lateral_targets": alert.hop_chain[1:] if len(alert.hop_chain) > 1 else []
        }
        attack_chains.append(chain)
    
    # Get graph stats
    stats = graph.get_graph_stats()
    
    # Build graph data for visualization
    graph_data = {
        "nodes": [],
        "edges": []
    }
    
    # Add nodes from recent alert chains
    node_set = set()
    for alert in alerts[-10:]:
        for ip in alert.hop_chain:
            if ip not in node_set:
                node_set.add(ip)
                graph_data["nodes"].append({
                    "id": ip,
                    "label": ip,
                    "color": "#ff5f5f" if ip == alert.source_ip else "#5fe2ff"
                })
    
    # Add edges
    for alert in alerts[-10:]:
        for i in range(len(alert.hop_chain) - 1):
            graph_data["edges"].append({
                "from": alert.hop_chain[i],
                "to": alert.hop_chain[i + 1],
                "color": "#ff5f5f"
            })
    
    return {
        "attack_chains": attack_chains,
        "total_chains": len(alerts),
        "lateral_movement_count": sum(1 for a in alerts if a.hop_count > 2),
        "total_nodes": stats.get("total_nodes", 0),
        "total_edges": stats.get("total_edges", 0),
        "graph_data": graph_data if graph_data["nodes"] else None
    }


if __name__ == "__main__":
    # Demo
    print("🕸️  Graph Intelligence Module - Demo")
    print("=" * 60)
    
    graph = NetworkGraph()
    
    # Simulate lateral movement attack
    print("\n[1] Simulating lateral movement attack...")
    attacker = "203.0.113.50"
    targets = ["192.168.1.10", "192.168.1.11", "192.168.1.12", "192.168.1.13", "192.168.1.14"]
    
    import time
    for i, target in enumerate(targets):
        if i > 0:
            graph.add_connection(targets[i-1], target, 22, "TCP", 1024)
        else:
            graph.add_connection(attacker, target, 22, "TCP", 1024)
        time.sleep(0.1)
    
    alerts = graph.detect_lateral_movement(time_window_minutes=1, min_hops=3)
    print(f"   Detected {len(alerts)} lateral movement alerts")
    
    # Simulate C2 pattern
    print("\n[2] Simulating C2 botnet pattern...")
    c2_server = "198.51.100.10"
    for i in range(15):
        bot = f"192.168.2.{i+1}"
        graph.add_connection(c2_server, bot, 443, "TCP", 512)
    
    c2_alerts = graph.detect_c2_patterns(min_controlled_nodes=10)
    print(f"   Detected {len(c2_alerts)} C2 patterns")
    
    # Graph stats
    print("\n[3] Graph Statistics:")
    stats = graph.get_graph_stats()
    for key, value in stats.items():
        print(f"   {key}: {value}")
    
    # Save
    print("\n[4] Saving graph data...")
    graph.save_graph()
    graph.save_alerts()
    print("   ✅ Graph data saved")
    
    print("\n✅ Demo complete!")
