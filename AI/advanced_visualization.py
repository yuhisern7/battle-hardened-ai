"""Advanced Visualization - Network Topology, Attack Flows, Heatmaps

Auto-generates visual data for professional security dashboards:
- Network topology map (auto-discover devices)
- Attack flow diagrams (source → victim visualization)
- Real-time threat heatmap
- Geographic attack origin maps
- Attack pattern timelines

All data generated automatically by AI for visualization in dashboards.
"""

import json
import os
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple, Any
from collections import defaultdict
from AI.path_helper import get_json_file


# Persistent storage
_VISUALIZATION_DATA_FILE = get_json_file('visualization_data.json')


def _get_current_time():
    """Get current datetime in configured timezone"""
    try:
        # Using timezone.utc instead of pytz for standard library compatibility
        return datetime.now(timezone.utc)
    except Exception:
        return datetime.now(timezone.utc)


def _load_threat_log() -> List[dict]:
    """Load threat log for visualization (includes ALL rotation files)."""
    try:
        threat_log_file = get_json_file('threat_log.json')
        
        # Load ALL rotation files (threat_log.json, threat_log_1.json, threat_log_2.json, etc.)
        # This ensures visualizations show complete historical attack patterns
        try:
            from file_rotation import load_all_rotations
            return load_all_rotations(threat_log_file)
        except ImportError:
            # Fallback: load only current file if file_rotation module not available
            if os.path.exists(threat_log_file):
                with open(threat_log_file, 'r') as f:
                    data = json.load(f)
                    # Ensure data is a list, not a string or other type
                    if isinstance(data, list):
                        return data
                    elif isinstance(data, dict):
                        # If it's a dict with 'threats' or 'logs' key, extract the list
                        return data.get('threats', data.get('logs', []))
                    else:
                        print(f"[VISUALIZATION] Unexpected threat log format: {type(data)}")
                        return []
    except json.JSONDecodeError as e:
        print(f"[VISUALIZATION] Failed to parse threat log JSON: {e}")
        return []
    except Exception as e:
        print(f"[VISUALIZATION] Failed to load threat log: {e}")
    
    return []


def _load_connected_devices() -> List[dict]:
    """Load connected devices for topology map."""
    try:
        devices_file = get_json_file('connected_devices.json')
        
        if os.path.exists(devices_file):
            with open(devices_file, 'r') as f:
                data = json.load(f)
                # Ensure data is a list
                if isinstance(data, list):
                    return data
                elif isinstance(data, dict):
                    # If it's a dict with 'devices' key
                    devices_data = data.get('devices', [])
                    
                    # Handle both list and dict formats
                    if isinstance(devices_data, list):
                        return devices_data
                    elif isinstance(devices_data, dict):
                        # Convert dict of dicts to list of dicts
                        devices_list = []
                        for mac, device_info in devices_data.items():
                            if isinstance(device_info, dict):
                                # Normalize the device info
                                normalized = {
                                    'ip_address': device_info.get('ip', ''),
                                    'hostname': device_info.get('hostname', 'Unknown'),
                                    'mac_address': device_info.get('mac', mac),
                                    'device_type': device_info.get('type', 'unknown'),
                                    'status': device_info.get('status', 'active'),
                                    'open_ports': device_info.get('open_ports', []),
                                    'first_seen': device_info.get('first_seen', ''),
                                    'last_seen': device_info.get('last_seen', '')
                                }
                                devices_list.append(normalized)
                        return devices_list
                    else:
                        print(f"[VISUALIZATION] Unexpected devices.devices format: {type(devices_data)}")
                        return []
                else:
                    print(f"[VISUALIZATION] Unexpected devices format: {type(data)}")
                    return []
    except json.JSONDecodeError as e:
        print(f"[VISUALIZATION] Failed to parse devices JSON: {e}")
        return []
    except Exception as e:
        print(f"[VISUALIZATION] Failed to load devices: {e}")
    
    return []


def generate_network_topology() -> dict:
    """Generate network topology map with auto-discovered devices.
    
    Returns:
        Network topology in graph format (nodes + edges)
    """
    devices = _load_connected_devices()
    threats = _load_threat_log()
    
    # Create nodes (devices)
    nodes = []
    
    # Add server/gateway as central node
    nodes.append({
        'id': 'gateway',
        'label': 'Security Gateway',
        'type': 'gateway',
        'ip': 'PROTECTED',
        'status': 'active',
        'threat_level': 'safe',
        'size': 50,
        'color': '#5fff9f'
    })
    
    # Add connected devices
    device_threat_count = defaultdict(int)
    for threat in threats[-1000:]:  # Last 1000 threats
        if isinstance(threat, dict):
            ip = threat.get('ip_address', '')
            if ip:
                device_threat_count[ip] += 1
    
    for device in devices:
        if not isinstance(device, dict):
            continue
        ip = device.get('ip_address', '')
        if not ip:
            continue
        threat_count = device_threat_count.get(ip, 0)
        
        # Determine threat level by count
        if threat_count == 0:
            threat_level = 'safe'
            color = '#5fff9f'
        elif threat_count < 5:
            threat_level = 'low'
            color = '#5fe2ff'
        elif threat_count < 20:
            threat_level = 'medium'
            color = '#ffb85f'
        else:
            threat_level = 'high'
            color = '#ff5f5f'
        
        nodes.append({
            'id': ip,
            'label': device.get('hostname', ip),
            'type': device.get('device_type', 'unknown'),
            'ip': ip,
            'mac': device.get('mac_address', ''),
            'status': device.get('status', 'active'),
            'threat_level': threat_level,
            'threat_count': threat_count,
            'size': 30,
            'color': color
        })
    
    # Create edges (connections)
    edges = []
    
    # Connect all devices to gateway
    for device in devices:
        ip = device.get('ip_address', '')
        threat_count = device_threat_count.get(ip, 0)
        
        # Edge color based on threat level
        if threat_count == 0:
            edge_color = '#5fff9f'
            edge_width = 1
        elif threat_count < 10:
            edge_color = '#ffb85f'
            edge_width = 2
        else:
            edge_color = '#ff5f5f'
            edge_width = 3
        
        edges.append({
            'from': 'gateway',
            'to': ip,
            'threat_count': threat_count,
            'color': edge_color,
            'width': edge_width
        })
    
    # Add external attackers as separate nodes
    external_ips = set()
    for threat in threats[-100:]:  # Recent attackers
        ip = threat.get('ip_address', '')
        # Only external IPs (not in our devices list)
        if not any(d.get('ip_address') == ip for d in devices):
            external_ips.add(ip)
    
    for attacker_ip in list(external_ips)[:20]:  # Limit to 20 attackers
        threat_count = device_threat_count[attacker_ip]
        
        nodes.append({
            'id': attacker_ip,
            'label': f'ATTACKER\\n{attacker_ip}',
            'type': 'attacker',
            'ip': attacker_ip,
            'status': 'hostile',
            'threat_level': 'critical',
            'threat_count': threat_count,
            'size': 25,
            'color': '#ff0000'
        })
        
        # Edge from attacker to gateway
        edges.append({
            'from': attacker_ip,
            'to': 'gateway',
            'threat_count': threat_count,
            'color': '#ff0000',
            'width': 3,
            'dashed': True
        })
    
    topology = {
        'generated_at': _get_current_time().isoformat(),
        'nodes': nodes,
        'edges': edges,
        'statistics': {
            'total_devices': len(devices),
            'active_devices': sum(1 for d in devices if d.get('status') == 'active'),
            'external_attackers': len(external_ips),
            'total_connections': len(edges)
        }
    }
    
    return topology


def generate_attack_flows(time_range_minutes: int = 60) -> dict:
    """Generate attack flow diagram showing source → target paths.
    
    Args:
        time_range_minutes: Time range for attack flows (default 60 minutes)
    
    Returns:
        Attack flow visualization data
    """
    threats = _load_threat_log()
    cutoff = _get_current_time() - timedelta(minutes=time_range_minutes)
    
    # Filter recent threats
    recent_threats = []
    for threat in threats:
        try:
            threat_time = datetime.fromisoformat(threat.get('timestamp', '').replace('Z', '+00:00'))
            if threat_time >= cutoff:
                recent_threats.append(threat)
        except:
            continue
    
    # Group attacks by source IP and type
    attack_flows: Dict[str, Any] = defaultdict(lambda: {
        'count': 0,
        'threat_types': set(),
        'severity': 'SAFE',
        'actions': defaultdict(int),
        'geolocation': {},
        'first_seen': None,
        'last_seen': None
    })
    
    for threat in recent_threats:
        ip = threat.get('ip_address', 'unknown')
        flow = attack_flows[ip]
        
        flow['count'] += 1
        flow['threat_types'].add(threat.get('threat_type', 'Unknown'))
        flow['actions'][threat.get('action', 'monitored')] += 1
        
        # Update severity (take highest)
        current_level = threat.get('level', 'SAFE')
        severity_rank = {'SAFE': 0, 'SUSPICIOUS': 1, 'DANGEROUS': 2, 'CRITICAL': 3}
        if severity_rank.get(current_level, 0) > severity_rank.get(flow['severity'], 0):
            flow['severity'] = current_level
        
        # Store geolocation
        if not flow['geolocation'] and threat.get('geolocation'):
            flow['geolocation'] = threat['geolocation']
        
        # Track time range
        threat_time = threat.get('timestamp', '')
        if not flow['first_seen']:
            flow['first_seen'] = threat_time
        flow['last_seen'] = threat_time
    
    # Convert to list format for visualization
    flows = []
    for ip, data in attack_flows.items():
        flows.append({
            'source_ip': ip,
            'source_country': data['geolocation'].get('country', 'Unknown'),
            'source_city': data['geolocation'].get('city', 'Unknown'),
            'target': 'Your Network',
            'attack_count': data['count'],
            'threat_types': list(data['threat_types']),
            'severity': data['severity'],
            'blocked': data['actions'].get('blocked', 0),
            'dropped': data['actions'].get('dropped', 0),
            'monitored': data['actions'].get('monitored', 0),
            'first_seen': data['first_seen'],
            'last_seen': data['last_seen']
        })
    
    # Sort by attack count
    flows.sort(key=lambda x: x['attack_count'], reverse=True)
    
    return {
        'generated_at': _get_current_time().isoformat(),
        'time_range_minutes': time_range_minutes,
        'total_attack_flows': len(flows),
        'total_attacks': sum(f['attack_count'] for f in flows),
        'flows': flows[:50]  # Top 50 attack flows
    }


def generate_threat_heatmap(hours: int = 24) -> dict:
    """Generate real-time threat heatmap (intensity by time and type).
    
    Args:
        hours: Number of hours to analyze (default 24)
    
    Returns:
        Heatmap data structure
    """
    threats = _load_threat_log()
    cutoff = _get_current_time() - timedelta(hours=hours)
    
    # Filter threats in time range
    recent_threats = []
    for threat in threats:
        try:
            threat_time = datetime.fromisoformat(threat.get('timestamp', '').replace('Z', '+00:00'))
            if threat_time >= cutoff:
                recent_threats.append(threat)
        except:
            continue
    
    # Create time buckets (1-hour intervals)
    time_buckets = []
    for i in range(hours):
        bucket_time = cutoff + timedelta(hours=i)
        time_buckets.append({
            'time': bucket_time.strftime('%Y-%m-%d %H:00'),
            'timestamp': bucket_time.isoformat(),
            'threats': defaultdict(int)
        })
    
    # Fill buckets with threat data
    for threat in recent_threats:
        try:
            threat_time = datetime.fromisoformat(threat.get('timestamp', '').replace('Z', '+00:00'))
            hours_diff = int((threat_time - cutoff).total_seconds() / 3600)
            
            if 0 <= hours_diff < hours:
                threat_type = threat.get('threat_type', 'Unknown')
                time_buckets[hours_diff]['threats'][threat_type] += 1
        except:
            continue
    
    # Get all unique threat types
    all_threat_types = set()
    for bucket in time_buckets:
        all_threat_types.update(bucket['threats'].keys())
    
    # Convert to heatmap matrix format
    threat_types = sorted(list(all_threat_types))
    
    heatmap_matrix = []
    for threat_type in threat_types:
        row = {
            'threat_type': threat_type,
            'data': []
        }
        
        for bucket in time_buckets:
            count = bucket['threats'].get(threat_type, 0)
            row['data'].append({
                'time': bucket['time'],
                'count': count
            })
        
        heatmap_matrix.append(row)
    
    # Calculate intensity levels for color coding
    max_count = max(
        (bucket['threats'].get(tt, 0) for bucket in time_buckets for tt in threat_types),
        default=1
    )
    
    return {
        'generated_at': _get_current_time().isoformat(),
        'time_range_hours': hours,
        'threat_types': threat_types,
        'time_labels': [b['time'] for b in time_buckets],
        'heatmap_matrix': heatmap_matrix,
        'max_intensity': max_count,
        'total_threats': len(recent_threats)
    }


def generate_geographic_map() -> dict:
    """Generate geographic attack origin map.
    
    Returns:
        Geographic data with country-level attack statistics
    """
    threats = _load_threat_log()
    
    # Last 7 days for geographic analysis
    cutoff = _get_current_time() - timedelta(days=7)
    recent_threats = []
    
    for threat in threats:
        try:
            threat_time = datetime.fromisoformat(threat.get('timestamp', '').replace('Z', '+00:00'))
            if threat_time >= cutoff:
                recent_threats.append(threat)
        except:
            continue
    
    # Group by country
    country_stats: Dict[str, Any] = defaultdict(lambda: {
        'attack_count': 0,
        'threat_types': set(),
        'severity_counts': defaultdict(int),
        'blocked': 0,
        'cities': set(),
        'ips': set()
    })
    
    for threat in recent_threats:
        geo = threat.get('geolocation', {})
        country = geo.get('country', 'Unknown')
        
        stats = country_stats[country]
        stats['attack_count'] += 1
        stats['threat_types'].add(threat.get('threat_type', 'Unknown'))
        stats['severity_counts'][threat.get('level', 'SAFE')] += 1
        
        if threat.get('action') in ['blocked', 'dropped']:
            stats['blocked'] += 1
        
        if geo.get('city'):
            stats['cities'].add(geo['city'])
        
        stats['ips'].add(threat.get('ip_address', ''))
    
    # Convert to list format
    geographic_data = []
    for country, stats in country_stats.items():
        geographic_data.append({
            'country': country,
            'attack_count': stats['attack_count'],
            'unique_ips': len(stats['ips']),
            'unique_cities': len(stats['cities']),
            'threat_types': list(stats['threat_types']),
            'critical_attacks': stats['severity_counts']['CRITICAL'],
            'dangerous_attacks': stats['severity_counts']['DANGEROUS'],
            'blocked_attacks': stats['blocked'],
            'threat_density': stats['attack_count'] / len(stats['ips']) if stats['ips'] else 0
        })
    
    # Sort by attack count
    geographic_data.sort(key=lambda x: x['attack_count'], reverse=True)
    
    return {
        'generated_at': _get_current_time().isoformat(),
        'time_range_days': 7,
        'total_countries': len(geographic_data),
        'total_attacks': sum(c['attack_count'] for c in geographic_data),
        'top_attacking_countries': geographic_data[:20],
        'country_data': geographic_data
    }


def generate_attack_timeline(hours: int = 24) -> dict:
    """Generate attack pattern timeline (attacks over time).
    
    Args:
        hours: Time range in hours (default 24)
    
    Returns:
        Timeline data with attack counts and types
    """
    threats = _load_threat_log()
    cutoff = _get_current_time() - timedelta(hours=hours)
    
    # Filter recent threats
    recent_threats = []
    for threat in threats:
        try:
            threat_time = datetime.fromisoformat(threat.get('timestamp', '').replace('Z', '+00:00'))
            if threat_time >= cutoff:
                recent_threats.append(threat)
        except:
            continue
    
    # Create 15-minute buckets for detailed timeline
    bucket_minutes = 15
    num_buckets = int(hours * 60 / bucket_minutes)
    
    timeline = []
    for i in range(num_buckets):
        bucket_start = cutoff + timedelta(minutes=i * bucket_minutes)
        bucket_end = bucket_start + timedelta(minutes=bucket_minutes)
        
        # Count threats in this bucket
        bucket_threats = [
            t for t in recent_threats
            if bucket_start <= datetime.fromisoformat(t.get('timestamp', '').replace('Z', '+00:00')) < bucket_end
        ]
        
        # Categorize by severity
        critical = sum(1 for t in bucket_threats if t.get('level') == 'CRITICAL')
        dangerous = sum(1 for t in bucket_threats if t.get('level') == 'DANGEROUS')
        suspicious = sum(1 for t in bucket_threats if t.get('level') == 'SUSPICIOUS')
        safe = sum(1 for t in bucket_threats if t.get('level') == 'SAFE')
        
        timeline.append({
            'time': bucket_start.strftime('%H:%M'),
            'timestamp': bucket_start.isoformat(),
            'total': len(bucket_threats),
            'critical': critical,
            'dangerous': dangerous,
            'suspicious': suspicious,
            'safe': safe
        })
    
    return {
        'generated_at': _get_current_time().isoformat(),
        'time_range_hours': hours,
        'bucket_size_minutes': bucket_minutes,
        'timeline': timeline,
        'peak_attacks': max((t['total'] for t in timeline), default=0),
        'total_attacks': sum(t['total'] for t in timeline)
    }


def generate_all_visualizations() -> dict:
    """Generate all visualization data at once.
    
    Returns:
        Dictionary with all visualization data
    """
    print("[VISUALIZATION] Generating all visualizations...")
    
    visualizations = {
        'network_topology': generate_network_topology(),
        'attack_flows': generate_attack_flows(),
        'threat_heatmap': generate_threat_heatmap(),
        'geographic_map': generate_geographic_map(),
        'attack_timeline': generate_attack_timeline()
    }
    
    # Save to disk
    save_visualization_data(visualizations)
    
    print("[VISUALIZATION] All visualizations generated successfully")
    
    return visualizations


def save_visualization_data(data: dict) -> None:
    """Save visualization data to disk."""
    try:
        os.makedirs(os.path.dirname(_VISUALIZATION_DATA_FILE), exist_ok=True)
        
        with open(_VISUALIZATION_DATA_FILE, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"[VISUALIZATION] Data saved: {_VISUALIZATION_DATA_FILE}")
    
    except Exception as e:
        print(f"[VISUALIZATION] Failed to save data: {e}")


def load_visualization_data() -> dict:
    """Load cached visualization data from disk."""
    try:
        if os.path.exists(_VISUALIZATION_DATA_FILE):
            with open(_VISUALIZATION_DATA_FILE, 'r') as f:
                return json.load(f)
    except Exception as e:
        print(f"[VISUALIZATION] Failed to load data: {e}")
    
    # Return empty structure if file doesn't exist
    return {}
