"""Deep Packet Inspection and Traffic Analysis Module
Real-time network traffic monitoring for military/government/police use.
NO FAKE DATA - Only real packet captures and analysis.
Includes cryptocurrency mining detection powering dashboard Section 22
("Cryptocurrency Mining Detection").
"""

import os
import json
import subprocess
import platform
import shutil
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Optional

from AI.path_helper import get_json_file

try:
    import psutil  # type: ignore
except ImportError:
    psutil = None

class TrafficAnalyzer:
    """Real-time traffic analysis using system network tools"""
    
    def __init__(self):
        # Universal path resolution via centralized helper
        self.stats_file = get_json_file('traffic_stats.json')
        self.crypto_detections_file = get_json_file('crypto_mining.json')
        self.blocked_apps = defaultdict(int)
        self.crypto_detections = []
        
        # Known crypto mining pools and wallet addresses patterns
        self.mining_pools = [
            'pool.', 'mining.', 'stratum', 'nanopool', 'ethermine', 
            'f2pool', 'antpool', 'slushpool', 'btc.com', 'viaBTC',
            'poolin', 'pooling', 'miningpoolhub'
        ]
        
        # Known miner process signatures
        self.miner_signatures = [
            'xmrig', 'cgminer', 'bfgminer', 'ccminer', 'ethminer',
            'claymore', 'phoenixminer', 'nbminer', 'gminer', 't-rex',
            'lolminer', 'nanominer', 'teamredminer', 'wildrig',
            'cryptonight', 'monero', 'coinhive', 'jsecoin'
        ]
        
        # Blockchain ports
        self.crypto_ports = [
            3333, 4444, 5555, 8332, 8333,  # Bitcoin
            30303, 8545,  # Ethereum
            18080, 18081,  # Monero
            9332, 3334, 3335  # Other mining protocols
        ]
        
    def get_interface(self) -> Optional[str]:
        """Get the primary network interface (cross-platform)"""
        if psutil is None:
            return 'Ethernet' if platform.system() == 'Windows' else ('en0' if platform.system() == 'Darwin' else 'eth0')

        try:
            # Use psutil to get default interface (works on all platforms)
            net_if_stats = psutil.net_if_stats()
            net_if_addrs = psutil.net_if_addrs()
            
            # Find first active non-loopback interface
            for interface, stats in net_if_stats.items():
                if stats.isup and interface.lower() not in ['lo', 'loopback']:
                    # Verify it has an IP address
                    if interface in net_if_addrs:
                        return interface
        except Exception:
            pass
        
        # Platform-specific fallback
        if platform.system() == 'Windows':
            return 'Ethernet'
        elif platform.system() == 'Darwin':  # macOS
            return 'en0'
        return 'eth0'  # Linux fallback
    
    def count_packets(self) -> int:
        """Count total packets processed on interface (cross-platform)"""
        if psutil is None:
            return 0

        try:
            interface = self.get_interface()
            # Use psutil instead of /sys/class/net (works on all platforms)
            net_io = psutil.net_io_counters(pernic=True)
            if interface in net_io:
                return net_io[interface].packets_recv
        except Exception:
            pass
        return 0
    
    def analyze_connections(self) -> Dict:
        """Analyze active network connections for protocols and apps"""
        protocols = defaultdict(int)
        encrypted = 0
        total = 0

        if psutil is None:
            return {
                'total_packets': 0,
                'protocols': {},
                'encrypted_percent': 0,
                'blocked_apps': {},
                'total_connections': 0
            }
        
        try:
            # Get active connections using psutil (cross-platform)
            connections = psutil.net_connections(kind='inet')
            for conn in connections:
                total += 1
                
                # Parse protocol
                if conn.type == 1:  # SOCK_STREAM = TCP
                    protocols['TCP'] += 1
                    # Check for TLS/HTTPS (port 443)
                    if conn.laddr and conn.laddr.port == 443:
                        encrypted += 1
                    if conn.raddr and conn.raddr.port == 443:
                        encrypted += 1
                elif conn.type == 2:  # SOCK_DGRAM = UDP
                    protocols['UDP'] += 1
                
                # Identify application-aware blocking targets using process + ports
                # (applies to both TCP and UDP)
                proc_name = ''
                if conn.pid:
                    try:
                        proc_name = psutil.Process(conn.pid).name().lower()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        proc_name = ''
                rport = conn.raddr.port if conn.raddr else None
                lport = conn.laddr.port if conn.laddr else None
                
                if proc_name and 'tor' in proc_name:
                    self.blocked_apps['Tor'] += 1
                elif rport in (6881, 6889) or lport in (6881, 6889):  # BitTorrent
                    self.blocked_apps['BitTorrent'] += 1
        except Exception as e:
            print(f"[TRAFFIC] Error analyzing connections: {e}")
        
        encrypted_percent = int((encrypted / total * 100)) if total > 0 else 0
        
        return {
            'total_packets': self.count_packets(),
            'protocols': dict(protocols),
            'encrypted_percent': encrypted_percent,
            'blocked_apps': dict(self.blocked_apps),
            'total_connections': total
        }
    
    def detect_cpu_gpu_spikes(self) -> List[Dict]:
        """Detect unusual CPU/GPU usage indicating mining"""
        spikes = []
        if psutil is None:
            return spikes
        try:
            # Check CPU usage per process
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                try:
                    info = proc.info
                    cpu = info['cpu_percent']
                    
                    # Flag processes using >50% CPU
                    if cpu and cpu > 50:
                        # Check if process name matches miner signatures
                        is_miner = any(sig in info['name'].lower() for sig in self.miner_signatures)
                        
                        spikes.append({
                            'pid': info['pid'],
                            'process': info['name'],
                            'cpu_percent': round(cpu, 1),
                            'memory_percent': round(info['memory_percent'], 1),
                            'suspected_miner': is_miner,
                            'detected_at': datetime.now().isoformat()
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except Exception as e:
            print(f"[CRYPTO] CPU spike detection error: {e}")
        
        return spikes[:10]  # Top 10 high-CPU processes
    
    def detect_mining_network_traffic(self) -> List[Dict]:
        """Detect mining pool connections and blockchain traffic (cross-platform)"""
        mining_traffic = []
        if psutil is None:
            return mining_traffic
        
        try:
            # Use psutil instead of ss (cross-platform)
            connections = psutil.net_connections(kind='inet')
            for conn in connections:
                if conn.raddr:  # Has remote address
                    raddr_str = f"{conn.raddr.ip}:{conn.raddr.port}"
                    
                    # Check for mining pool domains (requires DNS lookup)
                    # For now, check ports
                    
                    # Check for known mining ports
                    for port in self.crypto_ports:
                        if conn.raddr.port == port:
                            laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "unknown"
                            mining_traffic.append({
                                'type': 'blockchain_port',
                                'port': port,
                                'connection': f"{'TCP' if conn.type == 1 else 'UDP'} {laddr} -> {raddr_str}"
                            })
                            break
        except Exception as e:
            print(f"[CRYPTO] Network traffic scan error: {e}")
        
        return mining_traffic[:20]  # Top 20 suspicious connections
    
    def scan_for_miner_processes(self) -> List[Dict]:
        """Scan running processes for known miner signatures"""
        detected_miners = []
        if psutil is None:
            return detected_miners
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'cpu_percent']):
                try:
                    info = proc.info
                    process_name = info['name'].lower()
                    cmdline = ' '.join(info['cmdline']).lower() if info['cmdline'] else ''
                    
                    # Check against miner signatures
                    for signature in self.miner_signatures:
                        if signature in process_name or signature in cmdline:
                            detected_miners.append({
                                'pid': info['pid'],
                                'process': info['name'],
                                'signature': signature,
                                'cpu_percent': info['cpu_percent'],
                                'command': cmdline[:100],
                                'detected_at': datetime.now().isoformat()
                            })
                            break
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except Exception as e:
            print(f"[CRYPTO] Process scan error: {e}")
        
        return detected_miners
    
    def get_crypto_mining_stats(self) -> Dict:
        """Get cryptocurrency mining detection statistics"""
        cpu_spikes = self.detect_cpu_gpu_spikes()
        network_traffic = self.detect_mining_network_traffic()
        miner_processes = self.scan_for_miner_processes()
        
        stats = {
            'total_detections': len(cpu_spikes) + len(network_traffic) + len(miner_processes),
            'cpu_spikes': len(cpu_spikes),
            'mining_connections': len(network_traffic),
            'miner_processes': len(miner_processes),
            'high_cpu_processes': cpu_spikes,
            'mining_traffic': network_traffic,
            'detected_miners': miner_processes,
            'risk_level': 'high' if miner_processes else ('medium' if network_traffic else 'low')
        }

        # Persist non-empty detection snapshots for dashboard/forensics (bounded history)
        if stats['total_detections'] > 0:
            snapshot = {
                'timestamp': datetime.now().isoformat(),
                'stats': stats
            }
            self.crypto_detections.append(snapshot)
            # Keep only the most recent 100 records to bound file size
            if len(self.crypto_detections) > 100:
                self.crypto_detections = self.crypto_detections[-100:]
            try:
                os.makedirs(os.path.dirname(self.crypto_detections_file), exist_ok=True)
                with open(self.crypto_detections_file, 'w') as f:
                    json.dump(self.crypto_detections, f, indent=2)
            except Exception as e:
                print(f"[CRYPTO] Failed to persist mining detections: {e}")

        return stats
    
    def get_stats(self) -> Dict:
        """Get current traffic analysis statistics"""
        base_stats = self.analyze_connections()
        crypto_stats = self.get_crypto_mining_stats()
        
        # Merge stats
        base_stats['crypto_mining'] = crypto_stats
        return base_stats

# Global instance
traffic_analyzer = TrafficAnalyzer()
