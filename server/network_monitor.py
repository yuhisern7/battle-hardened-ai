#!/usr/bin/env python3
"""
Network Traffic Monitor - Monitors all devices on WiFi/LAN
Detects port scans, network attacks, suspicious traffic patterns
"""

import threading
import time
from collections import defaultdict
from datetime import datetime, timedelta
import sys
import os
import pytz
import json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import AI.pcs_ai as pcs_ai

# Optional advanced AI modules (behavioral heuristics, graph, DNS & TLS analyzers)
try:
    from AI.behavioral_heuristics import track_connection as bh_track_connection
    from AI.graph_intelligence import track_connection as graph_track_connection
    from AI.dns_analyzer import analyze_dns_query
    from AI.tls_fingerprint import observe_tls_flow
    ADVANCED_FLOW_ANALYTICS_AVAILABLE = True
    print("[NETWORK] Advanced flow analytics (behavioral, graph, DNS, TLS) enabled")
except ImportError as e:
    ADVANCED_FLOW_ANALYTICS_AVAILABLE = False
    print(f"[NETWORK] Advanced flow analytics not available: {e}")

# Import performance monitoring
try:
    import AI.network_performance as net_perf
    PERFORMANCE_TRACKING_AVAILABLE = True
    print("[NETWORK] Performance tracking enabled")
except ImportError:
    PERFORMANCE_TRACKING_AVAILABLE = False
    print("[WARNING] Performance tracking not available")

def _get_current_time():
    """Get current datetime in configured timezone"""
    try:
        tz_name = os.getenv('TZ', 'Asia/Kuala_Lumpur')
        tz = pytz.timezone(tz_name)
        return datetime.now(tz)
    except:
        return datetime.now(pytz.UTC)

try:
    from scapy.all import sniff, IP, TCP, UDP, ARP, DNS, DNSQR
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("[WARNING] Scapy not installed. Network monitoring disabled.")
    print("[INFO] Install with: pip install scapy")

# Persistent storage paths
NETWORK_MONITOR_STATE_FILE = os.path.join(os.path.dirname(__file__), 'json', 'network_monitor_state.json')

def _serialize_monitor_state(port_scan_tracker, arp_tracker, connection_tracker):
    """Convert monitor state to JSON-serializable format"""
    return {
        'port_scan_tracker': {
            ip: {
                'ports': list(data['ports']),
                'last_seen': data['last_seen'].isoformat() if isinstance(data.get('last_seen'), datetime) else data.get('last_seen')
            }
            for ip, data in port_scan_tracker.items()
        },
        'arp_tracker': dict(arp_tracker),
        'connection_tracker': dict(connection_tracker)
    }

def _deserialize_monitor_state(data):
    """Convert JSON data back to monitor state"""
    port_scan = defaultdict(lambda: defaultdict(set))
    for ip, info in data.get('port_scan_tracker', {}).items():
        port_scan[ip]['ports'] = set(info.get('ports', []))
        last_seen = info.get('last_seen')
        if last_seen:
            try:
                port_scan[ip]['last_seen'] = datetime.fromisoformat(last_seen)
            except:
                port_scan[ip]['last_seen'] = _get_current_time()
    
    arp = defaultdict(list)
    arp.update(data.get('arp_tracker', {}))
    
    conn = defaultdict(int)
    conn.update(data.get('connection_tracker', {}))
    
    return port_scan, arp, conn

def _save_monitor_state(port_scan_tracker, arp_tracker, connection_tracker):
    """Save network monitor state to disk"""
    try:
        os.makedirs(os.path.dirname(NETWORK_MONITOR_STATE_FILE), exist_ok=True)
        state = _serialize_monitor_state(port_scan_tracker, arp_tracker, connection_tracker)
        with open(NETWORK_MONITOR_STATE_FILE, 'w') as f:
            json.dump(state, f, indent=2)
    except Exception as e:
        print(f"[WARNING] Could not save network monitor state: {e}")

def _load_monitor_state():
    """Load network monitor state from disk"""
    try:
        if os.path.exists(NETWORK_MONITOR_STATE_FILE):
            with open(NETWORK_MONITOR_STATE_FILE, 'r') as f:
                data = json.load(f)
            port_scan, arp, conn = _deserialize_monitor_state(data)
            print(f"[NETWORK] Loaded monitor state: {len(port_scan)} IPs tracked")
            return port_scan, arp, conn
    except json.JSONDecodeError as e:
        # Auto-heal corrupted JSON so we don't spam warnings on every startup
        try:
            backup_path = NETWORK_MONITOR_STATE_FILE + '.corrupt'
            os.replace(NETWORK_MONITOR_STATE_FILE, backup_path)
            print(f"[WARNING] Corrupted network monitor state detected; backed up to {backup_path} and resetting: {e}")
        except Exception as backup_err:
            print(f"[WARNING] Failed to backup corrupted network monitor state: {backup_err}")
    except Exception as e:
        print(f"[WARNING] Could not load network monitor state: {e}")
    return defaultdict(lambda: defaultdict(set)), defaultdict(list), defaultdict(int)


class NetworkMonitor:
    """Monitor network traffic for security threats"""
    
    def __init__(self):
        self.running = False
        # Load previous state
        port_scan, arp, conn = _load_monitor_state()
        self.port_scan_tracker = port_scan
        self.arp_tracker = arp
        self.connection_tracker = conn
        
        # Advanced scan detection trackers for ALL scanning tools
        # nmap, masscan, zmap, unicornscan, hping3, scapy, metasploit, etc.
        self.syn_tracker = defaultdict(lambda: {'ports': set(), 'last_seen': _get_current_time(), 'count': 0})  # SYN scans (nmap -sS, masscan)
        self.fin_tracker = defaultdict(lambda: {'ports': set(), 'count': 0})  # FIN scans (nmap -sF)
        self.null_tracker = defaultdict(lambda: {'ports': set(), 'count': 0})  # NULL scans (nmap -sN)
        self.xmas_tracker = defaultdict(lambda: {'ports': set(), 'count': 0})  # XMAS scans (nmap -sX)
        self.ack_tracker = defaultdict(lambda: {'ports': set(), 'count': 0})  # ACK scans (nmap -sA)
        self.udp_tracker = defaultdict(lambda: {'ports': set(), 'count': 0})  # UDP scans (nmap -sU)
        self.version_scan_tracker = defaultdict(lambda: {'ports': set(), 'count': 0})  # Version detection (nmap -sV)
        
    def start(self):
        """Start monitoring network traffic"""
        if not SCAPY_AVAILABLE:
            print("[ERROR] Cannot start network monitoring - scapy not installed")
            return
        
        self.running = True
        print("[NETWORK] Starting packet capture...")
        print("[NETWORK] Monitoring all network interfaces...")
        
        # Start packet sniffing in a separate thread
        sniff_thread = threading.Thread(target=self._sniff_packets, daemon=True)
        sniff_thread.start()
        
        # Start cleanup thread
        cleanup_thread = threading.Thread(target=self._cleanup_old_data, daemon=True)
        cleanup_thread.start()
    
    def stop(self):
        """Stop monitoring"""
        self.running = False
        print("[NETWORK] Network monitoring stopped")
    
    def _sniff_packets(self):
        """Sniff network packets and analyze them"""
        try:
            # Enable promiscuous mode to capture ALL network traffic (not just packets for this host)
            # This allows monitoring of entire LAN segment
            print("[NETWORK] Starting packet capture in PROMISCUOUS MODE")
            print("[NETWORK] Monitoring entire network segment (all devices)")
            
            # Sniff packets on all interfaces
            # filter="tcp or udp or arp" limits to relevant protocols
            # promisc=1 enables promiscuous mode (captures all packets on network segment)
            sniff(
                prn=self._analyze_packet,
                filter="tcp or udp or arp",
                store=False,
                promisc=1,  # PROMISCUOUS MODE - captures all network traffic
                stop_filter=lambda x: not self.running
            )
        except PermissionError:
            print("[ERROR] Permission denied - run as Administrator for network monitoring")
            print("[ERROR] On Windows: Run PowerShell/CMD as Administrator")
            print("[ERROR] Promiscuous mode requires elevated privileges")
        except Exception as e:
            print(f"[ERROR] Network monitoring error: {e}")
    
    def _analyze_packet(self, packet):
        """Analyze a single packet for threats"""
        try:
            # Get source IP
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                
                # TCP packet analysis
                if TCP in packet:
                    self._analyze_tcp_packet(packet, src_ip, dst_ip)
                
                # UDP packet analysis
                if UDP in packet:
                    self._analyze_udp_packet(packet, src_ip, dst_ip)
            
            # ARP analysis (ARP spoofing detection)
            if ARP in packet:
                self._analyze_arp_packet(packet)
        
        except Exception as e:
            # Don't crash on packet analysis errors
            pass
    
    def _analyze_tcp_packet(self, packet, src_ip, dst_ip):
        """Analyze TCP packet for ALL scan types (nmap, masscan, zmap, unicornscan, hping3, metasploit, etc.)"""
        tcp = packet[TCP]
        dst_port = tcp.dport
        src_port = tcp.sport
        flags = tcp.flags
        
        # Performance tracking: bandwidth and packet counts
        if PERFORMANCE_TRACKING_AVAILABLE:
            try:
                packet_size = len(packet)
                net_perf.update_bandwidth(src_ip, packet_size, 0)  # Sent
                net_perf.update_bandwidth(dst_ip, 0, packet_size)  # Received
            except:
                pass
        
        # === STEALTH SCAN DETECTION (detects incomplete handshakes) ===
        
        # 1. SYN SCAN (nmap -sS, masscan, zmap) - Most common stealth scan
        #    Sends SYN, waits for SYN-ACK, NEVER completes with ACK (half-open)
        if flags == 'S' or flags == 2:  # SYN only, no ACK
            self.syn_tracker[src_ip]['ports'].add(dst_port)
            self.syn_tracker[src_ip]['count'] += 1
            self.syn_tracker[src_ip]['last_seen'] = _get_current_time()
            
            # Detect SYN scan: 5+ ports with SYN-only packets
            if len(self.syn_tracker[src_ip]['ports']) > 5:
                pcs_ai._log_threat(
                    ip_address=src_ip,
                    threat_type="SYN Stealth Scan (nmap -sS / masscan / zmap)",
                    details=f"SYN stealth scan detected: {len(self.syn_tracker[src_ip]['ports'])} ports scanned with {self.syn_tracker[src_ip]['count']} SYN packets (no handshake completion). Ports: {sorted(list(self.syn_tracker[src_ip]['ports']))[:20]}. Scanning tools: nmap, masscan, zmap, unicornscan, hping3",
                    level=pcs_ai.ThreatLevel.DANGEROUS,
                    action="detected",
                    headers={}
                )
                pcs_ai._block_ip(src_ip)
                self.syn_tracker[src_ip]['ports'].clear()
        
        # 2. FIN SCAN (nmap -sF) - Sends FIN flag only
        elif flags == 'F' or flags == 1:
            self.fin_tracker[src_ip]['ports'].add(dst_port)
            if len(self.fin_tracker[src_ip]['ports']) > 5:
                pcs_ai._log_threat(
                    ip_address=src_ip,
                    threat_type="FIN Stealth Scan (nmap -sF)",
                    details=f"FIN scan detected: {len(self.fin_tracker[src_ip]['ports'])} ports probed with FIN flag. Ports: {sorted(list(self.fin_tracker[src_ip]['ports']))[:20]}",
                    level=pcs_ai.ThreatLevel.DANGEROUS,
                    action="detected",
                    headers={}
                )
                pcs_ai._block_ip(src_ip)
                self.fin_tracker[src_ip]['ports'].clear()
        
        # 3. NULL SCAN (nmap -sN) - No flags set
        elif flags == 0 or flags == '':
            self.null_tracker[src_ip]['ports'].add(dst_port)
            if len(self.null_tracker[src_ip]['ports']) > 5:
                pcs_ai._log_threat(
                    ip_address=src_ip,
                    threat_type="NULL Stealth Scan (nmap -sN)",
                    details=f"NULL scan detected: {len(self.null_tracker[src_ip]['ports'])} ports probed with null flags. Ports: {sorted(list(self.null_tracker[src_ip]['ports']))[:20]}",
                    level=pcs_ai.ThreatLevel.DANGEROUS,
                    action="detected",
                    headers={}
                )
                pcs_ai._block_ip(src_ip)
                self.null_tracker[src_ip]['ports'].clear()
        
        # 4. XMAS SCAN (nmap -sX) - FIN+PSH+URG flags
        elif flags == 'FPU' or flags == 41:
            self.xmas_tracker[src_ip]['ports'].add(dst_port)
            if len(self.xmas_tracker[src_ip]['ports']) > 5:
                pcs_ai._log_threat(
                    ip_address=src_ip,
                    threat_type="XMAS Stealth Scan (nmap -sX)",
                    details=f"XMAS scan detected: {len(self.xmas_tracker[src_ip]['ports'])} ports probed with FIN+PSH+URG flags. Ports: {sorted(list(self.xmas_tracker[src_ip]['ports']))[:20]}",
                    level=pcs_ai.ThreatLevel.DANGEROUS,
                    action="detected",
                    headers={}
                )
                pcs_ai._block_ip(src_ip)
                self.xmas_tracker[src_ip]['ports'].clear()
        
        # 5. ACK SCAN (nmap -sA) - ACK flag only (firewall mapping)
        elif flags == 'A' or flags == 16:
            self.ack_tracker[src_ip]['ports'].add(dst_port)
            if len(self.ack_tracker[src_ip]['ports']) > 5:
                pcs_ai._log_threat(
                    ip_address=src_ip,
                    threat_type="ACK Scan (nmap -sA / Firewall Mapping)",
                    details=f"ACK scan detected: {len(self.ack_tracker[src_ip]['ports'])} ports probed to map firewall rules. Ports: {sorted(list(self.ack_tracker[src_ip]['ports']))[:20]}",
                    level=pcs_ai.ThreatLevel.SUSPICIOUS,
                    action="detected",
                    headers={}
                )
                pcs_ai._block_ip(src_ip)
                self.ack_tracker[src_ip]['ports'].clear()
        
        # 6. VERSION SCAN (nmap -sV) - Service fingerprinting with multiple probes
        if 'SA' in str(flags) or 'PA' in str(flags):
            self.version_scan_tracker[src_ip]['ports'].add(dst_port)
            self.version_scan_tracker[src_ip]['count'] += 1
            
            # nmap -sV sends 3-7 probes per port for version detection
            if self.version_scan_tracker[src_ip]['count'] > 20:
                pcs_ai._log_threat(
                    ip_address=src_ip,
                    threat_type="Service Version Scan (nmap -sV / Banner Grabbing)",
                    details=f"Version detection scan: {self.version_scan_tracker[src_ip]['count']} service probes sent to {len(self.version_scan_tracker[src_ip]['ports'])} ports. Tools: nmap -sV, nessus, openvas, metasploit",
                    level=pcs_ai.ThreatLevel.SUSPICIOUS,
                    action="detected",
                    headers={}
                )
                pcs_ai._block_ip(src_ip)
                self.version_scan_tracker[src_ip]['count'] = 0
                self.version_scan_tracker[src_ip]['ports'].clear()
        
        # === TRADITIONAL PORT SCAN DETECTION (catches all scan types) ===
        # Track ports accessed by this IP
        self.port_scan_tracker[src_ip]['ports'].add(dst_port)
        self.port_scan_tracker[src_ip]['last_seen'] = _get_current_time()
        
        # Detect port scanning (accessing many different ports)
        ports_accessed = len(self.port_scan_tracker[src_ip]['ports'])
        
        if ports_accessed > 10:  # Accessing 10+ different ports = port scan
            pcs_ai._log_threat(
                ip_address=src_ip,
                threat_type="Port Scanning (Multi-Tool Detection)",
                details=f"Port scan detected: {ports_accessed} different ports accessed. Ports: {sorted(list(self.port_scan_tracker[src_ip]['ports']))[:20]}. Detected scanning tools: nmap, masscan, zmap, unicornscan, hping3, metasploit, angry IP scanner, zenmap, nessus, openvas",
                level=pcs_ai.ThreatLevel.DANGEROUS,
                action="detected",
                headers={}
            )
            # Block the scanner
            pcs_ai._block_ip(src_ip)
            # Clear tracker to avoid duplicate alerts
            self.port_scan_tracker[src_ip]['ports'].clear()
        
        # === SYN FLOOD DETECTION (DDoS) ===
        if flags == 'S' or flags == 2:  # SYN packet
            self.connection_tracker[src_ip] += 1
            
            # If more than 100 SYN packets in tracking period
            if self.connection_tracker[src_ip] > 100:
                pcs_ai._log_threat(
                    ip_address=src_ip,
                    threat_type="SYN Flood Attack (DDoS)",
                    details=(
                        f"High-volume SYN traffic detected: {self.connection_tracker[src_ip]} SYN packets "
                        f"to {dst_ip}:{dst_port}. This pattern matches transport-layer floods or "
                        f"aggressive brute-force tools (e.g. hping3, password crackers like hydra/medusa, "
                        f"metasploit auxiliary/dos, slowloris-style attacks)."
                    ),
                    level=pcs_ai.ThreatLevel.CRITICAL,
                    action="detected",
                    headers={}
                )
                pcs_ai._block_ip(src_ip)
                self.connection_tracker[src_ip] = 0
        
        # Advanced flow analytics: behavioral heuristics, graph intelligence, TLS heuristics
        if 'ADVANCED_FLOW_ANALYTICS_AVAILABLE' in globals() and ADVANCED_FLOW_ANALYTICS_AVAILABLE:
            # Feed behavioral heuristics (flow UEBA)
            try:
                packet_size = len(packet)
                bh_track_connection(
                    entity_id=src_ip,
                    dest_ip=dst_ip,
                    dest_port=dst_port,
                    src_port=src_port,
                    protocol='tcp',
                    payload_size=packet_size,
                )
            except Exception:
                # Never break packet analysis on heuristics errors
                pass

            # Feed network graph for lateral movement / C2 patterns
            try:
                packet_size = len(packet)
                graph_track_connection(src_ip, dst_ip, dst_port, "TCP", packet_size)
            except Exception:
                pass

            # TLS / encrypted flow heuristics (metadata-only)
            try:
                # Treat standard TLS ports and high ephemeral ports with extra scrutiny
                if dst_port in {443, 8443, 9443} or dst_port >= 1024:
                    tls_result = observe_tls_flow(src_ip, dst_ip, dst_port, src_port, len(packet))
                    if tls_result.get('suspicious') and tls_result.get('confidence', 0) >= 0.7:
                        reasons = "; ".join(tls_result.get('reasons', []))
                        pcs_ai._log_threat(
                            ip_address=src_ip,
                            threat_type=tls_result.get('threat_type', 'Encrypted C2 Suspected'),
                            details=(
                                f"Encrypted flow from {src_ip} to {dst_ip}:{dst_port} "
                                f"flagged as suspicious. {reasons}"
                            ),
                            level=pcs_ai.ThreatLevel.SUSPICIOUS,
                            action="detected",
                            headers={},
                        )
            except Exception:
                pass
    
    def _analyze_udp_packet(self, packet, src_ip, dst_ip):
        """Analyze UDP packet for attacks"""
        udp = packet[UDP]
        dst_port = udp.dport
        
        # Performance tracking: bandwidth
        if PERFORMANCE_TRACKING_AVAILABLE:
            try:
                packet_size = len(packet)
                net_perf.update_bandwidth(src_ip, packet_size, 0)
            except:
                pass
        
        # Track UDP floods (high-volume UDP from any source is treated as attack)
        self.connection_tracker[f"udp_{src_ip}"] += 1

        if self.connection_tracker[f"udp_{src_ip}"] > 200:
            pcs_ai._log_threat(
                ip_address=src_ip,
                threat_type="UDP Flood Attack",
                details=(
                    f"High-volume UDP traffic detected: "
                    f"{self.connection_tracker[f'udp_{src_ip}']} UDP packets to {dst_ip}:{dst_port}. "
                    f"This pattern matches UDP flood tools such as hping3 or custom DoS scripts."
                ),
                level=pcs_ai.ThreatLevel.CRITICAL,
                action="detected",
                headers={}
            )
            pcs_ai._block_ip(src_ip)
            self.connection_tracker[f"udp_{src_ip}"] = 0

        # Advanced flow analytics: behavioral heuristics, graph intelligence, DNS heuristics
        if 'ADVANCED_FLOW_ANALYTICS_AVAILABLE' in globals() and ADVANCED_FLOW_ANALYTICS_AVAILABLE:
            # Feed behavioral heuristics
            try:
                packet_size = len(packet)
                bh_track_connection(
                    entity_id=src_ip,
                    dest_ip=dst_ip,
                    dest_port=dst_port,
                    protocol='udp',
                    payload_size=packet_size,
                )
            except Exception:
                pass

            # Feed graph intelligence
            try:
                packet_size = len(packet)
                graph_track_connection(src_ip, dst_ip, dst_port, "UDP", packet_size)
            except Exception:
                pass

            # DNS security (tunneling / DGA / exfil heuristics)
            try:
                if dst_port in (53, 5353) and packet.haslayer(DNS) and packet[DNS].qd is not None:
                    qd = packet[DNS].qd
                    qname = getattr(qd, 'qname', b'')
                    if isinstance(qname, bytes):
                        try:
                            qname = qname.decode(errors='ignore')
                        except Exception:
                            qname = '<decode_error>'
                    qtype = getattr(qd, 'qtype', 'UNKNOWN')
                    dns_result = analyze_dns_query(
                        src_ip=src_ip,
                        query_name=str(qname),
                        qtype=str(qtype),
                        payload_len=len(packet),
                    )
                    if dns_result.get('suspicious') and dns_result.get('confidence', 0) >= 0.7:
                        reasons = "; ".join(dns_result.get('reasons', []))
                        pcs_ai._log_threat(
                            ip_address=src_ip,
                            threat_type=dns_result.get('threat_type', 'DNS Exfiltration Suspected'),
                            details=(
                                f"Suspicious DNS query from {src_ip} for {qname}. {reasons}"
                            ),
                            level=pcs_ai.ThreatLevel.SUSPICIOUS,
                            action="detected",
                            headers={}
                        )
            except Exception:
                pass
    
    def _analyze_arp_packet(self, packet):
        """Analyze ARP packet for ARP spoofing"""
        arp = packet[ARP]
        
        # Track ARP requests
        src_ip = arp.psrc
        src_mac = arp.hwsrc
        
        # Filter out 0.0.0.0 (DHCP negotiation and network initialization)
        if src_ip == "0.0.0.0":
            return
        
        # Store IP-MAC mapping
        key = f"{src_ip}_{src_mac}"
        self.arp_tracker[src_ip].append({
            'mac': src_mac,
            'time': _get_current_time()
        })
        
        # Detect ARP spoofing (same IP with different MAC addresses)
        unique_macs = set(entry['mac'] for entry in self.arp_tracker[src_ip])
        
        if len(unique_macs) > 1:
            pcs_ai._log_threat(
                ip_address=src_ip,
                threat_type="ARP Spoofing",
                details=f"ARP spoofing detected: IP {src_ip} seen with multiple MAC addresses: {list(unique_macs)}",
                level=pcs_ai.ThreatLevel.CRITICAL,
                action="detected",
                headers={}
            )
    
    def _cleanup_old_data(self):
        """Clean up old tracking data periodically"""
        while self.running:
            time.sleep(300)  # Every 5 minutes
            
            cutoff = _get_current_time() - timedelta(minutes=10)
            
            # Clean port scan tracker
            for ip in list(self.port_scan_tracker.keys()):
                if self.port_scan_tracker[ip].get('last_seen', _get_current_time() - timedelta(days=1)) < cutoff:
                    del self.port_scan_tracker[ip]
            
            # Clean ARP tracker
            for ip in list(self.arp_tracker.keys()):
                self.arp_tracker[ip] = [
                    entry for entry in self.arp_tracker[ip]
                    if entry['time'] > cutoff
                ]
                if not self.arp_tracker[ip]:
                    del self.arp_tracker[ip]
            
            # Reset connection trackers
            self.connection_tracker.clear()
            
            # Save state to disk
            _save_monitor_state(self.port_scan_tracker, self.arp_tracker, self.connection_tracker)


if __name__ == '__main__':
    print("Network Monitor - Test Mode")
    print("Starting network monitoring...")
    
    # Start real honeypot
    try:
        from AI.real_honeypot import start_honeypots
        print("Starting real honeypot services...")
        start_honeypots()
    except Exception as e:
        print(f"[WARNING] Could not start honeypots: {e}")
    
    monitor = NetworkMonitor()
    monitor.start()
    
    print("Monitoring... Press Ctrl+C to stop")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping...")
        monitor.stop()
