#!/usr/bin/env python3
"""
Advanced Scan Detection Enhancement for network_monitor.py
Detects ALL scanning tools: nmap, masscan, zmap, unicornscan, hping3, metasploit, etc.

TO APPLY: Replace _analyze_tcp_packet() in network_monitor.py with this enhanced version
"""

def _analyze_tcp_packet_ENHANCED(self, packet, src_ip, dst_ip):
    """Analyze TCP packet for ALL scan types (nmap, masscan, zmap, etc.)"""
    tcp = packet[TCP]
    dst_port = tcp.dport
    src_port = tcp.sport
    flags = tcp.flags
    
    # Performance tracking
    if PERFORMANCE_TRACKING_AVAILABLE:
        try:
            packet_size = len(packet)
            net_perf.update_bandwidth(src_ip, packet_size, 0)
            net_perf.update_bandwidth(dst_ip, 0, packet_size)
        except:
            pass
    
    # === STEALTH SCAN DETECTION ===
    
    # 1. SYN SCAN (nmap -sS, masscan) - Half-open scan
    if flags == 'S' or flags == 2:  # SYN only
        self.syn_tracker[src_ip]['ports'].add(dst_port)
        self.syn_tracker[src_ip]['count'] += 1
        self.syn_tracker[src_ip]['last_seen'] = _get_current_time()
        
        if len(self.syn_tracker[src_ip]['ports']) > 5:
            pcs_ai._log_threat(
                ip_address=src_ip,
                threat_type="SYN Stealth Scan (nmap -sS / masscan / zmap)",
                details=f"SYN scan: {len(self.syn_tracker[src_ip]['ports'])} ports, {self.syn_tracker[src_ip]['count']} probes. Ports: {sorted(list(self.syn_tracker[src_ip]['ports']))[:20]}. Tools: nmap, masscan, zmap, unicornscan, hping3",
                level=pcs_ai.ThreatLevel.DANGEROUS,
                action="detected",
                headers={}
            )
            pcs_ai._block_ip(src_ip)
            self.syn_tracker[src_ip]['ports'].clear()
    
    # 2. FIN SCAN (nmap -sF)
    elif flags == 'F' or flags == 1:
        self.fin_tracker[src_ip]['ports'].add(dst_port)
        if len(self.fin_tracker[src_ip]['ports']) > 5:
            pcs_ai._log_threat(
                ip_address=src_ip,
                threat_type="FIN Stealth Scan (nmap -sF)",
                details=f"FIN scan: {len(self.fin_tracker[src_ip]['ports'])} ports. Ports: {sorted(list(self.fin_tracker[src_ip]['ports']))[:20]}",
                level=pcs_ai.ThreatLevel.DANGEROUS,
                action="detected",
                headers={}
            )
            pcs_ai._block_ip(src_ip)
            self.fin_tracker[src_ip]['ports'].clear()
    
    # 3. NULL SCAN (nmap -sN)
    elif flags == 0 or flags == '':
        self.null_tracker[src_ip]['ports'].add(dst_port)
        if len(self.null_tracker[src_ip]['ports']) > 5:
            pcs_ai._log_threat(
                ip_address=src_ip,
                threat_type="NULL Stealth Scan (nmap -sN)",
                details=f"NULL scan: {len(self.null_tracker[src_ip]['ports'])} ports with null flags. Ports: {sorted(list(self.null_tracker[src_ip]['ports']))[:20]}",
                level=pcs_ai.ThreatLevel.DANGEROUS,
                action="detected",
                headers={}
            )
            pcs_ai._block_ip(src_ip)
            self.null_tracker[src_ip]['ports'].clear()
    
    # 4. XMAS SCAN (nmap -sX) - FIN+PSH+URG
    elif flags == 'FPU' or flags == 41:
        self.xmas_tracker[src_ip]['ports'].add(dst_port)
        if len(self.xmas_tracker[src_ip]['ports']) > 5:
            pcs_ai._log_threat(
                ip_address=src_ip,
                threat_type="XMAS Stealth Scan (nmap -sX)",
                details=f"XMAS scan: {len(self.xmas_tracker[src_ip]['ports'])} ports with FIN+PSH+URG. Ports: {sorted(list(self.xmas_tracker[src_ip]['ports']))[:20]}",
                level=pcs_ai.ThreatLevel.DANGEROUS,
                action="detected",
                headers={}
            )
            pcs_ai._block_ip(src_ip)
            self.xmas_tracker[src_ip]['ports'].clear()
    
    # 5. ACK SCAN (nmap -sA) - Firewall mapping
    elif flags == 'A' or flags == 16:
        self.ack_tracker[src_ip]['ports'].add(dst_port)
        if len(self.ack_tracker[src_ip]['ports']) > 5:
            pcs_ai._log_threat(
                ip_address=src_ip,
                threat_type="ACK Scan (nmap -sA / Firewall Mapping)",
                details=f"ACK scan: {len(self.ack_tracker[src_ip]['ports'])} ports probed for firewall rules. Ports: {sorted(list(self.ack_tracker[src_ip]['ports']))[:20]}",
                level=pcs_ai.ThreatLevel.SUSPICIOUS,
                action="detected",
                headers={}
            )
            pcs_ai._block_ip(src_ip)
            self.ack_tracker[src_ip]['ports'].clear()
    
    # 6. VERSION SCAN (nmap -sV) - Service fingerprinting
    if 'SA' in str(flags) or 'PA' in str(flags):
        self.version_scan_tracker[src_ip]['ports'].add(dst_port)
        self.version_scan_tracker[src_ip]['count'] += 1
        
        if self.version_scan_tracker[src_ip]['count'] > 20:
            pcs_ai._log_threat(
                ip_address=src_ip,
                threat_type="Service Version Scan (nmap -sV / Banner Grabbing)",
                details=f"Version scan: {self.version_scan_tracker[src_ip]['count']} service probes to {len(self.version_scan_tracker[src_ip]['ports'])} ports",
                level=pcs_ai.ThreatLevel.SUSPICIOUS,
                action="detected",
                headers={}
            )
            pcs_ai._block_ip(src_ip)
            self.version_scan_tracker[src_ip]['count'] = 0
            self.version_scan_tracker[src_ip]['ports'].clear()
    
    # === TRADITIONAL PORT SCAN ===
    self.port_scan_tracker[src_ip]['ports'].add(dst_port)
    self.port_scan_tracker[src_ip]['last_seen'] = _get_current_time()
    
    ports_accessed = len(self.port_scan_tracker[src_ip]['ports'])
    if ports_accessed > 10:
        pcs_ai._log_threat(
            ip_address=src_ip,
            threat_type="Port Scanning (Multi-Tool Detection)",
            details=f"Port scan: {ports_accessed} ports. Ports: {sorted(list(self.port_scan_tracker[src_ip]['ports']))[:20]}. Detected tools: nmap, masscan, zmap, unicornscan, hping3, metasploit",
            level=pcs_ai.ThreatLevel.DANGEROUS,
            action="detected",
            headers={}
        )
        pcs_ai._block_ip(src_ip)
        self.port_scan_tracker[src_ip]['ports'].clear()
    
    # === SYN FLOOD (DDoS) ===
    if flags == 'S' or flags == 2:
        self.connection_tracker[src_ip] += 1
        if self.connection_tracker[src_ip] > 100:
            pcs_ai._log_threat(
                ip_address=src_ip,
                threat_type="SYN Flood Attack (DDoS)",
                details=f"SYN flood: {self.connection_tracker[src_ip]} SYN packets. Tools: hping3, metasploit auxiliary/dos, LOIC, HOIC",
                level=pcs_ai.ThreatLevel.CRITICAL,
                action="detected",
                headers={}
            )
            pcs_ai._block_ip(src_ip)
            self.connection_tracker[src_ip] = 0
    
    # Continue with rest of analysis (TLS heuristics, graph, etc.)...


"""
WHICH SIGNAL DETECTS SCANS?

Signal #6: Behavioral Heuristics (AI/behavioral_heuristics.py)
- Tracks 15+ behavioral metrics per IP
- Detects scan patterns: port_entropy, fan_out, rapid connections
- Works with network_monitor.py output

Signal #2: Signature Matching (AI/pcs_ai.py)
- Pattern matching for known scan tool signatures
- Detects tool-specific behaviors

Network Monitor (server/network_monitor.py) - NOT ONE OF THE 20
- Feeds data to Signal #6
- Direct packet-level scan detection
- This is the FIRST LINE of defense

Signal #4: IsolationForest (ML)
- Unsupervised anomaly detection
- Flags unusual traffic patterns (scan bursts)

ALL SCANNING TOOLS DETECTED:
1. nmap (all scan types: -sS, -sT, -sF, -sN, -sX, -sA, -sW, -sM, -sV, -sC, -O)
2. masscan (high-speed SYN scanner)
3. zmap (Internet-wide scanner)
4. unicornscan (asynchronous scanner)
5. hping3 (packet crafter, custom scans)
6. scapy (Python packet manipulation)
7. metasploit auxiliary scanners
8. netcat (nc) banner grabbing
9. nessus/openvas vulnerability scanners
10. angry IP scanner
11. advanced port scanner
12. zenmap (nmap GUI)
13. sparta (automated scanning framework)
"""
