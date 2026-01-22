"""Asset Inventory & Management Module
Complete asset database with software tracking, licenses, EOL detection.
NO FAKE DATA - Real system inventory.
"""

import os
import json
import subprocess
import platform
import shutil
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from collections import defaultdict
import logging

from AI.path_helper import get_json_dir, get_json_file

logger = logging.getLogger(__name__)

class AssetInventory:
    """Track hardware and software assets across the network"""
    
    def __init__(self):
        # Use centralized JSON directory helper for inventory files
        json_dir = get_json_dir()
        os.makedirs(json_dir, exist_ok=True)
        self.inventory_file = get_json_file('asset_inventory.json')
        self.software_file = get_json_file('software_inventory.json')
        self.assets = self.load_inventory()
        
    def load_inventory(self) -> Dict:
        """Load asset inventory from disk"""
        try:
            if os.path.exists(self.inventory_file):
                with open(self.inventory_file, 'r') as f:
                    return json.load(f)
        except:
            pass
        return {'hardware': [], 'software': [], 'licenses': []}
    
    def save_inventory(self):
        """Save asset inventory to disk"""
        try:
            with open(self.inventory_file, 'w') as f:
                json.dump(self.assets, f, indent=2)
        except Exception as e:
            logger.warning(f"[ASSET] Save error: {e}")

    def _load_connected_devices(self) -> List[Dict]:
        """Load discovered hardware devices from connected_devices.json"""
        try:
            connected_path = get_json_file('connected_devices.json')
            if not os.path.exists(connected_path):
                return []
            with open(connected_path, 'r') as f:
                data = json.load(f)
            devices = data.get('devices', {})
            return list(devices.values()) if isinstance(devices, dict) else []
        except Exception as e:
            logger.warning(f"[ASSET] Connected devices load error: {e}")
            return []
    
    def scan_software(self) -> List[Dict]:
        """Scan installed software packages (cross-platform)"""
        software = []
        system = platform.system()
        
        # Linux (Debian/Ubuntu) - dpkg
        if system == 'Linux' and shutil.which('dpkg'):
            try:
                result = subprocess.run(['dpkg', '-l'], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if line.startswith('ii'):
                            parts = line.split()
                            if len(parts) >= 3:
                                software.append({
                                    'name': parts[1],
                                    'version': parts[2],
                                    'type': 'system_package',
                                    'package_manager': 'dpkg',
                                    'device': platform.node(),
                                    'last_seen': datetime.now().isoformat()
                                })
            except:
                pass
        
        # macOS - Homebrew
        if system == 'Darwin' and shutil.which('brew'):
            try:
                result = subprocess.run(['brew', 'list', '--versions'], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if line.strip():
                            parts = line.split()
                            if len(parts) >= 2:
                                software.append({
                                    'name': parts[0],
                                    'version': parts[1],
                                    'type': 'system_package',
                                    'package_manager': 'brew',
                                    'device': platform.node(),
                                    'last_seen': datetime.now().isoformat()
                                })
            except:
                pass
        
        # Windows - via PowerShell Get-Package or wmic
        if system == 'Windows':
            try:
                # Try PowerShell Get-Package first
                result = subprocess.run(
                    ['powershell', '-Command', 'Get-Package | Select-Object Name,Version | ConvertTo-Csv -NoTypeInformation'],
                    capture_output=True, text=True, timeout=10
                )
                if result.returncode == 0:
                    lines = result.stdout.split('\n')[1:]  # Skip header
                    for line in lines:
                        if line.strip():
                            parts = line.strip('\"').split('\",\"')
                            if len(parts) >= 2:
                                software.append({
                                    'name': parts[0],
                                    'version': parts[1],
                                    'type': 'system_package',
                                    'package_manager': 'windows',
                                    'device': platform.node(),
                                    'last_seen': datetime.now().isoformat()
                                })
            except:
                pass
        
        # Python packages (cross-platform)
        if shutil.which('pip3') or shutil.which('pip'):
            try:
                pip_cmd = 'pip3' if shutil.which('pip3') else 'pip'
                result = subprocess.run([pip_cmd, 'list'], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    for line in result.stdout.split('\n')[2:]:  # Skip header
                        if line.strip():
                            parts = line.split()
                            if len(parts) >= 2:
                                software.append({
                                    'name': parts[0],
                                    'version': parts[1],
                                    'type': 'python_package',
                                    'package_manager': pip_cmd,
                                    'device': platform.node(),
                                    'last_seen': datetime.now().isoformat()
                                })
            except:
                pass
        
        return software[:100]  # Limit to 100 for performance
    
    def detect_eol_software(self, software_list: Optional[List[Dict]] = None) -> List[Dict]:
        """Detect end-of-life software (simplified detection)"""
        software_list = software_list if software_list is not None else self.scan_software()
        eol_software = []
        
        # Known EOL patterns (simplified - in production, use API)
        eol_patterns = {
            'python2': '2020-01-01',
            'python3.6': '2021-12-23',
            'ubuntu18.04': '2023-05-31',
            'debian9': '2022-06-30'
        }
        
        for software in software_list:
            name_lower = software['name'].lower()
            for pattern, eol_date in eol_patterns.items():
                if pattern in name_lower:
                    eol_software.append({
                        **software,
                        'eol_date': eol_date,
                        'status': 'end_of_life',
                        'risk': 'high'
                    })
                    break
        
        return eol_software
    
    def detect_shadow_it(self, software_list: Optional[List[Dict]] = None) -> List[Dict]:
        """Detect unauthorized/shadow IT software"""
        software_list = software_list if software_list is not None else self.scan_software()
        shadow_it = []
        
        # Unauthorized software patterns (example)
        unauthorized_patterns = ['torrent', 'telegram', 'discord', 'teamviewer']
        
        for software in software_list:
            name_lower = software['name'].lower()
            for pattern in unauthorized_patterns:
                if pattern in name_lower:
                    shadow_it.append({
                        **software,
                        'reason': f'Unauthorized software: {pattern}',
                        'detected_at': datetime.now().isoformat()
                    })
                    break
        
        return shadow_it
    
    def calculate_asset_criticality(self, asset: Dict) -> str:
        """Calculate asset criticality score"""
        # Simplified criticality logic
        asset_type = asset.get('type', '').lower()
        
        if 'server' in asset_type or 'router' in asset_type:
            return 'critical'
        elif 'computer' in asset_type or 'laptop' in asset_type:
            return 'high'
        elif 'camera' in asset_type or 'iot' in asset_type:
            return 'medium'
        else:
            return 'low'
    
    def get_stats(self) -> Dict:
        """Get asset inventory statistics including network devices"""
        # Load hardware from network discovery
        hardware_devices = self._load_connected_devices()
        hardware_count = len(hardware_devices)
        
        # Scan local software (container/host)
        software = self.scan_software()
        eol_software = self.detect_eol_software(software)
        shadow_it = self.detect_shadow_it(software)

        eol_names = {item.get('name', '').lower() for item in eol_software}
        shadow_names = {item.get('name', '').lower() for item in shadow_it}

        # Enrich software list with status and risk for UI
        software_list = []
        for pkg in software:
            name_lower = pkg.get('name', '').lower()
            status = 'ok'
            risk = 'low'
            if name_lower in eol_names:
                status = 'end_of_life'
                risk = 'high'
            elif name_lower in shadow_names:
                status = 'shadow_it'
                risk = 'high'
            software_list.append({
                'name': pkg.get('name', 'unknown'),
                'version': pkg.get('version', 'unknown'),
                'device': pkg.get('device', 'localhost'),
                'status': status,
                'risk': risk,
                'package_manager': pkg.get('package_manager', 'unknown'),
                'last_seen': pkg.get('last_seen', datetime.now().isoformat())
            })
        
        return {
            'total_assets': hardware_count + len(software),
            'hardware_assets': hardware_count,
            'software_packages': len(software),
            'devices_scanned': hardware_count,
            'eol_software': len(eol_software),
            'shadow_it': len(shadow_it),
            'licenses_tracked': len(self.assets.get('licenses', [])),
            'critical_assets': sum(1 for a in hardware_devices if self.calculate_asset_criticality(a) == 'critical'),
            'eol_list': eol_software[:10],
            'shadow_it_list': shadow_it[:10],
            'software_list': software_list[:100],
            'hardware_list': hardware_devices[:100]
        }

# Global instance
asset_inventory = AssetInventory()
