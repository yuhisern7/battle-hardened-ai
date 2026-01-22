"""File Analysis and Sandbox Module
Real file hash checking and basic malware detection.
NO FAKE VERDICTS - Real analysis only.
"""

import os
import hashlib
import subprocess
import json
import mimetypes
import platform
import shutil
import math
import re
from datetime import datetime
from typing import Dict, Optional, List

try:
    import requests  # type: ignore
except ImportError:  # pragma: no cover - optional dependency
    requests = None

from AI.path_helper import get_json_dir, get_json_file

class FileAnalyzer:
    """Analyze files for threats using hashes and file type detection"""
    
    def __init__(self):
        # Use centralized JSON directory helper for analysis log
        json_dir = get_json_dir()
        os.makedirs(json_dir, exist_ok=True)
        self.analysis_log = get_json_file('file_analysis.json')
        self.vt_config_file = get_json_file('virustotal_config.json')
        # Conservative maximum file size for analysis to prevent resource abuse
        self.max_size_bytes = 50 * 1024 * 1024  # 50 MB
        self.stats = {
            'analyzed': 0,
            'malicious': 0,
            'suspicious': 0,
            'clean': 0
        }
        self.load_stats()
        self.vt_config = self.load_vt_config()
        
    def load_stats(self):
        """Load analysis statistics"""
        try:
            if os.path.exists(self.analysis_log):
                with open(self.analysis_log, 'r') as f:
                    data = json.load(f)
                    self.stats = data.get('stats', self.stats)
        except:
            pass
    
    def save_stats(self):
        """Save analysis statistics"""
        try:
            with open(self.analysis_log, 'w') as f:
                json.dump({'stats': self.stats, 'updated': datetime.now().isoformat()}, f)
        except:
            pass

    def load_vt_config(self) -> Dict:
        """Load VirusTotal configuration.

        Configuration sources (in order of precedence):
        - Environment variable VT_API_KEY (simplest lab setup)
        - virustotal_config.json in the central JSON directory

        If no API key is present, VT integration is treated as disabled
        and sandbox results remain purely local.
        """
        config = {
            'enabled': False,
            'api_key': None,
            'timeout_seconds': 5,
            'only_hash': True  # we only ever query by hash here
        }

        # Env var takes precedence
        api_key = os.environ.get('VT_API_KEY')
        if api_key:
            config['enabled'] = True
            config['api_key'] = api_key.strip()
            return config

        # Fallback: JSON config file
        try:
            if os.path.exists(self.vt_config_file):
                with open(self.vt_config_file, 'r') as f:
                    file_cfg = json.load(f) or {}
                    if file_cfg.get('api_key'):
                        config.update({
                            'enabled': bool(file_cfg.get('enabled', True)),
                            'api_key': file_cfg.get('api_key'),
                            'timeout_seconds': int(file_cfg.get('timeout_seconds', 5)),
                            'only_hash': bool(file_cfg.get('only_hash', True))
                        })
        except Exception as e:
            print(f"[FILE_ANALYZER] VT config load error: {e}")

        return config
    
    def get_file_hash(self, filepath: str) -> Dict[str, str]:
        """Calculate file hashes"""
        hashes = {}
        try:
            with open(filepath, 'rb') as f:
                data = f.read()
                hashes['md5'] = hashlib.md5(data).hexdigest()
                hashes['sha256'] = hashlib.sha256(data).hexdigest()
        except Exception as e:
            print(f"[FILE_ANALYZER] Hash error: {e}")
        return hashes
    
    def get_file_type(self, filepath: str) -> str:
        """Detect file type (cross-platform)"""
        try:
            # Try mimetypes first (cross-platform)
            mime_type, _ = mimetypes.guess_type(filepath)
            if mime_type:
                return mime_type
            
            # Unix systems: try 'file' command
            if platform.system() in ['Linux', 'Darwin'] and shutil.which('file'):
                result = subprocess.run(['file', '-b', filepath], 
                                      capture_output=True, text=True, timeout=2)
                if result.returncode == 0:
                    return result.stdout.strip()[:100]
            
            # Fallback: check extension
            ext = os.path.splitext(filepath)[1].lower()
            ext_types = {
                '.txt': 'text/plain',
                '.pdf': 'application/pdf',
                '.exe': 'application/x-executable',
                '.dll': 'application/x-dll',
                '.sh': 'application/x-sh',
                '.py': 'text/x-python',
                '.js': 'text/javascript'
            }
            return ext_types.get(ext, 'application/octet-stream')
        except:
            return 'unknown'

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of file contents.

        High entropy binaries can indicate packed or encrypted payloads.
        """
        if not data:
            return 0.0

        byte_counts = [0] * 256
        for b in data:
            byte_counts[b] += 1

        entropy = 0.0
        length = float(len(data))
        for count in byte_counts:
            if count:
                p = count / length
                entropy -= p * math.log2(p)
        return round(entropy, 3)

    def _extract_strings(self, data: bytes, min_len: int = 6, max_strings: int = 200) -> List[str]:
        """Extract printable strings from binary data.

        This helps detect embedded commands, URLs, or tool names without
        executing the file.
        """
        try:
            text = data.decode('latin-1', errors='ignore')
        except Exception:
            return []

        # Printable runs of length >= min_len
        candidates = re.findall(r"[ -~]{" + str(min_len) + ",}", text)
        if len(candidates) > max_strings:
            return candidates[:max_strings]
        return candidates

    def _static_deep_analysis(self, filepath: str, file_type: str) -> Dict:
        """Perform deeper static analysis without executing the file.

        Adds:
        - Entropy estimate (packed/encrypted hint)
        - Suspicious string indicators (commands, URLs, malware tooling)
        - Simple risk hints to complement the main verdict.
        """
        analysis: Dict = {
            'entropy': None,
            'entropy_label': None,
            'suspicious_indicators': [],
            'suspicious_strings_sample': []
        }

        try:
            with open(filepath, 'rb') as f:
                data = f.read()
        except Exception as e:
            print(f"[FILE_ANALYZER] Deep analysis read error: {e}")
            return analysis

        # Entropy
        entropy = self._calculate_entropy(data)
        analysis['entropy'] = entropy
        if entropy >= 7.5:
            analysis['entropy_label'] = 'high'
            analysis['suspicious_indicators'].append('High entropy payload (possible packing/encryption)')
        elif entropy >= 5.0:
            analysis['entropy_label'] = 'medium'
        else:
            analysis['entropy_label'] = 'low'

        # Strings and simple heuristics
        strings = self._extract_strings(data)
        analysis['suspicious_strings_sample'] = strings[:25]

        lower_strings = ' '.join(strings).lower()
        indicators = []

        # Common malware / LOLBin style indicators
        suspicious_keywords = [
            'powershell', 'cmd.exe', 'wscript', 'cscript',
            'reg add', 'reg delete', 'schtasks', 'taskschd',
            'vssadmin', 'shadow copy', 'rundll32',
            'shellcode', 'virtualalloc', 'virtualprotect',
            'downloadstring', 'invoke-webrequest', 'curl', 'wget',
            'base64', 'frombase64string',
        ]

        for kw in suspicious_keywords:
            if kw in lower_strings:
                indicators.append(f'Suspicious command/tool reference: {kw}')

        # URLs / external beacons
        url_hits = re.findall(r"https?://[a-zA-Z0-9._\-/:?=&%]+", lower_strings)
        if url_hits:
            indicators.append(f'Contains {len(url_hits)} HTTP/HTTPS URL(s) (possible beacon or C2)')

        # If this looks like an executable and entropy is high, highlight packing
        exec_hints = ['executable', 'pe32', '.exe', 'dll', 'application/x-executable']
        if any(h in file_type.lower() for h in exec_hints) and entropy >= 7.0:
            indicators.append('Executable with high entropy (possible packed malware)')

        if indicators:
            analysis['suspicious_indicators'].extend(indicators)

        return analysis

    def _query_virustotal(self, sha256: str) -> Dict:
        """Optional VirusTotal hash reputation lookup.

        This is strictly additive: if VT is not configured or unavailable,
        the sandbox still returns a valid local analysis and these fields
        simply indicate VT was not used.
        """
        vt_result: Dict = {
            'vt_enabled': False,
            'vt_queried': False,
            'vt_detected': False,
            'vt_positives': 0,
            'vt_engine_count': 0,
            'vt_malware_names': [],
            'vt_error': None
        }

        if not sha256:
            return vt_result

        if not self.vt_config.get('enabled') or not self.vt_config.get('api_key'):
            return vt_result

        if requests is None:
            vt_result['vt_error'] = 'requests library not available for VT lookup'
            return vt_result

        vt_result['vt_enabled'] = True

        try:
            url = f"https://www.virustotal.com/api/v3/files/{sha256}"
            headers = {"x-apikey": self.vt_config['api_key']}
            resp = requests.get(url, headers=headers, timeout=self.vt_config.get('timeout_seconds', 5))
            vt_result['vt_queried'] = True

            if resp.status_code == 404:
                # Unknown hash – treat as "no VT data", not safe/unsafe
                vt_result['vt_error'] = 'Hash not found in VirusTotal'
                return vt_result

            if resp.status_code != 200:
                vt_result['vt_error'] = f'VT HTTP {resp.status_code}'
                return vt_result

            data = resp.json()
            attrs = (data.get('data') or {}).get('attributes') or {}
            stats = attrs.get('last_analysis_stats') or {}
            results = attrs.get('last_analysis_results') or {}

            malicious = int(stats.get('malicious', 0))
            suspicious = int(stats.get('suspicious', 0))
            harmless = int(stats.get('harmless', 0))
            undetected = int(stats.get('undetected', 0))

            vt_result['vt_positives'] = malicious + suspicious
            vt_result['vt_engine_count'] = malicious + suspicious + harmless + undetected
            vt_result['vt_detected'] = vt_result['vt_positives'] > 0

            # Collect a small set of malware names / labels
            names: List[str] = []
            for engine, res in results.items():
                label = res.get('result')
                if label:
                    names.append(str(label))
                if len(names) >= 10:
                    break
            vt_result['vt_malware_names'] = names

        except Exception as e:
            vt_result['vt_error'] = f'VT lookup error: {e}'

        return vt_result
    
    def analyze_file(self, filepath: str, filename: str) -> Dict:
        """Analyze uploaded file"""
        # Get file info
        file_size = os.path.getsize(filepath)
        # Enforce maximum size inside the analyzer as a second safety net
        if file_size > self.max_size_bytes:
            return {
                'success': False,
                'verdict': 'too_large',
                'filename': filename,
                'file_size': f"{file_size / (1024*1024):.2f} MB",
                'error': 'File too large for sandbox analysis'
            }

        self.stats['analyzed'] += 1
        
        file_type = self.get_file_type(filepath)
        hashes = self.get_file_hash(filepath)
        deep = self._static_deep_analysis(filepath, file_type)
        vt = self._query_virustotal(hashes.get('sha256', ''))
        
        # Basic threat detection
        verdict = 'clean'
        threats_detected = 0
        analysis_notes = []
        
        # Check file type for suspicious patterns
        suspicious_types = ['executable', 'script', 'PE32', '.exe', 'batch', 'powershell']
        if any(s.lower() in file_type.lower() for s in suspicious_types):
            verdict = 'suspicious'
            threats_detected += 1
            analysis_notes.append('Executable file type detected')
            self.stats['suspicious'] += 1
        else:
            self.stats['clean'] += 1
        
        # Check for known malicious hashes (load from threat intel if available)
        if self.check_hash_reputation(hashes['sha256']):
            verdict = 'malicious'
            threats_detected += 1
            analysis_notes.append('Hash matches known malware')
            self.stats['malicious'] += 1
            self.stats['suspicious'] = max(0, self.stats['suspicious'] - 1)  # Reclassify
        
        self.save_stats()
        
        result = {
            'success': True,
            'verdict': verdict,
            'filename': filename,
            'file_size': f"{file_size / 1024:.2f} KB" if file_size < 1024*1024 else f"{file_size / (1024*1024):.2f} MB",
            'file_type': file_type,
            'md5': hashes.get('md5', 'N/A'),
            'sha256': hashes.get('sha256', 'N/A'),
            'threats_detected': threats_detected,
            'analysis_notes': analysis_notes,
            'analysis_time': '< 1 second'
        }

        # Merge deep static analysis metadata (non-breaking extra fields)
        result.update(deep)
        # Merge optional VirusTotal metadata (also non-breaking)
        result.update(vt)
        return result
    
    def check_hash_reputation(self, sha256: str) -> bool:
        """Check if hash is known malicious (checks local threat intel)"""
        try:
            # Check if hash exists in threat log
            sig_file = os.path.join(os.path.dirname(__file__), '..', 'relay', 'ai_training_materials', 'ai_signatures', 'learned_signatures.json')
            if os.path.exists(sig_file):
                with open(sig_file, 'r') as f:
                    data = json.load(f)
                    # This is a simplified check - would need proper hash database
                    if sha256 in str(data):
                        return True
        except:
            pass
        return False
    
    def get_stats(self) -> Dict:
        """Get analysis statistics"""
        return self.stats

# Global instance
file_analyzer = FileAnalyzer()
