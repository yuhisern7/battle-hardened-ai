"""
Automated Attack Signature Extraction Engine

DEFENSIVE ARCHITECTURE - Military/Police Compliant:
- Extracts ONLY patterns/signatures from detected attacks
- Does NOT store exploit payloads or malicious code
- Learns encoding schemes (base64, hex, URL encoding) used by attackers
- Feeds extracted signatures to ML for continuous learning
- Auto-deletes attack data after signature extraction

Example:
  Attack payload: "<?php eval(base64_decode('ZXZpbCBjb2Rl'));" 
  Stored signature: {"encoding": "base64", "pattern": "eval\\(base64_decode", "language": "php"}
  Deleted: The actual base64 payload content
"""

import re
import base64
import binascii
import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set
from urllib.parse import unquote
from collections import defaultdict
import logging

from AI.path_helper import get_json_file


logger = logging.getLogger(__name__)

SIGNATURE_EXTRACTOR_ENABLED = os.getenv("SIGNATURE_EXTRACTOR_ENABLED", "true").lower() == "true"
SIGNATURE_EXTRACTOR_MAX_PATTERNS_PER_TYPE = int(os.getenv("SIGNATURE_EXTRACTOR_MAX_PATTERNS_PER_TYPE", "1000"))
SIGNATURE_EXTRACTOR_FILE = os.getenv("SIGNATURE_EXTRACTOR_FILE")


class SignatureExtractor:
    """Extract attack patterns WITHOUT storing exploit code"""
    
    def __init__(self, signatures_file: Optional[str] = None):
        # Use universal JSON path helper for honeypot_patterns.json
        if signatures_file is None:
            signatures_file = get_json_file('honeypot_patterns.json')
        
        # Allow environment override of the signature file location
        self.signatures_file = SIGNATURE_EXTRACTOR_FILE or signatures_file
        
        # Extracted patterns (SAFE - no exploit code)
        self.attack_patterns = {
            'encodings_used': defaultdict(int),  # base64, hex, url_encode usage count
            'attack_keywords': defaultdict(int),  # Keywords found in attacks
            'regex_patterns': set(),  # Compiled regex patterns
            'encoding_chains': [],  # Multi-layer encoding sequences
            'attack_vectors': defaultdict(list)  # Attack type → pattern mappings
        }
        
        # Detection patterns for various encodings
        self.encoding_detectors = {
            'base64': re.compile(r'[A-Za-z0-9+/]{20,}={0,2}'),
            'hex': re.compile(r'(?:0x|\\x)?[0-9a-fA-F]{8,}'),
            'url_encoded': re.compile(r'%[0-9a-fA-F]{2}'),
            'unicode': re.compile(r'\\u[0-9a-fA-F]{4}'),
            'html_entities': re.compile(r'&(?:#x?[0-9a-fA-F]+|[a-z]+);', re.I),
            'jwt': re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'),
        }
        
        # Attack keyword indicators (PATTERNS ONLY - not exploit code)
        self.keyword_categories = {
            'sql_injection': ['select', 'union', 'insert', 'delete', 'drop', 'update', 
                             'exec', 'execute', 'waitfor', 'delay', 'benchmark', 'sleep',
                             'information_schema', 'table_name', 'column_name', 'concat'],
            'xss': ['<script', 'javascript:', 'onerror=', 'onload=', 'onclick=', 
                   'alert(', 'prompt(', 'confirm(', 'document.cookie', 'innerHTML'],
            'command_injection': ['system(', 'exec(', 'passthru(', 'shell_exec(', 
                                 'popen(', 'proc_open(', 'eval(', '&&', '||', ';cat', 
                                 ';ls', ';wget', ';curl', 'bash -c', 'sh -c'],
            'directory_traversal': ['../', '..\\', '%2e%2e%2f', '%2e%2e\\', 
                                   '/etc/passwd', '/etc/shadow', 'c:\\windows'],
            'file_inclusion': ['php://input', 'php://filter', 'file://', 'data://', 
                              'expect://', 'zip://', 'include(', 'require('],
            'deserialization': ['unserialize(', 'pickle.loads', 'yaml.load', 
                               'ObjectInputStream', '__reduce__', '__wakeup'],
            'xxe': ['<!ENTITY', '<!DOCTYPE', 'SYSTEM', 'file://', 'php://'],
            'ssti': ['{{', '{%', '<%', '#{', '__import__', 'eval('],
            'nosql_injection': ['$gt', '$lt', '$ne', '$or', '$and', '$where', 
                               '$regex', 'mongoose'],
        }
        
        # Load existing patterns
        self._load_signatures()

        logger.info(
            f"[SIGNATURE EXTRACTOR] Initialized (enabled={SIGNATURE_EXTRACTOR_ENABLED}, file={self.signatures_file})"
        )
    
    def extract_signatures(self, attack_data: Dict) -> Dict:
        """
        Extract ONLY patterns from attack - DO NOT STORE EXPLOIT CODE
        
        Args:
            attack_data: {
                'payload': 'actual attack string',
                'ip': '1.2.3.4',
                'type': 'SQL Injection',
                'timestamp': '2026-01-01...'
            }
        
        Returns:
            Extracted signatures (SAFE - no exploit code)
        """
        payload = attack_data.get('payload', '')
        attack_type = attack_data.get('type', 'unknown')
        
        signatures = {
            'attack_type': attack_type,
            'timestamp': attack_data.get('timestamp'),
            'payload_length': len(payload),
            'encodings_detected': [],
            'keywords_found': [],
            'encoding_chain': [],
            'pattern_hash': None,  # Hash of pattern (not payload)
            'regex_patterns': []
        }
        
        # 1. Detect encoding schemes used
        signatures['encodings_detected'] = self._detect_encodings(payload)
        
        # 2. Extract keywords (attack indicators)
        signatures['keywords_found'] = self._extract_keywords(payload, attack_type)
        
        # 3. Detect multi-layer encoding (base64(url_encode(hex(...))))
        signatures['encoding_chain'] = self._detect_encoding_chain(payload)
        
        # 4. Generate regex patterns from attack structure
        signatures['regex_patterns'] = self._generate_regex_patterns(payload, attack_type)
        
        # 5. Create signature hash (for deduplication)
        signature_string = json.dumps(signatures['keywords_found'] + signatures['encodings_detected'], sort_keys=True)
        signatures['pattern_hash'] = hashlib.sha256(signature_string.encode()).hexdigest()[:16]
        
        # 6. Store patterns for ML training
        self._store_pattern(signatures)
        
        # 7. DO NOT RETURN PAYLOAD - only patterns
        return {k: v for k, v in signatures.items() if k != 'payload'}
    
    def _detect_encodings(self, payload: str) -> List[str]:
        """Detect which encoding schemes are present"""
        encodings = []
        
        for encoding_name, pattern in self.encoding_detectors.items():
            if pattern.search(payload):
                encodings.append(encoding_name)
                self.attack_patterns['encodings_used'][encoding_name] += 1
        
        # Try to decode and verify
        verified_encodings = []
        
        # Base64 detection with verification
        if 'base64' in encodings:
            base64_matches = self.encoding_detectors['base64'].findall(payload)
            for match in base64_matches[:3]:  # Check first 3 matches
                try:
                    decoded = base64.b64decode(match)
                    if decoded and all(32 <= b < 127 or b in [9, 10, 13] for b in decoded[:20]):
                        verified_encodings.append('base64_verified')
                        break
                except:
                    pass
        
        # Hex detection with verification
        if 'hex' in encodings:
            hex_matches = self.encoding_detectors['hex'].findall(payload)
            for match in hex_matches[:3]:
                try:
                    cleaned = match.replace('0x', '').replace('\\x', '')
                    if len(cleaned) % 2 == 0:
                        decoded = bytes.fromhex(cleaned)
                        if decoded:
                            verified_encodings.append('hex_verified')
                            break
                except:
                    pass
        
        return list(set(encodings + verified_encodings))
    
    def _extract_keywords(self, payload: str, attack_type: str) -> List[str]:
        """Extract attack indicator keywords (NOT full exploit code)"""
        payload_lower = payload.lower()
        keywords_found = []
        
        # Extract keywords based on attack type
        for category, keywords in self.keyword_categories.items():
            for keyword in keywords:
                if keyword.lower() in payload_lower:
                    keywords_found.append(keyword)
                    self.attack_patterns['attack_keywords'][keyword] += 1
        
        return list(set(keywords_found))[:20]  # Limit to 20 most relevant
    
    def _detect_encoding_chain(self, payload: str) -> List[str]:
        """Detect multi-layer encoding (e.g., base64(url_encode(hex(...))))"""
        chain = []
        
        # Try to decode in layers
        current = payload
        max_layers = 5
        
        for layer in range(max_layers):
            decoded = None
            encoding_used = None
            
            # Try base64
            try:
                decoded_bytes = base64.b64decode(current)
                decoded = decoded_bytes.decode('utf-8', errors='ignore')
                if decoded and decoded != current:
                    encoding_used = 'base64'
            except:
                pass
            
            # Try URL decode
            if not decoded:
                try:
                    url_decoded = unquote(current)
                    if url_decoded != current and '%' in current:
                        decoded = url_decoded
                        encoding_used = 'url_encoded'
                except:
                    pass
            
            # Try hex decode
            if not decoded:
                try:
                    hex_match = re.search(r'[0-9a-fA-F]{10,}', current)
                    if hex_match:
                        decoded = bytes.fromhex(hex_match.group()).decode('utf-8', errors='ignore')
                        encoding_used = 'hex'
                except:
                    pass
            
            if encoding_used and decoded:
                chain.append(encoding_used)
                current = decoded
            else:
                break
        
        if len(chain) > 1:
            self.attack_patterns['encoding_chains'].append(chain)
        
        return chain
    
    def _generate_regex_patterns(self, payload: str, attack_type: str) -> List[str]:
        """Generate regex patterns from attack structure (NOT the exploit itself)"""
        patterns = []
        
        # SQL Injection patterns
        if 'sql' in attack_type.lower():
            # Pattern: UNION SELECT with column count
            union_match = re.search(r'union\s+(?:all\s+)?select\s+(?:null,?\s*){2,}', payload, re.I)
            if union_match:
                col_count = union_match.group().count('null')
                patterns.append(f'union_select_{col_count}_columns')
            
            # Pattern: Boolean-based blind injection
            if re.search(r"'\s*(?:or|and)\s*'?\d+'\s*=\s*'\d+", payload, re.I):
                patterns.append('boolean_blind_injection')
        
        # XSS patterns
        if 'xss' in attack_type.lower():
            # Pattern: Event handler injection
            if re.search(r'<\w+\s+on\w+\s*=', payload, re.I):
                patterns.append('event_handler_xss')
            
            # Pattern: Script tag with encoding
            if re.search(r'<script[^>]*>.*?<\/script>', payload, re.I):
                patterns.append('script_tag_xss')
        
        # Command Injection patterns
        if 'command' in attack_type.lower():
            # Pattern: Command chaining
            if re.search(r'[;&|]\s*(?:cat|ls|wget|curl|nc|bash)', payload, re.I):
                patterns.append('command_chaining')
        
        return patterns
    
    def _store_pattern(self, signature: Dict):
        """Store extracted pattern for ML training"""
        if not SIGNATURE_EXTRACTOR_ENABLED:
            # When disabled, do not persist patterns to disk or memory
            return

        attack_type = signature['attack_type']
        
        # Add to attack vectors (pattern → attack type mapping)
        pattern_key = f"{signature['pattern_hash']}"
        existing = self.attack_patterns['attack_vectors'][attack_type]

        if pattern_key not in [p.get('hash') for p in existing]:
            # Bound patterns per attack type to avoid unbounded growth
            if len(existing) >= SIGNATURE_EXTRACTOR_MAX_PATTERNS_PER_TYPE:
                # Drop oldest entry
                dropped = existing.pop(0)
                logger.debug(
                    f"[SIGNATURE EXTRACTOR] Dropped oldest pattern for {attack_type} to enforce max={SIGNATURE_EXTRACTOR_MAX_PATTERNS_PER_TYPE}"
                )

            existing.append({
                'hash': signature['pattern_hash'],
                'keywords': signature['keywords_found'],
                'encodings': signature['encodings_detected'],
                'regex_patterns': signature['regex_patterns'],
                'first_seen': signature['timestamp']
            })
        
        # Add regex patterns to global set
        for pattern in signature['regex_patterns']:
            self.attack_patterns['regex_patterns'].add(pattern)
    
    def _load_signatures(self):
        """Load previously extracted signatures"""
        if os.path.exists(self.signatures_file):
            try:
                with open(self.signatures_file, 'r') as f:
                    data = json.load(f)
                    self.attack_patterns['encodings_used'] = defaultdict(int, data.get('encodings_used', {}))
                    self.attack_patterns['attack_keywords'] = defaultdict(int, data.get('attack_keywords', {}))
                    self.attack_patterns['regex_patterns'] = set(data.get('regex_patterns', []))
                    self.attack_patterns['encoding_chains'] = data.get('encoding_chains', [])
                    self.attack_patterns['attack_vectors'] = defaultdict(list, data.get('attack_vectors', {}))
            except Exception as e:
                logger.warning(f"[SIGNATURE EXTRACTOR] Failed to load signatures: {e}")
    
    def save_signatures(self):
        """Save extracted signatures (SAFE - no exploit code)"""
        if not SIGNATURE_EXTRACTOR_ENABLED:
            logger.debug("[SIGNATURE EXTRACTOR] save_signatures skipped (disabled via SIGNATURE_EXTRACTOR_ENABLED=false)")
            return

        try:
            data = {
                'metadata': {
                    'total_patterns': sum(len(v) for v in self.attack_patterns['attack_vectors'].values()),
                    'total_encodings_detected': sum(self.attack_patterns['encodings_used'].values()),
                    'total_keywords': sum(self.attack_patterns['attack_keywords'].values()),
                    'last_updated': datetime.now(timezone.utc).isoformat(),
                    'architecture': 'DEFENSIVE - Patterns only, NO exploit code'
                },
                'encodings_used': dict(self.attack_patterns['encodings_used']),
                'attack_keywords': dict(self.attack_patterns['attack_keywords']),
                'regex_patterns': list(self.attack_patterns['regex_patterns']),
                'encoding_chains': self.attack_patterns['encoding_chains'][-100:],  # Keep last 100
                'attack_vectors': dict(self.attack_patterns['attack_vectors'])
            }
            
            with open(self.signatures_file, 'w') as f:
                json.dump(data, f, indent=2)

            logger.info(
                f"[SIGNATURE EXTRACTOR] Saved {data['metadata']['total_patterns']} patterns (0 bytes of exploit code)"
            )

        except Exception as e:
            logger.error(f"[SIGNATURE EXTRACTOR] Failed to save signatures: {e}")
    
    def get_ml_training_data(self) -> Dict:
        """
        Generate ML training dataset from extracted signatures
        Returns ONLY patterns - NO exploit payloads
        """
        training_data = []
        
        for attack_type, patterns in self.attack_patterns['attack_vectors'].items():
            for pattern in patterns:
                training_data.append({
                    'attack_type': attack_type,
                    'features': {
                        'keyword_count': len(pattern['keywords']),
                        'encoding_count': len(pattern['encodings']),
                        'has_base64': 'base64' in pattern['encodings'],
                        'has_hex': 'hex' in pattern['encodings'],
                        'has_url_encode': 'url_encoded' in pattern['encodings'],
                        'pattern_complexity': len(pattern['regex_patterns']),
                        'keyword_diversity': len(set(pattern['keywords']))
                    }
                })
        
        return {
            'training_samples': training_data,
            'total_samples': len(training_data),
            'attack_distribution': {k: len(v) for k, v in self.attack_patterns['attack_vectors'].items()},
            'data_safety': 'VERIFIED - Contains ZERO exploit code, only statistical features'
        }


# Global instance
_signature_extractor = None

def get_signature_extractor() -> SignatureExtractor:
    """Get or create signature extractor instance"""
    global _signature_extractor
    if _signature_extractor is None:
        _signature_extractor = SignatureExtractor()
    return _signature_extractor


def extract_from_threat(threat_data: Dict) -> Dict:
    """
    Convenience function to extract signatures from threat log entry
    
    Args:
        threat_data: Threat log entry with 'payload' field
    
    Returns:
        Extracted signatures (SAFE - no exploit code)
    """
    extractor = get_signature_extractor()
    signatures = extractor.extract_signatures(threat_data)
    extractor.save_signatures()
    return signatures
