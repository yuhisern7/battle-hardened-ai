"""
File Rotation Utility for ML Training Logs

Implements automatic file rotation when files reach 100MB size limit.
When a file reaches ~100MB, it's renamed with a numeric suffix (_1, _2, _3, etc.)
and a new file is created.

This applies to ML training files that continuously log attacks:
- threat_log.json (local customer)
- comprehensive_audit.json (local customer)
- global_attacks.json (relay server - SANITIZED patterns only)

Usage:
    from file_rotation import rotate_if_needed

    # Example: rotate the main threat log resolved via AI.path_helper
    # from AI.path_helper import get_threat_log_file
    # rotate_if_needed(get_threat_log_file())
"""

import os
import json
import logging
from typing import Optional
from pathlib import Path

logger = logging.getLogger(__name__)

# 100MB in bytes (optimized for 1GB VPS servers - prevents memory issues)
MAX_FILE_SIZE = 100_000_000  # ~100MB
SIZE_CHECK_THRESHOLD = 95_000_000  # Start checking at 95MB

def get_file_size(filepath: str) -> int:
    """Get file size in bytes."""
    try:
        if os.path.exists(filepath):
            return os.path.getsize(filepath)
        return 0
    except Exception as e:
        logger.warning(f"[ROTATION] Failed to get size for {filepath}: {e}")
        return 0


def find_next_rotation_number(base_filepath: str) -> int:
    """Find the next available rotation number for a file.
    
    Example:
        If threat_log_1.json and threat_log_2.json exist,
        returns 3 for threat_log_3.json
    """
    directory = os.path.dirname(base_filepath)
    filename = os.path.basename(base_filepath)
    name, ext = os.path.splitext(filename)
    
    rotation_num = 1
    while True:  # Infinite rotation support
        rotated_name = f"{name}_{rotation_num}{ext}"
        rotated_path = os.path.join(directory, rotated_name)
        
        if not os.path.exists(rotated_path):
            return rotation_num
        
        rotation_num += 1


def rotate_file(filepath: str) -> Optional[str]:
    """Rotate a file by renaming it with a numeric suffix.
    
    Args:
        filepath: Path to the file to rotate
        
    Returns:
        Path to the rotated file, or None if rotation failed
        
    Example:
        threat_log.json → threat_log_1.json
        If threat_log_1.json exists → threat_log_2.json
    """
    try:
        if not os.path.exists(filepath):
            logger.debug(f"[ROTATION] File doesn't exist, no rotation needed: {filepath}")
            return None
            
        directory = os.path.dirname(filepath)
        filename = os.path.basename(filepath)
        name, ext = os.path.splitext(filename)
        
        # Find next available rotation number
        rotation_num = find_next_rotation_number(filepath)
        
        # Create rotated filename
        rotated_name = f"{name}_{rotation_num}{ext}"
        rotated_path = os.path.join(directory, rotated_name)
        
        # Rename file
        os.rename(filepath, rotated_path)
        
        file_size_mb = get_file_size(rotated_path) / 1_000_000
        logger.info(f"[ROTATION] Rotated {filename} → {rotated_name} ({file_size_mb:.1f} MB)")
        
        return rotated_path
        
    except Exception as e:
        logger.error(f"[ROTATION] Failed to rotate {filepath}: {e}")
        return None


def rotate_if_needed(filepath: str) -> bool:
    """Check if file needs rotation and rotate if necessary.
    
    Args:
        filepath: Path to check and potentially rotate
        
    Returns:
        True if file was rotated, False otherwise
    """
    try:
        file_size = get_file_size(filepath)
        
        # Only rotate if file exists and is >= 1GB
        if file_size >= MAX_FILE_SIZE:
            file_size_mb = file_size / 1_000_000
            logger.warning(
                f"[ROTATION] File {os.path.basename(filepath)} reached "
                f"{file_size_mb:.1f} MB (limit: {MAX_FILE_SIZE/1_000_000:.0f} MB), rotating..."
            )
            
            rotated_path = rotate_file(filepath)
            
            if rotated_path:
                logger.info(f"[ROTATION] Successfully rotated to {os.path.basename(rotated_path)}")
                return True
            else:
                logger.error(f"[ROTATION] Failed to rotate {filepath}")
                return False
                
        return False
        
    except Exception as e:
        logger.error(f"[ROTATION] Error checking rotation for {filepath}: {e}")
        return False


def get_rotation_status(filepath: str) -> dict:
    """Get rotation status for a file.
    
    Returns:
        Dictionary with file size, rotation info, and status
    """
    try:
        file_size = get_file_size(filepath)
        file_size_mb = file_size / 1_000_000
        file_size_gb = file_size / 1_000_000_000
        
        # Find existing rotations
        directory = os.path.dirname(filepath)
        filename = os.path.basename(filepath)
        name, ext = os.path.splitext(filename)
        
        rotations = []
        rotation_num = 1
        while rotation_num <= 100:  # Check up to 100 rotations
            rotated_name = f"{name}_{rotation_num}{ext}"
            rotated_path = os.path.join(directory, rotated_name)
            
            if os.path.exists(rotated_path):
                rotated_size = get_file_size(rotated_path)
                rotations.append({
                    'filename': rotated_name,
                    'size_mb': rotated_size / 1_000_000,
                    'size_gb': rotated_size / 1_000_000_000
                })
                rotation_num += 1
            else:
                break
        
        needs_rotation = file_size >= MAX_FILE_SIZE
        percentage_full = (file_size / MAX_FILE_SIZE) * 100
        
        return {
            'filepath': filepath,
            'exists': os.path.exists(filepath),
            'current_size_mb': file_size_mb,
            'current_size_gb': file_size_gb,
            'max_size_gb': MAX_FILE_SIZE / 1_000_000_000,
            'percentage_full': min(percentage_full, 100.0),
            'needs_rotation': needs_rotation,
            'rotated_files_count': len(rotations),
            'rotated_files': rotations,
            'total_size_gb': file_size_gb + sum(r['size_gb'] for r in rotations)
        }
        
    except Exception as e:
        logger.error(f"[ROTATION] Error getting status for {filepath}: {e}")
        return {
            'filepath': filepath,
            'error': str(e)
        }


# NO CLEANUP FUNCTION - ML TRAINING LOGS MUST BE PRESERVED
# All rotation files contain historical attack data needed for machine learning.
# Deleting rotation files would cause the AI to "forget" previously learned attacks.
# If storage is a concern, archive rotation files to cold storage instead of deleting.


def load_all_rotations(base_filepath: str) -> list:
    """Load data from base file AND all rotation files (infinite rotation support).
    
    This is critical for ML training, compliance reporting, and analysis.
    The AI needs access to ALL historical attack data, not just the current file.
    
    Args:
        base_filepath: Path to the base JSON file (for example, the
            threat_log.json file returned by AI.path_helper.get_threat_log_file()).
        
    Returns:
        Combined list of all entries from base file + all rotation files (_1, _2, _3, ...)
        Supports infinite rotations - will load threat_log_1.json through threat_log_999999.json etc.
        
    Example:
        # Load ALL threat logs (threat_log.json + threat_log_1.json + threat_log_2.json + ...)
        # from AI.path_helper import get_threat_log_file
        # all_threats = load_all_rotations(get_threat_log_file())
        # Returns complete attack history for ML training
    """
    all_data = []
    
    try:
        # Load base file first
        if os.path.exists(base_filepath):
            with open(base_filepath, 'r') as f:
                data = json.load(f)
                if isinstance(data, list):
                    all_data.extend(data)
                    logger.info(f"[ROTATION] Loaded {os.path.basename(base_filepath)}: {len(data)} entries")
                elif isinstance(data, dict) and 'events' in data:
                    # Handle comprehensive_audit.json format
                    all_data.extend(data['events'])
                    logger.info(f"[ROTATION] Loaded {os.path.basename(base_filepath)}: {len(data['events'])} entries")
        
        # Load all rotation files
        directory = os.path.dirname(base_filepath)
        filename = os.path.basename(base_filepath)
        name, ext = os.path.splitext(filename)
        
        rotation_num = 1
        while True:  # Infinite rotation support
            rotated_name = f"{name}_{rotation_num}{ext}"
            rotated_path = os.path.join(directory, rotated_name)
            
            if os.path.exists(rotated_path):
                with open(rotated_path, 'r') as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        all_data.extend(data)
                        logger.info(f"[ROTATION] Loaded {rotated_name}: {len(data)} entries")
                    elif isinstance(data, dict) and 'events' in data:
                        # Handle comprehensive_audit.json format
                        all_data.extend(data['events'])
                        logger.info(f"[ROTATION] Loaded {rotated_name}: {len(data['events'])} entries")
                rotation_num += 1
            else:
                break  # No more rotation files
        
        logger.info(f"[ROTATION] Total entries loaded from all files: {len(all_data)}")
        
    except Exception as e:
        logger.error(f"[ROTATION] Error loading rotation files for {base_filepath}: {e}")
    
    return all_data
