"""
System Log Collector - Multi-OS Log Aggregation

Collects and parses system logs from Linux, Windows, and macOS including:
- System crashes and panics
- Security events
- Application errors
- Authentication failures
- Kernel messages
- Service failures

Supports:
- Linux: /var/log/syslog, journalctl, dmesg, auth.log
- Windows: Event Viewer (System, Security, Application)
- macOS: unified logging system, /var/log/system.log
"""

import os
import platform
import subprocess
import json
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any
from collections import defaultdict

logger = logging.getLogger(__name__)

# Feature flag so operators can disable system log collection without code changes
SYSTEM_LOG_COLLECTION_ENABLED = os.getenv("SYSTEM_LOG_COLLECTION_ENABLED", "true").lower() == "true"


class SystemLogCollector:
    """Collect and parse system logs from multiple operating systems."""
    
    def __init__(self, max_entries: int = 500):
        """
        Initialize system log collector.
        
        Args:
            max_entries: Maximum log entries to collect per source
        """
        self.max_entries = max_entries
        self.os_type = platform.system()  # 'Linux', 'Windows', 'Darwin' (macOS)
        self.enabled = SYSTEM_LOG_COLLECTION_ENABLED
        
        if self.enabled:
            logger.info(f"[SYSTEM_LOGS] Initialized for {self.os_type} (collection enabled)")
        else:
            logger.info(f"[SYSTEM_LOGS] Initialized for {self.os_type} (collection DISABLED via SYSTEM_LOG_COLLECTION_ENABLED=false)")

    def _empty_logs(self, message: Optional[str] = None) -> Dict:
        """Return an empty log structure, optionally with a single info entry."""
        logs: Dict[str, Any] = {
            "crashes": [],
            "security": [],
            "authentication": [],
            "kernel": [],
            "services": [],
            "errors": [],
            "total_count": 0,
        }
        if message:
            logs["errors"].append({
                "timestamp": datetime.now().isoformat(),
                "message": message,
                "severity": "info",
            })
            logs["total_count"] = 1
        return logs
    
    def collect_linux_logs(self, hours: int = 168) -> Dict:
        """
        Collect Linux system logs from multiple sources.
        
        Args:
            hours: Hours of history to collect (default 7 days)
        
        Returns:
            Dict with categorized log entries
        """
        # Clamp hours to a safe window (1 hour – 30 days)
        hours = max(1, min(int(hours), 24 * 30))

        if not self.enabled:
            return self._empty_logs("System log collection disabled by SYSTEM_LOG_COLLECTION_ENABLED=false")

        logs = {
            "crashes": [],
            "security": [],
            "authentication": [],
            "kernel": [],
            "services": [],
            "errors": [],
            "total_count": 0,
        }
        
        try:
            # 1. System crashes and kernel panics (dmesg) - works in containers
            try:
                result = subprocess.run(['dmesg', '-T'], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    crash_keywords = ['panic', 'oops', 'bug', 'crash', 'segfault', 'killed', 'exception', 'error']
                    for line in result.stdout.splitlines()[-self.max_entries:]:
                        line_lower = line.lower()
                        if any(keyword in line_lower for keyword in crash_keywords):
                            logs["errors"].append({
                                "timestamp": self._extract_timestamp(line),
                                "message": line[:300],
                                "severity": "critical" if 'panic' in line_lower or 'oops' in line_lower else "error"
                            })
            except Exception as e:
                logger.debug(f"[LINUX_LOGS] dmesg not available: {e}")
            
            # 2. Check if running in Docker - collect container-specific logs
            in_container = os.path.exists('/.dockerenv') or os.path.exists('/app')
            
            if in_container:
                # Container mode - collect Python app logs and Docker-visible errors
                logs["errors"].append({
                    "timestamp": datetime.now().isoformat(),
                    "message": "Running in Docker container - showing container-level logs and kernel messages from dmesg",
                    "severity": "info"
                })
                
                # Check for recent Python errors in current process
                try:
                    log_file = '/app/server/logs/app.log' if os.path.exists('/app/server/logs') else None
                    if log_file and os.path.exists(log_file):
                        with open(log_file, 'r') as f:
                            for line in f.readlines()[-100:]:
                                if 'ERROR' in line or 'CRITICAL' in line or 'Exception' in line:
                                    logs["errors"].append({
                                        "timestamp": self._extract_timestamp(line),
                                        "message": line.strip()[:300],
                                        "severity": "error"
                                    })
                except Exception as e:
                    logger.debug(f"[LINUX_LOGS] Cannot read app logs: {e}")
            
            else:
                # Host mode - full system log access
                # 2. journalctl for systemd logs (host only)
                try:
                    since_time = f"{hours}h ago"
                    result = subprocess.run(
                        ['journalctl', '--since', since_time, '--no-pager', '-n', str(self.max_entries)],
                        capture_output=True, text=True, timeout=10
                    )
                    if result.returncode == 0:
                        for line in result.stdout.splitlines():
                            line_lower = line.lower()
                            if 'failed' in line_lower or 'error' in line_lower:
                                logs["services"].append({
                                    "timestamp": self._extract_timestamp(line),
                                    "message": line.strip()[:300],
                                    "severity": "error"
                                })
                except Exception as e:
                    logger.debug(f"[LINUX_LOGS] journalctl not available: {e}")
                
                # 3. Authentication logs (host only)
                auth_files = ['/var/log/auth.log', '/var/log/secure']
                for auth_file in auth_files:
                    if os.path.exists(auth_file):
                        try:
                            with open(auth_file, 'r') as f:
                                lines = f.readlines()[-self.max_entries:]
                                for line in lines:
                                    if any(keyword in line.lower() for keyword in ['failed', 'authentication failure', 'invalid user']):
                                        logs["authentication"].append({
                                            "timestamp": self._extract_timestamp(line),
                                            "message": line.strip()[:300],
                                            "severity": "warning"
                                        })
                        except PermissionError:
                            logger.debug(f"[LINUX_LOGS] No permission to read {auth_file}")
                        break
            
            # Calculate total count
            logs["total_count"] = sum(len(logs[key]) for key in logs if key != "total_count")
            
        except Exception as e:
            logger.error(f"[LINUX_LOGS] Error collecting logs: {e}")
        
        return logs
    
    def collect_windows_logs(self, hours: int = 168) -> Dict:
        """
        Collect Windows Event Viewer logs using Get-WinEvent (works on all modern Windows).
        
        Args:
            hours: Hours of history to collect
        
        Returns:
            Dict with categorized log entries
        """
        # Clamp hours to a safe window (1 hour – 30 days)
        hours = max(1, min(int(hours), 24 * 30))

        if not self.enabled:
            return self._empty_logs("System log collection disabled by SYSTEM_LOG_COLLECTION_ENABLED=false")

        # If this node is not actually running on Windows (for example, a Linux
        # Docker container on a Windows host), we cannot access the local
        # Windows Event Log APIs from here. In that case, return a clear
        # informational message instead of trying to launch the `powershell`
        # binary and surfacing a confusing FileNotFoundError in the UI.
        if self.os_type != 'Windows':
            return self._empty_logs(
                f"Windows event log collection is only available when this node runs directly on Windows. "
                f"Current OS: {self.os_type}. If you're running inside a Linux container on Windows, "
                f"the Windows tab is informational only."
            )

        logs = {
            "crashes": [],
            "security": [],
            "authentication": [],
            "kernel": [],
            "services": [],
            "errors": [],
            "total_count": 0,
        }
        
        try:
            # Calculate start time
            start_time = datetime.now() - timedelta(hours=hours)
            start_time_str = start_time.strftime('%Y-%m-%dT%H:%M:%S')
            
            # Method 1: Try Get-WinEvent (modern, works on all Windows Vista+)
            ps_command = f"""
$StartTime = [DateTime]::Parse('{start_time_str}')
$Events = @()

# System log - crashes and critical errors
try {{
    $SystemEvents = Get-WinEvent -FilterHashtable @{{
        LogName = 'System'
        Level = 1,2,3
        StartTime = $StartTime
    }} -MaxEvents {self.max_entries} -ErrorAction SilentlyContinue
    $Events += $SystemEvents
}} catch {{}}

# Application log - application crashes
try {{
    $AppEvents = Get-WinEvent -FilterHashtable @{{
        LogName = 'Application'
        Level = 1,2
        StartTime = $StartTime
    }} -MaxEvents {min(self.max_entries, 100)} -ErrorAction SilentlyContinue
    $Events += $AppEvents
}} catch {{}}

# Security log - authentication failures (Event ID 4625, 4740, 4648)
try {{
    $SecEvents = Get-WinEvent -FilterHashtable @{{
        LogName = 'Security'
        ID = 4625,4740,4648
        StartTime = $StartTime
    }} -MaxEvents {min(self.max_entries, 100)} -ErrorAction SilentlyContinue
    $Events += $SecEvents
}} catch {{}}

# Format and output
$Events | Select-Object -First {self.max_entries} | ForEach-Object {{
    [PSCustomObject]@{{
        TimeCreated = $_.TimeCreated.ToString('o')
        Level = $_.LevelDisplayName
        LogName = $_.LogName
        Id = $_.Id
        Source = $_.ProviderName
        Message = ($_.Message -replace '[\\r\\n]+', ' ').Substring(0, [Math]::Min(300, $_.Message.Length))
    }}
}} | ConvertTo-Json -Compress
"""
            
            # Execute PowerShell with bypass execution policy
            result = subprocess.run(
                ['powershell', '-ExecutionPolicy', 'Bypass', '-NoProfile', '-Command', ps_command],
                capture_output=True, text=True, timeout=30, creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
            )
            
            if result.returncode == 0 and result.stdout.strip():
                try:
                    # Handle both single object and array
                    output = result.stdout.strip()
                    if output.startswith('['):
                        events = json.loads(output)
                    else:
                        events = [json.loads(output)]
                    
                    for event in events:
                        timestamp = event.get('TimeCreated', datetime.now().isoformat())
                        log_name = event.get('LogName', '')
                        event_id = event.get('Id', 0)
                        message = event.get('Message', '')
                        source = event.get('Source', 'Unknown')
                        
                        entry = {
                            "timestamp": timestamp,
                            "message": f"[{source}] EventID {event_id}: {message}",
                            "severity": event.get('Level', 'Error').lower()
                        }
                        
                        # Categorize based on log type and content
                        message_lower = message.lower()
                        
                        # Authentication failures
                        if log_name == 'Security' or event_id in [4625, 4740, 4648]:
                            logs["authentication"].append(entry)
                        # System crashes and critical errors
                        elif any(keyword in message_lower for keyword in ['crash', 'bugcheck', 'bsod', 'stop error', 'critical error', 'system failure']):
                            logs["crashes"].append(entry)
                        # Service failures
                        elif any(keyword in message_lower for keyword in ['service', 'terminated unexpectedly', 'failed to start']):
                            logs["services"].append(entry)
                        # Kernel/driver errors
                        elif any(keyword in message_lower for keyword in ['driver', 'kernel', 'ntoskrnl']):
                            logs["kernel"].append(entry)
                        # General errors
                        else:
                            logs["errors"].append(entry)
                    
                except json.JSONDecodeError as e:
                    logger.error(f"[WINDOWS_LOGS] JSON parse error: {e}")
                    logger.debug(f"[WINDOWS_LOGS] Output was: {result.stdout[:500]}")
            else:
                # Fallback: Try simpler command if Get-WinEvent fails
                logger.warning(f"[WINDOWS_LOGS] Get-WinEvent failed (exit {result.returncode}), using fallback")
                self._windows_fallback_method(logs, hours)
            
            logs["total_count"] = sum(len(logs[key]) for key in logs if key != "total_count")
            
        except Exception as e:
            logger.error(f"[WINDOWS_LOGS] Error collecting logs: {e}")
            logs["errors"].append({
                "timestamp": datetime.now().isoformat(),
                "message": f"Failed to collect Windows logs: {str(e)}. May require Administrator privileges.",
                "severity": "error"
            })
        
        return logs
    
    def _windows_fallback_method(self, logs: Dict, hours: int):
        """Fallback method using wevtutil (command-line tool)."""
        try:
            # Use wevtutil which is always available
            result = subprocess.run(
                ['wevtutil', 'qe', 'System', '/c:50', '/rd:true', '/f:text', '/q:*[System[(Level=1 or Level=2 or Level=3)]]'],
                capture_output=True, text=True, timeout=10
            )
            
            if result.returncode == 0:
                # Parse text output (basic parsing)
                current_event = {}
                for line in result.stdout.splitlines()[:200]:
                    line = line.strip()
                    if line.startswith('Event ID:'):
                        if current_event:
                            logs["errors"].append(current_event)
                        current_event = {
                            "timestamp": datetime.now().isoformat(),
                            "message": "",
                            "severity": "error"
                        }
                    if current_event and line:
                        current_event["message"] += line + " "
                
                if current_event:
                    logs["errors"].append(current_event)
                    
        except Exception as e:
            logger.debug(f"[WINDOWS_LOGS] Fallback also failed: {e}")
    
    def collect_macos_logs(self, hours: int = 168) -> Dict:
        """
        Collect macOS unified logging system logs.
        
        Args:
            hours: Hours of history to collect
        
        Returns:
            Dict with categorized log entries
        """
        # Clamp hours to a safe window (1 hour – 30 days)
        hours = max(1, min(int(hours), 24 * 30))

        if not self.enabled:
            return self._empty_logs("System log collection disabled by SYSTEM_LOG_COLLECTION_ENABLED=false")

        logs = {
            "crashes": [],
            "security": [],
            "authentication": [],
            "kernel": [],
            "services": [],
            "errors": [],
            "total_count": 0,
        }
        
        try:
            # Use `log show` command for unified logging
            since_time = (datetime.now() - timedelta(hours=hours)).strftime('%Y-%m-%d %H:%M:%S')
            
            result = subprocess.run(
                ['log', 'show', '--predicate', '(eventType == "logEvent" OR eventType == "faultEvent") AND (level == "error" OR level == "fault")',
                 '--start', since_time, '--style', 'json'],
                capture_output=True, text=True, timeout=20
            )
            
            if result.returncode == 0 and result.stdout.strip():
                for line in result.stdout.splitlines()[-self.max_entries:]:
                    try:
                        event = json.loads(line)
                        entry = {
                            "timestamp": event.get('timestamp', ''),
                            "message": f"[{event.get('process', 'Unknown')}] {event.get('eventMessage', '')[:200]}",
                            "severity": event.get('messageType', 'error').lower()
                        }
                        
                        # Categorize
                        message_lower = entry["message"].lower()
                        if any(keyword in message_lower for keyword in ['crash', 'panic', 'abort']):
                            logs["crashes"].append(entry)
                        elif any(keyword in message_lower for keyword in ['auth', 'login', 'password']):
                            logs["authentication"].append(entry)
                        elif 'kernel' in message_lower:
                            logs["kernel"].append(entry)
                        else:
                            logs["errors"].append(entry)
                    except json.JSONDecodeError:
                        pass
            
            # Crash reports
            crash_dir = os.path.expanduser('~/Library/Logs/DiagnosticReports')
            if os.path.exists(crash_dir):
                try:
                    crash_files = sorted(
                        [f for f in os.listdir(crash_dir) if f.endswith('.crash')],
                        key=lambda x: os.path.getmtime(os.path.join(crash_dir, x)),
                        reverse=True
                    )[:20]
                    
                    for crash_file in crash_files:
                        logs["crashes"].append({
                            "timestamp": datetime.fromtimestamp(
                                os.path.getmtime(os.path.join(crash_dir, crash_file))
                            ).isoformat(),
                            "message": f"Crash Report: {crash_file}",
                            "severity": "critical"
                        })
                except Exception as e:
                    logger.debug(f"[MACOS_LOGS] Cannot read crash reports: {e}")
            
            logs["total_count"] = sum(len(logs[key]) for key in logs if key != "total_count")
            
        except Exception as e:
            logger.error(f"[MACOS_LOGS] Error collecting logs: {e}")
        
        return logs
    
    def collect_all_logs(self, hours: int = 168) -> Dict:
        """
        Collect logs for the current operating system.
        
        Args:
            hours: Hours of history to collect (default 7 days = 168 hours)
        
        Returns:
            Dict with OS-specific logs
        """
        # Clamp hours consistently
        hours = max(1, min(int(hours), 24 * 30))

        if not self.enabled:
            return self._empty_logs("System log collection disabled by SYSTEM_LOG_COLLECTION_ENABLED=false")

        if self.os_type == 'Linux':
            return self.collect_linux_logs(hours)
        elif self.os_type == 'Windows':
            return self.collect_windows_logs(hours)
        elif self.os_type == 'Darwin':  # macOS
            return self.collect_macos_logs(hours)
        else:
            logger.warning(f"[SYSTEM_LOGS] Unsupported OS: {self.os_type}")
            return {
                "crashes": [],
                "security": [],
                "authentication": [],
                "kernel": [],
                "services": [],
                "errors": [],
                "total_count": 0
            }
    
    def _extract_timestamp(self, log_line: str) -> str:
        """Extract timestamp from log line or return current time."""
        try:
            # Try to parse common timestamp formats
            # This is a simple implementation - enhance as needed
            if log_line[:19].count('-') >= 2:  # ISO format
                return log_line[:19]
            else:
                return datetime.now().isoformat()
        except:
            return datetime.now().isoformat()


# Singleton instance
_system_log_collector: Optional[SystemLogCollector] = None


def get_system_log_collector() -> SystemLogCollector:
    """Get singleton system log collector instance."""
    global _system_log_collector
    if _system_log_collector is None:
        _system_log_collector = SystemLogCollector()
    return _system_log_collector
