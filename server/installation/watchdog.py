"""
Process monitoring and automatic restart for Battle-Hardened AI Server
Ensures server stays running even if all workers crash

PLATFORM SUPPORT:
- Windows: Uses Waitress (pure Python, multi-threaded)
- Linux: Uses Gunicorn (multi-process, better performance)
"""

import subprocess
import time
import sys
import os
import platform
from datetime import datetime

# Change to parent server directory (one level up from installation/)
script_dir = os.path.dirname(os.path.abspath(__file__))
server_dir = os.path.dirname(script_dir)
os.chdir(server_dir)

MAX_RESTARTS_PER_HOUR = 10
restart_times = []

def log(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    # Avoid UnicodeEncodeError on Windows consoles with non-UTF8 code pages
    try:
        print(f"[{timestamp}] {message}", flush=True)
    except UnicodeEncodeError:
        safe = str(message).encode("ascii", "replace").decode("ascii")
        print(f"[{timestamp}] {safe}", flush=True)

def start_server():
    """Start the production server (server.py directly - has built-in SSL and threading)"""
    is_windows = platform.system() == "Windows"
    
    if is_windows:
        log("[WINDOWS] Detected Windows - using Flask with SSL")
        log("Starting Battle-Hardened AI Server...")
        
        # Run server.py (we're already in server/ directory thanks to os.chdir above)
        process = subprocess.Popen(
            [sys.executable, "server.py"]
            # No stdout/stderr capture - let it print directly to console
        )
    else:
        log("[LINUX] Detected Linux - using Gunicorn production server")
        log("Starting Battle-Hardened AI Server...")
        
        # Gunicorn multi-process server for Linux
        # Let output go directly to console
        process = subprocess.Popen(
            [sys.executable, "-m", "gunicorn", "--config", "installation/gunicorn_config.py", "server:app"]
            # No stdout/stderr capture - let it print directly to console
        )
    
    return process

def monitor_server():
    """Monitor server and restart on crash"""
    global restart_times
    
    log("Server watchdog started")
    log(f"Max restarts per hour: {MAX_RESTARTS_PER_HOUR}")
    
    while True:
        process = start_server()
        
        # Monitor process - check every second if it's still alive
        try:
            while True:
                # Check if process is still running
                return_code = process.poll()
                if return_code is not None:
                    # Process has exited
                    break
                # Process still running, wait a bit
                time.sleep(1)
        except KeyboardInterrupt:
            log("Received shutdown signal (Ctrl+C)")
            process.terminate()
            try:
                process.wait(timeout=10)
            except:
                process.kill()
            log("Server stopped gracefully")
            sys.exit(0)
        
        # If we get here, process exited (crashed or stopped)
        now = time.time()
        restart_times = [t for t in restart_times if now - t < 3600]  # Keep last hour
        
        if len(restart_times) >= MAX_RESTARTS_PER_HOUR:
            log(f"Server crashed {MAX_RESTARTS_PER_HOUR} times in 1 hour - STOPPING")
            log("Manual intervention required - check logs for errors")
            sys.exit(1)
        
        restart_times.append(now)
        
        log(f"Server crashed (exit code: {return_code})")
        log(f"Auto-restarting in 5 seconds... ({len(restart_times)}/{MAX_RESTARTS_PER_HOUR} restarts this hour)")
        time.sleep(5)

if __name__ == "__main__":
    try:
        monitor_server()
    except KeyboardInterrupt:
        log("Watchdog stopped")
        sys.exit(0)
