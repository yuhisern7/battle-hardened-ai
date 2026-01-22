"""
Gunicorn Production Configuration for Battle-Hardened AI Server
Optimized for handling simultaneous attacks without crashing
"""

import multiprocessing
import os

# Server socket
bind = "0.0.0.0:60000"
backlog = 2048  # Max pending connections (default 2048)

# Worker processes - scale with CPU cores but cap for memory safety
# Use fewer workers on systems with limited RAM to avoid OOM
cpu_count = multiprocessing.cpu_count()
workers = min(cpu_count * 2 + 1, 4)  # Max 4 workers (safe for 8GB RAM)
worker_class = "sync"  # Use 'gevent' for async if you install gevent
threads = 4  # Threads per worker (total = workers * threads)
worker_connections = 1000  # Max simultaneous clients per worker

# Worker lifecycle
max_requests = 1000  # Restart workers after N requests (prevent memory leaks)
max_requests_jitter = 50  # Randomize restart to avoid thundering herd
timeout = 30  # Worker timeout (30 seconds for request processing)
graceful_timeout = 30  # Grace period for worker shutdown
keepalive = 2  # Keep-alive connections

# Security limits
limit_request_line = 4096  # Max HTTP request line size
limit_request_fields = 100  # Max number of headers
limit_request_field_size = 8190  # Max header size

# Determine base directory for logs and TLS material
# - In Docker, BATTLE_HARDENED_PROJECT_ROOT is set to "/app".
# - In native installs, fall back to the server folder (one level up).
BASE_DIR = os.environ.get("BATTLE_HARDENED_PROJECT_ROOT") or os.path.dirname(os.path.dirname(__file__))

LOG_DIR = os.path.join(BASE_DIR, "logs")
os.makedirs(LOG_DIR, exist_ok=True)

# Logging
# Use '-' to log to stdout/stderr so errors are visible in the terminal
# on both native Linux and Docker.
accesslog = "-"
errorlog = "-"
loglevel = "info"
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)s'

# Process naming
proc_name = "battle-hardened-ai"

# Server mechanics
daemon = False  # Don't daemonize (use systemd/supervisor instead)
pidfile = os.path.join(LOG_DIR, "gunicorn.pid")
umask = 0o007
user = None  # Run as current user
group = None
tmp_upload_dir = None

# SSL/TLS Configuration (relative to BASE_DIR)
keyfile = os.path.join(BASE_DIR, "crypto_keys", "ssl_key.pem")
certfile = os.path.join(BASE_DIR, "crypto_keys", "ssl_cert.pem")
# Let Gunicorn/OpenSSL choose the recommended TLS protocol versions.
ciphers = "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS"

# Preload application (faster worker spawning, but uses more memory)
preload_app = False  # Set True if you have shared state

# Hook to limit memory per worker
def worker_abort(worker):
    worker.log.info(f"Worker {worker.pid} aborted - likely timeout or OOM")

def post_fork(server, worker):
    server.log.info(f"Worker spawned (pid: {worker.pid})")

def worker_exit(server, worker):
    server.log.info(f"Worker exited (pid: {worker.pid})")
