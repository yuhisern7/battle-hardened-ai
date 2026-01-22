"""
Gunicorn Extreme-Scale Configuration for Battle-Hardened AI Server
Optimized for 100,000+ concurrent connections (DDoS-grade protection)

REQUIREMENTS:
- 16+ CPU cores
- 32+ GB RAM
- Linux OS (mandatory for this scale)
- Reverse proxy (nginx/haproxy) recommended

SETUP:
1. Install gevent for async workers:
   pip install gevent

2. Increase system limits:
   sudo sysctl -w net.core.somaxconn=65535
   sudo sysctl -w net.ipv4.tcp_max_syn_backlog=65535
   ulimit -n 1000000

3. Use this config:
   gunicorn --config installation/gunicorn_config_extreme.py server:app
"""

import multiprocessing
import os

# Server socket
bind = "0.0.0.0:60000"
backlog = 65535  # Max pending connections (Linux max: 65535)

# Worker processes - maximize CPU utilization
workers = multiprocessing.cpu_count() * 4  # Formula: 4 x CPU cores
worker_class = "gevent"  # ASYNC workers (required for 100k+ connections)
threads = 1  # Not used with gevent (async handles concurrency)
worker_connections = 10000  # Max simultaneous clients per worker (gevent only)

# Example capacity calculation:
# 16 CPUs × 4 workers/CPU = 64 workers
# 64 workers × 10,000 connections/worker = 640,000 max connections

# Worker lifecycle
max_requests = 10000  # Restart workers after N requests (prevent memory leaks)
max_requests_jitter = 500  # Randomize restart to avoid thundering herd
timeout = 60  # Worker timeout (60 seconds for slow attacks)
graceful_timeout = 30  # Grace period for worker shutdown
keepalive = 5  # Keep-alive connections

# Security limits (stricter for DDoS protection)
limit_request_line = 2048  # Max HTTP request line size (smaller = less memory)
limit_request_fields = 50  # Max number of headers (reduce from 100)
limit_request_field_size = 4096  # Max header size (reduce from 8190)

# Logging (reduce I/O overhead, paths relative to server directory)
accesslog = None  # Disable access log (use nginx/haproxy logs instead)
errorlog = "../logs/gunicorn_error.log"
loglevel = "warning"  # Only log warnings/errors (not info)

# Process naming
proc_name = "battle-hardened-ai-extreme"

# Server mechanics
daemon = False  # Don't daemonize (use systemd instead)
pidfile = "../logs/gunicorn.pid"
umask = 0o007
user = None  # Run as current user
group = None
tmp_upload_dir = None

# SSL/TLS Configuration (consider terminating SSL at nginx for better performance)
# Paths relative to server directory
keyfile = "../crypto_keys/ssl_key.pem"
certfile = "../crypto_keys/ssl_cert.pem"
ssl_version = 5  # TLS 1.2+
ciphers = "ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL:!MD5:!DSS"

# Preload application (MUST be True for gevent to share memory)
preload_app = True  # Share app across workers (saves RAM)

# Memory optimization
worker_tmp_dir = "/dev/shm"  # Use RAM for temp files (faster)

# Hook to limit memory per worker
def worker_abort(worker):
    worker.log.warning(f"Worker {worker.pid} aborted - likely timeout or OOM")

def post_fork(server, worker):
    server.log.info(f"Worker spawned (pid: {worker.pid})")

def worker_exit(server, worker):
    server.log.info(f"Worker exited (pid: {worker.pid})")

def on_starting(server):
    server.log.info("=" * 60)
    server.log.info("EXTREME-SCALE MODE ACTIVATED")
    server.log.info(f"Workers: {workers}")
    server.log.info(f"Worker class: {worker_class}")
    server.log.info(f"Connections per worker: {worker_connections}")
    server.log.info(f"THEORETICAL MAX: {workers * worker_connections:,} connections")
    server.log.info("=" * 60)
