# Home WiFi Security System - Docker Image
FROM python:3.11-slim

# Install system dependencies for network monitoring + eBPF (MODULE A)
RUN apt-get update && apt-get install -y \
    tcpdump \
    libpcap-dev \
    gcc \
    openssl \
    iproute2 \
    iptables \
    ipset \
    samba-common-bin \
    avahi-utils \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Note: Full eBPF/BCC requires kernel headers and is complex to install in containers
# System gracefully falls back to scapy userland monitoring
# eBPF will work if host kernel supports it and container has proper capabilities
# For production eBPF: Use host-installed bpftool or Cilium eBPF Go library

# Set working directory
WORKDIR /app

# Copy requirements first (for better caching)
COPY server/requirements.txt .

# Install Python dependencies with increased timeout and retries for large packages
RUN pip install --no-cache-dir --default-timeout=1000 --retries 5 -r requirements.txt

# Copy AI folder (contains pcs_ai.py, dashboard, and ml_models)
COPY AI/ AI/

# Ensure ML models are available at the universal path helper location
# /app/ml_models (Docker) so that AI.path_helper.get_ml_models_dir() can
# find and persist models without depending on /app/AI layout.
RUN mkdir -p /app/ml_models && \
    if [ -d "AI/ml_models" ]; then cp -r AI/ml_models/* /app/ml_models/ || true; fi

# Create ml_models crypto_keys directory and copy customer/relay keys
RUN mkdir -p /app/ml_models/crypto_keys
COPY server/crypto_keys/ /app/ml_models/crypto_keys/

# Copy server files
COPY server/server.py .
COPY server/network_monitor.py .
COPY server/device_scanner.py .
COPY server/device_blocker.py .
COPY server/report_generator.py .

# Copy installation directory (contains init_json_files.py, watchdog.py, gunicorn configs)
COPY server/installation/ installation/

# Create and copy JSON data directory
RUN mkdir -p json
COPY server/json/ json/

# Copy entrypoint script and normalize line endings for Linux
COPY server/entrypoint.sh /app/entrypoint.sh
RUN sed -i 's/\r$//' /app/entrypoint.sh && chmod +x /app/entrypoint.sh

# Generate self-signed SSL certificate for encrypted communication
RUN mkdir -p /app/crypto_keys && \
    openssl req -x509 -newkey rsa:4096 -nodes \
    -keyout /app/crypto_keys/ssl_key.pem \
    -out /app/crypto_keys/ssl_cert.pem \
    -days 3650 \
    -subj "/C=US/ST=State/L=City/O=Security/CN=enterprise-security"

# Expose ports (Dashboard HTTPS and P2P)
EXPOSE 60000 60001

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    BATTLE_HARDENED_PROJECT_ROOT=/app

# Run as root (required for network monitoring)
USER root

# Health check (uses HTTPS on 60000)
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -kf https://localhost:60000/ || exit 1

# Start the server with HTTPS entrypoint
ENTRYPOINT ["/app/entrypoint.sh"]
