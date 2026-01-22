#!/bin/sh

echo "🔐 Enterprise Security - HTTPS Server Starting..."

# Check if SSL certificates exist
if [ ! -f /app/crypto_keys/ssl_cert.pem ] || [ ! -f /app/crypto_keys/ssl_key.pem ]; then
    echo "❌ SSL certificates not found!"
    exit 1
fi

echo "✅ SSL certificates found"

# Initialize ALL JSON data files automatically
echo "📁 Initializing JSON data files..."
python3 /app/installation/init_json_files.py

echo "✅ JSON initialization complete"

if [ ! -f /app/json/tracking_data.json ]; then
    echo '{}' > /app/json/tracking_data.json
    echo "✅ Created tracking_data.json"
fi

if [ ! -f /app/json/peer_threats.json ]; then
    echo '[]' > /app/json/peer_threats.json
    echo "✅ Created peer_threats.json"
fi

if [ ! -f /app/json/ml_training_data.json ]; then
    echo '[]' > /app/json/ml_training_data.json
    echo "✅ Created ml_training_data.json"
fi

if [ ! -f /app/json/ml_performance_metrics.json ]; then
    echo '{}' > /app/json/ml_performance_metrics.json
    echo "✅ Created ml_performance_metrics.json"
fi

# Set proper permissions
chmod -R 666 /app/json/*.json 2>/dev/null || true
echo "✅ JSON files initialized"

echo "📊 Dashboard: https://0.0.0.0:60000 (HTTPS - Secure)"
echo "⚠️  Your browser will show SSL warning (self-signed cert) - this is NORMAL"
echo "    Click 'Advanced' → 'Proceed to localhost' to access dashboard"
echo ""

cd /app

# Create logs directory
mkdir -p /app/logs
echo "✅ Logs directory created"

# Optionally start firewall sync daemon (host iptables/ipset) if enabled
if [ "${BH_FIREWALL_SYNC_ENABLED:-false}" = "true" ]; then
    echo "🛡️  Starting Battle-Hardened AI firewall sync daemon..."
    python3 /app/installation/bh_firewall_sync.py &
fi

# Start Gunicorn with production config (handles concurrent attacks)
echo "🔐 Starting Gunicorn with HTTPS (SSL)..."
echo "🛡️  Production mode: Multi-worker with auto-restart"
echo "⚡ Workers: Auto-scaled based on CPU cores"
echo "🔒 Crash protection: Workers respawn automatically"
echo ""

# Use production config if it exists, otherwise fallback to inline config
if [ -f /app/installation/gunicorn_config.py ]; then
    exec gunicorn --config /app/installation/gunicorn_config.py server:app
else
    exec gunicorn \
        --certfile=/app/crypto_keys/ssl_cert.pem \
        --keyfile=/app/crypto_keys/ssl_key.pem \
        --bind 0.0.0.0:60000 \
        --workers 4 \
        --threads 4 \
        --worker-class gthread \
        --timeout 30 \
        --graceful-timeout 30 \
        --max-requests 1000 \
        --max-requests-jitter 50 \
        --worker-tmp-dir /dev/shm \
        --access-logfile - \
        --error-logfile - \
        --log-level info \
        server:app
fi
