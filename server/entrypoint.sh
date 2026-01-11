#!/bin/sh

echo "🔐 Enterprise Security - HTTPS Server Starting..."

# Check if SSL certificates exist
if [ ! -f /app/ssl/cert.pem ] || [ ! -f /app/ssl/key.pem ]; then
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

# Start Gunicorn with HTTPS (runs Flask app directly)
echo "🔐 Starting Gunicorn with HTTPS (SSL)..."
echo "🛡️  Auto-restart enabled: Workers will restart on crash"
echo "⚡ Resource limits: 4GB RAM, 2 CPU cores max"
echo ""

exec gunicorn \
    --certfile=/app/ssl/cert.pem \
    --keyfile=/app/ssl/key.pem \
    --bind 0.0.0.0:60000 \
    --workers 1 \
    --threads 16 \
    --worker-class gthread \
    --timeout 120 \
    --graceful-timeout 30 \
    --max-requests 10000 \
    --max-requests-jitter 1000 \
    --worker-tmp-dir /dev/shm \
    --access-logfile - \
    --error-logfile - \
    --log-level info \
    server:app
