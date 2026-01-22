#!/bin/bash
# Battle-Hardened AI Server - Extreme-Scale Startup Script (100k+ connections)
# Requires: Linux, 32+ CPU cores, 64+ GB RAM, gevent installed

# Check requirements
if ! python3 -c "import gevent" 2>/dev/null; then
    echo "❌ ERROR: gevent not installed"
    echo "Run: pip install gevent"
    exit 1
fi

# Create logs directory in parent server folder
mkdir -p ../logs

echo "======================================="
echo "  EXTREME-SCALE MODE - 100K+ CONNECTIONS"
echo "======================================="
echo ""
echo "Workers: $(($(nproc) * 4))"
echo "Worker class: gevent (async)"
echo "Connections per worker: 10,000"
echo "THEORETICAL MAX: $(($(nproc) * 40000)) connections"
echo "Timeout: 60 seconds"
echo "SSL: Enabled (port 60000)"
echo ""
echo "Protection Features:"
echo "  ✓ Async workers (handles 100,000s of concurrent attacks)"
echo "  ✓ Auto-restart on crash (workers respawn automatically)"
echo "  ✓ Memory leak protection (workers recycle after 10,000 requests)"
echo "  ✓ Request size limits (prevent payload bombs)"
echo "  ✓ Timeout protection (kill slow/hanging requests)"
echo "  ✓ Connection backlog (queue 65,535 pending connections)"
echo ""
echo "System Requirements:"
echo "  ⚠️  Run 'sudo sysctl -w net.core.somaxconn=65535' if not done"
echo "  ⚠️  Run 'ulimit -n 1000000' if not done"
echo ""
echo "Press Ctrl+C to stop server"
echo "======================================="
echo ""

# Start Gunicorn with extreme-scale config
gunicorn --config installation/gunicorn_config_extreme.py server:app
