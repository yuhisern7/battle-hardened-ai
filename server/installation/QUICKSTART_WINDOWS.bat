@echo off
REM Quick start script for Windows (uses bridge networking with port mapping)

echo Starting Enterprise Security on Windows...
echo.

REM Check if running as Administrator (required for network monitoring)
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo WARNING: Not running as Administrator
    echo Network packet capture requires Administrator privileges
    echo Right-click this file and select "Run as Administrator"
    echo.
    pause
)

REM Change to server directory
cd /d "%~dp0\.."

REM Copy .env.windows to .env if .env doesn't exist
if not exist .env (
    echo Creating .env from .env.windows template...
    copy /Y .env.windows .env
)

REM Initialize JSON files using init_json_files.py
if not exist json\threat_log.json (
    echo Initializing JSON files...
    where python >nul 2>&1 && (
        python installation\init_json_files.py
    ) || (
        echo WARNING: Python not found - creating basic JSON structure...
        if not exist json mkdir json
        if not exist json\compliance_reports mkdir json\compliance_reports
        if not exist json\performance_metrics mkdir json\performance_metrics
        echo [] > json\threat_log.json
        echo [] > json\blocked_ips.json
        echo {} > json\visualization_data.json
    )
    echo JSON files initialized...
)

REM Use standard docker-compose.yml (Windows bridge mode)
docker compose down 2>nul
docker compose up -d --build

echo.
echo Container starting...
echo Dashboard: https://localhost:60000 (HTTPS - Secure)
echo SSL certificates auto-generated (self-signed)
echo Browser will show SSL warning - this is NORMAL
echo P2P Port: wss://localhost:60001
echo.
echo Waiting for container to be healthy...
timeout /t 30 /nobreak >nul

docker compose ps

echo.
echo Note: Windows Docker Desktop uses bridge networking
echo Network scanning works within Docker network
echo For full LAN scanning, use host network mode (Linux only)
