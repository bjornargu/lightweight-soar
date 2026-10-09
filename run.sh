#!/usr/bin/env bash

# Automatically locate project root
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_ROOT"

# Ensure virtual environment exists
if [ ! -d "venv" ]; then
    echo "[-] Virtual environment 'venv' not found in $PROJECT_ROOT"
    exit 1
fi

# Activate virtual environment
source venv/bin/activate

echo "=================================================="
echo " Starting Lightweight SOAR Environment"
echo "=================================================="

# Function to handle graceful shutdown on Ctrl+C
cleanup() {
    echo ""
    echo "[!] Shutting down SOAR services..."
    kill 0
    exit 0
}

# Trap SIGINT (Ctrl+C) to trigger cleanup
trap cleanup SIGINT SIGTERM

# 1. Start FastAPI server in background
echo "[+] Starting FastAPI Web Application (Port 8000)..."
uvicorn scripts.app:app --port 8000 &
FASTAPI_PID=$!

sleep 1.5

# 2. Start SOAR Engine with sudo privileges
echo "[+] Starting SOAR Engine (Requires sudo for iptables)..."
sudo "$PROJECT_ROOT/venv/bin/python3" scripts/soar-engine.py &
SOAR_PID=$!

echo "=================================================="
echo "[✓] Services running!"
echo "    - FastAPI PID: $FASTAPI_PID"
echo "    - SOAR Engine PID: $SOAR_PID"
echo "    - Press Ctrl+C to stop all services."
echo "=================================================="

# Keep script active to catch Ctrl+C
wait