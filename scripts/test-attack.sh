#!/bin/bash
# ==============================================================================
# Simulation Attack Script for Lightweight SOAR
# Supports both FastAPI (HTTP POST) and SSH (syslog/journalctl) attack vectors.
# ==============================================================================

TARGET_IP="${1:-185.220.101.5}"     # Default: Known Tor exit node
VECTOR="${2:-fastapi}"              # Default: 'fastapi' (or 'ssh')
API_URL="http://127.0.0.1:8000/api/v1/login"

print_usage() {
    echo "Usage: $0 [IP_ADDRESS] [VECTOR]"
    echo ""
    echo "Vectors:"
    echo "  fastapi   Simulate failed login against FastAPI endpoint (default)"
    echo "  ssh       Simulate failed login against systemd SSH journal"
    echo ""
    echo "Examples:"
    echo "  $0                          # Default: 185.220.101.5 via FastAPI"
    echo "  $0 185.220.101.5 ssh        # Test Tor node via SSH journal"
    echo "  $0 8.8.8.8 fastapi          # Test Google DNS via FastAPI"
}

if [[ "$1" == "-h" || "$1" == "--help" ]]; then
    print_usage
    exit 0
fi

echo "=================================================="
echo " [!] SOAR Attack Simulation Triggered"
echo " Target IP : $TARGET_IP"
echo " Vector    : $VECTOR"
echo "=================================================="

case "$VECTOR" in
    fastapi)
        echo "[*] Sending malicious POST payload to $API_URL..."
        RESPONSE=$(curl -s -X POST "$API_URL" \
            -H "Content-Type: application/json" \
            -H "X-Forwarded-For: $TARGET_IP" \
            -d "{\"username\": \"admin\", \"password\": \"SuperSecretP@ss123\", \"client_ip\": \"$TARGET_IP\"}")
        
        echo "[✓] Response received from FastAPI:"
        echo "    $RESPONSE"
        ;;

    ssh)
        echo "[*] Injecting simulated SSH failure into journalctl (-t sshd)..."
        logger -t sshd "Failed password for invalid user root from $TARGET_IP port 49152 ssh2"
        echo "[✓] Injected log entry with IP: $TARGET_IP"
        ;;

    *)
        echo "[-] Unknown vector: $VECTOR"
        print_usage
        exit 1
        ;;
esac

echo "--------------------------------------------------"
echo "[*] Check your soar-engine.py terminal and Discord channel for alert activity!"