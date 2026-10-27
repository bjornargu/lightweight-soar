#!/bin/bash
# ==============================================================================
# Simulation Attack Script for Lightweight SOAR
# Supports both FastAPI (HTTP POST) and SSH (syslog/journalctl) attack vectors,
# with single-request and rapid brute-force test modes.
# ==============================================================================

API_URL="http://127.0.0.1:8000/api/v1/login"

print_usage() {
    echo "Usage: $0 [IP_ADDRESS] [VECTOR] [MODE]"
    echo ""
    echo "Vectors:"
    echo "  fastapi   Simulate failed login against FastAPI endpoint (default)"
    echo "  ssh       Simulate failed login against systemd SSH journal"
    echo ""
    echo "Modes:"
    echo "  single    Send a single attack event (default)"
    echo "  brute     Send 6 rapid back-to-back failed attempts to trigger local burst containment"
    echo ""
    echo "Examples:"
    echo "  $0                                # Default: 185.220.101.5 via FastAPI (single)"
    echo "  $0 185.220.101.5 ssh              # Test Tor node via SSH journal (single)"
    echo "  $0 203.0.113.50 fastapi brute     # Test local burst threshold via FastAPI"
    echo "  $0 203.0.113.50 ssh brute         # Test local burst threshold via SSH"
    echo "  $0 brute                          # Shortcut: Run 6 rapid FastAPI attacks"
}

if [[ "$1" == "-h" || "$1" == "--help" ]]; then
    print_usage
    exit 0
fi

# Flexible argument parsing
if [[ "$1" == "brute" || "$1" == "--brute" ]]; then
    TARGET_IP="203.0.113.55"
    VECTOR="fastapi"
    MODE="brute"
elif [[ "$2" == "brute" || "$2" == "--brute" ]]; then
    TARGET_IP="$1"
    VECTOR="fastapi"
    MODE="brute"
else
    TARGET_IP="${1:-185.220.101.5}"
    VECTOR="${2:-fastapi}"
    MODE="${3:-single}"
fi

echo "=================================================="
echo " [!] SOAR Attack Simulation Triggered"
echo " Target IP : $TARGET_IP"
echo " Vector    : $VECTOR"
echo " Mode      : $MODE"
echo "=================================================="

if [[ "$MODE" == "brute" || "$MODE" == "bruteforce" ]]; then
    echo "[*] Triggering BRUTE FORCE simulation (6 rapid failed attempts)..."
    case "$VECTOR" in
        fastapi)
            for i in {1..6}; do
                echo "  [Burst $i/6] POST $API_URL (X-Forwarded-For: $TARGET_IP)..."
                RESPONSE=$(curl -s -X POST "$API_URL" \
                    -H "Content-Type: application/json" \
                    -H "X-Forwarded-For: $TARGET_IP" \
                    -d "{\"username\": \"admin$i\", \"password\": \"WrongPass$i\", \"client_ip\": \"$TARGET_IP\"}")
                echo "    --> Response: $RESPONSE"
            done
            ;;

        ssh)
            for i in {1..6}; do
                PORT=$((49150 + i))
                echo "  [Burst $i/6] Injecting SSH failure log for $TARGET_IP port $PORT..."
                logger -t sshd "Failed password for invalid user admin$i from $TARGET_IP port $PORT ssh2"
            done
            echo "[✓] Injected 6 SSH log entries into journalctl."
            ;;

        *)
            echo "[-] Unknown vector: $VECTOR"
            print_usage
            exit 1
            ;;
    esac
else
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
fi

echo "--------------------------------------------------"
echo "[*] Check your soar-engine.py terminal and Discord channel for alert activity!"