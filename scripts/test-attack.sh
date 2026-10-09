#!/usr/bin/env bash

# Default to known Tor exit node if no IP is provided as an argument
TARGET_IP="${1:-185.220.101.5}"
USERNAME="${2:-admin}"

echo "=================================================="
echo " Fire Simulated Attack Payload"
echo " Target Spoofed IP : $TARGET_IP"
echo " Target Username  : $USERNAME"
echo " Target Endpoint  : http://127.0.0.1:8000/api/v1/login"
echo "=================================================="

curl -s -X POST http://127.0.0.1:8000/api/v1/login \
     -H "Content-Type: application/json" \
     -H "X-Forwarded-For: $TARGET_IP" \
     -d "{\"username\": \"$USERNAME\", \"password\": \"123\"}"

echo -e "\n[✓] Payload sent!"