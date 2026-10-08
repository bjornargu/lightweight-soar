# soar_engine.py
import time
import re
import os
import requests
import subprocess

ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_API_KEY", "YOUR_FREE_API_KEY")
LOG_FILE = "logs/alerts.log"

def check_ip_reputation(ip):
    """Query AbuseIPDB API for threat score."""
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": "90"}
    
    try:
        res = requests.get(url, headers=headers, params=params, timeout=5)
        if res.status_code == 200:
            return res.json()["data"]["abuseConfidenceScore"]
    except Exception as e:
        print(f"[-] API Error: {e}")
    return 0

def block_ip(ip):
    """Automated containment via iptables."""
    print(f"[!] EXECUTING CONTAINMENT: Blocking IP {ip} via iptables...")
    # Note: Requires sudo permissions
    subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])

def process_line(line):
    match = re.search(r"IP=([\d\.]+)", line)
    if match:
        ip = match.group(1)
        print(f"[+] Extracted IP: {ip}. Checking Threat Intel...")
        score = check_ip_reputation(ip)
        print(f"[+] Abuse Confidence Score for {ip}: {score}%")
        
        if score >= 50: # Threshold for threat containment
            block_ip(ip)

def watch_logs():
    """Tail -f log file tailer."""
    with open(LOG_FILE, "r") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(1)
                continue
            process_line(line)

if __name__ == "__main__":
    print("[*] SOAR Engine Listening for Security Alerts...")
    watch_logs()