import os
import re
import time
import requests
import subprocess
from pathlib import Path
from dotenv import load_dotenv

# Set paths and load environment variables safely
BASE_DIR = Path(__file__).resolve().parent.parent
LOG_FILE = BASE_DIR / "logs" / "alerts.log"

load_dotenv(BASE_DIR / ".env")
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_API_KEY")

def check_ip_reputation(ip: str) -> int:
    """Query AbuseIPDB API v2 for an IP's threat score."""
    if not ABUSEIPDB_KEY or ABUSEIPDB_KEY == "your_actual_api_key_here":
        print("[!] Error: Missing valid ABUSEIPDB_API_KEY in .env file.")
        return 0

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": ABUSEIPDB_KEY,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": "90"
    }

    try:
        response = requests.get(url, headers=headers, params=params, timeout=5)
        if response.status_code == 200:
            data = response.json()["data"]
            score = data.get("abuseConfidenceScore", 0)
            reports = data.get("totalReports", 0)
            country = data.get("countryCode", "Unknown")
            print(f"[+] AbuseIPDB Match | Country: {country} | Reports: {reports} | Score: {score}%")
            return score
        elif response.status_code == 401:
            print("[-] API Authentication failed. Please check your ABUSEIPDB_API_KEY.")
        else:
            print(f"[-] AbuseIPDB API error HTTP status: {response.status_code}")
    except Exception as e:
        print(f"[-] Request failed for IP {ip}: {e}")

    return 0

def block_ip(ip: str):
    """Automated containment using OS iptables DROP rule."""
    print(f"[!] CONTAINMENT ACTION: Blocking IP {ip} via iptables...")
    try:
        # Prevent duplicate rules
        check = subprocess.run(["sudo", "iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"], capture_output=True)
        if check.returncode == 0:
            print(f"[*] IP {ip} is already blocked in iptables.")
            return

        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        print(f"[✓] Successfully added iptables DROP rule for {ip}")
    except Exception as e:
        print(f"[-] Failed to block IP {ip}: {e} (Ensure script runs with sudo permissions)")

def process_line(line: str):
    """Extract IP from incoming log entry and run threat evaluation."""
    match = re.search(r"IP=([\d\.]+)", line)
    if not match:
        return

    ip = match.group(1)

    # Skip loopback / RFC 1918 private IPs from external Threat Intel check
    if ip.startswith("127.") or ip.startswith("192.168.") or ip.startswith("10."):
        print(f"[*] Extracted local/loopback IP ({ip}). Skipping AbuseIPDB check.")
        return

    print(f"\n[+] Extracted External IP: {ip}. Querying AbuseIPDB API...")
    score = check_ip_reputation(ip)

    if score >= 50:
        block_ip(ip)

def watch_logs():
    """Tail alerts.log for new security events."""
    if not LOG_FILE.exists():
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        LOG_FILE.touch()

    print(f"[*] SOAR Engine Listening on {LOG_FILE}...")
    with open(LOG_FILE, "r") as f:
        f.seek(0, 2)  # Jump to end of file
        while True:
            line = f.readline()
            if not line:
                time.sleep(1)
                continue
            process_line(line.strip())

if __name__ == "__main__":
    watch_logs()