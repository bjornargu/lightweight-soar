import os
import re
import time
import requests
import subprocess
from pathlib import Path
from dotenv import load_dotenv

# Base paths and environment variables
BASE_DIR = Path(__file__).resolve().parent.parent
LOG_FILE = BASE_DIR / "logs" / "alerts.log"

load_dotenv(BASE_DIR / ".env")
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_API_KEY")
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL")

def send_discord_alert(ip: str, score: int, reports: int, country: str, blocked: bool):
    """Send a formatted embed alert to a Discord channel via Webhook."""
    if not DISCORD_WEBHOOK_URL:
        print("[!] Discord webhook URL not configured in .env")
        return

    color = 15158332 if blocked else 15105570  # Red if blocked, Orange if alert only

    payload = {
        "embeds": [
            {
                "title": "🚨 Automated Security Containment Event",
                "color": color,
                "fields": [
                    {"name": "Target IP", "value": f"`{ip}`", "inline": True},
                    {"name": "Threat Score", "value": f"**{score}%**", "inline": True},
                    {"name": "Country", "value": country, "inline": True},
                    {"name": "AbuseIPDB Reports", "value": str(reports), "inline": True},
                    {"name": "Action Taken", "value": "🛑 `iptables DROP`" if blocked else "⚠️ `Logged / Monitored`", "inline": True}
                ],
                "footer": {"text": "Lightweight Python SOAR Engine"},
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            }
        ]
    }

    try:
        res = requests.post(DISCORD_WEBHOOK_URL, json=payload, timeout=5)
        if res.status_code in [200, 204]:
            print("[✓] Discord alert sent successfully.")
        else:
            print(f"[-] Failed to send Discord alert. HTTP Status: {res.status_code}")
    except Exception as e:
        print(f"[-] Error sending Discord webhook: {e}")

def check_ip_reputation(ip: str) -> dict:
    """Query AbuseIPDB API for threat metadata."""
    if not ABUSEIPDB_KEY:
        print("[!] Missing ABUSEIPDB_API_KEY in .env file.")
        return {"score": 0, "reports": 0, "country": "Unknown"}

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": "90"}

    try:
        response = requests.get(url, headers=headers, params=params, timeout=5)
        if response.status_code == 200:
            data = response.json()["data"]
            return {
                "score": data.get("abuseConfidenceScore", 0),
                "reports": data.get("totalReports", 0),
                "country": data.get("countryCode", "Unknown")
            }
    except Exception as e:
        print(f"[-] Request error for IP {ip}: {e}")

    return {"score": 0, "reports": 0, "country": "Unknown"}

def block_ip(ip: str) -> bool:
    """Automated containment via iptables."""
    print(f"[!] CONTAINMENT ACTION: Blocking IP {ip} via iptables...")
    try:
        check = subprocess.run(["sudo", "iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"], capture_output=True)
        if check.returncode == 0:
            print(f"[*] IP {ip} is already blocked.")
            return True

        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        print(f"[✓] Successfully added iptables DROP rule for {ip}")
        return True
    except Exception as e:
        print(f"[-] Failed to block IP {ip}: {e}")
        return False

def process_line(line: str):
    """Extract IP and run threat evaluation pipeline."""
    match = re.search(r"IP=([\d\.]+)", line)
    if not match:
        return

    ip = match.group(1)

    if ip.startswith("127.") or ip.startswith("192.168.") or ip.startswith("10."):
        print(f"[*] Extracted local IP ({ip}). Skipping external threat lookup.")
        return

    print(f"\n[+] Extracted External IP: {ip}. Querying AbuseIPDB Threat Intel...")
    intel = check_ip_reputation(ip)
    score = intel["score"]
    
    print(f"[+] AbuseIPDB Match | Country: {intel['country']} | Reports: {intel['reports']} | Score: {score}%")

    if score >= 50:
        blocked = block_ip(ip)
        send_discord_alert(ip, score, intel["reports"], intel["country"], blocked)

def watch_logs():
    """Tail log file for incoming alerts."""
    if not LOG_FILE.exists():
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        LOG_FILE.touch()

    print(f"[*] SOAR Engine Listening on {LOG_FILE}...")
    with open(LOG_FILE, "r") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(1)
                continue
            process_line(line.strip())

if __name__ == "__main__":
    watch_logs()