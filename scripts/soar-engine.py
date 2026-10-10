import os
import re
import time
import threading
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

# Configuration settings
BLOCK_DURATION_SECONDS = 60  # 1 minute for local testing (change to 3600 for 1 hour)

# State management
print_lock = threading.Lock()
active_blocks = set()  # Track currently blocked IPs

def log_print(msg: str):
    with print_lock:
        print(msg)

# -------------------------------------------------------------------
# 1. DISCORD ALERTING ENGINE
# -------------------------------------------------------------------

def send_discord_block_alert(ip: str, score: int, reports: int, country: str, source: str, duration: int):
    """Send formatted Discord webhook alert when an IP is blocked."""
    if not DISCORD_WEBHOOK_URL:
        return

    payload = {
        "embeds": [
            {
                "title": "🚨 Automated Security Containment Event",
                "color": 15158332,  # Red
                "fields": [
                    {"name": "Target IP", "value": f"`{ip}`", "inline": True},
                    {"name": "Threat Score", "value": f"**{score}%**", "inline": True},
                    {"name": "Log Source", "value": f"`{source}`", "inline": True},
                    {"name": "Country", "value": country, "inline": True},
                    {"name": "AbuseIPDB Reports", "value": str(reports), "inline": True},
                    {"name": "Action Taken", "value": f"🛑 `iptables DROP ({duration}s temp block)`", "inline": True}
                ],
                "footer": {"text": "Lightweight Python SOAR Engine"},
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            }
        ]
    }

    try:
        res = requests.post(DISCORD_WEBHOOK_URL, json=payload, timeout=5)
        if res.status_code in [200, 204]:
            log_print("[✓] Discord block alert sent.")
    except Exception as e:
        log_print(f"[-] Discord alert error: {e}")

def send_discord_unblock_alert(ip: str, duration: int):
    """Send formatted Discord webhook alert when a temporary IP block expires."""
    if not DISCORD_WEBHOOK_URL:
        return

    payload = {
        "embeds": [
            {
                "title": "🟢 Automated Containment Recovery / Expiration",
                "color": 3066993,  # Green
                "fields": [
                    {"name": "Target IP", "value": f"`{ip}`", "inline": True},
                    {"name": "Status", "value": "🟢 `Unblocked`", "inline": True},
                    {"name": "Retention Period", "value": f"`{duration} seconds`", "inline": True},
                    {"name": "Action Taken", "value": "🔄 `iptables rule removed`", "inline": True}
                ],
                "footer": {"text": "Lightweight Python SOAR Engine"},
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            }
        ]
    }

    try:
        res = requests.post(DISCORD_WEBHOOK_URL, json=payload, timeout=5)
        if res.status_code in [200, 204]:
            log_print("[✓] Discord recovery alert sent.")
    except Exception as e:
        log_print(f"[-] Discord alert error: {e}")

# -------------------------------------------------------------------
# 2. CONTAINMENT & EXPIRATION LOGIC
# -------------------------------------------------------------------

def unblock_ip(ip: str):
    """Automated recovery: Remove iptables rule after timer expiration."""
    log_print(f"[🔄] EXPIRATION TIMER FIRED: Unblocking IP {ip}...")
    try:
        subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        log_print(f"[✓] Successfully removed iptables DROP rule for {ip}")
        if ip in active_blocks:
            active_blocks.remove(ip)
        send_discord_unblock_alert(ip, BLOCK_DURATION_SECONDS)
    except Exception as e:
        log_print(f"[-] Failed to unblock IP {ip}: {e}")

def block_ip(ip: str, score: int, reports: int, country: str, source: str) -> bool:
    """Automated containment via OS iptables with non-blocking expiration timer."""
    if ip in active_blocks:
        log_print(f"[*] IP {ip} is already actively blocked. Skipping duplicate rule.")
        return True

    log_print(f"[!] CONTAINMENT ACTION: Blocking IP {ip} via iptables for {BLOCK_DURATION_SECONDS}s...")
    try:
        # Verify rule presence to avoid duplicates
        check = subprocess.run(["sudo", "iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"], capture_output=True)
        if check.returncode == 0:
            log_print(f"[*] IP {ip} is already present in iptables.")
            active_blocks.add(ip)
            return True

        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        log_print(f"[✓] Successfully added iptables DROP rule for {ip}")
        active_blocks.add(ip)

        # Notify Discord of containment
        send_discord_block_alert(ip, score, reports, country, source, BLOCK_DURATION_SECONDS)

        # Schedule async unblock timer
        timer = threading.Timer(BLOCK_DURATION_SECONDS, unblock_ip, args=[ip])
        timer.daemon = True
        timer.start()
        log_print(f"[*] Expiration timer started for {ip} ({BLOCK_DURATION_SECONDS} seconds)")

        return True
    except Exception as e:
        log_print(f"[-] Failed to block IP {ip}: {e}")
        return False

def check_ip_reputation(ip: str) -> dict:
    """Query AbuseIPDB API v2."""
    if not ABUSEIPDB_KEY:
        log_print("[!] Missing ABUSEIPDB_API_KEY in .env file.")
        return {"score": 0, "reports": 0, "country": "Unknown"}

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": "90"}

    try:
        res = requests.get(url, headers=headers, params=params, timeout=5)
        if res.status_code == 200:
            data = res.json()["data"]
            return {
                "score": data.get("abuseConfidenceScore", 0),
                "reports": data.get("totalReports", 0),
                "country": data.get("countryCode", "Unknown")
            }
    except Exception as e:
        log_print(f"[-] API Request error for {ip}: {e}")

    return {"score": 0, "reports": 0, "country": "Unknown"}

def evaluate_threat(ip: str, source_name: str):
    """Core evaluation pipeline shared by all log sources."""
    if ip.startswith("127.") or ip.startswith("192.168.") or ip.startswith("10.") or ip == "::1":
        log_print(f"[*] [{source_name}] Extracted internal IP ({ip}). Skipping AbuseIPDB check.")
        return

    log_print(f"\n[+] [{source_name}] Extracted External IP: {ip}. Querying AbuseIPDB API...")
    intel = check_ip_reputation(ip)
    score = intel["score"]

    log_print(f"[+] [{source_name}] Match | Country: {intel['country']} | Reports: {intel['reports']} | Score: {score}%")

    if score >= 50:
        block_ip(ip, score, intel['reports'], intel['country'], source_name)

# -------------------------------------------------------------------
# 3. LOG INGESTION LISTENERS (THREADS)
# -------------------------------------------------------------------

def watch_fastapi_logs():
    """Thread 1: Tail FastAPI application alerts.log."""
    if not LOG_FILE.exists():
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        LOG_FILE.touch()

    log_print(f"[*] [FastAPI Listener] Monitoring {LOG_FILE}...")
    with open(LOG_FILE, "r") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(1)
                continue

            match = re.search(r"IP=([\d\.]+)", line)
            if match:
                evaluate_threat(match.group(1), "FastAPI App")

def watch_ssh_logs():
    """Thread 2: Stream live system SSH authentication events via journalctl."""
    log_print("[*] [SSH Listener] Streaming journalctl for sshd events...")
    
    cmd = ["journalctl", "-t", "sshd", "-f", "-n", "0"]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for line in proc.stdout:
            if "Failed password" in line or "Invalid user" in line:
                match = re.search(r"from ([\d\.]+) port", line)
                if match:
                    evaluate_threat(match.group(1), "System SSH Daemon")
    except Exception as e:
        log_print(f"[-] SSH Listener process error: {e}")

# -------------------------------------------------------------------
# 4. MAIN ORCHESTRATOR
# -------------------------------------------------------------------

if __name__ == "__main__":
    log_print("=== Starting Multi-Source SOAR Engine ===")
    log_print(f"[*] Automated Unblock Policy: Enabled ({BLOCK_DURATION_SECONDS}s timer)")

    fastapi_thread = threading.Thread(target=watch_fastapi_logs, daemon=True)
    ssh_thread = threading.Thread(target=watch_ssh_logs, daemon=True)

    fastapi_thread.start()
    ssh_thread.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log_print("\n[!] Shutting down SOAR Engine...")