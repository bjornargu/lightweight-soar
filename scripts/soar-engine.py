import os
import re
import time
import threading
import requests
import subprocess
from pathlib import Path
from collections import defaultdict
from typing import Optional, Dict, Any
from dotenv import load_dotenv
from google import genai

# Base paths and environment variables
BASE_DIR = Path(__file__).resolve().parent.parent
LOG_FILE = BASE_DIR / "logs" / "alerts.log"

load_dotenv(BASE_DIR / ".env")
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_API_KEY")
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
gemini_client = genai.Client(api_key=GEMINI_API_KEY) if GEMINI_API_KEY else None

# Configuration settings
BLOCK_DURATION_SECONDS = 60   # 1 minute for local testing 
LOCAL_BURST_THRESHOLD = 5     # Max attempts before triggering local containment
LOCAL_BURST_WINDOW = 30       # Sliding window in seconds
REPUTATION_CACHE_TTL = 3600   # 1 hour TTL for reputation cache

# State management
print_lock = threading.Lock()
active_blocks = set()  # Track currently blocked IPs
history_lock = threading.Lock()
ip_history = defaultdict(list)  # In-memory sliding window: IP -> list of timestamps
reputation_lock = threading.Lock()
reputation_cache = {}  # In-memory Threat Intel cache: IP -> {"intel": dict, "timestamp": float}

def log_print(msg: str):
    with print_lock:
        print(msg)

def record_ip_attempt(ip: str) -> int:
    """Record attempt timestamp for IP in a thread-safe sliding window and purge older records."""
    now = time.time()
    with history_lock:
        cutoff = now - LOCAL_BURST_WINDOW
        ip_history[ip] = [t for t in ip_history[ip] if t > cutoff]
        ip_history[ip].append(now)
        return len(ip_history[ip])

def get_cached_reputation(ip: str) -> Optional[Dict[str, Any]]:
    """Retrieve cached reputation intel for an IP if still within REPUTATION_CACHE_TTL.
    Purges expired entry and returns None on cache miss/expiry."""
    now = time.time()
    with reputation_lock:
        entry = reputation_cache.get(ip)
        if entry:
            if now - entry["timestamp"] <= REPUTATION_CACHE_TTL:
                return entry["intel"]
            else:
                del reputation_cache[ip]
    return None

def set_cached_reputation(ip: str, intel: Dict[str, Any]):
    """Thread-safely cache the reputation intel verdict for an IP."""
    with reputation_lock:
        reputation_cache[ip] = {
            "intel": intel,
            "timestamp": time.time()
        }

# -------------------------------------------------------------------
# 1. DISCORD ALERTING ENGINE
# -------------------------------------------------------------------

def send_discord_block_alert(ip: str, score: int, reports: int, country: str, source: str, duration: int, ai_analysis: str = None, intel_source: str = "AbuseIPDB API v2 (Live)"):
    """Send formatted Discord webhook alert when an IP is blocked."""
    if not DISCORD_WEBHOOK_URL:
        return

    fields = [
        {"name": "Target IP", "value": f"`{ip}`", "inline": True},
        {"name": "Threat Score", "value": f"**{score}%**", "inline": True},
        {"name": "Log Source", "value": f"`{source}`", "inline": True},
        {"name": "Country", "value": country, "inline": True},
        {"name": "AbuseIPDB Reports", "value": str(reports), "inline": True},
        {"name": "Intel Source", "value": f"`{intel_source}`", "inline": True},
        {"name": "Action Taken", "value": f"🛑 `iptables DROP ({duration}s temp block)`", "inline": False}
    ]

    # Append AI SOC Analyst triage brief if generated
    if ai_analysis:
        fields.append({
            "name": "🤖 AI SOC Analyst Triage",
            "value": ai_analysis,
            "inline": False  # Full width across the embed
        })

    payload = {
        "embeds": [
            {
                "title": "🚨 Automated Security Containment Event",
                "color": 15158332,  # Red
                "fields": fields,
                "footer": {"text": "Lightweight Python SOAR Engine | Automated Incident Triage"},
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

def send_discord_local_block_alert(ip: str, source: str, attempts: int, window: int, duration: int, abuseipdb_status: str = "Bypassed (Local Threshold Met)"):
    """Send formatted Discord webhook alert when an IP triggers local brute-force containment."""
    if not DISCORD_WEBHOOK_URL:
        return

    fields = [
        {"name": "Target IP", "value": f"`{ip}`", "inline": True},
        {"name": "Log Source", "value": f"`{source}`", "inline": True},
        {"name": "Reason", "value": f"🚨 `Local In-Memory Threshold Exceeded ({attempts} attempts in {window}s)`", "inline": False},
        {"name": "Status", "value": f"🛑 `Dropped at Host Netfilter (iptables) for {duration}s`", "inline": True},
        {"name": "AbuseIPDB Status", "value": f"`{abuseipdb_status}`", "inline": True}
    ]

    payload = {
        "embeds": [
            {
                "title": f"🚨 CONTAINMENT: Local Brute Force Detected ({attempts} attempts in <{window}s)",
                "color": 15158332,  # Red
                "fields": fields,
                "footer": {"text": "Lightweight Python SOAR Engine | In-Memory Sliding Window"},
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            }
        ]
    }

    try:
        res = requests.post(DISCORD_WEBHOOK_URL, json=payload, timeout=5)
        if res.status_code in [200, 204]:
            log_print("[✓] Discord local brute-force alert sent.")
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

def block_ip(ip: str) -> bool:
    """Automated containment via OS iptables with non-blocking expiration timer."""
    if ip in active_blocks:
        log_print(f"[*] IP {ip} is already actively blocked. Skipping duplicate rule.")
        return False

    log_print(f"[!] CONTAINMENT ACTION: Blocking IP {ip} via iptables for {BLOCK_DURATION_SECONDS}s...")
    try:
        # Verify rule presence to avoid duplicates
        check = subprocess.run(["sudo", "iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"], capture_output=True)
        if check.returncode == 0:
            log_print(f"[*] IP {ip} is already present in iptables.")
            active_blocks.add(ip)
            return False

        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        log_print(f"[✓] Successfully added iptables DROP rule for {ip}")
        active_blocks.add(ip)

        # Schedule async unblock timer
        timer = threading.Timer(BLOCK_DURATION_SECONDS, unblock_ip, args=[ip])
        timer.daemon = True
        timer.start()
        log_print(f"[*] Expiration timer started for {ip} ({BLOCK_DURATION_SECONDS} seconds)")

        return True
    except Exception as e:
        log_print(f"[-] Failed to block IP {ip}: {e}")
        return False

def check_ip_reputation(ip: str) -> Optional[Dict[str, Any]]:
    """Query AbuseIPDB API v2. Returns None on API error, timeout, or missing key."""
    if not ABUSEIPDB_KEY:
        log_print("[!] Missing ABUSEIPDB_API_KEY in .env file.")
        return None

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": "90"}

    try:
        res = requests.get(url, headers=headers, params=params, timeout=5)
        if res.status_code == 200:
            data = res.json().get("data", {})
            return {
                "score": data.get("abuseConfidenceScore", 0),
                "reports": data.get("totalReports", 0),
                "country": data.get("countryCode", "Unknown"),
                "isp": data.get("isp", "Unknown"),
                "usageType": data.get("usageType", "Unknown")
            }
        else:
            log_print(f"[-] AbuseIPDB API HTTP {res.status_code} for {ip}: {res.text[:200]}")
            return None
    except requests.exceptions.Timeout:
        log_print(f"[-] AbuseIPDB API timeout (5s) for {ip}")
        return None
    except Exception as e:
        log_print(f"[-] AbuseIPDB API request error for {ip}: {e}")
        return None

def generate_ai_triage(ip: str, source: str, threat_data: dict) -> str:
    """Generate an automated Tier 1 SOC Analyst summary using Gemini."""
    if not gemini_client:
        return "AI analysis skipped: GEMINI_API_KEY not configured."

    prompt = f"""
You are an autonomous Tier 1 SOC Analyst performing automated incident triage.
Analyze the following telemetry and provide an executive summary:

- Target IP: {ip}
- Ingestion Vector: {source}
- Abuse Confidence Score: {threat_data.get('score', 0)}%
- Country: {threat_data.get('country', 'Unknown')}
- Total Abuse Reports: {threat_data.get('reports', 0)}
- ISP: {threat_data.get('isp', 'Unknown')}
- Usage Type: {threat_data.get('usageType', 'Unknown')}

Instructions:
1. Explain the likely nature/intent of this traffic (e.g., botnet credential stuffing, Tor relay, automated scanner).
2. Assess the risk level.
3. Keep the total response under 3 sentences. Be direct, authoritative, and concise. No conversational filler.
"""
# 1. Try Primary Model
    try:
        response = gemini_client.models.generate_content(
            model="gemini-3.8-flash",
            contents=prompt,
        )
        return response.text.strip()
    except Exception as e:
        log_print(f"[-] [AI Analyst] Primary model (gemini-3.8-flash) failed: {e}")
        log_print("[*] [AI Analyst] Attempting fallback model (gemini-3.5-flash-lite)...")

    # 2. Try Fallback Model
    try:
        response = gemini_client.models.generate_content(
            model="gemini-3.5-flash-lite",
            contents=prompt,
        )
        return response.text.strip()
    except Exception as e:
        log_print(f"[-] [AI Analyst] Fallback model also failed: {e}")
        return "AI triage unavailable due to API error."

def evaluate_threat(ip: str, source_name: str):
    """Core evaluation pipeline shared by all log sources."""
    if ip.startswith("127.") or ip.startswith("192.168.") or ip.startswith("10.") or ip == "::1":
        log_print(f"[*] [{source_name}] Extracted internal IP ({ip}). Skipping checks.")
        return

    if ip in active_blocks:
        log_print(f"[*] [{source_name}] IP {ip} is already actively blocked. Skipping duplicate processing.")
        return

    # 1. Step A: Track attempt in sliding window & Local Brute-Force Check
    attempts = record_ip_attempt(ip)
    log_print(f"\n[+] [{source_name}] Extracted External IP: {ip} (Local count: {attempts}/{LOCAL_BURST_THRESHOLD} in {LOCAL_BURST_WINDOW}s)")

    if attempts >= LOCAL_BURST_THRESHOLD:
        log_print(f"[!] [{source_name}] LOCAL BRUTE-FORCE DETECTED: {ip} reached {attempts} attempts in {LOCAL_BURST_WINDOW}s. Initiating immediate containment...")
        if block_ip(ip):
            send_discord_local_block_alert(
                ip=ip,
                source=source_name,
                attempts=attempts,
                window=LOCAL_BURST_WINDOW,
                duration=BLOCK_DURATION_SECONDS,
                abuseipdb_status="Bypassed (Local Threshold Met)"
            )
        return

    # 2. Step B: Check Local Threat Intel Cache
    cached_intel = get_cached_reputation(ip)
    if cached_intel is not None:
        cached_score = cached_intel.get("score", 0)
        log_print(f"[+] [Threat Intel Cache] Cache hit for {ip} (Score: {cached_score}% | Country: {cached_intel.get('country')} | Reports: {cached_intel.get('reports')})")
        if cached_score >= 50:
            log_print(f"[!] [{source_name}] Known malicious IP from cache ({cached_score}% >= 50%). Blocking IP immediately...")
            if not block_ip(ip):
                return

            log_print(f"[*] [{source_name}] Requesting AI SOC triage for cached threat...")
            ai_summary = generate_ai_triage(ip, source_name, cached_intel)

            send_discord_block_alert(
                ip=ip,
                score=cached_score,
                reports=cached_intel.get('reports', 0),
                country=cached_intel.get('country', 'Unknown'),
                source=source_name,
                duration=BLOCK_DURATION_SECONDS,
                ai_analysis=ai_summary,
                intel_source="In-Memory Reputation Cache (Offline Match)"
            )
            return
        else:
            log_print(f"[*] [Threat Intel Cache] Cached score for {ip} is below threshold ({cached_score}% < 50%). Skipping AbuseIPDB check.")
            return

    # 3. Step C: Query AbuseIPDB API on Cache Miss
    log_print(f"[*] [{source_name}] Cache miss for {ip}. Querying AbuseIPDB API...")
    intel = check_ip_reputation(ip)

    # Handle AbuseIPDB Degradation / Fallback
    if intel is None:
        log_print(f"[!] [{source_name}] AbuseIPDB API degraded/unavailable for {ip}. Relying on local tracking.")
        if attempts >= LOCAL_BURST_THRESHOLD:
            log_print(f"[!] [{source_name}] Local in-memory threshold met for {ip} during threat intel degradation.")
            if block_ip(ip):
                send_discord_local_block_alert(
                    ip=ip,
                    source=source_name,
                    attempts=attempts,
                    window=LOCAL_BURST_WINDOW,
                    duration=BLOCK_DURATION_SECONDS,
                    abuseipdb_status="Down / API Error"
                )
        else:
            log_print(f"[-] [{source_name}] Warning: Threat intelligence offline. Monitoring IP {ip} via local tracking ({attempts}/{LOCAL_BURST_THRESHOLD} attempts).")
        return

    # Store verified verdict in local reputation cache
    set_cached_reputation(ip, intel)
    score = intel["score"]
    log_print(f"[+] [{source_name}] AbuseIPDB Match | Country: {intel['country']} | Reports: {intel['reports']} | Score: {score}% (Cached for {REPUTATION_CACHE_TTL}s)")

    # 4. Global Threat Intelligence Threshold Containment
    if score >= 50:
        log_print(f"[*] [{source_name}] Threat threshold met ({score}% >= 50%). Blocking IP immediately...")
        if not block_ip(ip):
            return

        log_print(f"[*] [{source_name}] Requesting AI SOC triage...")
        ai_summary = generate_ai_triage(ip, source_name, intel)

        send_discord_block_alert(
            ip=ip,
            score=score,
            reports=intel['reports'],
            country=intel['country'],
            source=source_name,
            duration=BLOCK_DURATION_SECONDS,
            ai_analysis=ai_summary,
            intel_source="AbuseIPDB API v2 (Live)"
        )

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
    log_print(f"[*] Local Brute-Force Policy: {LOCAL_BURST_THRESHOLD} attempts in {LOCAL_BURST_WINDOW}s window")
    log_print(f"[*] Threat Intel Cache: Enabled ({REPUTATION_CACHE_TTL}s TTL)")

    # --- SEED TEST DANGEROUS IP DIRECTLY INTO CACHE ---
    set_cached_reputation("198.51.100.77", {
        "score": 100,
        "reports": 999,
        "country": "XX",
        "isp": "Simulated Malicious ISP",
        "usageType": "Data Center"
    })
    log_print("[*] TEST: Pre-seeded 198.51.100.77 into threat intel cache (Score: 100%)")
    # --------------------------------------------------

    fastapi_thread = threading.Thread(target=watch_fastapi_logs, daemon=True)
    ssh_thread = threading.Thread(target=watch_ssh_logs, daemon=True)

    fastapi_thread.start()
    ssh_thread.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log_print("\n[!] Shutting down SOAR Engine...")