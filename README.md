# Lightweight Python SOAR Engine (SecOps)

The early stages of a lightweight Security Orchestration, Automation, and Response (SOAR) pipeline built in Python. Designed for rapid threat detection, automated threat intelligence enrichment, and host-level containment with minimal system overhead.

## Architecture & Workflow

1. **Ingestion:** FastAPI endpoint simulates an exposed web application logging client login attempts (`alerts.log`). Also monitors host-level SSH authentication events continuously via `journalctl -t sshd`.
2. **Parsing & Triage:** Python worker continuously tails the log streams and extracts client IP addresses using regex.
3. **Enrichment:** Queries the **AbuseIPDB API** to check the global reputation score and report history of external IPs.
4. **Automated Response:** If the threat score exceeds the defined threshold (e.g. 50%), the engine automatically executes an OS-level `iptables` DROP rule to isolate the host. An async timer (`threading.Timer`) with a defined threshold in seconds (e.g 300) removes the block rule (`iptables -D`) after said time. A discord webhook fires alerts on threath mitigation and recovery.

```mermaid
flowchart TD
    %% Styling
    classDef source fill:#1e293b,stroke:#475569,stroke-width:2px,color:#f8fafc;
    classDef engine fill:#0f172a,stroke:#38bdf8,stroke-width:2px,color:#f8fafc;
    classDef enrich fill:#1e1b4b,stroke:#818cf8,stroke-width:2px,color:#f8fafc;
    classDef ai fill:#312e81,stroke:#c084fc,stroke-width:2px,color:#f8fafc;
    classDef block fill:#450a0a,stroke:#ef4444,stroke-width:2px,color:#f8fafc;
    classDef recover fill:#052e16,stroke:#22c55e,stroke-width:2px,color:#f8fafc;
    classDef alert fill:#3b0764,stroke:#d8b4fe,stroke-width:2px,color:#f8fafc;

    %% Ingestion Sources
    subgraph Ingestion["1. Telemetry Ingestion"]
        APP["FastAPI Application<br/><code>logs/alerts.log</code>"]:::source
        SSH["System SSH Daemon<br/><code>journalctl -t sshd</code>"]:::source
    end

    %% Core Engine & Parsing
    subgraph Engine["2. Detection & Filtering"]
        SOAR["SOAR Engine Worker<br/><code>soar-engine.py</code>"]:::engine
        FILTER{"Private IP Check<br/>RFC 1918 / Loopback?"}:::engine
    end

    APP -->|Tail log stream| SOAR
    SSH -->|Stream events| SOAR
    SOAR -->|Regex extract IP| FILTER

    FILTER -->|Yes: Internal IP| SKIP["Drop & Skip Check"]:::source
    FILTER -->|No: External IP| API

    %% Threat Intelligence & AI Triage
    subgraph Analysis["3. Threat Intelligence & AI Triage"]
        API["AbuseIPDB API v2<br/>Reputation & Score"]:::enrich
        SCORE{"Abuse Score >= 50%?"}:::enrich
        GEMINI["Google Gemini API<br/><code>gemini-3.8-flash</code><br/>Tier 1 SOC Analyst Triage"]:::ai
    end

    API --> SCORE
    SCORE -->|No: Low Threat| LOG["Log & Monitor"]:::source
    SCORE -->|Yes: High Threat| GEMINI

    %% Automated Remediation & Alerts
    subgraph Response["4. Automated Remediation & Recovery"]
        IPTABLES["Execute Host Isolation<br/><code>iptables -A INPUT -s IP -j DROP</code>"]:::block
        TIMER["Async Recovery Timer<br/><code>threading.Timer (60s)</code>"]:::engine
        CLEANUP["Automated Rule Cleanup<br/><code>iptables -D INPUT -s IP -j DROP</code>"]:::recover
        DISCORD_BLOCK["Discord Webhook<br/>🚨 Containment Alert + AI Brief"]:::alert
        DISCORD_UNBLOCK["Discord Webhook<br/>🟢 Recovery Alert"]:::alert
    end

    GEMINI --> IPTABLES
    IPTABLES --> DISCORD_BLOCK
    IPTABLES --> TIMER
    TIMER -->|After 60s expiration| CLEANUP
    CLEANUP --> DISCORD_UNBLOCK
```
  

## Tech Stack
* **Language:** Python 3.12
* **Web Framework:** FastAPI / Uvicorn
* **Threat Intel:** AbuseIPDB v2 REST API
* **System Containment:** Linux `iptables` / Subprocess Orchestration

### Prerequisites
* Linux OS (Tested on Fedora)
* Python 3.10+
* `sudo` privileges for `iptables` rules


