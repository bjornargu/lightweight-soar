import logging
from pathlib import Path
from fastapi import FastAPI, Request

app = FastAPI()

BASE_DIR = Path(__file__).resolve().parent.parent
LOG_FILE = BASE_DIR / "logs" / "alerts.log"
LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

logging.basicConfig(filename=str(LOG_FILE), level=logging.INFO, format="%(asctime)s | %(message)s")

@app.post("/api/v1/login")
async def login(request: Request):
    forwarded_for = request.headers.get("X-Forwarded-For")
    client_ip = forwarded_for if forwarded_for else request.client.host

    body = await request.json()
    username = body.get("username", "unknown")

    logging.info(f"LOGIN_ATTEMPT | IP={client_ip} | User={username}")
    return {"status": "processed", "logged_ip": client_ip}