# app.py
from fastapi import FastAPI, Request
import logging

app = FastAPI()
logging.basicConfig(filename="logs/alerts.log", level=logging.INFO, format="%(asctime)s | %(message)s")

@app.post("/api/v1/login")
async def login(request: Request):
    client_ip = request.client.host
    body = await request.json()
    
    # Log event for the SOAR engine to process
    logging.info(f"LOGIN_ATTEMPT | IP={client_ip} | User={body.get('username')}")
    return {"status": "processed"}