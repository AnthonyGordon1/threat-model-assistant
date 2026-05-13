import os
import time
from fastapi import HTTPException, Security, Request
from fastapi.security.api_key import APIKeyHeader
from dotenv import load_dotenv
from app.services.logger import log_security_event

load_dotenv()

API_KEY = os.getenv("API_KEY")
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

failed_attempts = {}
MAX_ATTEMPTS = 10
LOCKOUT_SECONDS = 300

def is_locked_out(ip: str) -> bool:
    if ip not in failed_attempts:
        return False
    now = time.time()
    failed_attempts[ip] = [t for t in failed_attempts[ip] if now - t < LOCKOUT_SECONDS]
    return len(failed_attempts[ip]) >= MAX_ATTEMPTS

def record_failed_attempt(ip: str):
    if ip not in failed_attempts:
        failed_attempts[ip] = []
    failed_attempts[ip].append(time.time())

async def verify_api_key(request: Request, api_key: str = Security(api_key_header)):
    if not API_KEY:
        return

    ip = request.client.host

    if is_locked_out(ip):
        log_security_event(
            event_type="api_key_lockout",
            ip_address=ip,
            status_code=429
        )
        raise HTTPException(status_code=429, detail="Too many failed attempts. Try again in 5 minutes.")

    if api_key != API_KEY:
        record_failed_attempt(ip)
        log_security_event(
            event_type="invalid_api_key",
            ip_address=ip,
            status_code=403
        )
        raise HTTPException(status_code=403, detail="Invalid or missing API key")