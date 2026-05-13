import os
from fastapi import HTTPException, Security
from fastapi.security.api_key import APIKeyHeader
from dotenv import load_dotenv
from app.services.logger import log_security_event

load_dotenv()

API_KEY = os.getenv("API_KEY")
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

async def verify_api_key(api_key: str = Security(api_key_header)):
    if not API_KEY:
        return
    if api_key != API_KEY:
        log_security_event(
            event_type="invalid_api_key",
            status_code=403
        )
        raise HTTPException(status_code=403, detail="Invalid or missing API key")