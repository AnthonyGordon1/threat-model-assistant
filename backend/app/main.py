import os
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from dotenv import load_dotenv
from app.routes.threat_model import router as threat_model_router
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from app.routes.threat_model import router as threat_model_router
from app.services.logger import setup_security_logs_table, log_security_event
load_dotenv()

ENVIRONMENT = os.getenv("ENVIRONMENT", "development")
limiter = Limiter(key_func=get_remote_address)


app = FastAPI(
    title="Threat Model Assistant",
    description="AI-powered threat modeling using STRIDE and MITRE ATT&CK",
    version="1.0.0",
    docs_url="/docs" if os.getenv("ENVIRONMENT") == "development" else None,
    redoc_url="/redoc" if os.getenv("ENVIRONMENT") == "development" else None,
    openapi_url="/openapi.json" if os.getenv("ENVIRONMENT") == "development" else None,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["server"] = "webserver"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    response.headers["Cross-Origin-Embedder-Policy"] = "require-corp"
    response.headers["X-Permitted-Cross-Domain-Policies"] = "none"
    if ENVIRONMENT != "development":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = "default-src 'self'"
    return response

@app.middleware("http")
async def limit_request_size(request: Request, call_next):
    max_body_size = 10_000
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > max_body_size:
        log_security_event(
            event_type="oversized_request",
            ip_address=request.client.host,
            status_code=413
        )
        return JSONResponse(
            status_code=413,
            content={"detail": "Request body too large"}
        )
    return await call_next(request)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8080"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

app.include_router(threat_model_router, prefix="")

@app.on_event("startup")
async def startup():
    setup_security_logs_table()
    
@app.get("/health")
async def health():
    return {"status": "ok"}