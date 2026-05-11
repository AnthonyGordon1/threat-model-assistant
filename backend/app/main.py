from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
from app.routes.threat_model import router as threat_model_router

load_dotenv()

app = FastAPI(
    title="Threat Model Assistant",
    description="AI-powered threat modeling using STRIDE and MITRE ATT&CK",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8080"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(threat_model_router)

@app.get("/health")
async def health():
    return {"status": "ok"}