# ThreatModel AI

An AI-powered threat modeling assistant that generates STRIDE-mapped threat models with MITRE ATT&CK mappings, real-world breach examples, and kill chain analysis. Built to demonstrate practical application security engineering skills including RAG architecture, prompt injection mitigation, and secure LLM application design.

---

## What it does

Describe your system architecture and the feature you are building. ThreatModel AI searches a curated security knowledge base, generates a structured threat model using the STRIDE framework, and returns:

- Specific threat descriptions mapped to STRIDE categories
- Likelihood ratings (High / Medium / Low)
- Step-by-step attack mechanisms
- Real-world breach examples with costs and references
- Kill chain stage mappings
- MITRE ATT&CK technique IDs
- Actionable mitigation steps
- Export as CSV or PDF

---

## Security Architecture

This project was built specifically to demonstrate hands-on experience securing AI/LLM-enabled applications.

### Prompt Injection Detection
Every user input passes through an input guardrail layer before reaching the LLM. Known injection patterns are detected and blocked with a 400 error before the RAG pipeline is invoked. Blocked attempts are logged with timestamp and context.

### Output Filtering and Validation
LLM responses pass through an output guardrail that parses and validates the JSON structure, removes duplicate threats, and ensures every field conforms to the response schema before returning to the client.

### Tenant-Isolated Vector Retrieval
Documents are stored in pgvector with source metadata. The retrieval pipeline scopes queries to return only relevant knowledge base chunks — the foundation for multi-tenant isolation patterns.

### RAG Architecture
The application uses Retrieval-Augmented Generation to ground LLM responses in a curated security knowledge base. This prevents hallucination and ensures threat models reference real attack patterns, CVEs, and breach data rather than generic LLM output.

### CORS Lockdown
The API enforces strict CORS — only the frontend origin is permitted. Wildcard origins are explicitly rejected.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Frontend | React + Tailwind CSS (Lovable) |
| API | FastAPI (Python) |
| LLM Orchestration | LangChain |
| LLM | Groq (llama-3.1-8b-instant) |
| Vector Database | PostgreSQL + pgvector |
| Embeddings | Ollama (nomic-embed-text) |
| Export | ReportLab (PDF), Python csv (CSV) |

---

## Knowledge Base

The RAG pipeline searches a curated knowledge base of security documentation including:

- STRIDE threat modeling framework with attack mechanisms and code examples
- OWASP Top 10 2021 with vulnerable and secure code patterns
- OWASP API Security Top 10
- JWT attack patterns — alg:none, algorithm confusion, token theft, brute force
- File upload attack patterns — web shells, path traversal, ImageTragick, zip bombs
- Real-world breach analysis — Equifax, Capital One, British Airways, SolarWinds, Uber, Yahoo, LastPass
- 2026 threat intelligence — PCPJack, Salt Typhoon, AI-accelerated attack chains

---

## Project Structure

```
threat-model-assistant/
├── backend/
│   ├── app/
│   │   ├── main.py                  # FastAPI entry point, CORS, route registration
│   │   ├── routes/
│   │   │   └── threat_model.py      # /analyze, /export/csv, /export/pdf endpoints
│   │   ├── services/
│   │   │   ├── rag.py               # LangChain RAG pipeline, pgvector search, Groq LLM
│   │   │   ├── guardrails.py        # Input prompt injection detection, output validation
│   │   │   └── embeddings.py        # Knowledge base ingestion into pgvector
│   │   ├── models/
│   │   │   └── schemas.py           # Pydantic request/response models
│   │   └── db/
│   │       └── pgvector.py          # PostgreSQL connection, pgvector setup
│   └── data/
│       └── knowledge_base/          # Markdown security documents ingested into pgvector
│           ├── stride_expanded.md
│           ├── owasp_top10.md
│           ├── api_security.md
│           ├── jwt_attacks.md
│           ├── file_upload_attacks.md
│           ├── real_world_breaches.md
│           └── current_threats.md
└── frontend/                        # React + Tailwind frontend
```

---

## How it works

```
User submits architecture + feature
        ↓
FastAPI receives POST /analyze
        ↓
Input guardrail — scans for prompt injection patterns
        ↓
LangChain converts query to vector using Ollama nomic-embed-text
        ↓
pgvector finds top 5 most semantically similar knowledge base chunks
        ↓
Prompt assembled with architecture, feature, and retrieved context
        ↓
Groq LLM generates structured JSON threat model
        ↓
Output guardrail — parses JSON, removes duplicates, validates schema
        ↓
ThreatModelResponse returned to frontend
```

---

## Running Locally

### Prerequisites
- Python 3.13+
- Node.js 18+
- PostgreSQL 18 with pgvector extension
- Ollama with nomic-embed-text model
- Groq API key (free at console.groq.com)

### Backend Setup

```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
```

Create `.env` in the backend folder:

```
DATABASE_URL=postgresql://<your-mac-username>@localhost:5432/threatmodel
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=llama3
GROQ_API_KEY=your_groq_api_key_here
API_KEY=client_key_for_the_analyze_and_export_endpoints
ADMIN_API_KEY=separate_key_for_the_/security_dashboard_endpoints
```

`API_KEY` is sent by clients in the `X-API-Key` header; if it is unset the
protected endpoints are open (useful for local dev). `ADMIN_API_KEY` guards the
`/security/*` dashboard endpoints via the `X-Admin-Key` header and fails closed
when unset.

Set up the database:

```bash
createdb threatmodel
python3 -m app.db.pgvector
```

Ingest the knowledge base:

```bash
python3 -m app.services.embeddings
```

Start the API:

```bash
uvicorn app.main:app --reload
```

API runs at `http://localhost:8000`. Docs available at `http://localhost:8000/docs`.

### Frontend Setup

```bash
cd frontend
npm install
npm run dev
```

Frontend runs at `http://localhost:8080`.

---

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | /health | Health check |
| POST | /analyze | Run STRIDE threat model analysis |
| POST | /export/csv | Export threat model as CSV |
| POST | /export/pdf | Export threat model as PDF |

### Example Request

```bash
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "architecture": "Node.js REST API with JWT authentication, PostgreSQL, AWS S3",
    "feature": "User file upload"
  }'
```

### Example Response

```json
{
  "threats": [
    {
      "threat": "Attacker uploads malicious file bypassing type validation to achieve remote code execution",
      "category": "Tampering",
      "likelihood": "High",
      "mitigation": "Validate file type by reading magic bytes, generate random filenames, store outside web root",
      "mitre_mapping": "T1505 Server Software Component",
      "attack_mechanism": "Attacker renames a PHP web shell to profile.php.jpg, bypasses weak MIME check, uploads to web-accessible directory, visits the URL to execute arbitrary commands",
      "real_world_example": "Healthcare provider 2021 — web shell uploaded through insecure endpoint, 9 months of undetected access, 4 million patient records exfiltrated",
      "kill_chain": ["Initial Access", "Execution", "Persistence", "Exfiltration"],
      "code_example": "Never use user-supplied filenames or trust Content-Type headers for file type validation"
    }
  ],
  "raw_response": "..."
}
```

---

## Author

Anthony Gordon — AppSec Engineer  
[GitHub](https://github.com/AnthonyGordon1)