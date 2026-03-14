# HoneyPot Agent

<div align="center">

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-API-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Pytest](https://img.shields.io/badge/Tests-pytest-0A9EDC?style=for-the-badge&logo=pytest&logoColor=white)](https://docs.pytest.org/)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://docs.docker.com/compose/)
[![Redis](https://img.shields.io/badge/Redis-Session_Store-DC382D?style=for-the-badge&logo=redis&logoColor=white)](https://redis.io/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-Persistence-4169E1?style=for-the-badge&logo=postgresql&logoColor=white)](https://www.postgresql.org/)

</div>

Stateful, agentic honeypot backend for scam engagement. The service receives incoming scammer messages, detects scam intent, transitions through a deterministic agent state machine, extracts intelligence via regex, and triggers a final callback exactly once when the session exits.

## Key Capabilities

- Single public API endpoint for multi-turn engagement
- Strict per-session lifecycle with terminal closure rules
- Deterministic agent behavior driven by agent state
- Regex-only intelligence extraction with deduplication
- Exactly-once final callback dispatch on EXIT
- Optional redacted intelligence snapshot export
- Pluggable session store: in-memory or Redis + Postgres

## Project Structure

```text
.
|- app/
|  |- main.py                     # FastAPI app and request orchestration
|  |- agent/
|  |  |- controller.py            # State machine and transition signals
|  |  |- reply_service.py         # Persona/state-based reply generation
|  |- core/
|  |  |- scam_detection.py        # Scam detection scoring
|  |  |- intelligence.py          # Regex intelligence extraction
|  |  |- session.py               # Session schema and lifecycle manager
|  |- infrastructure/
|     |- session_store.py         # Memory / Redis+Postgres store wiring
|     |- callbacks.py             # Final callback dispatcher
|     |- intel_exporter.py        # Redacted export writer
|- docs/                          # Authoritative architecture and contracts
|- tests/                         # Pytest suite
|- tools/streamlit_app.py         # Streamlit test harness
|- docker-compose.yml
|- Dockerfile
|- requirements.txt
```

## API Summary

### Endpoint

- Method: POST
- Path: /honeypot/message
- Auth header: x-api-key

### Request (shape)

```json
{
  "sessionId": "optional-session-id",
  "message": {
    "sender": "scammer",
    "text": "Your account is blocked. Verify now.",
    "timestamp": 1738972800000
  },
  "conversationHistory": [],
  "metadata": {
    "channel": "WhatsApp",
    "language": "English",
    "locale": "IN"
  }
}
```

### Response (current runtime model)

```json
{
  "status": "success",
  "reply": "I am not sure. What should I do now?"
}
```

When a session is closed, the endpoint returns HTTP 409 with session summary details.

### Health Check

- GET /health
- POST /health
- HEAD /health

## Quick Start (Local)

1. Create and activate a virtual environment.

```bash
python -m venv venv
venv\Scripts\activate
```

2. Install dependencies.

```bash
pip install -r requirements.txt
```

3. Configure environment variables.

```bash
copy .env.example .env
```

At minimum set:

- HONEYPOT_API_KEY
- FINAL_CALLBACK_URL
- CALLBACK_API_KEY (if your callback endpoint requires it)

4. Start the API.

```bash
python -m app.main
```

5. Send a test request.

```bash
curl -X POST http://127.0.0.1:8000/honeypot/message \
  -H "Content-Type: application/json" \
  -H "x-api-key: YOUR_SECRET_API_KEY" \
  -d "{\"sessionId\":\"demo-1\",\"message\":{\"sender\":\"scammer\",\"text\":\"Your KYC is blocked. Share UPI now\",\"timestamp\":1738972800000}}"
```

## Run with Docker Compose

```bash
docker compose up --build
```

Compose provisions:

- App on port 8000
- Redis session layer
- Postgres persistence

Intelligence exports are written to exports/intel_snapshots.jsonl when enabled.

## Environment Variables

Use .env.example as the source of truth. Important variables include:

- ENVIRONMENT
- HONEYPOT_API_KEY
- SESSION_STORE (memory or redis_postgres)
- REDIS_URL
- POSTGRES_DSN
- FINAL_CALLBACK_URL
- CALLBACK_API_KEY
- USE_LLM, LLM_BACKEND, STRICT_LLM_MODE
- OPENAI_API_KEY / GEMINI_API_KEY (when using cloud LLM backends)
- INTEL_EXPORT_ENABLED, INTEL_EXPORT_PATH, INTEL_EXPORT_MAX_SAMPLES

## Testing

```bash
pytest -v
```

## Streamlit Tester

```bash
streamlit run tools/streamlit_app.py
```

## Reference Docs

- docs/PLAN.md
- docs/SESSION_SCHEMA.md
- docs/AGENT_STATE_MACHINE.md
- docs/INTELLIGENCE_EXTRACTION_RULES.md
- docs/API_CONTRACT.md
- docs/IMPLEMENTATION_FLOW.md

## Security and Operational Notes

- Keep sessions append-only and respect terminal flags
- Do not expose callback endpoints publicly without authentication
- Avoid logging raw sensitive intelligence values
- Prefer Redis + Postgres for durable deployments

## License

No explicit license file is currently present in this repository.
