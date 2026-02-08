# Agentic Honey-Pot System

A stateful, agentic honeypot that detects scam intent, engages with a controlled persona, extracts structured intelligence, and concludes the session safely. The system is built around a single API endpoint, strict session lifecycle rules, and deterministic state transitions.

## Why it is useful

- Keeps scammer engagement controlled and explainable
- Extracts actionable intelligence (UPI IDs, phone numbers, phishing links)
- Enforces session immutability and exactly-once final callbacks
- Optional, redacted intelligence export for display and audits

## Architecture at a glance

- API layer: FastAPI endpoint for incoming messages
- Session manager: append-only state, terminal flags, per-session locking
- Detection: scam scoring and confidence tracking
- Agent controller: deterministic state machine
- Reply service: persona-driven responses (template or LLM)
- Intelligence extraction: regex-based, deduplicated
- Final callback: exactly-once dispatch on EXIT

## Quickstart

1. Create a virtual environment and install dependencies.

```
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

2. Configure environment variables.

- Copy `.env.example` to `.env`
- Set `HONEYPOT_API_KEY`
- Set `FINAL_CALLBACK_URL`
- (Optional) Enable `INTEL_EXPORT_ENABLED`

3. Run the API server.

```
python -m app.main
```

4. Send a request.

```
curl -X POST http://127.0.0.1:8000/honeypot/message \
  -H "Content-Type: application/json" \
  -H "x-api-key: <YOUR_API_KEY>" \
  -d "{\"sessionId\": \"demo-1\", \"message\": {\"sender\": \"scammer\", \"text\": \"Your account is blocked, verify now\", \"timestamp\": 1738972800000}}"
```

## Optional display export

Set these variables to write redacted intelligence snapshots to JSONL:

- `INTEL_EXPORT_ENABLED=true`
- `INTEL_EXPORT_PATH=exports/intel_snapshots.jsonl`
- `INTEL_EXPORT_MAX_SAMPLES=5`

Each line contains counts and redacted samples only.

## Demo UI

A Streamlit tester is available in [tools/streamlit_app.py](tools/streamlit_app.py).

```
streamlit run tools/streamlit_app.py
```

## Tests

```
pytest
```

## Docs

- Architecture plan: [docs/PLAN.md](docs/PLAN.md)
- Session schema: [docs/SESSION_SCHEMA.md](docs/SESSION_SCHEMA.md)
- Agent state machine: [docs/AGENT_STATE_MACHINE.md](docs/AGENT_STATE_MACHINE.md)
- Intelligence extraction rules: [docs/INTELLIGENCE_EXTRACTION_RULES.md](docs/INTELLIGENCE_EXTRACTION_RULES.md)
- API contract: [docs/API_CONTRACT.md](docs/API_CONTRACT.md)
- Implementation flow: [docs/IMPLEMENTATION_FLOW.md](docs/IMPLEMENTATION_FLOW.md)

## Production notes

- Configure a durable session store (Redis) if needed
- Enforce TLS and rate limiting at the gateway
- Keep the callback endpoint private and authenticated
- Avoid logging raw extracted values
