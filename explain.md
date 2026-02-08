# Agentic Honey-Pot System Explanation

This document provides a detailed explanation of the Agentic Honey-Pot System, including its high-level architecture, a step-by-step workflow, and a file-by-file breakdown of the codebase.

## High-Level Overview

This project is an "Agentic Honey-Pot System" designed to interact with potential scammers. It uses a FastAPI backend to receive messages, analyze them for scam-related content, extract intelligence (like bank details or phishing links), and generate convincing replies using a stateful agent. The goal is to keep scammers engaged, gather actionable intelligence, and then terminate the conversation, sending a final report via a callback.

The project is structured into three main directories:

- `app/`: Contains the core backend logic for the FastAPI application.
- `tests/`: Includes automated tests to ensure the system behaves as expected.
- `tools/`: Contains auxiliary tools, such as a Streamlit application for interacting with the system.

---

## System Workflow

The system processes incoming messages through a well-defined pipeline:

1.  **API Request**: A client sends a POST request to the `/honeypot/message` endpoint with a message from a "scammer". The request must contain a valid API key.
2.  **Session Management**: The `SessionManager` retrieves the conversation session based on the `sessionId`. If it's the first message, a new session is created with a randomly assigned agent persona (e.g., "confused_elderly", "busy_professional").
3.  **Lifecycle Check**: The system immediately checks if the session is already closed. If so, it returns an HTTP `409 Conflict` response containing a final summary of the conversation, and processing stops.
4.  **Message Processing**: The new message is appended to the session's history.
5.  **Scam Detection**: If a scam has not yet been confirmed for the session, the `ScamDetectionEngine` analyzes the message. It uses a combination of keyword matching and optional LLM classification to produce a confidence score. If the score exceeds a threshold, the session is marked as `scamDetected`.
6.  **Intelligence Extraction**: The `IntelligenceExtractionEngine` uses regular expressions to parse the message for artifacts like phone numbers, UPI IDs, bank accounts, and phishing links. Any new findings are added to the session's intelligence log.
7.  **State Transition**: The `AgentController`, the agent's "brain," receives signals based on the analysis (e.g., `URGENCY_DETECTED`, `ARTIFACTS_SHARED`). It uses a deterministic state machine to decide the agent's next behavioral state (e.g., from `TRUST_BUILDING` to `INFORMATION_EXTRACTION`).
8.  **Reply Generation**: The `AgentReplyService` is tasked with generating a human-like response. Based on the agent's current state, its persona, and the conversation history, it either selects a response from a pre-defined template or uses an LLM to generate one.
9.  **Response & Update**: The agent's reply is appended to the session history and sent back to the client in an HTTP `200 OK` response.
10. **Exit and Callback**: This loop continues until the `AgentController` transitions the state to `EXIT`. At this point, the `FinalCallbackDispatcher` compiles a complete report of the session and sends it to a pre-configured webhook. Upon successful dispatch, the session is marked as `closed` and becomes immutable.
11. **Optional Export**: If enabled, a redacted snapshot of extracted intelligence is written to a local JSONL file for display or audit purposes.

---

## File-by-File Explanation

### Configuration Files

- **`.gitignore`**: Specifies files and directories that Git should ignore, such as the Python virtual environment (`venv/`), cache files (`__pycache__/`), and local environment configurations (`.env`).
- **`.python-version`**: A simple file containing `3.11`, used by tools like `pyenv` to ensure the correct Python version is used for the project.
- **`requirements.txt`**: Lists all the Python dependencies required to run the project, such as `fastapi`, `uvicorn`, `pydantic`, `streamlit`, and `requests`. This allows for easy installation of dependencies using `pip install -r requirements.txt`.
- **`.env.example`**: An example file that shows the structure and names of the environment variables needed to configure the application (e.g., API keys, callback URLs, LLM settings). It serves as a template for the actual `.env` file.

### `app/` (Core Application)

This directory contains the main application logic.

- **`app/__init__.py`**: An empty file that marks the `app` directory as a Python package, allowing modules within it to be imported.

- **`app/main.py`**:
  - **Role**: The central nervous system of the application.
  - **Functionality**: It sets up the FastAPI server and defines the primary `/honeypot/message` endpoint. It orchestrates the entire workflow described above, from validating the API key and managing the session to calling the various engines, controllers, and services, and finally returning the appropriate HTTP response.

#### `app/agent/`

This sub-package contains logic related to the honeypot agent's behavior.

- **`app/agent/__init__.py`**: An empty file that marks the `agent` directory as a Python sub-package.
- **`app/agent/controller.py`**:
  - **Role**: Defines the agent's "brain" and state machine.
  - **Functionality**: It contains the `AgentController` class, which implements a deterministic state machine (e.g., `INIT` -> `CONFUSED` -> `TRUST_BUILDING` -> `INFORMATION_EXTRACTION` -> `EXIT`). It uses `TransitionSignal` enums (like `URGENCY_DETECTED`) generated from message analysis to decide when to move from one state to the next. Helper functions like `detect_urgency` and `detect_payment_request` are included to produce these signals.
- **`app/agent/reply_service.py`**:
  - **Role**: Responsible for crafting the agent's textual replies.
  - **Functionality**: The `AgentReplyService` separates the _how_ of replying from the _what_ (which is decided by the `AgentController`). It can operate in two modes: using pre-defined, persona-specific templates for safe, deterministic replies, or (if enabled) using an LLM to generate more dynamic responses. It takes the agent's state, persona, and conversation context as input to generate a fitting reply.

#### `app/core/`

This sub-package holds the core data structures and analysis engines.

- **`app/core/__init__.py`**: An empty file that marks the `core` directory as a Python sub-package.
- **`app/core/session.py`**:
  - **Role**: Defines the data structures for managing conversation state.
  - **Functionality**: It contains the `Session` dataclass, which is the schema for a conversation's state (history, extracted intel, agent state, etc.). The `SessionManager` is a singleton class that holds all active sessions in an in-memory dictionary, providing methods to create, retrieve, and update sessions while enforcing lifecycle rules (e.g., an `EXIT` state is final).
- **`app/core/intelligence.py`**:
  - **Role**: The engine for extracting structured data from messages.
  - **Functionality**: The `IntelligenceExtractionEngine` is a stateless service that uses a set of compiled regular expressions to find and pull out artifacts like UPI IDs, Indian phone numbers, bank account numbers, and URLs from raw text.
- **`app/core/scam_detection.py`**:
  - **Role**: The engine for identifying scam attempts.
  - **Functionality**: The `ScamDetectionEngine` uses a multi-layered approach. It calculates a confidence score based on keyword matching and regex patterns. Optionally, it can use an LLM (local or cloud-based) for more nuanced classification. The scores are combined deterministically to decide if a message is a scam.

#### `app/infrastructure/`

This sub-package handles interactions with external systems.

- **`app/infrastructure/__init__.py`**: An empty file that marks the `infrastructure` directory as a Python sub-package.
- **`app/infrastructure/callbacks.py`**:
  - **Role**: Manages the final, exactly-once callback to the evaluation server.
  - **Functionality**: The `FinalCallbackDispatcher` is triggered when a session's state becomes `EXIT`. It constructs a final JSON payload with all the session's metrics and intelligence. It uses a robust HTTP client with automatic retries to send this payload to a configured webhook URL. To prevent duplicates, it marks the session as `callbackSent` and `sessionClosed` upon success.
- **`app/infrastructure/intel_exporter.py`**:
  - **Role**: Writes redacted intelligence snapshots for display.
  - **Functionality**: The `IntelligenceExporter` emits JSONL records with counts and redacted samples of extracted intelligence. It is controlled by environment variables and never writes raw sensitive values.

### `tests/` (Automated Tests)

This directory contains `pytest` tests to verify the application's logic.

- **`tests/__init__.py`**: An empty file that marks the `tests` directory as a Python package.
- **`tests/test_closed_session_409.py`**:
  - **Purpose**: Tests the crucial requirement that sending a message to a closed session must return an HTTP `409 Conflict` status. It also verifies that the response body contains the correct informational summary and that no session data is mutated.
- **`tests/test_multi_persona.py`**:
  - **Purpose**: This test appears to be a script to verify that the system can manage multiple sessions with different agent personas simultaneously, ensuring that session states and personas remain isolated and consistent.
- **`tests/test_session_lifecycle.py`**:
  - **Purpose**: This test validates the `SessionManager`. It checks that a session is initialized correctly, transitions through its lifecycle stages as expected, and that terminal states (like `EXIT` and `sessionClosed`) are enforced, making the session immutable after it ends.

### `tools/` (Utility Tools)

- **`tools/streamlit_app.py`**:
  - **Role**: A simple web-based UI for developers and testers.
  - **Functionality**: This script creates a chat interface using the Streamlit library. It allows a user to manually send messages to the honeypot's API endpoint and see the agent's replies in real-time. It's a valuable tool for debugging, demonstrating, and manually testing the agent's behavior without needing to write code or use `curl`.
