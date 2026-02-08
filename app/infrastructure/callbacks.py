"""
Final Callback Dispatcher – Agentic Honey-Pot System

This module implements the exactly-once final callback mechanism.
It is responsible for reporting session results to the central evaluation server
when the agent reaches the EXIT state.

CRITICAL RESPONSIBILITIES:
- Enforce exactly-once delivery (idempotency)
- Trigger only on strict conditions (scamDetected, EXIT, not sent yet)
- Handle network failures safely (retry logic)
- Mark session as closed upon success

DOES NOT:
- Decide WHEN to exit (AgentController responsibility)
- Modify conversation history
"""

import logging
import time
import requests
import os
from typing import Optional, Dict, Any
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from app.core.session import SessionManager, Session

# Configure logging
logger = logging.getLogger(__name__)


class FinalCallbackDispatcher:
    """
    Manages the reliable dispatch of the final session report.
    """

    def __init__(self, session_manager: SessionManager):
        self.session_manager = session_manager

        # Load from environment; must be configured for production
        self.callback_url = os.getenv("FINAL_CALLBACK_URL")
        if not self.callback_url:
            logger.error("FINAL_CALLBACK_URL is not configured. Callback disabled.")

        self.api_key = os.getenv("CALLBACK_API_KEY")

        self._http_client = self._configure_http_client()

    def _configure_http_client(self) -> requests.Session:
        """
        Configure HTTP client with retry logic for network resilience.

        WHY:
        - Network glitches shouldn't fail the entire evaluation
        - Retries with backoff prevent thundering herd
        """
        session = requests.Session()
        retries = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[500, 502, 503, 504],
            allowed_methods=["POST"],
        )
        adapter = HTTPAdapter(max_retries=retries)
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        return session

    def check_and_dispatch(self, session_id: str) -> bool:
        """
        Check if callback conditions are met and dispatch if so.
        """
        logger.info(f"Checking callback conditions for session {session_id}...")
        session = self.session_manager.get_session(session_id)

        if not session:
            logger.error(f"Session {session_id} not found during callback check.")
            return False

        # IDEMPOTENCY CHECK: If already sent, consider it a success (no-op)
        if session.callbackSent:
            logger.info(f"Callback already sent for session {session_id}. Skipping.")
            return True

        # TRIGGER CONDITIONS check
        if not self._should_trigger_callback(session):
            logger.info(
                f"Callback conditions NOT met for {session_id}. State={session.agentState}, ScamDetected={session.scamDetected}"
            )
            return False

        # Prepare Payload
        payload = self._build_payload(session)

        # Dispatch
        success = self._send_callback(payload)

        if success:
            try:
                # CRITICAL: Mark terminal state immediately after success
                self.session_manager.mark_callback_sent(session_id)
                self.session_manager.close_session(session_id)
                logger.info(f"Session {session_id} successfully finalized and closed.")
                return True
            except ValueError as e:
                # This catches race conditions where state might have changed
                logger.error(
                    f"Failed to close session {session_id} after callback: {str(e)}"
                )
                return False
        else:
            logger.error(
                f"Failed to send callback for session {session_id} after retries."
            )
            return False

    def _should_trigger_callback(self, session: Session) -> bool:
        """
        Evaluate if callback should be triggered.

        Must match docs/IMPLEMENTATION_FLOW.md Step 10 exactly.
        """
        if not session.scamDetected:
            return False

        if session.agentState != "EXIT":
            return False

        if session.callbackSent:
            return False

        return True

    def _build_payload(self, session: Session) -> Dict[str, Any]:
        """
        Construct payload matching API_CONTRACT.md final callback schema.
        """
        # Generate hybrid agent notes (Deterministic + Optional LLM)
        final_notes = self._generate_hybrid_agent_notes(session)

        # Update session with final notes for consistency
        session.agentNotes = final_notes

        return {
            "sessionId": session.sessionId,
            "status": "success",
            "scamDetected": session.scamDetected,
            "totalMessagesExchanged": session.totalMessagesExchanged,
            "engagementMetrics": {
                "engagementDurationSeconds": session.engagementMetrics.engagementDurationSeconds,
                "totalMessagesExchanged": session.totalMessagesExchanged,
            },
            "extractedIntelligence": {
                "bankAccounts": session.extractedIntelligence.bankAccounts,
                "upiIds": session.extractedIntelligence.upiIds,
                "phishingLinks": session.extractedIntelligence.phishingLinks,
                "phoneNumbers": session.extractedIntelligence.phoneNumbers,
                "suspiciousKeywords": session.extractedIntelligence.suspiciousKeywords,
            },
            "agentNotes": final_notes,
        }

    def _generate_hybrid_agent_notes(self, session: Session) -> str:
        """
        Generate agent notes using a deterministic base with optional LLM enrichment.
        """
        # 1. Deterministic Base (MANDATORY)
        base_notes = self._build_base_agent_notes(session)

        # 2. Optional LLM Enrichment (STRICTLY LIMITED)
        use_llm_notes = os.getenv("USE_LLM_AGENT_NOTES", "false").lower() == "true"

        if use_llm_notes:
            try:
                enriched_notes = self._enrich_notes_with_llm(base_notes)
                if enriched_notes:
                    return enriched_notes
            except Exception as e:
                logger.warning(
                    f"LLM agentNotes enrichment failed: {e}. Falling back to base notes."
                )

        return base_notes

    def _build_base_agent_notes(self, session: Session) -> str:
        """
        Derive deterministic, fact-based notes from extracted intelligence.
        """
        indicators = []
        intel = session.extractedIntelligence

        # Financial Credentials
        if intel.bankAccounts:
            indicators.append("Attempted financial credential extraction")

        # Urgency/Pressure
        urgency_terms = {
            "urgent",
            "immediately",
            "verify now",
            "block",
            "suspend",
            "expire",
            "act now",
        }
        if any(
            term in k.lower()
            for term in urgency_terms
            for k in intel.suspiciousKeywords
        ):
            indicators.append("Urgency and pressure tactics used")

        # Impersonation (inferred from bank keywords/context)
        if (
            "account" in str(intel.suspiciousKeywords).lower()
            or "bank" in str(intel.suspiciousKeywords).lower()
        ):
            indicators.append("Impersonation of bank authority")

        # External Redirection
        if intel.phishingLinks:
            indicators.append("Phishing vector deployed")
        if intel.upiIds or intel.phoneNumbers:
            indicators.append("External contact escalation attempted")

        # Coercion (Volume)
        if session.totalMessagesExchanged > 6:
            indicators.append("Repeated coercion across multiple messages")

        if not indicators:
            return "Scam intent detected; standard indicators observed."

        return "; ".join(indicators)

    def _enrich_notes_with_llm(self, base_notes: str) -> Optional[str]:
        """
        Refine base notes using LLM. Strictly rephrasing, no new facts.
        """
        # Only support Local/Ollama for this specific optional feature to keep it lightweight
        # or reuse the environment config if valid.

        backend = os.getenv("LLM_BACKEND", "local").lower()
        if backend != "local":
            return None  # Skip for non-local to avoid complexity in this helper for now

        base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")
        model_name = os.getenv("OLLAMA_MODEL", "llama3.1")

        prompt = (
            f"Task: Rewrite these scam indicators into ONE concise, professional analyst sentence.\n"
            f"Input: {base_notes}\n"
            f"Constraints: Do not add new facts. Do not speculate. Keep it under 30 words.\n"
            f"Output:"
        )

        try:
            response = requests.post(
                f"{base_url}/api/generate",
                json={"model": model_name, "prompt": prompt, "stream": False},
                timeout=5,
            )
            if response.status_code == 200:
                result = response.json().get("response", "").strip()
                return result if result else None
        except Exception:
            return None

        return None

    def _send_callback(self, payload: Dict[str, Any]) -> bool:
        """
        Execute the POST request with error handling.
        """
        if not self.callback_url:
            logger.error("Callback URL missing; cannot dispatch final callback.")
            return False
        try:
            logger.info("Sending final callback...")

            headers = {}
            if self.api_key:
                headers["x-api-key"] = self.api_key

            intel = payload.get("extractedIntelligence", {})
            intel_counts = {
                key: len(value)
                for key, value in intel.items()
                if isinstance(value, list)
            }
            logger.debug(
                "Sending callback payload summary: sessionId=%s, intelCounts=%s",
                payload.get("sessionId"),
                intel_counts,
            )

            response = self._http_client.post(
                self.callback_url, json=payload, headers=headers, timeout=10
            )

            if response.status_code in [200, 201, 202]:
                logger.info(f"Callback success: {response.status_code}")
                logger.info(f"Callback response body: {response.text}")
                return True
            else:
                logger.error(
                    f"Callback failed: {response.status_code} - {response.text}"
                )
                return False

        except requests.RequestException as e:
            logger.error(f"Callback network error: {str(e)}")
            return False
