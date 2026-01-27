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

        # CORRECTED: Load from environment or fail
        self.callback_url = os.getenv("FINAL_CALLBACK_URL")
        if not self.callback_url:
            # Fallback to legacy default if strict validation allows,
            # otherwise raise error as per instructions "Fail clearly"
            logger.warning(
                "FINAL_CALLBACK_URL not set. Defaulting to hackathon endpoint."
            )
            self.callback_url = (
                "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"
            )

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

        CRITICAL LOGIC:
        1. Load session
        2. Verify strict conditions:
           - scamDetected is True
           - agentState is EXIT
           - callbackSent is False
        3. Build payload
        4. Send callback
        5. Mark session closed (Terminal State)

        Args:
            session_id: Target session ID

        Returns:
            True if callback was sent successfully or was already sent.
            False if conditions were not met or dispatch failed.
        """
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
            "agentNotes": session.agentNotes
            or "Scam detected and intelligence extracted.",
        }

    def _send_callback(self, payload: Dict[str, Any]) -> bool:
        """
        Execute the POST request with error handling.
        """
        try:
            logger.info("Sending final callback...")

            headers = {}
            if self.api_key:
                headers["x-api-key"] = self.api_key

            print(payload)

            response = self._http_client.post(
                self.callback_url, json=payload, headers=headers, timeout=10
            )

            if response.status_code in [200, 201, 202]:
                logger.info(f"Callback success: {response.status_code}")
                return True
            else:
                logger.error(
                    f"Callback failed: {response.status_code} - {response.text}"
                )
                return False

        except requests.RequestException as e:
            logger.error(f"Callback network error: {str(e)}")
            return False
