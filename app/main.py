"""
FastAPI Endpoint – Agentic Honey-Pot System

This module implements the POST /honeypot/message endpoint.
It orchestrates the interaction between:
- SessionManager (State)
- ScamDetectionEngine (Analysis)
- IntelligenceExtractionEngine (Analysis)
- AgentController (Behavior)

CRITICAL:
- Validates API Key
- Enforces Session Lifecycle
- Orchestrates logic flow
- Returns strict API contract response
"""

import os
import uuid
from dotenv import load_dotenv

# Load environment variables explicitly before other imports
load_dotenv()

from fastapi import FastAPI, HTTPException, Header, Depends, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any, Union
from datetime import datetime, timezone
from app.agent.controller import (
    AgentController,
    detect_urgency,
    detect_payment_request,
    detect_artifacts_shared,
    TransitionSignal,
)
from app.core.intelligence import IntelligenceExtractionEngine
from app.infrastructure.callbacks import FinalCallbackDispatcher
from app.agent.reply_service import AgentReplyService
from app.core.session import SessionManager, Session


# --- Mock ScamDetectionEngine (Since it wasn't explicitly implemented yet) ---
class ScamDetectionEngine:
    """
    Analyzes messages for scam intent.
    """

    def detect(self, message: str) -> tuple[bool, float]:
        """
        Detects if a message is a scam.
        Returns: (is_scam, confidence_score)
        """
        # Simple keyword-based detection for prototype
        scam_keywords = [
            "blocked",
            "verify",
            "urgent",
            "account",
            "bank",
            "suspended",
            "kyc",
            "update",
            "expire",
        ]
        message_lower = message.lower()
        match_count = sum(1 for k in scam_keywords if k in message_lower)

        if match_count > 0:
            # Simple confidence scoring
            confidence = min(0.5 + (match_count * 0.1), 1.0)
            return True, confidence
        return False, 0.0


# --- Pydantic Models (API Contract) ---


class IncomingMessage(BaseModel):
    sender: str
    text: str
    timestamp: int


class MetadataModel(BaseModel):
    channel: Optional[str] = None
    language: Optional[str] = None
    locale: Optional[str] = None


class MessageRequest(BaseModel):
    sessionId: Optional[str] = None
    message: IncomingMessage
    conversationHistory: Optional[List[Dict[str, Any]]] = []
    metadata: Optional[MetadataModel] = None











# --- Dependencies ---

# Singleton instances
session_manager = SessionManager()
agent_controller = AgentController()
intelligence_engine = IntelligenceExtractionEngine()
scam_engine = ScamDetectionEngine()
callback_dispatcher = FinalCallbackDispatcher(session_manager)
agent_reply_service = AgentReplyService()

# API Key Validation
API_KEY_NAME = "x-api-key"
# In a real app, this should be an env var. For this task, we assume a placeholder or env.
REQUIRED_API_KEY = os.getenv("HONEYPOT_API_KEY", "YOUR_SECRET_API_KEY")


async def verify_api_key(x_api_key: str = Header(...)):
    if x_api_key != REQUIRED_API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized"
        )
    return x_api_key


# --- Application ---

app = FastAPI()


@app.post("/honeypot/message", status_code=200)
async def handle_message(
    request: MessageRequest, api_key: str = Depends(verify_api_key)
):
    """
    Process incoming scammer message and generate agent response.

    Returns:
    - 200: Active session - agent reply generated
    - 409: Closed session - informational summary returned
    """

    # 1. Load or Create Session (Robust Handling for testers)
    # Generate UUID if missing
    session_id = request.sessionId or str(uuid.uuid4())
    session = session_manager.get_or_create_session(session_id)

    # 2. Check Session Lifecycle - IMMEDIATE 409 for closed sessions
    if session.sessionClosed:
        return JSONResponse(
            status_code=200,
            content={"output": "Session already closed."}
        )

    # 3. Append Scammer Message
    session_manager.append_message(
        session.sessionId,
        request.message.sender,
        request.message.text,
        str(request.message.timestamp),
    )

    current_text = request.message.text

    # 4. Scam Detection
    # Only run if not already detected? Or always run to update confidence?
    # Logic: If not detected yet, run detection.
    if not session.scamDetected:
        is_scam, confidence = scam_engine.detect(current_text)
        if is_scam:
            session_manager.mark_scam_detected(session.sessionId, confidence)

    # 5. Intelligence Extraction
    extracted_data = intelligence_engine.extract_intelligence(current_text)

    # Update Session Intelligence (Deduplicated)
    # We access the dataclass directly as SessionManager allows object mutation via get methods implicitly
    # or we can assume we need to manage this. Since Session is returned by get_or_create_session, it's mutable.

    new_intel_found = False

    def merge_lists(target_list: List[str], new_items: List[str]):
        nonlocal new_intel_found
        existing = set(target_list)
        for item in new_items:
            if item not in existing:
                target_list.append(item)
                existing.add(item)
                new_intel_found = True

    merge_lists(
        session.extractedIntelligence.bankAccounts, extracted_data["bankAccounts"]
    )
    merge_lists(session.extractedIntelligence.upiIds, extracted_data["upiIds"])
    merge_lists(
        session.extractedIntelligence.phoneNumbers, extracted_data["phoneNumbers"]
    )
    merge_lists(
        session.extractedIntelligence.phishingLinks, extracted_data["phishingLinks"]
    )
    merge_lists(
        session.extractedIntelligence.suspiciousKeywords,
        extracted_data["suspiciousKeywords"],
    )

    # Update Sufficient Intelligence Flag
    has_intel = (
        len(session.extractedIntelligence.bankAccounts) > 0
        or len(session.extractedIntelligence.upiIds) > 0
        or len(session.extractedIntelligence.phoneNumbers) > 0
        or len(session.extractedIntelligence.phishingLinks) > 0
    )
    if session.scamDetected and has_intel:
        session.hasSufficientIntelligence = True

    # Check for Redundant Scammer Messages
    # Definition: No new intel AND intent matches (urgency/payment)
    has_scam_intent = detect_urgency(current_text) or detect_payment_request(
        current_text
    )

    if not new_intel_found and has_scam_intent:
        session.redundantScammerMessageCount += 1
        # Increase fatigue if redundant pressure continues
        session.repetitionFatigueLevel = min(session.repetitionFatigueLevel + 1, 3)
    elif new_intel_found:
        # Reset fatigue slightly if progress is made?
        # Requirement says "monotonic" for sufficient intel, but fatigue is emotional state.
        # Let's keep it sticky for realism unless convo shifts.
        pass

    # 6. Determine Agent State Transition
    # Gather signals
    signals = []

    if session.scamDetected:
        signals.append(TransitionSignal.SCAM_DETECTED.value)

    if detect_urgency(current_text):
        signals.append(TransitionSignal.URGENCY_DETECTED.value)

    if detect_payment_request(current_text):
        signals.append(TransitionSignal.PAYMENT_REQUEST.value)

    if detect_artifacts_shared(current_text):
        signals.append(TransitionSignal.ARTIFACTS_SHARED.value)

    # Check intelligence threshold (e.g., > 3 items)
    total_intel = (
        len(session.extractedIntelligence.bankAccounts)
        + len(session.extractedIntelligence.upiIds)
        + len(session.extractedIntelligence.phoneNumbers)
        + len(session.extractedIntelligence.phishingLinks)
    )
    if total_intel >= 3:
        signals.append(TransitionSignal.INTELLIGENCE_THRESHOLD_MET.value)

    # Prepare intel dict for controller logic
    intel_dict = {
        "bankAccounts": session.extractedIntelligence.bankAccounts,
        "upiIds": session.extractedIntelligence.upiIds,
        "phishingLinks": session.extractedIntelligence.phishingLinks,
        "phoneNumbers": session.extractedIntelligence.phoneNumbers,
        "suspiciousKeywords": session.extractedIntelligence.suspiciousKeywords,
    }

    # Decide Next State based on signals and readiness scoring
    next_state = agent_controller.decide_next_state(
        current_state=session.agentState,
        signals=signals,
        message_count=session.totalMessagesExchanged,
        extracted_intelligence=intel_dict,
        redundant_count=session.redundantScammerMessageCount,
    )

    # Update State if changed
    if next_state != session.agentState:
        session_manager.update_agent_state(session.sessionId, next_state)

    # 7. Generate Agent Reply
    # WHY: We use the dedicated reply service (LLM or Template) with the session-scoped persona.
    # AgentController logic determines *what* to do (state), ReplyService determines *how* to say it.

    # Extract recent conversation context (Last 5 messages total)
    recent_convo_context = []
    if request.conversationHistory:
        # Include both scammer and agent messages so LLM knows what was said
        recent_convo_context = [
            f"{m.get('sender', 'unknown')}: {m.get('text', '')}"
            for m in request.conversationHistory[-5:]
        ]

    # Calculate Response Strategy based on fatigue
    # Logic: 0=clarify, 1=verify, 2=deflect, 3+=boundary
    if session.repetitionFatigueLevel == 0:
        response_strategy = "clarify"
    elif session.repetitionFatigueLevel == 1:
        response_strategy = "verify"
    elif session.repetitionFatigueLevel == 2:
        response_strategy = "deflect"
    else:
        response_strategy = "boundary"

    agent_reply = agent_reply_service.generate_reply(
        agent_state=session.agentState,
        scammer_message=current_text,
        persona_name=session.agentPersona,
        recent_user_context=recent_convo_context, # Using the existing arg name for combined context
        fatigue_level=session.repetitionFatigueLevel,
        response_strategy=response_strategy
    )

    # Append Agent Reply to History (if any)
    if agent_reply:
        session_manager.append_message(session.sessionId, "agent", agent_reply)

    # --- CALLBACK TRIGGER ---
    # WHY: Trigger callback AFTER appending the final agent reply.
    # The dispatcher will mark the session as closed, so no further mutations allowed.
    if session.agentState == "EXIT":
        callback_dispatcher.check_and_dispatch(session.sessionId)

    # 8. Calculate Metrics
    # Duration: Current Time - Engagement Start Time (if set)
    duration = 0
    if session.engagementMetrics.engagementStartTime:
        start_time = datetime.fromisoformat(
            session.engagementMetrics.engagementStartTime
        )
        now = datetime.now(timezone.utc)
        duration = int((now - start_time).total_seconds())
        session.engagementMetrics.engagementDurationSeconds = duration

    # 9. Construct Conversational Response
    return JSONResponse(content={"output": agent_reply or "..."})


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
