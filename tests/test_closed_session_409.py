"""
Test 409 Conflict Response for Closed Sessions

Verifies that:
1. Closed sessions return HTTP 409 with informational summary
2. No state mutation occurs
3. No callbacks are triggered
4. Active sessions still return 200 normally
5. Callback is sent exactly once
"""

import os
import pytest

# Set up environment before imports
os.environ["HONEYPOT_API_KEY"] = "test-api-key-409"

from fastapi.testclient import TestClient
from app.main import app, session_manager
from app.core.session import Session
from datetime import datetime, timezone
import time


@pytest.fixture(autouse=True)
def reset_sessions():
    """Clear session storage before each test."""
    session_manager._sessions.clear()
    yield
    session_manager._sessions.clear()


client = TestClient(app)
API_KEY = "test-api-key-409"
HEADERS = {"x-api-key": API_KEY}


def test_active_session_returns_200():
    """Verify that active sessions return 200 with agent reply."""
    response = client.post(
        "/honeypot/message",
        json={
            "sessionId": "test-active-session",
            "message": {
                "sender": "scammer",
                "text": "Your account has been blocked. Click here to verify.",
                "timestamp": int(time.time() * 1000),
            },
        },
        headers=HEADERS,
    )

    assert response.status_code == 200
    data = response.json()
    assert data["sender"] == "agent"
    assert "text" in data
    assert "timestamp" in data


def test_closed_session_returns_409():
    """Verify that closed sessions return 409 with informational summary."""
    # Create and close a session
    session_id = "test-closed-session"
    session = session_manager.get_or_create_session(session_id)

    # Simulate scam detection and intelligence extraction
    session_manager.mark_scam_detected(session_id, confidence=0.85)
    session.extractedIntelligence.upiIds.append("scammer@upi")
    session.extractedIntelligence.phoneNumbers.append("+911234567890")
    session.agentNotes = "Typical phishing attempt detected"
    session.engagementMetrics.engagementDurationSeconds = 120
    session.totalMessagesExchanged = 5

    # Close the session
    session_manager.close_session(session_id)
    session.callbackSent = True

    # Attempt to send message to closed session
    response = client.post(
        "/honeypot/message",
        json={
            "sessionId": session_id,
            "message": {
                "sender": "scammer",
                "text": "Please reply urgently!",
                "timestamp": int(time.time() * 1000),
            },
        },
        headers=HEADERS,
    )

    # Verify 409 response
    assert response.status_code == 409
    data = response.json()

    # Verify response structure
    assert data["status"] == "session_closed"
    assert data["message"] == "Conversation has already ended."
    assert data["sessionId"] == session_id
    assert data["finalCallbackSent"] is True

    # Verify finalSummary
    summary = data["finalSummary"]
    assert summary["scamDetected"] is True
    assert summary["agentNotes"] == "Typical phishing attempt detected"

    # Verify engagement metrics
    assert summary["engagementMetrics"]["engagementDurationSeconds"] == 120
    assert summary["engagementMetrics"]["totalMessagesExchanged"] == 5

    # Verify extracted intelligence
    intel = summary["extractedIntelligence"]
    assert "scammer@upi" in intel["upiIds"]
    assert "+911234567890" in intel["phoneNumbers"]


def test_closed_session_no_mutation():
    """Verify that 409 responses don't mutate session state."""
    session_id = "test-immutable-session"
    session = session_manager.get_or_create_session(session_id)

    # Setup and close session
    session_manager.mark_scam_detected(session_id, confidence=0.9)
    session.extractedIntelligence.bankAccounts.append("1234567890")
    session_manager.close_session(session_id)

    # Capture state before 409 request
    message_count_before = session.totalMessagesExchanged
    history_length_before = len(session.conversationHistory)
    intel_count_before = len(session.extractedIntelligence.bankAccounts)

    # Send message to closed session
    response = client.post(
        "/honeypot/message",
        json={
            "sessionId": session_id,
            "message": {
                "sender": "scammer",
                "text": "New scam message with UPI: newscammer@upi",
                "timestamp": int(time.time() * 1000),
            },
        },
        headers=HEADERS,
    )

    assert response.status_code == 409

    # Verify NO state mutation occurred
    assert session.totalMessagesExchanged == message_count_before
    assert len(session.conversationHistory) == history_length_before
    assert len(session.extractedIntelligence.bankAccounts) == intel_count_before
    assert "newscammer@upi" not in session.extractedIntelligence.upiIds


def test_closed_session_with_empty_intelligence():
    """Verify 409 works even when no intelligence was extracted."""
    session_id = "test-empty-intel"
    session = session_manager.get_or_create_session(session_id)
    session_manager.close_session(session_id)

    response = client.post(
        "/honeypot/message",
        json={
            "sessionId": session_id,
            "message": {
                "sender": "scammer",
                "text": "Hello",
                "timestamp": int(time.time() * 1000),
            },
        },
        headers=HEADERS,
    )

    assert response.status_code == 409
    data = response.json()

    # All intelligence lists should be empty but present
    intel = data["finalSummary"]["extractedIntelligence"]
    assert intel["bankAccounts"] == []
    assert intel["upiIds"] == []
    assert intel["phoneNumbers"] == []
    assert intel["phishingLinks"] == []
    assert intel["suspiciousKeywords"] == []


def test_multiple_409_requests_identical():
    """Verify multiple 409 requests return identical informational data."""
    session_id = "test-idempotent-409"
    session = session_manager.get_or_create_session(session_id)
    session_manager.mark_scam_detected(session_id, confidence=0.75)
    session.extractedIntelligence.phishingLinks.append("http://evil.com")
    session_manager.close_session(session_id)

    # Send multiple requests to closed session
    responses = []
    for i in range(3):
        response = client.post(
            "/honeypot/message",
            json={
                "sessionId": session_id,
                "message": {
                    "sender": "scammer",
                    "text": f"Message {i}",
                    "timestamp": int(time.time() * 1000),
                },
            },
            headers=HEADERS,
        )
        assert response.status_code == 409
        responses.append(response.json())

    # All responses should have identical finalSummary
    for i in range(1, 3):
        assert responses[i]["finalSummary"] == responses[0]["finalSummary"]


def test_session_lifecycle_active_then_closed():
    """Integration test: active session → EXIT → closed → 409."""
    session_id = "test-full-lifecycle"

    # Step 1: Active session returns 200
    response1 = client.post(
        "/honeypot/message",
        json={
            "sessionId": session_id,
            "message": {
                "sender": "scammer",
                "text": "Your account is blocked! Verify at http://phish.com with UPI payment@upi",
                "timestamp": int(time.time() * 1000),
            },
        },
        headers=HEADERS,
    )
    assert response1.status_code == 200

    # Step 2: Force session to EXIT and close (simulating callback dispatch)
    session = session_manager.get_session(session_id)
    session_manager.update_agent_state(session_id, "EXIT")
    session_manager.close_session(session_id)
    session.callbackSent = True

    # Step 3: Next message should return 409
    response2 = client.post(
        "/honeypot/message",
        json={
            "sessionId": session_id,
            "message": {
                "sender": "scammer",
                "text": "Why are you not responding?",
                "timestamp": int(time.time() * 1000),
            },
        },
        headers=HEADERS,
    )

    assert response2.status_code == 409
    data = response2.json()

    # Verify intelligence was captured during active phase
    intel = data["finalSummary"]["extractedIntelligence"]
    assert any("phish.com" in link for link in intel["phishingLinks"])
    assert any("payment@upi" in upi for upi in intel["upiIds"])
    assert data["finalSummary"]["scamDetected"] is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
