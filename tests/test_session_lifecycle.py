"""
Tests for Session Schema and Lifecycle – Agentic Honey-Pot System

These tests validate that the SessionManager enforces strict schema compliance,
lifecycle transitions, and immutability rules.
"""

import pytest
from datetime import datetime
from app.core.session import SessionManager, Session

@pytest.fixture
def manager():
    return SessionManager()

@pytest.fixture
def session_id():
    return "test-session-123"

def test_new_session_initialization(manager, session_id):
    """Verify a new session starts in the correct initial state."""
    session = manager.get_or_create_session(session_id)
    
    assert session.sessionId == session_id
    assert session.agentState == "INIT"
    assert session.scamDetected is False
    assert session.callbackSent is False
    assert session.sessionClosed is False
    assert len(session.conversationHistory) == 0
    assert session.totalMessagesExchanged == 0
    assert session.extractedIntelligence.upiIds == []

def test_lifecycle_stage_scam_detection(manager, session_id):
    """Verify state changes after scam detection."""
    session = manager.get_or_create_session(session_id)
    
    # 1. Add first message (pre-detection)
    manager.append_message(session_id, "scammer", "Hello")
    assert session.scamDetected is False
    assert session.engagementMetrics.engagementStartTime is None
    
    # 2. Mark scam detected
    manager.mark_scam_detected(session_id, 0.95)
    
    assert session.scamDetected is True
    assert session.scamConfidence == 0.95
    assert session.engagementMetrics.engagementStartTime is not None
    
    # 3. Transition agent state
    manager.update_agent_state(session_id, "CONFUSED")
    assert session.agentState == "CONFUSED"

def test_lifecycle_information_extraction(manager, session_id):
    """Verify session behavior during extraction phase."""
    session = manager.get_or_create_session(session_id)
    manager.mark_scam_detected(session_id, 1.0)
    manager.update_agent_state(session_id, "INFORMATION_EXTRACTION")
    
    # Simulate extraction
    session.extractedIntelligence.upiIds.append("scammer@upi")
    session.extractedIntelligence.bankAccounts.append("1234567890")
    
    assert len(session.extractedIntelligence.upiIds) == 1
    assert session.agentState == "INFORMATION_EXTRACTION"
    
    # Verify history grows monotonically
    manager.append_message(session_id, "scammer", "pay here")
    manager.append_message(session_id, "agent", "ok")
    
    assert len(session.conversationHistory) == 2
    assert session.conversationHistory[0].sender == "scammer"
    assert session.conversationHistory[1].sender == "agent"

def test_terminal_lifecycle_exit_and_close(manager, session_id):
    """Verify strict enforcement of terminal states."""
    session = manager.get_or_create_session(session_id)
    manager.mark_scam_detected(session_id, 1.0)
    
    # 1. Transition to EXIT
    manager.update_agent_state(session_id, "EXIT")
    assert session.agentState == "EXIT"
    
    # 2. Try to transition back (Should fail if manager enforced it, 
    # but currently manager relies on AgentController logic for valid transitions,
    # EXCEPT for EXIT which IS enforced by manager)
    with pytest.raises(ValueError, match="Cannot transition from EXIT state"):
        manager.update_agent_state(session_id, "CONFUSED")
        
    # 3. Mark callback sent
    assert session.callbackSent is False
    manager.mark_callback_sent(session_id)
    assert session.callbackSent is True
    
    # 4. Close session
    assert session.sessionClosed is False
    manager.close_session(session_id)
    assert session.sessionClosed is True
    
    # 5. Verify Immutability
    with pytest.raises(ValueError, match="closed"):
        manager.append_message(session_id, "scammer", "late message")
        
    with pytest.raises(ValueError, match="closed"):
        manager.update_agent_state(session_id, "EXIT")
        
    with pytest.raises(ValueError, match="closed"):
        manager.mark_scam_detected(session_id, 1.0)

def test_callback_idempotency(manager, session_id):
    """Verify callbackSent flag prevents duplication."""
    manager.get_or_create_session(session_id)
    
    manager.mark_callback_sent(session_id)
    
    with pytest.raises(ValueError, match="Callback already sent"):
        manager.mark_callback_sent(session_id)

def test_monotonic_history(manager, session_id):
    """Ensure conversation history only grows."""
    session = manager.get_or_create_session(session_id)
    
    manager.append_message(session_id, "scammer", "1")
    len_1 = len(session.conversationHistory)
    
    manager.append_message(session_id, "agent", "2")
    len_2 = len(session.conversationHistory)
    
    assert len_2 > len_1
    assert session.totalMessagesExchanged == 2
