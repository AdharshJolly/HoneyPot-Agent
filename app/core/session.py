"""
Session Management Module – Agentic Honey-Pot System

This module defines the Session data structure and SessionManager class.
It implements the stateful session lifecycle defined in session_schema.md.

CRITICAL RULES:
- Sessions are keyed by sessionId
- conversationHistory is append-only
- extractedIntelligence is append-only
- callbackSent and sessionClosed are terminal flags (irreversible)
- Once sessionClosed=true, no further modifications allowed
"""

from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field, asdict
from copy import deepcopy
from contextlib import contextmanager
import os
import random
import threading

AVAILABLE_PERSONAS = [
    "confused_elderly",
    "busy_professional",
    "naive_student",
    "skeptical_user",
]


@dataclass
class Message:
    """Represents a single message in the conversation history."""

    sender: str  # "scammer" or "agent"
    text: str
    timestamp: str  # ISO-8601 format


@dataclass
class EngagementMetrics:
    """Tracks engagement timing for evaluation scoring."""

    engagementStartTime: Optional[str] = (
        None  # ISO-8601, set when scamDetected becomes true
    )
    engagementDurationSeconds: int = 0


@dataclass
class ExtractedIntelligence:
    """Stores extracted scam intelligence (append-only)."""

    bankAccounts: List[str] = field(default_factory=list)
    upiIds: List[str] = field(default_factory=list)
    phoneNumbers: List[str] = field(default_factory=list)
    phishingLinks: List[str] = field(default_factory=list)
    suspiciousKeywords: List[str] = field(default_factory=list)


@dataclass
class Session:
    """
    Represents a complete scam conversation lifecycle.

    Lifecycle states:
    - NEW: Just created, no scam confirmed
    - ACTIVE: Scam confirmed, agent engaged
    - EXIT: Agent decided to exit
    - CLOSED: Session terminated, immutable

    WHY these fields exist:
    - sessionId: Primary key for session lookup
    - conversationHistory: Required for context-aware agent responses
    - scamDetected: Gates agent activation (no replies until true)
    - agentState: Enforces deterministic, explainable behavior
    - callbackSent: Prevents duplicate final callbacks
    - sessionClosed: Makes session immutable after completion
    """

    sessionId: str
    createdAt: str
    lastUpdatedAt: str

    # Conversation tracking (append-only)
    conversationHistory: List[Message] = field(default_factory=list)
    totalMessagesExchanged: int = 0

    # Scam detection state
    scamDetected: bool = False
    scamConfidence: float = 0.0

    # Agent behavior control
    agentState: str = (
        "INIT"  # INIT, CONFUSED, TRUST_BUILDING, INFORMATION_EXTRACTION, EXIT
    )
    agentPersona: str = "confused_user"  # Set once, remains stable

    # Engagement tracking
    engagementMetrics: EngagementMetrics = field(default_factory=EngagementMetrics)

    # Intelligence extraction (append-only)
    extractedIntelligence: ExtractedIntelligence = field(
        default_factory=ExtractedIntelligence
    )

    # Agent summary
    agentNotes: str = ""

    # Redundancy tracking (Option B)
    redundantScammerMessageCount: int = 0
    hasSufficientIntelligence: bool = False

    # Conversation Pacing Control (Task 1)
    stateTurnCount: Dict[str, int] = field(
        default_factory=lambda: {
            "INIT": 0,
            "CONFUSED": 0,
            "TRUST_BUILDING": 0,
            "INFORMATION_EXTRACTION": 0,
            "EXIT": 0,
        }
    )
    stallCount: int = 0  # Number of stall tactics used

    # Repetition Fatigue (Tone Control)
    repetitionFatigueLevel: int = 0  # 0-3 scale: normal -> fatigued

    # Behavioral Realism (Option C)
    responseStrategy: str = "CONFUSED_CLARIFICATION"

    # Terminal flags (irreversible once true)
    callbackSent: bool = False
    sessionClosed: bool = False


class SessionManager:
    """
    Manages session lifecycle with strict enforcement of terminal flags.

    WHY this exists:
    - Ensures session continuity across API calls
    - Prevents data corruption through append-only operations
    - Enforces irreversible terminal states
    - Provides single source of truth for session state

    Storage:
    - In-memory dictionary keyed by sessionId
    - Suitable for local demo (can upgrade to Redis later)
    """

    def __init__(self):
        self._sessions: Dict[str, Session] = {}
        self._session_locks: Dict[str, threading.RLock] = {}
        self._global_lock = threading.RLock()

        # TTL defaults to disabled (0 or missing). Use env to enable without API changes.
        ttl_env = os.getenv("SESSION_TTL_SECONDS", "0").strip()
        try:
            self._session_ttl_seconds = max(int(ttl_env), 0)
        except ValueError:
            self._session_ttl_seconds = 0

        max_env = os.getenv("MAX_SESSIONS", "0").strip()
        try:
            self._max_sessions = max(int(max_env), 0)
        except ValueError:
            self._max_sessions = 0

    def _get_session_lock(self, session_id: str) -> threading.RLock:
        with self._global_lock:
            lock = self._session_locks.get(session_id)
            if lock is None:
                lock = threading.RLock()
                self._session_locks[session_id] = lock
            return lock

    @contextmanager
    def _locked_session(self, session_id: str):
        lock = self._get_session_lock(session_id)
        with lock:
            yield

    def _is_expired(self, session: Session, now: datetime) -> bool:
        if self._session_ttl_seconds <= 0:
            return False
        try:
            last_updated = datetime.fromisoformat(session.lastUpdatedAt)
        except ValueError:
            return False
        age_seconds = int((now - last_updated).total_seconds())
        return age_seconds > self._session_ttl_seconds

    def prune_expired_sessions(self) -> int:
        """
        Remove expired sessions to keep memory bounded.

        Returns:
            Number of sessions removed.
        """
        if self._session_ttl_seconds <= 0 and self._max_sessions <= 0:
            return 0

        now = datetime.now(timezone.utc)
        removed = 0

        with self._global_lock:
            if self._session_ttl_seconds > 0:
                expired_ids = [
                    sid
                    for sid, session in self._sessions.items()
                    if self._is_expired(session, now)
                ]
                for sid in expired_ids:
                    self._sessions.pop(sid, None)
                    self._session_locks.pop(sid, None)
                    removed += 1

            if self._max_sessions > 0 and len(self._sessions) > self._max_sessions:
                # Remove oldest by lastUpdatedAt to enforce cap.
                sorted_ids = sorted(
                    self._sessions.keys(),
                    key=lambda sid: self._sessions[sid].lastUpdatedAt,
                )
                while len(self._sessions) > self._max_sessions and sorted_ids:
                    sid = sorted_ids.pop(0)
                    self._sessions.pop(sid, None)
                    self._session_locks.pop(sid, None)
                    removed += 1

        return removed

    def get_or_create_session(self, session_id: str) -> Session:
        """
        Retrieve existing session or create new one.

        WHY get_or_create pattern:
        - First message in conversation creates session
        - Subsequent messages reuse existing session
        - Prevents duplicate session creation

        Args:
            session_id: Unique session identifier from platform

        Returns:
            Session object (existing or newly created)
        """
        with self._global_lock:
            if session_id in self._sessions:
                return self._sessions[session_id]

        # Create new session with default initial state
        now = datetime.now(timezone.utc).isoformat()
        # WHY: Persona is selected once at creation and remains immutable for the session.
        # This ensures consistent voice/tone throughout the engagement.
        selected_persona = random.choice(AVAILABLE_PERSONAS)

        new_session = Session(
            sessionId=session_id,
            createdAt=now,
            lastUpdatedAt=now,
            agentPersona=selected_persona,
        )

        with self._global_lock:
            self._sessions[session_id] = new_session
            self._session_locks.setdefault(session_id, threading.RLock())
            return new_session

    def append_message(
        self, session_id: str, sender: str, text: str, timestamp: Optional[str] = None
    ) -> None:
        """
        Append a message to conversation history.

        WHY append-only:
        - Preserves complete conversation context
        - Required for agent to generate coherent responses
        - Enables post-session analysis
        - Messages are never edited or deleted (data integrity)

        ENFORCES:
        - Session must not be closed

        Args:
            session_id: Target session
            sender: "scammer" or "agent"
            text: Message content
            timestamp: ISO-8601 timestamp (defaults to now)

        Raises:
            ValueError: If session is closed
        """
        with self._locked_session(session_id):
            session = self._sessions.get(session_id)
            if not session:
                raise ValueError(f"Session {session_id} does not exist")

            # TERMINAL FLAG CHECK: Cannot modify closed sessions
            if session.sessionClosed:
                raise ValueError(f"Session {session_id} is closed and immutable")

            if timestamp is None:
                timestamp = datetime.now(timezone.utc).isoformat()

            message = Message(sender=sender, text=text, timestamp=timestamp)
            session.conversationHistory.append(message)
            session.totalMessagesExchanged += 1
            session.lastUpdatedAt = datetime.now(timezone.utc).isoformat()

    def mark_scam_detected(self, session_id: str, confidence: float) -> None:
        """
        Mark scam as detected and record confidence score.

        WHY this method exists:
        - Gates agent activation (agent replies only when scamDetected=true)
        - Records engagementStartTime for evaluation metrics
        - Provides clear audit trail of detection moment

        SIDE EFFECTS:
        - Sets engagementStartTime if not already set

        Args:
            session_id: Target session
            confidence: Detection confidence (0.0-1.0)

        Raises:
            ValueError: If session doesn't exist or is closed
        """
        with self._locked_session(session_id):
            session = self._sessions.get(session_id)
            if not session:
                raise ValueError(f"Session {session_id} does not exist")

            if session.sessionClosed:
                raise ValueError(f"Session {session_id} is closed")

            # Set detection flag
            session.scamDetected = True
            session.scamConfidence = confidence

            # Record engagement start time (only on first detection)
            if session.engagementMetrics.engagementStartTime is None:
                session.engagementMetrics.engagementStartTime = datetime.now(
                    timezone.utc
                ).isoformat()

            session.lastUpdatedAt = datetime.now(timezone.utc).isoformat()

    def update_agent_state(self, session_id: str, new_state: str) -> None:
        """
        Transition agent to a new behavioral state.

        WHY state machine enforcement:
        - Ensures deterministic, explainable agent behavior
        - Prevents random or uncontrolled responses
        - Each state has defined allowed actions and transitions
        - Makes agent behavior auditable

        Valid states: INIT, CONFUSED, TRUST_BUILDING, INFORMATION_EXTRACTION, EXIT

        CRITICAL: EXIT state triggers final callback preparation

        Args:
            session_id: Target session
            new_state: Target state from agent_state_machine.md

        Raises:
            ValueError: If session doesn't exist, is closed, or invalid state
        """
        valid_states = {
            "INIT",
            "CONFUSED",
            "TRUST_BUILDING",
            "INFORMATION_EXTRACTION",
            "EXIT",
        }

        if new_state not in valid_states:
            raise ValueError(f"Invalid agent state: {new_state}")

        with self._locked_session(session_id):
            session = self._sessions.get(session_id)
            if not session:
                raise ValueError(f"Session {session_id} does not exist")

            if session.sessionClosed:
                raise ValueError(f"Session {session_id} is closed")

            # TERMINAL STATE PROTECTION: EXIT is irreversible
            # Agent Controller owns transition logic, but SessionManager protects terminal states
            if session.agentState == "EXIT":
                raise ValueError(
                    f"Cannot transition from EXIT state (terminal). Current: EXIT, Requested: {new_state}"
                )

            session.agentState = new_state
            session.lastUpdatedAt = datetime.now(timezone.utc).isoformat()

    def mark_callback_sent(self, session_id: str) -> None:
        """
        Mark that final callback has been sent.

        WHY this is critical:
        - Prevents duplicate callbacks (competition violation)
        - callbackSent is a terminal flag (irreversible)
        - Must be called exactly once per session

        TERMINAL FLAG: Once set to true, cannot be reversed

        Args:
            session_id: Target session

        Raises:
            ValueError: If session doesn't exist, is closed, or callback already sent
        """
        with self._locked_session(session_id):
            session = self._sessions.get(session_id)
            if not session:
                raise ValueError(f"Session {session_id} does not exist")

            if session.sessionClosed:
                raise ValueError(f"Session {session_id} is closed")

            # Prevent duplicate callback marking
            if session.callbackSent:
                raise ValueError(f"Callback already sent for session {session_id}")

            # TERMINAL FLAG: Irreversible
            session.callbackSent = True
            session.lastUpdatedAt = datetime.now(timezone.utc).isoformat()

    def close_session(self, session_id: str) -> None:
        """
        Mark session as closed and immutable.

        WHY this is critical:
        - Makes session immutable after callback sent
        - Prevents accidental modifications post-completion
        - sessionClosed is terminal (irreversible)
        - Closed sessions reject all modification attempts

        TERMINAL FLAG: Once set to true, session becomes read-only forever

        Should be called after:
        - agentState == EXIT
        - callbackSent == true

        Args:
            session_id: Target session

        Raises:
            ValueError: If session doesn't exist or already closed
        """
        with self._locked_session(session_id):
            session = self._sessions.get(session_id)
            if not session:
                raise ValueError(f"Session {session_id} does not exist")

            if session.sessionClosed:
                raise ValueError(f"Session {session_id} is already closed")

            # TERMINAL FLAG: Irreversible
            session.sessionClosed = True
            session.lastUpdatedAt = datetime.now(timezone.utc).isoformat()

    def get_session(self, session_id: str) -> Optional[Session]:
        """
        Retrieve session without creating if it doesn't exist.

        Use when you need to check session existence or read-only access.

        Returns:
            Session object or None if not found
        """
        with self._locked_session(session_id):
            return self._sessions.get(session_id)

    def session_exists(self, session_id: str) -> bool:
        """Check if session exists in storage."""
        with self._global_lock:
            return session_id in self._sessions

    def is_session_closed(self, session_id: str) -> bool:
        """
        Check if session is in terminal closed state.

        WHY this check matters:
        - Closed sessions must reject new incoming messages
        - API should return 409 Conflict for closed session requests
        """
        with self._locked_session(session_id):
            session = self._sessions.get(session_id)
            return session.sessionClosed if session else False

    def to_dict(self, session_id: str) -> Optional[Dict[str, Any]]:
        """
        Convert session to dictionary representation.

        Useful for:
        - API response serialization
        - Callback payload generation
        - Logging and debugging

        Returns:
            Dictionary representation or None if session not found
        """
        with self._locked_session(session_id):
            session = self._sessions.get(session_id)
            if not session:
                return None

            # Deep copy to prevent external mutation
            return deepcopy(asdict(session))
