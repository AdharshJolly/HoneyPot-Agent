"""
Agent Controller Module – Agentic Honey-Pot System

This module owns agent state transition legality and reply generation.
It implements the deterministic state machine defined in agent_state_machine.md.

CRITICAL RESPONSIBILITIES:
- Enforce legal state transitions
- Decide next state based on observable signals
- Generate context-appropriate, human-like replies
- Never reveal scam detection

DOES NOT:
- Store session state (SessionManager owns storage)
- Perform intelligence extraction (separate module)
- Make external API calls
- Modify sessions directly
"""

from typing import Tuple, Optional, Dict, Set, List
from enum import Enum
import random


class AgentState(Enum):
    """
    Agent behavioral states from agent_state_machine.md.

    Lifecycle: INIT → CONFUSED → TRUST_BUILDING → INFORMATION_EXTRACTION → EXIT
    """

    INIT = "INIT"
    CONFUSED = "CONFUSED"
    TRUST_BUILDING = "TRUST_BUILDING"
    INFORMATION_EXTRACTION = "INFORMATION_EXTRACTION"
    EXIT = "EXIT"


class TransitionSignal(Enum):
    """
    Observable signals that trigger state transitions.
    Extracted from message analysis, not free-form LLM inference.
    """

    # Scam detection confirmed
    SCAM_DETECTED = "scam_detected"

    # Urgency or pressure tactics
    URGENCY_DETECTED = "urgency_detected"

    # Payment or verification request
    PAYMENT_REQUEST = "payment_request"

    # Scam artifacts shared (links, accounts, UPIs)
    ARTIFACTS_SHARED = "artifacts_shared"

    # Sufficient intelligence extracted
    INTELLIGENCE_THRESHOLD_MET = "intelligence_threshold_met"

    # Scammer stopped responding or conversation stalled
    SCAMMER_DISENGAGED = "scammer_disengaged"


class AgentController:
    """
    Stateless controller for agent behavior and state transitions.

    WHY stateless:
    - SessionManager owns state storage
    - AgentController owns state transition logic
    - Clear separation enables independent testing
    - Can be called multiple times per session without side effects

    WHY explicit transition map:
    - Enforces deterministic, auditable behavior
    - Prevents random state jumps
    - Makes system explainable to evaluators
    - Aligns with competition requirements
    """

    # Allowed state transitions (strict forward progression)
    # WHY these specific transitions exist: Matches agent_state_machine.md flow
    ALLOWED_TRANSITIONS: Dict[AgentState, Set[AgentState]] = {
        AgentState.INIT: {AgentState.CONFUSED},  # Activated when scam detected
        AgentState.CONFUSED: {
            AgentState.TRUST_BUILDING  # When urgency/payment request appears
        },
        AgentState.TRUST_BUILDING: {
            AgentState.INFORMATION_EXTRACTION  # When scam artifacts shared
        },
        AgentState.INFORMATION_EXTRACTION: {
            AgentState.EXIT  # When intelligence goals met or scammer disengages
        },
        AgentState.EXIT: set(),  # Terminal state, no transitions allowed
    }

    def __init__(self):
        """Initialize controller with reply templates."""
        # WHY templates: Ensures human-like, consistent persona
        # WHY multiple options: Adds natural variation without randomness
        self._reply_templates = self._initialize_reply_templates()

    def _initialize_reply_templates(self) -> Dict[AgentState, List[str]]:
        """
        Define reply templates for each state.

        WHY these specific replies:
        - SHORT: Scammers expect quick mobile responses
        - CAUTIOUS: Real users don't blindly trust strangers
        - SLIGHTLY IMPERFECT: Adds authenticity (typos, casual language)
        - NEVER ACCUSATORY: Maintains cover

        Templates from agent_state_machine.md examples.
        """
        return {
            AgentState.CONFUSED: [
                "I don't understand this message",
                "Why would my account be blocked?",
                "Can you explain what you mean?",
                "What is this about?",
                "I'm confused, who are you?",
            ],
            AgentState.TRUST_BUILDING: [
                "Okay, but I want to be careful",
                "Is this official from the bank?",
                "I've never done this before",
                "Can you verify you're from the bank?",
                "How do I know this is real?",
            ],
            AgentState.INFORMATION_EXTRACTION: [
                "Can you send the link again?",
                "Is there another UPI? This one isn't working",
                "Please type the account number slowly",
                "The link isn't opening for me",
                "Can you send a different payment method?",
                "I'm trying but it's not working",
            ],
            AgentState.EXIT: [
                "I'll check this later",
                "I need to visit the bank tomorrow",
                "I'll get back to you",
                "Let me call the bank first",
                "I'm busy right now",
            ],
        }

    def decide_next_state(
        self,
        current_state: str,
        signals: List[str],
        message_count: int,
        extracted_intelligence: Dict[str, List[str]],
        redundant_count: int = 0,
    ) -> str:
        """
        Determine the next agent state based on current state and observed signals.

        WHY signal-driven:
        - Deterministic transitions based on observable events
        - Not dependent on LLM interpretation
        - Auditable decision trail

        WHY extracted_intelligence and redundant_count:
        - Enables sophisticated exit logic (Categories A, B, C)
        - Prevents premature exit

        Args:
            current_state: Current agentState (string from session)
            signals: List of TransitionSignal values detected
            message_count: Total messages in conversation
            extracted_intelligence: Dictionary of list of extracted artifacts
            redundant_count: Number of redundant scammer messages tracked

        Returns:
            Next state name (string)

        Raises:
            ValueError: If transition is illegal
        """
        try:
            current = AgentState(current_state)
        except ValueError:
            raise ValueError(f"Invalid current state: {current_state}")

        # TERMINAL STATE PROTECTION: Cannot transition out of EXIT
        if current == AgentState.EXIT:
            return AgentState.EXIT.value
            
        # CHECK EXIT CONDITIONS (Categories A + B + C)
        if self._should_exit(extracted_intelligence, message_count, redundant_count):
            return AgentState.EXIT.value

        # Determine next state based on current state and signals
        next_state = self._evaluate_transition(
            current, signals, message_count, 0 # intelligence_count unused in new logic, passing 0
        )

        # TRANSITION LEGALITY CHECK: Enforce allowed transitions
        if next_state not in self.ALLOWED_TRANSITIONS[current] and next_state != current:
             # Allow staying in same state, but if it changed, must be allowed
             # Actually, ALLOWED_TRANSITIONS only lists *changes*.
             # The logic below handles the check.
             pass

        # If state changed, validate it is allowed
        if next_state != current:
             if next_state not in self.ALLOWED_TRANSITIONS[current]:
                raise ValueError(
                    f"Illegal state transition: {current.value} → {next_state.value}. "
                    f"Allowed transitions: {[s.value for s in self.ALLOWED_TRANSITIONS[current]]}"
                )

        return next_state.value

    def _should_exit(
        self, intel: Dict[str, List[str]], message_count: int, redundant_count: int
    ) -> bool:
        """
        Evaluate strict exit conditions (Categories A, B, C).
        
        Returns True ONLY if all categories are satisfied.
        """
        # CATEGORY A: High-Value Intelligence Presence (REQUIRED)
        has_high_value = (
            len(intel.get("bankAccounts", [])) > 0 or 
            len(intel.get("upiIds", [])) > 0 or 
            len(intel.get("phishingLinks", [])) > 0 or 
            len(intel.get("phoneNumbers", [])) > 0
        )
        if not has_high_value:
            return False

        # CATEGORY B: Evidence Sufficiency (REQUIRED)
        # 1. Multi-modal (more than 1 type)
        types_count = sum([
            1 if len(intel.get("bankAccounts", [])) > 0 else 0,
            1 if len(intel.get("upiIds", [])) > 0 else 0,
            1 if len(intel.get("phishingLinks", [])) > 0 else 0,
            1 if len(intel.get("phoneNumbers", [])) > 0 else 0
        ])
        # 2. OR Redundancy (implies same artifact across turns)
        # 3. OR Minimum turns (default 6)
        is_sufficient = (types_count > 1) or (redundant_count > 0) or (message_count >= 6)
        
        if not is_sufficient:
            return False

        # CATEGORY C: Scammer Persistence or Pressure (REQUIRED)
        # 1. Suspicious keywords >= 2
        # 2. OR Redundant messages (implies repeated intent/urgency)
        keyword_count = len(intel.get("suspiciousKeywords", []))
        has_pressure = (keyword_count >= 2) or (redundant_count > 0)
        
        return has_pressure

        # TRANSITION LEGALITY CHECK: Enforce allowed transitions
        if next_state not in self.ALLOWED_TRANSITIONS[current] and next_state != current:
             # Allow staying in same state, but if it changed, must be allowed
             # Actually, ALLOWED_TRANSITIONS only lists *changes*.
             # The logic below handles the check.
             pass

        # If state changed, validate it is allowed
        if next_state != current:
             if next_state not in self.ALLOWED_TRANSITIONS[current]:
                raise ValueError(
                    f"Illegal state transition: {current.value} → {next_state.value}. "
                    f"Allowed transitions: {[s.value for s in self.ALLOWED_TRANSITIONS[current]]}"
                )

        return next_state.value

    def _evaluate_transition(
        self,
        current: AgentState,
        signals: List[str],
        message_count: int,
        intelligence_count: int,
    ) -> AgentState:
        """
        Evaluate which transition should occur based on current state and signals.

        WHY this logic:
        - Maps signals to state transitions per agent_state_machine.md
        - Adds safety timeouts to prevent infinite engagement
        - Prioritizes intelligence extraction goals

        Returns:
            Next AgentState (may be same as current if no transition triggered)
        """
        # Convert string signals to enum for type safety
        signal_set = set()
        for sig in signals:
            try:
                signal_set.add(TransitionSignal(sig))
            except ValueError:
                # Ignore unknown signals (defensive programming)
                pass

        # INIT → CONFUSED: Triggered when scam detected
        if current == AgentState.INIT:
            if TransitionSignal.SCAM_DETECTED in signal_set:
                return AgentState.CONFUSED
            return current  # Stay in INIT until scam confirmed

        # CONFUSED → TRUST_BUILDING: Triggered by urgency or payment request
        if current == AgentState.CONFUSED:
            if (
                TransitionSignal.URGENCY_DETECTED in signal_set
                or TransitionSignal.PAYMENT_REQUEST in signal_set
            ):
                return AgentState.TRUST_BUILDING
            # Stay CONFUSED for 2-3 turns to prolong engagement
            if message_count >= 4:
                return AgentState.TRUST_BUILDING
            return current

        # TRUST_BUILDING → INFORMATION_EXTRACTION: Triggered by artifact sharing
        if current == AgentState.TRUST_BUILDING:
            if TransitionSignal.ARTIFACTS_SHARED in signal_set:
                return AgentState.INFORMATION_EXTRACTION
            # Auto-transition after sufficient turns
            if message_count >= 6:
                return AgentState.INFORMATION_EXTRACTION
            return current

        # INFORMATION_EXTRACTION → EXIT: Triggered by intelligence threshold or disengagement
        if current == AgentState.INFORMATION_EXTRACTION:
            # Exit if intelligence goals met
            if TransitionSignal.INTELLIGENCE_THRESHOLD_MET in signal_set:
                return AgentState.EXIT
            # Exit if scammer disengaged
            if TransitionSignal.SCAMMER_DISENGAGED in signal_set:
                return AgentState.EXIT
            # Exit after extracting sufficient intelligence (3+ items)
            if intelligence_count >= 3:
                return AgentState.EXIT
            # Safety timeout: Exit after prolonged extraction phase
            if message_count >= 12:
                return AgentState.EXIT
            return current

        # Default: No transition
        return current

    def generate_reply(self, state: str, scammer_message: Optional[str] = None) -> str:
        """
        Generate a human-like reply appropriate to the current state.

        WHY this approach:
        - Pre-defined templates ensure safety (no LLM hallucination risk)
        - Random selection adds natural variation
        - Templates are short, cautious, and never accusatory
        - Matches real user behavior patterns

        Args:
            state: Current agentState
            scammer_message: Latest scammer message (optional, for context-aware replies)

        Returns:
            Agent reply string

        Raises:
            ValueError: If state is invalid or INIT (no reply in INIT)
        """
        try:
            agent_state = AgentState(state)
        except ValueError:
            raise ValueError(f"Invalid agent state: {state}")

        # INIT state: No agent reply (scam not yet detected)
        if agent_state == AgentState.INIT:
            return ""  # Silent observation, no engagement

        # Get templates for current state
        templates = self._reply_templates.get(agent_state, [])
        if not templates:
            raise ValueError(f"No reply templates defined for state: {state}")

        # WHY random selection: Adds natural variation without compromising safety
        # All templates are pre-vetted for safety and persona consistency
        reply = random.choice(templates)

        # Optional: Add context-awareness (simple keyword matching)
        # This is NOT LLM-based to maintain determinism
        if scammer_message and agent_state == AgentState.CONFUSED:
            msg_lower = scammer_message.lower()
            if "account" in msg_lower or "bank" in msg_lower:
                reply = "Why would my account have a problem?"
            elif "verify" in msg_lower or "confirm" in msg_lower:
                reply = "What do I need to verify?"

        return reply

    def can_transition(self, from_state: str, to_state: str) -> bool:
        """
        Check if a state transition is legally allowed.

        WHY this exists:
        - Validation before attempting transition
        - Useful for testing and debugging
        - Prevents invalid state updates

        Args:
            from_state: Source state
            to_state: Target state

        Returns:
            True if transition is allowed, False otherwise
        """
        try:
            from_enum = AgentState(from_state)
            to_enum = AgentState(to_state)
        except ValueError:
            return False

        return to_enum in self.ALLOWED_TRANSITIONS.get(from_enum, set())

    def get_allowed_transitions(self, state: str) -> List[str]:
        """
        Get list of allowed next states from current state.

        Useful for:
        - Debugging
        - Testing
        - UI/visualization

        Args:
            state: Current state

        Returns:
            List of allowed next state names
        """
        try:
            agent_state = AgentState(state)
        except ValueError:
            return []

        return [s.value for s in self.ALLOWED_TRANSITIONS.get(agent_state, set())]


# Signal detection helpers (used by higher-level orchestration)
# These analyze scammer messages to produce TransitionSignals


def detect_urgency(message: str) -> bool:
    """
    Detect urgency keywords in scammer message.

    WHY these keywords:
    - Common pressure tactics used by scammers
    - Observable, deterministic detection
    - No LLM inference required
    """
    urgency_keywords = [
        "urgent",
        "immediately",
        "now",
        "quickly",
        "hurry",
        "block",
        "blocked",
        "suspend",
        "suspended",
        "expire",
        "expired",
        "limited time",
        "act fast",
        "verify now",
        "confirm now",
    ]
    message_lower = message.lower()
    return any(keyword in message_lower for keyword in urgency_keywords)


def detect_payment_request(message: str) -> bool:
    """
    Detect payment or verification requests.

    WHY these keywords:
    - Indicate scam escalation
    - Trigger transition to trust-building phase
    """
    payment_keywords = [
        "pay",
        "payment",
        "send",
        "transfer",
        "upi",
        "account",
        "bank",
        "paytm",
        "phonepe",
        "gpay",
        "verify",
        "confirm",
        "authenticate",
        "otp",
        "cvv",
        "pin",
        "password",
    ]
    message_lower = message.lower()
    return any(keyword in message_lower for keyword in payment_keywords)


def detect_artifacts_shared(message: str) -> bool:
    """
    Detect if scammer shared links, account numbers, or UPI IDs.

    WHY this matters:
    - Indicates information extraction opportunity
    - Triggers transition to extraction phase
    """
    # Simple heuristic: URLs, phone numbers, or structured IDs
    indicators = [
        "http://",
        "https://",
        "www.",  # URLs
        "@",
        "upi",  # UPI IDs
        "account",
        "A/C",
        "acc",  # Account references
        "+91",
        "call",
        "whatsapp",  # Phone numbers
    ]
    message_lower = message.lower()
    return any(indicator in message_lower for indicator in indicators)