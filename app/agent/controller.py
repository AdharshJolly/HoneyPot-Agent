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
import logging

logger = logging.getLogger(__name__)


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

    # Readiness thresholds (signal-driven, not turn-driven)
    READINESS_THRESHOLD_TRUST = 3
    READINESS_THRESHOLD_EXTRACTION = 6

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

        # TERMINAL STATE PROTECTION: Cannot transition out of EXIT
        if current == AgentState.EXIT:
            return AgentState.EXIT.value

        # --- PACING CONTROL (TASK 1) ---
        # Minimum dwell times (agent turns) per state
        MIN_DWELL = {
            AgentState.CONFUSED: 2,
            AgentState.TRUST_BUILDING: 3,
            AgentState.INFORMATION_EXTRACTION: 2,
        }

        # Check current state dwell time
        # Note: state_turn_count passed from external session logic or tracked here?
        # The prompt says "Store counters in SessionManager".
        # But AgentController is stateless. We need these counters passed in.
        # Assuming we need to extend arguments or rely on message_count heuristics if pure stateless.
        # Wait, I can't modify SessionManager methods in this tool call, but I can assume the values are passed
        # or I can't easily access them without changing the signature again.
        # The previous instruction updated `session.py` to add fields.
        # I need to update `decide_next_state` signature to accept these counters.

        # BUT I can't update main.py in the same turn easily to pass them.
        # Actually, I can update the signature here, and then main.py.

        # Let's proceed with adding arguments to `decide_next_state`
        pass

    def decide_next_state(
        self,
        current_state: str,
        signals: List[str],
        message_count: int,
        extracted_intelligence: Dict[str, List[str]],
        redundant_count: int = 0,
        current_state_turns: int = 0,  # NEW: Current state dwell time
        stall_count: int = 0,  # NEW: Total stall tactics used
    ) -> str:
        """
        Determine next agent state with pacing and dwell time enforcement.
        """
        try:
            current = AgentState(current_state)
        except ValueError:
            raise ValueError(f"Invalid current state: {current_state}")

        if current == AgentState.EXIT:
            return AgentState.EXIT.value

        # --- PACING & DWELL TIME ENFORCEMENT ---
        min_dwell = {
            AgentState.CONFUSED: 2,
            AgentState.TRUST_BUILDING: 3,
            AgentState.INFORMATION_EXTRACTION: 2,
        }.get(current, 0)

        # Force remain in state if dwell time not met
        # Exception: Critical scam detection in INIT should move to CONFUSED immediately
        if current != AgentState.INIT and current_state_turns < min_dwell:
            return current.value

        # --- EXIT LOGIC ---
        # Exit AUTOMATICALLY once intelligence extraction goals are met (Categories A+B+C satisfied).
        # NO hard exit setup - the state machine drives it via _should_exit conditions.
        # This allows the agent to naturally conclude once sufficient artifacts are collected.
        if current == AgentState.INFORMATION_EXTRACTION:
            if self._should_exit(
                extracted_intelligence, message_count, redundant_count
            ):
                return AgentState.EXIT.value

        # Determine next state based on current state and signals
        intelligence_count = sum(len(v) for v in extracted_intelligence.values())
        next_state = self._evaluate_transition(
            current, signals, message_count, intelligence_count, redundant_count
        )

        # TRANSITION LEGALITY CHECK
        if next_state != current:
            if next_state not in self.ALLOWED_TRANSITIONS[current]:
                raise ValueError(
                    f"Illegal state transition: {current.value} → {next_state.value}"
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
            len(intel.get("bankAccounts", [])) > 0
            or len(intel.get("upiIds", [])) > 0
            or len(intel.get("phishingLinks", [])) > 0
            or len(intel.get("phoneNumbers", [])) > 0
        )

        # CATEGORY B: Evidence Sufficiency (REQUIRED)
        # 1. Multi-modal (more than 1 type)
        types_count = sum(
            [
                1 if len(intel.get("bankAccounts", [])) > 0 else 0,
                1 if len(intel.get("upiIds", [])) > 0 else 0,
                1 if len(intel.get("phishingLinks", [])) > 0 else 0,
                1 if len(intel.get("phoneNumbers", [])) > 0 else 0,
            ]
        )
        # 2. OR Redundancy (implies same artifact across turns)
        # 3. OR Minimum turns (default 6)
        is_sufficient = (
            (types_count > 1) or (redundant_count > 0) or (message_count >= 6)
        )

        # CATEGORY C: Scammer Persistence or Pressure (REQUIRED)
        # 1. Suspicious keywords >= 2
        # 2. OR Redundant messages (implies repeated intent/urgency)
        keyword_count = len(intel.get("suspiciousKeywords", []))
        has_pressure = (keyword_count >= 2) or (redundant_count > 0)

        should_exit = has_high_value and is_sufficient and has_pressure

        if not should_exit:
            logger.debug(
                f"Exit blocked: HighValue={has_high_value}, Sufficient={is_sufficient}, Pressure={has_pressure} "
                f"(Types={types_count}, Redundant={redundant_count}, Msgs={message_count})"
            )

        return should_exit

    def _evaluate_transition(
        self,
        current: AgentState,
        signals: List[str],
        message_count: int,
        intelligence_count: int,
        redundant_count: int,
    ) -> AgentState:
        """
        Evaluate which transition should occur based on accumulated readiness signals.

        State progression is driven by readiness score (signals + artifacts + pressure),
        not turn count. Keeps cautious progression for subtle scammers and accelerates
        for pushy ones.
        """
        signal_set = self._to_signal_set(signals)
        readiness = self._compute_readiness(
            signal_set, intelligence_count, message_count, redundant_count
        )

        # INIT → CONFUSED only after scam detected
        if current == AgentState.INIT:
            if TransitionSignal.SCAM_DETECTED in signal_set:
                return AgentState.CONFUSED
            return current

        # CONFUSED progression: can only advance to TRUST_BUILDING (never directly to extraction)
        if current == AgentState.CONFUSED:
            if readiness >= self.READINESS_THRESHOLD_TRUST:
                return AgentState.TRUST_BUILDING
            return AgentState.CONFUSED

        # TRUST_BUILDING progression: may enter extraction once readiness + evidence satisfied
        if current == AgentState.TRUST_BUILDING:
            if self._can_enter_extraction(signal_set, intelligence_count, readiness):
                return AgentState.INFORMATION_EXTRACTION
            return AgentState.TRUST_BUILDING

        # INFORMATION_EXTRACTION: remain until exit conditions satisfied elsewhere
        if current == AgentState.INFORMATION_EXTRACTION:
            # If scammer disengages and we already have intel, allow graceful exit
            if (
                TransitionSignal.SCAMMER_DISENGAGED in signal_set
                and intelligence_count > 0
            ):
                return AgentState.EXIT
            return AgentState.INFORMATION_EXTRACTION

        return current

    def _to_signal_set(self, signals: List[str]) -> Set[TransitionSignal]:
        signal_set: Set[TransitionSignal] = set()
        for sig in signals:
            try:
                signal_set.add(TransitionSignal(sig))
            except ValueError:
                # Ignore unknown signals
                continue
        return signal_set

    def _compute_readiness(
        self,
        signal_set: Set[TransitionSignal],
        intelligence_count: int,
        message_count: int,
        redundant_count: int,
    ) -> int:
        """Calculate readiness score from accumulated observable signals."""
        score = 0

        # Core scam confirmation
        if TransitionSignal.SCAM_DETECTED in signal_set:
            score += 1

        # Urgency / payment pressure
        if TransitionSignal.URGENCY_DETECTED in signal_set:
            score += 2
        if TransitionSignal.PAYMENT_REQUEST in signal_set:
            score += 2

        # Repeated demands / pushiness
        if redundant_count > 0:
            score += min(3, 1 + redundant_count)  # cap to avoid runaway

        # Voluntary disclosure (artifacts or extracted intel)
        if TransitionSignal.ARTIFACTS_SHARED in signal_set:
            score += 3
        if intelligence_count > 0:
            score += 2
        if intelligence_count > 2:
            score += 1

        # Pressure escalation combos
        if (
            TransitionSignal.URGENCY_DETECTED in signal_set
            and TransitionSignal.PAYMENT_REQUEST in signal_set
        ):
            score += 1
        if redundant_count >= 2:
            score += 1

        # Agent acknowledgement (indicates engagement is happening)
        if message_count >= 2:
            score += 1
        if message_count >= 4:
            score += 1

        return score

    def _can_enter_extraction(
        self,
        signal_set: Set[TransitionSignal],
        intelligence_count: int,
        readiness: int,
    ) -> bool:
        """Gate entry into INFORMATION_EXTRACTION with readiness + evidence."""
        has_artifact_signal = TransitionSignal.ARTIFACTS_SHARED in signal_set
        has_any_intel = intelligence_count > 0
        return readiness >= self.READINESS_THRESHOLD_EXTRACTION and (
            has_artifact_signal or has_any_intel
        )

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
