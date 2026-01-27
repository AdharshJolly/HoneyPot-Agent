"""
Agent Reply Service – Agentic Honey-Pot System

This module generates human-like agent replies using an LLM (Language Model).
It strictly separates "Decision Making" (AgentController) from "Generation" (AgentReplyService).

CRITICAL ARCHITECTURE RULES:
1. LLM NEVER decides state (AgentController does that).
2. LLM NEVER detects scams (ScamDetectionEngine does that).
3. LLM NEVER sees full session history (Privacy & Context limit).
4. LLM ONLY generates text matching the *assigned* state and persona.

Feature Flag:
- USE_LLM: If False, falls back to deterministic templates.
"""

import os
import random
from typing import Optional, List
import logging
import requests

# Configure logging
logger = logging.getLogger(__name__)


class AgentReplyService:
    """
    Stateless service to generate agent replies.
    Supports both LLM-based generation and Template-based fallback.
    """

    def __init__(self):
        # Environment mode detection
        self.development_mode = (
            os.getenv("ENVIRONMENT", "production").lower() == "development"
        )
        # New flag for strict LLM enforcement (Developer Testing)
        self.strict_llm_mode = os.getenv("STRICT_LLM_MODE", "false").lower() == "true"

        # Feature flag for easy toggling
        # CORRECTED: Standardized on USE_LLM
        self.use_llm = os.getenv("USE_LLM", "False").lower() == "true"

        # API Key (placeholder for actual LLM client integration)
        self.llm_api_key = os.getenv("LLM_API_KEY")

        # STRICT MODE: Enforce LLM requirement
        if self.strict_llm_mode:
            if not self.use_llm:
                raise ValueError(
                    "STRICT_LLM_MODE=true requires USE_LLM=true. "
                    "LLM must be available (no template fallback)."
                )
            logger.info("STRICT_LLM_MODE active. Template fallback disabled.")
        elif self.use_llm:
            logger.info("LLM generation enabled (with template fallback).")

        # Persona Definitions (Data-driven tone control)
        # Used to influence LLM generation without changing state logic
        self.PERSONA_DEFINITIONS = {
            "confused_elderly": "You are an elderly person (70+). You are not tech-savvy. You are polite, slow, and worried. You make small typos.",
            "busy_professional": "You are a busy professional. You are rushed and annoyed. You want to resolve this quickly. You use short sentences.",
            "naive_student": "You are a university student. You are fearful of losing money. You are eager to comply but easily confused.",
            "skeptical_user": "You are a cautious user. You suspect something might be wrong but you are curious. You ask for proof.",
        }
        
        # Fatigued/Disengaged templates (Fatigue Level >= 2)
        # Used across personas when pressure becomes repetitive
        self._fatigued_templates = [
            "I really can't deal with this right now.",
            "I've already said I need time.",
            "This is too much for me at the moment.",
            "Please stop rushing me.",
            "I can't do this right now.",
            "I'm getting confused, just wait.",
        ]
        
        # Strategy-Specific Templates (Tone Control)
        self._strategy_templates = {
            "GUARDED_RESISTANCE": [
                "I don't usually share details over messages.",
                "This doesn't sound like how my bank contacts me.",
                "I need to be sure who I'm talking to.",
                "My son told me never to share code.",
                "I'm not comfortable doing this so quickly.",
            ],
            "STRATEGIC_DELAY": [
                "I don't have my passbook with me.",
                "My son handles these things, I'll ask him.",
                "I'm outside right now, can't check.",
                "I'm driving, message later.",
                "Let me find my glasses first.",
                "The internet is very slow here."
            ]
        }

        # Persona-specific fallback templates per state
        # Each persona has distinct tone/vocabulary while maintaining state alignment
        self._fallback_templates = {
            "CONFUSED": {
                "confused_elderly": [
                    "I don't understand this message, dear.",
                    "Why would my account be blocked?",
                    "Can you explain this slowly?",
                    "What is happening?",
                    "I'm confused, who are you?",
                    "This doesn't make sense to me.",
                ],
                "busy_professional": [
                    "This is confusing, what exactly do you want?",
                    "Why would my account be blocked?",
                    "I don't have time for this, explain it.",
                    "What are you saying?",
                    "I'm not following you here.",
                ],
                "naive_student": [
                    "I don't understand, am I in trouble?",
                    "Wait, why would my account be blocked?",
                    "Can you explain what you mean?",
                    "What is this about?",
                    "I'm scared, what happened?",
                ],
                "skeptical_user": [
                    "I don't understand this message.",
                    "Why should I believe this?",
                    "Can you prove you're from the bank?",
                    "What proof do you have?",
                    "This seems suspicious.",
                ],
            },
            "TRUST_BUILDING": {
                "confused_elderly": [
                    "Okay, but I want to be careful.",
                    "Is this official from the bank?",
                    "How do I know you're real?",
                    "My children warned me about scams.",
                    "I need to be very sure before I do anything.",
                ],
                "busy_professional": [
                    "Okay, but I need proof.",
                    "Is this official from the bank?",
                    "Send me your credentials.",
                    "How do I verify this?",
                    "Give me a reference number.",
                ],
                "naive_student": [
                    "Okay, I'll try to help.",
                    "Is this official from the bank?",
                    "I've never done this before.",
                    "What exactly do I need to do?",
                    "I want to help but I'm worried.",
                ],
                "skeptical_user": [
                    "I need more information.",
                    "Can you verify you're from the bank?",
                    "How do I know this is legitimate?",
                    "What official channel is this?",
                    "I need written confirmation.",
                ],
            },
            "INFORMATION_EXTRACTION": {
                "confused_elderly": [
                    "Can you send the link again?",
                    "I didn't save it, can you repeat?",
                    "My computer is slow, please type it again.",
                    "What's the account number?",
                    "Can you say it more slowly?",
                ],
                "busy_professional": [
                    "Send me the link again.",
                    "I need the exact account number.",
                    "What's the UPI ID?",
                    "Type it out for me.",
                    "I need all the details.",
                ],
                "naive_student": [
                    "Can you send the link again?",
                    "Is there another way to do this?",
                    "Can you type the UPI?",
                    "I don't see the link.",
                    "Can you repeat the number?",
                ],
                "skeptical_user": [
                    "I need to verify the link first.",
                    "Send me the official portal address.",
                    "What's the account holder's name?",
                    "I want to call the bank first.",
                    "Can you give me a reference number?",
                ],
            },
            "EXIT": {
                "confused_elderly": [
                    "I'll check with my son first.",
                    "Let me visit the bank tomorrow.",
                    "I need to think about this.",
                    "I'll call you back later.",
                    "I need to rest now.",
                ],
                "busy_professional": [
                    "I'll check this later.",
                    "I need to verify through official channels.",
                    "Send me an email confirmation.",
                    "I'll handle this myself.",
                    "I don't have time right now.",
                ],
                "naive_student": [
                    "I'll check with my parents first.",
                    "Let me ask my bank.",
                    "I need to think about this.",
                    "I'll call you back.",
                    "I need to go to class.",
                ],
                "skeptical_user": [
                    "I'll verify this independently.",
                    "I'm calling my bank directly.",
                    "I'll check the official website.",
                    "Send me official documentation.",
                    "I don't trust this.",
                ],
            },
        }

    def generate_reply(
        self,
        agent_state: str,
        scammer_message: str,
        persona_name: str = "confused_elderly",
        recent_user_context: Optional[List[str]] = None,
        fatigue_level: int = 0,
        response_strategy: str = "CONFUSED_CLARIFICATION",
    ) -> str:
        """
        Generate a reply based on state, input, and persona.

        Args:
            agent_state: The *already decided* behavioral state.
            scammer_message: The trigger message to reply to.
            persona_name: The immutable session persona.
            recent_user_context: List of recent messages from the scammer for context.
            fatigue_level: 0-3 scale indicating repetition fatigue.
            response_strategy: High-level tone/tactic (e.g. STRATEGIC_DELAY).

        Returns:
            A single string reply.
        """

        # Safety check: No reply needed for INIT
        if agent_state == "INIT":
            return ""

        # TASK 2: Hard Stop for CONFUSED Loops
        # If strategy is still confusion but we've had multiple exchanges, force resistance
        effective_strategy = response_strategy
        if (
            response_strategy == "CONFUSED_CLARIFICATION"
            and recent_user_context
            and len(recent_user_context) >= 2
        ):
            logger.info("Confusion limit reached. Forcing GUARDED_RESISTANCE override.")
            effective_strategy = "GUARDED_RESISTANCE"

        # Attempt LLM generation if enabled
        if self.use_llm:
            try:
                return self._generate_with_llm(
                    agent_state,
                    scammer_message,
                    persona_name,
                    recent_user_context,
                    fatigue_level,
                    effective_strategy,
                )
            except Exception as e:
                # STRICT MODE: Crash if generation fails
                if self.strict_llm_mode:
                    logger.error(f"LLM generation failed in STRICT mode: {e}")
                    raise ValueError(f"LLM failure in STRICT mode: {e}")

                # Log failure and fallback to templates
                logger.error(f"LLM generation failed: {e}. Falling back to templates.")
                return self._generate_with_templates(
                    agent_state,
                    scammer_message,
                    persona_name,
                    fatigue_level,
                    effective_strategy,
                )

        # Check strict mode violation (LLM disabled but strict mode is on)
        if self.strict_llm_mode:
            raise ValueError("STRICT_LLM_MODE active but LLM disabled.")

        # Fallback to templates for all other cases (USE_LLM=False)
        return self._generate_with_templates(
            agent_state,
            scammer_message,
            persona_name,
            fatigue_level,
            effective_strategy,
        )

    def _generate_with_templates(
        self,
        agent_state: str,
        scammer_message: str = "",
        persona_name: str = "confused_elderly",
        fatigue_level: int = 0,
        response_strategy: str = "CONFUSED_CLARIFICATION",
    ) -> str:
        """
        Deterministic fallback generation with persona and context awareness.
        """
        # Improved EXIT templates for deterministic "memory" feel
        if agent_state == "EXIT":
            exit_templates = {
                "confused_elderly": "As I said, I need to ask my son about this. I'm hanging up now.",
                "busy_professional": "Like I mentioned, I'll verify this through official channels. Goodbye.",
                "naive_student": "I'm going to call my parents like I said. Bye.",
                "skeptical_user": "I told you I don't trust this. I'm verifying independently. Bye.",
            }
            return exit_templates.get(persona_name, "I need to go now. Goodbye.")

        # 1. FATIGUE OVERRIDE (Highest Priority)
        # If fatigue is high (>=2), use short, disengaged replies
        if fatigue_level >= 2 or response_strategy == "FATIGUED_DISENGAGEMENT":
            return random.choice(self._fatigued_templates)

        # 2. STRATEGY OVERRIDE
        # If strategy suggests specific phrasing (Resistance/Delay), prefer those templates
        if response_strategy in self._strategy_templates:
            return random.choice(self._strategy_templates[response_strategy])

        # 3. STATE/PERSONA FALLBACK
        # Get templates for this state and persona
        state_templates = self._fallback_templates.get(agent_state)
        if not state_templates:
            return "I don't understand."

        persona_templates = state_templates.get(persona_name)
        if not persona_templates:
            # Fallback to confused_elderly if persona not found
            persona_templates = state_templates.get(
                "confused_elderly", ["I don't understand."]
            )

        # Lightweight context sensitivity (keyword matching only)
        # No semantic parsing, no inference
        filtered_templates = self._filter_templates_by_context(
            persona_templates, scammer_message
        )

        # Select randomly from available templates
        return random.choice(filtered_templates)

    def _filter_templates_by_context(
        self, templates: List[str], scammer_message: str, max_candidates: int = 5
    ) -> List[str]:
        """
        Filters templates based on obvious cues in the scammer message.
        """
        if not scammer_message:
            return templates[:max_candidates]

        msg_lower = scammer_message.lower()

        # Obvious cues
        has_link = any(
            word in msg_lower for word in ["link", "http", "www", "visit", "click"]
        )
        has_payment = any(
            word in msg_lower
            for word in ["pay", "payment", "send", "upi", "paytm", "gpay", "transfer"]
        )
        has_account = any(
            word in msg_lower for word in ["account", "bank", "kyc", "verify", "identity"]
        )

        filtered = []

        if has_link:
            filtered.extend(
                [
                    t
                    for t in templates
                    if any(w in t.lower() for w in ["link", "site", "page", "open"])
                ]
            )

        if has_payment or has_account:
            filtered.extend(
                [
                    t
                    for t in templates
                    if any(
                        w in t.lower()
                        for w in ["account", "bank", "upi", "pay", "number", "code"]
                    )
                ]
            )

        # If no specific matches, return original list (limited by max_candidates)
        if not filtered:
            return templates[:max_candidates]

        # Remove duplicates while preserving order
        unique_filtered = []
        for t in filtered:
            if t not in unique_filtered:
                unique_filtered.append(t)

        return unique_filtered[:max_candidates]

    def _generate_with_llm(
        self,
        agent_state: str,
        scammer_message: str,
        persona_name: str,
        recent_user_context: Optional[List[str]] = None,
        fatigue_level: int = 0,
        response_strategy: str = "CONFUSED_CLARIFICATION",
    ) -> str:
        """
        Generate reply using LLM (Real local or Mock API).

        Supports local LLaMA via Ollama for privacy-safe generation.
        """

        # --- PROMPT DESIGN ---
        persona_desc = self.PERSONA_DEFINITIONS.get(
            persona_name, self.PERSONA_DEFINITIONS["confused_elderly"]
        )

        context_str = ""
        if recent_user_context:
            context_str = "Recent Conversation History:\n" + "\n".join(
                [f"- {msg}" for msg in recent_user_context]
            )

        # Strategy-specific instructions
        strategy_instruction = ""
        if response_strategy == "clarify":
            strategy_instruction = "Ask a specific question to clarify their request. Do NOT be vague."
        elif response_strategy == "verify":
            strategy_instruction = "Express mild doubt. Ask for proof or verification. Do NOT simply refuse."
        elif response_strategy == "deflect":
            strategy_instruction = "Use a plausible excuse to delay action (e.g., busy, driving, need to ask someone). Do NOT ask questions."
        elif response_strategy == "boundary":
            strategy_instruction = "Be firm but polite. Set a boundary. Indicate you are disengaging or need to stop."
        else: # Fallback for legacy strategy names or defaults
             if response_strategy == "GUARDED_RESISTANCE":
                 strategy_instruction = "Push back politely but firmly. Express mild doubt. Do NOT ask for more info."
             elif response_strategy == "STRATEGIC_DELAY":
                 strategy_instruction = "Use a realistic excuse to delay (e.g., driving, forgot glasses, need to ask someone). Do NOT ask questions."
             elif response_strategy == "FATIGUED_DISENGAGEMENT":
                 strategy_instruction = "Be short, dismissive, and sound like you are giving up on the conversation."
             elif response_strategy == "CONFUSED_CLARIFICATION":
                 strategy_instruction = "Ask a specific clarifying question about the request."

        # TASK 1: Update LLM SYSTEM PROMPT
        system_prompt = f"""You are simulating a real human being under possible scam pressure.
Persona: {persona_desc}

Current behavioral state: {agent_state}
Current response strategy: {response_strategy}
Strategy Instruction: {strategy_instruction}
Fatigue level: {fatigue_level}

IMPORTANT RULES:
- Never repeat the same type of response twice in a row.
- If confusion has already been expressed, shift to resistance or delay.
- Do NOT ask clarifying questions more than once per strategy if you are repeating yourself.
- Sound human, not procedural.
- Keep responses short (1 sentence) and emotionally consistent.
- NEVER accuse the scammer.
- NEVER provide real credentials.
- NEVER comply with requests for OTPs or account numbers.

General Strategy Guide:
- clarify: Ask ONE clarifying question, then move on.
- verify: Express mild doubt. Ask for proof or verification. Do NOT simply refuse.
- deflect: Use a plausible excuse to delay action (e.g., busy, driving, need to ask someone). Do NOT ask questions.
- boundary: Be firm but polite. Set a boundary. Indicate you are disengaging or need to stop."""

        full_prompt = f"""
        {system_prompt}
        
        {context_str}
        
        Latest Incoming Message: "{scammer_message}"
        
        Reply (1 concise sentence):
        """

        backend = os.getenv("LLM_BACKEND", "mock").lower()

        if backend == "local":
            # --- OLLAMA LOCAL CALL ---
            # Privacy-safe, offline generation using LLaMA 3.1
            # CORRECTED: Configurable URL and Model
            base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434").rstrip(
                "/"
            )
            model_name = os.getenv("OLLAMA_MODEL", "llama3.1")

            try:
                # Use streaming with NO read timeout to support long generation
                # timeout=(connect_timeout, read_timeout) -> (5, None)
                response = requests.post(
                    f"{base_url}/api/generate",
                    json={"model": model_name, "prompt": full_prompt, "stream": True},
                    stream=True,
                    timeout=(5, None) 
                )
                response.raise_for_status()
                
                full_reply = ""
                for line in response.iter_lines():
                    if line:
                        import json
                        try:
                            chunk = json.loads(line)
                            if "response" in chunk:
                                full_reply += chunk["response"]
                            if chunk.get("done", False):
                                break
                        except json.JSONDecodeError:
                            continue
                            
                full_reply = full_reply.strip()
                
                if full_reply:
                    return full_reply
                else:
                    raise ValueError("Empty response from Ollama")
            except Exception as e:
                logger.error(f"Local LLM call failed: {e}. Falling back.")
                raise e  # Re-raise to trigger template fallback in generate_reply

        else:
            # --- MOCK API CALL (Default) ---
            return f"[LLM-{agent_state}] {self._generate_with_templates(agent_state, scammer_message, persona_name, fatigue_level, response_strategy)}"


if __name__ == "__main__":
    # Quick test
    service = AgentReplyService()
    print("Template:", service.generate_reply("CONFUSED", "Block account now"))

    # Simulate LLM enabled
    service.use_llm = True
    service.llm_api_key = "dummy"
    print("LLM Path:", service.generate_reply("TRUST_BUILDING", "Verify here"))