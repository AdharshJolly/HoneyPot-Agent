"""
Scam Detection Engine – Agentic Honey-Pot System

This module implements multi-layered scam detection with optional LLM assistance.
It combines deterministic keyword/regex checks with optional LLM classification
while maintaining strict determinism for final scamDetected decision.

CRITICAL PRINCIPLES:
- Keyword-based detection is primary (always available)
- LLM classification is optional (graceful fallback)
- Final scamDetected is computed deterministically
- LLM output informs confidence, not the boolean decision
- Never let LLM directly control scamDetected
"""

import re
import os
import logging
from typing import Tuple, Optional, Dict, Any
from enum import Enum

logger = logging.getLogger(__name__)


class LLMBackend(Enum):
    """Supported LLM backends for optional classification."""

    LOCAL = "local"  # Ollama/LLaMA
    GEMINI = "gemini"  # Google Gemini
    OPENAI = "openai"  # OpenAI GPT
    DISABLED = "disabled"  # No LLM


class ScamDetectionEngine:
    """
    Multi-layered scam detection with optional LLM assistance.

    WHY this design:
    - Keyword-based detection: Fast, deterministic, always available
    - LLM assistance: More nuanced, context-aware, optional
    - Deterministic combination: Prevents LLM from controlling outcome
    - Safe fallback: Works offline if LLM unavailable

    Confidence scoring combines:
    - Keyword strength (baseline)
    - LLM classification (when available)
    - Pattern matching (heuristics)

    Final decision: deterministic rule-based on combined score
    """

    # Scam-related keywords from INTELLIGENCE_EXTRACTION_RULES.md
    # Organized by category for granular confidence scoring
    CRITICAL_SCAM_KEYWORDS = {
        # Financial threats (high confidence)
        "blocked",
        "suspended",
        "freeze",
        "deactivate",
        "urgent action",
        "immediate action",
        "act now",
        # Verification requests (high confidence)
        "verify",
        "confirm",
        "authenticate",
        "update",
        # Financial context (medium-high confidence)
        "account",
        "bank",
        "kyc",
        "expire",
        "expiry",
        # Pressure tactics (medium confidence)
        "urgent",
        "hurry",
        "limited time",
        "asap",
        # Payment methods (context-dependent)
        "transfer",
        "send",
        "upi",
        "paytm",
        "gpay",
    }

    # Scam patterns (regex) for more sophisticated detection
    SCAM_PATTERNS = {
        # Common scam message patterns
        r"(?:your|account)\s+(?:will\s+)?(?:be\s+)?(?:blocked|suspended|deactivated)",
        r"(?:urgent|immediate)(?:ly)?\s+(?:action|verification|confirmation)",
        r"(?:verify|confirm|update)\s+(?:your|account)\s+(?:details|information|kyc)",
        r"(?:click|open|visit)\s+(?:this|the)\s+link",
        r"(?:send|transfer|pay)\s+(?:to|via)\s+(?:upi|paytm|bank)",
        r"otp|one\s+time\s+password",
        r"cvv|pin|password",
    }

    # Compiled regex patterns
    COMPILED_PATTERNS = [
        re.compile(pattern, re.IGNORECASE) for pattern in SCAM_PATTERNS
    ]

    def __init__(
        self,
        use_llm: bool = True,
        llm_backend: str = "local",
        confidence_threshold: float = 0.5,
    ):
        """
        Initialize ScamDetectionEngine with optional LLM support.

        Args:
            use_llm: Whether to use LLM for classification
            llm_backend: LLM provider ("local", "gemini", "openai", "disabled")
            confidence_threshold: Score above which to mark as scam (0.0-1.0)
        """
        self.use_llm = use_llm
        self.confidence_threshold = confidence_threshold
        self.llm_backend = self._parse_llm_backend(llm_backend)
        self.llm_available = False
        self.llm_client = None

        # Initialize LLM client if enabled
        if self.use_llm and self.llm_backend != LLMBackend.DISABLED:
            self._initialize_llm_client()

    def _parse_llm_backend(self, backend: str) -> LLMBackend:
        """Parse string backend to LLMBackend enum."""
        try:
            return LLMBackend(backend.lower())
        except ValueError:
            logger.warning(f"Unknown LLM backend: {backend}, disabling LLM")
            return LLMBackend.DISABLED

    def _initialize_llm_client(self) -> None:
        """
        Initialize LLM client based on configured backend.

        WHY separate initialization:
        - Allows graceful degradation if LLM setup fails
        - Doesn't block system startup
        - Can be tested independently
        """
        try:
            if self.llm_backend == LLMBackend.LOCAL:
                self._initialize_ollama()
            elif self.llm_backend == LLMBackend.GEMINI:
                self._initialize_gemini()
            elif self.llm_backend == LLMBackend.OPENAI:
                self._initialize_openai()
            else:
                self.llm_available = False
        except Exception as e:
            logger.error(f"Failed to initialize LLM backend: {e}")
            self.llm_available = False

    def _initialize_ollama(self) -> None:
        """Initialize Ollama (local LLaMA) client."""
        try:
            import requests

            base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
            model = os.getenv("OLLAMA_MODEL", "llama2")

            # Test connection
            response = requests.get(f"{base_url}/api/tags", timeout=5)
            if response.status_code == 200:
                self.llm_client = {
                    "type": "ollama",
                    "base_url": base_url,
                    "model": model,
                }
                self.llm_available = True
                logger.info(f"Ollama LLM initialized: {model}")
            else:
                logger.warning("Ollama not responding")
        except Exception as e:
            logger.warning(f"Ollama initialization failed: {e}")

    def _initialize_gemini(self) -> None:
        """Initialize Google Gemini API client."""
        try:
            import google.generativeai as genai

            api_key = os.getenv("GEMINI_API_KEY")
            if not api_key:
                logger.warning("GEMINI_API_KEY not set")
                return

            genai.configure(api_key=api_key)
            self.llm_client = {"type": "gemini", "client": genai}
            self.llm_available = True
            logger.info("Gemini LLM initialized")
        except Exception as e:
            logger.warning(f"Gemini initialization failed: {e}")

    def _initialize_openai(self) -> None:
        """Initialize OpenAI API client."""
        try:
            import openai

            api_key = os.getenv("OPENAI_API_KEY")
            if not api_key:
                logger.warning("OPENAI_API_KEY not set")
                return

            openai.api_key = api_key
            self.llm_client = {"type": "openai", "client": openai}
            self.llm_available = True
            logger.info("OpenAI LLM initialized")
        except Exception as e:
            logger.warning(f"OpenAI initialization failed: {e}")

    def detect(self, message: str) -> Tuple[bool, float]:
        """
        Detect scam intent with optional LLM assistance.

        WHY this method structure:
        - Deterministic keyword check first (fast baseline)
        - Optional LLM check second (enriches confidence)
        - Combined score determines final decision
        - Always falls back to keywords if LLM unavailable

        Args:
            message: Scammer message to analyze

        Returns:
            Tuple of (is_scam: bool, confidence: float 0.0-1.0)
        """
        # Step 1: Keyword-based detection (primary, always available)
        keyword_score = self._detect_keyword_based(message)

        # Step 2: Optional LLM-assisted detection (enrichment only)
        llm_score = 0.0
        if self.use_llm and self.llm_available:
            llm_score = self._detect_llm_assisted(message)

        # Step 3: Combine scores deterministically
        combined_score = self._combine_scores(keyword_score, llm_score)

        # Step 4: Make final deterministic decision
        is_scam = combined_score >= self.confidence_threshold

        logger.debug(
            f"Scam detection: keyword={keyword_score:.2f}, "
            f"llm={llm_score:.2f}, combined={combined_score:.2f}, "
            f"is_scam={is_scam}"
        )

        return is_scam, combined_score

    def _detect_keyword_based(self, message: str) -> float:
        """
        Keyword and pattern-based scam detection.

        WHY separate method:
        - Can be tested independently
        - Always available (no dependencies)
        - Forms the deterministic baseline

        Returns:
            Confidence score (0.0-1.0)
        """
        message_lower = message.lower()
        confidence = 0.0

        # Check critical keywords (high weight)
        critical_matches = sum(
            1 for keyword in self.CRITICAL_SCAM_KEYWORDS if keyword in message_lower
        )
        confidence += min(critical_matches * 0.15, 0.6)

        # Check regex patterns (medium weight)
        pattern_matches = sum(
            1 for pattern in self.COMPILED_PATTERNS if pattern.search(message)
        )
        confidence += min(pattern_matches * 0.1, 0.4)

        # Check message length heuristics
        # Scam messages are often short and repetitive
        if 20 < len(message) < 500:
            confidence += 0.1

        # Cap confidence at 1.0
        return min(confidence, 1.0)

    def _detect_llm_assisted(self, message: str) -> float:
        """
        Optional LLM-based classification for nuance.

        WHY optional:
        - Adds context-awareness beyond keywords
        - Can understand sophisticated scams
        - Gracefully degrades if unavailable
        - Doesn't block if LLM is slow

        Returns:
            LLM confidence score (0.0-1.0), or 0.0 if unavailable
        """
        if not self.llm_available or not self.llm_client:
            return 0.0

        try:
            if self.llm_client["type"] == "ollama":
                return self._classify_with_ollama(message)
            elif self.llm_client["type"] == "gemini":
                return self._classify_with_gemini(message)
            elif self.llm_client["type"] == "openai":
                return self._classify_with_openai(message)
        except Exception as e:
            logger.error(f"LLM classification failed: {e}")
            return 0.0

        return 0.0

    def _classify_with_ollama(self, message: str) -> float:
        """
        Classify using Ollama (local LLaMA).

        WHY Ollama:
        - Runs locally (privacy-preserving)
        - No API costs
        - Fast inference
        - Can be used offline
        """
        try:
            import requests

            base_url = self.llm_client["base_url"]
            model = self.llm_client["model"]

            prompt = self._construct_classification_prompt(message)

            response = requests.post(
                f"{base_url}/api/generate",
                json={"model": model, "prompt": prompt, "stream": False},
                timeout=10,
            )

            if response.status_code == 200:
                output = response.json().get("response", "")
                confidence = self._parse_llm_response(output)
                return confidence
        except Exception as e:
            logger.debug(f"Ollama classification failed: {e}")

        return 0.0

    def _classify_with_gemini(self, message: str) -> float:
        """Classify using Google Gemini API."""
        try:
            import google.generativeai as genai

            model = genai.GenerativeModel("gemini-pro")
            prompt = self._construct_classification_prompt(message)

            response = model.generate_content(prompt)
            confidence = self._parse_llm_response(response.text)
            return confidence
        except Exception as e:
            logger.debug(f"Gemini classification failed: {e}")

        return 0.0

    def _classify_with_openai(self, message: str) -> float:
        """Classify using OpenAI GPT API."""
        try:
            import openai

            prompt = self._construct_classification_prompt(message)

            response = openai.ChatCompletion.create(
                model="gpt-3.5-turbo",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=100,
                timeout=10,
            )

            output = response.choices[0].message.content
            confidence = self._parse_llm_response(output)
            return confidence
        except Exception as e:
            logger.debug(f"OpenAI classification failed: {e}")

        return 0.0

    def _construct_classification_prompt(self, message: str) -> str:
        """
        Construct a prompt for LLM classification.

        WHY explicit prompt:
        - Controls LLM output format
        - Ensures parseable response
        - Keeps LLM focused on task
        """
        return f"""Analyze this message for scam/fraud indicators. Respond with ONLY a number between 0 and 1 indicating confidence that this is a scam message. 
0 = definitely not a scam
1 = definitely a scam

Message: "{message}"

Confidence (0-1):"""

    def _parse_llm_response(self, response: str) -> float:
        """
        Parse LLM response into confidence score.

        WHY defensive parsing:
        - LLM output can be unpredictable
        - Must handle invalid formats gracefully
        - Never crash on bad LLM response
        """
        try:
            # Extract first number found in response
            import re

            numbers = re.findall(r"\d+\.?\d*", response.strip())
            if numbers:
                score = float(numbers[0])
                # Clamp to valid range
                return max(0.0, min(1.0, score))
        except (ValueError, IndexError):
            pass

        # Default: treat unparseable response as neutral
        return 0.0

    def _combine_scores(self, keyword_score: float, llm_score: float) -> float:
        """
        Combine keyword and LLM scores deterministically.

        WHY weighted combination:
        - Keyword detection is always available (weight 0.7)
        - LLM enriches but doesn't override (weight 0.3)
        - Prevents LLM from controlling decision
        - Maintains determinism

        Args:
            keyword_score: Confidence from keyword detection (0.0-1.0)
            llm_score: Confidence from LLM (0.0-1.0)

        Returns:
            Combined confidence score (0.0-1.0)
        """
        # If LLM not available, just return keyword score
        if llm_score == 0.0:
            return keyword_score

        # Weighted combination: keyword is primary, LLM is secondary
        combined = (keyword_score * 0.7) + (llm_score * 0.3)

        # Apply boost if both agree (high confidence)
        if keyword_score > 0.5 and llm_score > 0.5:
            combined = min(combined * 1.15, 1.0)

        # Clamp to valid range
        return max(0.0, min(1.0, combined))

    def is_scam(self, message: str) -> bool:
        """
        Simple boolean check (convenience method).

        Returns:
            True if scam detected, False otherwise
        """
        is_scam, _ = self.detect(message)
        return is_scam

    def get_confidence(self, message: str) -> float:
        """
        Get only confidence score (convenience method).

        Returns:
            Confidence score (0.0-1.0)
        """
        _, confidence = self.detect(message)
        return confidence

    def set_confidence_threshold(self, threshold: float) -> None:
        """
        Adjust the confidence threshold for scam detection.

        WHY configurable:
        - Allows tuning detection sensitivity
        - Can adjust for false positive/negative balance
        - Useful for A/B testing

        Args:
            threshold: Score above which to mark as scam (0.0-1.0)
        """
        if 0.0 <= threshold <= 1.0:
            self.confidence_threshold = threshold
            logger.info(f"Confidence threshold set to {threshold}")
        else:
            logger.warning(f"Invalid threshold {threshold}, ignoring")
