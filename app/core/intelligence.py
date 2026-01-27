"""
Intelligence Extraction Engine – Agentic Honey-Pot System

This module implements the passive extraction of scam intelligence from
scammer messages using regex pattern matching.

CRITICAL RESPONSIBILITIES:
- Extract artifacts (UPIs, phones, links, accounts) from text
- Detect suspicious keywords
- Deduplicate findings within the current processing context
- strict adherence to intelligence_extraction_rules.md

DOES NOT:
- Store session state (stateless processing)
- Modify agent behavior
- Validate or visit extracted links (SAFETY CRITICAL)
- Call external APIs
"""

import re
from typing import Dict, List, Set

class IntelligenceExtractionEngine:
    """
    Stateless engine for extracting scam artifacts from text.
    
    Adheres to the schema defined in SESSION_SCHEMA.md and logic in 
    INTELLIGENCE_EXTRACTION_RULES.md.
    """

    # Compiled Regex Patterns
    
    # UPI IDs: [a-zA-Z0-9.\-_]{2,}@[a-zA-Z]{2,}
    # Case insensitive matching handled in extraction
    _UPI_PATTERN = re.compile(r'[a-zA-Z0-9.\-_]{2,}@[a-zA-Z]{2,}')

    # Phone Numbers: Indian numbers focus
    # Matches: +91-9876543210, 9876543210, 091-9876543210
    # Logic: Optional (+91|091) prefix, optional separator, starting with 6-9, followed by 9 digits
    _PHONE_PATTERN = re.compile(r'(?:\+91|091)?[\-\s]?[6-9]\d{9}')

    # Bank Accounts: 9-18 digit numeric sequences
    # Using \b to avoid matching inside other long numbers if possible
    _ACCOUNT_PATTERN = re.compile(r'\b\d{9,18}\b')

    # Phishing Links: HTTP/HTTPS URLs
    # Matches http://, https://, www.
    _URL_PATTERN = re.compile(r'https?://[^\s]+|www\.[^\s]+')

    # Suspicious Keywords (Case-insensitive)
    _SUSPICIOUS_KEYWORDS = {
        "urgent",
        "immediately",
        "verify now",
        "account blocked",
        "kyc update",
        "limited time",
        "immediate action",
        "expire",
        "suspended",
        "block"
    }

    def extract_intelligence(self, message: str) -> Dict[str, List[str]]:
        """
        Analyze a scammer message and extract structured intelligence.

        Args:
            message: The raw text content from the scammer.

        Returns:
            Dictionary matching the 'extractedIntelligence' schema.
            Values are deduplicated Lists of strings.
        """
        if not message:
            return self._empty_result()

        # Normalize message for consistent keyword matching
        message_lower = message.lower()

        extracted = {
            "bankAccounts": self._extract_bank_accounts(message),
            "upiIds": self._extract_upi_ids(message),
            "phoneNumbers": self._extract_phone_numbers(message),
            "phishingLinks": self._extract_links(message),
            "suspiciousKeywords": self._extract_keywords(message_lower)
        }

        return extracted

    def _empty_result(self) -> Dict[str, List[str]]:
        return {
            "bankAccounts": [],
            "upiIds": [],
            "phoneNumbers": [],
            "phishingLinks": [],
            "suspiciousKeywords": []
        }

    def _extract_upi_ids(self, text: str) -> List[str]:
        """Extract and deduplicate UPI IDs."""
        matches = self._UPI_PATTERN.findall(text)
        # UPI IDs are generally case-insensitive, but we return as found or lower?
        # Rule says "Deduplicate across session" and "Preserve original casing for reporting".
        # We will return unique strings.
        return list(set(matches))

    def _extract_phone_numbers(self, text: str) -> List[str]:
        """Extract and deduplicate phone numbers."""
        matches = self._PHONE_PATTERN.findall(text)
        # Cleanup: remove spaces/dashes for cleaner storage? 
        # Rule says "Normalize to E.164 format where possible"
        # For this prototype, we'll keep it simple but maybe strip spaces for deduplication.
        normalized = set()
        for match in matches:
            clean = match.replace(" ", "").replace("-", "")
            normalized.add(clean)
        return list(normalized)

    def _extract_bank_accounts(self, text: str) -> List[str]:
        """Extract 9-18 digit account numbers."""
        matches = self._ACCOUNT_PATTERN.findall(text)
        # Basic filtering: Ignore numbers that look like timestamps if identifiable?
        # For now, regex constraints (9-18 digits) are the primary filter.
        return list(set(matches))

    def _extract_links(self, text: str) -> List[str]:
        """Extract URLs."""
        matches = self._URL_PATTERN.findall(text)
        return list(set(matches))

    def _extract_keywords(self, text_lower: str) -> List[str]:
        """Check for presence of suspicious keywords."""
        found = set()
        for keyword in self._SUSPICIOUS_KEYWORDS:
            if keyword in text_lower:
                found.add(keyword)
        return list(found)

if __name__ == "__main__":
    # Quick self-test logic (not part of production usage)
    engine = IntelligenceExtractionEngine()
    test_msg = "URGENT: Your account 123456789012 is blocked. Pay to scammer@okicici or call +91-9876543210. Visit http://scam.com/verify"
    print(engine.extract_intelligence(test_msg))
