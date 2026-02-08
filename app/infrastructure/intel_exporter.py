"""
Intelligence export helper.

Exports redacted intelligence snapshots for display without exposing raw values.
"""

from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from typing import Dict, List
from urllib.parse import urlparse

from app.core.session import Session


class IntelligenceExporter:
    """
    Writes redacted intelligence snapshots to a JSONL file.

    This is optional and controlled by environment variables.
    """

    def __init__(self) -> None:
        self.enabled = os.getenv("INTEL_EXPORT_ENABLED", "false").lower() == "true"
        self.export_path = os.getenv(
            "INTEL_EXPORT_PATH", "exports/intel_snapshots.jsonl"
        )
        self.max_samples = self._read_int_env("INTEL_EXPORT_MAX_SAMPLES", 5)
        self._lock = threading.RLock()

    def export_snapshot(self, session: Session) -> None:
        if not self.enabled:
            return

        payload = self._build_payload(session)
        self._write_line(payload)

    def _build_payload(self, session: Session) -> Dict[str, object]:
        intel = session.extractedIntelligence
        return {
            "sessionId": session.sessionId,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agentState": session.agentState,
            "scamDetected": session.scamDetected,
            "counts": {
                "bankAccounts": len(intel.bankAccounts),
                "upiIds": len(intel.upiIds),
                "phoneNumbers": len(intel.phoneNumbers),
                "phishingLinks": len(intel.phishingLinks),
                "suspiciousKeywords": len(intel.suspiciousKeywords),
            },
            "samples": {
                "bankAccounts": self._sample_and_redact(
                    intel.bankAccounts, self._redact_digits
                ),
                "upiIds": self._sample_and_redact(intel.upiIds, self._redact_upi),
                "phoneNumbers": self._sample_and_redact(
                    intel.phoneNumbers, self._redact_digits
                ),
                "phishingLinks": self._sample_and_redact(
                    intel.phishingLinks, self._redact_url
                ),
                "suspiciousKeywords": self._sample(intel.suspiciousKeywords),
            },
        }

    def _sample_and_redact(self, items: List[str], redact_fn) -> List[str]:
        return [redact_fn(value) for value in self._sample(items)]

    def _sample(self, items: List[str]) -> List[str]:
        return items[: self.max_samples]

    def _redact_digits(self, value: str) -> str:
        digits = "".join(ch for ch in value if ch.isdigit())
        if len(digits) <= 4:
            return "****"
        return "****" + digits[-4:]

    def _redact_upi(self, value: str) -> str:
        if "@" not in value:
            return "***@***"
        local, domain = value.split("@", 1)
        if len(local) <= 2:
            masked_local = "*" * len(local)
        else:
            masked_local = local[:2] + "*" * (len(local) - 2)
        return f"{masked_local}@{domain}"

    def _redact_url(self, value: str) -> str:
        try:
            parsed = urlparse(value)
            if parsed.scheme and parsed.netloc:
                return f"{parsed.scheme}://{parsed.netloc}"
        except Exception:
            pass
        return "url://redacted"

    def _write_line(self, payload: Dict[str, object]) -> None:
        directory = os.path.dirname(self.export_path)
        if directory:
            os.makedirs(directory, exist_ok=True)

        line = json.dumps(payload, ensure_ascii=True)
        with self._lock:
            with open(self.export_path, "a", encoding="utf-8") as handle:
                handle.write(line + "\n")

    def _read_int_env(self, name: str, default: int) -> int:
        value = os.getenv(name)
        if value is None:
            return default
        try:
            parsed = int(value)
        except ValueError:
            return default
        return max(parsed, 0)
