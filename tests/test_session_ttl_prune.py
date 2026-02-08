"""
Session TTL pruning tests.
"""

from datetime import datetime, timezone, timedelta

from app.core.session import SessionManager


def test_prune_expired_sessions(monkeypatch):
    monkeypatch.setenv("SESSION_TTL_SECONDS", "1")
    manager = SessionManager()

    session = manager.get_or_create_session("ttl-session")
    session.lastUpdatedAt = (
        datetime.now(timezone.utc) - timedelta(seconds=10)
    ).isoformat()

    removed = manager.prune_expired_sessions()

    assert removed == 1
    assert manager.session_exists("ttl-session") is False
