"""
Session persistence with Redis (cache) and Postgres (durable).
"""

from __future__ import annotations

import json
import logging
import os
from typing import Optional

import psycopg
import redis

from app.core.session import Session, session_from_dict, session_to_dict

logger = logging.getLogger(__name__)


class SessionStore:
    """Abstract session store contract."""

    def get(self, session_id: str) -> Optional[Session]:
        raise NotImplementedError

    def save(self, session: Session) -> None:
        raise NotImplementedError

    def delete(self, session_id: str) -> None:
        raise NotImplementedError


class RedisPostgresSessionStore(SessionStore):
    """Redis cache + Postgres durable storage."""

    def __init__(self, redis_url: str, postgres_dsn: str, ttl_seconds: int = 0):
        if not redis_url or not postgres_dsn:
            raise ValueError("Redis and Postgres configuration required")

        self._redis = redis.Redis.from_url(redis_url, decode_responses=True)
        self._postgres_dsn = postgres_dsn
        self._ttl_seconds = max(ttl_seconds, 0)
        self._ensure_table()

    def get(self, session_id: str) -> Optional[Session]:
        cached = self._get_from_cache(session_id)
        if cached:
            return cached

        session = self._get_from_postgres(session_id)
        if session:
            self._set_cache(session_id, session)
        return session

    def save(self, session: Session) -> None:
        payload = session_to_dict(session)
        self._write_postgres(session.sessionId, payload)
        self._set_cache(session.sessionId, session)

    def delete(self, session_id: str) -> None:
        try:
            self._redis.delete(self._cache_key(session_id))
        except redis.RedisError as exc:
            logger.warning("Redis delete failed for %s: %s", session_id, exc)

        try:
            with psycopg.connect(self._postgres_dsn) as conn:
                with conn.cursor() as cursor:
                    cursor.execute(
                        "DELETE FROM honeypot_sessions WHERE session_id = %s",
                        (session_id,),
                    )
                conn.commit()
        except psycopg.Error as exc:
            logger.warning("Postgres delete failed for %s: %s", session_id, exc)

    def _ensure_table(self) -> None:
        try:
            with psycopg.connect(self._postgres_dsn) as conn:
                with conn.cursor() as cursor:
                    cursor.execute(
                        """
                        CREATE TABLE IF NOT EXISTS honeypot_sessions (
                            session_id TEXT PRIMARY KEY,
                            payload JSONB NOT NULL,
                            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                        )
                        """
                    )
                conn.commit()
        except psycopg.Error as exc:
            logger.error("Failed to ensure sessions table: %s", exc)
            raise

    def _get_from_cache(self, session_id: str) -> Optional[Session]:
        try:
            cached = self._redis.get(self._cache_key(session_id))
        except redis.RedisError as exc:
            logger.warning("Redis get failed for %s: %s", session_id, exc)
            return None

        if not cached:
            return None

        try:
            payload = json.loads(cached)
        except json.JSONDecodeError:
            return None

        return session_from_dict(payload)

    def _get_from_postgres(self, session_id: str) -> Optional[Session]:
        try:
            with psycopg.connect(self._postgres_dsn) as conn:
                with conn.cursor() as cursor:
                    cursor.execute(
                        "SELECT payload FROM honeypot_sessions WHERE session_id = %s",
                        (session_id,),
                    )
                    row = cursor.fetchone()
        except psycopg.Error as exc:
            logger.warning("Postgres fetch failed for %s: %s", session_id, exc)
            return None

        if not row:
            return None

        payload = row[0]
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except json.JSONDecodeError:
                return None

        return session_from_dict(payload)

    def _write_postgres(self, session_id: str, payload: dict) -> None:
        json_payload = json.dumps(payload, ensure_ascii=True)
        try:
            with psycopg.connect(self._postgres_dsn) as conn:
                with conn.cursor() as cursor:
                    cursor.execute(
                        """
                        INSERT INTO honeypot_sessions (session_id, payload, updated_at)
                        VALUES (%s, %s::jsonb, NOW())
                        ON CONFLICT (session_id)
                        DO UPDATE SET payload = EXCLUDED.payload, updated_at = NOW()
                        """,
                        (session_id, json_payload),
                    )
                conn.commit()
        except psycopg.Error as exc:
            logger.warning("Postgres write failed for %s: %s", session_id, exc)

    def _set_cache(self, session_id: str, session: Session) -> None:
        payload = json.dumps(session_to_dict(session), ensure_ascii=True)
        try:
            if self._ttl_seconds > 0:
                self._redis.setex(
                    self._cache_key(session_id), self._ttl_seconds, payload
                )
            else:
                self._redis.set(self._cache_key(session_id), payload)
        except redis.RedisError as exc:
            logger.warning("Redis write failed for %s: %s", session_id, exc)

    def _cache_key(self, session_id: str) -> str:
        return f"session:{session_id}"


def create_session_store_from_env() -> Optional[SessionStore]:
    store_type = os.getenv("SESSION_STORE", "memory").lower().strip()
    if store_type in {"memory", ""}:
        return None

    if store_type != "redis_postgres":
        logger.error("Unsupported SESSION_STORE value: %s", store_type)
        return None

    redis_url = os.getenv("REDIS_URL")
    postgres_dsn = os.getenv("POSTGRES_DSN")
    ttl_env = os.getenv("SESSION_TTL_SECONDS", "0").strip()
    try:
        ttl_seconds = max(int(ttl_env), 0)
    except ValueError:
        ttl_seconds = 0

    if not redis_url or not postgres_dsn:
        logger.error("REDIS_URL and POSTGRES_DSN are required for redis_postgres store")
        return None

    return RedisPostgresSessionStore(redis_url, postgres_dsn, ttl_seconds)
