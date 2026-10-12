"""One-shot, idempotent startup migration: remove the legacy "ollama_local" provider from stored data.

The database is built with create_all (no Alembic at runtime), so existing rows keep whatever they
held when the bundled Ollama still existed. This rewrites them so the UI never shows "Local Ollama"
for old chat sessions / workflows / configs, and drops any per-user Ollama URL (SSRF vector).
Each statement runs in its own transaction; a failure in one never blocks startup or the others.
"""
from __future__ import annotations

import logging

from sqlalchemy import text

logger = logging.getLogger(__name__)


def _q(ident: str) -> str:
    return '"' + ident.replace('"', '""') + '"'


async def _run(session_factory, sql: str, params: dict | None = None) -> int:
    try:
        async with session_factory() as db:
            res = await db.execute(text(sql), params or {})
            await db.commit()
            return res.rowcount or 0
    except Exception as exc:  # noqa: BLE001 - best effort, never fatal
        logger.debug("legacy-provider cleanup skipped a statement: %s", exc)
        return 0


async def purge_unused_provider_keys(session_factory) -> int:
    """Remove the plaintext per-user provider API keys (openai/anthropic/grok/openrouter/mistral/xai _api_key) that older versions
    saved in user_settings.llm_settings. Nothing ever read them; they were only exposed. Idempotent; never blocks startup."""
    keys = ("openai_api_key", "anthropic_api_key", "grok_api_key", "openrouter_api_key", "mistral_api_key", "xai_api_key")
    arr = "ARRAY[" + ", ".join(f"'{k}'" for k in keys) + "]"          # constants, not input
    try:
        async with session_factory() as db:
            row = (await db.execute(text(
                "SELECT data_type FROM information_schema.columns WHERE table_schema = 'public' "
                "AND table_name = 'user_settings' AND column_name = 'llm_settings'"))).first()
        if not row:
            return 0
        dtype = "jsonb" if row[0] == "jsonb" else "json"
        n = await _run(session_factory,
            f"UPDATE user_settings SET llm_settings = (llm_settings::jsonb - {arr})::{dtype} "
            f"WHERE jsonb_exists_any(llm_settings::jsonb, {arr})")     # exact: only rows that really hold one of the keys
        if n:
            logger.info("Removed stored plaintext provider API keys from %s user settings row(s)", n)
        return n
    except Exception as exc:  # noqa: BLE001
        logger.warning("Provider key purge skipped: %s", exc)
        return 0


async def normalize_legacy_providers(session_factory) -> dict:
    counts = {"llm_configs": 0, "chat_sessions": 0, "json_cells": 0, "user_urls": 0}

    counts["llm_configs"] = await _run(
        session_factory,
        "UPDATE llm_configs SET provider = 'ollama_remote' WHERE provider::text = 'ollama_local'",
    )
    counts["chat_sessions"] = await _run(
        session_factory,
        "UPDATE chat_sessions SET provider = 'ollama_remote' "
        "WHERE provider IN ('ollama_local', 'ollama-local', 'ollama')",
    )
    # New sessions must not default back to the removed provider on databases built by old migrations.
    await _run(session_factory, "ALTER TABLE chat_sessions ALTER COLUMN provider SET DEFAULT 'ollama_remote'")

    # Every json/jsonb column in the schema (workflows, user settings, templates, schedules, ...).
    cols: list[tuple[str, str, str]] = []
    try:
        async with session_factory() as db:
            rows = await db.execute(text(
                "SELECT table_name, column_name, data_type FROM information_schema.columns "
                "WHERE table_schema = 'public' AND data_type IN ('json', 'jsonb')"
            ))
            cols = [(r[0], r[1], r[2]) for r in rows.fetchall()]
    except Exception as exc:  # noqa: BLE001
        logger.debug("legacy-provider cleanup: could not list json columns: %s", exc)

    for table, column, dtype in cols:
        t, c = _q(table), _q(column)
        n = await _run(
            session_factory,
            f"UPDATE {t} SET {c} = REPLACE(REPLACE({c}::text, '\"ollama_local\"', '\"ollama_remote\"'), "
            f"'ollama_local:', 'ollama_remote:')::{dtype} "
            f"WHERE {c}::text LIKE '%ollama_local%'",
        )
        counts["json_cells"] += n
        if table == "user_settings" and column == "llm_settings":
            counts["user_urls"] += await _run(
                session_factory,
                f"UPDATE {t} SET {c} = ({c}::jsonb - 'ollama_base_url')::{dtype} "
                f"WHERE {c}::text LIKE '%ollama_base_url%'",
            )

    if any(counts.values()):
        logger.info("Legacy 'ollama_local' data migrated to the external Ollama provider: %s", counts)
    return counts
