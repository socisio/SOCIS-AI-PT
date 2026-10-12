"""Single source of truth for LLM provider names.

The bundled "local" Ollama container no longer exists: Ollama is an EXTERNAL server
configured by an admin (Admin -> Settings -> Remote Ollama), alongside the hosted API
providers. Old data (saved workflows, chat sessions, user settings, LLM configs) may still
carry the legacy name "ollama_local"; every boundary maps it to "ollama_remote" through
these helpers so nothing downstream ever sees it.
"""
from __future__ import annotations

from typing import Any, Tuple

CANONICAL_OLLAMA = "ollama_remote"
LEGACY_OLLAMA_ALIASES = frozenset({"ollama_local", "ollama-local", "local_ollama", "ollama"})
SUPPORTED_PROVIDERS = ("ollama_remote", "openai", "anthropic", "openrouter", "grok", "mistral", "custom")

# JSON keys whose string value is a provider name.
_PROVIDER_KEYS = frozenset({"provider", "chat_provider", "default_provider", "llm_provider"})
_LEGACY_ID_PREFIX = "ollama_local:"


def normalize_provider(value: Any, default: str = CANONICAL_OLLAMA) -> str:
    """Canonical provider string. None/empty -> default; legacy local aliases -> ollama_remote."""
    if value is None:
        return default
    v = str(getattr(value, "value", value)).strip().lower()
    if not v:
        return default
    return CANONICAL_OLLAMA if v in LEGACY_OLLAMA_ALIASES else v


async def resolve_llm_credentials(db: Any, provider: str) -> Tuple[Any, Any]:
    """The admin-saved (api_key, api_url) for a non-Ollama provider's default active LLMConfig row, or (None, None)
    if there isn't one — callers fall back to the provider's `.env` variable exactly as before this existed.

    Added because every chat_<provider>() method in llm_service.py only ever read its key from `.env`
    (settings.OPENAI_API_KEY etc.) — a key saved through Admin -> AI providers -> Add LLM Provider was stored
    encrypted in the database but NEVER read back at call time, so configuring a provider there looked like it
    worked (the save succeeded) but silently had no effect on what the platform actually used. This is the single
    place that resolution now happens, reused by every call site instead of five separate copies of the same lookup.

    Imports are deferred (not at module level) because this module is imported very early and widely; importing the
    DB/model/encryption layers at the top would risk a circular import.
    """
    provider = normalize_provider(provider)
    if provider == CANONICAL_OLLAMA:
        # Ollama's "credential" is just its URL, already resolved separately via SettingsService.get_ollama_remote_url
        # — this helper is for the API-key providers only.
        return None, None
    try:
        from sqlalchemy import select
        from app.models.llm_config import LLMConfig
        cfg = (
            await db.execute(
                select(LLMConfig)
                .where(LLMConfig.is_active == True, LLMConfig.provider == provider)  # noqa: E712
                .order_by(LLMConfig.is_default.desc(), LLMConfig.created_at.asc())
            )
        ).scalars().first()
        if cfg is None:
            return None, None
        api_url = cfg.api_url or None
        api_key = None
        if cfg.api_key_encrypted:
            try:
                from app.core.encryption import decrypt_secret
                api_key = decrypt_secret(cfg.api_key_encrypted)
            except ValueError:
                # Wrong/rotated ENCRYPTION_KEY, or corrupted ciphertext — fall back to .env rather than fail the
                # whole chat request; the caller's own settings.*_API_KEY fallback still applies when this is None.
                api_key = None
        return api_key, api_url
    except Exception:
        # Never let a credential-lookup problem take down a chat request — fall back to .env, same as before.
        return None, None


async def resolve_default_llm_config(db: Any) -> dict | None:
    """The admin's single, true default LLM config across ALL providers — not "the default row for a given
    provider" (that's what resolve_llm_credentials and every per-provider query elsewhere already does), but "which
    provider should an unattended process use when nothing told it which one to pick."

    Needed because scan_worker.py's automatic post-scan analysis (run_scan's "LLM Analysis" step, which fires after
    EVERY scan with no user request to read a provider from) was hardcoded to LLMProvider.OLLAMA_REMOTE with no
    lookup at all — so configuring e.g. OpenAI as the admin's provider had no effect on it whatsoever, exactly the
    gap reported: "I configure one Provider and I can't use it on... AI Analyzer."

    Returns {"provider", "model", "api_key", "api_url"} for the highest-priority active config (is_default=True
    first, then oldest), or None if no LLMConfig rows exist at all (caller should fall back to the Ollama .env
    defaults, same as before this existed).
    """
    try:
        from sqlalchemy import select
        from app.models.llm_config import LLMConfig
        cfg = (
            await db.execute(
                select(LLMConfig)
                .where(LLMConfig.is_active == True)  # noqa: E712
                .order_by(LLMConfig.is_default.desc(), LLMConfig.created_at.asc())
            )
        ).scalars().first()
        if cfg is None:
            return None
        provider = normalize_provider(getattr(cfg.provider, "value", cfg.provider))
        api_key = None
        api_url = cfg.api_url or None
        if provider != CANONICAL_OLLAMA and cfg.api_key_encrypted:
            try:
                from app.core.encryption import decrypt_secret
                api_key = decrypt_secret(cfg.api_key_encrypted)
            except ValueError:
                api_key = None
        return {"provider": provider, "model": cfg.model_name, "api_key": api_key, "api_url": api_url}
    except Exception:
        return None


def normalize_provider_fields(obj: Any) -> Tuple[Any, bool]:
    """Recursively rewrite legacy provider values inside JSON-like data.

    Returns (new_obj, changed). Handles {"provider": "ollama_local"}, {"chat_provider": ...} and
    model ids of the form "ollama_local:<model>". Input is not mutated.
    """
    if isinstance(obj, dict):
        changed, out = False, {}
        for k, v in obj.items():
            if k in _PROVIDER_KEYS and isinstance(v, str) and v.strip().lower() in LEGACY_OLLAMA_ALIASES:
                out[k], changed = CANONICAL_OLLAMA, True
            else:
                nv, c = normalize_provider_fields(v)
                out[k], changed = nv, changed or c
        return out, changed
    if isinstance(obj, list):
        changed, out = False, []
        for v in obj:
            nv, c = normalize_provider_fields(v)
            out.append(nv)
            changed = changed or c
        return out, changed
    if isinstance(obj, str) and obj.startswith(_LEGACY_ID_PREFIX):
        return "ollama_remote:" + obj[len(_LEGACY_ID_PREFIX):], True
    return obj, False


def sanitize_user_llm_settings(data: dict | None) -> dict:
    """User-level LLM settings must never carry an Ollama URL: the backend would call whatever
    address a user typed (SSRF). The Ollama endpoint is admin-only. Also maps the legacy provider."""
    out = dict(data or {})
    out.pop("ollama_base_url", None)
    # Personal provider API keys are never stored or returned: no code path ever used them (the AI chat takes its credentials from
    # the admin-managed provider configs, which are encrypted), so keeping them only added plaintext secrets to the database.
    for k in [k for k in out if str(k).endswith("_api_key")]:
        out.pop(k, None)
    if "chat_provider" in out:
        out["chat_provider"] = normalize_provider(out.get("chat_provider"))
    return out
