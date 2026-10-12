"""
SOCIS-AI-PT — Plugin Config Service
Handles CRUD for builtin plugin configurations with Fernet encryption for secrets.
"""

from __future__ import annotations
import json
import logging
import uuid
from typing import Any
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from fastapi import HTTPException
from app.models.plugin_config import PluginConfig
from app.core.encryption import encrypt_secret, decrypt_secret
from app.plugins.builtin import BUILTIN_REGISTRY, get_plugin_class, get_plugin_meta, get_all_plugin_ids

log = logging.getLogger(__name__)


def _sensitive_keys(plugin_id: str) -> set[str]:
    """Return the set of field keys marked sensitive for this plugin."""
    meta = get_plugin_meta(plugin_id)
    if not meta:
        return set()
    return {f["key"] for f in meta.get("fields", []) if f.get("sensitive")}


async def get_all_plugin_statuses(db: AsyncSession) -> list[dict]:
    """
    Return metadata + DB-stored status for all 12 builtin plugins.
    Sensitive config values are replaced with a boolean 'configured' flag.
    """
    rows = (await db.execute(select(PluginConfig))).scalars().all()
    db_map: dict[str, PluginConfig] = {r.plugin_id: r for r in rows}

    result = []
    for pid in get_all_plugin_ids():
        meta = get_plugin_meta(pid)
        row = db_map.get(pid)
        entry = {**meta,
                 "enabled": row.enabled if row else False,
                 "trigger_count": row.trigger_count if row else 0,
                 "last_triggered_at": row.last_triggered_at.isoformat() if row and row.last_triggered_at else None,
                 "last_error": row.last_error if row else None,
                 "configured": row is not None and (bool(row.config_encrypted) or bool(row.config_plain))}
        # Expose non-sensitive plain config values for display
        if row and row.config_plain:
            sens = _sensitive_keys(pid)
            entry["config_preview"] = {k: v for k, v in row.config_plain.items() if k not in sens}
        else:
            entry["config_preview"] = {}
        result.append(entry)
    return result


async def get_plugin_config_row(db: AsyncSession, plugin_id: str) -> PluginConfig | None:
    result = await db.execute(select(PluginConfig).where(PluginConfig.plugin_id == plugin_id))
    return result.scalar_one_or_none()


async def save_plugin_config(
    db: AsyncSession,
    plugin_id: str,
    config: dict,
    enabled: bool,
) -> PluginConfig:
    """
    Persist plugin configuration. Sensitive fields are Fernet-encrypted and stored
    in config_encrypted (as a JSON blob). Non-sensitive fields go into config_plain.
    """
    sens_keys = _sensitive_keys(plugin_id)
    plain: dict[str, Any] = {}
    secret: dict[str, Any] = {}

    for k, v in config.items():
        if k in sens_keys:
            secret[k] = v
        else:
            plain[k] = v

    # Encrypt the secret portion
    config_encrypted: str | None = None
    if secret:
        try:
            config_encrypted = encrypt_secret(json.dumps(secret))
        except Exception as exc:
            raise HTTPException(
                status_code=500,
                detail="Failed to encrypt plugin secrets",
            ) from exc

    row = (await db.execute(select(PluginConfig).where(PluginConfig.plugin_id == plugin_id))).scalar_one_or_none()
    if row:
        row.enabled = enabled
        row.config_encrypted = config_encrypted
        row.config_plain = plain
    else:
        row = PluginConfig(
            id=str(uuid.uuid4()),
            plugin_id=plugin_id,
            enabled=enabled,
            config_encrypted=config_encrypted,
            config_plain=plain,
        )
        db.add(row)

    await db.commit()
    await db.refresh(row)
    return row


async def toggle_plugin(db: AsyncSession, plugin_id: str, enabled: bool) -> PluginConfig:
    """Enable or disable a plugin without touching its config."""
    row = (await db.execute(select(PluginConfig).where(PluginConfig.plugin_id == plugin_id))).scalar_one_or_none()
    if not row:
        row = PluginConfig(id=str(uuid.uuid4()), plugin_id=plugin_id, enabled=enabled)
        db.add(row)
    else:
        row.enabled = enabled
    await db.commit()
    await db.refresh(row)
    return row


def load_plugin_instance(plugin_id: str, row: PluginConfig | None):
    """
    Instantiate a builtin plugin with its decrypted config.
    Returns None if the plugin_id is unknown.
    """
    cls = get_plugin_class(plugin_id)
    if not cls:
        return None

    config: dict = {}
    if row:
        # Merge plain config
        if row.config_plain:
            config.update(row.config_plain)
        # Decrypt and merge secret config
        if row.config_encrypted:
            try:
                secret = json.loads(decrypt_secret(row.config_encrypted))
                config.update(secret)
            except Exception as exc:
                log.error(f"Failed to decrypt config for plugin {plugin_id}: {exc}")

    return cls(config=config)


async def test_plugin_connection(db: AsyncSession, plugin_id: str) -> dict:
    """
    Instantiate the plugin with its saved config and call test_connection().
    """
    row = await get_plugin_config_row(db, plugin_id)
    instance = load_plugin_instance(plugin_id, row)
    if not instance:
        return {"ok": False, "message": f"Unknown plugin: {plugin_id}"}
    try:
        return await instance.test_connection()
    except Exception as exc:
        return {"ok": False, "message": str(exc)}
