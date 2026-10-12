"""
SOCIS-AI-PT — Tool Plugin Loader

Any .py file placed in PLUGINS_DIR runs with the FULL privileges of the backend/worker process the moment it is loaded
(class bodies aside, the module's top-level code executes immediately via exec_module — this is standard Python import
behaviour, not a bug, but it means this directory must be trusted exactly like the application's own source code).

Today the only way a file gets there is direct access to the `plugins_data` volume (shared by the backend, worker, and
worker-scale services only — the frontend and nginx containers do not mount it), which already implies host- or
container-level access equivalent to the application's own trust level. There is no HTTP upload path into this directory.
This module still hardens what it reasonably can: it will not follow a symlink out of the directory, it records what it
loaded (file name, size, sha256, mtime) so an administrator or incident responder can tell whether something changed, and
every load is written to the application log with enough detail to investigate later. See core/audit.py / the /admin/plugins
endpoints for how this is surfaced and audited.
"""

import hashlib
import importlib.util
import inspect
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Type

from app.services.tools.base import BaseSecurityTool

log = logging.getLogger(__name__)

PLUGINS_DIR = Path(os.getenv("PLUGINS_DIR", "/app/plugins"))


class PluginLoader:
    def __init__(self):
        self.plugins: Dict[str, Type[BaseSecurityTool]] = {}
        self.manifest: List[Dict[str, Any]] = []        # what was actually loaded last time, for visibility/audit

    def load_plugins(self) -> Dict[str, Type[BaseSecurityTool]]:
        """Scan the plugins directory and load every class inheriting from BaseSecurityTool. Returns {plugin_id: class}."""
        self.plugins = {}
        self.manifest = []
        if not PLUGINS_DIR.exists():
            log.info("Plugins directory %s does not exist, skipping.", PLUGINS_DIR)
            return self.plugins

        plugins_dir_resolved = PLUGINS_DIR.resolve()
        for filepath in sorted(PLUGINS_DIR.glob("*.py")):
            if filepath.name.startswith("_"):
                continue
            # A symlink could point outside the directory this feature is meant to trust (e.g. at host files reachable
            # through another mount). Only load a plain, in-directory file.
            if filepath.is_symlink():
                log.error("Refusing to load plugin %s: it is a symlink, not a regular file.", filepath.name)
                continue
            try:
                resolved = filepath.resolve()
                resolved.relative_to(plugins_dir_resolved)
            except (OSError, ValueError):
                log.error("Refusing to load plugin %s: it resolves outside the plugins directory.", filepath.name)
                continue

            try:
                raw = filepath.read_bytes()
            except OSError as e:
                log.error("Could not read plugin file %s: %s", filepath.name, e)
                continue
            digest = hashlib.sha256(raw).hexdigest()
            entry = {
                "file": filepath.name, "sha256": digest, "size": len(raw),
                "mtime": datetime.fromtimestamp(filepath.stat().st_mtime, tz=timezone.utc).isoformat(),
                "loaded_at": datetime.now(timezone.utc).isoformat(), "plugin_ids": [], "error": None,
            }

            module_name = f"app.plugins.{filepath.stem}"
            try:
                spec = importlib.util.spec_from_file_location(module_name, filepath)
                if not spec or not spec.loader:
                    entry["error"] = "could not build an import spec for this file"
                    self.manifest.append(entry)
                    continue

                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)

                # Inspect the module for classes that inherit from BaseSecurityTool (but not the base class itself).
                for name, obj in inspect.getmembers(module, inspect.isclass):
                    if issubclass(obj, BaseSecurityTool) and obj is not BaseSecurityTool:
                        plugin_id = getattr(obj, "id", None) or name.lower()
                        self.plugins[plugin_id] = obj
                        entry["plugin_ids"].append(plugin_id)
                        log.info("Loaded custom tool plugin: %s (from %s, sha256=%s)", plugin_id, filepath.name, digest[:12])

            except Exception as e:  # noqa: BLE001 — a broken/malicious plugin must not take the whole load down
                entry["error"] = str(e)
                log.error("Failed to load plugin %s (sha256=%s): %s", filepath.name, digest[:12], e)
            self.manifest.append(entry)

        return self.plugins


plugin_manager = PluginLoader()
