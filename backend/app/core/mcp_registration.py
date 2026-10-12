"""Validation for registering an MCP server through the API (pure, unit-testable).

A `stdio` MCP server is an arbitrary command the backend spawns, so letting an API
caller register one is remote code execution inside the backend container (which holds
the DB credentials and encryption key). It is therefore OFF unless MCP_ALLOW_STDIO_SERVERS
is explicitly enabled. HTTP servers are allowed on private networks (the built-in tool
servers live on the Docker network) but never loopback / link-local / cloud metadata.
"""
from __future__ import annotations

import re

from app.core.netguard import check_url

_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


class RegistrationError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status, self.message = status, message


def validate_registration(data: dict, *, allow_stdio: bool, existing: set) -> dict:
    if not isinstance(data, dict):
        raise RegistrationError(400, "Request body must be a JSON object")
    name = data.get("name")
    # Must be a real string: str(None) == "None" would otherwise pass the pattern below.
    if not isinstance(name, str) or not _NAME_RE.match(name.strip()):
        raise RegistrationError(400, "name must be 1-64 chars: letters, digits, '.', '_' or '-'")
    name = name.strip()
    if name in existing:
        # Overwriting a built-in server would let a caller redirect all of its tool traffic.
        raise RegistrationError(409, f"A server named '{name}' already exists")
    transport = str(data.get("transport", "http")).lower()
    if transport not in ("http", "sse", "stdio"):
        raise RegistrationError(400, "transport must be 'http', 'sse' or 'stdio'")

    if transport == "stdio":
        if not allow_stdio:
            raise RegistrationError(403, "stdio MCP servers execute arbitrary commands and are disabled. "
                                         "Set MCP_ALLOW_STDIO_SERVERS=true only if you accept that risk.")
        cmd = data.get("command")
        if not (isinstance(cmd, list) and cmd and all(isinstance(c, str) and c for c in cmd)):
            raise RegistrationError(400, "command must be a non-empty list of strings")
        return {"name": name, "transport": "stdio", "command": cmd, "url": None}

    url = data.get("url")
    if not isinstance(url, str) or not url:
        raise RegistrationError(400, "url is required for http/sse servers")
    try:
        check_url(url, allow_private=True)
    except ValueError as exc:
        raise RegistrationError(400, f"Invalid MCP server URL: {exc}")
    return {"name": name, "transport": transport, "command": None, "url": url}
