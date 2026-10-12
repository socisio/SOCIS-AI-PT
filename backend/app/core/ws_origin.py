"""WebSocket Origin check (defence against cross-site WebSocket hijacking).

Browsers attach cookies to WebSocket handshakes and the handshake is exempt from CORS,
and our HTTP CSRF guard (X-Requested-With) cannot apply to it. Without an Origin check,
a page on another origin that shares the cookie scope (sibling subdomain, another port on
the same host, an older browser without SameSite=Lax) could drive a victim's authenticated
socket — including the Metasploit terminal.

Rules: no Origin header -> allowed (non-browser client; it cannot ride ambient cookies).
Origin must match the Host the request arrived on (same-origin SPA behind nginx) or be in
the configured allow-list. Origin "null" (sandboxed iframes, file://) is rejected.
"""
from __future__ import annotations

from urllib.parse import urlparse


def _hostname(value: str) -> str:
    return (urlparse(value).hostname or "").lower()


def origin_allowed(origin: str | None, host: str | None, allowed: list[str] | None) -> bool:
    if not origin:
        return True
    origin = origin.strip()
    if origin.lower() == "null":
        return False
    o_host = _hostname(origin)
    if not o_host:
        return False
    # Same origin as the Host this request arrived on (port ignored: nginx forwards $host).
    # urlparse("//host:port") understands plain names, IPv4 and bracketed IPv6.
    h_name = (urlparse("//" + host.strip()).hostname or "").lower() if host else ""
    if h_name and o_host == h_name:
        return True
    for a in allowed or []:
        if origin.rstrip("/").lower() == str(a).rstrip("/").lower():
            return True
    return False
