"""Real client IP behind the nginx front door.

nginx terminates the connection, so request.client.host is nginx's container IP.
Rate limiting keyed on that gave ALL users one shared bucket (login 30/min for the
whole platform, MFA 5/min total) and audit logs recorded nginx's address.

nginx ALWAYS overwrites X-Real-IP with $remote_addr on every proxied location, so a
client cannot spoof it through nginx. We deliberately do NOT trust X-Forwarded-For:
nginx appends to a client-supplied value, so its left-most entry is attacker-controlled.
"""
from __future__ import annotations

import ipaddress


def get_client_ip(request) -> str:
    raw = (request.headers.get("x-real-ip") or "").strip()
    if raw:
        try:
            return str(ipaddress.ip_address(raw))
        except ValueError:
            pass                      # garbage header -> fall back to the socket peer
    client = getattr(request, "client", None)
    return client.host if client and client.host else "unknown"
