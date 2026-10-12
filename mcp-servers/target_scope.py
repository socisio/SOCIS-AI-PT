"""Is this target something an EXTERNAL service can meaningfully be asked about? (pure: unit-tested, no network by default)

SSL Labs (a public web service) can only assess public host names. Before this check the SSL tool sent EVERY target to it: an internal address or
name was disclosed to a third party for nothing, the call could never succeed, and the tool then polled for 90 seconds before returning an error
that the report counted as a successful run. WHOIS has the same problem for private addresses (it returns the IANA special-use record).
"""
from __future__ import annotations

import ipaddress
import socket
from typing import Callable, List, Optional

# names that are only meaningful inside a network (RFC 2606 / 6761 reserved names and the common internal suffixes)
INTERNAL_SUFFIXES = (".local", ".lan", ".internal", ".corp", ".home", ".localdomain", ".intranet", ".private", ".test", ".invalid", ".localhost", ".example")


def _ip(host: str):
    try:
        return ipaddress.ip_address(host.strip().strip("[]"))
    except ValueError:
        return None


def _ip_is_public(ip) -> bool:
    return ip.is_global and not (ip.is_multicast or ip.is_reserved)


def _default_resolve(host: str) -> List[str]:
    try:
        return [i[4][0] for i in socket.getaddrinfo(host, None)]
    except OSError:
        return []


def non_public_reason(host: str, resolve: Optional[Callable[[str], List[str]]] = None) -> Optional[str]:
    """A reason when `host` is not a public target, else None. Resolution only decides names that look public but resolve inside a network."""
    h = (host or "").strip().lower().rstrip(".")
    if not h:
        return "no host was given"
    ip = _ip(h)
    if ip is not None:
        return None if _ip_is_public(ip) else f"{h} is a private, loopback or reserved address"
    if h == "localhost" or h.endswith(INTERNAL_SUFFIXES):
        return f"{h} is an internal host name"
    if "." not in h:
        return f"{h} is a single-label (internal) host name"
    addrs = (resolve or _default_resolve)(h)
    parsed = [a for a in (_ip(x) for x in addrs) if a is not None]
    if parsed and not any(_ip_is_public(a) for a in parsed):
        return f"{h} resolves only to private or reserved addresses ({', '.join(str(a) for a in parsed[:3])})"
    return None


def ssl_labs_skip_reason(host: str, resolve: Optional[Callable[[str], List[str]]] = None) -> Optional[str]:
    """None when SSL Labs may be asked; otherwise why it must not be (and nothing is sent to it)."""
    h = (host or "").strip().strip("[]")
    if _ip(h) is not None:
        return "SSL Labs assesses public host names, not IP addresses"
    why = non_public_reason(h, resolve)
    return f"{why}; SSL Labs can only assess public host names" if why else None


def whois_skip_reason(host: str) -> Optional[str]:
    """WHOIS has nothing useful for private addresses or internal names (no DNS lookup here: whois is not told about the target by name)."""
    h = (host or "").strip().lower().rstrip(".")
    ip = _ip(h)
    if ip is not None:
        return None if _ip_is_public(ip) else f"{h} is a private, loopback or reserved address: there is no public registration record"
    if h == "localhost" or h.endswith(INTERNAL_SUFFIXES) or ("." not in h and h):
        return f"{h} is an internal host name: there is no public registration record"
    return None
