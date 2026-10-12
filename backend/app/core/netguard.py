"""Outbound-request guard (SSRF defence) shared by webhooks, MCP registration, etc.

Why not a hand-written list of networks: those miss cases (0.0.0.0, ::, IPv4-mapped
IPv6 such as ::ffff:169.254.169.254, fe80::/10, fc00::/7, 100.64.0.0/10) and are easy
to get subtly wrong. We classify each resolved address with the stdlib flags instead,
unwrap IPv4-mapped IPv6 first, and check EVERY address the name resolves to (a name
with several A/AAAA records must not pass on its first record alone).
"""
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

# Cloud metadata endpoints that must never be reachable, even when private ranges
# are allowed (some are ULA/CGNAT addresses that "is_private" would let through).
_METADATA = {
    ipaddress.ip_address("169.254.169.254"),
    ipaddress.ip_address("100.100.100.200"),   # Alibaba Cloud
    ipaddress.ip_address("192.0.0.192"),       # Oracle Cloud
    ipaddress.ip_address("fd00:ec2::254"),     # AWS IMDS over IPv6
}


def _unwrap(ip):
    mapped = getattr(ip, "ipv4_mapped", None)
    return mapped if mapped is not None else ip


def is_blocked_ip(ip, allow_private: bool = False) -> bool:
    """True if `ip` must not be contacted.

    Always blocked: loopback, link-local, unspecified, multicast, reserved, metadata.
    allow_private=False additionally blocks everything that is not globally routable
    (RFC1918, ULA, CGNAT, documentation ranges, ...).
    """
    ip = _unwrap(ip)
    if ip in _METADATA:
        return True
    if ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast or ip.is_reserved:
        return True
    return False if allow_private else (not ip.is_global)


def resolve_all(hostname: str) -> list:
    try:
        infos = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except Exception:
        raise ValueError(f"Unable to resolve hostname: {hostname}")
    addrs = []
    for info in infos:
        try:
            addrs.append(ipaddress.ip_address(info[4][0].split("%")[0]))
        except ValueError:
            continue
    if not addrs:
        raise ValueError(f"Unable to resolve hostname: {hostname}")
    return addrs


def check_url(url: str, allow_private: bool = False, resolve: bool = True) -> None:
    """Raise ValueError unless `url` is an http(s) URL whose EVERY resolved address is allowed."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("URL must use http or https")
    if parsed.username or parsed.password:
        raise ValueError("URL must not contain credentials")
    host = parsed.hostname
    if not host:
        raise ValueError("URL has no hostname")
    try:
        addrs = [ipaddress.ip_address(host)]            # IP literal — no DNS needed
    except ValueError:
        if not resolve:
            return
        addrs = resolve_all(host)
    for ip in addrs:
        if is_blocked_ip(ip, allow_private):
            raise ValueError(f"URL resolves to a blocked address: {ip}")


async def acheck_url(url: str, allow_private: bool = False) -> None:
    """check_url without blocking the event loop (DNS resolution runs in a worker thread)."""
    import asyncio
    await asyncio.to_thread(check_url, url, allow_private)
