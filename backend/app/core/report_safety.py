"""Safe handling of the two branding inputs that reach the PDF/HTML report: the accent colour and the logo images.

Both come from a user (saved settings, or straight from the request body of the report endpoint) and the report engine acts on them:
  * the colour is written into the template's CSS (`--accent: {{ brand_color }}`): HTML escaping does not stop CSS injection
    (`red; } body { background: url(http://internal/...) }`), so only a plain hex colour is accepted;
  * a logo URL is fetched BY THE SERVER while the PDF is rendered, with no restrictions (a request-forgery path to internal
    services, and redirects are followed). So the server now fetches logos itself, with the network guard, no unchecked redirects,
    a size limit and an image-type allowlist, and gives the template a self-contained data: URI. The template can then never be
    made to fetch a user-chosen address (it only ever sees a data: URI or nothing).
"""
from __future__ import annotations

import base64
import re
from typing import Awaitable, Callable, Dict, Optional, Tuple
from urllib.parse import urljoin, urlparse

from app.core.netguard import acheck_url, check_url

DEFAULT_ACCENT = "#0ff0fc"
_HEX = re.compile(r"^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})$")
# SVG is deliberately excluded: it can carry external references and scripts, and the PDF engine would act on them.
ALLOWED_IMAGE_TYPES = ("image/png", "image/jpeg", "image/gif", "image/webp")
MAX_LOGO_BYTES = 500_000
MAX_REDIRECTS = 3
_DATA_IMAGE = re.compile(r"^data:(image/(?:png|jpeg|gif|webp));base64,[A-Za-z0-9+/=\s]+$")


def safe_color(value: object, default: str = DEFAULT_ACCENT) -> str:
    """A plain #rgb / #rrggbb colour, nothing else (the value is placed inside CSS)."""
    v = str(value or "").strip()
    return v if _HEX.match(v) else default


def only_data_image(value: object) -> str:
    """The template may only ever receive a small self-contained image (a data: URI built by embed_logos), or nothing."""
    v = str(value or "").strip()
    return v if (len(v) <= MAX_LOGO_BYTES * 2 and _DATA_IMAGE.match(v)) else ""


def validate_logo_url_for_save(value: object) -> Optional[str]:
    """Message to show when a logo URL cannot be accepted (None = fine, including empty). Used when settings are saved."""
    v = str(value or "").strip()
    if not v:
        return None
    if v.startswith("data:"):
        return None if only_data_image(v) else "A data: logo must be a base64 PNG, JPEG, GIF or WebP image under 500 KB."
    p = urlparse(v)
    if p.scheme not in ("http", "https") or not p.hostname:
        return "A logo must be an http(s) address (or a small base64 image)."
    try:
        check_url(v, allow_private=False)
    except ValueError as e:
        return f"That logo address is not allowed: {e}"
    return None


# one HTTP GET WITHOUT following redirects: (status, headers (lower-case keys), body bytes, or None when it exceeded the limit)
GetFn = Callable[[str], Awaitable[Tuple[int, Dict[str, str], Optional[bytes]]]]


async def _httpx_get(url: str) -> Tuple[int, Dict[str, str], Optional[bytes]]:
    import httpx
    async with httpx.AsyncClient(timeout=8.0, follow_redirects=False) as client:
        async with client.stream("GET", url) as r:
            body = b""
            async for chunk in r.aiter_bytes():
                body += chunk
                if len(body) > MAX_LOGO_BYTES:
                    return r.status_code, {k.lower(): v for k, v in r.headers.items()}, None
            return r.status_code, {k.lower(): v for k, v in r.headers.items()}, body


async def fetch_image_data_uri(url: str, get: Optional[GetFn] = None, check: Optional[Callable[[str], Awaitable[None]]] = None) -> str:
    """Fetch a logo safely and return it as a data: URI, or "" if anything is wrong. Every hop (including each redirect) is checked
    against the network guard, so a public address cannot bounce the server to an internal one."""
    get = get or _httpx_get
    check = check or (lambda u: acheck_url(u, allow_private=False))
    cur = url.strip()
    for _ in range(MAX_REDIRECTS + 1):
        p = urlparse(cur)
        if p.scheme not in ("http", "https") or not p.hostname:
            return ""
        try:
            await check(cur)
            status, headers, body = await get(cur)
        except Exception:                                     # noqa: BLE001 — a bad logo must never break report generation
            return ""
        if status in (301, 302, 303, 307, 308) and headers.get("location"):
            cur = urljoin(cur, headers["location"])
            continue
        ctype = headers.get("content-type", "").split(";")[0].strip().lower()
        if status != 200 or body is None or not body or ctype not in ALLOWED_IMAGE_TYPES:
            return ""
        return f"data:{ctype};base64,{base64.b64encode(body).decode()}"
    return ""


async def embed_logos(branding: dict, get: Optional[GetFn] = None, check: Optional[Callable[[str], Awaitable[None]]] = None) -> dict:
    """Return a copy of `branding` that is safe to render: a plain hex colour, and logos as data: URIs (or empty)."""
    out = dict(branding or {})
    out["brand_color"] = safe_color(out.get("brand_color"))
    for key in ("brand_logo_url", "customer_logo_url"):
        v = str(out.get(key) or "").strip()
        if not v:
            out[key] = ""
        elif v.startswith("data:"):
            out[key] = only_data_image(v)
        else:
            out[key] = await fetch_image_data_uri(v, get=get, check=check)
    return out
