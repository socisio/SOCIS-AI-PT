"""Authorized-target scope: parsing entries and matching targets (pure: no database, no network, unit-tested).

An allowlist entry is one of:
    10.1.2.3                 a single address (IPv4 or IPv6)
    10.1.2.0/24              a network (prefix must be /8 or longer for IPv4, /32 or longer for IPv6: a typo like /0 or /4 would
                             authorize half the internet)
    10.1.2.10-10.1.2.50      an address range (also 10.1.2.10-50)
    app.example.com          exactly that host name (NOT its subdomains)
    *.example.com            any subdomain of example.com (NOT example.com itself: list both when you mean both)
A URL is accepted and reduced to its host (https://app.example.com:8443/admin -> app.example.com).

Matching is deliberately strict so nothing is allowed by accident:
  * a domain target is matched only against domain entries and an address target only against address entries (names are never
    resolved: DNS can change after approval, and it would let a name outside the contract reach an address inside it);
  * a network/range target must be fully inside ONE entry;
  * odd spellings of an address (decimal 2130706433, leading zeros 010.0.0.1) are rejected, not interpreted;
  * internationalized names are compared in their punycode form.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import re
from dataclasses import dataclass
from typing import Any, Iterable, List, Optional, Tuple
from urllib.parse import urlparse

MAX_ENTRIES = 500
MIN_V4_PREFIX = 8
MIN_V6_PREFIX = 32
MAX_ENTRY_LEN = 300

# argument names that carry a network target in tool calls (matched case-insensitively, at any depth up to 3)
TARGET_KEYS = frozenset({
    "target", "targets", "host", "hosts", "hostname", "hostnames", "domain", "domains", "url", "urls", "ip", "ips",
    "address", "addresses", "rhost", "rhosts", "remote_host", "target_host", "base_url", "site", "scan_target",
    "cidr", "cidrs", "subnet", "subnets", "network", "range", "ip_range",
})


class ScopeError(ValueError):
    """An entry or target that cannot be understood (the message is shown to the user)."""


@dataclass(frozen=True)
class Entry:
    kind: str                 # ip | cidr | range | domain | wildcard
    text: str                 # normalised form that is stored and shown
    version: int = 0          # 4 / 6 for address-based kinds
    lo: int = 0
    hi: int = 0
    host: str = ""            # domain: the name; wildcard: the base name (example.com for *.example.com)

    @property
    def is_address(self) -> bool:
        return self.kind in ("ip", "cidr", "range")


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    matched: Optional[str] = None
    target: str = ""


_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_RANGE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})\s*-\s*(\d{1,3}(?:\.\d{1,3}){3}|\d{1,3})$")


def _ip(text: str):
    """ipaddress.ip_address with IPv4-mapped IPv6 unwrapped; None when it is not an address."""
    try:
        a = ipaddress.ip_address(text)
    except ValueError:
        return None
    if isinstance(a, ipaddress.IPv6Address) and a.ipv4_mapped is not None:
        return a.ipv4_mapped
    return a


def _host(text: str) -> str:
    h = text.strip().strip(".").lower()
    if not h:
        raise ScopeError("empty host name")
    try:
        h = h.encode("idna").decode("ascii")
    except UnicodeError:
        raise ScopeError(f"'{text}' is not a valid host name")
    return h.lower()


def _valid_domain(h: str) -> bool:
    if not h or len(h) > 253:
        return False
    labels = h.split(".")
    if not all(_LABEL.match(l) for l in labels):
        return False
    if all(l.isdigit() for l in labels) or labels[-1].isdigit():   # 010.0.0.1, 2130706433, 1.2.3.4.5: number tricks, not names
        return False
    return True


def _iv(version: int, lo: int, hi: int, text: str, kind: str) -> Entry:
    return Entry(kind=kind, text=text, version=version, lo=lo, hi=hi)


def _parse(raw_in: str, *, as_entry: bool) -> Entry:
    raw = raw_in.split("#", 1)[0].strip()
    if not raw:
        raise ScopeError("empty entry")
    if len(raw) > MAX_ENTRY_LEN:
        raise ScopeError("too long")
    if raw.startswith("*") and not raw.startswith("*."):
        raise ScopeError("a wildcard must look like *.example.com")
    core = raw
    if "://" in core:
        h = urlparse(core).hostname
        if not h:
            raise ScopeError("no host name in this URL")
        core = h
    # network: 10.0.0.0/24
    if "/" in core:
        left, _, right = core.partition("/")
        left = left.strip().strip("[]")
        if right.strip().isdigit() and _ip(left) is not None:
            try:
                net = ipaddress.ip_network(f"{left}/{int(right)}", strict=False)
            except ValueError:
                raise ScopeError("not a valid network")
            if isinstance(net, ipaddress.IPv6Network) and net.network_address.ipv4_mapped is not None:
                raise ScopeError("write IPv4 networks as IPv4")
            if as_entry:
                minp = MIN_V4_PREFIX if net.version == 4 else MIN_V6_PREFIX
                if net.prefixlen < minp:
                    raise ScopeError(f"too broad: the shortest allowed prefix is /{minp} (this would authorize {net.num_addresses:,} addresses)")
            return _iv(net.version, int(net.network_address), int(net.broadcast_address), str(net), "cidr" if net.num_addresses > 1 else "ip")
        core = left                                                  # example.com/admin -> example.com
    core = core.strip()
    # range: 10.0.0.1-10.0.0.9 or 10.0.0.1-9
    m = _RANGE.match(core)
    if m:
        a = _ip(m.group(1))
        if not isinstance(a, ipaddress.IPv4Address):
            raise ScopeError("not a valid address range")
        if "." in m.group(2):
            b = _ip(m.group(2))
        else:
            last = int(m.group(2))
            if last > 255:
                raise ScopeError("not a valid address range")
            b = _ip(".".join(m.group(1).split(".")[:3] + [str(last)]))
        if not isinstance(b, ipaddress.IPv4Address) or int(b) < int(a):
            raise ScopeError("a range must go from a lower to a higher address")
        if as_entry and int(b) - int(a) + 1 > (1 << (32 - MIN_V4_PREFIX)):
            raise ScopeError("range too broad")
        return _iv(4, int(a), int(b), f"{a}-{b}", "range")
    # [v6]:port, host:port
    if core.startswith("["):
        end = core.find("]")
        if end == -1:
            raise ScopeError("unbalanced [ in address")
        core = core[1:end]
    elif core.count(":") == 1:
        h, _, port = core.partition(":")
        if port.isdigit():
            core = h
    a = _ip(core)
    if a is not None:
        return _iv(a.version, int(a), int(a), str(a), "ip")
    if core.startswith("*."):
        if not as_entry:
            raise ScopeError("a target cannot be a wildcard")
        base = _host(core[2:])
        if "." not in base or not _valid_domain(base):
            raise ScopeError("a wildcard needs a real domain with at least two labels, like *.example.com")
        return Entry(kind="wildcard", text=f"*.{base}", host=base)
    if ":" in core:
        raise ScopeError("not a valid address or host name")
    h = _host(core)
    if not _valid_domain(h):
        raise ScopeError("not a valid IP address, network, range or host name")
    return Entry(kind="domain", text=h, host=h)


def parse_entry(text: str) -> Entry:
    """Parse one allowlist entry (raises ScopeError with a readable reason)."""
    return _parse(text, as_entry=True)


def parse_target(text: str) -> Entry:
    """Parse a scan / tool target with the same grammar (no breadth limits, no wildcards)."""
    return _parse(text, as_entry=False)


def normalize_entries(values: Iterable[str]) -> List[str]:
    """Validate, normalise and de-duplicate (order kept). Raises ScopeError listing EVERY bad line so the user fixes them at once."""
    out: List[str] = []
    problems: List[str] = []
    vals = [v for v in (values or []) if str(v).split("#", 1)[0].strip()]
    if len(vals) > MAX_ENTRIES:
        raise ScopeError(f"too many entries ({len(vals)}); the limit is {MAX_ENTRIES}")
    for i, v in enumerate(vals, 1):
        try:
            t = parse_entry(str(v)).text
        except ScopeError as e:
            problems.append(f"Entry {i} ({str(v).strip()[:60]!r}): {e}")
            continue
        if t not in out:
            out.append(t)
    if problems:
        raise ScopeError("\n".join(problems))
    return out


def parse_scope_text(text: Optional[str]) -> Tuple[List[str], List[str]]:
    """Free text (one entry per line, or separated by commas/semicolons) -> (valid normalised entries, lines that could not be read).
    Used to turn an analyst's requested scope into a suggestion the administrator can approve."""
    good: List[str] = []
    bad: List[str] = []
    for chunk in re.split(r"[\n,;]+", text or ""):
        c = chunk.split("#", 1)[0].strip()
        if not c:
            continue
        try:
            t = parse_entry(c).text
        except ScopeError:
            bad.append(c[:80])
            continue
        if t not in good:
            good.append(t)
    return good, bad


def decide(target: str, entries: Iterable[Entry]) -> Decision:
    """Is `target` inside the authorized entries?"""
    try:
        t = parse_target(target)
    except ScopeError as e:
        return Decision(False, f"'{str(target).strip()[:80]}' is not a valid target ({e})", None, str(target))
    for e in entries:
        if t.is_address and e.is_address:
            if t.version == e.version and e.lo <= t.lo and t.hi <= e.hi:
                return Decision(True, f"inside {e.text}", e.text, t.text)
        elif not t.is_address and not e.is_address:
            if e.kind == "domain" and t.host == e.host:
                return Decision(True, f"matches {e.text}", e.text, t.text)
            if e.kind == "wildcard" and t.host.endswith("." + e.host) and t.host != e.host:
                return Decision(True, f"matches {e.text}", e.text, t.text)
    return Decision(False, f"{t.text} is not in the authorized scope", None, t.text)


def build_entries(texts: Iterable[str]) -> List[Entry]:
    """Parse stored entries, skipping any that no longer parse (never raises)."""
    out: List[Entry] = []
    for s in texts or []:
        try:
            out.append(parse_entry(str(s)))
        except ScopeError:
            continue
    return out


def extract_targets(arguments: Any, _depth: int = 0) -> List[str]:
    """Pull network targets out of a tool call's arguments: values of known target keys (top level or nested up to 3 deep, any case),
    split on commas / semicolons / whitespace. Tools with no such argument (CVE, EPSS, KEV lookups) yield nothing."""
    found: List[str] = []
    if _depth > 3 or not isinstance(arguments, dict):
        return found
    for k, v in arguments.items():
        key = str(k).strip().lower()
        if key in TARGET_KEYS:
            vals = v if isinstance(v, (list, tuple, set)) else [v]
            for item in vals:
                if isinstance(item, str):
                    for tok in re.split(r"[,;\s]+", item.strip()):
                        if tok:
                            found.append(tok)
        elif isinstance(v, dict):
            found.extend(extract_targets(v, _depth + 1))
        elif isinstance(v, (list, tuple)):
            for item in v:
                if isinstance(item, dict):
                    found.extend(extract_targets(item, _depth + 1))
    seen: List[str] = []
    for t in found:
        if t not in seen:
            seen.append(t)
    return seen


def sign_override(secret: str, scan_id: str, target: str, admin_id: str, reason: str) -> dict:
    """An administrator override is stored on the scan with an HMAC over (scan, target, admin, reason). The worker honours it only if
    the signature verifies, so nobody can forge one by putting a key into tool_config."""
    msg = f"{scan_id}|{target}|{admin_id}|{reason}".encode()
    return {"by": admin_id, "reason": reason, "sig": hmac.new(secret.encode(), msg, hashlib.sha256).hexdigest()}


def verify_override(secret: str, scan_id: str, target: str, marker: object) -> bool:
    if not isinstance(marker, dict):
        return False
    try:
        want = sign_override(secret, scan_id, target, str(marker.get("by", "")), str(marker.get("reason", "")))["sig"]
        return hmac.compare_digest(want, str(marker.get("sig", "")))
    except Exception:  # noqa: BLE001
        return False
