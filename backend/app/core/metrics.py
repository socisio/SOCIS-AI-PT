"""
Prometheus metrics for SOCIS-AI-PT (observability #9).

Exposes /metrics (Prometheus text format) and defines the custom metrics the
Grafana dashboards read: HTTP request rate/latency/status, scan queue depth and
durations, active AI-chat sessions, and LLM request latency/provider status.

Generic infra metrics (CPU, RAM, Postgres, Redis) come from the node/postgres/
redis exporters, not from here — this module is only the app-specific signals.

Safe to import even if prometheus_client isn't installed: it degrades to no-ops
so the app never fails to boot over a missing optional dependency.
"""
from __future__ import annotations

import logging

log = logging.getLogger(__name__)

try:
    from prometheus_client import (
        Counter, Gauge, Histogram, CONTENT_TYPE_LATEST, generate_latest,
    )
    _ENABLED = True
except Exception:  # pragma: no cover - optional dependency
    _ENABLED = False
    CONTENT_TYPE_LATEST = "text/plain"

    class _Noop:
        def labels(self, *a, **k): return self
        def inc(self, *a, **k): pass
        def dec(self, *a, **k): pass
        def set(self, *a, **k): pass
        def observe(self, *a, **k): pass

    def Counter(*a, **k): return _Noop()      # type: ignore
    def Gauge(*a, **k): return _Noop()        # type: ignore
    def Histogram(*a, **k): return _Noop()    # type: ignore
    def generate_latest(*a, **k): return b""  # type: ignore


# ─── HTTP (dashboard 1) ──────────────────────────────────────
HTTP_REQUESTS = Counter(
    "socis_http_requests_total", "Total HTTP requests",
    ["method", "path", "status"],
)
HTTP_LATENCY = Histogram(
    "socis_http_request_duration_seconds", "HTTP request latency",
    ["method", "path"],
    buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10),
)

# ─── Scans & workers (dashboard 2) ───────────────────────────
SCAN_QUEUE_DEPTH = Gauge("socis_scan_queue_depth", "Pending scans in the queue")
SCANS_IN_PROGRESS = Gauge("socis_scans_in_progress", "Scans currently running")
SCANS_TOTAL = Counter("socis_scans_total", "Scans finished", ["result"])
SCAN_DURATION = Histogram(
    "socis_scan_duration_seconds", "Scan duration",
    buckets=(10, 30, 60, 120, 300, 600, 1200, 1800, 3600),
)

# ─── AI chat & LLM (dashboard 4) ─────────────────────────────
CHAT_SESSIONS_ACTIVE = Gauge("socis_chat_sessions_active", "Active AI chat sessions")
LLM_REQUESTS = Counter("socis_llm_requests_total", "LLM requests", ["provider"])
LLM_LATENCY = Histogram(
    "socis_llm_request_duration_seconds", "LLM response latency",
    buckets=(0.25, 0.5, 1, 2, 4, 8, 15, 30, 60),
)
LLM_PROVIDER_UP = Gauge(
    "socis_llm_provider_up", "LLM provider reachable (1/0)", ["provider"],
)


def metrics_response():
    """Return (body, content_type) for the /metrics endpoint."""
    return generate_latest(), CONTENT_TYPE_LATEST


def normalize_path(path: str) -> str:
    """Collapse high-cardinality path segments (UUIDs, numeric ids) so the
    HTTP metrics don't explode into thousands of series."""
    import re
    p = re.sub(
        r"/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        "/:id", path,
    )
    p = re.sub(r"/\d+", "/:id", p)
    return p


def enabled() -> bool:
    return _ENABLED
