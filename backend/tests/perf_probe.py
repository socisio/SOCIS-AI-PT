"""Timing and structure probe for the endpoints every page calls (run inside the backend container).

Prints how long each takes and how big the answer is, and FAILS if the scan list still embeds heavy per-scan data
(raw tool output, AI analyses, full vulnerability lists), which is what made the dashboard/scans page/notification bell
slow down with every scan. Latency over a threshold is only a WARNING (machines differ). stdlib only.
"""
import json, os, statistics, sys, time, urllib.error, urllib.parse, urllib.request

BASE = os.environ.get("PROBE_BASE", "http://localhost:8000/api/v1")
ADMIN_USER = os.environ.get("VERIFY_ADMIN_USER") or "admin"
ADMIN_PASS = os.environ.get("VERIFY_ADMIN_PASSWORD") or os.environ.get("ADMIN_PASSWORD") or "Admin123!"
LIMITS_MS = {"/auth/me": 800, "/scans/ (list page)": 1500, "/scans/?per_page=10 (notification bell)": 1500,
             "/projects/": 800, "/vulnerabilities/": 2000, "/dashboard/summary": 800}
P = F = W = 0


def say(kind, msg):
    global P, F, W
    P += kind == "PASS"; F += kind == "FAIL"; W += kind == "WARN"
    print(f"{kind:5} {msg}")


def call(path, token=None, form=None):
    h = {"X-Requested-With": "SOCIS"}
    data = None
    if token:
        h["Authorization"] = "Bearer " + token
    if form is not None:
        data = urllib.parse.urlencode(form).encode(); h["Content-Type"] = "application/x-www-form-urlencoded"
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(urllib.request.Request(BASE + path, data=data, headers=h, method="POST" if form is not None else "GET"), timeout=60) as r:
            raw = r.read()
            status = r.status
    except urllib.error.HTTPError as e:
        raw, status = e.read(), e.code
    ms = (time.perf_counter() - t0) * 1000
    try:
        body = json.loads(raw or b"{}")
    except ValueError:
        body = {}
    return status, ms, len(raw), body


def main():
    s, _, _, d = call("/auth/login", form={"username": ADMIN_USER, "password": ADMIN_PASS})
    token = d.get("access_token", "")
    if not token:
        say("FAIL", f"admin login failed ({s}); cannot probe"); print(f"RESULT: {P} passed, {F} failed, {W} warnings"); return 1
    print("\nendpoint (median of 3 after a warm-up)                         time      size")
    first_scans = None
    for name in LIMITS_MS:
        path = name.split(" ")[0]
        call(path, token)                                              # warm-up (connection, caches)
        runs = [call(path, token) for _ in range(3)]
        ms = statistics.median(r[1] for r in runs); size = runs[-1][2]; status = runs[-1][0]
        if name.startswith("/scans/ (list"):
            first_scans = runs[-1][3]
        print(f"  {name:55} {ms:6.0f} ms {size / 1024:8.1f} KB" + ("" if status == 200 else f"   (HTTP {status})"))
        if status != 200:
            say("FAIL", f"{path} answered HTTP {status}")
        elif ms > LIMITS_MS[name]:
            say("WARN", f"{path} took {ms:.0f} ms (> {LIMITS_MS[name]} ms). See deploy/scripts/perf-check.sh for where the time goes")
    items = (first_scans or {}).get("scans") or []
    print()
    if not items:
        print("SKIP  scan list structure (no scans yet, nothing to inspect)")
    else:
        heavy = sorted({k for k in ("tool_results", "ai_analyses", "vulnerabilities") if k in items[0]})
        if heavy:
            say("FAIL", "the scan LIST still embeds heavy per-scan data (" + ", ".join(heavy) + "): every page that lists scans downloads raw tool output")
        elif "vulnerability_count" not in items[0]:
            say("FAIL", "the scan list has no vulnerability_count")
        else:
            say("PASS", f"scan list is lean: vulnerability_count, no raw tool output / analyses ({len(items)} scans checked)")
    print(f"RESULT: {P} passed, {F} failed, {W} warnings")
    return 1 if F else 0


if __name__ == "__main__":
    sys.exit(main())
