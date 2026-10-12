"""Live end-to-end check of the authorized-target scope (run inside the backend container by verify.sh). stdlib only.

An analyst creates a project (scanning is blocked until an administrator authorizes targets), invalid / too-broad entries are
refused, scans and tool calls aimed outside the list are blocked (403), the administrator override needs a written reason and
non-admins cannot use it, a forged override marker is ignored, and everything is audited. Always cleans up after itself.
Nothing is actually scanned except one administrator-override scan of a reserved documentation address, cancelled at once.
"""
import json, os, secrets, sys, time, urllib.error, urllib.parse, urllib.request

BASE = "http://localhost:8000/api/v1"
ADMIN_USER = os.environ.get("VERIFY_ADMIN_USER") or "admin"          # verify.sh passes a temporary admin (the real one may have two-factor on)
ADMIN_PASS = os.environ.get("VERIFY_ADMIN_PASSWORD") or os.environ.get("ADMIN_PASSWORD") or "Admin123!"
OUT, IN_ = "198.51.100.1", "192.0.2.10"          # TEST-NET-2 / TEST-NET-1: reserved for documentation, never routable
P = F = 0


def t(name, ok, extra=""):
    global P, F
    P += bool(ok); F += (not ok)
    print(("PASS  " if ok else "FAIL  ") + name + ((" - " + str(extra)[:300]) if (extra and not ok) else ""))


def call(method, path, token=None, body=None, form=None):
    h = {"X-Requested-With": "SOCIS"}
    data = None
    if token:
        h["Authorization"] = "Bearer " + token
    if form is not None:
        data = urllib.parse.urlencode(form).encode(); h["Content-Type"] = "application/x-www-form-urlencoded"
    elif body is not None:
        data = json.dumps(body).encode(); h["Content-Type"] = "application/json"
    req = urllib.request.Request(BASE + path, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=40) as r:
            raw = r.read().decode() or "{}"
            return r.status, (json.loads(raw) if raw.strip()[:1] in "{[" else {}), r.headers
    except urllib.error.HTTPError as e:
        raw = e.read().decode() or "{}"
        try:
            return e.code, json.loads(raw), e.headers
        except ValueError:
            return e.code, {"detail": raw[:200]}, e.headers


def login(user, pw):
    for _ in range(6):
        s, d, _h = call("POST", "/auth/login", form={"username": user, "password": pw})
        if s != 429:
            return s, d
        time.sleep(15)
    return s, d


def main():
    s, d = login(ADMIN_USER, ADMIN_PASS)
    admin = d.get("access_token", "")
    if not admin:
        print("FAIL  admin login", s, "(HTTP 202 means that account has two-factor on: run this through verify.sh, which uses a temporary admin)" if s == 202 else ""); print("RESULT: 0 passed, 1 failed"); return 1
    made_users, made_projects = [], []
    try:
        sfx = secrets.token_hex(3)
        s, u, _ = call("POST", "/admin/users", admin, {"email": f"verify-scope-{sfx}@socis-verify.com", "username": f"verify_scope_{sfx}", "role": "analyst"})
        made_users.append(u.get("id"))
        s, d = login(u.get("username", ""), u.get("temporary_password", "")); an = d.get("access_token", "")
        t("an analyst can sign in", s == 200 and an, s)

        # ── a new project starts enforced and empty; requested scope is only notes ──
        s, p, _ = call("POST", "/projects/", an, {"name": f"verify scope {sfx}", "scope": "192.0.2.0/24\nsee the statement of work"})
        pid = p.get("id"); made_projects.append(pid)
        t("a new project starts with scope enforcement ON and an EMPTY authorized list", s == 201 and p.get("scope_enforced") is True and p.get("scope_targets") == [], (s, p))
        s, d, _ = call("POST", "/projects/", an, {"name": f"verify scope x {sfx}", "scope_targets": ["10.0.0.0/8"]})
        t("an analyst cannot authorize targets when creating a project (403)", s == 403, (s, d))
        s, d, _ = call("PUT", f"/projects/{pid}/scope", an, {"targets": ["192.0.2.0/24"], "enforced": True})
        t("an analyst cannot change the authorized scope (403)", s == 403, (s, d))
        s, d, h = call("POST", "/scans/", an, {"project_id": pid, "target": IN_})
        t("scanning is blocked until an administrator authorizes the target (403 + error header)", s == 403 and h.get("X-SOCIS-Error") == "target_out_of_scope" and "authorized scope" in str(d.get("detail")), (s, d))
        s, d, _ = call("GET", f"/projects/{pid}/scope", an)
        t("the analyst sees their requested scope as suggestions, and cannot edit", s == 200 and "192.0.2.0/24" in d.get("suggested", []) and d.get("can_edit") is False and d.get("targets") == [], (s, d))

        # ── the administrator authorizes ──
        s, d, _ = call("PUT", f"/projects/{pid}/scope", admin, {"targets": ["0.0.0.0/0", "*.com", "junk here"], "enforced": True})
        t("too-broad and malformed entries are refused, ALL listed at once (422)", s == 422 and all(f"Entry {i}" in str(d.get("detail")) for i in (1, 2, 3)), (s, d))
        s, d, _ = call("PUT", f"/projects/{pid}/scope", admin, {"targets": ["192.0.2.0/24", "*.Scope-Test.example"], "enforced": True})
        t("an administrator sets the authorized scope (entries are normalised)", s == 200 and d.get("targets") == ["192.0.2.0/24", "*.scope-test.example"], (s, d))
        for tgt, want, why in ((IN_, True, "an address inside the network"), (OUT, False, "an address outside it"), ("a.scope-test.example", True, "a subdomain of the wildcard"), ("scope-test.example", False, "the bare domain (wildcard does not include it)")):
            s, d, _ = call("POST", f"/projects/{pid}/scope/check", an, {"target": tgt})
            t(f"check: {why} -> {'allowed' if want else 'blocked'}", s == 200 and d.get("allowed") is want, (s, d))

        # ── blocked paths ──
        s, d, _ = call("POST", "/scans/", an, {"project_id": pid, "target": OUT})
        t("an out-of-scope scan is blocked (403)", s == 403, (s, d))
        s, d, _ = call("POST", "/scans/", an, {"project_id": pid, "target": OUT, "scope_override_reason": "I really need this one please"})
        t("an analyst cannot override, even with a reason (403)", s == 403, (s, d))
        s, d, _ = call("POST", "/scans/", an, {"project_id": pid, "target": OUT, "tool_config": {"scope_override": {"by": "x", "reason": "forged forged forged", "sig": "00"}}})
        t("a forged override marker in the request is ignored (403)", s == 403, (s, d))
        s, bp, _ = call("POST", "/projects/", admin, {"name": f"verify scope admin-owned {sfx}", "scope_targets": [OUT], "scope_enforced": True}); made_projects.append(bp.get("id"))
        s, d, _ = call("POST", "/scans/", an, {"project_id": bp.get("id"), "target": OUT})
        t("an analyst cannot start a scan inside someone else's project (404)", s == 404, (s, d))

        # ── tool calls (nothing reaches a tool server: the guard answers first) ──
        mcp = "/mcp/servers/scope_test_no_such_server/call"
        s, d, _ = call("POST", mcp, an, {"tool": "nmap_scan", "arguments": {"target": OUT}})
        t("an MCP tool call aimed outside the scope is blocked (403)", s == 403 and "authorized scope" in str(d.get("detail")), (s, d))
        s, d, _ = call("POST", mcp, an, {"tool": "run_exploit", "arguments": {"module": "m", "options": {"RHOSTS": OUT}}})
        t("a target nested in the arguments (RHOSTS) is caught too (403)", s == 403, (s, d))
        s, d, _ = call("POST", mcp, an, {"tool": "nmap_scan", "arguments": {"target": IN_}})
        t("an in-scope target passes the guard (404 only because that test server does not exist)", s == 404, (s, d))
        s, d, _ = call("POST", mcp, an, {"tool": "lookup_cve", "arguments": {"cve_id": "CVE-2024-3094"}})
        t("a lookup with no target is never gated", s == 404, (s, d))

        # ── administrator override ──
        s, d, _ = call("POST", "/scans/", admin, {"project_id": pid, "target": "198.51.100.77", "scope_override_reason": "short"})
        t("an override with a too-short reason is refused (400)", s == 400, (s, d))
        s, d, h = call("POST", "/scans/", admin, {"project_id": pid, "target": "198.51.100.77"})
        t("an administrator without a reason is blocked and told an override is possible", s == 403 and h.get("X-SOCIS-Can-Override") == "1", (s, d))
        s, d, _ = call("POST", "/scans/", admin, {"project_id": pid, "target": "198.51.100.77", "scope_override_reason": "Customer approved this host by email on 2026-10-07"})
        t("an administrator override WITH a written reason is accepted (201)", s == 201 and d.get("id"), (s, d))
        if d.get("id"):
            call("POST", f"/scans/{d['id']}/cancel", admin)       # nothing is left running against that address

        # ── audit trail ──
        s, d, _ = call("GET", f"/projects/{pid}/scope", admin)
        acts = {e.get("action") for e in d.get("events", [])}
        t("blocked attempts, the override and the scope change are all audited", {"scope:blocked", "scope:override", "scope:updated"} <= acts, acts)

        # ── enforcement off ──
        s, d, _ = call("PUT", f"/projects/{pid}/scope", admin, {"targets": ["192.0.2.0/24"], "enforced": False})
        s, d, _ = call("POST", f"/projects/{pid}/scope/check", an, {"target": OUT})
        t("with enforcement off nothing is blocked (and the check says so)", s == 200 and d.get("allowed") is True and d.get("enforced") is False and d.get("in_list") is False, (s, d))
        # ── IDOR: a scan's AI-chat context cannot be read through someone else's project ──
        s, bp2, _ = call("POST", "/projects/", admin, {"name": f"verify idor {sfx}", "scope_targets": [IN_], "scope_enforced": True})
        made_projects.append(bp2.get("id"))
        s, sc, _ = call("POST", "/scans/", admin, {"project_id": bp2.get("id"), "target": IN_})
        s, d, _ = call("POST", "/llm/chat", an, {"messages": [{"role": "user", "content": "summarize"}], "scan_context_id": sc.get("id"), "stream": False})
        body = json.dumps(d)
        t("an analyst cannot pull another user's scan into AI chat as context (IDOR)", "198.51" not in body and "192.0.2" not in body, s)

        # ── plugins: code in that folder runs with full backend privileges, so who can see / reload it matters ──
        s, d, _ = call("GET", "/admin/plugins/manifest", an)
        t("an analyst cannot read the plugin manifest (403)", s == 403, (s, d))
        s, d, _ = call("POST", "/admin/plugins/reload", an)
        t("an analyst cannot trigger a plugin reload (403)", s == 403, (s, d))
        s, d, _ = call("GET", "/admin/plugins/manifest", admin)
        t("an administrator can read the plugin manifest: every file with its sha256", s == 200 and isinstance(d.get("files"), list) and all(len(str(x.get("sha256", ""))) == 64 for x in d["files"]), (s, d))
        s, d, _ = call("POST", "/admin/plugins/reload", admin)
        t("an administrator's reload answers with what was loaded (and is audited)", s == 200 and isinstance(d.get("files"), list), (s, d))
        # ── report branding: the PDF engine fetches logos server-side, so internal addresses must be refused at save time ──
        s, d, _ = call("POST", "/settings/reports", an, {"brand_logo_url": "http://169.254.169.254/latest/meta-data/"})
        t("a report logo pointing at the cloud metadata address is refused (400)", s == 400, (s, d))
        s, d, _ = call("POST", "/settings/reports", an, {"customer_logo_url": "http://10.0.0.5:6379/"})
        t("a report logo pointing at an internal service is refused (400)", s == 400, (s, d))
        s, d, _ = call("POST", "/settings/reports", an, {"brand_color": "#0ff0fc", "brand_logo_url": ""})
        t("normal report settings (hex colour, no logo) still save", s == 200, (s, d))
    finally:
        for pid_ in made_projects:
            if pid_:
                call("DELETE", f"/projects/{pid_}", admin)
        for uid in made_users:
            if uid:
                call("DELETE", f"/admin/users/{uid}", admin)
    print(f"RESULT: {P} passed, {F} failed")
    return 1 if F else 0


if __name__ == "__main__":
    sys.exit(main())
