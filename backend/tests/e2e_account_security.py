"""Live end-to-end check of account security (run inside the backend container by verify.sh). stdlib + pyotp (already installed).

Replays the MFA bypass that existed before the fix, runs the full two-factor enrol + sign-in flow, and checks API tokens,
sign-out-everywhere, password change (signs OTHER devices out) and webhooks. Always deletes what it creates.
"""
import json, os, re, secrets, sys, time, urllib.error, urllib.parse, urllib.request

BASE = "http://localhost:8000/api/v1"
ADMIN_USER = os.environ.get("VERIFY_ADMIN_USER") or "admin"          # verify.sh passes a temporary admin (the real one may have two-factor on)
ADMIN_PASS = os.environ.get("VERIFY_ADMIN_PASSWORD") or os.environ.get("ADMIN_PASSWORD") or "Admin123!"
P = F = 0


def t(name, ok, extra=""):
    global P, F
    P += bool(ok); F += (not ok)
    print(("PASS  " if ok else "FAIL  ") + name + ((" - " + str(extra)) if (extra and not ok) else ""))


def call(method, path, token=None, body=None, form=None, headers=None):
    h = {"X-Requested-With": "SOCIS", **(headers or {})}
    data = None
    if token:
        h["Authorization"] = "Bearer " + token
    if form is not None:
        data = urllib.parse.urlencode(form).encode(); h["Content-Type"] = "application/x-www-form-urlencoded"
    elif body is not None:
        data = json.dumps(body).encode(); h["Content-Type"] = "application/json"
    req = urllib.request.Request(BASE + path, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=25) as r:
            raw = r.read().decode() or "{}"
            return r.status, (json.loads(raw) if raw.strip()[:1] in "{[" else {}), r.headers
    except urllib.error.HTTPError as e:
        raw = e.read().decode() or "{}"
        try:
            return e.code, json.loads(raw), e.headers
        except ValueError:
            return e.code, {"detail": raw[:120]}, e.headers


RATE_WAIT = float(os.environ.get("E2E_RATE_WAIT", "15"))


def pcall(method, path, token=None, body=None, form=None):
    """call() that WAITS when the rate limiter (not the account lock-out) answers 429. The MFA routes allow 5 requests a minute per
    address and the counter outlives a run, so running this again within a minute of an earlier run would otherwise fail on leftovers."""
    for _ in range(8):
        s, d, h = call(method, path, token, body, form)
        if s == 429 and "Rate limit exceeded" in json.dumps(d):
            time.sleep(RATE_WAIT)
            continue
        return s, d, h
    return s, d, h


def login(user, pw):
    """Sign in. Login is limited to 30/minute per IP and the lifecycle test runs just before this one, so wait and retry on 429
    (a rate-limit answer here is not a security failure, it is the limiter doing its job)."""
    for _ in range(6):
        s, d, _h = call("POST", "/auth/login", form={"username": user, "password": pw})
        if s != 429:
            return s, d
        time.sleep(15)
    return s, d


def main():
    import pyotp
    s, d = login(ADMIN_USER, ADMIN_PASS)
    admin = d.get("access_token", "")
    if not admin:
        print("FAIL  admin login", s, "(HTTP 202 means that account has two-factor on: run this through verify.sh, which uses a temporary admin)" if s == 202 else ""); print("RESULT: 0 passed, 1 failed"); return 1
    for u in call("GET", "/admin/users?q=verify_acct_", admin)[1].get("users", []):      # leftovers from an interrupted run
        if str(u.get("username", "")).startswith("verify_acct_"):
            call("DELETE", f"/admin/users/{u['id']}", admin)

    made = []
    def newuser(tag):
        sfx = secrets.token_hex(3)
        s, d, _ = call("POST", "/admin/users", admin, {"email": f"verify-acct-{tag}-{sfx}@socis-verify.com", "username": f"verify_acct_{tag}_{sfx}", "role": "viewer"})
        made.append(d.get("id"))
        return d.get("id"), d.get("username"), d.get("temporary_password", "")

    try:
        uid, uname, pw = newuser("a")
        s, d = login(uname, pw); tok = d.get("access_token", "")
        t("a new user can sign in", s == 200 and tok, s)
        s, me, _ = call("GET", "/auth/me", tok)
        t("/auth/me returns the ROLE and mfa_enabled=false", s == 200 and me.get("role") == "viewer" and me.get("mfa_enabled") is False, me)

        # ── enrol two-factor ──
        s, setup, _ = call("POST", "/auth/mfa/setup", tok)
        secret = setup.get("secret", "")
        t("MFA setup returns a secret, a QR image and a URI", s == 200 and secret and str(setup.get("qr_code", "")).startswith("data:image/png") and "otpauth://" in str(setup.get("uri", "")), s)
        s, _, _ = pcall("POST", "/auth/mfa/verify", tok, {"code": "000000"})
        t("a wrong code does not enable MFA (400)", s == 400, s)
        s, _, _ = pcall("POST", "/auth/mfa/verify", tok, {"code": pyotp.TOTP(secret).now()})
        t("the right code enables MFA", s == 200, s)
        s, me, _ = call("GET", "/auth/me", tok)
        t("/auth/me now says mfa_enabled=true", s == 200 and me.get("mfa_enabled") is True, me)
        s, d, _ = call("POST", "/auth/mfa/setup", tok)
        t("SETUP REFUSES when MFA is already on (400): the secret cannot be swapped", s == 400, (s, d))

        # ── THE BYPASS, replayed ──
        s, d = login(uname, pw)
        mfa_tok = d.get("mfa_token", "")
        t("password alone no longer signs in: 202 + a temporary mfa_token", s == 202 and d.get("mfa_required") is True and mfa_tok and not d.get("access_token"), (s, d))
        for label, m, path, body in (("/auth/me", "GET", "/auth/me", None), ("MFA SETUP (the swap attack)", "POST", "/auth/mfa/setup", None), ("the scans API", "GET", "/scans/", None), ("sign-out-everywhere", "POST", "/auth/logout-all", None)):
            s, _, _ = call(m, path, mfa_tok, body)
            t(f"the temporary mfa_token is REJECTED as an access token on {label} (401)", s == 401, s)
        s, _, _ = call("POST", f"/auth/mfa/verify-login?mfa_token={mfa_tok}", None, {"code": pyotp.TOTP(secret).now()})
        t("the old URL-parameter form is gone (the token must be in the body)", s in (401, 422), s)
        s, _, _ = pcall("POST", "/auth/mfa/verify-login", None, {"mfa_token": mfa_tok, "code": "000000"})
        t("a wrong authenticator code is refused (401)", s == 401, s)
        s, d, _ = pcall("POST", "/auth/mfa/verify-login", None, {"mfa_token": mfa_tok, "code": pyotp.TOTP(secret).now()})
        full, refresh = d.get("access_token", ""), d.get("refresh_token", "")
        t("the right code completes sign-in and returns real tokens", s == 200 and full and refresh, (s, d))
        s, _, _ = call("GET", "/auth/me", full)
        t("the real access token works", s == 200, s)
        s, _, _ = pcall("POST", "/auth/mfa/verify-login", None, {"mfa_token": mfa_tok, "code": pyotp.TOTP(secret).now()})
        t("the temporary token is SINGLE USE (401 the second time)", s == 401, s)
        s, _, _ = call("GET", "/auth/me", refresh)
        t("a REFRESH token cannot be used as an access token (401)", s == 401, s)

        # ── API tokens ──
        s, k, _ = call("POST", "/api-keys/", full, {"name": "verify token"})
        raw, kid = k.get("raw_key", ""), k.get("id")
        t("an API token can be created and the raw key is returned once", s == 201 and raw.startswith("socis_") and kid and k.get("prefix") == raw[:12], (s, k))
        s, lst, _ = call("GET", "/api-keys/", full)
        t("the token list shows the prefix but never the key", s == 200 and any(x.get("id") == kid for x in lst) and not any("raw_key" in x for x in lst), lst)
        # API tokens are accepted by the permission-checked endpoints (e.g. /scans/); /auth/me is bearer/cookie only by design.
        s, _, _ = call("GET", "/scans/", None, headers={"X-API-Key": raw})
        t("the token authenticates API calls (scans:read)", s == 200, s)
        s, _, _ = call("POST", "/api-keys/", None, {"name": "x"}, headers={"X-API-Key": raw})
        t("a token cannot create other tokens (403)", s == 403, s)
        s, _, _ = call("DELETE", f"/api-keys/{kid}", full)
        t("a token can be revoked (204)", s == 204, s)
        s, _, _ = call("GET", "/scans/", None, headers={"X-API-Key": raw})
        t("a revoked token stops working at once (401)", s == 401, s)

        # ── change password signs OTHER devices out, keeps this one ──
        uid2, uname2, pw2 = newuser("b")
        _, dA = login(uname2, pw2); A = dA.get("access_token", "")
        time.sleep(2.2)
        _, dB = login(uname2, pw2); B = dB.get("access_token", "")
        time.sleep(1.2)
        newpw = "Quartz-Harbor-" + secrets.token_hex(3).upper() + "!"
        s, d, hdrs = call("POST", "/auth/change-password", A, {"current_password": pw2, "new_password": newpw})
        cookies = " ".join(hdrs.get_all("Set-Cookie") or [])
        new_access = (re.search(r"access_token=([^;]+)", cookies) or [None, ""])[1]
        t("changing the password succeeds and sets fresh cookies for THIS device", s == 200 and new_access, (s, d))
        time.sleep(1.1)
        s, _, _ = call("GET", "/auth/me", B)
        t("the OTHER device is signed out immediately", s == 401, s)
        s, _, _ = call("GET", "/auth/me", new_access)
        t("THIS device stays signed in (new cookie works)", s == 200, s)
        s, _ = login(uname2, pw2)
        t("the OLD password no longer works", s in (400, 401), s)
        s, d = login(uname2, newpw); C = d.get("access_token", "")
        t("the NEW password works", s == 200 and C, s)
        s, _, _ = call("POST", "/auth/change-password", C, {"current_password": newpw, "new_password": newpw})
        t("reusing the same password is refused (400)", s == 400, s)

        # ── sign out everywhere ──
        s, _, _ = call("POST", "/auth/logout-all", C)
        t("sign-out-everywhere succeeds", s == 200, s)
        s, _, _ = call("GET", "/auth/me", C)
        t("every session of that account is dead at once (401)", s == 401, s)

        # ── webhooks ──
        s, ev, _ = call("GET", "/webhooks/events", admin)
        t("the webhook event catalog lists the events the platform emits", s == 200 and {e["name"] for e in ev.get("events", [])} == {"scan.completed", "scan.failed", "scan.cancelled", "finding.critical"}, ev)
        s, d, _ = call("POST", "/webhooks/", admin, {"url": "https://1.1.1.1/hook", "events": ["scan.complete"]})
        t("a misspelt event is refused (400), not silently saved", s == 400, (s, d))
        s, d, _ = call("POST", "/webhooks/", admin, {"url": "http://127.0.0.1:8000/x", "events": ["scan.completed"]})
        t("an internal URL is refused at SAVE time (400)", s == 400, (s, d))
        s, d, _ = call("POST", "/webhooks/", admin, {"url": "https://1.1.1.1/hook", "events": ["scan.completed", "finding.critical"], "secret": "s3cret-value", "description": "verify"})
        wid = d.get("id")
        t("a valid webhook is saved and the secret is never returned", s == 201 and wid and "secret" not in d, (s, d))
        s, d, _ = call("PATCH", f"/webhooks/{wid}", admin, {"events": ["scan.failed"]})
        t("events can be changed", s == 200 and d.get("events") == ["scan.failed"], (s, d))
        s, d, _ = call("PATCH", f"/webhooks/{wid}", admin, {"events": ["nonsense"]})
        t("changing to an unknown event is refused (400)", s == 400, (s, d))
        s, _, _ = call("DELETE", f"/webhooks/{wid}", admin)
        t("a webhook can be deleted (204)", s == 204, s)

        # ── admin recovery for a lost authenticator ──
        s, _, _ = call("POST", f"/admin/users/{uid}/reset-mfa", admin)
        t("an admin can reset a lost-device user's two-factor", s == 200, s)
        s, d = login(uname, pw)
        t("after the reset that user signs in with the password alone", s == 200 and d.get("access_token"), (s, d))
        s, _, _ = call("POST", f"/admin/users/{uid}/reset-mfa", full)
        t("a non-admin cannot reset anyone's two-factor (403/401)", s in (401, 403), s)

        # ── brute force: wrong codes lock the account's MFA ──
        time.sleep(1.2)   # the admin reset above revoked sessions up to 'now': let the next sign-in's token be strictly newer
        s, setup, _ = call("POST", "/auth/mfa/setup", login(uname, pw)[1].get("access_token"))
        sec2 = setup.get("secret", ""); tok2 = login(uname, pw)[1].get("access_token")
        pcall("POST", "/auth/mfa/verify", tok2, {"code": pyotp.TOTP(sec2).now()})
        statuses = []
        for _ in range(7):
            sl, dl = login(uname, pw)
            mt = dl.get("mfa_token", "")
            if not mt:
                statuses.append(sl); continue
            sv, _, _ = call("POST", "/auth/mfa/verify-login", None, {"mfa_token": mt, "code": "123456"})
            statuses.append(sv)
            if sv == 429:
                break            # locked (or limited): proven, and no need to use up more of the per-minute budget
            time.sleep(0.3)
        t("repeated wrong codes end in a lock-out (429: per-account lock and/or the 5-per-minute limiter), not endless guessing", 429 in statuses, statuses)
    finally:
        for i in made:
            if i:
                call("DELETE", f"/admin/users/{i}", admin)
    print(f"RESULT: {P} passed, {F} failed")
    return 1 if F else 0


if __name__ == "__main__":
    sys.exit(main())
