"""Live end-to-end check of admin user management (run inside the backend container by verify.sh).

Creates a temporary user, signs in as them, and proves: RBAC is enforced, the safety rules hold, and
changing/deactivating/resetting a user signs them out IMMEDIATELY (not when their token expires).
Always deletes the temporary user. stdlib only.   Usage: python tests/e2e_user_lifecycle.py
"""
import json, os, secrets, sys, time, urllib.error, urllib.parse, urllib.request

BASE = "http://localhost:8000/api/v1"
ADMIN_USER = os.environ.get("VERIFY_ADMIN_USER") or "admin"          # verify.sh passes a temporary admin so two-factor on the real one does not block it
ADMIN_PASS = os.environ.get("VERIFY_ADMIN_PASSWORD") or os.environ.get("ADMIN_PASSWORD") or "Admin123!"
P = F = 0


def t(name, ok, extra=""):
    global P, F
    P += bool(ok); F += (not ok)
    print(("PASS  " if ok else "FAIL  ") + name + ((" — " + str(extra)) if (extra and not ok) else ""))


def call(method, path, token=None, body=None, form=None):
    headers = {"X-Requested-With": "SOCIS"}
    data = None
    if token:
        headers["Authorization"] = "Bearer " + token
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    elif body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(BASE + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            raw = r.read().decode() or "{}"
            return r.status, (json.loads(raw) if raw.strip().startswith(("{", "[")) else {})
    except urllib.error.HTTPError as e:
        raw = e.read().decode() or "{}"
        try:
            return e.code, json.loads(raw)
        except ValueError:
            return e.code, {"detail": raw[:120]}


def login(user, pw):
    s, d = call("POST", "/auth/login", form={"username": user, "password": pw})
    return s, d.get("access_token", "")


def main():
    s, admin = login(ADMIN_USER, ADMIN_PASS)
    if not admin:
        print("FAIL  admin login (cannot continue)", s); print("RESULT: 0 passed, 1 failed"); return 1
    _, me = call("GET", "/auth/me", admin)
    admin_id = me.get("id")

    # Leftovers from an earlier interrupted run would pollute the user list: remove them first (best effort).
    _, old = call("GET", "/admin/users?q=verify_tmp_", admin)
    for u in old.get("users", []):
        if str(u.get("username", "")).startswith("verify_tmp_"):
            call("DELETE", f"/admin/users/{u['id']}", admin)

    suffix = secrets.token_hex(3)
    uname, email = f"verify_tmp_{suffix}", f"verify-tmp-{suffix}@socis-verify.com"
    uid = pid = None
    try:
        s, d = call("GET", "/admin/roles", admin)
        t("roles endpoint lists admin, analyst and viewer", s == 200 and {r["name"] for r in d.get("roles", [])} == {"admin", "analyst", "viewer"}, d)

        s, d = call("POST", "/admin/users", admin, {"email": email, "username": uname, "role": "viewer", "full_name": "Verify Temp"})
        uid, tmp = d.get("id"), d.get("temporary_password", "")
        t("admin can CREATE a user (201) and gets a one-time temporary password", s == 201 and uid and len(tmp) >= 12, (s, d))
        t("the new user has the requested role", d.get("role") == "viewer")

        s, d = call("POST", "/admin/users", admin, {"email": email, "username": uname + "x", "role": "viewer"})
        t("duplicate email is refused (409)", s == 409, (s, d))
        s, d = call("POST", "/admin/users", admin, {"email": "x" + email, "username": uname, "role": "viewer"})
        t("duplicate username is refused (409)", s == 409, (s, d))
        s, d = call("POST", "/admin/users", admin, {"email": "y" + email, "username": uname + "y", "role": "superhero"})
        t("an unknown role is refused (400)", s == 400, (s, d))
        s, d = call("POST", "/admin/users", admin, {"email": "z" + email, "username": uname + "z", "role": "viewer", "password": "weak"})
        t("a weak password is refused (400)", s == 400, (s, d))

        s, tok = login(uname, tmp)
        t("the new user can sign in with the temporary password", s == 200 and tok, s)
        s, _ = call("GET", "/auth/me", tok)
        t("their session works", s == 200, s)
        s, _ = call("GET", "/admin/users", tok)
        t("RBAC: a viewer is FORBIDDEN from the admin API (403)", s == 403, s)

        # ── reset password: old sessions die at once, old password stops working ──
        s, d = call("POST", f"/admin/users/{uid}/reset-password", admin, {})
        new_tmp = d.get("temporary_password", "")
        t("admin can reset the password (new one-time password returned)", s == 200 and len(new_tmp) >= 12, (s, d))
        s, _ = call("GET", "/auth/me", tok)
        t("the user's EXISTING session is rejected immediately after the reset", s == 401, s)
        time.sleep(1.2)
        s, _ = login(uname, tmp)
        t("the OLD password no longer works", s in (400, 401), s)
        s, tok = login(uname, new_tmp)
        t("the NEW password works", s == 200 and tok, s)

        # ── role change: applies immediately ──
        s, _ = call("PATCH", f"/admin/users/{uid}", admin, {"role": "analyst"})
        t("admin can change the role (200)", s == 200, s)
        s, _ = call("GET", "/auth/me", tok)
        t("the old (viewer) token is rejected immediately after a role change", s == 401, s)
        time.sleep(1.2)
        s, tok = login(uname, new_tmp)
        s2, d2 = call("GET", "/auth/me", tok)
        t("signing in again works and /auth/me answers", s == 200 and s2 == 200, (s, s2))

        # ── a user who OWNS work cannot be deleted (the database would refuse): a clear 409, never a 500 ──
        s, d = call("POST", "/projects/", tok, {"name": f"verify_tmp_proj_{suffix}"})
        pid = d.get("id")
        t("an analyst can create a project (RBAC allows it)", s == 201 and pid, (s, d))
        s, d = call("DELETE", f"/admin/users/{uid}", admin)
        det = str(d.get("detail", ""))
        t("deleting a user who OWNS a project is refused with 409 and a clear message (never 500)", s == 409 and "project" in det and "Deactivate" in det, (s, det[:100]))

        # ── deactivate: locked out at once and cannot sign back in ──
        s, _ = call("PATCH", f"/admin/users/{uid}", admin, {"is_active": False})
        t("admin can deactivate the user (200)", s == 200, s)
        s, _ = call("GET", "/auth/me", tok)
        t("a deactivated user's token stops working IMMEDIATELY", s == 401, s)
        time.sleep(1.2)
        s, _ = login(uname, new_tmp)
        t("a deactivated user cannot sign in", s in (400, 401, 403), s)

        # ── safety rules ──
        s, d = call("PATCH", f"/admin/users/{admin_id}", admin, {"is_active": False})
        t("an admin cannot deactivate THEMSELVES (400)", s == 400, (s, d))
        s, d = call("PATCH", f"/admin/users/{admin_id}", admin, {"role": "viewer"})
        t("an admin cannot demote THEMSELVES (400)", s == 400, (s, d))
        s, d = call("DELETE", f"/admin/users/{admin_id}", admin)
        t("an admin cannot delete THEMSELVES (400)", s == 400, (s, d))
        s, d = call("PATCH", f"/admin/users/{uid}", admin, {"role": "superhero"})
        t("PATCH with an unknown role is refused, not silently ignored (400)", s == 400, (s, d))

        s, d = call("GET", "/admin/users?q=" + uname, admin)
        t("the user list shows role and status and supports search", s == 200 and any(u.get("username") == uname and u.get("role") == "analyst" and u.get("is_active") is False for u in d.get("users", [])), d)
    finally:
        if pid:
            s, _ = call("DELETE", f"/projects/{pid}", admin)
            t("cleanup: the temporary project is deleted", s in (200, 204), s)
        if uid:
            # The user has signed in several times (audit rows reference them): the delete must still succeed.
            s, _ = call("DELETE", f"/admin/users/{uid}", admin)
            t("cleanup: the temporary user is deleted (204)", s == 204, s)
            s, _ = call("DELETE", f"/admin/users/{uid}", admin)
            t("deleting again reports not found (404)", s == 404, s)
    print(f"RESULT: {P} passed, {F} failed")
    return 1 if F else 0


if __name__ == "__main__":
    sys.exit(main())
