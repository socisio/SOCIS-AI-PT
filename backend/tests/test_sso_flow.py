"""SSO sign-in tests: the REAL `_oauth_login_or_create` from api/v1/auth.py (its source is extracted and run) against an in-memory fake database.
The web framework and database layers are stand-ins, so this is a separate process from test_security_guards.py.

  python tests/test_sso_flow.py
"""
import asyncio, datetime as dt, json, os, re, sys, types, uuid
from typing import Optional

HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
P = F = 0
def t(name, ok, extra=""):
    global P, F
    if ok: P += 1; print("PASS ", name)
    else: F += 1; print("FAIL ", name, extra)

# ── fake database layer ─────────────────────────────────────────────────────
class Cond:
    def __init__(self, col, val): self.col, self.val = col, val
    def __and__(self, o): return And([self, o])
    def ok(self, u):
        if self.col == "lower:email": return (u.email or "").lower() == self.val
        return getattr(u, self.col, None) == self.val
class And:
    def __init__(self, cs): self.cs = cs
    def __and__(self, o): return And(self.cs + [o])
    def ok(self, u): return all(c.ok(u) for c in self.cs)
class Col:
    def __init__(self, n): self.n = n
    def __eq__(self, o): return Cond(self.n, o)
    __hash__ = None
class LowerCol:
    def __init__(self, c): self.n = "lower:" + c.n
    def __eq__(self, o): return Cond(self.n, o)
    __hash__ = None
class _Func:
    @staticmethod
    def lower(c): return LowerCol(c)
class Role:
    name = Col("name")
    def __init__(self, name): self.name = name
class User:
    oauth_provider, oauth_id, email, username = Col("oauth_provider"), Col("oauth_id"), Col("email"), Col("username")
    def __init__(self, **kw):
        self.id = uuid.uuid4(); self.roles = []; self.is_active = True; self.is_superuser = False; self.totp_enabled = False
        self.oauth_provider = None; self.oauth_id = None; self.avatar_url = None; self.last_login = None; self.full_name = ""
        self.__dict__.update(kw)
class Query:
    def __init__(self, model): self.model, self.cond = model, None
    def where(self, c): self.cond = c; return self
def select(model): return Query(model)
class Res:
    def __init__(self, rows): self.rows = rows
    def scalar_one_or_none(self): return self.rows[0] if self.rows else None
class FakeDB:
    def __init__(self, users, roles): self.users, self.roles, self.audits = users, roles, []
    async def execute(self, q):
        if q.model is User:
            return Res([u for u in self.users if q.cond.ok(u)])
        return Res([r for r in self.roles if getattr(q.cond, "val", None) == r.name])
    def add(self, u): self.users.append(u)
    async def flush(self): pass
class HTTPException(Exception):
    def __init__(self, status_code, detail="", headers=None): self.status_code, self.detail, self.headers = status_code, detail, headers
class Resp:
    def __init__(self, content="", media_type=None, status_code=200): self.content, self.media_type, self.status_code, self.cookies = content, media_type, status_code, None
class _Status: HTTP_202_ACCEPTED = 202
class _Settings: DEFAULT_USER_ROLE = "viewer"
class TokenResponse:
    def __init__(self, **kw): self.kw = kw
    def model_dump(self, mode=None): return {k: (v if not isinstance(v, dict) else v) for k, v in self.kw.items()}
class UserResponse:
    @staticmethod
    def model_validate(u): return {"id": str(u.id), "email": u.email, "username": u.username}

audit_calls = []
async def _audit_standalone(action, user_id, rtype, rid, details): audit_calls.append((action, details))
sys.modules["app.core.scope_guard"] = types.SimpleNamespace(audit_standalone=_audit_standalone)

src = open(os.path.join(ROOT, "app", "api", "v1", "auth.py"), encoding="utf-8").read()
fn_src = src[src.index("async def _oauth_login_or_create"):src.index("# ─── User Directory")]
auth_audits = []
async def _log_audit(db, **kw): db.audits.append(kw)
cookie_calls = []
ns = dict(select=select, func=_Func, User=User, Role=Role, HTTPException=HTTPException, Response=Resp, status=_Status, settings=_Settings, json=json,
          datetime=dt.datetime, timezone=dt.timezone, Optional=Optional, TokenResponse=TokenResponse, UserResponse=UserResponse, log_audit=_log_audit,
          create_mfa_token=lambda uid: "mfa-" + uid, create_access_token=lambda d: "access", create_refresh_token=lambda d: "refresh",
          _set_token_cookies=lambda r, a, rt: setattr(r, "cookies", (a, rt)), _CLEAR_OAUTH_STATE={"Set-Cookie": "oauth_state=; Max-Age=0"}, AsyncSession=object)
exec(fn_src, ns)
login = ns["_oauth_login_or_create"]

def run(oauth_user, users, cfg):
    audit_calls.clear()
    db = FakeDB(users, [Role("viewer"), Role("admin")])
    try:
        return asyncio.run(login(oauth_user, db, cfg)), None, db
    except HTTPException as e:
        return None, e, db

admin = User(email="admin@corp.com", username="admin", roles=[Role("admin")], is_superuser=True)
alice = User(email="alice@corp.com", username="alice", roles=[Role("analyst")])
G = lambda **k: dict({"provider": "google", "oauth_id": "g-123", "email": "alice@corp.com", "email_verified": True, "full_name": "Alice"}, **k)
M = lambda **k: dict({"provider": "microsoft", "oauth_id": "m-999", "email": "alice@corp.com", "email_verified": False, "full_name": "Mallory"}, **k)
CFG = lambda **k: dict({"sso_allowed_domains": "corp.com", "sso_auto_provision": False, "microsoft_tenant_id": "common"}, **k)

print("=== the attack: sign in with a provider account whose e-mail is an existing local account ===")
for label, cfg in (("domain list set", CFG()), ("no domain list at all", CFG(sso_allowed_domains="")), ("auto-provision on", CFG(sso_auto_provision=True))):
    adm = User(email="admin@corp.com", username="admin", roles=[Role("admin")], is_superuser=True)
    r, e, db = run(M(email="admin@corp.com", oauth_id="attacker-oid"), [adm], cfg)
    t(f"Microsoft identity claiming the admin's e-mail is REFUSED ({label}), the admin account is untouched, and no tokens are issued",
      e is not None and e.status_code == 403 and r is None and adm.oauth_provider is None and adm.oauth_id is None and adm.last_login is None)
t("the refusal is audited with its reason (in its own session, so it survives the rolled-back request)", audit_calls and audit_calls[-1][0] == "auth:sso_denied" and audit_calls[-1][1]["reason"] == "email_in_use_not_linkable")
t("the message shown never says whether an account exists", "exist" not in (e.detail or "").lower() and "administrator" in (e.detail or "").lower())
adm2 = User(email="admin@corp.com", username="admin", roles=[Role("admin")])
r, e, _ = run(G(email="admin@corp.com", oauth_id="g-evil"), [adm2], CFG())
t("even a VERIFIED Google address cannot take over an administrator account", e is not None and e.status_code == 403 and adm2.oauth_id is None)
e_hdr = e.headers or {}
t("the single-use state cookie is cleared on a refusal", "oauth_state=" in str(e_hdr.get("Set-Cookie", "")))

print("=== returning users ===")
linked = User(email="alice@corp.com", username="alice", roles=[Role("analyst")], oauth_provider="google", oauth_id="g-123")
r, e, db = run(G(), [linked], CFG(sso_allowed_domains=""))
t("a returning, linked, active user signs in: tokens + cookies, last_login set, the sign-in is audited", r is not None and r.status_code == 200 and r.cookies == ("access", "refresh") and linked.last_login and db.audits[-1]["action"] == "auth:sso_login")
off = User(email="alice@corp.com", username="alice", roles=[Role("analyst")], oauth_provider="google", oauth_id="g-123", is_active=False)
r, e, _ = run(G(), [off], CFG())
t("a DEACTIVATED user can no longer sign in through SSO (they could before)", e is not None and e.status_code == 403 and r is None and audit_calls[-1][1]["reason"] == "inactive")
mfa_user = User(email="alice@corp.com", username="alice", roles=[Role("analyst")], oauth_provider="google", oauth_id="g-123", totp_enabled=True)
r, e, _ = run(G(), [mfa_user], CFG())
body = json.loads(r.content) if r is not None else {}
t("an account with two-factor on still gets the authenticator-code step: 202 + a temporary token, NO session, last_login untouched", r is not None and r.status_code == 202 and body.get("mfa_required") is True and body.get("mfa_token", "").startswith("mfa-") and r.cookies is None and mfa_user.last_login is None)
r, e, _ = run(G(email="alice@evil.org"), [linked], CFG())
t("narrowing the allowed domains also stops RETURNING users from other domains", e is not None and audit_calls[-1][1]["reason"] == "domain_not_allowed")

print("=== linking an existing local account (the only case that is allowed) ===")
a1 = User(email="alice@corp.com", username="alice", roles=[Role("analyst")])
r, e, db = run(G(email="ALICE@Corp.com"), [a1], CFG())
t("a VERIFIED Google address on an allowed domain links a non-administrator account (e-mail compared case-insensitively) and audits it", r is not None and a1.oauth_provider == "google" and a1.oauth_id == "g-123" and any(a["action"] == "auth:sso_linked" for a in db.audits))
a2 = User(email="alice@corp.com", username="alice", roles=[Role("analyst")])
r, e, _ = run(G(email_verified=False), [a2], CFG())
t("an UNVERIFIED Google address links nothing", e is not None and a2.oauth_id is None)
a3 = User(email="alice@corp.com", username="alice", roles=[Role("analyst")])
r, e, _ = run(G(), [a3], CFG(sso_allowed_domains=""))
t("with no domain list nothing is ever linked by e-mail", e is not None and a3.oauth_id is None)
a4 = User(email="alice@corp.com", username="alice", roles=[Role("analyst")], oauth_provider="google", oauth_id="someone-else")
r, e, _ = run(G(), [a4], CFG())
t("an e-mail already linked to a DIFFERENT identity is refused (the link is not overwritten)", e is not None and a4.oauth_id == "someone-else")

print("=== creating accounts ===")
r, e, db = run(G(email="bob@corp.com", oauth_id="g-bob"), [], CFG())
t("by DEFAULT a first-time SSO sign-in creates nothing (auto-provision is off)", e is not None and db.users == [])
r, e, db = run(G(email="bob@corp.com", oauth_id="g-bob"), [], CFG(sso_auto_provision=True, sso_allowed_domains=""))
t("auto-provision without a domain list creates nothing (it used to create an account for ANY Google/Microsoft account)", e is not None and db.users == [])
r, e, db = run(G(email="bob@corp.com", oauth_id="g-bob"), [User(email="x@corp.com", username="bob", roles=[Role("viewer")])], CFG(sso_auto_provision=True))
new = [u for u in db.users if u.oauth_id == "g-bob"]
t("auto-provision + allowed domain + verified Google creates a viewer, with a unique username, and audits it", r is not None and len(new) == 1 and new[0].roles[0].name == "viewer" and new[0].username == "bob1" and any(a["action"] == "auth:sso_provisioned" for a in db.audits))
r, e, db = run(G(email="bob@corp.com", oauth_id="g-bob", email_verified=False), [], CFG(sso_auto_provision=True))
t("an unverified Google address is not turned into an account", e is not None and db.users == [])
r, e, db = run(M(email="bob@corp.com", oauth_id="m-bob"), [], CFG(sso_auto_provision=True, microsoft_tenant_id="common"))
t("Microsoft with the open 'common' tenant creates nothing (any tenant's administrator could claim any address)", e is not None and db.users == [])
r, e, db = run(M(email="bob@corp.com", oauth_id="m-bob"), [], CFG(sso_auto_provision=True, microsoft_tenant_id="3f2a9c1e-1111-4222-8333-944455556666"))
t("Microsoft with ONE named tenant, an allowed domain and auto-provision on creates a viewer", r is not None and any(u.oauth_id == "m-bob" for u in db.users))

print("=== wiring ===")
a = open(os.path.join(ROOT, "app", "api", "v1", "auth.py"), encoding="utf-8").read()
t("the state is compared in constant time and cleared on failure paths (single use), in both providers", "hmac.compare_digest" in a and a.count("_check_oauth_state(state, oauth_state)") == 2 and a.count("headers=_CLEAR_OAUTH_STATE") >= 4)
t("both callbacks pass the SSO settings to the sign-in function", a.count("_oauth_login_or_create(oauth_user, db, cfg)") == 2)
svc = open(os.path.join(ROOT, "app", "services", "auth_service.py"), encoding="utf-8").read()
t("Google's email_verified is carried through; Microsoft's e-mail is never marked verified; Google no longer asks for offline access", '"email_verified": user_info.get("email_verified") is True' in svc and '"email_verified": False' in svc and '"access_type"' not in svc)
adm_api = open(os.path.join(ROOT, "app", "api", "v1", "admin.py"), encoding="utf-8").read()
t("the admin SSO settings accept and audit the allowed domains and the auto-provision switch", "sso_allowed_domains: str" in adm_api and "sso_auto_provision: bool" in adm_api and '"sso_auto_provision": saved.get' in adm_api)
fe = os.path.join(ROOT, "..", "frontend", "src")
if os.path.isdir(fe):
    cb = os.path.join(fe, "app", "auth", "callback", "[provider]", "page.tsx")
    t("the OAuth callback page exists (without it every SSO sign-in ended in a 404) and sends the code only once", os.path.exists(cb) and "authApi.ssoCallback" in open(cb, encoding="utf-8").read() and "started.current" in open(cb, encoding="utf-8").read())
    lp = open(os.path.join(fe, "app", "login", "page.tsx"), encoding="utf-8").read()
    t("the login page picks up the two-factor hand-off from an SSO sign-in", "socis_sso_mfa" in lp and "setMfaToken(t)" in lp)

print(f"\nRESULT: {P} passed, {F} failed")
sys.exit(1 if F else 0)
