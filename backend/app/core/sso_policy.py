"""Who may sign in through Google / Microsoft, and as which local account? (pure: unit-tested, no database)

Found in the first audit of the SSO flow: after a provider login the code looked the person up BY EMAIL, and if a local account had that email
it OVERWROTE the account's SSO link and signed the caller in as that account, with no password and no two-factor. Microsoft gives no
verified email: the address is the Graph `mail`/`userPrincipalName` of a user in WHATEVER tenant signed in, and the default tenant is "common"
(every Entra tenant and personal accounts), so an attacker who controls any tenant can set `mail` to admin@your-company.com and become your
local admin. In addition: a deactivated user could still sign in this way, any Google/Microsoft account silently created a platform account
(no domain restriction), and Google's `email_verified` was never looked at.

The rules, in order (the first that applies wins):
  1. No provider identity (`oauth_id`)                            -> deny
  2. An allowed-domain list is set and the email is not in it     -> deny (applies to returning users too)
  3. The identity is already linked to a local account            -> sign in (deny if the account is deactivated)
  4. No email in the profile                                      -> deny
  5. A local account has this email (not linked to this identity) -> NEVER link by email except: Google, `email_verified` true, domain on the
                                                                     allow list, target is not an administrator and not deactivated; else deny
  6. Nobody has this email                                        -> create an account only if an administrator turned auto-provisioning on,
                                                                     the domain list is not empty, Google's email is verified, and Microsoft's
                                                                     tenant is a single named tenant (never common/organizations/consumers)
  7. Anything else                                                -> deny
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, Optional, Set

OPEN_MICROSOFT_TENANTS = {"common", "organizations", "consumers", ""}
GENERIC_DENIAL = "Single sign-on is not available for this account. Ask an administrator."


@dataclass(frozen=True)
class SsoDecision:
    action: str          # "login" | "link" | "provision" | "deny"
    reason: str          # short machine reason, for the audit log
    message: str = ""    # safe to show the person (never says whether an account exists)


def normalize_email(value: object) -> str:
    return str(value or "").strip().lower()


def email_domain(email: object) -> str:
    e = normalize_email(email)
    return e.rsplit("@", 1)[1] if "@" in e else ""


def parse_domains(value: object) -> Set[str]:
    """'Example.com, corp.example.org' -> {'example.com', 'corp.example.org'}"""
    raw = value if isinstance(value, str) else ",".join(value or [])  # type: ignore[arg-type]
    out = set()
    for tok in re.split(r"[,\s;]+", raw.strip().lower()):
        tok = tok.lstrip("@").strip(".")
        # Each label (between dots) must be a sane hostname label: starts/ends alphanumeric, no empty labels (rules out "bad..tld").
        if tok and re.fullmatch(r"[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+", tok):
            out.add(tok)
    return out


def tenant_is_open(tenant_id: object) -> bool:
    return str(tenant_id or "").strip().lower() in OPEN_MICROSOFT_TENANTS


def _deny(reason: str) -> SsoDecision:
    return SsoDecision("deny", reason, GENERIC_DENIAL)


def decide(oauth_user: dict, identity_user: Optional[dict], email_user: Optional[dict], allowed_domains: Iterable[str],
           auto_provision: bool, tenant_id: object = "") -> SsoDecision:
    """identity_user / email_user: None, or {"is_active": bool, "is_admin": bool, "linked": bool} for the local account found that way."""
    domains = set(allowed_domains or [])
    provider = str(oauth_user.get("provider") or "").lower()
    email = normalize_email(oauth_user.get("email"))
    verified = oauth_user.get("email_verified") is True

    if not str(oauth_user.get("oauth_id") or "").strip():
        return _deny("no_identity")
    if domains and email_domain(email) not in domains:
        return _deny("domain_not_allowed")
    if identity_user is not None:
        return SsoDecision("login", "identity_match") if identity_user.get("is_active") else _deny("inactive")
    if not email or "@" not in email:
        return _deny("no_email")
    if email_user is not None:
        if email_user.get("linked"):
            return _deny("email_linked_to_other_identity")
        if provider == "google" and verified and domains and not email_user.get("is_admin"):
            return SsoDecision("link", "google_verified_domain") if email_user.get("is_active") else _deny("inactive")
        return _deny("email_in_use_not_linkable")
    if not auto_provision:
        return _deny("auto_provision_off")
    if not domains:
        return _deny("no_domain_list")
    if provider == "google" and not verified:
        return _deny("google_email_unverified")
    if provider == "microsoft" and tenant_is_open(tenant_id):
        return _deny("microsoft_tenant_not_restricted")
    if provider not in ("google", "microsoft"):
        return _deny("unknown_provider")
    return SsoDecision("provision", "auto_provision")
