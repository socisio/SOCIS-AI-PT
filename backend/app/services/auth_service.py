"""
SOCIS-AI-PT — Auth Service
Full OAuth/SSO implementation for Google and Microsoft AD.
"""

import httpx
from typing import Optional, Dict
from urllib.parse import urlencode
from fastapi import HTTPException

from app.config import settings


class GoogleOAuthService:
    """Google OAuth 2.0 / OpenID Connect."""

    AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
    TOKEN_URL = "https://oauth2.googleapis.com/token"
    USERINFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo"

    def get_authorization_url(self, redirect_uri: str, state: str = "", client_id: Optional[str] = None) -> str:
        """Generate Google OAuth authorization URL."""
        effective_client_id = client_id or settings.GOOGLE_CLIENT_ID
        params = {
            "client_id": effective_client_id,
            "response_type": "code",
            "scope": "openid email profile",
            "redirect_uri": redirect_uri,
            "state": state,
            "prompt": "select_account",   # (was access_type=offline + prompt=consent: a refresh token nothing here ever used)
        }
        query = urlencode(params)
        return f"{self.AUTH_URL}?{query}"

    async def exchange_code(self, code: str, redirect_uri: str, client_id: Optional[str] = None, client_secret: Optional[str] = None) -> Dict:
        """Exchange authorization code for access token."""
        effective_client_id = client_id or settings.GOOGLE_CLIENT_ID
        effective_client_secret = client_secret or settings.GOOGLE_CLIENT_SECRET
        async with httpx.AsyncClient() as client:
            resp = await client.post(self.TOKEN_URL, data={
                "code": code,
                "client_id": effective_client_id,
                "client_secret": effective_client_secret,
                "redirect_uri": redirect_uri,
                "grant_type": "authorization_code",
            })
            resp.raise_for_status()
            return resp.json()

    async def get_user_info(self, access_token: str) -> Dict:
        """Fetch user profile from Google."""
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                self.USERINFO_URL,
                headers={"Authorization": f"Bearer {access_token}"},
            )
            resp.raise_for_status()
            return resp.json()

    async def authenticate(self, code: str, redirect_uri: str, client_id: Optional[str] = None, client_secret: Optional[str] = None) -> Dict:
        """Full Google OAuth flow: exchange code → get user info."""
        tokens = await self.exchange_code(code, redirect_uri, client_id=client_id, client_secret=client_secret)
        user_info = await self.get_user_info(tokens["access_token"])
        return {
            "provider": "google",
            "oauth_id": user_info["sub"],
            "email": user_info.get("email", ""),
            # Google states whether it verified this address; the sign-in policy (core/sso_policy.py) only links or creates accounts on a verified one.
            "email_verified": user_info.get("email_verified") is True,
            "full_name": user_info.get("name", ""),
            "avatar_url": user_info.get("picture", ""),
        }


class MicrosoftOAuthService:
    """Microsoft Azure AD OAuth 2.0 / OpenID Connect."""

    def authorize_url(self, tenant_id: Optional[str] = None) -> str:
        tenant = tenant_id or settings.MICROSOFT_TENANT_ID or "common"
        return f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize"

    def token_url(self, tenant_id: Optional[str] = None) -> str:
        tenant = tenant_id or settings.MICROSOFT_TENANT_ID or "common"
        return f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"

    GRAPH_ME_URL = "https://graph.microsoft.com/v1.0/me"

    def get_authorization_url(self, redirect_uri: str, state: str = "", client_id: Optional[str] = None, tenant_id: Optional[str] = None) -> str:
        """Generate Microsoft OAuth authorization URL."""
        effective_client_id = client_id or settings.MICROSOFT_CLIENT_ID
        params = {
            "client_id": effective_client_id,
            "response_type": "code",
            "scope": "openid email profile User.Read",
            "redirect_uri": redirect_uri,
            "state": state,
            "response_mode": "query",
        }
        query = urlencode(params)
        return f"{self.authorize_url(tenant_id)}?{query}"

    async def exchange_code(self, code: str, redirect_uri: str, client_id: Optional[str] = None, client_secret: Optional[str] = None, tenant_id: Optional[str] = None) -> Dict:
        """Exchange authorization code for access token."""
        effective_client_id = client_id or settings.MICROSOFT_CLIENT_ID
        effective_client_secret = client_secret or settings.MICROSOFT_CLIENT_SECRET
        async with httpx.AsyncClient() as client:
            resp = await client.post(self.token_url(tenant_id), data={
                "code": code,
                "client_id": effective_client_id,
                "client_secret": effective_client_secret,
                "redirect_uri": redirect_uri,
                "grant_type": "authorization_code",
            })
            resp.raise_for_status()
            return resp.json()

    async def get_user_info(self, access_token: str) -> Dict:
        """Fetch user profile from Microsoft Graph API."""
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                self.GRAPH_ME_URL,
                headers={"Authorization": f"Bearer {access_token}"},
            )
            resp.raise_for_status()
            return resp.json()

    async def authenticate(self, code: str, redirect_uri: str, client_id: Optional[str] = None, client_secret: Optional[str] = None, tenant_id: Optional[str] = None) -> Dict:
        """Full Microsoft OAuth flow: exchange code → get user info."""
        tokens = await self.exchange_code(
            code,
            redirect_uri,
            client_id=client_id,
            client_secret=client_secret,
            tenant_id=tenant_id,
        )
        user_info = await self.get_user_info(tokens["access_token"])
        return {
            "provider": "microsoft",
            "oauth_id": user_info.get("id", ""),
            "email": user_info.get("mail") or user_info.get("userPrincipalName", ""),
            # Microsoft never verifies this address (it is a profile field an administrator of ANY tenant can set to anything): never trusted as proof of ownership.
            "email_verified": False,
            "full_name": user_info.get("displayName", ""),
            "avatar_url": None,
        }


# Singletons
google_oauth = GoogleOAuthService()
microsoft_oauth = MicrosoftOAuthService()
