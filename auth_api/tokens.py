"""App JWT minting/validation for the django-bolt port (replaces simplejwt).

django-bolt's Rust verifier validates HS256 tokens signed with settings.SECRET_KEY
and requires a `sub` claim (the user pk) which it exposes as request.context["user_id"].
Custom_User's pk is the UUID field `user_id` (the model sets `id = None`), so tokens
are minted here with sub=str(user.pk) — do NOT use django_bolt.auth.create_jwt_for_user,
it hardcodes user.id which is None on this model.

Lifetimes mirror the old SIMPLE_JWT config: access 30 days, refresh 1 day. The legacy
`user_id` claim is kept alongside `sub` for clients that decode tokens locally.
"""
from __future__ import annotations

import time
import uuid
from typing import Any, Optional

import jwt
from django.conf import settings

ACCESS_TOKEN_LIFETIME_SECONDS = int(getattr(settings, "BOLT_ACCESS_TOKEN_LIFETIME_SECONDS", 30 * 24 * 3600))
REFRESH_TOKEN_LIFETIME_SECONDS = int(getattr(settings, "BOLT_REFRESH_TOKEN_LIFETIME_SECONDS", 24 * 3600))
ALGORITHM = "HS256"


def _mint(user, token_type: str, lifetime: int) -> str:
    now = int(time.time())
    claims: dict[str, Any] = {
        "sub": str(user.pk),
        "user_id": str(user.pk),
        "token_type": token_type,
        "exp": now + lifetime,
        "iat": now,
        "jti": uuid.uuid4().hex,
        "is_staff": bool(getattr(user, "is_staff", False)),
        "is_superuser": bool(getattr(user, "is_superuser", False)),
        "username": getattr(user, "username", "") or "",
    }
    email = getattr(user, "email", None)
    if email:
        claims["email"] = email
    return jwt.encode(claims, settings.SECRET_KEY, algorithm=ALGORITHM)


def mint_access(user, lifetime: Optional[int] = None) -> str:
    return _mint(user, "access", lifetime or ACCESS_TOKEN_LIFETIME_SECONDS)


def mint_refresh(user, lifetime: Optional[int] = None) -> str:
    return _mint(user, "refresh", lifetime or REFRESH_TOKEN_LIFETIME_SECONDS)


def mint_pair(user, access_lifetime: Optional[int] = None, refresh_lifetime: Optional[int] = None) -> tuple[str, str]:
    """Return (access, refresh) for a user — the replacement for RefreshToken.for_user()."""
    return mint_access(user, access_lifetime), mint_refresh(user, refresh_lifetime)


def decode(raw: str, expected_type: Optional[str] = None) -> Optional[dict[str, Any]]:
    """Decode+verify a token; returns claims or None (invalid/expired/wrong type)."""
    try:
        claims = jwt.decode(raw, settings.SECRET_KEY, algorithms=[ALGORITHM])
    except Exception:
        return None
    if expected_type and claims.get("token_type") != expected_type:
        return None
    if not claims.get("sub") and not claims.get("user_id"):
        return None
    return claims


def user_id_from_claims(claims: dict[str, Any]) -> Optional[str]:
    return claims.get("sub") or claims.get("user_id")
