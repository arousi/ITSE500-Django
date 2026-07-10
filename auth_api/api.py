"""django-bolt port of auth_api (was auth_api/views.py, ~1700 lines of DRF).

Serves the same paths the DRF version did under /api/v1/auth_api/. Token minting
moved from simplejwt to auth_api.tokens (Bolt-native JWTs carrying `sub`); the
OAuth provider HTTP calls moved from blocking `requests` to async `httpx`.

Response-shape parity notes:
- login/register keep their first-sync payloads (built by user_mang.services).
- OAuth callbacks keep all three shapes: JSON, SSR-HTML (postMessage/window.close),
  and the mobile deep-link bridge page; /oauth/result/<state>/ stays the one-time
  bridge fetch.
- github/microsoft authorize: the DRF views passed a nonexistent `user=` kwarg to
  OAuthState.objects.create() (the field is `user_id`); ported with the correct
  field. google/openrouter authorize's `state_id` now returns the OAuthState pk
  (the DRF version stringified the related user object).
- OTP endpoints stay 410 Gone.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import secrets
import string
import urllib.parse
import uuid
from typing import Any, Optional

import httpx
from asgiref.sync import sync_to_async
from django.conf import settings
from django.utils import timezone
from django_bolt import BoltAPI
from django_bolt.auth import AllowAny, IsAuthenticated, JWTAuthentication
from django_bolt.responses import HTML, Redirect, Response

from user_mang import services
from user_mang.models.custom_user import Custom_User

from .models import OAuthState, ProviderOAuthToken
from .tokens import decode as decode_token
from .tokens import mint_access, mint_pair, user_id_from_claims

logger = logging.getLogger("auth_api")

api = BoltAPI(prefix="/api/v1/auth_api", trailing_slash="keep")

_AUTH = [JWTAuthentication()]
_OPEN = [AllowAny()]
_REQUIRED = [IsAuthenticated()]

OAUTH_STATE_TTL_SECONDS = 600  # 10 minutes


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------

def _body(request) -> dict:
    try:
        raw = request.body
        if not raw:
            return {}
        data = json.loads(raw)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _auth_user_id(request) -> Optional[str]:
    ctx = getattr(request, "context", None) or {}
    return ctx.get("user_id") or (ctx.get("auth_claims") or {}).get("user_id")


def _headers(request) -> dict:
    return dict(getattr(request, "headers", None) or {})


def _base_url(request) -> str:
    headers = _headers(request)
    proto = headers.get("x-forwarded-proto", "http")
    host = headers.get("x-forwarded-host") or headers.get("host") or ""
    return f"{proto}://{host}" if host else ""


def _abs_uri(request, path: str) -> str:
    base = _base_url(request)
    return f"{base}{path}" if base else path


def _backend_hash(front_hash: str) -> str:
    salt = getattr(settings, "BACKEND_PASSWORD_SALT", "fallback_dev_salt")
    return hashlib.sha256((front_hash + salt).encode("utf-8")).hexdigest()


def generate_code_verifier(length: int = 64) -> str:
    chars = string.ascii_letters + string.digits + "-._~"
    return "".join(secrets.choice(chars) for _ in range(length))


def generate_code_challenge(code_verifier: str) -> str:
    digest = hashlib.sha256(code_verifier.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).decode("utf-8").rstrip("=")


def _resolve_refresh_bridge(request, body: dict) -> tuple[Optional[Custom_User], Optional[str], Optional[str]]:
    """EmailPinVerify/SetPassword accept a refresh token when no access token is
    presented. Returns (user, minted_access, refresh_raw) or (None, None, None)."""
    headers = _headers(request)
    auth_header = headers.get("authorization", "")
    refresh_raw = (
        headers.get("x-refresh-token")
        or headers.get("refresh-token")
        or (auth_header.split(" ", 1)[1] if auth_header.lower().startswith("refresh ") else None)
        or body.get("refresh_token")
        or (getattr(request, "cookies", None) or {}).get("refresh_token")
    )
    if not refresh_raw:
        return None, None, None
    claims = decode_token(refresh_raw, expected_type="refresh")
    if not claims:
        return None, None, None
    user = Custom_User.objects.filter(pk=user_id_from_claims(claims)).first()
    if not user:
        return None, None, None
    return user, mint_access(user), refresh_raw


# --------------------------------------------------------------------------
# Simple endpoints
# --------------------------------------------------------------------------

@api.get("/health/")
@api.get("/health")
async def health_check(request):
    return Response({"status": "ok", "message": "Server is up"}, status_code=200)


def _login_core(identifier: Optional[str], pwd: Optional[str]) -> tuple[int, dict]:
    if not identifier:
        return 400, {"detail": "Identifier required"}
    user = None
    if "@" in str(identifier):
        user = Custom_User.objects.filter(email=identifier).first()
    if not user:
        user = Custom_User.objects.filter(username=identifier).first()
    if not user:
        return 401, {"detail": "Invalid credentials."}
    if pwd:  # empty/missing password keeps the legacy passwordless path below
        if user.user_password != _backend_hash(str(pwd)):
            return 401, {"detail": "Invalid credentials."}
    if not user.is_active:
        return 403, {"detail": "User account is Locked."}

    access, refresh = mint_pair(user)
    conversations, attachments = services.build_login_sync_payload(user)
    return 200, {
        "message": "Login successful",
        "user_id": str(user.pk),
        "access_token": access,
        "refresh_token": refresh,
        "email_verified": user.email_verified,
        "conversations": conversations,
        "attachments": attachments,
    }


@api.post("/login/")
@api.post("/login")
async def login(request):
    body = _body(request)
    identifier = body.get("identifier") or body.get("email") or body.get("username")
    pwd = body.get("user_password") if "user_password" in body else body.get("password")
    try:
        status, payload = await sync_to_async(_login_core)(identifier, pwd)
    except Exception:
        logger.exception("[login] server error")
        return Response({"detail": "Login failed due to a server error."}, status_code=500)
    return Response(payload, status_code=status)


def _register_core(body: dict) -> tuple[int, dict]:
    temp_id = (body.get("temp_id") or "").strip()
    device_id = (body.get("device_id") or "").strip()
    email = body.get("email")
    user_id = body.get("user_id") or body.get("uuid")
    username = body.get("username")

    user: Optional[Custom_User] = None
    if email:
        user = Custom_User.objects.filter(email=email).first()
    if not user and user_id:
        user = Custom_User.objects.filter(user_id=user_id).first()
    if not user and username:
        user = Custom_User.objects.filter(username=username).first()
    if not user and temp_id:
        user = Custom_User.objects.filter(temp_id=temp_id).first()

    # SECURITY: existing identifier -> no tokens, no user data.
    if user:
        logger.info(f"[register] attempt for existing account: email={email} identifier={user_id or username or temp_id}")
        try:
            if not user.email_verified:
                user.email_verified = True
                try:
                    user.save(update_fields=["email_verified"])
                except Exception:
                    user.save()
            return 200, {"detail": "Email already registered."}
        except Exception:
            logger.exception("[register] error while handling existing user")
        return 409, {"detail": "invalid credentials."}

    # Validation (RegisterSerializer parity)
    errors: dict[str, list] = {}
    if not username:
        errors["username"] = ["This field is required."]
    if not email:
        errors["email"] = ["This field is required."]
    elif "@" not in str(email):
        errors["email"] = ["Enter a valid email address."]
    raw_pw = str(body.get("user_password") or "")
    if raw_pw and len(raw_pw) < 6:
        errors["user_password"] = ["Password must be at least 6 characters."]
    if errors:
        return 400, errors

    try:
        user = Custom_User(
            username=username,
            email=email,
            user_password=_backend_hash(raw_pw) if raw_pw else None,
            email_verified=True,  # this phase auto-verifies email
        )
        if temp_id:
            user.temp_id = temp_id
            user.is_visitor = True
        user.full_clean()
        user.save()
    except Exception as e:
        detail = getattr(e, "message_dict", None)
        if detail:
            return 400, detail
        logger.exception("[register] unexpected registration error")
        return 500, {"detail": "Registration failed due to a server error."}

    devices = user.get_related_devices()
    if device_id and device_id not in devices:
        devices.append(device_id)
        user.set_related_devices(devices)
        user.last_login = timezone.now()
        user.save()

    access, refresh = mint_pair(user)
    return 201, {
        "message": "User created. Verification PIN sent to email.",
        "user_id": str(user.user_id),
        "access_token": access,
        "refresh_token": refresh,
        "email": user.email,
        "onboarding": True,
        "conversations": services.build_register_conversations(user),
        "temp_id": user.temp_id,
        "device_id": device_id,
        "related_devices": devices if device_id else [],
    }


@api.post("/register/")
@api.post("/register")
async def register(request):
    body = _body(request)
    status, payload = await sync_to_async(_register_core)(body)
    return Response(payload, status_code=status)


def _verify_pin_core(auth_uid: Optional[str], email: str, pin: str) -> tuple[int, dict]:
    acting_user = Custom_User.objects.filter(pk=auth_uid).first() if auth_uid else None
    if acting_user is None:
        return 401, {"detail": "Authentication required (access or refresh token)."}
    if acting_user.email and str(acting_user.email).lower() != str(email).lower():
        return 403, {"detail": "Email does not belong to the authenticated user."}
    user = Custom_User.objects.filter(email=email).first()
    if user is None:
        return 404, {"detail": "User not found."}
    stored_pin = user.email_pin
    matches = (stored_pin == int(pin)) if str(pin).isdigit() else (stored_pin == pin)
    if not matches:
        return 400, {"detail": "Invalid PIN."}
    created = user.email_pin_created
    if not created or (timezone.now() - created).total_seconds() > 600:
        return 400, {"detail": "PIN expired."}
    user.email_verified = True
    try:
        user.email_pin = None
        user.save(update_fields=["email_verified", "email_pin"])
    except Exception:
        user.save(update_fields=["email_verified"])
    return 200, {"message": "Email verified. You may now set your password."}


@api.post("/verify-email-pin/", auth=_AUTH, guards=_OPEN)
@api.post("/verify-email-pin", auth=_AUTH, guards=_OPEN)
async def verify_email_pin(request):
    body = _body(request)
    email, pin = body.get("email"), body.get("pin")
    if not email or not pin:
        return Response({"detail": "Invalid data."}, status_code=400)

    auth_uid = _auth_user_id(request)
    minted_access = minted_refresh = None
    if not auth_uid:
        user, minted_access, minted_refresh = await sync_to_async(_resolve_refresh_bridge)(request, body)
        if user is None:
            return Response({"detail": "Authentication required (access or refresh token)."}, status_code=401)
        auth_uid = str(user.pk)

    status, payload = await sync_to_async(_verify_pin_core)(auth_uid, email, str(pin))
    headers = {}
    if status == 200 and minted_access:
        headers["X-New-Access-Token"] = minted_access
        headers["X-New-Refresh-Token"] = minted_refresh or ""
    return Response(payload, status_code=status, headers=headers)


def _set_password_core(auth_uid: Optional[str], email: str, front_hash: str) -> tuple[int, dict]:
    acting_user = Custom_User.objects.filter(pk=auth_uid).first() if auth_uid else None
    if acting_user is None:
        return 401, {"detail": "Authentication required (access or refresh token)."}
    user = Custom_User.objects.filter(email=email).first()
    if user is None:
        return 404, {"detail": "User not found."}
    if acting_user.email and str(acting_user.email).lower() != str(email).lower():
        return 403, {"detail": "Email does not belong to the authenticated user."}
    if not user.email_verified:
        return 400, {"detail": "Email not verified."}
    user.user_password = _backend_hash(front_hash)
    user.save(update_fields=["user_password"])
    return 200, {"message": "Password set successfully. You may now log in."}


@api.post("/set-password-after-email-verify/", auth=_AUTH, guards=_OPEN)
@api.post("/set-password-after-email-verify", auth=_AUTH, guards=_OPEN)
async def set_password_after_email_verify(request):
    body = _body(request)
    email, password = body.get("email"), body.get("password")
    if not email or not password or len(str(password)) < 6:
        return Response({"detail": "Invalid data."}, status_code=400)

    auth_uid = _auth_user_id(request)
    minted_access = minted_refresh = None
    if not auth_uid:
        user, minted_access, minted_refresh = await sync_to_async(_resolve_refresh_bridge)(request, body)
        if user is None:
            return Response({"detail": "Authentication required (access or refresh token)."}, status_code=401)
        auth_uid = str(user.pk)

    status, payload = await sync_to_async(_set_password_core)(auth_uid, email, str(password))
    headers = {}
    if status == 200 and minted_access:
        headers["X-New-Access-Token"] = minted_access
        headers["X-New-Refresh-Token"] = minted_refresh or ""
    return Response(payload, status_code=status, headers=headers)


@api.post("/logout/", auth=_AUTH, guards=_REQUIRED)
@api.post("/logout", auth=_AUTH, guards=_REQUIRED)
async def logout(request):
    # No server-side token deletion/blacklisting (parity with the DRF view):
    # provider OAuth tokens stay intact and clients discard JWTs client-side.
    logger.info(f"[logout] user_id={_auth_user_id(request)}")
    return Response({"detail": "Logged out successfully. Please discard tokens client-side."}, status_code=200)


@api.post("/token/refresh/")
@api.post("/token/refresh")
async def token_refresh(request):
    body = _body(request)
    raw = body.get("refresh")
    if not raw:
        return Response({"refresh": ["This field is required."]}, status_code=400)
    claims = decode_token(str(raw), expected_type="refresh")
    if not claims:
        return Response({"detail": "Token is invalid or expired", "code": "token_not_valid"}, status_code=401)
    user = await Custom_User.objects.filter(pk=user_id_from_claims(claims)).afirst()
    if user is None or not user.is_active:
        return Response({"detail": "Token is invalid or expired", "code": "token_not_valid"}, status_code=401)
    return Response({"access": mint_access(user)}, status_code=200)


@api.post("/otp-login/")
@api.post("/otp-login")
async def otp_login(request):
    return Response({"detail": "OTP endpoints are deprecated in this release."}, status_code=410)


# --------------------------------------------------------------------------
# OAuth: provider HTTP calls (async httpx)
# --------------------------------------------------------------------------

async def _exchange_google(code: str, code_verifier: str, redirect_uri: str) -> tuple[int, dict]:
    token_url = getattr(settings, "GOOGLE_OAUTH_TOKEN_URL", "https://oauth2.googleapis.com/token")
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": getattr(settings, "GOOGLE_OAUTH_CLIENT_ID", ""),
        "code_verifier": code_verifier,
        "client_secret": getattr(settings, "GOOGLE_OAUTH_CLIENT_SECRET", ""),
    }
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.post(token_url, data=data)
    try:
        payload = resp.json()
    except Exception:
        payload = {"raw": resp.text}
    return resp.status_code, payload


async def _fetch_google_userinfo(access_token: str) -> Optional[dict]:
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(
                "https://openidconnect.googleapis.com/v1/userinfo",
                headers={"Authorization": f"Bearer {access_token}"},
            )
        return r.json() if r.status_code == 200 else None
    except Exception:
        return None


async def _exchange_openrouter(code: str, code_verifier: str, redirect_uri: str) -> tuple[int, dict]:
    token_url = getattr(settings, "OPENROUTER_TOKEN_URL", "https://openrouter.ai/api/v1/auth/keys")
    json_body: dict[str, Any] = {
        "code": code,
        "code_verifier": code_verifier,
        "code_challenge_method": "S256",
    }
    if redirect_uri:
        json_body["callback_url"] = redirect_uri
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.post(token_url, json=json_body)
    try:
        payload = resp.json()
    except Exception:
        payload = {"raw": resp.text}
    return resp.status_code, payload


def build_google_authorize_url(state: str, code_challenge: str, scope: str, redirect_uri: str) -> str:
    base_auth = getattr(settings, "GOOGLE_OAUTH_AUTH_URL", "https://accounts.google.com/o/oauth2/v2/auth")
    client_id = getattr(settings, "GOOGLE_OAUTH_CLIENT_ID", "")
    return (
        f"{base_auth}?response_type=code&client_id={client_id}"
        f"&redirect_uri={redirect_uri}&scope={scope}&state={state}&access_type=offline&prompt=consent"
        f"&code_challenge={code_challenge}&code_challenge_method=S256"
    )


def build_openrouter_authorize_url(state: str, code_challenge: str, scope: str, redirect_uri: str) -> str:
    base_auth = getattr(settings, "OPENROUTER_AUTH_URL", "https://openrouter.ai/auth")
    params = {
        "callback_url": redirect_uri,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "state": state,
    }
    if scope:
        params["scope"] = scope
    return f"{base_auth}?{urllib.parse.urlencode(params)}"


# --------------------------------------------------------------------------
# OAuth: sync DB stages
# --------------------------------------------------------------------------

def _create_oauth_state(provider: str, state: str, code_challenge: Optional[str],
                        code_verifier: Optional[str], redirect_uri: Optional[str],
                        mobile_redirect: Optional[str], scope: str,
                        auth_uid: Optional[str]) -> OAuthState:
    user = Custom_User.objects.filter(pk=auth_uid).first() if auth_uid else None
    return OAuthState.objects.create(
        provider=provider,
        state=state,
        code_challenge=code_challenge or "",
        code_verifier=code_verifier,
        redirect_uri=redirect_uri,
        mobile_redirect=mobile_redirect,
        scope=scope,
        expires_at=timezone.now() + timezone.timedelta(seconds=OAUTH_STATE_TTL_SECONDS),
        user_id=user,
    )


def _load_oauth_state(state_value: str, provider: str) -> Optional[OAuthState]:
    return OAuthState.objects.select_related("user_id").filter(state=state_value, provider=provider).first()


def _persist_result_payload(oauth_state: OAuthState, payload: dict) -> None:
    try:
        oauth_state.result_payload = json.dumps(payload)
        oauth_state.save(update_fields=["result_payload"])
    except Exception:
        logger.exception(f"[oauth] failed to persist result_payload for state={oauth_state.state}")


def _finalize_google(oauth_state: OAuthState, token_payload: dict, userinfo: Optional[dict]) -> dict:
    access_token = token_payload.get("access_token")
    refresh_token = token_payload.get("refresh_token")
    expires_in = token_payload.get("expires_in")
    id_token = token_payload.get("id_token")
    email = (userinfo or {}).get("email")
    email_verified_claim = (userinfo or {}).get("email_verified")

    user = oauth_state.user_id
    if not user:
        if email and Custom_User.objects.filter(email=email).exists():
            user = Custom_User.objects.get(email=email)
        else:
            base_username = email.split("@")[0] if email else f"g_{uuid.uuid4().hex[:6]}"
            candidate, idx = base_username, 1
            while Custom_User.objects.filter(username=candidate).exists():
                candidate = f"{base_username}{idx}"
                idx += 1
            user = Custom_User.objects.create(
                username=candidate,
                email=email or f"pending_{uuid.uuid4().hex}@google.local",
                email_verified=bool(email_verified_claim) if email_verified_claim is not None else bool(email),
                is_google_user=True,
            )
    else:
        update_fields: list[str] = []
        if email and not user.email:
            user.email = email
            update_fields.append("email")
        if not user.is_google_user:
            user.is_google_user = True
            update_fields.append("is_google_user")
        if email and not user.email_verified and (email_verified_claim is None or bool(email_verified_claim)):
            user.email_verified = True
            update_fields.append("email_verified")
        if update_fields:
            user.save(update_fields=update_fields)

    expires_sec = 0
    if expires_in not in (None, ""):
        try:
            expires_sec = int(expires_in)
        except Exception:
            expires_sec = 0
    expires_at = timezone.now() + timezone.timedelta(seconds=expires_sec) if expires_sec else None
    ProviderOAuthToken.objects.update_or_create(
        user_id=user,
        provider="google",
        defaults={
            "access_token": access_token,
            "refresh_token": refresh_token,
            "expires_at": expires_at,
            "scope": oauth_state.scope,
            "token_type": token_payload.get("token_type") or "Bearer",
        },
    )
    oauth_state.mark_used()
    access, refresh = mint_pair(user)
    payload = {
        "message": "Google OAuth success",
        "user_id": str(user.pk),
        "username": user.username,
        "access_token": access,
        "refresh_token": refresh,
        "provider_scope": oauth_state.scope,
        "provider_expires_at": expires_at.isoformat() if expires_at else None,
        "id_token": id_token,
        "email": email,
        "email_verified": user.email_verified,
        "is_google_user": user.is_google_user,
    }
    _persist_result_payload(oauth_state, payload)
    return payload


def _finalize_openrouter(oauth_state: OAuthState, token_payload: dict) -> tuple[Optional[dict], Optional[dict]]:
    access_token = token_payload.get("key") or token_payload.get("access_token")
    if not access_token:
        return None, {"detail": "Provider did not return API key", "provider_payload": token_payload}
    user = oauth_state.user_id
    if not user:
        user = Custom_User.objects.create(
            username=f"or_{uuid.uuid4().hex[:10]}",
            email=f"pending_{uuid.uuid4().hex}@openrouter.local",
            is_openrouter_user=True,
        )
    elif not user.is_openrouter_user:
        user.is_openrouter_user = True
        user.save(update_fields=["is_openrouter_user"])
    ProviderOAuthToken.objects.update_or_create(
        user_id=user,
        provider="openrouter",
        defaults={
            "access_token": access_token,
            "refresh_token": None,
            "expires_at": None,
            "scope": oauth_state.scope,
            "token_type": "api_key",
        },
    )
    oauth_state.mark_used()
    access, refresh = mint_pair(user)
    payload = {
        "message": "OpenRouter OAuth success",
        "user_id": str(user.pk),
        "access_token": access,
        "refresh_token": refresh,
        "provider_access_token": access_token if getattr(settings, "OPENROUTER_EXPOSE_PROVIDER_TOKEN", True) else None,
        "provider_refresh_token": None,
        "provider_token_type": "api_key",
        "provider_scope": oauth_state.scope,
        "provider_expires_at": None,
        "is_openrouter_user": user.is_openrouter_user,
    }
    _persist_result_payload(oauth_state, payload)
    return payload, None


def _finalize_github(oauth_state: OAuthState, access_token: str, token_data: dict,
                     user_data: dict, email: Optional[str]) -> dict:
    user = oauth_state.user_id
    if not user:
        if email and Custom_User.objects.filter(email=email).exists():
            user = Custom_User.objects.get(email=email)
        else:
            base_username = user_data.get("login") or f"gh_{uuid.uuid4().hex[:6]}"
            candidate, idx = base_username, 1
            while Custom_User.objects.filter(username=candidate).exists():
                candidate = f"{base_username}{idx}"
                idx += 1
            user = Custom_User.objects.create(
                username=candidate,
                email=email or f"pending_{uuid.uuid4().hex}@github.local",
                email_verified=bool(email),
                is_github_user=True,
            )
    else:
        update_fields = []
        if email and not user.email:
            user.email = email
            update_fields.append("email")
        if not user.is_github_user:
            user.is_github_user = True
            update_fields.append("is_github_user")
        if email and not user.email_verified:
            user.email_verified = True
            update_fields.append("email_verified")
        if update_fields:
            user.save(update_fields=update_fields)
    ProviderOAuthToken.objects.update_or_create(
        user_id=user,
        provider="github",
        defaults={
            "access_token": access_token,
            "refresh_token": None,
            "expires_at": None,
            "scope": oauth_state.scope,
            "token_type": token_data.get("token_type") or "Bearer",
        },
    )
    oauth_state.mark_used()
    access, refresh = mint_pair(user)
    return {
        "message": "GitHub OAuth success",
        "user_id": str(user.pk),
        "username": user.username,
        "access_token": access,
        "refresh_token": refresh,
        "provider_scope": oauth_state.scope,
        "provider_access_token": access_token,
        "provider_expires_at": None,
        "email": email,
        "email_verified": user.email_verified,
        "is_github_user": user.is_github_user,
    }


def _finalize_microsoft(oauth_state: OAuthState, access_token: str, token_data: dict,
                        user_data: dict, email: Optional[str]) -> dict:
    user = oauth_state.user_id
    if not user:
        if email and Custom_User.objects.filter(email=email).exists():
            user = Custom_User.objects.get(email=email)
        else:
            base_username = email.split("@")[0] if email else f"ms_{uuid.uuid4().hex[:6]}"
            candidate, idx = base_username, 1
            while Custom_User.objects.filter(username=candidate).exists():
                candidate = f"{base_username}{idx}"
                idx += 1
            user = Custom_User.objects.create(
                username=candidate,
                email=email or f"pending_{uuid.uuid4().hex}@ms.local",
                email_verified=bool(email),
                is_microsoft_user=True,
            )
    else:
        update_fields = []
        if email and not user.email:
            user.email = email
            update_fields.append("email")
        if not user.is_microsoft_user:
            user.is_microsoft_user = True
            update_fields.append("is_microsoft_user")
        if email and not user.email_verified:
            user.email_verified = True
            update_fields.append("email_verified")
        if update_fields:
            user.save(update_fields=update_fields)
    ProviderOAuthToken.objects.update_or_create(
        user_id=user,
        provider="microsoft",
        defaults={
            "access_token": access_token,
            "refresh_token": token_data.get("refresh_token"),
            "expires_at": None,
            "scope": oauth_state.scope,
            "token_type": token_data.get("token_type") or "Bearer",
        },
    )
    oauth_state.mark_used()
    access, refresh = mint_pair(user)
    return {
        "message": "Microsoft OAuth success",
        "user_id": str(user.pk),
        "username": user.username,
        "access_token": access,
        "refresh_token": refresh,
        "provider_scope": oauth_state.scope,
        "provider_access_token": access_token,
        "provider_expires_at": None,
        "email": email,
        "email_verified": user.email_verified,
        "is_ms_user": getattr(user, "is_ms_user", False),
    }


# --------------------------------------------------------------------------
# OAuth: HTML shells (SSR close-tab page + mobile deep-link bridge)
# --------------------------------------------------------------------------

_SSR_DONE_HTML = """
<html>
<head>
    <title>Authentication Complete</title>
    <style>
    body { font-family: -apple-system, BlinkMacSystemFont, Segoe UI, Roboto, Helvetica, Arial, sans-serif; text-align: center; margin-top: 10%; color: #1b1f23; }
    .msg { font-size: 1.25rem; color: #2e7d32; margin-bottom: 0.5rem; }
    .sub { color: #586069; font-size: 0.95rem; }
    .spinner { margin: 1.25rem auto; width: 36px; height: 36px; border: 3px solid #e1e4e8; border-top-color: #2ea44f; border-radius: 50%; animation: spin 1s linear infinite; }
    @keyframes spin { to { transform: rotate(360deg); } }
    </style>
</head>
<body>
    <div class="msg">Authentication complete. You can close this tab.</div>
    <div class="sub">We'll finish signing you in back in the app.</div>
    <div class="spinner" aria-hidden="true"></div>
    <script>
    try {
      if (window.opener) {
        window.opener.postMessage({ success: true, type: "oauth" }, "*");
      }
      setTimeout(function(){ window.close(); }, 600);
    } catch (e) { /* no-op */ }
    </script>
</body>
</html>
"""


def _bridge_html(target: str) -> str:
    return f"""
    <html>
    <head>
        <title>Continue in App</title>
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, Segoe UI, Roboto, Helvetica, Arial, sans-serif; text-align: center; margin-top: 12%; color: #1b1f23; }}
        .msg {{ font-size: 1.15rem; margin-bottom: 0.75rem; }}
        .sub {{ color: #586069; font-size: 0.95rem; margin-bottom: 1rem; }}
        .btn {{ display: inline-block; background: #2ea44f; color: #fff; padding: 0.65rem 1rem; border-radius: 6px; text-decoration: none; }}
        .hint {{ margin-top: 0.75rem; font-size: 0.9rem; color: #6a737d; }}
        </style>
        <script>
          function openApp() {{
            try {{ window.location.href = {json.dumps(target)}; }} catch (e) {{ }}
          }}
          window.addEventListener('load', function() {{ setTimeout(openApp, 150); }});
        </script>
    </head>
    <body>
        <div class="msg">Authentication complete. Returning to the app…</div>
        <div class="sub">If nothing happens, tap the button below.</div>
        <p><a class="btn" href="{target}">Open the app</a></p>
        <div class="hint">You can close this tab after the app opens.</div>
    </body>
    </html>
    """


def _callback_response(request, params: dict, oauth_state: OAuthState, payload: dict):
    """Pick the response shape: mobile deep-link bridge, SSR-HTML, or JSON."""
    if oauth_state.mobile_redirect:
        target = f"{oauth_state.mobile_redirect.rstrip('/')}?state={urllib.parse.quote(oauth_state.state)}&bridge=1"
        if target.startswith("http://") or target.startswith("https://"):
            return Redirect(target, status_code=302)
        return HTML(_bridge_html(target))

    accepts = (_headers(request).get("accept", "") or "").lower()
    wants_html = ("text/html" in accepts) and ("application/json" not in accepts)
    if request.path.endswith("/callback/ssr/") or params.get("render") == "1" or wants_html:
        return HTML(_SSR_DONE_HTML)
    return Response(payload)


def _check_state(oauth_state: Optional[OAuthState], error: str, code: str):
    """Shared state validation; returns an error/idempotent Response or None to proceed."""
    if oauth_state is None:
        return Response({"detail": "Invalid state"}, status_code=400)
    if error:
        return Response({"detail": error}, status_code=400)
    if oauth_state.used and not oauth_state.is_expired():
        if oauth_state.result_payload:
            try:
                data = json.loads(oauth_state.result_payload)
                data["idempotent"] = True
                return Response(data)
            except Exception:
                pass
        return Response({"detail": "State already used", "error_code": "state_used"}, status_code=409)
    if oauth_state.is_expired():
        return Response({"detail": "State expired", "error_code": "state_expired"}, status_code=400)
    if not code:
        return Response({"detail": "Missing authorization code"}, status_code=400)
    return None


# --------------------------------------------------------------------------
# OAuth: authorize endpoints
# --------------------------------------------------------------------------

def _looks_local(u: str) -> bool:
    return any(h in u for h in ("127.0.0.1", "localhost", "10.0.2.2"))


async def _authorize_google_or_openrouter(request, provider: str):
    q = dict(getattr(request, "query", None) or {})
    scope = q.get("scope") or "openid"
    orig_redirect = q.get("redirect_uri")
    callback_host = q.get("callback_host")
    mobile_redirect: Optional[str] = None

    if provider == "google":
        scope_parts = [s for s in scope.split() if s and s != "offline_access"]
        for required in ("openid", "email", "profile"):
            if required not in scope_parts:
                scope_parts.append(required)
        scope = " ".join(scope_parts)
        redirect_uri = orig_redirect or getattr(settings, "GOOGLE_OAUTH_REDIRECT_URI", "")
        if callback_host:
            allowed_hosts = {"10.0.2.2", "127.0.0.1"} | set(getattr(settings, "OAUTH_CALLBACK_HOST_ALLOWLIST", []))
            if any(callback_host.startswith(prefix) for prefix in ("192.168.", "10.0.2.")):
                allowed_hosts.add(callback_host.split(":")[0])
            if callback_host.split(":")[0] in allowed_hosts:
                host_part = callback_host if ":" in callback_host else f"{callback_host}:8000"
                redirect_uri = f"http://{host_part}/api/v1/auth_api/google/callback/"
        if redirect_uri and (redirect_uri.startswith("prompeteer://") or redirect_uri.startswith("app://")):
            mobile_redirect = redirect_uri.rstrip("/")
            redirect_uri = getattr(settings, "GOOGLE_OAUTH_REDIRECT_URI", "")
        built_callback = _abs_uri(request, "/api/v1/auth_api/google/callback/")
        if not redirect_uri or _looks_local(redirect_uri):
            if built_callback:
                redirect_uri = built_callback
        if redirect_uri and not redirect_uri.endswith("/"):
            redirect_uri += "/"
        if not redirect_uri:
            return Response({"detail": "redirect_uri not configured"}, status_code=400)
        code_verifier = generate_code_verifier()
        code_challenge = generate_code_challenge(code_verifier)
        authorize_url_builder = build_google_authorize_url
    else:  # openrouter
        if "offline_access" not in scope.split():
            scope = scope + " offline_access"
        redirect_uri = orig_redirect or getattr(settings, "OPENROUTER_REDIRECT_URI", "")
        if redirect_uri and (redirect_uri.startswith("prompeteer://") or redirect_uri.startswith("app://")):
            mobile_redirect = redirect_uri.rstrip("/")
            redirect_uri = getattr(settings, "OPENROUTER_REDIRECT_URI", "")
        if not redirect_uri:
            redirect_uri = _abs_uri(request, "/api/v1/auth_api/openrouter/callback/")
            if not redirect_uri:
                return Response({"detail": "redirect_uri not configured"}, status_code=400)
        code_verifier = generate_code_verifier()
        code_challenge = generate_code_challenge(code_verifier)
        authorize_url_builder = build_openrouter_authorize_url

    state = secrets.token_urlsafe(24)
    oauth_state = await sync_to_async(_create_oauth_state)(
        provider, state, code_challenge, code_verifier, redirect_uri, mobile_redirect, scope, _auth_user_id(request)
    )
    authorize_url = authorize_url_builder(state, code_challenge, scope, redirect_uri)
    logger.info(f"[{provider}Authorize] created state={state} redirect_uri={redirect_uri} mobile_redirect={mobile_redirect}")

    if q.get("mode") == "redirect" or "authorize/ssr" in request.path:
        return Redirect(authorize_url, status_code=302)
    return Response({
        "authorize_url": authorize_url,
        "state": state,
        "state_id": str(oauth_state.oauth_state_id),
        "expires_at": oauth_state.expires_at.isoformat(),
        "bridge": bool(mobile_redirect),
    })


@api.get("/google/authorize")
@api.get("/google/authorize/")
@api.get("/google/authorize/ssr")
@api.get("/google/authorize/ssr/")
@api.get("/google/oauth")
@api.get("/google/oauth/")
async def google_authorize(request):
    return await _authorize_google_or_openrouter(request, "google")


@api.get("/openrouter/authorize")
@api.get("/openrouter/authorize/")
@api.get("/openrouter/authorize/ssr")
@api.get("/openrouter/authorize/ssr/")
@api.get("/openrouter/oauth")
@api.get("/openrouter/oauth/")
async def openrouter_authorize(request):
    return await _authorize_google_or_openrouter(request, "openrouter")


async def _authorize_simple(request, provider: str, default_scope: str, redirect_setting: str,
                            url_builder) -> Any:
    q = dict(getattr(request, "query", None) or {})
    scope = q.get("scope", default_scope)
    redirect_uri = getattr(settings, redirect_setting, "")
    if not redirect_uri:
        return Response({"detail": "redirect_uri not configured"}, status_code=400)
    state = secrets.token_urlsafe(24)
    oauth_state = await sync_to_async(_create_oauth_state)(
        provider, state, None, None, redirect_uri, None, scope, _auth_user_id(request)
    )
    authorize_url = url_builder(state, scope, redirect_uri)
    if q.get("mode") == "redirect" or "authorize/ssr" in request.path:
        return Redirect(authorize_url, status_code=302)
    return Response({
        "authorize_url": authorize_url,
        "state": state,
        "state_id": str(oauth_state.oauth_state_id),
        "expires_at": oauth_state.expires_at.isoformat(),
        "bridge": False,
    })


def _github_authorize_url(state: str, scope: str, redirect_uri: str) -> str:
    params = {
        "client_id": getattr(settings, "GITHUB_CLIENT_ID", ""),
        "redirect_uri": redirect_uri,
        "scope": scope,
        "state": state,
        "allow_signup": "true",
    }
    return f"https://github.com/login/oauth/authorize?{urllib.parse.urlencode(params)}"


def _microsoft_authorize_url(state: str, scope: str, redirect_uri: str) -> str:
    params = {
        "client_id": getattr(settings, "MS_CLIENT_ID", ""),
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "response_mode": "query",
        "scope": scope,
        "state": state,
    }
    return f"https://login.microsoftonline.com/common/oauth2/v2.0/authorize?{urllib.parse.urlencode(params)}"


@api.get("/github/authorize")
@api.get("/github/authorize/")
@api.get("/github/authorize/ssr")
@api.get("/github/authorize/ssr/")
async def github_authorize(request):
    return await _authorize_simple(request, "github", "read:user user:email", "GITHUB_REDIRECT_URI", _github_authorize_url)


@api.get("/microsoft/authorize")
@api.get("/microsoft/authorize/")
@api.get("/microsoft/authorize/ssr")
@api.get("/microsoft/authorize/ssr/")
async def microsoft_authorize(request):
    return await _authorize_simple(request, "microsoft", "openid email profile User.Read", "MS_REDIRECT_URI", _microsoft_authorize_url)


# --------------------------------------------------------------------------
# OAuth: callback endpoints
# --------------------------------------------------------------------------

def _callback_params(request) -> dict:
    params = dict(getattr(request, "query", None) or {})
    if request.method == "POST":
        params.update({k: v for k, v in _body(request).items() if v is not None})
    return params


async def _google_callback(request):
    params = _callback_params(request)
    state_value = params.get("state") or ""
    code = params.get("code") or ""
    error = params.get("error") or ""
    logger.info(f"[GoogleCallback] state={state_value} error={error} code_present={bool(code)}")

    oauth_state = await sync_to_async(_load_oauth_state)(state_value, "google")
    early = _check_state(oauth_state, error, code)
    if early is not None:
        return early

    # Use the exact callback URL Google just hit to avoid redirect_uri mismatch.
    redirect_used = _abs_uri(request, request.path.split("?")[0]) or str(oauth_state.redirect_uri or "")
    if redirect_used and not redirect_used.endswith("/"):
        redirect_used += "/"
    if oauth_state.redirect_uri and str(oauth_state.redirect_uri) != redirect_used:
        logger.info(f"[GoogleCallback] redirect_uri mismatch: stored={oauth_state.redirect_uri} used={redirect_used}")
        try:
            oauth_state.redirect_uri = redirect_used
            await sync_to_async(oauth_state.save)(update_fields=["redirect_uri"])
        except Exception:
            logger.debug("[GoogleCallback] failed to persist adjusted redirect_uri; continuing")

    status_code, token_payload = await _exchange_google(code, str(oauth_state.code_verifier or ""), redirect_used)
    if status_code != 200:
        return Response({"detail": "Token exchange failed", "provider_payload": token_payload}, status_code=400)
    userinfo = await _fetch_google_userinfo(token_payload.get("access_token")) if token_payload.get("access_token") else None
    payload = await sync_to_async(_finalize_google)(oauth_state, token_payload, userinfo)
    return _callback_response(request, params, oauth_state, payload)


@api.get("/google/callback/")
@api.get("/google/callback")
async def google_callback(request):
    return await _google_callback(request)


@api.post("/google/callback/")
@api.post("/google/callback")
async def google_callback_post(request):
    return await _google_callback(request)


async def _openrouter_callback(request):
    params = _callback_params(request)
    state_value = params.get("state") or ""
    code = params.get("code") or ""
    error = params.get("error") or ""
    logger.info(f"[OpenRouterCallback] state={state_value} error={error} code_present={bool(code)}")

    oauth_state = await sync_to_async(_load_oauth_state)(state_value, "openrouter")
    early = _check_state(oauth_state, error, code)
    if early is not None:
        return early

    status_code, token_payload = await _exchange_openrouter(
        code, str(oauth_state.code_verifier or ""), str(oauth_state.redirect_uri or "")
    )
    if status_code != 200:
        return Response({"detail": "Token exchange failed", "provider_payload": token_payload}, status_code=400)
    payload, err = await sync_to_async(_finalize_openrouter)(oauth_state, token_payload)
    if err is not None:
        return Response(err, status_code=400)
    return _callback_response(request, params, oauth_state, payload)


@api.get("/openrouter/callback/")
@api.get("/openrouter/callback")
async def openrouter_callback(request):
    return await _openrouter_callback(request)


@api.post("/openrouter/callback/")
@api.post("/openrouter/callback")
async def openrouter_callback_post(request):
    return await _openrouter_callback(request)


@api.get("/github/callback/")
@api.get("/github/callback")
async def github_callback(request):
    params = _callback_params(request)
    state_value = params.get("state") or ""
    code = params.get("code") or ""

    oauth_state = await sync_to_async(_load_oauth_state)(state_value, "github")
    early = _check_state(oauth_state, params.get("error") or "", code)
    if early is not None:
        return early

    async with httpx.AsyncClient(timeout=15) as client:
        token_resp = await client.post(
            "https://github.com/login/oauth/access_token",
            data={
                "client_id": getattr(settings, "GITHUB_CLIENT_ID", ""),
                "client_secret": getattr(settings, "GITHUB_CLIENT_SECRET", ""),
                "code": code,
                "redirect_uri": oauth_state.redirect_uri,
                "state": state_value,
            },
            headers={"Accept": "application/json"},
        )
        try:
            token_data = token_resp.json()
        except Exception:
            token_data = {"raw": token_resp.text}
        access_token = token_data.get("access_token")
        if not access_token:
            return Response({"detail": "Token exchange failed", "provider_payload": token_data}, status_code=400)
        user_resp = await client.get(
            "https://api.github.com/user",
            headers={"Authorization": f"token {access_token}"},
        )
        user_data = user_resp.json()
        email = user_data.get("email")
        if not email:
            emails_resp = await client.get(
                "https://api.github.com/user/emails",
                headers={"Authorization": f"token {access_token}"},
            )
            emails = emails_resp.json()
            if isinstance(emails, list):
                primary = next((e for e in emails if e.get("primary")), None)
                email = primary.get("email") if primary else None

    payload = await sync_to_async(_finalize_github)(oauth_state, access_token, token_data, user_data, email)
    if request.path.endswith("/callback/ssr/") or params.get("render") == "1":
        return HTML(_SSR_DONE_HTML)
    return Response(payload)


@api.get("/microsoft/callback/")
@api.get("/microsoft/callback")
async def microsoft_callback(request):
    params = _callback_params(request)
    state_value = params.get("state") or ""
    code = params.get("code") or ""

    oauth_state = await sync_to_async(_load_oauth_state)(state_value, "microsoft")
    early = _check_state(oauth_state, params.get("error") or "", code)
    if early is not None:
        return early

    async with httpx.AsyncClient(timeout=15) as client:
        token_resp = await client.post(
            "https://login.microsoftonline.com/common/oauth2/v2.0/token",
            data={
                "client_id": getattr(settings, "MS_CLIENT_ID", ""),
                "client_secret": getattr(settings, "MS_CLIENT_SECRET", ""),
                "code": code,
                "redirect_uri": oauth_state.redirect_uri,
                "grant_type": "authorization_code",
                "scope": oauth_state.scope,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        try:
            token_data = token_resp.json()
        except Exception:
            token_data = {"raw": token_resp.text}
        access_token = token_data.get("access_token")
        if not access_token:
            return Response({"detail": "Token exchange failed", "provider_payload": token_data}, status_code=400)
        user_resp = await client.get(
            "https://graph.microsoft.com/v1.0/me",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        user_data = user_resp.json()
        email = user_data.get("mail") or user_data.get("userPrincipalName")

    payload = await sync_to_async(_finalize_microsoft)(oauth_state, access_token, token_data, user_data, email)
    if request.path.endswith("/callback/ssr/") or params.get("render") == "1":
        return HTML(_SSR_DONE_HTML)
    return Response(payload)


# --------------------------------------------------------------------------
# OAuth: bridge result fetch (one-time)
# --------------------------------------------------------------------------

def _fetch_result(state_value: str) -> tuple[int, dict]:
    oauth_state = OAuthState.objects.filter(state=state_value).first()
    if oauth_state is None:
        return 404, {"detail": "Not found"}
    if not oauth_state.result_payload:
        logger.warning(f"[OAuthResult] not ready for state={state_value} (used={oauth_state.used})")
        return 202, {"detail": "Result not ready"}
    if oauth_state.result_retrieved:
        return 410, {"detail": "Result already retrieved"}
    data = json.loads(oauth_state.result_payload)
    oauth_state.result_retrieved = True
    oauth_state.save(update_fields=["result_retrieved"])
    return 200, data


@api.get("/oauth/result/{state_value}/")
@api.get("/oauth/result/{state_value}")
async def oauth_result(request, state_value: str):
    status, payload = await sync_to_async(_fetch_result)(state_value)
    return Response(payload, status_code=status)
