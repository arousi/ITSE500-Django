"""django-bolt port of user_mang (was user_mang/views.py: UnifiedSyncView).

Serves the same path the DRF version did — /api/v1/user_mang/me/ — with GET/POST/
PATCH/DELETE. JWT auth is optional per-route (AllowAny): authenticated requests act
on the token's user; unauthenticated requests may use the visitor temp_id flow.

Blocking ORM/serializer logic lives in user_mang.services and runs via sync_to_async
(the POST upsert keeps its transaction.atomic semantics that way).
"""
from __future__ import annotations

import json
import logging
from typing import Optional

from asgiref.sync import sync_to_async
from django.conf import settings
from django_bolt import BoltAPI
from django_bolt.auth import AllowAny, JWTAuthentication
from django_bolt.responses import FileResponse, Response

from auth_api.tokens import mint_access, mint_refresh
from user_mang import services
from user_mang.models.custom_user import Custom_User

logger = logging.getLogger("user_mang")

api = BoltAPI(prefix="/api/v1/user_mang")

_AUTH = [JWTAuthentication()]
_OPEN = [AllowAny()]


def _auth_user_id(request) -> Optional[str]:
    ctx = getattr(request, "context", None) or {}
    return ctx.get("user_id") or (ctx.get("auth_claims") or {}).get("user_id")


def _body(request) -> dict:
    try:
        raw = request.body
        if not raw:
            return {}
        data = json.loads(raw)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _params(request, body: dict) -> dict:
    """Merged query+body params the DRF view read from both places."""
    q = dict(getattr(request, "query", None) or {})
    merged: dict = {}
    for key in ("temp_id", "device_id", "user_id", "profile", "chat", "allow_public_uuid",
                "action", "reason", "download_now", "download", "export"):
        if key in body and body[key] is not None:
            merged[key] = body[key]
        elif key in q:
            merged[key] = q[key]
    return merged


def _flags(params: dict) -> tuple[bool, bool]:
    profile_flag = params.get("profile") in (True, "true")
    chat_flag = params.get("chat") in (True, "true")
    return profile_flag, chat_flag


def _base_url(request) -> str:
    headers = getattr(request, "headers", None) or {}
    proto = headers.get("x-forwarded-proto", "http")
    host = headers.get("x-forwarded-host") or headers.get("host") or ""
    return f"{proto}://{host}" if host else ""


@api.get("/me/", auth=_AUTH, guards=_OPEN)
@api.get("/me", auth=_AUTH, guards=_OPEN)
async def me_get(request):
    body = _body(request)
    params = _params(request, body)
    auth_uid = _auth_user_id(request)

    user, is_new, err, temp_id = await sync_to_async(services.resolve_user)(auth_uid, "GET", params)
    if err:
        return Response(err[1], status_code=err[0])

    # Unauthenticated visitor flow: issue short-lived visitor tokens for sync
    if (not auth_uid) and temp_id and user is not None and user.is_visitor:
        access_life = int(getattr(settings, "VISITOR_ACCESS_TOKEN_LIFETIME_SECONDS", 300))
        refresh_life = int(getattr(settings, "VISITOR_REFRESH_TOKEN_LIFETIME_SECONDS", 3600))
        return Response({
            "user_id": str(user.user_id),
            "is_new": is_new,
            "temp_id": temp_id,
            "tokens": {
                "access": mint_access(user, access_life),
                "refresh": mint_refresh(user, refresh_life),
            },
        }, status_code=200)

    profile_flag, chat_flag = _flags(params)
    response_data: dict = {
        "user_id": str(user.user_id) if user else None,
        "is_new": is_new,
        "temp_id": temp_id,
    }
    if profile_flag or not (profile_flag or chat_flag):
        response_data["profile"] = await sync_to_async(services.build_profile_payload)(user)
    if chat_flag or not (profile_flag or chat_flag):
        response_data["chat"] = await sync_to_async(services.build_chat_payload)(user)
    return Response(response_data, status_code=200)


@api.post("/me/", auth=_AUTH, guards=_OPEN)
@api.post("/me", auth=_AUTH, guards=_OPEN)
async def me_post(request):
    body = _body(request)
    params = _params(request, body)
    auth_uid = _auth_user_id(request)

    user, is_new, err, temp_id = await sync_to_async(services.resolve_user)(auth_uid, "POST", params)
    if err:
        return Response(err[1], status_code=err[0])

    profile_flag, chat_flag = _flags(params)
    summary: dict = {}
    errors: dict = {}

    # Profile upsert
    if profile_flag or not (profile_flag or chat_flag):
        profile_data = body.get("profile") if isinstance(body.get("profile"), dict) else {}
        if profile_data:
            if user is None:
                return Response({"error": "User not found"}, status_code=404)
            ok, details = await sync_to_async(services.update_profile_full)(user, profile_data)
            if not ok:
                return Response({"error": "Invalid profile data", "details": details}, status_code=400)
            summary["profile_updated"] = True
        else:
            summary["profile_updated"] = False

    # Chat upsert (transactional)
    if chat_flag or not (profile_flag or chat_flag):
        upsert_summary, errors, fatal = await sync_to_async(services.upsert_chat)(user, body)
        if fatal and upsert_summary is None and errors is None:
            return Response({"error": fatal}, status_code=400)
        if fatal:
            return Response({
                "error": "Transaction failed. No changes were applied.",
                "details": fatal,
                "errors": errors,
            }, status_code=500)
        summary.update(upsert_summary)

    response_payload: dict = {
        "summary": summary,
        "errors": errors,
        "user_id": str(user.user_id) if user else None,
        "temp_id": temp_id,
    }
    if profile_flag or not (profile_flag or chat_flag):
        response_payload["profile"] = await sync_to_async(services.build_profile_payload)(user)
    if chat_flag or not (profile_flag or chat_flag):
        response_payload["chat"] = await sync_to_async(services.build_chat_payload)(user)
    return Response(response_payload, status_code=200)


@api.patch("/me/", auth=_AUTH, guards=_OPEN)
@api.patch("/me", auth=_AUTH, guards=_OPEN)
async def me_patch(request):
    body = _body(request)
    params = _params(request, body)
    auth_uid = _auth_user_id(request)

    user, _, err, temp_id = await sync_to_async(services.resolve_user)(auth_uid, "PATCH", params)
    if err:
        return Response(err[1], status_code=err[0])

    profile_data = body.get("profile") if isinstance(body.get("profile"), dict) else body
    if not profile_data:
        return Response({"error": "No profile data provided"}, status_code=400)

    ok, payload = await sync_to_async(services.update_profile_safe)(user, profile_data)
    if not ok:
        return Response({"error": "Invalid profile data", "details": payload}, status_code=400)
    return Response({"profile": payload}, status_code=200)


@api.delete("/me/", auth=_AUTH, guards=_OPEN)
@api.delete("/me", auth=_AUTH, guards=_OPEN)
async def me_delete(request):
    body = _body(request)
    params = _params(request, body)
    auth_uid = _auth_user_id(request)

    user, _, err, temp_id = await sync_to_async(services.resolve_user)(auth_uid, "DELETE", params)
    if err:
        return Response(err[1], status_code=err[0])

    profile_flag, chat_flag = _flags(params)
    action = str(params.get("action") or "").lower()
    if action not in ("delete", "archive"):
        return Response({"error": "Invalid action. Use 'delete' or 'archive'."}, status_code=400)

    raw_download_now = params.get("download_now", params.get("download"))
    download_now = str(raw_download_now).lower() in ("1", "true", "yes") if raw_download_now is not None else False

    status, payload, zip_path = await sync_to_async(services.delete_or_archive)(
        user, action, profile_flag, chat_flag, download_now, _base_url(request)
    )
    if zip_path:
        return FileResponse(
            zip_path,
            filename=f"user_export_{user.user_id}.zip",
            media_type="application/zip",
        )
    return Response(payload, status_code=status)
