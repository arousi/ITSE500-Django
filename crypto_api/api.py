"""django-bolt port of crypto_api (was crypto_api/views.py: UserUMKView).

Phase-2 PoC: the first endpoint pair moved from DRF APIView to django-bolt.
Auto-discovered by `runbolt` (any app-level `api.py`). Serves the same paths the
DRF version did — /api/v1/crypto_api/umk — so existing clients are unaffected.

VALIDATED end-to-end on django-bolt 0.9 (runbolt + a real token): GET/POST round-trip.
Requirement confirmed: Bolt's Rust JWT verifier reads the `sub` claim (= user pk) and
exposes it as request.context["user_id"]. The app's simplejwt tokens must therefore
carry `sub` — which happens automatically once auth_api's login/register/OAuth minting
is ported to Bolt's create_jwt_for_user (it sets `sub`).
"""
from __future__ import annotations

import base64
import os
from typing import Annotated, Optional

import msgspec
from django_bolt import BoltAPI
from django_bolt.auth import IsAuthenticated, JWTAuthentication
from django_bolt.params import Query
from django_bolt.responses import Response

from .models import UserKeyMaterial

api = BoltAPI(prefix="/api/v1/crypto_api")

_AUTH = [JWTAuthentication()]
_GUARDS = [IsAuthenticated()]


class UMKOut(msgspec.Struct):
    exists: bool
    user_id: Optional[str] = None      # Custom_User.user_id is a UUID PK, not an int
    umk_b64: Optional[str] = None
    version: Optional[int] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


class UMKIn(msgspec.Struct):
    umk_b64: Optional[str] = None


def _current_user_id(request):
    """Resolve the caller's user id. Bolt puts the JWT `sub` (= user pk) into
    request.context["user_id"]; fall back to the raw `user_id` claim. Custom_User.user_id
    is a UUID PK, so keep it as a string (do NOT int() it)."""
    ctx = getattr(request, "context", None) or {}
    return ctx.get("user_id") or (ctx.get("auth_claims") or {}).get("user_id")


@api.get("/umk", auth=_AUTH, guards=_GUARDS)
async def get_umk(request) -> UMKOut:
    """Return the caller's UMK metadata + base64, or {exists: false}."""
    uid = _current_user_id(request)
    ukm = await UserKeyMaterial.objects.filter(user_id_id=uid).afirst()
    if ukm is None:
        return UMKOut(exists=False)
    return UMKOut(
        exists=True,
        user_id=ukm.user_id_id,
        umk_b64=ukm.umk_b64,
        version=ukm.version,
        created_at=ukm.created_at.isoformat(),
        updated_at=ukm.updated_at.isoformat(),
    )


@api.post("/umk", auth=_AUTH, guards=_GUARDS)
async def post_umk(request, body: UMKIn, rotate: Annotated[Optional[str], Query()] = None):
    """Provision the UMK once (409 if it exists; rotate=true -> 400, not implemented)."""
    uid = _current_user_id(request)
    if rotate == "true":
        return Response({"error": "Rotation not implemented"}, status_code=400)
    if await UserKeyMaterial.objects.filter(user_id_id=uid).aexists():
        return Response({"error": "UMK already provisioned"}, status_code=409)

    umk_b64 = body.umk_b64
    if umk_b64:
        try:
            raw = base64.b64decode(umk_b64)
        except Exception:
            return Response({"error": "Invalid base64 for umk_b64"}, status_code=400)
        if len(raw) != 32:
            return Response({"error": "Provided key must decode to 32 bytes"}, status_code=400)
    else:
        umk_b64 = base64.b64encode(os.urandom(32)).decode("utf-8")

    ukm = await UserKeyMaterial.objects.acreate(user_id_id=uid, umk_b64=umk_b64)
    return Response(
        {
            "user_id": ukm.user_id_id,
            "umk_b64": ukm.umk_b64,
            "version": ukm.version,
            "created_at": ukm.created_at.isoformat(),
            "updated_at": ukm.updated_at.isoformat(),
        },
        status_code=201,
    )
