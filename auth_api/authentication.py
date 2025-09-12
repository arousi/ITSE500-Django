from typing import Optional, Tuple

from django.contrib.auth.models import AnonymousUser
from rest_framework import exceptions
from rest_framework.request import Request
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens import RefreshToken


class JWTOrRefreshAuthentication(JWTAuthentication):
    """
    JWT authentication with auto-refresh fallback.

    Behavior:
    - Tries standard access token auth (Authorization: Bearer <access>). If valid, proceeds.
    - If access token is missing or invalid/expired, looks for a refresh token in:
        1) X-Refresh-Token header
        2) Refresh-Token header
        3) Authorization header with "Refresh <token>"
        4) Cookie named "refresh_token"
      If a refresh token is found and valid, mints a fresh access token and authenticates the user.

    Notes:
    - New tokens are attached to the request for optional use by views/middleware:
        request._new_access_token, request._new_refresh_token
    - This class does not modify the response itself; views/middleware may choose to expose the
      new tokens via headers or body if desired.
    """

    def authenticate(self, request: Request):  # type: ignore[override]
        # Attempt standard access token authentication first
        header = self.get_header(request)
        raw_token = self.get_raw_token(header)

        if raw_token is not None:
            try:
                validated_token = self.get_validated_token(raw_token)
                user = self.get_user(validated_token)
                return user, validated_token
            except exceptions.AuthenticationFailed:
                # Fall through to refresh-based auth
                pass

        # Try refresh-based authentication
        refresh_raw = self._get_refresh_token_from_request(request)
        if not refresh_raw:
            return None
        try:
            refresh_obj = RefreshToken(refresh_raw)  # type: ignore[arg-type]
            user = self.get_user(refresh_obj)
            new_access = refresh_obj.access_token
            # Attach freshly minted tokens for optional propagation
            setattr(request, "_new_access_token", str(new_access))
            setattr(request, "_new_refresh_token", str(refresh_obj))
            return user, new_access
        except Exception as e:
            raise exceptions.AuthenticationFailed("Invalid refresh token") from e

    def _get_refresh_token_from_request(self, request: Request) -> Optional[str]:
        meta = request.META or {}
        # Priority: explicit refresh headers
        token = meta.get("HTTP_X_REFRESH_TOKEN") or meta.get("HTTP_REFRESH_TOKEN")
        if token:
            return token.strip()
        # Authorization: Refresh <token>
        auth = meta.get("HTTP_AUTHORIZATION", "")
        if auth.lower().startswith("refresh "):
            return auth.split(" ", 1)[1].strip()
        # JSON body field fallback for POST/PUT/PATCH requests
        try:
            if hasattr(request, "data") and isinstance(request.data, dict):
                body_tok = request.data.get("refresh_token") or request.data.get("refresh")
                if isinstance(body_tok, str) and body_tok:
                    return body_tok.strip()
        except Exception:
            pass
        # Cookie fallback
        return request.COOKIES.get("refresh_token")
