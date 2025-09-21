"""auth_api views: authentication, OAuth, and security-related endpoints.

English
- Contains: Register/Login/Logout, Email PIN verify, Set password, OAuth (Google, OpenRouter, GitHub, Microsoft),
    health checks, and optional TOTP helpers. Returns JWT tokens for API access.
- Usage: All protected endpoints expect Authorization: Bearer <access>. Some allow refresh-only bridging.

العربية
- يحتوي على: التسجيل/الدخول/الخروج، تحقق كود البريد الإلكتروني، تعيين كلمة المرور، OAuth (جوجل، OpenRouter، GitHub، Microsoft)،
    وفحص الصحة، وخيارات TOTP الاختيارية. يرجع رموز JWT للوصول لواجهات API.
"""

import logging
import random
import hashlib
import uuid
import secrets
import base64
import string
import requests
import json
import pyotp
from typing import Any, Dict, Optional, cast
import urllib.parse
from django.shortcuts import redirect, render
from django.urls import reverse
from django.core.mail import send_mail
from django.utils import timezone
from django.conf import settings
from django.contrib.auth import logout
from rest_framework import status, serializers
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.authentication import JWTAuthentication
from .authentication import JWTOrRefreshAuthentication
from user_mang.models.custom_user import Custom_User
from .models import OAuthState, ProviderOAuthToken
from .serializers import (
    LoginSerializer,
    RegisterSerializer,
    OAuthCallbackSerializer,
    OAuthAuthorizeRequestSerializer,
    SendOTPSerializer,
    VerifyOTPSerializer,
)
from prompeteer_server.utils.emailer import send_verified_email

OAUTH_STATE_TTL_SECONDS = 600  # 10 minutes
OTP_EXPIRY_SECONDS = 300  # 5 minutes
OTP_RATE_LIMIT_WINDOW_SECONDS = 3600  # 1 hour
OTP_RATE_LIMIT_MAX = 5

def generate_code_verifier(length: int = 64) -> str:
    chars = string.ascii_letters + string.digits + '-._~'
    return ''.join(secrets.choice(chars) for _ in range(length))

def generate_code_challenge(code_verifier: str) -> str:
    digest = hashlib.sha256(code_verifier.encode('utf-8')).digest()
    return base64.urlsafe_b64encode(digest).decode('utf-8').rstrip('=')

def build_openrouter_authorize_url(state: str, code_challenge: str, scope: str, redirect_uri: str) -> str:
    base_auth = getattr(settings, 'OPENROUTER_AUTH_URL', 'https://openrouter.ai/auth')
    params = {
        'callback_url': redirect_uri,
        'code_challenge': code_challenge,
        'code_challenge_method': 'S256',
        'state': state,
    }
    if scope:
        params['scope'] = scope
    from urllib.parse import urlencode
    return f"{base_auth}?{urlencode(params)}"

def exchange_openrouter_token(code: str, code_verifier: str, redirect_uri: str):
    token_url = getattr(settings, 'OPENROUTER_TOKEN_URL', 'https://openrouter.ai/api/v1/auth/keys')
    json_body = {
        'code': code,
        'code_verifier': code_verifier,
        'code_challenge_method': 'S256',
    }
    if redirect_uri:
        json_body['callback_url'] = redirect_uri
    resp = requests.post(token_url, json=json_body, timeout=15)
    try:
        payload = resp.json()
    except Exception:
        payload = {'raw': resp.text}
    return resp.status_code, payload

def build_google_authorize_url(state: str, code_challenge: str, scope: str, redirect_uri: str) -> str:
    base_auth = getattr(settings, 'GOOGLE_OAUTH_AUTH_URL', 'https://accounts.google.com/o/oauth2/v2/auth')
    client_id = getattr(settings, 'GOOGLE_OAUTH_CLIENT_ID', '')
    return (
        f"{base_auth}?response_type=code&client_id={client_id}"
        f"&redirect_uri={redirect_uri}&scope={scope}&state={state}&access_type=offline&prompt=consent"
        f"&code_challenge={code_challenge}&code_challenge_method=S256"
    )

def exchange_google_token(code: str, code_verifier: str, redirect_uri: str):
    token_url = getattr(settings, 'GOOGLE_OAUTH_TOKEN_URL', 'https://oauth2.googleapis.com/token')
    client_id = getattr(settings, 'GOOGLE_OAUTH_CLIENT_ID', '')
    client_secret = getattr(settings, 'GOOGLE_OAUTH_CLIENT_SECRET', '')
    data = {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': redirect_uri,
        'client_id': client_id,
        'code_verifier': code_verifier,
        'client_secret': client_secret,
    }
    resp = requests.post(token_url, data=data, timeout=15)
    try:
        payload = resp.json()
    except Exception:
        payload = {'raw': resp.text}
    return resp.status_code, payload

def fetch_google_userinfo(access_token: str):
    try:
        r = requests.get('https://openidconnect.googleapis.com/v1/userinfo', headers={'Authorization': f'Bearer {access_token}'}, timeout=10)
        if r.status_code == 200:
            return r.json()
        return None
    except Exception:
        return None

logger = logging.getLogger('auth_api')

class RegisterView(APIView):
    """Register a new account or reconcile an existing identifier to avoid duplicates.

    Summary
    - Accepts temp_id and device_id for visitor migration/upgrade paths.
    - If an account already exists (email/uuid/username/temp_id), do NOT issue new tokens; a neutral
      response is returned to avoid leaking state. New accounts are created with email auto-verified in
      this release.
    - Returns onboarding details and a first sync payload when applicable.
    """
    permission_classes = [AllowAny]

    def post(self, request):
        """Handle registration: auto-verify in this phase; do not leak existing account details.

        Inputs (JSON)
        - email | username | uuid | temp_id
        - device_id (optional)

        Returns
        - 201 with tokens + initial data for new users.
        - 200/409 with neutral detail when account already exists.
        """
        logger.info(f"[RegisterView] Incoming registration request: data={request.data}")
        temp_id = (request.data.get("temp_id") or "").strip()
        device_id = (request.data.get("device_id") or "").strip()
        email = request.data.get('email')
        user_id = request.data.get('user_id') or request.data.get('uuid')
        username = request.data.get('username')
        # user may be a Custom_User instance or None
        user: Optional[Custom_User] = None
        # Try to find existing user by email, uuid, username, or temp_id
        if email:
            user = Custom_User.objects.filter(email=email).first()
        if not user and user_id:
            user = Custom_User.objects.filter(user_id=user_id).first()
        if not user and username:
            user = Custom_User.objects.filter(username=username).first()
        if not user and temp_id:
            user = Custom_User.objects.filter(temp_id=temp_id).first()

        created = False

        # SECURITY: If the identifier already exists, do NOT issue tokens or return user data.
        # - If the account is unverified, (re)send the verification PIN and instruct the client to check email.
        # - If the account is already verified, return a generic "invalid credentials." response.
        if user:
            logger.info(
                f"[RegisterView] Registration attempted for existing account: email={email} "
                f"identifier={user_id or username or temp_id}"
            )
            try:
                # Previously we sent verification PINs; this project phase auto-verifies emails.
                if not getattr(user, 'email_verified', False):
                    user.email_verified = True
                    try:
                        user.save(update_fields=['email_verified'])
                        logger.info(f"[RegisterView] Auto-verified existing user email: {user.email}")
                    except Exception:
                        user.save()
                # Inform client that the email is already registered. Do NOT issue tokens here.
                return Response({'detail': 'Email already registered.'}, status=status.HTTP_200_OK)
            except Exception:
                logger.exception("[RegisterView] Error while handling existing user during registration attempt")
            # Generic response to avoid leaking any info for verified accounts
            return Response({'detail': 'invalid credentials.'}, status=status.HTTP_409_CONFLICT)

        if not user:
            serializer = RegisterSerializer(data=request.data)
            try:
                serializer.is_valid(raise_exception=True)
                user = cast(Custom_User, serializer.save())  # type: ignore[assignment]
                raw_pw: str = str(request.data.get('user_password') or '')
                BACKEND_SALT = getattr(settings, 'BACKEND_PASSWORD_SALT', 'fallback_dev_salt')
                salted = (raw_pw + BACKEND_SALT).encode('utf-8')
                backend_hash = hashlib.sha256(salted).hexdigest()
                user.user_password = backend_hash
                # Email verification via PIN is disabled for this phase — auto-verify
                user.email_verified = True
                if temp_id:
                    user.temp_id = temp_id
                    user.is_visitor = True
                user.save()
                # OTP/email PIN sending is disabled in this phase. User is auto-verified.
                created = True
            except serializers.ValidationError as e:
                logger.warning(
                    f"[RegisterView] Registration failed: status=400, errors={e.detail}, req={request.data}"
                )
                return Response(e.detail, status=status.HTTP_400_BAD_REQUEST)
            except Exception as e:
                logger.exception(
                    f"[RegisterView] Unexpected registration error: {str(e)}, req={request.data}"
                )
                return Response({"detail": "Registration failed due to a server error."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        # Always persist device_id in related_devices
        devices = user.get_related_devices() if user else []
        if device_id:
            if device_id not in devices:
                devices.append(device_id)
                user.set_related_devices(devices)
                user.last_login = timezone.now()
                user.save()

        # At this point, user is set (either new or existing)
        refresh = RefreshToken.for_user(user)

        # Fetch all conversations/messages for this user (like SyncConversationsView.get)
        from chat_api.models import Conversation
        from chat_api.models.message import Message
        conversations = Conversation.objects.filter(user_id=user)
        result = []
        for conv in conversations:
            conv_data = {
                "conversation_id": str(conv.conversation_id),
                "user_id": str(user.user_id),
                "title": conv.title,
                "created_at": conv.created_at,
                "updated_at": conv.updated_at,
                "local_only": conv.local_only,
            }
            conv_messages = []
            for msg in conv.messages.all():  # type: ignore[attr-defined]
                msg_data = {
                    "message_id": str(msg.message_id),
                    "conversation_id": str(conv.conversation_id),
                    "user_id": str(user.user_id),
                    "request_id": str(getattr(msg.request_id, 'pk', None)) if (msg.request_id and getattr(msg.request_id, 'pk', None) is not None) else None,
                    "response_id": str(getattr(msg.response_id, 'pk', None)) if (msg.response_id and getattr(msg.response_id, 'pk', None) is not None) else None,
                    "output_id": str(getattr(msg.output_id, 'pk', None)) if (msg.output_id and getattr(msg.output_id, 'pk', None) is not None) else None,
                    "timestamp": msg.timestamp,
                    "vote": bool(msg.vote),
                    "has_image": bool(msg.has_image),
                    "img_Url": msg.img_Url.url if msg.img_Url else None,
                    "metadata": msg.metadata,
                    "has_embedding": bool(msg.has_embedding),
                    "has_document": bool(msg.has_document),
                    "doc_url": msg.doc_url.url if msg.doc_url else None,
                }
                # Optionally serialize nested request/response/output if needed
                conv_messages.append(msg_data)
            conv_data["messages"] = conv_messages
            result.append(conv_data)

        resp_data = {
            "message": "User created. Verification PIN sent to email." if created else "User already exists. Returning data.",
            "user_id": str(user.user_id),
            "access_token": str(refresh.access_token),
            "refresh_token": str(refresh),
            "email": user.email,
            "onboarding": created,
            "conversations": result,
            "temp_id": user.temp_id,
            "device_id": device_id,
            "related_devices": devices if device_id else [],
        }
        logger.info(f"[RegisterView] Registration/data sync success: status=201, user_id={user.user_id}")
        return Response(resp_data, status=status.HTTP_201_CREATED)

class EmailPinVerifyView(APIView):
    """
        Verify the 5-digit email PIN for the currently authenticated user.

        Purpose
        -------
        Confirms ownership of the email address associated with the authenticated account.
        On success, the user's `email_verified` flag is set and the one-time PIN is cleared.

        Authentication
        --------------
        - Requires a valid JWT access token (Authorization: Bearer <token>).
        - The endpoint operates on the server-side user identified by the JWT; the provided
            email must belong to the same account.

        HTTP
        ----
        - Method: POST
        - Path: /api/v1/auth_api/verify-email-pin/

        Request Body (JSON)
        -------------------
        {
            "email": "user@example.com",   # string, required; must match the authenticated user's email
            "pin":   "12345"               # string, required; 5-digit code (numeric string)
        }

        Response (Success)
        ------------------
        200 OK
        {
            "message": "Email verified. You may now set your password."
        }

        Error Responses
        ---------------
        - 400 Bad Request:
            - {"detail": "Invalid data."}                 # missing or malformed fields
            - {"detail": "Invalid PIN."}                  # PIN does not match
            - {"detail": "PIN expired."}                  # PIN older than allowed TTL
            - {"detail": "Email not associated with user"}# (if applicable) email mismatch
        - 401 Unauthorized: Missing/invalid JWT access token
        - 404 Not Found: {"detail": "User not found."}  # no user with the provided email

        Notes
        -----
        - The server expects a numeric PIN; non-numeric input is compared verbatim.
        - On success, the stored PIN is cleared to prevent reuse.
        - PIN lifetime is typically 10 minutes (600 seconds); configurable server-side.

        Examples
        --------
        Request:
            POST /api/v1/auth_api/verify-email-pin/
            Authorization: Bearer <access_token>
            Content-Type: application/json

            {
                "email": "user@example.com",
                "pin": "12345"
            }
        Response (200):
            { "message": "Email verified. You may now set your password." }
    """
    # AllowAny + inline auth (access or refresh) to avoid hard dependency on a custom auth class
    authentication_classes = [JWTAuthentication]
    permission_classes = [AllowAny]

    class InputSerializer(serializers.Serializer):
        email = serializers.EmailField()
        pin = serializers.CharField(max_length=5)

    def post(self, request):  # type: ignore[override]
        """Verify the 5-digit email PIN for the authenticated user.

        Expects JSON body with:
        - email: string; must match the authenticated user's email
        - pin: string; 5-digit code

        Returns 200 with a success message on valid PIN; 400 for invalid/expired PIN;
        404 if the user is not found; 401 if JWT is missing/invalid.
        """
        logger.info(f"[EmailPinVerifyView] Incoming PIN verify request: data={request.data}")
        ser = self.InputSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        validated_data = cast(Dict[str, Any], ser.validated_data)
        email = validated_data.get('email')
        pin = validated_data.get('pin')
        if not email or not pin:
            return Response({"detail": "Invalid data."}, status=status.HTTP_400_BAD_REQUEST)

        # Determine acting user via existing JWT or refresh token
        acting_user = request.user if getattr(request.user, 'is_authenticated', False) else None
        minted_access: Optional[str] = None
        minted_refresh: Optional[str] = None
        if acting_user is None:
            refresh_raw = (
                request.META.get('HTTP_X_REFRESH_TOKEN') or
                request.META.get('HTTP_REFRESH_TOKEN') or
                (request.META.get('HTTP_AUTHORIZATION','').split(' ',1)[1] if request.META.get('HTTP_AUTHORIZATION','').lower().startswith('refresh ') else None) or
                (request.data.get('refresh_token') if isinstance(request.data, dict) else None) or
                request.COOKIES.get('refresh_token')
            )
            if not refresh_raw:
                return Response({'detail': 'Authentication required (access or refresh token).'}, status=status.HTTP_401_UNAUTHORIZED)
            try:
                r = RefreshToken(refresh_raw)
                user_id = r.get('user_id')
                acting_user = Custom_User.objects.filter(pk=user_id).first()
                if not acting_user:
                    return Response({'detail': 'Invalid refresh token.'}, status=status.HTTP_401_UNAUTHORIZED)
                minted_access = str(r.access_token)
                minted_refresh = str(r)  # may or may not rotate depending on settings
            except Exception:
                return Response({'detail': 'Invalid refresh token.'}, status=status.HTTP_401_UNAUTHORIZED)

        # Ensure the provided email belongs to the acting user (defense-in-depth)
        if getattr(acting_user, 'email', None) and str(acting_user.email).lower() != str(email).lower():
            return Response({'detail': 'Email does not belong to the authenticated user.'}, status=status.HTTP_403_FORBIDDEN)
        try:
            user = Custom_User.objects.get(email=email)
        except Custom_User.DoesNotExist:
            return Response({"detail": "User not found."}, status=status.HTTP_404_NOT_FOUND)
        # Use correct field names on Custom_User
        if getattr(user, 'email_pin', None) != int(pin) if str(pin).isdigit() else getattr(user, 'email_pin', None) != pin:
            return Response({"detail": "Invalid PIN."}, status=status.HTTP_400_BAD_REQUEST)
        created = getattr(user, 'email_pin_created', None)
        if not created or (timezone.now() - created).total_seconds() > 600:
            return Response({"detail": "PIN expired."}, status=status.HTTP_400_BAD_REQUEST)
        user.email_verified = True
        # Clear PIN after successful verification
        try:
            user.email_pin = None
            user.save(update_fields=["email_verified", "email_pin"])
        except Exception:
            user.save(update_fields=["email_verified"])  # Fallback if update fields mismatch in some DBs
        resp = Response({"message": "Email verified. You may now set your password."})
        if minted_access:
            resp["X-New-Access-Token"] = minted_access
        if minted_refresh:
            resp["X-New-Refresh-Token"] = minted_refresh
        return resp

class SetPasswordAfterEmailVerifyView(APIView):
    """
        Set or reset the account password after email verification.

        Purpose
        -------
        Allows an authenticated and email-verified user to set a new password. The client
        sends a frontend-hashed password (sha256(raw)) that the server salts and hashes again
        before storing.

        Authentication
        --------------
        - Requires a valid JWT access token (Authorization: Bearer <token>).
        - The provided email must belong to the authenticated user.

        Prerequisite
        ------------
        The user's email must already be verified (e.g., via EmailPinVerifyView). If the
        email is not verified, the request is rejected.

        HTTP
        ----
        - Method: POST
        - Path: /api/v1/auth_api/set-password-after-email-verify/

        Request Body (JSON)
        -------------------
        {
            "email": "user@example.com",      # string, required; must match the authenticated user's email
            "password": "<sha256(raw)>"       # string, required; client-side SHA-256 of the raw password
        }

        Processing
        ----------
        - Server computes: sha256(frontend_hashed_password + BACKEND_SALT) and stores it
            as the user's credential.

        Response (Success)
        ------------------
        200 OK
        {
            "message": "Password set successfully. You may now log in."
        }

        Error Responses
        ---------------
        - 400 Bad Request:
            - {"detail": "Invalid data."}        # missing fields
            - {"detail": "Email not verified."} # email_verified is False
        - 401 Unauthorized: Missing/invalid JWT access token
        - 404 Not Found: {"detail": "User not found."}

        Security Notes
        --------------
        - Do not send plaintext passwords from the client; always send sha256(raw).
        - Server adds a backend-only salt before final hashing and storage.

        Examples
        --------
        Request:
            POST /api/v1/auth_api/set-password-after-email-verify/
            Authorization: Bearer <access_token>
            Content-Type: application/json

            {
                "email": "user@example.com",
                "password": "a3f5...sha256_of_raw...9c2"
            }
        Response (200):
            { "message": "Password set successfully. You may now log in." }
    """
    # AllowAny + inline auth (access or refresh)
    authentication_classes = [JWTAuthentication]
    permission_classes = [AllowAny]

    class InputSerializer(serializers.Serializer):
        email = serializers.EmailField()
        password = serializers.CharField(min_length=6)

    def post(self, request):  # type: ignore[override]
        """Set/reset the account password after email verification.

        Expects JSON body with:
        - email: string; must match the authenticated user's email
        - password: string; client-side sha256(raw)

        On success, stores a salted backend hash and returns 200 with a message.
        May return 400 if data is invalid or email not verified; 404 if user not found;
        401 if JWT is missing/invalid.
        """
        logger.info(f"[SetPasswordAfterEmailVerifyView] Incoming set-password request: data={request.data}")
        ser = self.InputSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        validated_data = cast(Dict[str, Any], ser.validated_data)
        email = validated_data.get('email')
        frontend_hashed_password = validated_data.get('password', '')
        if not email or not frontend_hashed_password:
            return Response({"detail": "Invalid data."}, status=status.HTTP_400_BAD_REQUEST)

        # Determine acting user: accept access or refresh
        acting_user = request.user if getattr(request.user, 'is_authenticated', False) else None
        minted_access: Optional[str] = None
        minted_refresh: Optional[str] = None
        if acting_user is None:
            refresh_raw = (
                request.META.get('HTTP_X_REFRESH_TOKEN') or
                request.META.get('HTTP_REFRESH_TOKEN') or
                (request.META.get('HTTP_AUTHORIZATION','').split(' ',1)[1] if request.META.get('HTTP_AUTHORIZATION','').lower().startswith('refresh ') else None) or
                (request.data.get('refresh_token') if isinstance(request.data, dict) else None) or
                request.COOKIES.get('refresh_token')
            )
            if not refresh_raw:
                return Response({'detail': 'Authentication required (access or refresh token).'}, status=status.HTTP_401_UNAUTHORIZED)
            try:
                r = RefreshToken(refresh_raw)
                user_id = r.get('user_id')
                acting_user = Custom_User.objects.filter(pk=user_id).first()
                if not acting_user:
                    return Response({'detail': 'Invalid refresh token.'}, status=status.HTTP_401_UNAUTHORIZED)
                minted_access = str(r.access_token)
                minted_refresh = str(r)
            except Exception:
                return Response({'detail': 'Invalid refresh token.'}, status=status.HTTP_401_UNAUTHORIZED)
        try:
            user = Custom_User.objects.get(email=email)
        except Custom_User.DoesNotExist:
            return Response({"detail": "User not found."}, status=status.HTTP_404_NOT_FOUND)
        # Ensure email matches acting user when we have one
        if getattr(acting_user, 'email', None) and str(acting_user.email).lower() != str(email).lower():
            return Response({'detail': 'Email does not belong to the authenticated user.'}, status=status.HTTP_403_FORBIDDEN)
        if not getattr(user, 'email_verified', False):
            return Response({"detail": "Email not verified."}, status=status.HTTP_400_BAD_REQUEST)
        BACKEND_SALT = getattr(settings, 'BACKEND_PASSWORD_SALT', 'fallback_dev_salt')
        backend_hash = hashlib.sha256((frontend_hashed_password + BACKEND_SALT).encode('utf-8')).hexdigest()
        user.user_password = backend_hash
        user.save(update_fields=["user_password"])
        resp = Response({"message": "Password set successfully. You may now log in."})
        if minted_access:
            resp["X-New-Access-Token"] = minted_access
        if minted_refresh:
            resp["X-New-Refresh-Token"] = minted_refresh
        return resp


class LoginView(APIView):
    """Authenticate a user and return JWTs plus initial sync payload.

    Example Request (POST /api/v1/auth_api/login/)
    {
        "email": "john@example.com",
        "password": "<sha256(raw)>"
    }

    Example Response (200)
    { "message": "Login successful", "access_token": "...", "refresh_token": "...", "conversations": [...], "attachments": [...] }
    """
    permission_classes = [AllowAny]

    def post(self, request):
        """Authenticate a user and return JWT tokens plus initial sync payload.
        Accepts identifier (email/username) and user_password/password. Returns 200
        with access/refresh tokens, conversations, and attachments on success.
        Returns 401 for invalid credentials, 403 if user is inactive/locked, or 400/500 otherwise.
        """
        logger.info(f"[LoginView] Incoming login request: data={request.data}")
    # Normalize incoming keys: allow clients to send 'password' or 'user_password',
    # and 'username' or 'email' or 'identifier' for the credential field.
        raw = request.data or {}
        identifier = raw.get('identifier') or raw.get('email') or raw.get   ('username')
        pwd = raw.get('user_password') if 'user_password' in raw else raw.get('password')
        serializer = LoginSerializer(data={'identifier': identifier, 'user_password': pwd}, context={'request': request})
        try:
            serializer.is_valid(raise_exception=True)
            data = serializer.validated_data
            user = cast(Custom_User, data.get('user', None))  # type: ignore[assignment]
            refresh = RefreshToken.for_user(user)

            # Fetch conversations and messages
            from chat_api.models import Conversation
            from chat_api.models.attachment import Attachment
            from user_mang.serializers import ConversationSerializer, AttachmentSerializer

            conversations = Conversation.objects.filter(user_id=user).prefetch_related("messages")
            conv_serializer = ConversationSerializer(conversations, many=True)

            # Attachment model links to Message via message_id; filter by messages owned by user
            attachments = Attachment.objects.filter(message_id__user_id=user)
            attach_serializer = AttachmentSerializer(attachments, many=True)

            resp_data = {
                "message": "Login successful",
                "user_id": user.pk,
                "access_token": str(refresh.access_token),
                "refresh_token": str(refresh),
                "email_verified": getattr(user, "email_verified", False),
                "conversations": conv_serializer.data,
                "attachments": attach_serializer.data,
            }
            logger.info(f"[LoginView] Login success: status=200, user_id={user.pk}, resp={resp_data}")
            return Response(resp_data, status=status.HTTP_200_OK)
        except serializers.ValidationError as e:
            error_detail = str(e.detail)
            logger.warning(f"[LoginView] Login failed: status=400, errors={e.detail}, req={request.data}")
            if "inactive" in error_detail:
                return Response({"detail": "User account is Locked."}, status=status.HTTP_403_FORBIDDEN)
            elif "Invalid credentials" in error_detail:
                return Response({"detail": "Invalid credentials."}, status=status.HTTP_401_UNAUTHORIZED)
            else:
                return Response({"detail": error_detail}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.exception(f"[LoginView] Login failed: {str(e)}, req={request.data}")
            return Response({"detail": "Login failed due to a server error."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
class LogoutView(APIView):
    """
    Handles user logout by clearing the session.

    Example API Request (POST /api/v1/auth_api/logout/):
        {}

    Example API Response (200):
        {
            "detail": "Logged out successfully."
        }
    """
    # Require JWT and authenticated user
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        """Invalidate the current session and instruct the client to discard tokens.
        Returns a 200 response with a brief message. Does not blacklist tokens server-side.
        Requires a valid JWT and authenticated user.
        """
        user = getattr(request, 'user', None)
        logger.info(f"[LogoutView] Incoming logout request: user_id={getattr(user, 'pk', None)}")
    # Clear authentication/session
        logout(request)
        logger.info(f"[LogoutView] User logged out: {user.user_id if user and getattr(user, 'is_authenticated', False) else 'anonymous'}")

    # No server-side token deletion: keep provider OAuth tokens intact so the user
    # can re-login via OAuth from another interface. We also avoid blacklisting
    # refresh tokens here; clients should discard tokens client-side after logout.
        resp_data = {"detail": "Logged out successfully. Please discard tokens client-side."}
        logger.info(f"[LogoutView] Logout response: status=200, resp={resp_data}")
        return Response(resp_data, status=status.HTTP_200_OK)


class HealthCheckView(APIView):
    """
    Simple health check endpoint for server status.

    Example API Request (GET /api/v1/auth_api/health-check/):
        None

    Example API Response (200):
        {
            "status": "ok",
            "message": "Server is up"
        }
    """
    permission_classes = [AllowAny]

    def get(self, request):
        """Report server liveness with a simple JSON payload and 200 status."""
        logger.info("[HealthCheckView] Health check performed.")
        resp_data = {"status": "ok", "message": "Server is up"}
        logger.info(f"[HealthCheckView] Health check response: status=200, resp={resp_data}")
        return Response(resp_data, status=status.HTTP_200_OK)

#* Base OAuth Authorize
class OAuthAuthorizeBase(APIView):
    """
    Base class for starting an OAuth2 authorization flow (Google or OpenRouter).

    Handles both SSR (server-side rendered) and bridge (SPA/mobile) flows.
    - For SSR: redirects the user to the provider's authorization URL.
    - For SPA/mobile: returns the authorization URL and state in JSON.

    Query Parameters:
        - scope (str, optional): OAuth scopes (default: 'openid').
        - redirect_uri (str, optional): Custom redirect URI for mobile/SPA.
        - callback_host (str, optional): Used for emulator/mobile callback host swapping.
        - mode (str, optional): If 'redirect', triggers SSR redirect.

    Example SSR Request:
        GET /api/v1/auth_api/google/authorize/?mode=redirect

    Example SPA/Mobile Request:
        GET /api/v1/auth_api/google/authorize/

    Example SPA/Mobile Response (200):
        {
            "authorize_url": "https://accounts.google.com/o/oauth2/v2/auth?...",
            "state": "random_state_string",
            "state_id": "uuid",
            "expires_at": "2025-08-22T12:34:56.789Z",
            "bridge": true
        }
    """
    permission_classes = [AllowAny]
    provider = None  # 'google' or 'openrouter'

    def get(self, request):
        """Start an OAuth2 authorization flow and return or redirect to an authorize URL.
        Supports SSR redirect (mode=redirect) and SPA/mobile JSON response containing
        the provider authorize_url and state metadata. Provider determined by subclass.
        """
        import secrets
        base_ser = OAuthAuthorizeRequestSerializer(data=request.query_params)
        base_ser.is_valid(raise_exception=True)
        base_data = cast(Dict[str, Any], base_ser.validated_data)
        scope = base_data.get('scope') or 'openid'
        orig_redirect = base_data.get('redirect_uri')
        callback_host = request.query_params.get('callback_host')
        mobile_redirect: Optional[str] = None

    # Provider-specific logic
        if self.provider == 'google':
            # Remove any accidental offline_access to avoid invalid_scope errors
            scope_parts = [s for s in scope.split() if s and s != 'offline_access']
            for required in ('openid', 'email', 'profile'):
                if required not in scope_parts:
                    scope_parts.append(required)
            scope = ' '.join(scope_parts)
            redirect_uri = orig_redirect or getattr(settings, 'GOOGLE_OAUTH_REDIRECT_URI', '')
            # Emulator host swap for mobile
            if callback_host:
                allowed_hosts = {'10.0.2.2', '127.0.0.1'} | set(getattr(settings, 'OAUTH_CALLBACK_HOST_ALLOWLIST', []))
                if any(callback_host.startswith(prefix) for prefix in ('192.168.', '10.0.2.')):
                    allowed_hosts.add(callback_host.split(':')[0])
                if callback_host.split(':')[0] in allowed_hosts:
                    host_part = callback_host
                    if ':' not in host_part:
                        host_part = f"{host_part}:8000"
                    scheme = 'http'
                    redirect_uri = f"{scheme}://{host_part}/api/v1/auth_api/google/callback/"
            if redirect_uri and (redirect_uri.startswith('prompeteer://') or redirect_uri.startswith('app://')):
                mobile_redirect = redirect_uri.rstrip('/')
                redirect_uri = getattr(settings, 'GOOGLE_OAUTH_REDIRECT_URI', '')
            # If redirect_uri is missing or points to a local host, build the absolute production callback from this request
            try:
                built_callback = request.build_absolute_uri(reverse('google-callback'))
            except Exception:
                built_callback = ''
            def _looks_local(u: str) -> bool:
                return any(h in u for h in ('127.0.0.1', 'localhost', '10.0.2.2'))
            if not redirect_uri or _looks_local(redirect_uri):
                if built_callback:
                    redirect_uri = built_callback
            if redirect_uri and not redirect_uri.endswith('/'):
                redirect_uri += '/'
            if not redirect_uri:
                return Response({'detail': 'redirect_uri not configured'}, status=status.HTTP_400_BAD_REQUEST)
            code_verifier = generate_code_verifier()
            code_challenge = generate_code_challenge(code_verifier)
            state = secrets.token_urlsafe(24)
            expires_at = timezone.now() + timezone.timedelta(seconds=OAUTH_STATE_TTL_SECONDS)
            oauth_state = OAuthState.objects.create(
                provider='google',
                state=state,
                code_challenge=code_challenge,
                code_verifier=code_verifier,
                redirect_uri=redirect_uri,
                mobile_redirect=mobile_redirect,
                scope=scope,
                expires_at=expires_at,
                user_id=request.user if request.user.is_authenticated else None,
            )
            logger.info(f"[GoogleAuthorize] created state={state} redirect_uri={redirect_uri} mobile_redirect={mobile_redirect} host={request.get_host()}")
            authorize_url = build_google_authorize_url(state, code_challenge, scope, redirect_uri)
        elif self.provider == 'openrouter':
            if 'offline_access' not in scope.split():
                scope = scope + ' offline_access'
            redirect_uri = orig_redirect or getattr(settings, 'OPENROUTER_REDIRECT_URI', '')
            if redirect_uri and (redirect_uri.startswith('prompeteer://') or redirect_uri.startswith('app://')):
                mobile_redirect = redirect_uri.rstrip('/')
                redirect_uri = getattr(settings, 'OPENROUTER_REDIRECT_URI', '')
            if not redirect_uri:
                try:
                    redirect_uri = request.build_absolute_uri(reverse('openrouter-callback'))
                except Exception:
                    return Response({'detail': 'redirect_uri not configured'}, status=status.HTTP_400_BAD_REQUEST)
            code_verifier = generate_code_verifier()
            code_challenge = generate_code_challenge(code_verifier)
            state = secrets.token_urlsafe(24)
            expires_at = timezone.now() + timezone.timedelta(seconds=OAUTH_STATE_TTL_SECONDS)
            oauth_state = OAuthState.objects.create(
                provider='openrouter',
                state=state,
                code_challenge=code_challenge,
                code_verifier=code_verifier,
                redirect_uri=redirect_uri,
                mobile_redirect=mobile_redirect,
                scope=scope,
                expires_at=expires_at,
                user_id=request.user if request.user.is_authenticated else None,
            )
            authorize_url = build_openrouter_authorize_url(state, code_challenge, scope, redirect_uri)
        elif self.provider == 'microsoft':
            import secrets, urllib.parse
            state = secrets.token_urlsafe(24)
            scope = request.query_params.get('scope', 'openid email profile User.Read')
            redirect_uri = getattr(settings, 'MS_REDIRECT_URI', '')
            if not redirect_uri:
                return Response({'detail': 'redirect_uri not configured'}, status=status.HTTP_400_BAD_REQUEST)
            params = {
                'client_id': getattr(settings, 'MS_CLIENT_ID', ''),
                'response_type': 'code',
                'redirect_uri': redirect_uri,
                'response_mode': 'query',
                'scope': scope,
                'state': state,
            }
            authorize_url = f"https://login.microsoftonline.com/common/oauth2/v2.0/authorize?{urllib.parse.urlencode(params)}"
            expires_at = timezone.now() + timezone.timedelta(seconds=OAUTH_STATE_TTL_SECONDS)
            oauth_state = OAuthState.objects.create(
                provider='microsoft',
                state=state,
                code_challenge=None,
                code_verifier=None,
                redirect_uri=redirect_uri,
                mobile_redirect=None,
                scope=scope,
                expires_at=expires_at,
                user_id=request.user if request.user.is_authenticated else None,
            )
        elif self.provider == 'github':
            import secrets, urllib.parse
            state = secrets.token_urlsafe(24)
            scope = request.query_params.get('scope', 'read:user user:email')
            redirect_uri = getattr(settings, 'GITHUB_REDIRECT_URI', '')
            if not redirect_uri:
                return Response({'detail': 'redirect_uri not configured'}, status=status.HTTP_400_BAD_REQUEST)
            params = {
                'client_id': getattr(settings, 'GITHUB_CLIENT_ID', ''),
                'redirect_uri': redirect_uri,
                'scope': scope,
                'state': state,
                'allow_signup': 'true',
            }
            authorize_url = f"https://github.com/login/oauth/authorize?{urllib.parse.urlencode(params)}"
            expires_at = timezone.now() + timezone.timedelta(seconds=OAUTH_STATE_TTL_SECONDS)
            oauth_state = OAuthState.objects.create(
                provider='github',
                state=state,
                code_challenge=None,
                code_verifier=None,
                redirect_uri=redirect_uri,
                mobile_redirect=None,
                scope=scope,
                expires_at=expires_at,
                user_id=request.user if request.user.is_authenticated else None,
            )
        else:
            return Response({'detail': 'Unknown provider'}, status=status.HTTP_400_BAD_REQUEST)

        # SSR: redirect if requested
        if request.query_params.get('mode') == 'redirect' or 'authorize/ssr' in request.path:
            return redirect(authorize_url)
        return Response({
            'authorize_url': authorize_url,
            'state': state,
            'state_id': str(oauth_state.user_id),
            'expires_at': expires_at.isoformat(),
            'bridge': bool(mobile_redirect)
        })

#* Base OAuth Callback
class OAuthCallbackBase(APIView):
    """
    Base class for handling OAuth2 callback from Google or OpenRouter.

    Handles both SSR (server-side rendered) and bridge (SPA/mobile) flows.
    - For SSR: can render an HTML page that posts the result to the opener window.
    - For SPA/mobile: stores the result payload for one-time retrieval.

    Query Parameters:
        - state (str): The state value returned by the provider.
        - code (str): The authorization code returned by the provider.
        - error (str, optional): Error message if the provider returned an error.

    Example SSR Callback:
        GET /api/v1/auth_api/google/callback/?state=...&code=...

    Example SPA/Mobile Callback:
        GET /api/v1/auth_api/google/callback/?state=...&code=...

    Example JSON Response (200):
        {
            "message": "Google OAuth success",
            "user_id": "42",
            "username": "john",
            "access_token": "jwt-access-token",
            "refresh_token": "jwt-refresh-token",
            "provider_scope": "...",
            "provider_expires_at": "...",
            "id_token": "...",
            "email": "john@example.com",
            "email_verified": true,
            "is_google_user": true,
            "is_openrouter_user": false
        }
    """
    permission_classes = [AllowAny]
    provider = None

    def get(self, request):
        """Handle an OAuth2 callback from a provider and return a unified JSON payload.
        Validates state, exchanges code for tokens, creates/updates a user, persists
        provider tokens, and returns app JWTs. For mobile bridge flows, may redirect.
        """
        ser = OAuthCallbackSerializer(data=request.GET)
        ser.is_valid(raise_exception=True)
        cb_data = cast(Dict[str, Any], ser.validated_data)
        state_value = cb_data.get('state') or ''
        code = cb_data.get('code') or ''
        error = cb_data.get('error') or ''
        provider_name = str(self.provider) if self.provider else "Unknown"
        logger.info(f"[{provider_name.capitalize()}CallbackView][GET] state={state_value} error={error} code_present={bool(code)}")
        try:
            oauth_state = OAuthState.objects.get(state=state_value, provider=self.provider)
        except OAuthState.DoesNotExist:
            return Response({'detail': 'Invalid state'}, status=status.HTTP_400_BAD_REQUEST)
        if error:
            return Response({'detail': error}, status=status.HTTP_400_BAD_REQUEST)
        if oauth_state.used and not oauth_state.is_expired():
            if oauth_state.result_payload:
                try:
                    data = json.loads(oauth_state.result_payload)
                    data['idempotent'] = True
                    return Response(data)
                except Exception:
                    pass
            return Response({'detail': 'State already used', 'error_code': 'state_used'}, status=status.HTTP_409_CONFLICT)
        if oauth_state.is_expired():
            return Response({'detail': 'State expired', 'error_code': 'state_expired'}, status=status.HTTP_400_BAD_REQUEST)
        if not code:
            return Response({'detail': 'Missing authorization code'}, status=status.HTTP_400_BAD_REQUEST)

        # Provider-specific token exchange and user logic
        if self.provider == 'google':
            # Use the exact callback URL that Google just hit for redirect_uri to avoid mismatch.
            # This ensures the redirect_uri in the token exchange matches the one used during authorize.
            try:
                redirect_used = request.build_absolute_uri(request.path)
            except Exception:
                redirect_used = str(oauth_state.redirect_uri or '')
            # Normalize trailing slash to match common configuration
            if redirect_used and not redirect_used.endswith('/'):
                redirect_used = redirect_used + '/'
            if oauth_state.redirect_uri and str(oauth_state.redirect_uri) != redirect_used:
                logger.info(
                    f"[GoogleCallbackView] redirect_uri mismatch detected. state={state_value} "
                    f"stored={oauth_state.redirect_uri} used={redirect_used}"
                )
                # Update stored redirect to the actually used one for consistency/debugging
                try:
                    oauth_state.redirect_uri = redirect_used
                    oauth_state.save(update_fields=["redirect_uri"])
                except Exception:
                    logger.debug("[GoogleCallbackView] Failed to persist adjusted redirect_uri; continuing")
            status_code, token_payload = exchange_google_token(
                str(code or ''), str(oauth_state.code_verifier or ''), redirect_used
            )
            if status_code != 200:
                return Response({'detail': 'Token exchange failed', 'provider_payload': token_payload}, status=status.HTTP_400_BAD_REQUEST)
            access_token = token_payload.get('access_token')
            refresh_token = token_payload.get('refresh_token')
            expires_in = token_payload.get('expires_in')
            id_token = token_payload.get('id_token')
            userinfo = fetch_google_userinfo(access_token) if access_token else None
            email = (userinfo or {}).get('email') if userinfo else None
            email_verified_claim = (userinfo or {}).get('email_verified') if userinfo else None
            user = oauth_state.user_id
            if not user:
                if email and Custom_User.objects.filter(email=email).exists():
                    user = Custom_User.objects.get(email=email)
                else:
                    base_username = (email.split('@')[0] if email else f"g_{uuid.uuid4().hex[:6]}")
                    candidate = base_username
                    idx = 1
                    while Custom_User.objects.filter(username=candidate).exists():
                        candidate = f"{base_username}{idx}"
                        idx += 1
                    user = Custom_User.objects.create(
                        username=candidate,
                        email=email or f"pending_{uuid.uuid4().hex}@google.local",
                        email_verified=bool(email_verified_claim) if email_verified_claim is not None else bool(email),
                        is_google_user=True
                    )
            else:
                update_fields: list[str] = []
                if email and not user.email:
                    user.email = email
                    update_fields.append('email')
                if not getattr(user, 'is_google_user', False):
                    user.is_google_user = True
                    update_fields.append('is_google_user')
                if email and not user.email_verified and (email_verified_claim or email_verified_claim is None):
                    if email_verified_claim is None or bool(email_verified_claim):
                        user.email_verified = True
                        update_fields.append('email_verified')
                if update_fields:
                    user.save(update_fields=update_fields)
            expires_sec: int = 0
            if expires_in not in (None, ''):
                try:
                    expires_sec = int(expires_in)
                except Exception:
                    expires_sec = 0
            expires_at = timezone.now() + timezone.timedelta(seconds=expires_sec) if expires_sec else None
            ProviderOAuthToken.objects.update_or_create(
                user_id=user,
                provider='google',
                defaults={
                    'access_token': access_token,
                    'refresh_token': refresh_token,
                    'expires_at': expires_at,
                    'scope': oauth_state.scope,
                    'token_type': token_payload.get('token_type') or 'Bearer',
                }
            )
            oauth_state.mark_used()
            refresh = RefreshToken.for_user(user)
            payload = {
                'message': 'Google OAuth success',
                'user_id': str(user.pk),
                'username': user.username,
                'access_token': str(refresh.access_token),
                'refresh_token': str(refresh),
                'provider_scope': oauth_state.scope,
                'provider_expires_at': expires_at.isoformat() if expires_at else None,
                'id_token': id_token,
                'email': email,
                'email_verified': user.email_verified,
                'is_google_user': getattr(user, 'is_google_user', False),
            }
        elif self.provider == 'openrouter':
            status_code, token_payload = exchange_openrouter_token(str(code or ''), str(oauth_state.code_verifier or ''), str(oauth_state.redirect_uri or ''))
            if status_code != 200:
                return Response({'detail': 'Token exchange failed', 'provider_payload': token_payload}, status=status.HTTP_400_BAD_REQUEST)
            access_token = token_payload.get('key') or token_payload.get('access_token')
            refresh_token = None
            scope = oauth_state.scope
            token_type = 'api_key'
            if not access_token:
                return Response({'detail': 'Provider did not return API key', 'provider_payload': token_payload}, status=status.HTTP_400_BAD_REQUEST)
            user = oauth_state.user_id
            if not user:
                user = Custom_User.objects.create(
                    username=f"or_{uuid.uuid4().hex[:10]}",
                    email=f"pending_{uuid.uuid4().hex}@openrouter.local",
                    is_openrouter_user=True
                )
            elif not getattr(user, 'is_openrouter_user', False):
                user.is_openrouter_user = True
                user.save(update_fields=['is_openrouter_user'])
            expires_at = None
            ProviderOAuthToken.objects.update_or_create(
                user_id=user,
                provider='openrouter',
                defaults={
                    'access_token': access_token,
                    'refresh_token': refresh_token,
                    'expires_at': expires_at,
                    'scope': scope,
                    'token_type': token_type,
                }
            )
            oauth_state.mark_used()
            refresh = RefreshToken.for_user(user)
            payload = {
                'message': 'OpenRouter OAuth success',
                'user_id': str(user.pk),
                'access_token': str(refresh.access_token),
                'refresh_token': str(refresh),
                'provider_access_token': access_token if getattr(settings, 'OPENROUTER_EXPOSE_PROVIDER_TOKEN', True) else None, #* User's api key secrete is given back to him.
                'provider_refresh_token': None,
                'provider_token_type': token_type,
                'provider_scope': scope,
                'provider_expires_at': None,
                'is_openrouter_user': getattr(user, 'is_openrouter_user', False),
            }
        else:
            return Response({'detail': 'Unknown provider'}, status=status.HTTP_400_BAD_REQUEST)

        # Persist the result payload so SPA/mobile bridge polling can retrieve it.
        # Previously this was only stored for mobile_redirect flows; store it for all successful callbacks.
        try:
            if payload is not None:
                oauth_state.result_payload = json.dumps(payload)
                oauth_state.save(update_fields=["result_payload"])
        except Exception:
            logger.exception(f"[OAuthCallbackBase] Failed to persist result_payload for state={state_value}")

        # Bridge deep link
        if oauth_state.mobile_redirect:
            target = f"{oauth_state.mobile_redirect.rstrip('/')}?state={urllib.parse.quote(state_value)}&bridge=1"
            # Only perform server redirect for http(s) URLs. For custom schemes (e.g., prompeteer://),
            # return an HTML bridge page that attempts navigation via JS without triggering DisallowedRedirect.
            if target.startswith('http://') or target.startswith('https://'):
                return redirect(target)
            else:
                html = f"""
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
                from django.http import HttpResponse
                return HttpResponse(html)

        # SSR/Browser UX: render a friendly close-tab page when requested or when browser prefers HTML
        accepts = (request.META.get('HTTP_ACCEPT', '') or '').lower()
        wants_html = ('text/html' in accepts) and ('application/json' not in accepts)
        if request.path.endswith('/callback/ssr/') or request.GET.get('render') == '1' or wants_html:
            html = """
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
                  // Try to close the window after a short delay (may be blocked by browser policies)
                  setTimeout(function(){ window.close(); }, 600);
                } catch (e) { /* no-op */ }
                </script>
            </body>
            </html>
            """
            from django.http import HttpResponse
            return HttpResponse(html)

        return Response(payload)

    def post(self, request):
        """Accept callback data via POST (bridge) and delegate to GET handler."""
        ser = OAuthCallbackSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        for k, v in request.data.items():
            request.GET._mutable = True  # type: ignore
            request.GET[k] = v  # type: ignore
            request.GET._mutable = False  # type: ignore
        return self.get(request)

#* Result of OAuth view to be called
class OAuthResultView(APIView):
    """
    Fetches the stored OAuth bridge payload (one-time) given a state.

    Used by SPA/mobile clients to retrieve the result after a deep link redirect.

    Path Parameter:
        - state_value (str): The state value used in the OAuth flow.

    Example Request:
        GET /api/v1/auth_api/oauth/result/<state_value>/

    Example Response (200):
        {
            "message": "Google OAuth success",
            "user_id": "42",
            "username": "john",
            ...
        }

    Error Responses:
        - 404: Not found (invalid state)
        - 409: Result not ready (payload not yet stored)
        - 410: Result already retrieved (one-time fetch)
    """
    permission_classes = [AllowAny]

    def get(self, request, state_value: str):
        """Fetch the stored OAuth result payload for the given state (one-time).
        Returns 202 if the result isn't ready yet, 410 if already retrieved, 404 if
        the state is unknown, and 200 with the payload on success.
        """
        try:
            oauth_state = OAuthState.objects.get(state=state_value)
        except OAuthState.DoesNotExist:
            return Response({'detail': 'Not found'}, status=status.HTTP_404_NOT_FOUND)
        # If no payload has been stored yet, treat this as "not ready" so SPA can continue polling.
        # Some deployed rows were observed with is_used=True but empty payload (race/partial write).
        # Return 202 Accepted so clients treat this as a pending result rather than a permanent 404.
        if not oauth_state.result_payload:
            logger.warning(f"[OAuthResultView] Result not ready for state={state_value} (used={oauth_state.used}, result_retrieved={oauth_state.result_retrieved})")
            return Response({'detail': 'Result not ready'}, status=status.HTTP_202_ACCEPTED)
        if oauth_state.result_retrieved:
            return Response({'detail': 'Result already retrieved'}, status=status.HTTP_410_GONE)
        data = json.loads(oauth_state.result_payload)
        oauth_state.result_retrieved = True
        oauth_state.save(update_fields=['result_retrieved'])
        return Response(data)

# -------------------------------- Providers -----------------------------------
class GoogleAuthorizeView(OAuthAuthorizeBase):
    """
    Starts the Google OAuth2 authorization flow.

    Inherits all behavior from OAuthAuthorizeBase.
    """
    provider = 'google'

class OpenRouterAuthorizeView(OAuthAuthorizeBase):
    """
    Starts the OpenRouter OAuth2 authorization flow.

    Inherits all behavior from OAuthAuthorizeBase.
    """
    provider = 'openrouter'

class GoogleCallbackView(OAuthCallbackBase):
    """
    Handles the callback from Google OAuth2.

    Inherits all behavior from OAuthCallbackBase.
    """
    provider = 'google'

class OpenRouterCallbackView(OAuthCallbackBase):
    """
    Handles the callback from OpenRouter OAuth2.

    Inherits all behavior from OAuthCallbackBase.
    """
    provider = 'openrouter'

class GitHubAuthorizeView(OAuthAuthorizeBase):
    """
    Starts the GitHub OAuth2 authorization flow.

    Handles both SSR (server-side rendered) and bridge (SPA/mobile) flows.
    """
    provider = 'github'

    def get(self, request):
        """Construct and return (or redirect to) the GitHub authorization URL."""
        import secrets, urllib.parse
        state = secrets.token_urlsafe(24)
        scope = request.query_params.get('scope', 'read:user user:email')
        redirect_uri = getattr(settings, 'GITHUB_REDIRECT_URI', '')
        if not redirect_uri:
            return Response({'detail': 'redirect_uri not configured'}, status=status.HTTP_400_BAD_REQUEST)
        params = {
            'client_id': getattr(settings, 'GITHUB_CLIENT_ID', ''),
            'redirect_uri': redirect_uri,
            'scope': scope,
            'state': state,
            'allow_signup': 'true',
        }
        authorize_url = f"https://github.com/login/oauth/authorize?{urllib.parse.urlencode(params)}"
        # Save state for CSRF protection if desired
        expires_at = timezone.now() + timezone.timedelta(seconds=OAUTH_STATE_TTL_SECONDS)
        oauth_state = OAuthState.objects.create(
            provider='github',
            state=state,
            code_challenge=None,
            code_verifier=None,
            redirect_uri=redirect_uri,
            mobile_redirect=None,
            scope=scope,
            expires_at=expires_at,
            user=request.user if request.user.is_authenticated else None,
        )
        if request.query_params.get('mode') == 'redirect':
            return redirect(authorize_url)
        return Response({
            'authorize_url': authorize_url,
            'state': state,
            'state_id': str(oauth_state.oauth_state_id),
            'expires_at': expires_at.isoformat(),
            'bridge': False
        })

class GitHubCallbackView(OAuthCallbackBase):
    """
    Handles the callback from GitHub OAuth2.
    """
    provider = 'github'

    def get(self, request):
        """Process GitHub callback: exchange code, upsert user, issue app JWTs."""
        import requests
        code = request.GET.get('code')
        state = request.GET.get('state')
        try:
            oauth_state = OAuthState.objects.get(state=state, provider='github')
        except OAuthState.DoesNotExist:
            return Response({'detail': 'Invalid state'}, status=status.HTTP_400_BAD_REQUEST)
        if oauth_state.used and not oauth_state.is_expired():
            return Response({'detail': 'State already used', 'error_code': 'state_used'}, status=status.HTTP_409_CONFLICT)
        if oauth_state.is_expired():
            return Response({'detail': 'State expired', 'error_code': 'state_expired'}, status=status.HTTP_400_BAD_REQUEST)
        if not code:
            return Response({'detail': 'Missing authorization code'}, status=status.HTTP_400_BAD_REQUEST)
        # Exchange code for token
        token_resp = requests.post(
            'https://github.com/login/oauth/access_token',
            data={
                'client_id': getattr(settings, 'GITHUB_CLIENT_ID', ''),
                'client_secret': getattr(settings, 'GITHUB_CLIENT_SECRET', ''),
                'code': code,
                'redirect_uri': oauth_state.redirect_uri,
                'state': state,
            },
            headers={'Accept': 'application/json'}
        )
        token_data = token_resp.json()
        access_token = token_data.get('access_token')
        if not access_token:
            return Response({'detail': 'Token exchange failed', 'provider_payload': token_data}, status=status.HTTP_400_BAD_REQUEST)
        # Get user info
        user_resp = requests.get(
            'https://api.github.com/user',
            headers={'Authorization': f'token {access_token}'}
        )
        user_data = user_resp.json()
        email = user_data.get('email')
        if not email:
            # Try to fetch primary email if not public
            emails_resp = requests.get(
                'https://api.github.com/user/emails',
                headers={'Authorization': f'token {access_token}'}
            )
            emails = emails_resp.json()
            if isinstance(emails, list):
                primary = next((e for e in emails if e.get('primary')), None)
                email = primary.get('email') if primary else None
        user = oauth_state.user_id
        if not user:
            if email and Custom_User.objects.filter(email=email).exists():
                user = Custom_User.objects.get(email=email)
            else:
                base_username = (user_data.get('login') or f"gh_{uuid.uuid4().hex[:6]}")
                candidate = base_username
                idx = 1
                while Custom_User.objects.filter(username=candidate).exists():
                    candidate = f"{base_username}{idx}"
                    idx += 1
                user = Custom_User.objects.create(
                    username=candidate,
                    email=email or f"pending_{uuid.uuid4().hex}@github.local",
                    email_verified=bool(email),
                    is_github_user=True
                )
        else:
            update_fields = []
            if email and not user.email:
                user.email = email
                update_fields.append('email')
            if not getattr(user, 'is_github_user', False):
                user.is_github_user = True
                update_fields.append('is_github_user')
            if email and not user.email_verified:
                user.email_verified = True
                update_fields.append('email_verified')
            if update_fields:
                user.save(update_fields=update_fields)
        ProviderOAuthToken.objects.update_or_create(
            user_id=user,
            provider='github',
            defaults={
                'access_token': access_token,
                'refresh_token': None,
                'expires_at': None,
                'scope': oauth_state.scope,
                'token_type': token_data.get('token_type') or 'Bearer',
            }
        )
        oauth_state.mark_used()
        refresh = RefreshToken.for_user(user)
        payload = {
            'message': 'GitHub OAuth success',
            'user_id': str(user.pk),
            'username': user.username,
            'access_token': str(refresh.access_token),
            'refresh_token': str(refresh),
            'provider_scope': oauth_state.scope,
            'provider_access_token': access_token,
            'provider_expires_at': None,
            'email': email,
            'email_verified': user.email_verified,
            'is_github_user': getattr(user, 'is_github_user', False),
        }
        # SSR: render HTML if requested
        if request.path.endswith('/callback/ssr/') or request.GET.get('render') == '1':
            html = """
            <html>
            <head>
                <title>Authentication Complete</title>
                <style>
                body { font-family: sans-serif; text-align: center; margin-top: 10%; }
                .msg { font-size: 1.5em; color: #2e7d32; }
                </style>
            </head>
            <body>
                <div class="msg"> All is fine! You may close this tab.</div>
                <script>
                if (window.opener) {
                    window.opener.postMessage({success: true, type: "oauth"}, "*");
                }
                </script>
            </body>
            </html>
            """
            from django.http import HttpResponse
            return HttpResponse(html)
        return Response(payload)

class MicrosoftAuthorizeView(OAuthAuthorizeBase):
    """
    Starts the Microsoft OAuth2 (Azure AD) authorization flow.

    Handles both SSR (server-side rendered) and bridge (SPA/mobile) flows.
    """
    provider = 'microsoft'

    def get(self, request):
        """Construct and return (or redirect to) the Microsoft authorization URL."""
        import secrets, urllib.parse
        state = secrets.token_urlsafe(24)
        scope = request.query_params.get('scope', 'openid email profile User.Read')
        redirect_uri = getattr(settings, 'MS_REDIRECT_URI', '')
        if not redirect_uri:
            return Response({'detail': 'redirect_uri not configured'}, status=status.HTTP_400_BAD_REQUEST)
        params = {
            'client_id': getattr(settings, 'MS_CLIENT_ID', ''),
            'response_type': 'code',
            'redirect_uri': redirect_uri,
            'response_mode': 'query',
            'scope': scope,
            'state': state,
        }
        authorize_url = f"https://login.microsoftonline.com/common/oauth2/v2.0/authorize?{urllib.parse.urlencode(params)}"
        expires_at = timezone.now() + timezone.timedelta(seconds=OAUTH_STATE_TTL_SECONDS)
        oauth_state = OAuthState.objects.create(
            provider='microsoft',
            state=state,
            code_challenge=None,
            code_verifier=None,
            redirect_uri=redirect_uri,
            mobile_redirect=None,
            scope=scope,
            expires_at=expires_at,
            user=request.user if request.user.is_authenticated else None,
        )
        if request.query_params.get('mode') == 'redirect':
            return redirect(authorize_url)
        return Response({
            'authorize_url': authorize_url,
            'state': state,
            'state_id': str(oauth_state.oauth_state_id),
            'expires_at': expires_at.isoformat(),
            'bridge': False
        })

class MicrosoftCallbackView(OAuthCallbackBase):
    """
    Handles the callback from Microsoft OAuth2 (Azure AD).
    """
    provider = 'microsoft'

    def get(self, request):
        """Process Microsoft callback: exchange code, upsert user, issue app JWTs."""
        import requests
        code = request.GET.get('code')
        state = request.GET.get('state')
        try:
            oauth_state = OAuthState.objects.get(state=state, provider='microsoft')
        except OAuthState.DoesNotExist:
            return Response({'detail': 'Invalid state'}, status=status.HTTP_400_BAD_REQUEST)
        if oauth_state.used and not oauth_state.is_expired():
            return Response({'detail': 'State already used', 'error_code': 'state_used'}, status=status.HTTP_409_CONFLICT)
        if oauth_state.is_expired():
            return Response({'detail': 'State expired', 'error_code': 'state_expired'}, status=status.HTTP_400_BAD_REQUEST)
        if not code:
            return Response({'detail': 'Missing authorization code'}, status=status.HTTP_400_BAD_REQUEST)
        # Exchange code for token
        token_resp = requests.post(
            'https://login.microsoftonline.com/common/oauth2/v2.0/token',
            data={
                'client_id': getattr(settings, 'MS_CLIENT_ID', ''),
                'client_secret': getattr(settings, 'MS_CLIENT_SECRET', ''),
                'code': code,
                'redirect_uri': oauth_state.redirect_uri,
                'grant_type': 'authorization_code',
                'scope': oauth_state.scope,
            },
            headers={'Content-Type': 'application/x-www-form-urlencoded'}
        )
        token_data = token_resp.json()
        access_token = token_data.get('access_token')
        if not access_token:
            return Response({'detail': 'Token exchange failed', 'provider_payload': token_data}, status=status.HTTP_400_BAD_REQUEST)
        # Get user info
        user_resp = requests.get(
            'https://graph.microsoft.com/v1.0/me',
            headers={'Authorization': f'Bearer {access_token}'}
        )
        user_data = user_resp.json()
        email = user_data.get('mail') or user_data.get('userPrincipalName')
        user = oauth_state.user_id
        if not user:
            if email and Custom_User.objects.filter(email=email).exists():
                user = Custom_User.objects.get(email=email)
            else:
                base_username = (email.split('@')[0] if email else f"ms_{uuid.uuid4().hex[:6]}")
                candidate = base_username
                idx = 1
                while Custom_User.objects.filter(username=candidate).exists():
                    candidate = f"{base_username}{idx}"
                    idx += 1
                user = Custom_User.objects.create(
                    username=candidate,
                    email=email or f"pending_{uuid.uuid4().hex}@ms.local",
                    email_verified=bool(email),
                    is_ms_user=True
                )
        else:
            update_fields = []
            if email and not user.email:
                user.email = email
                update_fields.append('email')
            if not getattr(user, 'is_microsoft_user', False):
                user.is_microsoft_user = True
                update_fields.append('is_microsoft_user')
            if email and not user.email_verified:
                user.email_verified = True
                update_fields.append('email_verified')
            if update_fields:
                user.save(update_fields=update_fields)
        ProviderOAuthToken.objects.update_or_create(
            user_id=user,
            provider='microsoft',
            defaults={
                'access_token': access_token,
                'refresh_token': token_data.get('refresh_token'),
                'expires_at': None,
                'scope': oauth_state.scope,
                'token_type': token_data.get('token_type') or 'Bearer',
            }
        )
        oauth_state.mark_used()
        refresh = RefreshToken.for_user(user)
        payload = {
            'message': 'Microsoft OAuth success',
            'user_id': str(user.pk),
            'username': user.username,
            'access_token': str(refresh.access_token),
            'refresh_token': str(refresh),
            'provider_scope': oauth_state.scope,
            'provider_access_token': access_token,
            'provider_expires_at': None,
            'email': email,
            'email_verified': user.email_verified,
            'is_ms_user': getattr(user, 'is_ms_user', False),
        }
        # SSR: render HTML if requested
        if request.path.endswith('/callback/ssr/') or request.GET.get('render') == '1':
            html = """
            <html>
            <head>
                <title>Authentication Complete</title>
                <style>
                body { font-family: sans-serif; text-align: center; margin-top: 10%; }
                .msg { font-size: 1.5em; color: #2e7d32; }
                </style>
            </head>
            <body>
                <div class="msg">✅ All is fine! You may close this tab.</div>
                <script>
                if (window.opener) {
                    window.opener.postMessage({success: true, type: "oauth"}, "*");
                }
                </script>
            </body>
            </html>
            """
            from django.http import HttpResponse
            return HttpResponse(html)
        return Response(payload)
# -------------------------------- Providers -----------------------------------


class SendLoginOTPView(APIView):
    """Sends a 6-digit OTP for passwordless login with simple rate limiting in case of the first 1 not working or not being received."""
    permission_classes = [AllowAny]

    def post(self, request):
        """
        Deprecated endpoint: OTP login is disabled in this release.
        
        ser = SendOTPSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        email = cast(Dict[str, Any], ser.validated_data).get('email')
        if not email:
            return Response({'detail': 'Invalid data'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            user = Custom_User.objects.get(email=email)
        except Custom_User.DoesNotExist:
            return Response({'detail': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        now = timezone.now()
        # Reset rate window daily (simplistic)
        if user.login_otp_last_sent and (now - user.login_otp_last_sent).total_seconds() > OTP_RATE_LIMIT_WINDOW_SECONDS:
            user.login_otp_sent_count = 0
        if user.login_otp_sent_count >= OTP_RATE_LIMIT_MAX:
            return Response({'detail': 'Rate limit exceeded'}, status=status.HTTP_429_TOO_MANY_REQUESTS)
        otp = f"{random.randint(100000, 999999)}"
        user.login_otp = otp
        user.login_otp_created = now
        user.login_otp_last_sent = now
        user.login_otp_sent_count += 1
        user.save(update_fields=['login_otp','login_otp_created','login_otp_last_sent','login_otp_sent_count'])
        try:
            result = send_verified_email(
                subject="Your Login OTP",
                message=f"Your login OTP is: {otp}",
                recipient_list=[user.email],
                html_message=f"<b>Your login OTP is: {otp}</b>",
                verify_with_zeruh=True,
            )
            logger.info(f"[SendLoginOTPView] OTP email send result: {result}")
        except Exception as e:
            logger.warning(f"[SendLoginOTPView] OTP email send failed (non-fatal): {e}")
        logger.info(f"[SendLoginOTPView] OTP sent email={email} count={user.login_otp_sent_count}")
        return Response({'message': 'OTP sent'}, status=status.HTTP_200_OK)

        """
        return Response({'detail': 'OTP endpoints are deprecated in this release.'}, status=status.HTTP_410_GONE)

class VerifyLoginOTPView(APIView):
    """Verifies OTP and returns JWT tokens."""
    permission_classes = [AllowAny]

    def post(self, request):
        """
        Deprecated endpoint: OTP verification is disabled in this release.
        
        """
        return Response({'detail': 'OTP endpoints are deprecated in this release.'}, status=status.HTTP_410_GONE)


class LoginWithOTPView(APIView):
    """
    Handles user login with OTP (One Time Password).

    Example API Request (POST /api/v1/auth_api/login-with-otp/):
        {
            "email": "john@example.com"
        }

    Example API Response (200):
        {
            "message": "OTP sent successfully."
        }
    """
    permission_classes = [AllowAny]

    def post(self, request):
        """Deprecated endpoint: Login-with-OTP is disabled in this release."""
        return Response({'detail': 'OTP endpoints are deprecated in this release.'}, status=status.HTTP_410_GONE)
        

class EnableTOTPView(APIView):
    """
    Generates a TOTP secret and provisioning URI for the user to scan with Microsoft Authenticator.
    """
    permission_classes = [AllowAny]  # Or IsAuthenticated if you want

    def post(self, request):
        """Enable TOTP for the authenticated user and return provisioning details."""
        user = request.user
        if not user.is_authenticated:
            return Response({'detail': 'Authentication required.'}, status=401)
        # Generate a new secret
        secret = pyotp.random_base32()
        user.totp_secret = secret
        user.save(update_fields=['totp_secret'])
        # Generate provisioning URI for QR code
        issuer = "YourAppName"
        email = user.email or user.username
        uri = pyotp.totp.TOTP(secret).provisioning_uri(name=email, issuer_name=issuer)
        return Response({
            'secret': secret,
            'provisioning_uri': uri,
            'qr_code_url': f"https://api.qrserver.com/v1/create-qr-code/?data={urllib.parse.quote(uri)}"
        })

class VerifyTOTPView(APIView):
    """
    Verifies a TOTP code from the user's Authenticator app.
    """
    permission_classes = [AllowAny]  # Or IsAuthenticated

    def post(self, request):
        """Verify a provided TOTP code for the authenticated user and return status."""
        user = request.user
        if not user.is_authenticated:
            return Response({'detail': 'Authentication required.'}, status=401)
        code = request.data.get('code')
        if not user.totp_secret:
            return Response({'detail': 'TOTP not enabled.'}, status=400)
        totp = pyotp.TOTP(user.totp_secret)
        if totp.verify(code):
            return Response({'message': 'TOTP verified.'})
        else:
            return Response({'detail': 'Invalid code.'}, status=400)