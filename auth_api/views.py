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

""" class VisitorLoginView(APIView):

    API endpoint to allow a user to start a guest session as a Visitor (no account required).
    Handles creation of a Visitor object and returns session details.

    Example API Request (POST /api/v1/auth_api/visitor-login/):
        {
            "device_id": "abc123xyz"
        }

    Example API Response (201):
        {
            "message": "Visitor session started.",
            "anon_id": "e7b8c1d2-...",
            "device_id": "abc123xyz",
            "date_joined": "2025-08-01T12:34:56Z"
        }

    permission_classes = [AllowAny]

    def post(self, request):

        Handle POST request to start a visitor session.
        Validates input, creates a Custom_User with is_visitor=True, and returns session info with JWT access token.

        logger.info(f"[VisitorLoginView] Incoming visitor login request: data={request.data}")
        serializer = VisitorSerializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
            device_id = serializer.validated_data.get('device_id')
            # Try to find an existing guest user for this device_id
            guest_user = Custom_User.objects.filter(device_id=device_id, is_visitor=True).first()
            if not guest_user:
                # Create a new guest user
                guest_user = Custom_User.objects.create(
                    device_id=device_id,
                    is_visitor=True,
                )
            # Generate a temporary JWT token for the guest user
            refresh = RefreshToken.for_user(guest_user)
            access_token = str(refresh.access_token)
            resp_data = {
                "message": "Visitor session started.",
                "anon_id": str(getattr(guest_user, 'anon_id', guest_user.pk)),
                "device_id": guest_user.device_id,
                "date_joined": guest_user.date_joined,
                "access_token": access_token,
                "refresh_token": str(refresh),
            }
            logger.info(f"[VisitorLoginView] Visitor login success: status=201, resp={resp_data}")
            return Response(resp_data, status=status.HTTP_201_CREATED)
        except serializers.ValidationError as e:
            logger.warning(f"[VisitorLoginView] Visitor login failed: status=400, errors={e.detail}, req={request.data}")
            return Response(e.detail, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.exception(f"[VisitorLoginView] Unexpected visitor login error: {str(e)}, req={request.data}")
            return Response({"detail": "Visitor login failed due to a server error."},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)

"""

class RegisterView(APIView):
    """
    API endpoint to handle user registration.
    Accepts temp_id and device_id for visitor migration/upgrade.
    If the user already exists (by email, uuid, username, or temp_id), returns their JWT tokens and all their conversations/messages.
    Otherwise, creates a new user, sends a verification PIN, and returns onboarding tokens and data.
    """
    permission_classes = [AllowAny]

    def post(self, request):
        """
        Handle POST request for user registration.
        If user exists (by email, uuid, username, or temp_id), returns JWT tokens and all their data.
        If new, creates user, sends PIN, and returns onboarding tokens and data.
        Always persists device_id in related_devices.
        """
        logger.info(f"[RegisterView] Incoming registration request: data={request.data}")
        temp_id = (request.data.get("temp_id") or "").strip()
        device_id = (request.data.get("device_id") or "").strip()
        email = request.data.get('email')
        user_id = request.data.get('user_id') or request.data.get('uuid')
        username = request.data.get('username')
        user: Optional[Custom_User] = None
        #! Errors here for static casting by PYLANCE!
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
            logger.info(f"[RegisterView] Registration attempted for existing account: email={email} identifier={user_id or username or temp_id}")
            try:
                if not getattr(user, 'email_verified', False):
                    # Ensure a PIN exists and send it (best-effort, non-fatal)
                    pin = getattr(user, 'profile_email_pin', None)
                    if not pin:
                        pin = f"{random.randint(10000, 99999)}"
                        user.email_pin = pin
                        user.email_pin_created = timezone.now()
                        try:
                            user.save(update_fields=['email_pin', 'email_pin_created'])
                        except Exception:
                            user.save()
                    try:
                        # Use send_verified_email (Zeruh + Maileroo) then fallback to send_mail if not sent
                        result = send_verified_email(
                            subject="Your Email Verification PIN",
                            message=f"Your verification PIN is: {pin}",
                            recipient_list=[user.email],
                            html_message=f"<b>Your verification PIN is: {pin}</b>",
                            verify_with_zeruh=True,
                        )
                        logger.info(f"[RegisterView] Resend PIN result: {result}")
                        recipient_result = result.get(user.email) if isinstance(result, dict) else None
                        if not recipient_result or not recipient_result.get('sent'):
                            try:
                                send_mail(
                                    subject="Your Email Verification PIN",
                                    message=f"Your verification PIN is: {pin}",
                                    from_email=getattr(settings, 'DEFAULT_FROM_EMAIL', 'no-reply@example.com'),
                                    recipient_list=[user.email],
                                    fail_silently=False,
                                )
                                logger.info(f"[RegisterView] Fallback direct send_mail succeeded for {user.email}")
                            except Exception as e:
                                logger.warning(f"[RegisterView] Fallback direct send_mail failed for {user.email}: {e}")
                    except Exception:
                        logger.warning("[RegisterView] Failed to resend verification PIN to existing user (non-fatal)")
                    # Inform client to check email — do NOT issue tokens or return user data
                    return Response({'detail': 'Email already registered. Check your email for verification PIN.'}, status=status.HTTP_200_OK)
            except Exception:
                logger.exception("[RegisterView] Error while handling existing user during registration attempt")
            # Generic response to avoid leaking any info for verified accounts
            return Response({'detail': 'invalid credentials.'}, status=status.HTTP_409_CONFLICT)
        
        if not user:
            serializer = RegisterSerializer(data=request.data)
            try:
                serializer.is_valid(raise_exception=True)
                user: Custom_User = cast(Custom_User, serializer.save())  # type: ignore[assignment]
                raw_pw: str = str(request.data.get('user_password') or '')
                BACKEND_SALT = getattr(settings, 'BACKEND_PASSWORD_SALT', 'fallback_dev_salt')
                salted = (raw_pw + BACKEND_SALT).encode('utf-8')
                backend_hash = hashlib.sha256(salted).hexdigest()
                user.user_password = backend_hash
                # Generate 5-digit PIN for email verification
                pin = f"{random.randint(10000, 99999)}"
                user.profile_email_pin = pin
                user.profile_email_pin_created = timezone.now()
                user.email_verified = False
                if temp_id:
                    user.temp_id = temp_id
                    user.is_visitor = True
                user.save()
                # Send PIN email (best effort)
                try:
                    result = send_verified_email(
                        subject="Your Email Verification PIN",
                        message=f"Your verification PIN is: {pin}",
                        recipient_list=[user.email],
                        html_message=f"<b>Your verification PIN is: {pin}</b>",
                        verify_with_zeruh=True,
                    )
                    logger.info(f"[RegisterView] PIN email send result: {result}")
                    # fallback: if Zeruh prevented send, try direct send_mail (best-effort)
                    recipient_result = result.get(user.email) if isinstance(result, dict) else None
                    if not recipient_result or not recipient_result.get('sent'):
                        try:
                            send_mail(
                                subject="Your Email Verification PIN",
                                message=f"Your verification PIN is: {pin}",
                                from_email=getattr(settings, 'DEFAULT_FROM_EMAIL', None),
                                recipient_list=[user.email],
                                html_message=f"<b>Your verification PIN is: {pin}</b>",
                                fail_silently=False,
                            )
                            logger.info(f"[RegisterView] Fallback direct send_mail succeeded for {user.email}")
                        except Exception as e:
                            logger.warning(f"[RegisterView] Fallback direct send_mail failed for {user.email}: {e}")
                except Exception as e:
                    logger.warning(f"[RegisterView] PIN email send failed (non-fatal): {e}")
                created = True
            except serializers.ValidationError as e:
                logger.warning(f"[RegisterView] Registration failed: status=400, errors={e.detail}, req={request.data}")
                return Response(e.detail, status=status.HTTP_400_BAD_REQUEST)
            except Exception as e:
                logger.exception(f"[RegisterView] Unexpected registration error: {str(e)}, req={request.data}")
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
            for msg in conv.messages.all():
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
    """Verify the 5-digit PIN sent to the user's email."""
    permission_classes = [AllowAny]

    class InputSerializer(serializers.Serializer):
        email = serializers.EmailField()
        pin = serializers.CharField(max_length=5)

    def post(self, request):  # type: ignore[override]
        logger.info(f"[EmailPinVerifyView] Incoming PIN verify request: data={request.data}")
        ser = self.InputSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        validated_data = cast(Dict[str, Any], ser.validated_data)
        email = validated_data.get('email')
        pin = validated_data.get('pin')
        if not email or not pin:
            return Response({"detail": "Invalid data."}, status=status.HTTP_400_BAD_REQUEST)
        try:
            user = Custom_User.objects.get(email=email)
        except Custom_User.DoesNotExist:
            return Response({"detail": "User not found."}, status=status.HTTP_404_NOT_FOUND)
        if getattr(user, 'profile_email_pin', None) != pin:
            return Response({"detail": "Invalid PIN."}, status=status.HTTP_400_BAD_REQUEST)
        created = getattr(user, 'profile_email_pin_created', None)
        if not created or (timezone.now() - created).total_seconds() > 600:
            return Response({"detail": "PIN expired."}, status=status.HTTP_400_BAD_REQUEST)
        user.email_verified = True
        # user.profile_email_pin = None  # Removed because attribute does not exist
        user.save(update_fields=["email_verified"])
        return Response({"message": "Email verified. You may now set your password."})

class SetPasswordAfterEmailVerifyView(APIView):
    """Set password after successful email PIN verification."""
    permission_classes = [AllowAny]

    class InputSerializer(serializers.Serializer):
        email = serializers.EmailField()
        password = serializers.CharField(min_length=6)
  
    def post(self, request):  # type: ignore[override]
            logger.info(f"[SetPasswordAfterEmailVerifyView] Incoming set-password request: data={request.data}")
            ser = self.InputSerializer(data=request.data)
            ser.is_valid(raise_exception=True)
            validated_data = cast(Dict[str, Any], ser.validated_data)
            email = validated_data.get('email')
            frontend_hashed_password = validated_data.get('password', '')
            if not email or not frontend_hashed_password:
                return Response({"detail": "Invalid data."}, status=status.HTTP_400_BAD_REQUEST)
            try:
                user = Custom_User.objects.get(email=email)
            except Custom_User.DoesNotExist:
                return Response({"detail": "User not found."}, status=status.HTTP_404_NOT_FOUND)
            if not getattr(user, 'email_verified', False):
                return Response({"detail": "Email not verified."}, status=status.HTTP_400_BAD_REQUEST)
            BACKEND_SALT = getattr(settings, 'BACKEND_PASSWORD_SALT', 'fallback_dev_salt')
            backend_hash = hashlib.sha256((frontend_hashed_password + BACKEND_SALT).encode('utf-8')).hexdigest()
            user.user_password = backend_hash
            user.save(update_fields=["user_password"])
            return Response({"message": "Password set successfully. You may now log in."})


class LoginView(APIView):
    """
    Handles user login and JWT token issuance.

    Example API Request (POST /api/v1/auth_api/login/):
        {
            "email": "john@example.com",
            "password": "hashedpassword123"
        }

    Example API Response (200):
        {
            "message": "Login successful",
            "user_id": 42,
            "access_token": "jwt-access-token",
            "refresh_token": "jwt-refresh-token",
            "email_verified": true,
            "conversations": [
                {
                    "conversation_id": "c1",
                    "title": "My Conversation",
                    "messages": [
                        {
                            "message_id": "m1",
                            "content": "Hello!"
                        }
                    ]
                }
            ],
            "attachments": [
                {
                    "id": 1,
                    "type": "image",
                    "file_path": "/media/attachments/1.png"
                }
            ]
        }
    """
    permission_classes = [AllowAny]

    def post(self, request):
        logger.info(f"[LoginView] Incoming login request: data={request.data}")
        serializer = LoginSerializer(data=request.data, context={'request': request})
        try:
            serializer.is_valid(raise_exception=True)
            data = serializer.validated_data
            user: Custom_User = cast(Custom_User, data.get('user', None))  # type: ignore[assignment]
            refresh = RefreshToken.for_user(user)

            # Fetch conversations and messages
            from chat_api.models import Conversation
            from chat_api.models.attachment import Attachment
            from user_mang.serializers import ConversationSerializer, AttachmentSerializer

            conversations = Conversation.objects.filter(user_id=user).prefetch_related("messages")
            conv_serializer = ConversationSerializer(conversations, many=True)

            attachments = Attachment.objects.filter(user_id=user)
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
                user=request.user if request.user.is_authenticated else None,
            )
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
                user=request.user if request.user.is_authenticated else None,
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
                user=request.user if request.user.is_authenticated else None,
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
                user=request.user if request.user.is_authenticated else None,
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
            status_code, token_payload = exchange_google_token(str(code or ''), str(oauth_state.code_verifier or ''), str(oauth_state.redirect_uri or ''))
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
                user=user,
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
                user=user,
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

        # Bridge deep link
        if oauth_state.mobile_redirect:
            oauth_state.result_payload = json.dumps(payload)
            oauth_state.save(update_fields=["result_payload"])
            mobile_url = f"{oauth_state.mobile_redirect}?state={urllib.parse.quote(state_value)}&bridge=1"
            return redirect(mobile_url)
        # SSR: render HTML if requested
        # ...existing code...
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

    def post(self, request):
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
        try:
            oauth_state = OAuthState.objects.get(state=state_value)
        except OAuthState.DoesNotExist:
            return Response({'detail': 'Not found'}, status=status.HTTP_404_NOT_FOUND)
        if not oauth_state.result_payload:
            return Response({'detail': 'Result not ready'}, status=status.HTTP_409_CONFLICT)
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
            user=user,
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
            user=user,
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

class VerifyLoginOTPView(APIView):
    """Verifies OTP and returns JWT tokens."""
    permission_classes = [AllowAny]

    def post(self, request):
        ser = VerifyOTPSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        validated = cast(Dict[str, Any], ser.validated_data)
        email = validated.get('email')
        otp = validated.get('otp')
        if not email or not otp:
            return Response({'detail': 'Invalid data'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            user = Custom_User.objects.get(email=email)
        except Custom_User.DoesNotExist:
            return Response({'detail': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        if not user.login_otp or user.login_otp != otp:
            return Response({'detail': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)
        if not user.login_otp_created or (timezone.now() - user.login_otp_created).total_seconds() > OTP_EXPIRY_SECONDS:
            return Response({'detail': 'OTP expired'}, status=status.HTTP_400_BAD_REQUEST)
        # Clear OTP
        user.login_otp = None
        user.login_otp_created = None
        user.save(update_fields=['login_otp','login_otp_created'])
        refresh = RefreshToken.for_user(user)
        logger.info(f"[VerifyLoginOTPView] OTP verified user={user.pk}")
        return Response({
            'message': 'Login successful',
            'user_id': str(user.pk),
            'access_token': str(refresh.access_token),
            'refresh_token': str(refresh),
        }, status=status.HTTP_200_OK)


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
        logger.info(f"[LoginWithOTPView] Incoming OTP login request: data={request.data}")
        serializer = LoginSerializer(data=request.data, context={'request': request})
        try:
            serializer.is_valid(raise_exception=True)
            user = serializer.validated_data['user']
            # Here you would generate and send the OTP
            resp_data = {"message": "OTP sent successfully."}
            logger.info(f"[LoginWithOTPView] OTP sent: status=200, user_id={user.pk}, resp={resp_data}")
            return Response(resp_data, status=status.HTTP_200_OK)
        except Exception as e:
            logger.exception(f"[LoginWithOTPView] Login with OTP failed: {str(e)}, req={request.data}")
            return Response({"detail": "Login with OTP failed."}, status=status.HTTP_400_BAD_REQUEST)
        

class EnableTOTPView(APIView):
    """
    Generates a TOTP secret and provisioning URI for the user to scan with Microsoft Authenticator.
    """
    permission_classes = [AllowAny]  # Or IsAuthenticated if you want

    def post(self, request):
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