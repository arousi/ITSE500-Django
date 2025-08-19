import logging
import random
import hashlib
import uuid
import secrets
import base64
import string
import requests
import json
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
from rest_framework.permissions import AllowAny
from rest_framework_simplejwt.tokens import RefreshToken
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
    """Build the OpenRouter authorize URL following current PKCE docs.

    Docs: https://openrouter.ai/docs/use-cases/oauth-pkce

    OpenRouter's published PKCE flow (Aug 2025) does NOT require a client_id. The
    minimal required params are:
        - callback_url
        - (optionally) code_challenge & code_challenge_method=S256 for PKCE

    We still append a 'state' parameter we manage server-side for CSRF protection; the
    provider should ignore unknown params if not used. "scope" is retained only for
    potential future compatibility but is not currently documented as required.
    """
    base_auth = getattr(settings, 'OPENROUTER_AUTH_URL', 'https://openrouter.ai/auth')
    # Use documented param 'callback_url' (our variable redirect_uri) and PKCE fields.
    # Preserve state for our validation even if OpenRouter ignores it.
    params = {
        'callback_url': redirect_uri,
        'code_challenge': code_challenge,
        'code_challenge_method': 'S256',
        'state': state,
    }
    # Only include scope if explicitly requested (legacy / experimental)
    if scope:
        params['scope'] = scope
    # Build query string
    from urllib.parse import urlencode
    return f"{base_auth}?{urlencode(params)}"

def exchange_openrouter_token(code: str, code_verifier: str, redirect_uri: str):
    """Exchange authorization code for a user-controlled OpenRouter API key.

    Per docs (Aug 2025): POST https://openrouter.ai/api/v1/auth/keys with JSON:
        { code, code_verifier, code_challenge_method: 'S256' }

    Returns JSON:
        { key: '<API_KEY>' }

    We return (status_code, payload) for parity with google helper.
    """
    token_url = getattr(settings, 'OPENROUTER_TOKEN_URL', 'https://openrouter.ai/api/v1/auth/keys')
    json_body = {
        'code': code,
        'code_verifier': code_verifier,
        'code_challenge_method': 'S256',  # must match what we used building authorize URL
    }
    # redirect/callback not currently required in exchange per docs; include if a future version needs it
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
        f"{base_auth}?response_type=code&client_id={client_id}" \
        f"&redirect_uri={redirect_uri}&scope={scope}&state={state}&access_type=offline&prompt=consent" \
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
    Creates a new user, generates a verification PIN, and sends it to the user's email.

    Example API Request (POST /api/v1/auth_api/reg/):
        {
            "username": "john_doe",
            "email": "john@example.com",
            "password": "hashedpassword123"
        }

    Example API Response (201):
        {
            "message": "User created. Verification PIN sent to email.",
            "user_id": "42",
            "access_token": "jwt-access-token",
            "refresh_token": "jwt-refresh-token",
            "email": "john@example.com",
            "onboarding": true
        }
    """
    permission_classes = [AllowAny]

    def post(self, request):
        """
        Handle POST request for user registration.
        Validates input, creates user, generates PIN, sends email, and returns onboarding tokens.
        """
        logger.info(f"[RegisterView] Incoming registration request: data={request.data}")
        serializer = RegisterSerializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
            user: Custom_User = cast(Custom_User, serializer.save())  # type: ignore[assignment]
            # Hash password with backend salt same as login flow expects
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
            user.save()
            # Send PIN email (best effort)
            try:
                send_mail(
                    subject="Your Email Verification PIN",
                    message=f"Your verification PIN is: {pin}",
                    from_email=getattr(settings, 'DEFAULT_FROM_EMAIL', 'no-reply@example.com'),
                    recipient_list=[user.email],
                    fail_silently=True,
                )
            except Exception:
                logger.warning("[RegisterView] PIN email send failed (non-fatal)")
            refresh = RefreshToken.for_user(user)
            resp_data = {
                "message": "User created. Verification PIN sent to email.",
                "user_id": str(user.user_id),
                "access_token": str(refresh.access_token),
                "refresh_token": str(refresh),
                "email": user.email,
                "onboarding": True
            }
            logger.info(f"[RegisterView] Registration success: status=201, user_id={user.user_id}")
            return Response(resp_data, status=status.HTTP_201_CREATED)
        except serializers.ValidationError as e:
            logger.warning(f"[RegisterView] Registration failed: status=400, errors={e.detail}, req={request.data}")
            return Response(e.detail, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.exception(f"[RegisterView] Unexpected registration error: {str(e)}, req={request.data}")
            return Response({"detail": "Registration failed due to a server error."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

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
        user.profile_email_pin = None
        user.save(update_fields=["email_verified", "profile_email_pin"])
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
            "email_verified": true
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
            resp_data = {
                "message": "Login successful",
                "user_id": user.pk,
                "access_token": str(refresh.access_token),
                "refresh_token": str(refresh),
                "email_verified": getattr(user, "email_verified", False)  # Updated field name
            }
            logger.info(f"[LoginView] Login success: status=200, user_id={user.pk}, resp={resp_data}")
            return Response(resp_data, status=status.HTTP_200_OK)
        except serializers.ValidationError as e:
            error_detail = str(e.detail)
            logger.warning(f"[LoginView] Login failed: status=400, errors={e.detail}, req={request.data}")
            # Custom error responses based on validation error
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
    def post(self, request):
        logger.info(f"[LogoutView] Incoming logout request: user_id={getattr(request.user, 'pk', None)}")
        logout(request)
        logger.info(f"[LogoutView] User logged out: {request.user.pk if request.user.is_authenticated else 'anonymous'}")
        resp_data = {"detail": "Logged out successfully."}
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


class GoogleOAuthView(APIView):
    """
    Handles Google OAuth2.0 authentication.

    Example API Request (POST /api/v1/auth_api/google-oauth/):
        {
            "token": "google-oauth-token"
        }

    Example API Response (200):
        {
            "message": "Google OAuth success"
        }

    Example API Response (401):
        {
            "error": "Invalid token"
        }
    """
    permission_classes = [AllowAny]

    def post(self, request):
        logger.info(f"[GoogleOAuthView] Incoming Google OAuth request: data={request.data}")
        token = request.data.get('token')
        if token == 'valid_google_token':
            resp_data = {'message': 'Google OAuth success'}
            logger.info(f"[GoogleOAuthView] Google OAuth success: status=200, token={token}, resp={resp_data}")
            return Response(resp_data, status=status.HTTP_200_OK)
        logger.warning(f"[GoogleOAuthView] Invalid Google token: {token}")
        resp_data = {'error': 'Invalid token'}
        logger.info(f"[GoogleOAuthView] Google OAuth failed: status=401, token={token}, resp={resp_data}")
        return Response(resp_data, status=status.HTTP_401_UNAUTHORIZED)


class OpenRouterOAuthView(APIView):
    """
    Handles OpenRouter OAuth2.0 authentication.

    Example API Request (POST /api/v1/auth_api/openrouter-oauth/):
        {
            "token": "openrouter-oauth-token"
        }

    Example API Response (200):
        {
            "message": "OpenRouter OAuth success"
        }

    Example API Response (401):
        {
            "error": "Invalid token"
        }
    """
    permission_classes = [AllowAny]

    def post(self, request):
        logger.info(f"[OpenRouterOAuthView] Incoming OpenRouter OAuth request: data={request.data}")
        token = request.data.get('token')
        if token == 'valid_openrouter_token':
            resp_data = {'message': 'OpenRouter OAuth success'}
            logger.info(f"[OpenRouterOAuthView] OpenRouter OAuth success: status=200, token={token}, resp={resp_data}")
            return Response(resp_data, status=status.HTTP_200_OK)
        logger.warning(f"[OpenRouterOAuthView] Invalid OpenRouter token: {token}")
        resp_data = {'error': 'Invalid token'}
        logger.info(f"[OpenRouterOAuthView] OpenRouter OAuth failed: status=401, token={token}, resp={resp_data}")
        return Response(resp_data, status=status.HTTP_401_UNAUTHORIZED)


class OpenRouterAuthorizeView(APIView):
    """Initiates PKCE OAuth flow for OpenRouter (SSR friendly).

    GET returns JSON with {authorize_url, state_id} for mobile / SPA.
    """
    permission_classes = [AllowAny]

    def get(self, request):
        base_ser = OAuthAuthorizeRequestSerializer(data=request.query_params)
        base_ser.is_valid(raise_exception=True)
        base_data = cast(Dict[str, Any], base_ser.validated_data)
        scope = base_data.get('scope') or 'openid'
        # Ensure OpenRouter optional offline scope if supported by provider spec
        if 'offline_access' not in scope.split():
            scope = scope + ' offline_access'
        orig_redirect = base_data.get('redirect_uri')
        redirect_uri = orig_redirect or getattr(settings, 'OPENROUTER_REDIRECT_URI', '')
        mobile_redirect: Optional[str] = None
        # Bridge: if client supplied a custom scheme, keep it separate and use server registered redirect for provider
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
        logger.info(f"[OpenRouterAuthorizeView] Generated state={state} id={oauth_state.id} redirect={redirect_uri} mobile_redirect={mobile_redirect}")
        return Response({'authorize_url': authorize_url,'state': state,'state_id': str(oauth_state.id),'expires_at': expires_at.isoformat(),'bridge': bool(mobile_redirect)})


class OpenRouterCallbackView(APIView):
    """Handles OAuth callback: validates state, exchanges code, stores tokens, returns JWT if new user."""
    permission_classes = [AllowAny]

    def post(self, request):
        ser = OAuthCallbackSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        cb_data = cast(Dict[str, Any], ser.validated_data)
        state_value = cb_data.get('state') or ''
        code = cb_data.get('code') or ''
        error = cb_data.get('error') or ''
        try:
            oauth_state = OAuthState.objects.get(state=state_value, provider='openrouter')
        except OAuthState.DoesNotExist:
            logger.warning(f"[OpenRouterCallbackView] Invalid state={state_value}")
            return Response({'detail': 'Invalid state'}, status=status.HTTP_400_BAD_REQUEST)
        if error:
            logger.warning(f"[OpenRouterCallbackView] Provider error state={state_value} error={error}")
            return Response({'detail': error}, status=status.HTTP_400_BAD_REQUEST)
        if oauth_state.used or oauth_state.is_expired():
            logger.warning(f"[OpenRouterCallbackView] Expired/used state={state_value}")
            return Response({'detail': 'State expired or already used'}, status=status.HTTP_400_BAD_REQUEST)
        if not code:
            return Response({'detail': 'Missing authorization code'}, status=status.HTTP_400_BAD_REQUEST)
        code_str = str(code or '')
        status_code, token_payload = exchange_openrouter_token(code_str, str(oauth_state.code_verifier or ''), str(oauth_state.redirect_uri or ''))
        if status_code != 200:
            logger.warning(f"[OpenRouterCallbackView] Token exchange failed state={state_value} status={status_code} payload={token_payload}")
            return Response({'detail': 'Token exchange failed', 'provider_payload': token_payload}, status=status.HTTP_400_BAD_REQUEST)

        access_token = token_payload.get('key') or token_payload.get('access_token')
        refresh_token = None  # Not provided by current spec
        scope = oauth_state.scope
        token_type = 'api_key'
        if not access_token:
            logger.error(f"[OpenRouterCallbackView] Missing 'key' in provider payload state={state_value} payload={token_payload}")
            return Response({'detail': 'Provider did not return API key', 'provider_payload': token_payload}, status=status.HTTP_400_BAD_REQUEST)
        user = oauth_state.user
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
        token_obj, created = ProviderOAuthToken.objects.update_or_create(
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
        logger.info(f"[OpenRouterCallbackView] Persisted provider token user={user.pk} created={created} token_id={token_obj.id}")
        oauth_state.mark_used()
        refresh = RefreshToken.for_user(user)
        logger.info(f"[OpenRouterCallbackView] OAuth success user={user.pk} state={state_value}")
        expose_provider_token = getattr(settings, 'OPENROUTER_EXPOSE_PROVIDER_TOKEN', True)
        provider_payload: Dict[str, Any] = {
            'provider_access_token': access_token if expose_provider_token else None,
            'provider_refresh_token': None,
            'provider_token_type': token_type,
            'provider_scope': scope,
            'provider_expires_at': None,
        }
        resp = {
            'message': 'OpenRouter OAuth success',
            'user_id': str(user.pk),
            'access_token': str(refresh.access_token),
            'refresh_token': str(refresh),
            'is_openrouter_user': getattr(user, 'is_openrouter_user', False),
            'is_google_user': getattr(user, 'is_google_user', False),
            **provider_payload,
        }
        return Response(resp)


class OpenRouterAuthorizeSSRView(APIView):
    """SSR flow: redirect user to provider directly (browser based)."""
    permission_classes = [AllowAny]

    def get(self, request):
        # Default scope for OpenRouter; ensure offline_access present for potential future refresh semantics
        scope = request.GET.get('scope', 'openid offline_access') or 'openid offline_access'
        if 'offline_access' not in scope.split():
            scope = scope + ' offline_access'
        # Prefer SSR-specific redirect first, fallback to generic
        redirect_uri = getattr(settings, 'OPENROUTER_REDIRECT_URI_SSR', '') or getattr(settings, 'OPENROUTER_REDIRECT_URI', '')
        if not redirect_uri:
            # Fallback: build absolute URL to SSR callback
            try:
                redirect_uri = request.build_absolute_uri(reverse('openrouter-callback-ssr'))
            except Exception:
                return Response({'detail': 'redirect_uri not configured'}, status=status.HTTP_400_BAD_REQUEST)
        code_verifier = generate_code_verifier()
        code_challenge = generate_code_challenge(code_verifier)
        state = secrets.token_urlsafe(24)
        expires_at = timezone.now() + timezone.timedelta(seconds=OAUTH_STATE_TTL_SECONDS)
        OAuthState.objects.create(
            provider='openrouter',
            state=state,
            code_challenge=code_challenge,
            code_verifier=code_verifier,
            redirect_uri=redirect_uri,
            scope=scope,
            expires_at=expires_at,
            user=request.user if request.user.is_authenticated else None,
        )
        authorize_url = build_openrouter_authorize_url(state, code_challenge, scope, redirect_uri)
        return redirect(authorize_url)


class OpenRouterCallbackSSRView(APIView):
    """SSR callback: exchanges code and renders template that posts message to opener."""
    permission_classes = [AllowAny]

    template_name_success = 'auth/openrouter_callback_success.html'
    template_name_error = 'auth/openrouter_callback_error.html'

    def get(self, request):
        # Accept query params
        ser = OAuthCallbackSerializer(data=request.GET)
        ser.is_valid(raise_exception=True)
        cb_data = cast(Dict[str, Any], ser.validated_data)
        state_value = cb_data.get('state') or ''
        code = cb_data.get('code') or ''
        error = cb_data.get('error') or ''
        context = {}
        try:
            oauth_state = OAuthState.objects.get(state=state_value, provider='openrouter')
        except OAuthState.DoesNotExist:
            context['error'] = 'Invalid state'
            return render(request, self.template_name_error, context, status=400)
        if error:
            context['error'] = error
            return render(request, self.template_name_error, context, status=400)
        if oauth_state.used or oauth_state.is_expired():
            context['error'] = 'State expired or already used'
            return render(request, self.template_name_error, context, status=400)
        if not code:
            context['error'] = 'Missing authorization code'
            return render(request, self.template_name_error, context, status=400)
        status_code, token_payload = exchange_openrouter_token(str(code or ''), str(oauth_state.code_verifier or ''), str(oauth_state.redirect_uri or ''))
        if status_code != 200:
            context['error'] = 'Token exchange failed'
            context['provider_payload'] = token_payload
            return render(request, self.template_name_error, context, status=400)

        access_token = token_payload.get('key') or token_payload.get('access_token')
        refresh_token = None
        scope = oauth_state.scope
        token_type = 'api_key'
        if not access_token:
            context['error'] = 'Provider did not return API key'
            context['provider_payload'] = token_payload
            logger.error(f"[OpenRouterCallbackSSRView] Missing 'key' in provider payload state={state_value} payload={token_payload}")
            return render(request, self.template_name_error, context, status=400)
        user = oauth_state.user
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
        token_obj, created = ProviderOAuthToken.objects.update_or_create(
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
        logger.info(f"[OpenRouterCallbackSSRView] Persisted provider token user={user.pk} created={created} token_id={token_obj.id}")
        oauth_state.mark_used()
        refresh = RefreshToken.for_user(user)
        payload = {
            'message': 'OpenRouter OAuth success',
            'user_id': str(user.pk),
            'access_token': str(refresh.access_token),
            'refresh_token': str(refresh),
            'provider_access_token': access_token if getattr(settings, 'OPENROUTER_EXPOSE_PROVIDER_TOKEN', True) else None,
            'provider_refresh_token': None,
            'provider_token_type': token_type,
            'provider_scope': scope,
            'provider_expires_at': None,
            'is_openrouter_user': getattr(user, 'is_openrouter_user', False),
            'is_google_user': getattr(user, 'is_google_user', False),
        }
        if oauth_state.mobile_redirect:
            # Store payload for retrieval then redirect with state reference only
            oauth_state.result_payload = json.dumps(payload)
            oauth_state.save(update_fields=["result_payload"])
            mobile_url = f"{oauth_state.mobile_redirect}?state={urllib.parse.quote(state_value)}&bridge=1"
            return redirect(mobile_url)
        return render(request, self.template_name_success, {'data_json': json.dumps(payload)})


# ----------------------- GOOGLE OAUTH (JSON + SSR) ---------------------------

class GoogleAuthorizeView(APIView):
    """JSON-based initiate for Google OAuth (PKCE)."""
    permission_classes = [AllowAny]

    def get(self, request):
        base_ser = OAuthAuthorizeRequestSerializer(data=request.query_params)
        base_ser.is_valid(raise_exception=True)
        base_data = cast(Dict[str, Any], base_ser.validated_data)
        # Enforce required Google scopes; strip unsupported offline_access (Google uses access_type=offline flag instead)
        requested_scope = base_data.get('scope') or ''
        # Remove any accidental offline_access to avoid invalid_scope errors
        scope_parts = [s for s in requested_scope.split() if s and s != 'offline_access']
        # Ensure baseline scopes present
        for required in ('openid', 'email', 'profile'):
            if required not in scope_parts:
                scope_parts.append(required)
        scope = ' '.join(scope_parts)
        orig_redirect = base_data.get('redirect_uri')
        redirect_uri = orig_redirect or getattr(settings, 'GOOGLE_OAUTH_REDIRECT_URI', '')
        # Optional host override: client may pass callback_host=10.0.2.2 to force emulator-friendly host
        callback_host = request.query_params.get('callback_host')
        if callback_host:
            allowed_hosts = {'10.0.2.2', '127.0.0.1'} | set(getattr(settings, 'OAUTH_CALLBACK_HOST_ALLOWLIST', []))
            if any(callback_host.startswith(prefix) for prefix in ('192.168.', '10.0.2.')):
                allowed_hosts.add(callback_host.split(':')[0])
            if callback_host.split(':')[0] in allowed_hosts:
                # Determine port (default 8000) if part of host param
                host_part = callback_host
                if ':' not in host_part:
                    host_part = f"{host_part}:8000"
                scheme = 'http'
                redirect_uri = f"{scheme}://{host_part}/api/v1/auth_api/google/callback/"
            else:
                logger.warning(f"[GoogleAuthorizeView] Ignoring disallowed callback_host={callback_host}")
        mobile_redirect: Optional[str] = None
        if redirect_uri and (redirect_uri.startswith('prompeteer://') or redirect_uri.startswith('app://')):
            mobile_redirect = redirect_uri.rstrip('/')
            redirect_uri = getattr(settings, 'GOOGLE_OAUTH_REDIRECT_URI', '')
        if redirect_uri and not redirect_uri.endswith('/'):
            redirect_uri += '/'
        if not redirect_uri:
            return Response({'detail': 'redirect_uri not configured'}, status=status.HTTP_400_BAD_REQUEST)
        # If this is a mobile bridge (custom scheme provided) and redirect host is loopback, swap to emulator host
        if mobile_redirect and callback_host is None:
            try:
                parsed = urllib.parse.urlparse(redirect_uri)
                if parsed.hostname in ('127.0.0.1', 'localhost'):
                    new_netloc = f"10.0.2.2:{parsed.port or 8000}"
                    redirect_uri = urllib.parse.urlunparse((parsed.scheme, new_netloc, parsed.path, parsed.params, parsed.query, parsed.fragment))
                    if not redirect_uri.endswith('/'):
                        redirect_uri += '/'
                    logger.info(f"[GoogleAuthorizeView] Auto-swapped redirect host to emulator 10.0.2.2 for mobile bridge (was {parsed.hostname})")
            except Exception:
                logger.warning("[GoogleAuthorizeView] Failed to auto-swap emulator host")
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
        logger.info(f"[GoogleAuthorizeView] Generated state={state} id={oauth_state.id} redirect_uri={redirect_uri} mobile_redirect={mobile_redirect} authorize_url={authorize_url}")
    # Unified behavior: if mode=redirect or path contains authorize/ssr treat as SSR and redirect immediately.
        if request.query_params.get('mode') == 'redirect' or 'authorize/ssr' in request.path:
            return redirect(authorize_url)
        return Response({'authorize_url': authorize_url,'state': state,'state_id': str(oauth_state.id),'expires_at': expires_at.isoformat(),'bridge': bool(mobile_redirect)})


class GoogleCallbackView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        """Allow GET redirects here (fallback) so if Google console is configured with /google/callback/ instead of /google/callback/ssr/ we still succeed.

        Behavior:
          - Performs same token exchange logic as POST & SSR variant.
          - If this was a mobile bridge initiation (mobile_redirect stored) we store result_payload and deep-link to mobile (like SSR view).
          - Otherwise returns JSON payload (instead of HTML template) to keep semantics consistent with API style endpoint.
        """
        ser = OAuthCallbackSerializer(data=request.GET)
        ser.is_valid(raise_exception=True)
        cb_data = cast(Dict[str, Any], ser.validated_data)
        state_value = cb_data.get('state') or ''
        code = cb_data.get('code') or ''
        error = cb_data.get('error') or ''
        logger.info(f"[GoogleCallbackView][GET] state={state_value} error={error} code_present={bool(code)}")
        try:
            oauth_state = OAuthState.objects.get(state=state_value, provider='google')
        except OAuthState.DoesNotExist:
            return Response({'detail': 'Invalid state'}, status=status.HTTP_400_BAD_REQUEST)
        if error:
            return Response({'detail': error}, status=status.HTTP_400_BAD_REQUEST)
        # Idempotent handling: if state already used but we still have payload, return it again (helpful when user changes host manually)
        if oauth_state.used and not oauth_state.is_expired():
            # Attempt to recover persisting tokens for the user
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
        user = oauth_state.user
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
        # Persist / update provider token
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
            'is_openrouter_user': getattr(user, 'is_openrouter_user', False),
        }
        logger.info(f"[GoogleCallbackView] Success state={state_value} user={user.pk} email={email} expires_at={expires_at}")
        # Mobile bridge deep link
        if oauth_state.mobile_redirect:
            oauth_state.result_payload = json.dumps(payload)
            oauth_state.save(update_fields=["result_payload"])
            mobile_url = f"{oauth_state.mobile_redirect}?state={urllib.parse.quote(state_value)}&bridge=1"
            return redirect(mobile_url)
        # Render HTML automatically for SSR callback path or if render=1 explicitly requested
        if request.path.endswith('/callback/ssr/') or request.GET.get('render') == '1':
            html = f"""<html><body><script>window.opener && window.opener.postMessage({json.dumps(payload)}, '*');</script><pre>{json.dumps(payload, indent=2)}</pre></body></html>"""
            from django.http import HttpResponse
            return HttpResponse(html)
        return Response(payload)

    # (POST not required for Google redirect callbacks normally, but allow parity with API clients)
    def post(self, request):  # type: ignore[override]
        ser = OAuthCallbackSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        # Reuse GET logic by faking query params object
        for k, v in request.data.items():
            request.GET._mutable = True  # type: ignore
            request.GET[k] = v  # type: ignore
            request.GET._mutable = False  # type: ignore
        return self.get(request)


class OAuthResultView(APIView):
    """Fetches stored bridge payload (one-time) given state.

    GET /api/v1/auth_api/oauth/result/<state>/
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


class SendLoginOTPView(APIView):
    """Sends a 6-digit OTP for passwordless login with simple rate limiting."""
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
        send_mail(
            subject='Your Login OTP',
            message=f'Your one-time login code is: {otp}',
            from_email=getattr(settings, 'DEFAULT_FROM_EMAIL', None),
            recipient_list=[email],
            fail_silently=True,
        )
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