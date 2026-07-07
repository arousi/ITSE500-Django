"""Core auth_api API tests (DRF APIClient, real endpoints only).

Covers the register -> verify-email-pin -> set-password -> login ->
token/refresh -> logout lifecycle, plus health checks and OTP-login
deprecation. OAuth provider network calls are mocked in
test_oauth_views.py.
"""
import hashlib

import pytest
from django.urls import reverse
from django.utils import timezone
from datetime import timedelta
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken

from user_mang.models.custom_user import Custom_User


# ---------------------------------------------------------------------------
# Register
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestRegisterView:
    def test_register_new_user_success(self, api_client):
        url = reverse("register")
        data = {"username": "newuser", "email": "newuser@example.com", "user_password": "secretpw"}
        resp = api_client.post(url, data, format="json")

        assert resp.status_code == status.HTTP_201_CREATED
        assert "access_token" in resp.data
        assert "refresh_token" in resp.data
        assert resp.data["onboarding"] is True
        assert resp.data["email"] == "newuser@example.com"

        # Persisted state: user is created, auto-verified, password hashed (not plaintext)
        user = Custom_User.objects.get(email="newuser@example.com")
        assert user.email_verified is True
        assert user.user_password != "secretpw"
        assert user.check_password("secretpw") is True

    def test_register_missing_fields_400(self, api_client):
        url = reverse("register")
        resp = api_client.post(url, {"username": "", "email": "", "user_password": ""}, format="json")
        assert resp.status_code == status.HTTP_400_BAD_REQUEST

    def test_register_existing_verified_user_returns_200_without_tokens(self, api_client, make_user):
        """SECURITY: existing accounts (verified or not) must never receive tokens or
        leak account state via the register endpoint. Current behavior always returns
        200 with a neutral detail for any pre-existing identifier (the 409 branch in
        RegisterView is unreachable in normal operation -- see bug report)."""
        make_user(username="existing", email="dup@example.com", email_verified=True)
        url = reverse("register")
        resp = api_client.post(
            url, {"username": "irrelevant", "email": "dup@example.com", "user_password": "whatever1"}, format="json"
        )
        assert resp.status_code == status.HTTP_200_OK
        assert "access_token" not in resp.data

    def test_register_existing_unverified_user_is_auto_verified_no_tokens_leaked(self, api_client, make_user):
        make_user(username="pending", email="pending@example.com", email_verified=False)
        url = reverse("register")
        resp = api_client.post(
            url, {"username": "irrelevant", "email": "pending@example.com", "user_password": "whatever1"}, format="json"
        )
        assert resp.status_code == status.HTTP_200_OK
        assert "access_token" not in resp.data
        user = Custom_User.objects.get(email="pending@example.com")
        assert user.email_verified is True


# ---------------------------------------------------------------------------
# verify-email-pin
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestEmailPinVerifyView:
    def _auth(self, api_client, user):
        refresh = RefreshToken.for_user(user)
        api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {refresh.access_token}")

    def test_verify_pin_success(self, api_client, make_user):
        user = make_user(
            username="pinuser", email="pin@example.com", email_verified=False,
            email_pin=12345, email_pin_created=timezone.now(),
        )
        self._auth(api_client, user)
        resp = api_client.post(reverse("email-pin-verify"), {"email": "pin@example.com", "pin": "12345"}, format="json")
        assert resp.status_code == status.HTTP_200_OK
        user.refresh_from_db()
        assert user.email_verified is True
        assert user.email_pin is None

    def test_verify_pin_wrong_pin_400(self, api_client, make_user):
        user = make_user(
            username="pinuser2", email="pin2@example.com", email_verified=False,
            email_pin=12345, email_pin_created=timezone.now(),
        )
        self._auth(api_client, user)
        resp = api_client.post(reverse("email-pin-verify"), {"email": "pin2@example.com", "pin": "99999"}, format="json")
        assert resp.status_code == status.HTTP_400_BAD_REQUEST

    def test_verify_pin_expired_400(self, api_client, make_user):
        user = make_user(
            username="pinuser3", email="pin3@example.com", email_verified=False,
            email_pin=12345, email_pin_created=timezone.now() - timedelta(minutes=15),
        )
        self._auth(api_client, user)
        resp = api_client.post(reverse("email-pin-verify"), {"email": "pin3@example.com", "pin": "12345"}, format="json")
        assert resp.status_code == status.HTTP_400_BAD_REQUEST

    def test_verify_pin_requires_authentication(self, api_client, make_user):
        make_user(
            username="pinuser4", email="pin4@example.com", email_verified=False,
            email_pin=12345, email_pin_created=timezone.now(),
        )
        resp = api_client.post(reverse("email-pin-verify"), {"email": "pin4@example.com", "pin": "12345"}, format="json")
        assert resp.status_code == status.HTTP_401_UNAUTHORIZED

    def test_verify_pin_rejects_mismatched_email(self, api_client, make_user):
        user = make_user(
            username="pinuser5", email="pin5@example.com", email_verified=False,
            email_pin=12345, email_pin_created=timezone.now(),
        )
        make_user(username="other", email="other@example.com", email_verified=False)
        self._auth(api_client, user)
        resp = api_client.post(reverse("email-pin-verify"), {"email": "other@example.com", "pin": "12345"}, format="json")
        assert resp.status_code == status.HTTP_403_FORBIDDEN


# ---------------------------------------------------------------------------
# set-password-after-email-verify
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestSetPasswordAfterEmailVerifyView:
    def _auth(self, api_client, user):
        refresh = RefreshToken.for_user(user)
        api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {refresh.access_token}")

    def test_set_password_success(self, api_client, make_user):
        user = make_user(username="spuser", email="sp@example.com", email_verified=True, raw_password=None)
        self._auth(api_client, user)
        resp = api_client.post(
            reverse("set-password"), {"email": "sp@example.com", "password": "hashedfrontend"}, format="json"
        )
        assert resp.status_code == status.HTTP_200_OK
        user.refresh_from_db()
        assert user.user_password is not None
        assert user.user_password != "hashedfrontend"  # server re-hashes with salt

    def test_set_password_email_not_verified_400(self, api_client, make_user):
        user = make_user(username="spuser2", email="sp2@example.com", email_verified=False, raw_password=None)
        self._auth(api_client, user)
        resp = api_client.post(
            reverse("set-password"), {"email": "sp2@example.com", "password": "hashedfrontend"}, format="json"
        )
        assert resp.status_code == status.HTTP_400_BAD_REQUEST

    def test_set_password_requires_authentication(self, api_client, make_user):
        make_user(username="spuser3", email="sp3@example.com", email_verified=True, raw_password=None)
        resp = api_client.post(
            reverse("set-password"), {"email": "sp3@example.com", "password": "hashedfrontend"}, format="json"
        )
        assert resp.status_code == status.HTTP_401_UNAUTHORIZED


# ---------------------------------------------------------------------------
# login
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestLoginView:
    def test_login_success(self, api_client, make_user, raw_password):
        make_user(username="loginuser", email="login@example.com", raw_password=raw_password)
        resp = api_client.post(
            reverse("login"), {"email": "login@example.com", "password": raw_password}, format="json"
        )
        assert resp.status_code == status.HTTP_200_OK
        assert "access_token" in resp.data
        assert "refresh_token" in resp.data
        assert resp.data["email_verified"] is True

    def test_login_wrong_password_401(self, api_client, make_user, raw_password):
        make_user(username="loginuser2", email="login2@example.com", raw_password=raw_password)
        resp = api_client.post(
            reverse("login"), {"email": "login2@example.com", "password": "wrong-password"}, format="json"
        )
        assert resp.status_code == status.HTTP_401_UNAUTHORIZED

    def test_login_unknown_identifier_401(self, api_client):
        resp = api_client.post(
            reverse("login"), {"email": "doesnotexist@example.com", "password": "whatever"}, format="json"
        )
        assert resp.status_code == status.HTTP_401_UNAUTHORIZED

    def test_login_inactive_user_403(self, api_client, make_user, raw_password):
        make_user(username="loginuser3", email="login3@example.com", raw_password=raw_password, is_active=False)
        resp = api_client.post(
            reverse("login"), {"email": "login3@example.com", "password": raw_password}, format="json"
        )
        assert resp.status_code == status.HTTP_403_FORBIDDEN


# ---------------------------------------------------------------------------
# token/refresh
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestTokenRefresh:
    def test_refresh_returns_new_access_token(self, api_client, make_user):
        user = make_user(username="refreshuser", email="refresh@example.com")
        refresh = RefreshToken.for_user(user)
        resp = api_client.post(reverse("token_refresh"), {"refresh": str(refresh)}, format="json")
        assert resp.status_code == status.HTTP_200_OK
        assert "access" in resp.data

    def test_refresh_invalid_token_401(self, api_client):
        resp = api_client.post(reverse("token_refresh"), {"refresh": "not-a-real-token"}, format="json")
        assert resp.status_code == status.HTTP_401_UNAUTHORIZED


# ---------------------------------------------------------------------------
# logout
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestLogoutView:
    def test_logout_requires_authentication(self, api_client):
        resp = api_client.post(reverse("logout"))
        assert resp.status_code == status.HTTP_401_UNAUTHORIZED

    def test_logout_success(self, api_client, make_user):
        user = make_user(username="logoutuser", email="logout@example.com")
        refresh = RefreshToken.for_user(user)
        api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {refresh.access_token}")
        resp = api_client.post(reverse("logout"))
        assert resp.status_code == status.HTTP_200_OK
        assert "detail" in resp.data


# ---------------------------------------------------------------------------
# health
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestHealthCheckView:
    def test_health_ok(self, api_client):
        resp = api_client.get(reverse("health-check"))
        assert resp.status_code == status.HTTP_200_OK
        assert resp.data["status"] == "ok"


@pytest.mark.django_db
def test_root_healthz(client):
    """Root-level liveness probe added by containerization."""
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


# ---------------------------------------------------------------------------
# otp-login (deprecated in this release -> must always return 410)
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestOTPLoginDeprecated:
    def test_otp_login_returns_410(self, api_client):
        resp = api_client.post(reverse("otp-login"), {"email": "x@example.com"}, format="json")
        assert resp.status_code == status.HTTP_410_GONE


# ---------------------------------------------------------------------------
# Full lifecycle integration: register -> verify pin -> set password -> login -> refresh -> logout
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestAuthLifecycleIntegration:
    def test_full_lifecycle(self, api_client):
        # Register (auto-verified in this release; no PIN step actually required server-side,
        # but we still exercise verify-email-pin/set-password as independent, JWT-gated endpoints).
        register_resp = api_client.post(
            reverse("register"),
            {"username": "flowuser", "email": "flow@example.com", "user_password": "initialpw"},
            format="json",
        )
        assert register_resp.status_code == status.HTTP_201_CREATED
        access = register_resp.data["access_token"]

        user = Custom_User.objects.get(email="flow@example.com")
        assert user.email_verified is True

        # Set a new password using the JWT minted at registration.
        api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {access}")
        set_pw_resp = api_client.post(
            reverse("set-password"), {"email": "flow@example.com", "password": "newhashedpw"}, format="json"
        )
        assert set_pw_resp.status_code == status.HTTP_200_OK

        # Login with the new (client-hashed) password.
        api_client.credentials()  # clear auth header
        login_resp = api_client.post(
            reverse("login"), {"email": "flow@example.com", "password": "newhashedpw"}, format="json"
        )
        assert login_resp.status_code == status.HTTP_200_OK
        refresh_token = login_resp.data["refresh_token"]

        # Refresh
        refresh_resp = api_client.post(reverse("token_refresh"), {"refresh": refresh_token}, format="json")
        assert refresh_resp.status_code == status.HTTP_200_OK

        # Logout
        api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {refresh_resp.data['access']}")
        logout_resp = api_client.post(reverse("logout"))
        assert logout_resp.status_code == status.HTTP_200_OK
