"""Shared pytest fixtures for the prompeteer_server test suite.

These fixtures are intentionally minimal and mirror the real API contract
(see auth_api/user_mang/crypto_api views + urls) rather than any legacy
assumptions. All external services (SMTP, OAuth providers) must be mocked
by individual tests -- no real network calls are permitted in the suite.
"""
import hashlib

import pytest
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from django.conf import settings

from user_mang.models.custom_user import Custom_User


@pytest.fixture
def api_client():
    return APIClient()


def _backend_hash(raw_password: str) -> str:
    """Reproduce the RegisterView/LoginSerializer password hashing scheme:
    sha256(password + BACKEND_PASSWORD_SALT). Note this differs from
    Custom_User.set_password()/check_password(), which double-hashes
    (sha256(sha256(raw) + salt)); the view layer (Register/Login/SetPassword)
    consistently uses the single-hash scheme, so tests must match that."""
    salt = getattr(settings, "BACKEND_PASSWORD_SALT", "fallback_dev_salt")
    return hashlib.sha256((raw_password + salt).encode("utf-8")).hexdigest()


@pytest.fixture
def raw_password():
    return "Sup3rSecret!"


@pytest.fixture
def make_user(db):
    """Factory fixture: create a Custom_User with a real, checkable password."""

    def _make(**kwargs):
        password = kwargs.pop("raw_password", "Sup3rSecret!")
        defaults = dict(
            username="testuser",
            email="test@example.com",
            email_verified=True,
            is_active=True,
        )
        defaults.update(kwargs)
        user = Custom_User.objects.create(**defaults)
        if password:
            user.user_password = _backend_hash(password)
            user.save(update_fields=["user_password"])
        return user

    return _make


@pytest.fixture
def verified_user(make_user, raw_password):
    return make_user(
        username="verifieduser",
        email="verified@example.com",
        email_verified=True,
        raw_password=raw_password,
    )


@pytest.fixture
def auth_client(api_client, verified_user):
    """An APIClient pre-authenticated (JWT) as verified_user."""
    refresh = RefreshToken.for_user(verified_user)
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {refresh.access_token}")
    return api_client, verified_user
