"""Abuse-protection throttle tests for the unauthenticated auth entry points.

Covers register, login, verify-email-pin, and otp-login: each carries a
`throttle_scope` (see auth_api/views.py + REST_FRAMEWORK['DEFAULT_THROTTLE_RATES']
in prompeteer_server/settings.py) enforced by DRF's ScopedRateThrottle. These
tests override the configured rate to a small deterministic value so the
suite doesn't depend on (or take as long as) the real production rate, then
assert the throttle actually engages (429) once the limit is exceeded, and
that a *different* client (different IP) is not affected by another client's
usage.
"""
from contextlib import contextmanager
from unittest import mock

import pytest
from django.core.cache import cache
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient
from rest_framework.throttling import ScopedRateThrottle


@contextmanager
def _throttle_rate_override(scope, rate):
    """Temporarily override a single DRF throttle scope's rate.

    NOTE: `django.test.override_settings(REST_FRAMEWORK=...)` does NOT work
    for this -- DRF's `ScopedRateThrottle.THROTTLE_RATES` is bound to
    `api_settings.DEFAULT_THROTTLE_RATES` as a class attribute at import
    time; `setting_changed` only resets DRF's cached `api_settings`
    properties, it does not re-bind that already-evaluated class attribute.
    Patching `ScopedRateThrottle.THROTTLE_RATES` directly is the reliable
    way to control the effective rate in tests.
    """
    rates = dict(ScopedRateThrottle.THROTTLE_RATES)
    rates[scope] = rate
    with mock.patch.object(ScopedRateThrottle, "THROTTLE_RATES", rates):
        yield


@pytest.fixture(autouse=True)
def _clear_throttle_cache():
    """DRF's ScopedRateThrottle stores hit counts in the default cache,
    keyed by scope + client IP. Clear it before and after every test in
    this module so throttle state never leaks between tests (or from
    earlier test modules that hit the same endpoints)."""
    cache.clear()
    yield
    cache.clear()


def _client(remote_addr="10.0.0.1"):
    c = APIClient()
    c.defaults["REMOTE_ADDR"] = remote_addr
    return c


@pytest.mark.django_db
class TestRegisterThrottle:
    def test_register_throttles_after_limit(self):
        with _throttle_rate_override("auth-register", "2/min"):
            url = reverse("register")
            client = _client()
            for i in range(2):
                resp = client.post(
                    url,
                    {"username": f"throttleuser{i}", "email": f"throttle{i}@example.com", "user_password": "secretpw"},
                    format="json",
                )
                assert resp.status_code == status.HTTP_201_CREATED

            resp = client.post(
                url,
                {"username": "throttleuser-over", "email": "throttle-over@example.com", "user_password": "secretpw"},
                format="json",
            )
            assert resp.status_code == status.HTTP_429_TOO_MANY_REQUESTS

    def test_register_throttle_is_per_client_ip(self):
        with _throttle_rate_override("auth-register", "1/min"):
            url = reverse("register")
            client_a = _client("10.0.0.10")
            client_b = _client("10.0.0.20")

            resp_a = client_a.post(
                url, {"username": "ipauser", "email": "ipa@example.com", "user_password": "secretpw"}, format="json"
            )
            assert resp_a.status_code == status.HTTP_201_CREATED

            resp_a2 = client_a.post(
                url, {"username": "ipauser2", "email": "ipa2@example.com", "user_password": "secretpw"}, format="json"
            )
            assert resp_a2.status_code == status.HTTP_429_TOO_MANY_REQUESTS

            # A different client IP is unaffected by client_a's usage.
            resp_b = client_b.post(
                url, {"username": "ipbuser", "email": "ipb@example.com", "user_password": "secretpw"}, format="json"
            )
            assert resp_b.status_code == status.HTTP_201_CREATED


@pytest.mark.django_db
class TestLoginThrottle:
    def test_login_throttles_after_limit_even_with_wrong_password(self, make_user, raw_password):
        """Brute-force defense: throttling must engage on the *wrong password*
        path too, since that's exactly the attack this protects against."""
        make_user(username="bfuser", email="bruteforce@example.com", raw_password=raw_password)
        with _throttle_rate_override("auth-login", "3/min"):
            url = reverse("login")
            client = _client()

            for _ in range(3):
                resp = client.post(
                    url, {"email": "bruteforce@example.com", "password": "wrong-password"}, format="json"
                )
                assert resp.status_code == status.HTTP_401_UNAUTHORIZED

            resp = client.post(
                url, {"email": "bruteforce@example.com", "password": "wrong-password"}, format="json"
            )
            assert resp.status_code == status.HTTP_429_TOO_MANY_REQUESTS

            # Even the *correct* password is rejected once throttled -- the
            # throttle is IP/scope-based, not credential-based.
            resp = client.post(
                url, {"email": "bruteforce@example.com", "password": raw_password}, format="json"
            )
            assert resp.status_code == status.HTTP_429_TOO_MANY_REQUESTS


@pytest.mark.django_db
class TestVerifyEmailPinThrottle:
    def test_verify_pin_throttles_after_limit(self, make_user):
        from django.utils import timezone
        from rest_framework_simplejwt.tokens import RefreshToken

        user = make_user(
            username="pinbfuser", email="pinbf@example.com", email_verified=False,
            email_pin=12345, email_pin_created=timezone.now(),
        )
        refresh = RefreshToken.for_user(user)
        client = _client()
        client.credentials(HTTP_AUTHORIZATION=f"Bearer {refresh.access_token}")

        with _throttle_rate_override("auth-verify-email-pin", "3/min"):
            url = reverse("email-pin-verify")
            for _ in range(3):
                resp = client.post(url, {"email": "pinbf@example.com", "pin": "00000"}, format="json")
                assert resp.status_code == status.HTTP_400_BAD_REQUEST

            resp = client.post(url, {"email": "pinbf@example.com", "pin": "00000"}, format="json")
            assert resp.status_code == status.HTTP_429_TOO_MANY_REQUESTS

            # The correct PIN is also rejected once throttled.
            resp = client.post(url, {"email": "pinbf@example.com", "pin": "12345"}, format="json")
            assert resp.status_code == status.HTTP_429_TOO_MANY_REQUESTS


@pytest.mark.django_db
class TestOTPLoginThrottle:
    def test_otp_login_throttles_after_limit(self):
        with _throttle_rate_override("auth-otp-login", "2/min"):
            url = reverse("otp-login")
            client = _client()

            for _ in range(2):
                resp = client.post(url, {"email": "otp@example.com"}, format="json")
                assert resp.status_code == status.HTTP_410_GONE

            resp = client.post(url, {"email": "otp@example.com"}, format="json")
            assert resp.status_code == status.HTTP_429_TOO_MANY_REQUESTS
