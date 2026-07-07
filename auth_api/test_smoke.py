"""Smoke tests for auth_api that match the CURRENT implementation.

Replaces the stale auth_api/tests.py stub (moved to legacy_tests/), which used
wrong URL-name casing and assumed Django's standard create_user/password flow
rather than this project's custom `user_password` hashing. A fuller auth suite
(register -> email-verify -> set-password -> login round-trip against the custom
auth) is a documented follow-up.
"""
from django.test import TestCase
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient

from user_mang.models.custom_user import Custom_User


class AuthSmokeTest(TestCase):
    def setUp(self):
        self.client = APIClient()

    def test_health_check_ok(self):
        resp = self.client.get(reverse("health-check"))
        self.assertEqual(resp.status_code, status.HTTP_200_OK)

    def test_otp_login_endpoint_is_deprecated_gone(self):
        # LoginWithOTPView is intentionally disabled in this release (410 Gone).
        resp = self.client.post(reverse("otp-login"), {}, format="json")
        self.assertEqual(resp.status_code, status.HTTP_410_GONE)

    def test_register_creates_user(self):
        before = Custom_User.objects.count()
        resp = self.client.post(
            reverse("register"),
            {"username": "smoketest", "email": "smoke@example.com",
             "user_password": "a-strong-password-123"},
            format="json",
        )
        self.assertIn(resp.status_code, (status.HTTP_200_OK, status.HTTP_201_CREATED))
        self.assertEqual(Custom_User.objects.filter(email="smoke@example.com").count(), 1)
        self.assertEqual(Custom_User.objects.count(), before + 1)
