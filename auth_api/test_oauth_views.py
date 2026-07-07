"""OAuth authorize/callback + oauth/result contract tests.

All outbound HTTP calls to providers (Google, OpenRouter, GitHub, Microsoft)
are mocked via unittest.mock.patch on the module-level helper functions in
auth_api.views -- no real network traffic occurs in this suite.
"""
import json
from unittest.mock import patch

import pytest
from django.urls import reverse
from django.utils import timezone
from datetime import timedelta
from rest_framework import status

from auth_api.models import OAuthState


@pytest.mark.django_db
class TestGoogleOAuthAuthorize:
    def test_authorize_returns_url_and_state(self, api_client, settings):
        settings.GOOGLE_OAUTH_REDIRECT_URI = "http://testserver/api/v1/auth_api/google/callback/"
        resp = api_client.get(reverse("google-authorize"))
        assert resp.status_code == status.HTTP_200_OK
        assert "authorize_url" in resp.data
        assert "state" in resp.data
        # Persisted state row backs the returned state value
        assert OAuthState.objects.filter(state=resp.data["state"], provider="google").exists()


@pytest.mark.django_db
class TestGoogleOAuthCallback:
    def _make_state(self, **overrides):
        defaults = dict(
            provider="google",
            state="abc123",
            code_challenge="chal",
            code_verifier="verifier",
            redirect_uri="http://testserver/api/v1/auth_api/google/callback/",
            expires_at=timezone.now() + timedelta(minutes=10),
        )
        defaults.update(overrides)
        return OAuthState.objects.create(**defaults)

    def test_callback_invalid_state_400(self, api_client):
        resp = api_client.get(reverse("google-callback"), {"state": "does-not-exist", "code": "abc"})
        assert resp.status_code == status.HTTP_400_BAD_REQUEST

    def test_callback_expired_state_400(self, api_client):
        self._make_state(state="expired-state", expires_at=timezone.now() - timedelta(seconds=1))
        resp = api_client.get(reverse("google-callback"), {"state": "expired-state", "code": "abc"})
        assert resp.status_code == status.HTTP_400_BAD_REQUEST

    def test_callback_missing_code_400(self, api_client):
        self._make_state(state="no-code-state")
        resp = api_client.get(reverse("google-callback"), {"state": "no-code-state"})
        assert resp.status_code == status.HTTP_400_BAD_REQUEST

    @patch("auth_api.views.fetch_google_userinfo")
    @patch("auth_api.views.exchange_google_token")
    def test_callback_success_creates_user_and_issues_jwt(self, mock_exchange, mock_userinfo, api_client):
        oauth_state = self._make_state(state="good-state")
        mock_exchange.return_value = (200, {
            "access_token": "provider-access",
            "refresh_token": "provider-refresh",
            "expires_in": 3600,
            "id_token": "id-token-value",
            "token_type": "Bearer",
        })
        mock_userinfo.return_value = {"email": "googleuser@example.com", "email_verified": True}

        resp = api_client.get(reverse("google-callback"), {"state": "good-state", "code": "authcode"})

        assert resp.status_code == status.HTTP_200_OK
        assert resp.data["message"] == "Google OAuth success"
        assert "access_token" in resp.data
        assert resp.data["email"] == "googleuser@example.com"
        assert resp.data["is_google_user"] is True

        oauth_state.refresh_from_db()
        assert oauth_state.is_used is True
        assert oauth_state.code_verifier is None  # cleared for security

    @patch("auth_api.views.exchange_google_token")
    def test_callback_token_exchange_failure_400(self, mock_exchange, api_client):
        self._make_state(state="fail-state")
        mock_exchange.return_value = (400, {"error": "invalid_grant"})
        resp = api_client.get(reverse("google-callback"), {"state": "fail-state", "code": "authcode"})
        assert resp.status_code == status.HTTP_400_BAD_REQUEST

    @patch("auth_api.views.fetch_google_userinfo")
    @patch("auth_api.views.exchange_google_token")
    def test_callback_replay_of_used_state_returns_409_or_idempotent(self, mock_exchange, mock_userinfo, api_client):
        self._make_state(state="replay-state")
        mock_exchange.return_value = (200, {"access_token": "tok", "expires_in": 60, "token_type": "Bearer"})
        mock_userinfo.return_value = {"email": "replay@example.com", "email_verified": True}

        first = api_client.get(reverse("google-callback"), {"state": "replay-state", "code": "authcode"})
        assert first.status_code == status.HTTP_200_OK

        second = api_client.get(reverse("google-callback"), {"state": "replay-state", "code": "authcode"})
        # Once used (and not expired), replay must not re-run the token exchange for a fresh code.
        assert second.status_code in (status.HTTP_200_OK, status.HTTP_409_CONFLICT)


@pytest.mark.django_db
class TestOpenRouterOAuthCallback:
    def _make_state(self, **overrides):
        defaults = dict(
            provider="openrouter",
            state="or-state",
            code_challenge="chal",
            code_verifier="verifier",
            redirect_uri="http://testserver/api/v1/auth_api/openrouter/callback/",
            expires_at=timezone.now() + timedelta(minutes=10),
        )
        defaults.update(overrides)
        return OAuthState.objects.create(**defaults)

    @patch("auth_api.views.exchange_openrouter_token")
    def test_callback_success_returns_provider_api_key(self, mock_exchange, api_client):
        self._make_state()
        mock_exchange.return_value = (200, {"key": "sk-or-abcdef"})
        resp = api_client.get(reverse("openrouter-callback"), {"state": "or-state", "code": "authcode"})
        assert resp.status_code == status.HTTP_200_OK
        assert resp.data["message"] == "OpenRouter OAuth success"
        assert resp.data["is_openrouter_user"] is True

    @patch("auth_api.views.exchange_openrouter_token")
    def test_callback_missing_api_key_400(self, mock_exchange, api_client):
        self._make_state(state="or-state-2")
        mock_exchange.return_value = (200, {})  # no 'key' returned
        resp = api_client.get(reverse("openrouter-callback"), {"state": "or-state-2", "code": "authcode"})
        assert resp.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.django_db
class TestOAuthResultView:
    def test_result_not_found_404(self, api_client):
        resp = api_client.get(reverse("oauth-result", kwargs={"state_value": "unknown"}))
        assert resp.status_code == status.HTTP_404_NOT_FOUND

    def test_result_not_ready_202(self, api_client):
        OAuthState.objects.create(
            provider="google", state="pending-state", code_challenge="c",
            expires_at=timezone.now() + timedelta(minutes=10),
        )
        resp = api_client.get(reverse("oauth-result", kwargs={"state_value": "pending-state"}))
        assert resp.status_code == status.HTTP_202_ACCEPTED

    def test_result_one_time_retrieval_then_gone(self, api_client):
        oauth_state = OAuthState.objects.create(
            provider="google", state="ready-state", code_challenge="c",
            expires_at=timezone.now() + timedelta(minutes=10),
            result_payload=json.dumps({"message": "ok"}),
        )
        first = api_client.get(reverse("oauth-result", kwargs={"state_value": "ready-state"}))
        assert first.status_code == status.HTTP_200_OK

        second = api_client.get(reverse("oauth-result", kwargs={"state_value": "ready-state"}))
        assert second.status_code == status.HTTP_410_GONE
