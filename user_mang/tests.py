"""UnifiedSyncView ("me/") API tests: auth-gated read/sync + IDOR guards.

This endpoint is the conversation/data sync surface the Flutter/React clients
use. It supports authenticated users and unauthenticated visitors (via
temp_id). Writes always operate on request.user / the resolved visitor --
never on an attacker-supplied user_id -- this suite asserts that invariant.
"""
import pytest
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken

from user_mang.models.custom_user import Custom_User
from chat_api.models.conversation import Conversation


ME_URL = "/api/v1/user_mang/me/"


@pytest.mark.django_db
class TestUnifiedSyncGet:
    def test_get_requires_authentication_or_temp_id(self, api_client):
        resp = api_client.get(ME_URL)
        assert resp.status_code == status.HTTP_401_UNAUTHORIZED

    def test_get_authenticated_returns_own_profile_and_chat(self, api_client, make_user):
        user = make_user(username="syncuser", email="sync@example.com")
        Conversation.objects.create(user_id=user, title="My chat")
        refresh = RefreshToken.for_user(user)
        api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {refresh.access_token}")

        resp = api_client.get(ME_URL)
        assert resp.status_code == status.HTTP_200_OK
        assert resp.data["user_id"] == str(user.user_id)
        assert resp.data["profile"]["username"] == "syncuser"
        assert len(resp.data["chat"]["conversations"]) == 1

    def test_get_does_not_leak_other_users_conversations(self, api_client, make_user):
        user_a = make_user(username="usera", email="a@example.com")
        user_b = make_user(username="userb", email="b@example.com")
        Conversation.objects.create(user_id=user_b, title="B's private chat")

        refresh = RefreshToken.for_user(user_a)
        api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {refresh.access_token}")
        resp = api_client.get(ME_URL)

        assert resp.status_code == status.HTTP_200_OK
        titles = [c["title"] for c in resp.data["chat"]["conversations"]]
        assert "B's private chat" not in titles

    def test_get_visitor_by_temp_id_creates_visitor(self, api_client):
        resp = api_client.get(ME_URL, {"temp_id": "visitor-temp-123"})
        assert resp.status_code == status.HTTP_200_OK
        assert resp.data["is_new"] is True
        assert Custom_User.objects.filter(temp_id="visitor-temp-123", is_visitor=True).exists()

    def test_get_ignores_client_supplied_user_id_for_authenticated_requests(self, api_client, make_user):
        """IDOR guard: an authenticated user cannot read another user's data by
        passing a foreign user_id -- the view always resolves to request.user."""
        user_a = make_user(username="usera2", email="a2@example.com")
        user_b = make_user(username="userb2", email="b2@example.com")
        Conversation.objects.create(user_id=user_b, title="B private")

        refresh = RefreshToken.for_user(user_a)
        api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {refresh.access_token}")
        resp = api_client.get(ME_URL, {"user_id": str(user_b.user_id)})

        assert resp.status_code == status.HTTP_200_OK
        assert resp.data["user_id"] == str(user_a.user_id)


@pytest.mark.django_db
class TestUnifiedSyncPost:
    def test_post_creates_conversation_owned_by_caller(self, api_client, make_user):
        """ConversationSerializer accepts a client-supplied conversation_id on create
        (upsert/idempotency semantics for offline-first clients), while the owning
        user_id is always forced to request.user regardless of payload content."""
        user = make_user(username="upsertuser", email="upsert@example.com")
        refresh = RefreshToken.for_user(user)
        api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {refresh.access_token}")

        client_conv_id = "11111111-1111-1111-1111-111111111111"
        payload = {
            "conversations": [{"conversation_id": client_conv_id, "title": "New convo"}],
        }
        resp = api_client.post(ME_URL, payload, format="json")
        assert resp.status_code == status.HTTP_200_OK
        assert resp.data["summary"]["conversations_created"] == 1
        conv = Conversation.objects.get(user_id=user, title="New convo")
        assert conv.user_id_id == user.pk  # FK forced to the authenticated user, not client-suppliable
        assert str(conv.conversation_id) == client_conv_id  # client-supplied id honored on create

    def test_post_cannot_hijack_existing_conversation_owned_by_another_user(self, api_client, make_user):
        """IDOR guard: upserting a conversation_id owned by a different user must not
        transfer ownership to the attacker."""
        victim = make_user(username="victim", email="victim@example.com")
        attacker = make_user(username="attacker", email="attacker@example.com")
        conv = Conversation.objects.create(
            conversation_id="22222222-2222-2222-2222-222222222222", user_id=victim, title="Victim convo"
        )

        refresh = RefreshToken.for_user(attacker)
        api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {refresh.access_token}")
        payload = {"conversations": [{"conversation_id": str(conv.conversation_id), "title": "Hijacked!"}]}
        api_client.post(ME_URL, payload, format="json")

        conv.refresh_from_db()
        assert conv.user_id_id == victim.pk  # ownership must remain with the victim

    def test_post_requires_authentication(self, api_client):
        resp = api_client.post(ME_URL, {"conversations": []}, format="json")
        assert resp.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.django_db
class TestUnifiedSyncPatch:
    def test_patch_updates_own_profile_whitelisted_field(self, api_client, make_user):
        """PATCH goes through ProfileSerializer, which whitelists only username,
        email, phone_number, biometric_enabled (by design -- excludes sensitive
        fields like email_verified/is_staff/user_password)."""
        user = make_user(username="patchuser", email="patch@example.com")
        refresh = RefreshToken.for_user(user)
        api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {refresh.access_token}")

        resp = api_client.patch(ME_URL, {"phone_number": "+15551234567"}, format="json")
        assert resp.status_code == status.HTTP_200_OK
        user.refresh_from_db()
        assert user.phone_number == "+15551234567"

    def test_patch_ignores_non_whitelisted_sensitive_fields(self, api_client, make_user):
        """A client cannot escalate privileges or bypass verification via PATCH."""
        user = make_user(username="patchuser2", email="patch2@example.com", email_verified=False)
        refresh = RefreshToken.for_user(user)
        api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {refresh.access_token}")

        resp = api_client.patch(
            ME_URL, {"phone_number": "+15550000000", "is_staff": True, "email_verified": True}, format="json"
        )
        assert resp.status_code == status.HTTP_200_OK
        user.refresh_from_db()
        assert user.is_staff is False
        assert user.email_verified is False

    def test_patch_requires_authentication(self, api_client):
        resp = api_client.patch(ME_URL, {"phone_number": "+15551234567"}, format="json")
        assert resp.status_code == status.HTTP_401_UNAUTHORIZED
